#include "haseeb/elf64_loader.hpp"
#include "haseeb/ext4_reader.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>

#define HASEEB_CHECK(cond)                                                              \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__              \
                      << ": " #cond << "\n";                                            \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif
#ifndef R_X86_64_64
#define R_X86_64_64 1
#endif
#ifndef R_X86_64_GLOB_DAT
#define R_X86_64_GLOB_DAT 6
#endif
#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE 8
#endif

namespace fs = std::filesystem;
using namespace haseeb::loader;

namespace {

std::string MakeTempDir(const std::string& tag) {
    std::string dir = "/tmp/haseeb_m2_" + tag + "_" + std::to_string(::getpid());
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

void WriteU16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    std::memcpy(buf.data() + off, &v, 2);
}

void WriteU32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    std::memcpy(buf.data() + off, &v, 4);
}

void WriteU64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    std::memcpy(buf.data() + off, &v, 8);
}

// Builds a valid raw 4 KiB-block ext4 image in memory and writes it to disk.
// Layout:
//   Block 0: boot padding + superblock @1024 (inodes=64, blocks=256, 64-bit BGDT desc_size=64)
//   Block 1: 64-byte Group Descriptor #0 -> inode table @ block 2
//   Block 2..5: Inode table (inodes 1..64, inode_size=256)
//   Block 10+: Directory & file data blocks
struct SyntheticExt4 {
    static constexpr uint32_t kBlockSize = 4096;
    static constexpr uint32_t kInodeSize = 256;
    static constexpr uint32_t kDescSize = 64;
    static constexpr uint32_t kTotalBlocks = 256;
    static constexpr uint32_t kInodeTableBlock = 2;

    std::vector<uint8_t> img;
    uint32_t next_free_block = 10;
    uint32_t next_free_inode = 12;

    SyntheticExt4() : img(kBlockSize * kTotalBlocks, 0) {
        // Superblock at byte offset 1024
        size_t sb = 1024;
        WriteU32(img, sb + 0, 64);                 // s_inodes_count
        WriteU32(img, sb + 4, kTotalBlocks);       // s_blocks_count_lo
        WriteU32(img, sb + 20, 0);                 // s_first_data_block (0 for 4K)
        WriteU32(img, sb + 24, 2);                 // s_log_block_size (1024<<2 = 4096)
        WriteU32(img, sb + 32, kTotalBlocks);      // s_blocks_per_group
        WriteU32(img, sb + 40, 64);                // s_inodes_per_group
        WriteU16(img, sb + 56, 0xEF53);            // s_magic
        WriteU32(img, sb + 76, 1);                 // s_rev_level = 1 (dynamic)
        WriteU16(img, sb + 88, kInodeSize);        // s_inode_size
        WriteU32(img, sb + 96, 0x0080u);           // s_feature_incompat = 64BIT
        WriteU16(img, sb + 254, kDescSize);        // s_desc_size
        std::memcpy(img.data() + sb + 120, "haseeb_sys", 10);

        // Group Descriptor 0 at Block 1 (byte 4096)
        size_t gd = kBlockSize;
        WriteU32(img, gd + 8, kInodeTableBlock);   // bg_inode_table_lo
    }

    size_t InodeOffset(uint32_t ino) const {
        return static_cast<size_t>(kInodeTableBlock) * kBlockSize +
               static_cast<size_t>(ino - 1) * kInodeSize;
    }

    uint32_t AllocBlocks(uint32_t count) {
        uint32_t start = next_free_block;
        next_free_block += count;
        HASEEB_CHECK(next_free_block <= kTotalBlocks);
        return start;
    }

    struct DirChild {
        uint32_t inode;
        uint8_t type;
        std::string name;
    };

    uint32_t CreateDirectory(uint32_t ino, const std::vector<DirChild>& children) {
        uint32_t blk = AllocBlocks(1);
        size_t off = InodeOffset(ino);
        WriteU16(img, off + 0, 0x41ED);            // S_IFDIR | 0755
        WriteU32(img, off + 4, kBlockSize);        // i_size_lo
        WriteU16(img, off + 26, 2);                // i_links_count
        WriteU32(img, off + 28, kBlockSize / 512); // i_blocks_lo
        WriteU32(img, off + 32, 0x00080000u);      // EXT4_EXTENTS_FL

        // Extent header + 1 leaf extent in i_block (off + 40)
        size_t eh = off + 40;
        WriteU16(img, eh + 0, 0xF30A);             // eh_magic
        WriteU16(img, eh + 2, 1);                  // eh_entries
        WriteU16(img, eh + 4, 4);                  // eh_max
        WriteU16(img, eh + 6, 0);                  // eh_depth
        WriteU32(img, eh + 12, 0);                 // ee_block
        WriteU16(img, eh + 16, 1);                 // ee_len
        WriteU16(img, eh + 18, 0);                 // ee_start_hi
        WriteU32(img, eh + 20, blk);               // ee_start_lo

        // Write ext4_dir_entry_2 entries inside block
        size_t pos = static_cast<size_t>(blk) * kBlockSize;
        size_t blk_end = pos + kBlockSize;
        for (size_t i = 0; i < children.size(); ++i) {
            const auto& ch = children[i];
            uint16_t raw_len = static_cast<uint16_t>(((8 + ch.name.size() + 3) / 4) * 4);
            uint16_t rec_len = (i + 1 == children.size())
                ? static_cast<uint16_t>(blk_end - pos)
                : raw_len;
            WriteU32(img, pos + 0, ch.inode);
            WriteU16(img, pos + 4, rec_len);
            img[pos + 6] = static_cast<uint8_t>(ch.name.size());
            img[pos + 7] = ch.type;
            std::memcpy(img.data() + pos + 8, ch.name.data(), ch.name.size());
            pos += rec_len;
        }
        return ino;
    }

    uint32_t CreateRegularFileExtents(const std::vector<uint8_t>& data) {
        uint32_t ino = next_free_inode++;
        uint32_t nblocks = std::max<uint32_t>(1u, static_cast<uint32_t>((data.size() + kBlockSize - 1) / kBlockSize));
        uint32_t start_blk = AllocBlocks(nblocks);

        size_t off = InodeOffset(ino);
        WriteU16(img, off + 0, 0x81A4);                        // S_IFREG | 0644
        WriteU32(img, off + 4, static_cast<uint32_t>(data.size()));
        WriteU16(img, off + 26, 1);
        WriteU32(img, off + 28, nblocks * (kBlockSize / 512));
        WriteU32(img, off + 32, 0x00080000u);                  // EXT4_EXTENTS_FL

        size_t eh = off + 40;
        WriteU16(img, eh + 0, 0xF30A);
        WriteU16(img, eh + 2, 1);
        WriteU16(img, eh + 4, 4);
        WriteU16(img, eh + 6, 0);
        WriteU32(img, eh + 12, 0);
        WriteU16(img, eh + 16, static_cast<uint16_t>(nblocks));
        WriteU16(img, eh + 18, 0);
        WriteU32(img, eh + 20, start_blk);

        if (!data.empty()) {
            std::memcpy(img.data() + static_cast<size_t>(start_blk) * kBlockSize, data.data(), data.size());
        }
        return ino;
    }

    uint32_t CreateRegularFileIndirect(const std::vector<uint8_t>& data) {
        uint32_t ino = next_free_inode++;
        uint32_t nblocks = static_cast<uint32_t>((data.size() + kBlockSize - 1) / kBlockSize);
        HASEEB_CHECK(nblocks > 12u);
        uint32_t ind_blk = AllocBlocks(1);
        uint32_t data_blk_start = AllocBlocks(nblocks);

        size_t off = InodeOffset(ino);
        WriteU16(img, off + 0, 0x81A4);
        WriteU32(img, off + 4, static_cast<uint32_t>(data.size()));
        WriteU16(img, off + 26, 1);
        WriteU32(img, off + 28, (nblocks + 1) * (kBlockSize / 512));
        WriteU32(img, off + 32, 0u); // legacy direct/indirect blocks

        for (uint32_t i = 0; i < 12; ++i) {
            WriteU32(img, off + 40 + i * 4, data_blk_start + i);
        }
        WriteU32(img, off + 40 + 12 * 4, ind_blk);
        for (uint32_t i = 12; i < nblocks; ++i) {
            WriteU32(img, static_cast<size_t>(ind_blk) * kBlockSize + (i - 12) * 4, data_blk_start + i);
        }
        std::memcpy(img.data() + static_cast<size_t>(data_blk_start) * kBlockSize, data.data(), data.size());
        return ino;
    }

    uint32_t CreateFastSymlink(const std::string& target) {
        HASEEB_CHECK(target.size() < 60u);
        uint32_t ino = next_free_inode++;
        size_t off = InodeOffset(ino);
        WriteU16(img, off + 0, 0xA1FF);
        WriteU32(img, off + 4, static_cast<uint32_t>(target.size()));
        WriteU16(img, off + 26, 1);
        WriteU32(img, off + 28, 0); // i_blocks_lo == 0 -> inline symlink
        std::memcpy(img.data() + off + 40, target.data(), target.size());
        return ino;
    }

    void WriteToFile(const std::string& path) const {
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        HASEEB_CHECK(ofs.good());
        ofs.write(reinterpret_cast<const char*>(img.data()), static_cast<std::streamsize>(img.size()));
        HASEEB_CHECK(ofs.good());
    }
};

void TestExt4MountFreeReader() {
    std::string dir = MakeTempDir("ext4");
    std::string img_path = dir + "/system.img";

    SyntheticExt4 fs_builder;
    std::string build_prop = "ro.build.version.sdk=35\nro.product.system.brand=Android\n";
    std::vector<uint8_t> prop_bytes(build_prop.begin(), build_prop.end());
    std::string rom_marker = "HASEEB_ROM_V1\n";
    std::vector<uint8_t> marker_bytes(rom_marker.begin(), rom_marker.end());

    // 14 blocks (56 KiB) exercising single-indirect block fallback
    std::vector<uint8_t> large_blob(14 * 4096 - 123, 0x5Au);
    large_blob[0] = 0x7F;
    large_blob.back() = 0xE7;

    uint32_t ino_build_prop = fs_builder.CreateRegularFileExtents(prop_bytes);
    uint32_t ino_rom_marker = fs_builder.CreateRegularFileExtents(marker_bytes);
    uint32_t ino_large = fs_builder.CreateRegularFileIndirect(large_blob);
    uint32_t ino_toybox = fs_builder.CreateRegularFileExtents({'T', 'O', 'Y', 'B', 'O', 'X'});
    uint32_t ino_sh_sym = fs_builder.CreateFastSymlink("toybox");

    uint32_t ino_bin = fs_builder.next_free_inode++;
    uint32_t ino_etc = fs_builder.next_free_inode++;
    uint32_t ino_system = fs_builder.next_free_inode++;

    fs_builder.CreateDirectory(ino_bin, {
        {ino_bin, 2, "."},
        {ino_system, 2, ".."},
        {ino_toybox, 1, "toybox"},
        {ino_sh_sym, 7, "sh"},
    });
    fs_builder.CreateDirectory(ino_etc, {
        {ino_etc, 2, "."},
        {ino_system, 2, ".."},
        {ino_rom_marker, 1, "haseeb_rom"},
        {ino_large, 1, "large_indirect.bin"},
    });
    fs_builder.CreateDirectory(ino_system, {
        {ino_system, 2, "."},
        {2, 2, ".."},
        {ino_build_prop, 1, "build.prop"},
        {ino_bin, 2, "bin"},
        {ino_etc, 2, "etc"},
    });
    fs_builder.CreateDirectory(2, {
        {2, 2, "."},
        {2, 2, ".."},
        {ino_system, 2, "system"},
    });
    fs_builder.WriteToFile(img_path);

    Ext4Reader reader;
    HASEEB_CHECK(reader.Open(img_path));
    HASEEB_CHECK(reader.BlockSize() == 4096u);
    HASEEB_CHECK(reader.VolumeName() == "haseeb_sys");
    HASEEB_CHECK(reader.Exists("/system/build.prop"));
    HASEEB_CHECK(reader.Exists("/system/bin/sh"));

    std::string txt;
    HASEEB_CHECK(reader.ReadFileString("/system/build.prop", txt) && txt == build_prop);
    HASEEB_CHECK(reader.ReadFileString("/system/etc/haseeb_rom", txt) && txt == rom_marker);

    // Symlink inspection + symlink target resolution via ReadFileString("/system/bin/sh")
    std::string target;
    HASEEB_CHECK(reader.ReadSymlink("/system/bin/sh", target) && target == "toybox");
    HASEEB_CHECK(reader.ReadFileString("/system/bin/sh", txt) && txt == "TOYBOX");

    Ext4Stat st{};
    HASEEB_CHECK(reader.Stat("/system/bin/sh", st) && st.IsSymlink());
    HASEEB_CHECK(reader.Stat("/system/bin/toybox", st) && st.IsRegular() && st.size == 6);

    // Directory listing
    std::vector<Ext4DirEntry> entries;
    HASEEB_CHECK(reader.ReadDir("/system/bin", entries));
    HASEEB_CHECK(entries.size() == 4);

    // Multi-block indirect read
    std::vector<uint8_t> read_large;
    HASEEB_CHECK(reader.ReadFile("/system/etc/large_indirect.bin", read_large));
    HASEEB_CHECK(read_large == large_blob);

    fs::remove_all(dir);
    std::cout << "[PASS] TestExt4MountFreeReader\n";
}

// Constructs a dependency DSO exporting `ext_magic_fn` at vaddr 0x1000
std::vector<uint8_t> BuildDependencyElf64() {
    std::vector<uint8_t> elf(0x3000, 0);
    auto* eh = reinterpret_cast<Elf64_Ehdr*>(elf.data());
    std::memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_DYN;
#if defined(__aarch64__)
    eh->e_machine = EM_AARCH64;
#else
    eh->e_machine = EM_X86_64;
#endif
    eh->e_version = EV_CURRENT;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_ehsize = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 2;

    auto* ph = reinterpret_cast<Elf64_Phdr*>(elf.data() + eh->e_phoff);
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0x1000;
    ph[0].p_vaddr = 0x1000;
    ph[0].p_paddr = 0x1000;
    ph[0].p_filesz = 0x1000;
    ph[0].p_memsz = 0x1000;
    ph[0].p_align = 4096;

    ph[1].p_type = PT_DYNAMIC;
    ph[1].p_flags = PF_R;
    ph[1].p_offset = 0x1200;
    ph[1].p_vaddr = 0x1200;
    ph[1].p_filesz = 0x100;
    ph[1].p_memsz = 0x100;
    ph[1].p_align = 8;

    // Symtab @0x1400, Strtab @0x1500
    const char strtab[] = "\0ext_magic_fn\0";
    std::memcpy(elf.data() + 0x1500, strtab, sizeof(strtab));

    auto* sym = reinterpret_cast<Elf64_Sym*>(elf.data() + 0x1400);
    sym[1].st_name = 1; // "ext_magic_fn"
    sym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym[1].st_shndx = 1;
    sym[1].st_value = 0x1040;

    auto* dyn = reinterpret_cast<Elf64_Dyn*>(elf.data() + 0x1200);
    dyn[0] = {DT_SYMTAB, {0x1400}};
    dyn[1] = {DT_STRTAB, {0x1500}};
    dyn[2] = {DT_STRSZ, {sizeof(strtab)}};
    dyn[3] = {DT_NULL, {0}};

    return elf;
}

// Constructs a guest ET_DYN ELF64 with:
// - 4 KiB misaligned PT_LOAD segments sharing a 16 KiB host page (0x1000 RX, 0x2000 RW)
// - Native machine code stub @ entry 0x1000 returning 42
// - DT_RELR (address @0x2000 + 63-bit bitmap covering @0x2008 and @0x2018)
// - DT_RELA (RELATIVE @0x2020 + GLOB_DAT resolving `ext_magic_fn` @0x2028)
// - PT_INTERP = "/system/bin/linker64"
std::vector<uint8_t> BuildRelocatableGuestElf64(const std::string& interp) {
    std::vector<uint8_t> elf(0x4000, 0);
    auto* eh = reinterpret_cast<Elf64_Ehdr*>(elf.data());
    std::memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_type = ET_DYN;
#if defined(__aarch64__)
    eh->e_machine = EM_AARCH64;
#else
    eh->e_machine = EM_X86_64;
#endif
    eh->e_version = EV_CURRENT;
    eh->e_entry = 0x1000;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_ehsize = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 4;

    auto* ph = reinterpret_cast<Elf64_Phdr*>(elf.data() + eh->e_phoff);
    // Segment 0: RX code starting at 4 KiB offset 0x1000
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0x1000;
    ph[0].p_vaddr = 0x1000;
    ph[0].p_paddr = 0x1000;
    ph[0].p_filesz = 0x1000;
    ph[0].p_memsz = 0x1000;
    ph[0].p_align = 4096;

    // Segment 1: RW data starting at 0x2000 (same 16 KiB page as Segment 0!)
    ph[1].p_type = PT_LOAD;
    ph[1].p_flags = PF_R | PF_W;
    ph[1].p_offset = 0x2000;
    ph[1].p_vaddr = 0x2000;
    ph[1].p_paddr = 0x2000;
    ph[1].p_filesz = 0x1800;
    ph[1].p_memsz = 0x2000;
    ph[1].p_align = 4096;

    // Segment 2: PT_INTERP at 0x2500
    ph[2].p_type = PT_INTERP;
    ph[2].p_flags = PF_R;
    ph[2].p_offset = 0x2500;
    ph[2].p_vaddr = 0x2500;
    ph[2].p_filesz = interp.size() + 1;
    ph[2].p_memsz = interp.size() + 1;
    ph[2].p_align = 1;
    std::memcpy(elf.data() + 0x2500, interp.c_str(), interp.size() + 1);

    // Segment 3: PT_DYNAMIC at 0x2100
    ph[3].p_type = PT_DYNAMIC;
    ph[3].p_flags = PF_R | PF_W;
    ph[3].p_offset = 0x2100;
    ph[3].p_vaddr = 0x2100;
    ph[3].p_filesz = 0x200;
    ph[3].p_memsz = 0x200;
    ph[3].p_align = 8;

    // Native executable payload @ 0x1000 returning 42
#if defined(__aarch64__)
    const uint8_t code[] = {0x40, 0x05, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}; // mov w0, #42; ret
#else
    const uint8_t code[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};             // mov eax, 42; ret
#endif
    std::memcpy(elf.data() + 0x1000, code, sizeof(code));

    // Relocation target initial values in RW segment (0x2000..0x202F)
    WriteU64(elf, 0x2000, 0x1111ull); // RELR address entry
    WriteU64(elf, 0x2008, 0x2222ull); // RELR bitmap bit 0 (0x2008)
    WriteU64(elf, 0x2018, 0x3333ull); // RELR bitmap bit 2 (0x2018)
    WriteU64(elf, 0x2020, 0ull);      // RELA RELATIVE -> load_bias + 0x1234
    WriteU64(elf, 0x2028, 0ull);      // RELA GLOB_DAT -> dep.ext_magic_fn

    // DT_RELR table @ 0x2300: [0x2000, ((1<<0)|(1<<2))<<1 | 1]
    WriteU64(elf, 0x2300, 0x2000ull);
    WriteU64(elf, 0x2308, (((1ull << 0) | (1ull << 2)) << 1) | 1ull);

    // DT_SYMTAB @ 0x2380, DT_STRTAB @ 0x2400
    const char strtab[] = "\0libdep.so\0ext_magic_fn\0";
    std::memcpy(elf.data() + 0x2400, strtab, sizeof(strtab));
    auto* sym = reinterpret_cast<Elf64_Sym*>(elf.data() + 0x2380);
    sym[1].st_name = 11; // "ext_magic_fn"
    sym[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym[1].st_shndx = SHN_UNDEF;

    // DT_RELA table @ 0x2340
    auto* rela = reinterpret_cast<Elf64_Rela*>(elf.data() + 0x2340);
#if defined(__aarch64__)
    rela[0] = {0x2020, ELF64_R_INFO(0, R_AARCH64_RELATIVE), 0x1234};
    rela[1] = {0x2028, ELF64_R_INFO(1, R_AARCH64_GLOB_DAT), 0};
#else
    rela[0] = {0x2020, ELF64_R_INFO(0, R_X86_64_RELATIVE), 0x1234};
    rela[1] = {0x2028, ELF64_R_INFO(1, R_X86_64_GLOB_DAT), 0};
#endif

    // PT_DYNAMIC @ 0x2100
    auto* dyn = reinterpret_cast<Elf64_Dyn*>(elf.data() + 0x2100);
    dyn[0] = {DT_NEEDED, {1}}; // "libdep.so"
    dyn[1] = {DT_RELR, {0x2300}};
    dyn[2] = {DT_RELRSZ, {16}};
    dyn[3] = {DT_RELRENT, {8}};
    dyn[4] = {DT_RELA, {0x2340}};
    dyn[5] = {DT_RELASZ, {2 * sizeof(Elf64_Rela)}};
    dyn[6] = {DT_RELAENT, {sizeof(Elf64_Rela)}};
    dyn[7] = {DT_SYMTAB, {0x2380}};
    dyn[8] = {DT_STRTAB, {0x2400}};
    dyn[9] = {DT_STRSZ, {sizeof(strtab)}};
    dyn[10] = {DT_NULL, {0}};

    return elf;
}

void TestElf64Relocations4kAnd16k() {
    // Test with forced 16 KiB page alignment even on 4 KiB x86_64 CI hosts
    Elf64Loader loader(16384);
    HASEEB_CHECK(loader.EffectivePageSize() == 16384u);

    auto dep_bytes = BuildDependencyElf64();
    auto dep_img = loader.LoadFromBytes("/system/lib64/libdep.so", dep_bytes, {}, true);
    HASEEB_CHECK(dep_img != nullptr);
    HASEEB_CHECK((dep_img->map_base % 16384u) == 0u);
    uintptr_t ext_addr = dep_img->FindSymbol("ext_magic_fn");
    HASEEB_CHECK(ext_addr == dep_img->load_bias + 0x1040u);

    auto exe_bytes = BuildRelocatableGuestElf64("/system/bin/linker64");
    auto exe_img = loader.LoadFromBytes("/system/bin/test_guest", exe_bytes, {dep_img.get()}, true);
    HASEEB_CHECK(exe_img != nullptr);
    HASEEB_CHECK((exe_img->map_base % 16384u) == 0u);
    HASEEB_CHECK(exe_img->interp_path == "/system/bin/linker64");
    HASEEB_CHECK(exe_img->needed_libs.size() == 1 && exe_img->needed_libs[0] == "libdep.so");
    HASEEB_CHECK(exe_img->relr_applied_count == 3u);
    HASEEB_CHECK(exe_img->rela_applied_count == 2u);

    // Verify exact RELR address + bitmap relocation results
    auto read_u64 = [&](uintptr_t vaddr) -> uint64_t {
        return *reinterpret_cast<const uint64_t*>(exe_img->load_bias + vaddr);
    };
    HASEEB_CHECK(read_u64(0x2000) == exe_img->load_bias + 0x1111ull);
    HASEEB_CHECK(read_u64(0x2008) == exe_img->load_bias + 0x2222ull);
    HASEEB_CHECK(read_u64(0x2018) == exe_img->load_bias + 0x3333ull);

    // Verify exact RELA RELATIVE + GLOB_DAT relocation results
    HASEEB_CHECK(read_u64(0x2020) == exe_img->load_bias + 0x1234ull);
    HASEEB_CHECK(read_u64(0x2028) == static_cast<uint64_t>(ext_addr));

    // Verify RW+RX page protection union allows live execution of entry point
    using EntryFn = int (*)();
    auto fn = reinterpret_cast<EntryFn>(exe_img->entry_point);
    HASEEB_CHECK(fn() == 42);

    std::cout << "[PASS] TestElf64Relocations4kAnd16k\n";
}

void TestLinker64AndAuxvAndSelfExe() {
    std::string dir = MakeTempDir("vfs");
    fs::create_directories(dir + "/apex/com.android.art/bin");
    fs::create_directories(dir + "/system/bin");
    {
        std::ofstream f(dir + "/apex/com.android.art/bin/linker64", std::ios::binary);
        f << "ART_LINKER";
    }
    {
        std::ofstream f(dir + "/system/bin/linker64", std::ios::binary);
        f << "SYS_LINKER";
    }

    GuestVfsResolver vfs;
    vfs.SetHostFallbackRoot(dir);
    HASEEB_CHECK(vfs.ResolveLinker64Path(29) == "/system/bin/linker64");
    HASEEB_CHECK(vfs.ResolveLinker64Path(35) == "/apex/com.android.art/bin/linker64");

    auto env35 = vfs.BuildLinker64Env(35, dir);
    HASEEB_CHECK(std::find(env35.begin(), env35.end(), "ANDROID_ART_ROOT=/apex/com.android.art") != env35.end());

    std::vector<uint8_t> exe_payload = {0x7F, 'E', 'L', 'F', 1, 2, 3, 4};
    HASEEB_CHECK(vfs.RegisterSelfExe("/system/bin/my_guest", exe_payload));
    std::string self_target;
    HASEEB_CHECK(vfs.ReadLink("/proc/self/exe", self_target) && self_target == "/system/bin/my_guest");
    std::vector<uint8_t> self_bytes;
    HASEEB_CHECK(vfs.ReadGuestFile("/proc/self/exe", self_bytes) && self_bytes == exe_payload);

    // Check auxv builder
    Elf64Loader loader(16384);
    auto dep_bytes = BuildDependencyElf64();
    auto linker_img = loader.LoadFromBytes("/system/bin/linker64", dep_bytes, {}, false);
    auto exe_img = loader.LoadFromBytes("/system/bin/my_guest", BuildRelocatableGuestElf64("/system/bin/linker64"), {}, false);
    HASEEB_CHECK(linker_img && exe_img);

    uint8_t rand16[16]{};
    auto auxv = GuestAuxvBuilder::BuildAuxv(*exe_img, linker_img.get(), 0xCAFEBABEull, reinterpret_cast<uintptr_t>(rand16), 16384);
    auto find_auxv = [&](uint64_t key, uint64_t& out) -> bool {
        for (size_t i = 0; i + 1 < auxv.size(); i += 2) {
            if (auxv[i] == key) {
                out = auxv[i + 1];
                return true;
            }
        }
        return false;
    };
    uint64_t v = 0;
    HASEEB_CHECK(find_auxv(AT_PHDR, v) && v == exe_img->phdr_addr);
    HASEEB_CHECK(find_auxv(AT_BASE, v) && v == linker_img->load_bias);
    HASEEB_CHECK(find_auxv(AT_ENTRY, v) && v == exe_img->entry_point);
    HASEEB_CHECK(find_auxv(AT_PAGESZ, v) && v == 16384u);
    HASEEB_CHECK(find_auxv(AT_EXECFN, v) && v == 0xCAFEBABEull);

    fs::remove_all(dir);
    std::cout << "[PASS] TestLinker64AndAuxvAndSelfExe\n";
}

void AppendLe16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

std::vector<uint8_t> PackAndroidSparse(const std::vector<uint8_t>& raw) {
    const uint32_t blk_sz = 4096u;
    const uint32_t total_blks = static_cast<uint32_t>((raw.size() + blk_sz - 1u) / blk_sz);
    std::vector<uint8_t> padded = raw;
    padded.resize(static_cast<size_t>(total_blks) * blk_sz, 0u);

    std::vector<std::tuple<uint16_t, uint32_t, uint32_t, const uint8_t*>> chunks;
    uint32_t b = 0;
    while (b < total_blks) {
        const uint8_t* p = padded.data() + static_cast<size_t>(b) * blk_sz;
        bool all_zero = true;
        for (uint32_t i = 0; i < blk_sz; ++i) {
            if (p[i] != 0u) { all_zero = false; break; }
        }
        if (all_zero) {
            uint32_t run = 1;
            while (b + run < total_blks) {
                const uint8_t* q = padded.data() + static_cast<size_t>(b + run) * blk_sz;
                bool z = true;
                for (uint32_t i = 0; i < blk_sz; ++i) {
                    if (q[i] != 0u) { z = false; break; }
                }
                if (!z) break;
                ++run;
            }
            chunks.emplace_back(0xCAC3u /* DONT_CARE */, run, 0u, nullptr);
            b += run;
        } else {
            chunks.emplace_back(0xCAC1u /* RAW */, 1u, 0u, p);
            b += 1u;
        }
    }
    chunks.emplace_back(0xCAC4u /* CRC32 */, 0u, 0x12345678u, nullptr);

    std::vector<uint8_t> out;
    AppendLe32(out, 0xED26FF3Au); // magic
    AppendLe16(out, 1u);          // major
    AppendLe16(out, 0u);          // minor
    AppendLe16(out, 28u);         // file_hdr_sz
    AppendLe16(out, 12u);         // chunk_hdr_sz
    AppendLe32(out, blk_sz);
    AppendLe32(out, total_blks);
    AppendLe32(out, static_cast<uint32_t>(chunks.size()));
    AppendLe32(out, 0u);

    for (const auto& [ctype, cblks, cval, ptr] : chunks) {
        AppendLe16(out, ctype);
        AppendLe16(out, 0u);
        AppendLe32(out, cblks);
        if (ctype == 0xCAC1u) {
            AppendLe32(out, 12u + cblks * blk_sz);
            out.insert(out.end(), ptr, ptr + static_cast<size_t>(cblks) * blk_sz);
        } else if (ctype == 0xCAC3u) {
            AppendLe32(out, 12u);
        } else {
            AppendLe32(out, 16u);
            AppendLe32(out, cval);
        }
    }
    return out;
}

void TestSparseAndGptAndLpSuperExt4() {
    std::string dir = MakeTempDir("ext4_formats");

    SyntheticExt4 fs_builder;
    std::string build_prop = "ro.product.model=SM-S938B\n";
    std::vector<uint8_t> prop_bytes(build_prop.begin(), build_prop.end());
    uint32_t ino_prop = fs_builder.CreateRegularFileExtents(prop_bytes);
    uint32_t ino_sys = fs_builder.next_free_inode++;
    fs_builder.CreateDirectory(ino_sys, {
        {ino_sys, 2, "."},
        {2, 2, ".."},
        {ino_prop, 1, "build.prop"},
    });
    fs_builder.CreateDirectory(2, {
        {2, 2, "."},
        {2, 2, ".."},
        {ino_sys, 2, "system"},
    });

    // 1. Test Android Sparse Image (0xED26FF3A)
    const std::string sparse_path = dir + "/system_sparse.img";
    {
        auto sparse = PackAndroidSparse(fs_builder.img);
        std::ofstream ofs(sparse_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(sparse.data()), static_cast<std::streamsize>(sparse.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(r.Open(sparse_path));
        HASEEB_CHECK(r.IsSparse());
        std::string read_prop;
        HASEEB_CHECK(r.ReadFileString("/system/build.prop", read_prop));
        HASEEB_CHECK(read_prop == build_prop);
    }

    // 2. Test GPT partitioned disk image (partition starting at LBA 64 = 32768)
    const std::string gpt_path = dir + "/disk_gpt.img";
    {
        const size_t part_off = 64u * 512u;
        std::vector<uint8_t> disk(part_off + fs_builder.img.size(), 0u);
        std::memcpy(disk.data() + part_off, fs_builder.img.data(), fs_builder.img.size());
        // GPT header at LBA 1 (512)
        std::memcpy(disk.data() + 512u, "EFI PART", 8u);
        const uint64_t part_lba = 2u;
        const uint32_t num_entries = 4u;
        const uint32_t entry_sz = 128u;
        std::memcpy(disk.data() + 512u + 72u, &part_lba, 8u);
        std::memcpy(disk.data() + 512u + 80u, &num_entries, 4u);
        std::memcpy(disk.data() + 512u + 84u, &entry_sz, 4u);

        uint8_t* pe = disk.data() + 2u * 512u;
        const uint64_t s_lba = 64u;
        const uint64_t e_lba = 64u + (fs_builder.img.size() / 512u) - 1u;
        std::memcpy(pe + 32u, &s_lba, 8u);
        std::memcpy(pe + 40u, &e_lba, 8u);
        const char* nm = "system_a";
        for (size_t i = 0; nm[i] != '\0'; ++i) {
            pe[56u + i * 2u] = static_cast<uint8_t>(nm[i]);
        }

        std::ofstream ofs(gpt_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(disk.data()), static_cast<std::streamsize>(disk.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(r.Open(gpt_path));
        HASEEB_CHECK(r.HasPartitionOffset());
        std::string read_prop;
        HASEEB_CHECK(r.ReadFileString("/system/build.prop", read_prop));
        HASEEB_CHECK(read_prop == build_prop);
    }

    // 3. Test Sparse super.img (LP metadata gDla + 0PLA pointing to system_a)
    const std::string super_path = dir + "/super_sparse.img";
    {
        const size_t part_off = 64u * 1024u; // sector 128
        std::vector<uint8_t> super_raw(part_off + fs_builder.img.size(), 0u);
        std::memcpy(super_raw.data() + part_off, fs_builder.img.data(), fs_builder.img.size());

        const uint32_t g_magic = 0x616C4467u;
        std::memcpy(super_raw.data() + 4096u, &g_magic, 4u);

        const size_t hdr_off = 12288u;
        const uint32_t m_magic = 0x414C5030u;
        const uint32_t h_size = 128u;
        std::memcpy(super_raw.data() + hdr_off + 0u, &m_magic, 4u);
        std::memcpy(super_raw.data() + hdr_off + 8u, &h_size, 4u);
        // partitions descriptor @0x50 (offset=0, num=1, entry_size=52)
        const uint32_t p_desc[3] = {0u, 1u, 52u};
        // extents descriptor @0x5C (offset=64, num=1, entry_size=24)
        const uint32_t e_desc[3] = {64u, 1u, 24u};
        std::memcpy(super_raw.data() + hdr_off + 0x50u, p_desc, sizeof(p_desc));
        std::memcpy(super_raw.data() + hdr_off + 0x5Cu, e_desc, sizeof(e_desc));

        const size_t tbase = hdr_off + h_size;
        std::memcpy(super_raw.data() + tbase + 0u, "system_a", 9u);
        const uint32_t first_ext = 0u, num_ext = 1u;
        std::memcpy(super_raw.data() + tbase + 40u, &first_ext, 4u);
        std::memcpy(super_raw.data() + tbase + 44u, &num_ext, 4u);

        const uint64_t ex_sectors = fs_builder.img.size() / 512u;
        const uint32_t ex_type = 0u; // LINEAR
        const uint64_t ex_data = part_off / 512u;
        std::memcpy(super_raw.data() + tbase + 64u + 0u, &ex_sectors, 8u);
        std::memcpy(super_raw.data() + tbase + 64u + 8u, &ex_type, 4u);
        std::memcpy(super_raw.data() + tbase + 64u + 12u, &ex_data, 8u);

        auto sparse_super = PackAndroidSparse(super_raw);
        std::ofstream ofs(super_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(sparse_super.data()),
                  static_cast<std::streamsize>(sparse_super.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(r.Open(super_path));
        HASEEB_CHECK(r.IsSparse());
        HASEEB_CHECK(r.HasPartitionOffset());
        std::string read_prop;
        HASEEB_CHECK(r.ReadFileString("/system/build.prop", read_prop));
        HASEEB_CHECK(read_prop == build_prop);
    }

    // 4. Test 4096-byte sector GPT disk image
    const std::string gpt4k_path = dir + "/disk_gpt4k.img";
    {
        const size_t part_off = 16u * 4096u;
        std::vector<uint8_t> disk(part_off + fs_builder.img.size(), 0u);
        std::memcpy(disk.data() + part_off, fs_builder.img.data(), fs_builder.img.size());
        std::memcpy(disk.data() + 4096u, "EFI PART", 8u);
        const uint64_t part_lba = 2u;
        const uint32_t num_entries = 4u;
        const uint32_t entry_sz = 128u;
        std::memcpy(disk.data() + 4096u + 72u, &part_lba, 8u);
        std::memcpy(disk.data() + 4096u + 80u, &num_entries, 4u);
        std::memcpy(disk.data() + 4096u + 84u, &entry_sz, 4u);

        uint8_t* pe = disk.data() + 2u * 4096u;
        const uint64_t s_lba = 16u;
        const uint64_t e_lba = 16u + (fs_builder.img.size() / 4096u) - 1u;
        std::memcpy(pe + 32u, &s_lba, 8u);
        std::memcpy(pe + 40u, &e_lba, 8u);
        const char* nm = "system";
        for (size_t i = 0; nm[i] != '\0'; ++i) {
            pe[56u + i * 2u] = static_cast<uint8_t>(nm[i]);
        }
        std::ofstream ofs(gpt4k_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(disk.data()), static_cast<std::streamsize>(disk.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(r.Open(gpt4k_path));
        HASEEB_CHECK(r.HasPartitionOffset());
        std::string read_prop;
        HASEEB_CHECK(r.ReadFileString("/system/build.prop", read_prop));
        HASEEB_CHECK(read_prop == build_prop);
    }

    // 5. Test 1 MiB padded ext4 offset probe (TryProbeExt4Offset)
    const std::string padded_path = dir + "/padded_1m.img";
    {
        const size_t pad = 1024u * 1024u;
        std::vector<uint8_t> raw(pad + fs_builder.img.size(), 0u);
        std::memcpy(raw.data() + pad, fs_builder.img.data(), fs_builder.img.size());
        std::ofstream ofs(padded_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(r.Open(padded_path));
        HASEEB_CHECK(r.HasPartitionOffset());
        std::string read_prop;
        HASEEB_CHECK(r.ReadFileString("/system/build.prop", read_prop));
        HASEEB_CHECK(read_prop == build_prop);
    }

    // 6. Test LP super.img containing EROFS reports clear diagnostic
    const std::string super_erofs_path = dir + "/super_erofs.img";
    {
        const size_t part_off = 64u * 1024u;
        std::vector<uint8_t> raw(part_off + 8192u, 0u);
        const uint32_t g_magic = 0x616C4467u;
        const uint32_t max_sz = 65536u;
        const uint32_t slots = 2u;
        std::memcpy(raw.data() + 4096u, &g_magic, 4u);
        std::memcpy(raw.data() + 4096u + 40u, &max_sz, 4u);
        std::memcpy(raw.data() + 4096u + 44u, &slots, 4u);
        const size_t hdr_off = 12288u;
        const uint32_t m_magic = 0x414C5030u;
        const uint32_t h_size = 128u;
        std::memcpy(raw.data() + hdr_off, &m_magic, 4u);
        std::memcpy(raw.data() + hdr_off + 8u, &h_size, 4u);
        const uint32_t p_desc[3] = {0u, 1u, 52u};
        const uint32_t e_desc[3] = {64u, 1u, 24u};
        std::memcpy(raw.data() + hdr_off + 0x50u, p_desc, sizeof(p_desc));
        std::memcpy(raw.data() + hdr_off + 0x5Cu, e_desc, sizeof(e_desc));
        const size_t tbase = hdr_off + h_size;
        std::memcpy(raw.data() + tbase, "system_a", 9u);
        const uint32_t first_ext = 0u, num_ext = 1u;
        std::memcpy(raw.data() + tbase + 40u, &first_ext, 4u);
        std::memcpy(raw.data() + tbase + 44u, &num_ext, 4u);
        const uint64_t ex_sectors = 16u;
        const uint32_t ex_type = 0u;
        const uint64_t ex_data = part_off / 512u;
        std::memcpy(raw.data() + tbase + 64u, &ex_sectors, 8u);
        std::memcpy(raw.data() + tbase + 64u + 8u, &ex_type, 4u);
        std::memcpy(raw.data() + tbase + 64u + 12u, &ex_data, 8u);
        const uint32_t erofs_magic = 0xE0F5E1E2u;
        std::memcpy(raw.data() + part_off + 1024u, &erofs_magic, 4u);
        std::ofstream ofs(super_erofs_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    }
    {
        Ext4Reader r;
        HASEEB_CHECK(!r.Open(super_erofs_path));
        HASEEB_CHECK(r.LastError().find("super.img (LP)") != std::string::npos);
        HASEEB_CHECK(r.LastError().find("EROFS") != std::string::npos);
    }

    fs::remove_all(dir);
    std::cout << "[PASS] TestSparseAndGptAndLpSuperExt4\n";
}

} // namespace

int main() {
    TestExt4MountFreeReader();
    TestSparseAndGptAndLpSuperExt4();
    TestElf64Relocations4kAnd16k();
    TestLinker64AndAuxvAndSelfExe();
    std::cout << "All M2 Guest Loader unit tests PASSED.\n";
    return 0;
}
