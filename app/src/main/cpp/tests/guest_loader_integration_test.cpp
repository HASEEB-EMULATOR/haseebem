#include "haseeb/elf64_loader.hpp"
#include "haseeb/ext4_reader.hpp"
#include "haseeb/prop_area.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
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
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif
#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE 8
#endif

namespace fs = std::filesystem;
using namespace haseeb::loader;
using namespace haseeb::prop;

namespace {

void WriteU16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    std::memcpy(buf.data() + off, &v, 2);
}

void WriteU32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    std::memcpy(buf.data() + off, &v, 4);
}

class RawExt4PartitionWriter {
public:
    static constexpr uint32_t kBlockSize = 4096;
    static constexpr uint32_t kInodeSize = 256;
    static constexpr uint32_t kDescSize = 64;
    static constexpr uint32_t kTotalBlocks = 128;
    static constexpr uint32_t kInodeTableBlock = 2;

    std::vector<uint8_t> img;
    uint32_t next_block = 8;
    uint32_t next_inode = 12;

    explicit RawExt4PartitionWriter(const std::string& label)
        : img(kBlockSize * kTotalBlocks, 0) {
        size_t sb = 1024;
        WriteU32(img, sb + 0, 64);
        WriteU32(img, sb + 4, kTotalBlocks);
        WriteU32(img, sb + 24, 2);
        WriteU32(img, sb + 32, kTotalBlocks);
        WriteU32(img, sb + 40, 64);
        WriteU16(img, sb + 56, 0xEF53);
        WriteU32(img, sb + 76, 1);
        WriteU16(img, sb + 88, kInodeSize);
        WriteU32(img, sb + 96, 0x0080u);
        WriteU16(img, sb + 254, kDescSize);
        std::memcpy(img.data() + sb + 120, label.data(), std::min<size_t>(label.size(), 15));
        WriteU32(img, kBlockSize + 8, kInodeTableBlock);
    }

    size_t InodeOff(uint32_t ino) const {
        return static_cast<size_t>(kInodeTableBlock) * kBlockSize +
               static_cast<size_t>(ino - 1) * kInodeSize;
    }

    uint32_t AllocBlocks(uint32_t n) {
        uint32_t s = next_block;
        next_block += n;
        HASEEB_CHECK(next_block <= kTotalBlocks);
        return s;
    }

    uint32_t AddFile(const std::vector<uint8_t>& data) {
        uint32_t ino = next_inode++;
        uint32_t nblocks = std::max<uint32_t>(1u, static_cast<uint32_t>((data.size() + kBlockSize - 1) / kBlockSize));
        uint32_t blk = AllocBlocks(nblocks);
        size_t off = InodeOff(ino);
        WriteU16(img, off + 0, 0x81ED);
        WriteU32(img, off + 4, static_cast<uint32_t>(data.size()));
        WriteU16(img, off + 26, 1);
        WriteU32(img, off + 28, nblocks * (kBlockSize / 512));
        WriteU32(img, off + 32, 0x00080000u);

        size_t eh = off + 40;
        WriteU16(img, eh + 0, 0xF30A);
        WriteU16(img, eh + 2, 1);
        WriteU16(img, eh + 4, 4);
        WriteU16(img, eh + 6, 0);
        WriteU32(img, eh + 12, 0);
        WriteU16(img, eh + 16, static_cast<uint16_t>(nblocks));
        WriteU32(img, eh + 20, blk);

        if (!data.empty()) {
            std::memcpy(img.data() + static_cast<size_t>(blk) * kBlockSize, data.data(), data.size());
        }
        return ino;
    }

    void PopulateDir(uint32_t ino, const std::vector<std::tuple<uint32_t, uint8_t, std::string>>& items) {
        uint32_t blk = AllocBlocks(1);
        size_t off = InodeOff(ino);
        WriteU16(img, off + 0, 0x41ED);
        WriteU32(img, off + 4, kBlockSize);
        WriteU16(img, off + 26, 2);
        WriteU32(img, off + 28, kBlockSize / 512);
        WriteU32(img, off + 32, 0x00080000u);

        size_t eh = off + 40;
        WriteU16(img, eh + 0, 0xF30A);
        WriteU16(img, eh + 2, 1);
        WriteU16(img, eh + 4, 4);
        WriteU16(img, eh + 6, 0);
        WriteU32(img, eh + 12, 0);
        WriteU16(img, eh + 16, 1);
        WriteU32(img, eh + 20, blk);

        size_t pos = static_cast<size_t>(blk) * kBlockSize;
        size_t end = pos + kBlockSize;
        for (size_t i = 0; i < items.size(); ++i) {
            uint32_t child_ino = std::get<0>(items[i]);
            uint8_t child_type = std::get<1>(items[i]);
            const std::string& name = std::get<2>(items[i]);
            uint16_t raw = static_cast<uint16_t>(((8 + name.size() + 3) / 4) * 4);
            uint16_t rec = (i + 1 == items.size()) ? static_cast<uint16_t>(end - pos) : raw;
            WriteU32(img, pos + 0, child_ino);
            WriteU16(img, pos + 4, rec);
            img[pos + 6] = static_cast<uint8_t>(name.size());
            img[pos + 7] = child_type;
            std::memcpy(img.data() + pos + 8, name.data(), name.size());
            pos += rec;
        }
    }

    void Save(const std::string& path) const {
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        HASEEB_CHECK(ofs.good());
        ofs.write(reinterpret_cast<const char*>(img.data()), static_cast<std::streamsize>(img.size()));
        HASEEB_CHECK(ofs.good());
    }
};

std::vector<uint8_t> BuildGuestBinary(int return_val, const std::string& interp) {
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
    eh->e_phnum = interp.empty() ? 2 : 3;

    auto* ph = reinterpret_cast<Elf64_Phdr*>(elf.data() + eh->e_phoff);
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_X;
    ph[0].p_offset = 0x1000;
    ph[0].p_vaddr = 0x1000;
    ph[0].p_paddr = 0x1000;
    ph[0].p_filesz = 0x1000;
    ph[0].p_memsz = 0x1000;
    ph[0].p_align = 4096;

    ph[1].p_type = PT_LOAD;
    ph[1].p_flags = PF_R | PF_W;
    ph[1].p_offset = 0x2000;
    ph[1].p_vaddr = 0x2000;
    ph[1].p_paddr = 0x2000;
    ph[1].p_filesz = 0x1000;
    ph[1].p_memsz = 0x1000;
    ph[1].p_align = 4096;

    // Native return stub returning `return_val` (must fit in uint8_t for compact test)
    uint8_t rv = static_cast<uint8_t>(return_val & 0xFF);
#if defined(__aarch64__)
    uint32_t movz = 0x52800000u | (static_cast<uint32_t>(rv) << 5);
    std::memcpy(elf.data() + 0x1000, &movz, 4);
    uint32_t ret_insn = 0xD65F03C0u;
    std::memcpy(elf.data() + 0x1004, &ret_insn, 4);
#else
    const uint8_t code[] = {0xB8, rv, 0x00, 0x00, 0x00, 0xC3};
    std::memcpy(elf.data() + 0x1000, code, sizeof(code));
#endif

    if (!interp.empty()) {
        ph[2].p_type = PT_INTERP;
        ph[2].p_flags = PF_R;
        ph[2].p_offset = 0x2200;
        ph[2].p_vaddr = 0x2200;
        ph[2].p_filesz = interp.size() + 1;
        ph[2].p_memsz = interp.size() + 1;
        ph[2].p_align = 1;
        std::memcpy(elf.data() + 0x2200, interp.c_str(), interp.size() + 1);
    }
    return elf;
}

} // namespace

int main() {
    std::string dir = "/tmp/haseeb_m2_integ_" + std::to_string(::getpid());
    fs::remove_all(dir);
    fs::create_directories(dir);

    // 1. Create synthetic system.img and vendor.img raw ext4 partitions
    RawExt4PartitionWriter sys_w("system");
    std::string sys_prop_txt =
        "ro.product.model=AOSP_GENERIC\n"
        "ro.build.version.release=15\n"
        "ro.hardware.egl=swiftshader_blocked\n"
        "ro.system.build.id=AP3A.241105.007\n";
    uint32_t ino_sys_prop = sys_w.AddFile({sys_prop_txt.begin(), sys_prop_txt.end()});
    uint32_t ino_linker64 = sys_w.AddFile(BuildGuestBinary(77, ""));
    uint32_t ino_guest_app = sys_w.AddFile(BuildGuestBinary(99, "/system/bin/linker64"));
    uint32_t ino_bin = sys_w.next_inode++;
    uint32_t ino_sys = sys_w.next_inode++;
    sys_w.PopulateDir(ino_bin, {
        {ino_bin, 2, "."},
        {ino_sys, 2, ".."},
        {ino_linker64, 1, "linker64"},
        {ino_guest_app, 1, "guest_app"},
    });
    sys_w.PopulateDir(ino_sys, {
        {ino_sys, 2, "."},
        {2, 2, ".."},
        {ino_sys_prop, 1, "build.prop"},
        {ino_bin, 2, "bin"},
    });
    sys_w.PopulateDir(2, {
        {2, 2, "."},
        {2, 2, ".."},
        {ino_sys, 2, "system"},
    });
    std::string sys_img_path = dir + "/system.img";
    sys_w.Save(sys_img_path);

    RawExt4PartitionWriter ven_w("vendor");
    std::string ven_prop_txt = "ro.vendor.product.device=haseeb_gaming\n";
    uint32_t ino_ven_prop = ven_w.AddFile({ven_prop_txt.begin(), ven_prop_txt.end()});
    ven_w.PopulateDir(2, {
        {2, 2, "."},
        {2, 2, ".."},
        {ino_ven_prop, 1, "build.prop"},
    });
    std::string ven_img_path = dir + "/vendor.img";
    ven_w.Save(ven_img_path);

    // 2. Mount-free M2 open + M1 property initialization with locked overrides
    Ext4Reader sys_ext4, ven_ext4;
    HASEEB_CHECK(sys_ext4.Open(sys_img_path));
    HASEEB_CHECK(ven_ext4.Open(ven_img_path));

    GuestVfsResolver vfs;
    vfs.AttachSystemExt4(&sys_ext4, sys_ext4.Exists("/system/build.prop"));
    vfs.AttachVendorExt4(&ven_ext4);

    PropertyAreaManager prop_mgr;
    prop_mgr.SetOverride("ro.product.model", "SM-S938B");
    prop_mgr.SetOverride("ro.haseeb.engine", "native-v1");
    HASEEB_CHECK(prop_mgr.Initialize(dir, dir));

    std::vector<uint8_t> prop_bytes;
    HASEEB_CHECK(vfs.ReadGuestFile("/system/build.prop", prop_bytes));
    HASEEB_CHECK(prop_mgr.LoadPropText({prop_bytes.begin(), prop_bytes.end()}));
    prop_bytes.clear();
    HASEEB_CHECK(vfs.ReadGuestFile("/vendor/build.prop", prop_bytes));
    HASEEB_CHECK(prop_mgr.LoadPropText({prop_bytes.begin(), prop_bytes.end()}));

    std::string val;
    HASEEB_CHECK(prop_mgr.GetProperty("ro.product.model", val) && val == "SM-S938B");
    HASEEB_CHECK(prop_mgr.GetProperty("ro.system.build.id", val) && val == "AP3A.241105.007");
    HASEEB_CHECK(prop_mgr.GetProperty("ro.vendor.product.device", val) && val == "haseeb_gaming");
    HASEEB_CHECK(!prop_mgr.GetProperty("ro.hardware.egl", val));

    // 3. Load guest_app + PT_INTERP (/system/bin/linker64) directly from raw ext4 image
    Elf64Loader loader(16384);
    std::unique_ptr<LoadedElfImage> guest_exe, guest_linker;
    std::string err;
    HASEEB_CHECK(loader.LoadWithInterpreter("/system/bin/guest_app", vfs, 35, guest_exe, guest_linker, err));
    HASEEB_CHECK(guest_exe != nullptr && guest_linker != nullptr);
    HASEEB_CHECK((guest_exe->map_base % 16384u) == 0u);
    HASEEB_CHECK((guest_linker->map_base % 16384u) == 0u);

    // 4. Verify /proc/self/exe resolution and auxv handoff
    std::string self_path;
    HASEEB_CHECK(vfs.ReadLink("/proc/self/exe", self_path) && self_path == "/system/bin/guest_app");
    HASEEB_CHECK(vfs.SelfExeMemFd() >= 0);

    uint8_t rand16[16]{};
    auto auxv = GuestAuxvBuilder::BuildAuxv(
        *guest_exe, guest_linker.get(), reinterpret_cast<uintptr_t>(self_path.c_str()),
        reinterpret_cast<uintptr_t>(rand16), 16384);
    HASEEB_CHECK(auxv.size() >= 28);

    // 5. Execute entry points of both loaded images
    using EntryFn = int (*)();
    HASEEB_CHECK(reinterpret_cast<EntryFn>(guest_linker->entry_point)() == 77);
    HASEEB_CHECK(reinterpret_cast<EntryFn>(guest_exe->entry_point)() == 99);

    fs::remove_all(dir);
    std::cout << "[PASS] guest_loader_integration_test (M1+M2 mount-free ext4 + linker64 + ELF64)\n";
    return 0;
}
