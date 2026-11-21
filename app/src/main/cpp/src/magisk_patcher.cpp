#include "haseeb/magisk_patcher.hpp"

#include "haseeb/compression.hpp"
#include "haseeb/cpio_reader.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace haseeb::vm {

namespace {

uint64_t AlignUpU64(uint64_t v, uint64_t a) {
    return (a == 0ULL) ? v : ((v + a - 1ULL) & ~(a - 1ULL));
}

uint32_t ReadLe32(const uint8_t* p) {
    uint32_t v = 0u;
    std::memcpy(&v, p, 4u);
    return v;
}

void WriteLe32(std::vector<uint8_t>& buf, size_t off, uint32_t val) {
    if (off + 4u > buf.size()) return;
    std::memcpy(buf.data() + off, &val, 4u);
}

// Tiny AArch64 assembler for default /magiskinit & /sbin/su ELF64 guests
uint32_t Movz(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0xD2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Movn(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0x92800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Movk(uint8_t xd, uint16_t imm16, uint8_t hw) {
    return 0xF2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Adr(uint8_t xd, int32_t byte_offset) {
    uint32_t u21 = static_cast<uint32_t>(byte_offset) & 0x1FFFFFu;
    return 0x10000000u | ((u21 & 3u) << 29) | (((u21 >> 2) & 0x7FFFFu) << 5) | (xd & 31u);
}
uint32_t StrX(uint8_t xt, uint8_t xn, uint16_t imm_bytes) {
    return 0xF9000000u | (static_cast<uint32_t>((imm_bytes / 8u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xt & 31u);
}
uint32_t SubImm64(uint8_t xd, uint8_t xn, uint16_t imm12) {
    return 0xD1000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xd & 31u);
}
uint32_t CmpImm64(uint8_t xn, uint16_t imm12) {
    return 0xF100001Fu | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5);
}
uint32_t Svc(uint16_t imm = 0) {
    return 0xD4000001u | (static_cast<uint32_t>(imm) << 5);
}
uint32_t BCond(uint8_t cond, int32_t rel_insns) {
    return 0x54000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (cond & 0xFu);
}

struct ElfCodeBuilder {
    std::vector<uint32_t> insns;
    std::vector<uint8_t> data;
    struct Patch { size_t insn_idx; uint8_t rd; size_t data_off; };
    std::vector<Patch> patches;

    size_t AddString(const std::string& s) {
        size_t off = data.size();
        data.insert(data.end(), s.begin(), s.end());
        data.push_back('\0');
        return off;
    }
    void EmitAdr(uint8_t rd, size_t data_off) {
        size_t idx = insns.size();
        insns.push_back(0u);
        patches.push_back({idx, rd, data_off});
    }
    std::vector<uint8_t> BuildElf() {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : patches) {
            insns[p.insn_idx] = Adr(p.rd, static_cast<int32_t>(code_bytes + p.data_off) -
                                          static_cast<int32_t>(p.insn_idx * 4u));
        }
        constexpr uint64_t kBaseVa = 0x0000000000400000ULL;
        constexpr uint64_t kCodeOff = 0x100ULL;
        const uint64_t total = kCodeOff + code_bytes + data.size();
        std::vector<uint8_t> elf(total, 0u);
        elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
        elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
        auto w16 = [&](size_t o, uint16_t v) { elf[o] = v & 0xFFu; elf[o + 1] = v >> 8; };
        auto w32 = [&](size_t o, uint32_t v) { std::memcpy(elf.data() + o, &v, 4u); };
        auto w64 = [&](size_t o, uint64_t v) { std::memcpy(elf.data() + o, &v, 8u); };
        w16(16, 2u); w16(18, 183u); w32(20, 1u);
        w64(24, kBaseVa + kCodeOff); w64(32, 64ULL);
        w16(52, 64u); w16(54, 56u); w16(56, 1u);
        w32(64 + 0, 1u); w32(64 + 4, 7u);
        w64(64 + 8, 0ULL); w64(64 + 16, kBaseVa); w64(64 + 24, kBaseVa);
        w64(64 + 32, total); w64(64 + 40, total + 4096ULL); w64(64 + 48, 4096ULL);
        for (size_t i = 0; i < insns.size(); ++i) {
            w32(kCodeOff + i * 4u, insns[i]);
        }
        if (!data.empty()) {
            std::memcpy(elf.data() + kCodeOff + code_bytes, data.data(), data.size());
        }
        return elf;
    }
};

std::vector<uint8_t> RepackBootV2(const std::vector<uint8_t>& orig_bytes,
                                  const ParsedBootImage& parsed,
                                  const std::vector<uint8_t>& new_ramdisk) {
    const uint32_t pg = std::max<uint32_t>(2048u, parsed.page_size);
    const uint64_t hdr_pages = 1ULL;
    const uint64_t k_len = parsed.kernel.size();
    const uint64_t r_len = new_ramdisk.size();
    const uint32_t second_size = (orig_bytes.size() >= 64u) ? ReadLe32(orig_bytes.data() + 24u) : 0u;
    const uint32_t dtbo_size = (parsed.header_version >= 1u && orig_bytes.size() >= 1648u)
                                   ? ReadLe32(orig_bytes.data() + 1632u)
                                   : 0u;
    const uint64_t d_len = parsed.dtb.size();

    const uint64_t k_aligned = AlignUpU64(k_len, pg);
    const uint64_t r_aligned = AlignUpU64(r_len, pg);
    const uint64_t s_aligned = AlignUpU64(second_size, pg);
    const uint64_t o_aligned = AlignUpU64(dtbo_size, pg);
    const uint64_t d_aligned = AlignUpU64(d_len, pg);

    std::vector<uint8_t> out(hdr_pages * pg + k_aligned + r_aligned + s_aligned + o_aligned + d_aligned, 0u);
    const size_t copy_hdr = std::min<size_t>(pg, orig_bytes.size());
    std::memcpy(out.data(), orig_bytes.data(), copy_hdr);
    WriteLe32(out, 8u, static_cast<uint32_t>(k_len));
    WriteLe32(out, 16u, static_cast<uint32_t>(r_len));
    if (parsed.header_version >= 2u) {
        WriteLe32(out, 1648u, static_cast<uint32_t>(d_len));
    }

    uint64_t off = hdr_pages * pg;
    if (!parsed.kernel.empty()) {
        std::memcpy(out.data() + off, parsed.kernel.data(), k_len);
    }
    off += k_aligned;
    if (!new_ramdisk.empty()) {
        std::memcpy(out.data() + off, new_ramdisk.data(), r_len);
    }
    off += r_aligned;

    // Copy optional second & recovery_dtbo payloads if present in original image
    uint64_t orig_off = hdr_pages * pg + AlignUpU64(ReadLe32(orig_bytes.data() + 8u), pg) +
                        AlignUpU64(ReadLe32(orig_bytes.data() + 16u), pg);
    if (second_size > 0u && orig_off + second_size <= orig_bytes.size()) {
        std::memcpy(out.data() + off, orig_bytes.data() + orig_off, second_size);
    }
    off += s_aligned;
    orig_off += s_aligned;
    if (dtbo_size > 0u && orig_off + dtbo_size <= orig_bytes.size()) {
        std::memcpy(out.data() + off, orig_bytes.data() + orig_off, dtbo_size);
    }
    off += o_aligned;

    if (!parsed.dtb.empty()) {
        std::memcpy(out.data() + off, parsed.dtb.data(), d_len);
    }
    return out;
}

std::vector<uint8_t> RepackBootV3V4(const std::vector<uint8_t>& orig_bytes,
                                    const ParsedBootImage& parsed,
                                    const std::vector<uint8_t>& new_ramdisk) {
    constexpr uint32_t pg = 4096u;
    const uint64_t k_aligned = AlignUpU64(parsed.kernel.size(), pg);
    const uint64_t r_aligned = AlignUpU64(new_ramdisk.size(), pg);
    std::vector<uint8_t> out(pg + k_aligned + r_aligned, 0u);
    const size_t copy_hdr = std::min<size_t>(pg, orig_bytes.size());
    std::memcpy(out.data(), orig_bytes.data(), copy_hdr);
    WriteLe32(out, 8u, static_cast<uint32_t>(parsed.kernel.size()));
    WriteLe32(out, 12u, static_cast<uint32_t>(new_ramdisk.size()));
    if (!parsed.kernel.empty()) {
        std::memcpy(out.data() + pg, parsed.kernel.data(), parsed.kernel.size());
    }
    if (!new_ramdisk.empty()) {
        std::memcpy(out.data() + pg + k_aligned, new_ramdisk.data(), new_ramdisk.size());
    }
    return out;
}

} // namespace

std::vector<uint8_t> BootImagePatcher::BuildDefaultMagiskInitElf() {
    ElfCodeBuilder cb;
    const std::string banner = "[MAGISK] magiskinit v27.0 initialized (SELinux=permissive)\n";
    const size_t banner_off = cb.AddString(banner);
    const size_t dev_su_off = cb.AddString("/dev/magisk_su");
    const size_t backup_init_off = cb.AddString("/.backup/init");
    const size_t sys_init_off = cb.AddString("/system/bin/init");
    const size_t sys_sh_off = cb.AddString("/system/bin/sh");

    cb.insns.push_back(SubImm64(31, 31, 64u));

    // write(1, banner, len)
    cb.insns.push_back(Movz(0, 1u, 0));
    cb.EmitAdr(1, banner_off);
    cb.insns.push_back(Movz(2, static_cast<uint16_t>(banner.size()), 0));
    cb.insns.push_back(Movz(8, 64u, 0)); // __NR_write
    cb.insns.push_back(Svc(0));

    // fd = openat(-100, "/dev/magisk_su", O_RDWR=2, 0)
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdr(1, dev_su_off);
    cb.insns.push_back(Movz(2, 2u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0)); // __NR_openat
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    cb.insns.push_back(BCond(11u /*LT*/, 6)); // skip ioctl if < 3

    // ioctl(fd, 0x4D4701 /*HASEEB_SU_REQUEST*/, 0)
    cb.insns.push_back(Movz(1, 0x4701u, 0));
    cb.insns.push_back(Movk(1, 0x004Du, 1));
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(8, 29u, 0)); // __NR_ioctl
    cb.insns.push_back(Svc(0));

    // Chain execve: /.backup/init -> /system/bin/init -> /system/bin/sh
    for (size_t path_off : {backup_init_off, sys_init_off, sys_sh_off}) {
        cb.EmitAdr(0, path_off);
        cb.insns.push_back(StrX(0, 31, 0u));
        cb.insns.push_back(StrX(31, 31, 8u)); // overwrite slot+8 before fixup:
        cb.insns.back() = 0xF90007FFu;        // STR XZR, [SP, #8]
        cb.insns.push_back(0x910003E1u);      // MOV X1, SP
        cb.insns.push_back(Movz(2, 0u, 0));
        cb.insns.push_back(Movz(8, 221u, 0)); // __NR_execve
        cb.insns.push_back(Svc(0));
    }

    // Fallback clean exit_group(0)
    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movz(8, 94u, 0));
    cb.insns.push_back(Svc(0));
    return cb.BuildElf();
}

std::vector<uint8_t> BootImagePatcher::BuildDefaultSuElf() {
    ElfCodeBuilder cb;
    const std::string granted_msg = "[MAGISK] su v27.0: superuser uid=0(root) granted\n";
    const size_t msg_off = cb.AddString(granted_msg);
    const size_t dev_su_off = cb.AddString("/dev/magisk_su");

    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdr(1, dev_su_off);
    cb.insns.push_back(Movz(2, 2u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    cb.insns.push_back(BCond(11u /*LT*/, 6));
    cb.insns.push_back(Movz(1, 0x4701u, 0));
    cb.insns.push_back(Movk(1, 0x004Du, 1));
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(Movz(0, 1u, 0));
    cb.EmitAdr(1, msg_off);
    cb.insns.push_back(Movz(2, static_cast<uint16_t>(granted_msg.size()), 0));
    cb.insns.push_back(Movz(8, 64u, 0));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movz(8, 94u, 0));
    cb.insns.push_back(Svc(0));
    return cb.BuildElf();
}

MagiskPatchResult BootImagePatcher::PatchBootBytes(const std::vector<uint8_t>& stock_boot_bytes,
                                                   const MagiskPatchOptions& opts) {
    MagiskPatchResult res;
    ParsedBootImage parsed;
    std::string err;
    VmError parse_err = BootImageParser::ParseBootBytes(stock_boot_bytes, parsed, err);
    if (parse_err != VmError::Ok) {
        res.error_code = parse_err;
        res.error = "Unpack failed: " + err;
        return res;
    }
    res.source_header_version = parsed.header_version;

    // Decompress stock ramdisk CPIO (gzip/lz4/raw); empty ramdisk starts fresh CPIO tree
    std::vector<CpioEntry> entries;
    if (!parsed.ramdisk.empty()) {
        std::vector<uint8_t> raw_cpio;
        VmError rd_err = BootImageParser::DecompressRamdisk(parsed.ramdisk, raw_cpio, err);
        if (rd_err != VmError::Ok) {
            res.error_code = rd_err;
            res.error = "Ramdisk decompression failed: " + err;
            return res;
        }
        if (!raw_cpio.empty() && !CpioArchive::Parse(raw_cpio, entries, err)) {
            res.error_code = VmError::InvalidBootImage;
            res.error = "Stock ramdisk is not a valid SVR4 newc CPIO: " + err;
            return res;
        }
    }
    res.original_ramdisk_entries = static_cast<uint32_t>(entries.size());

    auto upsert_entry = [&](const CpioEntry& entry) {
        for (auto& existing : entries) {
            if (existing.name == entry.name) {
                existing = entry;
                return;
            }
        }
        entries.push_back(entry);
    };

    auto ensure_dir = [&](const std::string& dir_name) {
        if (CpioArchive::FindEntry(entries, dir_name) == nullptr) {
            CpioEntry d;
            d.name = dir_name;
            d.mode = 0040755u;
            d.nlink = 2u;
            entries.push_back(std::move(d));
        }
    };

    // Preserve stock /init in .backup/init if present and not already magiskinit
    if (const CpioEntry* orig_init = CpioArchive::FindEntry(entries, "init")) {
        if (CpioArchive::FindEntry(entries, ".backup/init") == nullptr &&
            orig_init->IsRegular() && !orig_init->data.empty()) {
            ensure_dir(".backup");
            CpioEntry backup_init = *orig_init;
            backup_init.name = ".backup/init";
            upsert_entry(backup_init);
        }
    }

    const std::vector<uint8_t> magiskinit_bin =
        opts.custom_magiskinit.empty() ? BuildDefaultMagiskInitElf() : opts.custom_magiskinit;
    const std::vector<uint8_t> su_bin =
        opts.custom_su.empty() ? BuildDefaultSuElf() : opts.custom_su;

    ensure_dir(".backup");
    ensure_dir("overlay.d");
    ensure_dir("overlay.d/sbin");
    ensure_dir("sbin");

    // /magiskinit
    CpioEntry e_magiskinit;
    e_magiskinit.name = "magiskinit";
    e_magiskinit.mode = 0100755u;
    e_magiskinit.data = magiskinit_bin;
    upsert_entry(e_magiskinit);

    // Ensure /init points to /magiskinit when absent or replacing stock init
    CpioEntry e_init;
    e_init.name = "init";
    e_init.mode = 0100755u;
    e_init.data = magiskinit_bin;
    upsert_entry(e_init);

    // /sbin/su
    CpioEntry e_su;
    e_su.name = "sbin/su";
    e_su.mode = 0100755u;
    e_su.data = su_bin;
    upsert_entry(e_su);

    // .backup/.magisk configuration file matching Magisk v27 format
    std::ostringstream cfg;
    cfg << "KEEPVERITY=" << (opts.keep_verity ? "true" : "false") << "\n"
        << "KEEPFORCEENCRYPT=" << (opts.keep_force_encrypt ? "true" : "false") << "\n"
        << "RECOVERYMODE=" << (opts.recovery_mode ? "true" : "false") << "\n"
        << "PREINITDEVICE=" << opts.preinit_device << "\n"
        << "MAGISK_VER=" << opts.magisk_version << "\n"
        << "MAGISK_VER_CODE=" << opts.magisk_version_code << "\n"
        << "VALIDATED_RELEASE=" << MagiskPatchOptions::kValidatedRelease << "\n";
    const std::string cfg_str = cfg.str();
    CpioEntry e_cfg;
    e_cfg.name = ".backup/.magisk";
    e_cfg.mode = 0100644u;
    e_cfg.data.assign(cfg_str.begin(), cfg_str.end());
    upsert_entry(e_cfg);

    // overlay.d/init.magisk.rc
    std::ostringstream rc;
    rc << "on early-init\n"
       << "    setprop ro.magisk.version " << opts.magisk_version << "\n"
       << "    setprop ro.boot.verifiedbootstate orange\n"
       << "service magiskd /sbin/su --daemon\n"
       << "    class core\n"
       << "    user root\n";
    if (!opts.extra_overlay_rc.empty()) {
        rc << opts.extra_overlay_rc << "\n";
    }
    const std::string rc_str = rc.str();
    CpioEntry e_rc;
    e_rc.name = "overlay.d/init.magisk.rc";
    e_rc.mode = 0100644u;
    e_rc.data.assign(rc_str.begin(), rc_str.end());
    upsert_entry(e_rc);

    const std::vector<uint8_t> new_cpio = CpioArchive::Build(entries);
    const std::vector<uint8_t> compressed_rd =
        CompressionCodec::CompressGzip(new_cpio.data(), new_cpio.size());

    if (parsed.header_version <= 2u) {
        res.patched_image = RepackBootV2(stock_boot_bytes, parsed, compressed_rd);
    } else {
        res.patched_image = RepackBootV3V4(stock_boot_bytes, parsed, compressed_rd);
    }

    // Immediate self-verification via BootImageParser + Magisk scan
    ParsedBootImage verified_img;
    VmError v_err = BootImageParser::ParseBootBytes(res.patched_image, verified_img, err);
    if (v_err != VmError::Ok || !verified_img.magisk_detected) {
        res.error_code = (v_err != VmError::Ok) ? v_err : VmError::InvalidBootImage;
        res.error = "Patched boot verification failed: " +
                    (err.empty() ? "Magisk signature not detected" : err);
        return res;
    }

    res.ok = true;
    res.verified = true;
    res.patched_header_version = verified_img.header_version;
    res.patched_ramdisk_entries = static_cast<uint32_t>(entries.size());
    std::ostringstream sum;
    sum << "Patched boot v" << verified_img.header_version
        << " (" << res.patched_ramdisk_entries << " CPIO entries, "
        << res.patched_image.size() << " B) | " << verified_img.magisk_evidence
        << " | Validated: " << MagiskPatchOptions::kValidatedRelease;
    res.verification_summary = sum.str();
    return res;
}

MagiskPatchResult BootImagePatcher::PatchBootFile(const std::string& input_boot_path,
                                                  const std::string& output_boot_path,
                                                  const MagiskPatchOptions& opts) {
    MagiskPatchResult res;
    std::ifstream ifs(input_boot_path, std::ios::binary | std::ios::ate);
    if (!ifs.good()) {
        res.error_code = VmError::FileNotFound;
        res.error = "Unable to open stock boot image: " + input_boot_path;
        return res;
    }
    const std::streamsize sz = ifs.tellg();
    if (sz <= 0) {
        res.error_code = VmError::InvalidBootImage;
        res.error = "Empty boot image: " + input_boot_path;
        return res;
    }
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> raw(static_cast<size_t>(sz));
    if (!ifs.read(reinterpret_cast<char*>(raw.data()), sz)) {
        res.error_code = VmError::IoFailure;
        res.error = "Failed reading stock boot image bytes";
        return res;
    }

    res = PatchBootBytes(raw, opts);
    if (!res.ok) return res;

    std::ofstream ofs(output_boot_path, std::ios::binary | std::ios::trunc);
    if (!ofs.good()) {
        res.ok = false;
        res.verified = false;
        res.error_code = VmError::IoFailure;
        res.error = "Failed opening output boot image path: " + output_boot_path;
        return res;
    }
    ofs.write(reinterpret_cast<const char*>(res.patched_image.data()),
              static_cast<std::streamsize>(res.patched_image.size()));
    if (!ofs.good()) {
        res.ok = false;
        res.verified = false;
        res.error_code = VmError::IoFailure;
        res.error = "Failed writing patched boot image bytes";
        return res;
    }
    return res;
}

} // namespace haseeb::vm
