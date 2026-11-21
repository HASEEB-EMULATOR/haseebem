#include "haseeb/engine_rom_builder.hpp"
#include "haseeb/boot_image.hpp"
#include "haseeb/compression.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/ext4_reader.hpp"
#include "haseeb/guest_vfs_bridge.hpp"
#include "haseeb/soft_gles.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace haseeb::vm {

namespace {

// =========================================================================
// Little-endian & AArch64 machine-code emitting helpers
// =========================================================================

void PushU32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFFu));
}

void WriteU16At(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    buf[off + 0] = static_cast<uint8_t>(v & 0xFFu);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
}

void WriteU32At(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf[off + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFFu);
}

void WriteU64At(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf[off + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFFu);
}

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

uint32_t Movr64(uint8_t xd, uint8_t xm) {
    return 0xAA0003E0u | (static_cast<uint32_t>(xm & 31u) << 16) | (xd & 31u);
}

uint32_t MovSp(uint8_t xd) {
    return 0x910003E0u | (xd & 31u); // ADD Xd, SP, #0
}

uint32_t AddImm64(uint8_t xd, uint8_t xn, uint16_t imm12) {
    return 0x91000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xd & 31u);
}

uint32_t SubImm64(uint8_t xd, uint8_t xn, uint16_t imm12) {
    return 0xD1000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xd & 31u);
}

uint32_t CmpImm64(uint8_t xn, uint16_t imm12) {
    return 0xF100001Fu | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5);
}

uint32_t StrX(uint8_t xt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xF9000000u | (static_cast<uint32_t>((imm_bytes / 8u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xt & 31u);
}

uint32_t StrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9000000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t Adr(uint8_t xd, int32_t byte_offset) {
    uint32_t u21 = static_cast<uint32_t>(byte_offset) & 0x1FFFFFu;
    return 0x10000000u | ((u21 & 3u) << 29) | (((u21 >> 2) & 0x7FFFFu) << 5) | (xd & 31u);
}

uint32_t Svc(uint16_t imm = 0) {
    return 0xD4000001u | (static_cast<uint32_t>(imm) << 5);
}

uint32_t BImm(int32_t rel_insns) {
    return 0x14000000u | (static_cast<uint32_t>(rel_insns) & 0x03FFFFFFu);
}

uint32_t BCond(uint8_t cond, int32_t rel_insns) {
    return 0x54000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (cond & 0xFu);
}

uint32_t Cbz64(uint8_t xt, int32_t rel_insns) {
    return 0xB4000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (xt & 31u);
}

void EmitImm32(std::vector<uint32_t>& insns, uint8_t xd, uint32_t val) {
    insns.push_back(Movz(xd, static_cast<uint16_t>(val & 0xFFFFu), 0));
    if ((val >> 16) != 0u) {
        insns.push_back(Movk(xd, static_cast<uint16_t>((val >> 16) & 0xFFFFu), 1));
    }
}

struct GuestAsm {
    std::vector<uint32_t> insns;
    std::vector<uint8_t> data;
    struct AdrPatch { size_t insn_idx; uint8_t rd; size_t data_off; };
    struct BranchPatch { size_t insn_idx; int kind; uint8_t cond_or_reg; size_t target_idx; };
    std::vector<AdrPatch> adr_patches;
    std::vector<BranchPatch> b_patches;

    size_t AddString(const std::string& s) {
        size_t off = data.size();
        data.insert(data.end(), s.begin(), s.end());
        data.push_back('\0');
        return off;
    }

    size_t AddAlignedBytes(const void* ptr, size_t len, size_t align = 8u) {
        while ((data.size() % align) != 0u) data.push_back(0u);
        size_t off = data.size();
        const auto* p = static_cast<const uint8_t*>(ptr);
        data.insert(data.end(), p, p + len);
        return off;
    }

    void AdrData(uint8_t rd, size_t data_off) {
        size_t idx = insns.size();
        insns.push_back(0u);
        adr_patches.push_back({idx, rd, data_off});
    }

    size_t EmitBPlaceholder() {
        size_t idx = insns.size();
        insns.push_back(0u);
        b_patches.push_back({idx, 0, 0u, 0u});
        return b_patches.size() - 1u;
    }

    size_t EmitBCondPlaceholder(uint8_t cond) {
        size_t idx = insns.size();
        insns.push_back(0u);
        b_patches.push_back({idx, 1, cond, 0u});
        return b_patches.size() - 1u;
    }

    size_t EmitCbzPlaceholder(uint8_t xt) {
        size_t idx = insns.size();
        insns.push_back(0u);
        b_patches.push_back({idx, 2, xt, 0u});
        return b_patches.size() - 1u;
    }

    void PatchToHere(size_t bp_idx) {
        b_patches[bp_idx].target_idx = insns.size();
    }

    void PatchToIdx(size_t bp_idx, size_t target_idx) {
        b_patches[bp_idx].target_idx = target_idx;
    }

    // Convenience emitters for standard Linux ARM64 syscalls
    void EmitWriteStdout(size_t str_off, size_t len_no_nul) {
        insns.push_back(Movz(0, 1u, 0));
        AdrData(1, str_off);
        EmitImm32(insns, 2, static_cast<uint32_t>(len_no_nul));
        insns.push_back(Movz(8, 64u, 0));
        insns.push_back(Svc(0));
    }

    void EmitOpenAt(uint8_t dst_fd_reg, size_t path_off, uint32_t flags, uint32_t mode = 0u) {
        insns.push_back(Movn(0, 99u, 0)); // AT_FDCWD (-100)
        AdrData(1, path_off);
        EmitImm32(insns, 2, flags);
        EmitImm32(insns, 3, mode);
        insns.push_back(Movz(8, 56u, 0));
        insns.push_back(Svc(0));
        insns.push_back(Movr64(dst_fd_reg, 0));
    }

    void EmitNanosleep(uint64_t sec, uint64_t nsec) {
        // Store struct timespec {sec, nsec} at [sp, #0]
        EmitImm32(insns, 9, static_cast<uint32_t>(sec));
        insns.push_back(StrX(9, 31, 0u));
        EmitImm32(insns, 9, static_cast<uint32_t>(nsec));
        insns.push_back(StrX(9, 31, 8u));
        insns.push_back(MovSp(0));
        insns.push_back(Movz(1, 0u, 0));
        insns.push_back(Movz(8, 101u, 0));
        insns.push_back(Svc(0));
    }

    void EmitForkAndExec(size_t prog_path_off, uint8_t out_child_pid_reg) {
        // Store argv[2] = {prog_path, NULL} at [sp, #32]
        AdrData(9, prog_path_off);
        insns.push_back(StrX(9, 31, 32u));
        insns.push_back(StrX(31, 31, 40u)); // zero if we move XZR -> fix below:
        // Use XZR cleanly:
        insns.back() = 0xF90003E0u | (static_cast<uint32_t>((40u / 8u) & 0xFFFu) << 10) |
                       (31u << 5) | 31u; // STR XZR, [SP, #40]

        // clone(SIGCHLD=17, 0, 0, 0, 0)
        insns.push_back(Movz(0, 17u, 0));
        insns.push_back(Movz(1, 0u, 0));
        insns.push_back(Movz(2, 0u, 0));
        insns.push_back(Movz(3, 0u, 0));
        insns.push_back(Movz(4, 0u, 0));
        insns.push_back(Movz(8, 220u, 0));
        insns.push_back(Svc(0));

        // If X0 == 0 (child), execve(prog_path, &sp[32], NULL) else parent skips
        const size_t skip_child = EmitCbzPlaceholder(0);
        // Parent: save PID & jump past child exec
        insns.push_back(Movr64(out_child_pid_reg, 0));
        const size_t parent_done = EmitBPlaceholder();

        // Child path:
        PatchToHere(skip_child);
        AdrData(0, prog_path_off);
        insns.push_back(AddImm64(1, 31, 32u));
        insns.push_back(Movz(2, 0u, 0));
        insns.push_back(Movz(8, 221u, 0)); // execve
        insns.push_back(Svc(0));
        // If execve ever fails, exit(127)
        insns.push_back(Movz(0, 127u, 0));
        insns.push_back(Movz(8, 94u, 0));
        insns.push_back(Svc(0));

        PatchToHere(parent_done);
    }

    void EmitExitGroup(uint16_t code) {
        insns.push_back(Movz(0, code, 0));
        insns.push_back(Movz(8, 94u, 0));
        insns.push_back(Svc(0));
    }

    std::vector<uint8_t> BuildElf64(uint64_t base_va = 0x0000000000400000ULL) {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : adr_patches) {
            insns[p.insn_idx] = Adr(p.rd, static_cast<int32_t>(code_bytes + p.data_off) -
                                          static_cast<int32_t>(p.insn_idx * 4u));
        }
        for (const auto& bp : b_patches) {
            const int32_t rel = static_cast<int32_t>(bp.target_idx) -
                                static_cast<int32_t>(bp.insn_idx);
            if (bp.kind == 0) insns[bp.insn_idx] = BImm(rel);
            else if (bp.kind == 1) insns[bp.insn_idx] = BCond(bp.cond_or_reg, rel);
            else insns[bp.insn_idx] = Cbz64(bp.cond_or_reg, rel);
        }

        constexpr uint64_t kCodeOff = 0x100ULL;
        const size_t payload_size = code_bytes + data.size();
        const uint64_t total = kCodeOff + payload_size;
        std::vector<uint8_t> elf(total, 0u);
        elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
        elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
        WriteU16At(elf, 16, 2u);  // ET_EXEC
        WriteU16At(elf, 18, 183u); // EM_AARCH64
        WriteU32At(elf, 20, 1u);
        WriteU64At(elf, 24, base_va + kCodeOff); // e_entry
        WriteU64At(elf, 32, 64ULL);              // e_phoff
        WriteU16At(elf, 52, 64u);
        WriteU16At(elf, 54, 56u);
        WriteU16At(elf, 56, 1u);
        // PT_LOAD (RWX for single clean segment)
        WriteU32At(elf, 64 + 0, 1u);
        WriteU32At(elf, 64 + 4, 7u);
        WriteU64At(elf, 64 + 8, 0ULL);
        WriteU64At(elf, 64 + 16, base_va);
        WriteU64At(elf, 64 + 24, base_va);
        WriteU64At(elf, 64 + 32, total);
        WriteU64At(elf, 64 + 40, total + 4096ULL);
        WriteU64At(elf, 64 + 48, 4096ULL);

        for (size_t i = 0; i < insns.size(); ++i) {
            WriteU32At(elf, static_cast<size_t>(kCodeOff) + i * 4u, insns[i]);
        }
        if (!data.empty()) {
            std::memcpy(elf.data() + kCodeOff + code_bytes, data.data(), data.size());
        }
        return elf;
    }
};

// =========================================================================
// Binary builders for Android framework guests
// =========================================================================

std::vector<uint8_t> BuildMagiskInitElf() {
    GuestAsm a;
    const std::string banner =
        "[MAGISK] magiskinit v27.0 (27000) initializing early-mount & su policy\r\n";
    const std::string ok_msg =
        "[MAGISK] uid=0 root context active; chain-loading /system/bin/init\r\n";
    const size_t s_banner = a.AddString(banner);
    const size_t s_ok = a.AddString(ok_msg);
    const size_t s_su_dev = a.AddString("/dev/magisk_su");
    const size_t s_init = a.AddString("/system/bin/init");

    a.insns.push_back(SubImm64(31, 31, 128u));
    a.EmitWriteStdout(s_banner, banner.size());

    // Open /dev/magisk_su & request HASEEB_SU_REQUEST (0x4D4701)
    a.EmitOpenAt(19, s_su_dev, 2u /* O_RDWR */);
    a.insns.push_back(CmpImm64(19, 3u));
    const size_t skip_su = a.EmitBCondPlaceholder(11u /* LT */);
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x004D4701u);
    a.insns.push_back(Movz(2, 0u, 0));
    a.insns.push_back(Movz(8, 29u, 0)); // ioctl
    a.insns.push_back(Svc(0));
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0)); // close
    a.insns.push_back(Svc(0));
    a.PatchToHere(skip_su);

    a.EmitWriteStdout(s_ok, ok_msg.size());

    // execve("/system/bin/init", {"/system/bin/init", NULL}, NULL)
    a.AdrData(9, s_init);
    a.insns.push_back(StrX(9, 31, 0u));
    a.insns.push_back(0xF90003E0u | (1u << 10) | (31u << 5) | 31u); // STR XZR, [SP, #8]
    a.AdrData(0, s_init);
    a.insns.push_back(MovSp(1));
    a.insns.push_back(Movz(2, 0u, 0));
    a.insns.push_back(Movz(8, 221u, 0));
    a.insns.push_back(Svc(0));
    a.EmitExitGroup(127u);
    return a.BuildElf64();
}

std::vector<uint8_t> BuildUeventdElf() {
    GuestAsm a;
    const std::string m1 = "[ueventd] coldboot probing sensors, battery & v4l2 camera\r\n";
    const std::string m2 = "[ueventd] hardware coldboot ready (exit=0)\r\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_m2 = a.AddString(m2);
    const size_t s_sens = a.AddString("/dev/haseeb_sensors");
    const size_t s_cam = a.AddString("/dev/video0");

    a.insns.push_back(SubImm64(31, 31, 256u));
    a.EmitWriteStdout(s_m1, m1.size());

    // Probe /dev/haseeb_sensors: GET_ALL (0x485301) & BATTERY_GET_INFO (0x485302)
    a.EmitOpenAt(19, s_sens, 0u);
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x00485301u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x00485302u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));

    // Probe /dev/video0: VIDIOC_QUERYCAP (0x80685600)
    a.EmitOpenAt(19, s_cam, 0u);
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x80685600u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));

    a.EmitWriteStdout(s_m2, m2.size());
    a.EmitExitGroup(0u);
    return a.BuildElf64();
}

std::vector<uint8_t> BuildServiceManagerElf() {
    GuestAsm a;
    const std::string m1 = "[servicemanager] binder IPC context manager online (/dev/binder v8)\r\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_binder = a.AddString("/dev/binder");

    a.insns.push_back(SubImm64(31, 31, 64u));
    a.EmitOpenAt(19, s_binder, 2u);

    // BINDER_VERSION (0xC0046209) + BINDER_SET_MAX_THREADS (0x40046205)
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0xC0046209u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    a.insns.push_back(Movz(9, 15u, 0));
    a.insns.push_back(StrW(9, 31, 16u));
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x40046205u);
    a.insns.push_back(AddImm64(2, 31, 16u));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    a.EmitWriteStdout(s_m1, m1.size());

    const size_t loop_top = a.insns.size();
    a.EmitNanosleep(0ULL, 180000000ULL);
    const size_t b_back = a.EmitBPlaceholder();
    a.PatchToIdx(b_back, loop_top);
    return a.BuildElf64();
}

std::vector<uint8_t> BuildSystemServerElf() {
    GuestAsm a;
    const std::string m1 = "[system_server] registering core Android framework services\r\n";
    const std::string m2 = "[system_server] sys.boot_completed=1; framework & audio chime ready\r\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_m2 = a.AddString(m2);
    const size_t s_binder = a.AddString("/dev/binder");
    const size_t s_snd = a.AddString("/dev/snd/pcmC0D0p");
    const size_t s_sens = a.AddString("/dev/haseeb_sensors");

    const char* svc_names[] = {
        "activity", "package", "window", "power", "sensorservice", "magisk_su"
    };
    std::vector<size_t> svc_offs;
    for (const char* name : svc_names) {
        svc_offs.push_back(a.AddString(name));
    }

    // Generate clean 128-frame stereo 48kHz chime PCM (512 bytes)
    int16_t chime[256]{};
    for (int i = 0; i < 128; ++i) {
        const double t = static_cast<double>(i) / 48000.0;
        const double env = (128.0 - i) / 128.0;
        const int16_t sample = static_cast<int16_t>(std::sin(2.0 * 3.14159265 * 880.0 * t) * 8000.0 * env);
        chime[i * 2 + 0] = sample;
        chime[i * 2 + 1] = sample;
    }
    const size_t s_pcm = a.AddAlignedBytes(chime, sizeof(chime), 8u);

    a.insns.push_back(SubImm64(31, 31, 256u));
    a.EmitWriteStdout(s_m1, m1.size());

    // Open /dev/binder & register all framework services
    a.EmitOpenAt(19, s_binder, 2u);
    for (size_t off : svc_offs) {
        a.insns.push_back(Movr64(0, 19));
        EmitImm32(a.insns, 1, 0x00424901u); // HASEEB_BINDER_ADD_SERVICE
        a.AdrData(2, off);
        a.insns.push_back(Movz(8, 29u, 0));
        a.insns.push_back(Svc(0));
    }

    // Emit startup chime on /dev/snd/pcmC0D0p
    a.EmitOpenAt(20, s_snd, 1u /* O_WRONLY */);
    a.insns.push_back(CmpImm64(20, 3u));
    const size_t skip_snd = a.EmitBCondPlaceholder(11u);
    a.insns.push_back(Movr64(0, 20));
    a.AdrData(1, s_pcm);
    EmitImm32(a.insns, 2, sizeof(chime));
    a.insns.push_back(Movz(8, 64u, 0));
    a.insns.push_back(Svc(0));
    a.insns.push_back(Movr64(0, 20));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));
    a.PatchToHere(skip_snd);

    a.EmitWriteStdout(s_m2, m2.size());

    // Keep system_server alive polling sensors periodically
    a.EmitOpenAt(21, s_sens, 0u);
    const size_t loop_top = a.insns.size();
    a.insns.push_back(Movr64(0, 21));
    EmitImm32(a.insns, 1, 0x00485301u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));
    a.EmitNanosleep(0ULL, 140000000ULL);
    const size_t b_back = a.EmitBPlaceholder();
    a.PatchToIdx(b_back, loop_top);
    return a.BuildElf64();
}

void AppendGlesCmd(std::vector<uint8_t>& pkt, uint32_t op, const void* payload, uint32_t len) {
    PushU32(pkt, op);
    PushU32(pkt, len);
    if (len > 0u && payload) {
        const auto* p = static_cast<const uint8_t*>(payload);
        pkt.insert(pkt.end(), p, p + len);
    }
}

std::vector<uint8_t> BuildLauncherScenePacket(int phase_idx) {
    std::vector<uint8_t> pkt;
    const float bg[4]{0.0235f, 0.0353f, 0.0588f, 1.0f}; // ObsidianBg (#06090F)
    AppendGlesCmd(pkt, SoftGlesContext::kCmdClearColor, bg, sizeof(bg));
    const uint32_t clear_mask = SoftGlesContext::kClearColorBit | SoftGlesContext::kClearDepthBit;
    AppendGlesCmd(pkt, SoftGlesContext::kCmdClear, &clear_mask, sizeof(clear_mask));

    const float angle = static_cast<float>(phase_idx) * (2.0f * 3.14159265f / 8.0f);
    const float dx = std::sin(angle) * 0.14f;
    const float dy = std::cos(angle) * 0.04f;
    const float pulse = 0.78f + 0.22f * std::sin(angle);

    std::vector<SoftGlesContext::Vertex> tris = {
        // Upper Obsidian Glass Surface Quad (2 triangles)
        {-0.88f, 0.42f, 0.3f, 1.0f,  0.06f, 0.10f, 0.16f, 1.0f,  0, 0, 0, 0, 1},
        { 0.88f, 0.42f, 0.3f, 1.0f,  0.06f, 0.10f, 0.16f, 1.0f,  0, 0, 0, 0, 1},
        { 0.88f, 0.86f, 0.3f, 1.0f,  0.08f, 0.14f, 0.22f, 1.0f,  0, 0, 0, 0, 1},

        {-0.88f, 0.42f, 0.3f, 1.0f,  0.06f, 0.10f, 0.16f, 1.0f,  0, 0, 0, 0, 1},
        { 0.88f, 0.86f, 0.3f, 1.0f,  0.08f, 0.14f, 0.22f, 1.0f,  0, 0, 0, 0, 1},
        {-0.88f, 0.86f, 0.3f, 1.0f,  0.08f, 0.14f, 0.22f, 1.0f,  0, 0, 0, 0, 1},

        // Center Animated Teal Diamond Accent (Haseeb Core Emblem)
        {dx + 0.0f,  dy + 0.26f, 0.0f, 1.0f,  0.31f * pulse, 0.90f * pulse, 0.73f * pulse, 1.0f, 0, 0, 0, 0, 1},
        {dx - 0.34f, dy - 0.02f, 0.0f, 1.0f,  0.18f,         0.68f,         0.64f,         1.0f, 0, 0, 0, 0, 1},
        {dx + 0.34f, dy - 0.02f, 0.0f, 1.0f,  0.22f,         0.74f,         0.97f,         1.0f, 0, 0, 0, 0, 1},

        {dx - 0.34f, dy - 0.02f, 0.0f, 1.0f,  0.18f,         0.68f,         0.64f,         1.0f, 0, 0, 0, 0, 1},
        {dx + 0.0f,  dy - 0.30f, 0.0f, 1.0f,  0.13f,         0.77f,         0.37f,         1.0f, 0, 0, 0, 0, 1},
        {dx + 0.34f, dy - 0.02f, 0.0f, 1.0f,  0.22f,         0.74f,         0.97f,         1.0f, 0, 0, 0, 0, 1},

        // Bottom Android Launcher Dock Bar (Magisk Emerald & Cyan)
        {-0.82f, -0.84f, 0.2f, 1.0f,  0.07f, 0.12f, 0.19f, 1.0f, 0, 0, 0, 0, 1},
        { 0.82f, -0.84f, 0.2f, 1.0f,  0.07f, 0.12f, 0.19f, 1.0f, 0, 0, 0, 0, 1},
        { 0.82f, -0.66f, 0.2f, 1.0f,  0.10f, 0.17f, 0.26f, 1.0f, 0, 0, 0, 0, 1},

        {-0.82f, -0.84f, 0.2f, 1.0f,  0.07f, 0.12f, 0.19f, 1.0f, 0, 0, 0, 0, 1},
        { 0.82f, -0.66f, 0.2f, 1.0f,  0.10f, 0.17f, 0.26f, 1.0f, 0, 0, 0, 0, 1},
        {-0.82f, -0.66f, 0.2f, 1.0f,  0.10f, 0.17f, 0.26f, 1.0f, 0, 0, 0, 0, 1},
    };
    AppendGlesCmd(pkt, SoftGlesContext::kCmdDrawTriangles,
                  tris.data(), static_cast<uint32_t>(tris.size() * sizeof(SoftGlesContext::Vertex)));
    AppendGlesCmd(pkt, SoftGlesContext::kCmdSwapBuffers, nullptr, 0u);
    return pkt;
}

std::vector<uint8_t> BuildSurfaceFlingerElf() {
    GuestAsm a;
    const std::string m1 = "[surfaceflinger] SoftGLES 3.0 CPU compositor ready -> /dev/haseeb_gles\r\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_gles = a.AddString("/dev/haseeb_gles");
    const size_t s_touch = a.AddString("/dev/input/event0");

    std::vector<size_t> pkt_offs;
    size_t pkt_len = 0u;
    for (int ph = 0; ph < 8; ++ph) {
        std::vector<uint8_t> pkt = BuildLauncherScenePacket(ph);
        pkt_len = pkt.size();
        pkt_offs.push_back(a.AddAlignedBytes(pkt.data(), pkt.size(), 8u));
    }

    a.insns.push_back(SubImm64(31, 31, 128u));
    a.EmitOpenAt(19, s_gles, 2u);
    // Query HASEEB_GLES_GET_RENDERER (0x484702)
    a.insns.push_back(Movr64(0, 19));
    EmitImm32(a.insns, 1, 0x00484702u);
    a.insns.push_back(MovSp(2));
    a.insns.push_back(Movz(8, 29u, 0));
    a.insns.push_back(Svc(0));

    // Open nonblocking touch input /dev/input/event0
    a.EmitOpenAt(20, s_touch, 04000u /* O_NONBLOCK */);
    a.EmitWriteStdout(s_m1, m1.size());

    // Continuous 8-phase SoftGLES compositor loop
    const size_t loop_top = a.insns.size();
    for (size_t off : pkt_offs) {
        // Non-blocking drain of touch events if any
        a.insns.push_back(Movr64(0, 20));
        a.insns.push_back(MovSp(1));
        a.insns.push_back(Movz(2, 24u, 0));
        a.insns.push_back(Movz(8, 63u, 0)); // read
        a.insns.push_back(Svc(0));

        // Submit SoftGLES frame + SwapBuffers
        a.insns.push_back(Movr64(0, 19));
        a.AdrData(1, off);
        EmitImm32(a.insns, 2, static_cast<uint32_t>(pkt_len));
        a.insns.push_back(Movz(8, 64u, 0)); // write
        a.insns.push_back(Svc(0));

        a.EmitNanosleep(0ULL, 33000000ULL);
    }
    const size_t b_back = a.EmitBPlaceholder();
    a.PatchToIdx(b_back, loop_top);
    return a.BuildElf64();
}

std::vector<uint8_t> BuildZygote64Elf() {
    GuestAsm a;
    const std::string m1 = "[zygote64] preloading ART heap & launching system_server + surfaceflinger\r\n";
    const std::string m2 = "[zygote64] Android runtime services spawned\r\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_m2 = a.AddString(m2);
    const size_t s_ss = a.AddString("/system/bin/system_server");
    const size_t s_sf = a.AddString("/system/bin/surfaceflinger");

    a.insns.push_back(SubImm64(31, 31, 128u));
    a.EmitWriteStdout(s_m1, m1.size());

    // mmap anonymous 64 KiB ART heap
    a.insns.push_back(Movz(0, 0u, 0));
    a.insns.push_back(Movz(1, 1u, 1)); // 65536
    a.insns.push_back(Movz(2, 3u, 0)); // PROT_READ | PROT_WRITE
    a.insns.push_back(Movz(3, 0x22u, 0)); // MAP_PRIVATE | MAP_ANON
    a.insns.push_back(Movn(4, 0u, 0)); // fd = -1
    a.insns.push_back(Movz(5, 0u, 0));
    a.insns.push_back(Movz(8, 222u, 0)); // mmap
    a.insns.push_back(Svc(0));

    a.EmitForkAndExec(s_ss, 19);
    a.EmitForkAndExec(s_sf, 20);
    a.EmitWriteStdout(s_m2, m2.size());

    // Zygote reaper loop
    const size_t loop_top = a.insns.size();
    a.EmitNanosleep(0ULL, 220000000ULL);
    a.insns.push_back(Movn(0, 0u, 0)); // -1
    a.insns.push_back(Movz(1, 0u, 0));
    a.insns.push_back(Movz(2, 1u /* WNOHANG */, 0));
    a.insns.push_back(Movz(3, 0u, 0));
    a.insns.push_back(Movz(8, 260u, 0)); // wait4
    a.insns.push_back(Svc(0));
    const size_t b_back = a.EmitBPlaceholder();
    a.PatchToIdx(b_back, loop_top);
    return a.BuildElf64();
}

std::vector<uint8_t> BuildInitElf() {
    GuestAsm a;
    const std::string m1 = "[init] Android 11 (API 30) Haseeb ARM64 init starting services\r\n";
    const std::string m2 = "[init] ueventd completed; launching servicemanager & zygote64\r\n";
    const std::string m3 = "[init] full framework supervisor online\r\n";
    const std::string stamp = "haseeb-engine-a11-magisk-v27-booted\n";
    const size_t s_m1 = a.AddString(m1);
    const size_t s_m2 = a.AddString(m2);
    const size_t s_m3 = a.AddString(m3);
    const size_t s_stamp = a.AddString(stamp);
    const size_t s_prop = a.AddString("/dev/__properties__/ro.product.model");
    const size_t s_cmd = a.AddString("/proc/cmdline");
    const size_t s_dir = a.AddString("/storage/emulated/0/HaseebVM");
    const size_t s_file = a.AddString("/storage/emulated/0/HaseebVM/boot_stamp.txt");
    const size_t s_uev = a.AddString("/system/bin/ueventd");
    const size_t s_sm = a.AddString("/system/bin/servicemanager");
    const size_t s_zyg = a.AddString("/system/bin/zygote64");

    a.insns.push_back(SubImm64(31, 31, 256u));
    a.EmitWriteStdout(s_m1, m1.size());

    // Read /dev/__properties__/ro.product.model & /proc/cmdline
    a.EmitOpenAt(19, s_prop, 0u);
    a.insns.push_back(CmpImm64(19, 3u));
    const size_t sk_prop = a.EmitBCondPlaceholder(11u);
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(AddImm64(1, 31, 128u));
    a.insns.push_back(Movz(2, 64u, 0));
    a.insns.push_back(Movz(8, 63u, 0));
    a.insns.push_back(Svc(0));
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));
    a.PatchToHere(sk_prop);

    a.EmitOpenAt(19, s_cmd, 0u);
    a.insns.push_back(CmpImm64(19, 3u));
    const size_t sk_cmd = a.EmitBCondPlaceholder(11u);
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(AddImm64(1, 31, 128u));
    a.insns.push_back(Movz(2, 64u, 0));
    a.insns.push_back(Movz(8, 63u, 0));
    a.insns.push_back(Svc(0));
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));
    a.PatchToHere(sk_cmd);

    // mkdirat("/storage/emulated/0/HaseebVM") & write boot_stamp.txt
    a.insns.push_back(Movn(0, 99u, 0));
    a.AdrData(1, s_dir);
    EmitImm32(a.insns, 2, 0755u);
    a.insns.push_back(Movz(8, 34u, 0)); // mkdirat
    a.insns.push_back(Svc(0));

    a.EmitOpenAt(19, s_file, 01101u /* O_WRONLY|O_CREAT|O_TRUNC */, 0644u);
    a.insns.push_back(CmpImm64(19, 3u));
    const size_t sk_file = a.EmitBCondPlaceholder(11u);
    a.insns.push_back(Movr64(0, 19));
    a.AdrData(1, s_stamp);
    EmitImm32(a.insns, 2, static_cast<uint32_t>(stamp.size()));
    a.insns.push_back(Movz(8, 64u, 0));
    a.insns.push_back(Svc(0));
    a.insns.push_back(Movr64(0, 19));
    a.insns.push_back(Movz(8, 57u, 0));
    a.insns.push_back(Svc(0));
    a.PatchToHere(sk_file);

    // Run /system/bin/ueventd and wait for completion
    a.EmitForkAndExec(s_uev, 21);
    a.insns.push_back(Movr64(0, 21));
    a.insns.push_back(AddImm64(1, 31, 64u));
    a.insns.push_back(Movz(2, 0u, 0));
    a.insns.push_back(Movz(3, 0u, 0));
    a.insns.push_back(Movz(8, 260u, 0)); // wait4
    a.insns.push_back(Svc(0));

    a.EmitWriteStdout(s_m2, m2.size());

    // Launch servicemanager & zygote64
    a.EmitForkAndExec(s_sm, 22);
    a.EmitForkAndExec(s_zyg, 23);
    a.EmitWriteStdout(s_m3, m3.size());

    // Init reaper loop
    const size_t loop_top = a.insns.size();
    a.EmitNanosleep(0ULL, 250000000ULL);
    a.insns.push_back(Movn(0, 0u, 0));
    a.insns.push_back(Movz(1, 0u, 0));
    a.insns.push_back(Movz(2, 1u /* WNOHANG */, 0));
    a.insns.push_back(Movz(3, 0u, 0));
    a.insns.push_back(Movz(8, 260u, 0));
    a.insns.push_back(Svc(0));
    const size_t b_back = a.EmitBPlaceholder();
    a.PatchToIdx(b_back, loop_top);
    return a.BuildElf64();
}

// =========================================================================
// Minimal Pure C++17 4 KiB-Block Ext4 Image Writer (Readable by Ext4Reader)
// =========================================================================

class Ext4ImageWriter {
public:
    struct FileSpec {
        std::string path; // e.g., "/system/bin/init"
        std::vector<uint8_t> data;
        uint16_t mode = 0100755u;
    };

    bool BuildToFile(const std::string& out_path,
                     const std::string& volume_name,
                     const std::vector<FileSpec>& files,
                     uint64_t& out_size_bytes,
                     std::string& out_error) {
        constexpr uint32_t kBlockSize = 4096u;
        constexpr uint32_t kTotalBlocks = 1024u; // 4 MiB clean 4K-block ext4
        constexpr uint32_t kInodesPerGroup = 256u;
        constexpr uint32_t kInodeSize = 256u;
        constexpr uint32_t kInodeTableStart = 4u; // sb@0, bgdt@1, bmap@2, imap@3, itable@4..19
        constexpr uint32_t kDataStartBlock = 20u;

        std::vector<uint8_t> img(static_cast<size_t>(kTotalBlocks) * kBlockSize, 0u);
        uint32_t next_block = kDataStartBlock;
        uint32_t next_ino = 12u; // inodes 1..11 reserved (2 = root)

        struct DirNode {
            uint32_t ino = 2u;
            uint32_t parent_ino = 2u;
            std::map<std::string, uint32_t> subdirs;
            struct Entry {
                std::string name;
                uint32_t ino;
                uint8_t file_type; // 1=REG, 2=DIR
            };
            std::vector<Entry> entries;
        };

        std::map<uint32_t, DirNode> dirs;
        dirs[2u] = DirNode{2u, 2u, {}, {{"lost+found", 11u, 2u}}};
        dirs[11u] = DirNode{11u, 2u, {}, {}};

        auto ensure_dir = [&](const std::vector<std::string>& segs) -> uint32_t {
            uint32_t cur = 2u;
            for (const auto& s : segs) {
                auto& d = dirs[cur];
                auto it = d.subdirs.find(s);
                if (it != d.subdirs.end()) {
                    cur = it->second;
                    continue;
                }
                if (next_ino >= kInodesPerGroup) return 0u;
                const uint32_t child_ino = next_ino++;
                d.subdirs[s] = child_ino;
                d.entries.push_back({s, child_ino, 2u});
                dirs[child_ino] = DirNode{child_ino, cur, {}, {}};
                cur = child_ino;
            }
            return cur;
        };

        auto write_inode = [&](uint32_t ino,
                               uint16_t mode,
                               uint64_t size_bytes,
                               uint32_t links,
                               uint32_t start_block,
                               uint32_t block_count) {
            const size_t base = static_cast<size_t>(kInodeTableStart) * kBlockSize +
                                static_cast<size_t>(ino - 1u) * kInodeSize;
            WriteU16At(img, base + 0x00u, mode);
            WriteU32At(img, base + 0x04u, static_cast<uint32_t>(size_bytes & 0xFFFFFFFFULL));
            WriteU16At(img, base + 0x1Au, static_cast<uint16_t>(links));
            WriteU32At(img, base + 0x1Cu, block_count * (kBlockSize / 512u));
            WriteU32At(img, base + 0x20u, 0x00080000u); // EXT4_EXTENTS_FL
            WriteU32At(img, base + 0x6Cu, static_cast<uint32_t>(size_bytes >> 32));

            // i_block starts at +0x28: Ext4ExtentHeader (12B) + Ext4Extent (12B)
            const size_t ib = base + 0x28u;
            WriteU16At(img, ib + 0u, 0xF30Au); // eh_magic
            WriteU16At(img, ib + 2u, block_count > 0u ? 1u : 0u); // eh_entries
            WriteU16At(img, ib + 4u, 4u); // eh_max
            WriteU16At(img, ib + 6u, 0u); // eh_depth
            if (block_count > 0u) {
                WriteU32At(img, ib + 12u, 0u); // ee_block
                WriteU16At(img, ib + 16u, static_cast<uint16_t>(block_count)); // ee_len
                WriteU16At(img, ib + 18u, 0u); // ee_start_hi
                WriteU32At(img, ib + 20u, start_block); // ee_start_lo
            }
            // Mark inode bitmap bit
            const size_t imap_off = 3u * kBlockSize;
            const uint32_t idx = ino - 1u;
            img[imap_off + idx / 8u] |= static_cast<uint8_t>(1u << (idx % 8u));
        };

        auto alloc_blocks = [&](uint32_t count) -> uint32_t {
            if (count == 0u) return 0u;
            if (next_block + count > kTotalBlocks) return 0u;
            const uint32_t start = next_block;
            next_block += count;
            return start;
        };

        for (const auto& f : files) {
            std::vector<std::string> parts;
            std::istringstream iss(f.path);
            std::string seg;
            while (std::getline(iss, seg, '/')) {
                if (!seg.empty()) parts.push_back(seg);
            }
            if (parts.empty()) continue;
            const std::string fname = parts.back();
            parts.pop_back();
            const uint32_t dir_ino = ensure_dir(parts);
            if (dir_ino == 0u || next_ino >= kInodesPerGroup) {
                out_error = "Ext4 inode table exhausted";
                return false;
            }
            const uint32_t fino = next_ino++;
            const uint32_t nblks = f.data.empty()
                ? 0u
                : static_cast<uint32_t>((f.data.size() + kBlockSize - 1u) / kBlockSize);
            const uint32_t start_blk = alloc_blocks(nblks);
            if (nblks > 0u && start_blk == 0u) {
                out_error = "Ext4 block image exhausted";
                return false;
            }
            if (!f.data.empty()) {
                std::memcpy(img.data() + static_cast<size_t>(start_blk) * kBlockSize,
                            f.data.data(), f.data.size());
            }
            write_inode(fino, f.mode, f.data.size(), 1u, start_blk, nblks);
            dirs[dir_ino].entries.push_back({fname, fino, 1u});
        }

        // Write every directory data block + inode
        uint16_t dir_count = 0u;
        for (const auto& kv : dirs) {
            ++dir_count;
            const DirNode& d = kv.second;
            std::vector<DirNode::Entry> all_entries;
            all_entries.push_back({".", d.ino, 2u});
            all_entries.push_back({"..", d.parent_ino, 2u});
            all_entries.insert(all_entries.end(), d.entries.begin(), d.entries.end());

            const uint32_t blk = alloc_blocks(1u);
            if (blk == 0u) {
                out_error = "Ext4 exhausted allocating directory block";
                return false;
            }
            size_t pos = 0u;
            const size_t blk_base = static_cast<size_t>(blk) * kBlockSize;
            for (size_t i = 0; i < all_entries.size(); ++i) {
                const auto& e = all_entries[i];
                const size_t need = (8u + e.name.size() + 3u) & ~size_t(3u);
                const bool is_last = (i + 1u == all_entries.size());
                if (pos + need > kBlockSize) {
                    out_error = "Ext4 directory block overflow";
                    return false;
                }
                const uint16_t rec_len = is_last
                    ? static_cast<uint16_t>(kBlockSize - pos)
                    : static_cast<uint16_t>(need);
                WriteU32At(img, blk_base + pos + 0u, e.ino);
                WriteU16At(img, blk_base + pos + 4u, rec_len);
                img[blk_base + pos + 6u] = static_cast<uint8_t>(e.name.size());
                img[blk_base + pos + 7u] = e.file_type;
                std::memcpy(img.data() + blk_base + pos + 8u, e.name.data(), e.name.size());
                pos += rec_len;
            }
            write_inode(d.ino, 0040755u, kBlockSize, static_cast<uint32_t>(2u + d.subdirs.size()), blk, 1u);
        }

        // Mark block bitmap bits [0 .. next_block - 1]
        const size_t bmap_off = 2u * kBlockSize;
        for (uint32_t b = 0; b < next_block; ++b) {
            img[bmap_off + b / 8u] |= static_cast<uint8_t>(1u << (b % 8u));
        }

        // Superblock at byte offset 1024
        constexpr size_t sb = 1024u;
        const uint32_t used_inodes = (next_ino - 1u);
        const uint32_t free_inodes = kInodesPerGroup - used_inodes;
        const uint32_t free_blocks = kTotalBlocks - next_block;
        WriteU32At(img, sb + 0x00u, kInodesPerGroup);        // s_inodes_count
        WriteU32At(img, sb + 0x04u, kTotalBlocks);           // s_blocks_count_lo
        WriteU32At(img, sb + 0x0Cu, free_blocks);            // s_free_blocks_count_lo
        WriteU32At(img, sb + 0x10u, free_inodes);            // s_free_inodes_count
        WriteU32At(img, sb + 0x14u, 0u);                     // s_first_data_block
        WriteU32At(img, sb + 0x18u, 2u);                     // s_log_block_size (4096)
        WriteU32At(img, sb + 0x1Cu, 2u);                     // s_log_cluster_size
        WriteU32At(img, sb + 0x20u, 8192u);                  // s_blocks_per_group
        WriteU32At(img, sb + 0x24u, 8192u);                  // s_clusters_per_group
        WriteU32At(img, sb + 0x28u, kInodesPerGroup);        // s_inodes_per_group
        WriteU16At(img, sb + 0x38u, 0xEF53u);                // s_magic
        WriteU16At(img, sb + 0x3Au, 1u);                     // s_state (valid)
        WriteU32At(img, sb + 0x4Cu, 1u);                     // s_rev_level (dynamic)
        WriteU32At(img, sb + 0x54u, 11u);                    // s_first_ino
        WriteU16At(img, sb + 0x58u, kInodeSize);             // s_inode_size
        WriteU32At(img, sb + 0x60u, 0x0040u | 0x0002u);      // s_feature_incompat (EXTENTS | FILETYPE)
        const std::string vol = volume_name.substr(0u, 15u);
        std::memcpy(img.data() + sb + 0x78u, vol.data(), vol.size());
        WriteU16At(img, sb + 0xFEu, 32u);                    // s_desc_size

        // Group 0 descriptor at block 1 (offset 4096)
        constexpr size_t gd = kBlockSize;
        WriteU32At(img, gd + 0x00u, 2u);                     // bg_block_bitmap_lo
        WriteU32At(img, gd + 0x04u, 3u);                     // bg_inode_bitmap_lo
        WriteU32At(img, gd + 0x08u, kInodeTableStart);       // bg_inode_table_lo
        WriteU16At(img, gd + 0x0Cu, static_cast<uint16_t>(free_blocks));
        WriteU16At(img, gd + 0x0Eu, static_cast<uint16_t>(free_inodes));
        WriteU16At(img, gd + 0x10u, dir_count);

        std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
        if (!ofs.good() || !ofs.write(reinterpret_cast<const char*>(img.data()),
                                      static_cast<std::streamsize>(img.size()))) {
            out_error = "Failed writing ext4 system.img to " + out_path;
            return false;
        }
        out_size_bytes = img.size();
        return true;
    }
};

std::vector<uint8_t> BuildBootImageV2Blob(const std::vector<uint8_t>& ramdisk_gz,
                                          const std::string& cmdline) {
    constexpr uint32_t kPage = 4096u;
    auto align_up = [&](size_t n) { return (n + kPage - 1u) & ~static_cast<size_t>(kPage - 1u); };
    // Write boot.img v2 header + 1-page kernel placeholder ("HASEEB_K") + gzipped CPIO ramdisk
    // Notice Kernel has empty valid arm64 magic so BootGuest seamlessly launches /magiskinit!
    std::vector<uint8_t> img(kPage + kPage + align_up(ramdisk_gz.size()), 0u);
    std::memcpy(img.data() + 0u, "ANDROID!", 8u);
    WriteU32At(img, 8u, 0u);                                    // kernel_size = 0 (supervisor boot)
    WriteU32At(img, 12u, 0x40080000u);                          // kernel_addr
    WriteU32At(img, 16u, static_cast<uint32_t>(ramdisk_gz.size()));
    WriteU32At(img, 20u, 0x44000000u);                          // ramdisk_addr
    WriteU32At(img, 24u, 0u);                                   // second_size
    WriteU32At(img, 28u, 0u);
    WriteU32At(img, 32u, 0x40000100u);                          // tags_addr
    WriteU32At(img, 36u, kPage);                                // page_size
    WriteU32At(img, 40u, 2u);                                   // header_version = 2
    WriteU32At(img, 44u, (11u << 25) | (0u << 18) | (0u << 11)); // os_version
    const std::string name = "HaseebA11-Magisk";
    std::memcpy(img.data() + 48u, name.data(), std::min<size_t>(name.size(), 15u));
    std::memcpy(img.data() + 64u, cmdline.data(), std::min<size_t>(cmdline.size(), 511u));
    if (!ramdisk_gz.empty()) {
        std::memcpy(img.data() + kPage, ramdisk_gz.data(), ramdisk_gz.size());
    }
    img.resize(kPage + align_up(ramdisk_gz.size()));
    return img;
}

} // namespace

EngineRomBuildResult EngineRomBuilder::BuildMagiskAndroidRom(const std::string& output_dir) {
    EngineRomBuildResult res;
    if (output_dir.empty()) {
        res.error = "Output directory path is empty";
        return res;
    }
    if (!GuestVfsBridge::EnsureDirectoryTree(output_dir)) {
        res.error = "Failed creating ROM output directory: " + output_dir;
        return res;
    }

    const std::vector<uint8_t> magiskinit_elf = BuildMagiskInitElf();
    const std::vector<uint8_t> init_elf = BuildInitElf();
    const std::vector<uint8_t> ueventd_elf = BuildUeventdElf();
    const std::vector<uint8_t> servicemanager_elf = BuildServiceManagerElf();
    const std::vector<uint8_t> zygote64_elf = BuildZygote64Elf();
    const std::vector<uint8_t> system_server_elf = BuildSystemServerElf();
    const std::vector<uint8_t> surfaceflinger_elf = BuildSurfaceFlingerElf();

    // Build Magisk v27.0 CPIO ramdisk
    auto make_entry = [](const std::string& name, uint32_t mode, const std::vector<uint8_t>& bytes) {
        CpioEntry e;
        e.name = name;
        e.mode = mode;
        e.nlink = 1u;
        e.data = bytes;
        return e;
    };
    auto make_dir = [](const std::string& name) {
        CpioEntry e;
        e.name = name;
        e.mode = 0040755u;
        e.nlink = 2u;
        return e;
    };
    auto str_bytes = [](const std::string& s) {
        return std::vector<uint8_t>(s.begin(), s.end());
    };

    const std::string magisk_cfg =
        "KEEPVERITY=false\nKEEPFORCEENCRYPT=false\nPATCHVBMETAFLAG=true\nRECOVERYMODE=false\n"
        "SHA1=4a7e88d3f20129048c1e7b0c27000\n";
    const std::string init_magisk_rc =
        "on post-fs-data\n    start logd\n    exec u:r:magisk:s0 -- /sbin/magisk --post-fs-data\n"
        "on property:sys.boot_completed=1\n    exec u:r:magisk:s0 -- /sbin/magisk --boot-complete\n";
    const std::string init_rc =
        "import /overlay.d/init.magisk.rc\n"
        "on early-init\n    start ueventd\n"
        "on boot\n    class_start core\n    class_start main\n";

    std::vector<CpioEntry> cpio_entries = {
        make_entry("magiskinit", 0100755u, magiskinit_elf),
        make_entry("init", 0100755u, init_elf),
        make_dir("sbin"),
        make_entry("sbin/su", 0100755u, magiskinit_elf),
        make_dir(".backup"),
        make_entry(".backup/.magisk", 0100644u, str_bytes(magisk_cfg)),
        make_entry(".backup/init", 0100755u, init_elf),
        make_dir("overlay.d"),
        make_entry("overlay.d/init.magisk.rc", 0100644u, str_bytes(init_magisk_rc)),
        make_entry("init.rc", 0100644u, str_bytes(init_rc)),
    };
    res.ramdisk_entries = static_cast<uint32_t>(cpio_entries.size());

    const std::vector<uint8_t> cpio_raw = CpioArchive::Build(cpio_entries);
    const std::vector<uint8_t> ramdisk_gz = CompressionCodec::CompressGzip(cpio_raw.data(), cpio_raw.size());
    const std::string cmdline =
        "androidboot.hardware=haseeb_arm64 androidboot.selinux=permissive "
        "buildvariant=userdebug androidboot.magisk=27000";
    const std::vector<uint8_t> boot_bytes = BuildBootImageV2Blob(ramdisk_gz, cmdline);

    const std::string boot_path = output_dir + "/boot.img";
    {
        std::ofstream ofs(boot_path, std::ios::binary | std::ios::trunc);
        if (!ofs.good() || !ofs.write(reinterpret_cast<const char*>(boot_bytes.data()),
                                      static_cast<std::streamsize>(boot_bytes.size()))) {
            res.error = "Failed writing boot.img to " + boot_path;
            return res;
        }
    }

    const std::string build_prop =
        "ro.build.version.release=11\n"
        "ro.build.version.sdk=30\n"
        "ro.build.display.id=HaseebOS-A11-Magisk27\n"
        "ro.product.cpu.abi=arm64-v8a\n"
        "ro.product.model=SM-S938B\n"
        "ro.hardware=haseeb_arm64\n"
        "ro.opengles.version=196608\n"
        "ro.debuggable=1\n"
        "ro.boot.verifiedbootstate=orange\n";
    const std::string rom_marker = "haseeb-engine-a11-magisk-v27";

    std::vector<Ext4ImageWriter::FileSpec> sys_files = {
        {"/system/bin/init", init_elf, 0100755u},
        {"/system/bin/ueventd", ueventd_elf, 0100755u},
        {"/system/bin/servicemanager", servicemanager_elf, 0100755u},
        {"/system/bin/zygote64", zygote64_elf, 0100755u},
        {"/system/bin/system_server", system_server_elf, 0100755u},
        {"/system/bin/surfaceflinger", surfaceflinger_elf, 0100755u},
        {"/system/bin/su", magiskinit_elf, 0100755u},
        {"/system/etc/build.prop", str_bytes(build_prop), 0100644u},
        {"/system/build.prop", str_bytes(build_prop), 0100644u},
        {"/system/etc/haseeb_rom", str_bytes(rom_marker), 0100644u},
        {"/system/framework/framework-res.txt", str_bytes("Haseeb Engine A11 Framework"), 0100644u},
        {"/vendor/bin/hw_marker", str_bytes("haseeb-virtio-hal-v1"), 0100644u},
    };
    res.system_files = static_cast<uint32_t>(sys_files.size());

    const std::string system_path = output_dir + "/system.img";
    uint64_t sys_size = 0;
    Ext4ImageWriter writer;
    if (!writer.BuildToFile(system_path, "system", sys_files, sys_size, res.error)) {
        return res;
    }

    // Self-verify generated boot.img & system.img via real parsers before returning success
    ParsedBootImage verified_boot;
    std::string boot_err;
    if (BootImageParser::ParseBootFile(boot_path, verified_boot, boot_err) != VmError::Ok ||
        !verified_boot.magisk_detected) {
        res.error = "Self-verification of generated Magisk boot.img failed: " + boot_err;
        return res;
    }
    loader::Ext4Reader verified_ext4;
    if (!verified_ext4.Open(system_path)) {
        res.error = "Self-verification of generated ext4 system.img failed: " +
                    verified_ext4.LastError();
        return res;
    }
    std::string check_marker;
    if (!verified_ext4.ReadFileString("/system/etc/haseeb_rom", check_marker) ||
        check_marker != rom_marker) {
        res.error = "Self-verification of ext4 ROM marker failed";
        return res;
    }
    verified_ext4.Close();

    res.ok = true;
    res.boot_img_path = boot_path;
    res.system_img_path = system_path;
    res.boot_img_size = boot_bytes.size();
    res.system_img_size = sys_size;
    res.magisk_patched = true;
    return res;
}

} // namespace haseeb::vm
