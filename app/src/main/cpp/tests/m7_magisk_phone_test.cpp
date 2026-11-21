#include "haseeb/boot_image.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/magisk_patcher.hpp"
#include "haseeb/phone_hardware.hpp"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
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

using namespace haseeb::vm;

namespace {

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
uint32_t Adr(uint8_t xd, int32_t byte_offset) {
    uint32_t u21 = static_cast<uint32_t>(byte_offset) & 0x1FFFFFu;
    return 0x10000000u | ((u21 & 3u) << 29) | (((u21 >> 2) & 0x7FFFFu) << 5) | (xd & 31u);
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
uint32_t CmpReg64(uint8_t xn, uint8_t xm) {
    return 0xEB00001Fu | (static_cast<uint32_t>(xm & 31u) << 16) |
           (static_cast<uint32_t>(xn & 31u) << 5);
}
uint32_t LdrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9400000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
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

void AppendLe32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

struct CodeBlobBuilder {
    std::vector<uint32_t> insns;
    std::vector<uint8_t> data;
    struct Patch { size_t insn_idx; uint8_t rd; size_t data_offset; };
    std::vector<Patch> patches;
    struct BranchPatch { size_t insn_idx; bool is_cond; uint8_t cond; size_t target_idx; };
    std::vector<BranchPatch> b_patches;

    size_t AddString(const std::string& s) {
        size_t off = data.size();
        data.insert(data.end(), s.begin(), s.end());
        data.push_back('\0');
        return off;
    }
    void EmitAdrPlaceholder(uint8_t rd, size_t data_offset) {
        size_t idx = insns.size();
        insns.push_back(0);
        patches.push_back({idx, rd, data_offset});
    }
    size_t EmitCondPlaceholder(uint8_t cond) {
        size_t idx = insns.size();
        insns.push_back(0);
        b_patches.push_back({idx, true, cond, 0});
        return b_patches.size() - 1u;
    }
    void PatchBranchToHere(size_t bp_idx) {
        b_patches[bp_idx].target_idx = insns.size();
    }
    std::vector<uint8_t> Finalize() {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : patches) {
            insns[p.insn_idx] = Adr(p.rd, static_cast<int32_t>(code_bytes + p.data_offset) -
                                          static_cast<int32_t>(p.insn_idx * 4u));
        }
        for (const auto& bp : b_patches) {
            const int32_t rel = static_cast<int32_t>(bp.target_idx) -
                                static_cast<int32_t>(bp.insn_idx);
            insns[bp.insn_idx] = bp.is_cond ? BCond(bp.cond, rel) : BImm(rel);
        }
        std::vector<uint8_t> blob;
        blob.reserve(code_bytes + data.size());
        for (uint32_t i : insns) AppendLe32(blob, i);
        blob.insert(blob.end(), data.begin(), data.end());
        return blob;
    }
};

std::vector<uint8_t> BuildElf64(const std::vector<uint8_t>& code_and_data,
                                uint64_t base_va = 0x0000000000400000ULL) {
    constexpr uint64_t kCodeOff = 0x100ULL;
    const uint64_t total = kCodeOff + code_and_data.size();
    std::vector<uint8_t> elf(total, 0u);
    elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
    auto w16 = [&](size_t o, uint16_t v) { elf[o] = v & 0xFFu; elf[o + 1] = v >> 8; };
    auto w32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    auto w64 = [&](size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    w16(16, 2u); w16(18, 183u); w32(20, 1u);
    w64(24, base_va + kCodeOff); w64(32, 64ULL);
    w16(52, 64u); w16(54, 56u); w16(56, 1u);
    w32(64 + 0, 1u); w32(64 + 4, 7u);
    w64(64 + 8, 0ULL); w64(64 + 16, base_va); w64(64 + 24, base_va);
    w64(64 + 32, total); w64(64 + 40, total + 4096ULL); w64(64 + 48, 4096ULL);
    std::memcpy(elf.data() + kCodeOff, code_and_data.data(), code_and_data.size());
    return elf;
}

std::vector<uint8_t> BuildStockBootV2(const std::vector<uint8_t>& ramdisk) {
    constexpr uint32_t kPage = 4096u;
    auto align_up = [&](size_t v) { return (v + kPage - 1u) & ~static_cast<size_t>(kPage - 1u); };
    std::vector<uint8_t> img(kPage + align_up(ramdisk.size()), 0u);
    auto put32 = [&](size_t o, uint32_t v) {
        for (int i = 0; i < 4; ++i) img[o + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    std::memcpy(img.data(), "ANDROID!", 8);
    put32(16, static_cast<uint32_t>(ramdisk.size()));
    put32(36, kPage);
    put32(40, 2u);
    if (!ramdisk.empty()) std::memcpy(img.data() + kPage, ramdisk.data(), ramdisk.size());
    return img;
}

std::vector<uint8_t> BuildStockBootV3(const std::vector<uint8_t>& ramdisk) {
    constexpr uint32_t kPage = 4096u;
    auto align_up = [&](size_t v) { return (v + kPage - 1u) & ~static_cast<size_t>(kPage - 1u); };
    std::vector<uint8_t> img(kPage + align_up(ramdisk.size()), 0u);
    auto put32 = [&](size_t o, uint32_t v) {
        for (int i = 0; i < 4; ++i) img[o + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    std::memcpy(img.data(), "ANDROID!", 8);
    put32(12, static_cast<uint32_t>(ramdisk.size()));
    put32(20, 3u);
    put32(24, 1580u);
    std::memcpy(img.data() + 44u, "console=ttyAMA0", 15);
    if (!ramdisk.empty()) std::memcpy(img.data() + kPage, ramdisk.data(), ramdisk.size());
    return img;
}

void TestBootImagePatcherV2AndV3() {
    CpioEntry stock_init;
    stock_init.name = "init";
    stock_init.mode = 0100755u;
    stock_init.nlink = 1u;
    stock_init.data = BootImagePatcher::BuildDefaultSuElf();
    const std::vector<uint8_t> stock_cpio = CpioArchive::Build({stock_init});

    // Test v2 stock -> Magisk patched
    {
        auto stock_v2 = BuildStockBootV2(stock_cpio);
        MagiskPatchResult res = BootImagePatcher::PatchBootBytes(stock_v2);
        HASEEB_CHECK(res.ok);
        HASEEB_CHECK(res.verified);
        HASEEB_CHECK(res.source_header_version == 2u);
        HASEEB_CHECK(res.patched_header_version == 2u);
        HASEEB_CHECK(res.patched_ramdisk_entries > res.original_ramdisk_entries);

        ParsedBootImage parsed;
        std::string err;
        HASEEB_CHECK(BootImageParser::ParseBootBytes(res.patched_image, parsed, err) == VmError::Ok);
        HASEEB_CHECK(parsed.magisk_detected);

        std::vector<uint8_t> cpio_out;
        HASEEB_CHECK(BootImageParser::DecompressRamdisk(parsed.ramdisk, cpio_out, err) == VmError::Ok);
        std::vector<CpioEntry> entries;
        HASEEB_CHECK(CpioArchive::Parse(cpio_out, entries, err));
        HASEEB_CHECK(CpioArchive::FindEntry(entries, "magiskinit") != nullptr);
        HASEEB_CHECK(CpioArchive::FindEntry(entries, ".backup/init") != nullptr);
        HASEEB_CHECK(CpioArchive::FindEntry(entries, ".backup/.magisk") != nullptr);
        HASEEB_CHECK(CpioArchive::FindEntry(entries, "overlay.d/init.magisk.rc") != nullptr);
        HASEEB_CHECK(CpioArchive::FindEntry(entries, "sbin/su") != nullptr);
    }

    // Test v3 stock -> Magisk patched
    {
        auto stock_v3 = BuildStockBootV3(stock_cpio);
        MagiskPatchResult res = BootImagePatcher::PatchBootBytes(stock_v3);
        HASEEB_CHECK(res.ok);
        HASEEB_CHECK(res.verified);
        HASEEB_CHECK(res.source_header_version == 3u);
        HASEEB_CHECK(res.patched_header_version == 3u);

        ParsedBootImage parsed;
        std::string err;
        HASEEB_CHECK(BootImageParser::ParseBootBytes(res.patched_image, parsed, err) == VmError::Ok);
        HASEEB_CHECK(parsed.magisk_detected);
    }

    std::cout << "[PASS] Test 1: Pure C++17 Magisk v27.0 BootImagePatcher (boot v2/v3 unpack, backup, inject, gzip, verify)\n";
}

void TestPhoneHardwareHubRealSensorsAndCamera() {
    PhoneHardwareHub hw;
    hw.Reset();

    float min_z = 100.0f, max_z = -100.0f;
    float min_gx = 100.0f, max_gx = -100.0f;
    uint64_t prev_ts = 0;
    for (int i = 0; i < 16; ++i) {
        auto all = hw.SampleAllSensors();
        HASEEB_CHECK(all.size() == 6u);
        HASEEB_CHECK(all[0].type == PhoneHardwareHub::kSensorAccelerometer);
        HASEEB_CHECK(all[0].accuracy == 3u);
        HASEEB_CHECK(all[0].timestamp_ns >= prev_ts && all[0].timestamp_ns > 0ULL);
        prev_ts = all[0].timestamp_ns;
        min_z = std::min(min_z, all[0].v[2]);
        max_z = std::max(max_z, all[0].v[2]);
        min_gx = std::min(min_gx, all[2].v[0]);
        max_gx = std::max(max_gx, all[2].v[0]);
    }
    HASEEB_CHECK(min_z > 9.4f && max_z < 10.2f);
    HASEEB_CHECK(max_z > min_z);
    HASEEB_CHECK(max_gx > min_gx);

    // Override accel & verify deterministic center
    hw.SetSensorOverride(PhoneHardwareHub::kSensorAccelerometer, 2.5f, -1.0f, 9.2f, true);
    auto ov = hw.SampleSensor(PhoneHardwareHub::kSensorAccelerometer);
    HASEEB_CHECK(std::fabs(ov.v[0] - 2.5f) < 0.25f);
    HASEEB_CHECK(std::fabs(ov.v[1] - (-1.0f)) < 0.25f);

    // Thermal & battery tick + sysfs readability
    const auto before_snap = hw.Snapshot();
    for (int i = 0; i < 10; ++i) hw.TickLoad(5000000ULL);
    const auto after_snap = hw.Snapshot();
    HASEEB_CHECK(after_snap.soc_temp_c >= before_snap.soc_temp_c);

    std::string cap_txt, temp_txt;
    HASEEB_CHECK(hw.ReadVirtualSysfs("/sys/class/power_supply/battery/capacity", cap_txt));
    HASEEB_CHECK(hw.ReadVirtualSysfs("/sys/class/thermal/thermal_zone0/temp", temp_txt));
    HASEEB_CHECK(!cap_txt.empty() && !temp_txt.empty());

    // V4L2 camera frame generation
    hw.SetCameraFormat(320u, 240u, PhoneHardwareHub::kV4l2PixFmtRgba);
    uint64_t ts1 = 0, ts2 = 0;
    uint32_t seq1 = 0, seq2 = 0;
    auto f1 = hw.GenerateCameraFrame(ts1, seq1);
    auto f2 = hw.GenerateCameraFrame(ts2, seq2);
    HASEEB_CHECK(f1.size() == 320u * 240u * 4u);
    HASEEB_CHECK(seq1 == 1u && seq2 == 2u && ts2 >= ts1);

    std::cout << "[PASS] Test 2: PhoneHardwareHub Gaussian noise/drift sensors, thermal/battery sysfs & V4L2 camera\n";
}

void TestEl0MagiskPhonePropertiesSensorsAndStorage() {
    CodeBlobBuilder cb;
    const size_t s_prop_serial = cb.AddString("/dev/__properties__/properties_serial");
    const size_t s_build_prop = cb.AddString("/system/etc/build.prop");
    const size_t s_su_dev = cb.AddString("/dev/magisk_su");
    const size_t s_sens_dev = cb.AddString("/dev/haseeb_sensors");
    const size_t s_cam_dev = cb.AddString("/dev/video0");
    const size_t s_bat_cap = cb.AddString("/sys/class/power_supply/battery/capacity");
    const size_t s_dir = cb.AddString("/storage/emulated/0/HaseebSave");
    const size_t s_file1 = cb.AddString("/storage/emulated/0/HaseebSave/slot1.dat");
    const size_t s_file2 = cb.AddString("/storage/emulated/0/HaseebSave/slot2.dat");
    const size_t s_payload = cb.AddString("MAGISK-SAVE-OK");

    // Stack frame 2048 bytes
    cb.insns.push_back(SubImm64(31, 31, 2048u));

    auto emit_fail = [&](uint16_t code) {
        cb.insns.push_back(Movz(0, code, 0));
        cb.insns.push_back(Movz(8, 94u, 0));
        cb.insns.push_back(Svc(0));
    };

    // 1. Open & read /dev/__properties__/properties_serial (>= 16 bytes)
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_prop_serial);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    const size_t b_prop_fd = cb.EmitCondPlaceholder(10u /*GE*/);
    emit_fail(10u);
    cb.PatchBranchToHere(b_prop_fd);
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movr64(1, 31));
    cb.insns.push_back(Movz(2, 32u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 16u));
    const size_t b_prop_rd = cb.EmitCondPlaceholder(10u);
    emit_fail(11u);
    cb.PatchBranchToHere(b_prop_rd);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 2. Open & read /system/etc/build.prop (>= 20 bytes)
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_build_prop);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(1, 31));
    cb.insns.push_back(Movz(2, 256u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 20u));
    const size_t b_bp_rd = cb.EmitCondPlaceholder(10u);
    emit_fail(12u);
    cb.PatchBranchToHere(b_bp_rd);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 3. Open /dev/magisk_su & invoke HASEEB_SU_REQUEST (0x4D4701), verify getuid() == 0
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_su_dev);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4701u, 0));
    cb.insns.push_back(Movk(1, 0x004Du, 1));
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t b_su_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(13u);
    cb.PatchBranchToHere(b_su_ok);
    cb.insns.push_back(Movz(8, 174u, 0)); // getuid
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t b_uid_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(14u);
    cb.PatchBranchToHere(b_uid_ok);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 4. Open /dev/haseeb_sensors & ioctl HASEEB_SENSOR_GET_ALL (0x485301) -> expect 6
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_sens_dev);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movz(1, 0x5301u, 0));
    cb.insns.push_back(Movk(1, 0x0048u, 1));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 6u));
    const size_t b_sens_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(15u);
    cb.PatchBranchToHere(b_sens_ok);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 5. Open /dev/video0 -> VIDIOC_QUERYCAP (0x80685600) & read 1024 bytes of frame
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_cam_dev);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movz(1, 0x5600u, 0));
    cb.insns.push_back(Movk(1, 0x8068u, 1));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(9, 31, 0u)); // "hase" -> 0x65736168
    cb.insns.push_back(Movz(10, 0x6168u, 0));
    cb.insns.push_back(Movk(10, 0x6573u, 1));
    cb.insns.push_back(CmpReg64(9, 10));
    const size_t b_cam_cap = cb.EmitCondPlaceholder(0u);
    emit_fail(16u);
    cb.PatchBranchToHere(b_cam_cap);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(AddImm64(1, 31, 256u));
    cb.insns.push_back(Movz(2, 1024u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 1024u));
    const size_t b_cam_rd = cb.EmitCondPlaceholder(0u);
    emit_fail(17u);
    cb.PatchBranchToHere(b_cam_rd);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 6. Battery sysfs check
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_bat_cap);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(1, 31));
    cb.insns.push_back(Movz(2, 16u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 2u));
    const size_t b_bat_rd = cb.EmitCondPlaceholder(10u);
    emit_fail(18u);
    cb.PatchBranchToHere(b_bat_rd);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // 7. /storage/emulated/0 mkdirat + write + read + getdents64 + renameat
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_dir);
    cb.insns.push_back(Movz(2, 0755u, 0));
    cb.insns.push_back(Movz(8, 34u, 0)); // mkdirat
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t b_mkdir_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(19u);
    cb.PatchBranchToHere(b_mkdir_ok);

    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_file1);
    cb.insns.push_back(Movz(2, 0x0241u, 0)); // O_CREAT | O_WRONLY | O_TRUNC
    cb.insns.push_back(Movz(3, 0644u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    const size_t b_cr_ok = cb.EmitCondPlaceholder(10u);
    emit_fail(20u);
    cb.PatchBranchToHere(b_cr_ok);
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(0, 19));
    cb.EmitAdrPlaceholder(1, s_payload);
    cb.insns.push_back(Movz(2, 14u, 0));
    cb.insns.push_back(Movz(8, 64u, 0)); // write
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 14u));
    const size_t b_wr_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(21u);
    cb.PatchBranchToHere(b_wr_ok);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0)); // close
    cb.insns.push_back(Svc(0));

    // Reopen read-only & verify "MAGI"
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_file1);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movr64(1, 31));
    cb.insns.push_back(Movz(2, 14u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 14u));
    const size_t b_rd_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(22u);
    cb.PatchBranchToHere(b_rd_ok);
    cb.insns.push_back(LdrW(9, 31, 0u));
    cb.insns.push_back(Movz(10, 0x414Du, 0));
    cb.insns.push_back(Movk(10, 0x4947u, 1)); // "MAGI" LE
    cb.insns.push_back(CmpReg64(9, 10));
    const size_t b_magi_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(23u);
    cb.PatchBranchToHere(b_magi_ok);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // getdents64 on /storage/emulated/0/HaseebSave
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_dir);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(2, 1u, 1)); // 0x10000 O_DIRECTORY
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(AddImm64(1, 31, 512u));
    cb.insns.push_back(Movz(2, 512u, 0));
    cb.insns.push_back(Movz(8, 61u, 0)); // getdents64
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 20u));
    const size_t b_dents_ok = cb.EmitCondPlaceholder(10u);
    emit_fail(24u);
    cb.PatchBranchToHere(b_dents_ok);
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(8, 57u, 0));
    cb.insns.push_back(Svc(0));

    // renameat slot1.dat -> slot2.dat
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_file1);
    cb.insns.push_back(Movn(2, 99u, 0));
    cb.EmitAdrPlaceholder(3, s_file2);
    cb.insns.push_back(Movz(8, 38u, 0)); // renameat
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t b_ren_ok = cb.EmitCondPlaceholder(0u);
    emit_fail(25u);
    cb.PatchBranchToHere(b_ren_ok);

    // Done!
    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movz(8, 94u, 0));
    cb.insns.push_back(Svc(0));

    const std::vector<uint8_t> init_elf = BuildElf64(cb.Finalize());
    CpioEntry e_init;
    e_init.name = "init";
    e_init.mode = 0100755u;
    e_init.nlink = 1u;
    e_init.data = init_elf;

    // Package stock v2 boot image, then patch with BootImagePatcher!
    const std::vector<uint8_t> stock_boot = BuildStockBootV2(CpioArchive::Build({e_init}));
    MagiskPatchResult patch_res = BootImagePatcher::PatchBootBytes(stock_boot);
    HASEEB_CHECK(patch_res.ok && patch_res.verified);

    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(patch_res.patched_image, parsed, err) == VmError::Ok);
    HASEEB_CHECK(parsed.magisk_detected);

    const std::string base_tmp = "/tmp/haseeb_m7_test_" + std::to_string(static_cast<long>(::getpid()));
    const std::string storage_root = base_tmp + "/storage/emulated/0";
    std::string rm_cmd = "rm -rf " + base_tmp;
    std::system(rm_cmd.c_str());

    VirtualMachineSkeleton vm;
    vm.SetRuntimePaths(base_tmp, storage_root);
    vm.SetDeviceProperties({
        {"ro.product.model", "SM-S938B"},
        {"ro.product.brand", "samsung"},
        {"ro.product.marketname", "Galaxy S25 Ultra"},
    });

    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    cfg.width = 720u;
    cfg.height = 1280u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);

    std::string booted_target;
    HASEEB_CHECK(vm.BootGuest(true, booted_target, err) == VmError::Ok);
    HASEEB_CHECK(booted_target == "/magiskinit");

    HASEEB_CHECK(vm.StepGuest(200000ULL) == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);
    HASEEB_CHECK(vm.Supervisor()->Exited());
    HASEEB_CHECK(vm.Supervisor()->ExitStatus() == 0);
    // Verify magiskinit handed off via execve("/.backup/init")!
    HASEEB_CHECK(vm.Supervisor()->ActiveBinary() == "/.backup/init");

    const auto snap = vm.Hardware().Snapshot();
    HASEEB_CHECK(snap.magisk_detected);
    HASEEB_CHECK(snap.su_grants >= 1u);
    HASEEB_CHECK(snap.camera_frames >= 1u);

    // Verify file persisted in host-mapped shared storage directory
    std::ifstream ifs(storage_root + "/HaseebSave/slot2.dat", std::ios::binary);
    HASEEB_CHECK(ifs.good());
    std::string saved;
    std::getline(ifs, saved);
    HASEEB_CHECK(saved == "MAGISK-SAVE-OK");

    vm.Shutdown();
    std::system(rm_cmd.c_str());
    std::cout << "[PASS] Test 3: Patched boot -> /magiskinit -> /.backup/init -> su, Bionic __properties__, sensors, camera & /storage/emulated/0\n";
}

} // namespace

int main() {
    TestBootImagePatcherV2AndV3();
    TestPhoneHardwareHubRealSensorsAndCamera();
    TestEl0MagiskPhonePropertiesSensorsAndStorage();
    std::cout << "ALL M7 MAGISK, REAL PHONE & STORAGE TESTS PASSED.\n";
    return 0;
}
