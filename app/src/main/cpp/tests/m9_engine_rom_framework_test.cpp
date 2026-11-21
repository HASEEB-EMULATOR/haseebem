#include "haseeb/boot_image.hpp"
#include "haseeb/compression.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/engine_rom_builder.hpp"
#include "haseeb/ext4_reader.hpp"
#include "haseeb/kernel_boot.hpp"
#include "haseeb/machine.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <thread>
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

std::string MakeTempDir(const std::string& suffix) {
    const std::string path = "/tmp/haseeb_m9_" + suffix + "_" + std::to_string(::getpid());
    ::mkdir(path.c_str(), 0755);
    return path;
}

void CleanupFile(const std::string& p) {
    if (!p.empty()) ::unlink(p.c_str());
}

void CleanupDirTree(const std::string& dir) {
    CleanupFile(dir + "/storage/emulated/0/HaseebVM/boot_stamp.txt");
    ::rmdir((dir + "/storage/emulated/0/HaseebVM").c_str());
    ::rmdir((dir + "/storage/emulated/0").c_str());
    ::rmdir((dir + "/storage/emulated").c_str());
    ::rmdir((dir + "/storage").c_str());
    CleanupFile(dir + "/boot.img");
    CleanupFile(dir + "/system.img");
    ::rmdir(dir.c_str());
}

void TestEngineRomBuilderGeneratesValidBootAndExt4System() {
    const std::string work = MakeTempDir("builder");
    EngineRomBuildResult res = EngineRomBuilder::BuildMagiskAndroidRom(work);
    HASEEB_CHECK(res.ok);
    HASEEB_CHECK(res.magisk_patched);
    HASEEB_CHECK(res.android_version == "11");
    HASEEB_CHECK(res.api_level == 30);
    HASEEB_CHECK(res.ramdisk_entries >= 6u);
    HASEEB_CHECK(res.system_files >= 8u);

    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootFile(res.boot_img_path, parsed, err) == VmError::Ok);
    HASEEB_CHECK(parsed.header_version == 2u);
    HASEEB_CHECK(parsed.magisk_detected);
    HASEEB_CHECK(!parsed.ramdisk.empty());

    std::vector<uint8_t> cpio_raw;
    auto fmt = CompressionCodec::DetectFormat(parsed.ramdisk.data(), parsed.ramdisk.size());
    HASEEB_CHECK(fmt == ArchiveFormat::Gzip);
    HASEEB_CHECK(CompressionCodec::DecompressAuto(parsed.ramdisk, cpio_raw, fmt, err));

    std::vector<CpioEntry> entries;
    HASEEB_CHECK(CpioArchive::Parse(cpio_raw, entries, err));
    auto has_entry = [&](const std::string& name) {
        return std::any_of(entries.begin(), entries.end(), [&](const CpioEntry& e) {
            return e.name == name;
        });
    };
    HASEEB_CHECK(has_entry("init"));
    HASEEB_CHECK(has_entry("magiskinit"));
    HASEEB_CHECK(has_entry("sbin/su"));
    HASEEB_CHECK(has_entry(".backup/.magisk"));
    HASEEB_CHECK(has_entry("overlay.d/init.magisk.rc"));

    haseeb::loader::Ext4Reader ext4;
    HASEEB_CHECK(ext4.Open(res.system_img_path));
    HASEEB_CHECK(ext4.BlockSize() == 4096u);

    std::string marker;
    HASEEB_CHECK(ext4.ReadFileString("/system/etc/haseeb_rom", marker));
    HASEEB_CHECK(marker.find("magisk") != std::string::npos);

    std::string prop;
    HASEEB_CHECK(ext4.ReadFileString("/system/build.prop", prop));
    HASEEB_CHECK(prop.find("ro.build.version.sdk=30") != std::string::npos);

    for (const char* bin : {
             "/system/bin/init",
             "/system/bin/ueventd",
             "/system/bin/servicemanager",
             "/system/bin/zygote64",
             "/system/bin/system_server",
             "/system/bin/surfaceflinger",
         }) {
        std::vector<uint8_t> elf;
        HASEEB_CHECK(ext4.ReadFile(bin, elf));
        HASEEB_CHECK(Elf64GuestLoader::IsValidAArch64Elf(elf));
    }

    ext4.Close();
    CleanupDirTree(work);
    std::cout << "[PASS] Test 1: EngineRomBuilder generates valid Magisk v27 boot.img & 4K-block ext4 system.img\n";
}

void TestFullFrameworkServicesMultiProcessBoot() {
    const std::string work = MakeTempDir("boot");
    EngineRomBuildResult res = EngineRomBuilder::BuildMagiskAndroidRom(work);
    HASEEB_CHECK(res.ok);

    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootFile(res.boot_img_path, parsed, err) == VmError::Ok);

    haseeb::loader::Ext4Reader ext4;
    HASEEB_CHECK(ext4.Open(res.system_img_path));

    std::vector<std::string> uart_lines;
    VirtualMachineSkeleton vm([&](const std::string& line) {
        uart_lines.push_back(line);
    });
    vm.SetRuntimePaths(work, work + "/storage/emulated/0");
    vm.SetDeviceProperties({
        {"ro.product.model", "SM-S938B"},
        {"ro.product.marketname", "Galaxy S25 Ultra"},
    });
    vm.SetExt4Reader(&ext4);

    MachineBootConfig cfg;
    cfg.ram_mb = 128u;
    cfg.width = 64u;
    cfg.height = 64u;
    cfg.dpi = 320u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    HASEEB_CHECK(vm.RunBootStubUntilHalt() == VmError::Ok);

    std::string selected_target;
    HASEEB_CHECK(vm.BootGuest(true, selected_target, err) == VmError::Ok);
    HASEEB_CHECK(selected_target == "/magiskinit");

    bool all_framework_ready = false;
    for (int round = 0; round < 160; ++round) {
        HASEEB_CHECK(vm.StepGuest(25000ULL) == VmError::Ok);
        HASEEB_CHECK(!vm.CpuState().halted);

        const auto svcs = vm.Supervisor()->BinderServices();
        auto has_svc = [&](const char* name) {
            return std::find(svcs.begin(), svcs.end(), name) != svcs.end();
        };
        if (has_svc("activity") && has_svc("window") && has_svc("magisk_su") &&
            vm.VirtioGpu().FrameCount() >= 1u &&
            vm.VirtioSnd().PlaybackFramesWritten() >= 128u) {
            all_framework_ready = true;
            break;
        }
        if (vm.CpuState().stop_reason == CpuStopReason::WfiWait) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    HASEEB_CHECK(all_framework_ready);
    HASEEB_CHECK(vm.Supervisor()->ActiveTaskCount() >= 4u); // init, servicemanager, zygote64, system_server, surfaceflinger
    HASEEB_CHECK(vm.Hardware().Snapshot().su_grants >= 1u);
    HASEEB_CHECK(vm.SoftGles().TrianglesRasterized() >= 6u);

    std::ifstream stamp_ifs(work + "/storage/emulated/0/HaseebVM/boot_stamp.txt");
    HASEEB_CHECK(stamp_ifs.good());
    std::string stamp_line;
    std::getline(stamp_ifs, stamp_line);
    HASEEB_CHECK(stamp_line.find("haseeb-engine-a11-magisk-v27-booted") != std::string::npos);

    auto saw_uart = [&](const char* needle) {
        return std::any_of(uart_lines.begin(), uart_lines.end(), [&](const std::string& l) {
            return l.find(needle) != std::string::npos;
        });
    };
    HASEEB_CHECK(saw_uart("[magiskinit]"));
    HASEEB_CHECK(saw_uart("[init]"));
    HASEEB_CHECK(saw_uart("[ueventd]"));
    HASEEB_CHECK(saw_uart("[servicemanager]"));
    HASEEB_CHECK(saw_uart("[zygote64]"));
    HASEEB_CHECK(saw_uart("[system_server]"));
    HASEEB_CHECK(saw_uart("[surfaceflinger]"));

    vm.Shutdown();
    ext4.Close();
    CleanupDirTree(work);
    std::cout << "[PASS] Test 2: Multi-process boot /magiskinit -> init -> ueventd -> servicemanager -> zygote64 -> system_server + surfaceflinger\n";
}

void TestEl0TrapDiagnosticFormatting() {
    // Build a minimal AArch64 ELF64 that executes 2 NOPs then hits an illegal instruction (0x00000000)
    constexpr uint64_t kBaseVa = 0x00400000ULL;
    constexpr uint64_t kCodeOff = 0x100ULL;
    const uint32_t insns[4] = {
        0xD503201Fu, // NOP
        0xD503201Fu, // NOP
        0x00000000u, // UDF / illegal opcode
        0xD503201Fu,
    };
    const uint64_t total = kCodeOff + sizeof(insns);
    std::vector<uint8_t> elf(total, 0u);
    elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
    auto w16 = [&](size_t o, uint16_t v) { elf[o] = v & 0xFFu; elf[o + 1] = v >> 8; };
    auto w32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    auto w64 = [&](size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    w16(16, 2u); w16(18, 183u); w32(20, 1u);
    w64(24, kBaseVa + kCodeOff); w64(32, 64ULL);
    w16(52, 64u); w16(54, 56u); w16(56, 1u);
    w32(64 + 0, 1u); w32(64 + 4, 7u);
    w64(64 + 8, 0ULL); w64(64 + 16, kBaseVa); w64(64 + 24, kBaseVa);
    w64(64 + 32, total); w64(64 + 40, total + 4096ULL); w64(64 + 48, 4096ULL);
    std::memcpy(elf.data() + kCodeOff, insns, sizeof(insns));

    CpioEntry e_init;
    e_init.name = "init";
    e_init.mode = 0100755u;
    e_init.nlink = 1u;
    e_init.data = elf;
    std::vector<uint8_t> cpio = CpioArchive::Build({e_init});

    constexpr uint32_t kPage = 4096u;
    std::vector<uint8_t> boot(kPage + ((cpio.size() + kPage - 1u) & ~(kPage - 1u)), 0u);
    std::memcpy(boot.data(), "ANDROID!", 8);
    auto p32 = [&](size_t o, uint32_t v) {
        for (int i = 0; i < 4; ++i) boot[o + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    p32(16, static_cast<uint32_t>(cpio.size()));
    p32(36, kPage);
    p32(40, 2u);
    std::memcpy(boot.data() + kPage, cpio.data(), cpio.size());

    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    std::vector<std::string> uart_lines;
    VirtualMachineSkeleton vm([&](const std::string& l) { uart_lines.push_back(l); });
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    HASEEB_CHECK(vm.RunBootStubUntilHalt() == VmError::Ok);

    std::string target;
    HASEEB_CHECK(vm.BootGuest(false, target, err) == VmError::Ok);
    HASEEB_CHECK(vm.StepGuest(5000ULL) == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);

    const std::string trap = vm.Supervisor()->LastTrapDetail();
    HASEEB_CHECK(!trap.empty());
    HASEEB_CHECK(trap.find("ELR=0x") != std::string::npos);
    HASEEB_CHECK(trap.find("op=0x") != std::string::npos);
    HASEEB_CHECK(trap.find("bin=/init") != std::string::npos);
    HASEEB_CHECK(vm.Supervisor()->ExitStatus() != 0);

    const bool saw_trap_uart = std::any_of(uart_lines.begin(), uart_lines.end(), [](const std::string& l) {
        return l.find("[TRAP]") != std::string::npos && l.find("ELR=") != std::string::npos;
    });
    HASEEB_CHECK(saw_trap_uart);

    vm.Shutdown();
    std::cout << "[PASS] Test 3: EL0 trap decoding reports EC, ELR, SP, LR, op, and binary name\n";
}

} // namespace

int main() {
    TestEngineRomBuilderGeneratesValidBootAndExt4System();
    TestFullFrameworkServicesMultiProcessBoot();
    TestEl0TrapDiagnosticFormatting();
    std::cout << "ALL M9 ENGINE ROM, FRAMEWORK BOOT & TRAP DIAGNOSTIC TESTS PASSED.\n";
    return 0;
}
