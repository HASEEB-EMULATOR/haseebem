#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

struct EngineRomBuildResult {
    bool ok = false;
    std::string boot_img_path;
    std::string system_img_path;
    uint64_t boot_img_size = 0;
    uint64_t system_img_size = 0;
    uint32_t ramdisk_entries = 0;
    uint32_t system_files = 0;
    bool magisk_patched = false;
    std::string magisk_version = "27.0 (27000)";
    std::string android_version = "11";
    int api_level = 30;
    std::string error;
};

// Pure C++17 generator for Haseeb Engine's native AArch64 Android 11 (API 30)
// Magisk v27.0 pre-patched ROM (boot.img v2 + 4 KiB-block ext4 system.img).
// Every guest binary (/magiskinit, /system/bin/init, ueventd, servicemanager,
// zygote64, system_server, surfaceflinger) contains real executable AArch64
// machine code running at EL0 on AArch64CpuCore.
class EngineRomBuilder {
public:
    static EngineRomBuildResult BuildMagiskAndroidRom(const std::string& output_dir);
};

} // namespace haseeb::vm
