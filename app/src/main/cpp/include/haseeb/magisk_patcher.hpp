#pragma once

#include "haseeb/boot_image.hpp"
#include "haseeb/vm_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

struct MagiskPatchOptions {
    static constexpr const char* kValidatedRelease = "Magisk v27.0 (27000) arm64-v8a";

    bool keep_verity = false;
    bool keep_force_encrypt = false;
    bool recovery_mode = false;
    std::string magisk_version = "27.0";
    uint32_t magisk_version_code = 27000u;
    std::string preinit_device = "userdata";
    std::string extra_overlay_rc;

    // Optional caller-supplied arm64 binaries (from Magisk v27.0 APK); when empty,
    // BootImagePatcher synthesizes minimal AArch64 ELF64 magiskinit / su runners.
    std::vector<uint8_t> custom_magiskinit;
    std::vector<uint8_t> custom_su;
};

struct MagiskPatchResult {
    bool ok = false;
    VmError error_code = VmError::Ok;
    uint32_t source_header_version = 0;
    uint32_t patched_header_version = 0;
    uint32_t original_ramdisk_entries = 0;
    uint32_t patched_ramdisk_entries = 0;
    bool verified = false;
    std::string verification_summary;
    std::string error;
    std::vector<uint8_t> patched_image;
};

// Pure C++17 host-side Android boot image (v2/v3/v4) Magisk patcher & verifier.
// Validated against Magisk v27.0 (27000) ramdisk layout:
//   unpack -> preserve /.backup/init -> inject /magiskinit, /.backup/.magisk,
//   /overlay.d/init.magisk.rc & /sbin/su -> gzip repack -> verify headers & CPIO.
class BootImagePatcher {
public:
    static MagiskPatchResult PatchBootBytes(const std::vector<uint8_t>& stock_boot_bytes,
                                            const MagiskPatchOptions& opts = MagiskPatchOptions{});

    static MagiskPatchResult PatchBootFile(const std::string& input_boot_path,
                                           const std::string& output_boot_path,
                                           const MagiskPatchOptions& opts = MagiskPatchOptions{});

    static std::vector<uint8_t> BuildDefaultMagiskInitElf();
    static std::vector<uint8_t> BuildDefaultSuElf();
};

} // namespace haseeb::vm
