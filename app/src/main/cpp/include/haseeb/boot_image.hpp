#pragma once

#include "haseeb/vm_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

enum class KernelCompression {
    UncompressedArm64Image,
    Gzip,
    Lz4Legacy,
    Lz4Frame,
    Unknown,
};

struct Arm64KernelImageInfo {
    bool valid_arm64_magic = false;
    uint64_t text_offset = 0x80000ULL;
    uint64_t image_size = 0;
    uint64_t flags = 0;
    KernelCompression compression = KernelCompression::Unknown;
};

struct ParsedBootImage {
    uint32_t header_version = 0;
    uint32_t page_size = 4096;
    uint32_t os_version = 0;
    std::string cmdline;
    std::string bootconfig;
    std::vector<uint8_t> kernel;
    std::vector<uint8_t> ramdisk;
    std::vector<uint8_t> dtb;
    Arm64KernelImageInfo kernel_info;
    bool magisk_detected = false;
    std::string magisk_evidence;
};

// From-scratch parser for Android boot images (v0, v1, v2, v3, v4),
// init_boot (v3/v4), and vendor_boot (v3/v4).
class BootImageParser {
public:
    static VmError ParseBootFile(const std::string& boot_path,
                                 ParsedBootImage& out_boot,
                                 std::string& out_error);

    static VmError ParseBootBytes(const std::vector<uint8_t>& bytes,
                                  ParsedBootImage& out_boot,
                                  std::string& out_error);

    static VmError MergeVendorBootBytes(const std::vector<uint8_t>& vendor_bytes,
                                        ParsedBootImage& in_out_boot,
                                        std::string& out_error);

    static VmError MergeInitBootBytes(const std::vector<uint8_t>& init_boot_bytes,
                                      ParsedBootImage& in_out_boot,
                                      std::string& out_error);

    static Arm64KernelImageInfo InspectKernelImage(const std::vector<uint8_t>& kernel_bytes);
    static VmError DecompressKernelAndInspect(ParsedBootImage& in_out_boot, std::string& out_error);
    static VmError DecompressRamdisk(const std::vector<uint8_t>& ramdisk_bytes,
                                     std::vector<uint8_t>& out_cpio,
                                     std::string& out_error);
    static void ScanRamdiskForMagisk(ParsedBootImage& boot_img);
};

} // namespace haseeb::vm
