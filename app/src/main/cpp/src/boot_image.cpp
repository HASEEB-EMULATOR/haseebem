#include "haseeb/boot_image.hpp"
#include "haseeb/compression.hpp"
#include "haseeb/cpio_reader.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>

namespace haseeb::vm {

namespace {

inline constexpr char kBootMagic[8] = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
inline constexpr char kVendorBootMagic[8] = {'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'};
inline constexpr uint32_t kArm64KernelMagic = 0x644D5241u; // "ARM\x64" little-endian at offset 0x38

uint64_t AlignUpU64(uint64_t val, uint64_t align) {
    if (align == 0) return val;
    return (val + align - 1ull) & ~(align - 1ull);
}

uint32_t ReadLE32(const uint8_t* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

uint64_t ReadLE64(const uint8_t* p) {
    uint64_t v = 0;
    std::memcpy(&v, p, 8);
    return v;
}

std::string ReadCStringBounded(const uint8_t* p, size_t max_len) {
    size_t n = 0;
    while (n < max_len && p[n] != 0) {
        ++n;
    }
    return std::string(reinterpret_cast<const char*>(p), n);
}

#pragma pack(push, 1)
// Android boot image header v0/v1/v2 common fields (1660 bytes total up through v2)
struct BootImgHdrV2 {
    uint8_t magic[8];
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t header_version;
    uint32_t os_version;
    uint8_t name[16];
    uint8_t cmdline[512];
    uint32_t id[8];
    uint8_t extra_cmdline[1024];
    // v1 additions
    uint32_t recovery_dtbo_size;
    uint64_t recovery_dtbo_offset;
    uint32_t header_size;
    // v2 addition
    uint32_t dtb_size;
    uint64_t dtb_addr;
};

struct BootImgHdrV3V4 {
    uint8_t magic[8];
    uint32_t kernel_size;
    uint32_t ramdisk_size;
    uint32_t os_version;
    uint32_t header_size;
    uint32_t reserved[4];
    uint32_t header_version;
    uint8_t cmdline[1536];
    // v4 only (total 1584 bytes when signature_size included)
    uint32_t signature_size;
};

struct VendorBootHdrV3V4 {
    uint8_t magic[8];
    uint32_t header_version;
    uint32_t page_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_addr;
    uint32_t vendor_ramdisk_size;
    uint8_t cmdline[2048];
    uint32_t tags_addr;
    uint8_t name[16];
    uint32_t header_size;
    uint32_t dtb_size;
    uint64_t dtb_addr;
    // v4 fields
    uint32_t vendor_ramdisk_table_size;
    uint32_t vendor_ramdisk_table_entry_num;
    uint32_t vendor_ramdisk_table_entry_size;
    uint32_t bootconfig_size;
};
#pragma pack(pop)

bool SliceBytes(const std::vector<uint8_t>& src,
                uint64_t offset,
                uint64_t len,
                std::vector<uint8_t>& dst) {
    if (len == 0) {
        dst.clear();
        return true;
    }
    if (offset > src.size() || len > src.size() - offset) {
        return false;
    }
    dst.assign(src.begin() + static_cast<std::ptrdiff_t>(offset),
               src.begin() + static_cast<std::ptrdiff_t>(offset + len));
    return true;
}

bool ContainsAscii(const std::vector<uint8_t>& hay, const char* needle) {
    size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay.size() < nlen) return false;
    auto it = std::search(hay.begin(), hay.end(), needle, needle + nlen);
    return it != hay.end();
}

} // namespace

Arm64KernelImageInfo BootImageParser::InspectKernelImage(const std::vector<uint8_t>& kernel_bytes) {
    Arm64KernelImageInfo info;
    if (kernel_bytes.size() >= 64u) {
        uint32_t magic = ReadLE32(kernel_bytes.data() + 0x38);
        if (magic == kArm64KernelMagic) {
            info.valid_arm64_magic = true;
            info.text_offset = ReadLE64(kernel_bytes.data() + 0x08);
            info.image_size = ReadLE64(kernel_bytes.data() + 0x10);
            info.flags = ReadLE64(kernel_bytes.data() + 0x18);
            info.compression = KernelCompression::UncompressedArm64Image;
            return info;
        }
    }
    if (kernel_bytes.size() >= 2u && kernel_bytes[0] == 0x1Fu && kernel_bytes[1] == 0x8Bu) {
        info.compression = KernelCompression::Gzip;
    } else if (kernel_bytes.size() >= 4u) {
        uint32_t m = ReadLE32(kernel_bytes.data());
        if (m == 0x184D2204u) {
            info.compression = KernelCompression::Lz4Frame;
        } else if (m == 0x184C2102u || m == 0x184C2103u) {
            info.compression = KernelCompression::Lz4Legacy;
        }
    }
    return info;
}

VmError BootImageParser::DecompressKernelAndInspect(ParsedBootImage& in_out_boot,
                                                    std::string& out_error) {
    if (in_out_boot.kernel.empty()) {
        out_error = "Kernel payload is empty";
        return VmError::GuestKernelInvalid;
    }
    in_out_boot.kernel_info = InspectKernelImage(in_out_boot.kernel);
    if (in_out_boot.kernel_info.valid_arm64_magic) {
        return VmError::Ok;
    }

    ArchiveFormat fmt = ArchiveFormat::Unknown;
    std::vector<uint8_t> decompressed;
    if (!CompressionCodec::DecompressAuto(in_out_boot.kernel, decompressed, fmt, out_error)) {
        return VmError::GuestKernelInvalid;
    }
    if (fmt == ArchiveFormat::Uncompressed || fmt == ArchiveFormat::Unknown) {
        out_error = "Kernel image lacks ARM\\x64 header and is not Gzip/LZ4 compressed";
        return VmError::GuestKernelInvalid;
    }

    Arm64KernelImageInfo info = InspectKernelImage(decompressed);
    if (!info.valid_arm64_magic) {
        out_error = "Decompressed kernel does not contain valid ARM\\x64 Image header";
        return VmError::GuestKernelInvalid;
    }
    in_out_boot.kernel = std::move(decompressed);
    in_out_boot.kernel_info = info;
    return VmError::Ok;
}

VmError BootImageParser::DecompressRamdisk(const std::vector<uint8_t>& ramdisk_bytes,
                                           std::vector<uint8_t>& out_cpio,
                                           std::string& out_error) {
    out_cpio.clear();
    if (ramdisk_bytes.empty()) return VmError::Ok;

    ArchiveFormat fmt = ArchiveFormat::Unknown;
    if (!CompressionCodec::DecompressAuto(ramdisk_bytes, out_cpio, fmt, out_error)) {
        return VmError::InvalidBootImage;
    }
    return VmError::Ok;
}

void BootImageParser::ScanRamdiskForMagisk(ParsedBootImage& boot_img) {
    boot_img.magisk_detected = false;
    boot_img.magisk_evidence.clear();

    const std::vector<uint8_t>& rd = boot_img.ramdisk;
    if (rd.empty()) return;

    std::vector<uint8_t> decompressed;
    ArchiveFormat fmt = ArchiveFormat::Unknown;
    std::string err;
    const std::vector<uint8_t>* scan_buf = &rd;
    if (CompressionCodec::DecompressAuto(rd, decompressed, fmt, err) &&
        (fmt == ArchiveFormat::Gzip || fmt == ArchiveFormat::Lz4Frame || fmt == ArchiveFormat::Lz4Legacy)) {
        scan_buf = &decompressed;
    }

    std::vector<CpioEntry> entries;
    if (CpioArchive::Parse(*scan_buf, entries, err)) {
        if (CpioArchive::FindEntry(entries, "magiskinit") != nullptr) {
            boot_img.magisk_detected = true;
            boot_img.magisk_evidence = "Found 'magiskinit' binary in ramdisk cpio";
            return;
        }
        if (CpioArchive::FindEntry(entries, ".backup/.magisk") != nullptr) {
            boot_img.magisk_detected = true;
            boot_img.magisk_evidence = "Found '.backup/.magisk' config in ramdisk cpio";
            return;
        }
        for (const auto& e : entries) {
            if (e.name.rfind("overlay.d/", 0) == 0) {
                boot_img.magisk_detected = true;
                boot_img.magisk_evidence = "Found 'overlay.d/' Magisk overlay in ramdisk cpio";
                return;
            }
        }
    }

    // Fallback raw scan for compact/synthetic cpio stubs
    if (ContainsAscii(*scan_buf, "magiskinit")) {
        boot_img.magisk_detected = true;
        boot_img.magisk_evidence = "Found 'magiskinit' entry in ramdisk cpio";
        return;
    }
    if (ContainsAscii(*scan_buf, ".backup/.magisk") || ContainsAscii(*scan_buf, "overlay.d/")) {
        boot_img.magisk_detected = true;
        boot_img.magisk_evidence = "Found Magisk .backup/.magisk or overlay.d structure";
        return;
    }
}

VmError BootImageParser::ParseBootFile(const std::string& boot_path,
                                       ParsedBootImage& out_boot,
                                       std::string& out_error) {
    std::ifstream ifs(boot_path, std::ios::binary | std::ios::ate);
    if (!ifs.good()) {
        out_error = "Failed to open boot image: " + boot_path;
        return VmError::FileNotFound;
    }
    std::streamsize sz = ifs.tellg();
    if (sz < 2048) {
        out_error = "Boot image smaller than header size: " + boot_path;
        return VmError::InvalidBootImage;
    }
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(sz));
    if (!ifs.read(reinterpret_cast<char*>(bytes.data()), sz)) {
        out_error = "Failed reading boot image bytes";
        return VmError::IoFailure;
    }
    return ParseBootBytes(bytes, out_boot, out_error);
}

VmError BootImageParser::ParseBootBytes(const std::vector<uint8_t>& bytes,
                                        ParsedBootImage& out_boot,
                                        std::string& out_error) {
    if (bytes.size() < sizeof(BootImgHdrV3V4)) {
        out_error = "Boot image truncated";
        return VmError::InvalidBootImage;
    }
    if (std::memcmp(bytes.data(), kBootMagic, sizeof(kBootMagic)) != 0) {
        out_error = "Missing ANDROID! boot image magic";
        return VmError::InvalidBootImage;
    }

    // Header version resides at byte offset 40 in v0..v4
    uint32_t hdr_ver = ReadLE32(bytes.data() + 40);
    out_boot = ParsedBootImage{};
    out_boot.header_version = hdr_ver;

    if (hdr_ver <= 2u) {
        if (bytes.size() < sizeof(BootImgHdrV2)) {
            out_error = "Boot image v0..v2 header truncated";
            return VmError::InvalidBootImage;
        }
        BootImgHdrV2 hdr{};
        std::memcpy(&hdr, bytes.data(), sizeof(hdr));
        uint32_t pg = hdr.page_size;
        if (pg < 2048u || (pg & (pg - 1u)) != 0u) {
            out_error = "Invalid boot image page_size";
            return VmError::InvalidBootImage;
        }
        out_boot.page_size = pg;
        out_boot.os_version = hdr.os_version;
        out_boot.cmdline = ReadCStringBounded(hdr.cmdline, sizeof(hdr.cmdline));
        std::string extra = ReadCStringBounded(hdr.extra_cmdline, sizeof(hdr.extra_cmdline));
        if (!extra.empty()) {
            if (!out_boot.cmdline.empty()) out_boot.cmdline.push_back(' ');
            out_boot.cmdline += extra;
        }

        uint64_t off = pg; // header occupies 1 page
        if (!SliceBytes(bytes, off, hdr.kernel_size, out_boot.kernel)) {
            out_error = "Kernel section extends past end of boot image";
            return VmError::InvalidBootImage;
        }
        off += AlignUpU64(hdr.kernel_size, pg);

        if (!SliceBytes(bytes, off, hdr.ramdisk_size, out_boot.ramdisk)) {
            out_error = "Ramdisk section extends past end of boot image";
            return VmError::InvalidBootImage;
        }
        off += AlignUpU64(hdr.ramdisk_size, pg);
        off += AlignUpU64(hdr.second_size, pg);
        if (hdr_ver >= 1u) {
            off += AlignUpU64(hdr.recovery_dtbo_size, pg);
        }
        if (hdr_ver >= 2u && hdr.dtb_size > 0) {
            if (!SliceBytes(bytes, off, hdr.dtb_size, out_boot.dtb)) {
                out_error = "DTB section extends past end of boot v2 image";
                return VmError::InvalidBootImage;
            }
        }
    } else if (hdr_ver == 3u || hdr_ver == 4u) {
        BootImgHdrV3V4 hdr{};
        std::memcpy(&hdr, bytes.data(), sizeof(hdr));
        constexpr uint32_t pg = 4096u;
        out_boot.page_size = pg;
        out_boot.os_version = hdr.os_version;
        out_boot.cmdline = ReadCStringBounded(hdr.cmdline, sizeof(hdr.cmdline));

        uint64_t off = pg;
        if (!SliceBytes(bytes, off, hdr.kernel_size, out_boot.kernel)) {
            out_error = "Kernel section extends past end of boot v3/v4 image";
            return VmError::InvalidBootImage;
        }
        off += AlignUpU64(hdr.kernel_size, pg);

        if (!SliceBytes(bytes, off, hdr.ramdisk_size, out_boot.ramdisk)) {
            out_error = "Ramdisk section extends past end of boot v3/v4 image";
            return VmError::InvalidBootImage;
        }
    } else {
        out_error = "Unsupported Android boot header version: " + std::to_string(hdr_ver);
        return VmError::UnsupportedVersion;
    }

    out_boot.kernel_info = InspectKernelImage(out_boot.kernel);
    ScanRamdiskForMagisk(out_boot);
    return VmError::Ok;
}

VmError BootImageParser::MergeVendorBootBytes(const std::vector<uint8_t>& vendor_bytes,
                                              ParsedBootImage& in_out_boot,
                                              std::string& out_error) {
    if (vendor_bytes.size() < sizeof(VendorBootHdrV3V4)) {
        out_error = "vendor_boot image truncated";
        return VmError::InvalidBootImage;
    }
    if (std::memcmp(vendor_bytes.data(), kVendorBootMagic, sizeof(kVendorBootMagic)) != 0) {
        out_error = "Missing VNDRBOOT magic";
        return VmError::InvalidBootImage;
    }

    VendorBootHdrV3V4 hdr{};
    std::memcpy(&hdr, vendor_bytes.data(), sizeof(hdr));
    if (hdr.header_version < 3u || hdr.header_version > 4u) {
        out_error = "Unsupported vendor_boot version";
        return VmError::UnsupportedVersion;
    }
    uint32_t pg = hdr.page_size;
    if (pg < 2048u || (pg & (pg - 1u)) != 0u) {
        out_error = "Invalid vendor_boot page_size";
        return VmError::InvalidBootImage;
    }

    std::string vcmd = ReadCStringBounded(hdr.cmdline, sizeof(hdr.cmdline));
    if (!vcmd.empty()) {
        if (!in_out_boot.cmdline.empty()) in_out_boot.cmdline += " ";
        in_out_boot.cmdline += vcmd;
    }

    uint64_t hdr_pages = AlignUpU64(hdr.header_size, pg);
    uint64_t off = hdr_pages;

    std::vector<uint8_t> vendor_rd;
    if (!SliceBytes(vendor_bytes, off, hdr.vendor_ramdisk_size, vendor_rd)) {
        out_error = "vendor_ramdisk extends past end of vendor_boot";
        return VmError::InvalidBootImage;
    }
    off += AlignUpU64(hdr.vendor_ramdisk_size, pg);

    if (hdr.dtb_size > 0) {
        std::vector<uint8_t> vdtb;
        if (!SliceBytes(vendor_bytes, off, hdr.dtb_size, vdtb)) {
            out_error = "vendor_boot DTB extends past EOF";
            return VmError::InvalidBootImage;
        }
        in_out_boot.dtb = std::move(vdtb);
    }
    off += AlignUpU64(hdr.dtb_size, pg);

    if (hdr.header_version >= 4u) {
        off += AlignUpU64(hdr.vendor_ramdisk_table_size, pg);
        if (hdr.bootconfig_size > 0) {
            std::vector<uint8_t> bc;
            if (SliceBytes(vendor_bytes, off, hdr.bootconfig_size, bc)) {
                in_out_boot.bootconfig.assign(reinterpret_cast<const char*>(bc.data()), bc.size());
            }
        }
    }

    // Bootloader concatenates vendor ramdisk before generic boot/init_boot ramdisk
    if (!vendor_rd.empty()) {
        std::vector<uint8_t> merged;
        merged.reserve(vendor_rd.size() + in_out_boot.ramdisk.size());
        merged.insert(merged.end(), vendor_rd.begin(), vendor_rd.end());
        merged.insert(merged.end(), in_out_boot.ramdisk.begin(), in_out_boot.ramdisk.end());
        in_out_boot.ramdisk = std::move(merged);
    }
    ScanRamdiskForMagisk(in_out_boot);
    return VmError::Ok;
}

VmError BootImageParser::MergeInitBootBytes(const std::vector<uint8_t>& init_boot_bytes,
                                            ParsedBootImage& in_out_boot,
                                            std::string& out_error) {
    ParsedBootImage ib{};
    VmError err = ParseBootBytes(init_boot_bytes, ib, out_error);
    if (err != VmError::Ok) return err;
    if (!ib.ramdisk.empty()) {
        in_out_boot.ramdisk.insert(in_out_boot.ramdisk.end(), ib.ramdisk.begin(), ib.ramdisk.end());
    }
    if (!ib.cmdline.empty()) {
        if (!in_out_boot.cmdline.empty()) in_out_boot.cmdline.push_back(' ');
        in_out_boot.cmdline += ib.cmdline;
    }
    ScanRamdiskForMagisk(in_out_boot);
    return VmError::Ok;
}

} // namespace haseeb::vm
