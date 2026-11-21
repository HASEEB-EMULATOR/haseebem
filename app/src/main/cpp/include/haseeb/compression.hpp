#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

enum class ArchiveFormat {
    Uncompressed,
    Gzip,
    Lz4Frame,
    Lz4Legacy,
    Unknown,
};

// Pure from-scratch C++17 compression/decompression codecs (RFC 1951/1952 Gzip/DEFLATE,
// LZ4 Frame 0x184D2204, and Linux kernel LZ4 Legacy 0x184C2102/0x184C2103).
class CompressionCodec {
public:
    static ArchiveFormat DetectFormat(const uint8_t* data, size_t size);

    static bool DecompressGzip(const uint8_t* data,
                               size_t size,
                               std::vector<uint8_t>& out,
                               std::string& out_error,
                               size_t max_output_bytes = 256u * 1024u * 1024u,
                               size_t* out_consumed = nullptr);

    static bool DecompressLz4Frame(const uint8_t* data,
                                   size_t size,
                                   std::vector<uint8_t>& out,
                                   std::string& out_error,
                                   size_t max_output_bytes = 256u * 1024u * 1024u,
                                   size_t* out_consumed = nullptr);

    static bool DecompressLz4Legacy(const uint8_t* data,
                                    size_t size,
                                    std::vector<uint8_t>& out,
                                    std::string& out_error,
                                    size_t max_output_bytes = 256u * 1024u * 1024u,
                                    size_t* out_consumed = nullptr);

    // Auto-decompresses single or concatenated mixed-format streams (Gzip/LZ4/raw CPIO overlays).
    // If input is already uncompressed, copies it to `out` and sets format = Uncompressed.
    static bool DecompressAuto(const std::vector<uint8_t>& input,
                               std::vector<uint8_t>& out,
                               ArchiveFormat& out_format,
                               std::string& out_error,
                               size_t max_output_bytes = 256u * 1024u * 1024u);

    // Valid Gzip (RFC 1952) and LZ4 Frame / Legacy encoders for M4 testing & M7 repacking
    static std::vector<uint8_t> CompressGzip(const uint8_t* data, size_t size);
    static std::vector<uint8_t> CompressLz4Frame(const uint8_t* data, size_t size);
    static std::vector<uint8_t> CompressLz4Legacy(const uint8_t* data, size_t size);

    static uint32_t Crc32(const uint8_t* data, size_t size);
};

} // namespace haseeb::vm
