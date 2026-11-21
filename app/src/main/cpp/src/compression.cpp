#include "haseeb/compression.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_map>

namespace haseeb::vm {

namespace {

uint32_t ReadLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint16_t ReadLE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

void WriteLE16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

void WriteLE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

// =========================================================================
// RFC 1951 DEFLATE Bitstream & Huffman Decoder
// =========================================================================
struct BitReader {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t byte_pos = 0;
    uint64_t bit_buf = 0;
    unsigned bit_cnt = 0;

    bool Ensure(unsigned n) {
        while (bit_cnt < n) {
            if (byte_pos >= size) return false;
            bit_buf |= static_cast<uint64_t>(data[byte_pos++]) << bit_cnt;
            bit_cnt += 8u;
        }
        return true;
    }

    bool ReadBits(unsigned n, uint32_t& out) {
        if (n == 0u) {
            out = 0u;
            return true;
        }
        if (!Ensure(n)) return false;
        out = static_cast<uint32_t>(bit_buf & ((1ULL << n) - 1ULL));
        bit_buf >>= n;
        bit_cnt -= n;
        return true;
    }

    void AlignToByte() {
        unsigned drop = bit_cnt & 7u;
        bit_buf >>= drop;
        bit_cnt -= drop;
    }

    bool ReadAlignedBytes(uint8_t* dst, size_t n) {
        AlignToByte();
        while (n > 0 && bit_cnt >= 8u) {
            *dst++ = static_cast<uint8_t>(bit_buf & 0xFFu);
            bit_buf >>= 8;
            bit_cnt -= 8u;
            --n;
        }
        if (n > size - byte_pos) return false;
        if (n > 0) {
            std::memcpy(dst, data + byte_pos, n);
            byte_pos += n;
        }
        return true;
    }

    size_t BytesConsumed() const {
        return byte_pos - (bit_cnt / 8u);
    }
};

struct HuffmanTree {
    static constexpr unsigned kMaxBits = 15;
    std::array<uint16_t, kMaxBits + 1> count{};
    std::array<uint16_t, 320> symbols{};
    uint16_t max_len = 0;

    bool Build(const uint8_t* lengths, size_t num_syms) {
        count.fill(0);
        symbols.fill(0);
        max_len = 0;
        for (size_t i = 0; i < num_syms; ++i) {
            if (lengths[i] > kMaxBits) return false;
            count[lengths[i]]++;
            if (lengths[i] > max_len) max_len = lengths[i];
        }
        if (max_len == 0) return true;

        std::array<uint16_t, kMaxBits + 1> offsets{};
        int left = 1;
        for (unsigned len = 1; len <= kMaxBits; ++len) {
            left <<= 1;
            left -= count[len];
            if (left < 0) return false;
        }
        uint16_t acc = 0;
        for (unsigned len = 1; len <= kMaxBits; ++len) {
            offsets[len] = acc;
            acc = static_cast<uint16_t>(acc + count[len]);
        }
        for (size_t sym = 0; sym < num_syms; ++sym) {
            uint8_t len = lengths[sym];
            if (len != 0u) {
                symbols[offsets[len]++] = static_cast<uint16_t>(sym);
            }
        }
        return true;
    }

    bool Decode(BitReader& br, uint16_t& out_sym) const {
        int code = 0;
        int first = 0;
        int index = 0;
        for (unsigned len = 1; len <= kMaxBits; ++len) {
            uint32_t bit = 0;
            if (!br.ReadBits(1u, bit)) return false;
            code |= static_cast<int>(bit);
            int c = count[len];
            if (code - c < first) {
                out_sym = symbols[static_cast<size_t>(index + (code - first))];
                return true;
            }
            index += c;
            first += c;
            first <<= 1;
            code <<= 1;
        }
        return false;
    }
};

bool InflateDeflateStream(BitReader& br,
                          std::vector<uint8_t>& out,
                          size_t max_output_bytes,
                          std::string& out_error) {
    static constexpr uint16_t kLenBase[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static constexpr uint8_t kLenExtra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static constexpr uint16_t kDistBase[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    };
    static constexpr uint8_t kDistExtra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };
    static constexpr uint8_t kCodeOrder[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    };

    const size_t initial_out = out.size();
    uint32_t bfinal = 0;

    do {
        uint32_t btype = 0;
        if (!br.ReadBits(1u, bfinal) || !br.ReadBits(2u, btype)) {
            out_error = "Truncated DEFLATE block header";
            return false;
        }

        if (btype == 0u) {
            // Uncompressed stored block
            uint8_t hdr[4]{};
            if (!br.ReadAlignedBytes(hdr, 4u)) {
                out_error = "Truncated stored DEFLATE header";
                return false;
            }
            uint16_t len = ReadLE16(hdr);
            uint16_t nlen = ReadLE16(hdr + 2);
            if (static_cast<uint16_t>(len ^ 0xFFFFu) != nlen) {
                out_error = "Corrupt stored DEFLATE LEN/NLEN mismatch";
                return false;
            }
            if ((out.size() - initial_out) + len > max_output_bytes) {
                out_error = "Decompressed DEFLATE output exceeds limit";
                return false;
            }
            size_t old_sz = out.size();
            out.resize(old_sz + len);
            if (!br.ReadAlignedBytes(out.data() + old_sz, len)) {
                out_error = "Truncated stored DEFLATE payload";
                return false;
            }
            continue;
        }

        if (btype == 3u) {
            out_error = "Invalid DEFLATE block type 3";
            return false;
        }

        HuffmanTree lit_tree;
        HuffmanTree dist_tree;

        if (btype == 1u) {
            std::array<uint8_t, 288> lit_lens{};
            for (size_t i = 0; i <= 143; ++i) lit_lens[i] = 8u;
            for (size_t i = 144; i <= 255; ++i) lit_lens[i] = 9u;
            for (size_t i = 256; i <= 279; ++i) lit_lens[i] = 7u;
            for (size_t i = 280; i <= 287; ++i) lit_lens[i] = 8u;
            std::array<uint8_t, 32> dist_lens{};
            dist_lens.fill(5u);
            if (!lit_tree.Build(lit_lens.data(), 288u) || !dist_tree.Build(dist_lens.data(), 32u)) {
                out_error = "Failed building fixed Huffman tables";
                return false;
            }
        } else {
            uint32_t hlit = 0, hdist = 0, hclen = 0;
            if (!br.ReadBits(5u, hlit) || !br.ReadBits(5u, hdist) || !br.ReadBits(4u, hclen)) {
                out_error = "Truncated dynamic Huffman table header";
                return false;
            }
            hlit += 257u;
            hdist += 1u;
            hclen += 4u;
            if (hlit > 286u || hdist > 30u) {
                out_error = "Invalid dynamic Huffman alphabet size";
                return false;
            }

            std::array<uint8_t, 19> cl_lens{};
            for (uint32_t i = 0; i < hclen; ++i) {
                uint32_t v = 0;
                if (!br.ReadBits(3u, v)) {
                    out_error = "Truncated code-length alphabet";
                    return false;
                }
                cl_lens[kCodeOrder[i]] = static_cast<uint8_t>(v);
            }
            HuffmanTree cl_tree;
            if (!cl_tree.Build(cl_lens.data(), 19u)) {
                out_error = "Invalid dynamic code-length Huffman tree";
                return false;
            }

            std::vector<uint8_t> all_lens(hlit + hdist, 0u);
            size_t idx = 0;
            while (idx < all_lens.size()) {
                uint16_t sym = 0;
                if (!cl_tree.Decode(br, sym)) {
                    out_error = "Truncated dynamic length stream";
                    return false;
                }
                if (sym < 16u) {
                    all_lens[idx++] = static_cast<uint8_t>(sym);
                } else {
                    uint8_t rep_val = 0;
                    uint32_t rep_cnt = 0;
                    uint32_t extra = 0;
                    if (sym == 16u) {
                        if (idx == 0u || !br.ReadBits(2u, extra)) {
                            out_error = "Invalid dynamic repeat code 16";
                            return false;
                        }
                        rep_val = all_lens[idx - 1u];
                        rep_cnt = 3u + extra;
                    } else if (sym == 17u) {
                        if (!br.ReadBits(3u, extra)) {
                            out_error = "Truncated dynamic repeat code 17";
                            return false;
                        }
                        rep_cnt = 3u + extra;
                    } else {
                        if (!br.ReadBits(7u, extra)) {
                            out_error = "Truncated dynamic repeat code 18";
                            return false;
                        }
                        rep_cnt = 11u + extra;
                    }
                    if (idx + rep_cnt > all_lens.size()) {
                        out_error = "Dynamic Huffman length overrun";
                        return false;
                    }
                    for (uint32_t r = 0; r < rep_cnt; ++r) {
                        all_lens[idx++] = rep_val;
                    }
                }
            }
            if (!lit_tree.Build(all_lens.data(), hlit) ||
                !dist_tree.Build(all_lens.data() + hlit, hdist)) {
                out_error = "Invalid dynamic Huffman trees";
                return false;
            }
        }

        // Decode compressed symbols
        for (;;) {
            uint16_t sym = 0;
            if (!lit_tree.Decode(br, sym)) {
                out_error = "Truncated DEFLATE symbol";
                return false;
            }
            if (sym < 256u) {
                if ((out.size() - initial_out) + 1u > max_output_bytes) {
                    out_error = "Decompressed DEFLATE output exceeds limit";
                    return false;
                }
                out.push_back(static_cast<uint8_t>(sym));
            } else if (sym == 256u) {
                break; // End of block
            } else {
                uint32_t lidx = sym - 257u;
                if (lidx >= 29u) {
                    out_error = "Invalid DEFLATE length code";
                    return false;
                }
                uint32_t extra_l = 0;
                if (!br.ReadBits(kLenExtra[lidx], extra_l)) {
                    out_error = "Truncated DEFLATE length extra bits";
                    return false;
                }
                uint32_t match_len = kLenBase[lidx] + extra_l;

                uint16_t dsym = 0;
                if (!dist_tree.Decode(br, dsym) || dsym >= 30u) {
                    out_error = "Invalid or truncated DEFLATE distance code";
                    return false;
                }
                uint32_t extra_d = 0;
                if (!br.ReadBits(kDistExtra[dsym], extra_d)) {
                    out_error = "Truncated DEFLATE distance extra bits";
                    return false;
                }
                uint32_t dist = kDistBase[dsym] + extra_d;
                if (dist == 0u || dist > out.size() - initial_out) {
                    out_error = "DEFLATE match distance precedes stream start";
                    return false;
                }
                if ((out.size() - initial_out) + match_len > max_output_bytes) {
                    out_error = "Decompressed DEFLATE output exceeds limit";
                    return false;
                }
                // Copy byte-by-byte to support overlapping RLE matches
                for (uint32_t k = 0; k < match_len; ++k) {
                    uint8_t b = out[out.size() - dist];
                    out.push_back(b);
                }
            }
        }
    } while (bfinal == 0u);

    br.AlignToByte();
    return true;
}

// =========================================================================
// LZ4 Block Decompressor
// =========================================================================
bool DecompressLz4Block(const uint8_t* src,
                        size_t src_len,
                        std::vector<uint8_t>& out,
                        size_t hist_base,
                        size_t max_output_bytes,
                        std::string& out_error) {
    size_t pos = 0;
    while (pos < src_len) {
        uint8_t token = src[pos++];
        size_t lit_len = (token >> 4) & 0xFu;
        if (lit_len == 15u) {
            uint8_t add = 0;
            do {
                if (pos >= src_len) {
                    out_error = "Truncated LZ4 literal length";
                    return false;
                }
                add = src[pos++];
                lit_len += add;
            } while (add == 255u);
        }

        if (lit_len > src_len - pos) {
            out_error = "Truncated LZ4 literals";
            return false;
        }
        if ((out.size() - hist_base) + lit_len > max_output_bytes) {
            out_error = "LZ4 decompressed block exceeds memory limit";
            return false;
        }
        out.insert(out.end(), src + pos, src + pos + lit_len);
        pos += lit_len;

        // End of LZ4 block always ends with a literals-only sequence
        if (pos >= src_len) break;

        if (src_len - pos < 2u) {
            out_error = "Truncated LZ4 match offset";
            return false;
        }
        uint16_t offset = ReadLE16(src + pos);
        pos += 2u;
        if (offset == 0u || offset > (out.size() - hist_base)) {
            out_error = "Invalid LZ4 match offset";
            return false;
        }

        size_t match_len = (token & 0xFu) + 4u;
        if ((token & 0xFu) == 15u) {
            uint8_t add = 0;
            do {
                if (pos >= src_len) {
                    out_error = "Truncated LZ4 match length";
                    return false;
                }
                add = src[pos++];
                match_len += add;
            } while (add == 255u);
        }

        if ((out.size() - hist_base) + match_len > max_output_bytes) {
            out_error = "LZ4 decompressed match exceeds memory limit";
            return false;
        }
        for (size_t k = 0; k < match_len; ++k) {
            uint8_t b = out[out.size() - offset];
            out.push_back(b);
        }
    }
    return true;
}

uint32_t XxHash32HeaderChecksum(const uint8_t* data, size_t len) {
    static constexpr uint32_t kP1 = 0x9E3779B1u;
    static constexpr uint32_t kP2 = 0x85EBCA77u;
    static constexpr uint32_t kP3 = 0xC2B2AE3Du;
    static constexpr uint32_t kP4 = 0x27D4EB2Fu;
    static constexpr uint32_t kP5 = 0x165667B1u;
    auto rotl = [](uint32_t x, unsigned r) { return (x << r) | (x >> (32u - r)); };

    uint32_t h = kP5 + static_cast<uint32_t>(len);
    size_t i = 0;
    while (i + 4u <= len) {
        h += ReadLE32(data + i) * kP3;
        h = rotl(h, 17u) * kP4;
        i += 4u;
    }
    while (i < len) {
        h += static_cast<uint32_t>(data[i++]) * kP5;
        h = rotl(h, 11u) * kP1;
    }
    h ^= h >> 15;
    h *= kP2;
    h ^= h >> 13;
    h *= kP3;
    h ^= h >> 16;
    return h;
}

} // namespace

uint32_t CompressionCodec::Crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = (crc & 1u) ? 0xEDB88320u : 0u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

ArchiveFormat CompressionCodec::DetectFormat(const uint8_t* data, size_t size) {
    if (!data || size < 2u) return ArchiveFormat::Unknown;
    if (data[0] == 0x1Fu && data[1] == 0x8Bu) return ArchiveFormat::Gzip;
    if (size >= 4u) {
        uint32_t m = ReadLE32(data);
        if (m == 0x184D2204u) return ArchiveFormat::Lz4Frame;
        if (m == 0x184C2102u || m == 0x184C2103u) return ArchiveFormat::Lz4Legacy;
        if ((m & 0xFFFFFFF0u) == 0x184D2A50u) return ArchiveFormat::Lz4Frame;
    }
    if (size >= 6u && (std::memcmp(data, "070701", 6) == 0 || std::memcmp(data, "070702", 6) == 0)) {
        return ArchiveFormat::Uncompressed;
    }
    if (size >= 0x40u && ReadLE32(data + 0x38) == 0x644D5241u) {
        return ArchiveFormat::Uncompressed;
    }
    return ArchiveFormat::Unknown;
}

bool CompressionCodec::DecompressGzip(const uint8_t* data,
                                      size_t size,
                                      std::vector<uint8_t>& out,
                                      std::string& out_error,
                                      size_t max_output_bytes,
                                      size_t* out_consumed) {
    out.clear();
    size_t pos = 0;
    while (pos < size) {
        if (size - pos < 18u || data[pos] != 0x1Fu || data[pos + 1] != 0x8Bu || data[pos + 2] != 8u) {
            if (!out.empty()) {
                if (out_consumed) {
                    *out_consumed = pos;
                    return true;
                }
                if (data[pos] == 0u) break;
            }
            out_error = "Invalid Gzip member header";
            return false;
        }
        uint8_t flg = data[pos + 3];
        pos += 10u;

        if (flg & 0x04u) { // FEXTRA
            if (size - pos < 2u) { out_error = "Truncated Gzip FEXTRA"; return false; }
            uint16_t xlen = ReadLE16(data + pos);
            pos += 2u;
            if (xlen > size - pos) { out_error = "Truncated Gzip FEXTRA payload"; return false; }
            pos += xlen;
        }
        if (flg & 0x08u) { // FNAME
            while (pos < size && data[pos] != 0u) ++pos;
            if (pos >= size) { out_error = "Unterminated Gzip FNAME"; return false; }
            ++pos;
        }
        if (flg & 0x10u) { // FCOMMENT
            while (pos < size && data[pos] != 0u) ++pos;
            if (pos >= size) { out_error = "Unterminated Gzip FCOMMENT"; return false; }
            ++pos;
        }
        if (flg & 0x02u) { // FHCRC
            if (size - pos < 2u) { out_error = "Truncated Gzip FHCRC"; return false; }
            pos += 2u;
        }

        const size_t member_out_start = out.size();
        BitReader br{data + pos, size - pos, 0, 0, 0};
        if (!InflateDeflateStream(br, out, max_output_bytes - member_out_start, out_error)) {
            return false;
        }
        pos += br.BytesConsumed();
        if (size - pos < 8u) {
            out_error = "Truncated Gzip CRC32/ISIZE trailer";
            return false;
        }
        uint32_t expected_crc = ReadLE32(data + pos);
        uint32_t expected_isize = ReadLE32(data + pos + 4u);
        pos += 8u;

        const size_t member_len = out.size() - member_out_start;
        uint32_t actual_crc = Crc32(out.data() + member_out_start, member_len);
        if (actual_crc != expected_crc) {
            out_error = "Gzip CRC-32 mismatch";
            return false;
        }
        if (static_cast<uint32_t>(member_len & 0xFFFFFFFFULL) != expected_isize) {
            out_error = "Gzip ISIZE mismatch";
            return false;
        }
    }
    if (out_consumed) *out_consumed = pos;
    return true;
}

bool CompressionCodec::DecompressLz4Frame(const uint8_t* data,
                                          size_t size,
                                          std::vector<uint8_t>& out,
                                          std::string& out_error,
                                          size_t max_output_bytes,
                                          size_t* out_consumed) {
    out.clear();
    size_t pos = 0;

    while (pos < size) {
        if (size - pos < 4u) {
            if (!out.empty() && out_consumed) {
                *out_consumed = pos;
                return true;
            }
            out_error = "Truncated LZ4 frame magic";
            return false;
        }
        uint32_t magic = ReadLE32(data + pos);
        if (magic != 0x184D2204u && (magic & 0xFFFFFFF0u) != 0x184D2A50u) {
            if (!out.empty()) {
                if (out_consumed) {
                    *out_consumed = pos;
                    return true;
                }
                if (magic == 0u) break;
            }
            out_error = "Invalid LZ4 frame magic";
            return false;
        }
        pos += 4u;
        if ((magic & 0xFFFFFFF0u) == 0x184D2A50u) {
            if (size - pos < 4u) { out_error = "Truncated LZ4 skippable frame"; return false; }
            uint32_t skip_sz = ReadLE32(data + pos);
            pos += 4u;
            if (skip_sz > size - pos) { out_error = "Truncated LZ4 skippable payload"; return false; }
            pos += skip_sz;
            continue;
        }
        if (size - pos < 3u) {
            out_error = "Truncated LZ4 frame descriptor";
            return false;
        }
        uint8_t flg = data[pos++];
        pos++; // BD byte
        if (((flg >> 6) & 3u) != 1u) {
            out_error = "Unsupported LZ4 frame version";
            return false;
        }
        const bool has_block_chk = (flg & 0x10u) != 0;
        const bool has_csize = (flg & 0x08u) != 0;
        const bool has_cchk = (flg & 0x04u) != 0;
        const bool has_dict = (flg & 0x01u) != 0;

        if (has_csize) {
            if (size - pos < 8u) { out_error = "Truncated LZ4 ContentSize"; return false; }
            pos += 8u;
        }
        if (has_dict) {
            if (size - pos < 4u) { out_error = "Truncated LZ4 DictID"; return false; }
            pos += 4u;
        }
        if (pos >= size) { out_error = "Truncated LZ4 HC byte"; return false; }
        pos++; // HC byte

        const size_t frame_out_start = out.size();
        for (;;) {
            if (size - pos < 4u) {
                out_error = "Truncated LZ4 block size";
                return false;
            }
            uint32_t blk_sz = ReadLE32(data + pos);
            pos += 4u;
            if (blk_sz == 0u) break; // EndMark

            const bool uncompressed = (blk_sz & 0x80000000u) != 0;
            const uint32_t payload_sz = blk_sz & 0x7FFFFFFFu;
            if (payload_sz > size - pos) {
                out_error = "Truncated LZ4 frame block data";
                return false;
            }
            if (uncompressed) {
                if ((out.size() - frame_out_start) + payload_sz > max_output_bytes) {
                    out_error = "LZ4 frame output exceeds limit";
                    return false;
                }
                out.insert(out.end(), data + pos, data + pos + payload_sz);
            } else {
                const bool indep = (flg & 0x20u) != 0;
                const size_t hist_base = indep ? out.size() : frame_out_start;
                if (!DecompressLz4Block(data + pos, payload_sz, out, hist_base,
                                        max_output_bytes - (out.size() - frame_out_start),
                                        out_error)) {
                    return false;
                }
            }
            pos += payload_sz;
            if (has_block_chk) {
                if (size - pos < 4u) { out_error = "Truncated LZ4 block checksum"; return false; }
                pos += 4u;
            }
        }
        if (has_cchk) {
            if (size - pos < 4u) { out_error = "Truncated LZ4 content checksum"; return false; }
            pos += 4u;
        }
    }
    if (out_consumed) *out_consumed = pos;
    return true;
}

bool CompressionCodec::DecompressLz4Legacy(const uint8_t* data,
                                           size_t size,
                                           std::vector<uint8_t>& out,
                                           std::string& out_error,
                                           size_t max_output_bytes,
                                           size_t* out_consumed) {
    out.clear();
    if (size < 8u) {
        out_error = "Truncated LZ4 legacy stream";
        return false;
    }
    uint32_t magic = ReadLE32(data);
    if (magic != 0x184C2102u && magic != 0x184C2103u) {
        out_error = "Invalid LZ4 legacy magic";
        return false;
    }
    size_t pos = 4u;
    while (pos < size) {
        if (size - pos < 4u) break;
        uint32_t blk_sz = ReadLE32(data + pos);
        if (blk_sz == 0x184D2204u || (blk_sz & 0xFFFFu) == 0x8B1Fu) {
            if (out_consumed) {
                *out_consumed = pos;
                return true;
            }
        }
        pos += 4u;
        if (blk_sz == 0u || blk_sz == 0x184C2102u || blk_sz == 0x184C2103u) {
            if (blk_sz == 0u) break;
            continue;
        }
        if (blk_sz > size - pos) {
            if (size - pos == 0u) break;
            out_error = "Truncated LZ4 legacy block payload";
            return false;
        }
        const size_t block_hist = out.size();
        if (!DecompressLz4Block(data + pos, blk_sz, out, block_hist,
                                max_output_bytes - out.size(), out_error)) {
            return false;
        }
        pos += blk_sz;
    }
    if (out_consumed) *out_consumed = pos;
    return true;
}

bool CompressionCodec::DecompressAuto(const std::vector<uint8_t>& input,
                                      std::vector<uint8_t>& out,
                                      ArchiveFormat& out_format,
                                      std::string& out_error,
                                      size_t max_output_bytes) {
    out.clear();
    if (input.empty()) {
        out_format = ArchiveFormat::Uncompressed;
        return true;
    }

    out_format = DetectFormat(input.data(), input.size());
    if (out_format == ArchiveFormat::Uncompressed || out_format == ArchiveFormat::Unknown) {
        out = input;
        return true;
    }

    size_t pos = 0;
    while (pos < input.size()) {
        if (pos > 0) {
            while (pos < input.size() && input[pos] == 0u) ++pos;
            if (pos >= input.size()) break;
        }

        const uint8_t* ptr = input.data() + pos;
        const size_t rem = input.size() - pos;
        ArchiveFormat seg_fmt = DetectFormat(ptr, rem);
        if (seg_fmt == ArchiveFormat::Uncompressed &&
            rem >= 6u && (std::memcmp(ptr, "070701", 6) == 0 || std::memcmp(ptr, "070702", 6) == 0)) {
            if (out.size() + rem > max_output_bytes) {
                out_error = "Concatenated archive exceeds max output size";
                return false;
            }
            out.insert(out.end(), ptr, ptr + rem);
            break;
        }

        std::vector<uint8_t> part;
        size_t consumed = 0;
        const size_t budget = (max_output_bytes > out.size()) ? (max_output_bytes - out.size()) : 0u;
        bool ok = false;
        if (seg_fmt == ArchiveFormat::Gzip) {
            ok = DecompressGzip(ptr, rem, part, out_error, budget, &consumed);
        } else if (seg_fmt == ArchiveFormat::Lz4Frame) {
            ok = DecompressLz4Frame(ptr, rem, part, out_error, budget, &consumed);
        } else if (seg_fmt == ArchiveFormat::Lz4Legacy) {
            ok = DecompressLz4Legacy(ptr, rem, part, out_error, budget, &consumed);
        } else {
            out_error = "Trailing unrecognized archive data in concatenated stream";
            return false;
        }
        if (!ok || consumed == 0u) return false;
        out.insert(out.end(), part.begin(), part.end());
        pos += consumed;
    }
    return true;
}

std::vector<uint8_t> CompressionCodec::CompressGzip(const uint8_t* data, size_t size) {
    std::vector<uint8_t> out;
    // RFC 1952 10-byte minimal GZIP header (DEFLATE method=8, OS=Linux/Unix 3)
    out.push_back(0x1Fu);
    out.push_back(0x8Bu);
    out.push_back(0x08u);
    out.push_back(0x00u);
    WriteLE32(out, 0u);
    out.push_back(0x00u);
    out.push_back(0x03u);

    // Emit uncompressed DEFLATE blocks (max 65535 bytes per block)
    size_t off = 0;
    do {
        size_t chunk = std::min<size_t>(size - off, 65535u);
        bool is_last = (off + chunk == size);
        out.push_back(is_last ? 0x01u : 0x00u);
        uint16_t len16 = static_cast<uint16_t>(chunk);
        uint16_t nlen16 = static_cast<uint16_t>(~len16);
        WriteLE16(out, len16);
        WriteLE16(out, nlen16);
        if (chunk > 0) {
            out.insert(out.end(), data + off, data + off + chunk);
        }
        off += chunk;
    } while (off < size);

    WriteLE32(out, Crc32(data, size));
    WriteLE32(out, static_cast<uint32_t>(size & 0xFFFFFFFFULL));
    return out;
}

std::vector<uint8_t> CompressionCodec::CompressLz4Frame(const uint8_t* data, size_t size) {
    std::vector<uint8_t> out;
    WriteLE32(out, 0x184D2204u); // LZ4 Frame Magic
    const uint8_t desc[2] = {0x60u, 0x70u}; // FLG: v01 + B.Indep, BD: MaxBlockSize=4MB
    out.push_back(desc[0]);
    out.push_back(desc[1]);
    out.push_back(static_cast<uint8_t>((XxHash32HeaderChecksum(desc, 2u) >> 8) & 0xFFu));

    size_t off = 0;
    while (off < size) {
        size_t chunk = std::min<size_t>(size - off, 4u * 1024u * 1024u);
        WriteLE32(out, static_cast<uint32_t>(chunk) | 0x80000000u); // Uncompressed block flag
        out.insert(out.end(), data + off, data + off + chunk);
        off += chunk;
    }
    WriteLE32(out, 0u); // EndMark
    return out;
}

std::vector<uint8_t> CompressionCodec::CompressLz4Legacy(const uint8_t* data, size_t size) {
    std::vector<uint8_t> out;
    WriteLE32(out, 0x184C2102u); // Linux LZ4 Legacy Magic
    // Encode as valid literals-only LZ4 blocks (8 MiB max chunk)
    size_t off = 0;
    while (off < size) {
        size_t chunk = std::min<size_t>(size - off, 1024u * 1024u);
        std::vector<uint8_t> blk;
        uint8_t token = (chunk >= 15u) ? 0xF0u : static_cast<uint8_t>(chunk << 4);
        blk.push_back(token);
        if (chunk >= 15u) {
            size_t rem = chunk - 15u;
            while (rem >= 255u) {
                blk.push_back(255u);
                rem -= 255u;
            }
            blk.push_back(static_cast<uint8_t>(rem));
        }
        blk.insert(blk.end(), data + off, data + off + chunk);
        WriteLE32(out, static_cast<uint32_t>(blk.size()));
        out.insert(out.end(), blk.begin(), blk.end());
        off += chunk;
    }
    return out;
}

} // namespace haseeb::vm
