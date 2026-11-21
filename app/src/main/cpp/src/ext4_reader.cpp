#include "haseeb/ext4_reader.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace haseeb::loader {

namespace {

inline constexpr uint16_t kExt4SuperMagic = 0xEF53u;
inline constexpr uint16_t kExt4ExtentMagic = 0xF30Au;
inline constexpr uint32_t kExt4RootIno = 2u;
inline constexpr uint32_t kExt4ExtentsFl = 0x00080000u;
inline constexpr uint32_t kExt4FeatureIncompat64Bit = 0x0080u;
inline constexpr uint64_t kExt4SuperblockOffset = 1024ull;

// Android Sparse Image constants
inline constexpr uint32_t kSparseHeaderMagic = 0xED26FF3Au;
inline constexpr uint16_t kChunkTypeRaw      = 0xCAC1u;
inline constexpr uint16_t kChunkTypeFill     = 0xCAC2u;
inline constexpr uint16_t kChunkTypeDontCare = 0xCAC3u;
inline constexpr uint16_t kChunkTypeCrc32    = 0xCAC4u;

// Android Dynamic Partition (liblp) constants
inline constexpr uint32_t kLpGeometryMagic = 0x616C4467u; // "gDla"
inline constexpr uint32_t kLpMetadataMagic = 0x414C5030u; // "0PLA"
inline constexpr uint32_t kLpTargetTypeLinear = 0u;

// EROFS / F2FS / SquashFS magic constants for diagnostics
inline constexpr uint32_t kErofsSuperMagic = 0xE0F5E1E2u;
inline constexpr uint32_t kF2fsSuperMagic  = 0xF2F52010u;

#pragma pack(push, 1)
struct AndroidSparseHeader {
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t file_hdr_sz;
    uint16_t chunk_hdr_sz;
    uint32_t blk_sz;
    uint32_t total_blks;
    uint32_t total_chunks;
    uint32_t image_checksum;
};

struct AndroidSparseChunkHeader {
    uint16_t chunk_type;
    uint16_t reserved1;
    uint32_t chunk_sz;
    uint32_t total_sz;
};

struct LpMetadataGeometry {
    uint32_t magic;
    uint32_t struct_size;
    uint8_t  checksum[32];
    uint32_t metadata_max_size;
    uint32_t metadata_slot_count;
    uint32_t logical_block_size;
};

struct LpTableDescriptor {
    uint32_t offset;
    uint32_t num_entries;
    uint32_t entry_size;
};

struct LpMetadataHeader {
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t header_size;
    uint8_t  header_checksum[32];
    uint32_t tables_size;
    uint8_t  tables_checksum[32];
    LpTableDescriptor partitions;
    LpTableDescriptor extents;
    LpTableDescriptor groups;
    LpTableDescriptor block_devices;
};

struct LpMetadataPartition {
    char     name[36];
    uint32_t attributes;
    uint32_t first_extent_index;
    uint32_t num_extents;
    uint32_t group_index;
};

struct LpMetadataExtent {
    uint64_t num_sectors;
    uint32_t target_type;
    uint64_t target_data;
    uint32_t target_source;
};

struct GptHeader {
    char     signature[8]; // "EFI PART"
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t partition_entry_lba;
    uint32_t num_partition_entries;
    uint32_t size_of_partition_entry;
    uint32_t partition_array_crc32;
};

struct GptPartitionEntry {
    uint8_t  type_guid[16];
    uint8_t  unique_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    uint16_t name_utf16[36];
};

struct MbrPartitionEntry {
    uint8_t  status;
    uint8_t  chs_first[3];
    uint8_t  type;
    uint8_t  chs_last[3];
    uint32_t lba_start;
    uint32_t num_sectors;
};

struct Ext4SuperBlock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_r_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t s_uuid[16];
    char s_volume_name[16];
    char s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t s_prealloc_blocks;
    uint8_t s_prealloc_dir_blocks;
    uint16_t s_reserved_gdt_blocks;
    uint8_t s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint32_t s_hash_seed[4];
    uint8_t s_def_hash_version;
    uint8_t s_jnl_backup_type;
    uint16_t s_desc_size;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;
    uint32_t s_mkfs_time;
    uint32_t s_jnl_blocks[17];
    uint32_t s_blocks_count_hi;
};

struct Ext4GroupDesc {
    uint32_t bg_block_bitmap_lo;
    uint32_t bg_inode_bitmap_lo;
    uint32_t bg_inode_table_lo;
    uint16_t bg_free_blocks_count_lo;
    uint16_t bg_free_inodes_count_lo;
    uint16_t bg_used_dirs_count_lo;
    uint16_t bg_flags;
    uint32_t bg_exclude_bitmap_lo;
    uint16_t bg_block_bitmap_csum_lo;
    uint16_t bg_inode_bitmap_csum_lo;
    uint16_t bg_itable_unused_lo;
    uint16_t bg_checksum;
    uint32_t bg_block_bitmap_hi;
    uint32_t bg_inode_bitmap_hi;
    uint32_t bg_inode_table_hi;
};

struct Ext4ExtentHeader {
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
};

struct Ext4ExtentIdx {
    uint32_t ei_block;
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;
    uint16_t ei_unused;
};

struct Ext4Extent {
    uint32_t ee_block;
    uint16_t ee_len;
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
};

struct Ext4DirEntry2 {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[255];
};
#pragma pack(pop)

std::vector<std::string> SplitPath(const std::string& p) {
    std::vector<std::string> out;
    std::istringstream iss(p);
    std::string seg;
    while (std::getline(iss, seg, '/')) {
        if (!seg.empty() && seg != ".") {
            out.push_back(seg);
        }
    }
    return out;
}

std::string Utf16AsciiName(const uint16_t* u16, size_t max_chars) {
    std::string out;
    for (size_t i = 0; i < max_chars && u16[i] != 0u; ++i) {
        if (u16[i] < 0x80u) out.push_back(static_cast<char>(u16[i]));
    }
    return out;
}

} // namespace

struct Ext4Reader::RawInode {
    uint16_t i_mode = 0;
    uint16_t i_uid = 0;
    uint32_t i_size_lo = 0;
    uint32_t i_atime = 0;
    uint32_t i_ctime = 0;
    uint32_t i_mtime = 0;
    uint32_t i_dtime = 0;
    uint16_t i_gid = 0;
    uint16_t i_links_count = 0;
    uint32_t i_blocks_lo = 0;
    uint32_t i_flags = 0;
    uint32_t i_osd1 = 0;
    uint32_t i_block[15]{};
    uint32_t i_generation = 0;
    uint32_t i_file_acl_lo = 0;
    uint32_t i_size_high = 0;
    uint32_t i_obso_faddr = 0;
    uint8_t i_osd2[12]{};

    uint64_t Size() const {
        return static_cast<uint64_t>(i_size_lo) | (static_cast<uint64_t>(i_size_high) << 32);
    }
    bool UsesExtents() const { return (i_flags & kExt4ExtentsFl) != 0u; }
    bool IsDirectory() const { return (i_mode & 0xF000u) == 0x4000u; }
    bool IsRegular() const { return (i_mode & 0xF000u) == 0x8000u; }
    bool IsSymlink() const { return (i_mode & 0xF000u) == 0xA000u; }
};

Ext4Reader::~Ext4Reader() {
    Close();
}

void Ext4Reader::Close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    file_size_ = 0;
    virtual_size_ = 0;
    partition_offset_ = 0;
    image_size_ = 0;
    is_sparse_ = false;
    sparse_spans_.clear();
    lp_extents_.clear();
    volume_name_.clear();
}

bool Ext4Reader::ReadFileRawAt(uint64_t file_off, void* dst, size_t len) const {
    if (fd_ < 0 || file_off > file_size_ || len > file_size_ - file_off) return false;
    uint8_t* p = static_cast<uint8_t*>(dst);
    size_t done = 0;
    while (done < len) {
        ssize_t n = ::pread(fd_, p + done, len - done, static_cast<off_t>(file_off + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

bool Ext4Reader::ReadVirtualAt(uint64_t virt_off, void* dst, size_t len) const {
    if (fd_ < 0 || virt_off > virtual_size_ || len > virtual_size_ - virt_off) return false;
    if (len == 0) return true;
    if (!is_sparse_) {
        return ReadFileRawAt(virt_off, dst, len);
    }

    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    while (done < len) {
        const uint64_t cur = virt_off + done;
        auto it = std::upper_bound(
            sparse_spans_.begin(), sparse_spans_.end(), cur,
            [](uint64_t off, const SparseSpan& s) { return off < s.out_offset; });
        if (it == sparse_spans_.begin()) {
            // Gap before first span -> zero fill
            const uint64_t next_start = (it != sparse_spans_.end()) ? it->out_offset : virtual_size_;
            const size_t take = static_cast<size_t>(std::min<uint64_t>(len - done, next_start - cur));
            std::memset(out + done, 0, take);
            done += take;
            continue;
        }
        --it;
        const uint64_t span_end = it->out_offset + it->out_size;
        if (cur >= span_end) {
            auto next_it = it + 1;
            const uint64_t next_start = (next_it != sparse_spans_.end()) ? next_it->out_offset : virtual_size_;
            const size_t take = static_cast<size_t>(std::min<uint64_t>(len - done, next_start - cur));
            std::memset(out + done, 0, take);
            done += take;
            continue;
        }

        const uint64_t in_span_off = cur - it->out_offset;
        const size_t take = static_cast<size_t>(std::min<uint64_t>(len - done, span_end - cur));
        if (it->type == kChunkTypeRaw) {
            if (!ReadFileRawAt(it->file_offset + in_span_off, out + done, take)) {
                return false;
            }
        } else if (it->type == kChunkTypeFill) {
            uint8_t pat[4];
            std::memcpy(pat, &it->fill_val, 4);
            for (size_t i = 0; i < take; ++i) {
                out[done + i] = pat[(in_span_off + i) & 3u];
            }
        } else {
            std::memset(out + done, 0, take);
        }
        done += take;
    }
    return true;
}

bool Ext4Reader::ReadBytesAt(uint64_t offset, void* dst, size_t len) const {
    if (fd_ < 0 || offset > image_size_ || len > image_size_ - offset) return false;
    if (len == 0) return true;

    if (lp_extents_.empty()) {
        return ReadVirtualAt(partition_offset_ + offset, dst, len);
    }

    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    while (done < len) {
        const uint64_t cur = offset + done;
        auto it = std::upper_bound(
            lp_extents_.begin(), lp_extents_.end(), cur,
            [](uint64_t off, const LinearExtent& e) { return off < e.virt_offset; });
        if (it == lp_extents_.begin()) return false;
        --it;
        const uint64_t ext_end = it->virt_offset + it->size_bytes;
        if (cur >= ext_end) return false;
        const uint64_t in_ext = cur - it->virt_offset;
        const size_t take = static_cast<size_t>(std::min<uint64_t>(len - done, ext_end - cur));
        if (it->phys_offset == UINT64_MAX) {
            std::memset(out + done, 0, take);
        } else if (!ReadVirtualAt(it->phys_offset + in_ext, out + done, take)) {
            return false;
        }
        done += take;
    }
    return true;
}

bool Ext4Reader::ReadBlock(uint64_t block_num, void* dst) const {
    if (block_num == 0ull) {
        std::memset(dst, 0, block_size_);
        return true;
    }
    return ReadBytesAt(block_num * static_cast<uint64_t>(block_size_), dst, block_size_);
}

namespace {

bool IsValidExt4Superblock(const Ext4SuperBlock& sb, uint64_t avail_bytes) {
    if (sb.s_magic != kExt4SuperMagic) return false;
    if (sb.s_log_block_size > 6u) return false;
    if (sb.s_inodes_count < 2u || sb.s_blocks_per_group == 0u || sb.s_inodes_per_group == 0u) {
        return false;
    }
    if (sb.s_rev_level > 1u) return false;
    const uint32_t blk_sz = 1024u << sb.s_log_block_size;
    const uint16_t inode_sz = (sb.s_rev_level >= 1u && sb.s_inode_size >= 128u) ? sb.s_inode_size : 128u;
    if (inode_sz < 128u || inode_sz > blk_sz || (inode_sz & (inode_sz - 1u)) != 0u) {
        return false;
    }
    uint64_t blocks_cnt = static_cast<uint64_t>(sb.s_blocks_count_lo);
    if ((sb.s_feature_incompat & kExt4FeatureIncompat64Bit) != 0u) {
        blocks_cnt |= (static_cast<uint64_t>(sb.s_blocks_count_hi) << 32);
    }
    if (blocks_cnt < 4ull || sb.s_first_data_block >= blocks_cnt) {
        return false;
    }
    // Guard against uninitialized false-positive 0xEF53 in random binary data
    if (avail_bytes > 0 && blocks_cnt > (avail_bytes / blk_sz) + 65536ull) {
        return false;
    }
    return true;
}

} // namespace

bool Ext4Reader::HasExt4SuperblockAt(uint64_t virt_base) const {
    if (virt_base + kExt4SuperblockOffset + sizeof(Ext4SuperBlock) > virtual_size_) {
        return false;
    }
    uint16_t magic = 0;
    if (!ReadVirtualAt(virt_base + kExt4SuperblockOffset + offsetof(Ext4SuperBlock, s_magic),
                       &magic, sizeof(magic))) {
        return false;
    }
    return magic == kExt4SuperMagic;
}

bool Ext4Reader::HasValidExt4SuperblockAt(uint64_t virt_base) const {
    if (virt_base + kExt4SuperblockOffset + sizeof(Ext4SuperBlock) > virtual_size_) {
        return false;
    }
    Ext4SuperBlock sb{};
    if (!ReadVirtualAt(virt_base + kExt4SuperblockOffset, &sb, sizeof(sb))) {
        return false;
    }
    return IsValidExt4Superblock(sb, virtual_size_ - virt_base);
}

bool Ext4Reader::TryParseSparseImage() {
    if (file_size_ < sizeof(AndroidSparseHeader)) return false;
    AndroidSparseHeader hdr{};
    if (!ReadFileRawAt(0, &hdr, sizeof(hdr))) return false;
    if (hdr.magic != kSparseHeaderMagic) return false;
    if (hdr.major_version != 1u || hdr.file_hdr_sz < sizeof(AndroidSparseHeader) ||
        hdr.chunk_hdr_sz < sizeof(AndroidSparseChunkHeader) || hdr.blk_sz < 512u ||
        (hdr.blk_sz & (hdr.blk_sz - 1u)) != 0u) {
        last_error_ = "corrupt Android sparse header";
        return false;
    }

    uint64_t file_pos = hdr.file_hdr_sz;
    uint64_t out_pos = 0;
    std::vector<SparseSpan> spans;
    spans.reserve(std::min<uint32_t>(hdr.total_chunks, 65536u));

    for (uint32_t c = 0; c < hdr.total_chunks; ++c) {
        AndroidSparseChunkHeader ch{};
        if (!ReadFileRawAt(file_pos, &ch, sizeof(ch))) {
            last_error_ = "truncated Android sparse chunk header";
            return false;
        }
        if (ch.total_sz < hdr.chunk_hdr_sz || file_pos + ch.total_sz > file_size_) {
            last_error_ = "truncated Android sparse chunk payload";
            return false;
        }
        const uint64_t payload_off = file_pos + hdr.chunk_hdr_sz;
        const uint64_t out_bytes = static_cast<uint64_t>(ch.chunk_sz) * hdr.blk_sz;

        if (ch.chunk_type == kChunkTypeRaw) {
            if (ch.total_sz < hdr.chunk_hdr_sz + out_bytes) {
                last_error_ = "truncated Android sparse RAW chunk";
                return false;
            }
            if (out_bytes > 0) {
                spans.push_back(SparseSpan{out_pos, out_bytes, payload_off, 0u, kChunkTypeRaw});
            }
        } else if (ch.chunk_type == kChunkTypeFill) {
            uint32_t fill = 0;
            if (ch.total_sz >= hdr.chunk_hdr_sz + 4u) {
                ReadFileRawAt(payload_off, &fill, sizeof(fill));
            }
            if (out_bytes > 0) {
                spans.push_back(SparseSpan{out_pos, out_bytes, 0ull, fill, kChunkTypeFill});
            }
        } else if (ch.chunk_type == kChunkTypeDontCare) {
            if (out_bytes > 0) {
                spans.push_back(SparseSpan{out_pos, out_bytes, 0ull, 0u, kChunkTypeDontCare});
            }
        } else if (ch.chunk_type == kChunkTypeCrc32) {
            // CRC32 chunk carries no output blocks
        } else {
            last_error_ = "unsupported Android sparse chunk type";
            return false;
        }
        out_pos += out_bytes;
        file_pos += ch.total_sz;
    }

    const uint64_t declared_size = static_cast<uint64_t>(hdr.total_blks) * hdr.blk_sz;
    is_sparse_ = true;
    virtual_size_ = std::max(declared_size, out_pos);
    sparse_spans_ = std::move(spans);
    return true;
}

bool Ext4Reader::TryParseLpSuperPartition() {
    uint64_t geom_off = 0;
    LpMetadataGeometry geom{};
    const uint64_t geom_cands[3] = {4096ull, 8192ull, 0ull};
    for (uint64_t g : geom_cands) {
        if (ReadVirtualAt(g, &geom, sizeof(geom)) && geom.magic == kLpGeometryMagic) {
            geom_off = g;
            break;
        }
    }
    if (geom.magic != kLpGeometryMagic) {
        return false;
    }

    std::vector<uint64_t> hdr_cands;
    const uint64_t slot_sz = (geom.metadata_max_size >= 4096u && geom.metadata_max_size <= 16u * 1024u * 1024u)
                                 ? geom.metadata_max_size
                                 : 65536ull;
    const uint32_t slot_cnt = (geom.metadata_slot_count >= 1u && geom.metadata_slot_count <= 8u)
                                  ? geom.metadata_slot_count
                                  : 2u;
    if (geom_off == 4096ull) {
        for (uint32_t s = 0; s < slot_cnt; ++s) {
            hdr_cands.push_back(12288ull + static_cast<uint64_t>(s) * slot_sz);
        }
        for (uint32_t s = 0; s < slot_cnt; ++s) {
            hdr_cands.push_back(12288ull + static_cast<uint64_t>(slot_cnt + s) * slot_sz);
        }
    }
    hdr_cands.push_back(12288ull);
    hdr_cands.push_back(8192ull);
    hdr_cands.push_back(4096ull);

    for (uint64_t hdr_off : hdr_cands) {
        LpMetadataHeader hdr{};
        if (!ReadVirtualAt(hdr_off, &hdr, sizeof(hdr)) || hdr.magic != kLpMetadataMagic) {
            continue;
        }
        if (hdr.header_size < sizeof(LpMetadataHeader) ||
            hdr.partitions.entry_size < sizeof(LpMetadataPartition) ||
            hdr.extents.entry_size < sizeof(LpMetadataExtent) ||
            hdr.partitions.num_entries > 512u || hdr.extents.num_entries > 4096u) {
            continue;
        }

        const uint64_t tables_base = hdr_off + hdr.header_size;
        std::vector<LpMetadataPartition> parts(hdr.partitions.num_entries);
        bool ok = true;
        for (uint32_t i = 0; i < hdr.partitions.num_entries; ++i) {
            const uint64_t p_off = tables_base + hdr.partitions.offset +
                                   static_cast<uint64_t>(i) * hdr.partitions.entry_size;
            if (!ReadVirtualAt(p_off, &parts[i], sizeof(LpMetadataPartition))) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        std::vector<LpMetadataExtent> extents(hdr.extents.num_entries);
        for (uint32_t i = 0; i < hdr.extents.num_entries; ++i) {
            const uint64_t e_off = tables_base + hdr.extents.offset +
                                   static_cast<uint64_t>(i) * hdr.extents.entry_size;
            if (!ReadVirtualAt(e_off, &extents[i], sizeof(LpMetadataExtent))) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        auto try_select = [&](const char* wanted_name) -> bool {
            for (const auto& p : parts) {
                char name_buf[37]{};
                std::memcpy(name_buf, p.name, 36);
                std::string pname(name_buf);
                if (wanted_name && pname != wanted_name) continue;
                if (p.num_extents == 0 ||
                    p.first_extent_index + p.num_extents > extents.size()) {
                    continue;
                }
                const auto& first_e = extents[p.first_extent_index];
                if (first_e.target_type != kLpTargetTypeLinear) continue;
                const uint64_t first_byte = first_e.target_data * 512ull;
                if (!HasValidExt4SuperblockAt(first_byte)) continue;

                lp_extents_.clear();
                uint64_t v_cur = 0;
                for (uint32_t k = 0; k < p.num_extents; ++k) {
                    const auto& ex = extents[p.first_extent_index + k];
                    const uint64_t bytes = ex.num_sectors * 512ull;
                    const uint64_t phys = (ex.target_type == kLpTargetTypeLinear)
                                              ? (ex.target_data * 512ull)
                                              : UINT64_MAX;
                    lp_extents_.push_back(LinearExtent{v_cur, bytes, phys});
                    v_cur += bytes;
                }
                partition_offset_ = 0;
                image_size_ = v_cur;
                return true;
            }
            return false;
        };

        if (try_select("system_a") || try_select("system") ||
            try_select("system_b") || try_select(nullptr)) {
            return true;
        }
    }
    return false;
}

bool Ext4Reader::TryParseGptPartition() {
    const uint64_t lba_sizes[2] = {512ull, 4096ull};
    for (uint64_t lba_sz : lba_sizes) {
        GptHeader gpt{};
        if (!ReadVirtualAt(lba_sz, &gpt, sizeof(gpt))) continue;
        if (std::memcmp(gpt.signature, "EFI PART", 8) != 0) continue;
        if (gpt.size_of_partition_entry < sizeof(GptPartitionEntry) ||
            gpt.num_partition_entries == 0 || gpt.num_partition_entries > 256u) {
            continue;
        }

        const uint64_t table_off = gpt.partition_entry_lba * lba_sz;
        struct Cand {
            std::string name;
            uint64_t off;
            uint64_t size;
        };
        std::vector<Cand> cands;
        for (uint32_t i = 0; i < gpt.num_partition_entries; ++i) {
            GptPartitionEntry pe{};
            if (!ReadVirtualAt(table_off + static_cast<uint64_t>(i) * gpt.size_of_partition_entry,
                               &pe, sizeof(pe))) {
                break;
            }
            if (pe.starting_lba == 0 || pe.ending_lba < pe.starting_lba) continue;
            const uint64_t p_off = pe.starting_lba * lba_sz;
            const uint64_t p_sz = (pe.ending_lba - pe.starting_lba + 1ull) * lba_sz;
            if (HasValidExt4SuperblockAt(p_off)) {
                cands.push_back(Cand{Utf16AsciiName(pe.name_utf16, 36), p_off, p_sz});
            }
        }
        if (cands.empty()) continue;
        const Cand* best = &cands.front();
        for (const auto& c : cands) {
            if (c.name == "system" || c.name == "system_a" ||
                c.name == "system_b" || c.name == "rootfs" || c.name == "linux") {
                best = &c;
                break;
            }
        }
        partition_offset_ = best->off;
        image_size_ = std::min(best->size, virtual_size_ - partition_offset_);
        return true;
    }
    return false;
}

bool Ext4Reader::TryParseMbrPartition() {
    uint8_t mbr[512]{};
    if (!ReadVirtualAt(0, mbr, sizeof(mbr))) return false;
    if (mbr[510] != 0x55u || mbr[511] != 0xAAu) return false;

    MbrPartitionEntry parts[4]{};
    std::memcpy(parts, mbr + 0x1BE, sizeof(parts));
    for (const auto& p : parts) {
        if (p.type == 0 || p.num_sectors == 0 || p.lba_start == 0) continue;
        const uint64_t p_off = static_cast<uint64_t>(p.lba_start) * 512ull;
        const uint64_t p_sz = static_cast<uint64_t>(p.num_sectors) * 512ull;
        if (HasValidExt4SuperblockAt(p_off)) {
            partition_offset_ = p_off;
            image_size_ = std::min(p_sz, virtual_size_ - partition_offset_);
            return true;
        }
    }
    return false;
}

bool Ext4Reader::TryProbeExt4Offset() {
    const uint64_t max_scan = std::min<uint64_t>(virtual_size_, 16ull * 1024ull * 1024ull);
    const uint64_t chunk_sz = 256ull * 1024ull;
    std::vector<uint8_t> buf(chunk_sz + 2048ull, 0u);
    for (uint64_t base = 0; base + 2048ull <= max_scan; base += chunk_sz) {
        const size_t to_read = static_cast<size_t>(
            std::min<uint64_t>(chunk_sz + 2048ull, virtual_size_ - base));
        if (to_read < 2048u) break;
        if (!ReadVirtualAt(base, buf.data(), to_read)) break;
        const size_t limit = std::min<size_t>(chunk_sz, to_read - 2048u);
        for (size_t off = 0; off <= limit; off += 512u) {
            Ext4SuperBlock sb{};
            std::memcpy(&sb, buf.data() + off + kExt4SuperblockOffset, sizeof(sb));
            if (IsValidExt4Superblock(sb, virtual_size_ - (base + off))) {
                partition_offset_ = base + off;
                image_size_ = virtual_size_ - partition_offset_;
                return true;
            }
        }
    }
    return false;
}

bool Ext4Reader::TryLocateExt4Partition() {
    if (HasExt4SuperblockAt(0)) {
        partition_offset_ = 0;
        image_size_ = virtual_size_;
        return true;
    }
    if (TryParseLpSuperPartition()) return true;
    if (TryParseGptPartition()) return true;
    if (TryParseMbrPartition()) return true;
    if (TryProbeExt4Offset()) return true;
    return false;
}

std::string Ext4Reader::DescribeNonExt4Header() const {
    uint8_t head[16]{};
    ReadFileRawAt(0, head, std::min<size_t>(sizeof(head), static_cast<size_t>(file_size_)));

    if (file_size_ >= 2 && head[0] == 0x1Fu && head[1] == 0x8Bu) {
        return "gzip-compressed image (1F 8B); decompress .gz first";
    }
    if (file_size_ >= 4 && std::memcmp(head, "\x04\x22\x4D\x18", 4) == 0) {
        return "LZ4-compressed image; decompress first";
    }
    if (file_size_ >= 6 && std::memcmp(head, "\xFD\x37\x7A\x58\x5A\x00", 6) == 0) {
        return "XZ-compressed image; decompress .xz first";
    }
    if (file_size_ >= 4 && std::memcmp(head, "PK\x03\x04", 4) == 0) {
        return "ZIP archive passed directly as system.img";
    }
    if (file_size_ >= 8 && std::memcmp(head, "ANDROID!", 8) == 0) {
        return "Android boot.img passed as system.img";
    }
    if (file_size_ >= 6 && std::memcmp(head, "070701", 6) == 0) {
        return "CPIO ramdisk archive passed as system.img";
    }
    if (file_size_ >= 4 && std::memcmp(head, "hsqs", 4) == 0) {
        return "SquashFS image detected (only ext2/ext3/ext4 supported)";
    }
    if (file_size_ >= 4 && std::memcmp(head, "CrAU", 4) == 0) {
        return "Android OTA payload.bin passed directly (extract system.img first)";
    }
    if (file_size_ >= 4 && std::memcmp(head, "QFI\xFB", 4) == 0) {
        return "QCOW2 disk image detected (convert with qemu-img to raw ext4)";
    }
    if (file_size_ >= 6 && std::memcmp(head, "LUKS\xBA\xBE", 6) == 0) {
        return "LUKS encrypted image detected (not supported)";
    }
    if (file_size_ >= 512) {
        char ustar[6]{};
        ReadFileRawAt(257, ustar, 5);
        if (std::memcmp(ustar, "ustar", 5) == 0) {
            return "TAR archive passed as system.img (extract ext4 system.img first)";
        }
    }

    auto classify_slice = [&](uint64_t off) -> std::string {
        uint8_t blk[2048]{};
        if (!ReadVirtualAt(off, blk, sizeof(blk))) return "unreadable";
        uint32_t m1k = 0;
        std::memcpy(&m1k, blk + 1024, 4);
        uint16_t ext_m = 0;
        std::memcpy(&ext_m, blk + 1080, 2);
        if (ext_m == kExt4SuperMagic) return "ext4";
        if (m1k == kErofsSuperMagic) return "EROFS";
        if (m1k == kF2fsSuperMagic) return "F2FS";
        if (std::memcmp(blk, "hsqs", 4) == 0) return "SquashFS";
        if (blk[510] == 0x55u && blk[511] == 0xAAu) return "FAT/MBR";
        bool all_z = true;
        for (uint8_t b : blk) {
            if (b != 0u) { all_z = false; break; }
        }
        if (all_z) return "zeros";
        char buf[32]{};
        std::snprintf(buf, sizeof(buf), "%02X%02X%02X%02X", blk[0], blk[1], blk[2], blk[3]);
        return std::string(buf);
    };

    if (virtual_size_ >= 2048) {
        uint32_t magic_1k = 0;
        ReadVirtualAt(1024ull, &magic_1k, sizeof(magic_1k));
        if (magic_1k == kErofsSuperMagic) {
            return "EROFS filesystem detected (not ext4; repack ROM as ext4)";
        }
        if (magic_1k == kF2fsSuperMagic) {
            return "F2FS filesystem detected (not ext4; repack ROM as ext4)";
        }
    }

    // Check Android dynamic super.img (LP metadata)
    for (uint64_t g : {4096ull, 8192ull, 0ull}) {
        LpMetadataGeometry geom{};
        if (ReadVirtualAt(g, &geom, sizeof(geom)) && geom.magic == kLpGeometryMagic) {
            const uint64_t slot_sz = (geom.metadata_max_size >= 4096u && geom.metadata_max_size <= 16u * 1024u * 1024u)
                                         ? geom.metadata_max_size
                                         : 65536ull;
            const uint32_t slot_cnt = std::min<uint32_t>(
                (geom.metadata_slot_count >= 1u) ? geom.metadata_slot_count : 2u, 4u);
            std::string summary = "super.img (LP)";
            for (uint32_t s = 0; s < slot_cnt * 2u; ++s) {
                const uint64_t hdr_off = (g == 4096ull)
                    ? (12288ull + static_cast<uint64_t>(s) * slot_sz)
                    : (g + 4096ull + static_cast<uint64_t>(s) * slot_sz);
                LpMetadataHeader hdr{};
                if (ReadVirtualAt(hdr_off, &hdr, sizeof(hdr)) && hdr.magic == kLpMetadataMagic &&
                    hdr.partitions.num_entries <= 64u && hdr.extents.num_entries <= 512u &&
                    hdr.partitions.entry_size >= sizeof(LpMetadataPartition) &&
                    hdr.extents.entry_size >= sizeof(LpMetadataExtent)) {
                    const uint64_t tbase = hdr_off + hdr.header_size;
                    summary += " slot" + std::to_string(s) + ":";
                    for (uint32_t i = 0; i < std::min<uint32_t>(hdr.partitions.num_entries, 6u); ++i) {
                        LpMetadataPartition mp{};
                        if (!ReadVirtualAt(tbase + hdr.partitions.offset + static_cast<uint64_t>(i) * hdr.partitions.entry_size, &mp, sizeof(mp))) break;
                        char nbuf[37]{};
                        std::memcpy(nbuf, mp.name, 36);
                        std::string fs = "empty";
                        if (mp.num_extents > 0 && mp.first_extent_index < hdr.extents.num_entries) {
                            LpMetadataExtent ex{};
                            if (ReadVirtualAt(tbase + hdr.extents.offset + static_cast<uint64_t>(mp.first_extent_index) * hdr.extents.entry_size, &ex, sizeof(ex))) {
                                fs = (ex.target_type == kLpTargetTypeLinear) ? classify_slice(ex.target_data * 512ull) : "zero-extent";
                            }
                        }
                        summary += " " + std::string(nbuf) + "[" + fs + "]";
                    }
                    return summary;
                }
            }
            return "super.img (LP geometry found, no valid 0PLA metadata; possibly super_empty.img)";
        }
    }

    // Check GPT (512B or 4096B sector)
    for (uint64_t lba_sz : {512ull, 4096ull}) {
        GptHeader gpt{};
        if (ReadVirtualAt(lba_sz, &gpt, sizeof(gpt)) && std::memcmp(gpt.signature, "EFI PART", 8) == 0 &&
            gpt.num_partition_entries <= 256u && gpt.size_of_partition_entry >= sizeof(GptPartitionEntry)) {
            std::string summary = "GPT(" + std::to_string(lba_sz) + "B) no ext4:";
            const uint64_t t_off = gpt.partition_entry_lba * lba_sz;
            uint32_t listed = 0;
            for (uint32_t i = 0; i < gpt.num_partition_entries && listed < 6u; ++i) {
                GptPartitionEntry pe{};
                if (!ReadVirtualAt(t_off + static_cast<uint64_t>(i) * gpt.size_of_partition_entry, &pe, sizeof(pe))) break;
                if (pe.starting_lba == 0 || pe.ending_lba < pe.starting_lba) continue;
                std::string pname = Utf16AsciiName(pe.name_utf16, 36);
                if (pname.empty()) pname = "p" + std::to_string(i + 1);
                summary += " " + pname + "[" + classify_slice(pe.starting_lba * lba_sz) + "]";
                ++listed;
            }
            return summary;
        }
    }

    // Scan first 16 MiB for known filesystem magic or first non-zero bytes
    const uint64_t max_scan = std::min<uint64_t>(virtual_size_, 16ull * 1024ull * 1024ull);
    const uint64_t chunk_sz = 256ull * 1024ull;
    std::vector<uint8_t> buf(chunk_sz);
    uint64_t first_nz_off = UINT64_MAX;
    uint8_t first_nz_bytes[8]{};
    for (uint64_t base = 0; base < max_scan; base += chunk_sz) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(chunk_sz, max_scan - base));
        if (!ReadVirtualAt(base, buf.data(), n)) break;
        if (first_nz_off == UINT64_MAX) {
            for (size_t i = 0; i < n; ++i) {
                if (buf[i] != 0u) {
                    first_nz_off = base + i;
                    const size_t cp = std::min<size_t>(8u, n - i);
                    std::memcpy(first_nz_bytes, buf.data() + i, cp);
                    break;
                }
            }
        }
        for (size_t off = 0; off + 2048u <= n; off += 512u) {
            uint32_t m1k = 0;
            std::memcpy(&m1k, buf.data() + off + 1024u, 4);
            if (m1k == kErofsSuperMagic) {
                char msg[96]{};
                std::snprintf(msg, sizeof(msg), "EROFS at offset 0x%llX (not ext4)",
                              static_cast<unsigned long long>(base + off));
                return std::string(msg);
            }
            if (m1k == kF2fsSuperMagic) {
                char msg[96]{};
                std::snprintf(msg, sizeof(msg), "F2FS at offset 0x%llX (not ext4)",
                              static_cast<unsigned long long>(base + off));
                return std::string(msg);
            }
        }
    }

    char hex[128]{};
    if (first_nz_off == UINT64_MAX) {
        std::snprintf(hex, sizeof(hex),
                      "not ext4 (size=%lluB, first 16MiB all zeroes)",
                      static_cast<unsigned long long>(file_size_));
    } else {
        std::snprintf(hex, sizeof(hex),
                      "not ext4 (size=%lluB, head=%02X %02X %02X %02X, nz@0x%llX=%02X %02X %02X %02X)",
                      static_cast<unsigned long long>(file_size_),
                      head[0], head[1], head[2], head[3],
                      static_cast<unsigned long long>(first_nz_off),
                      first_nz_bytes[0], first_nz_bytes[1], first_nz_bytes[2], first_nz_bytes[3]);
    }
    return std::string(hex);
}

bool Ext4Reader::Open(const std::string& image_path) {
    Close();
    int fd = ::open(image_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        last_error_ = "open failed: " + std::string(std::strerror(errno));
        return false;
    }

    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size < 4096) {
        last_error_ = "invalid system image size (" +
                      std::to_string(st.st_size) + " bytes)";
        ::close(fd);
        return false;
    }

    fd_ = fd;
    file_size_ = static_cast<uint64_t>(st.st_size);
    virtual_size_ = file_size_;
    image_size_ = file_size_;

    uint32_t head_magic = 0;
    if (ReadFileRawAt(0, &head_magic, sizeof(head_magic)) && head_magic == kSparseHeaderMagic) {
        if (!TryParseSparseImage()) {
            Close();
            return false;
        }
    }

    if (!TryLocateExt4Partition()) {
        last_error_ = DescribeNonExt4Header();
        Close();
        return false;
    }

    Ext4SuperBlock sb{};
    if (!ReadBytesAt(kExt4SuperblockOffset, &sb, sizeof(sb))) {
        last_error_ = "failed to read ext4 superblock";
        Close();
        return false;
    }
    if (sb.s_magic != kExt4SuperMagic) {
        last_error_ = DescribeNonExt4Header();
        Close();
        return false;
    }
    if (sb.s_log_block_size > 6u) {
        last_error_ = "unsupported ext4 block size shift";
        Close();
        return false;
    }

    block_size_ = 1024u << sb.s_log_block_size;
    first_data_block_ = sb.s_first_data_block;
    blocks_per_group_ = sb.s_blocks_per_group;
    inodes_per_group_ = sb.s_inodes_per_group;
    inodes_count_ = sb.s_inodes_count;
    feature_incompat_ = sb.s_feature_incompat;
    inode_size_ = (sb.s_rev_level >= 1u && sb.s_inode_size >= 128u) ? sb.s_inode_size : 128u;
    desc_size_ = ((feature_incompat_ & kExt4FeatureIncompat64Bit) != 0u && sb.s_desc_size >= 64u)
        ? sb.s_desc_size
        : 32u;

    blocks_count_ = static_cast<uint64_t>(sb.s_blocks_count_lo);
    if ((feature_incompat_ & kExt4FeatureIncompat64Bit) != 0u) {
        blocks_count_ |= (static_cast<uint64_t>(sb.s_blocks_count_hi) << 32);
    }
    if (blocks_per_group_ == 0 || inodes_per_group_ == 0) {
        last_error_ = "invalid ext4 group geometry";
        Close();
        return false;
    }

    uint64_t data_blocks = blocks_count_ - first_data_block_;
    group_count_ = static_cast<uint32_t>((data_blocks + blocks_per_group_ - 1ull) / blocks_per_group_);
    bgdt_offset_ = static_cast<uint64_t>(first_data_block_ + 1u) * static_cast<uint64_t>(block_size_);

    char vol[17]{};
    std::memcpy(vol, sb.s_volume_name, 16);
    volume_name_ = vol;
    return true;
}

bool Ext4Reader::ReadInode(uint32_t inode_num, RawInode& out_inode) const {
    if (inode_num == 0 || inode_num > inodes_count_) return false;
    uint32_t group = (inode_num - 1u) / inodes_per_group_;
    uint32_t index = (inode_num - 1u) % inodes_per_group_;
    if (group >= group_count_) return false;

    Ext4GroupDesc gd{};
    uint64_t gd_off = bgdt_offset_ + static_cast<uint64_t>(group) * static_cast<uint64_t>(desc_size_);
    size_t read_gd_sz = std::min(sizeof(gd), static_cast<size_t>(desc_size_));
    if (!ReadBytesAt(gd_off, &gd, read_gd_sz)) return false;

    uint64_t itable_block = gd.bg_inode_table_lo;
    if (desc_size_ >= 64u) {
        itable_block |= (static_cast<uint64_t>(gd.bg_inode_table_hi) << 32);
    }

    uint64_t inode_off = itable_block * static_cast<uint64_t>(block_size_) +
                         static_cast<uint64_t>(index) * static_cast<uint64_t>(inode_size_);
    std::memset(&out_inode, 0, sizeof(out_inode));
    return ReadBytesAt(inode_off, &out_inode, std::min(sizeof(out_inode), static_cast<size_t>(inode_size_)));
}

bool Ext4Reader::SearchExtentTree(const uint8_t* node_bytes,
                                  uint32_t logical_block,
                                  uint64_t& out_phys_block) const {
    const auto* hdr = reinterpret_cast<const Ext4ExtentHeader*>(node_bytes);
    if (hdr->eh_magic != kExt4ExtentMagic) return false;

    if (hdr->eh_depth == 0u) {
        const auto* exts = reinterpret_cast<const Ext4Extent*>(node_bytes + sizeof(Ext4ExtentHeader));
        for (uint16_t i = 0; i < hdr->eh_entries; ++i) {
            uint32_t start = exts[i].ee_block;
            uint16_t raw_len = exts[i].ee_len;
            bool uninitialized = raw_len > 32768u;
            uint32_t len = uninitialized ? (raw_len - 32768u) : raw_len;
            if (logical_block >= start && logical_block < start + len) {
                if (uninitialized) {
                    out_phys_block = 0ull;
                    return true;
                }
                uint64_t phys_base = static_cast<uint64_t>(exts[i].ee_start_lo) |
                                     (static_cast<uint64_t>(exts[i].ee_start_hi) << 32);
                out_phys_block = phys_base + (logical_block - start);
                return true;
            }
        }
        out_phys_block = 0ull; // sparse hole
        return true;
    }

    const auto* idxs = reinterpret_cast<const Ext4ExtentIdx*>(node_bytes + sizeof(Ext4ExtentHeader));
    int chosen = -1;
    for (uint16_t i = 0; i < hdr->eh_entries; ++i) {
        if (idxs[i].ei_block <= logical_block) {
            chosen = static_cast<int>(i);
        } else {
            break;
        }
    }
    if (chosen < 0) {
        out_phys_block = 0ull;
        return true;
    }

    uint64_t child_block = static_cast<uint64_t>(idxs[chosen].ei_leaf_lo) |
                           (static_cast<uint64_t>(idxs[chosen].ei_leaf_hi) << 32);
    std::vector<uint8_t> child_buf(block_size_);
    if (!ReadBlock(child_block, child_buf.data())) return false;
    return SearchExtentTree(child_buf.data(), logical_block, out_phys_block);
}

bool Ext4Reader::ReadInodeBlock(const RawInode& inode,
                                uint32_t logical_block,
                                uint64_t& out_phys_block) const {
    if (inode.UsesExtents()) {
        return SearchExtentTree(reinterpret_cast<const uint8_t*>(inode.i_block), logical_block, out_phys_block);
    }

    const uint32_t ptrs_per_block = block_size_ / 4u;
    if (logical_block < 12u) {
        out_phys_block = inode.i_block[logical_block];
        return true;
    }

    logical_block -= 12u;
    if (logical_block < ptrs_per_block) {
        uint32_t ind = inode.i_block[12];
        if (ind == 0u) {
            out_phys_block = 0ull;
            return true;
        }
        std::vector<uint32_t> table(ptrs_per_block);
        if (!ReadBlock(ind, table.data())) return false;
        out_phys_block = table[logical_block];
        return true;
    }

    logical_block -= ptrs_per_block;
    uint64_t dind_cap = static_cast<uint64_t>(ptrs_per_block) * ptrs_per_block;
    if (logical_block < dind_cap) {
        uint32_t dind = inode.i_block[13];
        if (dind == 0u) {
            out_phys_block = 0ull;
            return true;
        }
        std::vector<uint32_t> l1(ptrs_per_block), l2(ptrs_per_block);
        if (!ReadBlock(dind, l1.data())) return false;
        uint32_t idx1 = logical_block / ptrs_per_block;
        uint32_t idx2 = logical_block % ptrs_per_block;
        if (l1[idx1] == 0u) {
            out_phys_block = 0ull;
            return true;
        }
        if (!ReadBlock(l1[idx1], l2.data())) return false;
        out_phys_block = l2[idx2];
        return true;
    }

    return false;
}

bool Ext4Reader::ReadInodeData(const RawInode& inode, std::vector<uint8_t>& out_data) const {
    uint64_t sz = inode.Size();
    if (sz > 512ull * 1024ull * 1024ull) {
        last_error_ = "file exceeds 512 MiB safety limit";
        return false;
    }
    out_data.resize(static_cast<size_t>(sz));
    if (sz == 0u) return true;

    std::vector<uint8_t> blk_buf(block_size_);
    uint32_t num_blocks = static_cast<uint32_t>((sz + block_size_ - 1ull) / block_size_);
    for (uint32_t lb = 0; lb < num_blocks; ++lb) {
        uint64_t phys = 0;
        if (!ReadInodeBlock(inode, lb, phys)) return false;
        if (!ReadBlock(phys, blk_buf.data())) return false;
        uint64_t offset = static_cast<uint64_t>(lb) * block_size_;
        size_t copy_len = static_cast<size_t>(std::min<uint64_t>(block_size_, sz - offset));
        std::memcpy(out_data.data() + offset, blk_buf.data(), copy_len);
    }
    return true;
}

bool Ext4Reader::ReadSymlinkFromInode(const RawInode& inode, std::string& out_target) const {
    if (!inode.IsSymlink()) return false;
    uint64_t sz = inode.Size();
    if (sz == 0u || sz > 4096u) return false;
    if (inode.i_blocks_lo == 0u && sz < 60u) {
        const char* inline_ptr = reinterpret_cast<const char*>(inode.i_block);
        out_target.assign(inline_ptr, static_cast<size_t>(sz));
        return true;
    }
    std::vector<uint8_t> buf;
    if (!ReadInodeData(inode, buf)) return false;
    out_target.assign(reinterpret_cast<const char*>(buf.data()), buf.size());
    return true;
}

bool Ext4Reader::ReadDirFromInode(const RawInode& inode, std::vector<Ext4DirEntry>& out_entries) const {
    if (!inode.IsDirectory()) return false;
    std::vector<uint8_t> dir_bytes;
    if (!ReadInodeData(inode, dir_bytes)) return false;

    out_entries.clear();
    size_t num_blocks = dir_bytes.size() / block_size_;
    for (size_t b = 0; b < num_blocks; ++b) {
        size_t blk_start = b * block_size_;
        size_t pos = 0;
        while (pos + 8u <= block_size_) {
            const auto* de = reinterpret_cast<const Ext4DirEntry2*>(dir_bytes.data() + blk_start + pos);
            if (de->rec_len < 8u || pos + de->rec_len > block_size_) {
                break;
            }
            if (de->inode != 0u && de->name_len > 0u && pos + 8u + de->name_len <= block_size_) {
                Ext4DirEntry entry;
                entry.inode = de->inode;
                entry.file_type = de->file_type;
                entry.name.assign(de->name, de->name_len);
                out_entries.push_back(std::move(entry));
            }
            pos += de->rec_len;
        }
    }
    return true;
}

bool Ext4Reader::ResolvePathInode(const std::string& guest_path,
                                  uint32_t& out_inode_num,
                                  RawInode& out_inode,
                                  bool follow_final_symlink,
                                  int depth) const {
    if (fd_ < 0 || depth > 16) return false;
    uint32_t cur_ino = kExt4RootIno;
    RawInode cur_inode{};
    if (!ReadInode(cur_ino, cur_inode)) return false;

    std::vector<std::string> parts = SplitPath(guest_path);
    std::vector<std::string> resolved_stack;

    for (size_t idx = 0; idx < parts.size(); ++idx) {
        const std::string& part = parts[idx];
        if (part == "..") {
            if (!resolved_stack.empty()) {
                resolved_stack.pop_back();
                std::string parent_path = "/";
                for (size_t j = 0; j < resolved_stack.size(); ++j) {
                    if (j > 0) parent_path += "/";
                    parent_path += resolved_stack[j];
                }
                if (!ResolvePathInode(parent_path, cur_ino, cur_inode, true, depth + 1)) {
                    return false;
                }
            }
            continue;
        }

        if (!cur_inode.IsDirectory()) return false;
        std::vector<Ext4DirEntry> entries;
        if (!ReadDirFromInode(cur_inode, entries)) return false;

        uint32_t next_ino = 0;
        for (const auto& e : entries) {
            if (e.name == part) {
                next_ino = e.inode;
                break;
            }
        }
        if (next_ino == 0u) return false;

        RawInode next_inode{};
        if (!ReadInode(next_ino, next_inode)) return false;

        bool is_last = (idx + 1 == parts.size());
        if (next_inode.IsSymlink() && (!is_last || follow_final_symlink)) {
            std::string target;
            if (!ReadSymlinkFromInode(next_inode, target)) return false;
            std::string expanded;
            if (!target.empty() && target[0] == '/') {
                expanded = target;
            } else {
                expanded = "/";
                for (size_t j = 0; j < resolved_stack.size(); ++j) {
                    if (j > 0) expanded += "/";
                    expanded += resolved_stack[j];
                }
                if (expanded != "/") expanded += "/";
                expanded += target;
            }
            for (size_t k = idx + 1; k < parts.size(); ++k) {
                expanded += "/" + parts[k];
            }
            return ResolvePathInode(expanded, out_inode_num, out_inode, follow_final_symlink, depth + 1);
        }

        cur_ino = next_ino;
        cur_inode = next_inode;
        resolved_stack.push_back(part);
    }

    out_inode_num = cur_ino;
    out_inode = cur_inode;
    return true;
}

bool Ext4Reader::Stat(const std::string& guest_path, Ext4Stat& out_stat) const {
    uint32_t ino = 0;
    RawInode raw{};
    if (!ResolvePathInode(guest_path, ino, raw, false)) return false;
    out_stat.inode = ino;
    out_stat.mode = raw.i_mode;
    out_stat.size = raw.Size();
    out_stat.uid = raw.i_uid;
    out_stat.gid = raw.i_gid;
    out_stat.links_count = raw.i_links_count;
    return true;
}

bool Ext4Reader::Exists(const std::string& guest_path) const {
    uint32_t ino = 0;
    RawInode raw{};
    return ResolvePathInode(guest_path, ino, raw, true);
}

bool Ext4Reader::ReadSymlink(const std::string& guest_path, std::string& out_target) const {
    uint32_t ino = 0;
    RawInode raw{};
    if (!ResolvePathInode(guest_path, ino, raw, false)) return false;
    return ReadSymlinkFromInode(raw, out_target);
}

bool Ext4Reader::ReadDir(const std::string& guest_path, std::vector<Ext4DirEntry>& out_entries) const {
    uint32_t ino = 0;
    RawInode raw{};
    if (!ResolvePathInode(guest_path, ino, raw, true)) return false;
    return ReadDirFromInode(raw, out_entries);
}

bool Ext4Reader::ReadFile(const std::string& guest_path, std::vector<uint8_t>& out_data) const {
    uint32_t ino = 0;
    RawInode raw{};
    if (!ResolvePathInode(guest_path, ino, raw, true)) return false;
    if (!raw.IsRegular()) return false;
    return ReadInodeData(raw, out_data);
}

bool Ext4Reader::ReadFileString(const std::string& guest_path, std::string& out_text) const {
    std::vector<uint8_t> bytes;
    if (!ReadFile(guest_path, bytes)) return false;
    out_text.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return true;
}

} // namespace haseeb::loader
