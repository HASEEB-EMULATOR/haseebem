#include "haseeb/kernel_boot.hpp"
#include "haseeb/guest_vfs_bridge.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace haseeb::vm {

namespace {

inline constexpr uint16_t kElfEtExec = 2u;
inline constexpr uint16_t kElfEtDyn  = 3u;
inline constexpr uint16_t kElfEmAarch64 = 183u;
inline constexpr uint32_t kPtLoad = 1u;
inline constexpr uint32_t kPtInterp = 3u;
inline constexpr uint32_t kPtPhdr = 6u;
inline constexpr uint32_t kPtTls = 7u;
inline constexpr uint32_t kPfX = 1u;
inline constexpr uint32_t kPfW = 2u;
inline constexpr uint64_t kInterpLoadBase = 0x0000000020000000ULL;

#pragma pack(push, 1)
struct Elf64Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)

uint64_t AlignDown4K(uint64_t v) { return v & ~0xFFFULL; }
uint64_t AlignUp4K(uint64_t v) { return (v + 0xFFFULL) & ~0xFFFULL; }
uint64_t UntagUserVa(uint64_t va) {
    return ((va & (1ULL << 55)) == 0ULL) ? (va & 0x00FFFFFFFFFFFFFFULL) : va;
}

int64_t NowSteadyNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool AllocZeroPage(GuestRam& ram, uint64_t& cursor, uint64_t limit, uint64_t& out_pa) {
    cursor = AlignUp4K(cursor);
    if (cursor + 4096ULL > limit) return false;
    uint8_t zeros[4096]{};
    if (!ram.WriteBytes(cursor, zeros, sizeof(zeros))) return false;
    out_pa = cursor;
    cursor += 4096ULL;
    return true;
}

void EraseVmRange(std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t start, uint64_t end) {
    if (start >= end || ranges.empty()) return;
    std::vector<std::pair<uint64_t, uint64_t>> next;
    next.reserve(ranges.size());
    for (const auto& r : ranges) {
        if (r.second <= start || r.first >= end) {
            next.push_back(r);
        } else {
            if (r.first < start) next.emplace_back(r.first, start);
            if (r.second > end) next.emplace_back(end, r.second);
        }
    }
    ranges.swap(next);
}

bool IsVaInVmRanges(const std::vector<std::pair<uint64_t, uint64_t>>& ranges, uint64_t va) {
    for (const auto& r : ranges) {
        if (va >= r.first && va < r.second) return true;
    }
    return false;
}

bool RangeOverlapsVmRanges(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                           uint64_t start,
                           uint64_t end) {
    for (const auto& r : ranges) {
        if (start < r.second && end > r.first) return true;
    }
    return false;
}

std::string NormalizeGuestPath(const std::string& raw) {
    if (raw.empty()) return "/";
    std::vector<std::string> parts;
    size_t i = 0;
    while (i < raw.size()) {
        while (i < raw.size() && raw[i] == '/') ++i;
        size_t j = i;
        while (j < raw.size() && raw[j] != '/') ++j;
        if (j > i) {
            std::string seg = raw.substr(i, j - i);
            if (seg == "..") {
                if (!parts.empty()) parts.pop_back();
            } else if (seg != ".") {
                parts.push_back(std::move(seg));
            }
        }
        i = j;
    }
    if (parts.empty()) return "/";
    std::string clean;
    for (const auto& p : parts) {
        clean.push_back('/');
        clean += p;
    }
    return clean;
}

bool ParseNonNegInt(const std::string& s, int& out_val);

bool ParseProcAttrPath(const std::string& norm, bool& out_is_dir, std::string& out_leaf) {
    out_is_dir = false;
    out_leaf.clear();
    if (norm.rfind("/proc/", 0) != 0) return false;
    const std::string rest = norm.substr(6);
    const size_t slash1 = rest.find('/');
    if (slash1 == std::string::npos) return false;
    const std::string who = rest.substr(0, slash1);
    int tmp_pid = 0;
    if (who != "self" && who != "thread-self" && !ParseNonNegInt(who, tmp_pid)) return false;
    const std::string tail = rest.substr(slash1 + 1u);
    if (tail == "attr") {
        out_is_dir = true;
        return true;
    }
    if (tail.rfind("attr/", 0) == 0) {
        const std::string leaf = tail.substr(5);
        if (leaf == "current" || leaf == "exec" || leaf == "fscreate" ||
            leaf == "sockcreate" || leaf == "keycreate" || leaf == "prev") {
            out_leaf = leaf;
            return true;
        }
    }
    return false;
}

bool IsProcAttrFilePath(const std::string& norm) {
    bool is_dir = false;
    std::string leaf;
    return ParseProcAttrPath(norm, is_dir, leaf) && !is_dir;
}

bool IsWritableGuestOverlayPath(const std::string& norm) {
    if (IsProcAttrFilePath(norm)) return true;
    static constexpr const char* kPrefixes[] = {
        "/dev", "/data", "/mnt", "/acct", "/cache", "/metadata",
        "/linkerconfig", "/tmp", "/var", "/apex", "/debug_ramdisk", "/config",
        "/sys/fs/cgroup", "/storage", "/proc/sys/kernel"
    };
    for (const char* p : kPrefixes) {
        const size_t plen = std::strlen(p);
        if (norm == p) return true;
        if (norm.size() > plen && norm.compare(0, plen, p) == 0 && norm[plen] == '/') return true;
    }
    return false;
}

std::string ParentDirOf(const std::string& norm) {
    const size_t slash = norm.find_last_of('/');
    if (slash == std::string::npos || slash == 0u) return "/";
    return norm.substr(0, slash);
}

uint64_t ComputeGuestInode(const std::string& key) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : key) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return (h == 0ULL) ? 1ULL : h;
}

bool IsBlockDevicePath(const std::string& norm) {
    return norm == "/dev/block/vda" ||
           norm.rfind("/dev/block/by-name/", 0) == 0;
}

bool IsSelinuxWritableNode(const std::string& norm) {
    return norm == "/sys/fs/selinux/load" ||
           norm == "/sys/fs/selinux/enforce" ||
           norm == "/sys/fs/selinux/disable" ||
           norm == "/sys/fs/selinux/checkreqprot" ||
           norm == "/sys/fs/selinux/deny_unknown" ||
           norm == "/sys/fs/selinux/commit_pending_bools" ||
           norm == "/sys/fs/selinux/access" ||
           norm == "/sys/fs/selinux/create" ||
           norm == "/sys/fs/selinux/context";
}

std::string ExtractCmdlineParam(const std::string& cmdline, const std::string& key) {
    const std::string needle = key + "=";
    size_t pos = cmdline.find(needle);
    while (pos != std::string::npos) {
        if (pos == 0 || cmdline[pos - 1] == ' ' || cmdline[pos - 1] == '\t') {
            const size_t vstart = pos + needle.size();
            size_t vend = vstart;
            while (vend < cmdline.size() && cmdline[vend] != ' ' &&
                   cmdline[vend] != '\t' && cmdline[vend] != '\n') {
                ++vend;
            }
            return cmdline.substr(vstart, vend - vstart);
        }
        pos = cmdline.find(needle, pos + 1u);
    }
    return {};
}

bool IsGuestCharDevicePath(const std::string& norm) {
    return norm == "/dev/null" || norm == "/dev/zero" ||
           norm == "/dev/urandom" || norm == "/dev/random" ||
           norm == "/dev/fb0" ||
           norm == "/dev/binder" || norm == "/dev/hwbinder" || norm == "/dev/vndbinder" ||
           norm == "/dev/ashmem" || norm == "/dev/ion" || norm == "/dev/dma_heap/system" ||
           norm == "/dev/kmsg" || norm == "/dev/tty" || norm == "/dev/ptmx" ||
           norm == "/dev/input/event0" || norm == "/dev/input/event1" ||
           norm == "/dev/haseeb_sensors" || norm == "/dev/video0" ||
           norm == "/dev/haseeb_gles" || norm == "/dev/magisk_su" ||
           norm == "/dev/snd/pcmC0D0p" || norm == "/dev/snd/pcmC0D0c" ||
           norm == "/dev/stdin" || norm == "/dev/stdout" || norm == "/dev/stderr" ||
           norm == "/sys/fs/selinux/null";
}

uint64_t ComputeDeviceRdev(const std::string& norm) {
    if (IsBlockDevicePath(norm)) return (254ULL << 8) | 0ULL;
    if (norm == "/dev/null" || norm == "/sys/fs/selinux/null") return (1ULL << 8) | 3ULL;
    if (norm == "/dev/zero") return (1ULL << 8) | 5ULL;
    if (norm == "/dev/random") return (1ULL << 8) | 8ULL;
    if (norm == "/dev/urandom") return (1ULL << 8) | 9ULL;
    if (norm == "/dev/kmsg") return (1ULL << 8) | 11ULL;
    if (norm == "/dev/tty") return (5ULL << 8) | 0ULL;
    if (norm == "/dev/ptmx") return (5ULL << 8) | 2ULL;
    if (IsGuestCharDevicePath(norm)) return (10ULL << 8) | 1ULL;
    return 0ULL;
}

bool ParseNonNegInt(const std::string& s, int& out_val) {
    if (s.empty() || s.size() > 9u) return false;
    uint64_t acc = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        acc = acc * 10ULL + static_cast<uint64_t>(c - '0');
        if (acc > 0x7FFFFFFFULL) return false;
    }
    out_val = static_cast<int>(acc);
    return true;
}

bool MapElfSegments(GuestRam& ram,
                    uint64_t ttbr0_pa,
                    uint64_t& phys_alloc_cursor,
                    uint64_t phys_alloc_limit,
                    const std::vector<uint8_t>& elf_bytes,
                    const Elf64Ehdr& eh,
                    uint64_t load_bias,
                    uint64_t& out_first_pt_load_va,
                    bool& out_has_pt_load,
                    uint64_t& inout_highest_va,
                    std::string& out_error) {
    std::unordered_map<uint64_t, uint64_t> mapped_va_to_pa;
    out_has_pt_load = false;
    out_first_pt_load_va = 0ULL;

    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64Phdr ph{};
        std::memcpy(&ph, elf_bytes.data() + eh.e_phoff + static_cast<size_t>(i) * eh.e_phentsize, sizeof(ph));
        if (ph.p_type != kPtLoad || ph.p_memsz == 0) continue;
        if (ph.p_offset + ph.p_filesz > elf_bytes.size()) {
            out_error = "ELF64 PT_LOAD segment out of file bounds";
            return false;
        }

        const uint64_t seg_va = load_bias + ph.p_vaddr;
        if (!out_has_pt_load) {
            out_first_pt_load_va = AlignDown4K(seg_va);
            out_has_pt_load = true;
        }
        const uint64_t page_start = AlignDown4K(seg_va);
        const uint64_t page_end = AlignUp4K(seg_va + ph.p_memsz);
        if (load_bias < kInterpLoadBase && page_end > inout_highest_va) {
            inout_highest_va = page_end;
        }

        const bool writable = (ph.p_flags & kPfW) != 0;
        const bool executable = (ph.p_flags & kPfX) != 0;

        for (uint64_t va = page_start; va < page_end; va += 4096ULL) {
            uint64_t pa = 0;
            auto it = mapped_va_to_pa.find(va);
            if (it == mapped_va_to_pa.end()) {
                if (!AllocZeroPage(ram, phys_alloc_cursor, phys_alloc_limit, pa)) {
                    out_error = "Out of guest RAM while mapping ELF64 segment";
                    return false;
                }
                mapped_va_to_pa[va] = pa;
            } else {
                pa = it->second;
            }
            if (!Elf64GuestLoader::MapPage4K(ram, ttbr0_pa, phys_alloc_cursor, phys_alloc_limit,
                                             va, pa, true, writable, executable)) {
                out_error = "Failed installing Stage-1 page table entry for ELF64";
                return false;
            }
        }

        uint64_t copied = 0;
        while (copied < ph.p_filesz) {
            const uint64_t cur_va = seg_va + copied;
            const uint64_t va_pg = AlignDown4K(cur_va);
            const uint64_t pg_off = cur_va - va_pg;
            const size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(4096ULL - pg_off, ph.p_filesz - copied));
            uint64_t pa = mapped_va_to_pa.at(va_pg);
            if (!ram.WriteBytes(pa + pg_off, elf_bytes.data() + ph.p_offset + copied, chunk)) {
                out_error = "Failed writing ELF64 segment bytes to guest RAM";
                return false;
            }
            copied += chunk;
        }
    }
    return true;
}

// Clones an EL0 address space for POSIX fork(): shares RX/RO & EL1 VBAR pages,
// deep-copies writable EL0 stack/data pages so parent and child never corrupt each other.
bool CloneUserAddressSpace(GuestRam& ram,
                           uint64_t src_ttbr0_pa,
                           uint64_t& dst_ttbr0_pa,
                           uint64_t& phys_cursor,
                           uint64_t phys_limit) {
    if (!AllocZeroPage(ram, phys_cursor, phys_limit, dst_ttbr0_pa)) {
        return false;
    }
    uint8_t copy_buf[4096];
    for (uint64_t l1 = 0; l1 < 512ULL; ++l1) {
        uint64_t d1 = 0;
        if (!ram.ReadU64(src_ttbr0_pa + l1 * 8ULL, d1) || (d1 & 3ULL) != 3ULL) continue;
        const uint64_t l2_pa = d1 & 0x0000FFFFFFFFF000ULL;
        for (uint64_t l2 = 0; l2 < 512ULL; ++l2) {
            uint64_t d2 = 0;
            if (!ram.ReadU64(l2_pa + l2 * 8ULL, d2) || (d2 & 3ULL) != 3ULL) continue;
            const uint64_t l3_pa = d2 & 0x0000FFFFFFFFF000ULL;
            for (uint64_t l3 = 0; l3 < 512ULL; ++l3) {
                uint64_t leaf = 0;
                if (!ram.ReadU64(l3_pa + l3 * 8ULL, leaf) || (leaf & 3ULL) != 3ULL) continue;
                const uint64_t va = (l1 << 30) | (l2 << 21) | (l3 << 12);
                const uint64_t pa = leaf & 0x0000FFFFFFFFF000ULL;
                const bool el0_access = (leaf & (1ULL << 6)) != 0ULL;
                const bool writable = (leaf & (1ULL << 7)) == 0ULL;
                const bool executable = el0_access ? ((leaf & (1ULL << 54)) == 0ULL)
                                                   : ((leaf & (1ULL << 53)) == 0ULL);

                uint64_t target_pa = pa;
                if (el0_access && writable && !executable) {
                    if (!AllocZeroPage(ram, phys_cursor, phys_limit, target_pa)) return false;
                    if (!ram.ReadBytes(pa, copy_buf, sizeof(copy_buf)) ||
                        !ram.WriteBytes(target_pa, copy_buf, sizeof(copy_buf))) {
                        return false;
                    }
                }
                if (!Elf64GuestLoader::MapPage4K(ram, dst_ttbr0_pa, phys_cursor, phys_limit,
                                                 va, target_pa, el0_access, writable, executable)) {
                    return false;
                }
            }
        }
    }
    return true;
}

const char* ExceptionClassName(uint32_t ec_val) {
    switch (ec_val) {
        case ec::kUnknown:       return "UNKNOWN_INSN";
        case ec::kTrapWfiWfe:    return "TRAP_WFI_WFE";
        case ec::kFpSimdAccess:  return "FP_SIMD_DISABLED";
        case ec::kIllegalState:  return "ILLEGAL_EXEC_STATE";
        case ec::kSvc64:         return "SVC64";
        case ec::kHvc64:         return "HVC64";
        case ec::kSmc64:         return "SMC64";
        case ec::kSysRegTrap:    return "SYSREG_TRAP";
        case ec::kInsnAbortLow:  return "INSN_ABORT_EL0";
        case ec::kInsnAbortSame: return "INSN_ABORT_EL1";
        case ec::kPcAlign:       return "PC_ALIGNMENT";
        case ec::kDataAbortLow:  return "DATA_ABORT_EL0";
        case ec::kDataAbortSame: return "DATA_ABORT_EL1";
        case ec::kSpAlign:       return "SP_ALIGNMENT";
        case ec::kBrk64:         return "BRK_TRAP";
        default:                 return "SYNC_TRAP";
    }
}

} // namespace

bool Elf64GuestLoader::IsValidAArch64Elf(const std::vector<uint8_t>& elf_bytes) {
    if (elf_bytes.size() < sizeof(Elf64Ehdr)) return false;
    Elf64Ehdr eh{};
    std::memcpy(&eh, elf_bytes.data(), sizeof(eh));
    return eh.e_ident[0] == 0x7Fu && eh.e_ident[1] == 'E' &&
           eh.e_ident[2] == 'L' && eh.e_ident[3] == 'F' &&
           eh.e_ident[4] == 2u && eh.e_ident[5] == 1u &&
           eh.e_machine == kElfEmAarch64 &&
           (eh.e_type == kElfEtExec || eh.e_type == kElfEtDyn);
}

bool Elf64GuestLoader::MapPage4K(GuestRam& ram,
                                 uint64_t ttbr0_pa,
                                 uint64_t& phys_alloc_cursor,
                                 uint64_t phys_alloc_limit,
                                 uint64_t va,
                                 uint64_t pa,
                                 bool el0_access,
                                 bool writable,
                                 bool executable) {
    const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
    const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
    const uint64_t l3_idx = (va >> 12) & 0x1FFULL;

    auto ensure_table = [&](uint64_t table_pa, uint64_t idx, uint64_t& next_table_pa) -> bool {
        uint64_t desc = 0;
        if (!ram.ReadU64(table_pa + idx * 8ULL, desc)) return false;
        if ((desc & 3ULL) == 3ULL) {
            next_table_pa = desc & 0x0000FFFFFFFFF000ULL;
            return true;
        }
        if (!AllocZeroPage(ram, phys_alloc_cursor, phys_alloc_limit, next_table_pa)) {
            return false;
        }
        return ram.WriteU64(table_pa + idx * 8ULL, next_table_pa | 3ULL);
    };

    uint64_t l2_pa = 0, l3_pa = 0;
    if (!ensure_table(ttbr0_pa, l1_idx, l2_pa) ||
        !ensure_table(l2_pa, l2_idx, l3_pa)) {
        return false;
    }

    uint64_t leaf = (pa & 0x0000FFFFFFFFF000ULL) | 3ULL; // Valid L3 page
    leaf |= (1ULL << 10);                                 // AF = 1
    if (el0_access) leaf |= (1ULL << 6);                  // AP[1] = 1 (EL0 allowed)
    if (!writable) leaf |= (1ULL << 7);                   // AP[2] = 1 (Read-Only)
    if (el0_access) {
        leaf |= (1ULL << 53);                             // PXN = 1 for user pages
        if (!executable) leaf |= (1ULL << 54);            // UXN = 1 when non-exec
    } else {
        leaf |= (1ULL << 54);                             // UXN = 1 for EL1 pages
        if (!executable) leaf |= (1ULL << 53);            // PXN = 1 when non-exec
    }
    return ram.WriteU64(l3_pa + l3_idx * 8ULL, leaf);
}

Elf64LoadResult Elf64GuestLoader::LoadAndMap(GuestRam& ram,
                                             uint64_t ttbr0_pa,
                                             uint64_t& phys_alloc_cursor,
                                             uint64_t phys_alloc_limit,
                                             const std::vector<uint8_t>& elf_bytes,
                                             const std::vector<std::string>& argv,
                                             const std::vector<std::string>& envp) {
    return LoadAndMap(ram, ttbr0_pa, phys_alloc_cursor, phys_alloc_limit, elf_bytes, argv, envp, {});
}

Elf64LoadResult Elf64GuestLoader::LoadAndMap(GuestRam& ram,
                                             uint64_t ttbr0_pa,
                                             uint64_t& phys_alloc_cursor,
                                             uint64_t phys_alloc_limit,
                                             const std::vector<uint8_t>& elf_bytes,
                                             const std::vector<std::string>& argv,
                                             const std::vector<std::string>& envp,
                                             const FileResolverFn& interp_resolver) {
    Elf64LoadResult res;
    if (!IsValidAArch64Elf(elf_bytes)) {
        res.error = "Invalid or non-AArch64 ELF64 binary";
        return res;
    }

    Elf64Ehdr eh{};
    std::memcpy(&eh, elf_bytes.data(), sizeof(eh));
    if (eh.e_phnum == 0 || eh.e_phentsize < sizeof(Elf64Phdr) ||
        eh.e_phoff + static_cast<uint64_t>(eh.e_phnum) * eh.e_phentsize > elf_bytes.size()) {
        res.error = "Corrupt ELF64 program header table";
        return res;
    }

    const uint64_t load_bias = (eh.e_type == kElfEtDyn) ? 0x0000000000400000ULL : 0ULL;
    uint64_t highest_va = load_bias + 0x10000ULL;
    uint64_t first_pt_load_va = 0;
    bool has_pt_load = false;

    uint64_t pt_phdr_va = 0;
    bool has_pt_phdr = false;
    uint64_t pt_load_phdr_va = 0;
    bool has_load_phdr = false;

    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64Phdr ph{};
        std::memcpy(&ph, elf_bytes.data() + eh.e_phoff + static_cast<size_t>(i) * eh.e_phentsize, sizeof(ph));
        if (ph.p_type == kPtPhdr && !has_pt_phdr) {
            pt_phdr_va = load_bias + ph.p_vaddr;
            has_pt_phdr = true;
        } else if (ph.p_type == kPtLoad && !has_load_phdr &&
                   eh.e_phoff >= ph.p_offset &&
                   eh.e_phoff < ph.p_offset + ph.p_filesz) {
            pt_load_phdr_va = load_bias + ph.p_vaddr + (eh.e_phoff - ph.p_offset);
            has_load_phdr = true;
        } else if (ph.p_type == kPtTls) {
            res.has_tls = true;
        } else if (ph.p_type == kPtInterp && ph.p_filesz > 1u &&
                   ph.p_offset + ph.p_filesz <= elf_bytes.size()) {
            res.is_dynamic = true;
            std::string raw(reinterpret_cast<const char*>(elf_bytes.data() + ph.p_offset),
                            static_cast<size_t>(ph.p_filesz));
            while (!raw.empty() && raw.back() == '\0') raw.pop_back();
            res.interp_path = raw;
        }
    }

    if (!MapElfSegments(ram, ttbr0_pa, phys_alloc_cursor, phys_alloc_limit, elf_bytes, eh,
                        load_bias, first_pt_load_va, has_pt_load, highest_va, res.error)) {
        return res;
    }

    uint64_t start_pc = load_bias + eh.e_entry;
    if (res.is_dynamic && !res.interp_path.empty()) {
        std::vector<uint8_t> interp_bytes;
        if (!interp_resolver || !interp_resolver(res.interp_path, interp_bytes)) {
            res.error = "Dynamic ELF64 requires interpreter " + res.interp_path +
                        " (not found in ramdisk or system.img)";
            return res;
        }
        if (!IsValidAArch64Elf(interp_bytes)) {
            res.error = "Invalid AArch64 ELF64 dynamic linker: " + res.interp_path;
            return res;
        }
        Elf64Ehdr interp_eh{};
        std::memcpy(&interp_eh, interp_bytes.data(), sizeof(interp_eh));
        if (interp_eh.e_phnum == 0 || interp_eh.e_phentsize < sizeof(Elf64Phdr) ||
            interp_eh.e_phoff + static_cast<uint64_t>(interp_eh.e_phnum) * interp_eh.e_phentsize >
                interp_bytes.size()) {
            res.error = "Corrupt dynamic linker program header table";
            return res;
        }
        const uint64_t interp_bias = (interp_eh.e_type == kElfEtDyn) ? kInterpLoadBase : 0ULL;
        uint64_t interp_first = 0ULL;
        bool interp_has_load = false;
        uint64_t interp_high = interp_bias;
        if (!MapElfSegments(ram, ttbr0_pa, phys_alloc_cursor, phys_alloc_limit, interp_bytes,
                            interp_eh, interp_bias, interp_first, interp_has_load,
                            interp_high, res.error)) {
            return res;
        }
        res.interp_base = interp_bias;
        start_pc = interp_bias + interp_eh.e_entry;
    }

    // Allocate 64 KiB EL0 user stack near top of 32-bit user VA space (0x7FFE0000..0x7FFF0000)
    constexpr uint64_t kUserStackTop = 0x000000007FFF0000ULL;
    constexpr uint64_t kUserStackSize = 64ULL * 1024ULL;
    const uint64_t stack_bottom = kUserStackTop - kUserStackSize;
    std::unordered_map<uint64_t, uint64_t> stack_pages;
    for (uint64_t va = stack_bottom; va < kUserStackTop; va += 4096ULL) {
        uint64_t pa = 0;
        if (!AllocZeroPage(ram, phys_alloc_cursor, phys_alloc_limit, pa) ||
            !MapPage4K(ram, ttbr0_pa, phys_alloc_cursor, phys_alloc_limit,
                       va, pa, true, true, false)) {
            res.error = "Out of guest RAM while mapping EL0 user stack";
            return res;
        }
        stack_pages[va] = pa;
    }

    auto write_stack = [&](uint64_t va, const void* src, size_t len) -> bool {
        size_t off = 0;
        while (off < len) {
            uint64_t cur = va + off;
            uint64_t pg = AlignDown4K(cur);
            size_t in_pg = static_cast<size_t>(cur - pg);
            size_t chunk = std::min(4096u - in_pg, len - off);
            if (!ram.WriteBytes(stack_pages.at(pg) + in_pg,
                                static_cast<const uint8_t*>(src) + off, chunk)) {
                return false;
            }
            off += chunk;
        }
        return true;
    };

    // Build Linux AArch64 initial user stack: strings + AT_PLATFORM + AT_RANDOM + auxv + envp + argv + argc
    uint64_t sp = kUserStackTop - 16ULL;
    const char platform_str[] = "aarch64";
    sp -= sizeof(platform_str);
    uint64_t platform_va = sp;
    write_stack(platform_va, platform_str, sizeof(platform_str));

    uint8_t rand16[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    sp -= 16ULL;
    uint64_t random_va = sp;
    write_stack(random_va, rand16, sizeof(rand16));

    std::vector<uint64_t> env_vas;
    for (const auto& s : envp) {
        sp -= (s.size() + 1u);
        write_stack(sp, s.c_str(), s.size() + 1u);
        env_vas.push_back(sp);
    }
    std::vector<uint64_t> arg_vas;
    for (const auto& s : argv) {
        sp -= (s.size() + 1u);
        write_stack(sp, s.c_str(), s.size() + 1u);
        arg_vas.push_back(sp);
    }

    sp &= ~15ULL; // 16-byte AArch64 SP alignment
    std::vector<uint64_t> words;
    words.push_back(argv.size());
    for (uint64_t p : arg_vas) words.push_back(p);
    words.push_back(0ULL);
    for (uint64_t p : env_vas) words.push_back(p);
    words.push_back(0ULL);

    const uint64_t phdr_va = has_pt_phdr
                                 ? pt_phdr_va
                                 : (has_load_phdr ? pt_load_phdr_va
                                                  : (has_pt_load ? (first_pt_load_va + eh.e_phoff) : 0ULL));
    auto push_aux = [&](uint64_t key, uint64_t val) {
        words.push_back(key);
        words.push_back(val);
    };
    push_aux(3u, phdr_va);                 // AT_PHDR
    push_aux(4u, eh.e_phentsize);          // AT_PHENT
    push_aux(5u, eh.e_phnum);              // AT_PHNUM
    push_aux(6u, 4096ULL);                 // AT_PAGESZ
    push_aux(7u, res.interp_base);         // AT_BASE
    push_aux(8u, 0ULL);                    // AT_FLAGS
    push_aux(9u, load_bias + eh.e_entry);  // AT_ENTRY
    push_aux(11u, 0ULL);                   // AT_UID
    push_aux(12u, 0ULL);                   // AT_EUID
    push_aux(13u, 0ULL);                   // AT_GID
    push_aux(14u, 0ULL);                   // AT_EGID
    push_aux(15u, platform_va);            // AT_PLATFORM
    push_aux(16u, 0x1FFULL);               // AT_HWCAP (FP|ASIMD|EVTSTRM|AES|PMULL|SHA1|SHA2|CRC32|ATOMICS)
    push_aux(17u, 100ULL);                 // AT_CLKTCK
    push_aux(23u, 0ULL);                   // AT_SECURE
    push_aux(25u, random_va);              // AT_RANDOM
    push_aux(26u, 0ULL);                   // AT_HWCAP2
    if (!arg_vas.empty()) {
        push_aux(31u, arg_vas.front());    // AT_EXECFN
    }
    push_aux(0u, 0ULL);                    // AT_NULL

    const uint64_t table_bytes = words.size() * sizeof(uint64_t);
    sp = (sp - table_bytes) & ~15ULL;
    if (!write_stack(sp, words.data(), table_bytes)) {
        res.error = "Failed writing initial EL0 stack frame";
        return res;
    }

    res.ok = true;
    res.entry_pc = start_pc;
    res.phdr_va = phdr_va;
    res.phent_size = eh.e_phentsize;
    res.phnum = eh.e_phnum;
    res.brk_start = highest_va;
    res.stack_top = kUserStackTop;
    res.initial_sp = sp;
    return res;
}

// =========================================================================
// LinuxGuestSupervisor (Multi-Process EL1 Trap & Linux ARM64 SVC Engine)
// =========================================================================

LinuxGuestSupervisor::LinuxGuestSupervisor(GuestRam& ram,
                                           Pl011Uart& uart,
                                           PsciController& psci,
                                           const loader::Ext4Reader* ext4,
                                           VirtioGpuDevice* gpu,
                                           VirtioInputDevice* touch,
                                           VirtioInputDevice* kbd)
    : ram_(ram), uart_(uart), psci_(psci), ext4_(ext4), gpu_(gpu), touch_(touch), kbd_(kbd) {}

LinuxGuestSupervisor::~LinuxGuestSupervisor() {
    CloseAllOpenFds();
}

LinuxGuestSupervisor::UnixSocketEndpoint::~UnixSocketEndpoint() {
    for (auto& chunk : rx_chunks) {
        for (auto& f : chunk.passed_fds) {
            if (f && f->host_fd >= 0) {
                ::close(f->host_fd);
                f->host_fd = -1;
            }
        }
    }
}

void LinuxGuestSupervisor::CloseSingleOpenFile(OpenFile& of) {
    if (of.host_fd >= 0) {
        ::close(of.host_fd);
        of.host_fd = -1;
    }
    if (of.unix_sock && of.unix_sock.use_count() == 1) {
        if (!of.unix_sock->bound_path.empty()) {
            auto bit = unix_bound_sockets_.find(of.unix_sock->bound_path);
            if (bit != unix_bound_sockets_.end()) {
                auto locked = bit->second.lock();
                if (!locked || locked.get() == of.unix_sock.get()) {
                    unix_bound_sockets_.erase(bit);
                }
            }
        }
        if (auto p = of.unix_sock->peer.lock()) {
            p->peer_closed = true;
            WakePollWaiters();
        }
    }
    if (of.is_binder && of.binder_client_id != 0u) {
        const uint32_t cid = of.binder_client_id;
        of.binder_client_id = 0u;
        bool still_referenced = false;
        for (const auto& t : tasks_) {
            if (!t || !t->files) continue;
            for (const auto& kv : t->files->fds) {
                if (kv.second.is_binder && kv.second.binder_client_id == cid) {
                    still_referenced = true;
                    break;
                }
            }
            if (still_referenced) break;
        }
        if (!still_referenced) {
            binder_broker_.CloseClient(cid, [this](int32_t target_pid) {
                WakeBinderWaitersForPid(target_pid);
            });
        }
    }
}

void LinuxGuestSupervisor::CloseTaskOpenFds(GuestTask& task) {
    if (!task.files || task.files.use_count() > 1) {
        task.files.reset();
        return;
    }
    auto fds_copy = std::move(task.files->fds);
    task.files->fds.clear();
    for (auto& kv : fds_copy) {
        CloseSingleOpenFile(kv.second);
    }
}

void LinuxGuestSupervisor::CloseAllOpenFds() {
    for (auto& t : tasks_) {
        if (t && t->files) {
            for (auto& kv : t->files->fds) {
                if (kv.second.host_fd >= 0) {
                    ::close(kv.second.host_fd);
                    kv.second.host_fd = -1;
                }
            }
            t->files->fds.clear();
        }
    }
    for (auto& kv : open_fds_) {
        if (kv.second.host_fd >= 0) {
            ::close(kv.second.host_fd);
            kv.second.host_fd = -1;
        }
    }
    open_fds_.clear();
    unix_bound_sockets_.clear();
    binder_broker_.Clear();
}

LinuxGuestSupervisor::GuestTask* LinuxGuestSupervisor::CurrentTask() {
    if (tasks_.empty() || current_task_idx_ >= tasks_.size()) return nullptr;
    return tasks_[current_task_idx_].get();
}

const LinuxGuestSupervisor::GuestTask* LinuxGuestSupervisor::CurrentTask() const {
    if (tasks_.empty() || current_task_idx_ >= tasks_.size()) return nullptr;
    return tasks_[current_task_idx_].get();
}

size_t LinuxGuestSupervisor::ActiveTaskCount() const {
    size_t count = 0;
    for (const auto& t : tasks_) {
        if (t && t->state != TaskState::Zombie) ++count;
    }
    return count;
}

void LinuxGuestSupervisor::SaveTaskContext(const CpuState& st, GuestTask& task) const {
    std::memcpy(task.cpu.x, st.x, sizeof(task.cpu.x));
    task.cpu.sp_el0 = st.sp_el[0];
    task.cpu.elr_el1 = st.sys.elr_el1;
    task.cpu.spsr_el1 = st.sys.spsr_el1;
    task.cpu.tpidr_el0 = st.sys.tpidr_el0;
    task.cpu.fpcr = st.fpcr;
    task.cpu.fpsr = st.fpsr;
    task.cpu.v = st.v;
    task.uid = uid_;
    task.gid = gid_;
    if (task.vm) {
        task.vm->current_brk = current_brk_;
        task.vm->mmap_cursor = mmap_cursor_;
        task.vm->ttbr0_pa = ttbr0_pa_;
    }
    task.binary = active_binary_;
}

void LinuxGuestSupervisor::RestoreTaskContext(AArch64CpuCore& cpu,
                                                CpuState& st,
                                                const GuestTask& task) const {
    const uint64_t vm_ttbr0 = task.vm ? task.vm->ttbr0_pa : 0ULL;
    const int32_t asid = (task.tgid > 0) ? task.tgid : task.pid;
    const uint64_t new_ttbr0 = (vm_ttbr0 & 0x0000FFFFFFFFF000ULL) |
                               (static_cast<uint64_t>(asid & 0xFFFFu) << 48);
    if (st.sys.ttbr0_el1 != new_ttbr0) {
        cpu.Mmu().InvalidateAll();
        cpu.Cache().InvalidateAll();
    }
    std::memcpy(st.x, task.cpu.x, sizeof(st.x));
    st.sp_el[0] = task.cpu.sp_el0;
    st.sys.elr_el1 = task.cpu.elr_el1;
    st.sys.spsr_el1 = task.cpu.spsr_el1;
    st.sys.tpidr_el0 = task.cpu.tpidr_el0;
    st.sys.ttbr0_el1 = new_ttbr0;
    st.fpcr = task.cpu.fpcr;
    st.fpsr = task.cpu.fpsr;
    st.v = task.cpu.v;
    st.waiting_for_interrupt = false;
}

uint32_t LinuxGuestSupervisor::ComputeFdPollEvents(const OpenFile& of) const {
    const int64_t now = NowSteadyNs();
    uint32_t ev = 0u;
    if (of.input_dev != nullptr) {
        if (of.input_dev->HasPendingEvdev()) ev |= 0x001u; // EPOLLIN
        return ev;
    }
    if (of.is_eventfd) {
        if (of.eventfd_counter > 0ULL) ev |= 0x001u;
        ev |= 0x004u; // EPOLLOUT
        return ev;
    }
    if (of.is_timerfd) {
        if (of.timerfd_expirations > 0ULL ||
            (of.timerfd_next_expire_ns > 0 && now >= of.timerfd_next_expire_ns)) {
            ev |= 0x001u;
        }
        return ev;
    }
    if (of.is_binder) {
        if (binder_broker_.HasPendingRead(of.binder_client_id)) ev |= 0x001u;
        ev |= 0x004u;
        return ev;
    }
    if (of.unix_sock) {
        if (of.unix_sock->listening) {
            if (!of.unix_sock->pending_accept.empty()) ev |= 0x001u;
        } else {
            if (!of.unix_sock->rx_chunks.empty()) ev |= 0x001u;
            if (of.unix_sock->peer_closed || of.unix_sock->shutdown_rd) ev |= 0x010u | 0x001u; // EPOLLHUP|EPOLLIN
            if (!of.unix_sock->shutdown_wr && !of.unix_sock->peer_closed) ev |= 0x004u;
        }
        return ev;
    }
    if (of.host_fd >= 0) {
        struct pollfd pfd{};
        pfd.fd = of.host_fd;
        pfd.events = POLLIN | POLLOUT;
        if (::poll(&pfd, 1, 0) > 0) {
            if (pfd.revents & POLLIN) ev |= 0x001u;
            if (pfd.revents & POLLOUT) ev |= 0x004u;
            if (pfd.revents & POLLERR) ev |= 0x008u;
            if (pfd.revents & POLLHUP) ev |= 0x010u;
        }
        return ev;
    }
    return 0x001u | 0x004u;
}

uint32_t LinuxGuestSupervisor::ComputeGuestFdPollEvents(const std::unordered_map<int, OpenFile>& fds,
                                                        int fd) const {
    if (fd < 0) return 0u;
    if (fd == 0) {
        return ((uart_.Read(0x018ULL, 4) & (1u << 4)) == 0u) ? 0x001u : 0u;
    }
    if (fd == 1 || fd == 2) return 0x004u;
    auto it = fds.find(fd);
    if (it == fds.end()) return 0x020u; // POLLNVAL
    return ComputeFdPollEvents(it->second);
}

void LinuxGuestSupervisor::WakeBinderWaitersForPid(int32_t target_pid) {
    for (auto& t : tasks_) {
        if (!t || t->state == TaskState::Zombie) continue;
        if (t->pid == target_pid || t->tgid == target_pid) {
            if (t->state == TaskState::BinderWait || t->state == TaskState::PollWait) {
                t->state = TaskState::Runnable;
            }
        }
    }
}

void LinuxGuestSupervisor::WakePollWaiters() {
    for (auto& t : tasks_) {
        if (t && t->state == TaskState::PollWait) {
            t->state = TaskState::Runnable;
        }
    }
}

int LinuxGuestSupervisor::WakeFutexWaiters(uint64_t pa, int max_wake, uint32_t bitset) {
    if (max_wake <= 0) return 0;
    int woken = 0;
    for (auto& t : tasks_) {
        if (!t || t->state != TaskState::FutexWait) continue;
        if (t->futex_pa == pa && (t->futex_bitset & bitset) != 0u) {
            t->cpu.x[0] = 0ULL;
            t->futex_pa = 0ULL;
            t->futex_has_timeout = false;
            t->state = TaskState::Runnable;
            if (++woken >= max_wake) break;
        }
    }
    return woken;
}

void LinuxGuestSupervisor::WakeSleepingTasks() {
    const int64_t now = NowSteadyNs();
    for (auto& t : tasks_) {
        if (!t || t->state == TaskState::Zombie || t->state == TaskState::Runnable) continue;

        // Advance armed timerfds
        if (t->files) {
            for (auto& kv : t->files->fds) {
                OpenFile& of = kv.second;
                if (of.is_timerfd && of.timerfd_next_expire_ns > 0 && now >= of.timerfd_next_expire_ns) {
                    if (of.timerfd_interval_ns > 0) {
                        const int64_t elapsed = now - of.timerfd_next_expire_ns;
                        const int64_t ticks = 1 + (elapsed / of.timerfd_interval_ns);
                        of.timerfd_expirations += static_cast<uint64_t>(ticks);
                        of.timerfd_next_expire_ns += ticks * of.timerfd_interval_ns;
                    } else {
                        ++of.timerfd_expirations;
                        of.timerfd_next_expire_ns = 0;
                    }
                }
            }
        }

        if (t->state == TaskState::Sleeping && now >= t->wakeup_ns) {
            t->state = TaskState::Runnable;
        } else if (t->state == TaskState::FutexWait && t->futex_has_timeout &&
                   now >= t->futex_deadline_ns) {
            t->cpu.x[0] = static_cast<uint64_t>(-110LL); // -ETIMEDOUT
            t->futex_pa = 0ULL;
            t->futex_has_timeout = false;
            t->state = TaskState::Runnable;
        } else if (t->state == TaskState::BinderWait && t->files) {
            for (const auto& kv : t->files->fds) {
                if (kv.second.is_binder && binder_broker_.HasPendingRead(kv.second.binder_client_id)) {
                    t->state = TaskState::Runnable;
                    break;
                }
            }
        } else if (t->state == TaskState::PollWait && t->files) {
            bool any_ready = false;
            if (t->poll_wait_epfd >= 0) {
                auto epit = t->files->fds.find(t->poll_wait_epfd);
                if (epit != t->files->fds.end()) {
                    for (const auto& w : epit->second.epoll_watches) {
                        const uint32_t rev = ComputeGuestFdPollEvents(t->files->fds, w.fd);
                        const uint32_t mask = w.events | 0x008u | 0x010u; // EPOLLERR|EPOLLHUP
                        if ((rev & mask) != 0u) {
                            any_ready = true;
                            break;
                        }
                    }
                } else {
                    any_ready = true;
                }
            } else if (!t->poll_wait_fds.empty()) {
                for (const auto& w : t->poll_wait_fds) {
                    const uint32_t rev = ComputeGuestFdPollEvents(t->files->fds, w.fd);
                    const uint32_t mask = w.events | 0x008u | 0x010u | 0x020u; // ERR|HUP|NVAL
                    if ((rev & mask) != 0u) {
                        any_ready = true;
                        break;
                    }
                }
            } else {
                any_ready = true;
            }
            if (any_ready) {
                t->poll_has_timeout = false;
                t->poll_wait_epfd = -1;
                t->poll_wait_fds.clear();
                t->state = TaskState::Runnable; // Retries svc and drains ready events
            } else if (t->poll_has_timeout && now >= t->poll_deadline_ns) {
                t->cpu.elr_el1 += 4ULL; // Skip retry; timed out with 0 events
                t->cpu.x[0] = 0ULL;
                t->poll_has_timeout = false;
                t->poll_wait_epfd = -1;
                t->poll_wait_fds.clear();
                t->state = TaskState::Runnable;
            }
        }
    }
}

void LinuxGuestSupervisor::ResumeIfWaiting(AArch64CpuCore& cpu) {
    WakeSleepingTasks();
    CpuState& st = cpu.State();
    if (!st.waiting_for_interrupt || tasks_.empty()) return;

    const size_t n = tasks_.size();
    for (size_t step = 0; step < n; ++step) {
        const size_t cand_idx = (current_task_idx_ + step) % n;
        GuestTask* cand = tasks_[cand_idx].get();
        if (cand && cand->state == TaskState::Runnable) {
            if (cand_idx != current_task_idx_) {
                current_task_idx_ = cand_idx;
                uid_ = cand->uid;
                gid_ = cand->gid;
                if (cand->vm) {
                    current_brk_ = cand->vm->current_brk;
                    mmap_cursor_ = cand->vm->mmap_cursor;
                    ttbr0_pa_ = cand->vm->ttbr0_pa;
                }
                active_binary_ = cand->binary;
                RestoreTaskContext(cpu, st, *cand);
                st.pc = cand->cpu.elr_el1;
                st.pstate.UnpackSpsr(static_cast<uint32_t>(cand->cpu.spsr_el1));
            } else {
                st.x[0] = cand->cpu.x[0];
                st.sys.elr_el1 = cand->cpu.elr_el1;
            }
            st.waiting_for_interrupt = false;
            return;
        }
    }
}

void LinuxGuestSupervisor::YieldTimeSlice(AArch64CpuCore& cpu) {
    CpuState& st = cpu.State();
    if (st.halted || st.waiting_for_interrupt || st.pstate.el != 0 || tasks_.size() <= 1u) {
        return;
    }
    WakeSleepingTasks();
    GuestTask* cur = CurrentTask();
    if (!cur || cur->state != TaskState::Runnable) return;

    const size_t n = tasks_.size();
    for (size_t step = 1; step < n; ++step) {
        const size_t cand_idx = (current_task_idx_ + step) % n;
        GuestTask* cand = tasks_[cand_idx].get();
        if (cand && cand->state == TaskState::Runnable) {
            SaveTaskContext(st, *cur);
            cur->cpu.elr_el1 = st.pc;
            cur->cpu.spsr_el1 = st.pstate.PackSpsr();

            current_task_idx_ = cand_idx;
            uid_ = cand->uid;
            gid_ = cand->gid;
            if (cand->vm) {
                current_brk_ = cand->vm->current_brk;
                mmap_cursor_ = cand->vm->mmap_cursor;
                ttbr0_pa_ = cand->vm->ttbr0_pa;
            }
            active_binary_ = cand->binary;
            RestoreTaskContext(cpu, st, *cand);
            st.pc = cand->cpu.elr_el1;
            st.pstate.UnpackSpsr(static_cast<uint32_t>(cand->cpu.spsr_el1));
            return;
        }
    }
}

bool LinuxGuestSupervisor::ScheduleNextTask(AArch64CpuCore& cpu,
                                            CpuState& st,
                                            bool& out_all_exited,
                                            bool& out_wfi_sleep) {
    out_all_exited = false;
    out_wfi_sleep = false;
    if (tasks_.empty()) {
        out_all_exited = exited_;
        return false;
    }

    WakeSleepingTasks();

    const size_t n = tasks_.size();
    for (size_t step = 1; step <= n; ++step) {
        const size_t cand_idx = (current_task_idx_ + step) % n;
        GuestTask* cand = tasks_[cand_idx].get();
        if (cand && cand->state == TaskState::Runnable) {
            if (cand_idx != current_task_idx_) {
                current_task_idx_ = cand_idx;
                uid_ = cand->uid;
                gid_ = cand->gid;
                if (cand->vm) {
                    current_brk_ = cand->vm->current_brk;
                    mmap_cursor_ = cand->vm->mmap_cursor;
                    ttbr0_pa_ = cand->vm->ttbr0_pa;
                }
                active_binary_ = cand->binary;
                RestoreTaskContext(cpu, st, *cand);
            } else {
                st.x[0] = cand->cpu.x[0];
                st.sys.elr_el1 = cand->cpu.elr_el1;
                st.waiting_for_interrupt = false;
            }
            return true;
        }
    }

    // Check if any non-zombie task still waits (Sleeping / WaitingChild / FutexWait / PollWait / BinderWait)
    for (const auto& t : tasks_) {
        if (t && t->state != TaskState::Zombie) {
            out_wfi_sleep = true;
            return false;
        }
    }

    out_all_exited = true;
    return false;
}

void LinuxGuestSupervisor::SetInitramfs(std::vector<CpioEntry> entries) {
    initramfs_ = std::move(entries);
}

void LinuxGuestSupervisor::SetSharedStorageRoot(const std::string& host_dir) {
    shared_storage_root_ = host_dir;
    if (!shared_storage_root_.empty()) {
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_);
    }
}

void LinuxGuestSupervisor::SetGuestIdentity(const std::string& cmdline, bool magisk_enabled) {
    cmdline_ = cmdline;
    magisk_enabled_ = magisk_enabled;
}

bool LinuxGuestSupervisor::ResolveHostStoragePath(const std::string& norm_guest_path,
                                                  std::string& out_host_path,
                                                  std::string& out_rel) const {
    return GuestVfsBridge::MapGuestStoragePath(
        shared_storage_root_, norm_guest_path, out_host_path, out_rel);
}

bool LinuxGuestSupervisor::ResolveGuestPathWithDirfd(
    const std::unordered_map<int, OpenFile>& fds,
    int dirfd,
    const std::string& raw_path,
    std::string& out_norm) const {
    if (raw_path.empty()) {
        out_norm.clear();
        return false;
    }
    if (raw_path.front() == '/') {
        out_norm = NormalizeGuestPath(raw_path);
        return true;
    }
    if (dirfd == -100) { // AT_FDCWD
        const GuestTask* cur = CurrentTask();
        const std::string& cwd = (cur && !cur->cwd.empty()) ? cur->cwd : std::string("/");
        out_norm = (cwd == "/") ? NormalizeGuestPath("/" + raw_path)
                                : NormalizeGuestPath(cwd + "/" + raw_path);
        return true;
    }
    auto it = fds.find(dirfd);
    if (it == fds.end()) {
        out_norm.clear();
        return false;
    }
    const std::string& base = it->second.path;
    if (base.empty() || base == "/") {
        out_norm = NormalizeGuestPath("/" + raw_path);
    } else {
        out_norm = NormalizeGuestPath(base + "/" + raw_path);
    }
    return true;
}

bool LinuxGuestSupervisor::ResolveProcSymlinkTarget(
    const std::unordered_map<int, OpenFile>& fds,
    const std::string& norm_path,
    std::string& out_target) const {
    out_target.clear();
    if (norm_path.rfind("/proc/", 0) != 0) return false;
    const std::string rest = norm_path.substr(6);
    const size_t slash1 = rest.find('/');
    if (slash1 == std::string::npos) return false;
    const std::string who = rest.substr(0, slash1);
    const std::string tail = rest.substr(slash1 + 1u);

    const GuestTask* cur = CurrentTask();
    const int32_t cur_pid = cur ? cur->pid : 1;
    const std::unordered_map<int, OpenFile>* target_fds = nullptr;
    std::string target_bin;
    std::string target_cwd = cur ? cur->cwd : "/";

    if (who == "self" || who == "thread-self") {
        target_fds = &fds;
        target_bin = active_binary_;
    } else {
        int req_pid = -1;
        if (!ParseNonNegInt(who, req_pid) || req_pid <= 0) return false;
        if (req_pid == cur_pid || (cur && req_pid == cur->tgid)) {
            target_fds = &fds;
            target_bin = active_binary_;
        } else {
            for (const auto& t : tasks_) {
                if (t && (t->pid == req_pid || t->tgid == req_pid) && t->files) {
                    target_fds = &t->files->fds;
                    target_bin = t->binary;
                    target_cwd = t->cwd;
                    break;
                }
            }
            if (!target_fds) return false;
        }
    }

    if (tail == "exe") {
        out_target = target_bin.empty() ? "/init" : target_bin;
        return true;
    }
    if (tail == "cwd") {
        out_target = target_cwd.empty() ? "/" : target_cwd;
        return true;
    }
    if (tail.rfind("fd/", 0) == 0) {
        const std::string fd_str = tail.substr(3);
        int fd_num = -1;
        if (!ParseNonNegInt(fd_str, fd_num)) return false;
        if (fd_num == 0) { out_target = "/dev/stdin"; return true; }
        if (fd_num == 1) { out_target = "/dev/stdout"; return true; }
        if (fd_num == 2) { out_target = "/dev/stderr"; return true; }
        auto it = target_fds->find(fd_num);
        if (it == target_fds->end() || it->second.path.empty()) return false;
        out_target = it->second.path;
        return true;
    }
    return false;
}

bool LinuxGuestSupervisor::ResolveSymlinkTarget(
    const std::unordered_map<int, OpenFile>& fds,
    const std::string& norm_path,
    std::string& out_target) const {
    out_target.clear();
    if (ResolveProcSymlinkTarget(fds, norm_path, out_target)) {
        return true;
    }
    auto link_it = runtime_symlinks_.find(norm_path);
    if (link_it != runtime_symlinks_.end() && !link_it->second.empty()) {
        out_target = link_it->second;
        return true;
    }
    if (norm_path.size() > 1u) {
        const std::string rel = norm_path.substr(1);
        if (const CpioEntry* ce = CpioArchive::FindEntry(initramfs_, rel)) {
            if (ce->IsSymlink()) {
                out_target.assign(ce->data.begin(), ce->data.end());
                while (!out_target.empty() && out_target.back() == '\0') out_target.pop_back();
                return !out_target.empty();
            }
            return false;
        }
    }
    if (ext4_ && ext4_->IsOpen()) {
        auto try_link = [&](const std::string& p) -> bool {
            loader::Ext4Stat st{};
            if (!ext4_->Stat(p, st) || !st.IsSymlink()) return false;
            return ext4_->ReadSymlink(p, out_target) && !out_target.empty();
        };
        if (try_link(norm_path)) return true;
        if (norm_path.rfind("/system/", 0) == 0 && try_link(norm_path.substr(7))) return true;
    }
    return false;
}

bool LinuxGuestSupervisor::ResolveVfsFile(const std::string& path,
                                          std::vector<uint8_t>& out_data,
                                          bool& out_is_dir,
                                          std::vector<std::string>& out_children,
                                          std::string* out_resolved_path,
                                          const std::unordered_map<int, OpenFile>* fds) const {
    std::string norm = NormalizeGuestPath(path);
    auto finish_ok = [&]() -> bool {
        if (out_resolved_path) *out_resolved_path = norm;
        return true;
    };

    for (int depth = 0; depth < 8; ++depth) {
        out_data.clear();
        out_children.clear();
        out_is_dir = false;

        if (norm == "/proc/self/exe" || norm == "/proc/thread-self/exe") {
            const std::string target = active_binary_.empty() ? "/init" : active_binary_;
            if (target == norm) return false;
            norm = NormalizeGuestPath(target);
            continue;
        }
        if (fds != nullptr) {
            std::string proc_target;
            if (ResolveProcSymlinkTarget(*fds, norm, proc_target)) {
                if (!proc_target.empty() && proc_target.front() == '/' && proc_target != norm) {
                    norm = NormalizeGuestPath(proc_target);
                    continue;
                }
            }
            if (norm == "/proc/self/fd" || norm == "/proc/thread-self/fd") {
                out_is_dir = true;
                out_children = {"0", "1", "2"};
                for (const auto& kv : *fds) {
                    out_children.push_back(std::to_string(kv.first));
                }
                return finish_ok();
            }
        }
        if (norm == "/proc/self/cmdline" || norm == "/proc/thread-self/cmdline") {
            const std::string bin = active_binary_.empty() ? "/init" : active_binary_;
            out_data.assign(bin.begin(), bin.end());
            out_data.push_back('\0');
            return finish_ok();
        }
        if (norm == "/proc/self/comm" || norm == "/proc/thread-self/comm") {
            std::string base = active_binary_.empty() ? "init" : active_binary_;
            const size_t sl = base.find_last_of('/');
            if (sl != std::string::npos) base = base.substr(sl + 1u);
            base += "\n";
            out_data.assign(base.begin(), base.end());
            return finish_ok();
        }
        if (norm == "/proc/self/status" || norm == "/proc/thread-self/status") {
            const GuestTask* cur = CurrentTask();
            const int32_t pid = cur ? cur->tgid : 1;
            const int32_t tid = cur ? cur->pid : 1;
            const int32_t ppid = cur ? cur->ppid : 0;
            std::string base = active_binary_.empty() ? "init" : active_binary_;
            const size_t sl = base.find_last_of('/');
            if (sl != std::string::npos) base = base.substr(sl + 1u);
            std::ostringstream oss;
            oss << "Name:\t" << base << "\n"
                << "State:\tR (running)\n"
                << "Tgid:\t" << pid << "\n"
                << "Pid:\t" << tid << "\n"
                << "PPid:\t" << ppid << "\n"
                << "TracerPid:\t0\n"
                << "Uid:\t" << uid_ << "\t" << uid_ << "\t" << uid_ << "\t" << uid_ << "\n"
                << "Gid:\t" << gid_ << "\t" << gid_ << "\t" << gid_ << "\t" << gid_ << "\n"
                << "Threads:\t" << std::max<size_t>(1u, ActiveTaskCount()) << "\n";
            const std::string s = oss.str();
            out_data.assign(s.begin(), s.end());
            return finish_ok();
        }
        if (norm == "/proc/self/stat" || norm == "/proc/thread-self/stat") {
            const GuestTask* cur = CurrentTask();
            const int32_t pid = cur ? cur->tgid : 1;
            const int32_t ppid = cur ? cur->ppid : 0;
            std::string base = active_binary_.empty() ? "init" : active_binary_;
            const size_t sl = base.find_last_of('/');
            if (sl != std::string::npos) base = base.substr(sl + 1u);
            std::ostringstream oss;
            oss << pid << " (" << base << ") R " << ppid
                << " 1 1 0 -1 4194560 0 0 0 0 10 5 0 0 20 0 "
                << std::max<size_t>(1u, ActiveTaskCount()) << " 0 1 67108864 1024 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n";
            const std::string s = oss.str();
            out_data.assign(s.begin(), s.end());
            return finish_ok();
        }
        if (norm == "/proc/self/maps" || norm == "/proc/thread-self/maps") {
            std::ostringstream oss;
            const std::string bin = active_binary_.empty() ? "/init" : active_binary_;
            oss << "00400000-00800000 r-xp 00000000 00:01 1 " << bin << "\n"
                << "20000000-20200000 r-xp 00000000 00:01 2 /system/bin/linker64\n"
                << "7ffe0000-7fff0000 rw-p 00000000 00:00 0 [stack]\n";
            const std::string s = oss.str();
            out_data.assign(s.begin(), s.end());
            return finish_ok();
        }
        if (norm == "/proc/cmdline") {
            std::string text = cmdline_ + "\n";
            out_data.assign(text.begin(), text.end());
            return finish_ok();
        }
        if (norm == "/proc/version") {
            std::string text = "Linux version 5.10.209-haseeb #1 SMP PREEMPT aarch64\n";
            out_data.assign(text.begin(), text.end());
            return finish_ok();
        }
        if (norm == "/dev/null" || norm == "/dev/zero" ||
            norm == "/dev/urandom" || norm == "/dev/random") {
            return finish_ok();
        }
        if (norm == "/dev/input") {
            out_is_dir = true;
            if (touch_) out_children.push_back("event0");
            if (kbd_) out_children.push_back("event1");
            return finish_ok();
        }
        if ((norm == "/dev/input/event0" && touch_) || (norm == "/dev/input/event1" && kbd_)) {
            return finish_ok();
        }

        if (GuestVfsBridge::TryResolveSpecialVfs(norm, shared_storage_root_, hardware_, prop_mgr_,
                                                 ram_bytes_, out_data, out_is_dir, out_children)) {
            return finish_ok();
        }

        if (auto sl = runtime_symlinks_.find(norm); sl != runtime_symlinks_.end() && !sl->second.empty()) {
            const std::string& target = sl->second;
            norm = (target.front() == '/')
                       ? NormalizeGuestPath(target)
                       : NormalizeGuestPath(ParentDirOf(norm) + "/" + target);
            continue;
        }
        if (auto rf = runtime_files_.find(norm); rf != runtime_files_.end()) {
            out_data = rf->second;
            return finish_ok();
        }
        {
            bool attr_is_dir = false;
            std::string attr_leaf;
            if (ParseProcAttrPath(norm, attr_is_dir, attr_leaf)) {
                if (attr_is_dir) {
                    out_is_dir = true;
                    out_children = {"current", "exec", "fscreate", "sockcreate", "keycreate", "prev"};
                    return finish_ok();
                }
                if (attr_leaf == "current") {
                    static constexpr char kInitCtx[] = "u:r:init:s0\0";
                    out_data.assign(kInitCtx, kInitCtx + sizeof(kInitCtx));
                }
                return finish_ok();
            }
        }
        if (runtime_dirs_.find(norm) != runtime_dirs_.end()) {
            out_is_dir = true;
            const std::string prefix = (norm == "/") ? "/" : (norm + "/");
            auto collect_child = [&](const std::string& p) {
                if (p.size() > prefix.size() && p.compare(0, prefix.size(), prefix) == 0) {
                    const std::string tail = p.substr(prefix.size());
                    if (!tail.empty() && tail.find('/') == std::string::npos) {
                        out_children.push_back(tail);
                    }
                }
            };
            for (const auto& d : runtime_dirs_) collect_child(d);
            for (const auto& f : runtime_files_) collect_child(f.first);
            for (const auto& s : runtime_symlinks_) collect_child(s.first);
            return finish_ok();
        }

        // 1. Check initramfs CPIO entries first
        if (norm == "/") {
            out_is_dir = true;
            for (const auto& e : initramfs_) {
                if (e.name.find('/') == std::string::npos) {
                    out_children.push_back(e.name);
                }
            }
            if (ext4_ && ext4_->IsOpen()) {
                std::vector<loader::Ext4DirEntry> root_entries;
                if (ext4_->ReadDir("/", root_entries)) {
                    for (const auto& re : root_entries) {
                        if (re.name != "." && re.name != "..") out_children.push_back(re.name);
                    }
                }
            }
            return finish_ok();
        }

        const std::string rel = norm.substr(1);
        if (const CpioEntry* ce = CpioArchive::FindEntry(initramfs_, rel)) {
            if (ce->IsSymlink()) {
                std::string target(ce->data.begin(), ce->data.end());
                while (!target.empty() && target.back() == '\0') target.pop_back();
                if (target.empty()) return false;
                norm = (target.front() == '/')
                           ? NormalizeGuestPath(target)
                           : NormalizeGuestPath(ParentDirOf(norm) + "/" + target);
                continue;
            }
            if (ce->IsDirectory()) {
                out_is_dir = true;
                std::string prefix = rel + "/";
                for (const auto& item : initramfs_) {
                    if (item.name.rfind(prefix, 0) == 0) {
                        std::string tail = item.name.substr(prefix.size());
                        if (!tail.empty() && tail.find('/') == std::string::npos) {
                            out_children.push_back(tail);
                        }
                    }
                }
            } else {
                out_data = ce->data;
            }
            return finish_ok();
        }

        // Check intermediate directory symlinks inside CPIO initramfs
        bool expanded_cpio_ancestor = false;
        for (size_t pos = rel.find('/'); pos != std::string::npos; pos = rel.find('/', pos + 1u)) {
            const std::string prefix_rel = rel.substr(0, pos);
            if (const CpioEntry* ace = CpioArchive::FindEntry(initramfs_, prefix_rel)) {
                if (ace->IsSymlink()) {
                    std::string target(ace->data.begin(), ace->data.end());
                    while (!target.empty() && target.back() == '\0') target.pop_back();
                    if (!target.empty()) {
                        const std::string parent = "/" + prefix_rel;
                        const std::string base_resolved = (target.front() == '/')
                                                              ? NormalizeGuestPath(target)
                                                              : NormalizeGuestPath(ParentDirOf(parent) + "/" + target);
                        norm = NormalizeGuestPath(base_resolved + "/" + rel.substr(pos + 1u));
                        expanded_cpio_ancestor = true;
                        break;
                    }
                }
            }
        }
        if (expanded_cpio_ancestor) continue;

        // 2. Fallback to mount-free Ext4Reader system image (both SAR and partition-root layouts)
        if (ext4_ && ext4_->IsOpen()) {
            bool followed_link = false;
            auto try_ext4 = [&](const std::string& p) -> bool {
                loader::Ext4Stat st{};
                if (!ext4_->Stat(p, st)) return false;
                if (st.IsSymlink()) {
                    std::string target;
                    if (!ext4_->ReadSymlink(p, target) || target.empty()) return false;
                    norm = (target.front() == '/')
                               ? NormalizeGuestPath(target)
                               : NormalizeGuestPath(ParentDirOf(norm) + "/" + target);
                    followed_link = true;
                    return false;
                }
                if (st.IsDirectory()) {
                    out_is_dir = true;
                    std::vector<loader::Ext4DirEntry> entries;
                    if (ext4_->ReadDir(p, entries)) {
                        for (const auto& de : entries) out_children.push_back(de.name);
                    }
                    return true;
                }
                return ext4_->ReadFile(p, out_data);
            };
            if (try_ext4(norm)) return finish_ok();
            if (followed_link) continue;
            if (norm.rfind("/system/", 0) == 0 && try_ext4(norm.substr(7))) return finish_ok();
            if (followed_link) continue;
            if (norm == "/system" && try_ext4("/")) return finish_ok();
            if (followed_link) continue;
        }
        // 3. Fallback default fstab for system-as-root init FirstStageMount when absent from image/DT
        if (norm.rfind("/fstab.", 0) == 0) {
            std::string hw = ExtractCmdlineParam(cmdline_, "androidboot.fstab_suffix");
            if (hw.empty()) hw = ExtractCmdlineParam(cmdline_, "androidboot.hardware");
            if (hw.empty()) hw = "virt";
            if (norm == "/fstab." + hw || norm == "/fstab.virt") {
                const std::string fstab_text =
                    "# Haseeb Virtual ARM64 Board default fstab\n"
                    "/dev/block/vda /data ext4 noatime,nosuid,nodev,noauto_da_alloc,errors=panic wait\n";
                out_data.assign(fstab_text.begin(), fstab_text.end());
                return finish_ok();
            }
        }
        // 4. Fallback standard Android mountpoint directories when omitted by SAR image
        if (norm == "/dev" || norm == "/dev/pts" || norm == "/dev/shm" ||
            norm == "/data" || norm == "/mnt" || norm == "/acct" || norm == "/cache" ||
            norm == "/metadata" || norm == "/linkerconfig" || norm == "/tmp" || norm == "/var" ||
            norm == "/apex" || norm == "/debug_ramdisk" || norm == "/config" ||
            norm == "/sys/fs/cgroup" || norm == "/storage" || norm == "/storage/self" ||
            norm == "/storage/emulated" || norm == "/proc" || norm == "/sys") {
            out_is_dir = true;
            if (norm == "/dev") {
                out_children = {"null", "zero", "urandom", "random", "kmsg", "tty", "ptmx",
                                "binder", "hwbinder", "vndbinder", "ashmem", "ion",
                                "dma_heap", "socket", "block", "input", "__properties__",
                                "pts", "shm"};
            } else if (norm == "/proc") {
                out_children = {"self", "cmdline", "cpuinfo", "meminfo", "mounts", "filesystems",
                                "stat", "uptime", "loadavg", "version", "device-tree", "sys"};
            } else if (norm == "/sys") {
                out_children = {"fs", "block", "devices", "class"};
            }
            return finish_ok();
        }
        return false;
    }
    return false;
}

bool LinuxGuestSupervisor::TryResolveElfForTask(const std::string& path,
                                                std::vector<uint8_t>& out_data) const {
    bool is_dir = false;
    std::vector<std::string> children;
    if (ResolveVfsFile(path, out_data, is_dir, children) && !is_dir &&
        Elf64GuestLoader::IsValidAArch64Elf(out_data)) {
        return true;
    }
    if (path.rfind("/system/", 0) != 0) {
        const std::string alt = "/system" + NormalizeGuestPath(path);
        if (ResolveVfsFile(alt, out_data, is_dir, children) && !is_dir &&
            Elf64GuestLoader::IsValidAArch64Elf(out_data)) {
            return true;
        }
    }
    return false;
}

bool LinuxGuestSupervisor::MapFreshAddressSpace(AArch64CpuCore& cpu,
                                                const std::vector<uint8_t>& elf_bytes,
                                                const std::vector<std::string>& argv,
                                                std::string& out_error,
                                                bool reset_phys_cursor,
                                                const std::vector<std::string>* envp_override) {
    if (reset_phys_cursor) {
        phys_cursor_ = arena_base_;
        vbar_pa_ = 0ULL;
    }

    if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, ttbr0_pa_)) {
        out_error = "Failed allocating guest TTBR0 root page";
        return false;
    }

    // Install EL1 VBAR exception trampoline page once (or after reset) and identity-map into every task TTBR0
    if (vbar_pa_ == 0ULL) {
        if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, vbar_pa_)) {
            out_error = "Failed allocating EL1 VBAR page";
            return false;
        }
        constexpr uint32_t kInsnHvcLx = 0xD4000002u | (static_cast<uint32_t>(kSyscallHypercallImm) << 5);
        constexpr uint32_t kInsnEret  = 0xD69F03E0u;
        const uint32_t trampoline[2] = {kInsnHvcLx, kInsnEret};
        ram_.WriteBytes(vbar_pa_ + 0x200ULL, trampoline, sizeof(trampoline));
        ram_.WriteBytes(vbar_pa_ + 0x400ULL, trampoline, sizeof(trampoline));
        ram_.WriteBytes(vbar_pa_ + 0x480ULL, trampoline, sizeof(trampoline));
    }
    if (!Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                     vbar_pa_, vbar_pa_, false, false, true)) {
        out_error = "Failed identity-mapping EL1 VBAR";
        return false;
    }

    std::vector<std::string> envp;
    if (envp_override != nullptr && !envp_override->empty()) {
        envp = *envp_override;
    } else {
        envp = {
            "PATH=/sbin:/system/bin:/vendor/bin",
            "HOME=/",
            "TERM=vt100",
            magisk_enabled_ ? "HASEEB_ROOT=magisk" : "HASEEB_ROOT=0",
        };
    }

    Elf64LoadResult load = Elf64GuestLoader::LoadAndMap(
        ram_, ttbr0_pa_, phys_cursor_, arena_limit_, elf_bytes, argv, envp,
        [this](const std::string& interp, std::vector<uint8_t>& out_bytes) {
            return TryResolveElfForTask(interp, out_bytes);
        });
    if (!load.ok) {
        out_error = load.error;
        return false;
    }

    current_brk_ = AlignUp4K(load.brk_start);
    mmap_cursor_ = 0x0000001000000000ULL;

    if (GuestTask* cur = CurrentTask()) {
        if (!cur->vm) cur->vm = std::make_shared<VmSpace>();
        cur->vm->ttbr0_pa = ttbr0_pa_;
        cur->vm->current_brk = current_brk_;
        cur->vm->mmap_cursor = mmap_cursor_;
        cur->vm->fb_mapped_pas.clear();
        cur->vm->lazy_prot_none_ranges.clear();
        cur->vm->tagged_addr_ctrl = 0ULL;
    }

    const int32_t active_asid = CurrentTask() ? CurrentTask()->tgid : 1;
    cpu.Mmu().InvalidateAll();
    cpu.Cache().InvalidateAll();
    cpu.Reset(load.entry_pc, load.initial_sp, 0);
    auto& st = cpu.State();
    st.sp_el[0] = load.initial_sp;
    st.pstate.el = 0;
    st.pstate.spsel = false;
    st.sys.vbar_el1 = vbar_pa_;
    st.sys.ttbr0_el1 = (ttbr0_pa_ & 0x0000FFFFFFFFF000ULL) |
                       (static_cast<uint64_t>(active_asid & 0xFFFFu) << 48);
    st.sys.tcr_el1 = 25ULL | (1ULL << 23) | (1ULL << 37); // T0SZ=25 (39-bit VA, 4K), EPD1=1, TBI0=1
    st.sys.mair_el1 = 0xFFULL;
    st.sys.cpacr_el1 = (3ULL << 20);
    st.sys.sctlr_el1 = 0x30D00801ULL; // MMU enabled (M=1)
    st.x[0] = 0;
    return true;
}

VmError LinuxGuestSupervisor::PrepareBoot(AArch64CpuCore& cpu,
                                          uint64_t ram_bytes,
                                          uint64_t kernel_reserved_end,
                                          const std::vector<std::string>& argv,
                                          std::string& out_selected_binary,
                                          std::string& out_error,
                                          uint64_t arena_max_limit) {
    ram_bytes_ = ram_bytes;
    arena_base_ = std::max<uint64_t>(kGuestRamBase + 0x00200000ULL, AlignUp4K(kernel_reserved_end));
    const uint64_t ram_top = kGuestRamBase + ram_bytes;
    const uint64_t default_top = ram_top - std::min<uint64_t>(ram_bytes / 4u, 0x00400000ULL);
    arena_limit_ = (arena_max_limit > 0ULL && arena_max_limit < default_top)
                       ? AlignDown4K(arena_max_limit)
                       : default_top;
    if (arena_limit_ <= arena_base_ + 0x00200000ULL) {
        out_error = "Insufficient guest RAM for EL0 init address space";
        return VmError::OutOfMemory;
    }

    exited_ = false;
    exit_status_ = 0;
    uid_ = 0u;
    gid_ = 0u;
    last_trap_detail_.clear();
    binder_services_.clear();
    syscall_head_ = 0;
    syscall_total_ = 0;
    logged_enosys_.clear();
    runtime_dirs_.clear();
    runtime_symlinks_.clear();
    runtime_files_.clear();
    runtime_xattrs_.clear();
    CloseAllOpenFds();
    tasks_.clear();
    current_task_idx_ = 0;
    next_pid_ = 1;
    fb_mapped_pas_.clear();
    next_fd_ = 3;

    // Priority order matching Android/Magisk boot flow: /magiskinit -> /init -> /system/bin/init -> /system/bin/sh
    std::vector<std::string> candidates;
    if (magisk_enabled_) candidates.push_back("/magiskinit");
    candidates.push_back("/init");
    if (!magisk_enabled_) candidates.push_back("/magiskinit");
    candidates.push_back("/system/bin/init");
    candidates.push_back("/system/bin/sh");

    std::vector<uint8_t> elf_bytes;
    std::string chosen;
    for (const auto& path : candidates) {
        std::vector<uint8_t> data;
        bool is_dir = false;
        std::vector<std::string> children;
        if (ResolveVfsFile(path, data, is_dir, children) && !is_dir &&
            Elf64GuestLoader::IsValidAArch64Elf(data)) {
            elf_bytes = std::move(data);
            chosen = path;
            break;
        }
    }

    if (chosen.empty()) {
        out_error = "No valid AArch64 ELF64 init/magiskinit/sh binary found in initramfs or system.img";
        return VmError::FileNotFound;
    }

    std::vector<std::string> eff_argv = argv;
    if (eff_argv.empty()) eff_argv.push_back(chosen);
    active_binary_ = chosen;
    out_selected_binary = chosen;

    auto root = std::make_unique<GuestTask>();
    root->pid = next_pid_++;
    root->tgid = root->pid;
    root->ppid = 0;
    root->uid = 0u;
    root->gid = 0u;
    root->binary = chosen;
    root->cwd = "/";
    root->state = TaskState::Runnable;
    tasks_.push_back(std::move(root));
    current_task_idx_ = 0;

    if (!MapFreshAddressSpace(cpu, elf_bytes, eff_argv, out_error, true)) {
        tasks_.clear();
        return VmError::ExecutionTrap;
    }
    SaveTaskContext(cpu.State(), *tasks_[0]);
    return VmError::Ok;
}

bool LinuxGuestSupervisor::ReadUserBytes(AArch64CpuCore& cpu,
                                         uint64_t uva,
                                         void* dst,
                                         size_t len) const {
    auto* out = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
        MmuTranslationResult tr = cpu.Mmu().Translate(cpu.State(), uva + i, MemAccessType::Read, false);
        if (!tr.ok || !ram_.ReadBytes(tr.phys_addr, out + i, 1)) return false;
    }
    return true;
}

bool LinuxGuestSupervisor::WriteUserBytes(AArch64CpuCore& cpu,
                                          uint64_t uva,
                                          const void* src,
                                          size_t len) const {
    const auto* in = static_cast<const uint8_t*>(src);
    for (size_t i = 0; i < len; ++i) {
        MmuTranslationResult tr = cpu.Mmu().Translate(cpu.State(), uva + i, MemAccessType::Write, false);
        if (!tr.ok || !ram_.WriteBytes(tr.phys_addr, in + i, 1)) return false;
    }
    return true;
}

bool LinuxGuestSupervisor::ReadUserString(AArch64CpuCore& cpu,
                                          uint64_t uva,
                                          std::string& out_str) const {
    out_str.clear();
    for (size_t i = 0; i < 4096u; ++i) {
        char ch = 0;
        if (!ReadUserBytes(cpu, uva + i, &ch, 1)) return false;
        if (ch == '\0') return true;
        out_str.push_back(ch);
    }
    return false;
}

bool LinuxGuestSupervisor::FlushFramebufferToGpu() {
    GuestTask* cur = CurrentTask();
    const auto& fb_pas = (cur && cur->vm) ? cur->vm->fb_mapped_pas : fb_mapped_pas_;
    if (!gpu_ || fb_pas.empty()) return false;
    const uint32_t w = gpu_->DisplayWidth();
    const uint32_t h = gpu_->DisplayHeight();
    if (w == 0u || h == 0u) return false;

    const size_t need_bytes = static_cast<size_t>(w) * h * 4u;
    std::vector<uint8_t> rgba(need_bytes, 0u);
    size_t offset = 0u;
    for (uint64_t pa : fb_pas) {
        if (offset >= need_bytes) break;
        const size_t chunk = std::min<size_t>(4096u, need_bytes - offset);
        if (!ram_.ReadBytes(pa, rgba.data() + offset, chunk)) {
            return false;
        }
        offset += chunk;
    }
    return gpu_->SubmitRawRgbaFrame(rgba.data(), w, h, w * 4u);
}

std::string LinuxGuestSupervisor::FormatExceptionTrap(AArch64CpuCore& cpu,
                                                      const CpuState& state,
                                                      uint32_t ec_val) const {
    uint32_t opcode = 0u;
    const bool has_opc = ReadUserBytes(cpu, state.sys.elr_el1, &opcode, sizeof(opcode));
    const GuestTask* cur = CurrentTask();
    const int32_t pid = cur ? cur->pid : 1;
    std::ostringstream oss;
    oss << ExceptionClassName(ec_val)
        << " (ec=0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << ec_val << ")"
        << " bin=" << (active_binary_.empty() ? "unknown" : active_binary_)
        << " pid=" << std::dec << pid
        << " ELR=0x" << std::hex << state.sys.elr_el1
        << " FAR=0x" << state.sys.far_el1
        << " SP=0x" << state.sp_el[0]
        << " LR=0x" << state.x[30];
    if (has_opc) {
        oss << " op=0x" << std::setw(8) << std::setfill('0') << opcode;
    }
    oss << " insns=" << std::dec << state.instructions_executed;
    return oss.str();
}

void LinuxGuestSupervisor::LogToUart(const std::string& msg) const {
    for (char c : msg) {
        uart_.Write(0x000ULL, 1, static_cast<uint8_t>(c));
    }
}

void LinuxGuestSupervisor::RecordSyscall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                                         int64_t ret, uint64_t pc, int32_t pid, const std::string& note) {
    SyscallTraceEntry entry{nr, a0, a1, a2, ret, pc, pid, {}};
    if (!note.empty()) {
        const size_t copy_len = std::min(note.size(), sizeof(entry.note) - 1u);
        if (note.size() > sizeof(entry.note) - 1u) {
            const size_t tail = sizeof(entry.note) - 4u;
            std::memcpy(entry.note, "...", 3u);
            std::memcpy(entry.note + 3u, note.data() + (note.size() - tail), tail);
            entry.note[sizeof(entry.note) - 1u] = '\0';
        } else {
            std::memcpy(entry.note, note.data(), copy_len);
            entry.note[copy_len] = '\0';
        }
    }
    syscall_ring_[syscall_head_] = entry;
    syscall_head_ = (syscall_head_ + 1u) % kSyscallTraceSize;
    ++syscall_total_;
}

std::string LinuxGuestSupervisor::DumpRecentSyscalls(size_t max_entries) const {
    const size_t avail = static_cast<size_t>(
        std::min<uint64_t>(syscall_total_, kSyscallTraceSize));
    const size_t count = std::min(avail, max_entries);
    if (count == 0u) return "[SYS] (none)\n";

    std::ostringstream oss;
    const size_t start = (syscall_head_ + kSyscallTraceSize - count) % kSyscallTraceSize;
    for (size_t i = 0; i < count; ++i) {
        const auto& e = syscall_ring_[(start + i) % kSyscallTraceSize];
        oss << "[SYS] pid=" << std::dec << e.pid
            << " nr=" << e.nr
            << "(0x" << std::hex << e.a0 << ",0x" << e.a1 << ",0x" << e.a2 << ")"
            << " -> " << std::dec << e.ret
            << " @0x" << std::hex << e.pc;
        if (e.note[0] != '\0') {
            oss << " (" << e.note << ")";
        }
        oss << "\n";
    }
    return oss.str();
}

void LinuxGuestSupervisor::EmitFailureDiagnostics(AArch64CpuCore& cpu,
                                                  const std::string& reason) const {
    const GuestTask* cur = CurrentTask();
    const int32_t pid = cur ? cur->pid : 1;
    std::ostringstream hdr;
    hdr << "[FAIL] " << reason
        << " bin=" << (active_binary_.empty() ? "unknown" : active_binary_)
        << " pid=" << std::dec << pid
        << " insns=" << cpu.State().instructions_executed << "\r\n";
    LogToUart(hdr.str());
    LogToUart(DumpRecentSyscalls(32));
    LogToUart(cpu.DumpRecentTrace(16));
}

bool LinuxGuestSupervisor::LookupL3Pte(uint64_t va,
                                       uint64_t& out_l3_entry_pa,
                                       uint64_t& out_leaf) const {
    if (ttbr0_pa_ == 0ULL) return false;
    va = UntagUserVa(va);
    const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
    const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
    const uint64_t l3_idx = (va >> 12) & 0x1FFULL;

    uint64_t d1 = 0, d2 = 0;
    if (!ram_.ReadU64(ttbr0_pa_ + l1_idx * 8ULL, d1) || (d1 & 3ULL) != 3ULL) return false;
    const uint64_t l2_pa = d1 & 0x0000FFFFFFFFF000ULL;
    if (!ram_.ReadU64(l2_pa + l2_idx * 8ULL, d2) || (d2 & 3ULL) != 3ULL) return false;
    const uint64_t l3_pa = d2 & 0x0000FFFFFFFFF000ULL;
    out_l3_entry_pa = l3_pa + l3_idx * 8ULL;
    if (!ram_.ReadU64(out_l3_entry_pa, out_leaf)) return false;
    return (out_leaf & 3ULL) == 3ULL;
}

bool LinuxGuestSupervisor::RangeHasAnyMapping(uint64_t addr, uint64_t len) const {
    const uint64_t start = AlignDown4K(UntagUserVa(addr));
    const uint64_t end = start + AlignUp4K(len);
    if (end <= start) return true;
    const GuestTask* cur = CurrentTask();
    if (cur && cur->vm && RangeOverlapsVmRanges(cur->vm->lazy_prot_none_ranges, start, end)) {
        return true;
    }
    if (ttbr0_pa_ == 0ULL) return false;

    uint64_t va = start;
    while (va < end) {
        const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
        uint64_t d1 = 0;
        if (!ram_.ReadU64(ttbr0_pa_ + l1_idx * 8ULL, d1) || (d1 & 3ULL) != 3ULL) {
            const uint64_t next_1g = ((va >> 30) + 1ULL) << 30;
            if (next_1g <= va || next_1g >= end) break;
            va = next_1g;
            continue;
        }
        const uint64_t l2_pa = d1 & 0x0000FFFFFFFFF000ULL;
        const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
        uint64_t d2 = 0;
        if (!ram_.ReadU64(l2_pa + l2_idx * 8ULL, d2) || (d2 & 3ULL) != 3ULL) {
            const uint64_t next_2m = ((va >> 21) + 1ULL) << 21;
            if (next_2m <= va || next_2m >= end) break;
            va = next_2m;
            continue;
        }
        const uint64_t l3_pa = d2 & 0x0000FFFFFFFFF000ULL;
        const uint64_t l3_idx = (va >> 12) & 0x1FFULL;
        uint64_t leaf = 0;
        if (ram_.ReadU64(l3_pa + l3_idx * 8ULL, leaf) && (leaf & 3ULL) == 3ULL) {
            return true;
        }
        va += 4096ULL;
    }
    return false;
}

void LinuxGuestSupervisor::UnmapRange4K(AArch64CpuCore& cpu, uint64_t addr, uint64_t len) {
    const uint64_t start = AlignDown4K(UntagUserVa(addr));
    const uint64_t end = start + AlignUp4K(len);
    if (end <= start) return;
    if (GuestTask* cur = CurrentTask(); cur && cur->vm) {
        EraseVmRange(cur->vm->lazy_prot_none_ranges, start, end);
    }
    if (ttbr0_pa_ == 0ULL) return;

    uint64_t va = start;
    while (va < end) {
        const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
        uint64_t d1 = 0;
        if (!ram_.ReadU64(ttbr0_pa_ + l1_idx * 8ULL, d1) || (d1 & 3ULL) != 3ULL) {
            const uint64_t next_1g = ((va >> 30) + 1ULL) << 30;
            if (next_1g <= va || next_1g >= end) break;
            va = next_1g;
            continue;
        }
        const uint64_t l2_pa = d1 & 0x0000FFFFFFFFF000ULL;
        const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
        uint64_t d2 = 0;
        if (!ram_.ReadU64(l2_pa + l2_idx * 8ULL, d2) || (d2 & 3ULL) != 3ULL) {
            const uint64_t next_2m = ((va >> 21) + 1ULL) << 21;
            if (next_2m <= va || next_2m >= end) break;
            va = next_2m;
            continue;
        }
        const uint64_t l3_pa = d2 & 0x0000FFFFFFFFF000ULL;
        const uint64_t l3_idx = (va >> 12) & 0x1FFULL;
        const uint64_t entry_pa = l3_pa + l3_idx * 8ULL;
        uint64_t leaf = 0;
        if (ram_.ReadU64(entry_pa, leaf) && (leaf & 3ULL) == 3ULL) {
            const uint64_t old_pa = leaf & 0x0000FFFFFFFFF000ULL;
            ram_.WriteU64(entry_pa, 0ULL);
            cpu.Mmu().InvalidateVa(va, true, 0);
            cpu.Cache().InvalidatePhysPage(old_pa);
        }
        va += 4096ULL;
    }
}

bool LinuxGuestSupervisor::ProtectRange4K(AArch64CpuCore& cpu,
                                          uint64_t addr,
                                          uint64_t len,
                                          bool r,
                                          bool w,
                                          bool x) {
    const uint64_t start = AlignDown4K(UntagUserVa(addr));
    const uint64_t end = start + AlignUp4K(len);
    if (end <= start) return true;
    const bool el0_allow = (r || w || x);
    GuestTask* cur = CurrentTask();

    uint64_t va = start;
    while (va < end) {
        uint64_t entry_pa = 0, leaf = 0;
        if (LookupL3Pte(va, entry_pa, leaf)) {
            const uint64_t pa = leaf & 0x0000FFFFFFFFF000ULL;
            uint64_t new_leaf = pa | 3ULL | (1ULL << 10) | (1ULL << 53); // AF=1, PXN=1
            if (el0_allow) new_leaf |= (1ULL << 6);  // AP[1]=1 (EL0 readable)
            if (!w)        new_leaf |= (1ULL << 7);  // AP[2]=1 (Read-Only)
            if (!x)        new_leaf |= (1ULL << 54); // UXN=1
            ram_.WriteU64(entry_pa, new_leaf);
            cpu.Mmu().InvalidateVa(va, true, 0);
            if (x) cpu.Cache().InvalidatePhysPage(pa);
            va += 4096ULL;
            continue;
        }

        if (el0_allow && cur && cur->vm && IsVaInVmRanges(cur->vm->lazy_prot_none_ranges, va)) {
            uint64_t new_pa = 0;
            if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, new_pa)) return false;
            if (!Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                             va, new_pa, el0_allow, w, x)) {
                return false;
            }
            cpu.Mmu().InvalidateVa(va, true, 0);
            if (x) cpu.Cache().InvalidatePhysPage(new_pa);
            va += 4096ULL;
            continue;
        }

        if (ttbr0_pa_ == 0ULL) break;
        const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
        uint64_t d1 = 0;
        if (!ram_.ReadU64(ttbr0_pa_ + l1_idx * 8ULL, d1) || (d1 & 3ULL) != 3ULL) {
            const uint64_t next_1g = ((va >> 30) + 1ULL) << 30;
            if (next_1g <= va || next_1g >= end) break;
            va = next_1g;
            continue;
        }
        const uint64_t l2_pa = d1 & 0x0000FFFFFFFFF000ULL;
        const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
        uint64_t d2 = 0;
        if (!ram_.ReadU64(l2_pa + l2_idx * 8ULL, d2) || (d2 & 3ULL) != 3ULL) {
            const uint64_t next_2m = ((va >> 21) + 1ULL) << 21;
            if (next_2m <= va || next_2m >= end) break;
            va = next_2m;
            continue;
        }
        va += 4096ULL;
    }
    if (el0_allow && cur && cur->vm) {
        EraseVmRange(cur->vm->lazy_prot_none_ranges, start, end);
    }
    return true;
}

int64_t LinuxGuestSupervisor::OpenGuestPath(std::unordered_map<int, OpenFile>& fds,
                                            int& next_fd,
                                            const std::string& norm,
                                            uint64_t flags,
                                            uint64_t mode,
                                            bool check_access_only) {
    const bool nonblock = (flags & 04000ULL) != 0ULL; // O_NONBLOCK
    const int cloexec = ((flags & 02000000ULL) != 0ULL) ? 1 : 0; // O_CLOEXEC
    if (norm == "/dev/null" || norm == "/dev/zero" ||
        norm == "/dev/urandom" || norm == "/dev/random" ||
        norm == "/sys/fs/selinux/null") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.is_dev_null = (norm == "/dev/null" || norm == "/sys/fs/selinux/null");
        of.is_dev_zero = (norm == "/dev/zero");
        of.is_dev_urandom = (norm == "/dev/urandom" || norm == "/dev/random");
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/fb0") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.is_framebuffer = true;
        of.nonblock = nonblock;
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/binder" || norm == "/dev/hwbinder" || norm == "/dev/vndbinder") {
        if (check_access_only) return 0;
        const GuestTask* cur = CurrentTask();
        const int32_t owner_pid = cur ? cur->tgid : 1;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.is_binder = true;
        of.binder_client_id = binder_broker_.OpenClient(
            BinderIpcBroker::DomainFromPath(norm), owner_pid, uid_);
        of.nonblock = nonblock;
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/ashmem" || norm == "/dev/ion" || norm == "/dev/dma_heap/system") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.is_ashmem = (norm == "/dev/ashmem");
        of.is_ion = (norm == "/dev/ion");
        of.is_dma_heap = (norm == "/dev/dma_heap/system");
        of.shared_pages = std::make_shared<std::vector<uint64_t>>();
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(norm + "#" + std::to_string(fd));
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/kmsg" || norm == "/dev/tty" || norm == "/dev/ptmx") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.is_kmsg = (norm == "/dev/kmsg");
        of.is_tty = (norm == "/dev/tty" || norm == "/dev/ptmx");
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if ((norm == "/dev/input/event0" && touch_) || (norm == "/dev/input/event1" && kbd_)) {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.input_dev = (norm == "/dev/input/event0") ? touch_ : kbd_;
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/haseeb_sensors" || norm == "/dev/video0" ||
        norm == "/dev/haseeb_gles" || norm == "/dev/magisk_su" ||
        norm == "/dev/snd/pcmC0D0p" || norm == "/dev/snd/pcmC0D0c") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.is_sensors = (norm == "/dev/haseeb_sensors");
        of.is_camera = (norm == "/dev/video0");
        of.is_gles = (norm == "/dev/haseeb_gles");
        of.is_magisk_su = (norm == "/dev/magisk_su");
        of.is_snd_play = (norm == "/dev/snd/pcmC0D0p");
        of.is_snd_cap = (norm == "/dev/snd/pcmC0D0c");
        of.st_dev = 2ULL;
        of.st_ino = ComputeGuestInode(of.path);
        fds.emplace(fd, std::move(of));
        return fd;
    }

    std::string host_path, rel;
    if (ResolveHostStoragePath(norm, host_path, rel)) {
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_);
        struct stat hst{};
        const bool exists = (::stat(host_path.c_str(), &hst) == 0);
        if (check_access_only) {
            return exists ? 0 : -2;
        }
        const bool want_dir = (flags & 0200000ULL /* O_DIRECTORY */) != 0ULL ||
                              (exists && S_ISDIR(hst.st_mode));
        if (want_dir) {
            if (!exists) return -2;
            std::vector<std::string> children;
            GuestVfsBridge::ListHostDirectory(host_path, children);
            int fd = next_fd++;
            OpenFile of;
            of.path = norm;
            of.host_path = host_path;
            of.fd_flags = cloexec;
            of.is_dir = true;
            of.is_host_storage = true;
            of.dir_children = std::move(children);
            of.st_dev = 3ULL;
            of.st_ino = (hst.st_ino != 0) ? static_cast<uint64_t>(hst.st_ino)
                                          : ComputeGuestInode(norm);
            fds.emplace(fd, std::move(of));
            return fd;
        }
        int host_flags = O_CLOEXEC;
        const uint64_t acc = flags & 3ULL;
        if (acc == 1ULL) host_flags |= O_WRONLY;
        else if (acc == 2ULL) host_flags |= O_RDWR;
        else host_flags |= O_RDONLY;
        if (flags & 0100ULL) host_flags |= O_CREAT;
        if (flags & 01000ULL) host_flags |= O_TRUNC;
        if (flags & 02000ULL) host_flags |= O_APPEND;
        if (flags & 0200ULL) host_flags |= O_EXCL;
        const mode_t fmode = mode ? static_cast<mode_t>(mode & 0777u) : 0644;
        int hfd = ::open(host_path.c_str(), host_flags, fmode);
        if (hfd < 0) return -static_cast<int64_t>(errno);
        struct stat hfd_st{};
        const bool has_hfd_st = (::fstat(hfd, &hfd_st) == 0);
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.host_path = host_path;
        of.host_fd = hfd;
        of.fd_flags = cloexec;
        of.is_host_storage = true;
        of.nonblock = nonblock;
        of.st_dev = 3ULL;
        of.st_ino = (has_hfd_st && hfd_st.st_ino != 0)
                        ? static_cast<uint64_t>(hfd_st.st_ino)
                        : ComputeGuestInode(norm);
        fds.emplace(fd, std::move(of));
        return fd;
    }

    std::vector<uint8_t> data;
    bool is_dir = false;
    std::vector<std::string> children;
    std::string resolved_path;
    const bool found_vfs = ResolveVfsFile(norm, data, is_dir, children, &resolved_path, &fds);
    if (!found_vfs) {
        if ((flags & 0100ULL /* O_CREAT */) != 0ULL && IsWritableGuestOverlayPath(norm)) {
            if (check_access_only) return 0;
            auto& stored = runtime_files_[norm];
            stored.clear();
            int fd = next_fd++;
            OpenFile of;
            of.path = norm;
            of.fd_flags = cloexec;
            of.nonblock = nonblock;
            of.is_writable_mem = true;
            of.is_runtime_vfs = true;
            of.st_dev = 3ULL;
            of.st_ino = ComputeGuestInode(norm);
            fds.emplace(fd, std::move(of));
            return fd;
        }
        return -2; // ENOENT
    }
    if (check_access_only) return 0;
    if ((flags & 0200000ULL /* O_DIRECTORY */) != 0ULL && !is_dir) return -20; // ENOTDIR
    const std::string eff_path = resolved_path.empty() ? norm : resolved_path;
    const bool overlay_writable = !is_dir && IsWritableGuestOverlayPath(eff_path);
    const bool selinux_writable = !is_dir && IsSelinuxWritableNode(eff_path);
    const bool open_for_write = ((flags & 3ULL) != 0ULL) || ((flags & 01000ULL) != 0ULL);
    if (overlay_writable && ((flags & 01000ULL /* O_TRUNC */) != 0ULL)) {
        data.clear();
        runtime_files_[eff_path].clear();
    } else if (overlay_writable && open_for_write && runtime_files_.find(eff_path) == runtime_files_.end()) {
        runtime_files_[eff_path] = data;
    }
    int fd = next_fd++;
    OpenFile of;
    of.path = eff_path;
    of.data = std::move(data);
    of.fd_flags = cloexec;
    of.is_dir = is_dir;
    of.nonblock = nonblock;
    of.is_writable_mem = overlay_writable || selinux_writable ||
                         (runtime_files_.find(eff_path) != runtime_files_.end());
    of.is_runtime_vfs = overlay_writable || (runtime_files_.find(eff_path) != runtime_files_.end());
    if ((flags & 02000ULL /* O_APPEND */) != 0ULL && of.is_writable_mem) {
        of.offset = of.data.size();
    }
    of.dir_children = std::move(children);
    of.st_dev = (IsGuestCharDevicePath(of.path) || IsBlockDevicePath(of.path)) ? 2ULL : 1ULL;
    of.st_ino = ComputeGuestInode(of.path);
    fds.emplace(fd, std::move(of));
    return fd;
}

int64_t LinuxGuestSupervisor::StatFd(const std::unordered_map<int, OpenFile>& fds,
                                     int fd,
                                     GuestStatMeta& out) const {
    if (fd < 0) return -9; // EBADF
    auto it = fds.find(fd);
    if (it == fds.end()) {
        if (fd <= 2) {
            out.st_dev = 2ULL;
            out.st_ino = static_cast<uint64_t>(100 + fd);
            out.st_mode = 0020666u;
            out.st_size = 0ULL;
            return 0;
        }
        return -9;
    }
    const OpenFile& of = it->second;
    out.st_dev = (of.st_dev != 0ULL) ? of.st_dev : 1ULL;
    out.st_ino = (of.st_ino != 0ULL) ? of.st_ino : ComputeGuestInode(of.path);
    if (of.host_fd >= 0) {
        struct stat hst{};
        if (::fstat(of.host_fd, &hst) == 0) {
            out.st_mode = S_ISDIR(hst.st_mode) ? 0040755u : 0100755u;
            out.st_size = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
            if (hst.st_ino != 0) out.st_ino = static_cast<uint64_t>(hst.st_ino);
            return 0;
        }
    }
    if (of.is_dir) {
        out.st_mode = 0040755u;
    } else if (of.unix_sock || of.is_host_inet_sock || of.is_netlink) {
        out.st_mode = 0140777u;
    } else if (IsBlockDevicePath(of.path)) {
        out.st_mode = 0060660u;
        out.st_rdev = ComputeDeviceRdev(of.path);
    } else if (IsGuestCharDevicePath(of.path) || of.is_kmsg || of.is_tty || of.is_dev_null ||
               of.is_dev_zero || of.is_dev_urandom) {
        out.st_mode = 0020666u;
        out.st_rdev = ComputeDeviceRdev(of.path);
    } else {
        out.st_mode = 0100755u;
    }
    out.st_size = (of.is_ashmem && of.ashmem_size > 0u) ? of.ashmem_size : of.data.size();
    return 0;
}

int64_t LinuxGuestSupervisor::StatGuestPath(const std::unordered_map<int, OpenFile>& fds,
                                            int dirfd,
                                            const std::string& raw_path,
                                            uint64_t flags,
                                            std::string* out_note,
                                            GuestStatMeta& out) const {
    if (raw_path.empty() && (flags & 0x1000ULL /* AT_EMPTY_PATH */) != 0ULL) {
        if (out_note) *out_note = "AT_EMPTY_PATH";
        return StatFd(fds, dirfd, out);
    }
    std::string norm;
    if (!ResolveGuestPathWithDirfd(fds, dirfd, raw_path, norm)) return -9;
    if (out_note) *out_note = norm;

    std::string target;
    if ((flags & 0x100ULL /* AT_SYMLINK_NOFOLLOW */) != 0ULL &&
        ResolveSymlinkTarget(fds, norm, target)) {
        out.st_dev = 1ULL;
        out.st_ino = ComputeGuestInode(norm);
        out.st_mode = 0120777u;
        out.st_size = target.size();
        return 0;
    }

    if ((flags & 0x100ULL) == 0ULL && ResolveProcSymlinkTarget(fds, norm, target) &&
        !target.empty() && target.front() != '/') {
        // Resolve /proc/self/fd/<n> pointing to anonymous/pipe/memfd/socket fd directly
        const size_t fd_pos = norm.rfind("/fd/");
        if (fd_pos != std::string::npos) {
            int ref_fd = -1;
            if (ParseNonNegInt(norm.substr(fd_pos + 4u), ref_fd)) {
                return StatFd(fds, ref_fd, out);
            }
        }
    }

    std::string host_path, rel;
    if (ResolveHostStoragePath(norm, host_path, rel)) {
        struct stat hst{};
        if (::stat(host_path.c_str(), &hst) != 0) return -2;
        out.st_dev = 3ULL;
        out.st_ino = (hst.st_ino != 0) ? static_cast<uint64_t>(hst.st_ino)
                                       : ComputeGuestInode(norm);
        out.st_mode = S_ISDIR(hst.st_mode) ? 0040755u : 0100755u;
        out.st_size = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
        return 0;
    }

    std::vector<uint8_t> data;
    bool is_dir = false;
    std::vector<std::string> children;
    std::string resolved_path;
    if (!ResolveVfsFile(norm, data, is_dir, children, &resolved_path, &fds)) return -2;
    const std::string& canon = resolved_path.empty() ? norm : resolved_path;
    if (is_dir) {
        out.st_dev = 1ULL;
        out.st_mode = 0040755u;
    } else if (IsBlockDevicePath(canon)) {
        out.st_dev = 2ULL;
        out.st_mode = 0060660u;
        out.st_rdev = ComputeDeviceRdev(canon);
    } else if (IsGuestCharDevicePath(canon)) {
        out.st_dev = 2ULL;
        out.st_mode = 0020666u;
        out.st_rdev = ComputeDeviceRdev(canon);
    } else {
        out.st_dev = 1ULL;
        out.st_mode = 0100755u;
    }
    out.st_ino = ComputeGuestInode(canon);
    out.st_size = data.size();
    return 0;
}

void LinuxGuestSupervisor::HandleBuiltInPropertyServicePacket(
    const std::shared_ptr<UnixSocketEndpoint>& client_ep,
    const std::vector<uint8_t>& pkt) {
    if (pkt.size() < 4u) return;
    uint32_t cmd = 0u;
    std::memcpy(&cmd, pkt.data(), 4u);

    std::string name;
    std::string value;
    bool parsed = false;

    if (cmd == 1u && pkt.size() >= 128u) { // PROP_MSG_SETPROP (legacy 128B)
        const char* nptr = reinterpret_cast<const char*>(pkt.data() + 4u);
        const char* vptr = reinterpret_cast<const char*>(pkt.data() + 36u);
        name.assign(nptr, strnlen(nptr, 32u));
        value.assign(vptr, strnlen(vptr, 92u));
        parsed = !name.empty();
    } else if (cmd == 0x00020001u && pkt.size() >= 12u) { // PROP_MSG_SETPROP2
        uint32_t nlen = 0u;
        std::memcpy(&nlen, pkt.data() + 4u, 4u);
        if (nlen > 0u && nlen <= 256u && 8u + nlen + 4u <= pkt.size()) {
            name.assign(reinterpret_cast<const char*>(pkt.data() + 8u), nlen);
            while (!name.empty() && name.back() == '\0') name.pop_back();
            uint32_t vlen = 0u;
            std::memcpy(&vlen, pkt.data() + 8u + nlen, 4u);
            if (vlen <= 4096u && 8u + nlen + 4u + vlen <= pkt.size()) {
                value.assign(reinterpret_cast<const char*>(pkt.data() + 12u + nlen), vlen);
                while (!value.empty() && value.back() == '\0') value.pop_back();
                parsed = !name.empty();
            }
        }
    }

    int32_t reply_code = parsed ? 0 : -1;
    if (parsed) {
        if (prop_mgr_) {
            prop_mgr_->SetProperty(name, value);
        }
        LogToUart("[PROP] set " + name + "=" + value + "\r\n");
    }
    if (client_ep) {
        UnixSocketEndpoint::Chunk ack;
        ack.data.resize(4u);
        std::memcpy(ack.data.data(), &reply_code, 4u);
        client_ep->rx_chunks.push_back(std::move(ack));
        WakePollWaiters();
    }
}

void LinuxGuestSupervisor::HandleBuiltInLogdPacket(const std::vector<uint8_t>& pkt) {
    if (pkt.empty()) return;
    // Standard Android logd wire format: android_log_header_t (11B) + prio (1B) + tag\0 + msg\0
    if (pkt.size() > 13u && pkt[0] <= 7u) {
        const size_t payload_off = 12u;
        const char* base = reinterpret_cast<const char*>(pkt.data() + payload_off);
        const size_t rem = pkt.size() - payload_off;
        const size_t tag_len = strnlen(base, rem);
        if (tag_len < rem) {
            std::string tag(base, tag_len);
            const char* msg_ptr = base + tag_len + 1u;
            const size_t msg_rem = rem - tag_len - 1u;
            std::string msg(msg_ptr, strnlen(msg_ptr, msg_rem));
            while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r')) msg.pop_back();
            if (!tag.empty() || !msg.empty()) {
                LogToUart("[LOGD] " + tag + ": " + msg + "\r\n");
                return;
            }
        }
    }
    std::string text;
    text.reserve(pkt.size());
    for (uint8_t b : pkt) {
        if (b >= 0x20u && b < 0x7Fu) text.push_back(static_cast<char>(b));
        else if (b == '\n' || b == '\r') text.push_back(' ');
    }
    if (!text.empty()) {
        LogToUart("[LOGD] " + text + "\r\n");
    }
}

namespace {

bool ParseGuestUnixPath(const uint8_t* sa, size_t sa_len, std::string& out_key) {
    if (sa_len < 2u) return false;
    uint16_t family = 0u;
    std::memcpy(&family, sa, 2u);
    if (family != 1u) return false; // AF_UNIX
    if (sa_len <= 2u) return false;
    const char* path_ptr = reinterpret_cast<const char*>(sa + 2u);
    const size_t path_cap = sa_len - 2u;
    if (path_ptr[0] == '\0') {
        if (path_cap <= 1u) return false;
        size_t len = path_cap - 1u;
        while (len > 0u && path_ptr[1u + len - 1u] == '\0') --len;
        if (len == 0u) return false;
        out_key = "@" + std::string(path_ptr + 1u, len);
        return true;
    }
    const size_t n = strnlen(path_ptr, path_cap);
    if (n == 0u) return false;
    out_key.assign(path_ptr, n);
    return true;
}

} // namespace

int64_t LinuxGuestSupervisor::DispatchSyscall(AArch64CpuCore& cpu,
                                              CpuState& st,
                                              bool& out_halt,
                                              bool& out_retry,
                                              bool& out_yield,
                                              std::string* out_note) {
    out_halt = false;
    out_retry = false;
    out_yield = false;
    const uint64_t nr = st.x[8];

    GuestTask* cur = CurrentTask();
    auto& fds = (cur && cur->files) ? cur->files->fds : open_fds_;
    int& next_fd = (cur && cur->files) ? cur->files->next_fd : next_fd_;
    auto& fb_pas = (cur && cur->vm) ? cur->vm->fb_mapped_pas : fb_mapped_pas_;

    switch (nr) {
        case 5:   // setxattr(path, name, value, size, flags)
        case 6:   // lsetxattr(path, name, value, size, flags)
        case 7: { // fsetxattr(fd, name, value, size, flags)
            std::string key_path;
            if (nr == 7) {
                const int fd = static_cast<int>(st.x[0]);
                auto fit = fds.find(fd);
                if (fit == fds.end()) return -9;
                key_path = fit->second.path;
            } else {
                std::string path, norm;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -9;
                key_path = norm;
            }
            std::string xname;
            if (!ReadUserString(cpu, st.x[1], xname)) return -14;
            const size_t xlen = std::min<size_t>(static_cast<size_t>(st.x[3]), 4096u);
            std::vector<uint8_t> xval(xlen);
            if (xlen > 0u && !ReadUserBytes(cpu, st.x[2], xval.data(), xlen)) return -14;
            runtime_xattrs_[key_path][xname] = std::move(xval);
            return 0;
        }
        case 8:   // getxattr(path, name, value, size)
        case 9:   // lgetxattr(path, name, value, size)
        case 10: { // fgetxattr(fd, name, value, size)
            std::string key_path;
            bool exists = false;
            if (nr == 10) {
                const int fd = static_cast<int>(st.x[0]);
                auto fit = fds.find(fd);
                if (fit != fds.end()) {
                    key_path = fit->second.path;
                    exists = true;
                } else if (fd >= 0 && fd <= 2) {
                    key_path = (fd == 0) ? "/dev/stdin" : (fd == 1 ? "/dev/stdout" : "/dev/stderr");
                    exists = true;
                } else {
                    return -9;
                }
            } else {
                std::string path, norm;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -9;
                key_path = norm;
                std::string hp, rel;
                if (ResolveHostStoragePath(norm, hp, rel)) {
                    struct stat hst{};
                    exists = (::stat(hp.c_str(), &hst) == 0);
                } else {
                    std::vector<uint8_t> tmp;
                    bool is_dir = false;
                    std::vector<std::string> ch;
                    exists = ResolveVfsFile(norm, tmp, is_dir, ch, nullptr, &fds);
                }
            }
            if (!exists) return -2; // ENOENT
            std::string xname;
            if (!ReadUserString(cpu, st.x[1], xname)) return -14;
            std::vector<uint8_t> val;
            bool found = false;
            if (auto pit = runtime_xattrs_.find(key_path); pit != runtime_xattrs_.end()) {
                if (auto xit = pit->second.find(xname); xit != pit->second.end()) {
                    val = xit->second;
                    found = true;
                }
            }
            if (!found && xname == "security.selinux") {
                static constexpr char kDefaultCtx[] = "u:object_r:unlabeled:s0\0";
                val.assign(kDefaultCtx, kDefaultCtx + sizeof(kDefaultCtx));
                found = true;
            }
            if (!found) return -61; // ENODATA
            const size_t cap = static_cast<size_t>(st.x[3]);
            if (cap == 0u) return static_cast<int64_t>(val.size());
            if (cap < val.size()) return -34; // ERANGE
            if (!val.empty() && !WriteUserBytes(cpu, st.x[2], val.data(), val.size())) return -14;
            return static_cast<int64_t>(val.size());
        }
        case 11:  // listxattr(path, list, size)
        case 12:  // llistxattr(path, list, size)
        case 13: { // flistxattr(fd, list, size)
            std::string key_path;
            if (nr == 13) {
                const int fd = static_cast<int>(st.x[0]);
                auto fit = fds.find(fd);
                if (fit == fds.end()) return (fd >= 0 && fd <= 2) ? 0 : -9;
                key_path = fit->second.path;
            } else {
                std::string path, norm;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -9;
                key_path = norm;
            }
            std::vector<uint8_t> out_list;
            if (auto pit = runtime_xattrs_.find(key_path); pit != runtime_xattrs_.end()) {
                for (const auto& kv : pit->second) {
                    out_list.insert(out_list.end(), kv.first.begin(), kv.first.end());
                    out_list.push_back('\0');
                }
            }
            const size_t cap = static_cast<size_t>(st.x[2]);
            if (cap == 0u) return static_cast<int64_t>(out_list.size());
            if (cap < out_list.size()) return -34;
            if (!out_list.empty() && !WriteUserBytes(cpu, st.x[1], out_list.data(), out_list.size())) return -14;
            return static_cast<int64_t>(out_list.size());
        }
        case 14:  // removexattr(path, name)
        case 15:  // lremovexattr(path, name)
        case 16: { // fremovexattr(fd, name)
            std::string key_path;
            if (nr == 16) {
                const int fd = static_cast<int>(st.x[0]);
                auto fit = fds.find(fd);
                if (fit == fds.end()) return -9;
                key_path = fit->second.path;
            } else {
                std::string path, norm;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -9;
                key_path = norm;
            }
            std::string xname;
            if (!ReadUserString(cpu, st.x[1], xname)) return -14;
            if (auto pit = runtime_xattrs_.find(key_path); pit != runtime_xattrs_.end()) {
                pit->second.erase(xname);
            }
            return 0;
        }
        case 17: { // getcwd(buf, size)
            uint64_t buf = st.x[0];
            uint64_t sz = st.x[1];
            const std::string cwd = (cur && !cur->cwd.empty()) ? cur->cwd : "/";
            if (sz < cwd.size() + 1u) return -34; // ERANGE
            return WriteUserBytes(cpu, buf, cwd.c_str(), cwd.size() + 1u)
                       ? static_cast<int64_t>(buf)
                       : -14;
        }
        case 49: { // chdir(path)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[0], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -2;
            std::string hp, rel;
            if (ResolveHostStoragePath(norm, hp, rel)) {
                struct stat hst{};
                if (::stat(hp.c_str(), &hst) != 0) return -2;
                if (!S_ISDIR(hst.st_mode)) return -20; // ENOTDIR
            } else {
                std::vector<uint8_t> tmp;
                bool is_dir = false;
                std::vector<std::string> ch;
                if (!ResolveVfsFile(norm, tmp, is_dir, ch, nullptr, &fds)) return -2;
                if (!is_dir) return -20; // ENOTDIR
            }
            if (cur) cur->cwd = norm;
            return 0;
        }
        case 50: { // fchdir(fd)
            const int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            if (!it->second.is_dir) return -20; // ENOTDIR
            if (cur && !it->second.path.empty()) cur->cwd = it->second.path;
            return 0;
        }
        case 19: { // eventfd2(initval, flags)
            const uint64_t initval = st.x[0];
            const uint64_t eflags = st.x[1];
            int fd = next_fd++;
            OpenFile of;
            of.path = "anon_inode:[eventfd]";
            of.is_eventfd = true;
            of.eventfd_counter = initval;
            of.nonblock = (eflags & 04000ULL) != 0ULL;
            of.fd_flags = ((eflags & 02000000ULL) != 0ULL) ? 1 : 0;
            of.st_dev = 4ULL;
            of.st_ino = ComputeGuestInode(of.path + "#" + std::to_string(fd));
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 20: { // epoll_create1(flags)
            int fd = next_fd++;
            OpenFile of;
            of.path = "anon_inode:[eventpoll]";
            of.is_epoll = true;
            of.fd_flags = ((st.x[0] & 02000000ULL) != 0ULL) ? 1 : 0;
            of.st_dev = 4ULL;
            of.st_ino = ComputeGuestInode(of.path + "#" + std::to_string(fd));
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 21: { // epoll_ctl(epfd, op, fd, event)
            const int epfd = static_cast<int>(st.x[0]);
            auto it = fds.find(epfd);
            if (it == fds.end() || !it->second.is_epoll) return -9;
            const int op = static_cast<int>(st.x[1]);
            const int target_fd = static_cast<int>(st.x[2]);
            if (target_fd < 0 || target_fd == epfd) return -22;
            if (target_fd > 2 && fds.find(target_fd) == fds.end()) return -9;

            struct LinuxEpollEventA64 {
                uint32_t events;
                uint32_t pad;
                uint64_t data;
            };
            static_assert(sizeof(LinuxEpollEventA64) == 16, "AArch64 epoll_event must be 16 bytes");

            auto& watches = it->second.epoll_watches;
            auto wit = std::find_if(watches.begin(), watches.end(),
                                    [target_fd](const EpollWatch& w) { return w.fd == target_fd; });
            if (op == 1) { // EPOLL_CTL_ADD
                if (wit != watches.end()) return -17; // EEXIST
                LinuxEpollEventA64 ev{};
                if (st.x[3] == 0ULL || !ReadUserBytes(cpu, st.x[3], &ev, sizeof(ev))) return -14;
                watches.push_back(EpollWatch{target_fd, ev.events, ev.data});
                return 0;
            }
            if (op == 2) { // EPOLL_CTL_DEL
                if (wit == watches.end()) return -2; // ENOENT
                watches.erase(wit);
                return 0;
            }
            if (op == 3) { // EPOLL_CTL_MOD
                if (wit == watches.end()) return -2; // ENOENT
                LinuxEpollEventA64 ev{};
                if (st.x[3] == 0ULL || !ReadUserBytes(cpu, st.x[3], &ev, sizeof(ev))) return -14;
                wit->events = ev.events;
                wit->data = ev.data;
                return 0;
            }
            return -22; // EINVAL
        }
        case 22: { // epoll_pwait(epfd, events, maxevents, timeout, sigmask)
            const int epfd = static_cast<int>(st.x[0]);
            auto it = fds.find(epfd);
            if (it == fds.end() || !it->second.is_epoll) return -9;
            const uint64_t events_uva = st.x[1];
            const int maxevents = static_cast<int>(static_cast<int32_t>(st.x[2]));
            const int timeout_ms = static_cast<int>(static_cast<int32_t>(st.x[3]));
            if (maxevents <= 0) return -22;

            struct LinuxEpollEventA64 {
                uint32_t events;
                uint32_t pad;
                uint64_t data;
            };
            std::vector<LinuxEpollEventA64> ready;
            const size_t limit = static_cast<size_t>(std::min(maxevents, 1024));
            for (auto& w : it->second.epoll_watches) {
                if (ready.size() >= limit) break;
                if (w.events == 0u) continue;
                const uint32_t rev = ComputeGuestFdPollEvents(fds, w.fd);
                const uint32_t mask = (w.events & 0x0FFFFFFFu) | 0x008u | 0x010u; // ERR|HUP
                const uint32_t hit = rev & mask;
                if (hit != 0u) {
                    LinuxEpollEventA64 ev{};
                    ev.events = hit;
                    ev.data = w.data;
                    ready.push_back(ev);
                    if ((w.events & 0x40000000u /* EPOLLONESHOT */) != 0u) {
                        w.events = 0u;
                    }
                }
            }
            if (ready.empty() && timeout_ms != 0 && cur != nullptr) {
                cur->state = TaskState::PollWait;
                cur->poll_wait_epfd = epfd;
                cur->poll_wait_fds.clear();
                cur->poll_events_uva = events_uva;
                cur->poll_maxevents = maxevents;
                if (timeout_ms > 0) {
                    cur->poll_has_timeout = true;
                    cur->poll_deadline_ns =
                        NowSteadyNs() + static_cast<int64_t>(timeout_ms) * 1000000LL;
                } else {
                    cur->poll_has_timeout = false;
                    cur->poll_deadline_ns = 0;
                }
                st.sys.elr_el1 -= 4ULL;
                out_retry = true;
                out_yield = true;
                return 0;
            }
            if (!ready.empty() &&
                !WriteUserBytes(cpu, events_uva, ready.data(),
                                ready.size() * sizeof(LinuxEpollEventA64))) {
                return -14;
            }
            return static_cast<int64_t>(ready.size());
        }
        case 85: { // timerfd_create(clockid, flags)
            const int clockid = static_cast<int>(st.x[0]);
            const uint64_t tflags = st.x[1];
            int fd = next_fd++;
            OpenFile of;
            of.path = "anon_inode:[timerfd]";
            of.is_timerfd = true;
            of.timerfd_clockid = clockid;
            of.nonblock = (tflags & 04000ULL) != 0ULL;
            of.fd_flags = ((tflags & 02000000ULL) != 0ULL) ? 1 : 0;
            of.st_dev = 4ULL;
            of.st_ino = ComputeGuestInode(of.path + "#" + std::to_string(fd));
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 86: { // timerfd_settime(fd, flags, new_value, old_value)
            auto it = fds.find(static_cast<int>(st.x[0]));
            if (it == fds.end() || !it->second.is_timerfd) return -9;
            const uint64_t flags = st.x[1];
            struct LinuxItimerspec {
                int64_t it_interval[2];
                int64_t it_value[2];
            };
            const int64_t now = NowSteadyNs();
            if (st.x[3] != 0ULL) {
                LinuxItimerspec old_spec{};
                if (it->second.timerfd_next_expire_ns > now) {
                    const int64_t rem = it->second.timerfd_next_expire_ns - now;
                    old_spec.it_value[0] = rem / 1000000000LL;
                    old_spec.it_value[1] = rem % 1000000000LL;
                }
                old_spec.it_interval[0] = it->second.timerfd_interval_ns / 1000000000LL;
                old_spec.it_interval[1] = it->second.timerfd_interval_ns % 1000000000LL;
                if (!WriteUserBytes(cpu, st.x[3], &old_spec, sizeof(old_spec))) return -14;
            }
            LinuxItimerspec new_spec{};
            if (!ReadUserBytes(cpu, st.x[2], &new_spec, sizeof(new_spec))) return -14;
            const int64_t val_ns = new_spec.it_value[0] * 1000000000LL + new_spec.it_value[1];
            const int64_t iv_ns = new_spec.it_interval[0] * 1000000000LL + new_spec.it_interval[1];
            if (val_ns < 0 || iv_ns < 0) return -22;
            it->second.timerfd_expirations = 0ULL;
            it->second.timerfd_interval_ns = iv_ns;
            if (val_ns == 0) {
                it->second.timerfd_next_expire_ns = 0;
            } else if ((flags & 1ULL /* TFD_TIMER_ABSTIME */) != 0ULL) {
                if (it->second.timerfd_clockid == 0) { // CLOCK_REALTIME
                    const int64_t real_now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    it->second.timerfd_next_expire_ns = now + (val_ns - real_now);
                } else {
                    it->second.timerfd_next_expire_ns = val_ns;
                }
            } else {
                it->second.timerfd_next_expire_ns = now + val_ns;
            }
            return 0;
        }
        case 87: { // timerfd_gettime(fd, curr_value)
            auto it = fds.find(static_cast<int>(st.x[0]));
            if (it == fds.end() || !it->second.is_timerfd) return -9;
            struct LinuxItimerspec {
                int64_t it_interval[2];
                int64_t it_value[2];
            } cur_spec{};
            const int64_t now = NowSteadyNs();
            if (it->second.timerfd_next_expire_ns > now) {
                const int64_t rem = it->second.timerfd_next_expire_ns - now;
                cur_spec.it_value[0] = rem / 1000000000LL;
                cur_spec.it_value[1] = rem % 1000000000LL;
            }
            cur_spec.it_interval[0] = it->second.timerfd_interval_ns / 1000000000LL;
            cur_spec.it_interval[1] = it->second.timerfd_interval_ns % 1000000000LL;
            return WriteUserBytes(cpu, st.x[1], &cur_spec, sizeof(cur_spec)) ? 0 : -14;
        }
        case 23: { // dup(oldfd)
            int oldfd = static_cast<int>(st.x[0]);
            auto it = fds.find(oldfd);
            if (it != fds.end()) {
                OpenFile copy = it->second;
                copy.fd_flags = 0;
                if (copy.host_fd >= 0) {
                    copy.host_fd = ::dup(copy.host_fd);
                    if (copy.host_fd < 0) return -static_cast<int64_t>(errno);
                }
                int newfd = next_fd++;
                fds.emplace(newfd, std::move(copy));
                return newfd;
            }
            if (oldfd >= 0 && oldfd <= 2) {
                int newfd = next_fd++;
                OpenFile of;
                of.path = (oldfd == 0) ? "/dev/stdin" : (oldfd == 1 ? "/dev/stdout" : "/dev/stderr");
                of.is_stdio_out = (oldfd == 1 || oldfd == 2);
                of.st_dev = 2ULL;
                of.st_ino = static_cast<uint64_t>(100 + oldfd);
                fds.emplace(newfd, std::move(of));
                return newfd;
            }
            return -9;
        }
        case 24: { // dup3(oldfd, newfd, flags)
            int oldfd = static_cast<int>(st.x[0]);
            int newfd = static_cast<int>(st.x[1]);
            uint64_t dflags = st.x[2];
            if (oldfd < 0 || newfd < 0) return -9;
            if (oldfd == newfd) return -22;
            OpenFile copy;
            auto it = fds.find(oldfd);
            if (it != fds.end()) {
                copy = it->second;
                if (copy.host_fd >= 0) {
                    copy.host_fd = ::dup(copy.host_fd);
                    if (copy.host_fd < 0) return -static_cast<int64_t>(errno);
                }
            } else if (oldfd >= 0 && oldfd <= 2) {
                copy.path = (oldfd == 0) ? "/dev/stdin" : (oldfd == 1 ? "/dev/stdout" : "/dev/stderr");
                copy.is_stdio_out = (oldfd == 1 || oldfd == 2);
                copy.st_dev = 2ULL;
                copy.st_ino = static_cast<uint64_t>(100 + oldfd);
            } else {
                return -9;
            }
            copy.fd_flags = ((dflags & 02000000ULL) != 0ULL) ? 1 : 0;
            auto existing = fds.find(newfd);
            if (existing != fds.end()) {
                CloseSingleOpenFile(existing->second);
                fds.erase(existing);
            }
            fds.emplace(newfd, std::move(copy));
            if (next_fd <= newfd) next_fd = newfd + 1;
            return newfd;
        }
        case 25: { // fcntl(fd, cmd, arg)
            int fd = static_cast<int>(st.x[0]);
            int cmd = static_cast<int>(st.x[1]);
            uint64_t arg = st.x[2];
            auto it = fds.find(fd);
            if (fd < 0 || (fd > 2 && it == fds.end())) return -9; // EBADF
            switch (cmd) {
                case 0:    // F_DUPFD
                case 1030: { // F_DUPFD_CLOEXEC
                    int min_fd = std::max<int>(3, static_cast<int>(arg));
                    while (fds.find(min_fd) != fds.end()) ++min_fd;
                    OpenFile copy;
                    if (it != fds.end()) {
                        copy = it->second;
                        if (copy.host_fd >= 0) {
                            copy.host_fd = ::dup(copy.host_fd);
                            if (copy.host_fd < 0) return -static_cast<int64_t>(errno);
                        }
                    } else {
                        copy.path = (fd == 0) ? "/dev/stdin" : (fd == 1 ? "/dev/stdout" : "/dev/stderr");
                        copy.is_stdio_out = (fd == 1 || fd == 2);
                        copy.st_dev = 2ULL;
                        copy.st_ino = static_cast<uint64_t>(100 + fd);
                    }
                    copy.fd_flags = (cmd == 1030) ? 1 : 0;
                    fds.emplace(min_fd, std::move(copy));
                    if (next_fd <= min_fd) next_fd = min_fd + 1;
                    return min_fd;
                }
                case 1: // F_GETFD
                    return (it != fds.end()) ? it->second.fd_flags : 0;
                case 2: // F_SETFD
                    if (it != fds.end()) it->second.fd_flags = static_cast<int>(arg & 1ULL);
                    return 0;
                case 3: // F_GETFL
                    return (it != fds.end()) ? (it->second.nonblock ? 04000 : 0) : 2;
                case 4: // F_SETFL
                    if (it != fds.end()) {
                        it->second.nonblock = (arg & 04000ULL) != 0ULL;
                        if (it->second.host_fd >= 0) {
                            int hf = ::fcntl(it->second.host_fd, F_GETFL, 0);
                            if (hf >= 0) {
                                ::fcntl(it->second.host_fd, F_SETFL,
                                        it->second.nonblock ? (hf | O_NONBLOCK) : (hf & ~O_NONBLOCK));
                            }
                        }
                    }
                    return 0;
                default:
                    return 0;
            }
        }
        case 26: { // inotify_init1(flags)
            const uint64_t iflags = st.x[0];
            const int ifd = next_fd++;
            OpenFile of;
            of.path = "anon_inode:inotify";
            of.fd_flags = ((iflags & 02000000ULL) != 0ULL) ? 1 : 0;
            of.nonblock = (iflags & 04000ULL) != 0ULL;
            of.is_dev_null = true;
            of.st_dev = 4ULL;
            of.st_ino = static_cast<uint64_t>(700000 + ifd);
            fds.emplace(ifd, std::move(of));
            return ifd;
        }
        case 27: // inotify_add_watch(fd, pathname, mask)
            return 1;
        case 28: // inotify_rm_watch(fd, wd)
        case 30: // ioprio_set(which, who, ioprio)
        case 31: // ioprio_get(which, who)
            return 0;
        case 34: { // mkdirat(dirfd, pathname, mode)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            std::string host_path, rel;
            if (!ResolveHostStoragePath(norm, host_path, rel)) {
                if (IsWritableGuestOverlayPath(norm)) {
                    runtime_dirs_.insert(norm);
                    return 0;
                }
                std::vector<uint8_t> tmp;
                bool is_dir = false;
                std::vector<std::string> ch;
                if (ResolveVfsFile(norm, tmp, is_dir, ch, nullptr, &fds)) {
                    return -17; // EEXIST
                }
                return -13; // EACCES
            }
            GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_);
            if (::mkdir(host_path.c_str(), static_cast<mode_t>(st.x[2] ? st.x[2] : 0755)) != 0) {
                if (errno == EEXIST) return 0;
                return -static_cast<int64_t>(errno);
            }
            return 0;
        }
        case 35: { // unlinkat(dirfd, pathname, flags)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            std::string host_path, rel;
            if (!ResolveHostStoragePath(norm, host_path, rel) || rel.empty()) {
                if (IsWritableGuestOverlayPath(norm)) {
                    const bool rm_dir = (st.x[2] & 0x200ULL) != 0ULL;
                    if (rm_dir) {
                        if (runtime_dirs_.erase(norm) > 0u) return 0;
                    } else {
                        if (runtime_files_.erase(norm) > 0u || runtime_symlinks_.erase(norm) > 0u) return 0;
                    }
                    return -2; // ENOENT
                }
                return -13;
            }
            const bool rm_dir = (st.x[2] & 0x200ULL) != 0ULL; // AT_REMOVEDIR
            const int rc = rm_dir ? ::rmdir(host_path.c_str()) : ::unlink(host_path.c_str());
            return (rc == 0) ? 0 : -static_cast<int64_t>(errno);
        }
        case 36: { // symlinkat(target, newdirfd, linkpath)
            std::string target, linkp, norm;
            if (!ReadUserString(cpu, st.x[0], target) || !ReadUserString(cpu, st.x[2], linkp)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[1]), linkp, norm)) return -9;
            if (IsWritableGuestOverlayPath(norm)) {
                runtime_symlinks_[norm] = target;
                return 0;
            }
            return 0;
        }
        case 38:   // renameat(olddirfd, oldpath, newdirfd, newpath)
        case 276: { // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
            std::string old_p, new_p, old_norm, new_norm;
            if (!ReadUserString(cpu, st.x[1], old_p) ||
                !ReadUserString(cpu, st.x[3], new_p)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), old_p, old_norm) ||
                !ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[2]), new_p, new_norm)) {
                return -9;
            }
            std::string h_old, r_old, h_new, r_new;
            if (!ResolveHostStoragePath(old_norm, h_old, r_old) ||
                !ResolveHostStoragePath(new_norm, h_new, r_new)) {
                if (auto rf = runtime_files_.find(old_norm); rf != runtime_files_.end()) {
                    runtime_files_[new_norm] = std::move(rf->second);
                    runtime_files_.erase(rf);
                    return 0;
                }
                if (auto sl = runtime_symlinks_.find(old_norm); sl != runtime_symlinks_.end()) {
                    runtime_symlinks_[new_norm] = std::move(sl->second);
                    runtime_symlinks_.erase(sl);
                    return 0;
                }
                if (runtime_dirs_.erase(old_norm) > 0u) {
                    runtime_dirs_.insert(new_norm);
                    return 0;
                }
                return -18; // EXDEV
            }
            return (::rename(h_old.c_str(), h_new.c_str()) == 0) ? 0 : -static_cast<int64_t>(errno);
        }
        case 43:   // statfs(path, buf)
        case 44: { // fstatfs(fd, buf)
            std::string fs_path;
            if (nr == 43) {
                std::string path;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                std::string norm;
                if (!ResolveGuestPathWithDirfd(fds, -100, path, norm)) return -2;
                fs_path = norm;
                std::string hp, rel;
                if (!ResolveHostStoragePath(norm, hp, rel)) {
                    std::vector<uint8_t> tmp;
                    bool is_dir = false;
                    std::vector<std::string> ch;
                    if (!ResolveVfsFile(norm, tmp, is_dir, ch, nullptr, &fds)) return -2;
                }
            } else {
                int fd = static_cast<int>(st.x[0]);
                auto fit = fds.find(fd);
                if (fd > 2 && fit == fds.end()) return -9;
                if (fit != fds.end()) fs_path = fit->second.path;
            }
            struct LinuxStatFs64 {
                int64_t f_type;
                int64_t f_bsize;
                uint64_t f_blocks;
                uint64_t f_bfree;
                uint64_t f_bavail;
                uint64_t f_files;
                uint64_t f_ffree;
                uint64_t f_fsid;
                int64_t f_namelen;
                int64_t f_frsize;
                int64_t f_flags;
                int64_t f_spare[4];
            } sfs{};
            const uint64_t blocks = std::max<uint64_t>(65536ULL, ram_bytes_ / 4096ULL);
            int64_t ftype = 0xEF53LL; // EXT4_SUPER_MAGIC
            if (fs_path == "/sys/fs/selinux" || fs_path.rfind("/sys/fs/selinux/", 0) == 0) {
                ftype = 0xF97CFF8CLL; // SELINUX_MAGIC
            } else if (fs_path == "/proc" || fs_path.rfind("/proc/", 0) == 0) {
                ftype = 0x9FA0LL; // PROC_SUPER_MAGIC
            } else if (fs_path == "/sys" || fs_path.rfind("/sys/", 0) == 0) {
                ftype = 0x62656572LL; // SYSFS_MAGIC
            } else if (IsWritableGuestOverlayPath(fs_path) &&
                       fs_path != "/data" && fs_path.rfind("/data/", 0) != 0) {
                ftype = 0x01021994LL; // TMPFS_MAGIC
            }
            sfs.f_type = ftype;
            sfs.f_bsize = 4096LL;
            sfs.f_blocks = blocks;
            sfs.f_bfree = blocks / 2ULL;
            sfs.f_bavail = blocks / 2ULL;
            sfs.f_files = 65536ULL;
            sfs.f_ffree = 32768ULL;
            sfs.f_namelen = 255LL;
            sfs.f_frsize = 4096LL;
            return WriteUserBytes(cpu, st.x[1], &sfs, sizeof(sfs)) ? 0 : -14;
        }
        case 46: { // ftruncate(fd, length)
            int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            if (it->second.is_memfd || it->second.is_ashmem || it->second.is_writable_mem) {
                const size_t new_len = static_cast<size_t>(std::min<uint64_t>(st.x[1], 64ULL * 1024ULL * 1024ULL));
                it->second.data.resize(new_len, 0u);
                if (it->second.is_ashmem) it->second.ashmem_size = new_len;
                if (it->second.is_runtime_vfs) runtime_files_[it->second.path] = it->second.data;
                return 0;
            }
            if (it->second.host_fd < 0) return -9;
            return (::ftruncate(it->second.host_fd, static_cast<off_t>(st.x[1])) == 0)
                       ? 0
                       : -static_cast<int64_t>(errno);
        }
        case 59: { // pipe2(pipefd[2], flags)
            int pfds[2]{-1, -1};
            if (::pipe(pfds) != 0) return -static_cast<int64_t>(errno);
            if (st.x[1] & 04000ULL) {
                ::fcntl(pfds[0], F_SETFL, O_NONBLOCK);
                ::fcntl(pfds[1], F_SETFL, O_NONBLOCK);
            }
            const int clo = ((st.x[1] & 02000000ULL) != 0ULL) ? 1 : 0;
            const int rfd = next_fd++;
            const int wfd = next_fd++;
            OpenFile rf, wf;
            rf.path = "pipe:[r]";
            rf.host_fd = pfds[0];
            rf.fd_flags = clo;
            rf.nonblock = (st.x[1] & 04000ULL) != 0ULL;
            rf.st_dev = 4ULL;
            rf.st_ino = ComputeGuestInode(rf.path + "#" + std::to_string(rfd));
            wf.path = "pipe:[w]";
            wf.host_fd = pfds[1];
            wf.fd_flags = clo;
            wf.nonblock = (st.x[1] & 04000ULL) != 0ULL;
            wf.st_dev = 4ULL;
            wf.st_ino = ComputeGuestInode(wf.path + "#" + std::to_string(wfd));
            fds.emplace(rfd, std::move(rf));
            fds.emplace(wfd, std::move(wf));
            int32_t out[2] = {rfd, wfd};
            if (!WriteUserBytes(cpu, st.x[0], out, sizeof(out))) return -14;
            return 0;
        }
        case 29: { // ioctl(fd, request, argp)
            int fd = static_cast<int>(st.x[0]);
            uint64_t req = st.x[1] & 0xFFFFFFFFULL;
            uint64_t arg = st.x[2];
            auto it = fds.find(fd);
            if (it != fds.end() && it->second.is_binder) {
                if (req == 0x424901ULL) { // HASEEB_BINDER_ADD_SERVICE(const char* name)
                    std::string svc_name;
                    if (!ReadUserString(cpu, arg, svc_name) || svc_name.empty()) return -14;
                    if (std::find(binder_services_.begin(), binder_services_.end(), svc_name) ==
                        binder_services_.end()) {
                        binder_services_.push_back(svc_name);
                        const int32_t pid = cur ? cur->pid : 1;
                        LogToUart("[BINDER] +service " + svc_name + " (pid=" + std::to_string(pid) + ")\r\n");
                    }
                    return 0;
                }
                if (req == 0x424902ULL) { // HASEEB_BINDER_LIST_COUNT
                    return static_cast<int64_t>(binder_services_.size());
                }
                bool would_block = false;
                auto dup_fd_fn = [this](int32_t sender_pid, int32_t target_pid, int32_t sender_fd) -> int32_t {
                    GuestTask* sender = nullptr;
                    GuestTask* target = nullptr;
                    for (auto& t : tasks_) {
                        if (!t || !t->files) continue;
                        if (!sender && (t->pid == sender_pid || t->tgid == sender_pid)) sender = t.get();
                        if (!target && (t->pid == target_pid || t->tgid == target_pid)) target = t.get();
                    }
                    if (!sender || !target) return -1;
                    auto sit = sender->files->fds.find(sender_fd);
                    if (sit == sender->files->fds.end()) return -1;
                    OpenFile copy = sit->second;
                    if (copy.host_fd >= 0) {
                        copy.host_fd = ::dup(copy.host_fd);
                        if (copy.host_fd < 0) return -1;
                    }
                    copy.fd_flags = 1; // FD_CLOEXEC
                    const int nfd = target->files->next_fd++;
                    target->files->fds.emplace(nfd, std::move(copy));
                    return nfd;
                };
                const int64_t brc = binder_broker_.HandleIoctl(
                    it->second.binder_client_id,
                    static_cast<uint32_t>(req),
                    arg,
                    ram_,
                    [&](uint64_t uva, void* dst, size_t len) { return ReadUserBytes(cpu, uva, dst, len); },
                    [&](uint64_t uva, const void* src, size_t len) { return WriteUserBytes(cpu, uva, src, len); },
                    dup_fd_fn,
                    [this](int32_t target_pid) { WakeBinderWaitersForPid(target_pid); },
                    it->second.nonblock,
                    would_block);
                if (would_block && cur != nullptr) {
                    cur->state = TaskState::BinderWait;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                return brc;
            }
            if (it != fds.end() && it->second.is_framebuffer) {
                const uint32_t w = gpu_ ? gpu_->DisplayWidth() : 720u;
                const uint32_t h = gpu_ ? gpu_->DisplayHeight() : 1560u;
                if (req == 0x4600ULL) { // FBIOGET_VSCREENINFO (160 bytes)
                    struct LinuxFbVarScreenInfo {
                        uint32_t xres, yres, xres_virtual, yres_virtual;
                        uint32_t xoffset, yoffset, bits_per_pixel, grayscale;
                        uint32_t red[3], green[3], blue[3], transp[3];
                        uint32_t nonstd, activate, height, width, accel_flags;
                        uint32_t pixclock, left_margin, right_margin, upper_margin;
                        uint32_t lower_margin, hsync_len, vsync_len, sync, vmode;
                        uint32_t rotate, colorspace, reserved[4];
                    } v{};
                    v.xres = w; v.yres = h;
                    v.xres_virtual = w; v.yres_virtual = h;
                    v.bits_per_pixel = 32u;
                    v.red[0] = 0u;    v.red[1] = 8u;
                    v.green[0] = 8u;  v.green[1] = 8u;
                    v.blue[0] = 16u;  v.blue[1] = 8u;
                    v.transp[0] = 24u; v.transp[1] = 8u;
                    return WriteUserBytes(cpu, arg, &v, sizeof(v)) ? 0 : -14;
                }
                if (req == 0x4601ULL) { // FBIOPUT_VSCREENINFO
                    return 0;
                }
                if (req == 0x4602ULL) { // FBIOGET_FSCREENINFO (68 bytes on arm64)
                    struct LinuxFbFixScreenInfo {
                        char id[16];
                        uint64_t smem_start;
                        uint32_t smem_len;
                        uint32_t type;
                        uint32_t type_aux;
                        uint32_t visual;
                        uint16_t xpanstep, ypanstep, ywrapstep;
                        uint16_t pad;
                        uint32_t line_length;
                        uint64_t mmio_start;
                        uint32_t mmio_len;
                        uint32_t accel;
                        uint16_t capabilities;
                        uint16_t reserved[2];
                    } f{};
                    std::snprintf(f.id, sizeof(f.id), "haseeb-fb");
                    f.smem_len = w * h * 4u;
                    f.visual = 2u; // FB_VISUAL_TRUECOLOR
                    f.line_length = w * 4u;
                    return WriteUserBytes(cpu, arg, &f, sizeof(f)) ? 0 : -14;
                }
                if (req == 0x4606ULL) { // FBIOPAN_DISPLAY -> scan out framebuffer to VirtioGpu
                    return FlushFramebufferToGpu() ? 0 : -5;
                }
            } else if (it != fds.end() && it->second.input_dev != nullptr) {
                VirtioInputDevice* indev = it->second.input_dev;
                const uint32_t ioc_type = static_cast<uint32_t>((req >> 8) & 0xFFu);
                const uint32_t ioc_nr = static_cast<uint32_t>(req & 0xFFu);
                const size_t ioc_size = static_cast<size_t>((req >> 16) & 0x3FFFu);
                if (ioc_type == 'E') {
                    if (ioc_nr == 0x01u) { // EVIOCGVERSION
                        uint32_t ver = 0x010001u;
                        return WriteUserBytes(cpu, arg, &ver, sizeof(ver)) ? 0 : -14;
                    }
                    if (ioc_nr == 0x02u) { // EVIOCGID
                        struct InputId { uint16_t bustype, vendor, product, version; } id{};
                        indev->GetDeviceIds(id.bustype, id.vendor, id.product, id.version);
                        return WriteUserBytes(cpu, arg, &id, sizeof(id)) ? 0 : -14;
                    }
                    if (ioc_nr == 0x06u || ioc_nr == 0x07u || ioc_nr == 0x08u) {
                        std::string s = (ioc_nr == 0x06u) ? indev->DeviceName()
                                      : (ioc_nr == 0x07u) ? indev->DevicePhys()
                                                          : indev->DeviceUniq();
                        const size_t max_len = std::min<size_t>(ioc_size > 0u ? ioc_size : 64u, s.size() + 1u);
                        std::vector<uint8_t> buf(max_len, 0u);
                        if (max_len > 1u) {
                            std::memcpy(buf.data(), s.data(), std::min(s.size(), max_len - 1u));
                        }
                        return WriteUserBytes(cpu, arg, buf.data(), buf.size())
                                   ? static_cast<int64_t>(buf.size())
                                   : -14;
                    }
                    if (ioc_nr == 0x09u) { // EVIOCGPROP(len)
                        const size_t n = std::clamp<size_t>(ioc_size, 1u, 64u);
                        std::vector<uint8_t> prop(n, 0u);
                        indev->FillPropBitmap(prop.data(), prop.size());
                        return WriteUserBytes(cpu, arg, prop.data(), prop.size())
                                   ? static_cast<int64_t>(prop.size())
                                   : -14;
                    }
                    if (ioc_nr >= 0x20u && ioc_nr <= 0x3Fu) { // EVIOCGBIT(ev, len)
                        const uint32_t ev_type = ioc_nr - 0x20u;
                        const size_t n = std::clamp<size_t>(ioc_size, 1u, 128u);
                        std::vector<uint8_t> bits(n, 0u);
                        indev->FillEventBitmap(ev_type, bits.data(), bits.size());
                        return WriteUserBytes(cpu, arg, bits.data(), bits.size())
                                   ? static_cast<int64_t>(bits.size())
                                   : -14;
                    }
                    if (ioc_nr >= 0x40u && ioc_nr <= 0x7Fu) { // EVIOCGABS(abs)
                        const uint16_t abs_code = static_cast<uint16_t>(ioc_nr - 0x40u);
                        const VirtioInputDevice::LinuxAbsInfo info = indev->GetAbsInfo(abs_code);
                        return WriteUserBytes(cpu, arg, &info, sizeof(info)) ? 0 : -14;
                    }
                    return -22; // EINVAL
                }
            } else if (it != fds.end() && it->second.is_ashmem) {
                const uint32_t ioc_type = static_cast<uint32_t>((req >> 8) & 0xFFu);
                const uint32_t ioc_nr = static_cast<uint32_t>(req & 0xFFu);
                if (ioc_type == 0x77u) { // '__ASHMEMIOC' = 0x77 ('w')
                    if (ioc_nr == 1u) { // ASHMEM_SET_NAME
                        std::string nm;
                        if (!ReadUserString(cpu, arg, nm)) return -14;
                        it->second.ashmem_name = nm;
                        return 0;
                    }
                    if (ioc_nr == 2u) { // ASHMEM_GET_NAME
                        char buf[256]{};
                        std::snprintf(buf, sizeof(buf), "%s", it->second.ashmem_name.c_str());
                        return WriteUserBytes(cpu, arg, buf, sizeof(buf)) ? 0 : -14;
                    }
                    if (ioc_nr == 3u) { // ASHMEM_SET_SIZE
                        const size_t new_sz = static_cast<size_t>(
                            std::min<uint64_t>(arg, 64ULL * 1024ULL * 1024ULL));
                        it->second.ashmem_size = new_sz;
                        it->second.data.resize(new_sz, 0u);
                        return 0;
                    }
                    if (ioc_nr == 4u) { // ASHMEM_GET_SIZE
                        return static_cast<int64_t>(it->second.ashmem_size);
                    }
                    if (ioc_nr == 5u) { // ASHMEM_SET_PROT_MASK
                        it->second.ashmem_prot = static_cast<uint32_t>(arg);
                        return 0;
                    }
                    if (ioc_nr == 6u) { // ASHMEM_GET_PROT_MASK
                        return static_cast<int64_t>(it->second.ashmem_prot);
                    }
                    if (ioc_nr == 7u) { // ASHMEM_PIN
                        it->second.ashmem_pinned = true;
                        return 0; // ASHMEM_NOT_PURGED
                    }
                    if (ioc_nr == 8u) { // ASHMEM_UNPIN
                        it->second.ashmem_pinned = false;
                        return 0;
                    }
                    if (ioc_nr == 9u) { // ASHMEM_GET_PIN_STATUS
                        return it->second.ashmem_pinned ? 0 : 1;
                    }
                }
                return 0;
            } else if (it != fds.end() && (it->second.is_dma_heap || it->second.is_ion)) {
                if (req == 0xC0184800ULL /* DMA_HEAP_IOCTL_ALLOC */) {
                    struct DmaHeapAllocationData {
                        uint64_t len;
                        uint32_t fd;
                        uint32_t fd_flags;
                        uint64_t heap_flags;
                    } alloc_req{};
                    if (!ReadUserBytes(cpu, arg, &alloc_req, sizeof(alloc_req))) return -14;
                    const size_t sz = static_cast<size_t>(
                        std::min<uint64_t>(AlignUp4K(alloc_req.len), 64ULL * 1024ULL * 1024ULL));
                    const int buf_fd = next_fd++;
                    OpenFile bof;
                    bof.path = "/dev/dma_heap/system:buf#" + std::to_string(buf_fd);
                    bof.is_memfd = true;
                    bof.is_dma_heap = true;
                    bof.is_writable_mem = true;
                    bof.ashmem_size = sz;
                    bof.data.resize(sz, 0u);
                    bof.shared_pages = std::make_shared<std::vector<uint64_t>>();
                    bof.fd_flags = ((alloc_req.fd_flags & 02000000u) != 0u) ? 1 : 0;
                    bof.st_dev = 4ULL;
                    bof.st_ino = ComputeGuestInode(bof.path);
                    fds.emplace(buf_fd, std::move(bof));
                    alloc_req.fd = static_cast<uint32_t>(buf_fd);
                    return WriteUserBytes(cpu, arg, &alloc_req, sizeof(alloc_req)) ? 0 : -14;
                }
                return 0;
            } else if (it != fds.end() &&
                       (it->second.is_sensors || it->second.is_camera ||
                        it->second.is_magisk_su || it->second.is_gles)) {
                return GuestVfsBridge::HandleSpecialIoctl(
                    it->second, req, arg, hardware_, soft_gles_, gpu_, uid_, gid_, active_binary_,
                    [&](uint64_t uva, void* dst, size_t len) { return ReadUserBytes(cpu, uva, dst, len); },
                    [&](uint64_t uva, const void* src, size_t len) { return WriteUserBytes(cpu, uva, src, len); });
            } else if (it != fds.end()) {
                if (req == 0x5421ULL) { // FIONBIO
                    int32_t nb = 0;
                    if (!ReadUserBytes(cpu, arg, &nb, sizeof(nb))) return -14;
                    it->second.nonblock = (nb != 0);
                    if (it->second.host_fd >= 0) {
                        int hf = ::fcntl(it->second.host_fd, F_GETFL, 0);
                        if (hf >= 0) {
                            ::fcntl(it->second.host_fd, F_SETFL,
                                    it->second.nonblock ? (hf | O_NONBLOCK) : (hf & ~O_NONBLOCK));
                        }
                    }
                    return 0;
                }
                if (req == 0x541BULL) { // FIONREAD
                    int32_t avail = 0;
                    if (it->second.unix_sock && !it->second.unix_sock->rx_chunks.empty()) {
                        avail = static_cast<int32_t>(it->second.unix_sock->rx_chunks.front().data.size());
                    } else if (it->second.host_fd >= 0) {
                        ::ioctl(it->second.host_fd, FIONREAD, &avail);
                    }
                    return WriteUserBytes(cpu, arg, &avail, sizeof(avail)) ? 0 : -14;
                }
            }
            return 0;
        }
        case 48:   // faccessat(dirfd, pathname, mode, flags)
        case 56:   // openat(dirfd, pathname, flags, mode)
        case 439: { // faccessat2(dirfd, pathname, mode, flags)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            if (out_note) *out_note = norm;
            return OpenGuestPath(fds, next_fd, norm,
                                 (nr == 56) ? st.x[2] : 0ULL,
                                 (nr == 56) ? st.x[3] : 0ULL,
                                 (nr != 56));
        }
        case 437: { // openat2(dirfd, pathname, how, size)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            if (out_note) *out_note = norm;
            uint64_t how[3]{};
            const size_t how_sz = std::min<size_t>(static_cast<size_t>(st.x[3]), sizeof(how));
            if (how_sz > 0u && !ReadUserBytes(cpu, st.x[2], how, how_sz)) return -14;
            return OpenGuestPath(fds, next_fd, norm, how[0], how[1], false);
        }
        case 57: { // close(fd)
            int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it == fds.end()) {
                return (fd >= 0 && fd <= 2) ? 0 : -9;
            }
            CloseSingleOpenFile(it->second);
            fds.erase(it);
            return 0;
        }
        case 61: { // getdents64(fd, dirp, count)
            int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            return GuestVfsBridge::BuildGetDents64(
                it->second, st.x[1], static_cast<size_t>(st.x[2]),
                [&](uint64_t uva, const void* src, size_t len) { return WriteUserBytes(cpu, uva, src, len); });
        }
        case 62: { // lseek
            int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            int64_t off = static_cast<int64_t>(st.x[1]);
            int whence = static_cast<int>(st.x[2]);
            if (it->second.host_fd >= 0) {
                off_t rc = ::lseek(it->second.host_fd, static_cast<off_t>(off), whence);
                return (rc >= 0) ? static_cast<int64_t>(rc) : -static_cast<int64_t>(errno);
            }
            int64_t target = off;
            if (whence == 1) target = static_cast<int64_t>(it->second.offset) + off;
            else if (whence == 2) target = static_cast<int64_t>(it->second.data.size()) + off;
            if (target < 0) return -22;
            it->second.offset = static_cast<size_t>(target);
            return target;
        }
        case 63: { // read(fd, buf, count)
            int fd = static_cast<int>(st.x[0]);
            uint64_t buf = st.x[1];
            size_t count = static_cast<size_t>(st.x[2]);
            auto it = fds.find(fd);
            if (fd == 0 && it == fds.end()) {
                size_t got = 0;
                while (got < count) {
                    if ((uart_.Read(0x018ULL, 4) & (1u << 4)) != 0u) break; // RXFE
                    uint8_t b = static_cast<uint8_t>(uart_.Read(0x000ULL, 4) & 0xFFu);
                    if (!WriteUserBytes(cpu, buf + got, &b, 1)) return -14;
                    ++got;
                    if (b == '\n' || b == '\r') break;
                }
                if (got == 0 && count > 0) {
                    st.waiting_for_interrupt = true;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    return 0;
                }
                return static_cast<int64_t>(got);
            }
            if (it == fds.end() || it->second.is_dir) return -9;
            if (it->second.is_dev_null) return 0;
            if (it->second.is_dev_zero) {
                if (count > 0u) {
                    std::vector<uint8_t> zeros(std::min<size_t>(count, 1048576u), 0u);
                    if (!WriteUserBytes(cpu, buf, zeros.data(), zeros.size())) return -14;
                    return static_cast<int64_t>(zeros.size());
                }
                return 0;
            }
            if (it->second.is_dev_urandom) {
                std::vector<uint8_t> rnd(std::min<size_t>(count, 4096u));
                std::random_device rd;
                for (auto& b : rnd) b = static_cast<uint8_t>(rd());
                return WriteUserBytes(cpu, buf, rnd.data(), rnd.size())
                           ? static_cast<int64_t>(rnd.size()) : -14;
            }
            if (it->second.is_eventfd) {
                if (count < 8u) return -22;
                if (it->second.eventfd_counter == 0ULL) {
                    if (it->second.nonblock || !cur) return -11; // EAGAIN
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{fd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                uint64_t val = it->second.eventfd_counter;
                it->second.eventfd_counter = 0ULL;
                return WriteUserBytes(cpu, buf, &val, sizeof(val)) ? 8 : -14;
            }
            if (it->second.is_timerfd) {
                if (count < 8u) return -22;
                const int64_t now = NowSteadyNs();
                if (it->second.timerfd_next_expire_ns > 0 && now >= it->second.timerfd_next_expire_ns) {
                    if (it->second.timerfd_interval_ns > 0) {
                        const int64_t elapsed = now - it->second.timerfd_next_expire_ns;
                        const int64_t ticks = 1 + (elapsed / it->second.timerfd_interval_ns);
                        it->second.timerfd_expirations += static_cast<uint64_t>(ticks);
                        it->second.timerfd_next_expire_ns += ticks * it->second.timerfd_interval_ns;
                    } else {
                        ++it->second.timerfd_expirations;
                        it->second.timerfd_next_expire_ns = 0;
                    }
                }
                if (it->second.timerfd_expirations == 0ULL) {
                    if (it->second.nonblock || !cur) return -11; // EAGAIN
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{fd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                uint64_t val = it->second.timerfd_expirations;
                it->second.timerfd_expirations = 0ULL;
                return WriteUserBytes(cpu, buf, &val, sizeof(val)) ? 8 : -14;
            }
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.rx_chunks.empty()) {
                    if (sock.peer_closed || sock.shutdown_rd) return 0;
                    if (it->second.nonblock || !cur) return -11; // EAGAIN
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{fd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                auto& front = sock.rx_chunks.front();
                const size_t n = std::min(count, front.data.size());
                if (n > 0u && !WriteUserBytes(cpu, buf, front.data.data(), n)) return -14;
                if (sock.sock_type == 1 /* SOCK_STREAM */ && n < front.data.size()) {
                    front.data.erase(front.data.begin(), front.data.begin() + static_cast<std::ptrdiff_t>(n));
                } else {
                    sock.rx_chunks.pop_front();
                }
                return static_cast<int64_t>(n);
            }
            if (it->second.input_dev != nullptr) {
                constexpr size_t kEvSize = sizeof(VirtioInputDevice::LinuxInputEvent);
                const size_t max_events = count / kEvSize;
                if (max_events == 0u) return -22; // EINVAL
                std::vector<VirtioInputDevice::LinuxInputEvent> evs(max_events);
                const size_t got = it->second.input_dev->PopEvdevEvents(evs.data(), max_events);
                if (got == 0u) {
                    if (it->second.nonblock) return -11; // EAGAIN
                    st.waiting_for_interrupt = true;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    return 0;
                }
                const size_t bytes = got * kEvSize;
                if (!WriteUserBytes(cpu, buf, evs.data(), bytes)) return -14;
                return static_cast<int64_t>(bytes);
            }
            if (it->second.host_fd >= 0) {
                std::vector<uint8_t> hbuf(count);
                ssize_t r = ::read(it->second.host_fd, hbuf.data(), count);
                if (r < 0) {
                    const int err = errno;
                    if ((err == EAGAIN || err == EWOULDBLOCK) && !it->second.nonblock && cur) {
                        cur->state = TaskState::PollWait;
                        cur->poll_wait_epfd = -1;
                        cur->poll_wait_fds = {EpollWatch{fd, 0x001u, 0ULL}};
                        cur->poll_has_timeout = false;
                        st.sys.elr_el1 -= 4ULL;
                        out_retry = true;
                        out_yield = true;
                        return 0;
                    }
                    return -static_cast<int64_t>(err);
                }
                if (r > 0 && !WriteUserBytes(cpu, buf, hbuf.data(), static_cast<size_t>(r))) return -14;
                return static_cast<int64_t>(r);
            }
            if (it->second.is_sensors && hardware_ != nullptr) {
                const auto samples = hardware_->SampleAllSensors();
                const size_t bytes = samples.size() * sizeof(PhoneHardwareHub::SensorSample);
                const size_t n = std::min(count, bytes);
                return (n == 0u || WriteUserBytes(cpu, buf, samples.data(), n))
                           ? static_cast<int64_t>(n)
                           : -14;
            }
            if (it->second.is_camera && hardware_ != nullptr) {
                if (it->second.data.empty() || it->second.offset >= it->second.data.size()) {
                    uint64_t ts = 0;
                    uint32_t seq = 0;
                    it->second.data = hardware_->GenerateCameraFrame(ts, seq);
                    it->second.offset = 0u;
                }
                const size_t avail = it->second.data.size() - it->second.offset;
                const size_t n = std::min(count, avail);
                if (n > 0 && !WriteUserBytes(cpu, buf, it->second.data.data() + it->second.offset, n)) {
                    return -14;
                }
                it->second.offset += n;
                return static_cast<int64_t>(n);
            }
            if (it->second.is_snd_cap && snd_ != nullptr) {
                const size_t max_samples = count / sizeof(int16_t);
                if (max_samples == 0u) return -22;
                std::vector<int16_t> pcm(max_samples, 0);
                const size_t got = snd_->PopCapturePcm(pcm.data(), max_samples);
                if (got == 0u) return it->second.nonblock ? -11 : 0;
                const size_t bytes = got * sizeof(int16_t);
                return WriteUserBytes(cpu, buf, pcm.data(), bytes) ? static_cast<int64_t>(bytes) : -14;
            }
            size_t avail = (it->second.offset < it->second.data.size())
                               ? (it->second.data.size() - it->second.offset)
                               : 0u;
            size_t n = std::min(count, avail);
            if (n > 0 && !WriteUserBytes(cpu, buf, it->second.data.data() + it->second.offset, n)) {
                return -14;
            }
            it->second.offset += n;
            return static_cast<int64_t>(n);
        }
        case 64: { // write(fd, buf, count)
            int fd = static_cast<int>(st.x[0]);
            uint64_t buf = st.x[1];
            size_t count = static_cast<size_t>(st.x[2]);
            std::vector<uint8_t> tmp(count);
            if (count > 0 && !ReadUserBytes(cpu, buf, tmp.data(), count)) return -14;
            auto it = fds.find(fd);
            if (it == fds.end()) {
                if (fd == 1 || fd == 2) {
                    for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
                    return static_cast<int64_t>(count);
                }
                return -9;
            }
            if (it->second.is_stdio_out || it->second.is_tty) {
                for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
                return static_cast<int64_t>(count);
            }
            if (it->second.is_kmsg) {
                std::string s(reinterpret_cast<const char*>(tmp.data()), tmp.size());
                if (!s.empty()) LogToUart("[KMSG] " + s + (s.back() == '\n' ? "" : "\r\n"));
                return static_cast<int64_t>(count);
            }
            if (it->second.is_dev_null || it->second.is_dev_zero) {
                return static_cast<int64_t>(count);
            }
            if (it->second.is_eventfd) {
                if (count < 8u) return -22;
                uint64_t val = 0;
                std::memcpy(&val, tmp.data(), sizeof(val));
                it->second.eventfd_counter += val;
                WakePollWaiters();
                return 8;
            }
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.shutdown_wr) return -32; // EPIPE
                if (sock.peer_path == "/dev/socket/property_service") {
                    HandleBuiltInPropertyServicePacket(it->second.unix_sock, tmp);
                    return static_cast<int64_t>(count);
                }
                if (sock.peer_path == "/dev/socket/logdw" || sock.peer_path == "/dev/socket/logd") {
                    HandleBuiltInLogdPacket(tmp);
                    return static_cast<int64_t>(count);
                }
                auto peer = sock.peer.lock();
                if (!peer || sock.peer_closed) return -32; // EPIPE
                UnixSocketEndpoint::Chunk ch;
                ch.data = std::move(tmp);
                ch.peer_addr = sock.bound_path;
                peer->rx_chunks.push_back(std::move(ch));
                WakePollWaiters();
                return static_cast<int64_t>(count);
            }
            if (it->second.host_fd >= 0) {
                ssize_t w = ::write(it->second.host_fd, tmp.data(), count);
                if (w > 0) WakePollWaiters();
                return (w >= 0) ? static_cast<int64_t>(w) : -static_cast<int64_t>(errno);
            }
            if (it->second.is_memfd || it->second.is_ashmem || it->second.is_writable_mem) {
                if (IsProcAttrFilePath(it->second.path) && it->second.offset == 0u) {
                    it->second.data = tmp;
                } else {
                    const size_t end = it->second.offset + count;
                    if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                    if (count > 0u) std::memcpy(it->second.data.data() + it->second.offset, tmp.data(), count);
                }
                it->second.offset = it->second.offset + count;
                if (it->second.is_runtime_vfs) runtime_files_[it->second.path] = it->second.data;
                return static_cast<int64_t>(count);
            }
            if (it->second.is_snd_play && snd_ != nullptr) {
                const size_t samples = count / sizeof(int16_t);
                if (samples > 0u) {
                    snd_->PushPlaybackPcm(reinterpret_cast<const int16_t*>(tmp.data()), samples);
                }
                return static_cast<int64_t>(count);
            }
            if (it->second.is_gles && soft_gles_ != nullptr) {
                return soft_gles_->ExecuteCommandStream(tmp.data(), count, gpu_)
                           ? static_cast<int64_t>(count)
                           : -22;
            }
            return -9;
        }
        case 65: { // readv(fd, iov, iovcnt)
            int fd = static_cast<int>(st.x[0]);
            uint64_t iov_va = st.x[1];
            int iovcnt = std::min(static_cast<int>(st.x[2]), 1024);
            if (iovcnt < 0) return -22;
            auto it = fds.find(fd);
            if (fd < 0 || (it == fds.end() && fd != 0) || (it != fds.end() && it->second.is_dir)) return -9;
            if (it != fds.end() && it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.rx_chunks.empty()) {
                    if (sock.peer_closed || sock.shutdown_rd) return 0;
                    if (it->second.nonblock || !cur) return -11;
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{fd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                int64_t total = 0;
                for (int i = 0; i < iovcnt && !sock.rx_chunks.empty(); ++i) {
                    uint64_t vec[2]{};
                    if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                    const size_t len = static_cast<size_t>(vec[1]);
                    if (len == 0u) continue;
                    auto& front = sock.rx_chunks.front();
                    const size_t n = std::min(len, front.data.size());
                    if (n > 0u && !WriteUserBytes(cpu, vec[0], front.data.data(), n)) return -14;
                    total += static_cast<int64_t>(n);
                    if (sock.sock_type == 1 && n < front.data.size()) {
                        front.data.erase(front.data.begin(), front.data.begin() + static_cast<std::ptrdiff_t>(n));
                    } else {
                        sock.rx_chunks.pop_front();
                        if (sock.sock_type != 1) break;
                    }
                }
                return total;
            }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; ++i) {
                uint64_t vec[2]{};
                if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                const size_t len = static_cast<size_t>(vec[1]);
                if (len == 0u) continue;
                if (fd == 0 && it == fds.end()) {
                    size_t got = 0;
                    while (got < len) {
                        if ((uart_.Read(0x018ULL, 4) & (1u << 4)) != 0u) break;
                        uint8_t b = static_cast<uint8_t>(uart_.Read(0x000ULL, 4) & 0xFFu);
                        if (!WriteUserBytes(cpu, vec[0] + got, &b, 1)) return -14;
                        ++got;
                        if (b == '\n' || b == '\r') break;
                    }
                    total += static_cast<int64_t>(got);
                    if (got < len) break;
                } else if (it->second.is_dev_null) {
                    break;
                } else if (it->second.is_dev_zero) {
                    std::vector<uint8_t> zeros(std::min<size_t>(len, 1048576u), 0u);
                    if (!WriteUserBytes(cpu, vec[0], zeros.data(), zeros.size())) return -14;
                    total += static_cast<int64_t>(zeros.size());
                } else if (it->second.is_dev_urandom) {
                    std::vector<uint8_t> rnd(std::min<size_t>(len, 4096u));
                    std::random_device rd;
                    for (auto& b : rnd) b = static_cast<uint8_t>(rd());
                    if (!WriteUserBytes(cpu, vec[0], rnd.data(), rnd.size())) return -14;
                    total += static_cast<int64_t>(rnd.size());
                } else if (it->second.host_fd >= 0) {
                    std::vector<uint8_t> hbuf(len);
                    ssize_t r = ::read(it->second.host_fd, hbuf.data(), len);
                    if (r < 0) return total > 0 ? total : -static_cast<int64_t>(errno);
                    if (r > 0 && !WriteUserBytes(cpu, vec[0], hbuf.data(), static_cast<size_t>(r))) return -14;
                    total += static_cast<int64_t>(r);
                    if (static_cast<size_t>(r) < len) break;
                } else {
                    size_t avail = (it->second.offset < it->second.data.size())
                                       ? (it->second.data.size() - it->second.offset)
                                       : 0u;
                    size_t n = std::min(len, avail);
                    if (n > 0 && !WriteUserBytes(cpu, vec[0], it->second.data.data() + it->second.offset, n)) {
                        return -14;
                    }
                    it->second.offset += n;
                    total += static_cast<int64_t>(n);
                    if (n < len) break;
                }
            }
            return total;
        }
        case 66: { // writev(fd, iov, iovcnt)
            int fd = static_cast<int>(st.x[0]);
            uint64_t iov_va = st.x[1];
            int iovcnt = std::min(static_cast<int>(st.x[2]), 1024);
            if (iovcnt < 0) return -22;
            auto it = fds.find(fd);
            if (fd < 0 || (it == fds.end() && fd != 1 && fd != 2)) return -9;
            if (it != fds.end() && it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.shutdown_wr) return -32;
                std::vector<uint8_t> combined;
                for (int i = 0; i < iovcnt; ++i) {
                    uint64_t vec[2]{};
                    if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                    if (vec[1] > 0) {
                        const size_t old_sz = combined.size();
                        combined.resize(old_sz + static_cast<size_t>(vec[1]));
                        if (!ReadUserBytes(cpu, vec[0], combined.data() + old_sz, static_cast<size_t>(vec[1]))) {
                            return -14;
                        }
                    }
                }
                const int64_t total = static_cast<int64_t>(combined.size());
                if (sock.peer_path == "/dev/socket/property_service") {
                    HandleBuiltInPropertyServicePacket(it->second.unix_sock, combined);
                    return total;
                }
                if (sock.peer_path == "/dev/socket/logdw" || sock.peer_path == "/dev/socket/logd") {
                    HandleBuiltInLogdPacket(combined);
                    return total;
                }
                auto peer = sock.peer.lock();
                if (!peer || sock.peer_closed) return -32;
                UnixSocketEndpoint::Chunk ch;
                ch.data = std::move(combined);
                ch.peer_addr = sock.bound_path;
                peer->rx_chunks.push_back(std::move(ch));
                WakePollWaiters();
                return total;
            }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; ++i) {
                uint64_t vec[2]{};
                if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                if (vec[1] > 0) {
                    std::vector<uint8_t> tmp(static_cast<size_t>(vec[1]));
                    if (!ReadUserBytes(cpu, vec[0], tmp.data(), tmp.size())) return -14;
                    if (it == fds.end() || it->second.is_stdio_out || it->second.is_tty) {
                        for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
                        total += static_cast<int64_t>(vec[1]);
                    } else if (it->second.is_kmsg) {
                        std::string s(reinterpret_cast<const char*>(tmp.data()), tmp.size());
                        if (!s.empty()) LogToUart("[KMSG] " + s + (s.back() == '\n' ? "" : "\r\n"));
                        total += static_cast<int64_t>(vec[1]);
                    } else if (it->second.is_dev_null || it->second.is_dev_zero) {
                        total += static_cast<int64_t>(vec[1]);
                    } else if (it->second.host_fd >= 0) {
                        ssize_t w = ::write(it->second.host_fd, tmp.data(), tmp.size());
                        if (w < 0) return total > 0 ? total : -static_cast<int64_t>(errno);
                        if (w > 0) WakePollWaiters();
                        total += static_cast<int64_t>(w);
                    } else if (it->second.is_memfd || it->second.is_ashmem || it->second.is_writable_mem) {
                        const size_t end = it->second.offset + tmp.size();
                        if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                        std::memcpy(it->second.data.data() + it->second.offset, tmp.data(), tmp.size());
                        it->second.offset = end;
                        if (it->second.is_runtime_vfs) runtime_files_[it->second.path] = it->second.data;
                        total += static_cast<int64_t>(tmp.size());
                    } else {
                        return -9;
                    }
                }
            }
            return total;
        }
        case 67: { // pread64(fd, buf, count, offset)
            int fd = static_cast<int>(st.x[0]);
            uint64_t buf = st.x[1];
            size_t count = static_cast<size_t>(st.x[2]);
            int64_t off = static_cast<int64_t>(st.x[3]);
            if (off < 0) return -22;
            auto it = fds.find(fd);
            if (it == fds.end() || it->second.is_dir) return -9;
            if (it->second.host_fd >= 0) {
                std::vector<uint8_t> hbuf(count);
                ssize_t r = ::pread(it->second.host_fd, hbuf.data(), count, static_cast<off_t>(off));
                if (r < 0) return -static_cast<int64_t>(errno);
                if (r > 0 && !WriteUserBytes(cpu, buf, hbuf.data(), static_cast<size_t>(r))) return -14;
                return static_cast<int64_t>(r);
            }
            const size_t start = static_cast<size_t>(off);
            const size_t avail = (start < it->second.data.size()) ? (it->second.data.size() - start) : 0u;
            const size_t n = std::min(count, avail);
            if (n > 0 && !WriteUserBytes(cpu, buf, it->second.data.data() + start, n)) return -14;
            return static_cast<int64_t>(n);
        }
        case 68: { // pwrite64(fd, buf, count, offset)
            int fd = static_cast<int>(st.x[0]);
            uint64_t buf = st.x[1];
            size_t count = static_cast<size_t>(st.x[2]);
            int64_t off = static_cast<int64_t>(st.x[3]);
            if (off < 0) return -22;
            auto it = fds.find(fd);
            if (it == fds.end() || it->second.is_dir) return -9;
            std::vector<uint8_t> tmp(count);
            if (count > 0 && !ReadUserBytes(cpu, buf, tmp.data(), count)) return -14;
            if (it->second.host_fd >= 0) {
                ssize_t w = ::pwrite(it->second.host_fd, tmp.data(), count, static_cast<off_t>(off));
                return (w >= 0) ? static_cast<int64_t>(w) : -static_cast<int64_t>(errno);
            }
            if (it->second.is_memfd || it->second.is_writable_mem) {
                const size_t end = static_cast<size_t>(off) + count;
                if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                if (count > 0) std::memcpy(it->second.data.data() + static_cast<size_t>(off), tmp.data(), count);
                if (it->second.is_runtime_vfs) runtime_files_[it->second.path] = it->second.data;
                return static_cast<int64_t>(count);
            }
            return -9;
        }
        case 72: { // pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
            const int nfds = std::clamp(static_cast<int>(static_cast<int32_t>(st.x[0])), 0, 1024);
            const uint64_t rfds_va = st.x[1];
            const uint64_t wfds_va = st.x[2];
            const uint64_t efds_va = st.x[3];
            const uint64_t tmo_va = st.x[4];
            bool zero_timeout = false;
            int64_t dur_ns = -1;
            if (tmo_va != 0ULL) {
                int64_t ts[2]{};
                if (!ReadUserBytes(cpu, tmo_va, ts, sizeof(ts))) return -14;
                dur_ns = ts[0] * 1000000000LL + ts[1];
                if (dur_ns < 0) return -22;
                zero_timeout = (dur_ns == 0);
            }
            const size_t mask_bytes = static_cast<size_t>((nfds + 63) / 64) * 8u;
            std::vector<uint64_t> rm(mask_bytes / 8u, 0ULL), wm(mask_bytes / 8u, 0ULL), em(mask_bytes / 8u, 0ULL);
            if (mask_bytes > 0u) {
                if (rfds_va && !ReadUserBytes(cpu, rfds_va, rm.data(), mask_bytes)) return -14;
                if (wfds_va && !ReadUserBytes(cpu, wfds_va, wm.data(), mask_bytes)) return -14;
                if (efds_va && !ReadUserBytes(cpu, efds_va, em.data(), mask_bytes)) return -14;
            }
            std::vector<uint64_t> out_r(rm.size(), 0ULL), out_w(wm.size(), 0ULL), out_e(em.size(), 0ULL);
            std::vector<EpollWatch> watches;
            int ready = 0;
            for (int fd = 0; fd < nfds; ++fd) {
                const size_t word = static_cast<size_t>(fd) / 64u;
                const uint64_t bit = 1ULL << (static_cast<unsigned>(fd) % 64u);
                const bool want_r = rfds_va && (rm[word] & bit) != 0ULL;
                const bool want_w = wfds_va && (wm[word] & bit) != 0ULL;
                const bool want_e = efds_va && (em[word] & bit) != 0ULL;
                if (!want_r && !want_w && !want_e) continue;
                const uint32_t rev = ComputeGuestFdPollEvents(fds, fd);
                if ((rev & 0x020u) != 0u) return -9; // EBADF
                if (want_r && (rev & (0x001u | 0x010u)) != 0u) { out_r[word] |= bit; ++ready; }
                if (want_w && (rev & 0x004u) != 0u)            { out_w[word] |= bit; ++ready; }
                if (want_e && (rev & 0x008u) != 0u)            { out_e[word] |= bit; ++ready; }
                uint32_t wmask = 0u;
                if (want_r) wmask |= 0x001u;
                if (want_w) wmask |= 0x004u;
                if (want_e) wmask |= 0x008u;
                watches.push_back(EpollWatch{fd, wmask, 0ULL});
            }
            if (ready == 0 && !zero_timeout && cur != nullptr && (!watches.empty() || dur_ns > 0)) {
                if (watches.empty()) {
                    cur->state = TaskState::Sleeping;
                    cur->wakeup_ns = NowSteadyNs() + std::min<int64_t>(dur_ns, 5000000000LL);
                    out_yield = true;
                    return 0;
                }
                cur->state = TaskState::PollWait;
                cur->poll_wait_epfd = -1;
                cur->poll_wait_fds = std::move(watches);
                cur->poll_has_timeout = (dur_ns > 0);
                cur->poll_deadline_ns = (dur_ns > 0) ? (NowSteadyNs() + dur_ns) : 0;
                st.sys.elr_el1 -= 4ULL;
                out_retry = true;
                out_yield = true;
                return 0;
            }
            if (mask_bytes > 0u) {
                if (rfds_va && !WriteUserBytes(cpu, rfds_va, out_r.data(), mask_bytes)) return -14;
                if (wfds_va && !WriteUserBytes(cpu, wfds_va, out_w.data(), mask_bytes)) return -14;
                if (efds_va && !WriteUserBytes(cpu, efds_va, out_e.data(), mask_bytes)) return -14;
            }
            return ready;
        }
        case 73: { // ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, sigmask)
            struct LinuxPollFd {
                int32_t fd;
                int16_t events;
                int16_t revents;
            };
            const uint64_t fds_va = st.x[0];
            const size_t nfds = std::min<size_t>(static_cast<size_t>(st.x[1]), 128u);
            const uint64_t tmo_va = st.x[2];
            bool zero_timeout = false;
            int64_t dur_ns = -1;
            if (tmo_va != 0ULL) {
                int64_t ts[2]{};
                if (!ReadUserBytes(cpu, tmo_va, ts, sizeof(ts))) return -14;
                dur_ns = ts[0] * 1000000000LL + ts[1];
                if (dur_ns < 0) return -22;
                zero_timeout = (dur_ns == 0);
            }
            std::vector<LinuxPollFd> pfds(nfds);
            if (nfds > 0u && !ReadUserBytes(cpu, fds_va, pfds.data(), nfds * sizeof(LinuxPollFd))) {
                return -14;
            }
            int ready = 0;
            std::vector<EpollWatch> watches;
            for (auto& p : pfds) {
                p.revents = 0;
                if (p.fd < 0) continue;
                const uint32_t rev = ComputeGuestFdPollEvents(fds, p.fd);
                if ((rev & 0x020u /* POLLNVAL */) != 0u) {
                    p.revents = 0x20;
                    ++ready;
                    continue;
                }
                const uint32_t want = static_cast<uint32_t>(static_cast<uint16_t>(p.events));
                const uint32_t hit = rev & (want | 0x008u | 0x010u); // POLLERR|POLLHUP
                p.revents = static_cast<int16_t>(hit);
                if (hit != 0u) ++ready;
                watches.push_back(EpollWatch{p.fd, want, 0ULL});
            }
            if (ready == 0 && !zero_timeout && cur != nullptr && (!watches.empty() || dur_ns > 0)) {
                if (watches.empty()) {
                    cur->state = TaskState::Sleeping;
                    cur->wakeup_ns = NowSteadyNs() + std::min<int64_t>(dur_ns, 5000000000LL);
                    out_yield = true;
                    return 0;
                }
                cur->state = TaskState::PollWait;
                cur->poll_wait_epfd = -1;
                cur->poll_wait_fds = std::move(watches);
                cur->poll_has_timeout = (dur_ns > 0);
                cur->poll_deadline_ns = (dur_ns > 0) ? (NowSteadyNs() + dur_ns) : 0;
                st.sys.elr_el1 -= 4ULL;
                out_retry = true;
                out_yield = true;
                return 0;
            }
            if (nfds > 0u && !WriteUserBytes(cpu, fds_va, pfds.data(), nfds * sizeof(LinuxPollFd))) {
                return -14;
            }
            return ready;
        }
        case 78: { // readlinkat(dirfd, pathname, buf, bufsiz)
            std::string path, norm, target;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            if (out_note) *out_note = norm;
            if (ResolveSymlinkTarget(fds, norm, target)) {
                const size_t n = std::min(target.size(), static_cast<size_t>(st.x[3]));
                if (n > 0u && !WriteUserBytes(cpu, st.x[2], target.data(), n)) return -14;
                return static_cast<int64_t>(n);
            }
            std::vector<uint8_t> data;
            bool is_dir = false;
            std::vector<std::string> ch;
            return ResolveVfsFile(norm, data, is_dir, ch, nullptr, &fds) ? -22 : -2;
        }
        case 79: // newfstatat(dirfd, pathname, statbuf, flags)
        case 80: { // fstat(fd, statbuf)
            uint64_t stat_va = (nr == 79) ? st.x[2] : st.x[1];
            GuestStatMeta meta{};
            if (nr == 79) {
                std::string path;
                if (!ReadUserString(cpu, st.x[1], path)) return -14;
                const int64_t rc = StatGuestPath(
                    fds, static_cast<int>(st.x[0]), path, st.x[3], out_note, meta);
                if (rc < 0) return rc;
            } else {
                const int64_t rc = StatFd(fds, static_cast<int>(st.x[0]), meta);
                if (rc < 0) return rc;
            }
            struct LinuxStatAArch64 {
                uint64_t st_dev;
                uint64_t st_ino;
                uint32_t st_mode;
                uint32_t st_nlink;
                uint32_t st_uid;
                uint32_t st_gid;
                uint64_t st_rdev;
                uint64_t pad1;
                int64_t  st_size;
                int32_t  st_blksize;
                int32_t  pad2;
                int64_t  st_blocks;
                uint64_t sec_pad[6];
            } ks{};
            ks.st_dev = meta.st_dev;
            ks.st_ino = meta.st_ino;
            ks.st_mode = meta.st_mode;
            ks.st_nlink = 1;
            ks.st_uid = uid_;
            ks.st_gid = gid_;
            ks.st_rdev = meta.st_rdev;
            ks.st_size = static_cast<int64_t>(meta.st_size);
            ks.st_blksize = 4096;
            ks.st_blocks = static_cast<int64_t>((meta.st_size + 511u) / 512u);
            return WriteUserBytes(cpu, stat_va, &ks, sizeof(ks)) ? 0 : -14;
        }
        case 291: { // statx(dirfd, pathname, flags, mask, statxbuf)
            std::string path;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            GuestStatMeta meta{};
            const int64_t rc = StatGuestPath(
                fds, static_cast<int>(st.x[0]), path, st.x[2], out_note, meta);
            if (rc < 0) return rc;
            uint8_t buf[256]{};
            const uint32_t mask = 0x000007FFu; // STATX_BASIC_STATS
            const uint32_t blksize = 4096u;
            const uint32_t nlink = 1u;
            const uint16_t mode = static_cast<uint16_t>(meta.st_mode & 0xFFFFu);
            const uint64_t blocks = (meta.st_size + 511u) / 512u;
            const uint32_t rdev_major = static_cast<uint32_t>((meta.st_rdev >> 8) & 0xFFFu);
            const uint32_t rdev_minor = static_cast<uint32_t>(meta.st_rdev & 0xFFu);
            const uint32_t dev_major = 0u;
            const uint32_t dev_minor = static_cast<uint32_t>(meta.st_dev & 0xFFu);
            std::memcpy(buf + 0u, &mask, 4u);
            std::memcpy(buf + 4u, &blksize, 4u);
            std::memcpy(buf + 16u, &nlink, 4u);
            std::memcpy(buf + 20u, &uid_, 4u);
            std::memcpy(buf + 24u, &gid_, 4u);
            std::memcpy(buf + 28u, &mode, 2u);
            std::memcpy(buf + 32u, &meta.st_ino, 8u);
            std::memcpy(buf + 40u, &meta.st_size, 8u);
            std::memcpy(buf + 48u, &blocks, 8u);
            std::memcpy(buf + 128u, &rdev_major, 4u);
            std::memcpy(buf + 132u, &rdev_minor, 4u);
            std::memcpy(buf + 136u, &dev_major, 4u);
            std::memcpy(buf + 140u, &dev_minor, 4u);
            return WriteUserBytes(cpu, st.x[4], buf, sizeof(buf)) ? 0 : -14;
        }
        case 82: // fsync
        case 83: { // fdatasync
            int fd = static_cast<int>(st.x[0]);
            auto it = fds.find(fd);
            if (it != fds.end() && it->second.is_framebuffer) {
                return FlushFramebufferToGpu() ? 0 : -5;
            }
            if (it != fds.end() && it->second.host_fd >= 0) {
                return (::fsync(it->second.host_fd) == 0) ? 0 : -static_cast<int64_t>(errno);
            }
            return 0;
        }
        case 90: { // capget(hdrp, datap)
            if (st.x[0] != 0ULL) {
                uint32_t hdr[2]{};
                if (!ReadUserBytes(cpu, st.x[0], hdr, sizeof(hdr))) return -14;
                if (hdr[0] != 0x20080522u && hdr[0] != 0x20071026u && hdr[0] != 0x19980330u) {
                    hdr[0] = 0x20080522u;
                    WriteUserBytes(cpu, st.x[0], hdr, sizeof(hdr));
                    return (st.x[1] == 0ULL) ? 0 : -22;
                }
            }
            if (st.x[1] != 0ULL) {
                uint32_t cap_data[6]{};
                if (uid_ == 0u) {
                    cap_data[0] = 0xFFFFFFFFu; cap_data[1] = 0xFFFFFFFFu; cap_data[2] = 0u;
                    cap_data[3] = 0x000001FFu; cap_data[4] = 0x000001FFu; cap_data[5] = 0u;
                }
                if (!WriteUserBytes(cpu, st.x[1], cap_data, sizeof(cap_data))) return -14;
            }
            return 0;
        }
        case 91: // capset
        case 92: // personality
            return 0;
        case 93:   // exit
        case 94: { // exit_group
            const int status = static_cast<int>(st.x[0]);
            if (tasks_.size() <= 1u || cur == nullptr) {
                exit_status_ = status;
                exited_ = true;
                out_halt = true;
                return 0;
            }
            const int32_t cur_tgid = cur->tgid;
            const int32_t cur_ppid = cur->ppid;
            auto clear_and_wake_tid = [&](GuestTask& task) {
                if (task.clear_child_tid != 0ULL) {
                    uint32_t zero = 0u;
                    WriteUserBytes(cpu, task.clear_child_tid, &zero, sizeof(zero));
                    const auto tr = cpu.Mmu().Translate(st, task.clear_child_tid, MemAccessType::Read, false);
                    if (tr.ok) {
                        WakeFutexWaiters(tr.phys_addr, 1, 0xFFFFFFFFu);
                    }
                }
            };

            if (nr == 94) { // exit_group kills all threads sharing tgid
                for (auto& t : tasks_) {
                    if (!t || t->state == TaskState::Zombie || t->tgid != cur_tgid) continue;
                    clear_and_wake_tid(*t);
                    CloseTaskOpenFds(*t);
                    t->state = TaskState::Zombie;
                    t->exit_status = status;
                }
            } else { // exit terminates calling thread only
                clear_and_wake_tid(*cur);
                CloseTaskOpenFds(*cur);
                cur->state = TaskState::Zombie;
                cur->exit_status = status;
            }

            bool group_still_alive = false;
            for (const auto& t : tasks_) {
                if (t && t->tgid == cur_tgid && t->state != TaskState::Zombie) {
                    group_still_alive = true;
                    break;
                }
            }
            if (!group_still_alive) {
                for (auto& t : tasks_) {
                    if (t && t->tgid == cur_ppid && t->state == TaskState::WaitingChild &&
                        (t->wait_target_pid == -1 || t->wait_target_pid == 0 ||
                         t->wait_target_pid == cur_tgid)) {
                        t->state = TaskState::Runnable;
                    }
                }
            }
            if ((cur_tgid == 1 && !group_still_alive) || ActiveTaskCount() == 0u) {
                exit_status_ = status;
                exited_ = true;
                out_halt = true;
                return 0;
            }
            out_yield = true;
            return 0;
        }
        case 95: { // waitid(idtype, id, infop, options, rusage)
            if (!cur) return -10;
            const int32_t caller_tgid = cur->tgid;
            const int32_t idtype = static_cast<int32_t>(static_cast<int64_t>(st.x[0]));
            const int32_t target = (idtype == 1 /* P_PID */) ? static_cast<int32_t>(static_cast<int64_t>(st.x[1])) : -1;
            const uint64_t infop_uva = st.x[2];
            const uint64_t options = st.x[3];

            bool has_matching_child = false;
            int32_t reap_tgid = -1;
            int reap_status = 0;
            for (const auto& up : tasks_) {
                const GuestTask* t = up.get();
                if (!t || t->ppid != caller_tgid) continue;
                if (idtype == 1 && t->tgid != target) continue;
                has_matching_child = true;
                bool group_all_zombie = true;
                for (const auto& gp : tasks_) {
                    if (gp && gp->tgid == t->tgid && gp->state != TaskState::Zombie) {
                        group_all_zombie = false;
                        break;
                    }
                }
                if (group_all_zombie) {
                    reap_tgid = t->tgid;
                    reap_status = t->exit_status;
                    break;
                }
            }
            if (reap_tgid > 0) {
                if (infop_uva != 0ULL) {
                    uint8_t si[128]{};
                    const int32_t signo = 17; // SIGCHLD
                    const int32_t code = 1;   // CLD_EXITED
                    std::memcpy(si + 0u, &signo, 4u);
                    std::memcpy(si + 8u, &code, 4u);
                    std::memcpy(si + 16u, &reap_tgid, 4u);
                    std::memcpy(si + 24u, &reap_status, 4u);
                    if (!WriteUserBytes(cpu, infop_uva, si, sizeof(si))) return -14;
                }
                if ((options & 0x01000000ULL /* WNOWAIT */) == 0ULL) {
                    const GuestTask* cur_ptr = CurrentTask();
                    for (size_t i = 0; i < tasks_.size(); ) {
                        if (tasks_[i] && tasks_[i]->tgid == reap_tgid) {
                            tasks_.erase(tasks_.begin() + static_cast<std::ptrdiff_t>(i));
                        } else {
                            ++i;
                        }
                    }
                    current_task_idx_ = 0;
                    for (size_t i = 0; i < tasks_.size(); ++i) {
                        if (tasks_[i].get() == cur_ptr) {
                            current_task_idx_ = i;
                            break;
                        }
                    }
                }
                return 0;
            }
            if (!has_matching_child) return -10; // ECHILD
            if ((options & 1ULL /* WNOHANG */) != 0ULL) {
                if (infop_uva != 0ULL) {
                    uint8_t zeros[128]{};
                    if (!WriteUserBytes(cpu, infop_uva, zeros, sizeof(zeros))) return -14;
                }
                return 0;
            }
            cur->state = TaskState::WaitingChild;
            cur->wait_target_pid = target;
            cur->wait_status_uva = 0ULL;
            st.sys.elr_el1 -= 4ULL;
            out_retry = true;
            out_yield = true;
            return 0;
        }
        case 96: { // set_tid_address(tidptr)
            if (cur) cur->clear_child_tid = st.x[0];
            return cur ? cur->pid : 1;
        }
        case 98: { // futex(uaddr, futex_op, val, timeout, uaddr2, val3)
            const uint32_t raw_op = static_cast<uint32_t>(st.x[1]);
            const uint32_t op = raw_op & 0x7Fu;
            const auto tr1 = cpu.Mmu().Translate(st, st.x[0], MemAccessType::Read, false);
            if (!tr1.ok) return -14; // EFAULT
            const uint64_t pa1 = tr1.phys_addr;

            if (op == 0u || op == 9u) { // FUTEX_WAIT / FUTEX_WAIT_BITSET
                const uint32_t bitset = (op == 9u) ? static_cast<uint32_t>(st.x[5]) : 0xFFFFFFFFu;
                if (bitset == 0u) return -22; // EINVAL
                uint32_t cur_val = 0u;
                if (!ReadUserBytes(cpu, st.x[0], &cur_val, sizeof(cur_val))) return -14;
                if (cur_val != static_cast<uint32_t>(st.x[2])) return -11; // EAGAIN
                bool has_tmo = false;
                int64_t deadline_ns = 0;
                if (st.x[3] != 0ULL) {
                    int64_t ts[2]{};
                    if (!ReadUserBytes(cpu, st.x[3], ts, sizeof(ts))) return -14;
                    if (ts[0] < 0 || ts[1] < 0 || ts[1] >= 1000000000LL) return -22;
                    const int64_t tns = ts[0] * 1000000000LL + ts[1];
                    has_tmo = true;
                    if (op == 9u) { // FUTEX_WAIT_BITSET uses absolute deadline
                        if ((raw_op & 256u /* FUTEX_CLOCK_REALTIME */) != 0u) {
                            const int64_t real_now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
                            deadline_ns = NowSteadyNs() + (tns - real_now);
                        } else {
                            deadline_ns = tns;
                        }
                    } else { // FUTEX_WAIT uses relative duration
                        deadline_ns = NowSteadyNs() + tns;
                    }
                    if (deadline_ns <= NowSteadyNs()) return -110; // ETIMEDOUT
                }
                if (cur) {
                    cur->state = TaskState::FutexWait;
                    cur->futex_pa = pa1;
                    cur->futex_bitset = bitset;
                    cur->futex_has_timeout = has_tmo;
                    cur->futex_deadline_ns = deadline_ns;
                }
                out_yield = true;
                return 0;
            }
            if (op == 1u || op == 10u) { // FUTEX_WAKE / FUTEX_WAKE_BITSET
                const uint32_t bitset = (op == 10u) ? static_cast<uint32_t>(st.x[5]) : 0xFFFFFFFFu;
                if (bitset == 0u) return -22;
                const int max_wake = std::max(0, static_cast<int>(static_cast<int32_t>(st.x[2])));
                return WakeFutexWaiters(pa1, max_wake, bitset);
            }
            if (op == 3u || op == 4u) { // FUTEX_REQUEUE / FUTEX_CMP_REQUEUE
                if (op == 4u) {
                    uint32_t cur_val = 0u;
                    if (!ReadUserBytes(cpu, st.x[0], &cur_val, sizeof(cur_val))) return -14;
                    if (cur_val != static_cast<uint32_t>(st.x[5])) return -11; // EAGAIN
                }
                const auto tr2 = cpu.Mmu().Translate(st, st.x[4], MemAccessType::Read, false);
                if (!tr2.ok) return -14;
                const int max_wake = std::max(0, static_cast<int>(static_cast<int32_t>(st.x[2])));
                const int max_requeue = std::max(0, static_cast<int>(static_cast<int32_t>(st.x[3])));
                int woken = WakeFutexWaiters(pa1, max_wake, 0xFFFFFFFFu);
                int requeued = 0;
                if (max_requeue > 0) {
                    for (auto& t : tasks_) {
                        if (!t || t->state != TaskState::FutexWait || t->futex_pa != pa1) continue;
                        t->futex_pa = tr2.phys_addr;
                        ++requeued;
                        if (requeued >= max_requeue) break;
                    }
                }
                return woken + requeued;
            }
            if (op == 5u) { // FUTEX_WAKE_OP
                const auto tr2 = cpu.Mmu().Translate(st, st.x[4], MemAccessType::Read, false);
                if (!tr2.ok) return -14;
                uint32_t oldval = 0u;
                if (!ReadUserBytes(cpu, st.x[4], &oldval, sizeof(oldval))) return -14;
                const uint32_t val3 = static_cast<uint32_t>(st.x[5]);
                const uint32_t op_type = (val3 >> 28) & 0xFu;
                const uint32_t cmp_type = (val3 >> 24) & 0xFu;
                const uint32_t oparg_raw = (val3 >> 12) & 0xFFFu;
                const uint32_t oparg = ((op_type & 8u) != 0u) ? (1u << (oparg_raw & 31u)) : oparg_raw;
                const uint32_t cmparg = val3 & 0xFFFu;
                uint32_t newval = oldval;
                switch (op_type & 7u) {
                    case 0u: newval = oparg; break;
                    case 1u: newval = oldval + oparg; break;
                    case 2u: newval = oldval | oparg; break;
                    case 3u: newval = oldval & ~oparg; break;
                    case 4u: newval = oldval ^ oparg; break;
                    default: break;
                }
                if (!WriteUserBytes(cpu, st.x[4], &newval, sizeof(newval))) return -14;
                const int max_wake1 = std::max(0, static_cast<int>(static_cast<int32_t>(st.x[2])));
                const int max_wake2 = std::max(0, static_cast<int>(static_cast<int32_t>(st.x[3])));
                int woken = WakeFutexWaiters(pa1, max_wake1, 0xFFFFFFFFu);
                bool cmp_ok = false;
                switch (cmp_type) {
                    case 0u: cmp_ok = (oldval == cmparg); break;
                    case 1u: cmp_ok = (oldval != cmparg); break;
                    case 2u: cmp_ok = (oldval < cmparg); break;
                    case 3u: cmp_ok = (oldval <= cmparg); break;
                    case 4u: cmp_ok = (oldval > cmparg); break;
                    case 5u: cmp_ok = (oldval >= cmparg); break;
                    default: break;
                }
                if (cmp_ok) woken += WakeFutexWaiters(tr2.phys_addr, max_wake2, 0xFFFFFFFFu);
                return woken;
            }
            return 0;
        }
        case 99: // set_robust_list
            return 0;
        case 101: // nanosleep(req, rem)
        case 115: { // clock_nanosleep(clockid, flags, req, rem)
            const uint64_t req_va = (nr == 101) ? st.x[0] : st.x[2];
            int64_t ts[2]{};
            if (!ReadUserBytes(cpu, req_va, ts, sizeof(ts))) return -14;
            int64_t dur_ns = ts[0] * 1000000000LL + ts[1];
            if (dur_ns < 0) return -22;
            if (dur_ns > 5000000000LL) dur_ns = 5000000000LL;
            if (cur && dur_ns > 0) {
                cur->state = TaskState::Sleeping;
                cur->wakeup_ns = NowSteadyNs() + dur_ns;
            }
            out_yield = true;
            return 0;
        }
        case 113: { // clock_gettime(clk_id, tp)
            const int64_t ns = (st.x[0] == 1ULL)
                ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch()).count()
                : std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t tp[2] = {ns / 1000000000LL, ns % 1000000000LL};
            return WriteUserBytes(cpu, st.x[1], tp, sizeof(tp)) ? 0 : -14;
        }
        case 114: { // clock_getres(clk_id, res)
            if (st.x[1] != 0ULL) {
                int64_t tp[2] = {0LL, 1LL};
                if (!WriteUserBytes(cpu, st.x[1], tp, sizeof(tp))) return -14;
            }
            return 0;
        }
        case 116: // syslog
            return 0;
        case 124: { // sched_yield
            out_yield = true;
            return 0;
        }
        case 125: // sched_get_priority_max
            return 99;
        case 126: // sched_get_priority_min
            return 1;
        case 129: // kill(pid, sig)
        case 130: // tkill(tid, sig)
        case 131: // tgkill(tgid, tid, sig)
        case 138: // rt_sigqueueinfo(tgid, sig, uinfo)
        case 240: { // rt_tgsigqueueinfo(tgid, tid, sig, uinfo)
            const uint64_t sig = (nr == 131 || nr == 240) ? st.x[2] : st.x[1];
            if (sig == 0ULL) return 0;
            if (sig == 6ULL || sig == 9ULL || sig == 11ULL) {
                const int32_t target_pid = static_cast<int32_t>(st.x[0]);
                const std::string smsg = "[SIGNAL] pid=" + std::to_string(target_pid) +
                                         " sig=" + std::to_string(sig) + "\r\n";
                LogToUart(smsg);
                if (tasks_.size() <= 1u || cur == nullptr || target_pid == cur->pid || target_pid == 1) {
                    exit_status_ = 128 + static_cast<int>(sig);
                    exited_ = true;
                    out_halt = true;
                }
            }
            return 0;
        }
        case 137: // rt_sigtimedwait(set, info, ts, sigsetsize)
            return -11; // EAGAIN
        case 132: { // sigaltstack(const stack_t* ss, stack_t* old_ss)
            struct LinuxSigAltStack {
                uint64_t ss_sp;
                int32_t ss_flags;
                int32_t pad;
                uint64_t ss_size;
            };
            static_assert(sizeof(LinuxSigAltStack) == 24, "AArch64 stack_t must be 24 bytes");

            uint64_t& cur_sp = cur ? cur->sigaltstack_sp : sigaltstack_sp_;
            int32_t& cur_flags = cur ? cur->sigaltstack_flags : sigaltstack_flags_;
            uint64_t& cur_size = cur ? cur->sigaltstack_size : sigaltstack_size_;

            LinuxSigAltStack old_ss{};
            old_ss.ss_sp = cur_sp;
            old_ss.ss_flags = cur_flags;
            old_ss.pad = 0;
            old_ss.ss_size = cur_size;

            if (st.x[0] != 0ULL) {
                LinuxSigAltStack new_ss{};
                if (!ReadUserBytes(cpu, st.x[0], &new_ss, sizeof(new_ss))) return -14;
                if ((static_cast<uint32_t>(new_ss.ss_flags) & ~0x80000002u) != 0u) {
                    return -22; // EINVAL
                }
                if ((new_ss.ss_flags & 2) != 0) { // SS_DISABLE
                    cur_sp = 0ULL;
                    cur_flags = 2;
                    cur_size = 0ULL;
                } else {
                    if (new_ss.ss_size < 2048ULL) return -12; // ENOMEM
                    cur_sp = new_ss.ss_sp;
                    cur_flags = new_ss.ss_flags & ~static_cast<int32_t>(0x80000000u);
                    cur_size = new_ss.ss_size;
                }
            }
            if (st.x[1] != 0ULL) {
                if (!WriteUserBytes(cpu, st.x[1], &old_ss, sizeof(old_ss))) return -14;
            }
            return 0;
        }
        case 134: // rt_sigaction
        case 135: // rt_sigprocmask
            return 0;
        case 160: { // uname(struct new_utsname* buf)
            struct LinuxUtsName {
                char sysname[65];
                char nodename[65];
                char release[65];
                char version[65];
                char machine[65];
                char domainname[65];
            } uts{};
            std::snprintf(uts.sysname, 65, "Linux");
            std::snprintf(uts.nodename, 65, "haseeb-android");
            std::snprintf(uts.release, 65, "5.10.209-haseeb");
            std::snprintf(uts.version, 65, "#1 SMP PREEMPT");
            std::snprintf(uts.machine, 65, "aarch64");
            std::snprintf(uts.domainname, 65, "localdomain");
            return WriteUserBytes(cpu, st.x[0], &uts, sizeof(uts)) ? 0 : -14;
        }
        case 163: { // getrlimit(resource, rlim)
            if (st.x[1] != 0ULL) {
                uint64_t lim[2] = {64ULL * 1024ULL * 1024ULL, 64ULL * 1024ULL * 1024ULL};
                if (!WriteUserBytes(cpu, st.x[1], lim, sizeof(lim))) return -14;
            }
            return 0;
        }
        case 164: // setrlimit
            return 0;
        case 166: // umask
            return 022;
        case 167: { // prctl(option, arg2, arg3, arg4, arg5)
            const uint64_t opt = st.x[0];
            if (opt == 3ULL /* PR_GET_DUMPABLE */) return 1;
            if (opt == 16ULL /* PR_GET_NAME */ && st.x[1] != 0ULL) {
                char comm[16]{};
                std::string base = active_binary_.empty() ? "init" : active_binary_;
                const size_t sl = base.find_last_of('/');
                if (sl != std::string::npos) base = base.substr(sl + 1u);
                std::snprintf(comm, sizeof(comm), "%s", base.c_str());
                return WriteUserBytes(cpu, st.x[1], comm, sizeof(comm)) ? 0 : -14;
            }
            if (opt == 23ULL /* PR_CAPBSET_READ */) {
                return (st.x[1] <= 40ULL) ? 1 : -22;
            }
            if (opt == 24ULL /* PR_CAPBSET_DROP */) {
                return (st.x[1] <= 40ULL) ? 0 : -22;
            }
            if (opt == 40ULL /* PR_GET_TID_ADDRESS */ && st.x[1] != 0ULL) {
                uint64_t tidptr = cur ? cur->clear_child_tid : 0ULL;
                return WriteUserBytes(cpu, st.x[1], &tidptr, sizeof(tidptr)) ? 0 : -14;
            }
            if (opt == 55ULL /* PR_SET_TAGGED_ADDR_CTRL */) {
                if (cur && cur->vm) cur->vm->tagged_addr_ctrl = (st.x[1] & 0x7ULL);
                return 0;
            }
            if (opt == 56ULL /* PR_GET_TAGGED_ADDR_CTRL */) {
                return (cur && cur->vm) ? static_cast<int64_t>(cur->vm->tagged_addr_ctrl) : 0;
            }
            return 0;
        }
        case 169: { // gettimeofday(tv, tz)
            const int64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
            if (st.x[0] != 0ULL) {
                int64_t tv[2] = {us / 1000000LL, us % 1000000LL};
                if (!WriteUserBytes(cpu, st.x[0], tv, sizeof(tv))) return -14;
            }
            if (st.x[1] != 0ULL) {
                int32_t tz[2] = {0, 0};
                if (!WriteUserBytes(cpu, st.x[1], tz, sizeof(tz))) return -14;
            }
            return 0;
        }
        case 172: // getpid
            return cur ? cur->tgid : 1;
        case 178: // gettid
            return cur ? cur->pid : 1;
        case 173: // getppid
            return cur ? cur->ppid : 0;
        case 174: // getuid
        case 175: // geteuid
            return static_cast<int64_t>(uid_);
        case 176: // getgid
        case 177: // getegid
            return static_cast<int64_t>(gid_);
        case 198: { // socket(domain, type, protocol)
            const int domain = static_cast<int>(st.x[0]);
            const int raw_type = static_cast<int>(st.x[1]);
            const int protocol = static_cast<int>(st.x[2]);
            const int base_type = raw_type & 0xF;
            const bool nb = (raw_type & 04000) != 0;
            const int clo = ((raw_type & 02000000) != 0) ? 1 : 0;

            if (domain == 1 /* AF_UNIX */) {
                auto ep = std::make_shared<UnixSocketEndpoint>();
                ep->domain = 1;
                ep->sock_type = (base_type == 0) ? 1 : base_type;
                const int sfd = next_fd++;
                OpenFile of;
                of.path = "socket:[unix#" + std::to_string(sfd) + "]";
                of.fd_flags = clo;
                of.nonblock = nb;
                of.unix_sock = std::move(ep);
                of.st_dev = 4ULL;
                of.st_ino = ComputeGuestInode(of.path);
                fds.emplace(sfd, std::move(of));
                return sfd;
            }
            if (domain == 2 /* AF_INET */ || domain == 10 /* AF_INET6 */) {
                const int host_dom = (domain == 10) ? AF_INET6 : AF_INET;
                const int htype = (base_type == 2) ? SOCK_DGRAM : SOCK_STREAM;
                int hfd = ::socket(host_dom, htype, protocol);
                if (hfd < 0) return -static_cast<int64_t>(errno);
                if (nb) {
                    const int fl = ::fcntl(hfd, F_GETFL, 0);
                    if (fl >= 0) ::fcntl(hfd, F_SETFL, fl | O_NONBLOCK);
                }
                ::fcntl(hfd, F_SETFD, FD_CLOEXEC);
                const int sfd = next_fd++;
                OpenFile of;
                of.path = "socket:[inet#" + std::to_string(sfd) + "]";
                of.host_fd = hfd;
                of.is_host_inet_sock = true;
                of.host_sock_domain = host_dom;
                of.host_sock_type = htype;
                of.fd_flags = clo;
                of.nonblock = nb;
                of.st_dev = 4ULL;
                of.st_ino = ComputeGuestInode(of.path);
                fds.emplace(sfd, std::move(of));
                return sfd;
            }
            if (domain == 16 /* AF_NETLINK */) {
                const int sfd = next_fd++;
                OpenFile of;
                of.path = "socket:[netlink#" + std::to_string(sfd) + "]";
                of.is_netlink = true;
                of.netlink_protocol = protocol;
                of.fd_flags = clo;
                of.nonblock = nb;
                of.st_dev = 4ULL;
                of.st_ino = ComputeGuestInode(of.path);
                fds.emplace(sfd, std::move(of));
                return sfd;
            }
            return -97; // EAFNOSUPPORT
        }
        case 199: { // socketpair(domain, type, protocol, sv[2])
            const int domain = static_cast<int>(st.x[0]);
            const int raw_type = static_cast<int>(st.x[1]);
            const int base_type = raw_type & 0xF;
            if (domain != 1 /* AF_UNIX */) return -97;
            const bool nb = (raw_type & 04000) != 0;
            const int clo = ((raw_type & 02000000) != 0) ? 1 : 0;

            auto ep0 = std::make_shared<UnixSocketEndpoint>();
            auto ep1 = std::make_shared<UnixSocketEndpoint>();
            ep0->domain = 1;
            ep1->domain = 1;
            ep0->sock_type = (base_type == 0) ? 1 : base_type;
            ep1->sock_type = ep0->sock_type;
            ep0->peer = ep1;
            ep1->peer = ep0;

            const int fd0 = next_fd++;
            const int fd1 = next_fd++;
            OpenFile f0, f1;
            f0.path = "socket:[pair#" + std::to_string(fd0) + "]";
            f0.unix_sock = ep0;
            f0.fd_flags = clo;
            f0.nonblock = nb;
            f0.st_dev = 4ULL;
            f0.st_ino = ComputeGuestInode(f0.path);
            f1.path = "socket:[pair#" + std::to_string(fd1) + "]";
            f1.unix_sock = ep1;
            f1.fd_flags = clo;
            f1.nonblock = nb;
            f1.st_dev = 4ULL;
            f1.st_ino = ComputeGuestInode(f1.path);
            fds.emplace(fd0, std::move(f0));
            fds.emplace(fd1, std::move(f1));
            int32_t out[2] = {fd0, fd1};
            if (!WriteUserBytes(cpu, st.x[3], out, sizeof(out))) return -14;
            return 0;
        }
        case 200: { // bind(fd, addr, addrlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const size_t alen = std::min<size_t>(static_cast<size_t>(st.x[2]), 256u);
            if (alen < 2u) return -22;
            std::vector<uint8_t> sa(alen);
            if (!ReadUserBytes(cpu, st.x[1], sa.data(), alen)) return -14;
            if (it->second.unix_sock) {
                std::string key;
                if (!ParseGuestUnixPath(sa.data(), alen, key)) return -22;
                auto existing = unix_bound_sockets_.find(key);
                if (existing != unix_bound_sockets_.end() && !existing->second.expired()) {
                    return -98; // EADDRINUSE
                }
                it->second.unix_sock->bound_path = key;
                unix_bound_sockets_[key] = it->second.unix_sock;
                return 0;
            }
            if (it->second.is_netlink) {
                if (alen >= 12u) {
                    uint32_t nl_pid = 0u, nl_groups = 0u;
                    std::memcpy(&nl_pid, sa.data() + 4u, 4u);
                    std::memcpy(&nl_groups, sa.data() + 8u, 4u);
                    it->second.netlink_pid = (nl_pid != 0u) ? nl_pid : static_cast<uint32_t>(cur ? cur->tgid : 1);
                    it->second.netlink_groups = nl_groups;
                }
                return 0;
            }
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                const int rc = ::bind(it->second.host_fd,
                                      reinterpret_cast<const struct sockaddr*>(sa.data()),
                                      static_cast<socklen_t>(alen));
                return (rc == 0) ? 0 : -static_cast<int64_t>(errno);
            }
            return -88; // ENOTSOCK
        }
        case 201: { // listen(fd, backlog)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const int backlog = std::max(1, static_cast<int>(st.x[1]));
            if (it->second.unix_sock) {
                it->second.unix_sock->listening = true;
                it->second.unix_sock->backlog = backlog;
                return 0;
            }
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                return (::listen(it->second.host_fd, backlog) == 0) ? 0 : -static_cast<int64_t>(errno);
            }
            return -88;
        }
        case 202:   // accept(fd, addr, addrlen)
        case 242: { // accept4(fd, addr, addrlen, flags)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const uint64_t aflags = (nr == 242) ? st.x[3] : 0ULL;
            const bool nb = (aflags & 04000ULL) != 0ULL;
            const int clo = ((aflags & 02000000ULL) != 0ULL) ? 1 : 0;

            if (it->second.unix_sock) {
                auto& lsock = *it->second.unix_sock;
                if (!lsock.listening) return -22;
                if (lsock.pending_accept.empty()) {
                    if (it->second.nonblock || !cur) return -11; // EAGAIN
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{sfd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                auto conn = lsock.pending_accept.front();
                lsock.pending_accept.pop_front();
                const int nfd = next_fd++;
                OpenFile nof;
                nof.path = "socket:[accepted#" + std::to_string(nfd) + "]";
                nof.unix_sock = conn;
                nof.fd_flags = clo;
                nof.nonblock = nb;
                nof.st_dev = 4ULL;
                nof.st_ino = ComputeGuestInode(nof.path);
                fds.emplace(nfd, std::move(nof));

                if (st.x[1] != 0ULL && st.x[2] != 0ULL) {
                    uint32_t ulen = 0u;
                    if (ReadUserBytes(cpu, st.x[2], &ulen, sizeof(ulen))) {
                        struct sockaddr_un un{};
                        un.sun_family = 1;
                        uint32_t actual = 2u;
                        if (!conn->peer_path.empty()) {
                            if (conn->peer_path.front() == '@') {
                                const size_t copy_n = std::min(conn->peer_path.size() - 1u, sizeof(un.sun_path) - 1u);
                                un.sun_path[0] = '\0';
                                std::memcpy(un.sun_path + 1, conn->peer_path.data() + 1u, copy_n);
                                actual = static_cast<uint32_t>(3u + copy_n);
                            } else {
                                const size_t copy_n = std::min(conn->peer_path.size(), sizeof(un.sun_path) - 1u);
                                std::memcpy(un.sun_path, conn->peer_path.data(), copy_n);
                                actual = static_cast<uint32_t>(2u + copy_n + 1u);
                            }
                        }
                        const size_t wr = std::min<size_t>(ulen, actual);
                        if (wr > 0u) WriteUserBytes(cpu, st.x[1], &un, wr);
                        WriteUserBytes(cpu, st.x[2], &actual, sizeof(actual));
                    }
                }
                return nfd;
            }
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                uint8_t sa[128]{};
                socklen_t slen = sizeof(sa);
                int hnew = ::accept(it->second.host_fd, reinterpret_cast<struct sockaddr*>(sa), &slen);
                if (hnew < 0) return -static_cast<int64_t>(errno);
                if (nb) {
                    const int fl = ::fcntl(hnew, F_GETFL, 0);
                    if (fl >= 0) ::fcntl(hnew, F_SETFL, fl | O_NONBLOCK);
                }
                ::fcntl(hnew, F_SETFD, FD_CLOEXEC);
                const int nfd = next_fd++;
                OpenFile nof;
                nof.path = "socket:[inet_acc#" + std::to_string(nfd) + "]";
                nof.host_fd = hnew;
                nof.is_host_inet_sock = true;
                nof.host_sock_domain = it->second.host_sock_domain;
                nof.host_sock_type = it->second.host_sock_type;
                nof.fd_flags = clo;
                nof.nonblock = nb;
                nof.st_dev = 4ULL;
                nof.st_ino = ComputeGuestInode(nof.path);
                fds.emplace(nfd, std::move(nof));
                if (st.x[1] != 0ULL && st.x[2] != 0ULL) {
                    uint32_t ulen = 0u;
                    if (ReadUserBytes(cpu, st.x[2], &ulen, sizeof(ulen))) {
                        const uint32_t actual = static_cast<uint32_t>(slen);
                        const size_t wr = std::min<size_t>(ulen, actual);
                        if (wr > 0u) WriteUserBytes(cpu, st.x[1], sa, wr);
                        WriteUserBytes(cpu, st.x[2], &actual, sizeof(actual));
                    }
                }
                return nfd;
            }
            return -88;
        }
        case 203: { // connect(fd, addr, addrlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const size_t alen = std::min<size_t>(static_cast<size_t>(st.x[2]), 256u);
            if (alen < 2u) return -22;
            std::vector<uint8_t> sa(alen);
            if (!ReadUserBytes(cpu, st.x[1], sa.data(), alen)) return -14;
            if (it->second.unix_sock) {
                std::string target;
                if (!ParseGuestUnixPath(sa.data(), alen, target)) return -22;
                if (target == "/dev/socket/property_service" ||
                    target == "/dev/socket/logdw" ||
                    target == "/dev/socket/logd") {
                    it->second.unix_sock->peer_path = target;
                    it->second.unix_sock->peer_closed = false;
                    return 0;
                }
                auto bit = unix_bound_sockets_.find(target);
                if (bit == unix_bound_sockets_.end()) return -111; // ECONNREFUSED
                auto target_ep = bit->second.lock();
                if (!target_ep) return -111;
                if (target_ep->listening) {
                    auto srv_ep = std::make_shared<UnixSocketEndpoint>();
                    srv_ep->domain = 1;
                    srv_ep->sock_type = it->second.unix_sock->sock_type;
                    srv_ep->bound_path = target;
                    srv_ep->peer_path = it->second.unix_sock->bound_path;
                    srv_ep->peer = it->second.unix_sock;
                    it->second.unix_sock->peer = srv_ep;
                    it->second.unix_sock->peer_path = target;
                    it->second.unix_sock->peer_closed = false;
                    target_ep->pending_accept.push_back(std::move(srv_ep));
                    WakePollWaiters();
                    return 0;
                }
                it->second.unix_sock->peer = target_ep;
                it->second.unix_sock->peer_path = target;
                it->second.unix_sock->peer_closed = false;
                return 0;
            }
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                const int rc = ::connect(it->second.host_fd,
                                         reinterpret_cast<const struct sockaddr*>(sa.data()),
                                         static_cast<socklen_t>(alen));
                if (rc == 0) return 0;
                it->second.so_error = errno;
                return -static_cast<int64_t>(errno);
            }
            return -88;
        }
        case 204:   // getsockname(fd, addr, addrlen)
        case 205: { // getpeername(fd, addr, addrlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            if (it->second.unix_sock) {
                const std::string& p = (nr == 204) ? it->second.unix_sock->bound_path
                                                   : it->second.unix_sock->peer_path;
                uint32_t ulen = 0u;
                if (!ReadUserBytes(cpu, st.x[2], &ulen, sizeof(ulen))) return -14;
                struct sockaddr_un un{};
                un.sun_family = 1;
                uint32_t actual = 2u;
                if (!p.empty()) {
                    if (p.front() == '@') {
                        const size_t copy_n = std::min(p.size() - 1u, sizeof(un.sun_path) - 1u);
                        un.sun_path[0] = '\0';
                        std::memcpy(un.sun_path + 1, p.data() + 1u, copy_n);
                        actual = static_cast<uint32_t>(3u + copy_n);
                    } else {
                        const size_t copy_n = std::min(p.size(), sizeof(un.sun_path) - 1u);
                        std::memcpy(un.sun_path, p.data(), copy_n);
                        actual = static_cast<uint32_t>(2u + copy_n + 1u);
                    }
                }
                const size_t wr = std::min<size_t>(ulen, actual);
                if (wr > 0u && !WriteUserBytes(cpu, st.x[1], &un, wr)) return -14;
                if (!WriteUserBytes(cpu, st.x[2], &actual, sizeof(actual))) return -14;
                return 0;
            }
            if (it->second.is_netlink) {
                uint32_t ulen = 0u;
                if (!ReadUserBytes(cpu, st.x[2], &ulen, sizeof(ulen))) return -14;
                struct { uint16_t nl_family; uint16_t nl_pad; uint32_t nl_pid; uint32_t nl_groups; } nl{};
                nl.nl_family = 16u;
                nl.nl_pid = it->second.netlink_pid ? it->second.netlink_pid
                                                   : static_cast<uint32_t>(cur ? cur->tgid : 1);
                nl.nl_groups = it->second.netlink_groups;
                const uint32_t actual = sizeof(nl);
                const size_t wr = std::min<size_t>(ulen, actual);
                if (wr > 0u && !WriteUserBytes(cpu, st.x[1], &nl, wr)) return -14;
                if (!WriteUserBytes(cpu, st.x[2], &actual, sizeof(actual))) return -14;
                return 0;
            }
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                uint32_t ulen = 0u;
                if (!ReadUserBytes(cpu, st.x[2], &ulen, sizeof(ulen))) return -14;
                uint8_t sa[128]{};
                socklen_t slen = sizeof(sa);
                const int rc = (nr == 204)
                    ? ::getsockname(it->second.host_fd, reinterpret_cast<struct sockaddr*>(sa), &slen)
                    : ::getpeername(it->second.host_fd, reinterpret_cast<struct sockaddr*>(sa), &slen);
                if (rc != 0) return -static_cast<int64_t>(errno);
                const uint32_t actual = static_cast<uint32_t>(slen);
                const size_t wr = std::min<size_t>(ulen, actual);
                if (wr > 0u && !WriteUserBytes(cpu, st.x[1], sa, wr)) return -14;
                if (!WriteUserBytes(cpu, st.x[2], &actual, sizeof(actual))) return -14;
                return 0;
            }
            return -88;
        }
        case 206: { // sendto(fd, buf, len, flags, dest_addr, addrlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const size_t len = static_cast<size_t>(st.x[2]);
            std::vector<uint8_t> tmp(len);
            if (len > 0u && !ReadUserBytes(cpu, st.x[1], tmp.data(), len)) return -14;

            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.shutdown_wr) return -32;
                std::string dest_key = sock.peer_path;
                if (st.x[4] != 0ULL && st.x[5] >= 2ULL) {
                    const size_t alen = std::min<size_t>(static_cast<size_t>(st.x[5]), 256u);
                    std::vector<uint8_t> sa(alen);
                    if (!ReadUserBytes(cpu, st.x[4], sa.data(), alen)) return -14;
                    ParseGuestUnixPath(sa.data(), alen, dest_key);
                }
                if (dest_key == "/dev/socket/property_service") {
                    HandleBuiltInPropertyServicePacket(it->second.unix_sock, tmp);
                    return static_cast<int64_t>(len);
                }
                if (dest_key == "/dev/socket/logdw" || dest_key == "/dev/socket/logd") {
                    HandleBuiltInLogdPacket(tmp);
                    return static_cast<int64_t>(len);
                }
                std::shared_ptr<UnixSocketEndpoint> target_ep = sock.peer.lock();
                if (!target_ep && !dest_key.empty()) {
                    auto bit = unix_bound_sockets_.find(dest_key);
                    if (bit != unix_bound_sockets_.end()) target_ep = bit->second.lock();
                }
                if (!target_ep || sock.peer_closed) return -107; // ENOTCONN / EPIPE
                UnixSocketEndpoint::Chunk ch;
                ch.data = std::move(tmp);
                ch.peer_addr = sock.bound_path;
                target_ep->rx_chunks.push_back(std::move(ch));
                WakePollWaiters();
                return static_cast<int64_t>(len);
            }
            if (it->second.is_netlink) {
                return static_cast<int64_t>(len);
            }
            if (it->second.host_fd >= 0) {
                std::vector<uint8_t> sa;
                socklen_t alen = 0;
                if (st.x[4] != 0ULL && st.x[5] > 0ULL) {
                    alen = static_cast<socklen_t>(std::min<uint64_t>(st.x[5], 256ULL));
                    sa.resize(alen);
                    if (!ReadUserBytes(cpu, st.x[4], sa.data(), alen)) return -14;
                }
                ssize_t w = ::sendto(it->second.host_fd, tmp.data(), len, static_cast<int>(st.x[3]),
                                     sa.empty() ? nullptr : reinterpret_cast<const struct sockaddr*>(sa.data()),
                                     alen);
                return (w >= 0) ? static_cast<int64_t>(w) : -static_cast<int64_t>(errno);
            }
            return -88;
        }
        case 207: { // recvfrom(fd, buf, len, flags, src_addr, addrlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const size_t len = static_cast<size_t>(st.x[2]);
            const int rflags = static_cast<int>(st.x[3]);
            const bool dontwait = it->second.nonblock || ((rflags & 0x40 /* MSG_DONTWAIT */) != 0);

            if (it->second.is_netlink) {
                return -11; // EAGAIN
            }
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.rx_chunks.empty()) {
                    if (sock.peer_closed || sock.shutdown_rd) return 0;
                    if (dontwait || !cur) return -11; // EAGAIN
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{sfd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                auto& front = sock.rx_chunks.front();
                const std::string sender_addr = front.peer_addr;
                const size_t n = std::min(len, front.data.size());
                if (n > 0u && !WriteUserBytes(cpu, st.x[1], front.data.data(), n)) return -14;
                if (st.x[4] != 0ULL && st.x[5] != 0ULL) {
                    uint32_t ulen = 0u;
                    if (ReadUserBytes(cpu, st.x[5], &ulen, sizeof(ulen))) {
                        struct sockaddr_un un{};
                        un.sun_family = 1;
                        uint32_t actual = 2u;
                        if (!sender_addr.empty()) {
                            if (sender_addr.front() == '@') {
                                const size_t copy_n = std::min(sender_addr.size() - 1u, sizeof(un.sun_path) - 1u);
                                un.sun_path[0] = '\0';
                                std::memcpy(un.sun_path + 1, sender_addr.data() + 1u, copy_n);
                                actual = static_cast<uint32_t>(3u + copy_n);
                            } else {
                                const size_t copy_n = std::min(sender_addr.size(), sizeof(un.sun_path) - 1u);
                                std::memcpy(un.sun_path, sender_addr.data(), copy_n);
                                actual = static_cast<uint32_t>(2u + copy_n + 1u);
                            }
                        }
                        const size_t wr = std::min<size_t>(ulen, actual);
                        if (wr > 0u) WriteUserBytes(cpu, st.x[4], &un, wr);
                        WriteUserBytes(cpu, st.x[5], &actual, sizeof(actual));
                    }
                }
                if (sock.sock_type == 1 && n < front.data.size()) {
                    front.data.erase(front.data.begin(), front.data.begin() + static_cast<std::ptrdiff_t>(n));
                } else {
                    sock.rx_chunks.pop_front();
                }
                return static_cast<int64_t>(n);
            }
            if (it->second.host_fd >= 0) {
                std::vector<uint8_t> hbuf(len);
                uint8_t sa[128]{};
                socklen_t alen = (st.x[4] != 0ULL && st.x[5] != 0ULL) ? sizeof(sa) : 0;
                ssize_t r = ::recvfrom(it->second.host_fd, hbuf.data(), len, rflags,
                                       alen ? reinterpret_cast<struct sockaddr*>(sa) : nullptr,
                                       alen ? &alen : nullptr);
                if (r < 0) return -static_cast<int64_t>(errno);
                if (r > 0 && !WriteUserBytes(cpu, st.x[1], hbuf.data(), static_cast<size_t>(r))) return -14;
                if (alen > 0 && st.x[4] != 0ULL && st.x[5] != 0ULL) {
                    uint32_t ulen = 0u;
                    if (ReadUserBytes(cpu, st.x[5], &ulen, sizeof(ulen))) {
                        const uint32_t actual = static_cast<uint32_t>(alen);
                        const size_t wr = std::min<size_t>(ulen, actual);
                        if (wr > 0u) WriteUserBytes(cpu, st.x[4], sa, wr);
                        WriteUserBytes(cpu, st.x[5], &actual, sizeof(actual));
                    }
                }
                return static_cast<int64_t>(r);
            }
            return -88;
        }
        case 208: { // setsockopt(fd, level, optname, optval, optlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                const socklen_t olen = static_cast<socklen_t>(std::min<uint64_t>(st.x[4], 256ULL));
                std::vector<uint8_t> val(olen);
                if (olen > 0 && !ReadUserBytes(cpu, st.x[3], val.data(), olen)) return -14;
                const int rc = ::setsockopt(it->second.host_fd, static_cast<int>(st.x[1]),
                                            static_cast<int>(st.x[2]), val.data(), olen);
                return (rc == 0) ? 0 : -static_cast<int64_t>(errno);
            }
            return 0;
        }
        case 209: { // getsockopt(fd, level, optname, optval, optlen)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const int level = static_cast<int>(st.x[1]);
            const int optname = static_cast<int>(st.x[2]);
            if (it->second.is_host_inet_sock && it->second.host_fd >= 0) {
                uint32_t ulen = 0u;
                if (!ReadUserBytes(cpu, st.x[4], &ulen, sizeof(ulen))) return -14;
                socklen_t hlen = static_cast<socklen_t>(std::min<uint32_t>(ulen, 256u));
                std::vector<uint8_t> val(std::max<socklen_t>(hlen, 4));
                const int rc = ::getsockopt(it->second.host_fd, level, optname, val.data(), &hlen);
                if (rc != 0) return -static_cast<int64_t>(errno);
                const uint32_t out_len = static_cast<uint32_t>(hlen);
                if (out_len > 0u && !WriteUserBytes(cpu, st.x[3], val.data(), std::min(out_len, ulen))) return -14;
                if (!WriteUserBytes(cpu, st.x[4], &out_len, sizeof(out_len))) return -14;
                return 0;
            }
            if (level == 1 /* SOL_SOCKET */) {
                uint32_t ulen = 0u;
                if (!ReadUserBytes(cpu, st.x[4], &ulen, sizeof(ulen))) return -14;
                if (optname == 17 /* SO_PEERCRED */ && ulen >= 12u) {
                    struct LinuxUcred { int32_t pid; uint32_t uid; uint32_t gid; } uc{
                        cur ? cur->tgid : 1, uid_, gid_};
                    const uint32_t sz = sizeof(uc);
                    if (!WriteUserBytes(cpu, st.x[3], &uc, sz)) return -14;
                    if (!WriteUserBytes(cpu, st.x[4], &sz, sizeof(sz))) return -14;
                    return 0;
                }
                if (optname == 4 /* SO_ERROR */ && ulen >= 4u) {
                    const int32_t err = it->second.so_error;
                    it->second.so_error = 0;
                    const uint32_t sz = 4u;
                    if (!WriteUserBytes(cpu, st.x[3], &err, sz)) return -14;
                    if (!WriteUserBytes(cpu, st.x[4], &sz, sizeof(sz))) return -14;
                    return 0;
                }
                if ((optname == 7 || optname == 8) && ulen >= 4u) {
                    const int32_t bsz = 65536;
                    const uint32_t sz = 4u;
                    if (!WriteUserBytes(cpu, st.x[3], &bsz, sz)) return -14;
                    if (!WriteUserBytes(cpu, st.x[4], &sz, sizeof(sz))) return -14;
                    return 0;
                }
            }
            return 0;
        }
        case 210: { // shutdown(fd, how)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const int how = static_cast<int>(st.x[1]);
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (how == 0 || how == 2) sock.shutdown_rd = true;
                if (how == 1 || how == 2) {
                    sock.shutdown_wr = true;
                    if (auto p = sock.peer.lock()) p->peer_closed = true;
                }
                WakePollWaiters();
                return 0;
            }
            if (it->second.host_fd >= 0) {
                return (::shutdown(it->second.host_fd, how) == 0) ? 0 : -static_cast<int64_t>(errno);
            }
            return -88;
        }
        case 211: { // sendmsg(fd, msg, flags)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            struct LinuxMsghdrA64 {
                uint64_t msg_name;
                uint32_t msg_namelen;
                uint32_t pad0;
                uint64_t msg_iov;
                uint64_t msg_iovlen;
                uint64_t msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t pad1;
            } hdr{};
            if (!ReadUserBytes(cpu, st.x[1], &hdr, sizeof(hdr))) return -14;
            std::vector<uint8_t> combined;
            const size_t iov_cnt = std::min<size_t>(hdr.msg_iovlen, 1024u);
            for (size_t i = 0; i < iov_cnt; ++i) {
                uint64_t vec[2]{};
                if (!ReadUserBytes(cpu, hdr.msg_iov + i * 16ULL, vec, 16)) return -14;
                if (vec[1] > 0) {
                    const size_t old_sz = combined.size();
                    combined.resize(old_sz + static_cast<size_t>(vec[1]));
                    if (!ReadUserBytes(cpu, vec[0], combined.data() + old_sz, static_cast<size_t>(vec[1]))) {
                        return -14;
                    }
                }
            }
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                if (sock.shutdown_wr) return -32;
                std::vector<std::shared_ptr<OpenFile>> passed;
                if (hdr.msg_control != 0ULL && hdr.msg_controllen >= 16ULL) {
                    const size_t clen = std::min<size_t>(hdr.msg_controllen, 4096u);
                    std::vector<uint8_t> cbuf(clen);
                    if (!ReadUserBytes(cpu, hdr.msg_control, cbuf.data(), clen)) return -14;
                    size_t off = 0u;
                    while (off + 16u <= clen) {
                        uint64_t cmsg_len = 0;
                        int32_t clevel = 0, ctype = 0;
                        std::memcpy(&cmsg_len, cbuf.data() + off, 8);
                        std::memcpy(&clevel, cbuf.data() + off + 8, 4);
                        std::memcpy(&ctype, cbuf.data() + off + 12, 4);
                        if (cmsg_len < 16u || off + cmsg_len > clen) break;
                        if (clevel == 1 /* SOL_SOCKET */ && ctype == 1 /* SCM_RIGHTS */) {
                            for (size_t foff = 16u; foff + 4u <= cmsg_len; foff += 4u) {
                                int32_t send_fd = -1;
                                std::memcpy(&send_fd, cbuf.data() + off + foff, 4);
                                auto s_it = fds.find(send_fd);
                                if (s_it == fds.end()) return -9;
                                OpenFile dup_f = s_it->second;
                                if (dup_f.host_fd >= 0) {
                                    dup_f.host_fd = ::dup(dup_f.host_fd);
                                    if (dup_f.host_fd < 0) return -static_cast<int64_t>(errno);
                                }
                                passed.push_back(std::make_shared<OpenFile>(std::move(dup_f)));
                            }
                        }
                        off += (cmsg_len + 7u) & ~size_t(7u);
                    }
                }
                std::string dest_key = sock.peer_path;
                if (hdr.msg_name != 0ULL && hdr.msg_namelen >= 2u) {
                    const size_t alen = std::min<size_t>(hdr.msg_namelen, 256u);
                    std::vector<uint8_t> sa(alen);
                    if (!ReadUserBytes(cpu, hdr.msg_name, sa.data(), alen)) return -14;
                    ParseGuestUnixPath(sa.data(), alen, dest_key);
                }
                const int64_t sent = static_cast<int64_t>(combined.size());
                if (dest_key == "/dev/socket/property_service") {
                    HandleBuiltInPropertyServicePacket(it->second.unix_sock, combined);
                    return sent;
                }
                if (dest_key == "/dev/socket/logdw" || dest_key == "/dev/socket/logd") {
                    HandleBuiltInLogdPacket(combined);
                    return sent;
                }
                std::shared_ptr<UnixSocketEndpoint> target_ep = sock.peer.lock();
                if (!target_ep && !dest_key.empty()) {
                    auto bit = unix_bound_sockets_.find(dest_key);
                    if (bit != unix_bound_sockets_.end()) target_ep = bit->second.lock();
                }
                if (!target_ep || sock.peer_closed) return -32;
                UnixSocketEndpoint::Chunk ch;
                ch.data = std::move(combined);
                ch.passed_fds = std::move(passed);
                ch.peer_addr = sock.bound_path;
                target_ep->rx_chunks.push_back(std::move(ch));
                WakePollWaiters();
                return sent;
            }
            if (it->second.is_netlink) {
                return static_cast<int64_t>(combined.size());
            }
            if (it->second.host_fd >= 0) {
                ssize_t w = ::send(it->second.host_fd, combined.data(), combined.size(),
                                   static_cast<int>(st.x[2]));
                return (w >= 0) ? static_cast<int64_t>(w) : -static_cast<int64_t>(errno);
            }
            return -88;
        }
        case 212: { // recvmsg(fd, msg, flags)
            const int sfd = static_cast<int>(st.x[0]);
            auto it = fds.find(sfd);
            if (it == fds.end()) return -9;
            const int rflags = static_cast<int>(st.x[2]);
            struct LinuxMsghdrA64 {
                uint64_t msg_name;
                uint32_t msg_namelen;
                uint32_t pad0;
                uint64_t msg_iov;
                uint64_t msg_iovlen;
                uint64_t msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t pad1;
            } hdr{};
            if (!ReadUserBytes(cpu, st.x[1], &hdr, sizeof(hdr))) return -14;
            if (it->second.unix_sock) {
                auto& sock = *it->second.unix_sock;
                const bool dontwait = it->second.nonblock || ((rflags & 0x40 /* MSG_DONTWAIT */) != 0);
                if (sock.rx_chunks.empty()) {
                    if (sock.peer_closed || sock.shutdown_rd) {
                        hdr.msg_controllen = 0ULL;
                        hdr.msg_flags = 0;
                        WriteUserBytes(cpu, st.x[1], &hdr, sizeof(hdr));
                        return 0;
                    }
                    if (dontwait || !cur) return -11;
                    cur->state = TaskState::PollWait;
                    cur->poll_wait_epfd = -1;
                    cur->poll_wait_fds = {EpollWatch{sfd, 0x001u, 0ULL}};
                    cur->poll_has_timeout = false;
                    st.sys.elr_el1 -= 4ULL;
                    out_retry = true;
                    out_yield = true;
                    return 0;
                }
                auto& front = sock.rx_chunks.front();
                size_t data_pos = 0u;
                const size_t iov_cnt = std::min<size_t>(hdr.msg_iovlen, 1024u);
                for (size_t i = 0; i < iov_cnt && data_pos < front.data.size(); ++i) {
                    uint64_t vec[2]{};
                    if (!ReadUserBytes(cpu, hdr.msg_iov + i * 16ULL, vec, 16)) return -14;
                    const size_t avail = front.data.size() - data_pos;
                    const size_t n = std::min(avail, static_cast<size_t>(vec[1]));
                    if (n > 0u && !WriteUserBytes(cpu, vec[0], front.data.data() + data_pos, n)) {
                        return -14;
                    }
                    data_pos += n;
                }
                uint64_t written_ctrl = 0ULL;
                hdr.msg_flags = 0;
                if (!front.passed_fds.empty()) {
                    const int new_clo = ((rflags & 0x40000000 /* MSG_CMSG_CLOEXEC */) != 0) ? 1 : 0;
                    if (hdr.msg_control != 0ULL && hdr.msg_controllen >= 16ULL) {
                        const size_t max_fds = static_cast<size_t>((hdr.msg_controllen - 16ULL) / 4ULL);
                        const size_t emit_cnt = std::min(max_fds, front.passed_fds.size());
                        if (emit_cnt < front.passed_fds.size()) hdr.msg_flags |= 0x08; // MSG_CTRUNC
                        if (emit_cnt > 0u) {
                            const uint64_t cmsg_len = 16ULL + emit_cnt * 4ULL;
                            const size_t buf_len = static_cast<size_t>((cmsg_len + 7ULL) & ~7ULL);
                            std::vector<uint8_t> cbuf(buf_len, 0u);
                            const int32_t clevel = 1; // SOL_SOCKET
                            const int32_t ctype = 1;  // SCM_RIGHTS
                            std::memcpy(cbuf.data() + 0u, &cmsg_len, 8);
                            std::memcpy(cbuf.data() + 8u, &clevel, 4);
                            std::memcpy(cbuf.data() + 12u, &ctype, 4);
                            for (size_t j = 0; j < emit_cnt; ++j) {
                                auto& pof = front.passed_fds[j];
                                OpenFile rcv = *pof;
                                pof->host_fd = -1; // ownership transferred to receiver fd table
                                rcv.fd_flags = new_clo;
                                const int rfd = next_fd++;
                                fds.emplace(rfd, std::move(rcv));
                                std::memcpy(cbuf.data() + 16u + j * 4u, &rfd, 4);
                            }
                            const size_t write_len = std::min<size_t>(buf_len, hdr.msg_controllen);
                            if (!WriteUserBytes(cpu, hdr.msg_control, cbuf.data(), write_len)) return -14;
                            written_ctrl = cmsg_len;
                        }
                    } else {
                        hdr.msg_flags |= 0x08; // MSG_CTRUNC
                    }
                    front.passed_fds.clear();
                }
                hdr.msg_controllen = written_ctrl;
                if (sock.sock_type == 1 && data_pos < front.data.size()) {
                    front.data.erase(front.data.begin(), front.data.begin() + static_cast<std::ptrdiff_t>(data_pos));
                } else {
                    sock.rx_chunks.pop_front();
                }
                if (!WriteUserBytes(cpu, st.x[1], &hdr, sizeof(hdr))) return -14;
                return static_cast<int64_t>(data_pos);
            }
            if (it->second.is_netlink) {
                return -11; // EAGAIN
            }
            return -88;
        }
        case 214: { // brk(addr)
            uint64_t req = UntagUserVa(st.x[0]);
            if (req == 0ULL || req <= current_brk_) return static_cast<int64_t>(current_brk_);
            uint64_t end_pg = AlignUp4K(req);
            for (uint64_t va = current_brk_; va < end_pg; va += 4096ULL) {
                uint64_t pa = 0;
                if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, pa) ||
                    !Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                                 va, pa, true, true, false)) {
                    return static_cast<int64_t>(current_brk_);
                }
            }
            current_brk_ = end_pg;
            if (cur && cur->vm) cur->vm->current_brk = current_brk_;
            return static_cast<int64_t>(req);
        }
        case 215: { // munmap(addr, len)
            const uint64_t addr = UntagUserVa(st.x[0]);
            const uint64_t len = AlignUp4K(st.x[1]);
            if ((addr & 0xFFFULL) != 0ULL || len == 0ULL) return -22;
            UnmapRange4K(cpu, addr, len);
            return 0;
        }
        case 216: { // mremap(old_address, old_size, new_size, flags, ...)
            const uint64_t old_addr = UntagUserVa(st.x[0]);
            const uint64_t old_sz = AlignUp4K(st.x[1]);
            const uint64_t new_sz = AlignUp4K(st.x[2]);
            const uint64_t mflags = st.x[3];
            if ((old_addr & 0xFFFULL) != 0ULL || new_sz == 0ULL) return -22;
            if (new_sz <= old_sz) {
                if (new_sz < old_sz) UnmapRange4K(cpu, old_addr + new_sz, old_sz - new_sz);
                return static_cast<int64_t>(old_addr);
            }
            if ((mflags & 1ULL /* MREMAP_MAYMOVE */) == 0ULL) return -12;
            const uint64_t new_addr = mmap_cursor_;
            mmap_cursor_ += new_sz + 4096ULL;
            if (cur && cur->vm) cur->vm->mmap_cursor = mmap_cursor_;
            uint8_t page_buf[4096]{};
            for (uint64_t off = 0ULL; off < new_sz; off += 4096ULL) {
                uint64_t new_pa = 0;
                if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, new_pa)) return -12;
                bool w = true, x = false;
                if (off < old_sz) {
                    uint64_t old_entry = 0, old_leaf = 0;
                    if (LookupL3Pte(old_addr + off, old_entry, old_leaf)) {
                        const uint64_t old_pa = old_leaf & 0x0000FFFFFFFFF000ULL;
                        w = (old_leaf & (1ULL << 7)) == 0ULL;
                        x = (old_leaf & (1ULL << 54)) == 0ULL;
                        ram_.ReadBytes(old_pa, page_buf, sizeof(page_buf));
                        ram_.WriteBytes(new_pa, page_buf, sizeof(page_buf));
                    }
                }
                if (!Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                                 new_addr + off, new_pa, true, w, x)) {
                    return -12;
                }
                cpu.Mmu().InvalidateVa(new_addr + off, true, 0);
                cpu.Cache().InvalidatePhysPage(new_pa);
            }
            UnmapRange4K(cpu, old_addr, old_sz);
            return static_cast<int64_t>(new_addr);
        }
        case 220: { // clone(flags, child_stack, ptid, tls, ctid)
            if (!cur) return -12;
            const uint64_t flags = st.x[0];
            const uint64_t child_stack = st.x[1];
            const bool share_vm = (flags & 0x00000100ULL /* CLONE_VM */) != 0ULL;
            const bool share_files = (flags & 0x00000400ULL /* CLONE_FILES */) != 0ULL;
            const bool same_thread_group = (flags & 0x00010000ULL /* CLONE_THREAD */) != 0ULL;

            SaveTaskContext(st, *cur);

            auto child = std::make_unique<GuestTask>();
            child->pid = next_pid_++;
            child->tgid = same_thread_group ? cur->tgid : child->pid;
            child->ppid = same_thread_group ? cur->ppid : cur->tgid;
            child->uid = uid_;
            child->gid = gid_;
            child->binary = cur->binary;
            child->cwd = cur->cwd;
            child->stack_top = cur->stack_top;
            child->state = TaskState::Runnable;
            child->cpu = cur->cpu;
            child->cpu.x[0] = 0ULL; // child returns 0
            if (child_stack != 0ULL) {
                child->cpu.sp_el0 = child_stack;
            }
            if ((flags & 0x00080000ULL /* CLONE_SETTLS */) != 0ULL) {
                child->cpu.tpidr_el0 = st.x[3];
            }
            if ((flags & 0x00200000ULL /* CLONE_CHILD_CLEARTID */) != 0ULL) {
                child->clear_child_tid = st.x[4];
            }

            if (share_vm && cur->vm) {
                child->vm = cur->vm;
            } else {
                uint64_t child_ttbr0 = 0ULL;
                if (!CloneUserAddressSpace(ram_, ttbr0_pa_, child_ttbr0, phys_cursor_, arena_limit_)) {
                    return -12; // ENOMEM
                }
                child->vm = std::make_shared<VmSpace>();
                child->vm->ttbr0_pa = child_ttbr0;
                child->vm->current_brk = current_brk_;
                child->vm->mmap_cursor = mmap_cursor_;
                if (cur->vm) {
                    child->vm->fb_mapped_pas = cur->vm->fb_mapped_pas;
                    child->vm->lazy_prot_none_ranges = cur->vm->lazy_prot_none_ranges;
                    child->vm->tagged_addr_ctrl = cur->vm->tagged_addr_ctrl;
                }
            }

            if (share_files && cur->files) {
                child->files = cur->files;
            } else {
                child->files = std::make_shared<FdTable>();
                child->files->next_fd = next_fd;
                for (const auto& kv : fds) {
                    OpenFile dup_of = kv.second;
                    if (dup_of.host_fd >= 0) {
                        dup_of.host_fd = ::dup(dup_of.host_fd);
                    }
                    child->files->fds.emplace(kv.first, std::move(dup_of));
                }
            }

            if ((flags & 0x00100000ULL /* CLONE_PARENT_SETTID */) != 0ULL && st.x[2] != 0ULL) {
                const int32_t cpid = child->pid;
                WriteUserBytes(cpu, st.x[2], &cpid, sizeof(cpid));
            }
            if ((flags & 0x01000000ULL /* CLONE_CHILD_SETTID */) != 0ULL && st.x[4] != 0ULL) {
                const int32_t cpid = child->pid;
                if (share_vm) {
                    WriteUserBytes(cpu, st.x[4], &cpid, sizeof(cpid));
                } else if (child->vm && child->vm->ttbr0_pa != 0ULL) {
                    const auto* bytes = reinterpret_cast<const uint8_t*>(&cpid);
                    for (size_t b = 0; b < sizeof(cpid); ++b) {
                        const uint64_t va = UntagUserVa(st.x[4]) + b;
                        uint64_t d1 = 0, d2 = 0, leaf = 0;
                        const uint64_t l1_idx = (va >> 30) & 0x1FFULL;
                        const uint64_t l2_idx = (va >> 21) & 0x1FFULL;
                        const uint64_t l3_idx = (va >> 12) & 0x1FFULL;
                        if (ram_.ReadU64(child->vm->ttbr0_pa + l1_idx * 8ULL, d1) && (d1 & 3ULL) == 3ULL &&
                            ram_.ReadU64((d1 & 0x0000FFFFFFFFF000ULL) + l2_idx * 8ULL, d2) && (d2 & 3ULL) == 3ULL &&
                            ram_.ReadU64((d2 & 0x0000FFFFFFFFF000ULL) + l3_idx * 8ULL, leaf) && (leaf & 3ULL) == 3ULL) {
                            const uint64_t pa = (leaf & 0x0000FFFFFFFFF000ULL) | (va & 0xFFFULL);
                            ram_.WriteBytes(pa, bytes + b, 1u);
                        }
                    }
                }
            }
            const int32_t ret_pid = child->pid;
            tasks_.push_back(std::move(child));
            return ret_pid;
        }
        case 221: { // execve(pathname, argv, envp)
            std::string path;
            if (!ReadUserString(cpu, st.x[0], path)) return -14;
            if (out_note) *out_note = path;
            std::vector<uint8_t> elf_bytes;
            if (!TryResolveElfForTask(path, elf_bytes)) {
                return -2;
            }
            std::vector<std::string> argv = {path};
            if (st.x[1] != 0ULL) {
                argv.clear();
                for (size_t idx = 0; idx < 32u; ++idx) {
                    uint64_t ptr = 0;
                    if (!ReadUserBytes(cpu, st.x[1] + idx * 8ULL, &ptr, 8) || ptr == 0ULL) break;
                    std::string arg;
                    if (ReadUserString(cpu, ptr, arg)) argv.push_back(std::move(arg));
                }
                if (argv.empty()) argv.push_back(path);
            }
            std::vector<std::string> envp;
            bool has_envp = false;
            if (st.x[2] != 0ULL) {
                for (size_t idx = 0; idx < 64u; ++idx) {
                    uint64_t ptr = 0;
                    if (!ReadUserBytes(cpu, st.x[2] + idx * 8ULL, &ptr, 8) || ptr == 0ULL) break;
                    std::string ev;
                    if (ReadUserString(cpu, ptr, ev)) envp.push_back(std::move(ev));
                }
                has_envp = !envp.empty();
            }

            // Unshare FdTable if shared via CLONE_FILES, then close all FD_CLOEXEC descriptors
            if (cur && cur->files) {
                if (cur->files.use_count() > 1) {
                    auto fresh = std::make_shared<FdTable>();
                    fresh->next_fd = cur->files->next_fd;
                    for (const auto& kv : cur->files->fds) {
                        if ((kv.second.fd_flags & 1) != 0) continue; // skip FD_CLOEXEC
                        OpenFile dup_of = kv.second;
                        if (dup_of.host_fd >= 0) dup_of.host_fd = ::dup(dup_of.host_fd);
                        fresh->fds.emplace(kv.first, std::move(dup_of));
                    }
                    cur->files = std::move(fresh);
                } else {
                    for (auto it = cur->files->fds.begin(); it != cur->files->fds.end(); ) {
                        if ((it->second.fd_flags & 1) != 0) {
                            CloseSingleOpenFile(it->second);
                            it = cur->files->fds.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
            }
            if (cur && cur->vm && cur->vm.use_count() > 1) {
                cur->vm = std::make_shared<VmSpace>();
            }

            std::string err;
            active_binary_ = path;
            const bool reset_arena = (tasks_.size() <= 1u);
            if (!MapFreshAddressSpace(cpu, elf_bytes, argv, err, reset_arena, has_envp ? &envp : nullptr)) {
                last_trap_detail_ = "execve(" + path + ") failed: " + err;
                LogToUart("[TRAP] " + last_trap_detail_ + "\r\n");
                return -8;
            }
            // Stay in EL1h so the immediately following ERET at VBAR+0x404 cleanly transitions to EL0t
            const uint64_t new_entry = st.pc;
            const uint64_t new_sp_el0 = st.sp_el[0];
            st.pstate.el = 1;
            st.pstate.spsel = true;
            st.pstate.d = true;
            st.pstate.a = true;
            st.pstate.i = true;
            st.pstate.f = true;
            st.sys.elr_el1 = new_entry;
            st.sys.spsr_el1 = 0ULL; // EL0t
            st.sp_el[0] = new_sp_el0;
            st.x[0] = 0ULL;
            sigaltstack_sp_ = 0ULL;
            sigaltstack_flags_ = 2;
            sigaltstack_size_ = 0ULL;
            if (cur) {
                cur->sigaltstack_sp = 0ULL;
                cur->sigaltstack_flags = 2;
                cur->sigaltstack_size = 0ULL;
                SaveTaskContext(st, *cur);
            }
            return 0;
        }
        case 222: { // mmap(addr, length, prot, flags, fd, offset)
            uint64_t addr = UntagUserVa(st.x[0]);
            const uint64_t len = AlignUp4K(st.x[1]);
            const uint64_t prot = st.x[2];
            const uint64_t mflags = st.x[3];
            const int fd = static_cast<int>(static_cast<int32_t>(st.x[4]));
            const uint64_t file_offset = st.x[5];
            if (len == 0ULL) return -22;

            const bool is_shared = (mflags & 0x01ULL /* MAP_SHARED */) != 0ULL;
            const bool is_fixed = (mflags & 0x10ULL /* MAP_FIXED */) != 0ULL;
            const bool is_anon = (mflags & 0x20ULL /* MAP_ANONYMOUS */) != 0ULL || fd < 0;

            auto fd_it = (!is_anon && fd >= 0) ? fds.find(fd) : fds.end();
            if (!is_anon && fd_it == fds.end()) return -9; // EBADF

            if (addr == 0ULL) {
                addr = mmap_cursor_;
                mmap_cursor_ += len + 4096ULL;
            } else {
                addr = AlignDown4K(addr);
                if (!is_fixed && RangeHasAnyMapping(addr, len)) {
                    addr = mmap_cursor_;
                    mmap_cursor_ += len + 4096ULL;
                }
                if (addr >= 0x0000001000000000ULL && addr + len < 0x0000008000000000ULL &&
                    addr + len >= mmap_cursor_) {
                    mmap_cursor_ = addr + len + 4096ULL;
                }
            }
            if (cur && cur->vm) cur->vm->mmap_cursor = mmap_cursor_;

            const bool r_perm = (prot & 1ULL) != 0;
            const bool w_perm = (prot & 2ULL) != 0;
            const bool x_perm = (prot & 4ULL) != 0;
            const bool el0_allow = (r_perm || w_perm || x_perm);

            // Lazy PROT_NONE anonymous virtual reservation (e.g. Scudo/ART 8+ GiB guard arenas)
            if (is_anon && !el0_allow) {
                if (is_fixed) {
                    UnmapRange4K(cpu, addr, len);
                }
                if (cur && cur->vm) {
                    cur->vm->lazy_prot_none_ranges.emplace_back(addr, addr + len);
                }
                return static_cast<int64_t>(addr);
            }
            if (is_fixed && cur && cur->vm) {
                EraseVmRange(cur->vm->lazy_prot_none_ranges, addr, addr + len);
            }

            const bool is_fb_map = (fd_it != fds.end() && fd_it->second.is_framebuffer);
            const bool is_binder_map = (!is_anon && fd_it != fds.end() && fd_it->second.is_binder);
            if (is_fb_map) fb_pas.clear();

            std::vector<uint64_t> binder_pa_pages;
            if (is_binder_map) binder_pa_pages.reserve(static_cast<size_t>(len >> 12));

            uint8_t page_buf[4096];
            for (uint64_t va = addr; va < addr + len; va += 4096ULL) {
                uint64_t old_ep = 0, old_leaf = 0;
                if (LookupL3Pte(va, old_ep, old_leaf)) {
                    cpu.Cache().InvalidatePhysPage(old_leaf & 0x0000FFFFFFFFF000ULL);
                }

                uint64_t pa = 0;
                bool reused_shared_page = false;
                const uint64_t pg_off = file_offset + (va - addr);
                const size_t pg_idx = static_cast<size_t>(pg_off >> 12);
                if (!is_anon && is_shared && fd_it != fds.end() && fd_it->second.shared_pages &&
                    pg_idx < fd_it->second.shared_pages->size() &&
                    (*fd_it->second.shared_pages)[pg_idx] != 0ULL) {
                    pa = (*fd_it->second.shared_pages)[pg_idx];
                    reused_shared_page = true;
                }

                if (!reused_shared_page) {
                    if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, pa)) {
                        return -12; // ENOMEM
                    }
                    if (!is_anon && !is_fb_map && fd_it != fds.end() && !fd_it->second.is_dev_zero) {
                        if (fd_it->second.host_fd >= 0) {
                            std::memset(page_buf, 0, sizeof(page_buf));
                            ssize_t got = ::pread(fd_it->second.host_fd, page_buf, sizeof(page_buf),
                                                  static_cast<off_t>(pg_off));
                            if (got > 0) {
                                ram_.WriteBytes(pa, page_buf, static_cast<size_t>(got));
                            }
                        } else if (!fd_it->second.data.empty() && pg_off < fd_it->second.data.size()) {
                            const size_t avail = static_cast<size_t>(
                                std::min<uint64_t>(4096ULL, fd_it->second.data.size() - pg_off));
                            ram_.WriteBytes(pa, fd_it->second.data.data() + pg_off, avail);
                        }
                    }
                    if (!is_anon && is_shared && fd_it != fds.end() &&
                        (fd_it->second.is_ashmem || fd_it->second.is_memfd ||
                         fd_it->second.is_dma_heap || fd_it->second.is_ion) &&
                        pg_idx < 1048576u) {
                        if (!fd_it->second.shared_pages) {
                            fd_it->second.shared_pages = std::make_shared<std::vector<uint64_t>>();
                        }
                        if (pg_idx >= fd_it->second.shared_pages->size()) {
                            fd_it->second.shared_pages->resize(pg_idx + 1u, 0ULL);
                        }
                        (*fd_it->second.shared_pages)[pg_idx] = pa;
                    }
                }

                if (!Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                                 va, pa, el0_allow, w_perm, x_perm)) {
                    return -12;
                }
                cpu.Mmu().InvalidateVa(va, true, 0);
                cpu.Cache().InvalidatePhysPage(pa);
                if (is_fb_map) fb_pas.push_back(pa);
                if (is_binder_map) binder_pa_pages.push_back(pa);
            }
            if (is_binder_map) {
                binder_broker_.RegisterMmap(fd_it->second.binder_client_id, addr, len,
                                            std::move(binder_pa_pages));
            }
            return static_cast<int64_t>(addr);
        }
        case 226: { // mprotect(addr, len, prot)
            const uint64_t addr = UntagUserVa(st.x[0]);
            const uint64_t len = st.x[1];
            const uint64_t prot = st.x[2];
            if ((addr & 0xFFFULL) != 0ULL) return -22;
            if (len == 0ULL) return 0;
            if (!ProtectRange4K(cpu, addr, len,
                                (prot & 1ULL) != 0ULL,
                                (prot & 2ULL) != 0ULL,
                                (prot & 4ULL) != 0ULL)) {
                return -12; // ENOMEM
            }
            return 0;
        }
        case 227: // msync
        case 228: // mlock
        case 229: // munlock
            return 0;
        case 260: { // wait4(pid, wstatus, options, rusage)
            if (!cur) return -10;
            const int32_t caller_tgid = cur->tgid;
            const int32_t target = static_cast<int32_t>(static_cast<int64_t>(st.x[0]));
            const uint64_t wstatus_uva = st.x[1];
            const uint64_t options = st.x[2];

            bool has_matching_child = false;
            int32_t reap_tgid = -1;
            int reap_status = 0;
            for (const auto& up : tasks_) {
                const GuestTask* t = up.get();
                if (!t || t->ppid != caller_tgid) continue;
                if (target > 0 && t->tgid != target) continue;
                has_matching_child = true;

                bool group_all_zombie = true;
                for (const auto& gp : tasks_) {
                    if (gp && gp->tgid == t->tgid && gp->state != TaskState::Zombie) {
                        group_all_zombie = false;
                        break;
                    }
                }
                if (group_all_zombie) {
                    reap_tgid = t->tgid;
                    reap_status = t->exit_status;
                    break;
                }
            }
            if (reap_tgid > 0) {
                const uint32_t wstatus = static_cast<uint32_t>((reap_status & 0xFF) << 8);
                if (wstatus_uva != 0ULL &&
                    !WriteUserBytes(cpu, wstatus_uva, &wstatus, sizeof(wstatus))) {
                    return -14;
                }
                const GuestTask* cur_ptr = CurrentTask();
                for (size_t i = 0; i < tasks_.size(); ) {
                    if (tasks_[i] && tasks_[i]->tgid == reap_tgid) {
                        tasks_.erase(tasks_.begin() + static_cast<std::ptrdiff_t>(i));
                    } else {
                        ++i;
                    }
                }
                current_task_idx_ = 0;
                for (size_t i = 0; i < tasks_.size(); ++i) {
                    if (tasks_[i].get() == cur_ptr) {
                        current_task_idx_ = i;
                        break;
                    }
                }
                return reap_tgid;
            }
            if (!has_matching_child) return -10; // ECHILD
            if ((options & 1ULL /* WNOHANG */) != 0ULL) return 0;

            cur->state = TaskState::WaitingChild;
            cur->wait_target_pid = target;
            cur->wait_status_uva = wstatus_uva;
            st.sys.elr_el1 -= 4ULL; // Retry wait4 once child wakes us
            out_retry = true;
            out_yield = true;
            return 0;
        }
        case 261: { // prlimit64(pid, resource, new_limit, old_limit)
            if (st.x[3] != 0ULL) {
                uint64_t lim[2] = {64ULL * 1024ULL * 1024ULL, 64ULL * 1024ULL * 1024ULL};
                if (!WriteUserBytes(cpu, st.x[3], lim, sizeof(lim))) return -14;
            }
            return 0;
        }
        case 278: { // getrandom(buf, buflen, flags)
            uint64_t buf = st.x[0];
            size_t len = static_cast<size_t>(st.x[1]);
            std::vector<uint8_t> rnd(len);
            std::random_device rd;
            for (size_t i = 0; i < len; ++i) rnd[i] = static_cast<uint8_t>(rd());
            return WriteUserBytes(cpu, buf, rnd.data(), len) ? static_cast<int64_t>(len) : -14;
        }
        case 279: { // memfd_create(uname, flags)
            std::string name;
            if (!ReadUserString(cpu, st.x[0], name)) return -14;
            int fd = next_fd++;
            OpenFile of;
            of.path = "memfd:" + name;
            of.is_memfd = true;
            of.is_writable_mem = true;
            of.fd_flags = ((st.x[1] & 1ULL /* MFD_CLOEXEC */) != 0ULL) ? 1 : 0;
            of.st_dev = 4ULL;
            of.st_ino = ComputeGuestInode(of.path + "#" + std::to_string(fd));
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 144: { // setgid
            gid_ = static_cast<uint32_t>(st.x[0]);
            return 0;
        }
        case 146: { // setuid
            uid_ = static_cast<uint32_t>(st.x[0]);
            return 0;
        }
        case 147: { // setresuid(ruid, euid, suid)
            if (static_cast<int32_t>(st.x[0]) != -1) uid_ = static_cast<uint32_t>(st.x[0]);
            return 0;
        }
        case 148: { // getresuid(ruid*, euid*, suid*)
            for (int idx = 0; idx < 3; ++idx) {
                if (st.x[idx] != 0ULL && !WriteUserBytes(cpu, st.x[idx], &uid_, sizeof(uid_))) {
                    return -14;
                }
            }
            return 0;
        }
        case 149: { // setresgid(rgid, egid, sgid)
            if (static_cast<int32_t>(st.x[0]) != -1) gid_ = static_cast<uint32_t>(st.x[0]);
            return 0;
        }
        case 150: { // getresgid(rgid*, egid*, sgid*)
            for (int idx = 0; idx < 3; ++idx) {
                if (st.x[idx] != 0ULL && !WriteUserBytes(cpu, st.x[idx], &gid_, sizeof(gid_))) {
                    return -14;
                }
            }
            return 0;
        }
        case 165: { // getrusage(who, usage)
            if (st.x[1] != 0ULL) {
                uint8_t zeros[144]{};
                if (!WriteUserBytes(cpu, st.x[1], zeros, sizeof(zeros))) return -14;
            }
            return 0;
        }
        case 179: { // sysinfo(info)
            if (st.x[0] != 0ULL) {
                struct LinuxSysInfo64 {
                    int64_t uptime;
                    uint64_t loads[3];
                    uint64_t totalram;
                    uint64_t freeram;
                    uint64_t sharedram;
                    uint64_t bufferram;
                    uint64_t totalswap;
                    uint64_t freeswap;
                    uint16_t procs;
                    uint16_t pad;
                    uint32_t pad2;
                    uint64_t totalhigh;
                    uint64_t freehigh;
                    uint32_t mem_unit;
                    uint32_t pad3;
                } si{};
                si.uptime = 1;
                si.totalram = ram_bytes_;
                si.freeram = ram_bytes_ / 2ULL;
                si.bufferram = 16ULL * 1024ULL * 1024ULL;
                si.procs = static_cast<uint16_t>(std::max<size_t>(1u, ActiveTaskCount()));
                si.mem_unit = 1u;
                if (!WriteUserBytes(cpu, st.x[0], &si, sizeof(si))) return -14;
            }
            return 0;
        }
        case 32: case 33: case 37: case 39: case 40: case 51:
        case 52: case 53: case 54: case 55: case 81: case 88:
        case 119: case 122: case 151: case 152: case 154:
        case 158: case 159: case 161: case 162: case 267: case 274:
            return 0;
        case 120: case 140:
            return 0;
        case 141: // getpriority(which, who) -> 20 - nice (nice=0 -> 20)
            return 20;
        case 168: { // getcpu(cpu, node, tcache)
            const uint32_t zero = 0u;
            if (st.x[0] != 0ULL && !WriteUserBytes(cpu, st.x[0], &zero, sizeof(zero))) return -14;
            if (st.x[1] != 0ULL && !WriteUserBytes(cpu, st.x[1], &zero, sizeof(zero))) return -14;
            return 0;
        }
        case 233: { // madvise(addr, length, advice)
            const uint64_t addr = AlignDown4K(UntagUserVa(st.x[0]));
            const uint64_t len = AlignUp4K(st.x[1]);
            const int advice = static_cast<int>(st.x[2]);
            if (advice == 4 /* MADV_DONTNEED */ && len > 0ULL && len <= (64ULL * 1024ULL * 1024ULL)) {
                static const uint8_t kZeros[4096]{};
                for (uint64_t va = addr; va < addr + len; va += 4096ULL) {
                    uint64_t entry_pa = 0, leaf = 0;
                    if (LookupL3Pte(va, entry_pa, leaf) && (leaf & (1ULL << 7)) == 0ULL) {
                        const uint64_t pa = leaf & 0x0000FFFFFFFFF000ULL;
                        ram_.WriteBytes(pa, kZeros, sizeof(kZeros));
                    }
                }
            }
            return 0;
        }
        case 123: { // sched_getaffinity(pid, cpusetsize, mask)
            const uint64_t mask_len = st.x[1];
            const uint64_t mask_uva = st.x[2];
            if (mask_len < 8ULL) return -22; // EINVAL
            const size_t zero_len = static_cast<size_t>(std::min<uint64_t>(mask_len, 128ULL));
            std::vector<uint8_t> mask(zero_len, 0u);
            mask[0] = 0x0Fu; // 4 virtual CPUs (matches /proc/cpuinfo)
            if (mask_uva != 0ULL && !WriteUserBytes(cpu, mask_uva, mask.data(), mask.size())) {
                return -14;
            }
            return static_cast<int64_t>(std::min<uint64_t>(mask_len, 8ULL));
        }
        case 275: { // sched_getattr
            const uint64_t attr_uva = st.x[1];
            const uint64_t attr_size = st.x[2];
            if (attr_uva != 0ULL && attr_size >= 48ULL) {
                uint8_t zeros[48] = {0};
                if (!WriteUserBytes(cpu, attr_uva, zeros, sizeof(zeros))) return -14;
            }
            return 0;
        }
        case 155: case 156: case 157:
            return cur ? cur->pid : 1;
        default:
            return -38; // ENOSYS
    }
}

HypercallResult LinuxGuestSupervisor::HandleHypercall(AArch64CpuCore& cpu,
                                                      CpuState& state,
                                                      uint16_t imm16,
                                                      bool is_smc) {
    if (!is_smc && imm16 == kSyscallHypercallImm) {
        const uint32_t ec_val = static_cast<uint32_t>(state.sys.esr_el1 >> 26) & 0x3Fu;
        if (ec_val == ec::kSvc64) {
            const uint64_t nr = state.x[8];
            const uint64_t a0 = state.x[0];
            const uint64_t a1 = state.x[1];
            const uint64_t a2 = state.x[2];
            const uint64_t pc = state.sys.elr_el1;
            const int32_t pid = CurrentTask() ? CurrentTask()->pid : 1;

            bool halt = false;
            bool retry = false;
            bool yield = false;
            std::string note;
            int64_t ret = DispatchSyscall(cpu, state, halt, retry, yield, &note);
            if (!retry) {
                state.x[0] = static_cast<uint64_t>(ret);
                RecordSyscall(nr, a0, a1, a2, ret, pc, pid, note);
                if (ret == -38 && logged_enosys_.insert(nr).second) {
                    std::ostringstream oss;
                    oss << "[SYS-ENOSYS] nr=" << std::dec << nr
                        << " pc=0x" << std::hex << pc
                        << " bin=" << (active_binary_.empty() ? "unknown" : active_binary_)
                        << "\r\n";
                    LogToUart(oss.str());
                }
            }
            if (halt) {
                if (exit_status_ != 0) {
                    const std::string reason =
                        "exit=" + std::to_string(exit_status_);
                    if (last_trap_detail_.empty()) {
                        last_trap_detail_ = "Guest halted with non-zero exit=" +
                                            std::to_string(exit_status_) +
                                            ", insns=" + std::to_string(state.instructions_executed);
                    }
                    EmitFailureDiagnostics(cpu, reason);
                }
                return HypercallResult{true, true};
            }
            if (yield && !tasks_.empty()) {
                if (GuestTask* cur = CurrentTask()) {
                    SaveTaskContext(state, *cur);
                }
                bool all_exited = false;
                bool wfi_sleep = false;
                if (!ScheduleNextTask(cpu, state, all_exited, wfi_sleep)) {
                    if (all_exited) {
                        exited_ = true;
                        return HypercallResult{true, true};
                    }
                    if (wfi_sleep) {
                        state.waiting_for_interrupt = true;
                    }
                }
            }
            return HypercallResult{true, false};
        }

        // Unexpected synchronous/IRQ trap inside EL0/EL1 supervisor — decode & log fully
        last_trap_detail_ = FormatExceptionTrap(cpu, state, ec_val);
        LogToUart("[TRAP] " + last_trap_detail_ + "\r\n");
        EmitFailureDiagnostics(cpu, "trap");
        exited_ = true;
        exit_status_ = -1;
        return HypercallResult{true, true};
    }
    return psci_.HandleHypercall(state, imm16, is_smc);
}

} // namespace haseeb::vm
