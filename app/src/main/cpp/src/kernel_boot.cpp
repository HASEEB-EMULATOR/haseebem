#include "haseeb/kernel_boot.hpp"
#include "haseeb/guest_vfs_bridge.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <random>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
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

std::string ParentDirOf(const std::string& norm) {
    const size_t slash = norm.find_last_of('/');
    if (slash == std::string::npos || slash == 0u) return "/";
    return norm.substr(0, slash);
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

    // Build Linux AArch64 initial user stack: strings + AT_RANDOM + auxv + envp + argv + argc
    uint64_t sp = kUserStackTop - 16ULL;
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
    push_aux(17u, 100ULL);                 // AT_CLKTCK
    push_aux(23u, 0ULL);                   // AT_SECURE
    push_aux(25u, random_va);              // AT_RANDOM
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

void LinuxGuestSupervisor::CloseTaskOpenFds(GuestTask& task) {
    for (auto& kv : task.open_fds) {
        if (kv.second.host_fd >= 0) {
            ::close(kv.second.host_fd);
            kv.second.host_fd = -1;
        }
    }
    task.open_fds.clear();
}

void LinuxGuestSupervisor::CloseAllOpenFds() {
    for (auto& t : tasks_) {
        if (t) CloseTaskOpenFds(*t);
    }
    for (auto& kv : open_fds_) {
        if (kv.second.host_fd >= 0) {
            ::close(kv.second.host_fd);
            kv.second.host_fd = -1;
        }
    }
    open_fds_.clear();
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
    task.current_brk = current_brk_;
    task.mmap_cursor = mmap_cursor_;
    task.ttbr0_pa = ttbr0_pa_;
    task.binary = active_binary_;
}

void LinuxGuestSupervisor::RestoreTaskContext(AArch64CpuCore& cpu,
                                                CpuState& st,
                                                const GuestTask& task) const {
    const uint64_t new_ttbr0 = (task.ttbr0_pa & 0x0000FFFFFFFFF000ULL) |
                               (static_cast<uint64_t>(task.pid & 0xFFFFu) << 48);
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

void LinuxGuestSupervisor::WakeSleepingTasks() {
    const int64_t now = NowSteadyNs();
    for (auto& t : tasks_) {
        if (t && t->state == TaskState::Sleeping && now >= t->wakeup_ns) {
            t->state = TaskState::Runnable;
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
                current_brk_ = cand->current_brk;
                mmap_cursor_ = cand->mmap_cursor;
                ttbr0_pa_ = cand->ttbr0_pa;
                active_binary_ = cand->binary;
                RestoreTaskContext(cpu, st, *cand);
                st.pc = cand->cpu.elr_el1;
                st.pstate.UnpackSpsr(static_cast<uint32_t>(cand->cpu.spsr_el1));
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
            current_brk_ = cand->current_brk;
            mmap_cursor_ = cand->mmap_cursor;
            ttbr0_pa_ = cand->ttbr0_pa;
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
                current_brk_ = cand->current_brk;
                mmap_cursor_ = cand->mmap_cursor;
                ttbr0_pa_ = cand->ttbr0_pa;
                active_binary_ = cand->binary;
                RestoreTaskContext(cpu, st, *cand);
            } else {
                st.waiting_for_interrupt = false;
            }
            return true;
        }
    }

    // Check if any non-zombie task still waits (Sleeping / WaitingChild)
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
        out_norm = NormalizeGuestPath("/" + raw_path);
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

bool LinuxGuestSupervisor::ResolveSymlinkTarget(const std::string& norm_path,
                                                std::string& out_target) const {
    out_target.clear();
    if (norm_path == "/proc/self/exe") {
        out_target = active_binary_.empty() ? "/init" : active_binary_;
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
                                          std::vector<std::string>& out_children) const {
    std::string norm = NormalizeGuestPath(path);
    for (int depth = 0; depth < 8; ++depth) {
        out_data.clear();
        out_children.clear();
        out_is_dir = false;

        if (norm == "/proc/self/exe") {
            const std::string target = active_binary_.empty() ? "/init" : active_binary_;
            if (target == norm) return false;
            norm = NormalizeGuestPath(target);
            continue;
        }
        if (norm == "/proc/cmdline") {
            std::string text = cmdline_ + "\n";
            out_data.assign(text.begin(), text.end());
            return true;
        }
        if (norm == "/proc/version") {
            std::string text = "Linux version 5.10.209-haseeb #1 SMP PREEMPT aarch64\n";
            out_data.assign(text.begin(), text.end());
            return true;
        }
        if (norm == "/dev/null" || norm == "/dev/zero" ||
            norm == "/dev/urandom" || norm == "/dev/random") {
            return true;
        }
        if (norm == "/dev/input") {
            out_is_dir = true;
            if (touch_) out_children.push_back("event0");
            if (kbd_) out_children.push_back("event1");
            return true;
        }
        if ((norm == "/dev/input/event0" && touch_) || (norm == "/dev/input/event1" && kbd_)) {
            return true;
        }

        if (GuestVfsBridge::TryResolveSpecialVfs(norm, shared_storage_root_, hardware_, prop_mgr_,
                                                 ram_bytes_, out_data, out_is_dir, out_children)) {
            return true;
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
            return true;
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
            return true;
        }

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
            if (try_ext4(norm)) return true;
            if (followed_link) continue;
            if (norm.rfind("/system/", 0) == 0 && try_ext4(norm.substr(7))) return true;
            if (followed_link) continue;
            if (norm == "/system" && try_ext4("/")) return true;
            if (followed_link) continue;
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
                                                bool reset_phys_cursor) {
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

    std::vector<std::string> envp = {
        "PATH=/sbin:/system/bin:/vendor/bin",
        "HOME=/",
        "TERM=vt100",
        magisk_enabled_ ? "HASEEB_ROOT=magisk" : "HASEEB_ROOT=0",
    };

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

    const int32_t active_pid = CurrentTask() ? CurrentTask()->pid : 1;
    cpu.Mmu().InvalidateAll();
    cpu.Cache().InvalidateAll();
    cpu.Reset(load.entry_pc, load.initial_sp, 0);
    auto& st = cpu.State();
    st.sp_el[0] = load.initial_sp;
    st.pstate.el = 0;
    st.pstate.spsel = false;
    st.sys.vbar_el1 = vbar_pa_;
    st.sys.ttbr0_el1 = (ttbr0_pa_ & 0x0000FFFFFFFFF000ULL) |
                       (static_cast<uint64_t>(active_pid & 0xFFFFu) << 48);
    st.sys.tcr_el1 = 25ULL | (1ULL << 23); // T0SZ=25 (39-bit VA, 4K), EPD1=1
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
    root->ppid = 0;
    root->uid = 0u;
    root->gid = 0u;
    root->binary = chosen;
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
    const auto& fb_pas = cur ? cur->fb_mapped_pas : fb_mapped_pas_;
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
    LogToUart(DumpRecentSyscalls(16));
    LogToUart(cpu.DumpRecentTrace(16));
}

bool LinuxGuestSupervisor::LookupL3Pte(uint64_t va,
                                       uint64_t& out_l3_entry_pa,
                                       uint64_t& out_leaf) const {
    if (ttbr0_pa_ == 0ULL) return false;
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

void LinuxGuestSupervisor::UnmapRange4K(AArch64CpuCore& cpu, uint64_t addr, uint64_t len) {
    const uint64_t start = AlignDown4K(addr);
    const uint64_t end = start + AlignUp4K(len);
    for (uint64_t va = start; va < end; va += 4096ULL) {
        uint64_t entry_pa = 0, leaf = 0;
        if (LookupL3Pte(va, entry_pa, leaf)) {
            const uint64_t old_pa = leaf & 0x0000FFFFFFFFF000ULL;
            ram_.WriteU64(entry_pa, 0ULL);
            cpu.Mmu().InvalidateVa(va, true, 0);
            cpu.Cache().InvalidatePhysPage(old_pa);
        }
    }
}

bool LinuxGuestSupervisor::ProtectRange4K(AArch64CpuCore& cpu,
                                          uint64_t addr,
                                          uint64_t len,
                                          bool r,
                                          bool w,
                                          bool x) {
    const uint64_t start = AlignDown4K(addr);
    const uint64_t end = start + AlignUp4K(len);
    const bool el0_allow = (r || w || x);
    for (uint64_t va = start; va < end; va += 4096ULL) {
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
        }
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
        norm == "/dev/urandom" || norm == "/dev/random") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.nonblock = nonblock;
        of.is_dev_null = (norm == "/dev/null");
        of.is_dev_zero = (norm == "/dev/zero");
        of.is_dev_urandom = (norm == "/dev/urandom" || norm == "/dev/random");
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
        fds.emplace(fd, std::move(of));
        return fd;
    }
    if (norm == "/dev/binder" || norm == "/dev/hwbinder" || norm == "/dev/vndbinder") {
        if (check_access_only) return 0;
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.fd_flags = cloexec;
        of.is_binder = true;
        of.nonblock = nonblock;
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
        int fd = next_fd++;
        OpenFile of;
        of.path = norm;
        of.host_path = host_path;
        of.host_fd = hfd;
        of.fd_flags = cloexec;
        of.is_host_storage = true;
        of.nonblock = nonblock;
        fds.emplace(fd, std::move(of));
        return fd;
    }

    std::vector<uint8_t> data;
    bool is_dir = false;
    std::vector<std::string> children;
    if (!ResolveVfsFile(norm, data, is_dir, children)) return -2; // ENOENT
    if (check_access_only) return 0;
    if ((flags & 0200000ULL /* O_DIRECTORY */) != 0ULL && !is_dir) return -20; // ENOTDIR
    int fd = next_fd++;
    OpenFile of;
    of.path = norm;
    of.data = std::move(data);
    of.fd_flags = cloexec;
    of.is_dir = is_dir;
    of.nonblock = nonblock;
    of.dir_children = std::move(children);
    fds.emplace(fd, std::move(of));
    return fd;
}

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
    auto& fds = cur ? cur->open_fds : open_fds_;
    int& next_fd = cur ? cur->next_fd : next_fd_;
    auto& fb_pas = cur ? cur->fb_mapped_pas : fb_mapped_pas_;

    switch (nr) {
        case 17: { // getcwd(buf, size)
            uint64_t buf = st.x[0];
            uint64_t sz = st.x[1];
            const char cwd[] = "/";
            if (sz < sizeof(cwd)) return -34; // ERANGE
            return WriteUserBytes(cpu, buf, cwd, sizeof(cwd)) ? static_cast<int64_t>(buf) : -14;
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
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 20: { // epoll_create1(flags)
            int fd = next_fd++;
            OpenFile of;
            of.path = "anon_inode:[eventpoll]";
            of.is_epoll = true;
            of.fd_flags = ((st.x[0] & 02000000ULL) != 0ULL) ? 1 : 0;
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 21: { // epoll_ctl(epfd, op, fd, event)
            auto it = fds.find(static_cast<int>(st.x[0]));
            if (it == fds.end() || !it->second.is_epoll) return -22;
            const int op = static_cast<int>(st.x[1]);
            const int target_fd = static_cast<int>(st.x[2]);
            auto& list = it->second.epoll_fds;
            if (op == 1) { // EPOLL_CTL_ADD
                if (std::find(list.begin(), list.end(), target_fd) == list.end()) {
                    list.push_back(target_fd);
                }
            } else if (op == 2) { // EPOLL_CTL_DEL
                list.erase(std::remove(list.begin(), list.end(), target_fd), list.end());
            }
            return 0;
        }
        case 22: { // epoll_pwait(epfd, events, maxevents, timeout, sigmask)
            auto it = fds.find(static_cast<int>(st.x[0]));
            if (it == fds.end() || !it->second.is_epoll) return -9;
            const int timeout_ms = static_cast<int>(static_cast<int32_t>(st.x[3]));
            if (timeout_ms > 0 && tasks_.size() > 1u) {
                out_yield = true;
            }
            return 0;
        }
        case 23: { // dup(oldfd)
            int oldfd = static_cast<int>(st.x[0]);
            if (oldfd >= 0 && oldfd <= 2) {
                int newfd = next_fd++;
                OpenFile of;
                of.path = (oldfd == 0) ? "/dev/stdin" : (oldfd == 1 ? "/dev/stdout" : "/dev/stderr");
                of.is_stdio_out = (oldfd == 1 || oldfd == 2);
                fds.emplace(newfd, std::move(of));
                return newfd;
            }
            auto it = fds.find(oldfd);
            if (it == fds.end()) return -9;
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
        case 24: { // dup3(oldfd, newfd, flags)
            int oldfd = static_cast<int>(st.x[0]);
            int newfd = static_cast<int>(st.x[1]);
            uint64_t dflags = st.x[2];
            if (oldfd == newfd) return -22;
            OpenFile copy;
            if (oldfd >= 0 && oldfd <= 2) {
                copy.path = (oldfd == 0) ? "/dev/stdin" : (oldfd == 1 ? "/dev/stdout" : "/dev/stderr");
                copy.is_stdio_out = (oldfd == 1 || oldfd == 2);
            } else {
                auto it = fds.find(oldfd);
                if (it == fds.end()) return -9;
                copy = it->second;
                if (copy.host_fd >= 0) {
                    copy.host_fd = ::dup(copy.host_fd);
                    if (copy.host_fd < 0) return -static_cast<int64_t>(errno);
                }
            }
            copy.fd_flags = ((dflags & 02000000ULL) != 0ULL) ? 1 : 0;
            if (newfd <= 2) return newfd;
            auto existing = fds.find(newfd);
            if (existing != fds.end()) {
                if (existing->second.host_fd >= 0) ::close(existing->second.host_fd);
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
            auto it = (fd > 2) ? fds.find(fd) : fds.end();
            if (fd < 0 || (fd > 2 && it == fds.end())) return -9; // EBADF
            switch (cmd) {
                case 0:    // F_DUPFD
                case 1030: { // F_DUPFD_CLOEXEC
                    int min_fd = std::max<int>(3, static_cast<int>(arg));
                    while (fds.find(min_fd) != fds.end()) ++min_fd;
                    OpenFile copy;
                    if (fd <= 2) {
                        copy.path = (fd == 0) ? "/dev/stdin" : (fd == 1 ? "/dev/stdout" : "/dev/stderr");
                        copy.is_stdio_out = (fd == 1 || fd == 2);
                    } else {
                        copy = it->second;
                        if (copy.host_fd >= 0) {
                            copy.host_fd = ::dup(copy.host_fd);
                            if (copy.host_fd < 0) return -static_cast<int64_t>(errno);
                        }
                    }
                    copy.fd_flags = (cmd == 1030) ? 1 : 0;
                    fds.emplace(min_fd, std::move(copy));
                    if (next_fd <= min_fd) next_fd = min_fd + 1;
                    return min_fd;
                }
                case 1: // F_GETFD
                    return (fd <= 2) ? 0 : it->second.fd_flags;
                case 2: // F_SETFD
                    if (fd > 2) it->second.fd_flags = static_cast<int>(arg & 1ULL);
                    return 0;
                case 3: // F_GETFL
                    return (fd <= 2) ? 2 : (it->second.nonblock ? 04000 : 0);
                case 4: // F_SETFL
                    if (fd > 2) it->second.nonblock = (arg & 04000ULL) != 0ULL;
                    return 0;
                default:
                    return 0;
            }
        }
        case 34: { // mkdirat(dirfd, pathname, mode)
            std::string path, norm;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
            std::string host_path, rel;
            if (!ResolveHostStoragePath(norm, host_path, rel)) return -13; // EACCES
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
            if (!ResolveHostStoragePath(norm, host_path, rel) || rel.empty()) return -13;
            const bool rm_dir = (st.x[2] & 0x200ULL) != 0ULL; // AT_REMOVEDIR
            const int rc = rm_dir ? ::rmdir(host_path.c_str()) : ::unlink(host_path.c_str());
            return (rc == 0) ? 0 : -static_cast<int64_t>(errno);
        }
        case 38: { // renameat(olddirfd, oldpath, newdirfd, newpath)
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
                return -18; // EXDEV
            }
            return (::rename(h_old.c_str(), h_new.c_str()) == 0) ? 0 : -static_cast<int64_t>(errno);
        }
        case 43:   // statfs(path, buf)
        case 44: { // fstatfs(fd, buf)
            if (nr == 43) {
                std::string path;
                if (!ReadUserString(cpu, st.x[0], path)) return -14;
                const std::string norm = NormalizeGuestPath(path);
                std::string hp, rel;
                if (!ResolveHostStoragePath(norm, hp, rel)) {
                    std::vector<uint8_t> tmp;
                    bool is_dir = false;
                    std::vector<std::string> ch;
                    if (!ResolveVfsFile(norm, tmp, is_dir, ch)) return -2;
                }
            } else {
                int fd = static_cast<int>(st.x[0]);
                if (fd > 2 && fds.find(fd) == fds.end()) return -9;
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
            sfs.f_type = 0xEF53LL; // EXT4_SUPER_MAGIC
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
            if (it->second.is_memfd) {
                const size_t new_len = static_cast<size_t>(std::min<uint64_t>(st.x[1], 64ULL * 1024ULL * 1024ULL));
                it->second.data.resize(new_len, 0u);
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
            wf.path = "pipe:[w]";
            wf.host_fd = pfds[1];
            wf.fd_flags = clo;
            wf.nonblock = (st.x[1] & 04000ULL) != 0ULL;
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
                if (req == 0x40046205ULL) { // BINDER_SET_MAX_THREADS
                    return 0;
                }
                if (req == 0xC0046209ULL) { // BINDER_VERSION
                    int32_t ver = 8;
                    return WriteUserBytes(cpu, arg, &ver, sizeof(ver)) ? 0 : -14;
                }
                if (req == 0xC0306201ULL) { // BINDER_WRITE_READ
                    return 0;
                }
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
                return 0;
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
            } else if (it != fds.end() &&
                       (it->second.is_sensors || it->second.is_camera ||
                        it->second.is_magisk_su || it->second.is_gles)) {
                return GuestVfsBridge::HandleSpecialIoctl(
                    it->second, req, arg, hardware_, soft_gles_, gpu_, uid_, gid_, active_binary_,
                    [&](uint64_t uva, void* dst, size_t len) { return ReadUserBytes(cpu, uva, dst, len); },
                    [&](uint64_t uva, const void* src, size_t len) { return WriteUserBytes(cpu, uva, src, len); });
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
            if (fd <= 2) return 0;
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            if (it->second.host_fd >= 0) ::close(it->second.host_fd);
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
            if (fd == 0) {
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
            auto it = fds.find(fd);
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
                    return -11; // EAGAIN
                }
                uint64_t val = it->second.eventfd_counter;
                it->second.eventfd_counter = 0ULL;
                return WriteUserBytes(cpu, buf, &val, sizeof(val)) ? 8 : -14;
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
                if (r < 0) return -static_cast<int64_t>(errno);
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
            if (fd == 1 || fd == 2) {
                for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
                return static_cast<int64_t>(count);
            }
            auto it = fds.find(fd);
            if (it == fds.end()) return -9;
            if (it->second.is_stdio_out) {
                for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
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
                return 8;
            }
            if (it->second.host_fd >= 0) {
                ssize_t w = ::write(it->second.host_fd, tmp.data(), count);
                return (w >= 0) ? static_cast<int64_t>(w) : -static_cast<int64_t>(errno);
            }
            if (it->second.is_memfd) {
                const size_t end = it->second.offset + count;
                if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                if (count > 0u) std::memcpy(it->second.data.data() + it->second.offset, tmp.data(), count);
                it->second.offset = end;
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
            auto it = (fd > 2) ? fds.find(fd) : fds.end();
            if (fd < 0 || (fd > 2 && (it == fds.end() || it->second.is_dir))) return -9;
            int64_t total = 0;
            for (int i = 0; i < iovcnt; ++i) {
                uint64_t vec[2]{};
                if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                const size_t len = static_cast<size_t>(vec[1]);
                if (len == 0u) continue;
                if (fd == 0) {
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
            auto it = (fd > 2) ? fds.find(fd) : fds.end();
            if (fd != 1 && fd != 2 && (fd < 0 || it == fds.end())) return -9;
            int64_t total = 0;
            for (int i = 0; i < iovcnt; ++i) {
                uint64_t vec[2]{};
                if (!ReadUserBytes(cpu, iov_va + static_cast<uint64_t>(i) * 16ULL, vec, 16)) return -14;
                if (vec[1] > 0) {
                    std::vector<uint8_t> tmp(static_cast<size_t>(vec[1]));
                    if (!ReadUserBytes(cpu, vec[0], tmp.data(), tmp.size())) return -14;
                    if (fd == 1 || fd == 2 || it->second.is_stdio_out) {
                        for (uint8_t b : tmp) uart_.Write(0x000ULL, 1, b);
                        total += static_cast<int64_t>(vec[1]);
                    } else if (it->second.is_dev_null || it->second.is_dev_zero) {
                        total += static_cast<int64_t>(vec[1]);
                    } else if (it->second.host_fd >= 0) {
                        ssize_t w = ::write(it->second.host_fd, tmp.data(), tmp.size());
                        if (w < 0) return total > 0 ? total : -static_cast<int64_t>(errno);
                        total += static_cast<int64_t>(w);
                    } else if (it->second.is_memfd) {
                        const size_t end = it->second.offset + tmp.size();
                        if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                        std::memcpy(it->second.data.data() + it->second.offset, tmp.data(), tmp.size());
                        it->second.offset = end;
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
            if (it->second.is_memfd) {
                const size_t end = static_cast<size_t>(off) + count;
                if (end > it->second.data.size()) it->second.data.resize(end, 0u);
                if (count > 0) std::memcpy(it->second.data.data() + static_cast<size_t>(off), tmp.data(), count);
                return static_cast<int64_t>(count);
            }
            return -9;
        }
        case 73: { // ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, sigmask)
            struct LinuxPollFd {
                int32_t fd;
                int16_t events;
                int16_t revents;
            };
            const uint64_t fds_va = st.x[0];
            const size_t nfds = std::min<size_t>(static_cast<size_t>(st.x[1]), 64u);
            const uint64_t tmo_va = st.x[2];
            bool zero_timeout = false;
            if (tmo_va != 0ULL) {
                int64_t ts[2]{};
                if (!ReadUserBytes(cpu, tmo_va, ts, sizeof(ts))) return -14;
                zero_timeout = (ts[0] == 0 && ts[1] == 0);
            }
            std::vector<LinuxPollFd> pfds(nfds);
            if (nfds > 0u && !ReadUserBytes(cpu, fds_va, pfds.data(), nfds * sizeof(LinuxPollFd))) {
                return -14;
            }
            int ready = 0;
            for (auto& p : pfds) {
                p.revents = 0;
                if (p.fd < 0) continue;
                bool readable = false;
                if (p.fd == 0) {
                    readable = (uart_.Read(0x018ULL, 4) & (1u << 4)) == 0u;
                } else {
                    auto f_it = fds.find(p.fd);
                    if (f_it == fds.end()) {
                        p.revents = 0x20; // POLLNVAL
                        ++ready;
                        continue;
                    }
                    if (f_it->second.input_dev != nullptr) {
                        readable = f_it->second.input_dev->HasPendingEvdev();
                    } else if (f_it->second.is_eventfd) {
                        readable = f_it->second.eventfd_counter > 0ULL;
                    } else {
                        readable = true;
                    }
                }
                if (readable && (p.events & 1 /* POLLIN */) != 0) {
                    p.revents = 1;
                    ++ready;
                }
            }
            if (ready == 0 && !zero_timeout && nfds > 0u) {
                st.waiting_for_interrupt = true;
                st.sys.elr_el1 -= 4ULL;
                out_retry = true;
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
            if (ResolveSymlinkTarget(norm, target)) {
                const size_t n = std::min(target.size(), static_cast<size_t>(st.x[3]));
                if (n > 0u && !WriteUserBytes(cpu, st.x[2], target.data(), n)) return -14;
                return static_cast<int64_t>(n);
            }
            std::vector<uint8_t> data;
            bool is_dir = false;
            std::vector<std::string> ch;
            return ResolveVfsFile(norm, data, is_dir, ch) ? -22 : -2;
        }
        case 79: // newfstatat(dirfd, pathname, statbuf, flags)
        case 80: { // fstat(fd, statbuf)
            uint64_t stat_va = (nr == 79) ? st.x[2] : st.x[1];
            bool is_dir = false;
            bool is_link = false;
            uint64_t size_bytes = 0;
            if (nr == 79) {
                std::string path;
                if (!ReadUserString(cpu, st.x[1], path)) return -14;
                const uint64_t flags = st.x[3];
                if (path.empty() && (flags & 0x1000ULL /* AT_EMPTY_PATH */) != 0ULL) {
                    if (out_note) *out_note = "AT_EMPTY_PATH";
                    int fd = static_cast<int>(st.x[0]);
                    if (fd > 2) {
                        auto it = fds.find(fd);
                        if (it == fds.end()) return -9;
                        is_dir = it->second.is_dir;
                        size_bytes = it->second.data.size();
                    }
                } else {
                    std::string norm;
                    if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
                    if (out_note) *out_note = norm;
                    std::string target;
                    if ((flags & 0x100ULL /* AT_SYMLINK_NOFOLLOW */) != 0ULL &&
                        ResolveSymlinkTarget(norm, target)) {
                        is_link = true;
                        size_bytes = target.size();
                    } else {
                        std::string host_path, rel;
                        if (ResolveHostStoragePath(norm, host_path, rel)) {
                            struct stat hst{};
                            if (::stat(host_path.c_str(), &hst) != 0) return -2;
                            is_dir = S_ISDIR(hst.st_mode);
                            size_bytes = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
                        } else {
                            std::vector<uint8_t> data;
                            std::vector<std::string> children;
                            if (!ResolveVfsFile(norm, data, is_dir, children)) return -2;
                            size_bytes = data.size();
                        }
                    }
                }
            } else {
                int fd = static_cast<int>(st.x[0]);
                if (fd <= 2) {
                    size_bytes = 0;
                } else {
                    auto it = fds.find(fd);
                    if (it == fds.end()) return -9;
                    is_dir = it->second.is_dir;
                    if (it->second.host_fd >= 0) {
                        struct stat hst{};
                        if (::fstat(it->second.host_fd, &hst) == 0) {
                            is_dir = S_ISDIR(hst.st_mode);
                            size_bytes = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
                        }
                    } else {
                        size_bytes = it->second.data.size();
                    }
                }
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
            ks.st_dev = 1;
            ks.st_ino = 1;
            ks.st_mode = is_link ? 0120777u : (is_dir ? 0040755u : 0100755u);
            ks.st_nlink = 1;
            ks.st_uid = uid_;
            ks.st_gid = gid_;
            ks.st_size = static_cast<int64_t>(size_bytes);
            ks.st_blksize = 4096;
            ks.st_blocks = static_cast<int64_t>((size_bytes + 511u) / 512u);
            return WriteUserBytes(cpu, stat_va, &ks, sizeof(ks)) ? 0 : -14;
        }
        case 291: { // statx(dirfd, pathname, flags, mask, statxbuf)
            std::string path;
            if (!ReadUserString(cpu, st.x[1], path)) return -14;
            const uint64_t flags = st.x[2];
            bool is_dir = false;
            bool is_link = false;
            uint64_t size_bytes = 0;
            if (path.empty() && (flags & 0x1000ULL /* AT_EMPTY_PATH */) != 0ULL) {
                int fd = static_cast<int>(st.x[0]);
                if (fd > 2) {
                    auto it = fds.find(fd);
                    if (it == fds.end()) return -9;
                    is_dir = it->second.is_dir;
                    if (it->second.host_fd >= 0) {
                        struct stat hst{};
                        if (::fstat(it->second.host_fd, &hst) == 0) {
                            is_dir = S_ISDIR(hst.st_mode);
                            size_bytes = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
                        }
                    } else {
                        size_bytes = it->second.data.size();
                    }
                }
            } else {
                std::string norm, target;
                if (!ResolveGuestPathWithDirfd(fds, static_cast<int>(st.x[0]), path, norm)) return -9;
                if (out_note) *out_note = norm;
                if ((flags & 0x100ULL /* AT_SYMLINK_NOFOLLOW */) != 0ULL &&
                    ResolveSymlinkTarget(norm, target)) {
                    is_link = true;
                    size_bytes = target.size();
                } else {
                    std::string host_path, rel;
                    if (ResolveHostStoragePath(norm, host_path, rel)) {
                        struct stat hst{};
                        if (::stat(host_path.c_str(), &hst) != 0) return -2;
                        is_dir = S_ISDIR(hst.st_mode);
                        size_bytes = static_cast<uint64_t>(std::max<off_t>(0, hst.st_size));
                    } else {
                        std::vector<uint8_t> data;
                        std::vector<std::string> children;
                        if (!ResolveVfsFile(norm, data, is_dir, children)) return -2;
                        size_bytes = data.size();
                    }
                }
            }
            uint8_t buf[256]{};
            const uint32_t mask = 0x000007FFu; // STATX_BASIC_STATS
            const uint32_t blksize = 4096u;
            const uint16_t mode = is_link ? 0120777u : (is_dir ? 0040755u : 0100755u);
            std::memcpy(buf + 0u, &mask, 4u);
            std::memcpy(buf + 4u, &blksize, 4u);
            std::memcpy(buf + 20u, &uid_, 4u);
            std::memcpy(buf + 24u, &gid_, 4u);
            std::memcpy(buf + 28u, &mode, 2u);
            std::memcpy(buf + 40u, &size_bytes, 8u);
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
            if (st.x[1] != 0ULL) {
                uint8_t zeros[24]{};
                if (!WriteUserBytes(cpu, st.x[1], zeros, sizeof(zeros))) return -14;
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
            const int32_t dead_pid = cur->pid;
            const int32_t ppid = cur->ppid;
            if (cur->clear_child_tid != 0ULL) {
                uint32_t zero = 0u;
                WriteUserBytes(cpu, cur->clear_child_tid, &zero, sizeof(zero));
            }
            CloseTaskOpenFds(*cur);
            cur->state = TaskState::Zombie;
            cur->exit_status = status;

            for (auto& t : tasks_) {
                if (t && t->pid == ppid && t->state == TaskState::WaitingChild &&
                    (t->wait_target_pid == -1 || t->wait_target_pid == 0 ||
                     t->wait_target_pid == dead_pid)) {
                    t->state = TaskState::Runnable;
                }
            }
            if (dead_pid == 1 || ActiveTaskCount() == 0u) {
                exit_status_ = status;
                exited_ = true;
                out_halt = true;
                return 0;
            }
            out_yield = true;
            return 0;
        }
        case 96: { // set_tid_address(tidptr)
            if (cur) cur->clear_child_tid = st.x[0];
            return cur ? cur->pid : 1;
        }
        case 98: { // futex(uaddr, futex_op, val, timeout, uaddr2, val3)
            const uint32_t op = static_cast<uint32_t>(st.x[1]) & 0x7Fu;
            if (op == 0u) { // FUTEX_WAIT
                uint32_t cur_val = 0u;
                if (!ReadUserBytes(cpu, st.x[0], &cur_val, sizeof(cur_val))) return -14;
                if (cur_val != static_cast<uint32_t>(st.x[2])) return -11; // EAGAIN
                out_yield = true;
                return 0;
            }
            return 0; // FUTEX_WAKE / others
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
        case 131: { // tgkill(tgid, tid, sig)
            const uint64_t sig = (nr == 131) ? st.x[2] : st.x[1];
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
            if (opt == 40ULL /* PR_GET_TID_ADDRESS */ && st.x[1] != 0ULL) {
                uint64_t tidptr = cur ? cur->clear_child_tid : 0ULL;
                return WriteUserBytes(cpu, st.x[1], &tidptr, sizeof(tidptr)) ? 0 : -14;
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
        case 199: { // socketpair(domain, type, protocol, sv[2])
            const int domain = static_cast<int>(st.x[0]);
            const int raw_type = static_cast<int>(st.x[1]);
            const int base_type = raw_type & 0xF;
            if (domain != 1 /* AF_UNIX */) return -97;
            int sv[2]{-1, -1};
            if (::socketpair(AF_UNIX, base_type == 2 ? SOCK_DGRAM : SOCK_STREAM, 0, sv) != 0) {
                return -static_cast<int64_t>(errno);
            }
            const bool nb = (raw_type & 04000) != 0;
            const int clo = ((raw_type & 02000000) != 0) ? 1 : 0;
            if (nb) {
                ::fcntl(sv[0], F_SETFL, O_NONBLOCK);
                ::fcntl(sv[1], F_SETFL, O_NONBLOCK);
            }
            int fd0 = next_fd++;
            int fd1 = next_fd++;
            OpenFile f0, f1;
            f0.path = "socket:[0]";
            f0.host_fd = sv[0];
            f0.fd_flags = clo;
            f0.nonblock = nb;
            f1.path = "socket:[1]";
            f1.host_fd = sv[1];
            f1.fd_flags = clo;
            f1.nonblock = nb;
            fds.emplace(fd0, std::move(f0));
            fds.emplace(fd1, std::move(f1));
            int32_t out[2] = {fd0, fd1};
            if (!WriteUserBytes(cpu, st.x[3], out, sizeof(out))) return -14;
            return 0;
        }
        case 198: // socket
        case 203: // connect
        case 208: // setsockopt
        case 209: // getsockopt
            return (nr == 198) ? -97 : 0; // -EAFNOSUPPORT / ok
        case 214: { // brk(addr)
            uint64_t req = st.x[0];
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
            return static_cast<int64_t>(req);
        }
        case 215: { // munmap(addr, len)
            const uint64_t addr = st.x[0];
            const uint64_t len = AlignUp4K(st.x[1]);
            if ((addr & 0xFFFULL) != 0ULL || len == 0ULL) return -22;
            UnmapRange4K(cpu, addr, len);
            return 0;
        }
        case 216: { // mremap(old_address, old_size, new_size, flags, ...)
            const uint64_t old_addr = st.x[0];
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

            SaveTaskContext(st, *cur);

            auto child = std::make_unique<GuestTask>();
            child->pid = next_pid_++;
            child->ppid = cur->pid;
            child->uid = uid_;
            child->gid = gid_;
            child->binary = cur->binary;
            child->current_brk = current_brk_;
            child->mmap_cursor = mmap_cursor_;
            child->stack_top = cur->stack_top;
            child->next_fd = cur->next_fd;
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
            if (share_vm) {
                child->ttbr0_pa = ttbr0_pa_;
            } else {
                uint64_t child_ttbr0 = 0ULL;
                if (!CloneUserAddressSpace(ram_, ttbr0_pa_, child_ttbr0, phys_cursor_, arena_limit_)) {
                    return -12; // ENOMEM
                }
                child->ttbr0_pa = child_ttbr0;
            }
            for (const auto& kv : cur->open_fds) {
                OpenFile dup_of = kv.second;
                if (dup_of.host_fd >= 0) {
                    dup_of.host_fd = ::dup(dup_of.host_fd);
                }
                child->open_fds.emplace(kv.first, std::move(dup_of));
            }
            if ((flags & 0x00100000ULL /* CLONE_PARENT_SETTID */) != 0ULL && st.x[2] != 0ULL) {
                int32_t cpid = child->pid;
                WriteUserBytes(cpu, st.x[2], &cpid, sizeof(cpid));
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
                for (size_t idx = 0; idx < 16u; ++idx) {
                    uint64_t ptr = 0;
                    if (!ReadUserBytes(cpu, st.x[1] + idx * 8ULL, &ptr, 8) || ptr == 0ULL) break;
                    std::string arg;
                    if (ReadUserString(cpu, ptr, arg)) argv.push_back(arg);
                }
                if (argv.empty()) argv.push_back(path);
            }
            std::string err;
            active_binary_ = path;
            const bool reset_arena = (tasks_.size() <= 1u);
            if (!MapFreshAddressSpace(cpu, elf_bytes, argv, err, reset_arena)) {
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
            uint64_t addr = st.x[0];
            const uint64_t len = AlignUp4K(st.x[1]);
            const uint64_t prot = st.x[2];
            const uint64_t mflags = st.x[3];
            const int fd = static_cast<int>(static_cast<int32_t>(st.x[4]));
            const uint64_t file_offset = st.x[5];
            if (len == 0ULL) return -22;

            const bool is_fixed = (mflags & 0x10ULL /* MAP_FIXED */) != 0ULL;
            const bool is_anon = (mflags & 0x20ULL /* MAP_ANONYMOUS */) != 0ULL || fd < 0;

            auto fd_it = (!is_anon && fd >= 0) ? fds.find(fd) : fds.end();
            if (!is_anon && fd_it == fds.end()) return -9; // EBADF

            if (addr == 0ULL) {
                addr = mmap_cursor_;
                mmap_cursor_ += len + 4096ULL;
            } else {
                addr = AlignDown4K(addr);
                if (!is_fixed) {
                    bool overlaps = false;
                    for (uint64_t va = addr; va < addr + len; va += 4096ULL) {
                        uint64_t ep = 0, lf = 0;
                        if (LookupL3Pte(va, ep, lf)) {
                            overlaps = true;
                            break;
                        }
                    }
                    if (overlaps) {
                        addr = mmap_cursor_;
                        mmap_cursor_ += len + 4096ULL;
                    }
                }
                if (addr >= 0x0000001000000000ULL && addr + len < 0x0000008000000000ULL &&
                    addr + len >= mmap_cursor_) {
                    mmap_cursor_ = addr + len + 4096ULL;
                }
            }

            const bool r_perm = (prot & 1ULL) != 0;
            const bool w_perm = (prot & 2ULL) != 0;
            const bool x_perm = (prot & 4ULL) != 0;
            const bool el0_allow = (r_perm || w_perm || x_perm);

            const bool is_fb_map = (fd_it != fds.end() && fd_it->second.is_framebuffer);
            if (is_fb_map) fb_pas.clear();

            uint8_t page_buf[4096];
            for (uint64_t va = addr; va < addr + len; va += 4096ULL) {
                uint64_t old_ep = 0, old_leaf = 0;
                if (LookupL3Pte(va, old_ep, old_leaf)) {
                    cpu.Cache().InvalidatePhysPage(old_leaf & 0x0000FFFFFFFFF000ULL);
                }
                uint64_t pa = 0;
                if (!AllocZeroPage(ram_, phys_cursor_, arena_limit_, pa)) {
                    return -12; // ENOMEM
                }
                if (!is_anon && !is_fb_map && fd_it != fds.end() && !fd_it->second.is_dev_zero) {
                    const uint64_t pg_off = file_offset + (va - addr);
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
                if (!Elf64GuestLoader::MapPage4K(ram_, ttbr0_pa_, phys_cursor_, arena_limit_,
                                                 va, pa, el0_allow, w_perm, x_perm)) {
                    return -12;
                }
                cpu.Mmu().InvalidateVa(va, true, 0);
                cpu.Cache().InvalidatePhysPage(pa);
                if (is_fb_map) fb_pas.push_back(pa);
            }
            return static_cast<int64_t>(addr);
        }
        case 226: { // mprotect(addr, len, prot)
            const uint64_t addr = st.x[0];
            const uint64_t len = st.x[1];
            const uint64_t prot = st.x[2];
            if ((addr & 0xFFFULL) != 0ULL) return -22;
            if (len == 0ULL) return 0;
            ProtectRange4K(cpu, addr, len,
                           (prot & 1ULL) != 0ULL,
                           (prot & 2ULL) != 0ULL,
                           (prot & 4ULL) != 0ULL);
            return 0;
        }
        case 227: // msync
        case 228: // mlock
        case 229: // munlock
            return 0;
        case 260: { // wait4(pid, wstatus, options, rusage)
            if (!cur) return -10;
            const int32_t target = static_cast<int32_t>(static_cast<int64_t>(st.x[0]));
            const uint64_t wstatus_uva = st.x[1];
            const uint64_t options = st.x[2];

            bool has_matching_child = false;
            for (size_t i = 0; i < tasks_.size(); ++i) {
                GuestTask* t = tasks_[i].get();
                if (!t || t->ppid != cur->pid) continue;
                if (target > 0 && t->pid != target) continue;
                has_matching_child = true;
                if (t->state == TaskState::Zombie) {
                    const int32_t reaped_pid = t->pid;
                    const uint32_t wstatus = static_cast<uint32_t>((t->exit_status & 0xFF) << 8);
                    if (wstatus_uva != 0ULL &&
                        !WriteUserBytes(cpu, wstatus_uva, &wstatus, sizeof(wstatus))) {
                        return -14;
                    }
                    tasks_.erase(tasks_.begin() + static_cast<std::ptrdiff_t>(i));
                    if (i < current_task_idx_) {
                        --current_task_idx_;
                    }
                    return reaped_pid;
                }
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
            fds.emplace(fd, std::move(of));
            return fd;
        }
        case 39: case 40: case 49: case 50: case 51:
        case 119: case 122: case 141: case 233: case 274:
            return 0;
        case 120: case 140:
            return 0;
        case 123: { // sched_getaffinity
            const uint64_t mask_uva = st.x[2];
            if (mask_uva != 0ULL) {
                uint8_t mask[16];
                for (int i = 0; i < 16; ++i) mask[i] = 0xFF;
                if (!WriteUserBytes(cpu, mask_uva, mask, sizeof(mask))) return -14;
            }
            return 16;
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
        case 155: case 156:
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
