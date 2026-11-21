#include "haseeb/mmu_tlb.hpp"

#include <cstring>

namespace haseeb::vm {

namespace {

inline constexpr uint64_t kSctlrM   = 1ULL << 0;
inline constexpr uint64_t kSctlrWxn = 1ULL << 19;
inline constexpr uint64_t kTcrEpd0  = 1ULL << 7;
inline constexpr uint64_t kTcrEpd1  = 1ULL << 23;
inline constexpr uint64_t kTcrA1    = 1ULL << 22;
inline constexpr uint64_t kTcrTbi0  = 1ULL << 37;
inline constexpr uint64_t kTcrTbi1  = 1ULL << 38;
inline constexpr uint64_t kTcrHa    = 1ULL << 39;
inline constexpr uint64_t kTcrHd    = 1ULL << 40;

MmuFaultStatus TranslationFaultForLevel(int level) {
    switch (level) {
        case 0: return MmuFaultStatus::TranslationL0;
        case 1: return MmuFaultStatus::TranslationL1;
        case 2: return MmuFaultStatus::TranslationL2;
        default: return MmuFaultStatus::TranslationL3;
    }
}

MmuFaultStatus AccessFlagFaultForLevel(int level) {
    switch (level) {
        case 1: return MmuFaultStatus::AccessFlagL1;
        case 2: return MmuFaultStatus::AccessFlagL2;
        default: return MmuFaultStatus::AccessFlagL3;
    }
}

MmuFaultStatus PermissionFaultForLevel(int level) {
    switch (level) {
        case 1: return MmuFaultStatus::PermissionL1;
        case 2: return MmuFaultStatus::PermissionL2;
        default: return MmuFaultStatus::PermissionL3;
    }
}

} // namespace

Arm64Mmu::Arm64Mmu(GuestRam& ram) : ram_(ram) {}

bool Arm64Mmu::IsMmuEnabled(const CpuState& cpu) {
    return (cpu.sys.sctlr_el1 & kSctlrM) != 0;
}

uint16_t Arm64Mmu::CurrentAsid(const CpuState& cpu, uint64_t /*va*/) {
    const uint64_t ttbr = (cpu.sys.tcr_el1 & kTcrA1) ? cpu.sys.ttbr1_el1 : cpu.sys.ttbr0_el1;
    return static_cast<uint16_t>((ttbr >> 48) & 0xFFFFu);
}

void Arm64Mmu::InvalidateAll() {
    ++epoch_;
    if (epoch_ == 0) {
        for (auto& e : tlb_) e.valid = false;
        epoch_ = 1;
    }
}

void Arm64Mmu::InvalidateAsid(uint16_t asid) {
    for (auto& e : tlb_) {
        if (e.valid && !e.global && e.asid == asid) {
            e.valid = false;
        }
    }
}

void Arm64Mmu::InvalidateVa(uint64_t va, bool all_asids, uint16_t asid) {
    // Check both 4K and 16K granularity tags safely by invalidating matching sets
    for (auto& e : tlb_) {
        if (!e.valid) continue;
        if ((va & e.va_page_mask) == (e.va_tag & e.va_page_mask)) {
            if (all_asids || e.global || e.asid == asid) {
                e.valid = false;
            }
        }
    }
}

MmuTranslationResult Arm64Mmu::Translate(CpuState& cpu,
                                         uint64_t va,
                                         MemAccessType access,
                                         bool is_el1_access) {
    if (!IsMmuEnabled(cpu)) {
        MmuTranslationResult res;
        res.ok = true;
        res.phys_addr = va & 0x0000FFFFFFFFFFFFULL;
        res.host_ram_ptr = ram_.HostPtr(res.phys_addr, 1);
        res.writable = true;
        res.executable = true;
        return res;
    }

    const uint16_t asid = CurrentAsid(cpu, va);
    // Probe software TLB (index with 12-bit page shift so both 4K and 16K pages distribute cleanly)
    const size_t idx = static_cast<size_t>((va >> 12) & (kTlbSets - 1u));
    const SoftTlbEntry& e = tlb_[idx];
    if (e.valid && e.epoch == epoch_ && (va & e.va_page_mask) == e.va_tag &&
        (e.global || e.asid == asid)) {
        bool perm_ok = false;
        if (access == MemAccessType::Read) {
            perm_ok = is_el1_access ? (e.el1_readable != 0) : (e.el0_readable != 0);
        } else if (access == MemAccessType::Write) {
            perm_ok = is_el1_access ? (e.el1_writable != 0) : (e.el0_writable != 0);
        } else {
            perm_ok = is_el1_access ? (e.el1_exec != 0) : (e.el0_exec != 0);
        }

        if (perm_ok) {
            ++tlb_hits_;
            const uint64_t page_off = va & ~e.va_page_mask;
            MmuTranslationResult res;
            res.ok = true;
            res.phys_addr = e.pa_page | page_off;
            res.host_ram_ptr = e.host_page_ptr ? (e.host_page_ptr + page_off) : nullptr;
            res.mair_attr = e.mair_attr;
            res.writable = is_el1_access ? (e.el1_writable != 0) : (e.el0_writable != 0);
            res.executable = is_el1_access ? (e.el1_exec != 0) : (e.el0_exec != 0);
            return res;
        }
    }

    ++tlb_misses_;
    return WalkStage1(cpu, va, access, is_el1_access);
}

MmuTranslationResult Arm64Mmu::WalkStage1(CpuState& cpu,
                                          uint64_t va,
                                          MemAccessType access,
                                          bool is_el1_access) {
    MmuTranslationResult fail;
    const uint64_t tcr = cpu.sys.tcr_el1;
    const bool is_upper = (va & (1ULL << 63)) != 0;

    uint32_t t_sz = 0;
    uint32_t tg = 0;
    bool epd = false;
    bool tbi = false;
    uint64_t ttbr = 0;
    uint32_t page_shift = 12;

    if (!is_upper) {
        t_sz = static_cast<uint32_t>(tcr & 0x3Fu);
        epd = (tcr & kTcrEpd0) != 0;
        tbi = (tcr & kTcrTbi0) != 0;
        tg = static_cast<uint32_t>((tcr >> 14) & 3u);
        ttbr = cpu.sys.ttbr0_el1;
        if (tg == 0u) page_shift = 12u;       // 4 KiB
        else if (tg == 2u) page_shift = 14u;  // 16 KiB
        else if (tg == 1u) page_shift = 16u;  // 64 KiB
        else {
            fail.fault_status = MmuFaultStatus::TranslationL0;
            return fail;
        }
    } else {
        t_sz = static_cast<uint32_t>((tcr >> 16) & 0x3Fu);
        epd = (tcr & kTcrEpd1) != 0;
        tbi = (tcr & kTcrTbi1) != 0;
        tg = static_cast<uint32_t>((tcr >> 30) & 3u);
        ttbr = cpu.sys.ttbr1_el1;
        if (tg == 2u) page_shift = 12u;       // 4 KiB
        else if (tg == 1u) page_shift = 14u;  // 16 KiB
        else if (tg == 3u) page_shift = 16u;  // 64 KiB
        else {
            fail.fault_status = MmuFaultStatus::TranslationL0;
            return fail;
        }
    }

    if (epd || t_sz > 39u || t_sz < 16u) {
        fail.fault_status = MmuFaultStatus::TranslationL0;
        return fail;
    }

    const uint32_t ia_bits = 64u - t_sz;
    const uint32_t top_check_msb = tbi ? 55u : 63u;
    if (ia_bits <= top_check_msb) {
        const uint64_t mask = (~0ULL << ia_bits) & ((top_check_msb == 63u) ? ~0ULL : ((1ULL << 56) - 1ULL));
        const uint64_t expected = is_upper ? mask : 0ULL;
        if ((va & mask) != expected) {
            fail.fault_status = MmuFaultStatus::TranslationL0;
            return fail;
        }
    }

    const uint32_t stride = page_shift - 3u; // 9 for 4K, 11 for 16K
    int start_level = 3;
    if (page_shift == 12u) {
        if (ia_bits > 39u) start_level = 0;
        else if (ia_bits > 30u) start_level = 1;
        else if (ia_bits > 21u) start_level = 2;
    } else if (page_shift == 14u) {
        if (ia_bits > 47u) start_level = 0;
        else if (ia_bits > 36u) start_level = 1;
        else if (ia_bits > 25u) start_level = 2;
    } else { // 64K
        if (ia_bits > 42u) start_level = 1;
        else if (ia_bits > 29u) start_level = 2;
    }

    const uint64_t oa_mask = 0x0000FFFFFFFFFFFFULL & ~((1ULL << page_shift) - 1ULL);
    uint64_t table_pa = ttbr & oa_mask;

    // Hierarchical restrictions accumulated from table descriptors
    bool tbl_ap_no_el0 = false;
    bool tbl_ap_ro = false;
    bool tbl_pxn = false;
    bool tbl_uxn = false;

    for (int level = start_level; level <= 3; ++level) {
        const uint32_t lsb = page_shift + static_cast<uint32_t>(3 - level) * stride;
        uint32_t bits_at_level = stride;
        if (level == start_level && ia_bits > lsb) {
            bits_at_level = ia_bits - lsb;
            if (bits_at_level > stride) bits_at_level = stride;
        }
        const uint64_t index = (va >> lsb) & ((1ULL << bits_at_level) - 1ULL);
        const uint64_t desc_pa = table_pa + index * 8ULL;

        uint64_t desc = 0;
        if (!ram_.ReadU64(desc_pa, desc)) {
            fail.fault_status = TranslationFaultForLevel(level);
            return fail;
        }

        const uint64_t type = desc & 3ULL;
        if (type == 0ULL || type == 2ULL) {
            fail.fault_status = TranslationFaultForLevel(level);
            return fail;
        }

        if (level < 3 && type == 3ULL) {
            // Table descriptor
            if (desc & (1ULL << 59)) tbl_pxn = true;
            if (desc & (1ULL << 60)) tbl_uxn = true;
            const uint64_t ap_table = (desc >> 61) & 3ULL;
            if (ap_table & 1ULL) tbl_ap_no_el0 = true;
            if (ap_table & 2ULL) tbl_ap_ro = true;
            table_pa = desc & oa_mask;
            continue;
        }

        // Block descriptor at level 1 or 2 (or page descriptor at level 3)
        if (level == 0 || (level == 3 && type != 3ULL)) {
            fail.fault_status = TranslationFaultForLevel(level);
            return fail;
        }
        if (level == 1 && page_shift != 12u) {
            // 16K/64K granules do not allow L1 blocks in ARMv8.0
            fail.fault_status = TranslationFaultForLevel(level);
            return fail;
        }

        const uint64_t block_size = 1ULL << lsb;
        const uint64_t block_mask = ~(block_size - 1ULL);
        const uint64_t oa_base = desc & (0x0000FFFFFFFFFFFFULL & block_mask);

        // Access Flag (AF = bit 10)
        bool af = (desc & (1ULL << 10)) != 0;
        if (!af) {
            if ((tcr & kTcrHa) != 0) {
                desc |= (1ULL << 10);
                ram_.WriteU64(desc_pa, desc);
                af = true;
            } else {
                fail.fault_status = AccessFlagFaultForLevel(level);
                return fail;
            }
        }

        // AP[2:1] = desc[7:6]
        const uint64_t ap21 = (desc >> 6) & 3ULL;
        bool el0_can_access = (ap21 & 1ULL) != 0 && !tbl_ap_no_el0;
        bool is_ro = ((ap21 & 2ULL) != 0) || tbl_ap_ro;
        const bool dbm = (desc & (1ULL << 51)) != 0;

        // Hardware dirty bit update (HD=1, DBM=1, SW RO=1, no hierarchical RO restriction)
        if (access == MemAccessType::Write && is_ro && dbm && !tbl_ap_ro && (tcr & kTcrHd) != 0) {
            desc &= ~(1ULL << 7); // clear AP[2] to make descriptor writable
            ram_.WriteU64(desc_pa, desc);
            is_ro = false;
        }

        bool el1_read = true;
        bool el1_write = !is_ro;
        bool el0_read = el0_can_access;
        bool el0_write = el0_can_access && !is_ro;

        // PAN check: if PAN=1 at EL1 and AP[1]==1 (EL0 readable), EL1 read/write faults unless AT
        if (is_el1_access && cpu.pstate.pan && el0_can_access && access != MemAccessType::Execute) {
            el1_read = false;
            el1_write = false;
        }

        const bool pxn = ((desc & (1ULL << 53)) != 0) || tbl_pxn;
        const bool uxn = ((desc & (1ULL << 54)) != 0) || tbl_uxn;
        const bool wxn = (cpu.sys.sctlr_el1 & kSctlrWxn) != 0;

        bool el1_exec = !pxn && !(wxn && el1_write);
        if (el0_can_access) {
            // Architectural rule: EL0-writable pages are never executable at EL1
            el1_exec = el1_exec && !el0_write;
        }
        bool el0_exec = el0_can_access && !uxn && !(wxn && el0_write);

        bool perm_ok = false;
        if (access == MemAccessType::Read) {
            perm_ok = is_el1_access ? el1_read : el0_read;
        } else if (access == MemAccessType::Write) {
            perm_ok = is_el1_access ? el1_write : el0_write;
        } else {
            perm_ok = is_el1_access ? el1_exec : el0_exec;
        }

        if (!perm_ok) {
            fail.fault_status = PermissionFaultForLevel(level);
            return fail;
        }

        const uint8_t attr_idx = static_cast<uint8_t>((desc >> 2) & 7ULL);
        const uint8_t mair = static_cast<uint8_t>((cpu.sys.mair_el1 >> (attr_idx * 8u)) & 0xFFu);
        const bool is_global = (desc & (1ULL << 11)) == 0; // nG = 0 => global

        // Populate software TLB using the current granule page size so index stays aligned
        const uint64_t page_size = 1ULL << page_shift;
        const uint64_t va_page_mask = ~(page_size - 1ULL);
        const uint64_t va_page = va & va_page_mask;
        const uint64_t pa_page = oa_base | (va_page & ~block_mask);

        const size_t idx = static_cast<size_t>((va >> 12) & (kTlbSets - 1u));
        SoftTlbEntry& e = tlb_[idx];
        e.va_tag = va_page;
        e.va_page_mask = va_page_mask;
        e.pa_page = pa_page;
        e.host_page_ptr = ram_.HostPtr(pa_page, static_cast<size_t>(page_size));
        e.asid = CurrentAsid(cpu, va);
        e.epoch = epoch_;
        e.el0_readable = el0_read ? 1 : 0;
        e.el0_writable = el0_write ? 1 : 0;
        e.el0_exec = el0_exec ? 1 : 0;
        e.el1_readable = el1_read ? 1 : 0;
        e.el1_writable = el1_write ? 1 : 0;
        e.el1_exec = el1_exec ? 1 : 0;
        e.mair_attr = mair;
        e.global = is_global;
        e.valid = true;

        const uint64_t offset_in_page = va & ~va_page_mask;
        MmuTranslationResult ok;
        ok.ok = true;
        ok.phys_addr = pa_page | offset_in_page;
        ok.host_ram_ptr = e.host_page_ptr ? (e.host_page_ptr + offset_in_page) : nullptr;
        ok.mair_attr = mair;
        ok.writable = is_el1_access ? el1_write : el0_write;
        ok.executable = is_el1_access ? el1_exec : el0_exec;
        return ok;
    }

    fail.fault_status = MmuFaultStatus::TranslationL3;
    return fail;
}

uint64_t Arm64Mmu::AddressTranslateForPar(CpuState& cpu,
                                          uint64_t va,
                                          bool write_perm,
                                          bool el0_stage) {
    MmuTranslationResult r = Translate(
        cpu, va, write_perm ? MemAccessType::Write : MemAccessType::Read, !el0_stage);
    if (!r.ok) {
        // PAR_EL1.F = 1, FST[6:1] = fault status
        return 1ULL | (static_cast<uint64_t>(r.fault_status) << 1);
    }
    // PAR_EL1.F = 0, PA[47:12], ATTR[63:56], SH[8:7] = Inner Shareable (0b11)
    return (r.phys_addr & 0x0000FFFFFFFFF000ULL) |
           (static_cast<uint64_t>(r.mair_attr) << 56) |
           (3ULL << 7);
}

} // namespace haseeb::vm
