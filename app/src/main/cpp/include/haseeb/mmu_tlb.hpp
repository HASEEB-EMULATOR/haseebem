#pragma once

#include "haseeb/cpu_state.hpp"
#include "haseeb/guest_ram.hpp"

#include <array>
#include <cstdint>

namespace haseeb::vm {

enum class MemAccessType : uint8_t {
    Read = 0,
    Write = 1,
    Execute = 2,
};

// ARMv8 Fault Status Code (DFSC / IFSC) for ESR_EL1[5:0]
enum class MmuFaultStatus : uint8_t {
    None              = 0x00,
    AddrSizeL0        = 0x00,
    TranslationL0     = 0x04,
    TranslationL1     = 0x05,
    TranslationL2     = 0x06,
    TranslationL3     = 0x07,
    AccessFlagL1      = 0x09,
    AccessFlagL2      = 0x0A,
    AccessFlagL3      = 0x0B,
    PermissionL1      = 0x0D,
    PermissionL2      = 0x0E,
    PermissionL3      = 0x0F,
    AlignmentFault    = 0x21,
};

struct MmuTranslationResult {
    bool ok = false;
    uint64_t phys_addr = 0;
    uint8_t* host_ram_ptr = nullptr; // Non-null when phys_addr maps directly to GuestRam
    uint8_t mair_attr = 0xFFu;
    bool writable = false;
    bool executable = false;
    MmuFaultStatus fault_status = MmuFaultStatus::None;
};

// Software TLB entry caching a translated guest page (4 KiB or 16 KiB)
struct SoftTlbEntry {
    uint64_t va_tag = 0;        // (va >> 12) ^ ...
    uint64_t va_page_mask = 0;  // ~(page_size - 1)
    uint64_t pa_page = 0;
    uint8_t* host_page_ptr = nullptr; // Null if MMIO or invalid for direct RAM pointer
    uint32_t asid = 0;
    uint32_t epoch = 0;
    uint8_t el0_readable = 0;
    uint8_t el0_writable = 0;
    uint8_t el0_exec = 0;
    uint8_t el1_readable = 0;
    uint8_t el1_writable = 0;
    uint8_t el1_exec = 0;
    uint8_t mair_attr = 0xFFu;
    bool valid = false;
    bool global = false;
};

// ARMv8 Stage-1 MMU supporting 4 KiB and 16 KiB granules, 4-level translation table walk,
// hierarchical table bits, Access Flag (AF) / Dirty Bit Modification (DBM), WXN, ASID, and TLB.
class Arm64Mmu {
public:
    static constexpr size_t kTlbSets = 512;

    explicit Arm64Mmu(GuestRam& ram);

    void InvalidateAll();
    void InvalidateAsid(uint16_t asid);
    void InvalidateVa(uint64_t va, bool all_asids, uint16_t asid);

    // Fast path + table-walk fallback
    MmuTranslationResult Translate(CpuState& cpu,
                                   uint64_t va,
                                   MemAccessType access,
                                   bool is_el1_access);

    // Address translation (AT S1E1R/W, AT S1E0R/W) returning PAR_EL1 value
    uint64_t AddressTranslateForPar(CpuState& cpu,
                                    uint64_t va,
                                    bool write_perm,
                                    bool el0_stage);

    uint64_t TlbHits() const { return tlb_hits_; }
    uint64_t TlbMisses() const { return tlb_misses_; }

private:
    MmuTranslationResult WalkStage1(CpuState& cpu,
                                    uint64_t va,
                                    MemAccessType access,
                                    bool is_el1_access);

    static bool IsMmuEnabled(const CpuState& cpu);
    static uint16_t CurrentAsid(const CpuState& cpu, uint64_t va);

    GuestRam& ram_;
    std::array<SoftTlbEntry, kTlbSets> tlb_{};
    uint32_t epoch_ = 1;
    uint64_t tlb_hits_ = 0;
    uint64_t tlb_misses_ = 0;
};

} // namespace haseeb::vm
