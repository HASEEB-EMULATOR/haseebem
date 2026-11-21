#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace haseeb::vm {

// Decoded AArch64 IR categories for translated basic blocks
enum class InsnKind : uint16_t {
    Unmapped = 0,
    NopHint,
    // PC-relative & moves
    Adr,
    Adrp,
    MovWide,      // MOVZ / MOVN / MOVK
    // Integer ALU
    AddSubImm,
    AddSubReg,
    AddSubExt,
    AddSubCarry,
    LogicalImm,
    LogicalReg,
    Bitfield,     // SBFM / BFM / UBFM
    Extract,      // EXTR
    ShiftVar,     // LSLV / LSRV / ASRV / RORV
    Unary1Src,    // CLZ / CLS / RBIT / REV / REV16 / REV32
    MulDiv3Src,   // MADD / MSUB / SMADDL / SMSUBL / SMULH / UMADDL / UMSUBL / UMULH / UDIV / SDIV
    CondSelect,   // CSEL / CSINC / CSINV / CSNEG
    CondCmp,      // CCMP / CCMN (reg & imm)
    // Branches & block terminators
    BranchImm,    // B / BL
    BranchCond,   // B.cond
    CompareBranch,// CBZ / CBNZ
    TestBranch,   // TBZ / TBNZ
    BranchReg,    // BR / BLR / RET
    Eret,
    // Loads & stores
    LoadLiteral,  // LDR / LDRSW / LDR SIMD (PC-rel)
    LoadStoreImm, // pre/post/unscaled/unsigned-offset (GPR + SIMD)
    LoadStoreReg, // register-offset with shift/extend (GPR + SIMD)
    LoadStorePair,// LDP / STP / LDPSW (GPR + SIMD)
    LoadStoreSimdStruct, // AdvSIMD LD1..LD4 / ST1..ST4 / LD1R..LD4R
    Exclusive,    // LDXR / STXR / LDAXR / STLXR / LDXP / STXP / LDAR / STLR / LDAPR
    AtomicLse,    // LDADD / LDCLR / LDEOR / LDSET / SWP / CAS / CASP
    // Barriers & system
    Barrier,      // DSB / DMB / ISB / CLREX
    Svc,
    Hvc,
    Smc,
    Brk,
    Hlt,
    Mrs,
    MsrReg,
    MsrImm,
    SysOp,        // IC / DC / AT / TLBI
    // Scalar FP & Vector NEON
    FpScalar,
    NeonSimd,
};

struct DecodedInsn {
    uint32_t raw = 0;
    InsnKind kind = InsnKind::Unmapped;
    uint8_t rd = 0;
    uint8_t rn = 0;
    uint8_t rm = 0;
    uint8_t ra = 0;
    uint8_t cond = 0;
    bool sf64 = false;
    bool set_flags = false;
    bool is_terminating = false;
    uint64_t imm = 0;
    int64_t simm = 0;
};

struct TranslatedBlock {
    uint64_t guest_va = 0;
    uint64_t phys_pc = 0;
    uint64_t context_tag = 0; // (el << 16) | (mmu_on << 17) | asid
    std::vector<DecodedInsn> insns;
    std::vector<uint64_t> covered_phys_pages; // 4 KiB-granule physical page keys for SMC invalidation
    TranslatedBlock* direct_link[2]{nullptr, nullptr}; // Direct chained targets (taken / fallthrough)
    uint64_t link_va[2]{0, 0};
    uint64_t exec_count = 0;
    bool valid = true;
};

// Decodes AArch64 instructions once per basic block and caches translated blocks
// with direct block chaining and physical-page self-modifying code (SMC) invalidation.
class TranslationCache {
public:
    static constexpr size_t kL1Slots = 4096;
    static constexpr size_t kMaxBlockInsns = 64;
    static constexpr size_t kMaxL2Blocks = 32768;

    TranslationCache();

    static DecodedInsn DecodeOne(uint32_t insn);

    // L1 fast lookup (inlineable hot path)
    TranslatedBlock* LookupL1(uint64_t guest_va, uint64_t context_tag) const {
        const size_t idx = (guest_va >> 2) & (kL1Slots - 1u);
        TranslatedBlock* tb = l1_table_[idx];
        if (tb && tb->valid && tb->guest_va == guest_va && tb->context_tag == context_tag) {
            return tb;
        }
        return nullptr;
    }

    TranslatedBlock* LookupL2(uint64_t guest_va, uint64_t phys_pc, uint64_t context_tag);
    void Insert(std::unique_ptr<TranslatedBlock> block);

    // Self-modifying code & cache maintenance invalidation
    void InvalidatePhysPage(uint64_t phys_addr);
    void InvalidateAll();

    uint64_t Hits() const { return hits_; }
    uint64_t Misses() const { return misses_; }
    uint64_t SmcInvalidations() const { return smc_invalidations_; }

private:
    struct BlockKey {
        uint64_t phys_pc;
        uint64_t guest_va;
        uint64_t context_tag;
        bool operator==(const BlockKey& o) const {
            return phys_pc == o.phys_pc && guest_va == o.guest_va && context_tag == o.context_tag;
        }
    };

    struct BlockKeyHash {
        size_t operator()(const BlockKey& k) const {
            uint64_t h = k.phys_pc * 0x9E3779B97F4A7C15ULL;
            h ^= k.guest_va * 0xBF58476D1CE4E5B9ULL;
            h ^= k.context_tag * 0x94D049BB133111EBULL;
            return static_cast<size_t>(h ^ (h >> 30));
        }
    };

    std::vector<TranslatedBlock*> l1_table_;
    std::unordered_map<BlockKey, std::unique_ptr<TranslatedBlock>, BlockKeyHash> l2_map_;
    // Map from 4 KiB physical page base -> blocks executing code from that page
    std::unordered_map<uint64_t, std::vector<TranslatedBlock*>> phys_page_index_;
    std::unordered_set<uint64_t> active_code_pages_;
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
    uint64_t smc_invalidations_ = 0;
};

} // namespace haseeb::vm
