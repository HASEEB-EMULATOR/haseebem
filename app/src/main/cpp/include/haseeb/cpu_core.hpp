#pragma once

#include "haseeb/cpu_state.hpp"
#include "haseeb/dbt_cache.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/mmu_tlb.hpp"
#include "haseeb/vm_types.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <string>

namespace haseeb::vm {

class GicV3;

// Compact recent execution entry for diagnosing early guest traps or non-zero exits
struct InsnTraceEntry {
    uint64_t pc = 0;
    uint32_t insn = 0;
    uint32_t nzcv = 0;
    uint64_t x0 = 0;
    uint64_t x1 = 0;
};

// Hypervisor/Supervisor HVC/SMC callback used by M3 PSCI / Virtio / Paravirt traps
struct HypercallResult {
    bool handled = false;
    bool halt_vm = false;
};

using HypercallHandler = std::function<HypercallResult(CpuState& cpu, uint16_t imm16, bool is_smc)>;

// Complete AArch64 EL0/EL1 CPU core with DBT basic-block cache, 4K/16K stage-1 MMU + TLB,
// full exception/interrupt vectoring, system registers, exclusives/LSE atomics, and NEON/FP.
class AArch64CpuCore {
public:
    static constexpr size_t kInsnTraceSize = 64;

    AArch64CpuCore(GuestRam& ram, MmioBus& mmio_bus, uint32_t cpu_id = 0);

    void Reset(uint64_t entry_pc, uint64_t initial_sp = 0, uint8_t start_el = 1);
    void SetHypercallHandler(HypercallHandler handler) { hvc_handler_ = std::move(handler); }
    void SetGic(GicV3* gic) { gic_ = gic; }
    void EvaluateTimersAndIrqs();

    // Execute up to max_insns guest instructions; returns VmError::Ok on clean halt/budget/WFI,
    // or VmError::ExecutionTrap if an unhandled fatal condition occurs.
    VmError Run(uint64_t max_insns = 1000000ULL);
    void RequestStop() { stop_requested_ = true; }

    // Exception & interrupt entry helpers
    void RaiseException(uint32_t ec, uint32_t iss, uint64_t far_val, bool use_far, uint64_t return_pc);
    void ReturnFromException();
    void DeliverInterrupt(bool is_fiq);

    CpuState& State() { return state_; }
    const CpuState& State() const { return state_; }
    Arm64Mmu& Mmu() { return mmu_; }
    const Arm64Mmu& Mmu() const { return mmu_; }
    TranslationCache& Cache() { return cache_; }
    const TranslationCache& Cache() const { return cache_; }
    std::string DumpRecentTrace(size_t max_entries = 16) const;

private:
    uint64_t ContextTag() const;
    TranslatedBlock* GetOrTranslateBlock(uint64_t guest_va, bool& out_faulted);

    bool ReadMem(uint64_t va, unsigned size_bytes, uint64_t& out_val, bool acquire = false);
    bool WriteMem(uint64_t va, unsigned size_bytes, uint64_t val, bool release = false);
    bool ReadMem128(uint64_t va, uint64_t& lo, uint64_t& hi);
    bool WriteMem128(uint64_t va, uint64_t lo, uint64_t hi);
    bool FetchInsn(uint64_t va, uint32_t& out_insn, uint64_t& out_phys);

    bool EvalCond(uint8_t cond) const;
    void SetFlagsAdd64(uint64_t op1, uint64_t op2, uint64_t res, bool c_in);
    void SetFlagsSub64(uint64_t op1, uint64_t op2, uint64_t res, bool borrow_in);
    void SetFlagsAdd32(uint32_t op1, uint32_t op2, uint32_t res, bool c_in);
    void SetFlagsSub32(uint32_t op1, uint32_t op2, uint32_t res, bool borrow_in);

    bool ExecuteInstruction(const DecodedInsn& insn, uint64_t& next_pc);
    bool ExecuteLoadStoreImm(const DecodedInsn& d);
    bool ExecuteLoadStoreReg(const DecodedInsn& d);
    bool ExecuteLoadStorePair(const DecodedInsn& d);
    bool ExecuteLoadStoreSimdStruct(const DecodedInsn& d);
    bool ExecuteExclusive(const DecodedInsn& d);
    bool ExecuteAtomicLse(const DecodedInsn& d);

    // Implemented in cpu_sysregs.cpp
    bool ExecuteMrs(uint32_t insn);
    bool ExecuteMsrReg(uint32_t insn);
    bool ExecuteMsrImm(uint32_t insn);
    bool ExecuteSysOp(uint32_t insn);
    uint64_t ReadSystemTimerTicks() const;

    // Implemented in cpu_neon.cpp
    bool CheckFpSimdEnabled();
    bool ExecuteFpScalar(uint32_t insn);
    bool ExecuteNeonSimd(uint32_t insn);

    GuestRam& ram_;
    MmioBus& mmio_bus_;
    CpuState state_{};
    Arm64Mmu mmu_;
    TranslationCache cache_;
    GicV3* gic_ = nullptr;
    HypercallHandler hvc_handler_;
    bool stop_requested_ = false;
    std::array<InsnTraceEntry, kInsnTraceSize> trace_ring_{};
    size_t trace_head_ = 0;
    uint64_t trace_total_ = 0;
};

} // namespace haseeb::vm
