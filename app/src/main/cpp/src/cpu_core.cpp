#include "haseeb/cpu_core.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace haseeb::vm {

namespace {

int64_t SignExtend(uint64_t v, int bits) {
    uint64_t shift = 64 - bits;
    return static_cast<int64_t>(v << shift) >> shift;
}

uint64_t Ror64(uint64_t val, unsigned r, unsigned width) {
    if (width == 32u) {
        uint32_t v = static_cast<uint32_t>(val);
        r &= 31u;
        return (r == 0u) ? v : ((v >> r) | (v << (32u - r)));
    }
    r &= 63u;
    return (r == 0u) ? val : ((val >> r) | (val << (64u - r)));
}

bool DecodeBitMasks(uint32_t N, uint32_t imms, uint32_t immr, uint32_t reg_size,
                    uint64_t& out_wmask, uint64_t& out_tmask) {
    uint32_t comb = ((N & 1u) << 6) | (~imms & 0x3Fu);
    if (comb == 0u) return false;
    int len = 31 - __builtin_clz(comb);
    if (len < 1) return false;
    uint32_t esize = 1u << len;
    if (esize > reg_size) return false;

    uint32_t levels = esize - 1u;
    uint32_t s = imms & levels;
    uint32_t r = immr & levels;
    uint32_t diff = (s - r) & levels;

    uint64_t welem = (s + 1u == 64u) ? ~0ULL : ((1ULL << (s + 1u)) - 1ULL);
    uint64_t telem = (diff + 1u == 64u) ? ~0ULL : ((1ULL << (diff + 1u)) - 1ULL);

    // Rotate welem right by r within esize
    uint64_t w_rot = 0;
    if (esize == 64u) {
        w_rot = Ror64(welem, r, 64u);
    } else {
        uint64_t mask_e = (1ULL << esize) - 1ULL;
        uint64_t w_e = welem & mask_e;
        w_rot = (r == 0u) ? w_e : (((w_e >> r) | (w_e << (esize - r))) & mask_e);
    }

    auto replicate = [esize](uint64_t pattern) -> uint64_t {
        if (esize == 64u) return pattern;
        uint64_t res = 0;
        for (uint32_t off = 0; off < 64u; off += esize) {
            res |= (pattern << off);
        }
        return res;
    };

    const uint64_t reg_mask = (reg_size == 32u) ? 0xFFFFFFFFULL : ~0ULL;
    out_wmask = replicate(w_rot) & reg_mask;
    out_tmask = replicate(telem) & reg_mask;
    return true;
}

uint64_t ApplyShift(uint64_t val, uint32_t shift_type, uint32_t amount, bool sf64) {
    if (!sf64) {
        uint32_t v = static_cast<uint32_t>(val);
        amount &= 31u;
        if (amount == 0u) return v;
        switch (shift_type) {
            case 0u: return static_cast<uint32_t>(v << amount);
            case 1u: return static_cast<uint32_t>(v >> amount);
            case 2u: return static_cast<uint32_t>(static_cast<int32_t>(v) >> amount);
            case 3u: return static_cast<uint32_t>((v >> amount) | (v << (32u - amount)));
        }
        return v;
    }
    amount &= 63u;
    if (amount == 0u) return val;
    switch (shift_type) {
        case 0u: return val << amount;
        case 1u: return val >> amount;
        case 2u: return static_cast<uint64_t>(static_cast<int64_t>(val) >> amount);
        case 3u: return (val >> amount) | (val << (64u - amount));
    }
    return val;
}

uint64_t ExtendValue(uint64_t val, uint32_t option, uint32_t shift, bool sf64) {
    uint64_t ext = 0;
    switch (option & 7u) {
        case 0u: ext = val & 0xFFULL; break;                                   // UXTB
        case 1u: ext = val & 0xFFFFULL; break;                                 // UXTH
        case 2u: ext = val & 0xFFFFFFFFULL; break;                             // UXTW
        case 3u: ext = val; break;                                             // UXTX
        case 4u: ext = static_cast<uint64_t>(SignExtend(val, 8)); break;       // SXTB
        case 5u: ext = static_cast<uint64_t>(SignExtend(val, 16)); break;      // SXTH
        case 6u: ext = static_cast<uint64_t>(SignExtend(val, 32)); break;      // SXTW
        case 7u: ext = val; break;                                             // SXTX
    }
    uint64_t out = ext << (shift & 7u);
    return sf64 ? out : (out & 0xFFFFFFFFULL);
}

uint32_t ReverseBits32(uint32_t v) {
    v = ((v >> 1) & 0x55555555u) | ((v & 0x55555555u) << 1);
    v = ((v >> 2) & 0x33333333u) | ((v & 0x33333333u) << 2);
    v = ((v >> 4) & 0x0F0F0F0Fu) | ((v & 0x0F0F0F0Fu) << 4);
    v = ((v >> 8) & 0x00FF00FFu) | ((v & 0x00FF00FFu) << 8);
    return (v >> 16) | (v << 16);
}

uint64_t ReverseBits64(uint64_t v) {
    return (static_cast<uint64_t>(ReverseBits32(static_cast<uint32_t>(v))) << 32) |
           ReverseBits32(static_cast<uint32_t>(v >> 32));
}

} // namespace

AArch64CpuCore::AArch64CpuCore(GuestRam& ram, MmioBus& mmio_bus, uint32_t cpu_id)
    : ram_(ram), mmio_bus_(mmio_bus), mmu_(ram) {
    state_.cpu_id = cpu_id;
}

void AArch64CpuCore::Reset(uint64_t entry_pc, uint64_t initial_sp, uint8_t start_el) {
    const uint32_t id = state_.cpu_id;
    state_ = CpuState{};
    state_.cpu_id = id;
    state_.pc = entry_pc;
    state_.pstate.el = start_el & 1u;
    state_.pstate.spsel = true;
    state_.sp_el[0] = initial_sp;
    state_.sp_el[1] = initial_sp;
    mmu_.InvalidateAll();
    cache_.InvalidateAll();
    stop_requested_ = false;
    trace_head_ = 0;
    trace_total_ = 0;
}

std::string AArch64CpuCore::DumpRecentTrace(size_t max_entries) const {
    const size_t count = std::min<size_t>(
        max_entries, static_cast<size_t>(std::min<uint64_t>(trace_total_, kInsnTraceSize)));
    if (count == 0u) return "";
    std::ostringstream oss;
    const size_t start = (trace_head_ + kInsnTraceSize - count) % kInsnTraceSize;
    for (size_t i = 0; i < count; ++i) {
        const InsnTraceEntry& e = trace_ring_[(start + i) % kInsnTraceSize];
        oss << "[TRACE] pc=0x" << std::hex << std::setfill('0') << std::setw(8) << e.pc
            << " op=0x" << std::setw(8) << e.insn
            << " x0=0x" << e.x0
            << " x1=0x" << e.x1
            << " nzcv=0x" << std::setw(1) << (e.nzcv >> 28)
            << "\r\n";
    }
    return oss.str();
}

uint64_t AArch64CpuCore::ContextTag() const {
    const uint64_t ttbr = (state_.sys.tcr_el1 & (1ULL << 22)) ? state_.sys.ttbr1_el1 : state_.sys.ttbr0_el1;
    const uint64_t asid = (ttbr >> 48) & 0xFFFFULL;
    const uint64_t mmu_on = (state_.sys.sctlr_el1 & 1ULL);
    return asid | (static_cast<uint64_t>(state_.pstate.el) << 16) | (mmu_on << 17);
}

bool AArch64CpuCore::EvalCond(uint8_t cond) const {
    const bool n = state_.pstate.n;
    const bool z = state_.pstate.z;
    const bool c = state_.pstate.c;
    const bool v = state_.pstate.v;
    bool res = false;
    switch (cond >> 1) {
        case 0: res = z; break;                 // EQ / NE
        case 1: res = c; break;                 // CS / CC
        case 2: res = n; break;                 // MI / PL
        case 3: res = v; break;                 // VS / VC
        case 4: res = c && !z; break;           // HI / LS
        case 5: res = (n == v); break;          // GE / LT
        case 6: res = (n == v) && !z; break;    // GT / LE
        case 7: res = true; break;              // AL / NV
    }
    return ((cond & 1u) != 0 && (cond >> 1) != 7u) ? !res : res;
}

void AArch64CpuCore::SetFlagsAdd64(uint64_t op1, uint64_t op2, uint64_t res, bool c_in) {
    state_.pstate.n = (res >> 63) != 0;
    state_.pstate.z = (res == 0);
    unsigned __int128 sum = static_cast<unsigned __int128>(op1) + op2 + (c_in ? 1u : 0u);
    state_.pstate.c = (sum >> 64) != 0;
    state_.pstate.v = (((op1 ^ ~op2) & (op1 ^ res)) >> 63) != 0;
}

void AArch64CpuCore::SetFlagsSub64(uint64_t op1, uint64_t op2, uint64_t res, bool c_in) {
    // ARM64 SUBS/SBC computes op1 + ~op2 + c_in (where c_in = 1 for normal SUBS, PSTATE.C for SBC)
    SetFlagsAdd64(op1, ~op2, res, c_in);
}

void AArch64CpuCore::SetFlagsAdd32(uint32_t op1, uint32_t op2, uint32_t res, bool c_in) {
    state_.pstate.n = (res >> 31) != 0;
    state_.pstate.z = (res == 0);
    uint64_t sum = static_cast<uint64_t>(op1) + op2 + (c_in ? 1u : 0u);
    state_.pstate.c = (sum >> 32) != 0;
    state_.pstate.v = (((op1 ^ ~op2) & (op1 ^ res)) >> 31) != 0;
}

void AArch64CpuCore::SetFlagsSub32(uint32_t op1, uint32_t op2, uint32_t res, bool c_in) {
    SetFlagsAdd32(op1, ~op2, res, c_in);
}

void AArch64CpuCore::RaiseException(uint32_t ec_val,
                                    uint32_t iss,
                                    uint64_t far_val,
                                    bool use_far,
                                    uint64_t return_pc) {
    const uint8_t from_el = state_.pstate.el;
    const bool from_spsel = state_.pstate.spsel;

    state_.sys.spsr_el1 = state_.pstate.PackSpsr();
    state_.sys.elr_el1 = return_pc;
    state_.sys.esr_el1 = (static_cast<uint64_t>(ec_val & 0x3Fu) << 26) |
                         (1ULL << 25) | // IL = 1 (32-bit instruction)
                         (static_cast<uint64_t>(iss) & 0x1FFFFFFULL);
    if (use_far) {
        state_.sys.far_el1 = far_val;
    }

    state_.excl.valid = false;
    state_.pstate.el = 1;
    state_.pstate.spsel = true;
    state_.pstate.d = true;
    state_.pstate.a = true;
    state_.pstate.i = true;
    state_.pstate.f = true;
    state_.waiting_for_interrupt = false;
    ++state_.exceptions_taken;

    uint64_t vector_offset = 0x000ULL;
    if (from_el == 0) {
        vector_offset = 0x400ULL; // Lower EL using AArch64 -> Synchronous
    } else if (from_spsel) {
        vector_offset = 0x200ULL; // Current EL with SPx -> Synchronous
    }
    state_.pc = state_.sys.vbar_el1 + vector_offset;
}

void AArch64CpuCore::DeliverInterrupt(bool is_fiq) {
    if (is_fiq && state_.pstate.f) return;
    if (!is_fiq && state_.pstate.i) return;

    const uint8_t from_el = state_.pstate.el;
    const bool from_spsel = state_.pstate.spsel;

    state_.sys.spsr_el1 = state_.pstate.PackSpsr();
    state_.sys.elr_el1 = state_.pc;
    state_.excl.valid = false;
    state_.pstate.el = 1;
    state_.pstate.spsel = true;
    state_.pstate.d = true;
    state_.pstate.a = true;
    state_.pstate.i = true;
    state_.pstate.f = true;
    state_.waiting_for_interrupt = false;
    ++state_.exceptions_taken;

    uint64_t base_off = (from_el == 0) ? 0x400ULL : (from_spsel ? 0x200ULL : 0x000ULL);
    uint64_t type_off = is_fiq ? 0x100ULL : 0x080ULL;
    state_.pc = state_.sys.vbar_el1 + base_off + type_off;
}

void AArch64CpuCore::ReturnFromException() {
    state_.excl.valid = false;
    state_.pstate.UnpackSpsr(static_cast<uint32_t>(state_.sys.spsr_el1));
    state_.pc = state_.sys.elr_el1;
}

TranslatedBlock* AArch64CpuCore::GetOrTranslateBlock(uint64_t guest_va, bool& out_faulted) {
    out_faulted = false;
    const uint64_t tag = ContextTag();
    if (TranslatedBlock* l1 = cache_.LookupL1(guest_va, tag)) {
        return l1;
    }

    uint32_t first_raw = 0;
    uint64_t first_phys = 0;
    if (!FetchInsn(guest_va, first_raw, first_phys)) {
        out_faulted = true;
        return nullptr;
    }

    if (TranslatedBlock* l2 = cache_.LookupL2(guest_va, first_phys, tag)) {
        return l2;
    }

    auto tb = std::make_unique<TranslatedBlock>();
    tb->guest_va = guest_va;
    tb->phys_pc = first_phys;
    tb->context_tag = tag;

    uint64_t cur_va = guest_va;
    for (size_t i = 0; i < TranslationCache::kMaxBlockInsns; ++i) {
        uint32_t raw = first_raw;
        uint64_t phys = first_phys;
        if (i > 0) {
            // Do not fetch instructions across an unknown page boundary speculatively if faulted
            if (!FetchInsn(cur_va, raw, phys)) {
                if (tb->insns.empty()) {
                    out_faulted = true;
                    return nullptr;
                }
                break;
            }
        }
        const uint64_t page_base = phys & ~0xFFFULL;
        if (std::find(tb->covered_phys_pages.begin(), tb->covered_phys_pages.end(), page_base) ==
            tb->covered_phys_pages.end()) {
            tb->covered_phys_pages.push_back(page_base);
        }

        DecodedInsn dec = TranslationCache::DecodeOne(raw);
        tb->insns.push_back(dec);
        cur_va += 4ULL;
        if (dec.is_terminating) {
            break;
        }
    }

    TranslatedBlock* raw_ptr = tb.get();
    cache_.Insert(std::move(tb));
    return raw_ptr;
}

VmError AArch64CpuCore::Run(uint64_t max_insns) {
    stop_requested_ = false;
    state_.stop_reason = CpuStopReason::None;
    const uint64_t start_count = state_.instructions_executed;
    TranslatedBlock* prev_tb = nullptr;
    int prev_link_slot = -1;
    uint32_t consecutive_fetch_faults = 0u;

    while (!state_.halted && !stop_requested_ &&
           (state_.instructions_executed - start_count) < max_insns) {
        EvaluateTimersAndIrqs();
        if (state_.waiting_for_interrupt && (state_.pending_irq || state_.pending_fiq)) {
            state_.waiting_for_interrupt = false;
        }
        if (state_.pending_fiq && !state_.pstate.f) {
            DeliverInterrupt(true);
            prev_tb = nullptr;
        } else if (state_.pending_irq && !state_.pstate.i) {
            DeliverInterrupt(false);
            prev_tb = nullptr;
        }

        if (state_.waiting_for_interrupt) {
            state_.stop_reason = CpuStopReason::WfiWait;
            return VmError::Ok;
        }

        const uint64_t tag = ContextTag();
        TranslatedBlock* tb = nullptr;
        if (prev_tb && prev_tb->valid && prev_link_slot >= 0) {
            TranslatedBlock* chained = prev_tb->direct_link[prev_link_slot];
            if (chained && chained->valid && chained->guest_va == state_.pc && chained->context_tag == tag) {
                tb = chained;
            }
        }

        if (!tb) {
            bool faulted = false;
            tb = GetOrTranslateBlock(state_.pc, faulted);
            if (!tb) {
                prev_tb = nullptr;
                if (faulted) {
                    if (++consecutive_fetch_faults >= 4u) {
                        state_.stop_reason = CpuStopReason::MemoryFault;
                        return VmError::ExecutionTrap;
                    }
                    continue; // Exception handler placed new PC (unless halted)
                }
                state_.stop_reason = CpuStopReason::MemoryFault;
                return VmError::ExecutionTrap;
            }
            if (prev_tb && prev_tb->valid && prev_link_slot >= 0 &&
                prev_tb->link_va[prev_link_slot] == tb->guest_va &&
                prev_tb->context_tag == tb->context_tag) {
                prev_tb->direct_link[prev_link_slot] = tb;
            }
        }
        consecutive_fetch_faults = 0u;

        ++tb->exec_count;
        int exit_slot = 0;
        bool block_interrupted = false;

        for (size_t i = 0; i < tb->insns.size(); ++i) {
            const DecodedInsn insn = tb->insns[i];
            const size_t tb_len = tb->insns.size();
            const uint64_t tb_va = tb->guest_va;
            trace_ring_[trace_head_] = InsnTraceEntry{
                state_.pc, insn.raw, state_.pstate.PackNzcv(), state_.x[0], state_.x[1]};
            trace_head_ = (trace_head_ + 1u) % kInsnTraceSize;
            ++trace_total_;
            uint64_t next_pc = state_.pc + 4ULL;
            const bool ok = ExecuteInstruction(insn, next_pc);
            ++state_.instructions_executed;

            if (!ok) {
                // Exception, ERET, HLT, WFI, or fatal trap altered PC/state directly
                block_interrupted = true;
                if (state_.stop_reason == CpuStopReason::TrapUnhandled) {
                    return VmError::ExecutionTrap;
                }
                break;
            }
            state_.pc = next_pc;

            // Hypercalls / SysOps (like execve address-space reset or IC IALLU) may invalidate tb
            if (insn.kind == InsnKind::Hvc || insn.kind == InsnKind::Smc ||
                insn.kind == InsnKind::SysOp) {
                block_interrupted = true;
                break;
            }

            if (insn.kind == InsnKind::BranchCond || insn.kind == InsnKind::CompareBranch ||
                insn.kind == InsnKind::TestBranch) {
                const uint64_t taken_pc = tb_va + i * 4ULL + static_cast<uint64_t>(insn.simm);
                exit_slot = (next_pc == taken_pc) ? 1 : 0;
                tb->link_va[exit_slot] = next_pc;
            } else if (insn.kind == InsnKind::BranchImm && !insn.set_flags) {
                exit_slot = 0;
                tb->link_va[0] = next_pc;
            } else if (i + 1u == tb_len) {
                exit_slot = (insn.kind == InsnKind::BranchReg || insn.is_terminating) ? -1 : 0;
                if (exit_slot == 0) tb->link_va[0] = next_pc;
            }

            if ((state_.instructions_executed - start_count) >= max_insns) {
                break;
            }
        }

        if (block_interrupted) {
            prev_tb = nullptr;
            prev_link_slot = -1;
        } else {
            prev_tb = tb;
            prev_link_slot = exit_slot;
        }
    }

    if (state_.halted) {
        state_.stop_reason = CpuStopReason::Halted;
    } else if (state_.stop_reason == CpuStopReason::None) {
        state_.stop_reason = CpuStopReason::StepBudgetExhausted;
    }
    return VmError::Ok;
}

bool AArch64CpuCore::ExecuteInstruction(const DecodedInsn& d, uint64_t& next_pc) {
    const uint32_t insn = d.raw;

    switch (d.kind) {
        case InsnKind::NopHint: {
            if (d.imm == 3u) { // WFI
                state_.pc += 4ULL;
                state_.waiting_for_interrupt = true;
                return false;
            }
            return true;
        }

        case InsnKind::Barrier: {
            if ((insn & 0xFFFFF0FFu) == 0xD503305Fu) {
                state_.excl.valid = false; // CLREX
            }
            return true;
        }

        case InsnKind::Adr: {
            uint64_t res = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::Adrp: {
            uint64_t page = state_.pc & ~0xFFFULL;
            uint64_t res = static_cast<uint64_t>(static_cast<int64_t>(page) + d.simm);
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::MovWide: {
            const uint32_t shift = d.rm * 16u;
            uint64_t val = 0;
            if (d.cond == 2u) { // MOVZ
                val = d.imm << shift;
            } else if (d.cond == 0u) { // MOVN
                val = ~(d.imm << shift);
            } else if (d.cond == 3u) { // MOVK
                uint64_t cur = state_.ReadRegOrZero(d.rd);
                val = (cur & ~(0xFFFFULL << shift)) | (d.imm << shift);
            }
            if (!d.sf64) val &= 0xFFFFFFFFULL;
            state_.WriteRegOrDiscard(d.rd, val);
            return true;
        }

        case InsnKind::AddSubImm: {
            const uint64_t op1 = state_.ReadRegOrSp(d.rn);
            const uint64_t op2 = d.imm;
            const bool is_sub = (d.cond != 0);
            if (d.sf64) {
                uint64_t res = is_sub ? (op1 - op2) : (op1 + op2);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub64(op1, op2, res, true);
                    else SetFlagsAdd64(op1, op2, res, false);
                    state_.WriteRegOrDiscard(d.rd, res);
                } else {
                    state_.WriteRegOrSp(d.rd, res);
                }
            } else {
                uint32_t a = static_cast<uint32_t>(op1);
                uint32_t b = static_cast<uint32_t>(op2);
                uint32_t res = is_sub ? (a - b) : (a + b);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub32(a, b, res, true);
                    else SetFlagsAdd32(a, b, res, false);
                    state_.WriteRegOrDiscard(d.rd, res);
                } else {
                    state_.WriteRegOrSp(d.rd, res);
                }
            }
            return true;
        }

        case InsnKind::AddSubReg: {
            const uint32_t shift_type = (insn >> 22) & 3u;
            const uint32_t imm6 = (insn >> 10) & 0x3Fu;
            const uint64_t op1 = state_.ReadRegOrZero(d.rn);
            const uint64_t op2 = ApplyShift(state_.ReadRegOrZero(d.rm), shift_type, imm6, d.sf64);
            const bool is_sub = (d.cond != 0);
            if (d.sf64) {
                uint64_t res = is_sub ? (op1 - op2) : (op1 + op2);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub64(op1, op2, res, true);
                    else SetFlagsAdd64(op1, op2, res, false);
                }
                state_.WriteRegOrDiscard(d.rd, res);
            } else {
                uint32_t a = static_cast<uint32_t>(op1);
                uint32_t b = static_cast<uint32_t>(op2);
                uint32_t res = is_sub ? (a - b) : (a + b);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub32(a, b, res, true);
                    else SetFlagsAdd32(a, b, res, false);
                }
                state_.WriteRegOrDiscard(d.rd, res);
            }
            return true;
        }

        case InsnKind::AddSubExt: {
            const uint32_t option = (insn >> 13) & 7u;
            const uint32_t imm3 = (insn >> 10) & 7u;
            const uint64_t op1 = state_.ReadRegOrSp(d.rn);
            const uint64_t op2 = ExtendValue(state_.ReadRegOrZero(d.rm), option, imm3, d.sf64);
            const bool is_sub = (d.cond != 0);
            if (d.sf64) {
                uint64_t res = is_sub ? (op1 - op2) : (op1 + op2);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub64(op1, op2, res, true);
                    else SetFlagsAdd64(op1, op2, res, false);
                    state_.WriteRegOrDiscard(d.rd, res);
                } else {
                    state_.WriteRegOrSp(d.rd, res);
                }
            } else {
                uint32_t a = static_cast<uint32_t>(op1);
                uint32_t b = static_cast<uint32_t>(op2);
                uint32_t res = is_sub ? (a - b) : (a + b);
                if (d.set_flags) {
                    if (is_sub) SetFlagsSub32(a, b, res, true);
                    else SetFlagsAdd32(a, b, res, false);
                    state_.WriteRegOrDiscard(d.rd, res);
                } else {
                    state_.WriteRegOrSp(d.rd, res);
                }
            }
            return true;
        }

        case InsnKind::AddSubCarry: {
            const bool is_sub = ((insn >> 30) & 1u) != 0;
            const bool set_flags = ((insn >> 29) & 1u) != 0;
            const uint64_t op1 = state_.ReadRegOrZero(d.rn);
            const uint64_t op2 = state_.ReadRegOrZero(d.rm);
            const uint64_t c_in = state_.pstate.c ? 1ULL : 0ULL;
            if (d.sf64) {
                uint64_t b = is_sub ? ~op2 : op2;
                uint64_t res = op1 + b + c_in;
                if (set_flags) SetFlagsAdd64(op1, b, res, state_.pstate.c);
                state_.WriteRegOrDiscard(d.rd, res);
            } else {
                uint32_t a = static_cast<uint32_t>(op1);
                uint32_t b = is_sub ? ~static_cast<uint32_t>(op2) : static_cast<uint32_t>(op2);
                uint32_t res = a + b + static_cast<uint32_t>(c_in);
                if (set_flags) SetFlagsAdd32(a, b, res, state_.pstate.c);
                state_.WriteRegOrDiscard(d.rd, res);
            }
            return true;
        }

        case InsnKind::LogicalImm: {
            const uint32_t N = (insn >> 22) & 1u;
            const uint32_t immr = (insn >> 16) & 0x3Fu;
            const uint32_t imms = (insn >> 10) & 0x3Fu;
            uint64_t wmask = 0, tmask = 0;
            if (!DecodeBitMasks(N, imms, immr, d.sf64 ? 64u : 32u, wmask, tmask)) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            uint64_t op1 = state_.ReadRegOrZero(d.rn);
            uint64_t res = 0;
            switch (d.cond) {
                case 0u: res = op1 & wmask; break;
                case 1u: res = op1 | wmask; break;
                case 2u: res = op1 ^ wmask; break;
                case 3u: res = op1 & wmask; break;
            }
            if (!d.sf64) res &= 0xFFFFFFFFULL;
            if (d.set_flags) {
                state_.pstate.n = d.sf64 ? ((res >> 63) != 0) : (((res >> 31) & 1u) != 0);
                state_.pstate.z = (res == 0);
                state_.pstate.c = false;
                state_.pstate.v = false;
                state_.WriteRegOrDiscard(d.rd, res);
            } else {
                state_.WriteRegOrSp(d.rd, res);
            }
            return true;
        }

        case InsnKind::LogicalReg: {
            const uint32_t opc = (insn >> 29) & 3u;
            const uint32_t shift_type = (insn >> 22) & 3u;
            const bool invert_n = ((insn >> 21) & 1u) != 0;
            const uint32_t imm6 = (insn >> 10) & 0x3Fu;
            uint64_t op1 = state_.ReadRegOrZero(d.rn);
            uint64_t op2 = ApplyShift(state_.ReadRegOrZero(d.rm), shift_type, imm6, d.sf64);
            if (invert_n) op2 = ~op2;
            uint64_t res = 0;
            if (opc == 0u || opc == 3u) res = op1 & op2;
            else if (opc == 1u) res = op1 | op2;
            else res = op1 ^ op2;
            if (!d.sf64) res &= 0xFFFFFFFFULL;
            if (opc == 3u) {
                state_.pstate.n = d.sf64 ? ((res >> 63) != 0) : (((res >> 31) & 1u) != 0);
                state_.pstate.z = (res == 0);
                state_.pstate.c = false;
                state_.pstate.v = false;
            }
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::Bitfield: {
            const uint32_t N = (insn >> 22) & 1u;
            const uint32_t immr = (insn >> 16) & 0x3Fu;
            const uint32_t imms = (insn >> 10) & 0x3Fu;
            const uint32_t reg_size = d.sf64 ? 64u : 32u;
            uint64_t wmask = 0, tmask = 0;
            if (!DecodeBitMasks(N, imms, immr, reg_size, wmask, tmask)) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            uint64_t src = state_.ReadRegOrZero(d.rn);
            if (!d.sf64) src &= 0xFFFFFFFFULL;
            uint64_t bot = Ror64(src, immr, reg_size) & wmask;
            uint64_t res = 0;
            if (d.cond == 2u) { // UBFM
                res = bot & tmask;
            } else if (d.cond == 0u) { // SBFM
                uint64_t sbit = (src >> (imms & (reg_size - 1u))) & 1ULL;
                uint64_t top = sbit ? ~0ULL : 0ULL;
                res = (top & ~tmask) | (bot & tmask);
            } else { // BFM
                uint64_t dst = state_.ReadRegOrZero(d.rd);
                res = (dst & ~(wmask & tmask)) | (bot & tmask);
            }
            if (!d.sf64) res &= 0xFFFFFFFFULL;
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::Extract: {
            const uint32_t lsb = static_cast<uint32_t>(d.imm);
            uint64_t hi = state_.ReadRegOrZero(d.rn);
            uint64_t lo = state_.ReadRegOrZero(d.rm);
            uint64_t res = 0;
            if (d.sf64) {
                res = (lsb == 0u) ? lo : ((lo >> lsb) | (hi << (64u - lsb)));
            } else {
                uint32_t h32 = static_cast<uint32_t>(hi);
                uint32_t l32 = static_cast<uint32_t>(lo);
                uint32_t s = lsb & 31u;
                res = (s == 0u) ? l32 : ((l32 >> s) | (h32 << (32u - s)));
            }
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::ShiftVar: {
            const uint32_t opcode = (insn >> 10) & 0x3Fu;
            if ((opcode & 0x38u) == 0x10u) {
                const bool is_crc32c = (opcode & 4u) != 0u;
                const uint32_t sz = opcode & 3u;
                if (sz == 3u && !d.sf64) {
                    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                    return false;
                }
                const uint32_t poly = is_crc32c ? 0x82F63B78u : 0xEDB88320u;
                uint32_t crc = static_cast<uint32_t>(state_.ReadRegOrZero(d.rn));
                const uint64_t val = state_.ReadRegOrZero(d.rm);
                const uint32_t nbits = 8u << sz;
                for (uint32_t b = 0; b < nbits; ++b) {
                    const uint32_t bit = static_cast<uint32_t>((val >> b) & 1ULL);
                    const uint32_t lsb = (crc ^ bit) & 1u;
                    crc >>= 1;
                    if (lsb) crc ^= poly;
                }
                state_.WriteRegOrDiscard(d.rd, static_cast<uint64_t>(crc));
                return true;
            }
            const uint32_t op2 = opcode & 3u; // 0=LSL, 1=LSR, 2=ASR, 3=ROR
            const uint32_t amt = static_cast<uint32_t>(state_.ReadRegOrZero(d.rm));
            uint64_t res = ApplyShift(state_.ReadRegOrZero(d.rn), op2, amt, d.sf64);
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::Unary1Src: {
            const uint32_t opcode = (insn >> 10) & 0x3Fu;
            const uint64_t src = state_.ReadRegOrZero(d.rn);
            uint64_t res = 0;
            if (d.sf64) {
                switch (opcode) {
                    case 0u: res = ReverseBits64(src); break;
                    case 1u: // REV16
                        res = ((src & 0x00FF00FF00FF00FFULL) << 8) | ((src & 0xFF00FF00FF00FF00ULL) >> 8);
                        break;
                    case 2u: // REV32
                        res = (static_cast<uint64_t>(__builtin_bswap32(static_cast<uint32_t>(src >> 32))) << 32) |
                              __builtin_bswap32(static_cast<uint32_t>(src));
                        break;
                    case 3u: res = __builtin_bswap64(src); break;
                    case 4u: res = (src == 0ULL) ? 64ULL : static_cast<uint64_t>(__builtin_clzll(src)); break;
                    case 5u: {
                        uint64_t x = ((src >> 63) ? ~src : src) << 1;
                        res = (x == 0ULL) ? 63ULL : static_cast<uint64_t>(__builtin_clzll(x));
                        break;
                    }
                }
            } else {
                uint32_t v = static_cast<uint32_t>(src);
                switch (opcode) {
                    case 0u: res = ReverseBits32(v); break;
                    case 1u: res = ((v & 0x00FF00FFu) << 8) | ((v & 0xFF00FF00u) >> 8); break;
                    case 2u: res = __builtin_bswap32(v); break;
                    case 4u: res = (v == 0u) ? 32u : static_cast<uint32_t>(__builtin_clz(v)); break;
                    case 5u: {
                        uint32_t x = ((v >> 31) ? ~v : v) << 1;
                        res = (x == 0u) ? 31u : static_cast<uint32_t>(__builtin_clz(x));
                        break;
                    }
                }
            }
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::MulDiv3Src: {
            if ((insn & 0x1FE00000u) == 0x1AC00000u) {
                // UDIV / SDIV
                const bool is_sdiv = ((insn >> 10) & 1u) != 0;
                const uint64_t a = state_.ReadRegOrZero(d.rn);
                const uint64_t b = state_.ReadRegOrZero(d.rm);
                uint64_t res = 0;
                if (d.sf64) {
                    if (b != 0ULL) {
                        if (is_sdiv) {
                            int64_t sa = static_cast<int64_t>(a);
                            int64_t sb = static_cast<int64_t>(b);
                            res = (sa == INT64_MIN && sb == -1) ? static_cast<uint64_t>(INT64_MIN)
                                                                : static_cast<uint64_t>(sa / sb);
                        } else {
                            res = a / b;
                        }
                    }
                } else {
                    uint32_t u32a = static_cast<uint32_t>(a);
                    uint32_t u32b = static_cast<uint32_t>(b);
                    if (u32b != 0u) {
                        if (is_sdiv) {
                            int32_t sa = static_cast<int32_t>(u32a);
                            int32_t sb = static_cast<int32_t>(u32b);
                            res = (sa == INT32_MIN && sb == -1) ? static_cast<uint32_t>(INT32_MIN)
                                                                : static_cast<uint32_t>(sa / sb);
                        } else {
                            res = u32a / u32b;
                        }
                    }
                }
                state_.WriteRegOrDiscard(d.rd, res);
                return true;
            }
            const uint32_t op31 = (insn >> 21) & 7u;
            const bool o0 = ((insn >> 15) & 1u) != 0;
            const uint64_t rn_v = state_.ReadRegOrZero(d.rn);
            const uint64_t rm_v = state_.ReadRegOrZero(d.rm);
            const uint64_t ra_v = state_.ReadRegOrZero(d.ra);
            uint64_t res = 0;
            if (op31 == 0u) { // MADD / MSUB
                if (d.sf64) res = o0 ? (ra_v - rn_v * rm_v) : (ra_v + rn_v * rm_v);
                else res = static_cast<uint32_t>(o0 ? (ra_v - rn_v * rm_v) : (ra_v + rn_v * rm_v));
            } else if (op31 == 1u) { // SMADDL / SMSUBL
                int64_t prod = static_cast<int64_t>(static_cast<int32_t>(rn_v)) *
                               static_cast<int64_t>(static_cast<int32_t>(rm_v));
                res = o0 ? static_cast<uint64_t>(static_cast<int64_t>(ra_v) - prod)
                         : static_cast<uint64_t>(static_cast<int64_t>(ra_v) + prod);
            } else if (op31 == 2u) { // SMULH
                __int128 prod = static_cast<__int128>(static_cast<int64_t>(rn_v)) *
                                static_cast<__int128>(static_cast<int64_t>(rm_v));
                res = static_cast<uint64_t>(static_cast<unsigned __int128>(prod) >> 64);
            } else if (op31 == 5u) { // UMADDL / UMSUBL
                uint64_t prod = static_cast<uint64_t>(static_cast<uint32_t>(rn_v)) *
                                static_cast<uint64_t>(static_cast<uint32_t>(rm_v));
                res = o0 ? (ra_v - prod) : (ra_v + prod);
            } else if (op31 == 6u) { // UMULH
                unsigned __int128 prod = static_cast<unsigned __int128>(rn_v) *
                                         static_cast<unsigned __int128>(rm_v);
                res = static_cast<uint64_t>(prod >> 64);
            }
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::CondSelect: {
            const uint8_t cond = static_cast<uint8_t>((insn >> 12) & 0xFu);
            const bool else_inv = ((insn >> 30) & 1u) != 0;
            const bool else_inc = ((insn >> 10) & 1u) != 0;
            uint64_t res = 0;
            if (EvalCond(cond)) {
                res = state_.ReadRegOrZero(d.rn);
            } else {
                res = state_.ReadRegOrZero(d.rm);
                if (else_inv) res = ~res;
                if (else_inc) res += 1ULL;
            }
            if (!d.sf64) res &= 0xFFFFFFFFULL;
            state_.WriteRegOrDiscard(d.rd, res);
            return true;
        }

        case InsnKind::CondCmp: {
            const uint8_t cond = static_cast<uint8_t>((insn >> 12) & 0xFu);
            const uint32_t nzcv = static_cast<uint32_t>(insn & 0xFu) << 28;
            const bool is_ccmn = ((insn >> 30) & 1u) == 0;
            const bool is_imm = ((insn >> 11) & 1u) != 0;
            if (!EvalCond(cond)) {
                state_.pstate.UnpackNzcv(nzcv);
                return true;
            }
            uint64_t op1 = state_.ReadRegOrZero(d.rn);
            uint64_t op2 = is_imm ? static_cast<uint64_t>((insn >> 16) & 0x1Fu) : state_.ReadRegOrZero(d.rm);
            if (d.sf64) {
                if (is_ccmn) SetFlagsAdd64(op1, op2, op1 + op2, false);
                else SetFlagsSub64(op1, op2, op1 - op2, true);
            } else {
                uint32_t a = static_cast<uint32_t>(op1);
                uint32_t b = static_cast<uint32_t>(op2);
                if (is_ccmn) SetFlagsAdd32(a, b, a + b, false);
                else SetFlagsSub32(a, b, a - b, true);
            }
            return true;
        }

        case InsnKind::BranchImm: {
            if (d.set_flags) {
                state_.x[30] = state_.pc + 4ULL; // BL
            }
            next_pc = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            return true;
        }

        case InsnKind::BranchCond: {
            if (EvalCond(d.cond)) {
                next_pc = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            }
            return true;
        }

        case InsnKind::CompareBranch: {
            uint64_t val = state_.ReadRegOrZero(d.rd);
            if (!d.sf64) val &= 0xFFFFFFFFULL;
            const bool taken = (d.cond == 0u) ? (val == 0ULL) : (val != 0ULL);
            if (taken) {
                next_pc = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            }
            return true;
        }

        case InsnKind::TestBranch: {
            uint64_t val = state_.ReadRegOrZero(d.rd);
            bool bit = ((val >> d.imm) & 1ULL) != 0;
            const bool taken = (d.cond == 0u) ? !bit : bit;
            if (taken) {
                next_pc = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            }
            return true;
        }

        case InsnKind::BranchReg: {
            uint64_t target = state_.ReadRegOrZero(d.rn);
            if (d.cond == 1u) { // BLR
                state_.x[30] = state_.pc + 4ULL;
            }
            next_pc = target;
            return true;
        }

        case InsnKind::Eret: {
            if (state_.pstate.el == 0) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            ReturnFromException();
            return false; // PC already restored to ELR_EL1
        }

        case InsnKind::LoadLiteral: {
            const uint32_t opc = (insn >> 30) & 3u;
            const bool v_simd = ((insn >> 26) & 1u) != 0;
            const uint64_t addr = static_cast<uint64_t>(static_cast<int64_t>(state_.pc) + d.simm);
            if (v_simd) {
                if (!CheckFpSimdEnabled()) return false;
                uint32_t bytes = (opc == 0u) ? 4u : ((opc == 1u) ? 8u : 16u);
                state_.v[d.rd] = NeonReg{};
                if (bytes == 16u) return ReadMem128(addr, state_.v[d.rd].u64[0], state_.v[d.rd].u64[1]);
                return ReadMem(addr, bytes, state_.v[d.rd].u64[0], false);
            }
            if (opc == 3u) return true; // PRFM literal hint (no-op)
            uint32_t bytes = (opc == 1u) ? 8u : 4u;
            uint64_t val = 0;
            if (!ReadMem(addr, bytes, val, false)) return false;
            if (opc == 2u) val = static_cast<uint64_t>(SignExtend(val, 32));
            state_.WriteRegOrDiscard(d.rd, val);
            return true;
        }

        case InsnKind::LoadStoreImm:        return ExecuteLoadStoreImm(d);
        case InsnKind::LoadStoreReg:        return ExecuteLoadStoreReg(d);
        case InsnKind::LoadStorePair:       return ExecuteLoadStorePair(d);
        case InsnKind::LoadStoreSimdStruct: return ExecuteLoadStoreSimdStruct(d);
        case InsnKind::Exclusive:           return ExecuteExclusive(d);
        case InsnKind::AtomicLse:      return ExecuteAtomicLse(d);

        case InsnKind::Svc: {
            RaiseException(ec::kSvc64, static_cast<uint32_t>(d.imm), 0, false, state_.pc + 4ULL);
            return false;
        }

        case InsnKind::Hvc: {
            if (state_.pstate.el == 0) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            if (hvc_handler_) {
                HypercallResult hr = hvc_handler_(state_, static_cast<uint16_t>(d.imm), false);
                if (hr.halt_vm) {
                    state_.halted = true;
                    state_.pc += 4ULL;
                    return false;
                }
                if (hr.handled) return true;
            }
            state_.x[0] = static_cast<uint64_t>(-1LL); // PSCI NOT_SUPPORTED fallback
            return true;
        }

        case InsnKind::Smc: {
            if (state_.pstate.el == 0) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            if (hvc_handler_) {
                HypercallResult hr = hvc_handler_(state_, static_cast<uint16_t>(d.imm), true);
                if (hr.halt_vm) {
                    state_.halted = true;
                    state_.pc += 4ULL;
                    return false;
                }
                if (hr.handled) return true;
            }
            state_.x[0] = static_cast<uint64_t>(-1LL);
            return true;
        }

        case InsnKind::Brk: {
            RaiseException(ec::kBrk64, static_cast<uint32_t>(d.imm), 0, false, state_.pc);
            return false;
        }

        case InsnKind::Hlt: {
            state_.halted = true;
            state_.pc += 4ULL;
            return false;
        }

        case InsnKind::Mrs:     return ExecuteMrs(insn);
        case InsnKind::MsrReg:  return ExecuteMsrReg(insn);
        case InsnKind::MsrImm:  return ExecuteMsrImm(insn);
        case InsnKind::SysOp:   return ExecuteSysOp(insn);
        case InsnKind::FpScalar:return ExecuteFpScalar(insn);
        case InsnKind::NeonSimd:return ExecuteNeonSimd(insn);

        case InsnKind::Unmapped:
        default: {
            RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
            return false;
        }
    }
}

} // namespace haseeb::vm
