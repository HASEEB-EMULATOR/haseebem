#include "haseeb/cpu_core.hpp"
#include "haseeb/gicv3.hpp"

#include <chrono>

namespace haseeb::vm {

namespace {

constexpr uint32_t PackSysRegKey(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
    return ((op0 & 3u) << 14) | ((op1 & 7u) << 11) | ((crn & 15u) << 7) |
           ((crm & 15u) << 3) | (op2 & 7u);
}

constexpr uint32_t ExtractSysRegKey(uint32_t insn) {
    const uint32_t op0 = (insn >> 19) & 3u;
    const uint32_t op1 = (insn >> 16) & 7u;
    const uint32_t crn = (insn >> 12) & 15u;
    const uint32_t crm = (insn >> 8) & 15u;
    const uint32_t op2 = (insn >> 5) & 7u;
    return PackSysRegKey(op0, op1, crn, crm, op2);
}

// Key system register encodings (op0, op1, CRn, CRm, op2)
inline constexpr uint32_t kMidrEl1         = PackSysRegKey(3, 0, 0, 0, 0);
inline constexpr uint32_t kMpidrEl1        = PackSysRegKey(3, 0, 0, 0, 5);
inline constexpr uint32_t kRevidrEl1       = PackSysRegKey(3, 0, 0, 0, 6);
inline constexpr uint32_t kIdPfr0El1       = PackSysRegKey(3, 0, 0, 4, 0);
inline constexpr uint32_t kIdPfr1El1       = PackSysRegKey(3, 0, 0, 4, 1);
inline constexpr uint32_t kIdDfr0El1       = PackSysRegKey(3, 0, 0, 5, 0);
inline constexpr uint32_t kIdIsar0El1      = PackSysRegKey(3, 0, 0, 6, 0);
inline constexpr uint32_t kIdIsar1El1      = PackSysRegKey(3, 0, 0, 6, 1);
inline constexpr uint32_t kIdMmfr0El1      = PackSysRegKey(3, 0, 0, 7, 0);
inline constexpr uint32_t kIdMmfr1El1      = PackSysRegKey(3, 0, 0, 7, 1);
inline constexpr uint32_t kIdMmfr2El1      = PackSysRegKey(3, 0, 0, 7, 2);

inline constexpr uint32_t kCcsidrEl1       = PackSysRegKey(3, 1, 0, 0, 0);
inline constexpr uint32_t kClidrEl1        = PackSysRegKey(3, 1, 0, 0, 1);
inline constexpr uint32_t kAidrEl1         = PackSysRegKey(3, 1, 0, 0, 7);
inline constexpr uint32_t kCsselrEl1       = PackSysRegKey(3, 2, 0, 0, 0);

inline constexpr uint32_t kCtrEl0          = PackSysRegKey(3, 3, 0, 0, 1);
inline constexpr uint32_t kDczidEl0        = PackSysRegKey(3, 3, 0, 0, 7);

inline constexpr uint32_t kSctlrEl1        = PackSysRegKey(3, 0, 1, 0, 0);
inline constexpr uint32_t kActlrEl1        = PackSysRegKey(3, 0, 1, 0, 1);
inline constexpr uint32_t kCpacrEl1        = PackSysRegKey(3, 0, 1, 0, 2);

inline constexpr uint32_t kTtbr0El1        = PackSysRegKey(3, 0, 2, 0, 0);
inline constexpr uint32_t kTtbr1El1        = PackSysRegKey(3, 0, 2, 0, 1);
inline constexpr uint32_t kTcrEl1          = PackSysRegKey(3, 0, 2, 0, 2);

inline constexpr uint32_t kAfsr0El1        = PackSysRegKey(3, 0, 5, 1, 0);
inline constexpr uint32_t kAfsr1El1        = PackSysRegKey(3, 0, 5, 1, 1);
inline constexpr uint32_t kEsrEl1          = PackSysRegKey(3, 0, 5, 2, 0);
inline constexpr uint32_t kFarEl1          = PackSysRegKey(3, 0, 6, 0, 0);
inline constexpr uint32_t kParEl1          = PackSysRegKey(3, 0, 7, 4, 0);

inline constexpr uint32_t kMairEl1         = PackSysRegKey(3, 0, 10, 2, 0);
inline constexpr uint32_t kAmairEl1        = PackSysRegKey(3, 0, 10, 3, 0);
inline constexpr uint32_t kVbarEl1         = PackSysRegKey(3, 0, 12, 0, 0);
inline constexpr uint32_t kContextidrEl1   = PackSysRegKey(3, 0, 13, 0, 1);
inline constexpr uint32_t kTpidrEl1        = PackSysRegKey(3, 0, 13, 0, 4);

inline constexpr uint32_t kTpidrEl0        = PackSysRegKey(3, 3, 13, 0, 2);
inline constexpr uint32_t kTpidrroEl0      = PackSysRegKey(3, 3, 13, 0, 3);

inline constexpr uint32_t kSpEl0           = PackSysRegKey(3, 0, 4, 1, 0);
inline constexpr uint32_t kSpsel           = PackSysRegKey(3, 0, 4, 2, 0);
inline constexpr uint32_t kCurrentEl       = PackSysRegKey(3, 0, 4, 2, 2);
inline constexpr uint32_t kPan             = PackSysRegKey(3, 0, 4, 2, 3);
inline constexpr uint32_t kSpsrEl1         = PackSysRegKey(3, 0, 4, 0, 0);
inline constexpr uint32_t kElrEl1          = PackSysRegKey(3, 0, 4, 0, 1);

inline constexpr uint32_t kNzcv            = PackSysRegKey(3, 3, 4, 2, 0);
inline constexpr uint32_t kDaif            = PackSysRegKey(3, 3, 4, 2, 1);
inline constexpr uint32_t kFpcr            = PackSysRegKey(3, 3, 4, 4, 0);
inline constexpr uint32_t kFpsr            = PackSysRegKey(3, 3, 4, 4, 1);

// Debug / OS lock stubs needed by Linux early boot
inline constexpr uint32_t kMdscrEl1        = PackSysRegKey(2, 0, 0, 2, 2);
inline constexpr uint32_t kOslarEl1        = PackSysRegKey(2, 0, 1, 0, 4);
inline constexpr uint32_t kOslsrEl1        = PackSysRegKey(2, 0, 1, 1, 4);
inline constexpr uint32_t kOsdlrEl1        = PackSysRegKey(2, 0, 1, 3, 4);

// Generic timer registers
inline constexpr uint32_t kCntfrqEl0       = PackSysRegKey(3, 3, 14, 0, 0);
inline constexpr uint32_t kCntpctEl0       = PackSysRegKey(3, 3, 14, 0, 1);
inline constexpr uint32_t kCntvctEl0       = PackSysRegKey(3, 3, 14, 0, 2);
inline constexpr uint32_t kCntkctlEl1      = PackSysRegKey(3, 0, 14, 1, 0);
inline constexpr uint32_t kCntpTvalEl0     = PackSysRegKey(3, 3, 14, 2, 0);
inline constexpr uint32_t kCntpCtlEl0      = PackSysRegKey(3, 3, 14, 2, 1);
inline constexpr uint32_t kCntpCvalEl0     = PackSysRegKey(3, 3, 14, 2, 2);
inline constexpr uint32_t kCntvTvalEl0     = PackSysRegKey(3, 3, 14, 3, 0);
inline constexpr uint32_t kCntvCtlEl0      = PackSysRegKey(3, 3, 14, 3, 1);
inline constexpr uint32_t kCntvCvalEl0     = PackSysRegKey(3, 3, 14, 3, 2);

} // namespace

uint64_t AArch64CpuCore::ReadSystemTimerTicks() const {
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    // 62.5 MHz = 1 tick per 16 ns
    return (static_cast<uint64_t>(ns) >> 4) + state_.timer_offset_ticks;
}

void AArch64CpuCore::EvaluateTimersAndIrqs() {
    if (!gic_) return;
    const uint64_t pct = ReadSystemTimerTicks();
    const uint64_t vct = pct - state_.sys.cntvoff_el2;

    const bool p_en = (state_.sys.cntp_ctl_el0 & 1ULL) != 0;
    const bool p_imask = (state_.sys.cntp_ctl_el0 & 2ULL) != 0;
    const bool p_met = p_en && (pct >= state_.sys.cntp_cval_el0);
    if (p_met) state_.sys.cntp_ctl_el0 |= 4ULL;
    else state_.sys.cntp_ctl_el0 &= ~4ULL;
    // INTID 30 = Non-secure Physical Timer PPI 14 (16 + 14)
    gic_->SetPpiLevel(state_.cpu_id, 30u, p_met && !p_imask);

    const bool v_en = (state_.sys.cntv_ctl_el0 & 1ULL) != 0;
    const bool v_imask = (state_.sys.cntv_ctl_el0 & 2ULL) != 0;
    const bool v_met = v_en && (vct >= state_.sys.cntv_cval_el0);
    if (v_met) state_.sys.cntv_ctl_el0 |= 4ULL;
    else state_.sys.cntv_ctl_el0 &= ~4ULL;
    // INTID 27 = Virtual Timer PPI 11 (16 + 11)
    gic_->SetPpiLevel(state_.cpu_id, 27u, v_met && !v_imask);

    state_.pending_irq = gic_->HasPendingIrq(state_.cpu_id);
}

bool AArch64CpuCore::ExecuteMrs(uint32_t insn) {
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);
    const uint32_t op1 = (insn >> 16) & 7u;
    const uint32_t key = ExtractSysRegKey(insn);

    // Privilege check: op1 != 3 requires EL1 (except explicit EL0-accessible regs)
    if (state_.pstate.el == 0 && op1 != 3u) {
        RaiseException(ec::kSysRegTrap, 0, 0, false, state_.pc);
        return false;
    }

    uint64_t val = 0;
    switch (key) {
        case kMidrEl1:     val = 0x411FD050ULL; break; // ARM Cortex-A55 r1p0
        case kMpidrEl1:    val = 0x80000000ULL | state_.cpu_id; break;
        case kRevidrEl1:   val = 0; break;
        case kIdPfr0El1:   val = 0x0000000001000011ULL; break; // EL0/EL1 AArch64, FP/AdvSIMD, GIC sysreg v3/v4
        case kIdPfr1El1:   val = 0x0000000000000000ULL; break;
        case kIdDfr0El1:   val = 0x0000000010305106ULL; break;
        case kIdIsar0El1:  val = 0x0000000000211120ULL; break; // LSE atomics + CRC32
        case kIdIsar1El1:  val = 0x0000000000011001ULL; break;
        case kIdMmfr0El1:  val = 0x0000000000101122ULL; break; // 4K + 16K granules, 40-bit PA, 16-bit ASID
        case kIdMmfr1El1:  val = 0x0000000000210000ULL; break; // HAFDBS (HA+HD supported)
        case kIdMmfr2El1:  val = 0x0000000000000000ULL; break;

        case kClidrEl1:    val = 0x0A200023ULL; break;
        case kCcsidrEl1:   val = 0x700FE01AULL; break; // 64B cache line
        case kAidrEl1:     val = 0; break;
        case kCsselrEl1:   val = state_.sys.csselr_el1; break;

        case kCtrEl0:      val = 0x8444C004ULL; break; // 64B I/D lines
        case kDczidEl0:    val = 0x00000004ULL; break; // BS=4 => 16 words = 64B DC ZVA block

        case kSctlrEl1:    val = state_.sys.sctlr_el1; break;
        case kActlrEl1:    val = state_.sys.actlr_el1; break;
        case kCpacrEl1:    val = state_.sys.cpacr_el1; break;
        case kTtbr0El1:    val = state_.sys.ttbr0_el1; break;
        case kTtbr1El1:    val = state_.sys.ttbr1_el1; break;
        case kTcrEl1:      val = state_.sys.tcr_el1; break;
        case kAfsr0El1:    val = state_.sys.afsr0_el1; break;
        case kAfsr1El1:    val = state_.sys.afsr1_el1; break;
        case kEsrEl1:      val = state_.sys.esr_el1; break;
        case kFarEl1:      val = state_.sys.far_el1; break;
        case kParEl1:      val = state_.sys.par_el1; break;
        case kMairEl1:     val = state_.sys.mair_el1; break;
        case kAmairEl1:    val = state_.sys.amair_el1; break;
        case kVbarEl1:     val = state_.sys.vbar_el1; break;
        case kContextidrEl1: val = state_.sys.contextidr_el1; break;
        case kTpidrEl1:    val = state_.sys.tpidr_el1; break;
        case kTpidrEl0:    val = state_.sys.tpidr_el0; break;
        case kTpidrroEl0:  val = state_.sys.tpidrro_el0; break;
        case kSpEl0:       val = state_.sp_el[0]; break;
        case kSpsel:       val = state_.pstate.spsel ? 1ULL : 0ULL; break;
        case kCurrentEl:   val = static_cast<uint64_t>(state_.pstate.el) << 2; break;
        case kPan:         val = state_.pstate.pan ? (1ULL << 22) : 0ULL; break;
        case kSpsrEl1:     val = state_.sys.spsr_el1; break;
        case kElrEl1:      val = state_.sys.elr_el1; break;
        case kNzcv:        val = state_.pstate.PackNzcv(); break;
        case kDaif:        val = state_.pstate.PackDaif(); break;
        case kFpcr:        val = state_.fpcr; break;
        case kFpsr:        val = state_.fpsr; break;

        case kMdscrEl1:    val = state_.sys.mdscr_el1; break;
        case kOslsrEl1:    val = 0x8ULL; break;
        case kOsdlrEl1:    val = 0; break;

        case kCntfrqEl0:   val = state_.sys.cntfrq_el0; break;
        case kCntpctEl0:   val = ReadSystemTimerTicks(); break;
        case kCntvctEl0:   val = ReadSystemTimerTicks() - state_.sys.cntvoff_el2; break;
        case kCntkctlEl1:  val = state_.sys.cntkctl_el1; break;
        case kCntpCtlEl0: {
            EvaluateTimersAndIrqs();
            val = state_.sys.cntp_ctl_el0;
            break;
        }
        case kCntpCvalEl0: val = state_.sys.cntp_cval_el0; break;
        case kCntpTvalEl0: {
            int64_t diff = static_cast<int64_t>(state_.sys.cntp_cval_el0 - ReadSystemTimerTicks());
            val = static_cast<uint32_t>(diff);
            break;
        }
        case kCntvCtlEl0: {
            EvaluateTimersAndIrqs();
            val = state_.sys.cntv_ctl_el0;
            break;
        }
        case kCntvCvalEl0: val = state_.sys.cntv_cval_el0; break;
        case kCntvTvalEl0: {
            uint64_t vct = ReadSystemTimerTicks() - state_.sys.cntvoff_el2;
            int64_t diff = static_cast<int64_t>(state_.sys.cntv_cval_el0 - vct);
            val = static_cast<uint32_t>(diff);
            break;
        }
        case GicV3::kIccPmrEl1:
        case GicV3::kIccIar0El1:
        case GicV3::kIccHppir0El1:
        case GicV3::kIccBpr0El1:
        case GicV3::kIccRprEl1:
        case GicV3::kIccIar1El1:
        case GicV3::kIccHppir1El1:
        case GicV3::kIccBpr1El1:
        case GicV3::kIccCtlrEl1:
        case GicV3::kIccSreEl1:
        case GicV3::kIccIgrpen0El1:
        case GicV3::kIccIgrpen1El1: {
            val = gic_ ? gic_->ReadSysReg(state_.cpu_id, key) : 0ULL;
            if (gic_ && (key == GicV3::kIccIar0El1 || key == GicV3::kIccIar1El1)) {
                state_.pending_irq = gic_->HasPendingIrq(state_.cpu_id);
            }
            break;
        }
        default:
            val = 0;
            break;
    }

    state_.WriteRegOrDiscard(rt, val);
    return true;
}

bool AArch64CpuCore::ExecuteMsrReg(uint32_t insn) {
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);
    const uint32_t op1 = (insn >> 16) & 7u;
    const uint32_t key = ExtractSysRegKey(insn);
    const uint64_t val = state_.ReadRegOrZero(rt);

    const bool el0_writable = (key == kTpidrEl0 || key == kNzcv || key == kFpcr || key == kFpsr);
    if (state_.pstate.el == 0 && !el0_writable && op1 != 3u) {
        RaiseException(ec::kSysRegTrap, 0, 0, false, state_.pc);
        return false;
    }
    if (state_.pstate.el == 0 && op1 == 3u && !el0_writable) {
        RaiseException(ec::kSysRegTrap, 0, 0, false, state_.pc);
        return false;
    }

    switch (key) {
        case kCsselrEl1:     state_.sys.csselr_el1 = val & 0xFu; break;
        case kSctlrEl1: {
            uint64_t prev_m = state_.sys.sctlr_el1 & 1ULL;
            state_.sys.sctlr_el1 = val;
            if ((val & 1ULL) != prev_m) {
                mmu_.InvalidateAll();
                cache_.InvalidateAll();
            }
            break;
        }
        case kActlrEl1:      state_.sys.actlr_el1 = val; break;
        case kCpacrEl1:      state_.sys.cpacr_el1 = val; break;
        case kTtbr0El1:      state_.sys.ttbr0_el1 = val; mmu_.InvalidateAll(); break;
        case kTtbr1El1:      state_.sys.ttbr1_el1 = val; mmu_.InvalidateAll(); break;
        case kTcrEl1:        state_.sys.tcr_el1 = val; mmu_.InvalidateAll(); break;
        case kAfsr0El1:      state_.sys.afsr0_el1 = val; break;
        case kAfsr1El1:      state_.sys.afsr1_el1 = val; break;
        case kEsrEl1:        state_.sys.esr_el1 = val; break;
        case kFarEl1:        state_.sys.far_el1 = val; break;
        case kParEl1:        state_.sys.par_el1 = val; break;
        case kMairEl1:       state_.sys.mair_el1 = val; mmu_.InvalidateAll(); break;
        case kAmairEl1:      state_.sys.amair_el1 = val; break;
        case kVbarEl1:       state_.sys.vbar_el1 = val & ~0x7FFULL; break;
        case kContextidrEl1: state_.sys.contextidr_el1 = val; break;
        case kTpidrEl1:      state_.sys.tpidr_el1 = val; break;
        case kTpidrEl0:      state_.sys.tpidr_el0 = val; break;
        case kTpidrroEl0:    state_.sys.tpidrro_el0 = val; break;
        case kSpEl0:         state_.sp_el[0] = val; break;
        case kSpsel:         state_.pstate.spsel = (val & 1ULL) != 0; break;
        case kPan:           state_.pstate.pan = (val & (1ULL << 22)) != 0; break;
        case kSpsrEl1:       state_.sys.spsr_el1 = val; break;
        case kElrEl1:        state_.sys.elr_el1 = val; break;
        case kNzcv:          state_.pstate.UnpackNzcv(static_cast<uint32_t>(val)); break;
        case kDaif:          state_.pstate.UnpackDaif(static_cast<uint32_t>(val)); break;
        case kFpcr:          state_.fpcr = static_cast<uint32_t>(val); break;
        case kFpsr:          state_.fpsr = static_cast<uint32_t>(val); break;
        case kMdscrEl1:      state_.sys.mdscr_el1 = val; break;
        case kOslarEl1:      break;
        case kCntkctlEl1:    state_.sys.cntkctl_el1 = val; break;
        case kCntpCtlEl0:    state_.sys.cntp_ctl_el0 = val & 3ULL; EvaluateTimersAndIrqs(); break;
        case kCntpCvalEl0:   state_.sys.cntp_cval_el0 = val; EvaluateTimersAndIrqs(); break;
        case kCntpTvalEl0: {
            int64_t tval = static_cast<int32_t>(val & 0xFFFFFFFFULL);
            state_.sys.cntp_cval_el0 = ReadSystemTimerTicks() + static_cast<uint64_t>(tval);
            EvaluateTimersAndIrqs();
            break;
        }
        case kCntvCtlEl0:    state_.sys.cntv_ctl_el0 = val & 3ULL; EvaluateTimersAndIrqs(); break;
        case kCntvCvalEl0:   state_.sys.cntv_cval_el0 = val; EvaluateTimersAndIrqs(); break;
        case kCntvTvalEl0: {
            int64_t tval = static_cast<int32_t>(val & 0xFFFFFFFFULL);
            uint64_t vct = ReadSystemTimerTicks() - state_.sys.cntvoff_el2;
            state_.sys.cntv_cval_el0 = vct + static_cast<uint64_t>(tval);
            EvaluateTimersAndIrqs();
            break;
        }
        case GicV3::kIccPmrEl1:
        case GicV3::kIccEoir0El1:
        case GicV3::kIccBpr0El1:
        case GicV3::kIccDirEl1:
        case GicV3::kIccSgi1rEl1:
        case GicV3::kIccAsgi1rEl1:
        case GicV3::kIccSgi0rEl1:
        case GicV3::kIccEoir1El1:
        case GicV3::kIccBpr1El1:
        case GicV3::kIccCtlrEl1:
        case GicV3::kIccSreEl1:
        case GicV3::kIccIgrpen0El1:
        case GicV3::kIccIgrpen1El1: {
            if (gic_) {
                gic_->WriteSysReg(state_.cpu_id, key, val);
                EvaluateTimersAndIrqs();
            }
            break;
        }
        default:
            break;
    }
    return true;
}

bool AArch64CpuCore::ExecuteMsrImm(uint32_t insn) {
    if (state_.pstate.el == 0) {
        RaiseException(ec::kSysRegTrap, 0, 0, false, state_.pc);
        return false;
    }
    const uint32_t op1 = (insn >> 16) & 7u;
    const uint32_t crm = (insn >> 8) & 15u;
    const uint32_t op2 = (insn >> 5) & 7u;

    if (op1 == 0u && op2 == 5u) {
        // SPSel
        state_.pstate.spsel = (crm & 1u) != 0;
    } else if (op1 == 0u && op2 == 4u) {
        // PAN
        state_.pstate.pan = (crm & 1u) != 0;
    } else if (op1 == 3u && op2 == 6u) {
        // DAIFSet
        if (crm & 8u) state_.pstate.d = true;
        if (crm & 4u) state_.pstate.a = true;
        if (crm & 2u) state_.pstate.i = true;
        if (crm & 1u) state_.pstate.f = true;
    } else if (op1 == 3u && op2 == 7u) {
        // DAIFClr
        if (crm & 8u) state_.pstate.d = false;
        if (crm & 4u) state_.pstate.a = false;
        if (crm & 2u) state_.pstate.i = false;
        if (crm & 1u) state_.pstate.f = false;
    }
    return true;
}

bool AArch64CpuCore::ExecuteSysOp(uint32_t insn) {
    const uint32_t op1 = (insn >> 16) & 7u;
    const uint32_t crn = (insn >> 12) & 15u;
    const uint32_t crm = (insn >> 8) & 15u;
    const uint32_t op2 = (insn >> 5) & 7u;
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);
    const uint64_t arg = state_.ReadRegOrZero(rt);

    if (state_.pstate.el == 0 && op1 != 3u) {
        RaiseException(ec::kSysRegTrap, 0, 0, false, state_.pc);
        return false;
    }

    // DC ops (CRn = 7, op1 = 3 for DC ZVA / CVAU / CIVAC)
    if (crn == 7u && op1 == 3u && crm == 4u && op2 == 1u) {
        // DC ZVA: zero 64-byte cache line containing Xt
        const uint64_t line_base = arg & ~63ULL;
        for (uint64_t off = 0; off < 64ULL; off += 8ULL) {
            if (!WriteMem(line_base + off, 8, 0ULL, false)) {
                return false;
            }
        }
        return true;
    }

    // IC IALLU / IC IALLUIS / IC IVAU -> flush instruction translation cache
    if (crn == 7u && (crm == 1u || crm == 5u)) {
        if (crm == 5u && op2 == 1u) {
            auto r = mmu_.Translate(state_, arg, MemAccessType::Read, state_.pstate.el > 0);
            if (r.ok) cache_.InvalidatePhysPage(r.phys_addr);
        } else {
            cache_.InvalidateAll();
        }
        return true;
    }

    // AT S1E1R / S1E1W / S1E0R / S1E0W (CRn = 7, CRm = 8)
    if (crn == 7u && crm == 8u && op1 == 0u) {
        const bool write_perm = (op2 == 1u || op2 == 3u);
        const bool el0_stage = (op2 == 2u || op2 == 3u);
        state_.sys.par_el1 = mmu_.AddressTranslateForPar(state_, arg, write_perm, el0_stage);
        return true;
    }

    // TLBI (CRn = 8)
    if (crn == 8u) {
        if (crm == 7u || crm == 3u) {
            // VMALLE1 / VMALLE1IS / ALLE1 / VAE1 / ASIDE1 / VAAE1
            if (op2 == 0u) {
                mmu_.InvalidateAll();
            } else if (op2 == 1u || op2 == 5u) {
                const uint64_t va = (arg & 0x00000FFFFFFFFFFFULL) << 12;
                const uint16_t asid = static_cast<uint16_t>((arg >> 48) & 0xFFFFu);
                mmu_.InvalidateVa(va, false, asid);
            } else if (op2 == 2u) {
                mmu_.InvalidateAsid(static_cast<uint16_t>((arg >> 48) & 0xFFFFu));
            } else if (op2 == 3u || op2 == 7u) {
                const uint64_t va = (arg & 0x00000FFFFFFFFFFFULL) << 12;
                mmu_.InvalidateVa(va, true, 0);
            } else {
                mmu_.InvalidateAll();
            }
        } else {
            mmu_.InvalidateAll();
        }
        return true;
    }

    return true;
}

} // namespace haseeb::vm
