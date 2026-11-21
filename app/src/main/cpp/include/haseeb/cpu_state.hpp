#pragma once

#include <array>
#include <cstdint>
#include <functional>

namespace haseeb::vm {

// AArch64 128-bit NEON / Scalar FP register
union NeonReg {
    uint64_t u64[2];
    int64_t  i64[2];
    uint32_t u32[4];
    int32_t  i32[4];
    uint16_t u16[8];
    int16_t  i16[8];
    uint8_t  u8[16];
    int8_t   i8[16];
    float    f32[4];
    double   f64[2];
};

// ARMv8 PSTATE fields used at EL0 / EL1
struct PState {
    bool n = false;
    bool z = false;
    bool c = false;
    bool v = false;
    bool d = true;
    bool a = true;
    bool i = true;
    bool f = true;
    uint8_t el = 1;       // 0 = EL0, 1 = EL1
    bool spsel = true;    // true = SP_EL1 (EL1h), false = SP_EL0 (EL1t)
    bool pan = false;

    uint32_t PackSpsr() const {
        uint32_t r = 0;
        if (n) r |= (1u << 31);
        if (z) r |= (1u << 30);
        if (c) r |= (1u << 29);
        if (v) r |= (1u << 28);
        if (pan) r |= (1u << 22);
        if (d) r |= (1u << 9);
        if (a) r |= (1u << 8);
        if (i) r |= (1u << 7);
        if (f) r |= (1u << 6);
        r |= (static_cast<uint32_t>(el & 3u) << 2);
        if (el > 0 && spsel) r |= 1u;
        return r;
    }

    void UnpackSpsr(uint32_t spsr) {
        n = (spsr & (1u << 31)) != 0;
        z = (spsr & (1u << 30)) != 0;
        c = (spsr & (1u << 29)) != 0;
        v = (spsr & (1u << 28)) != 0;
        pan = (spsr & (1u << 22)) != 0;
        d = (spsr & (1u << 9)) != 0;
        a = (spsr & (1u << 8)) != 0;
        i = (spsr & (1u << 7)) != 0;
        f = (spsr & (1u << 6)) != 0;
        uint8_t mode = static_cast<uint8_t>(spsr & 0xFu);
        if ((mode & 0xCu) == 0u) {
            el = 0;
            spsel = false;
        } else {
            el = 1;
            spsel = (mode & 1u) != 0;
        }
    }

    uint32_t PackNzcv() const {
        return (n ? (1u << 31) : 0u) |
               (z ? (1u << 30) : 0u) |
               (c ? (1u << 29) : 0u) |
               (v ? (1u << 28) : 0u);
    }

    void UnpackNzcv(uint32_t val) {
        n = (val & (1u << 31)) != 0;
        z = (val & (1u << 30)) != 0;
        c = (val & (1u << 29)) != 0;
        v = (val & (1u << 28)) != 0;
    }

    uint32_t PackDaif() const {
        return (d ? (1u << 9) : 0u) |
               (a ? (1u << 8) : 0u) |
               (i ? (1u << 7) : 0u) |
               (f ? (1u << 6) : 0u);
    }

    void UnpackDaif(uint32_t val) {
        d = (val & (1u << 9)) != 0;
        a = (val & (1u << 8)) != 0;
        i = (val & (1u << 7)) != 0;
        f = (val & (1u << 6)) != 0;
    }
};

// EL0 / EL1 system register bank
struct SysRegs {
    uint64_t sctlr_el1 = 0x30D00800ULL; // RES1 bits, M=0, C=0, I=0, endianness=LE
    uint64_t actlr_el1 = 0;
    uint64_t cpacr_el1 = 0x00300000ULL; // FPEN = 11 (allow FP/NEON by default at boot)
    uint64_t ttbr0_el1 = 0;
    uint64_t ttbr1_el1 = 0;
    uint64_t tcr_el1 = 0;
    uint64_t mair_el1 = 0;
    uint64_t amair_el1 = 0;
    uint64_t vbar_el1 = 0;
    uint64_t contextidr_el1 = 0;
    uint64_t tpidr_el0 = 0;
    uint64_t tpidrro_el0 = 0;
    uint64_t tpidr_el1 = 0;
    uint64_t spsr_el1 = 0;
    uint64_t elr_el1 = 0;
    uint64_t esr_el1 = 0;
    uint64_t far_el1 = 0;
    uint64_t par_el1 = 0;
    uint64_t afsr0_el1 = 0;
    uint64_t afsr1_el1 = 0;
    uint64_t mdscr_el1 = 0;
    uint64_t csselr_el1 = 0;

    // Generic timer (62.5 MHz base frequency)
    uint64_t cntfrq_el0 = 62500000ULL;
    uint64_t cntkctl_el1 = 0;
    uint64_t cntvoff_el2 = 0;
    uint64_t cntp_ctl_el0 = 0;
    uint64_t cntp_cval_el0 = 0;
    uint64_t cntv_ctl_el0 = 0;
    uint64_t cntv_cval_el0 = 0;
};

struct ExclusiveMonitor {
    bool valid = false;
    uint64_t phys_addr = 0;
    uint8_t size_bytes = 0;
};

enum class CpuStopReason : uint8_t {
    None = 0,
    StepBudgetExhausted,
    Halted,
    WfiWait,
    TrapUnhandled,
    MemoryFault,
};

struct CpuState {
    uint32_t cpu_id = 0;
    uint64_t x[31]{};      // X0..X30
    uint64_t sp_el[2]{};   // sp_el[0] = SP_EL0, sp_el[1] = SP_EL1
    uint64_t pc = 0;
    PState pstate{};
    std::array<NeonReg, 32> v{};
    uint32_t fpcr = 0;
    uint32_t fpsr = 0;
    SysRegs sys{};
    ExclusiveMonitor excl{};

    bool halted = false;
    bool waiting_for_interrupt = false;
    bool pending_irq = false;
    bool pending_fiq = false;
    uint64_t instructions_executed = 0;
    uint64_t exceptions_taken = 0;
    uint64_t timer_offset_ticks = 0;
    CpuStopReason stop_reason = CpuStopReason::None;

    uint64_t CurrentSp() const {
        return (pstate.el == 0 || !pstate.spsel) ? sp_el[0] : sp_el[1];
    }

    void SetCurrentSp(uint64_t val) {
        if (pstate.el == 0 || !pstate.spsel) {
            sp_el[0] = val;
        } else {
            sp_el[1] = val;
        }
    }

    uint64_t ReadRegOrSp(uint8_t reg) const {
        return (reg == 31u) ? CurrentSp() : x[reg];
    }

    void WriteRegOrSp(uint8_t reg, uint64_t val) {
        if (reg == 31u) {
            SetCurrentSp(val);
        } else {
            x[reg] = val;
        }
    }

    uint64_t ReadRegOrZero(uint8_t reg) const {
        return (reg == 31u) ? 0ULL : x[reg];
    }

    void WriteRegOrDiscard(uint8_t reg, uint64_t val) {
        if (reg < 31u) {
            x[reg] = val;
        }
    }
};

// ARMv8 Exception Class (EC) values for ESR_EL1[31:26]
namespace ec {
inline constexpr uint32_t kUnknown       = 0x00u;
inline constexpr uint32_t kTrapWfiWfe    = 0x01u;
inline constexpr uint32_t kFpSimdAccess  = 0x07u;
inline constexpr uint32_t kIllegalState  = 0x0Eu;
inline constexpr uint32_t kSvc64         = 0x15u;
inline constexpr uint32_t kHvc64         = 0x16u;
inline constexpr uint32_t kSmc64         = 0x17u;
inline constexpr uint32_t kSysRegTrap    = 0x18u;
inline constexpr uint32_t kInsnAbortLow  = 0x20u;
inline constexpr uint32_t kInsnAbortSame = 0x21u;
inline constexpr uint32_t kPcAlign       = 0x22u;
inline constexpr uint32_t kDataAbortLow  = 0x24u;
inline constexpr uint32_t kDataAbortSame = 0x25u;
inline constexpr uint32_t kSpAlign       = 0x26u;
inline constexpr uint32_t kBrk64         = 0x3Cu;
} // namespace ec

} // namespace haseeb::vm
