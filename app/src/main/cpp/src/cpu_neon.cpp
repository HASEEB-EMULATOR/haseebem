#include "haseeb/cpu_core.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace haseeb::vm {

namespace {

uint64_t ClampToInt64(double v) {
    if (std::isnan(v)) return 0;
    if (v >= 9223372036854775808.0) return static_cast<uint64_t>(INT64_MAX);
    if (v < -9223372036854775808.0) return static_cast<uint64_t>(INT64_MIN);
    return static_cast<uint64_t>(static_cast<int64_t>(v));
}

uint64_t ClampToUint64(double v) {
    if (std::isnan(v) || v < 0.0) return 0;
    if (v >= 18446744073709551616.0) return UINT64_MAX;
    return static_cast<uint64_t>(v);
}

int32_t ClampToInt32(double v) {
    if (std::isnan(v)) return 0;
    if (v >= 2147483648.0) return INT32_MAX;
    if (v < -2147483648.0) return INT32_MIN;
    return static_cast<int32_t>(v);
}

uint32_t ClampToUint32(double v) {
    if (std::isnan(v) || v < 0.0) return 0;
    if (v >= 4294967296.0) return UINT32_MAX;
    return static_cast<uint32_t>(v);
}

int64_t Ashr64(int64_t v, uint32_t s) {
    if (s >= 64u) return (v < 0) ? -1LL : 0LL;
    return v >> s;
}

uint64_t Lshr64(uint64_t v, uint32_t s) {
    if (s >= 64u) return 0ULL;
    return v >> s;
}

int64_t AshrRound64(int64_t v, uint32_t s) {
    if (s == 0u) return v;
    return Ashr64(v, s) + (Ashr64(v, s - 1u) & 1LL);
}

uint64_t LshrRound64(uint64_t v, uint32_t s) {
    if (s == 0u) return v;
    return Lshr64(v, s) + (Lshr64(v, s - 1u) & 1ULL);
}

uint32_t VfpExpandImm32(uint8_t imm8) {
    const uint32_t sign = (imm8 >> 7) & 1u;
    const uint32_t exp_top = ((imm8 >> 6) & 1u) ^ 1u;
    const uint32_t rep = ((imm8 >> 6) & 1u) ? 0x1Fu : 0u;
    const uint32_t exp_rest = (imm8 >> 4) & 3u;
    const uint32_t mant = imm8 & 0xFu;
    return (sign << 31) | (exp_top << 30) | (rep << 25) | (exp_rest << 23) | (mant << 19);
}

uint64_t VfpExpandImm64(uint8_t imm8) {
    const uint64_t sign = (imm8 >> 7) & 1u;
    const uint64_t exp_top = ((imm8 >> 6) & 1u) ^ 1u;
    const uint64_t rep = ((imm8 >> 6) & 1u) ? 0xFFULL : 0ULL;
    const uint64_t exp_rest = (imm8 >> 4) & 3u;
    const uint64_t mant = imm8 & 0xFu;
    return (sign << 63) | (exp_top << 62) | (rep << 54) | (exp_rest << 52) | (mant << 48);
}

int64_t SatSigned128(__int128 v, uint32_t bits) {
    const unsigned __int128 half = static_cast<unsigned __int128>(1) << (bits - 1u);
    const __int128 max_v = static_cast<__int128>(half - 1u);
    const __int128 min_v = -max_v - 1;
    if (v < min_v) return static_cast<int64_t>(min_v);
    if (v > max_v) return static_cast<int64_t>(max_v);
    return static_cast<int64_t>(v);
}

uint64_t SatUnsigned128(__int128 v, uint32_t bits) {
    if (v < 0) return 0ULL;
    const unsigned __int128 uv = static_cast<unsigned __int128>(v);
    const unsigned __int128 max_v = (bits == 64u)
        ? static_cast<unsigned __int128>(UINT64_MAX)
        : ((static_cast<unsigned __int128>(1) << bits) - 1u);
    return (uv > max_v) ? static_cast<uint64_t>(max_v) : static_cast<uint64_t>(uv);
}

uint16_t PolyMul8(uint8_t a, uint8_t b) {
    uint16_t res = 0;
    for (uint32_t k = 0; k < 8u; ++k) {
        if ((a >> k) & 1u) res ^= static_cast<uint16_t>(b) << k;
    }
    return res;
}

void PolyMul64(uint64_t a, uint64_t b, uint64_t& out_lo, uint64_t& out_hi) {
    uint64_t lo = 0, hi = 0;
    for (uint32_t k = 0; k < 64u; ++k) {
        if ((a >> k) & 1ULL) {
            lo ^= (b << k);
            if (k != 0u) hi ^= (b >> (64u - k));
        }
    }
    out_lo = lo;
    out_hi = hi;
}

uint64_t NeonGetLane(const NeonReg& r, uint32_t esize, uint32_t idx) {
    if (esize == 0u) return r.u8[idx];
    if (esize == 1u) return r.u16[idx];
    if (esize == 2u) return r.u32[idx];
    return r.u64[idx];
}

int64_t NeonGetLaneSigned(const NeonReg& r, uint32_t esize, uint32_t idx) {
    if (esize == 0u) return r.i8[idx];
    if (esize == 1u) return r.i16[idx];
    if (esize == 2u) return r.i32[idx];
    return r.i64[idx];
}

void NeonSetLane(NeonReg& r, uint32_t esize, uint32_t idx, uint64_t val) {
    if (esize == 0u) r.u8[idx] = static_cast<uint8_t>(val);
    else if (esize == 1u) r.u16[idx] = static_cast<uint16_t>(val);
    else if (esize == 2u) r.u32[idx] = static_cast<uint32_t>(val);
    else r.u64[idx] = val;
}

constexpr uint8_t kAesSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

constexpr uint8_t kAesInvSbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

uint8_t GfMul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1u) res ^= a;
        const bool hi = (a & 0x80u) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1Bu;
        b >>= 1;
    }
    return res;
}

uint32_t Rol32(uint32_t v, unsigned r) {
    r &= 31u;
    return r ? ((v << r) | (v >> (32u - r))) : v;
}

uint32_t Ror32(uint32_t v, unsigned r) {
    r &= 31u;
    return r ? ((v >> r) | (v << (32u - r))) : v;
}

} // namespace

bool AArch64CpuCore::CheckFpSimdEnabled() {
    const uint32_t fpen = (state_.sys.cpacr_el1 >> 20) & 3u;
    if ((state_.pstate.el == 0 && fpen != 3u) || (state_.pstate.el == 1 && (fpen & 1u) == 0u)) {
        RaiseException(ec::kFpSimdAccess, 0x001E0000u, 0, false, state_.pc);
        return false;
    }
    return true;
}

bool AArch64CpuCore::ExecuteFpScalar(uint32_t insn) {
    if (!CheckFpSimdEnabled()) return false;

    const uint8_t rd = static_cast<uint8_t>(insn & 31u);
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rm = static_cast<uint8_t>((insn >> 16) & 31u);
    const uint32_t ftype = (insn >> 22) & 3u; // 0=S(f32), 1=D(f64)

    // Floating-point <-> integer conversions & FMOV GPR<->FPR:
    // (insn & 0x7F20FC00) == 0x1E200000
    if ((insn & 0x7F20FC00u) == 0x1E200000u) {
        const uint8_t sf = static_cast<uint8_t>((insn >> 31) & 1u);
        const uint8_t rmode = static_cast<uint8_t>((insn >> 19) & 3u);
        const uint8_t opcode = static_cast<uint8_t>((insn >> 16) & 7u);

        if (rmode == 0u && opcode == 6u) {
            // FMOV Wd/Xd, Sn/Dn (FP -> GPR)
            uint64_t val = (ftype == 0u) ? state_.v[rn].u32[0] : state_.v[rn].u64[0];
            if (!sf) val &= 0xFFFFFFFFULL;
            state_.WriteRegOrDiscard(rd, val);
            return true;
        }
        if (rmode == 0u && opcode == 7u) {
            // FMOV Sd/Dd, Wn/Xn (GPR -> FP)
            uint64_t src = state_.ReadRegOrZero(rn);
            state_.v[rd].u64[0] = (ftype == 0u) ? (src & 0xFFFFFFFFULL) : src;
            state_.v[rd].u64[1] = 0;
            return true;
        }
        if (opcode == 2u || opcode == 3u) {
            // SCVTF / UCVTF (GPR -> FP)
            const uint64_t raw = state_.ReadRegOrZero(rn);
            const bool is_unsigned = (opcode == 3u);
            double dval = 0.0;
            if (sf) {
                dval = is_unsigned ? static_cast<double>(raw) : static_cast<double>(static_cast<int64_t>(raw));
            } else {
                uint32_t w = static_cast<uint32_t>(raw);
                dval = is_unsigned ? static_cast<double>(w) : static_cast<double>(static_cast<int32_t>(w));
            }
            if (ftype == 0u) {
                state_.v[rd].f32[0] = static_cast<float>(dval);
                state_.v[rd].u32[1] = 0;
                state_.v[rd].u64[1] = 0;
            } else {
                state_.v[rd].f64[0] = dval;
                state_.v[rd].u64[1] = 0;
            }
            return true;
        }
        if ((opcode == 0u || opcode == 1u || opcode == 4u || opcode == 5u) && rmode != 0u) {
            const bool is_unsigned = (opcode == 1u || opcode == 5u);
            const double dval = (ftype == 0u)
                ? static_cast<double>(state_.v[rn].f32[0])
                : state_.v[rn].f64[0];
            double rounded;
            if (opcode >= 4u) {
                rounded = std::trunc(dval);        // FCVTZS / FCVTZU
            } else if (rmode == 1u) {
                rounded = std::nearbyint(dval);    // FCVTNS / FCVTNU
            } else if (rmode == 2u) {
                rounded = std::round(dval);        // FCVTAS / FCVTAU
            } else {
                rounded = std::ceil(dval);         // FCVTPS / FCVTPU
            }
            uint64_t out;
            if (is_unsigned) {
                out = sf ? ClampToUint64(rounded)
                         : static_cast<uint64_t>(ClampToUint32(rounded));
            } else {
                out = sf ? static_cast<uint64_t>(ClampToInt64(rounded))
                         : static_cast<uint64_t>(static_cast<uint32_t>(ClampToInt32(rounded)));
            }
            state_.WriteRegOrDiscard(rd, out);
            return true;
        }
    }

    // FMOV (immediate): (insn & 0x7F3FE01F) -> bits[28:24]=11110, bit21=1, bit12..10=100
    if ((insn & 0x5FA01C00u) == 0x1E201000u && ((insn >> 21) & 1u) == 1u) {
        const uint8_t imm8 = static_cast<uint8_t>((insn >> 13) & 0xFFu);
        const uint64_t sign = (imm8 >> 7) & 1u;
        const uint64_t exp_top = ((imm8 >> 6) & 1u) ^ 1u;
        const uint64_t exp_rest = (imm8 >> 4) & 3u;
        const uint64_t mant = imm8 & 0xFu;
        if (ftype == 0u) {
            uint32_t bits = static_cast<uint32_t>((sign << 31) |
                            (((imm8 & 0x40u) ? 0x3Fu : 0x40u) << 23) |
                            (exp_top << 30) | (exp_rest << 23) | (mant << 19));
            // Exact VFPExpandImm for binary32: sign:not(b6):rep(b6,5):b5..b0:zeros(19)
            uint32_t rep = ((imm8 >> 6) & 1u) ? 0x1Fu : 0u;
            bits = static_cast<uint32_t>((sign << 31) | (exp_top << 30) | (rep << 25) |
                                         (exp_rest << 23) | (mant << 19));
            state_.v[rd].u32[0] = bits;
            state_.v[rd].u32[1] = 0;
            state_.v[rd].u64[1] = 0;
        } else {
            uint64_t rep = ((imm8 >> 6) & 1u) ? 0xFFULL : 0ULL;
            uint64_t bits = (sign << 63) | (exp_top << 62) | (rep << 54) |
                            (exp_rest << 52) | (mant << 48);
            state_.v[rd].u64[0] = bits;
            state_.v[rd].u64[1] = 0;
        }
        return true;
    }

    // Floating-point data-processing (1 source): bit21=1, bit14..10=10000
    if ((insn & 0x5FA07C00u) == 0x1E204000u && ((insn >> 21) & 1u) == 1u) {
        const uint8_t opc = static_cast<uint8_t>((insn >> 15) & 0x3Fu);
        if (ftype == 0u) {
            float a = state_.v[rn].f32[0];
            if (opc == 0u) state_.v[rd].f32[0] = a;                  // FMOV
            else if (opc == 1u) state_.v[rd].f32[0] = std::fabs(a);  // FABS
            else if (opc == 2u) state_.v[rd].f32[0] = -a;            // FNEG
            else if (opc == 3u) state_.v[rd].f32[0] = std::sqrt(a);  // FSQRT
            else if (opc == 5u) {                                    // FCVT Dd, Sn
                state_.v[rd].f64[0] = static_cast<double>(a);
                state_.v[rd].u64[1] = 0;
                return true;
            }
            else if (opc == 8u) state_.v[rd].f32[0] = std::nearbyint(a); // FRINTN
            else if (opc == 9u) state_.v[rd].f32[0] = std::ceil(a);      // FRINTP
            else if (opc == 10u) state_.v[rd].f32[0] = std::floor(a);    // FRINTM
            else if (opc == 11u) state_.v[rd].f32[0] = std::trunc(a);    // FRINTZ
            else if (opc == 12u) state_.v[rd].f32[0] = std::round(a);    // FRINTA
            else {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            state_.v[rd].u32[1] = 0;
            state_.v[rd].u64[1] = 0;
        } else {
            double a = state_.v[rn].f64[0];
            if (opc == 0u) state_.v[rd].f64[0] = a;
            else if (opc == 1u) state_.v[rd].f64[0] = std::fabs(a);
            else if (opc == 2u) state_.v[rd].f64[0] = -a;
            else if (opc == 3u) state_.v[rd].f64[0] = std::sqrt(a);
            else if (opc == 4u) {                                    // FCVT Sd, Dn
                state_.v[rd].f32[0] = static_cast<float>(a);
                state_.v[rd].u32[1] = 0;
                state_.v[rd].u64[1] = 0;
                return true;
            }
            else if (opc == 8u) state_.v[rd].f64[0] = std::nearbyint(a); // FRINTN
            else if (opc == 9u) state_.v[rd].f64[0] = std::ceil(a);      // FRINTP
            else if (opc == 10u) state_.v[rd].f64[0] = std::floor(a);    // FRINTM
            else if (opc == 11u) state_.v[rd].f64[0] = std::trunc(a);    // FRINTZ
            else if (opc == 12u) state_.v[rd].f64[0] = std::round(a);    // FRINTA
            else {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            state_.v[rd].u64[1] = 0;
        }
        return true;
    }

    // Floating-point compare (FCMP / FCMPE): bit21=1, bit13..10=1000
    if ((insn & 0x5FA03C00u) == 0x1E202000u && ((insn >> 21) & 1u) == 1u) {
        const bool cmp_zero = ((insn >> 3) & 1u) != 0;
        double a = (ftype == 0u) ? state_.v[rn].f32[0] : state_.v[rn].f64[0];
        double b = cmp_zero ? 0.0 : ((ftype == 0u) ? state_.v[rm].f32[0] : state_.v[rm].f64[0]);
        if (std::isnan(a) || std::isnan(b)) {
            state_.pstate.n = false;
            state_.pstate.z = false;
            state_.pstate.c = true;
            state_.pstate.v = true;
        } else if (a == b) {
            state_.pstate.n = false;
            state_.pstate.z = true;
            state_.pstate.c = true;
            state_.pstate.v = false;
        } else if (a < b) {
            state_.pstate.n = true;
            state_.pstate.z = false;
            state_.pstate.c = false;
            state_.pstate.v = false;
        } else {
            state_.pstate.n = false;
            state_.pstate.z = false;
            state_.pstate.c = true;
            state_.pstate.v = false;
        }
        return true;
    }

    // Floating-point conditional compare (FCCMP / FCCMPE): bit21=1, bit11..10=01
    if ((insn & 0x5FA00C00u) == 0x1E200400u && ((insn >> 21) & 1u) == 1u) {
        const uint8_t cond = static_cast<uint8_t>((insn >> 12) & 0xFu);
        const uint32_t nzcv = static_cast<uint32_t>(insn & 0xFu) << 28;
        if (!EvalCond(cond)) {
            state_.pstate.UnpackNzcv(nzcv);
            return true;
        }
        double a = (ftype == 0u) ? state_.v[rn].f32[0] : state_.v[rn].f64[0];
        double b = (ftype == 0u) ? state_.v[rm].f32[0] : state_.v[rm].f64[0];
        if (std::isnan(a) || std::isnan(b)) {
            state_.pstate.n = false; state_.pstate.z = false; state_.pstate.c = true; state_.pstate.v = true;
        } else if (a == b) {
            state_.pstate.n = false; state_.pstate.z = true; state_.pstate.c = true; state_.pstate.v = false;
        } else if (a < b) {
            state_.pstate.n = true; state_.pstate.z = false; state_.pstate.c = false; state_.pstate.v = false;
        } else {
            state_.pstate.n = false; state_.pstate.z = false; state_.pstate.c = true; state_.pstate.v = false;
        }
        return true;
    }

    // Floating-point conditional select (FCSEL): bit21=1, bit11..10=11
    if ((insn & 0x5FA00C00u) == 0x1E200C00u && ((insn >> 21) & 1u) == 1u) {
        const uint8_t cond = static_cast<uint8_t>((insn >> 12) & 0xFu);
        const uint8_t src = EvalCond(cond) ? rn : rm;
        if (ftype == 0u) {
            state_.v[rd].u32[0] = state_.v[src].u32[0];
            state_.v[rd].u32[1] = 0;
        } else {
            state_.v[rd].u64[0] = state_.v[src].u64[0];
        }
        state_.v[rd].u64[1] = 0;
        return true;
    }

    // Floating-point data-processing (2 source): bit21=1, bit11..10=10
    if ((insn & 0x5FA00C00u) == 0x1E200800u && ((insn >> 21) & 1u) == 1u) {
        const uint8_t opc = static_cast<uint8_t>((insn >> 12) & 0xFu);
        if (ftype == 0u) {
            float a = state_.v[rn].f32[0];
            float b = state_.v[rm].f32[0];
            float r = 0.0f;
            switch (opc) {
                case 0: r = a * b; break;
                case 1: r = a / b; break;
                case 2: r = a + b; break;
                case 3: r = a - b; break;
                case 4: r = (std::isnan(a) || std::isnan(b)) ? (a + b) : std::fmax(a, b); break;
                case 5: r = (std::isnan(a) || std::isnan(b)) ? (a + b) : std::fmin(a, b); break;
                case 6: r = std::fmax(a, b); break; // FMAXNM
                case 7: r = std::fmin(a, b); break; // FMINNM
                case 8: r = -(a * b); break;        // FNMUL
                default:
                    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                    return false;
            }
            state_.v[rd].f32[0] = r;
            state_.v[rd].u32[1] = 0;
            state_.v[rd].u64[1] = 0;
        } else {
            double a = state_.v[rn].f64[0];
            double b = state_.v[rm].f64[0];
            double r = 0.0;
            switch (opc) {
                case 0: r = a * b; break;
                case 1: r = a / b; break;
                case 2: r = a + b; break;
                case 3: r = a - b; break;
                case 4: r = (std::isnan(a) || std::isnan(b)) ? (a + b) : std::fmax(a, b); break;
                case 5: r = (std::isnan(a) || std::isnan(b)) ? (a + b) : std::fmin(a, b); break;
                case 6: r = std::fmax(a, b); break; // FMAXNM
                case 7: r = std::fmin(a, b); break; // FMINNM
                case 8: r = -(a * b); break;        // FNMUL
                default:
                    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                    return false;
            }
            state_.v[rd].f64[0] = r;
            state_.v[rd].u64[1] = 0;
        }
        return true;
    }

    // Floating-point data-processing (3 source): FMADD/FMSUB/FNMADD/FNMSUB (bits[28:24]=11111)
    if ((insn & 0x5F000000u) == 0x1F000000u) {
        const uint8_t ra = static_cast<uint8_t>((insn >> 10) & 31u);
        const bool o0 = ((insn >> 15) & 1u) != 0;
        const bool o1 = ((insn >> 21) & 1u) != 0;
        if (ftype == 0u) {
            float a = state_.v[rn].f32[0];
            float b = state_.v[rm].f32[0];
            float c = state_.v[ra].f32[0];
            if (o1) c = -c;
            float prod = (o0 ^ o1) ? -(a * b) : (a * b);
            state_.v[rd].f32[0] = c + prod;
            state_.v[rd].u32[1] = 0;
            state_.v[rd].u64[1] = 0;
        } else {
            double a = state_.v[rn].f64[0];
            double b = state_.v[rm].f64[0];
            double c = state_.v[ra].f64[0];
            if (o1) c = -c;
            double prod = (o0 ^ o1) ? -(a * b) : (a * b);
            state_.v[rd].f64[0] = c + prod;
            state_.v[rd].u64[1] = 0;
        }
        return true;
    }

    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
    return false;
}

bool AArch64CpuCore::ExecuteNeonSimd(uint32_t insn) {
    if (!CheckFpSimdEnabled()) return false;

    const uint8_t rd = static_cast<uint8_t>(insn & 31u);
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rm = static_cast<uint8_t>((insn >> 16) & 31u);
    const bool q = ((insn >> 30) & 1u) != 0;
    const uint32_t size = (insn >> 22) & 3u;
    const uint32_t lanes_bytes = q ? 16u : 8u;

    // 1. AdvSIMD Modified Immediate (MOVI / ORR / BIC / MVNI): bits[28:24]=01111, bits[23:19]=00000
    if ((insn & 0x9FF80400u) == 0x0F000400u) {
        const uint32_t cmode = (insn >> 12) & 0xFu;
        const uint32_t op = (insn >> 29) & 1u;
        const uint64_t abc = (insn >> 16) & 7u;
        const uint64_t defgh = (insn >> 5) & 0x1Fu;
        const uint64_t imm8 = (abc << 5) | defgh;
        uint64_t pattern64 = 0;
        bool is_orr = false;
        bool is_bic = false;

        if (cmode == 0xEu && op == 0u) {
            // MOVI Vd.8B / 16B, #imm8
            pattern64 = imm8 * 0x0101010101010101ULL;
        } else if (cmode == 0xEu && op == 1u) {
            // MOVI Vd.2D, #imm64 (each bit of imm8 expanded to 8 bits)
            for (int b = 0; b < 8; ++b) {
                if ((imm8 >> b) & 1u) {
                    pattern64 |= (0xFFULL << (b * 8));
                }
            }
        } else if ((cmode & 8u) == 0u) {
            // 32-bit shifted immediate: LSL 0/8/16/24
            uint32_t v32 = static_cast<uint32_t>(imm8) << (((cmode >> 1) & 3u) * 8u);
            if ((cmode & 1u) != 0u) {
                if (op == 0u) is_orr = true;
                else is_bic = true;
            } else if (op != 0u) {
                v32 = ~v32; // MVNI
            }
            pattern64 = (static_cast<uint64_t>(v32) << 32) | v32;
        } else if ((cmode & 0xCu) == 0x8u) {
            // 16-bit shifted immediate: MOVI/MVNI/ORR/BIC LSL 0/8
            uint16_t v16 = static_cast<uint16_t>(imm8 << (((cmode >> 1) & 1u) * 8u));
            if ((cmode & 1u) != 0u) {
                if (op == 0u) is_orr = true;
                else is_bic = true;
            } else if (op != 0u) {
                v16 = static_cast<uint16_t>(~v16);
            }
            uint64_t p16 = v16;
            pattern64 = p16 | (p16 << 16) | (p16 << 32) | (p16 << 48);
        } else if ((cmode & 0xEu) == 0xCu) {
            // MOVI / MVNI with MSL (1-fill shift 8 or 16)
            uint32_t v32 = (cmode == 0xCu)
                ? ((static_cast<uint32_t>(imm8) << 8) | 0xFFu)
                : ((static_cast<uint32_t>(imm8) << 16) | 0xFFFFu);
            if (op != 0u) v32 = ~v32;
            pattern64 = (static_cast<uint64_t>(v32) << 32) | v32;
        } else if (cmode == 0xFu) {
            if (op == 0u) {
                uint64_t b32 = VfpExpandImm32(static_cast<uint8_t>(imm8));
                pattern64 = (b32 << 32) | b32;
            } else if (q) {
                pattern64 = VfpExpandImm64(static_cast<uint8_t>(imm8));
            } else {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
        } else {
            pattern64 = imm8 * 0x0101010101010101ULL;
        }

        if (is_orr) {
            state_.v[rd].u64[0] |= pattern64;
            state_.v[rd].u64[1] = q ? (state_.v[rd].u64[1] | pattern64) : 0ULL;
        } else if (is_bic) {
            state_.v[rd].u64[0] &= ~pattern64;
            state_.v[rd].u64[1] = q ? (state_.v[rd].u64[1] & ~pattern64) : 0ULL;
        } else {
            state_.v[rd].u64[0] = pattern64;
            state_.v[rd].u64[1] = q ? pattern64 : 0ULL;
        }
        return true;
    }

    // 1b/1c. AdvSIMD Vector & Scalar Shift by immediate:
    //   Vector: 0 Q U 011110 immh(4)!=0 immb(3) opcode(5) 1 Rn Rd
    //   Scalar: 0 1 U 111110 immh(4)!=0 immb(3) opcode(5) 1 Rn Rd
    const bool is_vec_shift_imm = ((insn & 0x9F800400u) == 0x0F000400u) && (((insn >> 19) & 0xFu) != 0u);
    const bool is_sca_shift_imm = ((insn & 0xDF800400u) == 0x5F000400u) && (((insn >> 19) & 0xFu) != 0u);
    if (is_vec_shift_imm || is_sca_shift_imm) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t immh = (insn >> 19) & 0xFu;
        const uint32_t immb = (insn >> 16) & 7u;
        const uint32_t opcode = (insn >> 11) & 0x1Fu;
        const uint32_t imm7 = (immh << 3) | immb;
        const NeonReg src_v = state_.v[rn];

        uint32_t esize = 0;
        if (immh & 8u) esize = 3u;
        else if (immh & 4u) esize = 2u;
        else if (immh & 2u) esize = 1u;
        else esize = 0u;
        const uint32_t elem_bits = 8u << esize;
        const uint32_t count = is_sca_shift_imm ? 1u : (lanes_bytes >> esize);

        // Narrowing right-shifts: SHRN(u=0,0x10), RSHRN(u=0,0x11), SQSHRUN(u=1,0x10), SQRSHRUN(u=1,0x11),
        //                         SQSHRN(u=0,0x12), UQSHRN(u=1,0x12), SQRSHRN(u=0,0x13), UQRSHRN(u=1,0x13)
        if ((opcode == 0x10u || opcode == 0x11u || opcode == 0x12u || opcode == 0x13u) && esize <= 2u) {
            const uint32_t shift = (16u << esize) - imm7;
            const bool rounding = (opcode == 0x11u || opcode == 0x13u);
            const bool is_vec_hi = is_vec_shift_imm && q;
            NeonReg out = is_vec_hi ? state_.v[rd] : NeonReg{};
            const uint32_t dst_off = is_vec_hi ? (8u >> esize) : 0u;
            const uint32_t n = is_sca_shift_imm ? 1u : (8u >> esize);
            for (uint32_t i = 0; i < n; ++i) {
                uint64_t val = 0;
                if (opcode <= 0x11u && u == 0u) {
                    uint64_t v = NeonGetLane(src_v, esize + 1u, i);
                    val = rounding ? LshrRound64(v, shift) : Lshr64(v, shift);
                } else if (opcode <= 0x11u && u == 1u) {
                    int64_t v = NeonGetLaneSigned(src_v, esize + 1u, i);
                    int64_t s = rounding ? AshrRound64(v, shift) : Ashr64(v, shift);
                    val = SatUnsigned128(s, elem_bits);
                } else if (u == 0u) {
                    int64_t v = NeonGetLaneSigned(src_v, esize + 1u, i);
                    int64_t s = rounding ? AshrRound64(v, shift) : Ashr64(v, shift);
                    val = static_cast<uint64_t>(SatSigned128(s, elem_bits));
                } else {
                    uint64_t v = NeonGetLane(src_v, esize + 1u, i);
                    uint64_t s = rounding ? LshrRound64(v, shift) : Lshr64(v, shift);
                    val = SatUnsigned128(static_cast<__int128>(s), elem_bits);
                }
                NeonSetLane(out, esize, dst_off + i, val);
            }
            if (!is_vec_hi) out.u64[1] = 0ULL;
            state_.v[rd] = out;
            return true;
        }
        // Widening left-shift: SSHLL(u=0,0x14) / USHLL(u=1,0x14)
        if (is_vec_shift_imm && opcode == 0x14u && esize <= 2u) {
            const uint32_t shift = imm7 - elem_bits;
            const bool is_unsigned = (u == 1u);
            const uint32_t src_off = q ? (8u >> esize) : 0u;
            const uint32_t n = 8u >> esize;
            NeonReg out{};
            for (uint32_t i = 0; i < n; ++i) {
                uint64_t ext = is_unsigned
                    ? NeonGetLane(src_v, esize, src_off + i)
                    : static_cast<uint64_t>(NeonGetLaneSigned(src_v, esize, src_off + i));
                NeonSetLane(out, esize + 1u, i, ext << shift);
            }
            state_.v[rd] = out;
            return true;
        }
        // Fixed-point conversions: SCVTF(u=0,0x1C), UCVTF(u=1,0x1C), FCVTZS(u=0,0x1F), FCVTZU(u=1,0x1F)
        if ((opcode == 0x1Cu || opcode == 0x1Fu) && (esize == 2u || esize == 3u)) {
            const int fbits = static_cast<int>((16u << esize) - imm7);
            NeonReg out{};
            for (uint32_t i = 0; i < count; ++i) {
                if (opcode == 0x1Cu) {
                    double dv = (u == 1u)
                        ? static_cast<double>(NeonGetLane(src_v, esize, i))
                        : static_cast<double>(NeonGetLaneSigned(src_v, esize, i));
                    double scaled = std::ldexp(dv, -fbits);
                    if (esize == 2u) out.f32[i] = static_cast<float>(scaled);
                    else out.f64[i] = scaled;
                } else {
                    double fv = (esize == 2u) ? static_cast<double>(src_v.f32[i]) : src_v.f64[i];
                    double scaled = std::trunc(std::ldexp(fv, fbits));
                    if (esize == 2u) {
                        out.u32[i] = (u == 1u) ? ClampToUint32(scaled) : static_cast<uint32_t>(ClampToInt32(scaled));
                    } else {
                        out.u64[i] = (u == 1u) ? ClampToUint64(scaled) : ClampToInt64(scaled);
                    }
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // Core element-wise shift-by-imm:
        //   0x00: SSHR/USHR, 0x02: SSRA/USRA, 0x04: SRSHR/URSHR, 0x06: SRSRA/URSRA,
        //   0x08(u=1): SRI, 0x0A: SHL/SLI, 0x0C(u=1): SQSHLU, 0x0E: SQSHL/UQSHL
        if (opcode == 0x00u || opcode == 0x02u || opcode == 0x04u || opcode == 0x06u ||
            (u == 1u && opcode == 0x08u) || opcode == 0x0Au ||
            (u == 1u && opcode == 0x0Cu) || opcode == 0x0Eu) {
            const bool is_left = (opcode == 0x0Au || opcode == 0x0Cu || opcode == 0x0Eu);
            const uint32_t shift = is_left ? (imm7 - elem_bits) : ((16u << esize) - imm7);
            const bool is_rounding = (opcode == 0x04u || opcode == 0x06u);
            const bool is_accum = (opcode == 0x02u || opcode == 0x06u);
            const bool insert_right = (u == 1u && opcode == 0x08u);
            const bool insert_left = (opcode == 0x0Au && u == 1u);
            NeonReg out = (insert_left || insert_right || is_accum) ? state_.v[rd] : NeonReg{};
            if ((is_sca_shift_imm || !q) && (insert_left || insert_right || is_accum)) {
                out.u64[1] = 0ULL;
            }
            const uint64_t lane_mask = (elem_bits == 64u) ? ~0ULL : ((1ULL << elem_bits) - 1ULL);
            const uint64_t sri_keep = (shift >= elem_bits) ? lane_mask : (lane_mask ^ (lane_mask >> shift));
            const uint64_t sli_mask = (shift == 0u) ? 0ULL : ((shift >= elem_bits) ? lane_mask : ((1ULL << shift) - 1ULL));

            for (uint32_t i = 0; i < count; ++i) {
                uint64_t res = 0;
                if (opcode == 0x0Cu || opcode == 0x0Eu) {
                    if (opcode == 0x0Cu) { // SQSHLU
                        __int128 sv = static_cast<__int128>(NeonGetLaneSigned(src_v, esize, i));
                        res = SatUnsigned128(sv << shift, elem_bits);
                    } else if (u == 0u) { // SQSHL
                        __int128 sv = static_cast<__int128>(NeonGetLaneSigned(src_v, esize, i));
                        res = static_cast<uint64_t>(SatSigned128(sv << shift, elem_bits));
                    } else { // UQSHL
                        unsigned __int128 uv = static_cast<unsigned __int128>(NeonGetLane(src_v, esize, i)) << shift;
                        const unsigned __int128 max_v = (elem_bits == 64u) ? UINT64_MAX : lane_mask;
                        res = (uv > max_v) ? static_cast<uint64_t>(max_v) : static_cast<uint64_t>(uv);
                    }
                } else if (opcode == 0x0Au) { // SHL / SLI
                    uint64_t v = (shift >= elem_bits) ? 0ULL : ((NeonGetLane(src_v, esize, i) << shift) & lane_mask);
                    res = insert_left ? ((NeonGetLane(out, esize, i) & sli_mask) | v) : v;
                } else if (insert_right) { // SRI
                    uint64_t v = Lshr64(NeonGetLane(src_v, esize, i), shift);
                    res = (NeonGetLane(out, esize, i) & sri_keep) | (v & ~sri_keep);
                } else if (u == 0u) { // Signed right shift (SSHR / SSRA / SRSHR / SRSRA)
                    int64_t sv = NeonGetLaneSigned(src_v, esize, i);
                    int64_t r = is_rounding ? AshrRound64(sv, shift) : Ashr64(sv, shift);
                    res = is_accum ? static_cast<uint64_t>(NeonGetLaneSigned(out, esize, i) + r)
                                   : static_cast<uint64_t>(r);
                } else { // Unsigned right shift (USHR / USRA / URSHR / URSRA)
                    uint64_t uv = NeonGetLane(src_v, esize, i);
                    uint64_t r = is_rounding ? LshrRound64(uv, shift) : Lshr64(uv, shift);
                    res = is_accum ? (NeonGetLane(out, esize, i) + r) : r;
                }
                NeonSetLane(out, esize, i, res);
            }
            if (is_sca_shift_imm) {
                for (uint32_t b = (1u << esize); b < 16u; ++b) out.u8[b] = 0u;
            }
            state_.v[rd] = out;
            return true;
        }
    }

    // 1d/1e. AdvSIMD Vector & Scalar Indexed by Element:
    //   Vector: 0 Q U 01111 size L M Rm(4) opcode(4) H 0 Rn Rd
    //   Scalar: 0 1 U 11111 size L M Rm(4) opcode(4) H 0 Rn Rd
    const bool is_vec_elem = ((insn & 0x9F000400u) == 0x0F000000u);
    const bool is_sca_elem = ((insn & 0xDF000400u) == 0x5F000000u);
    if (is_vec_elem || is_sca_elem) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t l = (insn >> 21) & 1u;
        const uint32_t m = (insn >> 20) & 1u;
        const uint32_t h = (insn >> 11) & 1u;
        const uint32_t opcode = (insn >> 12) & 0xFu;
        const NeonReg a = state_.v[rn];

        // Floating-point indexed ops: FMLA(u=0,1), FMLS(u=0,5), FMUL(u=0,9), FMULX(u=1,9)
        if ((opcode == 0x1u || opcode == 0x5u || opcode == 0x9u) && (size & 2u) != 0u) {
            const bool is_f64 = (size & 1u) != 0u;
            const uint32_t rm_reg = (insn >> 16) & 31u;
            const uint32_t idx = is_f64 ? h : ((h << 1) | l);
            const NeonReg b = state_.v[rm_reg];
            if (is_vec_elem && is_f64 && !q) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            NeonReg out = (opcode == 0x1u || opcode == 0x5u) ? state_.v[rd] : NeonReg{};
            if (is_sca_elem || !q) out.u64[1] = 0ULL;
            const uint32_t cnt = is_sca_elem ? 1u : (is_f64 ? 2u : (q ? 4u : 2u));
            if (is_f64) {
                const double bv = b.f64[idx];
                if (is_sca_elem) out.u64[1] = 0ULL;
                for (uint32_t i = 0; i < cnt; ++i) {
                    const double av = a.f64[i];
                    if (opcode == 0x1u && u == 0u) out.f64[i] += av * bv;
                    else if (opcode == 0x5u && u == 0u) out.f64[i] -= av * bv;
                    else if (opcode == 0x9u && u == 0u) out.f64[i] = av * bv;
                    else if (opcode == 0x9u && u == 1u) {
                        out.f64[i] = ((av == 0.0 && std::isinf(bv)) || (std::isinf(av) && bv == 0.0)) ? 2.0 : (av * bv);
                    }
                }
            } else {
                const float bv = b.f32[idx];
                if (is_sca_elem) { out.u32[1] = 0u; out.u64[1] = 0ULL; }
                for (uint32_t i = 0; i < cnt; ++i) {
                    const float av = a.f32[i];
                    if (opcode == 0x1u && u == 0u) out.f32[i] += av * bv;
                    else if (opcode == 0x5u && u == 0u) out.f32[i] -= av * bv;
                    else if (opcode == 0x9u && u == 0u) out.f32[i] = av * bv;
                    else if (opcode == 0x9u && u == 1u) {
                        out.f32[i] = ((av == 0.0f && std::isinf(bv)) || (std::isinf(av) && bv == 0.0f)) ? 2.0f : (av * bv);
                    }
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Integer indexed ops (size == 1 -> H[0..7], size == 2 -> S[0..3])
        if (size == 1u || size == 2u) {
            const uint32_t rm_reg = (size == 1u) ? ((insn >> 16) & 15u) : ((insn >> 16) & 31u);
            const uint32_t idx = (size == 1u) ? ((h << 2) | (l << 1) | m) : ((h << 1) | l);
            const NeonReg b = state_.v[rm_reg];
            const bool is_unsigned = (u == 1u);
            const uint32_t esize_bits = 8u << size;

            // Widening indexed: SMULL/UMULL(0xA), SMLAL/UMLAL(0x2), SMLSL/UMLSL(0x6), SQDMULL(u=0,0xB)
            if (opcode == 0x2u || opcode == 0x6u || opcode == 0xAu || (u == 0u && opcode == 0xBu)) {
                const bool is_accum = (opcode == 0x2u || opcode == 0x6u);
                const bool is_sub = (opcode == 0x6u);
                const bool is_qdm = (opcode == 0xBu);
                NeonReg out = is_accum ? state_.v[rd] : NeonReg{};
                const uint32_t cnt = is_sca_elem ? 1u : (8u >> size);
                const uint32_t off = (is_vec_elem && q) ? cnt : 0u;
                for (uint32_t i = 0; i < cnt; ++i) {
                    if (is_unsigned && !is_qdm) {
                        uint64_t av = NeonGetLane(a, size, off + i);
                        uint64_t bv = NeonGetLane(b, size, idx);
                        uint64_t prod = av * bv;
                        uint64_t acc = is_accum ? NeonGetLane(out, size + 1u, i) : 0ULL;
                        NeonSetLane(out, size + 1u, i, is_accum ? (is_sub ? (acc - prod) : (acc + prod)) : prod);
                    } else {
                        int64_t av = NeonGetLaneSigned(a, size, off + i);
                        int64_t bv = NeonGetLaneSigned(b, size, idx);
                        __int128 prod = static_cast<__int128>(av) * static_cast<__int128>(bv);
                        if (is_qdm) {
                            NeonSetLane(out, size + 1u, i, static_cast<uint64_t>(SatSigned128(prod * 2, esize_bits * 2u)));
                        } else {
                            int64_t p = static_cast<int64_t>(prod);
                            int64_t acc = is_accum ? NeonGetLaneSigned(out, size + 1u, i) : 0LL;
                            NeonSetLane(out, size + 1u, i, static_cast<uint64_t>(is_accum ? (is_sub ? (acc - p) : (acc + p)) : p));
                        }
                    }
                }
                if (is_sca_elem && size == 1u) { out.u32[1] = 0u; out.u64[1] = 0ULL; }
                state_.v[rd] = out;
                return true;
            }
            // Same-width indexed: MUL(u=0,0x8), MLA(u=1,0x0), MLS(u=1,0x4), SQDMULH(u=0,0xC), SQRDMULH(u=0,0xD)
            if ((is_vec_elem && ((u == 0u && opcode == 0x8u) || (u == 1u && (opcode == 0x0u || opcode == 0x4u)))) ||
                (u == 0u && (opcode == 0xCu || opcode == 0xDu))) {
                const bool is_mla = (opcode == 0x0u);
                const bool is_mls = (opcode == 0x4u);
                const bool is_sqdm = (opcode == 0xCu || opcode == 0xDu);
                const bool rounding = (opcode == 0xDu);
                NeonReg out = (is_mla || is_mls) ? state_.v[rd] : NeonReg{};
                if (!q && (is_mla || is_mls)) out.u64[1] = 0ULL;
                const uint32_t cnt = is_sca_elem ? 1u : (lanes_bytes >> size);
                for (uint32_t i = 0; i < cnt; ++i) {
                    if (is_sqdm) {
                        int64_t av = NeonGetLaneSigned(a, size, i);
                        int64_t bv = NeonGetLaneSigned(b, size, idx);
                        __int128 prod = static_cast<__int128>(av) * static_cast<__int128>(bv) * 2;
                        if (rounding) prod += (static_cast<__int128>(1) << (esize_bits - 1u));
                        NeonSetLane(out, size, i, static_cast<uint64_t>(SatSigned128(prod >> esize_bits, esize_bits)));
                    } else {
                        uint64_t prod = NeonGetLane(a, size, i) * NeonGetLane(b, size, idx);
                        uint64_t cur = NeonGetLane(out, size, i);
                        NeonSetLane(out, size, i, is_mla ? (cur + prod) : (is_mls ? (cur - prod) : prod));
                    }
                }
                if (is_sca_elem) {
                    for (uint32_t b_i = (1u << size); b_i < 16u; ++b_i) out.u8[b_i] = 0u;
                }
                state_.v[rd] = out;
                return true;
            }
        }
    }

    // 2a. AdvSIMD Scalar Copy: DUP Bd/Hd/Sd/Dd, Vn.Ts[index] (0101 1110 000 imm5 0 0000 1 Rn Rd)
    if ((insn & 0xFFE0FC00u) == 0x5E000400u) {
        const uint32_t imm5 = (insn >> 16) & 0x1Fu;
        const NeonReg src_v = state_.v[rn];
        state_.v[rd] = NeonReg{};
        if (imm5 & 1u) {
            state_.v[rd].u8[0] = src_v.u8[(imm5 >> 1) & 15u];
        } else if (imm5 & 2u) {
            state_.v[rd].u16[0] = src_v.u16[(imm5 >> 2) & 7u];
        } else if (imm5 & 4u) {
            state_.v[rd].u32[0] = src_v.u32[(imm5 >> 3) & 3u];
        } else if (imm5 & 8u) {
            state_.v[rd].u64[0] = src_v.u64[(imm5 >> 4) & 1u];
        }
        return true;
    }

    // 2. AdvSIMD Copy: DUP (element), DUP (general), INS (general), INS (element), SMOV, UMOV
    // Encoding: 0 Q U 01110 imm5 0 imm4 1 Rn Rd
    if ((insn & 0x9F208400u) == 0x0E000400u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t imm5 = (insn >> 16) & 0x1Fu;
        const uint32_t imm4 = (insn >> 11) & 0xFu;

        if (u == 0u && imm4 == 0u) {
            // DUP Vd.T, Vn.Ts[index] (element)
            const NeonReg src_v = state_.v[rn];
            state_.v[rd] = NeonReg{};
            if (imm5 & 1u) {
                uint8_t b = src_v.u8[(imm5 >> 1) & 15u];
                for (uint32_t i = 0; i < lanes_bytes; ++i) state_.v[rd].u8[i] = b;
            } else if (imm5 & 2u) {
                uint16_t h = src_v.u16[(imm5 >> 2) & 7u];
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) state_.v[rd].u16[i] = h;
            } else if (imm5 & 4u) {
                uint32_t w = src_v.u32[(imm5 >> 3) & 3u];
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) state_.v[rd].u32[i] = w;
            } else if (imm5 & 8u) {
                uint64_t d = src_v.u64[(imm5 >> 4) & 1u];
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) state_.v[rd].u64[i] = d;
            }
            return true;
        }
        if (u == 0u && imm4 == 1u) {
            // DUP Vd.T, Wn/Xn (general)
            const uint64_t src = state_.ReadRegOrZero(rn);
            state_.v[rd] = NeonReg{};
            if (imm5 & 1u) {
                uint8_t b = static_cast<uint8_t>(src);
                for (uint32_t i = 0; i < lanes_bytes; ++i) state_.v[rd].u8[i] = b;
            } else if (imm5 & 2u) {
                uint16_t h = static_cast<uint16_t>(src);
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) state_.v[rd].u16[i] = h;
            } else if (imm5 & 4u) {
                uint32_t w = static_cast<uint32_t>(src);
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) state_.v[rd].u32[i] = w;
            } else if (imm5 & 8u) {
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) state_.v[rd].u64[i] = src;
            }
            return true;
        }
        if (u == 0u && imm4 == 3u) {
            // INS Vd.Ts[index], Wn/Xn
            const uint64_t src = state_.ReadRegOrZero(rn);
            if (imm5 & 1u) state_.v[rd].u8[(imm5 >> 1) & 15u] = static_cast<uint8_t>(src);
            else if (imm5 & 2u) state_.v[rd].u16[(imm5 >> 2) & 7u] = static_cast<uint16_t>(src);
            else if (imm5 & 4u) state_.v[rd].u32[(imm5 >> 3) & 3u] = static_cast<uint32_t>(src);
            else if (imm5 & 8u) state_.v[rd].u64[(imm5 >> 4) & 1u] = src;
            return true;
        }
        if (u == 0u && imm4 == 5u) {
            // SMOV Wd/Xd, Vn.Ts[index]
            int64_t val = 0;
            if (imm5 & 1u) val = state_.v[rn].i8[(imm5 >> 1) & 15u];
            else if (imm5 & 2u) val = state_.v[rn].i16[(imm5 >> 2) & 7u];
            else if (imm5 & 4u) val = state_.v[rn].i32[(imm5 >> 3) & 3u];
            uint64_t out = static_cast<uint64_t>(val);
            if (!q) out &= 0xFFFFFFFFULL;
            state_.WriteRegOrDiscard(rd, out);
            return true;
        }
        if (u == 0u && imm4 == 7u) {
            // UMOV Wd/Xd, Vn.Ts[index]
            uint64_t val = 0;
            if (imm5 & 1u) val = state_.v[rn].u8[(imm5 >> 1) & 15u];
            else if (imm5 & 2u) val = state_.v[rn].u16[(imm5 >> 2) & 7u];
            else if (imm5 & 4u) val = state_.v[rn].u32[(imm5 >> 3) & 3u];
            else if (imm5 & 8u) val = state_.v[rn].u64[(imm5 >> 4) & 1u];
            state_.WriteRegOrDiscard(rd, val);
            return true;
        }
        if (u == 1u) {
            // INS Vd.Ts[dst_idx], Vn.Ts[src_idx]
            const NeonReg src_v = state_.v[rn];
            if (imm5 & 1u) {
                state_.v[rd].u8[(imm5 >> 1) & 15u] = src_v.u8[imm4 & 15u];
            } else if (imm5 & 2u) {
                state_.v[rd].u16[(imm5 >> 2) & 7u] = src_v.u16[(imm4 >> 1) & 7u];
            } else if (imm5 & 4u) {
                state_.v[rd].u32[(imm5 >> 3) & 3u] = src_v.u32[(imm4 >> 2) & 3u];
            } else if (imm5 & 8u) {
                state_.v[rd].u64[(imm5 >> 4) & 1u] = src_v.u64[(imm4 >> 3) & 1u];
            }
            return true;
        }
    }

    // 3/3a. AdvSIMD Vector & Scalar Three Same:
    //   Vector: 0 Q U 01110 size 1 Rm opcode 1 Rn Rd
    //   Scalar: 0 1 U 11110 size 1 Rm opcode 1 Rn Rd
    const bool is_vec_three_same = ((insn & 0x9F200400u) == 0x0E200400u);
    const bool is_sca_three_same = ((insn & 0xDF200400u) == 0x5E200400u);
    if (is_vec_three_same || is_sca_three_same) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 11) & 0x1Fu;
        NeonReg out{};
        const NeonReg a = state_.v[rn];
        const NeonReg b = state_.v[rm];
        const uint32_t count = is_sca_three_same ? 1u : (lanes_bytes >> size);
        const uint32_t elem_bits = 8u << size;

        // Bitwise logical ops (vector only, opcode == 0x03)
        if (is_vec_three_same && opcode == 0x03u) {
            for (uint32_t i = 0; i < (q ? 2u : 1u); ++i) {
                uint64_t va = a.u64[i], vb = b.u64[i], vc = state_.v[rd].u64[i];
                if (u == 0u) {
                    if (size == 0u) out.u64[i] = va & vb;          // AND
                    else if (size == 1u) out.u64[i] = va & ~vb;    // BIC
                    else if (size == 2u) out.u64[i] = va | vb;     // ORR
                    else out.u64[i] = va | ~vb;                    // ORN
                } else {
                    if (size == 0u) out.u64[i] = va ^ vb;          // EOR
                    else if (size == 1u) out.u64[i] = (va & vc) | (vb & ~vc); // BSL
                    else if (size == 2u) out.u64[i] = (va & vb) | (vc & ~vb); // BIT
                    else out.u64[i] = (va & ~vb) | (vc & vb);                 // BIF
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Integer ADD (u=0, 0x10) / SUB (u=1, 0x10) / ADDP (u=0, 0x17)
        if (opcode == 0x10u || (is_vec_three_same && u == 0u && opcode == 0x17u)) {
            const bool is_sub = (u == 1u && opcode == 0x10u);
            if (opcode == 0x17u) {
                const uint32_t half = count / 2u;
                for (uint32_t i = 0; i < half; ++i) {
                    NeonSetLane(out, size, i, NeonGetLane(a, size, 2u * i) + NeonGetLane(a, size, 2u * i + 1u));
                    NeonSetLane(out, size, half + i, NeonGetLane(b, size, 2u * i) + NeonGetLane(b, size, 2u * i + 1u));
                }
            } else {
                for (uint32_t i = 0; i < count; ++i) {
                    uint64_t va = NeonGetLane(a, size, i), vb = NeonGetLane(b, size, i);
                    NeonSetLane(out, size, i, is_sub ? (va - vb) : (va + vb));
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Saturating & Halving ADD/SUB: SHADD(0x00), SQADD(0x01), SRHADD(0x02), SHSUB(0x04), SQSUB(0x05)
        if (opcode == 0x00u || opcode == 0x01u || opcode == 0x02u || opcode == 0x04u || opcode == 0x05u) {
            const bool is_sat = (opcode == 0x01u || opcode == 0x05u);
            const bool is_sub = (opcode == 0x04u || opcode == 0x05u);
            const bool is_round = (opcode == 0x02u);
            const bool is_unsigned = (u == 1u);
            for (uint32_t i = 0; i < count; ++i) {
                __int128 va = is_unsigned ? static_cast<__int128>(NeonGetLane(a, size, i))
                                          : static_cast<__int128>(NeonGetLaneSigned(a, size, i));
                __int128 vb = is_unsigned ? static_cast<__int128>(NeonGetLane(b, size, i))
                                          : static_cast<__int128>(NeonGetLaneSigned(b, size, i));
                __int128 sum = is_sub ? (va - vb) : (va + vb);
                if (is_sat) {
                    NeonSetLane(out, size, i, is_unsigned
                        ? SatUnsigned128(sum, elem_bits)
                        : static_cast<uint64_t>(SatSigned128(sum, elem_bits)));
                } else {
                    if (is_round) sum += 1;
                    NeonSetLane(out, size, i, static_cast<uint64_t>(sum >> 1));
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Integer Variable Shifts: SSHL/USHL(0x08), SQSHL/UQSHL(0x09), SRSHL/URSHL(0x0A), SQRSHL/UQRSHL(0x0B)
        if (opcode == 0x08u || opcode == 0x09u || opcode == 0x0Au || opcode == 0x0Bu) {
            const bool is_sat = (opcode == 0x09u || opcode == 0x0Bu);
            const bool is_round = (opcode == 0x0Au || opcode == 0x0Bu);
            const bool is_unsigned = (u == 1u);
            for (uint32_t i = 0; i < count; ++i) {
                int32_t sh = static_cast<int8_t>(NeonGetLane(b, size, i) & 0xFFu);
                if (is_unsigned) {
                    uint64_t va = NeonGetLane(a, size, i);
                    uint64_t res = 0;
                    if (sh >= 0) {
                        uint32_t ls = static_cast<uint32_t>(sh);
                        if (is_sat) {
                            res = (ls >= elem_bits) ? (va ? ((elem_bits == 64u) ? ~0ULL : ((1ULL << elem_bits) - 1ULL)) : 0ULL)
                                                    : SatUnsigned128(static_cast<__int128>(static_cast<unsigned __int128>(va) << ls), elem_bits);
                        } else {
                            res = (ls >= elem_bits) ? 0ULL : (va << ls);
                        }
                    } else {
                        uint32_t rs = static_cast<uint32_t>(-sh);
                        res = is_round ? LshrRound64(va, rs) : Lshr64(va, rs);
                    }
                    NeonSetLane(out, size, i, res);
                } else {
                    int64_t va = NeonGetLaneSigned(a, size, i);
                    int64_t res = 0;
                    if (sh >= 0) {
                        uint32_t ls = static_cast<uint32_t>(sh);
                        if (is_sat) {
                            res = (ls >= elem_bits)
                                ? ((va > 0) ? SatSigned128((static_cast<__int128>(1) << 120), elem_bits)
                                            : ((va < 0) ? SatSigned128(-(static_cast<__int128>(1) << 120), elem_bits) : 0LL))
                                : SatSigned128(static_cast<__int128>(va) << ls, elem_bits);
                        } else {
                            res = (ls >= elem_bits) ? 0LL : static_cast<int64_t>(static_cast<uint64_t>(va) << ls);
                        }
                    } else {
                        uint32_t rs = static_cast<uint32_t>(-sh);
                        res = is_round ? AshrRound64(va, rs) : Ashr64(va, rs);
                    }
                    NeonSetLane(out, size, i, static_cast<uint64_t>(res));
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Vector/Scalar Integer Comparisons: CMGT/CMHI (0x06), CMGE/CMHS (0x07), CMTST/CMEQ (0x11)
        if (opcode == 0x06u || opcode == 0x07u || opcode == 0x11u) {
            const bool is_signed = (u == 0u && (opcode == 0x06u || opcode == 0x07u));
            for (uint32_t i = 0; i < count; ++i) {
                bool res = false;
                if (is_signed) {
                    int64_t va = NeonGetLaneSigned(a, size, i), vb = NeonGetLaneSigned(b, size, i);
                    res = (opcode == 0x06u) ? (va > vb) : (va >= vb);
                } else {
                    uint64_t va = NeonGetLane(a, size, i), vb = NeonGetLane(b, size, i);
                    if (opcode == 0x11u) res = (u == 1u) ? (va == vb) : ((va & vb) != 0ULL);
                    else if (opcode == 0x06u) res = (va > vb);
                    else res = (va >= vb);
                }
                NeonSetLane(out, size, i, res ? ~0ULL : 0ULL);
            }
            state_.v[rd] = out;
            return true;
        }

        // Vector SMAX/UMAX (0x0C), SMIN/UMIN (0x0D), SMAXP/UMAXP (0x14), SMINP/UMINP (0x15)
        if (is_vec_three_same && (opcode == 0x0Cu || opcode == 0x0Du || opcode == 0x14u || opcode == 0x15u) && size <= 2u) {
            const bool is_pairwise = (opcode == 0x14u || opcode == 0x15u);
            const bool is_min = (opcode == 0x0Du || opcode == 0x15u);
            const bool is_unsigned = (u == 1u);
            auto pick = [&](uint32_t ia, uint32_t ib, const NeonReg& ra, const NeonReg& rb) -> uint64_t {
                if (is_unsigned) {
                    uint64_t x = NeonGetLane(ra, size, ia), y = NeonGetLane(rb, size, ib);
                    return is_min ? std::min(x, y) : std::max(x, y);
                }
                int64_t x = NeonGetLaneSigned(ra, size, ia), y = NeonGetLaneSigned(rb, size, ib);
                return static_cast<uint64_t>(is_min ? std::min(x, y) : std::max(x, y));
            };
            if (!is_pairwise) {
                for (uint32_t i = 0; i < count; ++i) NeonSetLane(out, size, i, pick(i, i, a, b));
            } else {
                const uint32_t half = count / 2u;
                for (uint32_t i = 0; i < half; ++i) {
                    NeonSetLane(out, size, i, pick(2u * i, 2u * i + 1u, a, a));
                    NeonSetLane(out, size, half + i, pick(2u * i, 2u * i + 1u, b, b));
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // SABD/UABD (0x0E) and SABA/UABA (0x0F)
        if (is_vec_three_same && (opcode == 0x0Eu || opcode == 0x0Fu) && size <= 2u) {
            const bool is_accum = (opcode == 0x0Fu);
            const bool is_unsigned = (u == 1u);
            out = is_accum ? state_.v[rd] : NeonReg{};
            if (!q && is_accum) out.u64[1] = 0ULL;
            for (uint32_t i = 0; i < count; ++i) {
                uint64_t diff = 0;
                if (is_unsigned) {
                    uint64_t va = NeonGetLane(a, size, i), vb = NeonGetLane(b, size, i);
                    diff = (va >= vb) ? (va - vb) : (vb - va);
                } else {
                    int64_t va = NeonGetLaneSigned(a, size, i), vb = NeonGetLaneSigned(b, size, i);
                    diff = static_cast<uint64_t>((va >= vb) ? (va - vb) : (vb - va));
                }
                NeonSetLane(out, size, i, is_accum ? (NeonGetLane(out, size, i) + diff) : diff);
            }
            state_.v[rd] = out;
            return true;
        }

        // Integer MUL (u=0, opcode=0x13), PMUL (u=1, size=0, opcode=0x13), MLA/MLS (opcode=0x12),
        // SQDMULH/SQRDMULH (opcode=0x16)
        if (opcode == 0x13u || (is_vec_three_same && opcode == 0x12u) || opcode == 0x16u) {
            if (opcode == 0x16u && (size == 1u || size == 2u)) {
                const bool rounding = (u == 1u);
                for (uint32_t i = 0; i < count; ++i) {
                    int64_t va = NeonGetLaneSigned(a, size, i), vb = NeonGetLaneSigned(b, size, i);
                    __int128 prod = static_cast<__int128>(va) * static_cast<__int128>(vb) * 2;
                    if (rounding) prod += (static_cast<__int128>(1) << (elem_bits - 1u));
                    NeonSetLane(out, size, i, static_cast<uint64_t>(SatSigned128(prod >> elem_bits, elem_bits)));
                }
                state_.v[rd] = out;
                return true;
            }
            if (is_vec_three_same && u == 1u && opcode == 0x13u && size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) {
                    out.u8[i] = static_cast<uint8_t>(PolyMul8(a.u8[i], b.u8[i]));
                }
                state_.v[rd] = out;
                return true;
            }
            if (is_vec_three_same && ((u == 0u && opcode == 0x13u) || opcode == 0x12u) && size <= 2u) {
                const bool is_mul = (opcode == 0x13u);
                const bool is_sub = (opcode == 0x12u && u == 1u);
                const NeonReg acc = state_.v[rd];
                for (uint32_t i = 0; i < count; ++i) {
                    uint64_t prod = NeonGetLane(a, size, i) * NeonGetLane(b, size, i);
                    uint64_t cur = NeonGetLane(acc, size, i);
                    NeonSetLane(out, size, i, is_mul ? prod : (is_sub ? (cur - prod) : (cur + prod)));
                }
                state_.v[rd] = out;
                return true;
            }
        }

        // Floating-point Vector & Scalar Three Same (opcode 0x18..0x1F):
        //   sz = size & 1u (0=f32, 1=f64), op_hi = (size & 2u) != 0
        if (opcode >= 0x18u) {
            const bool is_f64 = (size & 1u) != 0u;
            const bool op_hi = (size & 2u) != 0u;
            if (is_vec_three_same && is_f64 && !q) {
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
            }
            const uint32_t fcnt = is_sca_three_same ? 1u : (is_f64 ? 2u : (q ? 4u : 2u));
            const bool is_accum = (u == 0u && opcode == 0x19u);
            if (is_accum) out = state_.v[rd];
            const bool is_pairwise = is_vec_three_same && (u == 1u) &&
                                     ((opcode == 0x1Au && !op_hi) || opcode == 0x1Eu || opcode == 0x18u);

            auto eval_fp = [&](double av, double bv, double cur, bool& is_cmp, bool& cmp_out) -> double {
                is_cmp = false;
                if (opcode == 0x18u) { // FMAXNM / FMINNM
                    return op_hi ? std::fmin(av, bv) : std::fmax(av, bv);
                }
                if (opcode == 0x19u && u == 0u) { // FMLA / FMLS
                    return op_hi ? (cur - av * bv) : (cur + av * bv);
                }
                if (opcode == 0x1Au) { // FADD / FSUB / FADDP / FABD (u=1, op_hi=1)
                    if (op_hi) return (u == 1u) ? std::fabs(av - bv) : (av - bv);
                    return av + bv;
                }
                if (opcode == 0x1Bu && !op_hi) { // FMUL (u=1) / FMULX (u=0)
                    if (u == 0u && ((av == 0.0 && std::isinf(bv)) || (std::isinf(av) && bv == 0.0))) return 2.0;
                    return av * bv;
                }
                if (opcode == 0x1Cu) { // FCMEQ / FCMGE / FCMGT
                    is_cmp = true;
                    if (u == 0u && !op_hi) cmp_out = (av == bv);
                    else if (u == 1u && !op_hi) cmp_out = (av >= bv);
                    else cmp_out = (av > bv);
                    return 0.0;
                }
                if (opcode == 0x1Du && u == 1u) { // FACGE / FACGT
                    is_cmp = true;
                    double aa = std::fabs(av), bb = std::fabs(bv);
                    cmp_out = op_hi ? (aa > bb) : (aa >= bb);
                    return 0.0;
                }
                if (opcode == 0x1Eu) { // FMAX / FMIN / FMAXP / FMINP
                    if (std::isnan(av) || std::isnan(bv)) return av + bv;
                    return op_hi ? std::fmin(av, bv) : std::fmax(av, bv);
                }
                if (opcode == 0x1Fu) { // FDIV (u=1, !op_hi), FRECPS (u=0, !op_hi), FRSQRTS (u=0, op_hi)
                    if (u == 1u && !op_hi) return av / bv;
                    if (u == 0u && !op_hi) return 2.0 - (av * bv);
                    if (u == 0u && op_hi) return (3.0 - (av * bv)) * 0.5;
                }
                return 0.0;
            };

            if (is_pairwise) {
                const uint32_t half = fcnt / 2u;
                for (uint32_t i = 0; i < half; ++i) {
                    bool dummy1 = false, dummy2 = false;
                    if (is_f64) {
                        out.f64[0] = eval_fp(a.f64[0], a.f64[1], 0.0, dummy1, dummy2);
                        out.f64[1] = eval_fp(b.f64[0], b.f64[1], 0.0, dummy1, dummy2);
                    } else {
                        out.f32[i] = static_cast<float>(eval_fp(a.f32[2u * i], a.f32[2u * i + 1u], 0.0, dummy1, dummy2));
                        out.f32[half + i] = static_cast<float>(eval_fp(b.f32[2u * i], b.f32[2u * i + 1u], 0.0, dummy1, dummy2));
                    }
                }
            } else {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    bool is_cmp = false, cmp_out = false;
                    if (is_f64) {
                        double r = eval_fp(a.f64[i], b.f64[i], out.f64[i], is_cmp, cmp_out);
                        if (is_cmp) out.u64[i] = cmp_out ? ~0ULL : 0ULL;
                        else out.f64[i] = r;
                    } else {
                        double r = eval_fp(a.f32[i], b.f32[i], out.f32[i], is_cmp, cmp_out);
                        if (is_cmp) out.u32[i] = cmp_out ? 0xFFFFFFFFu : 0u;
                        else out.f32[i] = static_cast<float>(r);
                    }
                }
            }
            if (is_sca_three_same) {
                if (!is_f64) out.u32[1] = 0u;
                out.u64[1] = 0ULL;
            }
            state_.v[rd] = out;
            return true;
        }
    }

    // 3b. AdvSIMD Permute: UZP1/TRN1/ZIP1/UZP2/TRN2/ZIP2 (0 Q 0 01110 size 0 Rm 0 opcode(3) 10 Rn Rd)
    if ((insn & 0xBF208C00u) == 0x0E000800u) {
        const uint32_t opcode = (insn >> 12) & 7u;
        const NeonReg a = state_.v[rn];
        const NeonReg b = state_.v[rm];
        NeonReg out{};
        if (opcode == 1u || opcode == 2u || opcode == 3u ||
            opcode == 5u || opcode == 6u || opcode == 7u) {
            const uint32_t ebytes = 1u << size;
            const uint32_t count = lanes_bytes / ebytes;
            auto get_elem = [&](const NeonReg& reg, uint32_t idx) -> uint64_t {
                if (ebytes == 1u) return reg.u8[idx];
                if (ebytes == 2u) return reg.u16[idx];
                if (ebytes == 4u) return reg.u32[idx];
                return reg.u64[idx];
            };
            auto set_elem = [&](uint32_t idx, uint64_t val) {
                if (ebytes == 1u) out.u8[idx] = static_cast<uint8_t>(val);
                else if (ebytes == 2u) out.u16[idx] = static_cast<uint16_t>(val);
                else if (ebytes == 4u) out.u32[idx] = static_cast<uint32_t>(val);
                else out.u64[idx] = val;
            };
            const uint32_t half = count / 2u;
            if (opcode == 1u || opcode == 5u) { // UZP1 / UZP2
                const uint32_t part = (opcode == 5u) ? 1u : 0u;
                for (uint32_t i = 0; i < half; ++i) {
                    set_elem(i, get_elem(a, 2u * i + part));
                    set_elem(half + i, get_elem(b, 2u * i + part));
                }
            } else if (opcode == 3u || opcode == 7u) { // ZIP1 / ZIP2
                const uint32_t base_idx = (opcode == 7u) ? half : 0u;
                for (uint32_t i = 0; i < half; ++i) {
                    set_elem(2u * i, get_elem(a, base_idx + i));
                    set_elem(2u * i + 1u, get_elem(b, base_idx + i));
                }
            } else { // TRN1 (2) / TRN2 (6)
                const uint32_t part = (opcode == 6u) ? 1u : 0u;
                for (uint32_t i = 0; i < half; ++i) {
                    set_elem(2u * i, get_elem(a, 2u * i + part));
                    set_elem(2u * i + 1u, get_elem(b, 2u * i + part));
                }
            }
            state_.v[rd] = out;
            return true;
        }
    }

    // 3c. AdvSIMD TBL / TBX: 0 Q 001110 000 Rm 0 len(2) op(1) 00 Rn Rd
    if ((insn & 0xBFE09C00u) == 0x0E000000u) {
        const uint32_t len = ((insn >> 13) & 3u) + 1u;
        const bool is_tbx = ((insn >> 12) & 1u) != 0;
        const NeonReg indices = state_.v[rm];
        NeonReg out = is_tbx ? state_.v[rd] : NeonReg{};
        if (!q) out.u64[1] = 0ULL;
        const uint32_t max_idx = len * 16u;
        for (uint32_t i = 0; i < lanes_bytes; ++i) {
            const uint8_t idx = indices.u8[i];
            if (idx < max_idx) {
                out.u8[i] = state_.v[(rn + (idx >> 4)) & 31u].u8[idx & 15u];
            } else if (!is_tbx) {
                out.u8[i] = 0u;
            }
        }
        state_.v[rd] = out;
        return true;
    }

    // 3d. AdvSIMD Three Different:
    //   SADDL/UADDL(0x0), SADDW/UADDW(0x1), SSUBL/USUBL(0x2), SSUBW/USUBW(0x3),
    //   ADDHN/RADDHN(0x4), SABAL/UABAL(0x5), SUBHN/RSUBHN(0x6), SABDL/UABDL(0x7),
    //   SMLAL/UMLAL(0x8), SMLSL/UMLSL(0xA), SMULL/UMULL(0xC), SQDMULL(0xD), PMULL(0xE)
    // Encoding: 0 Q U 01110 size 1 Rm opcode(4) 00 Rn Rd
    if ((insn & 0x9F200C00u) == 0x0E200000u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 12) & 0xFu;
        const bool is_unsigned = (u == 1u);
        const NeonReg a = state_.v[rn];
        const NeonReg b = state_.v[rm];

        // PMULL / PMULL2 (u == 0, opcode == 0xE, size == 0 or size == 3)
        if (u == 0u && opcode == 0xEu && (size == 0u || size == 3u)) {
            NeonReg out{};
            if (size == 0u) {
                const uint32_t off = q ? 8u : 0u;
                for (uint32_t i = 0; i < 8u; ++i) out.u16[i] = PolyMul8(a.u8[off + i], b.u8[off + i]);
            } else {
                const uint32_t idx = q ? 1u : 0u;
                PolyMul64(a.u64[idx], b.u64[idx], out.u64[0], out.u64[1]);
            }
            state_.v[rd] = out;
            return true;
        }

        if (size <= 2u) {
            // ADDHN / RADDHN (0x4) & SUBHN / RSUBHN (0x6)
            if (opcode == 0x4u || opcode == 0x6u) {
                const bool is_sub = (opcode == 0x6u);
                const bool is_round = (u == 1u);
                const uint32_t dst_bits = 8u << size;
                const uint64_t round_c = is_round ? (1ULL << (dst_bits - 1u)) : 0ULL;
                NeonReg out = q ? state_.v[rd] : NeonReg{};
                const uint32_t dst_off = q ? (8u >> size) : 0u;
                const uint32_t n = 8u >> size;
                for (uint32_t i = 0; i < n; ++i) {
                    uint64_t va = NeonGetLane(a, size + 1u, i);
                    uint64_t vb = NeonGetLane(b, size + 1u, i);
                    __int128 sum = is_sub ? (static_cast<__int128>(va) - static_cast<__int128>(vb))
                                          : (static_cast<__int128>(va) + static_cast<__int128>(vb));
                    sum += static_cast<__int128>(round_c);
                    uint64_t res = static_cast<uint64_t>(static_cast<unsigned __int128>(sum) >> dst_bits);
                    NeonSetLane(out, size, dst_off + i, res);
                }
                if (!q) out.u64[1] = 0ULL;
                state_.v[rd] = out;
                return true;
            }

            // Widening ops: SADDL..SMULL (0x0..0x3, 0x7, 0xC) + SABAL(0x5), SMLAL(0x8), SMLSL(0xA), SQDMULL(0xD)
            if (opcode == 0x0u || opcode == 0x1u || opcode == 0x2u || opcode == 0x3u ||
                opcode == 0x5u || opcode == 0x7u || opcode == 0x8u || opcode == 0xAu ||
                opcode == 0xCu || (u == 0u && opcode == 0xDu && size != 0u)) {
                const bool is_wide_a = (opcode == 0x1u || opcode == 0x3u);
                const bool is_sub = (opcode == 0x2u || opcode == 0x3u || opcode == 0xAu);
                const bool is_abd = (opcode == 0x5u || opcode == 0x7u);
                const bool is_mul = (opcode == 0x8u || opcode == 0xAu || opcode == 0xCu || opcode == 0xDu);
                const bool is_accum = (opcode == 0x5u || opcode == 0x8u || opcode == 0xAu);
                const bool is_qdm = (opcode == 0xDu);
                NeonReg out = is_accum ? state_.v[rd] : NeonReg{};
                const uint32_t n = 8u >> size;
                const uint32_t off = q ? n : 0u;
                for (uint32_t i = 0; i < n; ++i) {
                    if (is_unsigned && !is_qdm) {
                        uint64_t va = is_wide_a ? NeonGetLane(a, size + 1u, i) : NeonGetLane(a, size, off + i);
                        uint64_t vb = NeonGetLane(b, size, off + i);
                        uint64_t val = 0;
                        if (is_mul) val = va * vb;
                        else if (is_abd) val = (va >= vb) ? (va - vb) : (vb - va);
                        else val = is_sub ? (va - vb) : (va + vb);
                        if (is_accum) {
                            uint64_t cur = NeonGetLane(out, size + 1u, i);
                            val = is_sub ? (cur - val) : (cur + val);
                        }
                        NeonSetLane(out, size + 1u, i, val);
                    } else {
                        int64_t va = is_wide_a ? NeonGetLaneSigned(a, size + 1u, i) : NeonGetLaneSigned(a, size, off + i);
                        int64_t vb = NeonGetLaneSigned(b, size, off + i);
                        if (is_qdm) {
                            __int128 prod = static_cast<__int128>(va) * static_cast<__int128>(vb) * 2;
                            NeonSetLane(out, size + 1u, i, static_cast<uint64_t>(SatSigned128(prod, 16u << size)));
                        } else {
                            int64_t val = 0;
                            if (is_mul) val = va * vb;
                            else if (is_abd) val = (va >= vb) ? (va - vb) : (vb - va);
                            else val = is_sub ? (va - vb) : (va + vb);
                            if (is_accum) {
                                int64_t cur = NeonGetLaneSigned(out, size + 1u, i);
                                val = is_sub ? (cur - val) : (cur + val);
                            }
                            NeonSetLane(out, size + 1u, i, static_cast<uint64_t>(val));
                        }
                    }
                }
                state_.v[rd] = out;
                return true;
            }
        }
    }

    // 4a. AdvSIMD Scalar Pairwise: ADDP Dd, Vn.2D / FADDP / FMAXP / FMINP / FMAXNMP / FMINNMP
    if ((insn & 0xDF3E0C00u) == 0x5E300800u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        const NeonReg a = state_.v[rn];
        state_.v[rd] = NeonReg{};
        if (u == 0u && opcode == 0x1Bu && size == 3u) {
            state_.v[rd].u64[0] = a.u64[0] + a.u64[1];
            return true;
        }
        if (u == 1u && (opcode == 0x0Cu || opcode == 0x0Du || opcode == 0x0Fu)) {
            const bool is_f64 = (size & 1u) != 0u;
            const bool op_hi = (size & 2u) != 0u;
            if (!is_f64) {
                float x = a.f32[0], y = a.f32[1];
                if (opcode == 0x0Du && !op_hi) state_.v[rd].f32[0] = x + y;
                else if (opcode == 0x0Cu) state_.v[rd].f32[0] = op_hi ? std::fmin(x, y) : std::fmax(x, y);
                else if (opcode == 0x0Fu) {
                    state_.v[rd].f32[0] = (std::isnan(x) || std::isnan(y)) ? (x + y)
                                        : (op_hi ? std::fmin(x, y) : std::fmax(x, y));
                } else {
                    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                    return false;
                }
            } else {
                double x = a.f64[0], y = a.f64[1];
                if (opcode == 0x0Du && !op_hi) state_.v[rd].f64[0] = x + y;
                else if (opcode == 0x0Cu) state_.v[rd].f64[0] = op_hi ? std::fmin(x, y) : std::fmax(x, y);
                else if (opcode == 0x0Fu) {
                    state_.v[rd].f64[0] = (std::isnan(x) || std::isnan(y)) ? (x + y)
                                        : (op_hi ? std::fmin(x, y) : std::fmax(x, y));
                } else {
                    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                    return false;
                }
            }
            return true;
        }
    }

    // 4. AdvSIMD Across Lanes: SADDLV / UADDLV / ADDV / SMAXV / UMAXV / SMINV / UMINV (0 Q U 01110 size 11000 opcode 10 Rn Rd)
    if ((insn & 0x9F3E0C00u) == 0x0E300800u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        // CRITICAL: copy by value BEFORE zeroing v[rd], since rd == rn is standard (e.g. ADDV B0, V0.8B)
        const NeonReg a = state_.v[rn];
        state_.v[rd] = NeonReg{};
        if (opcode == 0x03u) {
            // SADDLV (u=0) / UADDLV (u=1)
            if (u == 1u) {
                uint64_t sum = 0;
                if (size == 0u) for (uint32_t i = 0; i < lanes_bytes; ++i) sum += a.u8[i];
                else if (size == 1u) for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) sum += a.u16[i];
                else if (size == 2u) for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) sum += a.u32[i];
                state_.v[rd].u64[0] = sum;
            } else {
                int64_t sum = 0;
                if (size == 0u) for (uint32_t i = 0; i < lanes_bytes; ++i) sum += a.i8[i];
                else if (size == 1u) for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) sum += a.i16[i];
                else if (size == 2u) for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) sum += a.i32[i];
                state_.v[rd].i64[0] = sum;
            }
            return true;
        }
        if (u == 0u && opcode == 0x1Bu) {
            // ADDV
            uint64_t sum = 0;
            if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) sum += a.u8[i];
                state_.v[rd].u8[0] = static_cast<uint8_t>(sum);
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) sum += a.u16[i];
                state_.v[rd].u16[0] = static_cast<uint16_t>(sum);
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) sum += a.u32[i];
                state_.v[rd].u32[0] = static_cast<uint32_t>(sum);
            }
            return true;
        }
        if (opcode == 0x0Au || opcode == 0x1Au) {
            // SMAXV (u=0, 0x0A), UMAXV (u=1, 0x0A), SMINV (u=0, 0x1A), UMINV (u=1, 0x1A)
            const bool is_min = (opcode == 0x1Au);
            const bool is_unsigned = (u == 1u);
            if (size == 0u) {
                if (is_unsigned) {
                    uint8_t best = a.u8[0];
                    for (uint32_t i = 1; i < lanes_bytes; ++i)
                        best = is_min ? std::min(best, a.u8[i]) : std::max(best, a.u8[i]);
                    state_.v[rd].u8[0] = best;
                } else {
                    int8_t best = a.i8[0];
                    for (uint32_t i = 1; i < lanes_bytes; ++i)
                        best = is_min ? std::min(best, a.i8[i]) : std::max(best, a.i8[i]);
                    state_.v[rd].i8[0] = best;
                }
            } else if (size == 1u) {
                if (is_unsigned) {
                    uint16_t best = a.u16[0];
                    for (uint32_t i = 1; i < lanes_bytes / 2u; ++i)
                        best = is_min ? std::min(best, a.u16[i]) : std::max(best, a.u16[i]);
                    state_.v[rd].u16[0] = best;
                } else {
                    int16_t best = a.i16[0];
                    for (uint32_t i = 1; i < lanes_bytes / 2u; ++i)
                        best = is_min ? std::min(best, a.i16[i]) : std::max(best, a.i16[i]);
                    state_.v[rd].i16[0] = best;
                }
            } else if (size == 2u) {
                if (is_unsigned) {
                    uint32_t best = a.u32[0];
                    for (uint32_t i = 1; i < lanes_bytes / 4u; ++i)
                        best = is_min ? std::min(best, a.u32[i]) : std::max(best, a.u32[i]);
                    state_.v[rd].u32[0] = best;
                } else {
                    int32_t best = a.i32[0];
                    for (uint32_t i = 1; i < lanes_bytes / 4u; ++i)
                        best = is_min ? std::min(best, a.i32[i]) : std::max(best, a.i32[i]);
                    state_.v[rd].i32[0] = best;
                }
            }
            return true;
        }
    }

    // 5. AdvSIMD EXT (byte extract across Vn:Vm)
    if ((insn & 0xBFE08400u) == 0x2E000000u) {
        const uint32_t imm4 = (insn >> 11) & 0xFu;
        uint8_t concat[32]{};
        std::memcpy(concat, state_.v[rn].u8, 16);
        std::memcpy(concat + 16, state_.v[rm].u8, 16);
        state_.v[rd] = NeonReg{};
        std::memcpy(state_.v[rd].u8, concat + imm4, lanes_bytes);
        return true;
    }

    // 5a. ARMv8 Crypto AES (01001110 00101000 opcode(5) 10 Rn Rd)
    if ((insn & 0xFFFF0C00u) == 0x4E280800u) {
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        if (opcode == 4u || opcode == 5u) { // AESE (4) / AESD (5)
            const bool dec = (opcode == 5u);
            NeonReg st{};
            for (int i = 0; i < 16; ++i) st.u8[i] = state_.v[rd].u8[i] ^ state_.v[rn].u8[i];
            NeonReg out{};
            for (int c = 0; c < 4; ++c) {
                for (int r = 0; r < 4; ++r) {
                    const int src_c = dec ? ((c + 4 - r) & 3) : ((c + r) & 3);
                    const uint8_t b = st.u8[src_c * 4 + r];
                    out.u8[c * 4 + r] = dec ? kAesInvSbox[b] : kAesSbox[b];
                }
            }
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 6u || opcode == 7u) { // AESMC (6) / AESIMC (7)
            const bool inv = (opcode == 7u);
            const NeonReg in = state_.v[rn];
            NeonReg out{};
            for (int c = 0; c < 4; ++c) {
                const uint8_t a0 = in.u8[c * 4 + 0], a1 = in.u8[c * 4 + 1];
                const uint8_t a2 = in.u8[c * 4 + 2], a3 = in.u8[c * 4 + 3];
                if (!inv) {
                    out.u8[c * 4 + 0] = GfMul(a0, 2) ^ GfMul(a1, 3) ^ a2 ^ a3;
                    out.u8[c * 4 + 1] = a0 ^ GfMul(a1, 2) ^ GfMul(a2, 3) ^ a3;
                    out.u8[c * 4 + 2] = a0 ^ a1 ^ GfMul(a2, 2) ^ GfMul(a3, 3);
                    out.u8[c * 4 + 3] = GfMul(a0, 3) ^ a1 ^ a2 ^ GfMul(a3, 2);
                } else {
                    out.u8[c * 4 + 0] = GfMul(a0, 0x0E) ^ GfMul(a1, 0x0B) ^ GfMul(a2, 0x0D) ^ GfMul(a3, 0x09);
                    out.u8[c * 4 + 1] = GfMul(a0, 0x09) ^ GfMul(a1, 0x0E) ^ GfMul(a2, 0x0B) ^ GfMul(a3, 0x0D);
                    out.u8[c * 4 + 2] = GfMul(a0, 0x0D) ^ GfMul(a1, 0x09) ^ GfMul(a2, 0x0E) ^ GfMul(a3, 0x0B);
                    out.u8[c * 4 + 3] = GfMul(a0, 0x0B) ^ GfMul(a1, 0x0D) ^ GfMul(a2, 0x09) ^ GfMul(a3, 0x0E);
                }
            }
            state_.v[rd] = out;
            return true;
        }
    }

    // 5b. ARMv8 Crypto SHA Two-Reg (01011110 00101000 opcode(5) 10 Rn Rd)
    if ((insn & 0xFFFF0C00u) == 0x5E280800u) {
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        const NeonReg a = state_.v[rd];
        const NeonReg b = state_.v[rn];
        NeonReg out{};
        if (opcode == 0u) { // SHA1H
            out.u32[0] = Rol32(b.u32[0], 30u);
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 1u) { // SHA1SU1
            uint32_t t0 = a.u32[0] ^ b.u32[1];
            uint32_t t1 = a.u32[1] ^ b.u32[2];
            uint32_t t2 = a.u32[2] ^ b.u32[3];
            uint32_t t3 = a.u32[3];
            out.u32[0] = Rol32(t0, 1u);
            out.u32[1] = Rol32(t1, 1u);
            out.u32[2] = Rol32(t2, 1u);
            out.u32[3] = Rol32(t3 ^ out.u32[0], 1u);
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 2u) { // SHA256SU0
            auto s0 = [](uint32_t x) { return Ror32(x, 7u) ^ Ror32(x, 18u) ^ (x >> 3); };
            uint32_t t[4] = { a.u32[1], a.u32[2], a.u32[3], b.u32[0] };
            for (int i = 0; i < 4; ++i) out.u32[i] = a.u32[i] + s0(t[i]);
            state_.v[rd] = out;
            return true;
        }
    }

    // 5c. ARMv8 Crypto SHA Three-Reg (01011110 000 Rm 0 opcode(3) 00 Rn Rd)
    if ((insn & 0xFFE08C00u) == 0x5E000000u) {
        const uint32_t opcode = (insn >> 12) & 7u;
        const NeonReg a = state_.v[rd];
        const NeonReg b = state_.v[rn];
        const NeonReg c = state_.v[rm];
        NeonReg out{};
        if (opcode <= 2u) { // SHA1C (0), SHA1P (1), SHA1M (2)
            uint32_t X[4] = { a.u32[0], a.u32[1], a.u32[2], a.u32[3] };
            uint32_t E = b.u32[0];
            for (int e = 0; e < 4; ++e) {
                uint32_t t = 0;
                if (opcode == 0u) t = (X[1] & X[2]) ^ (~X[1] & X[3]);
                else if (opcode == 1u) t = X[1] ^ X[2] ^ X[3];
                else t = (X[1] & X[2]) | ((X[1] | X[2]) & X[3]);
                uint32_t next = E + Rol32(X[0], 5u) + t + c.u32[e];
                X[1] = Rol32(X[1], 30u);
                E = X[3];
                X[3] = X[2]; X[2] = X[1]; X[1] = X[0]; X[0] = next;
            }
            for (int i = 0; i < 4; ++i) out.u32[i] = X[i];
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 3u) { // SHA1SU0
            out.u32[0] = a.u32[2] ^ a.u32[0] ^ c.u32[0];
            out.u32[1] = a.u32[3] ^ a.u32[1] ^ c.u32[1];
            out.u32[2] = b.u32[0] ^ a.u32[2] ^ c.u32[2];
            out.u32[3] = b.u32[1] ^ a.u32[3] ^ c.u32[3];
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 4u || opcode == 5u) { // SHA256H (4) / SHA256H2 (5)
            auto S0 = [](uint32_t x) { return Ror32(x, 2u) ^ Ror32(x, 13u) ^ Ror32(x, 22u); };
            auto S1 = [](uint32_t x) { return Ror32(x, 6u) ^ Ror32(x, 11u) ^ Ror32(x, 25u); };
            const bool part1 = (opcode == 4u);
            uint32_t X[4] = {
                part1 ? a.u32[0] : b.u32[0],
                part1 ? a.u32[1] : b.u32[1],
                part1 ? a.u32[2] : b.u32[2],
                part1 ? a.u32[3] : b.u32[3],
            };
            uint32_t Y[4] = {
                part1 ? b.u32[0] : a.u32[0],
                part1 ? b.u32[1] : a.u32[1],
                part1 ? b.u32[2] : a.u32[2],
                part1 ? b.u32[3] : a.u32[3],
            };
            for (int e = 0; e < 4; ++e) {
                uint32_t ch = (Y[0] & Y[1]) ^ (~Y[0] & Y[2]);
                uint32_t maj = (X[0] & X[1]) ^ (X[0] & X[2]) ^ (X[1] & X[2]);
                uint32_t t1 = Y[3] + S1(Y[0]) + ch + c.u32[e];
                uint32_t t2 = S0(X[0]) + maj;
                Y[3] = Y[2]; Y[2] = Y[1]; Y[1] = Y[0]; Y[0] = t1 + X[3];
                X[3] = X[2]; X[2] = X[1]; X[1] = X[0]; X[0] = t1 + t2;
            }
            for (int i = 0; i < 4; ++i) out.u32[i] = part1 ? X[i] : Y[i];
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 6u) { // SHA256SU1
            auto s1 = [](uint32_t x) { return Ror32(x, 17u) ^ Ror32(x, 19u) ^ (x >> 10); };
            out.u32[0] = a.u32[0] + b.u32[1] + s1(c.u32[2]);
            out.u32[1] = a.u32[1] + b.u32[2] + s1(c.u32[3]);
            out.u32[2] = a.u32[2] + b.u32[3] + s1(out.u32[0]);
            out.u32[3] = a.u32[3] + c.u32[0] + s1(out.u32[1]);
            state_.v[rd] = out;
            return true;
        }
    }

    // 6/6a. AdvSIMD Vector & Scalar Two-reg misc:
    //   Vector: 0 Q U 01110 size 10000 opcode(5) 10 Rn Rd
    //   Scalar: 0 1 U 11110 size 10000 opcode(5) 10 Rn Rd
    const bool is_vec_misc = ((insn & 0x9F3E0C00u) == 0x0E200800u);
    const bool is_sca_misc = ((insn & 0xDF3E0C00u) == 0x5E200800u);
    if (is_vec_misc || is_sca_misc) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        const NeonReg a = state_.v[rn];
        NeonReg out{};
        const uint32_t count = is_sca_misc ? 1u : (lanes_bytes >> size);

        // SUQADD (u=0, op=0x03) / USQADD (u=1, op=0x03) — Vector & Scalar
        if (opcode == 0x03u) {
            const uint32_t elem_bits = 8u << size;
            const NeonReg cur_d = state_.v[rd];
            for (uint32_t i = 0; i < count; ++i) {
                if (u == 0u) {
                    __int128 sum = static_cast<__int128>(NeonGetLaneSigned(cur_d, size, i)) +
                                   static_cast<__int128>(NeonGetLane(a, size, i));
                    NeonSetLane(out, size, i, static_cast<uint64_t>(SatSigned128(sum, elem_bits)));
                } else {
                    __int128 sum = static_cast<__int128>(NeonGetLane(cur_d, size, i)) +
                                   static_cast<__int128>(NeonGetLaneSigned(a, size, i));
                    NeonSetLane(out, size, i, SatUnsigned128(sum, elem_bits));
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // SQABS (u=0, op=0x07) / SQNEG (u=1, op=0x07) — Vector & Scalar
        if (opcode == 0x07u) {
            const uint32_t elem_bits = 8u << size;
            for (uint32_t i = 0; i < count; ++i) {
                const __int128 v = static_cast<__int128>(NeonGetLaneSigned(a, size, i));
                const __int128 r = (u == 1u) ? -v : ((v < 0) ? -v : v);
                NeonSetLane(out, size, i, static_cast<uint64_t>(SatSigned128(r, elem_bits)));
            }
            state_.v[rd] = out;
            return true;
        }

        if (is_vec_misc && u == 0u && opcode == 0x00u) {
            // REV64 Vd.T, Vn.T
            const uint32_t halves = q ? 2u : 1u;
            for (uint32_t h = 0; h < halves; ++h) {
                if (size == 0u) for (uint32_t i = 0; i < 8u; ++i) out.u8[h * 8u + i] = a.u8[h * 8u + (7u - i)];
                else if (size == 1u) for (uint32_t i = 0; i < 4u; ++i) out.u16[h * 4u + i] = a.u16[h * 4u + (3u - i)];
                else if (size == 2u) for (uint32_t i = 0; i < 2u; ++i) out.u32[h * 2u + i] = a.u32[h * 2u + (1u - i)];
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 1u && opcode == 0x00u && (size == 0u || size == 1u)) {
            // REV32 Vd.T, Vn.T
            const uint32_t words = q ? 4u : 2u;
            for (uint32_t w = 0; w < words; ++w) {
                if (size == 0u) for (uint32_t i = 0; i < 4u; ++i) out.u8[w * 4u + i] = a.u8[w * 4u + (3u - i)];
                else { out.u16[w * 2u] = a.u16[w * 2u + 1u]; out.u16[w * 2u + 1u] = a.u16[w * 2u]; }
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 0u && opcode == 0x01u && size == 0u) {
            // REV16 Vd.T, Vn.T
            const uint32_t halfwords = q ? 8u : 4u;
            for (uint32_t h = 0; h < halfwords; ++h) {
                out.u8[h * 2u] = a.u8[h * 2u + 1u]; out.u8[h * 2u + 1u] = a.u8[h * 2u];
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && (opcode == 0x02u || opcode == 0x06u) && size < 3u) {
            // SADDLP/UADDLP (opcode=0x02) and SADALP/UADALP (opcode=0x06)
            const bool is_accum = (opcode == 0x06u);
            const bool is_unsigned = (u == 1u);
            if (is_accum) {
                out = state_.v[rd];
                if (!q) out.u64[1] = 0ULL;
            }
            const uint32_t dst_count = count / 2u;
            for (uint32_t i = 0; i < dst_count; ++i) {
                if (is_unsigned) {
                    uint64_t sum = NeonGetLane(a, size, 2u * i) + NeonGetLane(a, size, 2u * i + 1u);
                    if (is_accum) sum += NeonGetLane(out, size + 1u, i);
                    NeonSetLane(out, size + 1u, i, sum);
                } else {
                    int64_t sum = NeonGetLaneSigned(a, size, 2u * i) + NeonGetLaneSigned(a, size, 2u * i + 1u);
                    if (is_accum) sum += NeonGetLaneSigned(out, size + 1u, i);
                    NeonSetLane(out, size + 1u, i, static_cast<uint64_t>(sum));
                }
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && opcode == 0x04u && size < 3u) {
            // CLS (u=0) / CLZ (u=1)
            auto clz_n = [](uint32_t val, uint32_t bits) -> uint32_t {
                uint32_t c = 0;
                for (int b = static_cast<int>(bits) - 1; b >= 0; --b) {
                    if ((val >> b) & 1u) break;
                    ++c;
                }
                return c;
            };
            auto cls_n = [](uint32_t val, uint32_t bits) -> uint32_t {
                uint32_t sign_bit = (val >> (bits - 1u)) & 1u;
                uint32_t c = 0;
                for (int b = static_cast<int>(bits) - 2; b >= 0; --b) {
                    if (((val >> b) & 1u) != sign_bit) break;
                    ++c;
                }
                return c;
            };
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t v = static_cast<uint32_t>(NeonGetLane(a, size, i));
                NeonSetLane(out, size, i, (u == 1u) ? clz_n(v, 8u << size) : cls_n(v, 8u << size));
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 0u && opcode == 0x05u && size == 0u) {
            for (uint32_t i = 0; i < lanes_bytes; ++i) out.u8[i] = static_cast<uint8_t>(__builtin_popcount(a.u8[i]));
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 1u && opcode == 0x05u && size == 0u) {
            for (uint32_t i = 0; i < (q ? 2u : 1u); ++i) out.u64[i] = ~a.u64[i];
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 1u && opcode == 0x05u && size == 1u) {
            for (uint32_t i = 0; i < lanes_bytes; ++i) {
                uint8_t b = a.u8[i], r = 0;
                for (int bit = 0; bit < 8; ++bit) r = static_cast<uint8_t>((r << 1) | ((b >> bit) & 1u));
                out.u8[i] = r;
            }
            state_.v[rd] = out;
            return true;
        }
        // XTN(0x12,u=0), SQXTUN(0x12,u=1), SQXTN(0x14,u=0), UQXTN(0x14,u=1) — Vector & Scalar
        if ((opcode == 0x12u || opcode == 0x14u) && size < 3u) {
            if (is_vec_misc && u == 0u && opcode == 0x12u) { /* XTN */ }
            const bool is_vec_hi = is_vec_misc && q;
            out = is_vec_hi ? state_.v[rd] : NeonReg{};
            const uint32_t dst_off = is_vec_hi ? (8u >> size) : 0u;
            const uint32_t n = is_sca_misc ? 1u : (8u >> size);
            const uint32_t dst_bits = 8u << size;
            for (uint32_t i = 0; i < n; ++i) {
                uint64_t r = 0;
                if (opcode == 0x12u && u == 0u) r = NeonGetLane(a, size + 1u, i);
                else if (opcode == 0x12u && u == 1u) r = SatUnsigned128(NeonGetLaneSigned(a, size + 1u, i), dst_bits);
                else if (opcode == 0x14u && u == 0u) r = static_cast<uint64_t>(SatSigned128(NeonGetLaneSigned(a, size + 1u, i), dst_bits));
                else r = SatUnsigned128(static_cast<__int128>(NeonGetLane(a, size + 1u, i)), dst_bits);
                NeonSetLane(out, size, dst_off + i, r);
            }
            if (!is_vec_hi) out.u64[1] = 0ULL;
            state_.v[rd] = out;
            return true;
        }
        // Vector FCVTN / FCVTN2 (u=0, op=0x16, size=1) & FCVTL / FCVTL2 (u=0, op=0x17, size=1)
        if (is_vec_misc && u == 0u && (opcode == 0x16u || opcode == 0x17u) && (size & 1u) == 1u && (size & 2u) == 0u) {
            if (opcode == 0x16u) {
                out = q ? state_.v[rd] : NeonReg{};
                const uint32_t off = q ? 2u : 0u;
                for (uint32_t i = 0; i < 2u; ++i) out.f32[off + i] = static_cast<float>(a.f64[i]);
                if (!q) out.u64[1] = 0ULL;
            } else {
                const uint32_t off = q ? 2u : 0u;
                for (uint32_t i = 0; i < 2u; ++i) out.f64[i] = static_cast<double>(a.f32[off + i]);
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && u == 1u && opcode == 0x13u && size < 3u) {
            // SHLL / SHLL2
            const uint32_t n = 8u >> size;
            const uint32_t off = q ? n : 0u;
            const uint32_t sh = 8u << size;
            for (uint32_t i = 0; i < n; ++i) NeonSetLane(out, size + 1u, i, NeonGetLane(a, size, off + i) << sh);
            state_.v[rd] = out;
            return true;
        }
        // Integer Zero comparisons (0x08/0x09/0x0A) — Vector & Scalar
        if (opcode == 0x08u || opcode == 0x09u || opcode == 0x0Au) {
            for (uint32_t i = 0; i < count; ++i) {
                int64_t v = NeonGetLaneSigned(a, size, i);
                bool cmp = false;
                if (opcode == 0x08u) cmp = (u == 0u) ? (v > 0) : (v >= 0);
                else if (opcode == 0x09u) cmp = (u == 0u) ? (v == 0) : (v <= 0);
                else cmp = (u == 0u) ? (v < 0) : false;
                NeonSetLane(out, size, i, cmp ? ~0ULL : 0ULL);
            }
            state_.v[rd] = out;
            return true;
        }
        // Integer ABS (u=0, 0x0B) / NEG (u=1, 0x0B) — Vector & Scalar
        if (opcode == 0x0Bu) {
            const bool is_neg = (u == 1u);
            for (uint32_t i = 0; i < count; ++i) {
                int64_t v = NeonGetLaneSigned(a, size, i);
                int64_t r = is_neg ? static_cast<int64_t>(-static_cast<uint64_t>(v))
                                   : ((v < 0) ? static_cast<int64_t>(-static_cast<uint64_t>(v)) : v);
                NeonSetLane(out, size, i, static_cast<uint64_t>(r));
            }
            state_.v[rd] = out;
            return true;
        }
        // FP ops in Two-Reg Misc (size & 2 != 0 -> f32 if !(size&1), f64 if (size&1))
        const bool fp_hi_size = (size & 2u) != 0u;
        const bool fp_is_f64 = (size & 1u) != 0u;
        const uint32_t fcnt = is_sca_misc ? 1u : (fp_is_f64 ? 2u : (q ? 4u : 2u));

        if ((opcode == 0x0Cu || opcode == 0x0Du || opcode == 0x0Eu) && fp_hi_size) {
            // FCMGT0/FCMGE0/FCMEQ0/FCMLE0/FCMLT0 — Vector & Scalar
            auto fcmp0 = [&](double v) -> bool {
                if (std::isnan(v)) return false;
                if (opcode == 0x0Cu) return (u == 0u) ? (v > 0.0) : (v >= 0.0);
                if (opcode == 0x0Du) return (u == 0u) ? (v == 0.0) : (v <= 0.0);
                return (u == 0u) ? (v < 0.0) : false;
            };
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) out.u32[i] = fcmp0(a.f32[i]) ? 0xFFFFFFFFu : 0u;
            } else if (is_sca_misc || q) {
                for (uint32_t i = 0; i < fcnt; ++i) out.u64[i] = fcmp0(a.f64[i]) ? ~0ULL : 0ULL;
            }
            state_.v[rd] = out;
            return true;
        }
        if (is_vec_misc && opcode == 0x0Fu && fp_hi_size) {
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) out.f32[i] = (u == 1u) ? -a.f32[i] : std::fabs(a.f32[i]);
            } else if (q) {
                for (uint32_t i = 0; i < 2u; ++i) out.f64[i] = (u == 1u) ? -a.f64[i] : std::fabs(a.f64[i]);
            }
            state_.v[rd] = out;
            return true;
        }
        // FSQRT (u=1, op=0x1F)
        if (is_vec_misc && u == 1u && opcode == 0x1Fu && fp_hi_size) {
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) out.f32[i] = std::sqrt(a.f32[i]);
            } else if (q) {
                for (uint32_t i = 0; i < 2u; ++i) out.f64[i] = std::sqrt(a.f64[i]);
            }
            state_.v[rd] = out;
            return true;
        }
        // FRECPE (u=0, op=0x1D) & FRSQRTE (u=1, op=0x1D) — Vector & Scalar
        if (opcode == 0x1Du && fp_hi_size) {
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    out.f32[i] = (u == 1u) ? (1.0f / std::sqrt(a.f32[i])) : (1.0f / a.f32[i]);
                }
            } else if (is_sca_misc || q) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    out.f64[i] = (u == 1u) ? (1.0 / std::sqrt(a.f64[i])) : (1.0 / a.f64[i]);
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // SCVTF (u=0, op=0x1D, !fp_hi_size) / UCVTF (u=1, op=0x1D, !fp_hi_size) — Vector & Scalar
        if (opcode == 0x1Du && !fp_hi_size) {
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    out.f32[i] = (u == 1u) ? static_cast<float>(a.u32[i]) : static_cast<float>(a.i32[i]);
                }
            } else if (is_sca_misc || q) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    out.f64[i] = (u == 1u) ? static_cast<double>(a.u64[i]) : static_cast<double>(a.i64[i]);
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // FCVTNS/U (0x1A, !fp_hi_size), FCVTPS/U (0x1A, fp_hi_size),
        // FCVTMS/U (0x1B, !fp_hi_size), FCVTZS/U (0x1B, fp_hi_size),
        // FCVTAS/U (0x1C, !fp_hi_size) — Vector & Scalar
        if ((opcode == 0x1Au || opcode == 0x1Bu || (opcode == 0x1Cu && !fp_hi_size))) {
            auto round_mode = [&](double v) -> double {
                if (opcode == 0x1Au) return fp_hi_size ? std::ceil(v) : std::nearbyint(v);
                if (opcode == 0x1Bu) return fp_hi_size ? std::trunc(v) : std::floor(v);
                return std::round(v); // FCVTAS / FCVTAU
            };
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    double t = round_mode(static_cast<double>(a.f32[i]));
                    out.u32[i] = (u == 1u) ? ClampToUint32(t) : static_cast<uint32_t>(ClampToInt32(t));
                }
            } else if (is_sca_misc || q) {
                for (uint32_t i = 0; i < fcnt; ++i) {
                    double t = round_mode(a.f64[i]);
                    out.u64[i] = (u == 1u) ? ClampToUint64(t) : ClampToInt64(t);
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // URECPE (u=0, 0x1C, size=2) & URSQRTE (u=1, 0x1C, size=2) — Vector 32-bit
        if (is_vec_misc && opcode == 0x1Cu && size == 2u) {
            for (uint32_t i = 0; i < fcnt; ++i) {
                const uint32_t val = a.u32[i];
                if (u == 0u) {
                    out.u32[i] = (val == 0u) ? 0xFFFFFFFFu : static_cast<uint32_t>(0x100000000ULL / val);
                } else {
                    if (val == 0u) out.u32[i] = 0xFFFFFFFFu;
                    else {
                        double est = std::floor(4294967296.0 / std::sqrt(static_cast<double>(val)));
                        out.u32[i] = (est >= 4294967295.0) ? 0xFFFFFFFFu : static_cast<uint32_t>(est);
                    }
                }
            }
            state_.v[rd] = out;
            return true;
        }
        // FRINTN / FRINTM / FRINTP / FRINTZ / FRINTA / FRINTX / FRINTI — Vector
        if (is_vec_misc && (opcode == 0x18u || opcode == 0x19u) && !(u == 1u && fp_hi_size && opcode == 0x19u)) {
            auto do_rint = [&](double v) -> double {
                if (opcode == 0x18u && u == 0u && !fp_hi_size) return std::nearbyint(v); // FRINTN
                if (opcode == 0x19u && u == 0u && !fp_hi_size) return std::floor(v);     // FRINTM
                if (opcode == 0x18u && u == 0u && fp_hi_size)  return std::ceil(v);      // FRINTP
                if (opcode == 0x19u && u == 0u && fp_hi_size)  return std::trunc(v);     // FRINTZ
                if (opcode == 0x18u && u == 1u && !fp_hi_size) return std::round(v);     // FRINTA
                return std::nearbyint(v);                                                // FRINTX / FRINTI
            };
            if (!fp_is_f64) {
                for (uint32_t i = 0; i < fcnt; ++i) out.f32[i] = static_cast<float>(do_rint(a.f32[i]));
                state_.v[rd] = out;
                return true;
            } else if (q) {
                for (uint32_t i = 0; i < 2u; ++i) out.f64[i] = do_rint(a.f64[i]);
                state_.v[rd] = out;
                return true;
            }
        }
        // FRECPX (scalar, u=0, op=0x1F, fp_hi_size)
        if (is_sca_misc && u == 0u && opcode == 0x1Fu && fp_hi_size) {
            if (!fp_is_f64) {
                int exp = 0;
                std::frexp(a.f32[0], &exp);
                out.f32[0] = std::ldexp(1.0f, -exp);
            } else {
                int exp = 0;
                std::frexp(a.f64[0], &exp);
                out.f64[0] = std::ldexp(1.0, -exp);
            }
            state_.v[rd] = out;
            return true;
        }
    }

    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
    return false;
}

} // namespace haseeb::vm
