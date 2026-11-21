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
                case 4: r = std::fmax(a, b); break;
                case 5: r = std::fmin(a, b); break;
                default: break;
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
                case 4: r = std::fmax(a, b); break;
                case 5: r = std::fmin(a, b); break;
                default: break;
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

    // 1b. AdvSIMD Shift by immediate: 0 Q U 011110 immh(4)!=0 immb(3) opcode(5) 1 Rn Rd
    if ((insn & 0x9F800400u) == 0x0F000400u && ((insn >> 19) & 0xFu) != 0u) {
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

        if (u == 0u && opcode == 0x10u) {
            // SHRN / SHRN2: right-shift 2*elem_bits elements into low/high 64 bits
            const uint32_t shift = (16u << esize) - imm7;
            NeonReg out = q ? state_.v[rd] : NeonReg{};
            const uint32_t byte_off = q ? 8u : 0u;
            if (esize == 0u) {
                for (uint32_t i = 0; i < 8u; ++i) out.u8[byte_off + i] = static_cast<uint8_t>(src_v.u16[i] >> shift);
            } else if (esize == 1u) {
                for (uint32_t i = 0; i < 4u; ++i) out.u16[(byte_off / 2u) + i] = static_cast<uint16_t>(src_v.u32[i] >> shift);
            } else if (esize == 2u) {
                for (uint32_t i = 0; i < 2u; ++i) out.u32[(byte_off / 4u) + i] = static_cast<uint32_t>(src_v.u64[i] >> shift);
            }
            if (!q) out.u64[1] = 0ULL;
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 0x00u || opcode == 0x0Au) {
            const bool is_left = (opcode == 0x0Au);
            const uint32_t shift = is_left ? (imm7 - (8u << esize)) : ((16u << esize) - imm7);
            const bool is_signed = !is_left && (u == 0u);
            const bool insert_left = is_left && (u == 1u); // SLI
            NeonReg out = insert_left ? state_.v[rd] : NeonReg{};
            if (esize == 0u) {
                const uint8_t mask = insert_left ? static_cast<uint8_t>((1u << shift) - 1u) : 0u;
                for (uint32_t i = 0; i < lanes_bytes; ++i) {
                    if (is_left) {
                        uint8_t v = static_cast<uint8_t>(src_v.u8[i] << shift);
                        out.u8[i] = insert_left ? static_cast<uint8_t>((out.u8[i] & mask) | v) : v;
                    } else if (is_signed) {
                        out.i8[i] = static_cast<int8_t>(src_v.i8[i] >> shift);
                    } else {
                        out.u8[i] = static_cast<uint8_t>(src_v.u8[i] >> shift);
                    }
                }
            } else if (esize == 1u) {
                const uint16_t mask = insert_left ? static_cast<uint16_t>((1u << shift) - 1u) : 0u;
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) {
                    if (is_left) {
                        uint16_t v = static_cast<uint16_t>(src_v.u16[i] << shift);
                        out.u16[i] = insert_left ? static_cast<uint16_t>((out.u16[i] & mask) | v) : v;
                    } else if (is_signed) {
                        out.i16[i] = static_cast<int16_t>(src_v.i16[i] >> shift);
                    } else {
                        out.u16[i] = static_cast<uint16_t>(src_v.u16[i] >> shift);
                    }
                }
            } else if (esize == 2u) {
                const uint32_t mask = insert_left ? ((1u << shift) - 1u) : 0u;
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) {
                    if (is_left) {
                        uint32_t v = src_v.u32[i] << shift;
                        out.u32[i] = insert_left ? ((out.u32[i] & mask) | v) : v;
                    } else if (is_signed) {
                        out.i32[i] = src_v.i32[i] >> shift;
                    } else {
                        out.u32[i] = src_v.u32[i] >> shift;
                    }
                }
            } else {
                const uint64_t mask = insert_left ? ((shift == 64u) ? ~0ULL : ((1ULL << shift) - 1ULL)) : 0ULL;
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) {
                    if (is_left) {
                        uint64_t v = src_v.u64[i] << shift;
                        out.u64[i] = insert_left ? ((out.u64[i] & mask) | v) : v;
                    } else if (is_signed) {
                        out.i64[i] = src_v.i64[i] >> shift;
                    } else {
                        out.u64[i] = src_v.u64[i] >> shift;
                    }
                }
            }
            state_.v[rd] = out;
            return true;
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

    // 3. AdvSIMD Three Same: 0 Q U 01110 size 1 Rm opcode 1 Rn Rd
    if ((insn & 0x9F200400u) == 0x0E200400u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 11) & 0x1Fu;
        NeonReg out{};
        const NeonReg& a = state_.v[rn];
        const NeonReg& b = state_.v[rm];

        // Bitwise logical ops (opcode == 0x03: AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF encoded via size & u)
        if (opcode == 0x03u) {
            for (uint32_t i = 0; i < (q ? 2u : 1u); ++i) {
                uint64_t va = a.u64[i], vb = b.u64[i], vc = state_.v[rd].u64[i];
                if (u == 0u) {
                    if (size == 0u) out.u64[i] = va & vb;          // AND
                    else if (size == 1u) out.u64[i] = va & ~vb;    // BIC
                    else if (size == 2u) out.u64[i] = va | vb;     // ORR (MOV Vd, Vn when rn==rm)
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

        // Integer ADD (u=0, opcode=0x10) / SUB (u=1, opcode=0x10) / ADDP (u=0, opcode=0x17)
        if (opcode == 0x10u || (u == 0u && opcode == 0x17u)) {
            const bool is_sub = (u == 1u && opcode == 0x10u);
            const bool is_addp = (opcode == 0x17u);
            if (is_addp) {
                if (size == 0u) {
                    const uint32_t half = lanes_bytes / 2u;
                    for (uint32_t i = 0; i < half; ++i) {
                        out.u8[i] = static_cast<uint8_t>(a.u8[2u * i] + a.u8[2u * i + 1u]);
                        out.u8[half + i] = static_cast<uint8_t>(b.u8[2u * i] + b.u8[2u * i + 1u]);
                    }
                } else if (size == 1u) {
                    const uint32_t half = lanes_bytes / 4u;
                    for (uint32_t i = 0; i < half; ++i) {
                        out.u16[i] = static_cast<uint16_t>(a.u16[2u * i] + a.u16[2u * i + 1u]);
                        out.u16[half + i] = static_cast<uint16_t>(b.u16[2u * i] + b.u16[2u * i + 1u]);
                    }
                } else if (size == 2u) {
                    const uint32_t half = lanes_bytes / 8u;
                    for (uint32_t i = 0; i < half; ++i) {
                        out.u32[i] = a.u32[2u * i] + a.u32[2u * i + 1u];
                        out.u32[half + i] = b.u32[2u * i] + b.u32[2u * i + 1u];
                    }
                } else if (q) {
                    out.u64[0] = a.u64[0] + a.u64[1];
                    out.u64[1] = b.u64[0] + b.u64[1];
                }
            } else if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) out.u8[i] = is_sub ? (a.u8[i] - b.u8[i]) : (a.u8[i] + b.u8[i]);
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) out.u16[i] = is_sub ? (a.u16[i] - b.u16[i]) : (a.u16[i] + b.u16[i]);
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) out.u32[i] = is_sub ? (a.u32[i] - b.u32[i]) : (a.u32[i] + b.u32[i]);
            } else {
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) out.u64[i] = is_sub ? (a.u64[i] - b.u64[i]) : (a.u64[i] + b.u64[i]);
            }
            state_.v[rd] = out;
            return true;
        }

        // Vector Comparisons: CMGT/CMHI (0x06), CMGE/CMHS (0x07), CMTST/CMEQ (0x11)
        if (opcode == 0x06u || opcode == 0x07u || opcode == 0x11u) {
            auto cmp_u = [&](uint64_t va, uint64_t vb) -> bool {
                if (opcode == 0x11u) return (u == 1u) ? (va == vb) : ((va & vb) != 0ULL);
                if (opcode == 0x06u) return va > vb; // CMHI
                return va >= vb;                      // CMHS
            };
            auto cmp_s = [&](int64_t va, int64_t vb) -> bool {
                return (opcode == 0x06u) ? (va > vb) : (va >= vb); // CMGT / CMGE
            };
            const bool is_signed = (u == 0u && (opcode == 0x06u || opcode == 0x07u));
            if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) {
                    bool res = is_signed ? cmp_s(a.i8[i], b.i8[i]) : cmp_u(a.u8[i], b.u8[i]);
                    out.u8[i] = res ? 0xFFu : 0u;
                }
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) {
                    bool res = is_signed ? cmp_s(a.i16[i], b.i16[i]) : cmp_u(a.u16[i], b.u16[i]);
                    out.u16[i] = res ? 0xFFFFu : 0u;
                }
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) {
                    bool res = is_signed ? cmp_s(a.i32[i], b.i32[i]) : cmp_u(a.u32[i], b.u32[i]);
                    out.u32[i] = res ? 0xFFFFFFFFu : 0u;
                }
            } else {
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) {
                    bool res = is_signed ? cmp_s(a.i64[i], b.i64[i]) : cmp_u(a.u64[i], b.u64[i]);
                    out.u64[i] = res ? 0xFFFFFFFFFFFFFFFFULL : 0ULL;
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Vector SMAX/UMAX (0x0C), SMIN/UMIN (0x0D), SMAXP/UMAXP (0x14), SMINP/UMINP (0x15)
        if (opcode == 0x0Cu || opcode == 0x0Du || opcode == 0x14u || opcode == 0x15u) {
            const bool is_pairwise = (opcode == 0x14u || opcode == 0x15u);
            const bool is_min = (opcode == 0x0Du || opcode == 0x15u);
            const bool is_unsigned = (u == 1u);
            auto pick_i = [&](int64_t x, int64_t y) -> int64_t {
                return is_min ? std::min(x, y) : std::max(x, y);
            };
            auto pick_u = [&](uint64_t x, uint64_t y) -> uint64_t {
                return is_min ? std::min(x, y) : std::max(x, y);
            };
            if (!is_pairwise) {
                if (size == 0u) {
                    for (uint32_t i = 0; i < lanes_bytes; ++i) {
                        if (is_unsigned) out.u8[i] = static_cast<uint8_t>(pick_u(a.u8[i], b.u8[i]));
                        else out.i8[i] = static_cast<int8_t>(pick_i(a.i8[i], b.i8[i]));
                    }
                } else if (size == 1u) {
                    for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) {
                        if (is_unsigned) out.u16[i] = static_cast<uint16_t>(pick_u(a.u16[i], b.u16[i]));
                        else out.i16[i] = static_cast<int16_t>(pick_i(a.i16[i], b.i16[i]));
                    }
                } else if (size == 2u) {
                    for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) {
                        if (is_unsigned) out.u32[i] = static_cast<uint32_t>(pick_u(a.u32[i], b.u32[i]));
                        else out.i32[i] = static_cast<int32_t>(pick_i(a.i32[i], b.i32[i]));
                    }
                }
            } else {
                if (size == 0u) {
                    const uint32_t half = lanes_bytes / 2u;
                    for (uint32_t i = 0; i < half; ++i) {
                        if (is_unsigned) {
                            out.u8[i] = static_cast<uint8_t>(pick_u(a.u8[2u * i], a.u8[2u * i + 1u]));
                            out.u8[half + i] = static_cast<uint8_t>(pick_u(b.u8[2u * i], b.u8[2u * i + 1u]));
                        } else {
                            out.i8[i] = static_cast<int8_t>(pick_i(a.i8[2u * i], a.i8[2u * i + 1u]));
                            out.i8[half + i] = static_cast<int8_t>(pick_i(b.i8[2u * i], b.i8[2u * i + 1u]));
                        }
                    }
                } else if (size == 1u) {
                    const uint32_t half = lanes_bytes / 4u;
                    for (uint32_t i = 0; i < half; ++i) {
                        if (is_unsigned) {
                            out.u16[i] = static_cast<uint16_t>(pick_u(a.u16[2u * i], a.u16[2u * i + 1u]));
                            out.u16[half + i] = static_cast<uint16_t>(pick_u(b.u16[2u * i], b.u16[2u * i + 1u]));
                        } else {
                            out.i16[i] = static_cast<int16_t>(pick_i(a.i16[2u * i], a.i16[2u * i + 1u]));
                            out.i16[half + i] = static_cast<int16_t>(pick_i(b.i16[2u * i], b.i16[2u * i + 1u]));
                        }
                    }
                } else if (size == 2u) {
                    const uint32_t half = lanes_bytes / 8u;
                    for (uint32_t i = 0; i < half; ++i) {
                        if (is_unsigned) {
                            out.u32[i] = static_cast<uint32_t>(pick_u(a.u32[2u * i], a.u32[2u * i + 1u]));
                            out.u32[half + i] = static_cast<uint32_t>(pick_u(b.u32[2u * i], b.u32[2u * i + 1u]));
                        } else {
                            out.i32[i] = static_cast<int32_t>(pick_i(a.i32[2u * i], a.i32[2u * i + 1u]));
                            out.i32[half + i] = static_cast<int32_t>(pick_i(b.i32[2u * i], b.i32[2u * i + 1u]));
                        }
                    }
                }
            }
            state_.v[rd] = out;
            return true;
        }

        // Integer MUL (u=0, opcode=0x13)
        if (u == 0u && opcode == 0x13u) {
            if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) out.u8[i] = a.u8[i] * b.u8[i];
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) out.u16[i] = a.u16[i] * b.u16[i];
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) out.u32[i] = a.u32[i] * b.u32[i];
            }
            state_.v[rd] = out;
            return true;
        }

        // Floating-point vector FADD (u=0, size&1==0, opcode=0x1A) / FSUB (size&1==1, opcode=0x1A) / FMUL (u=1, size&1==0, opcode=0x1B)
        if (opcode == 0x1Au || opcode == 0x1Bu) {
            const bool is_f64 = (size & 2u) != 0;
            const bool is_sub = (opcode == 0x1Au) && ((size & 1u) != 0);
            const bool is_mul = (opcode == 0x1Bu) && (u == 1u);
            if (!is_f64) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) {
                    out.f32[i] = is_mul ? (a.f32[i] * b.f32[i])
                                        : (is_sub ? (a.f32[i] - b.f32[i]) : (a.f32[i] + b.f32[i]));
                }
            } else if (q) {
                for (uint32_t i = 0; i < 2u; ++i) {
                    out.f64[i] = is_mul ? (a.f64[i] * b.f64[i])
                                        : (is_sub ? (a.f64[i] - b.f64[i]) : (a.f64[i] + b.f64[i]));
                }
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

    // 6. AdvSIMD Two-reg misc: REV64 / CNT / NOT / RBIT / CMEQ0 / CMGT0 / CMGE0 / CMLT0 / CMLE0 / ABS / NEG
    if ((insn & 0x9F3E0C00u) == 0x0E200800u) {
        const uint32_t u = (insn >> 29) & 1u;
        const uint32_t opcode = (insn >> 12) & 0x1Fu;
        const NeonReg a = state_.v[rn];
        NeonReg out{};
        if (u == 0u && opcode == 0x00u) {
            // REV64 Vd.T, Vn.T
            const uint32_t halves = q ? 2u : 1u;
            for (uint32_t h = 0; h < halves; ++h) {
                if (size == 0u) {
                    for (uint32_t i = 0; i < 8u; ++i) out.u8[h * 8u + i] = a.u8[h * 8u + (7u - i)];
                } else if (size == 1u) {
                    for (uint32_t i = 0; i < 4u; ++i) out.u16[h * 4u + i] = a.u16[h * 4u + (3u - i)];
                } else if (size == 2u) {
                    for (uint32_t i = 0; i < 2u; ++i) out.u32[h * 2u + i] = a.u32[h * 2u + (1u - i)];
                }
            }
            state_.v[rd] = out;
            return true;
        }
        if (u == 0u && opcode == 0x05u && size == 0u) {
            // CNT Vd.T, Vn.T
            for (uint32_t i = 0; i < lanes_bytes; ++i) {
                out.u8[i] = static_cast<uint8_t>(__builtin_popcount(a.u8[i]));
            }
            state_.v[rd] = out;
            return true;
        }
        if (u == 1u && opcode == 0x05u && size == 0u) {
            // NOT (MVN) Vd.T, Vn.T
            for (uint32_t i = 0; i < (q ? 2u : 1u); ++i) out.u64[i] = ~a.u64[i];
            state_.v[rd] = out;
            return true;
        }
        if (u == 1u && opcode == 0x05u && size == 1u) {
            // RBIT Vd.T, Vn.T
            for (uint32_t i = 0; i < lanes_bytes; ++i) {
                uint8_t b = a.u8[i];
                uint8_t r = 0;
                for (int bit = 0; bit < 8; ++bit) {
                    r = static_cast<uint8_t>((r << 1) | ((b >> bit) & 1u));
                }
                out.u8[i] = r;
            }
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 0x08u || opcode == 0x09u || opcode == 0x0Au) {
            // Zero comparisons: CMGT(u=0,op=8), CMGE(u=1,op=8), CMEQ(u=0,op=9), CMLE(u=1,op=9), CMLT(u=0,op=10)
            auto cmp0 = [&](int64_t v) -> bool {
                if (opcode == 0x08u) return (u == 0u) ? (v > 0) : (v >= 0);
                if (opcode == 0x09u) return (u == 0u) ? (v == 0) : (v <= 0);
                return (u == 0u) ? (v < 0) : false;
            };
            if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i) out.u8[i] = cmp0(a.i8[i]) ? 0xFFu : 0u;
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i) out.u16[i] = cmp0(a.i16[i]) ? 0xFFFFu : 0u;
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i) out.u32[i] = cmp0(a.i32[i]) ? 0xFFFFFFFFu : 0u;
            } else {
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i) out.u64[i] = cmp0(a.i64[i]) ? ~0ULL : 0ULL;
            }
            state_.v[rd] = out;
            return true;
        }
        if (opcode == 0x0Bu) {
            // ABS (u=0) / NEG (u=1)
            const bool is_neg = (u == 1u);
            if (size == 0u) {
                for (uint32_t i = 0; i < lanes_bytes; ++i)
                    out.i8[i] = is_neg ? static_cast<int8_t>(-a.i8[i]) : static_cast<int8_t>(a.i8[i] < 0 ? -a.i8[i] : a.i8[i]);
            } else if (size == 1u) {
                for (uint32_t i = 0; i < lanes_bytes / 2u; ++i)
                    out.i16[i] = is_neg ? static_cast<int16_t>(-a.i16[i]) : static_cast<int16_t>(a.i16[i] < 0 ? -a.i16[i] : a.i16[i]);
            } else if (size == 2u) {
                for (uint32_t i = 0; i < lanes_bytes / 4u; ++i)
                    out.i32[i] = is_neg ? -a.i32[i] : (a.i32[i] < 0 ? -a.i32[i] : a.i32[i]);
            } else {
                for (uint32_t i = 0; i < lanes_bytes / 8u; ++i)
                    out.i64[i] = is_neg ? -a.i64[i] : (a.i64[i] < 0 ? -a.i64[i] : a.i64[i]);
            }
            state_.v[rd] = out;
            return true;
        }
    }

    RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
    return false;
}

} // namespace haseeb::vm
