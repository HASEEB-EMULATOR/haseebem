#include "haseeb/cpu_core.hpp"

#include <cstring>

namespace haseeb::vm {

namespace {

int64_t SignExtend(uint64_t v, int bits) {
    uint64_t shift = 64 - bits;
    return static_cast<int64_t>(v << shift) >> shift;
}

uint64_t ZeroOrSignExtendValue(uint64_t val, int src_bits, bool sign_ext, bool target_64) {
    uint64_t out = val;
    if (sign_ext) {
        out = static_cast<uint64_t>(SignExtend(val, src_bits));
    }
    if (!target_64) {
        out &= 0xFFFFFFFFULL;
    }
    return out;
}

} // namespace

bool AArch64CpuCore::FetchInsn(uint64_t va, uint32_t& out_insn, uint64_t& out_phys) {
    if ((va & 3ULL) != 0) {
        RaiseException(ec::kPcAlign, 0, va, true, va);
        return false;
    }
    const bool is_el1 = state_.pstate.el > 0;
    MmuTranslationResult tr = mmu_.Translate(state_, va, MemAccessType::Execute, is_el1);
    if (!tr.ok) {
        const uint32_t ec_code = is_el1 ? ec::kInsnAbortSame : ec::kInsnAbortLow;
        const uint32_t iss = static_cast<uint32_t>(tr.fault_status) & 0x3Fu;
        RaiseException(ec_code, iss, va, true, va);
        return false;
    }
    out_phys = tr.phys_addr;
    if (tr.host_ram_ptr) {
        std::memcpy(&out_insn, tr.host_ram_ptr, sizeof(out_insn));
        return true;
    }
    if (!ram_.ReadU32(tr.phys_addr, out_insn)) {
        const uint32_t ec_code = is_el1 ? ec::kInsnAbortSame : ec::kInsnAbortLow;
        RaiseException(ec_code, 0x10u, va, true, va);
        return false;
    }
    return true;
}

bool AArch64CpuCore::ReadMem(uint64_t va, unsigned size_bytes, uint64_t& out_val, bool /*acquire*/) {
    const bool is_el1 = state_.pstate.el > 0;
    MmuTranslationResult tr = mmu_.Translate(state_, va, MemAccessType::Read, is_el1);
    if (!tr.ok) {
        const uint32_t ec_code = is_el1 ? ec::kDataAbortSame : ec::kDataAbortLow;
        const uint32_t iss = static_cast<uint32_t>(tr.fault_status) & 0x3Fu;
        RaiseException(ec_code, iss, va, true, state_.pc);
        return false;
    }

    // Fast path for normal RAM accesses within a single host page
    if (tr.host_ram_ptr && ((va & 0xFFFu) + size_bytes <= 4096u)) {
        out_val = 0;
        std::memcpy(&out_val, tr.host_ram_ptr, size_bytes);
        return true;
    }

    // Page-crossing load fallback
    if ((va & 0xFFFu) + size_bytes > 4096u) {
        uint64_t acc = 0;
        for (unsigned b = 0; b < size_bytes; ++b) {
            uint64_t byte_val = 0;
            if (!ReadMem(va + b, 1, byte_val, false)) return false;
            acc |= (byte_val & 0xFFULL) << (b * 8u);
        }
        out_val = acc;
        return true;
    }

    uint64_t mmio_v = 0;
    if (mmio_bus_.Read(tr.phys_addr, size_bytes, mmio_v)) {
        out_val = mmio_v;
        return true;
    }

    out_val = 0;
    if (!ram_.ReadBytes(tr.phys_addr, &out_val, size_bytes)) {
        const uint32_t ec_code = is_el1 ? ec::kDataAbortSame : ec::kDataAbortLow;
        RaiseException(ec_code, 0x10u, va, true, state_.pc);
        return false;
    }
    return true;
}

bool AArch64CpuCore::WriteMem(uint64_t va, unsigned size_bytes, uint64_t val, bool /*release*/) {
    const bool is_el1 = state_.pstate.el > 0;
    MmuTranslationResult tr = mmu_.Translate(state_, va, MemAccessType::Write, is_el1);
    if (!tr.ok) {
        const uint32_t ec_code = is_el1 ? ec::kDataAbortSame : ec::kDataAbortLow;
        const uint32_t iss = (1u << 6) | (static_cast<uint32_t>(tr.fault_status) & 0x3Fu); // WnR=1
        RaiseException(ec_code, iss, va, true, state_.pc);
        return false;
    }

    // Cross-page write fallback
    if ((va & 0xFFFu) + size_bytes > 4096u) {
        for (unsigned b = 0; b < size_bytes; ++b) {
            if (!WriteMem(va + b, 1, (val >> (b * 8u)) & 0xFFULL, false)) return false;
        }
        return true;
    }

    // Invalidate exclusive monitor if store overlaps reserved physical address
    if (state_.excl.valid) {
        const uint64_t ex_start = state_.excl.phys_addr & ~7ULL;
        const uint64_t ex_end = ex_start + 16ULL;
        if (tr.phys_addr < ex_end && tr.phys_addr + size_bytes > ex_start) {
            state_.excl.valid = false;
        }
    }

    if (tr.host_ram_ptr) {
        std::memcpy(tr.host_ram_ptr, &val, size_bytes);
        cache_.InvalidatePhysPage(tr.phys_addr);
        return true;
    }

    if (mmio_bus_.Write(tr.phys_addr, size_bytes, val)) {
        return true;
    }

    if (!ram_.WriteBytes(tr.phys_addr, &val, size_bytes)) {
        const uint32_t ec_code = is_el1 ? ec::kDataAbortSame : ec::kDataAbortLow;
        RaiseException(ec_code, (1u << 6) | 0x10u, va, true, state_.pc);
        return false;
    }
    cache_.InvalidatePhysPage(tr.phys_addr);
    return true;
}

bool AArch64CpuCore::ReadMem128(uint64_t va, uint64_t& lo, uint64_t& hi) {
    return ReadMem(va, 8, lo, false) && ReadMem(va + 8, 8, hi, false);
}

bool AArch64CpuCore::WriteMem128(uint64_t va, uint64_t lo, uint64_t hi) {
    return WriteMem(va, 8, lo, false) && WriteMem(va + 8, 8, hi, false);
}

bool AArch64CpuCore::ExecuteLoadStoreImm(const DecodedInsn& d) {
    const uint32_t insn = d.raw;
    const uint32_t size = (insn >> 30) & 3u;
    const bool v_simd = ((insn >> 26) & 1u) != 0;
    const uint32_t opc = (insn >> 22) & 3u;
    const bool is_unsigned_imm = ((insn >> 24) & 1u) != 0;
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);

    if (v_simd && !CheckFpSimdEnabled()) return false;

    uint32_t datasize = 1u << size;
    if (v_simd && (opc & 2u) != 0 && size == 0u) {
        datasize = 16u; // 128-bit Qt load/store
    }

    uint64_t base = state_.ReadRegOrSp(rn);
    int64_t offset = 0;
    bool writeback = false;
    bool post_index = false;

    if (is_unsigned_imm) {
        uint64_t imm12 = (insn >> 10) & 0xFFFu;
        offset = static_cast<int64_t>(imm12 * datasize);
    } else {
        uint32_t mode = (insn >> 10) & 3u; // 00=unscaled, 01=post-index, 11=pre-index
        offset = SignExtend((insn >> 12) & 0x1FFu, 9);
        if (mode == 1u) {
            writeback = true;
            post_index = true;
        } else if (mode == 3u) {
            writeback = true;
            post_index = false;
        }
    }

    const uint64_t addr = post_index ? base : static_cast<uint64_t>(static_cast<int64_t>(base) + offset);

    bool is_store = false;
    bool sign_ext = false;
    bool target_64 = true;
    if (v_simd) {
        is_store = ((opc & 1u) == 0u);
    } else {
        if (size == 3u && opc == 2u) {
            return true; // PRFM immediate is an architectural hint (no-op)
        }
        is_store = (opc == 0u);
        sign_ext = (opc >= 2u);
        target_64 = (opc == 2u) || (size == 3u);
    }

    if (is_store) {
        if (v_simd) {
            if (datasize == 16u) {
                if (!WriteMem128(addr, state_.v[rt].u64[0], state_.v[rt].u64[1])) return false;
            } else {
                if (!WriteMem(addr, datasize, state_.v[rt].u64[0], false)) return false;
            }
        } else {
            uint64_t v = state_.ReadRegOrZero(rt);
            if (!WriteMem(addr, datasize, v, false)) return false;
        }
    } else {
        if (v_simd) {
            state_.v[rt] = NeonReg{};
            if (datasize == 16u) {
                uint64_t lo = 0, hi = 0;
                if (!ReadMem128(addr, lo, hi)) return false;
                state_.v[rt].u64[0] = lo;
                state_.v[rt].u64[1] = hi;
            } else {
                uint64_t lo = 0;
                if (!ReadMem(addr, datasize, lo, false)) return false;
                state_.v[rt].u64[0] = lo;
            }
        } else {
            uint64_t loaded = 0;
            if (!ReadMem(addr, datasize, loaded, false)) return false;
            uint64_t final_val = ZeroOrSignExtendValue(loaded, static_cast<int>(datasize * 8u), sign_ext, target_64);
            state_.WriteRegOrDiscard(rt, final_val);
        }
    }

    if (writeback) {
        state_.WriteRegOrSp(rn, static_cast<uint64_t>(static_cast<int64_t>(base) + offset));
    }
    return true;
}

bool AArch64CpuCore::ExecuteLoadStoreReg(const DecodedInsn& d) {
    const uint32_t insn = d.raw;
    const uint32_t size = (insn >> 30) & 3u;
    const bool v_simd = ((insn >> 26) & 1u) != 0;
    const uint32_t opc = (insn >> 22) & 3u;
    const uint8_t rm = static_cast<uint8_t>((insn >> 16) & 31u);
    const uint32_t option = (insn >> 13) & 7u;
    const bool s_bit = ((insn >> 12) & 1u) != 0;
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);

    if (v_simd && !CheckFpSimdEnabled()) return false;

    uint32_t datasize = 1u << size;
    uint32_t scale = size;
    if (v_simd && (opc & 2u) != 0 && size == 0u) {
        datasize = 16u;
        scale = 4u;
    }

    uint64_t idx = state_.ReadRegOrZero(rm);
    if (option == 2u) idx = static_cast<uint64_t>(static_cast<uint32_t>(idx));       // UXTW
    else if (option == 6u) idx = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(idx))); // SXTW
    else if (option == 7u) idx = static_cast<uint64_t>(static_cast<int64_t>(idx));   // SXTX
    // option == 3 => LSL (64-bit)
    if (s_bit) idx <<= scale;

    const uint64_t addr = state_.ReadRegOrSp(rn) + idx;
    if (!v_simd && size == 3u && opc == 2u) {
        return true; // PRFM register is an architectural hint (no-op)
    }
    bool is_store = v_simd ? ((opc & 1u) == 0u) : (opc == 0u);
    bool sign_ext = !v_simd && (opc >= 2u);
    bool target_64 = v_simd || (opc == 2u) || (size == 3u);

    if (is_store) {
        if (v_simd) {
            if (datasize == 16u) return WriteMem128(addr, state_.v[rt].u64[0], state_.v[rt].u64[1]);
            return WriteMem(addr, datasize, state_.v[rt].u64[0], false);
        }
        return WriteMem(addr, datasize, state_.ReadRegOrZero(rt), false);
    } else {
        if (v_simd) {
            state_.v[rt] = NeonReg{};
            if (datasize == 16u) return ReadMem128(addr, state_.v[rt].u64[0], state_.v[rt].u64[1]);
            return ReadMem(addr, datasize, state_.v[rt].u64[0], false);
        }
        uint64_t loaded = 0;
        if (!ReadMem(addr, datasize, loaded, false)) return false;
        state_.WriteRegOrDiscard(rt, ZeroOrSignExtendValue(loaded, static_cast<int>(datasize * 8u), sign_ext, target_64));
        return true;
    }
}

bool AArch64CpuCore::ExecuteLoadStorePair(const DecodedInsn& d) {
    const uint32_t insn = d.raw;
    const uint32_t opc = (insn >> 30) & 3u;
    const bool v_simd = ((insn >> 26) & 1u) != 0;
    const uint32_t mode = (insn >> 23) & 3u; // 0=NP, 1=post, 2=offset, 3=pre
    const bool is_load = ((insn >> 22) & 1u) != 0;
    const int64_t imm7 = SignExtend((insn >> 15) & 0x7Fu, 7);
    const uint8_t rt2 = static_cast<uint8_t>((insn >> 10) & 31u);
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);

    if (v_simd && !CheckFpSimdEnabled()) return false;

    uint32_t datasize = 4u;
    if (v_simd) {
        datasize = (opc == 0u) ? 4u : (opc == 1u ? 8u : 16u);
    } else {
        datasize = (opc >= 2u) ? 8u : 4u;
    }

    const int64_t offset = imm7 * static_cast<int64_t>(datasize);
    const uint64_t base = state_.ReadRegOrSp(rn);
    const bool post_index = (mode == 1u);
    const bool writeback = (mode == 1u || mode == 3u);
    const uint64_t addr = post_index ? base : static_cast<uint64_t>(static_cast<int64_t>(base) + offset);

    if (is_load) {
        if (v_simd) {
            state_.v[rt] = NeonReg{};
            state_.v[rt2] = NeonReg{};
            if (datasize == 16u) {
                if (!ReadMem128(addr, state_.v[rt].u64[0], state_.v[rt].u64[1])) return false;
                if (!ReadMem128(addr + 16u, state_.v[rt2].u64[0], state_.v[rt2].u64[1])) return false;
            } else {
                if (!ReadMem(addr, datasize, state_.v[rt].u64[0], false)) return false;
                if (!ReadMem(addr + datasize, datasize, state_.v[rt2].u64[0], false)) return false;
            }
        } else {
            uint64_t v1 = 0, v2 = 0;
            if (!ReadMem(addr, datasize, v1, false)) return false;
            if (!ReadMem(addr + datasize, datasize, v2, false)) return false;
            const bool sign_ext = (opc == 1u); // LDPSW
            state_.WriteRegOrDiscard(rt, ZeroOrSignExtendValue(v1, static_cast<int>(datasize * 8u), sign_ext, datasize == 8u || sign_ext));
            state_.WriteRegOrDiscard(rt2, ZeroOrSignExtendValue(v2, static_cast<int>(datasize * 8u), sign_ext, datasize == 8u || sign_ext));
        }
    } else {
        if (v_simd) {
            if (datasize == 16u) {
                if (!WriteMem128(addr, state_.v[rt].u64[0], state_.v[rt].u64[1])) return false;
                if (!WriteMem128(addr + 16u, state_.v[rt2].u64[0], state_.v[rt2].u64[1])) return false;
            } else {
                if (!WriteMem(addr, datasize, state_.v[rt].u64[0], false)) return false;
                if (!WriteMem(addr + datasize, datasize, state_.v[rt2].u64[0], false)) return false;
            }
        } else {
            if (!WriteMem(addr, datasize, state_.ReadRegOrZero(rt), false)) return false;
            if (!WriteMem(addr + datasize, datasize, state_.ReadRegOrZero(rt2), false)) return false;
        }
    }

    if (writeback) {
        state_.WriteRegOrSp(rn, static_cast<uint64_t>(static_cast<int64_t>(base) + offset));
    }
    return true;
}

bool AArch64CpuCore::ExecuteExclusive(const DecodedInsn& d) {
    const uint32_t insn = d.raw;
    const uint32_t size = (insn >> 30) & 3u;
    const uint32_t o2 = (insn >> 23) & 1u;
    const uint32_t l_bit = (insn >> 22) & 1u;
    const uint32_t o1 = (insn >> 21) & 1u;
    const uint8_t rs = static_cast<uint8_t>((insn >> 16) & 31u);
    const uint32_t o0 = (insn >> 15) & 1u;
    const uint8_t rt2 = static_cast<uint8_t>((insn >> 10) & 31u);
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);

    const uint32_t datasize = 1u << size;
    const uint64_t addr = state_.ReadRegOrSp(rn);

    // Load-Acquire / Store-Release (o2 == 1, o1 == 0)
    if (o2 == 1u && o1 == 0u) {
        if (l_bit) {
            uint64_t val = 0;
            if (!ReadMem(addr, datasize, val, o0 == 1u)) return false;
            state_.WriteRegOrDiscard(rt, val);
        } else {
            if (!WriteMem(addr, datasize, state_.ReadRegOrZero(rt), o0 == 1u)) return false;
        }
        return true;
    }

    // Exclusive pairs (o1 == 1: LDXP/STXP/LDAXP/STLXP)
    if (o1 == 1u) {
        const uint32_t pair_bytes = datasize * 2u;
        MmuTranslationResult tr = mmu_.Translate(state_, addr,
            l_bit ? MemAccessType::Read : MemAccessType::Write, state_.pstate.el > 0);
        if (!tr.ok) {
            const uint32_t ec_code = (state_.pstate.el > 0) ? ec::kDataAbortSame : ec::kDataAbortLow;
            RaiseException(ec_code, (l_bit ? 0u : (1u << 6)) | static_cast<uint32_t>(tr.fault_status), addr, true, state_.pc);
            return false;
        }
        if (l_bit) {
            uint64_t v1 = 0, v2 = 0;
            if (!ReadMem(addr, datasize, v1, o0 == 1u)) return false;
            if (!ReadMem(addr + datasize, datasize, v2, o0 == 1u)) return false;
            state_.WriteRegOrDiscard(rt, v1);
            state_.WriteRegOrDiscard(rt2, v2);
            state_.excl.valid = true;
            state_.excl.phys_addr = tr.phys_addr;
            state_.excl.size_bytes = static_cast<uint8_t>(pair_bytes);
        } else {
            if (state_.excl.valid && state_.excl.phys_addr == tr.phys_addr && state_.excl.size_bytes == pair_bytes) {
                state_.excl.valid = false;
                if (!WriteMem(addr, datasize, state_.ReadRegOrZero(rt), o0 == 1u)) return false;
                if (!WriteMem(addr + datasize, datasize, state_.ReadRegOrZero(rt2), o0 == 1u)) return false;
                state_.WriteRegOrDiscard(rs, 0ULL); // success
            } else {
                state_.excl.valid = false;
                state_.WriteRegOrDiscard(rs, 1ULL); // failed
            }
        }
        return true;
    }

    // Single exclusive (o2 == 0, o1 == 0: LDXR/STXR/LDAXR/STLXR)
    MmuTranslationResult tr = mmu_.Translate(state_, addr,
        l_bit ? MemAccessType::Read : MemAccessType::Write, state_.pstate.el > 0);
    if (!tr.ok) {
        const uint32_t ec_code = (state_.pstate.el > 0) ? ec::kDataAbortSame : ec::kDataAbortLow;
        RaiseException(ec_code, (l_bit ? 0u : (1u << 6)) | static_cast<uint32_t>(tr.fault_status), addr, true, state_.pc);
        return false;
    }

    if (l_bit) {
        uint64_t val = 0;
        if (!ReadMem(addr, datasize, val, o0 == 1u)) return false;
        state_.WriteRegOrDiscard(rt, val);
        state_.excl.valid = true;
        state_.excl.phys_addr = tr.phys_addr;
        state_.excl.size_bytes = static_cast<uint8_t>(datasize);
    } else {
        if (state_.excl.valid && state_.excl.phys_addr == tr.phys_addr && state_.excl.size_bytes == datasize) {
            state_.excl.valid = false;
            if (!WriteMem(addr, datasize, state_.ReadRegOrZero(rt), o0 == 1u)) return false;
            state_.WriteRegOrDiscard(rs, 0ULL); // 0 = store succeeded
        } else {
            state_.excl.valid = false;
            state_.WriteRegOrDiscard(rs, 1ULL); // 1 = store failed
        }
    }
    return true;
}

bool AArch64CpuCore::ExecuteAtomicLse(const DecodedInsn& d) {
    const uint32_t insn = d.raw;
    const uint32_t size = (insn >> 30) & 3u;
    const uint32_t datasize = 1u << size;
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);
    const uint64_t addr = state_.ReadRegOrSp(rn);

    // CAS / CASP (bits[29:24] == 001000)
    if ((insn & 0x3F000000u) == 0x08000000u) {
        const uint8_t rs = static_cast<uint8_t>((insn >> 16) & 31u);
        uint64_t expected = state_.ReadRegOrZero(rs);
        uint64_t desired = state_.ReadRegOrZero(rt);
        uint64_t mask = (datasize == 8u) ? ~0ULL : ((1ULL << (datasize * 8u)) - 1ULL);
        uint64_t cur = 0;
        if (!ReadMem(addr, datasize, cur, true)) return false;
        if ((cur & mask) == (expected & mask)) {
            if (!WriteMem(addr, datasize, desired & mask, true)) return false;
        }
        state_.WriteRegOrDiscard(rs, cur & mask);
        return true;
    }

    // LDADD / LDCLR / LDEOR / LDSET / SWP
    const uint8_t rs = static_cast<uint8_t>((insn >> 16) & 31u);
    const uint32_t opc = (insn >> 12) & 7u;
    const bool is_swp = ((insn >> 12) & 0xFu) == 8u;
    const uint64_t mask = (datasize == 8u) ? ~0ULL : ((1ULL << (datasize * 8u)) - 1ULL);

    uint64_t old_val = 0;
    if (!ReadMem(addr, datasize, old_val, true)) return false;
    old_val &= mask;

    const uint64_t arg = state_.ReadRegOrZero(rs) & mask;
    uint64_t new_val = old_val;
    if (is_swp) {
        new_val = arg;
    } else {
        switch (opc) {
            case 0u: new_val = (old_val + arg) & mask; break;     // LDADD
            case 1u: new_val = (old_val & ~arg) & mask; break;    // LDCLR
            case 2u: new_val = (old_val ^ arg) & mask; break;     // LDEOR
            case 3u: new_val = (old_val | arg) & mask; break;     // LDSET
            case 4u: new_val = (static_cast<int64_t>(SignExtend(old_val, datasize * 8)) >
                                static_cast<int64_t>(SignExtend(arg, datasize * 8))) ? old_val : arg; break;
            case 5u: new_val = (static_cast<int64_t>(SignExtend(old_val, datasize * 8)) <
                                static_cast<int64_t>(SignExtend(arg, datasize * 8))) ? old_val : arg; break;
            case 6u: new_val = (old_val > arg) ? old_val : arg; break;
            case 7u: new_val = (old_val < arg) ? old_val : arg; break;
        }
    }

    if (!WriteMem(addr, datasize, new_val, true)) return false;
    state_.WriteRegOrDiscard(rt, old_val);
    return true;
}

bool AArch64CpuCore::ExecuteLoadStoreSimdStruct(const DecodedInsn& d) {
    if (!CheckFpSimdEnabled()) return false;

    const uint32_t insn = d.raw;
    const bool q = ((insn >> 30) & 1u) != 0;
    const bool is_single = ((insn >> 24) & 1u) != 0;
    const bool is_post = ((insn >> 23) & 1u) != 0;
    const bool is_load = ((insn >> 22) & 1u) != 0;
    const uint8_t rm = static_cast<uint8_t>((insn >> 16) & 31u);
    const uint8_t rn = static_cast<uint8_t>((insn >> 5) & 31u);
    const uint8_t rt = static_cast<uint8_t>(insn & 31u);

    const uint64_t base = state_.ReadRegOrSp(rn);
    const uint32_t reg_bytes = q ? 16u : 8u;

    auto write_elem = [&](uint8_t reg_idx, uint32_t elem_bytes, uint32_t elem_idx, uint64_t val) {
        if (elem_bytes == 1u) state_.v[reg_idx].u8[elem_idx] = static_cast<uint8_t>(val);
        else if (elem_bytes == 2u) state_.v[reg_idx].u16[elem_idx] = static_cast<uint16_t>(val);
        else if (elem_bytes == 4u) state_.v[reg_idx].u32[elem_idx] = static_cast<uint32_t>(val);
        else state_.v[reg_idx].u64[elem_idx] = val;
    };
    auto read_elem = [&](uint8_t reg_idx, uint32_t elem_bytes, uint32_t elem_idx) -> uint64_t {
        if (elem_bytes == 1u) return state_.v[reg_idx].u8[elem_idx];
        if (elem_bytes == 2u) return state_.v[reg_idx].u16[elem_idx];
        if (elem_bytes == 4u) return state_.v[reg_idx].u32[elem_idx];
        return state_.v[reg_idx].u64[elem_idx];
    };

    if (!is_single) {
        // AdvSIMD Load/Store multiple structures: 0 Q 001100 P L 0 Rm opcode size Rn Rt
        const uint32_t opcode = (insn >> 12) & 0xFu;
        const uint32_t size = (insn >> 10) & 3u;
        uint32_t rpt = 1u;
        uint32_t selem = 1u;
        switch (opcode) {
            case 0x7u: rpt = 1u; selem = 1u; break; // LD1/ST1 (1 reg)
            case 0xAu: rpt = 2u; selem = 1u; break; // LD1/ST1 (2 regs)
            case 0x6u: rpt = 3u; selem = 1u; break; // LD1/ST1 (3 regs)
            case 0x2u: rpt = 4u; selem = 1u; break; // LD1/ST1 (4 regs)
            case 0x8u: rpt = 1u; selem = 2u; break; // LD2/ST2
            case 0x4u: rpt = 1u; selem = 3u; break; // LD3/ST3
            case 0x0u: rpt = 1u; selem = 4u; break; // LD4/ST4
            default:
                RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
                return false;
        }
        const uint32_t elem_bytes = 1u << size;
        if (elem_bytes > reg_bytes) {
            RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
            return false;
        }
        const uint32_t elems_per_reg = reg_bytes / elem_bytes;
        const uint32_t nregs = rpt * selem;

        uint64_t addr = base;
        if (is_load) {
            for (uint32_t i = 0; i < nregs; ++i) {
                const uint8_t reg_idx = static_cast<uint8_t>((rt + i) & 31u);
                if (!q) state_.v[reg_idx].u64[1] = 0ULL;
            }
            for (uint32_t r = 0; r < rpt; ++r) {
                for (uint32_t e = 0; e < elems_per_reg; ++e) {
                    uint8_t tt = static_cast<uint8_t>((rt + r) & 31u);
                    for (uint32_t s = 0; s < selem; ++s) {
                        uint64_t val = 0;
                        if (!ReadMem(addr, elem_bytes, val, false)) return false;
                        write_elem(tt, elem_bytes, e, val);
                        addr += elem_bytes;
                        tt = static_cast<uint8_t>((tt + 1u) & 31u);
                    }
                }
            }
        } else {
            for (uint32_t r = 0; r < rpt; ++r) {
                for (uint32_t e = 0; e < elems_per_reg; ++e) {
                    uint8_t tt = static_cast<uint8_t>((rt + r) & 31u);
                    for (uint32_t s = 0; s < selem; ++s) {
                        const uint64_t val = read_elem(tt, elem_bytes, e);
                        if (!WriteMem(addr, elem_bytes, val, false)) return false;
                        addr += elem_bytes;
                        tt = static_cast<uint8_t>((tt + 1u) & 31u);
                    }
                }
            }
        }

        if (is_post) {
            const uint64_t wb_off = (rm == 31u)
                ? static_cast<uint64_t>(nregs * reg_bytes)
                : state_.ReadRegOrZero(rm);
            state_.WriteRegOrSp(rn, base + wb_off);
        }
        return true;
    }

    // AdvSIMD Load/Store single structure: 0 Q 001101 P L R Rm opcode S size Rn Rt
    const bool r_bit = ((insn >> 21) & 1u) != 0;
    const uint32_t opcode = (insn >> 13) & 7u;
    const uint32_t s_bit = (insn >> 12) & 1u;
    const uint32_t size = (insn >> 10) & 3u;
    const uint32_t scale = opcode >> 1;
    const uint32_t selem = (((opcode & 1u) << 1) | (r_bit ? 1u : 0u)) + 1u;
    const bool replicate = (scale == 3u);

    uint32_t elem_bytes = 1u;
    uint32_t index = 0u;
    if (replicate) {
        if (!is_load || s_bit != 0u) {
            RaiseException(ec::kUnknown, 0, 0, false, state_.pc);
            return false;
        }
        elem_bytes = 1u << size;
    } else if (scale == 0u) {
        elem_bytes = 1u;
        index = ((q ? 1u : 0u) << 3) | (s_bit << 2) | size;
    } else if (scale == 1u) {
        elem_bytes = 2u;
        index = ((q ? 1u : 0u) << 2) | (s_bit << 1) | (size >> 1);
    } else if ((size & 1u) == 0u) {
        elem_bytes = 4u;
        index = ((q ? 1u : 0u) << 1) | s_bit;
    } else {
        elem_bytes = 8u;
        index = q ? 1u : 0u;
    }

    uint64_t addr = base;
    for (uint32_t s = 0; s < selem; ++s) {
        const uint8_t tt = static_cast<uint8_t>((rt + s) & 31u);
        if (is_load) {
            uint64_t val = 0;
            if (!ReadMem(addr, elem_bytes, val, false)) return false;
            if (replicate) {
                const uint32_t count = reg_bytes / elem_bytes;
                state_.v[tt] = NeonReg{};
                for (uint32_t e = 0; e < count; ++e) {
                    write_elem(tt, elem_bytes, e, val);
                }
            } else {
                write_elem(tt, elem_bytes, index, val);
            }
        } else {
            const uint64_t val = read_elem(tt, elem_bytes, index);
            if (!WriteMem(addr, elem_bytes, val, false)) return false;
        }
        addr += elem_bytes;
    }

    if (is_post) {
        const uint64_t wb_off = (rm == 31u)
            ? static_cast<uint64_t>(selem * elem_bytes)
            : state_.ReadRegOrZero(rm);
        state_.WriteRegOrSp(rn, base + wb_off);
    }
    return true;
}

} // namespace haseeb::vm
