#include "haseeb/dbt_cache.hpp"

#include <algorithm>

namespace haseeb::vm {

namespace {

int64_t SignExtend(uint64_t v, int bits) {
    uint64_t shift = 64 - bits;
    return static_cast<int64_t>(v << shift) >> shift;
}

} // namespace

TranslationCache::TranslationCache() : l1_table_(kL1Slots, nullptr) {}

DecodedInsn TranslationCache::DecodeOne(uint32_t insn) {
    DecodedInsn d{};
    d.raw = insn;

    // 1. Branches, Exception Generation, System Instructions (bits[28:25] == 101x)
    if ((insn & 0x1C000000u) == 0x14000000u) {
        // Unconditional branch immediate: B / BL
        if ((insn & 0x7C000000u) == 0x14000000u) {
            d.kind = InsnKind::BranchImm;
            d.set_flags = ((insn >> 31) & 1u) != 0; // BL links X30
            d.simm = SignExtend(insn & 0x03FFFFFFu, 26) * 4;
            d.is_terminating = true;
            return d;
        }
        // Conditional branch: B.cond
        if ((insn & 0xFF000010u) == 0x54000000u) {
            d.kind = InsnKind::BranchCond;
            d.cond = static_cast<uint8_t>(insn & 0xFu);
            d.simm = SignExtend((insn >> 5) & 0x7FFFFu, 19) * 4;
            d.is_terminating = true;
            return d;
        }
        // Compare & branch: CBZ / CBNZ
        if ((insn & 0x7E000000u) == 0x34000000u) {
            d.kind = InsnKind::CompareBranch;
            d.sf64 = (insn >> 31) != 0;
            d.cond = static_cast<uint8_t>((insn >> 24) & 1u); // 0=CBZ, 1=CBNZ
            d.rd = static_cast<uint8_t>(insn & 31u);
            d.simm = SignExtend((insn >> 5) & 0x7FFFFu, 19) * 4;
            d.is_terminating = true;
            return d;
        }
        // Test & branch: TBZ / TBNZ
        if ((insn & 0x7E000000u) == 0x36000000u) {
            d.kind = InsnKind::TestBranch;
            d.cond = static_cast<uint8_t>((insn >> 24) & 1u); // 0=TBZ, 1=TBNZ
            d.imm = (((insn >> 31) & 1u) << 5) | ((insn >> 19) & 0x1Fu); // bit index 0..63
            d.rd = static_cast<uint8_t>(insn & 31u);
            d.simm = SignExtend((insn >> 5) & 0x3FFFu, 14) * 4;
            d.is_terminating = true;
            return d;
        }
        // Exception generation
        if ((insn & 0xFF000000u) == 0xD4000000u) {
            d.imm = (insn >> 5) & 0xFFFFu;
            d.is_terminating = true;
            if ((insn & 0xFFE0001Fu) == 0xD4000001u) {
                d.kind = InsnKind::Svc;
                return d;
            }
            if ((insn & 0xFFE0001Fu) == 0xD4000002u) {
                d.kind = InsnKind::Hvc;
                return d;
            }
            if ((insn & 0xFFE0001Fu) == 0xD4000003u) {
                d.kind = InsnKind::Smc;
                return d;
            }
            if ((insn & 0xFFE0001Fu) == 0xD4200000u) {
                d.kind = InsnKind::Brk;
                return d;
            }
            if ((insn & 0xFFE0001Fu) == 0xD4400000u) {
                d.kind = InsnKind::Hlt;
                return d;
            }
            d.kind = InsnKind::Unmapped;
            return d;
        }
        // System instructions
        if ((insn & 0xFFC00000u) == 0xD5000000u) {
            if ((insn & 0xFFFFF01Fu) == 0xD503201Fu) {
                d.kind = InsnKind::NopHint;
                uint32_t hint = (insn >> 5) & 0x7Fu;
                d.imm = hint;
                d.is_terminating = (hint == 2u || hint == 3u); // WFE/WFI break block
                return d;
            }
            if ((insn & 0xFFFFF0FFu) == 0xD503305Fu ||
                (insn & 0xFFFFF09Fu) == 0xD503309Fu) {
                d.kind = InsnKind::Barrier;
                // ISB forces end of basic block for SMC / context sync correctness
                d.is_terminating = ((insn & 0xFFFFF0FFu) == 0xD50330DFu);
                return d;
            }
            if ((insn & 0xFFF8F01Fu) == 0xD500401Fu) {
                d.kind = InsnKind::MsrImm;
                d.is_terminating = true; // PSTATE/SPSEL/DAIF change ends block
                return d;
            }
            if ((insn & 0xFFF80000u) == 0xD5080000u) {
                d.kind = InsnKind::SysOp;
                d.rd = static_cast<uint8_t>(insn & 31u);
                d.is_terminating = true;
                return d;
            }
            if ((insn & 0xFFF00000u) == 0xD5100000u) {
                d.kind = InsnKind::MsrReg;
                d.rd = static_cast<uint8_t>(insn & 31u);
                d.is_terminating = true; // Sysreg writes (SCTLR/TTBR/VBAR) may alter MMU/ctx
                return d;
            }
            if ((insn & 0xFFF00000u) == 0xD5300000u) {
                d.kind = InsnKind::Mrs;
                d.rd = static_cast<uint8_t>(insn & 31u);
                return d;
            }
            d.kind = InsnKind::Unmapped;
            d.is_terminating = true;
            return d;
        }
        // Unconditional branch (register) & ERET
        if ((insn & 0xFE000000u) == 0xD6000000u) {
            d.is_terminating = true;
            if (insn == 0xD69F03E0u) {
                d.kind = InsnKind::Eret;
                return d;
            }
            if ((insn & 0xFF9FFC1Fu) == 0xD61F0000u) {
                // BR (opc=00), BLR (opc=01), RET (opc=10)
                d.kind = InsnKind::BranchReg;
                d.cond = static_cast<uint8_t>((insn >> 21) & 3u);
                d.rn = static_cast<uint8_t>((insn >> 5) & 31u);
                return d;
            }
            d.kind = InsnKind::Unmapped;
            return d;
        }
    }

    // 2. Data Processing — Immediate (bits[28:26] == 100)
    if ((insn & 0x1C000000u) == 0x10000000u) {
        d.sf64 = (insn >> 31) != 0;
        d.rd = static_cast<uint8_t>(insn & 31u);
        d.rn = static_cast<uint8_t>((insn >> 5) & 31u);
        if ((insn & 0x1F000000u) == 0x10000000u) {
            d.kind = ((insn >> 31) != 0) ? InsnKind::Adrp : InsnKind::Adr;
            uint64_t immlo = (insn >> 29) & 3u;
            uint64_t immhi = (insn >> 5) & 0x7FFFFu;
            int64_t imm21 = SignExtend((immhi << 2) | immlo, 21);
            d.simm = (d.kind == InsnKind::Adrp) ? (imm21 << 12) : imm21;
            return d;
        }
        if ((insn & 0x1F800000u) == 0x11000000u) {
            d.kind = InsnKind::AddSubImm;
            d.cond = static_cast<uint8_t>((insn >> 30) & 1u); // 0=ADD, 1=SUB
            d.set_flags = ((insn >> 29) & 1u) != 0;
            uint64_t imm12 = (insn >> 10) & 0xFFFu;
            if ((insn >> 22) & 1u) imm12 <<= 12;
            d.imm = imm12;
            return d;
        }
        if ((insn & 0x1F800000u) == 0x12000000u) {
            d.kind = InsnKind::LogicalImm;
            d.cond = static_cast<uint8_t>((insn >> 29) & 3u); // 0=AND,1=ORR,2=EOR,3=ANDS
            d.set_flags = (d.cond == 3u);
            return d;
        }
        if ((insn & 0x1F800000u) == 0x12800000u) {
            d.kind = InsnKind::MovWide;
            d.cond = static_cast<uint8_t>((insn >> 29) & 3u); // 0=MOVN,2=MOVZ,3=MOVK
            d.rm = static_cast<uint8_t>((insn >> 21) & 3u);   // hw
            d.imm = (insn >> 5) & 0xFFFFu;
            return d;
        }
        if ((insn & 0x1F800000u) == 0x13000000u) {
            d.kind = InsnKind::Bitfield;
            d.cond = static_cast<uint8_t>((insn >> 29) & 3u); // 0=SBFM,1=BFM,2=UBFM
            return d;
        }
        if ((insn & 0x1F800000u) == 0x13800000u) {
            d.kind = InsnKind::Extract;
            d.rm = static_cast<uint8_t>((insn >> 16) & 31u);
            d.imm = (insn >> 10) & 0x3Fu;
            return d;
        }
    }

    // 3. Loads and Stores (op0 bits[27:25] = x1x0 -> (insn & 0x0A000000) == 0x08000000)
    if ((insn & 0x0A000000u) == 0x08000000u) {
        // AdvSIMD Load/Store multiple & single structures (LD1..4 / ST1..4 / LD1R..4R)
        if ((insn & 0xBFBF0000u) == 0x0C000000u ||
            (insn & 0xBFA00000u) == 0x0C800000u ||
            (insn & 0xBF9F0000u) == 0x0D000000u ||
            (insn & 0xBF800000u) == 0x0D800000u) {
            d.kind = InsnKind::LoadStoreSimdStruct;
            return d;
        }
        // Load/Store Exclusive & Ordered + CAS (bits[29:24] == 001000)
        if ((insn & 0x3F000000u) == 0x08000000u) {
            // Distinguish CAS/CASP (bit21 == 1 and bits[14:10] == 11111) vs Exclusives (bit21 == 0)
            if ((insn & 0x00207C00u) == 0x00207C00u) {
                d.kind = InsnKind::AtomicLse;
            } else {
                d.kind = InsnKind::Exclusive;
            }
            return d;
        }
        // Load register (literal)
        if ((insn & 0x3B000000u) == 0x18000000u) {
            d.kind = InsnKind::LoadLiteral;
            d.rd = static_cast<uint8_t>(insn & 31u);
            d.simm = SignExtend((insn >> 5) & 0x7FFFFu, 19) * 4;
            return d;
        }
        // Load/Store Pair (including LDNP/STNP and SIMD pairs)
        if ((insn & 0x3A000000u) == 0x28000000u) {
            d.kind = InsnKind::LoadStorePair;
            return d;
        }
        // Load/Store single register + LSE Atomics
        if ((insn & 0x3B000000u) == 0x38000000u || (insn & 0x3B000000u) == 0x39000000u) {
            const bool is_unsigned_imm = ((insn >> 24) & 1u) != 0;
            const bool bit21 = ((insn >> 21) & 1u) != 0;
            const uint32_t bits11_10 = (insn >> 10) & 3u;
            const bool is_simd = ((insn >> 26) & 1u) != 0;
            if (!is_unsigned_imm && bit21) {
                if (bits11_10 == 2u) {
                    d.kind = InsnKind::LoadStoreReg;
                } else if (!is_simd && bits11_10 == 0u && ((insn >> 15) & 1u) == 0) {
                    d.kind = InsnKind::AtomicLse;
                } else {
                    d.kind = InsnKind::Unmapped;
                    d.is_terminating = true;
                }
            } else {
                d.kind = InsnKind::LoadStoreImm;
            }
            return d;
        }
    }

    // 4. Data Processing — Register (bits[27:25] == 101 -> (insn & 0x0E000000) == 0x0A000000)
    if ((insn & 0x0E000000u) == 0x0A000000u) {
        d.sf64 = (insn >> 31) != 0;
        d.rd = static_cast<uint8_t>(insn & 31u);
        d.rn = static_cast<uint8_t>((insn >> 5) & 31u);
        d.rm = static_cast<uint8_t>((insn >> 16) & 31u);
        d.ra = static_cast<uint8_t>((insn >> 10) & 31u);

        if ((insn & 0x1F000000u) == 0x0A000000u) {
            d.kind = InsnKind::LogicalReg;
            return d;
        }
        if ((insn & 0x1F200000u) == 0x0B000000u) {
            d.kind = InsnKind::AddSubReg;
            d.cond = static_cast<uint8_t>((insn >> 30) & 1u);
            d.set_flags = ((insn >> 29) & 1u) != 0;
            return d;
        }
        if ((insn & 0x1FE00000u) == 0x0B200000u) {
            d.kind = InsnKind::AddSubExt;
            d.cond = static_cast<uint8_t>((insn >> 30) & 1u);
            d.set_flags = ((insn >> 29) & 1u) != 0;
            return d;
        }
        if ((insn & 0x1FE00000u) == 0x1A000000u) {
            d.kind = InsnKind::AddSubCarry;
            return d;
        }
        if ((insn & 0x1FE00400u) == 0x1A400000u) {
            d.kind = InsnKind::CondCmp;
            return d;
        }
        if ((insn & 0x1FE00000u) == 0x1A800000u) {
            d.kind = InsnKind::CondSelect;
            return d;
        }
        if ((insn & 0x5FE00000u) == 0x5AC00000u) {
            d.kind = InsnKind::Unary1Src;
            return d;
        }
        if ((insn & 0x1FE00000u) == 0x1AC00000u) {
            // Differentiate 2-source (UDIV/SDIV/LSLV/LSRV/ASRV/RORV) vs 1-source (bit30=1 handled above)
            uint32_t opcode = (insn >> 10) & 0x3Fu;
            if (opcode == 2u || opcode == 3u) {
                d.kind = InsnKind::MulDiv3Src;
            } else {
                d.kind = InsnKind::ShiftVar;
            }
            return d;
        }
        if ((insn & 0x1F000000u) == 0x1B000000u) {
            d.kind = InsnKind::MulDiv3Src;
            return d;
        }
    }

    // 5. Data Processing — SIMD & Floating Point (bits[27:25] == 111)
    if ((insn & 0x0E000000u) == 0x0E000000u) {
        if ((insn & 0x5E000000u) == 0x1E000000u) {
            d.kind = InsnKind::FpScalar;
        } else {
            d.kind = InsnKind::NeonSimd;
        }
        return d;
    }

    d.kind = InsnKind::Unmapped;
    d.is_terminating = true;
    return d;
}

TranslatedBlock* TranslationCache::LookupL2(uint64_t guest_va,
                                            uint64_t phys_pc,
                                            uint64_t context_tag) {
    BlockKey key{phys_pc, guest_va, context_tag};
    auto it = l2_map_.find(key);
    if (it != l2_map_.end() && it->second->valid) {
        TranslatedBlock* tb = it->second.get();
        const size_t l1_idx = (guest_va >> 2) & (kL1Slots - 1u);
        l1_table_[l1_idx] = tb;
        ++hits_;
        return tb;
    }
    ++misses_;
    return nullptr;
}

void TranslationCache::Insert(std::unique_ptr<TranslatedBlock> block) {
    if (!block) return;
    if (l2_map_.size() >= kMaxL2Blocks) {
        InvalidateAll();
    }
    TranslatedBlock* raw_ptr = block.get();
    BlockKey key{block->phys_pc, block->guest_va, block->context_tag};

    for (uint64_t page_base : block->covered_phys_pages) {
        active_code_pages_.insert(page_base);
        phys_page_index_[page_base].push_back(raw_ptr);
    }

    const size_t l1_idx = (block->guest_va >> 2) & (kL1Slots - 1u);
    l1_table_[l1_idx] = raw_ptr;
    l2_map_[key] = std::move(block);
}

void TranslationCache::InvalidatePhysPage(uint64_t phys_addr) {
    const uint64_t page_base = phys_addr & ~0xFFFULL;
    if (active_code_pages_.find(page_base) == active_code_pages_.end()) {
        return; // Fast O(1) skip for normal data writes
    }

    std::vector<BlockKey> to_erase;
    auto it = phys_page_index_.find(page_base);
    if (it != phys_page_index_.end()) {
        for (TranslatedBlock* tb : it->second) {
            if (!tb || !tb->valid) continue;
            tb->valid = false;
            tb->direct_link[0] = nullptr;
            tb->direct_link[1] = nullptr;
            const size_t l1_idx = (tb->guest_va >> 2) & (kL1Slots - 1u);
            if (l1_table_[l1_idx] == tb) {
                l1_table_[l1_idx] = nullptr;
            }
            for (uint64_t other_page : tb->covered_phys_pages) {
                if (other_page == page_base) continue;
                auto oit = phys_page_index_.find(other_page);
                if (oit != phys_page_index_.end()) {
                    auto& vec = oit->second;
                    vec.erase(std::remove(vec.begin(), vec.end(), tb), vec.end());
                    if (vec.empty()) {
                        phys_page_index_.erase(oit);
                        active_code_pages_.erase(other_page);
                    }
                }
            }
            to_erase.push_back(BlockKey{tb->phys_pc, tb->guest_va, tb->context_tag});
        }
        phys_page_index_.erase(it);
    }
    active_code_pages_.erase(page_base);

    // Clear any direct_link pointers referencing invalidated blocks before freeing them
    for (auto& kv : l2_map_) {
        TranslatedBlock* other = kv.second.get();
        if (other->direct_link[0] && !other->direct_link[0]->valid) other->direct_link[0] = nullptr;
        if (other->direct_link[1] && !other->direct_link[1]->valid) other->direct_link[1] = nullptr;
    }
    for (const auto& key : to_erase) {
        l2_map_.erase(key);
    }
    ++smc_invalidations_;
}

void TranslationCache::InvalidateAll() {
    std::fill(l1_table_.begin(), l1_table_.end(), nullptr);
    l2_map_.clear();
    phys_page_index_.clear();
    active_code_pages_.clear();
}

} // namespace haseeb::vm
