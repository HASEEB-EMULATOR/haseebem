#include "haseeb/gicv3.hpp"

#include <algorithm>

namespace haseeb::vm {

namespace {

inline constexpr uint32_t kIcdCtlrEnableGrp0   = 1u << 0;
inline constexpr uint32_t kIcdCtlrEnableGrp1Ns = 1u << 1;

} // namespace

GicV3::GicV3(uint32_t num_cpus)
    : dist_mmio_(*this), redist_mmio_(*this) {
    Reset(num_cpus);
}

void GicV3::Reset(uint32_t num_cpus) {
    std::lock_guard<std::mutex> lock(mutex_);
    num_cpus_ = std::clamp(num_cpus, 1u, kMaxCpus);
    gicd_ctlr_ = 0x10u; // ARE_NS = 1
    for (auto& spi : spis_) {
        spi = IrqLineState{};
    }
    for (uint32_t c = 0; c < kMaxCpus; ++c) {
        cpus_[c] = CpuInterfaceState{};
        for (uint32_t i = 0; i < 16u; ++i) {
            cpus_[c].private_irqs[i].edge_triggered = true; // SGIs are edge-triggered
        }
        // Enable SGIs 0..15 by default per GICv3 architecture convenience (software can disable)
        for (uint32_t i = 0; i < 32u; ++i) {
            cpus_[c].private_irqs[i].group = 1;
            cpus_[c].private_irqs[i].priority = 0xA0;
        }
    }
}

void GicV3::SetSpiLevel(uint32_t spi_num, bool high) {
    const uint32_t intid = 32u + spi_num;
    if (intid >= kMaxIrqs) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto& irq = spis_[intid];
    const bool prev = irq.level_high;
    irq.level_high = high;
    if (irq.edge_triggered) {
        if (!prev && high) {
            irq.pending = true;
        }
    } else {
        irq.pending = high;
    }
}

void GicV3::RaiseSpiPulse(uint32_t spi_num) {
    const uint32_t intid = 32u + spi_num;
    if (intid >= kMaxIrqs) return;
    std::lock_guard<std::mutex> lock(mutex_);
    spis_[intid].pending = true;
}

void GicV3::SetPpiLevel(uint32_t cpu_id, uint32_t intid, bool high) {
    if (cpu_id >= num_cpus_ || intid >= 32u) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto& irq = cpus_[cpu_id].private_irqs[intid];
    const bool prev = irq.level_high;
    irq.level_high = high;
    if (irq.edge_triggered) {
        if (!prev && high) {
            irq.pending = true;
        }
    } else {
        irq.pending = high;
    }
}

uint8_t GicV3::RunningPriorityLocked(uint32_t cpu_id) const {
    const auto& ci = cpus_[cpu_id];
    if (ci.active_stack_count == 0u) return 0xFFu;
    return ci.running_priorities[ci.active_stack_count - 1u];
}

uint32_t GicV3::BestPendingIntidLocked(uint32_t cpu_id, uint8_t& out_prio) const {
    if (cpu_id >= num_cpus_) {
        out_prio = 0xFFu;
        return kSpuriousIrq;
    }
    const auto& ci = cpus_[cpu_id];
    const uint8_t run_prio = RunningPriorityLocked(cpu_id);
    const uint8_t thresh = std::min(ci.pmr, run_prio);

    uint32_t best_id = kSpuriousIrq;
    uint8_t best_prio = thresh;

    auto group_enabled = [&](uint8_t grp) -> bool {
        if (grp == 0u) {
            return ci.igrpen0 && ((gicd_ctlr_ & kIcdCtlrEnableGrp0) != 0);
        }
        return ci.igrpen1 && ((gicd_ctlr_ & kIcdCtlrEnableGrp1Ns) != 0);
    };

    // Private SGIs & PPIs (0..31)
    for (uint32_t i = 0; i < 32u; ++i) {
        const auto& irq = ci.private_irqs[i];
        if (!irq.enabled || !irq.pending || irq.active) continue;
        if (!group_enabled(irq.group)) continue;
        if (irq.priority < best_prio) {
            best_prio = irq.priority;
            best_id = i;
        }
    }

    // Shared SPIs (32..255)
    for (uint32_t i = 32u; i < kMaxIrqs; ++i) {
        const auto& irq = spis_[i];
        if (!irq.enabled || !irq.pending || irq.active) continue;
        if (!group_enabled(irq.group)) continue;
        const uint32_t target_cpu = static_cast<uint32_t>(irq.router & 0xFFULL);
        const bool is_1_of_n = (irq.router & (1ULL << 31)) != 0;
        if (!is_1_of_n && target_cpu != cpu_id) continue;
        if (irq.priority < best_prio) {
            best_prio = irq.priority;
            best_id = i;
        }
    }

    out_prio = best_prio;
    return best_id;
}

bool GicV3::HasPendingIrq(uint32_t cpu_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint8_t prio = 0xFFu;
    return BestPendingIntidLocked(cpu_id, prio) != kSpuriousIrq;
}

uint32_t GicV3::AcknowledgeIrqLocked(uint32_t cpu_id, uint8_t group) {
    if (cpu_id >= num_cpus_) return kSpuriousIrq;
    uint8_t prio = 0xFFu;
    const uint32_t best = BestPendingIntidLocked(cpu_id, prio);
    if (best == kSpuriousIrq) return kSpuriousIrq;

    auto& ci = cpus_[cpu_id];
    IrqLineState& irq = (best < 32u) ? ci.private_irqs[best] : spis_[best];
    if (irq.group != group) return kSpuriousIrq;

    irq.active = true;
    if (irq.edge_triggered || best < 16u) {
        irq.pending = false;
    }
    if (ci.active_stack_count < ci.running_priorities.size()) {
        ci.running_priorities[ci.active_stack_count++] = prio;
    }
    return best;
}

void GicV3::EndOfIrqLocked(uint32_t cpu_id, uint32_t intid) {
    if (cpu_id >= num_cpus_) return;
    auto& ci = cpus_[cpu_id];
    if (ci.active_stack_count > 0u) {
        --ci.active_stack_count;
    }
    if (intid < 32u) {
        auto& irq = ci.private_irqs[intid];
        irq.active = false;
        if (!irq.edge_triggered && irq.level_high) {
            irq.pending = true;
        }
    } else if (intid < kMaxIrqs) {
        auto& irq = spis_[intid];
        irq.active = false;
        if (!irq.edge_triggered && irq.level_high) {
            irq.pending = true;
        }
    }
}

uint64_t GicV3::ReadSysReg(uint32_t cpu_id, uint32_t key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cpu_id >= num_cpus_) return 0;
    const auto& ci = cpus_[cpu_id];

    switch (key) {
        case kIccSreEl1:     return 0x7ULL; // SRE=1, DFB=1, DIB=1
        case kIccPmrEl1:     return ci.pmr;
        case kIccBpr0El1:    return ci.bpr0;
        case kIccBpr1El1:    return ci.bpr1;
        case kIccCtlrEl1:    return ci.ctlr | (7ULL << 8); // PRIbits = 8 (field=7)
        case kIccIgrpen0El1: return ci.igrpen0 ? 1ULL : 0ULL;
        case kIccIgrpen1El1: return ci.igrpen1 ? 1ULL : 0ULL;
        case kIccRprEl1:     return RunningPriorityLocked(cpu_id);
        case kIccHppir0El1: {
            uint8_t p = 0xFFu;
            uint32_t id = BestPendingIntidLocked(cpu_id, p);
            if (id < kMaxIrqs) {
                uint8_t grp = (id < 32u) ? ci.private_irqs[id].group : spis_[id].group;
                return (grp == 0u) ? id : kSpuriousIrq;
            }
            return kSpuriousIrq;
        }
        case kIccHppir1El1: {
            uint8_t p = 0xFFu;
            uint32_t id = BestPendingIntidLocked(cpu_id, p);
            if (id < kMaxIrqs) {
                uint8_t grp = (id < 32u) ? ci.private_irqs[id].group : spis_[id].group;
                return (grp == 1u) ? id : kSpuriousIrq;
            }
            return kSpuriousIrq;
        }
        case kIccIar0El1:    return AcknowledgeIrqLocked(cpu_id, 0u);
        case kIccIar1El1:    return AcknowledgeIrqLocked(cpu_id, 1u);
        default:             return 0ULL;
    }
}

void GicV3::WriteSysReg(uint32_t cpu_id, uint32_t key, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cpu_id >= num_cpus_) return;
    auto& ci = cpus_[cpu_id];

    switch (key) {
        case kIccPmrEl1:     ci.pmr = static_cast<uint8_t>(value & 0xFFu); break;
        case kIccBpr0El1:    ci.bpr0 = static_cast<uint8_t>(value & 7u); break;
        case kIccBpr1El1:    ci.bpr1 = static_cast<uint8_t>(value & 7u); break;
        case kIccCtlrEl1:    ci.ctlr = static_cast<uint32_t>(value & 0x3u); break;
        case kIccIgrpen0El1: ci.igrpen0 = (value & 1ULL) != 0; break;
        case kIccIgrpen1El1: ci.igrpen1 = (value & 1ULL) != 0; break;
        case kIccEoir0El1:
        case kIccEoir1El1:
        case kIccDirEl1:     EndOfIrqLocked(cpu_id, static_cast<uint32_t>(value & 0xFFFFFFULL)); break;
        case kIccSgi1rEl1:
        case kIccAsgi1rEl1:
        case kIccSgi0rEl1: {
            const uint32_t intid = static_cast<uint32_t>((value >> 24) & 0xFu);
            const bool irm = ((value >> 40) & 1ULL) != 0;
            const uint32_t target_list = static_cast<uint32_t>(value & 0xFFFFu);
            const uint8_t grp = (key == kIccSgi0rEl1) ? 0u : 1u;
            for (uint32_t target = 0; target < num_cpus_; ++target) {
                const bool match = irm ? (target != cpu_id) : ((target_list & (1u << target)) != 0);
                if (match) {
                    cpus_[target].private_irqs[intid].group = grp;
                    cpus_[target].private_irqs[intid].pending = true;
                }
            }
            break;
        }
        case kIccSreEl1:
        default:
            break;
    }
}

uint32_t GicV3::ReadGicd(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x0000) return gicd_ctlr_;
    if (offset == 0x0004) {
        // ITLinesNumber = (256 / 32) - 1 = 7, CPUNumber = num_cpus - 1, IDbits = 9 (10 bits)
        return ((kMaxIrqs / 32u) - 1u) | (((num_cpus_ - 1u) & 7u) << 5) | (9u << 19);
    }
    if (offset == 0x0008) return 0x0402043Bu; // ARM GICv3 implementer
    if (offset == 0x0010) return 0u;
    if (offset == 0xFFE8) return 0x30u;       // PIDR2 ArchRev = 3 (GICv3)

    auto read_bitmap = [&](uint64_t base, auto getter) -> uint32_t {
        uint32_t word_idx = static_cast<uint32_t>((offset - base) / 4u);
        uint32_t start = word_idx * 32u;
        uint32_t val = 0;
        for (uint32_t b = 0; b < 32u && (start + b) < kMaxIrqs; ++b) {
            uint32_t id = start + b;
            if (id >= 32u && getter(spis_[id])) {
                val |= (1u << b);
            }
        }
        return val;
    };

    if (offset >= 0x0080 && offset < 0x0100) return read_bitmap(0x0080, [](const IrqLineState& s) { return s.group != 0; });
    if (offset >= 0x0100 && offset < 0x0180) return read_bitmap(0x0100, [](const IrqLineState& s) { return s.enabled; });
    if (offset >= 0x0180 && offset < 0x0200) return read_bitmap(0x0180, [](const IrqLineState& s) { return s.enabled; });
    if (offset >= 0x0200 && offset < 0x0280) return read_bitmap(0x0200, [](const IrqLineState& s) { return s.pending; });
    if (offset >= 0x0280 && offset < 0x0300) return read_bitmap(0x0280, [](const IrqLineState& s) { return s.pending; });
    if (offset >= 0x0300 && offset < 0x0380) return read_bitmap(0x0300, [](const IrqLineState& s) { return s.active; });
    if (offset >= 0x0380 && offset < 0x0400) return read_bitmap(0x0380, [](const IrqLineState& s) { return s.active; });

    if (offset >= 0x0400 && offset < 0x0800) {
        uint32_t base_id = static_cast<uint32_t>(offset - 0x0400);
        uint32_t out = 0;
        for (uint32_t b = 0; b < 4u && (base_id + b) < kMaxIrqs; ++b) {
            uint32_t id = base_id + b;
            uint8_t p = (id < 32u) ? 0xA0u : spis_[id].priority;
            out |= (static_cast<uint32_t>(p) << (b * 8u));
        }
        return out;
    }

    if (offset >= 0x0C00 && offset < 0x0D00) {
        uint32_t word = static_cast<uint32_t>((offset - 0x0C00) / 4u);
        uint32_t base_id = word * 16u;
        uint32_t out = 0;
        for (uint32_t i = 0; i < 16u && (base_id + i) < kMaxIrqs; ++i) {
            uint32_t id = base_id + i;
            if (id >= 32u && spis_[id].edge_triggered) {
                out |= (2u << (i * 2u));
            }
        }
        return out;
    }

    if (offset >= 0x6000 && offset < 0x8000) {
        uint32_t intid = static_cast<uint32_t>((offset - 0x6000) / 8u);
        if (intid < kMaxIrqs) {
            uint64_t r = spis_[intid].router;
            return ((offset & 4u) != 0) ? static_cast<uint32_t>(r >> 32) : static_cast<uint32_t>(r);
        }
    }
    return 0u;
}

void GicV3::WriteGicd(uint64_t offset, unsigned size_bytes, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x0000) {
        gicd_ctlr_ = (static_cast<uint32_t>(value) & 0x37u) | 0x10u; // keep ARE_NS=1
        return;
    }

    auto apply_bitmap = [&](uint64_t base, auto fn) {
        uint32_t word_idx = static_cast<uint32_t>((offset - base) / 4u);
        uint32_t start = word_idx * 32u;
        uint32_t mask = static_cast<uint32_t>(value);
        for (uint32_t b = 0; b < 32u && (start + b) < kMaxIrqs; ++b) {
            uint32_t id = start + b;
            if (id >= 32u) fn(spis_[id], (mask & (1u << b)) != 0);
        }
    };

    if (offset >= 0x0080 && offset < 0x0100) {
        apply_bitmap(0x0080, [](IrqLineState& s, bool set) { s.group = set ? 1u : 0u; });
    } else if (offset >= 0x0100 && offset < 0x0180) {
        apply_bitmap(0x0100, [](IrqLineState& s, bool set) { if (set) s.enabled = true; });
    } else if (offset >= 0x0180 && offset < 0x0200) {
        apply_bitmap(0x0180, [](IrqLineState& s, bool set) { if (set) s.enabled = false; });
    } else if (offset >= 0x0200 && offset < 0x0280) {
        apply_bitmap(0x0200, [](IrqLineState& s, bool set) { if (set) s.pending = true; });
    } else if (offset >= 0x0280 && offset < 0x0300) {
        apply_bitmap(0x0280, [](IrqLineState& s, bool set) { if (set && (s.edge_triggered || !s.level_high)) s.pending = false; });
    } else if (offset >= 0x0300 && offset < 0x0380) {
        apply_bitmap(0x0300, [](IrqLineState& s, bool set) { if (set) s.active = true; });
    } else if (offset >= 0x0380 && offset < 0x0400) {
        apply_bitmap(0x0380, [](IrqLineState& s, bool set) { if (set) s.active = false; });
    } else if (offset >= 0x0400 && offset < 0x0800) {
        uint32_t base_id = static_cast<uint32_t>(offset - 0x0400);
        unsigned count = (size_bytes == 1u) ? 1u : 4u;
        for (unsigned b = 0; b < count && (base_id + b) < kMaxIrqs; ++b) {
            if (base_id + b >= 32u) {
                spis_[base_id + b].priority = static_cast<uint8_t>((value >> (b * 8u)) & 0xFFu);
            }
        }
    } else if (offset >= 0x0C00 && offset < 0x0D00) {
        uint32_t word = static_cast<uint32_t>((offset - 0x0C00) / 4u);
        uint32_t base_id = word * 16u;
        for (uint32_t i = 0; i < 16u && (base_id + i) < kMaxIrqs; ++i) {
            if (base_id + i >= 32u) {
                spis_[base_id + i].edge_triggered = (((value >> (i * 2u)) & 2u) != 0);
            }
        }
    } else if (offset >= 0x6000 && offset < 0x8000) {
        uint32_t intid = static_cast<uint32_t>((offset - 0x6000) / 8u);
        if (intid < kMaxIrqs) {
            if (size_bytes == 8u && (offset & 7u) == 0u) {
                spis_[intid].router = value;
            } else if ((offset & 4u) == 0u) {
                spis_[intid].router = (spis_[intid].router & 0xFFFFFFFF00000000ULL) | (value & 0xFFFFFFFFULL);
            } else {
                spis_[intid].router = (spis_[intid].router & 0xFFFFFFFFULL) | (value << 32);
            }
        }
    }
}

uint64_t GicV3::ReadGicr(uint64_t offset, unsigned size_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint32_t cpu_id = static_cast<uint32_t>(offset / 0x20000ULL);
    if (cpu_id >= num_cpus_) return 0ULL;
    const uint64_t local_off = offset % 0x20000ULL;
    const auto& ci = cpus_[cpu_id];

    if (local_off < 0x10000ULL) {
        // RD_base
        if (local_off == 0x0000) return 0u;           // GICR_CTLR
        if (local_off == 0x0004) return 0x0402043Bu;  // GICR_IIDR
        if (local_off == 0x0008 || local_off == 0x000C) {
            uint64_t typer = (static_cast<uint64_t>(cpu_id) << 32) |
                             (static_cast<uint64_t>(cpu_id) << 8) |
                             ((cpu_id + 1u == num_cpus_) ? (1ULL << 4) : 0ULL);
            if (size_bytes == 8u && local_off == 0x0008) return typer;
            return (local_off == 0x000C) ? (typer >> 32) : (typer & 0xFFFFFFFFULL);
        }
        if (local_off == 0x0014) return ci.waker;
        if (local_off == 0xFFE8) return 0x30u; // GICR_PIDR2 ArchRev=3
        return 0ULL;
    }

    // SGI_base (local_off >= 0x10000)
    const uint64_t sgi_off = local_off - 0x10000ULL;
    auto pack32 = [&](auto pred) -> uint32_t {
        uint32_t out = 0;
        for (uint32_t i = 0; i < 32u; ++i) {
            if (pred(ci.private_irqs[i])) out |= (1u << i);
        }
        return out;
    };

    if (sgi_off == 0x0080) return pack32([](const IrqLineState& s) { return s.group != 0; });
    if (sgi_off == 0x0100 || sgi_off == 0x0180) return pack32([](const IrqLineState& s) { return s.enabled; });
    if (sgi_off == 0x0200 || sgi_off == 0x0280) return pack32([](const IrqLineState& s) { return s.pending; });
    if (sgi_off == 0x0300 || sgi_off == 0x0380) return pack32([](const IrqLineState& s) { return s.active; });

    if (sgi_off >= 0x0400 && sgi_off < 0x0420) {
        uint32_t base_id = static_cast<uint32_t>(sgi_off - 0x0400);
        uint32_t out = 0;
        for (uint32_t b = 0; b < 4u && (base_id + b) < 32u; ++b) {
            out |= (static_cast<uint32_t>(ci.private_irqs[base_id + b].priority) << (b * 8u));
        }
        return out;
    }
    if (sgi_off == 0x0C00 || sgi_off == 0x0C04) {
        uint32_t base_id = (sgi_off == 0x0C04) ? 16u : 0u;
        uint32_t out = 0;
        for (uint32_t i = 0; i < 16u; ++i) {
            if (ci.private_irqs[base_id + i].edge_triggered) out |= (2u << (i * 2u));
        }
        return out;
    }
    return 0ULL;
}

void GicV3::WriteGicr(uint64_t offset, unsigned size_bytes, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint32_t cpu_id = static_cast<uint32_t>(offset / 0x20000ULL);
    if (cpu_id >= num_cpus_) return;
    const uint64_t local_off = offset % 0x20000ULL;
    auto& ci = cpus_[cpu_id];

    if (local_off < 0x10000ULL) {
        if (local_off == 0x0014) {
            // Clearing ProcessorSleep (bit 1) immediately clears ChildrenAsleep (bit 2)
            uint32_t sleep = static_cast<uint32_t>(value) & (1u << 1);
            ci.waker = sleep ? ((1u << 1) | (1u << 2)) : 0u;
        }
        return;
    }

    const uint64_t sgi_off = local_off - 0x10000ULL;
    uint32_t v = static_cast<uint32_t>(value);
    if (sgi_off == 0x0080) {
        for (uint32_t i = 0; i < 32u; ++i) ci.private_irqs[i].group = ((v >> i) & 1u);
    } else if (sgi_off == 0x0100) {
        for (uint32_t i = 0; i < 32u; ++i) if ((v >> i) & 1u) ci.private_irqs[i].enabled = true;
    } else if (sgi_off == 0x0180) {
        for (uint32_t i = 0; i < 32u; ++i) if ((v >> i) & 1u) ci.private_irqs[i].enabled = false;
    } else if (sgi_off == 0x0200) {
        for (uint32_t i = 0; i < 32u; ++i) if ((v >> i) & 1u) ci.private_irqs[i].pending = true;
    } else if (sgi_off == 0x0280) {
        for (uint32_t i = 0; i < 32u; ++i) {
            if ((v >> i) & 1u) {
                if (ci.private_irqs[i].edge_triggered || !ci.private_irqs[i].level_high) {
                    ci.private_irqs[i].pending = false;
                }
            }
        }
    } else if (sgi_off == 0x0300) {
        for (uint32_t i = 0; i < 32u; ++i) if ((v >> i) & 1u) ci.private_irqs[i].active = true;
    } else if (sgi_off == 0x0380) {
        for (uint32_t i = 0; i < 32u; ++i) if ((v >> i) & 1u) ci.private_irqs[i].active = false;
    } else if (sgi_off >= 0x0400 && sgi_off < 0x0420) {
        uint32_t base_id = static_cast<uint32_t>(sgi_off - 0x0400);
        unsigned count = (size_bytes == 1u) ? 1u : 4u;
        for (unsigned b = 0; b < count && (base_id + b) < 32u; ++b) {
            ci.private_irqs[base_id + b].priority = static_cast<uint8_t>((value >> (b * 8u)) & 0xFFu);
        }
    } else if (sgi_off == 0x0C04) {
        for (uint32_t i = 0; i < 16u; ++i) {
            ci.private_irqs[16u + i].edge_triggered = (((v >> (i * 2u)) & 2u) != 0);
        }
    }
}

} // namespace haseeb::vm
