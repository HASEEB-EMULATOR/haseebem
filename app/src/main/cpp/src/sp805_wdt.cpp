#include "haseeb/sp805_wdt.hpp"

namespace haseeb::vm {

namespace {
inline constexpr uint32_t kWdogUnlockMagic = 0x1ACCE551u;
} // namespace

Sp805Watchdog::Sp805Watchdog(IrqCallback irq_cb) : irq_cb_(std::move(irq_cb)) {}

void Sp805Watchdog::SetIrqCallback(IrqCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    irq_cb_ = std::move(cb);
}

void Sp805Watchdog::SetResetCallback(ResetCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    reset_cb_ = std::move(cb);
}

bool Sp805Watchdog::ResetTriggered() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reset_triggered_;
}

void Sp805Watchdog::Reset() {
    IrqCallback cb;
    bool notify = false;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        load_ = 0xFFFFFFFFu;
        value_ = 0xFFFFFFFFu;
        control_ = 0;
        ris_ = 0;
        unlocked_ = true;
        reset_triggered_ = false;
        level = false;
        notify = (last_irq_level_ != level);
        last_irq_level_ = level;
        cb = irq_cb_;
    }
    if (notify && cb) cb(level);
}

void Sp805Watchdog::NotifyIrqLocked(IrqCallback& out_cb, bool& out_level) {
    out_level = ((ris_ & (control_ & 1u)) != 0);
    if (out_level != last_irq_level_) {
        last_irq_level_ = out_level;
        out_cb = irq_cb_;
    } else {
        out_cb = nullptr;
    }
}

void Sp805Watchdog::Tick(uint32_t ticks) {
    IrqCallback irq_cb;
    ResetCallback rst_cb;
    bool irq_level = false;
    bool do_reset = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if ((control_ & 1u) == 0u || ticks == 0u) return;

        if (ticks >= value_) {
            if ((ris_ & 1u) != 0 && (control_ & 2u) != 0) {
                // Second expiry while interrupt un-cleared and RESEN=1 -> system reset
                reset_triggered_ = true;
                do_reset = true;
                rst_cb = reset_cb_;
            } else {
                ris_ |= 1u;
                value_ = load_;
            }
        } else {
            value_ -= ticks;
        }
        NotifyIrqLocked(irq_cb, irq_level);
    }
    if (irq_cb) irq_cb(irq_level);
    if (do_reset && rst_cb) rst_cb();
}

uint64_t Sp805Watchdog::Read(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (offset) {
        case 0x000: return load_;
        case 0x004: return value_;
        case 0x008: return control_;
        case 0x010: return ris_;
        case 0x014: return ris_ & (control_ & 1u);
        case 0xC00: return unlocked_ ? 0u : 1u; // WDOGLOCK (0=unlocked, 1=locked)
        case 0xFE0: return 0x05u;
        case 0xFE4: return 0x18u;
        case 0xFE8: return 0x14u;
        case 0xFEC: return 0x00u;
        case 0xFF0: return 0x0Du;
        case 0xFF4: return 0xF0u;
        case 0xFF8: return 0x05u;
        case 0xFFC: return 0xB1u;
        default:    return 0u;
    }
}

void Sp805Watchdog::Write(uint64_t offset, unsigned /*size_bytes*/, uint64_t value) {
    IrqCallback cb;
    bool irq_level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t v = static_cast<uint32_t>(value);
        if (offset == 0xC00) {
            unlocked_ = (v == kWdogUnlockMagic);
            return;
        }
        if (!unlocked_) return;

        switch (offset) {
            case 0x000:
                load_ = v;
                value_ = v;
                break;
            case 0x008:
                control_ = v & 3u;
                break;
            case 0x00C: // WDOGINTCLR (any write reloads value and clears interrupt)
                ris_ = 0;
                value_ = load_;
                break;
            default:
                break;
        }
        NotifyIrqLocked(cb, irq_level);
    }
    if (cb) cb(irq_level);
}

} // namespace haseeb::vm
