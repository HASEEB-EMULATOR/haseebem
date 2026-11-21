#include "haseeb/pl031_rtc.hpp"

#include <chrono>

namespace haseeb::vm {

Pl031Rtc::Pl031Rtc(IrqCallback irq_cb) : irq_cb_(std::move(irq_cb)) {}

void Pl031Rtc::SetIrqCallback(IrqCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    irq_cb_ = std::move(cb);
}

void Pl031Rtc::SetTimeOffsetSeconds(int64_t offset) {
    bool notify = false;
    bool level = false;
    IrqCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        time_offset_sec_ = offset;
        UpdateIrqLocked(notify, level);
        cb = irq_cb_;
    }
    if (notify && cb) cb(level);
}

void Pl031Rtc::Reset() {
    bool notify = false;
    bool level = false;
    IrqCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        time_offset_sec_ = 0;
        mr_ = 0;
        lr_ = 0;
        cr_ = 1;
        imsc_ = 0;
        ris_ = 0;
        UpdateIrqLocked(notify, level);
        cb = irq_cb_;
    }
    if (notify && cb) cb(level);
}

uint32_t Pl031Rtc::ComputeSecondsLocked() const {
    const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return static_cast<uint32_t>(now_s + time_offset_sec_);
}

uint32_t Pl031Rtc::CurrentSeconds() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ComputeSecondsLocked();
}

void Pl031Rtc::UpdateIrqLocked(bool& out_notify, bool& out_level) {
    const bool level = ((ris_ & imsc_) & 1u) != 0;
    out_notify = (level != last_irq_level_);
    out_level = level;
    last_irq_level_ = level;
}

void Pl031Rtc::Tick() {
    bool notify = false;
    bool level = false;
    IrqCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if ((cr_ & 1u) != 0 && mr_ != 0 && ComputeSecondsLocked() >= mr_) {
            ris_ |= 1u;
        }
        UpdateIrqLocked(notify, level);
        cb = irq_cb_;
    }
    if (notify && cb) cb(level);
}

uint64_t Pl031Rtc::Read(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (offset) {
        case 0x000: return ComputeSecondsLocked(); // RTCDR
        case 0x004: return mr_;                    // RTCMR
        case 0x008: return lr_;                    // RTCLR
        case 0x00C: return cr_;                    // RTCCR
        case 0x010: return imsc_;                  // RTCIMSC
        case 0x014: return ris_;                   // RTCRIS
        case 0x018: return ris_ & imsc_;           // RTCMIS
        // AMBA PrimeCell PL031 IDs
        case 0xFE0: return 0x31u;
        case 0xFE4: return 0x10u;
        case 0xFE8: return 0x04u;
        case 0xFEC: return 0x00u;
        case 0xFF0: return 0x0Du;
        case 0xFF4: return 0xF0u;
        case 0xFF8: return 0x05u;
        case 0xFFC: return 0xB1u;
        default:    return 0u;
    }
}

void Pl031Rtc::Write(uint64_t offset, unsigned /*size_bytes*/, uint64_t value) {
    bool notify = false;
    bool level = false;
    IrqCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t v = static_cast<uint32_t>(value);
        switch (offset) {
            case 0x004:
                mr_ = v;
                if ((cr_ & 1u) != 0 && mr_ != 0 && ComputeSecondsLocked() >= mr_) {
                    ris_ |= 1u;
                }
                break;
            case 0x008: {
                lr_ = v;
                const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                time_offset_sec_ = static_cast<int64_t>(v) - now_s;
                break;
            }
            case 0x00C: cr_ = v & 1u; break;
            case 0x010: imsc_ = v & 1u; break;
            case 0x01C: ris_ &= ~(v & 1u); break; // RTCICR
            default: break;
        }
        UpdateIrqLocked(notify, level);
        cb = irq_cb_;
    }
    if (notify && cb) cb(level);
}

} // namespace haseeb::vm
