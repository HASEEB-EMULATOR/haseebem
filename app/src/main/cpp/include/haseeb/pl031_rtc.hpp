#pragma once

#include "haseeb/guest_ram.hpp"

#include <cstdint>
#include <functional>
#include <mutex>

namespace haseeb::vm {

// ARM PrimeCell PL031 Real-Time Clock (0x09010000, 4 KiB MMIO, SPI 2 / INTID 34)
class Pl031Rtc : public MmioDevice {
public:
    using IrqCallback = std::function<void(bool level)>;

    explicit Pl031Rtc(IrqCallback irq_cb = nullptr);

    const char* Name() const override { return "pl031-rtc"; }
    uint64_t Read(uint64_t offset, unsigned size_bytes) override;
    void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override;

    void SetIrqCallback(IrqCallback cb);
    void SetTimeOffsetSeconds(int64_t offset);
    void Tick(); // Evaluate match register against current time
    void Reset();

    uint32_t CurrentSeconds() const;

private:
    uint32_t ComputeSecondsLocked() const;
    void UpdateIrqLocked(bool& out_notify, bool& out_level);

    mutable std::mutex mutex_;
    IrqCallback irq_cb_;
    int64_t time_offset_sec_ = 0;
    uint32_t mr_ = 0;    // Match register
    uint32_t lr_ = 0;    // Load register
    uint32_t cr_ = 1;    // Bit 0 = RTC enable
    uint32_t imsc_ = 0;  // Interrupt mask
    uint32_t ris_ = 0;   // Raw interrupt status
    bool last_irq_level_ = false;
};

} // namespace haseeb::vm
