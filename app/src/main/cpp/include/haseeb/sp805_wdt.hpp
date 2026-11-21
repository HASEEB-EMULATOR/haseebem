#pragma once

#include "haseeb/guest_ram.hpp"

#include <cstdint>
#include <functional>
#include <mutex>

namespace haseeb::vm {

// ARM PrimeCell SP805 Watchdog Timer (0x09020000, 4 KiB MMIO, SPI 3 / INTID 35)
class Sp805Watchdog : public MmioDevice {
public:
    using IrqCallback = std::function<void(bool level)>;
    using ResetCallback = std::function<void()>;

    explicit Sp805Watchdog(IrqCallback irq_cb = nullptr);

    const char* Name() const override { return "sp805-wdt"; }
    uint64_t Read(uint64_t offset, unsigned size_bytes) override;
    void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override;

    void SetIrqCallback(IrqCallback cb);
    void SetResetCallback(ResetCallback cb);
    void Tick(uint32_t ticks = 1);
    void Reset();

    bool ResetTriggered() const;

private:
    void NotifyIrqLocked(IrqCallback& out_cb, bool& out_level);

    mutable std::mutex mutex_;
    IrqCallback irq_cb_;
    ResetCallback reset_cb_;
    uint32_t load_ = 0xFFFFFFFFu;
    uint32_t value_ = 0xFFFFFFFFu;
    uint32_t control_ = 0; // bit 0: INTEN, bit 1: RESEN
    uint32_t ris_ = 0;
    bool unlocked_ = true;
    bool reset_triggered_ = false;
    bool last_irq_level_ = false;
};

} // namespace haseeb::vm
