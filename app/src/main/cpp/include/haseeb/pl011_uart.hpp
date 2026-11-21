#pragma once

#include "haseeb/guest_ram.hpp"

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>

namespace haseeb::vm {

// ARM PrimeCell PL011 UART (0x09000000, 4 KiB MMIO)
class Pl011Uart : public MmioDevice {
public:
    using TxLineCallback = std::function<void(const std::string& line)>;
    using IrqCallback = std::function<void(bool level)>;

    explicit Pl011Uart(TxLineCallback on_line = nullptr);

    const char* Name() const override { return "pl011-uart"; }
    uint64_t Read(uint64_t offset, unsigned size_bytes) override;
    void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override;

    void SetLineCallback(TxLineCallback cb);
    void SetIrqCallback(IrqCallback cb);
    void PushRxString(const std::string& input);
    void FlushLine();
    std::string CapturedOutput() const;
    void Reset();

private:
    void UpdateIrqLocked(IrqCallback& out_cb, bool& out_level);

    mutable std::mutex mutex_;
    TxLineCallback on_line_;
    IrqCallback irq_cb_;
    std::string line_buf_;
    std::string total_output_;
    std::deque<uint8_t> rx_fifo_;

    uint32_t rsr_ = 0;
    uint32_t ibrd_ = 1;
    uint32_t fbrd_ = 0;
    uint32_t lcr_h_ = 0x70;
    uint32_t cr_ = 0x0301;
    uint32_t ifls_ = 0x12;
    uint32_t imsc_ = 0;
    uint32_t ris_ = 0;
    bool last_irq_level_ = false;
};

} // namespace haseeb::vm
