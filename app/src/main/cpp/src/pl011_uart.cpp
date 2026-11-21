#include "haseeb/pl011_uart.hpp"

#include <utility>

namespace haseeb::vm {

Pl011Uart::Pl011Uart(TxLineCallback on_line) : on_line_(std::move(on_line)) {}

void Pl011Uart::SetLineCallback(TxLineCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_line_ = std::move(cb);
}

void Pl011Uart::SetIrqCallback(IrqCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    irq_cb_ = std::move(cb);
}

void Pl011Uart::UpdateIrqLocked(IrqCallback& out_cb, bool& out_level) {
    out_level = ((ris_ & imsc_) != 0u);
    if (out_level != last_irq_level_) {
        last_irq_level_ = out_level;
        out_cb = irq_cb_;
    } else {
        out_cb = nullptr;
    }
}

void Pl011Uart::Reset() {
    IrqCallback cb;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        line_buf_.clear();
        total_output_.clear();
        rx_fifo_.clear();
        rsr_ = 0;
        ibrd_ = 1;
        fbrd_ = 0;
        lcr_h_ = 0x70;
        cr_ = 0x0301;
        ifls_ = 0x12;
        imsc_ = 0;
        ris_ = 0;
        UpdateIrqLocked(cb, level);
    }
    if (cb) cb(level);
}

void Pl011Uart::PushRxString(const std::string& input) {
    IrqCallback cb;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (char c : input) {
            rx_fifo_.push_back(static_cast<uint8_t>(c));
        }
        if (!rx_fifo_.empty()) {
            ris_ |= (1u << 4); // RXRIS
        }
        UpdateIrqLocked(cb, level);
    }
    if (cb) cb(level);
}

void Pl011Uart::FlushLine() {
    TxLineCallback cb;
    std::string pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (line_buf_.empty()) return;
        pending.swap(line_buf_);
        cb = on_line_;
    }
    if (cb && !pending.empty()) {
        cb(pending);
    }
}

std::string Pl011Uart::CapturedOutput() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_output_;
}

uint64_t Pl011Uart::Read(uint64_t offset, unsigned /*size_bytes*/) {
    IrqCallback irq_cb;
    bool irq_level = false;
    uint64_t ret = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        switch (offset) {
            case 0x000: { // UARTDR
                if (!rx_fifo_.empty()) {
                    ret = rx_fifo_.front();
                    rx_fifo_.pop_front();
                    if (rx_fifo_.empty()) ris_ &= ~(1u << 4);
                    UpdateIrqLocked(irq_cb, irq_level);
                }
                break;
            }
            case 0x004: ret = rsr_; break;
            case 0x018: { // UARTFR: TXFE (bit 7), RXFE (bit 4)
                uint32_t fr = (1u << 7);
                if (rx_fifo_.empty()) fr |= (1u << 4);
                ret = fr;
                break;
            }
            case 0x024: ret = ibrd_; break;
            case 0x028: ret = fbrd_; break;
            case 0x02C: ret = lcr_h_; break;
            case 0x030: ret = cr_; break;
            case 0x034: ret = ifls_; break;
            case 0x038: ret = imsc_; break;
            case 0x03C: ret = ris_; break;
            case 0x040: ret = ris_ & imsc_; break;
            case 0xFE0: ret = 0x11u; break;
            case 0xFE4: ret = 0x10u; break;
            case 0xFE8: ret = 0x14u; break;
            case 0xFEC: ret = 0x00u; break;
            case 0xFF0: ret = 0x0Du; break;
            case 0xFF4: ret = 0xF0u; break;
            case 0xFF8: ret = 0x05u; break;
            case 0xFFC: ret = 0xB1u; break;
            default:    ret = 0u; break;
        }
    }
    if (irq_cb) irq_cb(irq_level);
    return ret;
}

void Pl011Uart::Write(uint64_t offset, unsigned /*size_bytes*/, uint64_t value) {
    TxLineCallback line_cb;
    IrqCallback irq_cb;
    bool irq_level = false;
    std::string completed_line;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        switch (offset) {
            case 0x000: { // UARTDR TX byte
                char ch = static_cast<char>(value & 0xFFu);
                total_output_.push_back(ch);
                if (ch == '\r') {
                } else if (ch == '\n') {
                    completed_line.swap(line_buf_);
                    line_cb = on_line_;
                } else {
                    line_buf_.push_back(ch);
                }
                ris_ |= (1u << 5); // TXRIS
                break;
            }
            case 0x004: rsr_ = 0; break;
            case 0x024: ibrd_ = static_cast<uint32_t>(value); break;
            case 0x028: fbrd_ = static_cast<uint32_t>(value); break;
            case 0x02C: lcr_h_ = static_cast<uint32_t>(value); break;
            case 0x030: cr_ = static_cast<uint32_t>(value); break;
            case 0x034: ifls_ = static_cast<uint32_t>(value); break;
            case 0x038: imsc_ = static_cast<uint32_t>(value); break;
            case 0x044: ris_ &= ~static_cast<uint32_t>(value); break;
            default: break;
        }
        UpdateIrqLocked(irq_cb, irq_level);
    }

    if (irq_cb) irq_cb(irq_level);
    if (line_cb && !completed_line.empty()) {
        line_cb(completed_line);
    }
}

} // namespace haseeb::vm
