#pragma once

#include "haseeb/guest_ram.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace haseeb::vm {

// Single segment in a split-virtqueue descriptor chain
struct VirtqBufferSegment {
    uint64_t guest_pa = 0;
    uint32_t len = 0;
    bool writable = false; // Device writes to guest RAM when true, reads when false
};

struct VirtqChain {
    uint16_t head_idx = 0;
    std::vector<VirtqBufferSegment> read_segs;
    std::vector<VirtqBufferSegment> write_segs;
};

class VirtioMmioDevice;

class VirtioDeviceBackend {
public:
    virtual ~VirtioDeviceBackend() = default;
    virtual uint32_t DeviceId() const = 0;
    virtual uint64_t DeviceFeatures() const = 0;
    virtual uint32_t NumQueues() const = 0;
    virtual uint32_t QueueMaxSize(uint32_t /*queue_idx*/) const { return 256u; }
    virtual uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) = 0;
    virtual void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) = 0;
    virtual void OnReset() {}
    virtual void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) = 0;
};

// Virtio-MMIO v2 Transport (magic 'virt' 0x74726976, version 2, split virtqueue)
class VirtioMmioDevice : public MmioDevice {
public:
    using IrqCallback = std::function<void(bool level)>;

    static constexpr uint32_t kMagicValue = 0x74726976u; // "virt"
    static constexpr uint32_t kVersion2 = 2u;
    static constexpr uint32_t kVendorId = 0x48534256u;   // "HSBV"
    static constexpr uint32_t kMaxQueues = 4u;

    VirtioMmioDevice(GuestRam& ram, VirtioDeviceBackend* backend, IrqCallback irq_cb = nullptr);

    const char* Name() const override { return "virtio-mmio"; }
    uint64_t Read(uint64_t offset, unsigned size_bytes) override;
    void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override;

    void SetIrqCallback(IrqCallback cb);
    void ResetDevice();

    // Virtqueue operations used by device backends
    bool PopAvailChain(uint32_t queue_idx, VirtqChain& out_chain);
    void PushUsed(uint32_t queue_idx, uint16_t head_idx, uint32_t bytes_written);
    void RaiseConfigInterrupt();
    void RaiseVringInterrupt();

    // Helpers to read/write scattered descriptor segments in GuestRam
    bool CopyFromChain(const VirtqChain& chain, size_t offset, void* dst, size_t len) const;
    bool CopyToChain(const VirtqChain& chain, size_t offset, const void* src, size_t len) const;
    size_t TotalReadBytes(const VirtqChain& chain) const;
    size_t TotalWriteBytes(const VirtqChain& chain) const;

    GuestRam& Ram() { return ram_; }
    uint64_t DriverFeatures() const { return driver_features_; }
    uint32_t Status() const { return status_; }

private:
    struct VirtQueue {
        uint32_t num_max = 256u;
        uint32_t num = 0;
        bool ready = false;
        uint64_t desc_addr = 0;
        uint64_t driver_addr = 0;
        uint64_t device_addr = 0;
        uint16_t last_avail_idx = 0;
        uint16_t last_used_idx = 0;
    };

    void UpdateIrqLocked(IrqCallback& out_cb, bool& out_level);

    GuestRam& ram_;
    VirtioDeviceBackend* backend_ = nullptr;
    mutable std::mutex mutex_;
    IrqCallback irq_cb_;

    uint32_t device_features_sel_ = 0;
    uint32_t driver_features_sel_ = 0;
    uint64_t driver_features_ = 0;
    uint32_t queue_sel_ = 0;
    uint32_t interrupt_status_ = 0; // bit 0: used buffer, bit 1: config change
    uint32_t status_ = 0;
    uint32_t config_generation_ = 0;
    bool last_irq_level_ = false;
    std::array<VirtQueue, kMaxQueues> queues_{};
};

} // namespace haseeb::vm
