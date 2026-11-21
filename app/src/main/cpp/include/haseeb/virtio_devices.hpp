#pragma once

#include "haseeb/virtio_mmio.hpp"

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace haseeb::vm {

// 1. virtio-blk (Device ID = 2)
class VirtioBlkDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdBlk = 2u;
    static constexpr uint32_t kSectorSize = 512u;

    ~VirtioBlkDevice() override;

    bool AttachFile(const std::string& path, bool read_only = false);
    void AttachMemoryDisk(uint64_t size_bytes, bool read_only = false);
    void Detach();

    uint64_t CapacitySectors() const { return capacity_sectors_; }
    bool IsReadOnly() const { return read_only_; }

    uint32_t DeviceId() const override { return kVirtioIdBlk; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 1u; }
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    bool ReadSectors(uint64_t sector, uint8_t* dst, size_t bytes);
    bool WriteSectors(uint64_t sector, const uint8_t* src, size_t bytes);
    void FlushBacking();

    mutable std::mutex mutex_;
    int fd_ = -1;
    bool read_only_ = false;
    uint64_t capacity_sectors_ = 0;
    std::vector<uint8_t> mem_disk_;
    std::string disk_id_ = "HASEEB-VBLK-001";
};

// 2. virtio-net (Device ID = 1)
class VirtioNetDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdNet = 1u;
    using TxFrameCallback = std::function<void(const std::vector<uint8_t>& eth_frame)>;

    VirtioNetDevice();

    void SetMacAddress(const std::array<uint8_t, 6>& mac);
    void SetTxCallback(TxFrameCallback cb);
    void InjectRxFrame(VirtioMmioDevice& transport, const std::vector<uint8_t>& eth_frame);
    std::vector<std::vector<uint8_t>> DrainTxFrames();

    uint32_t DeviceId() const override { return kVirtioIdNet; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 2u; } // 0 = RX, 1 = TX
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    void DrainRxPendingLocked(VirtioMmioDevice& transport);

    mutable std::mutex mutex_;
    std::array<uint8_t, 6> mac_{0x52, 0x54, 0x00, 0x48, 0x53, 0x01};
    TxFrameCallback tx_cb_;
    std::deque<std::vector<uint8_t>> tx_capture_;
    std::deque<std::vector<uint8_t>> rx_pending_;
};

// 3. virtio-console (Device ID = 3)
class VirtioConsoleDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdConsole = 3u;
    using TxBytesCallback = std::function<void(const std::string& text)>;

    explicit VirtioConsoleDevice(TxBytesCallback tx_cb = nullptr);

    void SetTxCallback(TxBytesCallback cb);
    void PushRxBytes(VirtioMmioDevice& transport, const std::string& text);
    std::string CapturedOutput() const;

    uint32_t DeviceId() const override { return kVirtioIdConsole; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 2u; } // 0 = receiveq, 1 = transmitq
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    void DrainRxPendingLocked(VirtioMmioDevice& transport);

    mutable std::mutex mutex_;
    TxBytesCallback tx_cb_;
    std::string captured_tx_;
    std::deque<uint8_t> rx_pending_;
    uint16_t cols_ = 80;
    uint16_t rows_ = 25;
};

// 4. virtio-rng (Device ID = 4)
class VirtioRngDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdRng = 4u;

    uint32_t DeviceId() const override { return kVirtioIdRng; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 1u; }
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;
};

// 5. virtio-balloon (Device ID = 5)
class VirtioBalloonDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdBalloon = 5u;

    void SetTargetPages(VirtioMmioDevice& transport, uint32_t num_pages);
    uint32_t TargetPages() const;
    uint32_t ActualPages() const;
    size_t InflatedPfnCount() const;

    uint32_t DeviceId() const override { return kVirtioIdBalloon; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 2u; } // 0 = inflateq, 1 = deflateq
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void OnReset() override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    mutable std::mutex mutex_;
    uint32_t num_pages_ = 0;
    uint32_t actual_pages_ = 0;
    std::vector<uint32_t> inflated_pfns_;
};

} // namespace haseeb::vm
