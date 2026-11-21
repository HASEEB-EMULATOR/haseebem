#include "haseeb/virtio_devices.hpp"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <sys/stat.h>
#include <unistd.h>

namespace haseeb::vm {

// =========================================================================
// 1. virtio-blk (Device ID = 2)
// =========================================================================
namespace {
struct VirtioBlkReqHdr {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
};
static_assert(sizeof(VirtioBlkReqHdr) == 16, "VirtioBlkReqHdr must be 16 bytes");

inline constexpr uint32_t kBlkTIn    = 0u;
inline constexpr uint32_t kBlkTOut   = 1u;
inline constexpr uint32_t kBlkTFlush = 4u;
inline constexpr uint32_t kBlkTGetId = 8u;

inline constexpr uint8_t kBlkSOk     = 0u;
inline constexpr uint8_t kBlkSIoErr  = 1u;
inline constexpr uint8_t kBlkSUnsupp = 2u;
} // namespace

VirtioBlkDevice::~VirtioBlkDevice() {
    Detach();
}

void VirtioBlkDevice::Detach() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    mem_disk_.clear();
    capacity_sectors_ = 0;
    read_only_ = false;
}

bool VirtioBlkDevice::AttachFile(const std::string& path, bool read_only) {
    Detach();
    int flags = read_only ? O_RDONLY : O_RDWR;
    int fd = open(path.c_str(), flags | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(kSectorSize)) {
        close(fd);
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    fd_ = fd;
    read_only_ = read_only;
    capacity_sectors_ = static_cast<uint64_t>(st.st_size) / kSectorSize;
    return true;
}

void VirtioBlkDevice::AttachMemoryDisk(uint64_t size_bytes, bool read_only) {
    Detach();
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t aligned = (size_bytes / kSectorSize) * kSectorSize;
    mem_disk_.assign(aligned, 0u);
    capacity_sectors_ = aligned / kSectorSize;
    read_only_ = read_only;
}

uint64_t VirtioBlkDevice::DeviceFeatures() const {
    uint64_t feats = (1ULL << 6) | (1ULL << 9); // BLK_SIZE | FLUSH
    if (read_only_) feats |= (1ULL << 5);       // RO
    return feats;
}

uint32_t VirtioBlkDevice::ReadConfig(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (offset) {
        case 0x00: return static_cast<uint32_t>(capacity_sectors_ & 0xFFFFFFFFULL);
        case 0x04: return static_cast<uint32_t>(capacity_sectors_ >> 32);
        case 0x08: return 0x100000u;    // size_max (1 MiB)
        case 0x0C: return 128u;         // seg_max
        case 0x14: return kSectorSize;  // blk_size
        default:   return 0u;
    }
}

void VirtioBlkDevice::WriteConfig(uint64_t /*offset*/, unsigned /*size_bytes*/, uint64_t /*value*/) {}

bool VirtioBlkDevice::ReadSectors(uint64_t sector, uint8_t* dst, size_t bytes) {
    if (sector + (bytes / kSectorSize) > capacity_sectors_) return false;
    const uint64_t off = sector * kSectorSize;
    if (fd_ >= 0) {
        size_t done = 0;
        while (done < bytes) {
            ssize_t n = pread(fd_, dst + done, bytes - done, static_cast<off_t>(off + done));
            if (n <= 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    }
    if (off + bytes <= mem_disk_.size()) {
        std::memcpy(dst, mem_disk_.data() + off, bytes);
        return true;
    }
    return false;
}

bool VirtioBlkDevice::WriteSectors(uint64_t sector, const uint8_t* src, size_t bytes) {
    if (read_only_ || sector + (bytes / kSectorSize) > capacity_sectors_) return false;
    const uint64_t off = sector * kSectorSize;
    if (fd_ >= 0) {
        size_t done = 0;
        while (done < bytes) {
            ssize_t n = pwrite(fd_, src + done, bytes - done, static_cast<off_t>(off + done));
            if (n <= 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    }
    if (off + bytes <= mem_disk_.size()) {
        std::memcpy(mem_disk_.data() + off, src, bytes);
        return true;
    }
    return false;
}

void VirtioBlkDevice::FlushBacking() {
    if (fd_ >= 0) fsync(fd_);
}

void VirtioBlkDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx != 0u) return;
    VirtqChain chain;
    while (transport.PopAvailChain(0u, chain)) {
        VirtioBlkReqHdr hdr{};
        uint8_t status = kBlkSIoErr;
        uint32_t bytes_written = 1u;

        if (transport.CopyFromChain(chain, 0, &hdr, sizeof(hdr))) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (hdr.type == kBlkTIn) {
                size_t total_w = transport.TotalWriteBytes(chain);
                if (total_w >= 1u) {
                    size_t data_bytes = total_w - 1u;
                    std::vector<uint8_t> buf(data_bytes, 0);
                    if (ReadSectors(hdr.sector, buf.data(), data_bytes) &&
                        transport.CopyToChain(chain, 0, buf.data(), data_bytes)) {
                        status = kBlkSOk;
                        bytes_written = static_cast<uint32_t>(data_bytes + 1u);
                    }
                    transport.CopyToChain(chain, data_bytes, &status, 1);
                }
            } else if (hdr.type == kBlkTOut) {
                size_t total_r = transport.TotalReadBytes(chain);
                if (total_r >= sizeof(hdr)) {
                    size_t data_bytes = total_r - sizeof(hdr);
                    std::vector<uint8_t> buf(data_bytes, 0);
                    if (transport.CopyFromChain(chain, sizeof(hdr), buf.data(), data_bytes) &&
                        WriteSectors(hdr.sector, buf.data(), data_bytes)) {
                        status = kBlkSOk;
                    }
                    transport.CopyToChain(chain, 0, &status, 1);
                }
            } else if (hdr.type == kBlkTFlush) {
                FlushBacking();
                status = kBlkSOk;
                transport.CopyToChain(chain, 0, &status, 1);
            } else if (hdr.type == kBlkTGetId) {
                size_t total_w = transport.TotalWriteBytes(chain);
                if (total_w >= 21u) {
                    uint8_t id_buf[20]{};
                    std::memcpy(id_buf, disk_id_.data(), std::min<size_t>(disk_id_.size(), 20));
                    transport.CopyToChain(chain, 0, id_buf, 20);
                    status = kBlkSOk;
                    transport.CopyToChain(chain, 20, &status, 1);
                    bytes_written = 21u;
                }
            } else {
                status = kBlkSUnsupp;
                transport.CopyToChain(chain, 0, &status, 1);
            }
        }
        transport.PushUsed(0u, chain.head_idx, bytes_written);
    }
}

// =========================================================================
// 2. virtio-net (Device ID = 1)
// =========================================================================
namespace {
inline constexpr size_t kVirtioNetHdrLen = 12u; // struct virtio_net_hdr_v1
} // namespace

VirtioNetDevice::VirtioNetDevice() = default;

void VirtioNetDevice::SetMacAddress(const std::array<uint8_t, 6>& mac) {
    std::lock_guard<std::mutex> lock(mutex_);
    mac_ = mac;
}

void VirtioNetDevice::SetTxCallback(TxFrameCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    tx_cb_ = std::move(cb);
}

uint64_t VirtioNetDevice::DeviceFeatures() const {
    return (1ULL << 5) | (1ULL << 16); // VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS
}

uint32_t VirtioNetDevice::ReadConfig(uint64_t offset, unsigned size_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t out = 0;
    for (unsigned b = 0; b < size_bytes; ++b) {
        uint64_t off = offset + b;
        uint8_t byte_val = 0;
        if (off < 6u) byte_val = mac_[off];
        else if (off == 6u) byte_val = 1u; // VIRTIO_NET_S_LINK_UP
        out |= (static_cast<uint32_t>(byte_val) << (b * 8u));
    }
    return out;
}

void VirtioNetDevice::WriteConfig(uint64_t /*offset*/, unsigned /*size_bytes*/, uint64_t /*value*/) {}

std::vector<std::vector<uint8_t>> VirtioNetDevice::DrainTxFrames() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::vector<uint8_t>> out;
    while (!tx_capture_.empty()) {
        out.push_back(std::move(tx_capture_.front()));
        tx_capture_.pop_front();
    }
    return out;
}

void VirtioNetDevice::InjectRxFrame(VirtioMmioDevice& transport, const std::vector<uint8_t>& eth_frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    rx_pending_.push_back(eth_frame);
    DrainRxPendingLocked(transport);
}

void VirtioNetDevice::DrainRxPendingLocked(VirtioMmioDevice& transport) {
    while (!rx_pending_.empty()) {
        VirtqChain chain;
        if (!transport.PopAvailChain(0u, chain)) break;
        const auto& frame = rx_pending_.front();
        const size_t total_len = kVirtioNetHdrLen + frame.size();
        std::vector<uint8_t> pkt(total_len, 0u);
        std::memcpy(pkt.data() + kVirtioNetHdrLen, frame.data(), frame.size());
        uint32_t written = 0;
        if (transport.TotalWriteBytes(chain) >= total_len &&
            transport.CopyToChain(chain, 0, pkt.data(), total_len)) {
            written = static_cast<uint32_t>(total_len);
        }
        transport.PushUsed(0u, chain.head_idx, written);
        rx_pending_.pop_front();
    }
}

void VirtioNetDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx == 0u) {
        std::lock_guard<std::mutex> lock(mutex_);
        DrainRxPendingLocked(transport);
        return;
    }
    if (queue_idx == 1u) {
        VirtqChain chain;
        while (transport.PopAvailChain(1u, chain)) {
            size_t total_r = transport.TotalReadBytes(chain);
            if (total_r > kVirtioNetHdrLen) {
                std::vector<uint8_t> frame(total_r - kVirtioNetHdrLen);
                if (transport.CopyFromChain(chain, kVirtioNetHdrLen, frame.data(), frame.size())) {
                    TxFrameCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        tx_capture_.push_back(frame);
                        cb = tx_cb_;
                    }
                    if (cb) cb(frame);
                }
            }
            transport.PushUsed(1u, chain.head_idx, 0u);
        }
    }
}

// =========================================================================
// 3. virtio-console (Device ID = 3)
// =========================================================================
VirtioConsoleDevice::VirtioConsoleDevice(TxBytesCallback tx_cb) : tx_cb_(std::move(tx_cb)) {}

void VirtioConsoleDevice::SetTxCallback(TxBytesCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    tx_cb_ = std::move(cb);
}

std::string VirtioConsoleDevice::CapturedOutput() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return captured_tx_;
}

uint64_t VirtioConsoleDevice::DeviceFeatures() const {
    return (1ULL << 0); // VIRTIO_CONSOLE_F_SIZE
}

uint32_t VirtioConsoleDevice::ReadConfig(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x00) return static_cast<uint32_t>(cols_) | (static_cast<uint32_t>(rows_) << 16);
    if (offset == 0x02) return rows_;
    return 0u;
}

void VirtioConsoleDevice::WriteConfig(uint64_t /*offset*/, unsigned /*size_bytes*/, uint64_t /*value*/) {}

void VirtioConsoleDevice::PushRxBytes(VirtioMmioDevice& transport, const std::string& text) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (char c : text) rx_pending_.push_back(static_cast<uint8_t>(c));
    DrainRxPendingLocked(transport);
}

void VirtioConsoleDevice::DrainRxPendingLocked(VirtioMmioDevice& transport) {
    while (!rx_pending_.empty()) {
        VirtqChain chain;
        if (!transport.PopAvailChain(0u, chain)) break;
        size_t cap = transport.TotalWriteBytes(chain);
        size_t n = std::min(cap, rx_pending_.size());
        std::vector<uint8_t> buf(n);
        for (size_t i = 0; i < n; ++i) {
            buf[i] = rx_pending_.front();
            rx_pending_.pop_front();
        }
        uint32_t written = 0;
        if (n > 0 && transport.CopyToChain(chain, 0, buf.data(), n)) {
            written = static_cast<uint32_t>(n);
        }
        transport.PushUsed(0u, chain.head_idx, written);
    }
}

void VirtioConsoleDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx == 0u) {
        std::lock_guard<std::mutex> lock(mutex_);
        DrainRxPendingLocked(transport);
        return;
    }
    if (queue_idx == 1u) {
        VirtqChain chain;
        while (transport.PopAvailChain(1u, chain)) {
            size_t len = transport.TotalReadBytes(chain);
            if (len > 0) {
                std::string chunk(len, '\0');
                if (transport.CopyFromChain(chain, 0, chunk.data(), len)) {
                    TxBytesCallback cb;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        captured_tx_ += chunk;
                        cb = tx_cb_;
                    }
                    if (cb) cb(chunk);
                }
            }
            transport.PushUsed(1u, chain.head_idx, 0u);
        }
    }
}

// =========================================================================
// 4. virtio-rng (Device ID = 4)
// =========================================================================
uint64_t VirtioRngDevice::DeviceFeatures() const { return 0ULL; }
uint32_t VirtioRngDevice::ReadConfig(uint64_t /*offset*/, unsigned /*size_bytes*/) { return 0u; }
void VirtioRngDevice::WriteConfig(uint64_t /*offset*/, unsigned /*size_bytes*/, uint64_t /*value*/) {}

void VirtioRngDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx != 0u) return;
    VirtqChain chain;
    while (transport.PopAvailChain(0u, chain)) {
        size_t req_bytes = transport.TotalWriteBytes(chain);
        std::vector<uint8_t> entropy(req_bytes, 0u);
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        size_t filled = 0;
        if (fd >= 0) {
            while (filled < req_bytes) {
                ssize_t n = read(fd, entropy.data() + filled, req_bytes - filled);
                if (n <= 0) break;
                filled += static_cast<size_t>(n);
            }
            close(fd);
        }
        if (filled < req_bytes) {
            std::random_device rd;
            while (filled < req_bytes) {
                uint32_t r = rd();
                size_t copy = std::min<size_t>(sizeof(r), req_bytes - filled);
                std::memcpy(entropy.data() + filled, &r, copy);
                filled += copy;
            }
        }
        uint32_t written = 0;
        if (req_bytes > 0 && transport.CopyToChain(chain, 0, entropy.data(), req_bytes)) {
            written = static_cast<uint32_t>(req_bytes);
        }
        transport.PushUsed(0u, chain.head_idx, written);
    }
}

// =========================================================================
// 5. virtio-balloon (Device ID = 5)
// =========================================================================
uint64_t VirtioBalloonDevice::DeviceFeatures() const { return 0ULL; }

void VirtioBalloonDevice::SetTargetPages(VirtioMmioDevice& transport, uint32_t num_pages) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        num_pages_ = num_pages;
    }
    transport.RaiseConfigInterrupt();
}

uint32_t VirtioBalloonDevice::TargetPages() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return num_pages_;
}

uint32_t VirtioBalloonDevice::ActualPages() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return actual_pages_;
}

size_t VirtioBalloonDevice::InflatedPfnCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return inflated_pfns_.size();
}

void VirtioBalloonDevice::OnReset() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_pages_ = 0;
    actual_pages_ = 0;
    inflated_pfns_.clear();
}

uint32_t VirtioBalloonDevice::ReadConfig(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x00) return num_pages_;
    if (offset == 0x04) return actual_pages_;
    return 0u;
}

void VirtioBalloonDevice::WriteConfig(uint64_t offset, unsigned /*size_bytes*/, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x04) {
        actual_pages_ = static_cast<uint32_t>(value);
    }
}

void VirtioBalloonDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx != 0u && queue_idx != 1u) return;
    VirtqChain chain;
    while (transport.PopAvailChain(queue_idx, chain)) {
        size_t len = transport.TotalReadBytes(chain);
        size_t count = len / sizeof(uint32_t);
        if (count > 0) {
            std::vector<uint32_t> pfns(count);
            if (transport.CopyFromChain(chain, 0, pfns.data(), count * sizeof(uint32_t))) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (queue_idx == 0u) {
                    for (uint32_t pfn : pfns) inflated_pfns_.push_back(pfn);
                    actual_pages_ = static_cast<uint32_t>(inflated_pfns_.size());
                } else {
                    for (uint32_t pfn : pfns) {
                        auto it = std::find(inflated_pfns_.begin(), inflated_pfns_.end(), pfn);
                        if (it != inflated_pfns_.end()) inflated_pfns_.erase(it);
                    }
                    actual_pages_ = static_cast<uint32_t>(inflated_pfns_.size());
                }
            }
        }
        transport.PushUsed(queue_idx, chain.head_idx, 0u);
    }
}

} // namespace haseeb::vm
