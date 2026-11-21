#include "haseeb/virtio_mmio.hpp"

#include <algorithm>
#include <cstring>

namespace haseeb::vm {

namespace {

inline constexpr uint16_t kVringDescFNext  = 1u;
inline constexpr uint16_t kVringDescFWrite = 2u;

// Split virtqueue descriptor (16 bytes)
struct RawVringDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};
static_assert(sizeof(RawVringDesc) == 16, "RawVringDesc must be 16 bytes");

} // namespace

VirtioMmioDevice::VirtioMmioDevice(GuestRam& ram, VirtioDeviceBackend* backend, IrqCallback irq_cb)
    : ram_(ram), backend_(backend), irq_cb_(std::move(irq_cb)) {
    ResetDevice();
}

void VirtioMmioDevice::SetIrqCallback(IrqCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    irq_cb_ = std::move(cb);
}

void VirtioMmioDevice::ResetDevice() {
    IrqCallback cb;
    bool notify = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        device_features_sel_ = 0;
        driver_features_sel_ = 0;
        driver_features_ = 0;
        queue_sel_ = 0;
        interrupt_status_ = 0;
        status_ = 0;
        for (uint32_t i = 0; i < kMaxQueues; ++i) {
            queues_[i] = VirtQueue{};
            queues_[i].num_max = backend_ ? backend_->QueueMaxSize(i) : 256u;
        }
        if (last_irq_level_) {
            last_irq_level_ = false;
            notify = true;
            cb = irq_cb_;
        }
    }
    if (notify && cb) cb(false);
    if (backend_) backend_->OnReset();
}

void VirtioMmioDevice::UpdateIrqLocked(IrqCallback& out_cb, bool& out_level) {
    out_level = (interrupt_status_ != 0u);
    if (out_level != last_irq_level_) {
        last_irq_level_ = out_level;
        out_cb = irq_cb_;
    } else {
        out_cb = nullptr;
    }
}

void VirtioMmioDevice::RaiseVringInterrupt() {
    IrqCallback cb;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        interrupt_status_ |= 1u;
        UpdateIrqLocked(cb, level);
    }
    if (cb) cb(level);
}

void VirtioMmioDevice::RaiseConfigInterrupt() {
    IrqCallback cb;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++config_generation_;
        interrupt_status_ |= 2u;
        UpdateIrqLocked(cb, level);
    }
    if (cb) cb(level);
}

uint64_t VirtioMmioDevice::Read(uint64_t offset, unsigned size_bytes) {
    if (offset >= 0x100) {
        return backend_ ? backend_->ReadConfig(offset - 0x100, size_bytes) : 0ULL;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    switch (offset) {
        case 0x000: return kMagicValue;
        case 0x004: return kVersion2;
        case 0x008: return backend_ ? backend_->DeviceId() : 0u;
        case 0x00C: return kVendorId;
        case 0x010: {
            if (!backend_) return 0u;
            uint64_t feats = backend_->DeviceFeatures() | (1ULL << 32); // VIRTIO_F_VERSION_1
            return (device_features_sel_ == 0u)
                       ? static_cast<uint32_t>(feats & 0xFFFFFFFFULL)
                       : static_cast<uint32_t>(feats >> 32);
        }
        case 0x034: {
            uint32_t max_q = backend_ ? backend_->NumQueues() : 0u;
            return (queue_sel_ < max_q && queue_sel_ < kMaxQueues) ? queues_[queue_sel_].num_max : 0u;
        }
        case 0x044:
            return (queue_sel_ < kMaxQueues && queues_[queue_sel_].ready) ? 1u : 0u;
        case 0x060:
            return interrupt_status_;
        case 0x070:
            return status_;
        case 0x0FC:
            return config_generation_;
        default:
            return 0u;
    }
}

void VirtioMmioDevice::Write(uint64_t offset, unsigned size_bytes, uint64_t value) {
    if (offset >= 0x100) {
        if (backend_) backend_->WriteConfig(offset - 0x100, size_bytes, value);
        return;
    }

    uint32_t v = static_cast<uint32_t>(value);
    if (offset == 0x050) { // QueueNotify
        if (backend_ && v < backend_->NumQueues()) {
            backend_->HandleQueue(*this, v);
        }
        return;
    }
    if (offset == 0x070 && v == 0u) { // Device reset
        ResetDevice();
        return;
    }

    IrqCallback cb;
    bool level = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        switch (offset) {
            case 0x014: device_features_sel_ = v; break;
            case 0x020:
                if (driver_features_sel_ == 0u) {
                    driver_features_ = (driver_features_ & 0xFFFFFFFF00000000ULL) | v;
                } else if (driver_features_sel_ == 1u) {
                    driver_features_ = (driver_features_ & 0xFFFFFFFFULL) | (static_cast<uint64_t>(v) << 32);
                }
                break;
            case 0x024: driver_features_sel_ = v; break;
            case 0x030: queue_sel_ = v; break;
            case 0x038:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].num = std::min(v, queues_[queue_sel_].num_max);
                }
                break;
            case 0x044:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].ready = (v & 1u) != 0;
                }
                break;
            case 0x064:
                interrupt_status_ &= ~v;
                UpdateIrqLocked(cb, level);
                break;
            case 0x070:
                status_ = v;
                break;
            case 0x080:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].desc_addr = (queues_[queue_sel_].desc_addr & 0xFFFFFFFF00000000ULL) | v;
                }
                break;
            case 0x084:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].desc_addr = (queues_[queue_sel_].desc_addr & 0xFFFFFFFFULL) | (static_cast<uint64_t>(v) << 32);
                }
                break;
            case 0x090:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].driver_addr = (queues_[queue_sel_].driver_addr & 0xFFFFFFFF00000000ULL) | v;
                }
                break;
            case 0x094:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].driver_addr = (queues_[queue_sel_].driver_addr & 0xFFFFFFFFULL) | (static_cast<uint64_t>(v) << 32);
                }
                break;
            case 0x0A0:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].device_addr = (queues_[queue_sel_].device_addr & 0xFFFFFFFF00000000ULL) | v;
                }
                break;
            case 0x0A4:
                if (queue_sel_ < kMaxQueues) {
                    queues_[queue_sel_].device_addr = (queues_[queue_sel_].device_addr & 0xFFFFFFFFULL) | (static_cast<uint64_t>(v) << 32);
                }
                break;
            default:
                break;
        }
    }
    if (cb) cb(level);
}

bool VirtioMmioDevice::PopAvailChain(uint32_t queue_idx, VirtqChain& out_chain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_idx >= kMaxQueues) return false;
    VirtQueue& q = queues_[queue_idx];
    if (!q.ready || q.num == 0u || q.desc_addr == 0ULL || q.driver_addr == 0ULL || q.device_addr == 0ULL) {
        return false;
    }

    uint16_t avail_idx = 0;
    if (!ram_.ReadBytes(q.driver_addr + 2u, &avail_idx, sizeof(avail_idx))) return false;
    if (q.last_avail_idx == avail_idx) return false;

    const uint32_t slot = static_cast<uint32_t>(q.last_avail_idx) % q.num;
    uint16_t head_idx = 0;
    if (!ram_.ReadBytes(q.driver_addr + 4u + slot * 2u, &head_idx, sizeof(head_idx))) return false;
    if (head_idx >= q.num) return false;

    out_chain = VirtqChain{};
    out_chain.head_idx = head_idx;

    uint16_t cur = head_idx;
    for (uint32_t hops = 0; hops < q.num; ++hops) {
        RawVringDesc desc{};
        if (!ram_.ReadBytes(q.desc_addr + static_cast<uint64_t>(cur) * sizeof(RawVringDesc), &desc, sizeof(desc))) {
            return false;
        }
        VirtqBufferSegment seg{desc.addr, desc.len, (desc.flags & kVringDescFWrite) != 0};
        if (seg.writable) out_chain.write_segs.push_back(seg);
        else out_chain.read_segs.push_back(seg);

        if ((desc.flags & kVringDescFNext) == 0u) break;
        if (desc.next >= q.num) return false;
        cur = desc.next;
    }

    ++q.last_avail_idx;
    return true;
}

void VirtioMmioDevice::PushUsed(uint32_t queue_idx, uint16_t head_idx, uint32_t bytes_written) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_idx >= kMaxQueues) return;
        VirtQueue& q = queues_[queue_idx];
        if (!q.ready || q.num == 0u || q.device_addr == 0ULL) return;

        const uint32_t slot = static_cast<uint32_t>(q.last_used_idx) % q.num;
        struct {
            uint32_t id;
            uint32_t len;
        } elem{head_idx, bytes_written};
        ram_.WriteBytes(q.device_addr + 4u + slot * 8u, &elem, sizeof(elem));
        ++q.last_used_idx;
        ram_.WriteBytes(q.device_addr + 2u, &q.last_used_idx, sizeof(q.last_used_idx));
    }
    RaiseVringInterrupt();
}

size_t VirtioMmioDevice::TotalReadBytes(const VirtqChain& chain) const {
    size_t total = 0;
    for (const auto& s : chain.read_segs) total += s.len;
    return total;
}

size_t VirtioMmioDevice::TotalWriteBytes(const VirtqChain& chain) const {
    size_t total = 0;
    for (const auto& s : chain.write_segs) total += s.len;
    return total;
}

bool VirtioMmioDevice::CopyFromChain(const VirtqChain& chain, size_t offset, void* dst, size_t len) const {
    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t copied = 0;
    size_t cur_off = 0;
    for (const auto& s : chain.read_segs) {
        if (copied == len) break;
        if (cur_off + s.len <= offset) {
            cur_off += s.len;
            continue;
        }
        size_t seg_off = (offset > cur_off) ? (offset - cur_off) : 0u;
        size_t take = std::min(len - copied, static_cast<size_t>(s.len) - seg_off);
        if (!ram_.ReadBytes(s.guest_pa + seg_off, out + copied, take)) return false;
        copied += take;
        cur_off += s.len;
    }
    return copied == len;
}

bool VirtioMmioDevice::CopyToChain(const VirtqChain& chain, size_t offset, const void* src, size_t len) const {
    const uint8_t* in = static_cast<const uint8_t*>(src);
    size_t copied = 0;
    size_t cur_off = 0;
    for (const auto& s : chain.write_segs) {
        if (copied == len) break;
        if (cur_off + s.len <= offset) {
            cur_off += s.len;
            continue;
        }
        size_t seg_off = (offset > cur_off) ? (offset - cur_off) : 0u;
        size_t put = std::min(len - copied, static_cast<size_t>(s.len) - seg_off);
        if (!ram_.WriteBytes(s.guest_pa + seg_off, in + copied, put)) return false;
        copied += put;
        cur_off += s.len;
    }
    return copied == len;
}

} // namespace haseeb::vm
