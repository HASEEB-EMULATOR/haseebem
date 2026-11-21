#include "haseeb/virtio_gpu.hpp"

#include <algorithm>
#include <cstring>

namespace haseeb::vm {

namespace {

inline constexpr uint64_t kVirtioFVersion1 = (1ULL << 32);

#pragma pack(push, 1)
struct VirtioGpuCtrlHdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
};

struct VirtioGpuRect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

struct VirtioGpuDisplayOne {
    VirtioGpuRect r;
    uint32_t enabled;
    uint32_t flags;
};

struct VirtioGpuRespDisplayInfo {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuDisplayOne pmodes[16];
};

struct VirtioGpuResourceCreate2d {
    VirtioGpuCtrlHdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
};

struct VirtioGpuResourceUnref {
    VirtioGpuCtrlHdr hdr;
    uint32_t resource_id;
    uint32_t padding;
};

struct VirtioGpuSetScanout {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    uint32_t scanout_id;
    uint32_t resource_id;
};

struct VirtioGpuResourceFlush {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    uint32_t resource_id;
    uint32_t padding;
};

struct VirtioGpuTransferToHost2d {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuRect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
};

struct VirtioGpuResourceAttachBacking {
    VirtioGpuCtrlHdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
};

struct VirtioGpuMemEntry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
};

struct VirtioGpuResourceDetachBacking {
    VirtioGpuCtrlHdr hdr;
    uint32_t resource_id;
    uint32_t padding;
};

struct VirtioGpuCursorPos {
    uint32_t scanout_id;
    uint32_t x;
    uint32_t y;
    uint32_t padding;
};

struct VirtioGpuUpdateCursor {
    VirtioGpuCtrlHdr hdr;
    VirtioGpuCursorPos pos;
    uint32_t resource_id;
    uint32_t hot_x;
    uint32_t hot_y;
    uint32_t padding;
};
#pragma pack(pop)

void InitRespHeader(VirtioGpuCtrlHdr& out, const VirtioGpuCtrlHdr& req, uint32_t resp_type) {
    out = {};
    out.type = resp_type;
    out.flags = (req.flags & 1u); // preserve VIRTIO_GPU_FLAG_FENCE
    out.fence_id = req.fence_id;
    out.ctx_id = req.ctx_id;
    out.ring_idx = req.ring_idx;
}

bool ReadFromBacking(GuestRam& ram,
                     const std::vector<VirtioGpuDevice::MemExtent>& backing,
                     uint64_t offset,
                     void* dst,
                     size_t len) {
    auto* out = static_cast<uint8_t*>(dst);
    uint64_t cursor = 0;
    size_t written = 0;
    for (const auto& ext : backing) {
        if (written >= len) break;
        uint64_t ext_end = cursor + ext.length;
        if (offset + written < ext_end) {
            uint64_t in_ext_off = (offset + written) - cursor;
            size_t take = static_cast<size_t>(
                std::min<uint64_t>(ext.length - in_ext_off, len - written));
            if (!ram.ReadBytes(ext.guest_pa + in_ext_off, out + written, take)) {
                return false;
            }
            written += take;
        }
        cursor = ext_end;
    }
    return written == len;
}

} // namespace

uint32_t VirtioGpuDevice::ConvertPixelToRgba8888(uint32_t raw_le, uint32_t format) {
    const uint8_t b0 = static_cast<uint8_t>(raw_le & 0xFFu);
    const uint8_t b1 = static_cast<uint8_t>((raw_le >> 8) & 0xFFu);
    const uint8_t b2 = static_cast<uint8_t>((raw_le >> 16) & 0xFFu);
    const uint8_t b3 = static_cast<uint8_t>((raw_le >> 24) & 0xFFu);

    uint8_t r = b0, g = b1, b = b2, a = b3;
    switch (format) {
        case kFormatB8G8R8A8Unorm: // memory bytes B, G, R, A -> R, G, B, A
            r = b2; g = b1; b = b0; a = b3;
            break;
        case kFormatB8G8R8X8Unorm:
            r = b2; g = b1; b = b0; a = 0xFFu;
            break;
        case kFormatA8R8G8B8Unorm: // memory bytes A, R, G, B -> R, G, B, A
            r = b1; g = b2; b = b3; a = b0;
            break;
        case kFormatX8R8G8B8Unorm:
            r = b1; g = b2; b = b3; a = 0xFFu;
            break;
        case kFormatR8G8B8A8Unorm:
            r = b0; g = b1; b = b2; a = b3;
            break;
        case kFormatR8G8B8X8Unorm:
            r = b0; g = b1; b = b2; a = 0xFFu;
            break;
        case kFormatA8B8G8R8Unorm:
            r = b3; g = b2; b = b1; a = b0;
            break;
        case kFormatX8B8G8R8Unorm:
            r = b3; g = b2; b = b1; a = 0xFFu;
            break;
        default:
            break;
    }
    return static_cast<uint32_t>(r) |
           (static_cast<uint32_t>(g) << 8) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(a) << 24);
}

void VirtioGpuDevice::ConfigureDisplay(uint32_t width, uint32_t height) {
    if (width == 0 || height == 0) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        display_width_.store(width);
        display_height_.store(height);
        events_read_ |= 1u; // VIRTIO_GPU_EVENT_DISPLAY
    }
}

void VirtioGpuDevice::SetScanoutCallback(ScanoutCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    scanout_cb_ = std::move(cb);
}

uint64_t VirtioGpuDevice::DeviceFeatures() const {
    return kVirtioFVersion1;
}

uint32_t VirtioGpuDevice::ReadConfig(uint64_t offset, unsigned /*size_bytes*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (offset) {
        case 0x00: return events_read_;
        case 0x04: return 0u;
        case 0x08: return 1u; // num_scanouts = 1
        case 0x0C: return 0u; // num_capsets = 0
        default:   return 0u;
    }
}

void VirtioGpuDevice::WriteConfig(uint64_t offset, unsigned /*size_bytes*/, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (offset == 0x04) {
        events_read_ &= ~static_cast<uint32_t>(value);
    }
}

void VirtioGpuDevice::OnReset() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_read_ = 0;
    scanout_resource_id_ = 0;
    scanout_x_ = 0;
    scanout_y_ = 0;
    scanout_w_ = 0;
    scanout_h_ = 0;
    cursor_x_ = 0;
    cursor_y_ = 0;
    cursor_resource_id_ = 0;
    resources_.clear();
    latest_frame_.clear();
    latest_w_ = 0;
    latest_h_ = 0;
    frame_count_.store(0ULL);
}

uint32_t VirtioGpuDevice::ActiveScanoutResourceId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scanout_resource_id_;
}

int32_t VirtioGpuDevice::CursorX() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cursor_x_;
}

int32_t VirtioGpuDevice::CursorY() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cursor_y_;
}

bool VirtioGpuDevice::CursorVisible() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cursor_resource_id_ != 0u;
}

bool VirtioGpuDevice::CopyLatestFrame(std::vector<uint32_t>& out_rgba,
                                      uint32_t& out_width,
                                      uint32_t& out_height) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (latest_frame_.empty() || latest_w_ == 0 || latest_h_ == 0) return false;
    out_rgba = latest_frame_;
    out_width = latest_w_;
    out_height = latest_h_;
    return true;
}

bool VirtioGpuDevice::SubmitRawRgbaFrame(const uint8_t* src_rgba,
                                         uint32_t width,
                                         uint32_t height,
                                         uint32_t stride_bytes) {
    if (!src_rgba || width == 0 || height == 0 || width > 4096u || height > 4096u) {
        return false;
    }
    const uint32_t min_stride = width * 4u;
    if (stride_bytes < min_stride) stride_bytes = min_stride;

    ScanoutCallback cb;
    std::vector<uint32_t> frame_copy(static_cast<size_t>(width) * height);
    for (uint32_t y = 0; y < height; ++y) {
        const uint8_t* row = src_rgba + static_cast<size_t>(y) * stride_bytes;
        std::memcpy(frame_copy.data() + static_cast<size_t>(y) * width, row, min_stride);
    }

    uint64_t frame_idx = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        latest_frame_ = frame_copy;
        latest_w_ = width;
        latest_h_ = height;
        frame_idx = frame_count_.fetch_add(1ULL) + 1ULL;
        cb = scanout_cb_;
    }
    if (cb) {
        cb(frame_copy.data(), width, height, frame_idx);
    }
    return true;
}

uint32_t VirtioGpuDevice::FlushScanoutLocked(ScanoutCallback& out_cb,
                                             std::vector<uint32_t>& out_pixels,
                                             uint32_t& out_w,
                                             uint32_t& out_h,
                                             uint64_t& out_frame_idx) {
    if (scanout_resource_id_ == 0u) {
        return kRespOkNodata;
    }
    auto it = resources_.find(scanout_resource_id_);
    if (it == resources_.end()) {
        return kRespErrInvalidResourceId;
    }
    const Resource2d& res = it->second;
    const uint32_t w = (scanout_w_ > 0u) ? std::min(scanout_w_, res.width) : res.width;
    const uint32_t h = (scanout_h_ > 0u) ? std::min(scanout_h_, res.height) : res.height;
    if (w == 0u || h == 0u || scanout_x_ >= res.width || scanout_y_ >= res.height) {
        return kRespErrInvalidParameter;
    }

    const uint32_t eff_w = std::min(w, res.width - scanout_x_);
    const uint32_t eff_h = std::min(h, res.height - scanout_y_);
    out_pixels.resize(static_cast<size_t>(eff_w) * eff_h);
    for (uint32_t row = 0; row < eff_h; ++row) {
        const size_t src_idx = static_cast<size_t>(scanout_y_ + row) * res.width + scanout_x_;
        const size_t dst_idx = static_cast<size_t>(row) * eff_w;
        std::memcpy(out_pixels.data() + dst_idx, res.pixels_rgba.data() + src_idx, eff_w * 4u);
    }

    latest_frame_ = out_pixels;
    latest_w_ = eff_w;
    latest_h_ = eff_h;
    out_w = eff_w;
    out_h = eff_h;
    out_frame_idx = frame_count_.fetch_add(1ULL) + 1ULL;
    out_cb = scanout_cb_;
    return kRespOkNodata;
}

uint32_t VirtioGpuDevice::HandleControlCommand(VirtioMmioDevice& transport,
                                               const VirtqChain& /*chain*/,
                                               const std::vector<uint8_t>& req,
                                               std::vector<uint8_t>& resp) {
    if (req.size() < sizeof(VirtioGpuCtrlHdr)) {
        return 0u;
    }
    VirtioGpuCtrlHdr hdr{};
    std::memcpy(&hdr, req.data(), sizeof(hdr));

    auto write_nodata = [&](uint32_t status) -> uint32_t {
        resp.resize(sizeof(VirtioGpuCtrlHdr));
        VirtioGpuCtrlHdr rh{};
        InitRespHeader(rh, hdr, status);
        std::memcpy(resp.data(), &rh, sizeof(rh));
        return static_cast<uint32_t>(resp.size());
    };

    switch (hdr.type) {
        case kCmdGetDisplayInfo: {
            VirtioGpuRespDisplayInfo di{};
            InitRespHeader(di.hdr, hdr, kRespOkDisplayInfo);
            di.pmodes[0].r.x = 0u;
            di.pmodes[0].r.y = 0u;
            di.pmodes[0].r.width = display_width_.load();
            di.pmodes[0].r.height = display_height_.load();
            di.pmodes[0].enabled = 1u;
            di.pmodes[0].flags = 0u;
            resp.resize(sizeof(di));
            std::memcpy(resp.data(), &di, sizeof(di));
            return static_cast<uint32_t>(resp.size());
        }

        case kCmdResourceCreate2d: {
            if (req.size() < sizeof(VirtioGpuResourceCreate2d)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuResourceCreate2d cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            if (cmd.resource_id == 0u || cmd.width == 0u || cmd.height == 0u ||
                cmd.width > 4096u || cmd.height > 4096u) {
                return write_nodata(kRespErrInvalidParameter);
            }
            const size_t total_px = static_cast<size_t>(cmd.width) * cmd.height;
            std::lock_guard<std::mutex> lock(mutex_);
            if (resources_.find(cmd.resource_id) != resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            Resource2d r;
            r.id = cmd.resource_id;
            r.format = cmd.format;
            r.width = cmd.width;
            r.height = cmd.height;
            r.pixels_rgba.assign(total_px, 0xFF000000u);
            resources_.emplace(cmd.resource_id, std::move(r));
            return write_nodata(kRespOkNodata);
        }

        case kCmdResourceUnref: {
            if (req.size() < sizeof(VirtioGpuResourceUnref)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuResourceUnref cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = resources_.find(cmd.resource_id);
            if (it == resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            if (scanout_resource_id_ == cmd.resource_id) {
                scanout_resource_id_ = 0u;
            }
            resources_.erase(it);
            return write_nodata(kRespOkNodata);
        }

        case kCmdSetScanout: {
            if (req.size() < sizeof(VirtioGpuSetScanout)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuSetScanout cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            if (cmd.scanout_id != 0u) {
                return write_nodata(kRespErrInvalidScanoutId);
            }
            std::lock_guard<std::mutex> lock(mutex_);
            if (cmd.resource_id == 0u) {
                scanout_resource_id_ = 0u;
                scanout_x_ = scanout_y_ = scanout_w_ = scanout_h_ = 0u;
                return write_nodata(kRespOkNodata);
            }
            auto it = resources_.find(cmd.resource_id);
            if (it == resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            scanout_resource_id_ = cmd.resource_id;
            scanout_x_ = cmd.r.x;
            scanout_y_ = cmd.r.y;
            scanout_w_ = (cmd.r.width > 0u) ? cmd.r.width : it->second.width;
            scanout_h_ = (cmd.r.height > 0u) ? cmd.r.height : it->second.height;
            return write_nodata(kRespOkNodata);
        }

        case kCmdResourceAttachBacking: {
            if (req.size() < sizeof(VirtioGpuResourceAttachBacking)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuResourceAttachBacking cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            const size_t entries_bytes = static_cast<size_t>(cmd.nr_entries) * sizeof(VirtioGpuMemEntry);
            if (cmd.nr_entries > 4096u ||
                req.size() < sizeof(VirtioGpuResourceAttachBacking) + entries_bytes) {
                return write_nodata(kRespErrInvalidParameter);
            }
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = resources_.find(cmd.resource_id);
            if (it == resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            it->second.backing.clear();
            const uint8_t* ptr = req.data() + sizeof(VirtioGpuResourceAttachBacking);
            for (uint32_t i = 0; i < cmd.nr_entries; ++i) {
                VirtioGpuMemEntry me{};
                std::memcpy(&me, ptr + static_cast<size_t>(i) * sizeof(me), sizeof(me));
                it->second.backing.push_back(MemExtent{me.addr, me.length});
            }
            return write_nodata(kRespOkNodata);
        }

        case kCmdResourceDetachBacking: {
            if (req.size() < sizeof(VirtioGpuResourceDetachBacking)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuResourceDetachBacking cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = resources_.find(cmd.resource_id);
            if (it == resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            it->second.backing.clear();
            return write_nodata(kRespOkNodata);
        }

        case kCmdTransferToHost2d: {
            if (req.size() < sizeof(VirtioGpuTransferToHost2d)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuTransferToHost2d cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = resources_.find(cmd.resource_id);
            if (it == resources_.end()) {
                return write_nodata(kRespErrInvalidResourceId);
            }
            Resource2d& res = it->second;
            if (cmd.r.x + cmd.r.width > res.width || cmd.r.y + cmd.r.height > res.height) {
                return write_nodata(kRespErrInvalidParameter);
            }
            if (cmd.r.width == 0u || cmd.r.height == 0u) {
                return write_nodata(kRespOkNodata);
            }
            const uint64_t row_stride = static_cast<uint64_t>(res.width) * 4ULL;
            std::vector<uint8_t> row_buf(static_cast<size_t>(cmd.r.width) * 4u);
            for (uint32_t dy = 0; dy < cmd.r.height; ++dy) {
                const uint64_t src_off = cmd.offset + static_cast<uint64_t>(dy) * row_stride;
                if (!ReadFromBacking(transport.Ram(), res.backing, src_off,
                                     row_buf.data(), row_buf.size())) {
                    return write_nodata(kRespErrInvalidParameter);
                }
                const size_t dst_base = static_cast<size_t>(cmd.r.y + dy) * res.width + cmd.r.x;
                for (uint32_t dx = 0; dx < cmd.r.width; ++dx) {
                    uint32_t raw_px = 0;
                    std::memcpy(&raw_px, row_buf.data() + static_cast<size_t>(dx) * 4u, 4u);
                    res.pixels_rgba[dst_base + dx] = ConvertPixelToRgba8888(raw_px, res.format);
                }
            }
            return write_nodata(kRespOkNodata);
        }

        case kCmdResourceFlush: {
            if (req.size() < sizeof(VirtioGpuResourceFlush)) {
                return write_nodata(kRespErrInvalidParameter);
            }
            VirtioGpuResourceFlush cmd{};
            std::memcpy(&cmd, req.data(), sizeof(cmd));

            ScanoutCallback cb;
            std::vector<uint32_t> frame_pixels;
            uint32_t fw = 0, fh = 0;
            uint64_t fidx = 0;
            uint32_t status = kRespOkNodata;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = resources_.find(cmd.resource_id);
                if (it == resources_.end()) {
                    return write_nodata(kRespErrInvalidResourceId);
                }
                if (scanout_resource_id_ == cmd.resource_id) {
                    status = FlushScanoutLocked(cb, frame_pixels, fw, fh, fidx);
                }
            }
            if (status == kRespOkNodata && cb && !frame_pixels.empty()) {
                cb(frame_pixels.data(), fw, fh, fidx);
            }
            return write_nodata(status);
        }

        default:
            return write_nodata(kRespErrUnspec);
    }
}

void VirtioGpuDevice::HandleCursorCommand(const std::vector<uint8_t>& req) {
    if (req.size() < sizeof(VirtioGpuUpdateCursor)) return;
    VirtioGpuUpdateCursor uc{};
    std::memcpy(&uc, req.data(), sizeof(uc));
    std::lock_guard<std::mutex> lock(mutex_);
    if (uc.hdr.type == kCmdUpdateCursor) {
        cursor_resource_id_ = uc.resource_id;
        cursor_x_ = static_cast<int32_t>(uc.pos.x);
        cursor_y_ = static_cast<int32_t>(uc.pos.y);
    } else if (uc.hdr.type == kCmdMoveCursor) {
        cursor_x_ = static_cast<int32_t>(uc.pos.x);
        cursor_y_ = static_cast<int32_t>(uc.pos.y);
    }
}

void VirtioGpuDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    VirtqChain chain;
    while (transport.PopAvailChain(queue_idx, chain)) {
        const size_t req_len = transport.TotalReadBytes(chain);
        std::vector<uint8_t> req(req_len);
        if (req_len > 0 && !transport.CopyFromChain(chain, 0, req.data(), req_len)) {
            transport.PushUsed(queue_idx, chain.head_idx, 0u);
            continue;
        }

        uint32_t written = 0u;
        if (queue_idx == 0u) {
            std::vector<uint8_t> resp;
            written = HandleControlCommand(transport, chain, req, resp);
            if (written > 0u && transport.TotalWriteBytes(chain) >= written) {
                transport.CopyToChain(chain, 0, resp.data(), written);
            } else {
                written = 0u;
            }
        } else if (queue_idx == 1u) {
            HandleCursorCommand(req);
            written = 0u;
        }
        transport.PushUsed(queue_idx, chain.head_idx, written);
    }
}

} // namespace haseeb::vm
