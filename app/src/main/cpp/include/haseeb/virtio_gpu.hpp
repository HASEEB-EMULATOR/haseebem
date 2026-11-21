#pragma once

#include "haseeb/virtio_mmio.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace haseeb::vm {

// Virtio-GPU 2D Device (Device ID = 16, Virtio 1.0 spec section 5.7)
// Queue 0 = controlq, Queue 1 = cursorq
class VirtioGpuDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdGpu = 16u;

    enum Format : uint32_t {
        kFormatB8G8R8A8Unorm = 1u,
        kFormatB8G8R8X8Unorm = 2u,
        kFormatA8R8G8B8Unorm = 3u,
        kFormatX8R8G8B8Unorm = 4u,
        kFormatR8G8B8A8Unorm = 67u,
        kFormatR8G8B8X8Unorm = 68u,
        kFormatA8B8G8R8Unorm = 121u,
        kFormatX8B8G8R8Unorm = 134u,
    };

    enum CtrlType : uint32_t {
        kCmdGetDisplayInfo        = 0x0100u,
        kCmdResourceCreate2d      = 0x0101u,
        kCmdResourceUnref         = 0x0102u,
        kCmdSetScanout            = 0x0103u,
        kCmdResourceFlush         = 0x0104u,
        kCmdTransferToHost2d      = 0x0105u,
        kCmdResourceAttachBacking = 0x0106u,
        kCmdResourceDetachBacking = 0x0107u,

        kCmdUpdateCursor          = 0x0300u,
        kCmdMoveCursor            = 0x0301u,

        kRespOkNodata             = 0x1100u,
        kRespOkDisplayInfo        = 0x1101u,

        kRespErrUnspec            = 0x1200u,
        kRespErrOutOfMemory       = 0x1201u,
        kRespErrInvalidScanoutId  = 0x1202u,
        kRespErrInvalidResourceId = 0x1203u,
        kRespErrInvalidContextId  = 0x1204u,
        kRespErrInvalidParameter  = 0x1205u,
    };

    using ScanoutCallback = std::function<void(const uint32_t* rgba_pixels,
                                               uint32_t width,
                                               uint32_t height,
                                               uint64_t frame_index)>;

    struct MemExtent {
        uint64_t guest_pa = 0;
        uint32_t length = 0;
    };

    VirtioGpuDevice() = default;

    void ConfigureDisplay(uint32_t width, uint32_t height);
    void SetScanoutCallback(ScanoutCallback cb);

    // Submits a raw RGBA8888 (0xAABBGGRR LE bytes R,G,B,A) framebuffer directly
    // (used by EL0 /dev/fb0 + SurfaceFlinger/HWC scanout bridge).
    bool SubmitRawRgbaFrame(const uint8_t* src_rgba,
                            uint32_t width,
                            uint32_t height,
                            uint32_t stride_bytes);

    bool CopyLatestFrame(std::vector<uint32_t>& out_rgba,
                         uint32_t& out_width,
                         uint32_t& out_height) const;

    uint32_t DisplayWidth() const { return display_width_.load(); }
    uint32_t DisplayHeight() const { return display_height_.load(); }
    uint64_t FrameCount() const { return frame_count_.load(); }
    uint32_t ActiveScanoutResourceId() const;
    int32_t CursorX() const;
    int32_t CursorY() const;
    bool CursorVisible() const;

    uint32_t DeviceId() const override { return kVirtioIdGpu; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 2u; }
    uint32_t QueueMaxSize(uint32_t /*queue_idx*/) const override { return 128u; }
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void OnReset() override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    struct Resource2d {
        uint32_t id = 0;
        uint32_t format = kFormatR8G8B8A8Unorm;
        uint32_t width = 0;
        uint32_t height = 0;
        std::vector<uint32_t> pixels_rgba; // Host RGBA8888 bytes [R,G,B,A] packed LE
        std::vector<MemExtent> backing;
    };

    uint32_t HandleControlCommand(VirtioMmioDevice& transport,
                                  const VirtqChain& chain,
                                  const std::vector<uint8_t>& req,
                                  std::vector<uint8_t>& resp);
    void HandleCursorCommand(const std::vector<uint8_t>& req);
    uint32_t FlushScanoutLocked(ScanoutCallback& out_cb,
                                std::vector<uint32_t>& out_pixels,
                                uint32_t& out_w,
                                uint32_t& out_h,
                                uint64_t& out_frame_idx);

    static uint32_t ConvertPixelToRgba8888(uint32_t raw_le, uint32_t format);

    mutable std::mutex mutex_;
    std::atomic<uint32_t> display_width_{720u};
    std::atomic<uint32_t> display_height_{1560u};
    std::atomic<uint64_t> frame_count_{0ULL};

    uint32_t events_read_ = 0;
    uint32_t scanout_resource_id_ = 0;
    uint32_t scanout_x_ = 0;
    uint32_t scanout_y_ = 0;
    uint32_t scanout_w_ = 0;
    uint32_t scanout_h_ = 0;

    int32_t cursor_x_ = 0;
    int32_t cursor_y_ = 0;
    uint32_t cursor_resource_id_ = 0;

    std::unordered_map<uint32_t, Resource2d> resources_;
    std::vector<uint32_t> latest_frame_;
    uint32_t latest_w_ = 0;
    uint32_t latest_h_ = 0;
    ScanoutCallback scanout_cb_;
};

} // namespace haseeb::vm
