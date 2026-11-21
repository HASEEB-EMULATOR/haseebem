#pragma once

#include "haseeb/virtio_mmio.hpp"

#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace haseeb::vm {

// Virtio-Input Device (Device ID = 18, Virtio 1.0 spec section 5.8)
// Queue 0 = eventq (device -> guest), Queue 1 = statusq (guest -> device)
// Simultaneously mirrors 24-byte Linux struct input_event records for EL0 /dev/input/event*
class VirtioInputDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdInput = 18u;

    enum class Role : uint8_t {
        MultiTouch = 0,
        KeyboardGamepad = 1,
    };

    enum ConfigSelect : uint8_t {
        kCfgUnset     = 0x00u,
        kCfgIdName    = 0x01u,
        kCfgIdSerial  = 0x02u,
        kCfgIdDevids  = 0x03u,
        kCfgPropBits  = 0x10u,
        kCfgEvBits    = 0x11u,
        kCfgAbsInfo   = 0x12u,
    };

    // Linux input event types
    static constexpr uint16_t kEvSyn = 0x00u;
    static constexpr uint16_t kEvKey = 0x01u;
    static constexpr uint16_t kEvRel = 0x02u;
    static constexpr uint16_t kEvAbs = 0x03u;
    static constexpr uint16_t kEvLed = 0x11u;

    // Linux EV_SYN codes
    static constexpr uint16_t kSynReport = 0x00u;

    // Linux EV_ABS codes
    static constexpr uint16_t kAbsX            = 0x00u;
    static constexpr uint16_t kAbsY            = 0x01u;
    static constexpr uint16_t kAbsZ            = 0x02u;
    static constexpr uint16_t kAbsRx           = 0x03u;
    static constexpr uint16_t kAbsRy           = 0x04u;
    static constexpr uint16_t kAbsRz           = 0x05u;
    static constexpr uint16_t kAbsHat0X        = 0x10u;
    static constexpr uint16_t kAbsHat0Y        = 0x11u;
    static constexpr uint16_t kAbsPressure     = 0x18u;
    static constexpr uint16_t kAbsMtSlot       = 0x2Fu;
    static constexpr uint16_t kAbsMtTouchMajor = 0x30u;
    static constexpr uint16_t kAbsMtPositionX  = 0x35u;
    static constexpr uint16_t kAbsMtPositionY  = 0x36u;
    static constexpr uint16_t kAbsMtTrackingId = 0x39u;

    // Linux EV_KEY touch/gamepad/common codes
    static constexpr uint16_t kBtnTouch     = 0x14Au;
    static constexpr uint16_t kBtnSouth     = 0x130u; // A
    static constexpr uint16_t kBtnEast      = 0x131u; // B
    static constexpr uint16_t kBtnNorth     = 0x133u; // X
    static constexpr uint16_t kBtnWest      = 0x134u; // Y
    static constexpr uint16_t kBtnTl        = 0x136u; // L1
    static constexpr uint16_t kBtnTr        = 0x137u; // R1
    static constexpr uint16_t kBtnTl2       = 0x138u; // L2
    static constexpr uint16_t kBtnTr2       = 0x139u; // R2
    static constexpr uint16_t kBtnSelect    = 0x13Au;
    static constexpr uint16_t kBtnStart     = 0x13Bu;
    static constexpr uint16_t kBtnMode      = 0x13Cu;
    static constexpr uint16_t kBtnThumbL    = 0x13Du;
    static constexpr uint16_t kBtnThumbR    = 0x13Eu;
    static constexpr uint16_t kBtnDpadUp    = 0x220u;
    static constexpr uint16_t kBtnDpadDown  = 0x221u;
    static constexpr uint16_t kBtnDpadLeft  = 0x222u;
    static constexpr uint16_t kBtnDpadRight = 0x223u;

    static constexpr uint32_t kMaxMtSlots = 16u;

    struct VirtioInputEvent {
        uint16_t type = 0;
        uint16_t code = 0;
        int32_t value = 0;
    };

    // Standard Linux AArch64 24-byte struct input_event
    struct LinuxInputEvent {
        int64_t tv_sec = 0;
        int64_t tv_usec = 0;
        uint16_t type = 0;
        uint16_t code = 0;
        int32_t value = 0;
    };

    struct LinuxAbsInfo {
        int32_t value = 0;
        int32_t minimum = 0;
        int32_t maximum = 0;
        int32_t fuzz = 0;
        int32_t flat = 0;
        int32_t resolution = 0;
    };

    explicit VirtioInputDevice(Role role);

    Role DeviceRole() const { return role_; }
    std::string DeviceName() const;
    std::string DevicePhys() const;
    std::string DeviceUniq() const;
    void GetDeviceIds(uint16_t& bustype, uint16_t& vendor, uint16_t& product, uint16_t& version) const;

    void ConfigureDisplay(uint32_t width, uint32_t height);

    // Android MotionEvent actions: 0=DOWN, 1=UP, 2=MOVE, 3=CANCEL, 5=POINTER_DOWN, 6=POINTER_UP
    void PushTouch(int action, int32_t x, int32_t y, int32_t pointer_id);
    void PushLinuxKey(uint16_t linux_code, bool down);
    void PushAndroidKey(int android_keycode, bool down);
    void PushAbsAxis(uint16_t abs_code, int32_t value);

    // Maps Android KeyEvent.KEYCODE_* to Linux KEY_* / BTN_* codes (0 if unmapped)
    static uint16_t TranslateAndroidKeyCode(int android_keycode);

    // Flushes queued virtio_input_events into guest eventq descriptors if transport is ready
    void FlushEvents(VirtioMmioDevice& transport);

    // EL0 /dev/input/event* evdev consumer APIs
    bool HasPendingEvdev() const;
    size_t PopEvdevEvents(LinuxInputEvent* out_events, size_t max_events);
    void FillEventBitmap(uint32_t ev_type, uint8_t* dst, size_t dst_len) const;
    void FillPropBitmap(uint8_t* dst, size_t dst_len) const;
    LinuxAbsInfo GetAbsInfo(uint16_t abs_code) const;
    uint32_t LedStateMask() const;

    // VirtioDeviceBackend overrides
    uint32_t DeviceId() const override { return kVirtioIdInput; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 2u; }
    uint32_t QueueMaxSize(uint32_t /*queue_idx*/) const override { return 128u; }
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void OnReset() override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    struct MtSlot {
        bool active = false;
        int32_t pointer_id = -1;
        int32_t tracking_id = -1;
        int32_t x = 0;
        int32_t y = 0;
    };

    void EnqueueEventLocked(uint16_t type, uint16_t code, int32_t value);
    void EnqueueSynLocked();
    uint32_t ActiveTouchCountLocked() const;
    int FindSlotForPointerLocked(int32_t pointer_id) const;
    int AllocSlotForPointerLocked(int32_t pointer_id);
    std::vector<uint8_t> BuildConfigPayloadLocked(uint8_t select, uint8_t subsel) const;
    static void SetBit(std::vector<uint8_t>& bits, uint16_t bit);

    Role role_;
    mutable std::mutex mutex_;

    uint32_t display_width_ = 720u;
    uint32_t display_height_ = 1560u;

    uint8_t cfg_select_ = 0u;
    uint8_t cfg_subsel_ = 0u;

    std::array<MtSlot, kMaxMtSlots> mt_slots_{};
    int32_t next_tracking_id_ = 1;
    uint32_t current_mt_slot_ = 0u;
    bool btn_touch_down_ = false;

    uint32_t led_mask_ = 0u;
    std::deque<VirtioInputEvent> virtq_events_;
    std::deque<LinuxInputEvent> evdev_events_;
    static constexpr size_t kMaxQueuedEvents = 4096u;
};

} // namespace haseeb::vm
