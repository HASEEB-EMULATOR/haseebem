#include "haseeb/virtio_input.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace haseeb::vm {

namespace {

inline constexpr uint64_t kVirtioFVersion1 = (1ULL << 32);

void GetNowSecUsec(int64_t& out_sec, int64_t& out_usec) {
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    out_sec = static_cast<int64_t>(us / 1000000LL);
    out_usec = static_cast<int64_t>(us % 1000000LL);
}

void WriteAbsInfoBytes(std::vector<uint8_t>& out, const VirtioInputDevice::LinuxAbsInfo& info) {
    // virtio_input_absinfo: min, max, fuzz, flat, res (5 x uint32_t LE = 20 bytes)
    out.resize(20u, 0u);
    auto put32 = [&](size_t off, int32_t val) {
        const uint32_t u = static_cast<uint32_t>(val);
        out[off + 0] = static_cast<uint8_t>(u & 0xFFu);
        out[off + 1] = static_cast<uint8_t>((u >> 8) & 0xFFu);
        out[off + 2] = static_cast<uint8_t>((u >> 16) & 0xFFu);
        out[off + 3] = static_cast<uint8_t>((u >> 24) & 0xFFu);
    };
    put32(0, info.minimum);
    put32(4, info.maximum);
    put32(8, info.fuzz);
    put32(12, info.flat);
    put32(16, info.resolution);
}

} // namespace

VirtioInputDevice::VirtioInputDevice(Role role) : role_(role) {}

std::string VirtioInputDevice::DeviceName() const {
    return (role_ == Role::MultiTouch)
               ? "Haseeb Virtual MultiTouch"
               : "Haseeb Virtual Keyboard & Gamepad";
}

std::string VirtioInputDevice::DevicePhys() const {
    return (role_ == Role::MultiTouch) ? "virtio-mmio/input0" : "virtio-mmio/input1";
}

std::string VirtioInputDevice::DeviceUniq() const {
    return (role_ == Role::MultiTouch) ? "haseeb-input-mt0" : "haseeb-input-kbd0";
}

void VirtioInputDevice::GetDeviceIds(uint16_t& bustype,
                                     uint16_t& vendor,
                                     uint16_t& product,
                                     uint16_t& version) const {
    bustype = 0x0006u; // BUS_VIRTUAL
    vendor = 0x4853u;  // "HS"
    product = (role_ == Role::MultiTouch) ? 0x0001u : 0x0002u;
    version = 0x0100u;
}

void VirtioInputDevice::ConfigureDisplay(uint32_t width, uint32_t height) {
    if (width == 0u || height == 0u) return;
    std::lock_guard<std::mutex> lock(mutex_);
    display_width_ = width;
    display_height_ = height;
}

uint64_t VirtioInputDevice::DeviceFeatures() const {
    return kVirtioFVersion1;
}

void VirtioInputDevice::SetBit(std::vector<uint8_t>& bits, uint16_t bit) {
    const size_t byte_idx = static_cast<size_t>(bit / 8u);
    if (byte_idx >= bits.size()) {
        bits.resize(byte_idx + 1u, 0u);
    }
    bits[byte_idx] |= static_cast<uint8_t>(1u << (bit & 7u));
}

VirtioInputDevice::LinuxAbsInfo VirtioInputDevice::GetAbsInfo(uint16_t abs_code) const {
    std::lock_guard<std::mutex> lock(mutex_);
    LinuxAbsInfo info{};
    if (role_ == Role::MultiTouch) {
        switch (abs_code) {
            case kAbsX:
            case kAbsMtPositionX:
                info.minimum = 0;
                info.maximum = static_cast<int32_t>(std::max<uint32_t>(1u, display_width_) - 1u);
                info.resolution = 10;
                break;
            case kAbsY:
            case kAbsMtPositionY:
                info.minimum = 0;
                info.maximum = static_cast<int32_t>(std::max<uint32_t>(1u, display_height_) - 1u);
                info.resolution = 10;
                break;
            case kAbsMtSlot:
                info.minimum = 0;
                info.maximum = static_cast<int32_t>(kMaxMtSlots - 1u);
                break;
            case kAbsMtTouchMajor:
                info.minimum = 0;
                info.maximum = 255;
                break;
            case kAbsMtTrackingId:
                info.minimum = 0;
                info.maximum = 65535;
                break;
            case kAbsPressure:
                info.minimum = 0;
                info.maximum = 255;
                break;
            default:
                break;
        }
    } else {
        switch (abs_code) {
            case kAbsX:
            case kAbsY:
            case kAbsZ:
            case kAbsRx:
            case kAbsRy:
            case kAbsRz:
                info.minimum = -32768;
                info.maximum = 32767;
                info.flat = 128;
                break;
            case kAbsHat0X:
            case kAbsHat0Y:
                info.minimum = -1;
                info.maximum = 1;
                break;
            default:
                break;
        }
    }
    return info;
}

void VirtioInputDevice::FillPropBitmap(uint8_t* dst, size_t dst_len) const {
    if (!dst || dst_len == 0u) return;
    std::memset(dst, 0, dst_len);
    if (role_ == Role::MultiTouch) {
        // INPUT_PROP_DIRECT = 1
        dst[0] |= static_cast<uint8_t>(1u << 1);
    }
}

void VirtioInputDevice::FillEventBitmap(uint32_t ev_type, uint8_t* dst, size_t dst_len) const {
    if (!dst || dst_len == 0u) return;
    std::vector<uint8_t> bits;

    if (ev_type == 0u) {
        // EVIOCGBIT(0, ...): supported EV_* types
        SetBit(bits, kEvSyn);
        SetBit(bits, kEvKey);
        SetBit(bits, kEvAbs);
        if (role_ == Role::KeyboardGamepad) {
            SetBit(bits, kEvLed);
        }
    } else if (ev_type == kEvKey) {
        if (role_ == Role::MultiTouch) {
            SetBit(bits, kBtnTouch);
        } else {
            for (uint16_t k = 1u; k <= 127u; ++k) SetBit(bits, k);
            for (uint16_t k = kBtnSouth; k <= kBtnThumbR; ++k) SetBit(bits, k);
            for (uint16_t k = kBtnDpadUp; k <= kBtnDpadRight; ++k) SetBit(bits, k);
        }
    } else if (ev_type == kEvAbs) {
        if (role_ == Role::MultiTouch) {
            SetBit(bits, kAbsX);
            SetBit(bits, kAbsY);
            SetBit(bits, kAbsPressure);
            SetBit(bits, kAbsMtSlot);
            SetBit(bits, kAbsMtTouchMajor);
            SetBit(bits, kAbsMtPositionX);
            SetBit(bits, kAbsMtPositionY);
            SetBit(bits, kAbsMtTrackingId);
        } else {
            SetBit(bits, kAbsX);
            SetBit(bits, kAbsY);
            SetBit(bits, kAbsZ);
            SetBit(bits, kAbsRx);
            SetBit(bits, kAbsRy);
            SetBit(bits, kAbsRz);
            SetBit(bits, kAbsHat0X);
            SetBit(bits, kAbsHat0Y);
        }
    } else if (ev_type == kEvLed && role_ == Role::KeyboardGamepad) {
        SetBit(bits, 0u); // LED_NUML
        SetBit(bits, 1u); // LED_CAPSL
        SetBit(bits, 2u); // LED_SCROLLL
    }

    std::memset(dst, 0, dst_len);
    const size_t copy_n = std::min(dst_len, bits.size());
    if (copy_n > 0u) {
        std::memcpy(dst, bits.data(), copy_n);
    }
}

std::vector<uint8_t> VirtioInputDevice::BuildConfigPayloadLocked(uint8_t select,
                                                                  uint8_t subsel) const {
    std::vector<uint8_t> payload;
    switch (select) {
        case kCfgIdName: {
            const std::string name = DeviceName();
            payload.assign(name.begin(), name.end());
            break;
        }
        case kCfgIdSerial: {
            const std::string serial = DeviceUniq();
            payload.assign(serial.begin(), serial.end());
            break;
        }
        case kCfgIdDevids: {
            uint16_t bus = 0, ven = 0, prod = 0, ver = 0;
            GetDeviceIds(bus, ven, prod, ver);
            payload.resize(8u, 0u);
            auto put16 = [&](size_t off, uint16_t v) {
                payload[off] = static_cast<uint8_t>(v & 0xFFu);
                payload[off + 1] = static_cast<uint8_t>(v >> 8);
            };
            put16(0, bus);
            put16(2, ven);
            put16(4, prod);
            put16(6, ver);
            break;
        }
        case kCfgPropBits: {
            if (subsel == 0u && role_ == Role::MultiTouch) {
                payload.resize(1u, 0u);
                FillPropBitmap(payload.data(), payload.size());
            }
            break;
        }
        case kCfgEvBits: {
            payload.resize(128u, 0u);
            FillEventBitmap(subsel, payload.data(), payload.size());
            while (!payload.empty() && payload.back() == 0u) {
                payload.pop_back();
            }
            break;
        }
        case kCfgAbsInfo: {
            if ((role_ == Role::MultiTouch &&
                 (subsel == kAbsX || subsel == kAbsY || subsel == kAbsPressure ||
                  subsel == kAbsMtSlot || subsel == kAbsMtTouchMajor ||
                  subsel == kAbsMtPositionX || subsel == kAbsMtPositionY ||
                  subsel == kAbsMtTrackingId)) ||
                (role_ == Role::KeyboardGamepad &&
                 (subsel <= kAbsRz || subsel == kAbsHat0X || subsel == kAbsHat0Y))) {
                // Unlock not needed since we copy display_* fields? Wait: mutex_ is held!
                LinuxAbsInfo info{};
                if (role_ == Role::MultiTouch) {
                    if (subsel == kAbsX || subsel == kAbsMtPositionX) {
                        info.maximum = static_cast<int32_t>(std::max<uint32_t>(1u, display_width_) - 1u);
                        info.resolution = 10;
                    } else if (subsel == kAbsY || subsel == kAbsMtPositionY) {
                        info.maximum = static_cast<int32_t>(std::max<uint32_t>(1u, display_height_) - 1u);
                        info.resolution = 10;
                    } else if (subsel == kAbsMtSlot) {
                        info.maximum = static_cast<int32_t>(kMaxMtSlots - 1u);
                    } else if (subsel == kAbsMtTrackingId) {
                        info.maximum = 65535;
                    } else if (subsel == kAbsMtTouchMajor || subsel == kAbsPressure) {
                        info.maximum = 255;
                    }
                } else {
                    if (subsel <= kAbsRz) {
                        info.minimum = -32768;
                        info.maximum = 32767;
                        info.flat = 128;
                    } else {
                        info.minimum = -1;
                        info.maximum = 1;
                    }
                }
                WriteAbsInfoBytes(payload, info);
            }
            break;
        }
        default:
            break;
    }
    if (payload.size() > 128u) {
        payload.resize(128u);
    }
    return payload;
}

uint32_t VirtioInputDevice::ReadConfig(uint64_t offset, unsigned size_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::array<uint8_t, 136> cfg{};
    cfg[0] = cfg_select_;
    cfg[1] = cfg_subsel_;
    std::vector<uint8_t> payload = BuildConfigPayloadLocked(cfg_select_, cfg_subsel_);
    cfg[2] = static_cast<uint8_t>(payload.size());
    if (!payload.empty()) {
        std::memcpy(cfg.data() + 8u, payload.data(), payload.size());
    }

    if (offset >= cfg.size()) return 0u;
    uint32_t out = 0u;
    const unsigned count = std::min<unsigned>(size_bytes, 4u);
    for (unsigned i = 0; i < count && (offset + i) < cfg.size(); ++i) {
        out |= (static_cast<uint32_t>(cfg[offset + i]) << (8u * i));
    }
    return out;
}

void VirtioInputDevice::WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    const unsigned count = std::min<unsigned>(size_bytes, 4u);
    for (unsigned i = 0; i < count; ++i) {
        const uint64_t addr = offset + i;
        const uint8_t b = static_cast<uint8_t>((value >> (8u * i)) & 0xFFu);
        if (addr == 0u) cfg_select_ = b;
        else if (addr == 1u) cfg_subsel_ = b;
    }
}

void VirtioInputDevice::OnReset() {
    std::lock_guard<std::mutex> lock(mutex_);
    cfg_select_ = 0u;
    cfg_subsel_ = 0u;
    mt_slots_ = {};
    next_tracking_id_ = 1;
    current_mt_slot_ = 0u;
    btn_touch_down_ = false;
    led_mask_ = 0u;
    virtq_events_.clear();
    evdev_events_.clear();
}

void VirtioInputDevice::EnqueueEventLocked(uint16_t type, uint16_t code, int32_t value) {
    if (virtq_events_.size() >= kMaxQueuedEvents) {
        virtq_events_.pop_front();
    }
    virtq_events_.push_back(VirtioInputEvent{type, code, value});

    if (evdev_events_.size() >= kMaxQueuedEvents) {
        evdev_events_.pop_front();
    }
    int64_t sec = 0, usec = 0;
    GetNowSecUsec(sec, usec);
    evdev_events_.push_back(LinuxInputEvent{sec, usec, type, code, value});
}

void VirtioInputDevice::EnqueueSynLocked() {
    EnqueueEventLocked(kEvSyn, kSynReport, 0);
}

uint32_t VirtioInputDevice::ActiveTouchCountLocked() const {
    uint32_t n = 0u;
    for (const auto& s : mt_slots_) {
        if (s.active) ++n;
    }
    return n;
}

int VirtioInputDevice::FindSlotForPointerLocked(int32_t pointer_id) const {
    for (size_t i = 0; i < mt_slots_.size(); ++i) {
        if (mt_slots_[i].active && mt_slots_[i].pointer_id == pointer_id) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int VirtioInputDevice::AllocSlotForPointerLocked(int32_t pointer_id) {
    const int existing = FindSlotForPointerLocked(pointer_id);
    if (existing >= 0) return existing;
    for (size_t i = 0; i < mt_slots_.size(); ++i) {
        if (!mt_slots_[i].active) {
            mt_slots_[i].active = true;
            mt_slots_[i].pointer_id = pointer_id;
            mt_slots_[i].tracking_id = next_tracking_id_++;
            if (next_tracking_id_ > 65000) next_tracking_id_ = 1;
            return static_cast<int>(i);
        }
    }
    return -1;
}

void VirtioInputDevice::PushTouch(int action, int32_t x, int32_t y, int32_t pointer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const int32_t max_x = static_cast<int32_t>(std::max<uint32_t>(1u, display_width_) - 1u);
    const int32_t max_y = static_cast<int32_t>(std::max<uint32_t>(1u, display_height_) - 1u);
    const int32_t cx = std::clamp(x, 0, max_x);
    const int32_t cy = std::clamp(y, 0, max_y);

    // MotionEvent: 0=ACTION_DOWN, 1=ACTION_UP, 2=ACTION_MOVE, 3=ACTION_CANCEL,
    //              5=ACTION_POINTER_DOWN, 6=ACTION_POINTER_UP
    if (action == 3 /* ACTION_CANCEL */) {
        bool emitted = false;
        for (size_t i = 0; i < mt_slots_.size(); ++i) {
            if (!mt_slots_[i].active) continue;
            if (current_mt_slot_ != i) {
                current_mt_slot_ = static_cast<uint32_t>(i);
                EnqueueEventLocked(kEvAbs, kAbsMtSlot, static_cast<int32_t>(i));
            }
            EnqueueEventLocked(kEvAbs, kAbsMtTrackingId, -1);
            mt_slots_[i] = MtSlot{};
            emitted = true;
        }
        if (btn_touch_down_) {
            btn_touch_down_ = false;
            EnqueueEventLocked(kEvKey, kBtnTouch, 0);
            emitted = true;
        }
        if (emitted) EnqueueSynLocked();
        return;
    }

    if (action == 0 /* ACTION_DOWN */ || action == 5 /* ACTION_POINTER_DOWN */) {
        const int slot = AllocSlotForPointerLocked(pointer_id);
        if (slot < 0) return;
        mt_slots_[slot].x = cx;
        mt_slots_[slot].y = cy;

        if (current_mt_slot_ != static_cast<uint32_t>(slot)) {
            current_mt_slot_ = static_cast<uint32_t>(slot);
            EnqueueEventLocked(kEvAbs, kAbsMtSlot, slot);
        }
        EnqueueEventLocked(kEvAbs, kAbsMtTrackingId, mt_slots_[slot].tracking_id);
        EnqueueEventLocked(kEvAbs, kAbsMtPositionX, cx);
        EnqueueEventLocked(kEvAbs, kAbsMtPositionY, cy);
        EnqueueEventLocked(kEvAbs, kAbsMtTouchMajor, 12);

        if (!btn_touch_down_) {
            btn_touch_down_ = true;
            EnqueueEventLocked(kEvKey, kBtnTouch, 1);
            EnqueueEventLocked(kEvAbs, kAbsX, cx);
            EnqueueEventLocked(kEvAbs, kAbsY, cy);
            EnqueueEventLocked(kEvAbs, kAbsPressure, 128);
        }
        EnqueueSynLocked();
        return;
    }

    if (action == 1 /* ACTION_UP */ || action == 6 /* ACTION_POINTER_UP */) {
        const int slot = FindSlotForPointerLocked(pointer_id);
        if (slot >= 0) {
            if (current_mt_slot_ != static_cast<uint32_t>(slot)) {
                current_mt_slot_ = static_cast<uint32_t>(slot);
                EnqueueEventLocked(kEvAbs, kAbsMtSlot, slot);
            }
            EnqueueEventLocked(kEvAbs, kAbsMtTrackingId, -1);
            mt_slots_[slot] = MtSlot{};
        }
        if (action == 1 || ActiveTouchCountLocked() == 0u) {
            if (btn_touch_down_) {
                btn_touch_down_ = false;
                EnqueueEventLocked(kEvKey, kBtnTouch, 0);
                EnqueueEventLocked(kEvAbs, kAbsPressure, 0);
            }
        }
        EnqueueSynLocked();
        return;
    }

    // ACTION_MOVE (2)
    int slot = FindSlotForPointerLocked(pointer_id);
    if (slot < 0) {
        slot = AllocSlotForPointerLocked(pointer_id);
        if (slot < 0) return;
        if (current_mt_slot_ != static_cast<uint32_t>(slot)) {
            current_mt_slot_ = static_cast<uint32_t>(slot);
            EnqueueEventLocked(kEvAbs, kAbsMtSlot, slot);
        }
        EnqueueEventLocked(kEvAbs, kAbsMtTrackingId, mt_slots_[slot].tracking_id);
    } else if (current_mt_slot_ != static_cast<uint32_t>(slot)) {
        current_mt_slot_ = static_cast<uint32_t>(slot);
        EnqueueEventLocked(kEvAbs, kAbsMtSlot, slot);
    }

    mt_slots_[slot].x = cx;
    mt_slots_[slot].y = cy;
    EnqueueEventLocked(kEvAbs, kAbsMtPositionX, cx);
    EnqueueEventLocked(kEvAbs, kAbsMtPositionY, cy);
    if (slot == 0) {
        EnqueueEventLocked(kEvAbs, kAbsX, cx);
        EnqueueEventLocked(kEvAbs, kAbsY, cy);
    }
    EnqueueSynLocked();
}

uint16_t VirtioInputDevice::TranslateAndroidKeyCode(int android_keycode) {
    // Pass through explicit Linux KEY_/BTN_ codes above 0x100 if directly supplied
    if (android_keycode >= 0x130) {
        return static_cast<uint16_t>(android_keycode);
    }
    switch (android_keycode) {
        // Navigation & System
        case 4:   return 158u; // KEYCODE_BACK -> KEY_BACK
        case 3:   return 172u; // KEYCODE_HOME -> KEY_HOMEPAGE
        case 82:  return 139u; // KEYCODE_MENU -> KEY_MENU
        case 24:  return 115u; // KEYCODE_VOLUME_UP -> KEY_VOLUMEUP
        case 25:  return 114u; // KEYCODE_VOLUME_DOWN -> KEY_VOLUMEDOWN
        case 26:  return 116u; // KEYCODE_POWER -> KEY_POWER
        case 111: return 1u;   // KEYCODE_ESCAPE -> KEY_ESC

        // D-Pad
        case 19:  return 103u; // KEYCODE_DPAD_UP -> KEY_UP
        case 20:  return 108u; // KEYCODE_DPAD_DOWN -> KEY_DOWN
        case 21:  return 105u; // KEYCODE_DPAD_LEFT -> KEY_LEFT
        case 22:  return 106u; // KEYCODE_DPAD_RIGHT -> KEY_RIGHT
        case 23:  return 28u;  // KEYCODE_DPAD_CENTER -> KEY_ENTER

        // Numbers 0..9 (KEYCODE_0=7 .. KEYCODE_9=16)
        case 7:   return 11u;  // KEY_0
        case 8:   return 2u;   // KEY_1
        case 9:   return 3u;   // KEY_2
        case 10:  return 4u;   // KEY_3
        case 11:  return 5u;   // KEY_4
        case 12:  return 6u;   // KEY_5
        case 13:  return 7u;   // KEY_6
        case 14:  return 8u;   // KEY_7
        case 15:  return 9u;   // KEY_8
        case 16:  return 10u;  // KEY_9

        // Letters A..Z (KEYCODE_A=29 .. KEYCODE_Z=54)
        case 29: return 30u; case 30: return 48u; case 31: return 46u; case 32: return 32u;
        case 33: return 18u; case 34: return 33u; case 35: return 34u; case 36: return 35u;
        case 37: return 23u; case 38: return 36u; case 39: return 37u; case 40: return 38u;
        case 41: return 50u; case 42: return 49u; case 43: return 24u; case 44: return 25u;
        case 45: return 16u; case 46: return 19u; case 47: return 31u; case 48: return 20u;
        case 49: return 22u; case 50: return 47u; case 51: return 17u; case 52: return 45u;
        case 53: return 21u; case 54: return 44u;

        // Editing & modifiers
        case 61:  return 15u;  // KEYCODE_TAB
        case 62:  return 57u;  // KEYCODE_SPACE
        case 66:  return 28u;  // KEYCODE_ENTER
        case 67:  return 14u;  // KEYCODE_DEL -> KEY_BACKSPACE
        case 59:  return 42u;  // KEYCODE_SHIFT_LEFT
        case 60:  return 54u;  // KEYCODE_SHIFT_RIGHT
        case 113: return 29u;  // KEYCODE_CTRL_LEFT
        case 57:  return 56u;  // KEYCODE_ALT_LEFT

        // Gamepad buttons (Android KeyEvent.KEYCODE_BUTTON_*)
        case 96:  return kBtnSouth;  // BUTTON_A
        case 97:  return kBtnEast;   // BUTTON_B
        case 99:  return kBtnNorth;  // BUTTON_X
        case 100: return kBtnWest;   // BUTTON_Y
        case 102: return kBtnTl;     // BUTTON_L1
        case 103: return kBtnTr;     // BUTTON_R1
        case 104: return kBtnTl2;    // BUTTON_L2
        case 105: return kBtnTr2;    // BUTTON_R2
        case 106: return kBtnThumbL; // BUTTON_THUMBL
        case 107: return kBtnThumbR; // BUTTON_THUMBR
        case 108: return kBtnStart;  // BUTTON_START
        case 109: return kBtnSelect; // BUTTON_SELECT
        case 110: return kBtnMode;   // BUTTON_MODE
        default:  return 0u;
    }
}

void VirtioInputDevice::PushLinuxKey(uint16_t linux_code, bool down) {
    if (linux_code == 0u) return;
    std::lock_guard<std::mutex> lock(mutex_);
    EnqueueEventLocked(kEvKey, linux_code, down ? 1 : 0);
    EnqueueSynLocked();
}

void VirtioInputDevice::PushAndroidKey(int android_keycode, bool down) {
    const uint16_t linux_code = TranslateAndroidKeyCode(android_keycode);
    if (linux_code == 0u) return;
    PushLinuxKey(linux_code, down);
}

void VirtioInputDevice::PushAbsAxis(uint16_t abs_code, int32_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    EnqueueEventLocked(kEvAbs, abs_code, value);
    EnqueueSynLocked();
}

bool VirtioInputDevice::HasPendingEvdev() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !evdev_events_.empty();
}

size_t VirtioInputDevice::PopEvdevEvents(LinuxInputEvent* out_events, size_t max_events) {
    if (!out_events || max_events == 0u) return 0u;
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t n = std::min(max_events, evdev_events_.size());
    for (size_t i = 0; i < n; ++i) {
        out_events[i] = evdev_events_.front();
        evdev_events_.pop_front();
    }
    return n;
}

uint32_t VirtioInputDevice::LedStateMask() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return led_mask_;
}

void VirtioInputDevice::FlushEvents(VirtioMmioDevice& transport) {
    VirtqChain chain;
    while (true) {
        VirtioInputEvent ev{};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (virtq_events_.empty()) break;
            if (!transport.PopAvailChain(0u, chain)) break;
            if (transport.TotalWriteBytes(chain) < sizeof(VirtioInputEvent)) {
                transport.PushUsed(0u, chain.head_idx, 0u);
                continue;
            }
            ev = virtq_events_.front();
            virtq_events_.pop_front();
        }
        uint8_t raw[8]{};
        raw[0] = static_cast<uint8_t>(ev.type & 0xFFu);
        raw[1] = static_cast<uint8_t>(ev.type >> 8);
        raw[2] = static_cast<uint8_t>(ev.code & 0xFFu);
        raw[3] = static_cast<uint8_t>(ev.code >> 8);
        const uint32_t uv = static_cast<uint32_t>(ev.value);
        raw[4] = static_cast<uint8_t>(uv & 0xFFu);
        raw[5] = static_cast<uint8_t>((uv >> 8) & 0xFFu);
        raw[6] = static_cast<uint8_t>((uv >> 16) & 0xFFu);
        raw[7] = static_cast<uint8_t>((uv >> 24) & 0xFFu);
        transport.CopyToChain(chain, 0u, raw, sizeof(raw));
        transport.PushUsed(0u, chain.head_idx, sizeof(raw));
    }
}

void VirtioInputDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    if (queue_idx == 0u) {
        // Guest posted receive buffers into eventq; immediately deliver any buffered events
        FlushEvents(transport);
        return;
    }
    if (queue_idx == 1u) {
        // statusq: consume LED/status writes from guest driver
        VirtqChain chain;
        while (transport.PopAvailChain(1u, chain)) {
            const size_t n = transport.TotalReadBytes(chain);
            if (n >= sizeof(VirtioInputEvent)) {
                std::vector<uint8_t> buf(n);
                if (transport.CopyFromChain(chain, 0u, buf.data(), n)) {
                    for (size_t off = 0; off + 8u <= buf.size(); off += 8u) {
                        const uint16_t type = static_cast<uint16_t>(buf[off]) |
                                              (static_cast<uint16_t>(buf[off + 1]) << 8);
                        const uint16_t code = static_cast<uint16_t>(buf[off + 2]) |
                                              (static_cast<uint16_t>(buf[off + 3]) << 8);
                        const int32_t val = static_cast<int32_t>(
                            static_cast<uint32_t>(buf[off + 4]) |
                            (static_cast<uint32_t>(buf[off + 5]) << 8) |
                            (static_cast<uint32_t>(buf[off + 6]) << 16) |
                            (static_cast<uint32_t>(buf[off + 7]) << 24));
                        if (type == kEvLed && code < 32u) {
                            std::lock_guard<std::mutex> lock(mutex_);
                            if (val != 0) led_mask_ |= (1u << code);
                            else led_mask_ &= ~(1u << code);
                        }
                    }
                }
            }
            transport.PushUsed(1u, chain.head_idx, 0u);
        }
    }
}

} // namespace haseeb::vm
