#include "haseeb/phone_hardware.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace haseeb::vm {

PhoneHardwareHub::PhoneHardwareHub() : rng_(0x4853425F534E5352ULL) {
    Reset();
}

uint64_t PhoneHardwareHub::MonotonicNowNs() {
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return static_cast<uint64_t>(std::max<int64_t>(0, ns));
}

void PhoneHardwareHub::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    boot_ns_ = MonotonicNowNs();
    total_insns_ = 0;
    accel_override_ = {};
    gyro_override_ = {};
    mag_override_ = {};
    light_override_ = {};
    prox_override_ = {};
    pressure_override_ = {};
    battery_pct_ = 88;
    charging_ = false;
    thermal_c_ = 34.2f;
    drain_accum_insns_ = 0;
    cam_fmt_ = CameraFormat{};
    cam_streaming_ = false;
    cam_seq_ = 0;
    su_grants_ = 0;
    last_su_caller_.clear();
}

float PhoneHardwareHub::GaussianNoise(float stddev) {
    std::normal_distribution<float> dist(0.0f, stddev);
    return dist(rng_);
}

void PhoneHardwareHub::TickLoad(uint64_t instructions_delta) {
    std::lock_guard<std::mutex> lock(mutex_);
    total_insns_ += instructions_delta;
    drain_accum_insns_ += instructions_delta;

    // Gentle realistic thermal rise with workload, cooling back toward 34.2 C
    const float target_c = charging_ ? 38.5f : 37.8f;
    const float heat_step = static_cast<float>(std::min<uint64_t>(instructions_delta, 1000000ULL)) * 2e-7f;
    thermal_c_ = std::clamp(thermal_c_ + heat_step - 0.002f * (thermal_c_ - 34.2f), 31.0f, 44.8f);
    if (thermal_c_ > target_c) {
        thermal_c_ -= 0.01f;
    }

    constexpr uint64_t kInsnsPerBatteryStep = 250000000ULL;
    if (drain_accum_insns_ >= kInsnsPerBatteryStep) {
        drain_accum_insns_ %= kInsnsPerBatteryStep;
        if (charging_ && battery_pct_ < 100) {
            ++battery_pct_;
        } else if (!charging_ && battery_pct_ > 5) {
            --battery_pct_;
        }
    }
}

void PhoneHardwareHub::SetSensorOverride(uint32_t sensor_type, float x, float y, float z, bool active) {
    std::lock_guard<std::mutex> lock(mutex_);
    OverrideVec ov{active, x, y, z};
    switch (sensor_type) {
        case kSensorAccelerometer: accel_override_ = ov; break;
        case kSensorGyroscope:     gyro_override_ = ov; break;
        case kSensorMagneticField: mag_override_ = ov; break;
        case kSensorLight:         light_override_ = ov; break;
        case kSensorProximity:     prox_override_ = ov; break;
        case kSensorPressure:      pressure_override_ = ov; break;
        default: break;
    }
}

void PhoneHardwareHub::ClearSensorOverrides() {
    std::lock_guard<std::mutex> lock(mutex_);
    accel_override_ = {};
    gyro_override_ = {};
    mag_override_ = {};
    light_override_ = {};
    prox_override_ = {};
    pressure_override_ = {};
}

PhoneHardwareHub::SensorSample PhoneHardwareHub::SampleSensor(uint32_t sensor_type) {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t now_ns = MonotonicNowNs();
    const double t_sec = static_cast<double>(now_ns - boot_ns_) * 1e-9;

    SensorSample s{};
    s.type = sensor_type;
    s.accuracy = 3u;
    s.timestamp_ns = now_ns;

    // Slow thermal/temporal drift proportional to uptime
    const float drift = static_cast<float>(std::sin(t_sec * 0.17) * 0.012 +
                                           (thermal_c_ - 34.2f) * 0.0018f);

    switch (sensor_type) {
        case kSensorAccelerometer: {
            const float bx = accel_override_.enabled ? accel_override_.x : 0.02f;
            const float by = accel_override_.enabled ? accel_override_.y : 9.80665f;
            const float bz = accel_override_.enabled ? accel_override_.z : 0.05f;
            const float micro_sway = static_cast<float>(std::sin(t_sec * 2.3) * 0.018);
            s.v[0] = bx + micro_sway + GaussianNoise(0.015f);
            s.v[1] = by + drift + GaussianNoise(0.015f);
            s.v[2] = bz - micro_sway * 0.5f + GaussianNoise(0.015f);
            break;
        }
        case kSensorGyroscope: {
            const float bx = gyro_override_.enabled ? gyro_override_.x : 0.0f;
            const float by = gyro_override_.enabled ? gyro_override_.y : 0.0f;
            const float bz = gyro_override_.enabled ? gyro_override_.z : 0.0f;
            const float bias = (thermal_c_ - 34.2f) * 0.0003f;
            s.v[0] = bx + bias + GaussianNoise(0.0025f);
            s.v[1] = by - bias * 0.5f + GaussianNoise(0.0025f);
            s.v[2] = bz + bias * 0.25f + GaussianNoise(0.0025f);
            break;
        }
        case kSensorMagneticField: {
            const float bx = mag_override_.enabled ? mag_override_.x : 21.4f;
            const float by = mag_override_.enabled ? mag_override_.y : -4.8f;
            const float bz = mag_override_.enabled ? mag_override_.z : -42.1f;
            s.v[0] = bx + drift * 5.0f + GaussianNoise(0.18f);
            s.v[1] = by - drift * 3.0f + GaussianNoise(0.18f);
            s.v[2] = bz + GaussianNoise(0.18f);
            break;
        }
        case kSensorLight: {
            const float base = light_override_.enabled ? light_override_.x : 350.0f;
            s.v[0] = std::max(0.0f, base + static_cast<float>(std::sin(t_sec * 0.35) * 4.5) +
                                        GaussianNoise(1.2f));
            break;
        }
        case kSensorPressure: {
            const float base = pressure_override_.enabled ? pressure_override_.x : 1013.25f;
            s.v[0] = base + drift * 2.0f + GaussianNoise(0.04f);
            break;
        }
        case kSensorProximity: {
            const float base = prox_override_.enabled ? prox_override_.x : 5.0f;
            s.v[0] = (base < 2.5f) ? 0.0f : 5.0f;
            break;
        }
        default:
            break;
    }
    return s;
}

std::vector<PhoneHardwareHub::SensorSample> PhoneHardwareHub::SampleAllSensors() {
    return {
        SampleSensor(kSensorAccelerometer),
        SampleSensor(kSensorGyroscope),
        SampleSensor(kSensorMagneticField),
        SampleSensor(kSensorLight),
        SampleSensor(kSensorPressure),
        SampleSensor(kSensorProximity),
    };
}

void PhoneHardwareHub::SetBatteryState(int32_t capacity_pct, bool charging, int32_t temp_tenths_c) {
    std::lock_guard<std::mutex> lock(mutex_);
    battery_pct_ = std::clamp(capacity_pct, 1, 100);
    charging_ = charging;
    thermal_c_ = std::clamp(static_cast<float>(temp_tenths_c) / 10.0f, 15.0f, 55.0f);
}

PhoneHardwareHub::BatteryState PhoneHardwareHub::GetBatteryState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    BatteryState b{};
    b.capacity_pct = battery_pct_;
    b.temp_tenths_c = static_cast<int32_t>(std::lround(thermal_c_ * 10.0f));
    b.voltage_uv = 3600000 + battery_pct_ * 6800; // ~3.6V..4.28V Li-Ion curve
    b.charging = charging_ ? 1u : 0u;
    b.current_ua = charging_ ? 1850000 : -415000;
    std::snprintf(b.status, sizeof(b.status), "%s",
                  charging_ ? (battery_pct_ >= 100 ? "Full" : "Charging") : "Discharging");
    std::snprintf(b.health, sizeof(b.health), "%s", thermal_c_ > 44.0f ? "Warm" : "Good");
    return b;
}

int32_t PhoneHardwareHub::SocTempMillidegrees() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int32_t>(std::lround((thermal_c_ + 2.0f) * 1000.0f));
}

void PhoneHardwareHub::SetCameraFormat(uint32_t width, uint32_t height, uint32_t pixelformat) {
    std::lock_guard<std::mutex> lock(mutex_);
    cam_fmt_.width = std::clamp(width, 64u, 1920u);
    cam_fmt_.height = std::clamp(height, 64u, 1080u);
    cam_fmt_.pixelformat = (pixelformat == kV4l2PixFmtRgba) ? kV4l2PixFmtRgba : kV4l2PixFmtNv21;
    if (cam_fmt_.pixelformat == kV4l2PixFmtRgba) {
        cam_fmt_.bytesperline = cam_fmt_.width * 4u;
        cam_fmt_.sizeimage = cam_fmt_.bytesperline * cam_fmt_.height;
    } else {
        cam_fmt_.bytesperline = cam_fmt_.width;
        cam_fmt_.sizeimage = cam_fmt_.width * cam_fmt_.height * 3u / 2u;
    }
}

PhoneHardwareHub::CameraFormat PhoneHardwareHub::GetCameraFormat() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cam_fmt_;
}

void PhoneHardwareHub::SetCameraStreaming(bool streaming) {
    std::lock_guard<std::mutex> lock(mutex_);
    cam_streaming_ = streaming;
}

bool PhoneHardwareHub::IsCameraStreaming() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cam_streaming_;
}

std::vector<uint8_t> PhoneHardwareHub::GenerateCameraFrame(uint64_t& out_timestamp_ns, uint32_t& out_seq) {
    std::lock_guard<std::mutex> lock(mutex_);
    out_timestamp_ns = MonotonicNowNs();
    out_seq = ++cam_seq_;

    const uint32_t w = cam_fmt_.width;
    const uint32_t h = cam_fmt_.height;
    std::vector<uint8_t> frame(cam_fmt_.sizeimage, 0u);
    const uint8_t phase = static_cast<uint8_t>((out_seq * 9u) & 0xFFu);

    if (cam_fmt_.pixelformat == kV4l2PixFmtRgba) {
        for (uint32_t y = 0; y < h; ++y) {
            for (uint32_t x = 0; x < w; ++x) {
                const size_t idx = (static_cast<size_t>(y) * w + x) * 4u;
                frame[idx + 0] = static_cast<uint8_t>((x * 255u / w + phase) & 0xFFu);
                frame[idx + 1] = static_cast<uint8_t>((y * 255u / h) & 0xFFu);
                frame[idx + 2] = static_cast<uint8_t>(200u - (phase >> 1));
                frame[idx + 3] = 0xFFu;
            }
        }
    } else {
        // NV21: Y plane (w * h) followed by interleaved VU plane (w * h / 2)
        const size_t y_bytes = static_cast<size_t>(w) * h;
        for (uint32_t y = 0; y < h; ++y) {
            const uint8_t luma = static_cast<uint8_t>(40u + ((y * 180u) / h + (phase >> 2)) % 200u);
            std::memset(frame.data() + static_cast<size_t>(y) * w, luma, w);
        }
        for (size_t i = y_bytes; i + 1u < frame.size(); i += 2u) {
            frame[i + 0] = static_cast<uint8_t>(128u + ((phase >> 3) & 0x1Fu)); // V
            frame[i + 1] = static_cast<uint8_t>(112u);                           // U
        }
    }
    return frame;
}

void PhoneHardwareHub::SetMagiskState(bool detected, bool prompt_enabled, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    magisk_detected_ = detected;
    magisk_prompt_enabled_ = prompt_enabled;
    if (!version.empty()) magisk_version_ = version;
}

bool PhoneHardwareHub::RecordSuRequest(uint32_t /*uid*/, const std::string& caller, bool& out_granted) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!magisk_detected_ && !magisk_prompt_enabled_) {
        out_granted = false;
        return false;
    }
    out_granted = true;
    ++su_grants_;
    last_su_caller_ = caller.empty() ? "shell" : caller;
    return true;
}

bool PhoneHardwareHub::ReadVirtualSysfs(const std::string& norm_path, std::string& out_text) {
    out_text.clear();
    if (norm_path == "/sys/class/power_supply/battery/capacity") {
        out_text = std::to_string(GetBatteryState().capacity_pct) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/status") {
        out_text = std::string(GetBatteryState().status) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/health") {
        out_text = std::string(GetBatteryState().health) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/temp") {
        out_text = std::to_string(GetBatteryState().temp_tenths_c) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/voltage_now") {
        out_text = std::to_string(GetBatteryState().voltage_uv) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/current_now") {
        out_text = std::to_string(GetBatteryState().current_ua) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/battery/present") {
        out_text = "1\n";
        return true;
    }
    if (norm_path == "/sys/class/power_supply/usb/online") {
        out_text = std::to_string(GetBatteryState().charging) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/thermal/thermal_zone0/temp") {
        out_text = std::to_string(SocTempMillidegrees()) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/thermal/thermal_zone0/type") {
        out_text = "soc-thermal\n";
        return true;
    }
    if (norm_path == "/sys/class/sensors/accel/value") {
        const auto s = SampleSensor(kSensorAccelerometer);
        std::ostringstream oss;
        oss << s.v[0] << " " << s.v[1] << " " << s.v[2] << "\n";
        out_text = oss.str();
        return true;
    }
    if (norm_path == "/sys/class/sensors/gyro/value") {
        const auto s = SampleSensor(kSensorGyroscope);
        std::ostringstream oss;
        oss << s.v[0] << " " << s.v[1] << " " << s.v[2] << "\n";
        out_text = oss.str();
        return true;
    }
    if (norm_path == "/sys/class/sensors/mag/value") {
        const auto s = SampleSensor(kSensorMagneticField);
        std::ostringstream oss;
        oss << s.v[0] << " " << s.v[1] << " " << s.v[2] << "\n";
        out_text = oss.str();
        return true;
    }
    if (norm_path == "/sys/class/sensors/light/value") {
        out_text = std::to_string(SampleSensor(kSensorLight).v[0]) + "\n";
        return true;
    }
    if (norm_path == "/sys/class/sensors/proximity/value") {
        out_text = std::to_string(SampleSensor(kSensorProximity).v[0]) + "\n";
        return true;
    }
    return false;
}

PhoneHardwareHub::TelemetrySnapshot PhoneHardwareHub::Snapshot() {
    TelemetrySnapshot snap{};
    snap.battery = GetBatteryState();
    snap.soc_temp_c = static_cast<float>(SocTempMillidegrees()) / 1000.0f;
    snap.accel = SampleSensor(kSensorAccelerometer);
    snap.gyro = SampleSensor(kSensorGyroscope);
    snap.mag = SampleSensor(kSensorMagneticField);
    snap.light_lux = SampleSensor(kSensorLight).v[0];
    snap.proximity_cm = SampleSensor(kSensorProximity).v[0];
    snap.pressure_hpa = SampleSensor(kSensorPressure).v[0];
    std::lock_guard<std::mutex> lock(mutex_);
    snap.camera_frames = cam_seq_;
    snap.magisk_detected = magisk_detected_;
    snap.magisk_prompt_enabled = magisk_prompt_enabled_;
    snap.su_grants = su_grants_;
    snap.magisk_version = magisk_version_;
    snap.last_su_caller = last_su_caller_;
    return snap;
}

} // namespace haseeb::vm
