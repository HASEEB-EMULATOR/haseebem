#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <random>
#include <string>
#include <vector>

namespace haseeb::vm {

// Realistic Android sensor hub, battery/thermal power supply, V4L2 camera stub,
// and Magisk superuser verification state tracker for M7.
class PhoneHardwareHub {
public:
    static constexpr uint32_t kSensorAccelerometer = 1u;
    static constexpr uint32_t kSensorMagneticField = 2u;
    static constexpr uint32_t kSensorGyroscope     = 4u;
    static constexpr uint32_t kSensorLight         = 5u;
    static constexpr uint32_t kSensorPressure      = 6u;
    static constexpr uint32_t kSensorProximity     = 8u;

    static constexpr uint32_t kV4l2PixFmtNv21  = 0x3132564Eu; // 'N','V','2','1'
    static constexpr uint32_t kV4l2PixFmtRgba  = 0x34424752u; // 'R','G','B','4'

    struct SensorSample {
        uint32_t type = 0;
        uint32_t accuracy = 3; // SENSOR_STATUS_ACCURACY_HIGH
        uint64_t timestamp_ns = 0;
        float v[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    };

    struct BatteryState {
        int32_t capacity_pct = 88;
        int32_t temp_tenths_c = 342; // 34.2 C
        int32_t voltage_uv = 4180000;
        int32_t current_ua = -415000;
        uint32_t charging = 0u;
        char status[16] = "Discharging";
        char health[16] = "Good";
    };

    struct CameraFormat {
        uint32_t width = 640u;
        uint32_t height = 480u;
        uint32_t pixelformat = kV4l2PixFmtNv21;
        uint32_t bytesperline = 640u;
        uint32_t sizeimage = 640u * 480u * 3u / 2u;
    };

    struct TelemetrySnapshot {
        BatteryState battery{};
        float soc_temp_c = 36.2f;
        SensorSample accel{};
        SensorSample gyro{};
        SensorSample mag{};
        float light_lux = 350.0f;
        float proximity_cm = 5.0f;
        float pressure_hpa = 1013.25f;
        uint64_t camera_frames = 0;
        bool magisk_detected = false;
        bool magisk_prompt_enabled = true;
        uint32_t su_grants = 0;
        std::string magisk_version = "27.0";
        std::string last_su_caller;
    };

    PhoneHardwareHub();

    void Reset();
    void TickLoad(uint64_t instructions_delta);

    void SetSensorOverride(uint32_t sensor_type, float x, float y, float z, bool active = true);
    void ClearSensorOverrides();
    SensorSample SampleSensor(uint32_t sensor_type);
    std::vector<SensorSample> SampleAllSensors();

    void SetBatteryState(int32_t capacity_pct, bool charging, int32_t temp_tenths_c);
    BatteryState GetBatteryState() const;
    int32_t SocTempMillidegrees() const;

    void SetCameraFormat(uint32_t width, uint32_t height, uint32_t pixelformat);
    CameraFormat GetCameraFormat() const;
    void SetCameraStreaming(bool streaming);
    bool IsCameraStreaming() const;
    std::vector<uint8_t> GenerateCameraFrame(uint64_t& out_timestamp_ns, uint32_t& out_seq);

    void SetMagiskState(bool detected, bool prompt_enabled, const std::string& version = "27.0");
    bool RecordSuRequest(uint32_t uid, const std::string& caller, bool& out_granted);

    bool ReadVirtualSysfs(const std::string& norm_path, std::string& out_text);
    TelemetrySnapshot Snapshot();

private:
    struct OverrideVec {
        bool enabled = false;
        float x = 0.0f;
        float y = 0.0f;
        float z = 0.0f;
    };

    static uint64_t MonotonicNowNs();
    float GaussianNoise(float stddev);

    mutable std::mutex mutex_;
    std::mt19937_64 rng_;
    uint64_t boot_ns_ = 0;
    uint64_t total_insns_ = 0;

    OverrideVec accel_override_{};
    OverrideVec gyro_override_{};
    OverrideVec mag_override_{};
    OverrideVec light_override_{};
    OverrideVec prox_override_{};
    OverrideVec pressure_override_{};

    int32_t battery_pct_ = 88;
    bool charging_ = false;
    float thermal_c_ = 34.2f;
    uint64_t drain_accum_insns_ = 0;

    CameraFormat cam_fmt_{};
    bool cam_streaming_ = false;
    uint32_t cam_seq_ = 0;

    bool magisk_detected_ = false;
    bool magisk_prompt_enabled_ = true;
    std::string magisk_version_ = "27.0";
    uint32_t su_grants_ = 0;
    std::string last_su_caller_;
};

} // namespace haseeb::vm
