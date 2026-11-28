#include "haseeb/engine_runtime.hpp"
#include "haseeb/compression.hpp"

#include <algorithm>
#include <android/log.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "HaseebVM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
std::string EscapeJson(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) >= 0x20u) out.push_back(c);
                break;
        }
    }
    return out;
}
} // namespace

namespace haseeb::engine {

EngineRuntime& EngineRuntime::Instance() {
    static EngineRuntime instance;
    return instance;
}

EngineRuntime::EngineRuntime()
    : machine_([this](const std::string& line) {
          AppendLog("UART", line);
      }) {
    machine_.VirtioGpu().SetScanoutCallback(
        [this](const uint32_t* px, uint32_t w, uint32_t h, uint64_t /*frame_idx*/) {
            PresentRgbaFrame(px, w, h);
        });
}

EngineRuntime::~EngineRuntime() {
    Stop();
}

vm::VmError EngineRuntime::SetPath(const std::string& dir) {
    if (dir.empty()) return vm::VmError::InvalidArgument;
    std::lock_guard<std::mutex> lock(mutex_);
    work_dir_ = dir;
    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        boot_trace_path_ = work_dir_ + "/boot_trace.log";
    }
    machine_.SetRuntimePaths(work_dir_, work_dir_ + "/storage/emulated/0");
    AppendLog("INFO", "Engine root path configured: " + dir);
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::SetNativeLibDir(const std::string& lib_dir) {
    if (lib_dir.empty()) return vm::VmError::InvalidArgument;
    std::lock_guard<std::mutex> lock(mutex_);
    native_lib_dir_ = lib_dir;
    AppendLog("INFO", "Native library directory set: " + lib_dir);
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::LoadBootImage(const std::string& path) {
    if (path.empty()) return vm::VmError::InvalidArgument;
    SetCheckpoint("BOOT_IMG_PARSE", "Parsing Android boot image header & ramdisk");
    std::lock_guard<std::mutex> lock(mutex_);
    vm::ParsedBootImage parsed;
    std::string err;
    vm::VmError res = vm::BootImageParser::ParseBootFile(path, parsed, err);
    if (res != vm::VmError::Ok) {
        AppendLog("ERROR", "loadBootImage(" + path + ") failed: " + err);
        SetCheckpoint("BOOT_IMG_ERROR", err);
        return res;
    }

    boot_image_ = std::move(parsed);
    boot_image_path_ = path;
    has_boot_image_ = true;

    std::ostringstream oss;
    oss << "Loaded boot.img v" << boot_image_.header_version
        << " (kernel=" << boot_image_.kernel.size()
        << "B, arm64_magic=" << (boot_image_.kernel_info.valid_arm64_magic ? "yes" : "compressed/no")
        << ", ramdisk=" << boot_image_.ramdisk.size()
        << "B, magisk=" << (boot_image_.magisk_detected ? "detected" : "not-detected") << ")";
    AppendLog("INFO", oss.str());
    SetCheckpoint("BOOT_IMG_OK", oss.str());
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::LoadSystemImage(const std::string& path) {
    if (path.empty()) return vm::VmError::InvalidArgument;
    SetCheckpoint("SYS_IMG_PROBE", "Probing system partition container & ext4 superblock");
    std::lock_guard<std::mutex> lock(mutex_);
    if (::access(path.c_str(), R_OK) != 0) {
        AppendLog("ERROR", "loadSystemImage(" + path + ") failed: file unreadable");
        SetCheckpoint("SYS_IMG_ERROR", "System image file unreadable");
        return vm::VmError::FileNotFound;
    }

    std::string effective_path = path;
    {
        std::ifstream probe(path, std::ios::binary | std::ios::ate);
        if (probe.good()) {
            const std::streamsize fsz = probe.tellg();
            probe.seekg(0, std::ios::beg);
            uint8_t head[4]{};
            if (fsz >= 16 && probe.read(reinterpret_cast<char*>(head), 4)) {
                auto fmt = vm::CompressionCodec::DetectFormat(head, 4);
                if (fmt == vm::ArchiveFormat::Gzip ||
                    fmt == vm::ArchiveFormat::Lz4Frame ||
                    fmt == vm::ArchiveFormat::Lz4Legacy) {
                    // Guard against excessive heap spikes on mobile devices
                    if (fsz <= 128LL * 1024LL * 1024LL) {
                        SetCheckpoint("SYS_IMG_UNPACK", "Decompressing compressed system image");
                        std::vector<uint8_t> comp(static_cast<size_t>(fsz));
                        probe.seekg(0, std::ios::beg);
                        if (probe.read(reinterpret_cast<char*>(comp.data()), fsz)) {
                            std::vector<uint8_t> raw;
                            std::string derr;
                            if (vm::CompressionCodec::DecompressAuto(
                                    comp, raw, fmt, derr, 256u * 1024u * 1024u) &&
                                !raw.empty()) {
                                const std::string out_raw = work_dir_.empty()
                                    ? (path + ".raw")
                                    : (work_dir_ + "/system_unpacked.img");
                                std::ofstream ofs(out_raw, std::ios::binary | std::ios::trunc);
                                if (ofs.good() &&
                                    ofs.write(reinterpret_cast<const char*>(raw.data()),
                                              static_cast<std::streamsize>(raw.size()))) {
                                    effective_path = out_raw;
                                    AppendLog("INFO", "Decompressed compressed system.img -> " + out_raw);
                                }
                            } else {
                                AppendLog("ERROR", "loadSystemImage decompression failed: " + derr);
                            }
                        }
                    } else {
                        AppendLog("WARN", "Compressed system.img exceeds 128 MiB inline unpack budget; probing directly");
                    }
                }
            }
        }
    }

    system_ext4_.Close();
    if (!system_ext4_.Open(effective_path)) {
        AppendLog("ERROR", "loadSystemImage invalid image: " + system_ext4_.LastError());
        SetCheckpoint("SYS_IMG_ERROR", system_ext4_.LastError());
        return vm::VmError::InvalidSystemImage;
    }

    system_image_path_ = effective_path;
    has_system_image_ = true;

    std::string marker;
    const bool has_marker = system_ext4_.ReadFileString("/system/etc/haseeb_rom", marker) ||
                            system_ext4_.ReadFileString("/etc/haseeb_rom", marker);
    const std::string info_msg =
        "Loaded system.img (" + std::to_string(system_ext4_.ImageSizeBytes() / (1024 * 1024)) +
        " MiB, blk=" + std::to_string(system_ext4_.BlockSize()) +
        (system_ext4_.IsSparse() ? ", sparse" : "") +
        (system_ext4_.HasPartitionOffset() ? ", partitioned" : "") +
        (has_marker ? ", marker=" + marker : "") + ")";
    AppendLog("INFO", info_msg);
    SetCheckpoint("SYS_IMG_OK", info_msg);
    return vm::VmError::Ok;
}

void EngineRuntime::ConfigureGuestProps(const GuestConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    target_fps_.store(config.target_fps);
    machine_.SetDeviceProperties({
        {"ro.product.model", config.model},
        {"ro.product.brand", config.brand},
        {"ro.product.manufacturer", config.manufacturer},
        {"ro.product.device", config.device},
        {"ro.product.name", config.name},
        {"ro.product.marketname", config.marketname},
        {"ro.build.fingerprint", config.fingerprint},
        {"qemu.hw.mainkeys", config.nav_bar_off ? "1" : "0"},
    });
    machine_.Hardware().SetMagiskState(
        has_boot_image_ && boot_image_.magisk_detected,
        config.magisk_prompt_enabled);
    AppendLog("INFO", "Configured device profile: " + config.marketname + " (" + config.model + ")");
}

vm::MagiskPatchResult EngineRuntime::PatchBootImage(const std::string& input_path,
                                                    const std::string& output_path) {
    vm::MagiskPatchOptions opts;
    vm::MagiskPatchResult res = vm::BootImagePatcher::PatchBootFile(input_path, output_path, opts);
    if (res.ok) {
        std::lock_guard<std::mutex> lock(mutex_);
        machine_.Hardware().SetMagiskState(true, config_.magisk_prompt_enabled);
        AppendLog("INFO", "Magisk patched boot.img -> " + output_path + " (" + res.verification_summary + ")");
    } else {
        AppendLog("ERROR", "Magisk boot patch failed: " + res.error);
    }
    return res;
}

vm::EngineRomBuildResult EngineRuntime::BuildEngineMagiskRom(const std::string& output_dir) {
    SetCheckpoint("ROM_BUILD", "Generating AArch64 Android 11 Magisk v27.0 ROM images");
    vm::EngineRomBuildResult res = vm::EngineRomBuilder::BuildMagiskAndroidRom(output_dir);
    if (res.ok) {
        const std::string msg =
            "Built Engine Magisk ROM -> boot.img (" + std::to_string(res.boot_img_size / 1024) +
            " KiB, " + std::to_string(res.ramdisk_entries) + " ramdisk entries), system.img (" +
            std::to_string(res.system_img_size / (1024 * 1024)) + " MiB ext4, " +
            std::to_string(res.system_files) + " files)";
        AppendLog("INFO", msg);
        SetCheckpoint("ROM_READY", msg);
    } else {
        AppendLog("ERROR", "Engine Magisk ROM build failed: " + res.error);
        SetCheckpoint("ROM_ERROR", res.error);
    }
    return res;
}

std::string EngineRuntime::GetPhoneTelemetryJson() {
    auto snap = machine_.Hardware().Snapshot();
    const char* gl_renderer = machine_.SoftGles().GlGetString(vm::SoftGlesContext::kGlRenderer);
    const std::string storage_root = machine_.SharedStorageRoot().empty() && !work_dir_.empty()
                                         ? (work_dir_ + "/storage/emulated/0")
                                         : machine_.SharedStorageRoot();
    std::string active_bin;
    std::string boot_stage;
    std::string last_trap;
    std::vector<std::string> svc_list;
    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        active_bin = active_binary_snapshot_.empty() ? "idle" : active_binary_snapshot_;
        boot_stage = boot_stage_;
        last_trap = last_trap_summary_;
        svc_list = framework_services_snapshot_;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << "{"
        << "\"running\":" << (running_.load() ? "true" : "false") << ","
        << "\"bootStage\":\"" << EscapeJson(boot_stage) << "\","
        << "\"effectiveRamMb\":" << effective_ram_mb_.load() << ","
        << "\"exitCode\":" << last_exit_code_.load() << ","
        << "\"activeTasks\":" << active_tasks_snapshot_.load() << ","
        << "\"instructionsExecuted\":" << instructions_executed_.load() << ","
        << "\"lastTrap\":\"" << EscapeJson(last_trap) << "\","
        << "\"model\":\"" << EscapeJson(config_.model) << "\","
        << "\"marketname\":\"" << EscapeJson(config_.marketname) << "\","
        << "\"glRenderer\":\"" << EscapeJson(gl_renderer ? gl_renderer : "") << "\","
        << "\"guestFps\":" << measured_fps_.load() << ","
        << "\"drawCalls\":" << machine_.SoftGles().DrawCalls() << ","
        << "\"triangles\":" << machine_.SoftGles().TrianglesRasterized() << ","
        << "\"framesSwapped\":" << machine_.SoftGles().FramesSwapped() << ","
        << "\"magiskDetected\":" << (snap.magisk_detected ? "true" : "false") << ","
        << "\"magiskVersion\":\"" << EscapeJson(snap.magisk_version) << "\","
        << "\"suGrants\":" << snap.su_grants << ","
        << "\"lastSuCaller\":\"" << EscapeJson(snap.last_su_caller) << "\","
        << "\"batteryPct\":" << snap.battery.capacity_pct << ","
        << "\"charging\":" << (snap.battery.charging != 0u ? "true" : "false") << ","
        << "\"batteryTempC\":" << (snap.battery.temp_tenths_c / 10.0f) << ","
        << "\"socTempC\":" << snap.soc_temp_c << ","
        << "\"accel\":[" << snap.accel.v[0] << "," << snap.accel.v[1] << "," << snap.accel.v[2] << "],"
        << "\"gyro\":[" << snap.gyro.v[0] << "," << snap.gyro.v[1] << "," << snap.gyro.v[2] << "],"
        << "\"mag\":[" << snap.mag.v[0] << "," << snap.mag.v[1] << "," << snap.mag.v[2] << "],"
        << "\"lightLux\":" << snap.light_lux << ","
        << "\"proximityCm\":" << snap.proximity_cm << ","
        << "\"pressureHpa\":" << snap.pressure_hpa << ","
        << "\"cameraFrames\":" << snap.camera_frames << ","
        << "\"audioPlayFrames\":" << machine_.VirtioSnd().PlaybackFramesWritten() << ","
        << "\"netTxPackets\":" << machine_.NatRouter().TxPackets() << ","
        << "\"netRxPackets\":" << machine_.NatRouter().RxPackets() << ","
        << "\"dnsQueries\":" << machine_.NatRouter().DnsQueries() << ","
        << "\"sharedStorageRoot\":\"" << EscapeJson(storage_root) << "\","
        << "\"activeBinary\":\"" << EscapeJson(active_bin) << "\","
        << "\"frameworkServices\":[";
    for (size_t i = 0; i < svc_list.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJson(svc_list[i]) << "\"";
    }
    oss << "]}";
    return oss.str();
}

std::string EngineRuntime::GetBootStatusJson() {
    std::string stage;
    std::string detail;
    std::string trap;
    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        stage = boot_stage_;
        detail = boot_detail_;
        trap = last_trap_summary_;
    }
    std::ostringstream oss;
    oss << "{"
        << "\"stage\":\"" << EscapeJson(stage) << "\","
        << "\"detail\":\"" << EscapeJson(detail) << "\","
        << "\"effectiveRamMb\":" << effective_ram_mb_.load() << ","
        << "\"exitCode\":" << last_exit_code_.load() << ","
        << "\"activeTasks\":" << active_tasks_snapshot_.load() << ","
        << "\"instructionsExecuted\":" << instructions_executed_.load() << ","
        << "\"lastTrap\":\"" << EscapeJson(trap) << "\","
        << "\"running\":" << (running_.load() ? "true" : "false")
        << "}";
    return oss.str();
}

std::string EngineRuntime::ReadBootTrace(int max_bytes) {
    if (max_bytes <= 0) return "";
    std::string path;
    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        path = boot_trace_path_;
    }
    if (!path.empty()) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (ifs.good()) {
            const std::streamsize sz = ifs.tellg();
            if (sz > 0) {
                const std::streamsize take = std::min<std::streamsize>(sz, max_bytes);
                ifs.seekg(sz - take, std::ios::beg);
                std::string buf(static_cast<size_t>(take), '\0');
                if (ifs.read(buf.data(), take)) {
                    return buf;
                }
            }
        }
    }
    return ReadLog(max_bytes);
}

vm::VmError EngineRuntime::SetSensorOverride(
    uint32_t sensor_type, float x, float y, float z, bool active) {
    machine_.Hardware().SetSensorOverride(sensor_type, x, y, z, active);
    return vm::VmError::Ok;
}

size_t EngineRuntime::DrainAudioPcm(int16_t* dst, size_t max_samples) {
    if (!dst || max_samples == 0u) return 0u;
    return machine_.VirtioSnd().PopPlaybackPcm(dst, max_samples);
}

vm::VmError EngineRuntime::Start(int api, int width, int height, int dpi, int ram_mb) {
    SetCheckpoint("VM_STAGING", "Preparing VM board & memory allocation");
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_.load()) {
        AppendLog("WARN", "Start ignored: VM already running");
        return vm::VmError::AlreadyRunning;
    }
    if (work_dir_.empty()) {
        AppendLog("ERROR", "Cannot start VM: setPath(dir) was not called");
        SetCheckpoint("STAGING_ERROR", "Engine work directory not set");
        return vm::VmError::PathNotSet;
    }
    if (width <= 0 || height <= 0 || dpi <= 0 || ram_mb < 64 || ram_mb > 4096) {
        AppendLog("ERROR", "Invalid VM geometry or RAM argument");
        SetCheckpoint("STAGING_ERROR", "Invalid VM geometry or RAM argument");
        return vm::VmError::InvalidArgument;
    }

    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        last_trap_summary_.clear();
        active_binary_snapshot_ = "staging";
        framework_services_snapshot_.clear();
    }
    last_exit_code_.store(0);
    active_tasks_snapshot_.store(0);
    instructions_executed_.store(0ULL);
    effective_ram_mb_.store(0);

    config_.api_level = api;
    config_.width = width;
    config_.height = height;
    config_.dpi = dpi;

    // Build RAM candidate list with automatic step-down fallback on low-RAM phones
    std::vector<int> ram_candidates;
    ram_candidates.push_back(ram_mb);
    for (int fallback : {1024, 768, 512, 256}) {
        if (fallback < ram_mb) {
            ram_candidates.push_back(fallback);
        }
    }

    std::string err;
    machine_.SetRuntimePaths(work_dir_, work_dir_ + "/storage/emulated/0");
    machine_.SetDeviceProperties({
        {"ro.product.model", config_.model},
        {"ro.product.brand", config_.brand},
        {"ro.product.manufacturer", config_.manufacturer},
        {"ro.product.device", config_.device},
        {"ro.product.name", config_.name},
        {"ro.product.marketname", config_.marketname},
        {"ro.build.fingerprint", config_.fingerprint},
        {"qemu.hw.mainkeys", config_.nav_bar_off ? "1" : "0"},
    });
    machine_.SetExt4Reader(has_system_image_ ? &system_ext4_ : nullptr);
    const vm::ParsedBootImage* boot_ptr = has_boot_image_ ? &boot_image_ : nullptr;

    vm::VmError stage_err = vm::VmError::OutOfMemory;
    int staged_ram_mb = ram_mb;
    for (size_t idx = 0; idx < ram_candidates.size(); ++idx) {
        const int cand = ram_candidates[idx];
        SetCheckpoint("RAM_ALLOC", "Staging " + std::to_string(cand) + " MiB guest memfd");
        vm::MachineBootConfig mcfg;
        mcfg.ram_mb = static_cast<uint32_t>(cand);
        mcfg.vcpu_count = static_cast<uint32_t>(config_.vcpu_count);
        mcfg.api_level = static_cast<uint32_t>(api);
        mcfg.width = static_cast<uint32_t>(width);
        mcfg.height = static_cast<uint32_t>(height);
        mcfg.dpi = static_cast<uint32_t>(dpi);
        mcfg.extra_cmdline = "androidboot.selinux=permissive haseeb.api=" + std::to_string(api);

        err.clear();
        stage_err = machine_.InitializeAndStage(mcfg, boot_ptr, err);
        if (stage_err == vm::VmError::Ok) {
            staged_ram_mb = cand;
            if (idx > 0) {
                AppendLog("WARN", "RAM auto step-down applied: requested " +
                          std::to_string(ram_mb) + " MiB -> allocated " +
                          std::to_string(cand) + " MiB");
            }
            break;
        }
        if (stage_err != vm::VmError::OutOfMemory) {
            break;
        }
        AppendLog("WARN", "RAM allocation " + std::to_string(cand) +
                  " MiB failed (OOM); stepping down");
    }

    if (stage_err != vm::VmError::Ok) {
        AppendLog("ERROR", "VM staging failed: " + err);
        SetCheckpoint("STAGING_ERROR", err.empty() ? vm::VmErrorToString(stage_err) : err);
        return stage_err;
    }

    config_.ram_mb = staged_ram_mb;
    effective_ram_mb_.store(staged_ram_mb);

    if (has_system_image_ && !system_ext4_.IsSparse() && !system_ext4_.HasPartitionOffset()) {
        machine_.VirtioBlk().AttachFile(system_image_path_, true);
    }
    machine_.Hardware().SetMagiskState(
        has_boot_image_ && boot_image_.magisk_detected,
        config_.magisk_prompt_enabled);

    if (guest_thread_.joinable()) {
        guest_thread_.join();
    }

    running_.store(true);
    measured_fps_.store(0.0f);
    last_scanout_ns_.store(0);
    fps_window_start_ns_.store(0);
    fps_window_frames_.store(0);

    AppendLog("INFO", "Full-System VM staged (RAM=" + std::to_string(staged_ram_mb) +
              " MiB via memfd, FDT @0x" + std::to_string(machine_.DtbGuestAddr()) + ")");

    SetCheckpoint("BOOT_STUB", "Executing AArch64 bootloader stub");
    vm::VmError boot_res = machine_.RunBootStubUntilHalt();
    if (boot_res != vm::VmError::Ok) {
        const std::string msg = "Bootloader stub trap: " + std::string(vm::VmErrorToString(boot_res));
        AppendLog("ERROR", msg);
        SetCheckpoint("STUB_TRAP", msg);
        machine_.Shutdown();
        running_.store(false);
        return boot_res;
    }

    PresentBootFrame();

    // M-A Stage 4 diagnostic: run AArch64 powerof2(8, 64, 1, 7) self-test stub & capture RAM bytes
    {
        std::string self_test_bits;
        vm::VmError st_res = machine_.RunPowerOf2SelfTest(self_test_bits);
        const std::string st_line = "[SELF-TEST] powerof2(8,64,1,7)=" + self_test_bits +
                                    " (rc=" + std::to_string(static_cast<int>(st_res)) + ")";
        AppendLog("INFO", st_line);
        if (!work_dir_.empty()) {
            std::ofstream st_file(work_dir_ + "/powerof2_selftest.txt", std::ios::trunc);
            if (st_file.good()) {
                st_file << st_line << "\n";
                st_file.flush();
            }
        }
    }

    // Launch M4 guest kernel / EL0 init+sh execution loop when a runnable target exists
    if (has_boot_image_ || has_system_image_) {
        SetCheckpoint("GUEST_HANDOFF", "Handing off to guest kernel / init binary");
        std::string target;
        std::string launch_err;
        vm::VmError launch_res = machine_.BootGuest(
            config_.magisk_prompt_enabled, target, launch_err);
        if (launch_res == vm::VmError::Ok) {
            {
                std::lock_guard<std::mutex> tlock(trace_mutex_);
                active_binary_snapshot_ = target;
            }
            AppendLog("INFO", "Booting guest target [" + target + "] on AArch64 DBT/MMU core");
            SetCheckpoint("RUNNING", "Executing [" + target + "] (" + std::to_string(staged_ram_mb) + " MiB)");
            guest_thread_ = std::thread(&EngineRuntime::RunGuestLoop, this);
        } else {
            {
                std::lock_guard<std::mutex> tlock(trace_mutex_);
                active_binary_snapshot_ = "standby";
            }
            AppendLog("INFO", "Guest ELF/kernel handoff skipped (" + launch_err + "); staying ready");
            SetCheckpoint("STANDBY", "Guest handoff skipped: " + launch_err);
        }
    } else {
        SetCheckpoint("STANDBY", "No boot/system image attached; bootloader ready");
    }
    return vm::VmError::Ok;
}

void EngineRuntime::RunGuestLoop() {
    uint64_t next_milestone = 100000ULL;
    while (running_.load()) {
        vm::VmError step_res = machine_.StepGuest(100000ULL);
        const auto& st = machine_.CpuState();
        instructions_executed_.store(st.instructions_executed);

        if (auto* sup = machine_.Supervisor()) {
            active_tasks_snapshot_.store(static_cast<int>(sup->ActiveTaskCount()));
            std::lock_guard<std::mutex> tlock(trace_mutex_);
            if (!sup->ActiveBinary().empty()) {
                active_binary_snapshot_ = sup->ActiveBinary();
            }
            framework_services_snapshot_ = sup->BinderServices();
        }

        if (st.instructions_executed >= next_milestone) {
            SetCheckpoint("RUNNING",
                          "Guest alive (" + std::to_string(st.instructions_executed) + " insns)");
            if (next_milestone < 1000000ULL) {
                next_milestone *= 10ULL;
            } else {
                next_milestone = UINT64_MAX;
            }
        }

        if (step_res != vm::VmError::Ok) {
            const std::string sup_trap = machine_.Supervisor() ? machine_.Supervisor()->LastTrapDetail() : "";
            std::string trap_str = sup_trap;
            if (trap_str.empty()) {
                std::ostringstream trap;
                trap << vm::VmErrorToString(step_res)
                     << " @ PC=0x" << std::hex << st.pc
                     << " EL" << std::dec << static_cast<int>(st.pstate.el)
                     << " ESR=0x" << std::hex << st.sys.esr_el1
                     << " FAR=0x" << st.sys.far_el1
                     << " LR=0x" << st.x[30]
                     << " SP=0x" << st.CurrentSp()
                     << " insns=" << std::dec << st.instructions_executed;
                trap_str = trap.str();
            }
            last_exit_code_.store(-1);
            {
                std::lock_guard<std::mutex> tlock(trace_mutex_);
                last_trap_summary_ = trap_str;
            }
            AppendLog("ERROR", "Guest CPU trap: " + trap_str);
            SetCheckpoint("TRAPPED", trap_str);
            running_.store(false);
            break;
        }
        if (st.halted || machine_.ResetRequested()) {
            const int exit_code = machine_.Supervisor() ? machine_.Supervisor()->ExitStatus() : 0;
            const std::string sup_trap = machine_.Supervisor() ? machine_.Supervisor()->LastTrapDetail() : "";
            last_exit_code_.store(exit_code);
            if (!sup_trap.empty() || exit_code != 0) {
                const std::string err_detail = !sup_trap.empty()
                    ? sup_trap
                    : ("Guest halted with non-zero exit=" + std::to_string(exit_code) +
                       ", insns=" + std::to_string(st.instructions_executed));
                {
                    std::lock_guard<std::mutex> tlock(trace_mutex_);
                    last_trap_summary_ = err_detail;
                }
                AppendLog("ERROR", "Guest fault: " + err_detail);
                SetCheckpoint("TRAPPED", err_detail);
            } else {
                const std::string halt_msg =
                    "Guest execution halted (exit=0, insns=" +
                    std::to_string(st.instructions_executed) + ")";
                AppendLog("INFO", halt_msg);
                SetCheckpoint("HALTED", halt_msg);
            }
            running_.store(false);
            break;
        }
        if (st.stop_reason == vm::CpuStopReason::WfiWait) {
            std::this_thread::sleep_for(std::chrono::milliseconds(4));
        } else {
            // Cooperative yield so tight DBT loops never starve Android UI / RenderThread
            std::this_thread::yield();
        }
    }
}

vm::VmError EngineRuntime::AttachSurface(ANativeWindow* window) {
    bool has_gpu_frame = false;
    std::vector<uint32_t> frame;
    uint32_t fw = 0, fh = 0;
    const bool is_running = running_.load();
    if (window != nullptr && is_running) {
        // Snapshot latest GPU frame BEFORE acquiring window_mutex_ to prevent AB-BA lock inversion
        has_gpu_frame = machine_.VirtioGpu().CopyLatestFrame(frame, fw, fh);
    }

    std::lock_guard<std::mutex> lock(window_mutex_);
    if (window_ != nullptr) {
        ANativeWindow_release(window_);
        window_ = nullptr;
    }
    window_ = window;
    if (window_ != nullptr) {
        int32_t rc = ANativeWindow_setBuffersGeometry(
            window_, config_.width, config_.height, WINDOW_FORMAT_RGBA_8888);
        if (rc != 0) {
            AppendLog("ERROR", "ANativeWindow_setBuffersGeometry failed rc=" + std::to_string(rc));
            return vm::VmError::SurfaceAttachFailed;
        }
        AppendLog("INFO", "Attached ANativeWindow (" + std::to_string(config_.width) + "x" +
                  std::to_string(config_.height) + ")");
        if (is_running && running_.load()) {
            if (has_gpu_frame && !frame.empty()) {
                PresentRgbaFrameLocked(frame.data(), fw, fh);
            } else {
                PresentBootFrameLocked();
            }
        }
    } else {
        AppendLog("INFO", "Detached ANativeWindow");
    }
    return vm::VmError::Ok;
}

void EngineRuntime::PresentBootFrame() {
    std::unique_lock<std::mutex> lock(window_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    PresentBootFrameLocked();
}

void EngineRuntime::PresentBootFrameLocked() {
    if (window_ == nullptr) return;
    ANativeWindow_Buffer buf{};
    if (ANativeWindow_lock(window_, &buf, nullptr) == 0 && buf.bits &&
        buf.width > 0 && buf.height > 0) {
        auto* pixels = static_cast<uint32_t*>(buf.bits);
        for (int y = 0; y < buf.height; ++y) {
            uint32_t color = (y < 4) ? 0xFFBBE64Fu : 0xFF0F0906u;
            uint32_t* row = pixels + static_cast<size_t>(y) * buf.stride;
            for (int x = 0; x < buf.width; ++x) {
                row[x] = color;
            }
        }
        ANativeWindow_unlockAndPost(window_);
    }
}

void EngineRuntime::PresentRgbaFrame(const uint32_t* pixels, uint32_t src_w, uint32_t src_h) {
    if (!pixels || src_w == 0u || src_h == 0u) return;

    const int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    const int64_t prev_ns = last_scanout_ns_.load();
    const int fps_cap = std::max(1, target_fps_.load());
    const int64_t min_interval_ns = 1000000000LL / static_cast<int64_t>(fps_cap);
    if (prev_ns > 0 && (now_ns - prev_ns) < (min_interval_ns / 2)) {
        return; // Pace scanout frames so BufferQueue never stalls UI/RenderThread
    }

    const int64_t win_start = fps_window_start_ns_.load();
    if (win_start == 0) {
        fps_window_start_ns_.store(now_ns);
        fps_window_frames_.store(1u);
    } else {
        const uint32_t frames = fps_window_frames_.fetch_add(1u) + 1u;
        const int64_t elapsed_ns = now_ns - win_start;
        if (elapsed_ns >= 500000000LL) {
            const float fps = static_cast<float>(frames) * 1e9f / static_cast<float>(elapsed_ns);
            measured_fps_.store(fps);
            fps_window_start_ns_.store(now_ns);
            fps_window_frames_.store(0u);
        } else if (prev_ns > 0 && now_ns > prev_ns) {
            const float inst_fps = 1e9f / static_cast<float>(now_ns - prev_ns);
            if (measured_fps_.load() == 0.0f) {
                measured_fps_.store(std::min(inst_fps, 240.0f));
            }
        }
    }
    last_scanout_ns_.store(now_ns);

    std::unique_lock<std::mutex> lock(window_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    PresentRgbaFrameLocked(pixels, src_w, src_h);
}

void EngineRuntime::PresentRgbaFrameLocked(const uint32_t* pixels, uint32_t src_w, uint32_t src_h) {
    if (window_ == nullptr || !pixels || src_w == 0u || src_h == 0u) return;
    ANativeWindow_Buffer buf{};
    if (ANativeWindow_lock(window_, &buf, nullptr) == 0 && buf.bits &&
        buf.width > 0 && buf.height > 0) {
        auto* dst = static_cast<uint32_t*>(buf.bits);
        const uint32_t dst_w = static_cast<uint32_t>(buf.width);
        const uint32_t dst_h = static_cast<uint32_t>(buf.height);
        if (dst_w == src_w && dst_h == src_h) {
            for (uint32_t y = 0; y < dst_h; ++y) {
                std::memcpy(dst + static_cast<size_t>(y) * buf.stride,
                            pixels + static_cast<size_t>(y) * src_w,
                            src_w * sizeof(uint32_t));
            }
        } else {
            for (uint32_t y = 0; y < dst_h; ++y) {
                const uint32_t sy = static_cast<uint32_t>(
                    (static_cast<uint64_t>(y) * src_h) / dst_h);
                const uint32_t* src_row = pixels + static_cast<size_t>(sy) * src_w;
                uint32_t* dst_row = dst + static_cast<size_t>(y) * buf.stride;
                for (uint32_t x = 0; x < dst_w; ++x) {
                    const uint32_t sx = static_cast<uint32_t>(
                        (static_cast<uint64_t>(x) * src_w) / dst_w);
                    dst_row[x] = src_row[sx];
                }
            }
        }
        ANativeWindow_unlockAndPost(window_);
    }
}

vm::VmError EngineRuntime::SendTouch(int action, int x, int y, int pointer_id) {
    if (!running_.load()) return vm::VmError::NotRunning;
    machine_.InjectTouch(action, x, y, pointer_id);
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::SendKey(int code, bool down) {
    if (!running_.load()) return vm::VmError::NotRunning;
    machine_.InjectKey(code, down);
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::SendText(const std::string& text) {
    if (!running_.load()) return vm::VmError::NotRunning;
    machine_.Uart().PushRxString(text);
    AppendLog("INPUT", "Text(len=" + std::to_string(text.size()) + ") pushed to PL011 RX");
    return vm::VmError::Ok;
}

vm::VmError EngineRuntime::SetTargetFps(int fps) {
    if (fps < 1 || fps > 240) return vm::VmError::InvalidArgument;
    target_fps_.store(fps);
    config_.target_fps = fps;
    AppendLog("INFO", "Target display FPS set to " + std::to_string(fps) + " Hz");
    return vm::VmError::Ok;
}

std::string EngineRuntime::ReadLog(int max_bytes) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (max_bytes <= 0) return "";
    std::string combined;
    for (const auto& line : log_lines_) {
        combined += line;
        combined.push_back('\n');
    }
    if (combined.size() > static_cast<size_t>(max_bytes)) {
        return combined.substr(combined.size() - static_cast<size_t>(max_bytes));
    }
    return combined;
}

vm::VmError EngineRuntime::Stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_.exchange(false)) {
        if (guest_thread_.joinable()) guest_thread_.join();
        SetCheckpoint("IDLE", "VM stopped");
        return vm::VmError::NotRunning;
    }
    machine_.Cpu().RequestStop();
    if (guest_thread_.joinable()) {
        guest_thread_.join();
    }
    machine_.Shutdown();
    system_ext4_.Close();
    {
        std::lock_guard<std::mutex> wlock(window_mutex_);
        if (window_ != nullptr) {
            ANativeWindow_release(window_);
            window_ = nullptr;
        }
    }
    measured_fps_.store(0.0f);
    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        active_binary_snapshot_ = "idle";
    }
    AppendLog("INFO", "VM stopped cleanly");
    SetCheckpoint("STOPPED", "VM stopped cleanly");
    return vm::VmError::Ok;
}

void EngineRuntime::SetCheckpoint(const std::string& stage, const std::string& detail) {
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    std::ostringstream oss;
    oss << "[" << now_ms << "][STAGE:" << stage << "] " << detail;
    const std::string line = oss.str();

    {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        boot_stage_ = stage;
        boot_detail_ = detail;
        WriteTraceFileLocked(line);
    }
}

void EngineRuntime::WriteTraceFileLocked(const std::string& line) {
    if (boot_trace_path_.empty()) return;
    struct stat st{};
    if (::stat(boot_trace_path_.c_str(), &st) == 0 && st.st_size > 512 * 1024) {
        std::ofstream trunc_ofs(boot_trace_path_, std::ios::trunc);
        trunc_ofs << "[TRACE_ROTATED]\n";
    }
    std::ofstream ofs(boot_trace_path_, std::ios::app);
    if (ofs.good()) {
        ofs << line << "\n";
        ofs.flush();
    }
}

void EngineRuntime::AppendLog(const std::string& level, const std::string& msg) {
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    std::ostringstream oss;
    oss << "[" << now_ms << "][" << level << "] " << msg;
    const std::string line = oss.str();
    LOGI("%s", line.c_str());

    const bool is_diag_uart = (level == "UART") &&
        (msg.rfind("[TRAP]", 0) == 0 || msg.rfind("[FAIL]", 0) == 0 ||
         msg.rfind("[SIGNAL]", 0) == 0 || msg.rfind("[SYS", 0) == 0 ||
         msg.rfind("[TRACE]", 0) == 0 || msg.rfind("[REGS]", 0) == 0 ||
         msg.rfind("[BT]", 0) == 0 || msg.rfind("[PMSG]", 0) == 0 ||
         msg.rfind("[LOGD]", 0) == 0 || msg.rfind("[KMSG]", 0) == 0 ||
         msg.rfind("[BINDER]", 0) == 0 ||
         msg.find("CANNOT LINK") != std::string::npos);
    if (level == "ERROR" || level == "WARN" || level == "INFO" || is_diag_uart) {
        std::lock_guard<std::mutex> tlock(trace_mutex_);
        WriteTraceFileLocked(line);
    }

    std::lock_guard<std::mutex> lock(log_mutex_);
    log_lines_.push_back(line);
    log_bytes_ += line.size() + 1;
    while (log_bytes_ > kMaxLogBufferBytes && !log_lines_.empty()) {
        log_bytes_ -= log_lines_.front().size() + 1;
        log_lines_.pop_front();
    }
}

} // namespace haseeb::engine
