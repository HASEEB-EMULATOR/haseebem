#pragma once

#include <cstdint>
#include <string>

namespace haseeb::vm {

// Host-safe 16 KiB alignment for Android 15+ devices
inline constexpr size_t kHostSafePageSize = 16384u;

// Standard ARM64 virt-compatible guest physical memory map
inline constexpr uint64_t kFlashBase        = 0x00000000ULL;
inline constexpr uint64_t kFlashSize        = 0x04000000ULL; // 64 MiB
inline constexpr uint64_t kGicDistBase      = 0x08000000ULL; // 64 KiB
inline constexpr uint64_t kGicRedistBase    = 0x080A0000ULL; // 128 KiB * vCPUs
inline constexpr uint64_t kPl011UartBase    = 0x09000000ULL; // 4 KiB
inline constexpr uint64_t kPl031RtcBase     = 0x09010000ULL; // 4 KiB
inline constexpr uint64_t kSp805WdtBase     = 0x09020000ULL; // 4 KiB
inline constexpr uint64_t kVirtioMmioBase   = 0x0A000000ULL; // 9 slots * 0x200 bytes
inline constexpr uint64_t kVirtioMmioStride = 0x00000200ULL;
inline constexpr uint32_t kVirtioMmioCount  = 9u;

inline constexpr uint64_t kGuestRamBase     = 0x40000000ULL;
inline constexpr uint64_t kBootStubBase     = 0x40000000ULL; // 2nd-stage trampoline page
inline constexpr uint64_t kKernelLoadBase   = 0x40080000ULL; // RAM base + default arm64 TEXT_OFFSET
inline constexpr uint64_t kInitrdLoadBase   = 0x48000000ULL; // Ramdisk load address (128 MiB above RAM base)
inline constexpr uint64_t kFdtMaxOffsetEnd  = 0x00200000ULL; // DTB placed 2 MiB below top of RAM

// Deliverable 6 documented JNI/Engine error codes (0 = success, negative = failure)
enum class VmError : int32_t {
    Ok                   = 0,
    InvalidArgument      = -1,
    PathNotSet           = -2,
    FileNotFound         = -3,
    IoFailure            = -4,
    InvalidBootImage     = -5,
    UnsupportedVersion   = -6,
    InvalidSystemImage   = -7,
    OutOfMemory          = -8,
    AlreadyRunning       = -9,
    NotRunning           = -10,
    SurfaceAttachFailed  = -11,
    GuestKernelInvalid   = -12,
    FdtBuildFailed       = -13,
    ExecutionTrap        = -14,
};

inline const char* VmErrorToString(VmError err) {
    switch (err) {
        case VmError::Ok:                 return "VM_OK";
        case VmError::InvalidArgument:    return "ERR_INVALID_ARGUMENT (-1)";
        case VmError::PathNotSet:         return "ERR_PATH_NOT_SET (-2)";
        case VmError::FileNotFound:       return "ERR_FILE_NOT_FOUND (-3)";
        case VmError::IoFailure:          return "ERR_IO_FAILURE (-4)";
        case VmError::InvalidBootImage:   return "ERR_INVALID_BOOT_IMAGE (-5)";
        case VmError::UnsupportedVersion: return "ERR_UNSUPPORTED_VERSION (-6)";
        case VmError::InvalidSystemImage: return "ERR_INVALID_SYSTEM_IMAGE (-7)";
        case VmError::OutOfMemory:        return "ERR_OUT_OF_MEMORY (-8)";
        case VmError::AlreadyRunning:     return "ERR_ALREADY_RUNNING (-9)";
        case VmError::NotRunning:         return "ERR_NOT_RUNNING (-10)";
        case VmError::SurfaceAttachFailed:return "ERR_SURFACE_ATTACH_FAILED (-11)";
        case VmError::GuestKernelInvalid: return "ERR_GUEST_KERNEL_INVALID (-12)";
        case VmError::FdtBuildFailed:     return "ERR_FDT_BUILD_FAILED (-13)";
        case VmError::ExecutionTrap:      return "ERR_EXECUTION_TRAP (-14)";
    }
    return "ERR_UNKNOWN";
}

struct MachineBootConfig {
    uint32_t vcpu_count = 4;
    uint32_t ram_mb = 2048;
    uint32_t api_level = 29;
    uint32_t width = 720;
    uint32_t height = 1560;
    uint32_t dpi = 320;
    std::string extra_cmdline;
};

} // namespace haseeb::vm
