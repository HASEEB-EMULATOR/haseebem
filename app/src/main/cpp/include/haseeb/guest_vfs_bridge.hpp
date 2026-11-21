#pragma once

#include "haseeb/kernel_boot.hpp"
#include "haseeb/phone_hardware.hpp"
#include "haseeb/prop_area.hpp"
#include "haseeb/soft_gles.hpp"
#include "haseeb/virtio_gpu.hpp"
#include "haseeb/virtio_snd_net.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace haseeb::vm {

// Modular M7/M8 EL0 VFS & ioctl bridge separating host-directory /storage/emulated/0
// POSIX operations, Bionic __properties__, sensors/battery/camera/Magisk su nodes,
// and SoftGLES / Virtio-Snd ioctl/read/write dispatch from kernel_boot.cpp.
class GuestVfsBridge {
public:
    using ReadUserFn = std::function<bool(uint64_t uva, void* dst, size_t len)>;
    using WriteUserFn = std::function<bool(uint64_t uva, const void* src, size_t len)>;

    static bool EnsureDirectoryTree(const std::string& host_dir);

    static bool MapGuestStoragePath(const std::string& host_root,
                                    const std::string& norm_guest_path,
                                    std::string& out_host_path,
                                    std::string& out_rel);

    static bool ListHostDirectory(const std::string& host_dir,
                                  std::vector<std::string>& out_children);

    static bool ReadHostFileBytes(const std::string& host_path,
                                  std::vector<uint8_t>& out_data);

    static bool TryResolveSpecialVfs(const std::string& norm_path,
                                     const std::string& host_storage_root,
                                     PhoneHardwareHub* hw,
                                     haseeb::prop::PropertyAreaManager* prop_mgr,
                                     uint64_t ram_bytes,
                                     std::vector<uint8_t>& out_data,
                                     bool& out_is_dir,
                                     std::vector<std::string>& out_children);

    static int64_t HandleSpecialIoctl(LinuxGuestSupervisor::OpenFile& of,
                                      uint64_t req,
                                      uint64_t arg,
                                      PhoneHardwareHub* hw,
                                      SoftGlesContext* gles,
                                      VirtioGpuDevice* gpu,
                                      uint32_t& uid,
                                      uint32_t& gid,
                                      const std::string& caller,
                                      const ReadUserFn& read_user,
                                      const WriteUserFn& write_user);

    static int64_t BuildGetDents64(LinuxGuestSupervisor::OpenFile& of,
                                   uint64_t dirp_va,
                                   size_t count,
                                   const WriteUserFn& write_user);
};

} // namespace haseeb::vm
