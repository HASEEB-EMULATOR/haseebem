#include "haseeb/guest_vfs_bridge.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace haseeb::vm {

namespace {

std::vector<std::string> SplitSafeSegments(const std::string& rel) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < rel.size()) {
        while (i < rel.size() && rel[i] == '/') ++i;
        size_t j = i;
        while (j < rel.size() && rel[j] != '/') ++j;
        if (j > i) {
            const std::string seg = rel.substr(i, j - i);
            if (seg == "..") {
                if (!out.empty()) out.pop_back();
            } else if (seg != ".") {
                out.push_back(seg);
            }
        }
        i = j;
    }
    return out;
}

} // namespace

bool GuestVfsBridge::EnsureDirectoryTree(const std::string& host_dir) {
    if (host_dir.empty()) return false;
    std::string cur;
    for (size_t i = 0; i < host_dir.size(); ++i) {
        cur.push_back(host_dir[i]);
        if (host_dir[i] == '/' || i + 1u == host_dir.size()) {
            if (cur == "/") continue;
            struct stat st{};
            if (::stat(cur.c_str(), &st) != 0) {
                if (::mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool GuestVfsBridge::MapGuestStoragePath(const std::string& host_root,
                                         const std::string& norm_guest_path,
                                         std::string& out_host_path,
                                         std::string& out_rel) {
    if (host_root.empty()) return false;
    std::string tail;
    if (norm_guest_path == "/storage/emulated/0" || norm_guest_path == "/sdcard" ||
        norm_guest_path == "/data/media/0") {
        tail.clear();
    } else if (norm_guest_path.rfind("/storage/emulated/0/", 0) == 0) {
        tail = norm_guest_path.substr(std::strlen("/storage/emulated/0/"));
    } else if (norm_guest_path.rfind("/sdcard/", 0) == 0) {
        tail = norm_guest_path.substr(std::strlen("/sdcard/"));
    } else if (norm_guest_path.rfind("/data/media/0/", 0) == 0) {
        tail = norm_guest_path.substr(std::strlen("/data/media/0/"));
    } else {
        return false;
    }

    const auto segs = SplitSafeSegments(tail);
    out_rel.clear();
    out_host_path = host_root;
    while (out_host_path.size() > 1u && out_host_path.back() == '/') {
        out_host_path.pop_back();
    }
    for (const auto& s : segs) {
        if (!out_rel.empty()) out_rel.push_back('/');
        out_rel += s;
        out_host_path.push_back('/');
        out_host_path += s;
    }
    return true;
}

bool GuestVfsBridge::ListHostDirectory(const std::string& host_dir,
                                       std::vector<std::string>& out_children) {
    out_children.clear();
    DIR* dir = ::opendir(host_dir.c_str());
    if (!dir) return false;
    while (struct dirent* ent = ::readdir(dir)) {
        const std::string name(ent->d_name);
        if (name == "." || name == "..") continue;
        out_children.push_back(name);
    }
    ::closedir(dir);
    std::sort(out_children.begin(), out_children.end());
    return true;
}

bool GuestVfsBridge::ReadHostFileBytes(const std::string& host_path,
                                       std::vector<uint8_t>& out_data) {
    std::ifstream ifs(host_path, std::ios::binary | std::ios::ate);
    if (!ifs.good()) return false;
    const std::streamsize sz = ifs.tellg();
    if (sz < 0) return false;
    out_data.resize(static_cast<size_t>(sz));
    if (sz > 0) {
        ifs.seekg(0, std::ios::beg);
        if (!ifs.read(reinterpret_cast<char*>(out_data.data()), sz)) {
            out_data.clear();
            return false;
        }
    }
    return true;
}

bool GuestVfsBridge::TryResolveSpecialVfs(const std::string& norm_path,
                                          const std::string& host_storage_root,
                                          PhoneHardwareHub* hw,
                                          haseeb::prop::PropertyAreaManager* prop_mgr,
                                          uint64_t ram_bytes,
                                          std::vector<uint8_t>& out_data,
                                          bool& out_is_dir,
                                          std::vector<std::string>& out_children) {
    out_data.clear();
    out_children.clear();
    out_is_dir = false;

    // 1. /proc/cpuinfo & /proc/meminfo
    if (norm_path == "/proc/cpuinfo") {
        std::ostringstream oss;
        for (int i = 0; i < 4; ++i) {
            oss << "processor\t: " << i << "\n"
                << "BogoMIPS\t: 38.40\n"
                << "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\n"
                << "CPU implementer\t: 0x41\n"
                << "CPU architecture: 8\n"
                << "CPU variant\t: 0x1\n"
                << "CPU part\t: 0xd0b\n"
                << "CPU revision\t: 0\n\n";
        }
        oss << "Hardware\t: Haseeb Virtual ARM64 Board\n";
        const std::string text = oss.str();
        out_data.assign(text.begin(), text.end());
        return true;
    }
    if (norm_path == "/proc/meminfo") {
        const uint64_t kb = ram_bytes / 1024ULL;
        const uint64_t avail_kb = (kb * 3ULL) / 4ULL;
        std::ostringstream oss;
        oss << "MemTotal:       " << kb << " kB\n"
            << "MemFree:        " << (kb / 2ULL) << " kB\n"
            << "MemAvailable:   " << avail_kb << " kB\n"
            << "Buffers:        " << 16384 << " kB\n"
            << "Cached:         " << 65536 << " kB\n";
        const std::string text = oss.str();
        out_data.assign(text.begin(), text.end());
        return true;
    }

    // 2. Virtual sysfs battery/thermal/sensor nodes
    if (hw != nullptr) {
        std::string sysfs_val;
        if (hw->ReadVirtualSysfs(norm_path, sysfs_val)) {
            out_data.assign(sysfs_val.begin(), sysfs_val.end());
            return true;
        }
    }

    // 3. Bionic property directory & serialized build.prop view
    if (prop_mgr != nullptr) {
        if (norm_path == "/dev/__properties__") {
            out_is_dir = true;
            return ListHostDirectory(prop_mgr->PropertiesDir(), out_children);
        }
        if (norm_path.rfind("/dev/__properties__/", 0) == 0) {
            const std::string tail = norm_path.substr(std::strlen("/dev/__properties__/"));
            if (tail.find("..") == std::string::npos && !prop_mgr->PropertiesDir().empty()) {
                return ReadHostFileBytes(prop_mgr->PropertiesDir() + "/" + tail, out_data);
            }
        }
        if (norm_path == "/system/etc/build.prop") {
            std::ostringstream oss;
            for (const auto& kv : prop_mgr->ListAll()) {
                oss << kv.first << "=" << kv.second << "\n";
            }
            const std::string s = oss.str();
            out_data.assign(s.begin(), s.end());
            return true;
        }
    }

    // 4. Device nodes
    if (norm_path == "/dev/haseeb_sensors" || norm_path == "/dev/video0" ||
        norm_path == "/dev/haseeb_gles" || norm_path == "/dev/magisk_su" ||
        norm_path == "/dev/snd/pcmC0D0p" || norm_path == "/dev/snd/pcmC0D0c" ||
        norm_path == "/dev/binder" || norm_path == "/dev/hwbinder" ||
        norm_path == "/dev/vndbinder") {
        return true;
    }

    // 5. App-private host directory mapped to /storage/emulated/0, /sdcard, /data/media/0
    std::string host_path, rel;
    if (MapGuestStoragePath(host_storage_root, norm_path, host_path, rel)) {
        EnsureDirectoryTree(host_storage_root);
        struct stat st{};
        if (::stat(host_path.c_str(), &st) != 0) return false;
        if (S_ISDIR(st.st_mode)) {
            out_is_dir = true;
            return ListHostDirectory(host_path, out_children);
        }
        return ReadHostFileBytes(host_path, out_data);
    }

    return false;
}

int64_t GuestVfsBridge::HandleSpecialIoctl(LinuxGuestSupervisor::OpenFile& of,
                                           uint64_t req,
                                           uint64_t arg,
                                           PhoneHardwareHub* hw,
                                           SoftGlesContext* gles,
                                           VirtioGpuDevice* gpu,
                                           uint32_t& uid,
                                           uint32_t& gid,
                                           const std::string& caller,
                                           const ReadUserFn& read_user,
                                           const WriteUserFn& write_user) {
    const uint32_t req32 = static_cast<uint32_t>(req & 0xFFFFFFFFULL);

    if (of.is_sensors && hw != nullptr) {
        if (req32 == 0x485301u) { // HASEEB_SENSOR_GET_ALL (6 * SensorSample)
            const auto samples = hw->SampleAllSensors();
            return write_user(arg, samples.data(),
                              samples.size() * sizeof(PhoneHardwareHub::SensorSample))
                       ? static_cast<int64_t>(samples.size())
                       : -14;
        }
        if (req32 == 0x485302u) { // HASEEB_BATTERY_GET_INFO
            const auto bat = hw->GetBatteryState();
            return write_user(arg, &bat, sizeof(bat)) ? 0 : -14;
        }
        if (req32 >= 0x485310u && req32 <= 0x48531Fu) { // HASEEB_SENSOR_GET_ONE + type
            const uint32_t type = req32 - 0x485310u;
            const auto s = hw->SampleSensor(type);
            return write_user(arg, &s, sizeof(s)) ? 0 : -14;
        }
        return -22;
    }

    if (of.is_camera && hw != nullptr) {
        if (req32 == 0x80685600u) { // VIDIOC_QUERYCAP (104 bytes)
            struct V4l2Cap {
                char driver[16];
                char card[32];
                char bus_info[32];
                uint32_t version;
                uint32_t capabilities;
                uint32_t device_caps;
                uint32_t reserved[3];
            } cap{};
            std::snprintf(cap.driver, sizeof(cap.driver), "haseeb-cam");
            std::snprintf(cap.card, sizeof(cap.card), "Haseeb Virtual Camera");
            std::snprintf(cap.bus_info, sizeof(cap.bus_info), "platform:haseeb-v4l2");
            cap.version = 0x050A00u;
            cap.capabilities = 0x85000001u; // VIDEO_CAPTURE | READWRITE | DEVICE_CAPS
            cap.device_caps = 0x05000001u;
            return write_user(arg, &cap, sizeof(cap)) ? 0 : -14;
        }
        if (req32 == 0xC0D05604u || req32 == 0xC0D05605u) { // VIDIOC_G_FMT / VIDIOC_S_FMT
            // Simplified arm64 v4l2_format (208 bytes): type@0=1, fmt.pix.{width@8, height@12, pixfmt@16, bytesperline@28, sizeimage@32}
            uint8_t fmt[208]{};
            if (req32 == 0xC0D05605u) {
                if (!read_user(arg, fmt, sizeof(fmt))) return -14;
                uint32_t w = 640u, h = 480u, pf = PhoneHardwareHub::kV4l2PixFmtNv21;
                std::memcpy(&w, fmt + 8u, 4u);
                std::memcpy(&h, fmt + 12u, 4u);
                std::memcpy(&pf, fmt + 16u, 4u);
                hw->SetCameraFormat(w, h, pf);
            }
            const auto cf = hw->GetCameraFormat();
            const uint32_t type = 1u; // V4L2_BUF_TYPE_VIDEO_CAPTURE
            std::memcpy(fmt + 0u, &type, 4u);
            std::memcpy(fmt + 8u, &cf.width, 4u);
            std::memcpy(fmt + 12u, &cf.height, 4u);
            std::memcpy(fmt + 16u, &cf.pixelformat, 4u);
            std::memcpy(fmt + 28u, &cf.bytesperline, 4u);
            std::memcpy(fmt + 32u, &cf.sizeimage, 4u);
            return write_user(arg, fmt, sizeof(fmt)) ? 0 : -14;
        }
        if (req32 == 0x40045612u) { // VIDIOC_STREAMON
            hw->SetCameraStreaming(true);
            return 0;
        }
        if (req32 == 0x40045613u) { // VIDIOC_STREAMOFF
            hw->SetCameraStreaming(false);
            return 0;
        }
        return -22;
    }

    if (of.is_magisk_su && hw != nullptr) {
        if (req32 == 0x4D4701u) { // HASEEB_SU_REQUEST
            bool granted = false;
            hw->RecordSuRequest(uid, caller, granted);
            if (!granted) return -1; // -EPERM
            uid = 0u;
            gid = 0u;
            return 0;
        }
        return -22;
    }

    if (of.is_gles && gles != nullptr) {
        if (req32 == 0x484701u) { // HASEEB_GLES_EXECUTE { uint64_t ptr; uint64_t size; }
            uint64_t desc[2]{};
            if (!read_user(arg, desc, sizeof(desc))) return -14;
            if (desc[1] == 0ULL || desc[1] > 4ULL * 1024ULL * 1024ULL) return -22;
            std::vector<uint8_t> pkt(static_cast<size_t>(desc[1]));
            if (!read_user(desc[0], pkt.data(), pkt.size())) return -14;
            return gles->ExecuteCommandStream(pkt.data(), pkt.size(), gpu) ? 0 : -22;
        }
        if (req32 == 0x484702u) { // HASEEB_GLES_GET_RENDERER (copies <=64B string)
            const char* r = gles->GlGetString(SoftGlesContext::kGlRenderer);
            const size_t n = std::min<size_t>(63u, std::strlen(r));
            std::vector<char> buf(64u, 0);
            std::memcpy(buf.data(), r, n);
            return write_user(arg, buf.data(), buf.size()) ? 0 : -14;
        }
        if (req32 == 0x484703u) { // HASEEB_GLES_SWAP
            return gles->SwapBuffers(gpu) ? 0 : -5;
        }
        return -22;
    }

    return -22;
}

int64_t GuestVfsBridge::BuildGetDents64(LinuxGuestSupervisor::OpenFile& of,
                                        uint64_t dirp_va,
                                        size_t count,
                                        const WriteUserFn& write_user) {
    if (!of.is_dir) return -20; // -ENOTDIR
    std::vector<uint8_t> out;
    while (of.dir_cursor < of.dir_children.size()) {
        const std::string& name = of.dir_children[of.dir_cursor];
        const size_t rec_len = (19u + name.size() + 1u + 7u) & ~size_t(7u);
        if (out.size() + rec_len > count) break;
        const size_t start = out.size();
        out.resize(start + rec_len, 0u);
        const uint64_t d_ino = static_cast<uint64_t>(of.dir_cursor + 2u);
        const int64_t d_off = static_cast<int64_t>(of.dir_cursor + 1u);
        const uint16_t d_reclen = static_cast<uint16_t>(rec_len);
        std::memcpy(out.data() + start + 0u, &d_ino, 8u);
        std::memcpy(out.data() + start + 8u, &d_off, 8u);
        std::memcpy(out.data() + start + 16u, &d_reclen, 2u);
        out[start + 18u] = 8u; // DT_REG
        std::memcpy(out.data() + start + 19u, name.data(), name.size());
        out[start + 19u + name.size()] = 0u;
        ++of.dir_cursor;
    }
    if (!out.empty() && !write_user(dirp_va, out.data(), out.size())) {
        return -14;
    }
    return static_cast<int64_t>(out.size());
}

} // namespace haseeb::vm
