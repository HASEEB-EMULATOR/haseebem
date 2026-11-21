#include "haseeb/prop_area.hpp"
#include "haseeb/prop_layout.hpp"
#include "haseeb/property_service.hpp"

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define HASEEB_CHECK(cond)                                                              \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__              \
                      << ": " #cond << "\n";                                            \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

namespace fs = std::filesystem;
using namespace haseeb::prop;

namespace {

// Raw Bionic-compatible guest reader (simulates guest `getprop` reading /dev/__properties__/ via mmap)
bool RawBionicGetProp(const std::string& arena_file, const std::string& name, std::string& out) {
    int fd = ::open(arena_file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(kPropAreaHeaderSize)) {
        ::close(fd);
        return false;
    }

    void* map = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) return false;

    const auto* base = static_cast<const uint8_t*>(map);
    const auto* hdr = reinterpret_cast<const PropAreaHeader*>(base);
    if (hdr->magic != kPropAreaMagic || hdr->version != kPropAreaVersion) {
        ::munmap(map, static_cast<size_t>(st.st_size));
        return false;
    }

    const uint8_t* data = base + kPropAreaHeaderSize;
    const auto* cur = reinterpret_cast<const PropBt*>(data);

    size_t pos = 0;
    while (pos <= name.size()) {
        size_t dot = name.find('.', pos);
        size_t seg_len = (dot == std::string::npos) ? (name.size() - pos) : (dot - pos);
        const char* seg = name.data() + pos;

        uint32_t child_off = cur->children.load(std::memory_order_acquire);
        const PropBt* matched = nullptr;
        while (child_off != 0u) {
            const auto* node = reinterpret_cast<const PropBt*>(data + child_off);
            int cmp = (seg_len < node->namelen) ? -1
                    : (seg_len > node->namelen) ? 1
                    : std::memcmp(seg, node->name, seg_len);
            if (cmp == 0) {
                matched = node;
                break;
            }
            child_off = (cmp < 0) ? node->left.load(std::memory_order_acquire)
                                  : node->right.load(std::memory_order_acquire);
        }
        if (!matched) {
            ::munmap(map, static_cast<size_t>(st.st_size));
            return false;
        }
        cur = matched;
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }

    uint32_t prop_off = cur->prop.load(std::memory_order_acquire);
    if (prop_off == 0u) {
        ::munmap(map, static_cast<size_t>(st.st_size));
        return false;
    }

    const auto* info = reinterpret_cast<const PropInfo*>(data + prop_off);
    uint32_t s = info->serial.load(std::memory_order_acquire);
    uint8_t len = SerialValueLen(s);
    out.assign(info->value, len);
    ::munmap(map, static_cast<size_t>(st.st_size));
    return true;
}

bool GuestShellSetProp(const std::string& sock_path, const std::string& name, const std::string& val) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    uint32_t cmd = kPropMsgSetProp2;
    uint32_t klen = static_cast<uint32_t>(name.size() + 1);
    uint32_t vlen = static_cast<uint32_t>(val.size() + 1);
    ::send(fd, &cmd, 4, 0);
    ::send(fd, &klen, 4, 0);
    ::send(fd, name.c_str(), klen, 0);
    ::send(fd, &vlen, 4, 0);
    ::send(fd, val.c_str(), vlen, 0);
    uint32_t rc = 1u;
    ::recv(fd, &rc, 4, MSG_WAITALL);
    ::close(fd);
    return rc == kPropSuccess;
}

} // namespace

int main() {
    std::string dir = "/tmp/haseeb_guest_prop_it_" + std::to_string(::getpid());
    fs::remove_all(dir);
    fs::create_directories(dir + "/dev/socket");

    PropertyAreaManager mgr;
    mgr.SetOverride("ro.product.model", "ASUS_AI2501");
    mgr.SetOverride("ro.product.marketname", "ROG Phone 9");
    HASEEB_CHECK(mgr.Initialize(dir));

    PropertyService svc(mgr);
    std::string sock_path = dir + "/dev/socket/property_service";
    HASEEB_CHECK(svc.Start(sock_path));

    // Simulate guest shell `getprop ro.product.model` via raw Bionic mmap reader
    std::string out;
    std::string serial_file = dir + "/dev/__properties__/properties_serial";
    std::string build_ctx_file = dir + "/dev/__properties__/u:object_r:build_prop:s0";
    HASEEB_CHECK(RawBionicGetProp(serial_file, "ro.product.model", out) && out == "ASUS_AI2501");
    HASEEB_CHECK(RawBionicGetProp(build_ctx_file, "ro.product.marketname", out) && out == "ROG Phone 9");

    // Simulate guest shell `setprop debug.haseeb.game com.tencent.ig` -> `getprop debug.haseeb.game`
    HASEEB_CHECK(GuestShellSetProp(sock_path, "debug.haseeb.game", "com.tencent.ig"));
    HASEEB_CHECK(RawBionicGetProp(serial_file, "debug.haseeb.game", out) && out == "com.tencent.ig");

    svc.Stop();
    fs::remove_all(dir);
    std::cout << "[PASS] M1 Guest getprop/setprop integration test passed.\n";
    return 0;
}
