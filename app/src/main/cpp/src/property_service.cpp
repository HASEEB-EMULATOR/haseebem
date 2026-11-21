#include "haseeb/property_service.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace haseeb::prop {

namespace {

bool ReadExactFd(int fd, void* dst, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(dst);
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(fd, p + got, len - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool WriteExactFd(int fd, const void* src, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(src);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

PropertyService::PropertyService(PropertyAreaManager& manager) : manager_(manager) {}

PropertyService::~PropertyService() {
    Stop();
}

bool PropertyService::Start(const std::string& socket_path) {
    if (running_.load()) return true;
    socket_path_ = socket_path;

    std::string parent = socket_path.substr(0, socket_path.find_last_of('/'));
    if (!parent.empty()) {
        ::mkdir(parent.c_str(), 0755);
    }
    ::unlink(socket_path.c_str());

    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;

    sockaddr_un addr{};
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return false;
    }
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    if (::listen(fd, 16) != 0) {
        ::close(fd);
        ::unlink(socket_path.c_str());
        return false;
    }

    listen_fd_ = fd;
    running_.store(true);
    accept_thread_ = std::thread(&PropertyService::AcceptLoop, this);
    return true;
}

void PropertyService::Stop() {
    if (!running_.exchange(false)) {
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
        return;
    }
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (!socket_path_.empty()) {
        ::unlink(socket_path_.c_str());
    }
}

uint32_t PropertyService::HandleSetPropRequest(const std::string& name, const std::string& value) {
    if (name.empty() || name.size() >= kPropNameMax) {
        return kPropErrorInvalidName;
    }
    if (PropertyAreaManager::IsBlockedGpuOverride(name)) {
        return kPropErrorReadOnlyProperty;
    }
    // ro.* properties are write-once after initial override unless unset
    if (name.rfind("ro.", 0) == 0) {
        std::string existing;
        if (manager_.GetProperty(name, existing)) {
            return kPropErrorReadOnlyProperty;
        }
    }
    return manager_.SetProperty(name, value, false) ? kPropSuccess : kPropErrorInvalidValue;
}

void PropertyService::AcceptLoop() {
    while (running_.load()) {
        int client = ::accept(listen_fd_, nullptr, nullptr);
        if (client < 0) {
            if (!running_.load() || errno == EBADF || errno == EINVAL) break;
            continue;
        }
        HandleClient(client);
        ::close(client);
    }
}

void PropertyService::HandleClient(int client_fd) {
    uint32_t cmd = 0;
    if (!ReadExactFd(client_fd, &cmd, sizeof(cmd))) return;
    if (cmd != kPropMsgSetProp2) {
        uint32_t err = kPropErrorInvalidValue;
        WriteExactFd(client_fd, &err, sizeof(err));
        return;
    }

    uint32_t name_len = 0;
    if (!ReadExactFd(client_fd, &name_len, sizeof(name_len)) || name_len == 0 || name_len > kPropNameMax) {
        uint32_t err = kPropErrorInvalidName;
        WriteExactFd(client_fd, &err, sizeof(err));
        return;
    }
    std::string name(name_len, '\0');
    if (!ReadExactFd(client_fd, name.data(), name_len)) return;
    if (!name.empty() && name.back() == '\0') name.pop_back();

    uint32_t val_len = 0;
    if (!ReadExactFd(client_fd, &val_len, sizeof(val_len)) || val_len > 4096u) {
        uint32_t err = kPropErrorInvalidValue;
        WriteExactFd(client_fd, &err, sizeof(err));
        return;
    }
    std::string value(val_len, '\0');
    if (val_len > 0 && !ReadExactFd(client_fd, value.data(), val_len)) return;
    if (!value.empty() && value.back() == '\0') value.pop_back();

    uint32_t result = HandleSetPropRequest(name, value);
    WriteExactFd(client_fd, &result, sizeof(result));
}

} // namespace haseeb::prop
