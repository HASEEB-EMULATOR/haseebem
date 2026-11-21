#pragma once

#include "haseeb/prop_area.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace haseeb::prop {

// Android Bionic property_service Unix socket wire constants (PROP_MSG_SETPROP2)
inline constexpr uint32_t kPropMsgSetProp2 = 0x00020001u;
inline constexpr uint32_t kPropSuccess = 0u;
inline constexpr uint32_t kPropErrorReadOnlyProperty = 0x0003u;
inline constexpr uint32_t kPropErrorInvalidName = 0x0004u;
inline constexpr uint32_t kPropErrorInvalidValue = 0x0005u;

class PropertyService {
public:
    explicit PropertyService(PropertyAreaManager& manager);
    ~PropertyService();

    PropertyService(const PropertyService&) = delete;
    PropertyService& operator=(const PropertyService&) = delete;

    // Binds <runtime_dir>/dev/socket/property_service (or abstract/custom path) and serves requests.
    bool Start(const std::string& socket_path);
    void Stop();

    bool IsRunning() const { return running_.load(); }
    const std::string& SocketPath() const { return socket_path_; }

    // Handles a single PROP_MSG_SETPROP2 request synchronously (used both by socket loop & unit tests).
    uint32_t HandleSetPropRequest(const std::string& name, const std::string& value);

private:
    void AcceptLoop();
    void HandleClient(int client_fd);

    PropertyAreaManager& manager_;
    std::string socket_path_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

} // namespace haseeb::prop
