#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace haseeb::prop {

// Bionic-compatible property area constants (AOSP system_properties ABI)
inline constexpr uint32_t kPropAreaMagic = 0x504f5250u;   // 'P','R','O','P'
inline constexpr uint32_t kPropAreaVersion = 0xfc6ed0abu; // Bionic PROP_AREA_VERSION
inline constexpr size_t kPropAreaDefaultSize = 1024u * 1024u; // 1 MiB (64 x 16 KiB pages)
inline constexpr size_t kPropAreaHeaderSize = 128u;
inline constexpr size_t kPropNameMax = 256u;
inline constexpr size_t kPropValueMax = 92u;
inline constexpr size_t kPageSize16K = 16384u;

// prop_info::serial bitfields matching Bionic
inline constexpr uint32_t kDirtyFlag = 1u << 0;
inline constexpr uint32_t kLongFlag = 1u << 16;
inline constexpr uint32_t kLongLegacyErrorLen = 56u;

struct alignas(4) PropBt {
    uint32_t namelen;
    std::atomic<uint32_t> prop;
    std::atomic<uint32_t> left;
    std::atomic<uint32_t> right;
    std::atomic<uint32_t> children;
    char name[0];
};
static_assert(sizeof(PropBt) == 20, "PropBt must match Bionic 20-byte layout");

struct alignas(4) PropInfo {
    std::atomic<uint32_t> serial;
    union {
        char value[kPropValueMax];
        struct {
            char error_message[kLongLegacyErrorLen];
            uint32_t offset;
        } long_property;
    };
    char name[0];
};
static_assert(sizeof(PropInfo) == 96, "PropInfo must match Bionic 96-byte layout");

struct alignas(16) PropAreaHeader {
    std::atomic<uint32_t> bytes_used;
    std::atomic<uint32_t> serial;
    uint32_t magic;
    uint32_t version;
    uint32_t reserved[28];
    uint8_t data[0];
};
static_assert(sizeof(PropAreaHeader) == kPropAreaHeaderSize, "PropAreaHeader must be 128 bytes");

inline constexpr size_t AlignUp(size_t value, size_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

inline uint8_t SerialValueLen(uint32_t serial) {
    return static_cast<uint8_t>(serial >> 24);
}

inline bool SerialIsLong(uint32_t serial) {
    return (serial & kLongFlag) != 0u;
}

inline uint32_t MakeSerial(uint32_t seq, uint8_t len, bool is_long) {
    uint32_t s = (seq & 0x0000FFFEu) | (static_cast<uint32_t>(len) << 24);
    if (is_long) s |= kLongFlag;
    return s;
}

} // namespace haseeb::prop
