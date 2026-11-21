#include "haseeb/guest_ram.hpp"

#include <cstring>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace haseeb::vm {

namespace {

int CreateMemfd(const char* name) {
#if defined(__NR_memfd_create)
    return static_cast<int>(::syscall(__NR_memfd_create, name, MFD_CLOEXEC));
#else
    (void)name;
    return -1;
#endif
}

} // namespace

// ---------------- MmioBus ----------------

void MmioBus::Register(uint64_t base, uint64_t size, MmioDevice* dev) {
    if (!dev || size == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    regions_.push_back({base, size, dev});
}

void MmioBus::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    regions_.clear();
}

bool MmioBus::Read(uint64_t paddr, unsigned size_bytes, uint64_t& out_val) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : regions_) {
        if (paddr >= r.base && paddr + size_bytes <= r.base + r.size) {
            out_val = r.device->Read(paddr - r.base, size_bytes);
            return true;
        }
    }
    return false;
}

bool MmioBus::Write(uint64_t paddr, unsigned size_bytes, uint64_t value) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : regions_) {
        if (paddr >= r.base && paddr + size_bytes <= r.base + r.size) {
            r.device->Write(paddr - r.base, size_bytes, value);
            return true;
        }
    }
    return false;
}

// ---------------- GuestRam ----------------

GuestRam::~GuestRam() {
    Free();
}

VmError GuestRam::Allocate(uint64_t base_addr, uint64_t size_bytes) {
    Free();
    if (size_bytes == 0 || (size_bytes % kHostSafePageSize) != 0) {
        size_bytes = (size_bytes + kHostSafePageSize - 1ull) & ~(kHostSafePageSize - 1ull);
    }
    if (size_bytes == 0) return VmError::InvalidArgument;

    int fd = CreateMemfd("haseeb_guest_ram");
    if (fd >= 0) {
        if (::ftruncate(fd, static_cast<off_t>(size_bytes)) != 0) {
            ::close(fd);
            fd = -1;
        }
    }

    void* ptr = MAP_FAILED;
    if (fd >= 0) {
        ptr = ::mmap(nullptr, static_cast<size_t>(size_bytes),
                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    } else {
        ptr = ::mmap(nullptr, static_cast<size_t>(size_bytes),
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    if (ptr == MAP_FAILED) {
        if (fd >= 0) ::close(fd);
        return VmError::OutOfMemory;
    }

    memfd_ = fd;
    mapping_ = static_cast<uint8_t*>(ptr);
    base_addr_ = base_addr;
    size_bytes_ = size_bytes;
    return VmError::Ok;
}

void GuestRam::Free() {
    if (mapping_ != nullptr && size_bytes_ > 0) {
        ::munmap(mapping_, static_cast<size_t>(size_bytes_));
    }
    if (memfd_ >= 0) {
        ::close(memfd_);
    }
    mapping_ = nullptr;
    memfd_ = -1;
    size_bytes_ = 0;
}

uint8_t* GuestRam::HostPtr(uint64_t paddr, size_t len) const {
    if (!mapping_ || paddr < base_addr_) return nullptr;
    uint64_t off = paddr - base_addr_;
    if (off > size_bytes_ || len > size_bytes_ - off) return nullptr;
    return mapping_ + off;
}

bool GuestRam::WriteBytes(uint64_t paddr, const void* src, size_t len) {
    uint8_t* dst = HostPtr(paddr, len);
    if (!dst) return false;
    if (len > 0) std::memcpy(dst, src, len);
    return true;
}

bool GuestRam::ReadBytes(uint64_t paddr, void* dst, size_t len) const {
    uint8_t* src = HostPtr(paddr, len);
    if (!src) return false;
    if (len > 0) std::memcpy(dst, src, len);
    return true;
}

bool GuestRam::ReadU32(uint64_t paddr, uint32_t& out) const {
    return ReadBytes(paddr, &out, sizeof(out));
}

bool GuestRam::WriteU32(uint64_t paddr, uint32_t val) {
    return WriteBytes(paddr, &val, sizeof(val));
}

bool GuestRam::ReadU64(uint64_t paddr, uint64_t& out) const {
    return ReadBytes(paddr, &out, sizeof(out));
}

bool GuestRam::WriteU64(uint64_t paddr, uint64_t val) {
    return WriteBytes(paddr, &val, sizeof(val));
}

bool GuestRam::ReadU8(uint64_t paddr, uint8_t& out) const {
    uint8_t* src = HostPtr(paddr, 1);
    if (!src) return false;
    out = *src;
    return true;
}

bool GuestRam::WriteU8(uint64_t paddr, uint8_t val) {
    uint8_t* dst = HostPtr(paddr, 1);
    if (!dst) return false;
    *dst = val;
    return true;
}

} // namespace haseeb::vm
