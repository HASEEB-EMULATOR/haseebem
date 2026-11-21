#pragma once

#include "haseeb/vm_types.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace haseeb::vm {

class MmioDevice {
public:
    virtual ~MmioDevice() = default;
    virtual const char* Name() const = 0;
    virtual uint64_t Read(uint64_t offset, unsigned size_bytes) = 0;
    virtual void Write(uint64_t offset, unsigned size_bytes, uint64_t value) = 0;
};

struct MmioRegion {
    uint64_t base = 0;
    uint64_t size = 0;
    MmioDevice* device = nullptr;
};

class MmioBus {
public:
    void Register(uint64_t base, uint64_t size, MmioDevice* dev);
    void Clear();

    bool Read(uint64_t paddr, unsigned size_bytes, uint64_t& out_val) const;
    bool Write(uint64_t paddr, unsigned size_bytes, uint64_t value) const;

private:
    mutable std::mutex mutex_;
    std::vector<MmioRegion> regions_;
};

// Guest physical RAM backed strictly by memfd_create (zero ashmem), 16 KiB aligned.
class GuestRam {
public:
    GuestRam() = default;
    ~GuestRam();

    GuestRam(const GuestRam&) = delete;
    GuestRam& operator=(const GuestRam&) = delete;

    VmError Allocate(uint64_t base_addr, uint64_t size_bytes);
    void Free();

    bool IsAllocated() const { return mapping_ != nullptr; }
    uint64_t BaseAddr() const { return base_addr_; }
    uint64_t SizeBytes() const { return size_bytes_; }
    int MemFd() const { return memfd_; }
    uint8_t* HostPtr(uint64_t paddr, size_t len) const;

    bool WriteBytes(uint64_t paddr, const void* src, size_t len);
    bool ReadBytes(uint64_t paddr, void* dst, size_t len) const;

    bool ReadU32(uint64_t paddr, uint32_t& out) const;
    bool WriteU32(uint64_t paddr, uint32_t val);
    bool ReadU64(uint64_t paddr, uint64_t& out) const;
    bool WriteU64(uint64_t paddr, uint64_t val);
    bool ReadU8(uint64_t paddr, uint8_t& out) const;
    bool WriteU8(uint64_t paddr, uint8_t val);

private:
    int memfd_ = -1;
    uint8_t* mapping_ = nullptr;
    uint64_t base_addr_ = kGuestRamBase;
    uint64_t size_bytes_ = 0;
};

} // namespace haseeb::vm
