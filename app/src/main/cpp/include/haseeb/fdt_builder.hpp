#pragma once

#include "haseeb/vm_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

struct FdtBuildParams {
    uint64_t ram_base = kGuestRamBase;
    uint64_t ram_size_bytes = 2048ULL * 1024ULL * 1024ULL;
    uint32_t vcpu_count = 4;
    uint64_t initrd_start = 0;
    uint64_t initrd_end = 0;
    std::string bootargs;
};

// From-scratch Flattened Device Tree (.dtb, magic 0xD00DFEED, version 17) compiler
// emitting a Linux ARM64 virtual board device tree for GICv3, Generic Timer, PSCI,
// PL011 UART, PL031 RTC, and virtio-mmio slots.
class FdtBuilder {
public:
    static bool Build(const FdtBuildParams& params,
                      std::vector<uint8_t>& out_dtb,
                      std::string& out_error);
};

} // namespace haseeb::vm
