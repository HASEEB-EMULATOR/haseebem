#include "haseeb/boot_image.hpp"
#include "haseeb/fdt_builder.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/pl011_uart.hpp"
#include "haseeb/vm_types.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#define HASEEB_CHECK(cond)                                                              \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__              \
                      << ": " #cond << "\n";                                            \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

namespace fs = std::filesystem;
using namespace haseeb::vm;

namespace {

void WriteLE32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    std::memcpy(buf.data() + off, &v, 4);
}

void WriteLE64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    std::memcpy(buf.data() + off, &v, 8);
}

uint32_t ReadBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

std::vector<uint8_t> MakeArm64KernelStub(size_t size_bytes, uint64_t text_offset) {
    std::vector<uint8_t> k(std::max<size_t>(size_bytes, 128), 0);
    WriteLE64(k, 0x08, text_offset);
    WriteLE64(k, 0x10, k.size());
    WriteLE32(k, 0x38, 0x644D5241u); // "ARM\x64"
    return k;
}

std::vector<uint8_t> MakeSyntheticCpioWithMagisk() {
    const std::string entry = "07070100000001000081ED00000000magiskinit\0TRAILER!!!";
    return std::vector<uint8_t>(entry.begin(), entry.end());
}

std::vector<uint8_t> BuildBootV2(const std::vector<uint8_t>& kernel,
                                 const std::vector<uint8_t>& ramdisk,
                                 const std::vector<uint8_t>& dtb,
                                 const std::string& cmdline) {
    constexpr uint32_t pg = 4096u;
    auto align_pg = [&](size_t n) { return ((n + pg - 1u) / pg) * pg; };
    size_t total = pg + align_pg(kernel.size()) + align_pg(ramdisk.size()) + align_pg(dtb.size());
    std::vector<uint8_t> img(total, 0);

    std::memcpy(img.data(), "ANDROID!", 8);
    WriteLE32(img, 8, static_cast<uint32_t>(kernel.size()));
    WriteLE32(img, 16, static_cast<uint32_t>(ramdisk.size()));
    WriteLE32(img, 36, pg);
    WriteLE32(img, 40, 2u); // header_version = 2
    std::memcpy(img.data() + 64, cmdline.data(), std::min<size_t>(cmdline.size(), 511));
    WriteLE32(img, 1648, static_cast<uint32_t>(dtb.size()));

    size_t off = pg;
    if (!kernel.empty()) std::memcpy(img.data() + off, kernel.data(), kernel.size());
    off += align_pg(kernel.size());
    if (!ramdisk.empty()) std::memcpy(img.data() + off, ramdisk.data(), ramdisk.size());
    off += align_pg(ramdisk.size());
    if (!dtb.empty()) std::memcpy(img.data() + off, dtb.data(), dtb.size());
    return img;
}

std::vector<uint8_t> BuildBootV4(const std::vector<uint8_t>& kernel,
                                 const std::vector<uint8_t>& ramdisk,
                                 const std::string& cmdline) {
    constexpr uint32_t pg = 4096u;
    auto align_pg = [&](size_t n) { return ((n + pg - 1u) / pg) * pg; };
    size_t total = pg + align_pg(kernel.size()) + align_pg(ramdisk.size());
    std::vector<uint8_t> img(total, 0);

    std::memcpy(img.data(), "ANDROID!", 8);
    WriteLE32(img, 8, static_cast<uint32_t>(kernel.size()));
    WriteLE32(img, 12, static_cast<uint32_t>(ramdisk.size()));
    WriteLE32(img, 20, 1584u); // header_size v4
    WriteLE32(img, 40, 4u);    // header_version = 4
    std::memcpy(img.data() + 44, cmdline.data(), std::min<size_t>(cmdline.size(), 1535));

    size_t off = pg;
    if (!kernel.empty()) std::memcpy(img.data() + off, kernel.data(), kernel.size());
    off += align_pg(kernel.size());
    if (!ramdisk.empty()) std::memcpy(img.data() + off, ramdisk.data(), ramdisk.size());
    return img;
}

std::vector<uint8_t> BuildVendorBootV4(const std::vector<uint8_t>& vramdisk,
                                       const std::string& vcmdline,
                                       const std::string& bootconfig) {
    constexpr uint32_t pg = 4096u;
    auto align_pg = [&](size_t n) { return ((n + pg - 1u) / pg) * pg; };
    size_t total = pg + align_pg(vramdisk.size()) + align_pg(bootconfig.size());
    std::vector<uint8_t> img(total, 0);

    std::memcpy(img.data(), "VNDRBOOT", 8);
    WriteLE32(img, 8, 4u);  // header_version = 4
    WriteLE32(img, 12, pg); // page_size
    WriteLE32(img, 24, static_cast<uint32_t>(vramdisk.size()));
    std::memcpy(img.data() + 28, vcmdline.data(), std::min<size_t>(vcmdline.size(), 2047));
    WriteLE32(img, 2096, 2128u); // header_size
    WriteLE32(img, 2124, static_cast<uint32_t>(bootconfig.size()));

    size_t off = pg;
    if (!vramdisk.empty()) std::memcpy(img.data() + off, vramdisk.data(), vramdisk.size());
    off += align_pg(vramdisk.size());
    if (!bootconfig.empty()) std::memcpy(img.data() + off, bootconfig.data(), bootconfig.size());
    return img;
}

void TestBootImageV2AndV4Parsing() {
    auto kernel = MakeArm64KernelStub(4096, 0x80000ULL);
    auto ramdisk_magisk = MakeSyntheticCpioWithMagisk();
    std::vector<uint8_t> dummy_dtb = {0xD0, 0x0D, 0xFE, 0xED, 0, 0, 0, 40};

    // v2 boot image with Magisk
    auto v2_bytes = BuildBootV2(kernel, ramdisk_magisk, dummy_dtb, "buildvariant=userdebug");
    ParsedBootImage parsed_v2;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(v2_bytes, parsed_v2, err) == VmError::Ok);
    HASEEB_CHECK(parsed_v2.header_version == 2u);
    HASEEB_CHECK(parsed_v2.kernel_info.valid_arm64_magic);
    HASEEB_CHECK(parsed_v2.kernel_info.text_offset == 0x80000ULL);
    HASEEB_CHECK(parsed_v2.magisk_detected);
    HASEEB_CHECK(parsed_v2.dtb.size() == dummy_dtb.size());

    // v4 boot + vendor_boot + init_boot merge
    auto v4_bytes = BuildBootV4(kernel, {}, "console=ttyAMA0");
    ParsedBootImage parsed_v4;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(v4_bytes, parsed_v4, err) == VmError::Ok);
    HASEEB_CHECK(!parsed_v4.magisk_detected);

    std::vector<uint8_t> vendor_rd = {'V', 'E', 'N', 'D'};
    auto vboot = BuildVendorBootV4(vendor_rd, "androidboot.boot_devices=a000000.virtio_mmio",
                                   "androidboot.force_normal_boot=1\n");
    HASEEB_CHECK(BootImageParser::MergeVendorBootBytes(vboot, parsed_v4, err) == VmError::Ok);
    auto init_boot = BuildBootV4({}, ramdisk_magisk, "");
    HASEEB_CHECK(BootImageParser::MergeInitBootBytes(init_boot, parsed_v4, err) == VmError::Ok);
    HASEEB_CHECK(parsed_v4.magisk_detected);
    HASEEB_CHECK(parsed_v4.ramdisk.size() == vendor_rd.size() + ramdisk_magisk.size());
    HASEEB_CHECK(parsed_v4.bootconfig.find("force_normal_boot=1") != std::string::npos);

    std::cout << "[PASS] TestBootImageV2AndV4Parsing\n";
}

void TestFdtBuilderAndMachineBootToUart() {
    auto kernel = MakeArm64KernelStub(4096, 0x80000ULL);
    auto ramdisk = MakeSyntheticCpioWithMagisk();
    auto boot_bytes = BuildBootV2(kernel, ramdisk, {}, "androidboot.selinux=permissive");

    ParsedBootImage boot;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(boot_bytes, boot, err) == VmError::Ok);

    std::vector<std::string> uart_lines;
    VirtualMachineSkeleton vm([&](const std::string& line) {
        uart_lines.push_back(line);
    });

    MachineBootConfig cfg;
    cfg.ram_mb = 256; // compact test RAM footprint
    cfg.vcpu_count = 4;
    cfg.extra_cmdline = "haseeb.test=1";

    HASEEB_CHECK(vm.InitializeAndStage(cfg, &boot, err) == VmError::Ok);
    HASEEB_CHECK(vm.Ram().IsAllocated());
    HASEEB_CHECK(vm.Ram().MemFd() >= 0);

    // Check compiled FDT magic in guest RAM at dtb_guest_addr
    uint8_t hdr[8]{};
    HASEEB_CHECK(vm.Ram().ReadBytes(vm.DtbGuestAddr(), hdr, sizeof(hdr)));
    HASEEB_CHECK(ReadBE32(hdr) == 0xD00DFEEDu);

    // Execute AArch64 2nd-stage bootloader stub to PL011 UART output
    HASEEB_CHECK(vm.RunBootStubUntilHalt() == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);
    HASEEB_CHECK(vm.CpuState().x[0] == vm.DtbGuestAddr());
    HASEEB_CHECK(vm.CpuState().x[1] == 0 && vm.CpuState().x[2] == 0 && vm.CpuState().x[3] == 0);
    HASEEB_CHECK(vm.CpuState().instructions_executed > 20);

    const std::string uart_out = vm.Uart().CapturedOutput();
    HASEEB_CHECK(uart_out.find("[HASEEB-VM] AArch64 bootloader stub initialized") != std::string::npos);
    HASEEB_CHECK(uart_out.find("Magisk ramdisk signature detected") != std::string::npos);
    HASEEB_CHECK(uart_out.find("haseeb.test=1") != std::string::npos);
    HASEEB_CHECK(!uart_lines.empty());

    std::string p2_bits;
    HASEEB_CHECK(vm.RunPowerOf2SelfTest(p2_bits) == VmError::Ok);
    HASEEB_CHECK(p2_bits == "1110");
    HASEEB_CHECK(vm.Uart().CapturedOutput().find("[SELF-TEST] powerof2(8,64,1,7)=1110") != std::string::npos);
    HASEEB_CHECK(vm.CpuState().x[0] == vm.DtbGuestAddr());

    vm.Shutdown();
    HASEEB_CHECK(!vm.IsStaged());

    std::cout << "[PASS] TestFdtBuilderAndMachineBootToUart\n";
}

} // namespace

int main() {
    TestBootImageV2AndV4Parsing();
    TestFdtBuilderAndMachineBootToUart();
    std::cout << "All M1 Full-System VM Boot & Machine tests PASSED.\n";
    return 0;
}
