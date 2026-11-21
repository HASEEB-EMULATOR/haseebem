#pragma once

#include "haseeb/boot_image.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/cpu_core.hpp"
#include "haseeb/ext4_reader.hpp"
#include "haseeb/fdt_builder.hpp"
#include "haseeb/gicv3.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/kernel_boot.hpp"
#include "haseeb/phone_hardware.hpp"
#include "haseeb/pl011_uart.hpp"
#include "haseeb/pl031_rtc.hpp"
#include "haseeb/prop_area.hpp"
#include "haseeb/property_service.hpp"
#include "haseeb/psci.hpp"
#include "haseeb/soft_gles.hpp"
#include "haseeb/sp805_wdt.hpp"
#include "haseeb/virtio_devices.hpp"
#include "haseeb/virtio_gpu.hpp"
#include "haseeb/virtio_input.hpp"
#include "haseeb/virtio_mmio.hpp"
#include "haseeb/virtio_snd_net.hpp"
#include "haseeb/vm_types.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace haseeb::vm {

enum class GuestLaunchMode : uint8_t {
    None = 0,
    BootStub,
    KernelDirect,
    InitSupervisor,
};

// Virtual machine host board: owns guest memfd RAM, MMIO bus, GICv3, PSCI v1.0,
// PL011 UART, PL031 RTC, SP805 Watchdog, Virtio-MMIO transports/backends, FDT,
// boot image decompression/staging, CPIO/Ext4 EL0 supervisor, and DBT CPU + MMU core.
class VirtualMachineSkeleton {
public:
    explicit VirtualMachineSkeleton(Pl011Uart::TxLineCallback uart_cb = nullptr);
    ~VirtualMachineSkeleton();

    VirtualMachineSkeleton(const VirtualMachineSkeleton&) = delete;
    VirtualMachineSkeleton& operator=(const VirtualMachineSkeleton&) = delete;

    void SetExt4Reader(const loader::Ext4Reader* ext4) { ext4_reader_ = ext4; }
    void SetRuntimePaths(const std::string& runtime_dir, const std::string& shared_storage_root);
    void SetDeviceProperties(const std::vector<std::pair<std::string, std::string>>& props);

    VmError InitializeAndStage(const MachineBootConfig& config,
                               const ParsedBootImage* boot_img,
                               std::string& out_error);

    // Executes the staged bootloader stub (M1/M2 compatibility)
    VmError RunBootStubUntilHalt(uint64_t max_steps = 100000ULL);

    // M-A CPU diagnostic stub: executes powerof2(8, 64, 1, 7) on AArch64CpuCore,
    // outputs ASCII '1'/'0' characters to PL011 UART, and stores the 4 bytes in RAM.
    VmError RunPowerOf2SelfTest(std::string& out_bits);

    // M4 Boot modes: direct uncompressed/decompressed ARM64 Linux kernel Image, or
    // EL1->EL0 supervisor booting /magiskinit -> /init -> /system/bin/init -> /system/bin/sh.
    VmError PrepareKernelDirectBoot(std::string& out_error);
    VmError PrepareInitSupervisorBoot(const std::vector<std::string>& argv,
                                      bool magisk_enabled,
                                      std::string& out_selected_binary,
                                      std::string& out_error);
    VmError BootGuest(bool magisk_enabled,
                      std::string& out_booted_target,
                      std::string& out_error);
    VmError StepGuest(uint64_t max_insns = 50000ULL);

    void Shutdown();

    bool IsStaged() const { return ram_.IsAllocated(); }
    GuestLaunchMode LaunchMode() const { return launch_mode_; }
    uint64_t DtbGuestAddr() const { return dtb_guest_addr_; }
    uint64_t KernelGuestAddr() const { return kernel_guest_addr_; }
    uint64_t KernelSizeBytes() const { return kernel_size_; }
    uint64_t InitrdGuestAddr() const { return initrd_guest_addr_; }
    uint64_t InitrdSizeBytes() const { return initrd_size_; }
    const std::vector<CpioEntry>& InitramfsEntries() const { return initramfs_entries_; }
    bool ResetRequested() const { return reset_requested_.load(); }

    const LinuxGuestSupervisor* Supervisor() const { return supervisor_.get(); }
    LinuxGuestSupervisor* Supervisor() { return supervisor_.get(); }

    const CpuState& CpuState() const { return cpu_.State(); }
    AArch64CpuCore& Cpu() { return cpu_; }
    const AArch64CpuCore& Cpu() const { return cpu_; }

    GicV3& Gic() { return gic_; }
    const GicV3& Gic() const { return gic_; }
    PsciController& Psci() { return psci_; }
    const PsciController& Psci() const { return psci_; }
    Pl011Uart& Uart() { return uart_; }
    const Pl011Uart& Uart() const { return uart_; }
    Pl031Rtc& Rtc() { return rtc_; }
    const Pl031Rtc& Rtc() const { return rtc_; }
    Sp805Watchdog& Watchdog() { return wdt_; }
    const Sp805Watchdog& Watchdog() const { return wdt_; }

    VirtioBlkDevice& VirtioBlk() { return virtio_blk_; }
    VirtioNetDevice& VirtioNet() { return virtio_net_; }
    VirtioConsoleDevice& VirtioConsole() { return virtio_console_; }
    VirtioRngDevice& VirtioRng() { return virtio_rng_; }
    VirtioBalloonDevice& VirtioBalloon() { return virtio_balloon_; }
    VirtioGpuDevice& VirtioGpu() { return virtio_gpu_; }
    const VirtioGpuDevice& VirtioGpu() const { return virtio_gpu_; }
    VirtioInputDevice& VirtioTouch() { return virtio_touch_; }
    const VirtioInputDevice& VirtioTouch() const { return virtio_touch_; }
    VirtioInputDevice& VirtioKbd() { return virtio_kbd_; }
    const VirtioInputDevice& VirtioKbd() const { return virtio_kbd_; }
    VirtioSndDevice& VirtioSnd() { return virtio_snd_; }
    const VirtioSndDevice& VirtioSnd() const { return virtio_snd_; }

    PhoneHardwareHub& Hardware() { return hardware_; }
    const PhoneHardwareHub& Hardware() const { return hardware_; }
    SoftGlesContext& SoftGles() { return soft_gles_; }
    const SoftGlesContext& SoftGles() const { return soft_gles_; }
    UserNatRouter& NatRouter() { return nat_router_; }
    const UserNatRouter& NatRouter() const { return nat_router_; }
    haseeb::prop::PropertyAreaManager& PropManager() { return prop_manager_; }
    const haseeb::prop::PropertyAreaManager& PropManager() const { return prop_manager_; }
    const std::string& SharedStorageRoot() const { return shared_storage_root_; }

    void InjectTouch(int action, int32_t x, int32_t y, int32_t pointer_id);
    void InjectKey(int android_keycode, bool down);

    VirtioMmioDevice& VirtioMmio(uint32_t slot) { return *virtio_transports_[slot]; }

    const GuestRam& Ram() const { return ram_; }
    GuestRam& Ram() { return ram_; }
    const MmioBus& Bus() const { return mmio_bus_; }
    MmioBus& Bus() { return mmio_bus_; }

private:
    void EmitBootloaderStub(uint64_t dtb_addr,
                            uint64_t msg_addr,
                            const std::string& banner_msg);

    GuestRam ram_;
    MmioBus mmio_bus_;
    GicV3 gic_;
    PsciController psci_;
    Pl011Uart uart_;
    Pl031Rtc rtc_;
    Sp805Watchdog wdt_;

    VirtioBlkDevice virtio_blk_;
    VirtioNetDevice virtio_net_;
    VirtioConsoleDevice virtio_console_;
    VirtioRngDevice virtio_rng_;
    VirtioBalloonDevice virtio_balloon_;
    VirtioGpuDevice virtio_gpu_;
    VirtioInputDevice virtio_touch_;
    VirtioInputDevice virtio_kbd_;
    VirtioSndDevice virtio_snd_;
    std::array<std::unique_ptr<VirtioMmioDevice>, kVirtioMmioCount> virtio_transports_;

    PhoneHardwareHub hardware_;
    SoftGlesContext soft_gles_;
    UserNatRouter nat_router_;
    haseeb::prop::PropertyAreaManager prop_manager_;
    std::unique_ptr<haseeb::prop::PropertyService> prop_service_;
    std::string runtime_dir_;
    std::string shared_storage_root_;
    std::vector<std::pair<std::string, std::string>> device_props_;

    AArch64CpuCore cpu_;
    const loader::Ext4Reader* ext4_reader_ = nullptr;
    std::unique_ptr<LinuxGuestSupervisor> supervisor_;
    std::vector<CpioEntry> initramfs_entries_;

    GuestLaunchMode launch_mode_ = GuestLaunchMode::None;
    uint64_t ram_bytes_ = 0;
    uint64_t dtb_guest_addr_ = 0;
    uint64_t kernel_guest_addr_ = 0;
    uint64_t kernel_size_ = 0;
    bool kernel_valid_arm64_ = false;
    bool kernel_has_exec_header_ = false;
    uint64_t initrd_guest_addr_ = 0;
    uint64_t initrd_size_ = 0;
    std::string staged_cmdline_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> reset_requested_{false};
};

} // namespace haseeb::vm
