#include "haseeb/machine.hpp"
#include "haseeb/guest_vfs_bridge.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <unistd.h>

namespace haseeb::vm {

namespace {

// AArch64 second-stage bootloader opcode encoders
uint32_t EncodeMovz(uint8_t xd, uint16_t imm16, uint8_t hw) {
    return 0xD2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}

uint32_t EncodeMovk(uint8_t xd, uint16_t imm16, uint8_t hw) {
    return 0xF2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}

void EmitLoadImm64(std::vector<uint32_t>& code, uint8_t xd, uint64_t val) {
    code.push_back(EncodeMovz(xd, static_cast<uint16_t>(val & 0xFFFFu), 0));
    code.push_back(EncodeMovk(xd, static_cast<uint16_t>((val >> 16) & 0xFFFFu), 1));
    code.push_back(EncodeMovk(xd, static_cast<uint16_t>((val >> 32) & 0xFFFFu), 2));
    code.push_back(EncodeMovk(xd, static_cast<uint16_t>((val >> 48) & 0xFFFFu), 3));
}

uint32_t EncodeLdrbPostInc(uint8_t wt, uint8_t xn, int16_t simm9) {
    uint32_t u9 = static_cast<uint32_t>(simm9) & 0x1FFu;
    return 0x38400400u | (u9 << 12) | (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t EncodeStrbZero(uint8_t wt, uint8_t xn) {
    return 0x39000000u | (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t EncodeCbz64(uint8_t xt, int32_t rel_insns) {
    uint32_t u19 = static_cast<uint32_t>(rel_insns) & 0x7FFFFu;
    return 0xB4000000u | (u19 << 5) | (xt & 31u);
}

uint32_t EncodeB(int32_t rel_insns) {
    uint32_t u26 = static_cast<uint32_t>(rel_insns) & 0x03FFFFFFu;
    return 0x14000000u | u26;
}

uint32_t EncodeHlt(uint16_t imm16) {
    return 0xD4400000u | (static_cast<uint32_t>(imm16) << 5);
}

uint32_t EncodeMovz32(uint8_t wd, uint16_t imm16) {
    return 0x52800000u | (static_cast<uint32_t>(imm16) << 5) | (wd & 31u);
}

uint32_t EncodeAddSubImm32(bool is_sub, bool set_flags, uint8_t wd, uint8_t wn, uint16_t imm12) {
    return 0x11000000u |
           (is_sub ? (1u << 30) : 0u) |
           (set_flags ? (1u << 29) : 0u) |
           (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(wn & 31u) << 5) |
           (wd & 31u);
}

uint32_t EncodeAndReg32(uint8_t wd, uint8_t wn, uint8_t wm) {
    return 0x0A000000u |
           (static_cast<uint32_t>(wm & 31u) << 16) |
           (static_cast<uint32_t>(wn & 31u) << 5) |
           (wd & 31u);
}

uint32_t EncodeCsetEq32(uint8_t wd) {
    // CSINC Wd, WZR, WZR, NE (cond = 1)
    return 0x1A9F17E0u | (wd & 31u);
}

uint32_t EncodeStrbPostInc(uint8_t wt, uint8_t xn, int16_t simm9) {
    uint32_t u9 = static_cast<uint32_t>(simm9) & 0x1FFu;
    return 0x38000400u | (u9 << 12) | (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

} // namespace

VirtualMachineSkeleton::VirtualMachineSkeleton(Pl011Uart::TxLineCallback uart_cb)
    : gic_(4),
      psci_(4),
      uart_(std::move(uart_cb)),
      virtio_touch_(VirtioInputDevice::Role::MultiTouch),
      virtio_kbd_(VirtioInputDevice::Role::KeyboardGamepad),
      cpu_(ram_, mmio_bus_, 0) {
    virtio_transports_[0] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_blk_);
    virtio_transports_[1] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_net_);
    virtio_transports_[2] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_console_);
    virtio_transports_[3] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_rng_);
    virtio_transports_[4] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_balloon_);
    virtio_transports_[5] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_gpu_);
    virtio_transports_[6] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_touch_);
    virtio_transports_[7] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_kbd_);
    virtio_transports_[8] = std::make_unique<VirtioMmioDevice>(ram_, &virtio_snd_);
}

VirtualMachineSkeleton::~VirtualMachineSkeleton() {
    Shutdown();
}

void VirtualMachineSkeleton::SetRuntimePaths(const std::string& runtime_dir,
                                             const std::string& shared_storage_root) {
    runtime_dir_ = runtime_dir;
    shared_storage_root_ = shared_storage_root;
}

void VirtualMachineSkeleton::SetDeviceProperties(
    const std::vector<std::pair<std::string, std::string>>& props) {
    device_props_ = props;
    for (const auto& kv : device_props_) {
        prop_manager_.SetOverride(kv.first, kv.second);
        prop_manager_.SetProperty(kv.first, kv.second, true);
    }
}

void VirtualMachineSkeleton::Shutdown() {
    stop_requested_.store(true);
    cpu_.RequestStop();
    cpu_.SetGic(nullptr);
    cpu_.SetHypercallHandler(nullptr);
    if (prop_service_) {
        prop_service_->Stop();
        prop_service_.reset();
    }
    supervisor_.reset();
    initramfs_entries_.clear();
    launch_mode_ = GuestLaunchMode::None;

    uart_.SetIrqCallback(nullptr);
    rtc_.SetIrqCallback(nullptr);
    wdt_.SetIrqCallback(nullptr);
    wdt_.SetResetCallback(nullptr);
    psci_.SetSystemActionCallback(nullptr);
    virtio_net_.SetTxCallback(nullptr);
    for (auto& vt : virtio_transports_) {
        if (vt) vt->SetIrqCallback(nullptr);
    }

    uart_.FlushLine();
    mmio_bus_.Clear();
    ram_.Free();
    ram_bytes_ = 0;
    dtb_guest_addr_ = 0;
    kernel_guest_addr_ = 0;
    kernel_size_ = 0;
    kernel_valid_arm64_ = false;
    kernel_has_exec_header_ = false;
    initrd_guest_addr_ = 0;
    initrd_size_ = 0;
    staged_cmdline_.clear();
}

void VirtualMachineSkeleton::EmitBootloaderStub(uint64_t dtb_addr,
                                                uint64_t msg_addr,
                                                const std::string& banner_msg) {
    std::string nul_msg = banner_msg;
    nul_msg.push_back('\0');
    ram_.WriteBytes(msg_addr, nul_msg.data(), nul_msg.size());

    std::vector<uint32_t> code;
    EmitLoadImm64(code, 0, dtb_addr);        // Linux arm64 boot protocol: x0 = physical DTB ptr
    EmitLoadImm64(code, 1, 0);               // x1 = 0
    EmitLoadImm64(code, 2, 0);               // x2 = 0
    EmitLoadImm64(code, 3, 0);               // x3 = 0
    EmitLoadImm64(code, 10, kPl011UartBase); // x10 = UARTDR base
    EmitLoadImm64(code, 11, msg_addr);       // x11 = banner string cursor

    code.push_back(EncodeLdrbPostInc(12, 11, 1));
    code.push_back(EncodeCbz64(12, 3));
    code.push_back(EncodeStrbZero(12, 10));
    code.push_back(EncodeB(-3));
    code.push_back(EncodeHlt(0));

    ram_.WriteBytes(kBootStubBase, code.data(), code.size() * sizeof(uint32_t));
}

VmError VirtualMachineSkeleton::InitializeAndStage(const MachineBootConfig& config,
                                                     const ParsedBootImage* boot_img,
                                                     std::string& out_error) {
    Shutdown();
    stop_requested_.store(false);
    reset_requested_.store(false);

    const uint32_t vcpus = std::clamp<uint32_t>(config.vcpu_count, 1u, 4u);
    gic_.Reset(vcpus);
    psci_.Reset(vcpus);
    uart_.Reset();
    rtc_.Reset();
    wdt_.Reset();
    for (auto& vt : virtio_transports_) {
        if (vt) vt->ResetDevice();
    }
    virtio_gpu_.ConfigureDisplay(config.width, config.height);
    virtio_touch_.ConfigureDisplay(config.width, config.height);
    hardware_.Reset();
    soft_gles_.Reset(config.width, config.height);
    virtio_snd_.ResetAudio();
    nat_router_.Attach(virtio_net_, virtio_transports_[1].get());

    if (!shared_storage_root_.empty()) {
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_);
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_ + "/Download");
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_ + "/DCIM");
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_ + "/Documents");
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_ + "/Android/data");
        GuestVfsBridge::EnsureDirectoryTree(shared_storage_root_ + "/Magisk");
    }

    const std::string eff_runtime = !runtime_dir_.empty()
                                        ? runtime_dir_
                                        : ("/tmp/haseeb_props_" + std::to_string(static_cast<long>(::getpid())));
    if (prop_manager_.Initialize(eff_runtime)) {
        prop_manager_.SetOverride("ro.hardware", "haseeb_arm64");
        prop_manager_.SetOverride("ro.opengles.version", "196608");
        prop_manager_.SetOverride("ro.debuggable", "1");
        prop_manager_.SetOverride("ro.boot.verifiedbootstate", "orange");
        prop_manager_.SetOverride("ro.product.cpu.abi", "arm64-v8a");
        prop_manager_.SetOverride("ro.sf.lcd_density", std::to_string(config.dpi));
        for (const auto& kv : device_props_) {
            prop_manager_.SetOverride(kv.first, kv.second);
        }
        if (ext4_reader_ && ext4_reader_->IsOpen()) {
            std::string bprop;
            if (ext4_reader_->ReadFileString("/system/build.prop", bprop) ||
                ext4_reader_->ReadFileString("/system/etc/build.prop", bprop) ||
                ext4_reader_->ReadFileString("/build.prop", bprop)) {
                prop_manager_.LoadPropText(bprop);
            }
        }
        prop_manager_.SetProperty("ro.hardware", "haseeb_arm64", true);
        prop_manager_.SetProperty("ro.opengles.version", "196608", true);
        prop_manager_.SetProperty("ro.debuggable", "1", true);
        prop_manager_.SetProperty("ro.boot.verifiedbootstate", "orange", true);
        prop_manager_.SetProperty("ro.product.cpu.abi", "arm64-v8a", true);
        prop_manager_.SetProperty("ro.sf.lcd_density", std::to_string(config.dpi), true);
        for (const auto& kv : device_props_) {
            prop_manager_.SetProperty(kv.first, kv.second, true);
        }
        GuestVfsBridge::EnsureDirectoryTree(eff_runtime + "/dev/socket");
        prop_service_ = std::make_unique<haseeb::prop::PropertyService>(prop_manager_);
        prop_service_->Start(eff_runtime + "/dev/socket/property_service");
    }

    const uint64_t ram_bytes = static_cast<uint64_t>(config.ram_mb) * 1024ULL * 1024ULL;
    VmError err = ram_.Allocate(kGuestRamBase, ram_bytes);
    if (err != VmError::Ok) {
        out_error = "Failed to allocate guest RAM (" + std::to_string(config.ram_mb) + " MiB)";
        return err;
    }
    ram_bytes_ = ram_bytes;

    // Wire IRQ lines matching FdtBuilder device tree SPI assignments
    uart_.SetIrqCallback([this](bool level) { gic_.SetSpiLevel(1u, level); });
    rtc_.SetIrqCallback([this](bool level) { gic_.SetSpiLevel(2u, level); });
    wdt_.SetIrqCallback([this](bool level) { gic_.SetSpiLevel(3u, level); });
    wdt_.SetResetCallback([this]() {
        reset_requested_.store(true);
        stop_requested_.store(true);
        cpu_.RequestStop();
    });
    for (uint32_t slot = 0; slot < virtio_transports_.size(); ++slot) {
        virtio_transports_[slot]->SetIrqCallback([this, slot](bool level) {
            gic_.SetSpiLevel(16u + slot, level);
        });
    }

    psci_.SetSystemActionCallback([this](bool is_reset) {
        if (is_reset) reset_requested_.store(true);
        stop_requested_.store(true);
        cpu_.RequestStop();
    });

    // Register MMIO devices onto guest physical bus
    mmio_bus_.Register(kGicDistBase, 0x10000ULL, gic_.DistributorMmio());
    mmio_bus_.Register(kGicRedistBase, static_cast<uint64_t>(vcpus) * 0x20000ULL,
                       gic_.RedistributorMmio());
    mmio_bus_.Register(kPl011UartBase, 0x1000ULL, &uart_);
    mmio_bus_.Register(kPl031RtcBase, 0x1000ULL, &rtc_);
    mmio_bus_.Register(kSp805WdtBase, 0x1000ULL, &wdt_);
    for (uint32_t slot = 0; slot < virtio_transports_.size(); ++slot) {
        mmio_bus_.Register(kVirtioMmioBase + static_cast<uint64_t>(slot) * kVirtioMmioStride,
                           kVirtioMmioStride,
                           virtio_transports_[slot].get());
    }

    staged_cmdline_ = "console=ttyAMA0 earlycon=pl011,0x09000000 androidboot.hardware=virt";
    if (boot_img && !boot_img->cmdline.empty()) {
        staged_cmdline_ += " " + boot_img->cmdline;
    }
    if (!config.extra_cmdline.empty()) {
        staged_cmdline_ += " " + config.extra_cmdline;
    }

    // Reserve DTB address at upper RAM before staging kernel & initrd
    const uint64_t ram_top = kGuestRamBase + ram_bytes;
    dtb_guest_addr_ = (ram_top - std::min<uint64_t>(ram_bytes / 4, kFdtMaxOffsetEnd)) & ~0x3FFFULL;

    ParsedBootImage working_boot;
    if (boot_img) {
        working_boot = *boot_img;
        if (!working_boot.kernel.empty() &&
            working_boot.kernel_info.compression != KernelCompression::UncompressedArm64Image) {
            std::string k_err;
            VmError dec_err = BootImageParser::DecompressKernelAndInspect(working_boot, k_err);
            if (dec_err != VmError::Ok &&
                working_boot.kernel_info.compression != KernelCompression::Unknown) {
                out_error = k_err;
                return dec_err;
            }
        }
    }

    uint64_t kernel_offset = 0x80000ULL;
    if (boot_img && !working_boot.kernel.empty()) {
        if (working_boot.kernel_info.valid_arm64_magic) {
            kernel_offset = working_boot.kernel_info.text_offset;
        }
        kernel_guest_addr_ = kGuestRamBase + kernel_offset;
        if (!ram_.WriteBytes(kernel_guest_addr_, working_boot.kernel.data(), working_boot.kernel.size())) {
            out_error = "Kernel image exceeds guest RAM bounds";
            return VmError::GuestKernelInvalid;
        }
        kernel_size_ = working_boot.kernel.size();
        kernel_valid_arm64_ = working_boot.kernel_info.valid_arm64_magic;
        kernel_has_exec_header_ =
            kernel_valid_arm64_ && working_boot.kernel.size() >= 68u &&
            ReadLe32(working_boot.kernel.data()) != 0u;
    } else {
        kernel_guest_addr_ = kGuestRamBase + kernel_offset;
        kernel_size_ = 0;
        kernel_valid_arm64_ = false;
        kernel_has_exec_header_ = false;
    }

    if (boot_img && !working_boot.ramdisk.empty()) {
        std::vector<uint8_t> cpio_bytes;
        std::string rd_err;
        if (BootImageParser::DecompressRamdisk(working_boot.ramdisk, cpio_bytes, rd_err) == VmError::Ok &&
            !cpio_bytes.empty()) {
            if (CpioArchive::LooksLikeNewc(cpio_bytes)) {
                std::string cpio_err;
                CpioArchive::Parse(cpio_bytes, initramfs_entries_, cpio_err);
            }
        } else {
            cpio_bytes = working_boot.ramdisk;
        }

        // Keep fixed kInitrdLoadBase when it fits below DTB; otherwise place safely below DTB
        const uint64_t ramdisk_sz = cpio_bytes.size();
        uint64_t target_initrd = kInitrdLoadBase;
        if (target_initrd + ramdisk_sz > dtb_guest_addr_) {
            const uint64_t kEnd = std::max<uint64_t>(kGuestRamBase + 0x200000ULL,
                                                     kernel_guest_addr_ + kernel_size_);
            if (dtb_guest_addr_ < ramdisk_sz + 0x4000ULL ||
                ((dtb_guest_addr_ - ramdisk_sz) & ~0x3FFFULL) < kEnd) {
                out_error = "Ramdisk exceeds guest RAM bounds";
                return VmError::OutOfMemory;
            }
            target_initrd = (dtb_guest_addr_ - ramdisk_sz) & ~0x3FFFULL;
        }

        if (!ram_.WriteBytes(target_initrd, cpio_bytes.data(), cpio_bytes.size())) {
            out_error = "Ramdisk exceeds guest RAM bounds";
            return VmError::OutOfMemory;
        }
        initrd_guest_addr_ = target_initrd;
        initrd_size_ = cpio_bytes.size();
        if (!working_boot.magisk_detected) {
            BootImageParser::ScanRamdiskForMagisk(working_boot);
        }
    }

    std::vector<uint8_t> dtb_blob;
    FdtBuildParams fdt_params;
    fdt_params.ram_base = kGuestRamBase;
    fdt_params.ram_size_bytes = ram_bytes;
    fdt_params.vcpu_count = vcpus;
    fdt_params.initrd_start = initrd_guest_addr_;
    fdt_params.initrd_end = initrd_guest_addr_ + initrd_size_;
    fdt_params.bootargs = staged_cmdline_;

    if (!FdtBuilder::Build(fdt_params, dtb_blob, out_error)) {
        return VmError::FdtBuildFailed;
    }

    if (!ram_.WriteBytes(dtb_guest_addr_, dtb_blob.data(), dtb_blob.size())) {
        out_error = "Failed writing compiled DTB into guest RAM";
        return VmError::OutOfMemory;
    }

    std::ostringstream banner;
    banner << "[HASEEB-VM] AArch64 bootloader stub initialized\r\n"
           << "[HASEEB-VM] RAM: " << config.ram_mb << " MiB @ 0x40000000, DTB @ 0x"
           << std::hex << dtb_guest_addr_ << std::dec << " (" << dtb_blob.size() << " B)\r\n"
           << "[HASEEB-VM] Kernel @ 0x" << std::hex << kernel_guest_addr_ << std::dec
           << " (" << kernel_size_ << " B), Initrd @ 0x" << std::hex << initrd_guest_addr_ << std::dec
           << " (" << initrd_size_ << " B, cpio=" << initramfs_entries_.size() << " entries)\r\n"
           << "[HASEEB-VM] Bootargs: " << staged_cmdline_ << "\r\n";
    if (boot_img && working_boot.magisk_detected) {
        hardware_.SetMagiskState(true, true);
        banner << "[HASEEB-VM] Magisk ramdisk signature detected: "
               << working_boot.magisk_evidence << "\r\n";
    }
    banner << "[HASEEB-VM] GICv3, PSCI v1.0, PL011/PL031/SP805 & Virtio-MMIO (blk/net/con/rng/balloon/gpu/touch/kbd/snd) online.\r\n";

    EmitBootloaderStub(dtb_guest_addr_, kBootStubBase + 0x400ULL, banner.str());

    cpu_.Reset(kBootStubBase, dtb_guest_addr_, 1);
    cpu_.SetGic(&gic_);
    cpu_.SetHypercallHandler([this](struct CpuState& st, uint16_t imm16, bool is_smc) {
        return psci_.HandleHypercall(st, imm16, is_smc);
    });
    launch_mode_ = GuestLaunchMode::BootStub;
    return VmError::Ok;
}

VmError VirtualMachineSkeleton::RunBootStubUntilHalt(uint64_t max_steps) {
    if (!ram_.IsAllocated()) return VmError::NotRunning;

    VmError res = cpu_.Run(max_steps);
    uart_.FlushLine();
    if (res != VmError::Ok) return res;
    return (cpu_.State().halted || stop_requested_.load()) ? VmError::Ok : VmError::ExecutionTrap;
}

VmError VirtualMachineSkeleton::RunPowerOf2SelfTest(std::string& out_bits) {
    out_bits.clear();
    if (!ram_.IsAllocated()) return VmError::NotRunning;

    constexpr uint64_t kSelfTestCodeAddr = kBootStubBase + 0x2000ULL;
    constexpr uint64_t kSelfTestBufAddr  = kBootStubBase + 0x2400ULL;
    constexpr uint64_t kSelfTestMsgAddr  = kBootStubBase + 0x2440ULL;

    const char zeros[4] = {0, 0, 0, 0};
    if (!ram_.WriteBytes(kSelfTestBufAddr, zeros, sizeof(zeros))) {
        return VmError::OutOfMemory;
    }

    const std::string prefix = "[SELF-TEST] powerof2(8,64,1,7)=";
    std::string prefix_nul = prefix;
    prefix_nul.push_back('\0');
    if (!ram_.WriteBytes(kSelfTestMsgAddr, prefix_nul.data(), prefix_nul.size())) {
        return VmError::OutOfMemory;
    }

    std::vector<uint32_t> code;
    EmitLoadImm64(code, 10, kPl011UartBase);   // X10 = PL011 UARTDR
    EmitLoadImm64(code, 11, kSelfTestBufAddr); // X11 = guest RAM capture buffer
    EmitLoadImm64(code, 12, kSelfTestMsgAddr); // X12 = label prefix cursor

    // Print "[SELF-TEST] powerof2(8,64,1,7)="
    code.push_back(EncodeLdrbPostInc(13, 12, 1));
    code.push_back(EncodeCbz64(13, 3));
    code.push_back(EncodeStrbZero(13, 10));
    code.push_back(EncodeB(-3));

    // Execute exact M-A sequence for v = 8, 64, 1, 7:
    // MOVZ W0,#v ; SUB W1,W0,#1 ; AND W2,W0,W1 ; CMP W2,#0 ; CSET W3,EQ ; ADD W3,W3,#48 ; STRB W3,[X10]
    constexpr uint16_t kTestValues[4] = {8u, 64u, 1u, 7u};
    for (uint16_t v : kTestValues) {
        code.push_back(EncodeMovz32(0, v));
        code.push_back(EncodeAddSubImm32(true, false, 1, 0, 1));    // SUB W1, W0, #1
        code.push_back(EncodeAndReg32(2, 0, 1));                     // AND W2, W0, W1
        code.push_back(EncodeAddSubImm32(true, true, 31, 2, 0));     // CMP W2, #0 (SUBS WZR, W2, #0)
        code.push_back(EncodeCsetEq32(3));                           // CSET W3, EQ
        code.push_back(EncodeAddSubImm32(false, false, 3, 3, 48));   // ADD W3, W3, #48
        code.push_back(EncodeStrbZero(3, 10));                       // STRB W3, [X10] (PL011 UART)
        code.push_back(EncodeStrbPostInc(3, 11, 1));                 // STRB W3, [X11], #1 (RAM capture)
    }

    // Emit CRLF & halt
    code.push_back(EncodeMovz32(3, '\r'));
    code.push_back(EncodeStrbZero(3, 10));
    code.push_back(EncodeMovz32(3, '\n'));
    code.push_back(EncodeStrbZero(3, 10));
    code.push_back(EncodeHlt(0));

    if (!ram_.WriteBytes(kSelfTestCodeAddr, code.data(), code.size() * sizeof(uint32_t))) {
        return VmError::OutOfMemory;
    }

    const struct CpuState saved_state = cpu_.State();
    cpu_.Reset(kSelfTestCodeAddr, dtb_guest_addr_, 1);
    cpu_.SetGic(&gic_);
    cpu_.SetHypercallHandler([this](struct CpuState& st, uint16_t imm16, bool is_smc) {
        return psci_.HandleHypercall(st, imm16, is_smc);
    });

    VmError res = cpu_.Run(10000ULL);
    uart_.FlushLine();

    char buf[4]{};
    ram_.ReadBytes(kSelfTestBufAddr, buf, sizeof(buf));
    for (char c : buf) {
        out_bits.push_back(c != '\0' ? c : '?');
    }

    // Restore pre-test halted bootloader register snapshot so M1/stub callers stay unaffected
    cpu_.State() = saved_state;

    if (res != VmError::Ok) return res;
    return VmError::Ok;
}

VmError VirtualMachineSkeleton::PrepareKernelDirectBoot(std::string& out_error) {
    if (!ram_.IsAllocated()) {
        out_error = "VM RAM not initialized";
        return VmError::NotRunning;
    }
    if (!kernel_has_exec_header_) {
        out_error = "No executable ARM64 Image kernel staged";
        return VmError::GuestKernelInvalid;
    }

    stop_requested_.store(false);
    reset_requested_.store(false);
    supervisor_.reset();

    cpu_.Reset(kernel_guest_addr_, dtb_guest_addr_, 1);
    auto& st = cpu_.State();
    st.x[0] = dtb_guest_addr_; // Linux ARM64 boot protocol: X0 = physical DTB pointer
    st.x[1] = 0ULL;
    st.x[2] = 0ULL;
    st.x[3] = 0ULL;
    cpu_.SetGic(&gic_);
    cpu_.SetHypercallHandler([this](struct CpuState& s, uint16_t imm16, bool is_smc) {
        return psci_.HandleHypercall(s, imm16, is_smc);
    });
    launch_mode_ = GuestLaunchMode::KernelDirect;
    return VmError::Ok;
}

VmError VirtualMachineSkeleton::PrepareInitSupervisorBoot(const std::vector<std::string>& argv,
                                                          bool magisk_enabled,
                                                          std::string& out_selected_binary,
                                                          std::string& out_error) {
    if (!ram_.IsAllocated()) {
        out_error = "VM RAM not initialized";
        return VmError::NotRunning;
    }

    stop_requested_.store(false);
    reset_requested_.store(false);

    supervisor_ = std::make_unique<LinuxGuestSupervisor>(
        ram_, uart_, psci_, ext4_reader_, &virtio_gpu_, &virtio_touch_, &virtio_kbd_);
    supervisor_->SetInitramfs(initramfs_entries_);
    supervisor_->SetHardwareHub(&hardware_);
    supervisor_->SetSoftGles(&soft_gles_);
    supervisor_->SetSndDevice(&virtio_snd_);
    supervisor_->SetPropertyManager(&prop_manager_);
    if (!shared_storage_root_.empty()) {
        supervisor_->SetSharedStorageRoot(shared_storage_root_);
    }
    if (magisk_enabled) {
        hardware_.SetMagiskState(true, true);
    }
    supervisor_->SetGuestIdentity(staged_cmdline_, magisk_enabled);

    const uint64_t reserved_end = std::max<uint64_t>(
        kGuestRamBase + 0x00200000ULL,
        kernel_size_ > 0ULL ? (kernel_guest_addr_ + kernel_size_) : 0ULL);

    uint64_t arena_max = dtb_guest_addr_;
    if (initrd_guest_addr_ > reserved_end && initrd_guest_addr_ < arena_max) {
        arena_max = initrd_guest_addr_;
    }

    VmError err = supervisor_->PrepareBoot(
        cpu_, ram_bytes_, reserved_end, argv, out_selected_binary, out_error, arena_max);
    if (err != VmError::Ok) {
        supervisor_.reset();
        return err;
    }

    cpu_.SetGic(&gic_);
    cpu_.SetHypercallHandler([this](struct CpuState& st, uint16_t imm16, bool is_smc) {
        return supervisor_->HandleHypercall(cpu_, st, imm16, is_smc);
    });
    launch_mode_ = GuestLaunchMode::InitSupervisor;
    return VmError::Ok;
}

VmError VirtualMachineSkeleton::BootGuest(bool magisk_enabled,
                                          std::string& out_booted_target,
                                          std::string& out_error) {
    if (!ram_.IsAllocated()) {
        out_error = "VM RAM not initialized";
        return VmError::NotRunning;
    }
    if (kernel_has_exec_header_) {
        VmError err = PrepareKernelDirectBoot(out_error);
        if (err == VmError::Ok) out_booted_target = "arm64-kernel";
        return err;
    }
    return PrepareInitSupervisorBoot({}, magisk_enabled, out_booted_target, out_error);
}

void VirtualMachineSkeleton::InjectTouch(int action, int32_t x, int32_t y, int32_t pointer_id) {
    virtio_touch_.PushTouch(action, x, y, pointer_id);
    if (virtio_transports_[6]) {
        virtio_touch_.FlushEvents(*virtio_transports_[6]);
    }
}

void VirtualMachineSkeleton::InjectKey(int android_keycode, bool down) {
    virtio_kbd_.PushAndroidKey(android_keycode, down);
    if (virtio_transports_[7]) {
        virtio_kbd_.FlushEvents(*virtio_transports_[7]);
    }
}

VmError VirtualMachineSkeleton::StepGuest(uint64_t max_insns) {
    if (!ram_.IsAllocated()) return VmError::NotRunning;
    if (stop_requested_.load() || cpu_.State().halted) return VmError::Ok;

    if (supervisor_) {
        supervisor_->ResumeIfWaiting(cpu_);
    }

    // Wake WFI stdin / evdev reader if new PL011 RX or VirtioInput bytes arrived
    if (cpu_.State().waiting_for_interrupt &&
        (((uart_.Read(0x018ULL, 4) & (1u << 4)) == 0u) ||
         virtio_touch_.HasPendingEvdev() ||
         virtio_kbd_.HasPendingEvdev())) {
        cpu_.State().waiting_for_interrupt = false;
    }

    const uint64_t before_insns = cpu_.State().instructions_executed;
    VmError res = cpu_.Run(max_insns);
    const uint64_t delta = cpu_.State().instructions_executed - before_insns;
    if (delta > 0ULL) {
        hardware_.TickLoad(delta);
    }
    if (supervisor_ && res == VmError::Ok && !cpu_.State().halted) {
        supervisor_->YieldTimeSlice(cpu_);
    }
    if (cpu_.State().halted || stop_requested_.load() ||
        cpu_.State().stop_reason == CpuStopReason::WfiWait) {
        uart_.FlushLine();
    }
    return res;
}

} // namespace haseeb::vm
