#include "haseeb/cpu_core.hpp"
#include "haseeb/gicv3.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/pl011_uart.hpp"
#include "haseeb/pl031_rtc.hpp"
#include "haseeb/psci.hpp"
#include "haseeb/sp805_wdt.hpp"
#include "haseeb/virtio_devices.hpp"
#include "haseeb/virtio_mmio.hpp"
#include "haseeb/vm_types.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#define HASEEB_CHECK(cond)                                                              \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__              \
                      << ": " #cond << "\n";                                            \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

using namespace haseeb::vm;

namespace {

// Minimal AArch64 assembler helpers for self-contained M3 verification
uint32_t Movz(uint8_t rd, uint16_t imm16, uint8_t hw = 0) {
    return 0xD2800000u | (static_cast<uint32_t>(hw) << 21) | (static_cast<uint32_t>(imm16) << 5) | rd;
}

uint32_t Movk(uint8_t rd, uint16_t imm16, uint8_t hw) {
    return 0xF2800000u | (static_cast<uint32_t>(hw) << 21) | (static_cast<uint32_t>(imm16) << 5) | rd;
}

void EmitImm64(std::vector<uint32_t>& code, uint8_t rd, uint64_t val) {
    code.push_back(Movz(rd, static_cast<uint16_t>(val & 0xFFFFu), 0));
    code.push_back(Movk(rd, static_cast<uint16_t>((val >> 16) & 0xFFFFu), 1));
    code.push_back(Movk(rd, static_cast<uint16_t>((val >> 32) & 0xFFFFu), 2));
    code.push_back(Movk(rd, static_cast<uint16_t>((val >> 48) & 0xFFFFu), 3));
}

uint32_t AddImm(uint8_t rd, uint8_t rn, uint16_t imm12) {
    return 0x91000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) | (rn << 5) | rd;
}

uint32_t Str32(uint8_t rt, uint8_t rn, uint16_t imm_bytes = 0) {
    return 0xB9000000u | (((imm_bytes / 4u) & 0xFFFu) << 10) | (rn << 5) | rt;
}

uint32_t Hvc(uint16_t imm16 = 0) {
    return 0xD4000002u | (static_cast<uint32_t>(imm16) << 5);
}

uint32_t Wfi() { return 0xD503207Fu; }
uint32_t Eret() { return 0xD69F03E0u; }
uint32_t Hlt(uint16_t imm16 = 0) { return 0xD4400000u | (static_cast<uint32_t>(imm16) << 5); }

uint32_t Mrs(uint8_t rt, uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
    return 0xD5200000u | ((op0 & 3u) << 19) | ((op1 & 7u) << 16) | ((crn & 15u) << 12) |
           ((crm & 15u) << 8) | ((op2 & 7u) << 5) | rt;
}

uint32_t Msr(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2, uint8_t rt) {
    return 0xD5000000u | ((op0 & 3u) << 19) | ((op1 & 7u) << 16) | ((crn & 15u) << 12) |
           ((crm & 15u) << 8) | ((op2 & 7u) << 5) | rt;
}

uint32_t MsrDaifClr(uint8_t imm4) {
    return 0xD50340DFu | (static_cast<uint32_t>(imm4 & 0xFu) << 8);
}

struct SplitQueueLayout {
    uint64_t desc_pa = 0;
    uint64_t avail_pa = 0;
    uint64_t used_pa = 0;
    uint32_t qsize = 16;
    uint16_t next_avail = 0;
    uint16_t next_used_seen = 0;
};

struct RawVringDescTest {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

SplitQueueLayout SetupVirtq(GuestRam& ram,
                            VirtioMmioDevice& dev,
                            uint32_t qidx,
                            uint64_t base_pa,
                            uint32_t qsize = 16) {
    SplitQueueLayout q;
    q.desc_pa = base_pa;
    q.avail_pa = base_pa + 0x1000ULL;
    q.used_pa = base_pa + 0x2000ULL;
    q.qsize = qsize;

    // Zero ring memory
    std::vector<uint8_t> zeros(0x3000, 0);
    HASEEB_CHECK(ram.WriteBytes(base_pa, zeros.data(), zeros.size()));

    dev.Write(0x030, 4, qidx); // QueueSel
    HASEEB_CHECK(dev.Read(0x034, 4) >= qsize);
    dev.Write(0x038, 4, qsize);
    dev.Write(0x080, 4, static_cast<uint32_t>(q.desc_pa & 0xFFFFFFFFULL));
    dev.Write(0x084, 4, static_cast<uint32_t>(q.desc_pa >> 32));
    dev.Write(0x090, 4, static_cast<uint32_t>(q.avail_pa & 0xFFFFFFFFULL));
    dev.Write(0x094, 4, static_cast<uint32_t>(q.avail_pa >> 32));
    dev.Write(0x0A0, 4, static_cast<uint32_t>(q.used_pa & 0xFFFFFFFFULL));
    dev.Write(0x0A4, 4, static_cast<uint32_t>(q.used_pa >> 32));
    dev.Write(0x044, 4, 1); // QueueReady = 1
    return q;
}

void PostSingleDesc(GuestRam& ram, SplitQueueLayout& q, uint16_t desc_idx,
                    uint64_t buf_pa, uint32_t len, bool writable) {
    RawVringDescTest d{buf_pa, len, writable ? uint16_t(2u) : uint16_t(0u), 0};
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(desc_idx) * 16ULL, &d, sizeof(d)));

    uint16_t slot = q.next_avail % q.qsize;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + slot * 2ULL, &desc_idx, sizeof(desc_idx)));
    ++q.next_avail;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));
}

void PostTwoDescChain(GuestRam& ram, SplitQueueLayout& q,
                      uint16_t idx0, uint64_t pa0, uint32_t len0, bool w0,
                      uint16_t idx1, uint64_t pa1, uint32_t len1, bool w1) {
    RawVringDescTest d0{pa0, len0, static_cast<uint16_t>(1u | (w0 ? 2u : 0u)), idx1};
    RawVringDescTest d1{pa1, len1, static_cast<uint16_t>(w1 ? 2u : 0u), 0};
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(idx0) * 16ULL, &d0, sizeof(d0)));
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(idx1) * 16ULL, &d1, sizeof(d1)));

    uint16_t slot = q.next_avail % q.qsize;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + slot * 2ULL, &idx0, sizeof(idx0)));
    ++q.next_avail;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));
}

uint32_t PopUsedEntry(GuestRam& ram, SplitQueueLayout& q, uint16_t& out_id) {
    uint16_t used_idx = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 2ULL, &used_idx, sizeof(used_idx)));
    HASEEB_CHECK(used_idx != q.next_used_seen);
    uint16_t slot = q.next_used_seen % q.qsize;
    uint32_t elem_id = 0;
    uint32_t elem_len = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + slot * 8ULL, &elem_id, 4));
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + slot * 8ULL + 4ULL, &elem_len, 4));
    ++q.next_used_seen;
    out_id = static_cast<uint16_t>(elem_id);
    return elem_len;
}

uint32_t BusRead32(const MmioBus& bus, uint64_t paddr) {
    uint64_t val = 0;
    HASEEB_CHECK(bus.Read(paddr, 4u, val));
    return static_cast<uint32_t>(val);
}

// =========================================================================
// Test 1: GICv3 GICD / GICR / ICC_*_EL1 (SPI, PPI, SGI)
// =========================================================================
void TestGicV3GicdGicrAndSgiPpiSpi() {
    GicV3 gic(4);

    // Architectural GICv3 IDs
    HASEEB_CHECK(gic.ReadGicd(0xFFE8, 4) == 0x30u); // GICD_PIDR2 ArchRev=3
    HASEEB_CHECK(gic.ReadGicr(0xFFE8, 4) == 0x30u); // GICR_PIDR2 ArchRev=3
    HASEEB_CHECK(gic.ReadSysReg(0, GicV3::kIccSreEl1) == 0x7ULL);

    // Enable Group 1 NS on distributor + wake CPU0 & CPU1 redistributors
    gic.WriteGicd(0x0000, 4, 0x2u);
    gic.WriteGicr(0x0014, 4, 0x0u);          // CPU 0 GICR_WAKER
    gic.WriteGicr(0x20000ULL + 0x0014, 4, 0); // CPU 1 GICR_WAKER

    gic.WriteSysReg(0, GicV3::kIccPmrEl1, 0xFFu);
    gic.WriteSysReg(0, GicV3::kIccIgrpen1El1, 1u);
    gic.WriteSysReg(1, GicV3::kIccPmrEl1, 0xFFu);
    gic.WriteSysReg(1, GicV3::kIccIgrpen1El1, 1u);

    // 1. SPI 1 (INTID 33): enable + route to CPU 0 + assert level
    gic.WriteGicd(0x0104, 4, (1u << 1)); // GICD_ISENABLER1 bit 1 = INTID 33
    gic.WriteGicd(0x6000 + 33u * 8u, 8, 0ULL); // Route INTID 33 -> CPU 0
    HASEEB_CHECK(!gic.HasPendingIrq(0));

    gic.SetSpiLevel(1u, true);
    HASEEB_CHECK(gic.HasPendingIrq(0));
    HASEEB_CHECK(!gic.HasPendingIrq(1));
    HASEEB_CHECK(gic.ReadSysReg(0, GicV3::kIccHppir1El1) == 33u);

    uint64_t ack_spi = gic.ReadSysReg(0, GicV3::kIccIar1El1);
    HASEEB_CHECK(ack_spi == 33u);
    HASEEB_CHECK(gic.ReadSysReg(0, GicV3::kIccRprEl1) == 0xA0u);

    // Level cleared before EOI -> no re-pend after EOI
    gic.SetSpiLevel(1u, false);
    gic.WriteSysReg(0, GicV3::kIccEoir1El1, ack_spi);
    HASEEB_CHECK(!gic.HasPendingIrq(0));
    HASEEB_CHECK(gic.ReadSysReg(0, GicV3::kIccIar1El1) == GicV3::kSpuriousIrq);

    // 2. PPI 27 on CPU 0
    gic.WriteGicr(0x10100ULL, 4, (1u << 27)); // GICR_ISENABLER0 bit 27
    gic.SetPpiLevel(0, 27, true);
    HASEEB_CHECK(gic.HasPendingIrq(0));
    HASEEB_CHECK(gic.ReadSysReg(0, GicV3::kIccIar1El1) == 27u);
    gic.SetPpiLevel(0, 27, false);
    gic.WriteSysReg(0, GicV3::kIccEoir1El1, 27u);
    HASEEB_CHECK(!gic.HasPendingIrq(0));

    // 3. SGI 5 from CPU 0 -> CPU 1 via ICC_SGI1R_EL1
    gic.WriteGicr(0x20000ULL + 0x10100ULL, 4, (1u << 5)); // Enable SGI 5 on CPU 1
    uint64_t sgi1r = (5ULL << 24) | (1ULL << 1); // INTID=5, TargetList=CPU1
    gic.WriteSysReg(0, GicV3::kIccSgi1rEl1, sgi1r);
    HASEEB_CHECK(gic.HasPendingIrq(1));
    HASEEB_CHECK(!gic.HasPendingIrq(0));
    HASEEB_CHECK(gic.ReadSysReg(1, GicV3::kIccIar1El1) == 5u);
    gic.WriteSysReg(1, GicV3::kIccEoir1El1, 5u);
    HASEEB_CHECK(!gic.HasPendingIrq(1));

    std::cout << "[PASS] TestGicV3GicdGicrAndSgiPpiSpi\n";
}

// =========================================================================
// Test 2: ARMv8 Generic Timer + GICv3 + AArch64CpuCore IRQ Vector Delivery
// =========================================================================
void TestArmv8TimerIrqViaCpuAndGicv3() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    GicV3 gic(1);
    bus.Register(kGicDistBase, 0x10000ULL, gic.DistributorMmio());
    bus.Register(kGicRedistBase, 0x20000ULL, gic.RedistributorMmio());

    AArch64CpuCore cpu(ram, bus, 0);
    cpu.SetGic(&gic);

    const uint64_t vbar = kGuestRamBase + 0x2000ULL;
    const uint64_t irq_vec = vbar + 0x280ULL; // Current EL with SPx, IRQ
    const uint64_t code_addr = kGuestRamBase;

    // IRQ Vector Handler at VBAR + 0x280:
    //  - MRS x20, ICC_IAR1_EL1  (op0=3,op1=0,crn=12,crm=12,op2=0)
    //  - MRS x21, CNTV_CTL_EL0  (op0=3,op1=3,crn=14,crm=3,op2=1)
    //  - MOVZ x23, #0
    //  - MSR CNTV_CTL_EL0, x23  (disable timer & deassert PPI 27)
    //  - MSR ICC_EOIR1_EL1, x20 (op0=3,op1=0,crn=12,crm=12,op2=1)
    //  - ADD x22, x22, #1
    //  - ERET
    std::vector<uint32_t> irq_code;
    irq_code.push_back(Mrs(20, 3, 0, 12, 12, 0)); // ICC_IAR1_EL1
    irq_code.push_back(Mrs(21, 3, 3, 14, 3, 1));  // CNTV_CTL_EL0
    irq_code.push_back(Movz(23, 0));
    irq_code.push_back(Msr(3, 3, 14, 3, 1, 23));  // CNTV_CTL_EL0 = 0
    irq_code.push_back(Msr(3, 0, 12, 12, 1, 20)); // ICC_EOIR1_EL1 = x20
    irq_code.push_back(AddImm(22, 22, 1));
    irq_code.push_back(Eret());
    HASEEB_CHECK(ram.WriteBytes(irq_vec, irq_code.data(), irq_code.size() * sizeof(uint32_t)));

    // Main guest code:
    //  - Set VBAR_EL1 = vbar
    //  - Enable GICD_CTLR = 2, GICR_WAKER = 0, GICR_ISENABLER0 = (1<<27)
    //  - ICC_PMR_EL1 = 0xFF, ICC_IGRPEN1_EL1 = 1
    //  - CNTV_TVAL_EL0 = 1000 ticks (~16 us @ 62.5 MHz), CNTV_CTL_EL0 = 1 (ENABLE)
    //  - MSR DAIFClr, #2 (unmask IRQ)
    //  - WFI
    //  - HLT #0
    std::vector<uint32_t> main_code;
    EmitImm64(main_code, 0, vbar);
    main_code.push_back(Msr(3, 0, 12, 0, 0, 0)); // VBAR_EL1

    EmitImm64(main_code, 1, kGicDistBase);
    main_code.push_back(Movz(2, 2));
    main_code.push_back(Str32(2, 1, 0));         // GICD_CTLR = 2 (EnableGrp1NS)

    EmitImm64(main_code, 1, kGicRedistBase);
    main_code.push_back(Str32(31, 1, 0x14));     // GICR_WAKER = 0 (wake)

    EmitImm64(main_code, 1, kGicRedistBase + 0x10100ULL);
    EmitImm64(main_code, 2, (1ULL << 27));
    main_code.push_back(Str32(2, 1, 0));         // GICR_ISENABLER0 = PPI 27

    main_code.push_back(Movz(2, 0xFF));
    main_code.push_back(Msr(3, 0, 4, 6, 0, 2));  // ICC_PMR_EL1 = 0xFF
    main_code.push_back(Movz(2, 1));
    main_code.push_back(Msr(3, 0, 12, 12, 7, 2)); // ICC_IGRPEN1_EL1 = 1

    EmitImm64(main_code, 2, 1000);
    main_code.push_back(Msr(3, 3, 14, 3, 0, 2)); // CNTV_TVAL_EL0 = 1000 ticks
    main_code.push_back(Movz(2, 1));
    main_code.push_back(Msr(3, 3, 14, 3, 1, 2)); // CNTV_CTL_EL0 = 1

    main_code.push_back(MsrDaifClr(2));          // Unmask IRQ (DAIF.I = 0)
    main_code.push_back(Wfi());
    main_code.push_back(Hlt(0));
    HASEEB_CHECK(ram.WriteBytes(code_addr, main_code.data(), main_code.size() * sizeof(uint32_t)));

    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);

    for (int attempt = 0; attempt < 200 && !cpu.State().halted; ++attempt) {
        HASEEB_CHECK(cpu.Run(10000) == VmError::Ok);
        if (!cpu.State().halted) {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    }

    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[20] == 27u);           // Acknowledged virtual timer PPI 27
    HASEEB_CHECK((cpu.State().x[21] & 4u) != 0u);     // CNTV_CTL_EL0.ISTATUS was set
    HASEEB_CHECK(cpu.State().x[22] == 1u);            // Handler ran exactly once
    HASEEB_CHECK(cpu.State().exceptions_taken == 1u);
    HASEEB_CHECK(!gic.HasPendingIrq(0));

    std::cout << "[PASS] TestArmv8TimerIrqViaCpuAndGicv3\n";
}

// =========================================================================
// Test 3: PSCI v1.0 Guest HVC #0 Hypercalls
// =========================================================================
void TestPsciV1GuestHypercalls() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 8ULL * 1024ULL * 1024ULL) == VmError::Ok);

    PsciController psci(4);
    AArch64CpuCore cpu(ram, bus, 0);
    cpu.SetHypercallHandler([&](CpuState& st, uint16_t imm16, bool is_smc) {
        return psci.HandleHypercall(st, imm16, is_smc);
    });

    std::vector<uint32_t> code;
    // PSCI_VERSION
    EmitImm64(code, 0, PsciController::kPsciVersion);
    code.push_back(Hvc(0));
    code.push_back(AddImm(10, 0, 0)); // x10 = version

    // PSCI_FEATURES(CPU_ON_64)
    EmitImm64(code, 0, PsciController::kPsciFeatures);
    EmitImm64(code, 1, PsciController::kCpuOn64);
    code.push_back(Hvc(0));
    code.push_back(AddImm(11, 0, 0)); // x11 = features rc (0 = supported)

    // CPU_ON(cpu=1, entry=0x40080000, ctx=0xCAFEBABE)
    EmitImm64(code, 0, PsciController::kCpuOn64);
    EmitImm64(code, 1, 1);
    EmitImm64(code, 2, 0x40080000ULL);
    EmitImm64(code, 3, 0xCAFEBABEULL);
    code.push_back(Hvc(0));
    code.push_back(AddImm(12, 0, 0)); // x12 = 0 (SUCCESS)

    // AFFINITY_INFO(1, 0)
    EmitImm64(code, 0, PsciController::kAffinityInfo64);
    EmitImm64(code, 1, 1);
    EmitImm64(code, 2, 0);
    code.push_back(Hvc(0));
    code.push_back(AddImm(13, 0, 0)); // x13 = 0 (ON)

    // SYSTEM_OFF -> halts VM
    EmitImm64(code, 0, PsciController::kSystemOff);
    code.push_back(Hvc(0));

    HASEEB_CHECK(ram.WriteBytes(kGuestRamBase, code.data(), code.size() * sizeof(uint32_t)));
    cpu.Reset(kGuestRamBase, kGuestRamBase + 0x40000ULL, 1);
    HASEEB_CHECK(cpu.Run(10000) == VmError::Ok);

    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(psci.SystemOffRequested());
    HASEEB_CHECK(cpu.State().x[10] == 0x00010000ULL); // PSCI 1.0
    HASEEB_CHECK(cpu.State().x[11] == 0ULL);
    HASEEB_CHECK(cpu.State().x[12] == 0ULL);
    HASEEB_CHECK(cpu.State().x[13] == 0ULL);
    HASEEB_CHECK(psci.IsCpuOnline(1));

    auto boots = psci.DrainPendingCpuBoots();
    HASEEB_CHECK(boots.size() == 1u);
    HASEEB_CHECK(boots[0].target_cpu == 1u);
    HASEEB_CHECK(boots[0].entry_pc == 0x40080000ULL);
    HASEEB_CHECK(boots[0].context_id == 0xCAFEBABEULL);

    std::cout << "[PASS] TestPsciV1GuestHypercalls\n";
}

// =========================================================================
// Test 4: PL031 RTC + SP805 Watchdog + PL011 UART IRQs wired through GICv3
// =========================================================================
void TestPl031RtcSp805WdtAndPl011UartIrqs() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64;
    cfg.vcpu_count = 1;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    // Enable GICv3 Grp1NS + CPU0 redistributor + SPI 1 (33), SPI 2 (34), SPI 3 (35)
    vm.Gic().WriteGicd(0x0000, 4, 0x2u);
    vm.Gic().WriteGicr(0x0014, 4, 0x0u);
    vm.Gic().WriteGicr(0x10100ULL, 4, 0u);
    vm.Gic().WriteGicd(0x0104, 4, (1u << 1) | (1u << 2) | (1u << 3)); // INTIDs 33, 34, 35
    vm.Gic().WriteSysReg(0, GicV3::kIccPmrEl1, 0xFFu);
    vm.Gic().WriteSysReg(0, GicV3::kIccIgrpen1El1, 1u);

    // 1. PL011 UART RX IRQ (SPI 1 = INTID 33)
    vm.Bus().Write(kPl011UartBase + 0x038ULL, 4, (1u << 4)); // UARTIMSC RXIM
    vm.Uart().PushRxString("AB");
    HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
    HASEEB_CHECK(vm.Gic().ReadSysReg(0, GicV3::kIccHppir1El1) == 33u);
    HASEEB_CHECK(BusRead32(vm.Bus(), kPl011UartBase) == 'A');
    HASEEB_CHECK(BusRead32(vm.Bus(), kPl011UartBase) == 'B');
    HASEEB_CHECK(!vm.Gic().HasPendingIrq(0));

    // 2. PL031 RTC real wall time + match alarm IRQ (SPI 2 = INTID 34)
    uint32_t rtc_now = BusRead32(vm.Bus(), kPl031RtcBase + 0x000ULL);
    HASEEB_CHECK(rtc_now > 1700000000u);
    vm.Bus().Write(kPl031RtcBase + 0x004ULL, 4, rtc_now + 10u); // RTCMR
    vm.Bus().Write(kPl031RtcBase + 0x010ULL, 4, 1u);            // RTCIMSC
    vm.Rtc().Tick();
    HASEEB_CHECK(!vm.Gic().HasPendingIrq(0));
    vm.Rtc().SetTimeOffsetSeconds(15);
    vm.Rtc().Tick();
    HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
    HASEEB_CHECK(vm.Gic().ReadSysReg(0, GicV3::kIccHppir1El1) == 34u);
    vm.Bus().Write(kPl031RtcBase + 0x01CULL, 4, 1u); // RTCICR clear
    HASEEB_CHECK(!vm.Gic().HasPendingIrq(0));

    // 3. SP805 Watchdog lock, IRQ on 1st expiry (SPI 3 = INTID 35), reset on 2nd expiry
    vm.Bus().Write(kSp805WdtBase + 0xC00ULL, 4, 0u);          // Lock
    HASEEB_CHECK(BusRead32(vm.Bus(), kSp805WdtBase + 0xC00ULL) == 1u);
    vm.Bus().Write(kSp805WdtBase + 0x000ULL, 4, 123u);        // Ignored while locked
    HASEEB_CHECK(BusRead32(vm.Bus(), kSp805WdtBase + 0x000ULL) != 123u);

    vm.Bus().Write(kSp805WdtBase + 0xC00ULL, 4, 0x1ACCE551u); // Unlock
    HASEEB_CHECK(BusRead32(vm.Bus(), kSp805WdtBase + 0xC00ULL) == 0u);
    vm.Bus().Write(kSp805WdtBase + 0x000ULL, 4, 5u);          // WDOGLOAD = 5
    vm.Bus().Write(kSp805WdtBase + 0x008ULL, 4, 3u);          // INTEN | RESEN

    vm.Watchdog().Tick(5u); // 1st expiry -> IRQ + reload
    HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
    HASEEB_CHECK(vm.Gic().ReadSysReg(0, GicV3::kIccHppir1El1) == 35u);
    HASEEB_CHECK(!vm.ResetRequested());

    vm.Watchdog().Tick(5u); // 2nd expiry while RIS still asserted -> Reset!
    HASEEB_CHECK(vm.ResetRequested());
    vm.Bus().Write(kSp805WdtBase + 0x00CULL, 4, 1u); // WDOGINTCLR clears IRQ
    HASEEB_CHECK(!vm.Gic().HasPendingIrq(0));

    vm.Shutdown();
    std::cout << "[PASS] TestPl031RtcSp805WdtAndPl011UartIrqs\n";
}

// =========================================================================
// Test 5: Virtio-MMIO v2 Transport + All 5 Backends + GICv3 SPIs 16..20
// =========================================================================
void TestVirtioMmioAndAllFiveBackends() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64;
    cfg.vcpu_count = 1;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    // Enable GICv3 Grp1NS + SPIs 16..20 (INTIDs 48..52)
    vm.Gic().WriteGicd(0x0000, 4, 0x2u);
    vm.Gic().WriteGicr(0x0014, 4, 0x0u);
    vm.Gic().WriteGicd(0x0104, 4, (0x1Fu << 16)); // Bits 16..20 of GICD_ISENABLER1 = INTIDs 48..52
    vm.Gic().WriteSysReg(0, GicV3::kIccPmrEl1, 0xFFu);
    vm.Gic().WriteSysReg(0, GicV3::kIccIgrpen1El1, 1u);

    auto clear_virtio_irq = [&](uint32_t slot, uint32_t expected_intid) {
        HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
        uint64_t ack = vm.Gic().ReadSysReg(0, GicV3::kIccIar1El1);
        HASEEB_CHECK(ack == expected_intid);
        uint64_t mmio_base = kVirtioMmioBase + static_cast<uint64_t>(slot) * kVirtioMmioStride;
        uint32_t isr = BusRead32(vm.Bus(), mmio_base + 0x060ULL);
        HASEEB_CHECK(isr != 0u);
        vm.Bus().Write(mmio_base + 0x064ULL, 4, isr); // InterruptACK
        vm.Gic().WriteSysReg(0, GicV3::kIccEoir1El1, ack);
        HASEEB_CHECK(!vm.Gic().HasPendingIrq(0));
    };

    GuestRam& ram = vm.Ram();
    const uint64_t ring_region = kGuestRamBase + 0x100000ULL;
    const uint64_t data_region = kGuestRamBase + 0x200000ULL;

    // ---------------------------------------------------------------------
    // Slot 0: virtio-blk (ID=2, SPI 16 -> INTID 48)
    // ---------------------------------------------------------------------
    vm.VirtioBlk().AttachMemoryDisk(64u * 1024u, false);
    VirtioMmioDevice& blk_dev = vm.VirtioMmio(0);
    HASEEB_CHECK(blk_dev.Read(0x000, 4) == VirtioMmioDevice::kMagicValue);
    HASEEB_CHECK(blk_dev.Read(0x004, 4) == 2u);
    HASEEB_CHECK(blk_dev.Read(0x008, 4) == 2u);
    HASEEB_CHECK(blk_dev.Read(0x100, 4) == 128u); // 64 KiB / 512 B = 128 sectors
    SplitQueueLayout blk_q = SetupVirtq(ram, blk_dev, 0, ring_region);

    struct { uint32_t type; uint32_t reserved; uint64_t sector; } req_out{1u, 0u, 3u};
    uint8_t sector_write[512]{};
    std::memcpy(sector_write, "HASEEB-VBLK-SECTOR3", 19);
    uint8_t write_req_buf[16 + 512]{};
    std::memcpy(write_req_buf, &req_out, 16);
    std::memcpy(write_req_buf + 16, sector_write, 512);
    uint8_t status_byte = 0xFFu;

    HASEEB_CHECK(ram.WriteBytes(data_region, write_req_buf, sizeof(write_req_buf)));
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x1000ULL, &status_byte, 1));
    PostTwoDescChain(ram, blk_q,
                     0, data_region, sizeof(write_req_buf), false,
                     1, data_region + 0x1000ULL, 1, true);
    blk_dev.Write(0x050, 4, 0); // Notify queue 0
    clear_virtio_irq(0, 48u);
    uint16_t used_id = 0;
    PopUsedEntry(ram, blk_q, used_id);
    HASEEB_CHECK(ram.ReadBytes(data_region + 0x1000ULL, &status_byte, 1) && status_byte == 0u);

    // Read back sector 3 + status
    struct { uint32_t type; uint32_t reserved; uint64_t sector; } req_in{0u, 0u, 3u};
    uint8_t read_back[513]{};
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x2000ULL, &req_in, 16));
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x3000ULL, read_back, sizeof(read_back)));
    PostTwoDescChain(ram, blk_q,
                     2, data_region + 0x2000ULL, 16, false,
                     3, data_region + 0x3000ULL, 513, true);
    blk_dev.Write(0x050, 4, 0);
    clear_virtio_irq(0, 48u);
    HASEEB_CHECK(PopUsedEntry(ram, blk_q, used_id) == 513u);
    HASEEB_CHECK(ram.ReadBytes(data_region + 0x3000ULL, read_back, sizeof(read_back)));
    HASEEB_CHECK(std::memcmp(read_back, "HASEEB-VBLK-SECTOR3", 19) == 0);
    HASEEB_CHECK(read_back[512] == 0u);

    // ---------------------------------------------------------------------
    // Slot 1: virtio-net (ID=1, SPI 17 -> INTID 49)
    // ---------------------------------------------------------------------
    VirtioMmioDevice& net_dev = vm.VirtioMmio(1);
    HASEEB_CHECK(net_dev.Read(0x008, 4) == 1u);
    HASEEB_CHECK((net_dev.Read(0x100, 1) & 0xFFu) == 0x52u); // MAC byte 0
    HASEEB_CHECK((net_dev.Read(0x106, 1) & 0xFFu) == 0x01u); // LINK_UP

    SplitQueueLayout net_rx = SetupVirtq(ram, net_dev, 0, ring_region + 0x10000ULL);
    SplitQueueLayout net_tx = SetupVirtq(ram, net_dev, 1, ring_region + 0x20000ULL);

    // TX frame: 12-byte virtio_net_hdr_v1 + ethernet frame
    std::vector<uint8_t> tx_pkt(12 + 14, 0u);
    tx_pkt[12] = 0xFF; tx_pkt[13] = 0xFF; tx_pkt[24] = 0x08; tx_pkt[25] = 0x00;
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x10000ULL, tx_pkt.data(), tx_pkt.size()));
    PostSingleDesc(ram, net_tx, 0, data_region + 0x10000ULL, static_cast<uint32_t>(tx_pkt.size()), false);
    net_dev.Write(0x050, 4, 1);
    clear_virtio_irq(1, 49u);
    PopUsedEntry(ram, net_tx, used_id);
    auto tx_frames = vm.VirtioNet().DrainTxFrames();
    HASEEB_CHECK(tx_frames.size() == 1u && tx_frames[0].size() == 14u && tx_frames[0][12] == 0x08);

    // RX injection
    PostSingleDesc(ram, net_rx, 0, data_region + 0x11000ULL, 128u, true);
    vm.VirtioNet().InjectRxFrame(net_dev, {0xAA, 0xBB, 0xCC, 0xDD});
    clear_virtio_irq(1, 49u);
    HASEEB_CHECK(PopUsedEntry(ram, net_rx, used_id) == 16u);
    uint8_t rx_buf[16]{};
    HASEEB_CHECK(ram.ReadBytes(data_region + 0x11000ULL, rx_buf, 16));
    HASEEB_CHECK(rx_buf[12] == 0xAA && rx_buf[15] == 0xDD);

    // ---------------------------------------------------------------------
    // Slot 2: virtio-console (ID=3, SPI 18 -> INTID 50)
    // ---------------------------------------------------------------------
    VirtioMmioDevice& con_dev = vm.VirtioMmio(2);
    HASEEB_CHECK(con_dev.Read(0x008, 4) == 3u);
    SplitQueueLayout con_rx = SetupVirtq(ram, con_dev, 0, ring_region + 0x30000ULL);
    SplitQueueLayout con_tx = SetupVirtq(ram, con_dev, 1, ring_region + 0x40000ULL);

    const char msg[] = "hello-virtcon\n";
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x20000ULL, msg, sizeof(msg) - 1));
    PostSingleDesc(ram, con_tx, 0, data_region + 0x20000ULL, static_cast<uint32_t>(sizeof(msg) - 1), false);
    con_dev.Write(0x050, 4, 1);
    clear_virtio_irq(2, 50u);
    PopUsedEntry(ram, con_tx, used_id);
    HASEEB_CHECK(vm.VirtioConsole().CapturedOutput() == "hello-virtcon\n");

    PostSingleDesc(ram, con_rx, 0, data_region + 0x21000ULL, 64u, true);
    vm.VirtioConsole().PushRxBytes(con_dev, "ping");
    clear_virtio_irq(2, 50u);
    HASEEB_CHECK(PopUsedEntry(ram, con_rx, used_id) == 4u);
    char con_in[5]{};
    HASEEB_CHECK(ram.ReadBytes(data_region + 0x21000ULL, con_in, 4));
    HASEEB_CHECK(std::string(con_in, 4) == "ping");

    // ---------------------------------------------------------------------
    // Slot 3: virtio-rng (ID=4, SPI 19 -> INTID 51)
    // ---------------------------------------------------------------------
    VirtioMmioDevice& rng_dev = vm.VirtioMmio(3);
    HASEEB_CHECK(rng_dev.Read(0x008, 4) == 4u);
    SplitQueueLayout rng_q = SetupVirtq(ram, rng_dev, 0, ring_region + 0x50000ULL);
    uint8_t rng_zeros[32]{};
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x30000ULL, rng_zeros, 32));
    PostSingleDesc(ram, rng_q, 0, data_region + 0x30000ULL, 32u, true);
    rng_dev.Write(0x050, 4, 0);
    clear_virtio_irq(3, 51u);
    HASEEB_CHECK(PopUsedEntry(ram, rng_q, used_id) == 32u);
    uint8_t rng_out[32]{};
    HASEEB_CHECK(ram.ReadBytes(data_region + 0x30000ULL, rng_out, 32));
    bool non_zero = false;
    for (uint8_t b : rng_out) {
        if (b != 0u) non_zero = true;
    }
    HASEEB_CHECK(non_zero);

    // ---------------------------------------------------------------------
    // Slot 4: virtio-balloon (ID=5, SPI 20 -> INTID 52)
    // ---------------------------------------------------------------------
    VirtioMmioDevice& bal_dev = vm.VirtioMmio(4);
    HASEEB_CHECK(bal_dev.Read(0x008, 4) == 5u);
    SplitQueueLayout bal_inf = SetupVirtq(ram, bal_dev, 0, ring_region + 0x60000ULL);
    SplitQueueLayout bal_def = SetupVirtq(ram, bal_dev, 1, ring_region + 0x70000ULL);

    uint32_t pfns_in[3]{10u, 20u, 30u};
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x40000ULL, pfns_in, sizeof(pfns_in)));
    PostSingleDesc(ram, bal_inf, 0, data_region + 0x40000ULL, sizeof(pfns_in), false);
    bal_dev.Write(0x050, 4, 0);
    clear_virtio_irq(4, 52u);
    PopUsedEntry(ram, bal_inf, used_id);
    HASEEB_CHECK(vm.VirtioBalloon().ActualPages() == 3u);

    uint32_t pfn_out = 20u;
    HASEEB_CHECK(ram.WriteBytes(data_region + 0x41000ULL, &pfn_out, sizeof(pfn_out)));
    PostSingleDesc(ram, bal_def, 0, data_region + 0x41000ULL, sizeof(pfn_out), false);
    bal_dev.Write(0x050, 4, 1);
    clear_virtio_irq(4, 52u);
    PopUsedEntry(ram, bal_def, used_id);
    HASEEB_CHECK(vm.VirtioBalloon().ActualPages() == 2u);

    vm.VirtioBalloon().SetTargetPages(bal_dev, 10u);
    HASEEB_CHECK((bal_dev.Read(0x060, 4) & 2u) != 0u); // config change interrupt
    HASEEB_CHECK(bal_dev.Read(0x100, 4) == 10u);
    clear_virtio_irq(4, 52u);

    vm.Shutdown();
    std::cout << "[PASS] TestVirtioMmioAndAllFiveBackends\n";
}

} // namespace

int main() {
    TestGicV3GicdGicrAndSgiPpiSpi();
    TestArmv8TimerIrqViaCpuAndGicv3();
    TestPsciV1GuestHypercalls();
    TestPl031RtcSp805WdtAndPl011UartIrqs();
    TestVirtioMmioAndAllFiveBackends();
    std::cout << "All M3 Devices, GICv3, Timers, PSCI & Virtio-MMIO tests PASSED.\n";
    return 0;
}
