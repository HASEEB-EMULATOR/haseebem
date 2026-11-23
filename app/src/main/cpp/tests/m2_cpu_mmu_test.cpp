#include "haseeb/cpu_core.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/vm_types.hpp"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
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

// Minimal AArch64 assembler helpers for self-contained M2 verification
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

uint32_t AddImm(uint8_t rd, uint8_t rn, uint16_t imm12, bool set_flags = false) {
    return 0x91000000u | (set_flags ? (1u << 29) : 0u) | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) | (rn << 5) | rd;
}

uint32_t SubImm(uint8_t rd, uint8_t rn, uint16_t imm12, bool set_flags = false) {
    return 0xD1000000u | (set_flags ? (1u << 29) : 0u) | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) | (rn << 5) | rd;
}

uint32_t AddReg(uint8_t rd, uint8_t rn, uint8_t rm) {
    return 0x8B000000u | (rm << 16) | (rn << 5) | rd;
}

uint32_t Mul64(uint8_t rd, uint8_t rn, uint8_t rm) {
    return 0x9B007C00u | (rm << 16) | (rn << 5) | rd;
}

uint32_t Udiv64(uint8_t rd, uint8_t rn, uint8_t rm) {
    return 0x9AC00800u | (rm << 16) | (rn << 5) | rd;
}

uint32_t LslImm64(uint8_t rd, uint8_t rn, uint8_t shift) {
    uint32_t immr = (64u - shift) & 63u;
    uint32_t imms = 63u - shift;
    return 0xD3400000u | (1u << 22) | (immr << 16) | (imms << 10) | (rn << 5) | rd;
}

uint32_t Csel64(uint8_t rd, uint8_t rn, uint8_t rm, uint8_t cond) {
    return 0x9A800000u | (rm << 16) | (cond << 12) | (rn << 5) | rd;
}

uint32_t Str64(uint8_t rt, uint8_t rn, uint16_t imm_bytes = 0) {
    return 0xF9000000u | (((imm_bytes / 8u) & 0xFFFu) << 10) | (rn << 5) | rt;
}

uint32_t Ldr64(uint8_t rt, uint8_t rn, uint16_t imm_bytes = 0) {
    return 0xF9400000u | (((imm_bytes / 8u) & 0xFFFu) << 10) | (rn << 5) | rt;
}

uint32_t Ldxr64(uint8_t rt, uint8_t rn) {
    return 0xC85F7C00u | (rn << 5) | rt;
}

uint32_t Stxr64(uint8_t rs, uint8_t rt, uint8_t rn) {
    return 0xC8007C00u | (rs << 16) | (rn << 5) | rt;
}

uint32_t Ldaddal64(uint8_t rs, uint8_t rt, uint8_t rn) {
    return 0xF8E00000u | (rs << 16) | (rn << 5) | rt;
}

uint32_t Casal64(uint8_t rs, uint8_t rt, uint8_t rn) {
    return 0xC860FC00u | (rs << 16) | (rn << 5) | rt;
}

uint32_t Clrex() { return 0xD503305Fu; }
uint32_t Bl(int32_t insns) { return 0x94000000u | (static_cast<uint32_t>(insns) & 0x03FFFFFFu); }
uint32_t Ret(uint8_t rn = 30) { return 0xD65F0000u | (rn << 5); }
uint32_t BCond(uint8_t cond, int32_t insns) {
    return 0x54000000u | ((static_cast<uint32_t>(insns) & 0x7FFFFu) << 5) | (cond & 0xFu);
}
uint32_t Svc(uint16_t imm16) { return 0xD4000001u | (static_cast<uint32_t>(imm16) << 5); }
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

void TestAluBranchesAndExclusives() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    AArch64CpuCore cpu(ram, bus, 0);
    const uint64_t code_addr = kGuestRamBase;
    const uint64_t data_addr = kGuestRamBase + 0x10000ULL;

    // Program:
    //  0: x1 = 10, x2 = 3
    //  1: x3 = x1 * x2 (30)
    //  2: x4 = x3 / 5 (6)
    //  3: x5 = x4 << 3 (48)
    //  4: x6 = (x5 == 48) ? 100 : 200
    //  5: atomic LDADDAL x4 -> [data_addr] (initial 1000 -> old=1000, mem=1006)
    //  6: CASAL x10(1006) -> x11(2025) at [data_addr] -> succeeds
    //  7: LDXR x12, [data_addr+8] ; CLREX ; STXR w13, x12, [data_addr+8] -> w13 == 1 (fail)
    //  8: LDXR x14, [data_addr+8] ; STXR w15, x6, [data_addr+8] -> w15 == 0 (success)
    //  9: BL +3 (calls mini subroutine adding 7 to x0)
    // 10: HLT
    // 12: ADD x0, x6, #7 ; RET
    std::vector<uint32_t> code;
    code.push_back(Movz(1, 10));
    code.push_back(Movz(2, 3));
    code.push_back(Movz(7, 5));
    code.push_back(Mul64(3, 1, 2));          // x3 = 30
    code.push_back(Udiv64(4, 3, 7));         // x4 = 6
    code.push_back(LslImm64(5, 4, 3));       // x5 = 48
    code.push_back(SubImm(31, 5, 48, true)); // CMP x5, #48
    code.push_back(Movz(8, 100));
    code.push_back(Movz(9, 200));
    code.push_back(Csel64(6, 8, 9, 0));      // EQ -> x6 = 100

    EmitImm64(code, 20, data_addr);
    code.push_back(Ldaddal64(4, 21, 20));    // x21 = 1000, [data] = 1006
    code.push_back(Movz(10, 1006));
    code.push_back(Movz(11, 2025));
    code.push_back(Casal64(10, 11, 20));     // [data] = 2025, x10 = 1006

    code.push_back(AddImm(22, 20, 8));
    code.push_back(Ldxr64(12, 22));
    code.push_back(Clrex());
    code.push_back(Stxr64(13, 12, 22));      // x13 = 1 (cleared)

    code.push_back(Ldxr64(14, 22));
    code.push_back(Stxr64(15, 6, 22));       // x15 = 0 (success), [data+8] = 100
    code.push_back(Str64(6, 20, 16));        // [data+16] = 100
    code.push_back(Ldr64(16, 20, 16));       // x16 = 100
    code.push_back(AddReg(17, 16, 4));       // x17 = 100 + 6 = 106

    code.push_back(Bl(2));                   // skips HLT (+1) to subroutine (+2)
    code.push_back(Hlt(0));
    code.push_back(AddImm(0, 6, 7));
    code.push_back(Ret());

    ram.WriteU64(data_addr, 1000ULL);
    ram.WriteU64(data_addr + 8ULL, 555ULL);
    ram.WriteBytes(code_addr, code.data(), code.size() * 4u);

    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(10000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[3] == 30ULL);
    HASEEB_CHECK(cpu.State().x[4] == 6ULL);
    HASEEB_CHECK(cpu.State().x[5] == 48ULL);
    HASEEB_CHECK(cpu.State().x[6] == 100ULL);
    HASEEB_CHECK(cpu.State().x[16] == 100ULL);
    HASEEB_CHECK(cpu.State().x[17] == 106ULL);
    HASEEB_CHECK(cpu.State().x[21] == 1000ULL);
    uint64_t v0 = 0, v1 = 0;
    ram.ReadU64(data_addr, v0);
    ram.ReadU64(data_addr + 8ULL, v1);
    HASEEB_CHECK(v0 == 2025ULL);
    HASEEB_CHECK(cpu.State().x[13] == 1ULL);
    HASEEB_CHECK(cpu.State().x[15] == 0ULL);
    HASEEB_CHECK(v1 == 100ULL);
    HASEEB_CHECK(cpu.State().x[0] == 107ULL);

    std::cout << "[PASS] TestAluBranchesAndExclusives\n";
}

void TestNeonAndScalarFp() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    AArch64CpuCore cpu(ram, bus, 0);
    const uint64_t code_addr = kGuestRamBase;
    const uint64_t buf_addr = kGuestRamBase + 0x20000ULL;

    std::vector<uint32_t> code;
    // Scalar FP: x1 = 9 -> SCVTF D0, x1 -> FSQRT D1, D0 -> FCVTZS x2, D1 (expect 3)
    code.push_back(Movz(1, 9));
    code.push_back(0x9E620020u); // SCVTF D0, X1
    code.push_back(0x1E61C001u); // FSQRT D1, D0
    code.push_back(0x9E780022u); // FCVTZS X2, D1

    // Vector NEON: DUP V2.16B, W3 (0x10); DUP V3.16B, W4 (0x05); ADD V4.16B, V2.16B, V3.16B; STR Q4, [X10]
    code.push_back(Movz(3, 0x10));
    code.push_back(Movz(4, 0x05));
    code.push_back(0x4E010C62u); // DUP V2.16B, W3
    code.push_back(0x4E010C83u); // DUP V3.16B, W4
    code.push_back(0x4E238444u); // ADD V4.16B, V2.16B, V3.16B
    EmitImm64(code, 10, buf_addr);
    code.push_back(0x3D800144u); // STR Q4, [X10]
    code.push_back(0x0E013C85u); // UMOV W5, V4.B[0]
    code.push_back(Hlt(0));

    ram.WriteBytes(code_addr, code.data(), code.size() * 4u);
    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(1000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[2] == 3ULL);
    HASEEB_CHECK(cpu.State().x[5] == 0x15ULL);
    uint8_t b0 = 0, b15 = 0;
    ram.ReadU8(buf_addr, b0);
    ram.ReadU8(buf_addr + 15, b15);
    HASEEB_CHECK(b0 == 0x15u && b15 == 0x15u);

    std::cout << "[PASS] TestNeonAndScalarFp\n";
}

void TestStage1Mmu4KAnd16KPlusDirtyAccessed() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 32ULL * 1024ULL * 1024ULL) == VmError::Ok);
    AArch64CpuCore cpu(ram, bus, 0);

    // ---- Test 1: 4 KiB granule (L1 -> L2 -> L3, T0SZ = 25 => 39-bit VA) ----
    const uint64_t l1_pa = kGuestRamBase + 0x00100000ULL;
    const uint64_t l2_pa = kGuestRamBase + 0x00101000ULL;
    const uint64_t l3_pa = kGuestRamBase + 0x00102000ULL;
    const uint64_t target_pa = kGuestRamBase + 0x00200000ULL;

    // Map VA 0x0000_0000_0000_1000 -> PA target_pa
    // L1[0] -> l2_pa | 0x3, L2[0] -> l3_pa | 0x3, L3[1] -> target_pa | page attrs
    ram.WriteU64(l1_pa + 0 * 8, l2_pa | 0x3ULL);
    ram.WriteU64(l2_pa + 0 * 8, l3_pa | 0x3ULL);
    // Initially: Valid page (3), AF=0 (no bit 10), AP=10 (bit7 => SW RO), DBM=1 (bit51), UXN=1
    const uint64_t pte_initial = target_pa | 0x3ULL | (1ULL << 7) | (1ULL << 51) | (1ULL << 54);
    ram.WriteU64(l3_pa + 1 * 8, pte_initial);

    cpu.Reset(kGuestRamBase, 0, 1);
    cpu.State().sys.ttbr0_el1 = l1_pa;
    cpu.State().sys.mair_el1 = 0xFFULL;
    // T0SZ=25 (39-bit VA), TG0=00 (4K), HA=0, HD=0
    cpu.State().sys.tcr_el1 = 25ULL;
    cpu.State().sys.sctlr_el1 |= 1ULL; // M=1
    cpu.Mmu().InvalidateAll();

    // Expect AccessFlagL3 fault when HA=0 and AF=0
    auto r1 = cpu.Mmu().Translate(cpu.State(), 0x1040ULL, MemAccessType::Read, true);
    HASEEB_CHECK(!r1.ok && r1.fault_status == MmuFaultStatus::AccessFlagL3);

    // Enable hardware AF (HA=bit39) and HD (HD=bit40) -> Read sets AF, Write clears AP[2] (dirty!)
    cpu.State().sys.tcr_el1 |= (1ULL << 39) | (1ULL << 40);
    auto r2 = cpu.Mmu().Translate(cpu.State(), 0x1040ULL, MemAccessType::Read, true);
    HASEEB_CHECK(r2.ok && r2.phys_addr == target_pa + 0x40ULL);

    uint64_t updated_pte = 0;
    ram.ReadU64(l3_pa + 1 * 8, updated_pte);
    HASEEB_CHECK((updated_pte & (1ULL << 10)) != 0); // Hardware AF set!

    // Write triggers hardware DBM -> clears AP[2] (bit 7)
    auto r3 = cpu.Mmu().Translate(cpu.State(), 0x1040ULL, MemAccessType::Write, true);
    HASEEB_CHECK(r3.ok && r3.writable);
    ram.ReadU64(l3_pa + 1 * 8, updated_pte);
    HASEEB_CHECK((updated_pte & (1ULL << 7)) == 0);  // Hardware dirty bit cleared AP[2]

    // Next read hits Software TLB!
    const uint64_t hits_before = cpu.Mmu().TlbHits();
    auto r4 = cpu.Mmu().Translate(cpu.State(), 0x1080ULL, MemAccessType::Read, true);
    HASEEB_CHECK(r4.ok && cpu.Mmu().TlbHits() == hits_before + 1);

    // ---- Test 2: 16 KiB granule (TG0 = 10 -> 16K pages, T0SZ = 28 => 36-bit VA starting at L2) ----
    const uint64_t l2_16k = kGuestRamBase + 0x00400000ULL;
    const uint64_t l3_16k = kGuestRamBase + 0x00404000ULL;
    const uint64_t pa_16k = kGuestRamBase + 0x00500000ULL;
    // VA 0x0000_0000_0000_4000 => L2[0] -> l3_16k, L3[1] -> pa_16k (AF=1, RO AP[2]=1, DBM=0)
    ram.WriteU64(l2_16k + 0 * 8, l3_16k | 0x3ULL);
    ram.WriteU64(l3_16k + 1 * 8, pa_16k | 0x3ULL | (1ULL << 10) | (1ULL << 7));

    cpu.State().sys.ttbr0_el1 = l2_16k;
    cpu.State().sys.tcr_el1 = 28ULL | (2ULL << 14); // T0SZ=28, TG0=10 (16K)
    cpu.Mmu().InvalidateAll();

    auto r16_r = cpu.Mmu().Translate(cpu.State(), 0x4123ULL, MemAccessType::Read, true);
    HASEEB_CHECK(r16_r.ok && r16_r.phys_addr == pa_16k + 0x123ULL);
    auto r16_w = cpu.Mmu().Translate(cpu.State(), 0x4123ULL, MemAccessType::Write, true);
    HASEEB_CHECK(!r16_w.ok && r16_w.fault_status == MmuFaultStatus::PermissionL3);

    // AT S1E1R -> PAR_EL1
    uint64_t par = cpu.Mmu().AddressTranslateForPar(cpu.State(), 0x4000ULL, false, false);
    HASEEB_CHECK((par & 1ULL) == 0 && (par & 0x0000FFFFFFFFF000ULL) == pa_16k);

    std::cout << "[PASS] TestStage1Mmu4KAnd16KPlusDirtyAccessed\n";
}

void TestEl0El1ExceptionsSysregsAndSmc() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);
    AArch64CpuCore cpu(ram, bus, 2); // cpu_id = 2

    const uint64_t el1_entry = kGuestRamBase;
    const uint64_t vbar      = kGuestRamBase + 0x00010000ULL;
    const uint64_t el0_entry = kGuestRamBase + 0x00020000ULL;
    const uint64_t smc_code  = kGuestRamBase + 0x00030000ULL;

    // 1. EL1 setup: read MIDR_EL1/MPIDR_EL1, set VBAR_EL1, ELR_EL1=el0_entry, SPSR_EL1=0 (EL0t), ERET
    std::vector<uint32_t> el1;
    el1.push_back(Mrs(10, 3, 0, 0, 0, 0)); // X10 = MIDR_EL1
    el1.push_back(Mrs(11, 3, 0, 0, 0, 5)); // X11 = MPIDR_EL1
    EmitImm64(el1, 1, vbar);
    el1.push_back(Msr(3, 0, 12, 0, 0, 1)); // MSR VBAR_EL1, X1
    EmitImm64(el1, 2, el0_entry);
    el1.push_back(Msr(3, 0, 4, 0, 1, 2));  // MSR ELR_EL1, X2
    el1.push_back(Movz(3, 0));             // EL0t
    el1.push_back(Msr(3, 0, 4, 0, 0, 3));  // MSR SPSR_EL1, X3
    el1.push_back(Eret());
    ram.WriteBytes(el1_entry, el1.data(), el1.size() * 4u);

    // 2. EL0 user code: X0 = 77, SVC #0x42, then returns from EL1 with X0 += 1, then HLT?
    // Wait: EL0 cannot halt directly, so EL0 does SVC #0x42 and SVC handler inspects ESR_EL1 & returns or updates X0 -> ERET -> SVC #0x99 -> EL1 HLTs!
    std::vector<uint32_t> el0;
    el0.push_back(Movz(0, 77));
    el0.push_back(Svc(0x42));
    el0.push_back(AddImm(0, 0, 5));
    el0.push_back(Svc(0x99));
    ram.WriteBytes(el0_entry, el0.data(), el0.size() * 4u);

    // 3. VBAR_EL1 + 0x400 (Lower EL AArch64 Synchronous handler):
    // Check ESR_EL1 low 16 bits: if 0x42 -> X0 += 10, ERET; else HLT #0
    std::vector<uint32_t> vec;
    vec.push_back(Mrs(12, 3, 0, 5, 2, 0));   // X12 = ESR_EL1
    vec.push_back(0x92403D8Du);              // AND X13, X12, #0xFFFF (imms=15, immr=0, N=1 -> 0xFFFF)
    vec.push_back(SubImm(31, 13, 0x42, true)); // CMP X13, #0x42
    vec.push_back(BCond(1, 3));              // B.NE +3 (to HLT)
    vec.push_back(AddImm(0, 0, 10));         // X0 += 10
    vec.push_back(Eret());
    vec.push_back(Hlt(0));
    ram.WriteBytes(vbar + 0x400ULL, vec.data(), vec.size() * 4u);

    cpu.Reset(el1_entry, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(10000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[10] == 0x411FD050ULL);
    HASEEB_CHECK((cpu.State().x[11] & 0xFFULL) == 2ULL);
    HASEEB_CHECK(cpu.State().x[0] == 92ULL); // 77 + 10 (in SVC #0x42) + 5 (in EL0)
    HASEEB_CHECK((cpu.State().sys.esr_el1 >> 26) == ec::kSvc64);
    HASEEB_CHECK((cpu.State().sys.esr_el1 & 0xFFFFULL) == 0x99ULL);

    // 4. Self-Modifying Code (SMC) invalidation test in DBT TranslationCache
    // First run block at smc_code: MOVZ X0, #11 ; HLT #0 -> X0 == 11
    std::vector<uint32_t> smc = {Movz(0, 11), Hlt(0)};
    ram.WriteBytes(smc_code, smc.data(), smc.size() * 4u);
    cpu.Reset(smc_code, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(100) == VmError::Ok);
    HASEEB_CHECK(cpu.State().x[0] == 11ULL);

    // Now have guest CPU itself write MOVZ X0, #99 over smc_code via STR W1, [X2], then branch back to smc_code!
    const uint64_t writer_code = kGuestRamBase + 0x00040000ULL;
    std::vector<uint32_t> writer;
    EmitImm64(writer, 1, Movz(0, 99));
    EmitImm64(writer, 2, smc_code);
    writer.push_back(0xB9000041u); // STR W1, [X2] (overwrites cached code page!)
    writer.push_back(Hlt(0));
    ram.WriteBytes(writer_code, writer.data(), writer.size() * 4u);

    // Re-run writer without wiping TranslationCache (preserve cached smc_code block!)
    cpu.State().halted = false;
    cpu.State().pc = writer_code;
    HASEEB_CHECK(cpu.Run(100) == VmError::Ok);
    HASEEB_CHECK(cpu.Cache().SmcInvalidations() >= 1u);

    // Execute smc_code again -> must pick up newly written MOVZ X0, #99!
    cpu.State().halted = false;
    cpu.State().pc = smc_code;
    HASEEB_CHECK(cpu.Run(100) == VmError::Ok);
    HASEEB_CHECK(cpu.State().x[0] == 99ULL);

    std::cout << "[PASS] TestEl0El1ExceptionsSysregsAndSmc\n";
}

void TestLinkerNeonAndTrace() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    AArch64CpuCore cpu(ram, bus, 0);
    const uint64_t code_addr = kGuestRamBase;

    // 1. Replicate bionic/linker64 powerof2(64) with rd == rn == 0:
    //    FMOV D0, X0       -> 0x9E670000
    //    CNT  V0.8B, V0.8B -> 0x0E205800
    //    ADDV B0, V0.8B    -> 0x0E31B800
    //    UMOV W1, V0.B[0]  -> 0x0E013C01
    // Also test powerof2(48) in X2 -> V1, plus UADDLV H1, V1.8B (0x2E303821):
    //    FMOV D1, X2       -> 0x9E670041
    //    CNT  V1.8B, V1.8B -> 0x0E205821
    //    UADDLV H1, V1.8B  -> 0x2E303821 (rd == rn == 1!)
    //    UMOV W3, V1.H[0]  -> 0x0E023C23
    // Additional A5 NEON coverage:
    //    DUP V2.4S, W4     -> 0x4E040C82 (4 lanes of 0x11223344)
    //    DUP W5, V2.S[2]   -> 0x5E140445 (AdvSIMD Copy DUP scalar elem)
    //    INS V2.S[1], W6   -> 0x4E0C1CC2 (index=1, imm5=0b01100=12 -> 0x4E0C1CC2)
    //    UMOV W7, V2.S[1]  -> 0x0E0C3C47 (0xAABBCCDD)
    //    SMOV X8, V2.H[0]  -> 0x4E022C48 (sign-extend 0x3344 or negative low half)
    //    UMINV B9, V0.8B   -> 0x2E31A809
    //    UMAXV B10, V2.16B -> 0x6E30A84A
    //    CMEQ V11.4S, V2.4S, #0 -> 0x4EA0984B
    //    SHRN V14.4H, V2.4S, #16 -> 0x0F10844E
    std::vector<uint32_t> code;
    code.push_back(Movz(0, 64));
    code.push_back(0x9E670000u); // FMOV D0, X0
    code.push_back(0x0E205800u); // CNT V0.8B, V0.8B
    code.push_back(0x0E31B800u); // ADDV B0, V0.8B (rd == rn == 0)
    code.push_back(0x0E013C01u); // UMOV W1, V0.B[0] -> 1!

    code.push_back(Movz(2, 48));
    code.push_back(0x9E670041u); // FMOV D1, X2
    code.push_back(0x0E205821u); // CNT V1.8B, V1.8B
    code.push_back(0x2E303821u); // UADDLV H1, V1.8B (rd == rn == 1)
    code.push_back(0x0E023C23u); // UMOV W3, V1.H[0] -> 2!

    // V2 initialized via W4 = 0xAABBCCDD (signed negative in H0 = 0xCCDD)
    EmitImm64(code, 4, 0xAABBCCDDULL);
    EmitImm64(code, 6, 0x11223344ULL);
    code.push_back(0x4E040C82u); // DUP V2.4S, W4
    code.push_back(0x5E140445u); // DUP S5, V2.S[2]
    code.push_back(0x0E043CA5u); // UMOV W5, V5.S[0]
    code.push_back(0x4E0C1CC2u); // INS V2.S[1], W6
    code.push_back(0x0E0C3C47u); // UMOV W7, V2.S[1]
    code.push_back(0x4E022C48u); // SMOV X8, V2.H[0]
    code.push_back(0x6E30A84Au); // UMAXV B10, V2.16B
    code.push_back(0x0E013D4Au); // UMOV W10, V10.B[0]
    code.push_back(0x6E31A84Bu); // UMINV B11, V2.16B
    code.push_back(0x0E013D6Bu); // UMOV W11, V11.B[0]

    code.push_back(Movz(12, 0));
    code.push_back(0x4E040D8Cu); // DUP V12.4S, W12 (all zero)
    code.push_back(0x4EA0998Du); // CMEQ V13.4S, V12.4S, #0 -> all 0xFFFFFFFF
    code.push_back(0x0E043DADu); // UMOV W13, V13.S[0]
    code.push_back(0x0F10844Eu); // SHRN V14.4H, V2.4S, #16 (0xAABBCCDD >> 16 -> 0xAABB)
    code.push_back(0x0E023DCEu); // UMOV W14, V14.H[0]
    code.push_back(Hlt(0));

    ram.WriteBytes(code_addr, code.data(), code.size() * 4u);
    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(1000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[1] == 1ULL);           // powerof2(64): popcnt == 1
    HASEEB_CHECK(cpu.State().x[3] == 2ULL);           // powerof2(48): popcnt == 2
    HASEEB_CHECK(cpu.State().x[5] == 0xAABBCCDDULL);  // DUP S5, V2.S[2]
    HASEEB_CHECK(cpu.State().x[7] == 0x11223344ULL);  // INS V2.S[1], W6
    HASEEB_CHECK(static_cast<int64_t>(cpu.State().x[8]) == -13091LL); // SMOV sign-ext 0xCCDD
    HASEEB_CHECK(cpu.State().x[10] == 0xDDU);         // UMAXV max byte
    HASEEB_CHECK(cpu.State().x[11] == 0x11U);         // UMINV min byte
    HASEEB_CHECK(cpu.State().x[13] == 0xFFFFFFFFULL); // CMEQ #0
    HASEEB_CHECK(cpu.State().x[14] == 0xAABBULL);     // SHRN #16

    const std::string trace = cpu.DumpRecentTrace(8);
    HASEEB_CHECK(!trace.empty());
    HASEEB_CHECK(trace.find("pc=0x") != std::string::npos);

    std::cout << "[PASS] TestLinkerNeonAndTrace\n";
}

void TestLoadStoreSimdStructAndBionicNeon() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    AArch64CpuCore cpu(ram, bus, 0);
    const uint64_t code_addr = kGuestRamBase;
    const uint64_t data_addr = kGuestRamBase + 0x30000ULL;

    // Seed 64 bytes at data_addr: byte[i] = 0x10 + i
    uint8_t buf[64]{};
    for (uint32_t i = 0; i < 64; ++i) buf[i] = static_cast<uint8_t>(0x10u + i);
    ram.WriteBytes(data_addr, buf, sizeof(buf));

    std::vector<uint32_t> code;
    EmitImm64(code, 2, data_addr);
    // Exact instruction that halted /init at insns=58437:
    // 0x4CDFA041 = LD1 {V1.16B, V2.16B}, [X2], #32
    code.push_back(0x4CDFA041u);
    code.push_back(0x0E013C23u); // UMOV W3, V1.B[0] -> 0x10
    code.push_back(0x0E013C44u); // UMOV W4, V2.B[0] -> 0x20
    // ST1 {V1.16B, V2.16B}, [X2] (no-offset: 0x4C00A041) -> writes 32 bytes to data_addr + 32
    code.push_back(0x4C00A041u);
    // LD1R {V5.16B}, [X2] -> 0x4D40C045 (replicates byte 0x10 into all 16 lanes of V5)
    code.push_back(0x4D40C045u);
    code.push_back(0x0E103CA6u); // UMOV W6, V5.B[15] (imm5 = 11111 = 0x1F -> 0x0E1F3CA6)
    // Wait: fix UMOV W6, V5.B[15]: imm5=(15<<1)|1 = 31 -> 0x0E1F3CA6u
    code.pop_back();
    code.push_back(0x0E1F3CA6u);

    // ADDP V6.16B, V1.16B, V2.16B (0x4E22BC26):
    // V6.B[0] = V1.B[0] + V1.B[1] = 0x10 + 0x11 = 0x21
    // V6.B[8] = V2.B[0] + V2.B[1] = 0x20 + 0x21 = 0x41
    code.push_back(0x4E22BC26u);
    code.push_back(0x0E013CC7u); // UMOV W7, V6.B[0] -> 0x21
    code.push_back(0x0E113CC8u); // UMOV W8, V6.B[8] -> 0x41

    // CMHI V7.16B, V2.16B, V1.16B (0x6E213447): all 0xFF since V2 > V1
    code.push_back(0x6E213447u);
    code.push_back(0x0E013CE9u); // UMOV W9, V7.B[0] -> 0xFF

    // ZIP1 V8.16B, V1.16B, V2.16B (0x4E023828): [V1[0]=0x10, V2[0]=0x20, ...]
    code.push_back(0x4E023828u);
    code.push_back(0x0E033D0Au); // UMOV W10, V8.B[1] -> 0x20

    // TBL V9.16B, {V1.16B}, V10.16B: index=15 -> V1.B[15] = 0x1F
    code.push_back(Movz(11, 15u));
    code.push_back(0x4E010D6Au); // DUP V10.16B, W11 (all 15)
    code.push_back(0x4E0A0029u); // TBL V9.16B, {V1.16B}, V10.16B
    code.push_back(0x0E013D2Cu); // UMOV W12, V9.B[0] -> 0x1F
    code.push_back(Hlt(0));

    ram.WriteBytes(code_addr, code.data(), code.size() * 4u);
    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(1000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[2] == data_addr + 32ULL);
    HASEEB_CHECK(cpu.State().x[3] == 0x10ULL);
    HASEEB_CHECK(cpu.State().x[4] == 0x20ULL);
    HASEEB_CHECK(cpu.State().x[6] == 0x10ULL);
    HASEEB_CHECK(cpu.State().x[7] == 0x21ULL);
    HASEEB_CHECK(cpu.State().x[8] == 0x41ULL);
    HASEEB_CHECK(cpu.State().x[9] == 0xFFULL);
    HASEEB_CHECK(cpu.State().x[10] == 0x20ULL);
    HASEEB_CHECK(cpu.State().x[12] == 0x1FULL);

    uint8_t stored_b0 = 0, stored_b16 = 0;
    ram.ReadU8(data_addr + 32ULL, stored_b0);
    ram.ReadU8(data_addr + 48ULL, stored_b16);
    HASEEB_CHECK(stored_b0 == 0x10u && stored_b16 == 0x20u);

    std::cout << "[PASS] TestLoadStoreSimdStructAndBionicNeon\n";
}

void TestExtendedAdvSimdShiftAndMisc() {
    GuestRam ram;
    MmioBus bus;
    HASEEB_CHECK(ram.Allocate(kGuestRamBase, 16ULL * 1024ULL * 1024ULL) == VmError::Ok);

    AArch64CpuCore cpu(ram, bus, 0);
    const uint64_t code_addr = kGuestRamBase;

    std::vector<uint32_t> code;
    // Seed V1 with 16 bytes: low 8 bytes = [0x80, 0x05, 0xFF, 0x10, 0x01, 0x02, 0x03, 0x04]
    // high 8 bytes = [0xFE, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
    EmitImm64(code, 0, 0x0403020110FF0580ULL);
    EmitImm64(code, 1, 0x80706050403020FEULL);
    code.push_back(0x9E670001u); // FMOV D1, X0
    code.push_back(0x4E081C21u); // INS V1.D[1], X1 (Wait: INS Vd.D[1], Xn = 0x4E181C21 -> imm5=11000=0x18!)
    code.pop_back();
    code.push_back(0x4E181C21u); // INS V1.D[1], X1

    // Save original V1 into V20 (ORR V20.16B, V1.16B, V1.16B = 0x4EA11C34)
    code.push_back(0x4EA11C34u);

    // 1. Exact instruction from insns=753495 trap:
    //    0x2F08A421 = UXTL V1.8H, V1.8B (USHLL V1.8H, V1.8B, #0, rd == rn == 1!)
    //    V1.H[0] = 0x0080, V1.H[2] = 0x00FF
    code.push_back(0x2F08A421u);
    code.push_back(0x0E023C22u); // UMOV W2, V1.H[0] -> 0x0080
    code.push_back(0x0E0A3C23u); // UMOV W3, V1.H[2] -> 0x00FF

    // 2. USHLL2 V2.8H, V20.16B, #0 (0x6F08A682) -> V2.H[0] = 0x00FE, V2.H[1] = 0x0020
    code.push_back(0x6F08A682u);
    code.push_back(0x0E023C44u); // UMOV W4, V2.H[0] -> 0x00FE

    // 3. SSHLL V3.8H, V20.8B, #0 (SXTL: 0x0F08A683) -> V3.H[0] = 0xFF80 (-128)
    code.push_back(0x0F08A683u);
    code.push_back(0x0E023C65u); // UMOV W5, V3.H[0] -> 0xFF80

    // 4. USHLL V4.4S, V2.4H, #3 (0x2F13A444) -> V4.S[0] = 0x00FE << 3 = 0x07F0
    code.push_back(0x2F13A444u);
    code.push_back(0x0E043C86u); // UMOV W6, V4.S[0] -> 0x07F0

    // 5. SHLL V5.8H, V20.8B, #8 (0x2E213A85) -> V5.H[0] = 0x8000
    code.push_back(0x2E213A85u);
    code.push_back(0x0E023CA7u); // UMOV W7, V5.H[0] -> 0x8000

    // 6. RSHRN V6.8B, V1.8H, #4 (0x0F0C8C26): V1.H[0]=0x0080 -> (0x80+8)>>4 = 8; V1.H[2]=0x00FF -> (0xFF+8)>>4 = 0x10
    code.push_back(0x0F0C8C26u);
    code.push_back(0x0E013CC8u); // UMOV W8, V6.B[0] -> 8
    code.push_back(0x0E053CC9u); // UMOV W9, V6.B[2] -> 0x10

    // 7. SRI V6.8B, V20.8B, #4 (0x2F0C4686): V6.B[0]=0x08 (top 4 bits 0), V20.B[0]=0x80 >> 4 = 0x08 -> (0x08 & 0xF0) | 0x08 = 0x08;
    //    V6.B[2]=0x10 (top 4 bits 0x10), V20.B[2]=0xFF >> 4 = 0x0F -> 0x1F
    code.push_back(0x2F0C4686u);
    code.push_back(0x0E053CCAu); // UMOV W10, V6.B[2] -> 0x1F

    // 8. REV16 V7.8B, V20.8B (0x0E201A87) -> [0x05, 0x80, ...] -> H[0] = 0x8005
    code.push_back(0x0E201A87u);
    code.push_back(0x0E023CEBu); // UMOV W11, V7.H[0] -> 0x8005

    // 9. CLZ V8.8B, V20.8B (0x2E204A88) -> V20.B[4]=0x01 -> clz=7
    code.push_back(0x2E204A88u);
    code.push_back(0x0E093D0Cu); // UMOV W12, V8.B[4] -> 7

    // 10. ADDP D9, V20.2D (0x5EF1BA89) -> 0x0403020110FF0580 + 0x80706050403020FE
    code.push_back(0x5EF1BA89u);
    code.push_back(0x9E66012Du); // FMOV X13, D9

    // 11. XTN V10.8B, V1.8H (0x0E21282A) -> V10.B[0]=0x80, V10.B[2]=0xFF
    code.push_back(0x0E21282Au);
    code.push_back(0x0E013D4Eu); // UMOV W14, V10.B[0] -> 0x80
    code.push_back(Hlt(0));

    ram.WriteBytes(code_addr, code.data(), code.size() * 4u);
    cpu.Reset(code_addr, kGuestRamBase + 0x80000ULL, 1);
    HASEEB_CHECK(cpu.Run(1000) == VmError::Ok);
    HASEEB_CHECK(cpu.State().halted);
    HASEEB_CHECK(cpu.State().x[2] == 0x0080ULL);
    HASEEB_CHECK(cpu.State().x[3] == 0x00FFULL);
    HASEEB_CHECK(cpu.State().x[4] == 0x00FEULL);
    HASEEB_CHECK(cpu.State().x[5] == 0xFF80ULL);
    HASEEB_CHECK(cpu.State().x[6] == 0x07F0ULL);
    HASEEB_CHECK(cpu.State().x[7] == 0x8000ULL);
    HASEEB_CHECK(cpu.State().x[8] == 8ULL);
    HASEEB_CHECK(cpu.State().x[9] == 0x10ULL);
    HASEEB_CHECK(cpu.State().x[10] == 0x1FULL);
    HASEEB_CHECK(cpu.State().x[11] == 0x8005ULL);
    HASEEB_CHECK(cpu.State().x[12] == 7ULL);
    HASEEB_CHECK(cpu.State().x[13] == (0x0403020110FF0580ULL + 0x80706050403020FEULL));
    HASEEB_CHECK(cpu.State().x[14] == 0x80ULL);

    std::cout << "[PASS] TestExtendedAdvSimdShiftAndMisc\n";
}

} // namespace

int main() {
    TestAluBranchesAndExclusives();
    TestNeonAndScalarFp();
    TestStage1Mmu4KAnd16KPlusDirtyAccessed();
    TestEl0El1ExceptionsSysregsAndSmc();
    TestLinkerNeonAndTrace();
    TestLoadStoreSimdStructAndBionicNeon();
    TestExtendedAdvSimdShiftAndMisc();
    std::cout << "All M2 AArch64 CPU, DBT, MMU & Exception tests PASSED.\n";
    return 0;
}
