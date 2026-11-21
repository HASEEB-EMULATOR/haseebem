#include "haseeb/boot_image.hpp"
#include "haseeb/kernel_boot.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/virtio_input.hpp"
#include "haseeb/virtio_mmio.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
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

struct SplitQueueLayout {
    uint64_t desc_pa = 0;
    uint64_t avail_pa = 0;
    uint64_t used_pa = 0;
    uint32_t qsize = 32;
    uint16_t next_avail = 0;
    uint16_t next_used_seen = 0;
};

struct RawVringDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

SplitQueueLayout SetupVirtq(GuestRam& ram,
                            VirtioMmioDevice& dev,
                            uint32_t qidx,
                            uint64_t base_pa,
                            uint32_t qsize = 32u) {
    SplitQueueLayout q;
    q.desc_pa = base_pa;
    q.avail_pa = base_pa + 0x1000ULL;
    q.used_pa = base_pa + 0x2000ULL;
    q.qsize = qsize;

    std::vector<uint8_t> zeros(0x3000u, 0u);
    HASEEB_CHECK(ram.WriteBytes(base_pa, zeros.data(), zeros.size()));

    dev.Write(0x030u, 4, qidx);
    HASEEB_CHECK(dev.Read(0x034u, 4) >= qsize);
    dev.Write(0x038u, 4, qsize);
    dev.Write(0x080u, 4, static_cast<uint32_t>(q.desc_pa & 0xFFFFFFFFULL));
    dev.Write(0x084u, 4, static_cast<uint32_t>(q.desc_pa >> 32));
    dev.Write(0x090u, 4, static_cast<uint32_t>(q.avail_pa & 0xFFFFFFFFULL));
    dev.Write(0x094u, 4, static_cast<uint32_t>(q.avail_pa >> 32));
    dev.Write(0x0A0u, 4, static_cast<uint32_t>(q.used_pa & 0xFFFFFFFFULL));
    dev.Write(0x0A4u, 4, static_cast<uint32_t>(q.used_pa >> 32));
    dev.Write(0x044u, 4, 1u);
    return q;
}

void PostRxBuffers(GuestRam& ram,
                   VirtioMmioDevice& dev,
                   SplitQueueLayout& q,
                   uint32_t qidx,
                   uint64_t buf_base_pa,
                   uint32_t count,
                   uint32_t stride_bytes = 16u) {
    for (uint32_t i = 0; i < count; ++i) {
        const uint16_t d_idx = q.next_avail % q.qsize;
        RawVringDesc d{buf_base_pa + static_cast<uint64_t>(d_idx) * stride_bytes,
                       stride_bytes, 2u /*VRING_DESC_F_WRITE*/, 0u};
        HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d_idx) * 16ULL, &d, sizeof(d)));
        HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + d_idx * 2ULL, &d_idx, sizeof(d_idx)));
        ++q.next_avail;
    }
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));
    dev.Write(0x050u, 4, qidx);
}

std::vector<VirtioInputDevice::VirtioInputEvent> DrainUsedEvents(GuestRam& ram,
                                                                 SplitQueueLayout& q,
                                                                 uint64_t buf_base_pa,
                                                                 uint32_t stride_bytes = 16u) {
    uint16_t used_idx = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 2ULL, &used_idx, sizeof(used_idx)));
    std::vector<VirtioInputDevice::VirtioInputEvent> out;
    while (q.next_used_seen != used_idx) {
        const uint16_t u_slot = q.next_used_seen % q.qsize;
        uint32_t id = 0;
        uint32_t len = 0;
        HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + u_slot * 8ULL, &id, 4));
        HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + u_slot * 8ULL + 4ULL, &len, 4));
        HASEEB_CHECK(len == sizeof(VirtioInputDevice::VirtioInputEvent));
        VirtioInputDevice::VirtioInputEvent ev{};
        HASEEB_CHECK(ram.ReadBytes(buf_base_pa + static_cast<uint64_t>(id) * stride_bytes,
                                   &ev, sizeof(ev)));
        out.push_back(ev);
        ++q.next_used_seen;
    }
    return out;
}

void SubmitOutBuffer(GuestRam& ram,
                     VirtioMmioDevice& dev,
                     SplitQueueLayout& q,
                     uint32_t qidx,
                     uint64_t buf_pa,
                     const void* data,
                     uint32_t len) {
    HASEEB_CHECK(ram.WriteBytes(buf_pa, data, len));
    const uint16_t d_idx = q.next_avail % q.qsize;
    RawVringDesc d{buf_pa, len, 0u, 0u};
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d_idx) * 16ULL, &d, sizeof(d)));
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + d_idx * 2ULL, &d_idx, sizeof(d_idx)));
    ++q.next_avail;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));
    dev.Write(0x050u, 4, qidx);

    uint16_t used_idx = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 2ULL, &used_idx, sizeof(used_idx)));
    HASEEB_CHECK(used_idx != q.next_used_seen);
    ++q.next_used_seen;
}

std::vector<uint8_t> ReadInputConfig(MmioBus& bus, uint64_t base, uint8_t select, uint8_t subsel) {
    HASEEB_CHECK(bus.Write(base + 0x100u, 1, select));
    HASEEB_CHECK(bus.Write(base + 0x101u, 1, subsel));
    uint64_t sz = 0;
    HASEEB_CHECK(bus.Read(base + 0x102u, 1, sz));
    std::vector<uint8_t> payload(static_cast<size_t>(sz), 0u);
    for (size_t i = 0; i < payload.size(); ++i) {
        uint64_t b = 0;
        HASEEB_CHECK(bus.Read(base + 0x108u + i, 1, b));
        payload[i] = static_cast<uint8_t>(b);
    }
    return payload;
}

bool HasBit(const std::vector<uint8_t>& bits, uint16_t bit) {
    const size_t byte_idx = bit / 8u;
    if (byte_idx >= bits.size()) return false;
    return (bits[byte_idx] & static_cast<uint8_t>(1u << (bit & 7u))) != 0u;
}

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// Minimal AArch64 assembler helpers for EL0 evdev test
uint32_t Movz(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0xD2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Movn(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0x92800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Movk(uint8_t xd, uint16_t imm16, uint8_t hw) {
    return 0xF2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}
uint32_t Movr64(uint8_t xd, uint8_t xm) {
    return 0xAA0003E0u | (static_cast<uint32_t>(xm & 31u) << 16) | (xd & 31u);
}
uint32_t Adr(uint8_t xd, int32_t byte_offset) {
    uint32_t u21 = static_cast<uint32_t>(byte_offset) & 0x1FFFFFu;
    return 0x10000000u | ((u21 & 3u) << 29) | (((u21 >> 2) & 0x7FFFFu) << 5) | (xd & 31u);
}
uint32_t AddImm64(uint8_t xd, uint8_t xn, uint16_t imm12) {
    return 0x91000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xd & 31u);
}
uint32_t SubImm64(uint8_t xd, uint8_t xn, uint16_t imm12) {
    return 0xD1000000u | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xd & 31u);
}
uint32_t CmpImm64(uint8_t xn, uint16_t imm12) {
    return 0xF100001Fu | (static_cast<uint32_t>(imm12 & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5);
}
uint32_t CmpReg64(uint8_t xn, uint8_t xm) {
    return 0xEB00001Fu | (static_cast<uint32_t>(xm & 31u) << 16) |
           (static_cast<uint32_t>(xn & 31u) << 5);
}
uint32_t LdrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9400000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t LdrH(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0x79400000u | (static_cast<uint32_t>((imm_bytes / 2u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t StrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9000000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t StrH(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0x79000000u | (static_cast<uint32_t>((imm_bytes / 2u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t Svc(uint16_t imm = 0) {
    return 0xD4000001u | (static_cast<uint32_t>(imm) << 5);
}
uint32_t BImm(int32_t rel_insns) {
    return 0x14000000u | (static_cast<uint32_t>(rel_insns) & 0x03FFFFFFu);
}
uint32_t BCond(uint8_t cond, int32_t rel_insns) {
    return 0x54000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (cond & 0xFu);
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

struct CodeBlobBuilder {
    std::vector<uint32_t> insns;
    std::vector<uint8_t> data;
    struct Patch { size_t insn_idx; uint8_t rd; size_t data_offset; };
    std::vector<Patch> patches;
    struct BranchPatch { size_t insn_idx; bool is_cond; uint8_t cond; size_t target_idx; };
    std::vector<BranchPatch> b_patches;

    size_t AddString(const std::string& s) {
        size_t off = data.size();
        data.insert(data.end(), s.begin(), s.end());
        data.push_back('\0');
        return off;
    }
    void EmitAdrPlaceholder(uint8_t rd, size_t data_offset) {
        size_t idx = insns.size();
        insns.push_back(0);
        patches.push_back({idx, rd, data_offset});
    }
    size_t EmitCondPlaceholder(uint8_t cond) {
        size_t idx = insns.size();
        insns.push_back(0);
        b_patches.push_back({idx, true, cond, 0});
        return b_patches.size() - 1u;
    }
    size_t EmitJumpPlaceholder() {
        size_t idx = insns.size();
        insns.push_back(0);
        b_patches.push_back({idx, false, 0, 0});
        return b_patches.size() - 1u;
    }
    void PatchBranchToHere(size_t bp_idx) {
        b_patches[bp_idx].target_idx = insns.size();
    }
    std::vector<uint8_t> Finalize() {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : patches) {
            insns[p.insn_idx] = Adr(p.rd, static_cast<int32_t>(code_bytes + p.data_offset) -
                                          static_cast<int32_t>(p.insn_idx * 4u));
        }
        for (const auto& bp : b_patches) {
            const int32_t rel = static_cast<int32_t>(bp.target_idx) -
                                static_cast<int32_t>(bp.insn_idx);
            insns[bp.insn_idx] = bp.is_cond ? BCond(bp.cond, rel) : BImm(rel);
        }
        std::vector<uint8_t> blob;
        blob.reserve(code_bytes + data.size());
        for (uint32_t i : insns) AppendLe32(blob, i);
        blob.insert(blob.end(), data.begin(), data.end());
        return blob;
    }
};

std::vector<uint8_t> BuildElf64(const std::vector<uint8_t>& code_and_data,
                                uint64_t base_va = 0x0000000000400000ULL) {
    constexpr uint64_t kCodeOff = 0x100ULL;
    const uint64_t total = kCodeOff + code_and_data.size();
    std::vector<uint8_t> elf(total, 0u);
    elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
    auto w16 = [&](size_t o, uint16_t v) { elf[o] = v & 0xFFu; elf[o + 1] = v >> 8; };
    auto w32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    auto w64 = [&](size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) elf[o + i] = (v >> (8 * i)) & 0xFFu; };
    w16(16, 2u); w16(18, 183u); w32(20, 1u);
    w64(24, base_va + kCodeOff); w64(32, 64ULL);
    w16(52, 64u); w16(54, 56u); w16(56, 1u);
    w32(64 + 0, 1u); w32(64 + 4, 7u);
    w64(64 + 8, 0ULL); w64(64 + 16, base_va); w64(64 + 24, base_va);
    w64(64 + 32, total); w64(64 + 40, total + 4096ULL); w64(64 + 48, 4096ULL);
    std::memcpy(elf.data() + kCodeOff, code_and_data.data(), code_and_data.size());
    return elf;
}

std::vector<uint8_t> BuildBootImgV2(const std::vector<uint8_t>& ramdisk) {
    constexpr uint32_t kPage = 4096u;
    auto align_up = [&](size_t v) { return (v + kPage - 1u) & ~static_cast<size_t>(kPage - 1u); };
    std::vector<uint8_t> img(kPage + align_up(ramdisk.size()), 0u);
    auto put32 = [&](size_t o, uint32_t v) {
        for (int i = 0; i < 4; ++i) img[o + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    std::memcpy(img.data(), "ANDROID!", 8);
    put32(16, static_cast<uint32_t>(ramdisk.size()));
    put32(36, kPage);
    put32(40, 2u);
    if (!ramdisk.empty()) std::memcpy(img.data() + kPage, ramdisk.data(), ramdisk.size());
    return img;
}

// Test 1: Virtio-MMIO slots 6 & 7 probe (DeviceID=18), config space queries,
// eventq delivery, statusq LED mask, and GICv3 SPI 22 / SPI 23 interrupts.
void TestVirtioInputProbeConfigAndIrq() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    cfg.width = 800u;
    cfg.height = 600u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    // Enable GICv3 distributor + CPU0 redistributor to observe SPI 22 (INTID 54) & SPI 23 (INTID 55)
    vm.Gic().WriteGicd(0x0000u, 4, 0x2u);
    vm.Gic().WriteGicr(0x0014u, 4, 0x0u);
    vm.Gic().WriteSysReg(0, GicV3::kIccPmrEl1, 0xFFu);
    vm.Gic().WriteSysReg(0, GicV3::kIccIgrpen1El1, 1u);
    vm.Gic().WriteGicd(0x0104u, 4, (1u << (54u - 32u)) | (1u << (55u - 32u)));
    vm.Gic().WriteGicd(0x6000u + 54u * 8u, 8, 0ULL);
    vm.Gic().WriteGicd(0x6000u + 55u * 8u, 8, 0ULL);

    const uint64_t touch_base = kVirtioMmioBase + 6ULL * kVirtioMmioStride; // 0x0A000C00
    const uint64_t kbd_base   = kVirtioMmioBase + 7ULL * kVirtioMmioStride; // 0x0A000E00
    uint64_t val = 0;

    for (uint64_t base : {touch_base, kbd_base}) {
        HASEEB_CHECK(vm.Bus().Read(base + 0x000u, 4, val) && val == 0x74726976u);
        HASEEB_CHECK(vm.Bus().Read(base + 0x004u, 4, val) && val == 2u);
        HASEEB_CHECK(vm.Bus().Read(base + 0x008u, 4, val) && val == VirtioInputDevice::kVirtioIdInput);
    }

    // Touch config checks
    std::vector<uint8_t> t_name = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgIdName, 0u);
    HASEEB_CHECK(std::string(t_name.begin(), t_name.end()) == "Haseeb Virtual MultiTouch");

    std::vector<uint8_t> t_serial = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgIdSerial, 0u);
    HASEEB_CHECK(std::string(t_serial.begin(), t_serial.end()) == "haseeb-input-mt0");

    std::vector<uint8_t> t_ids = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgIdDevids, 0u);
    HASEEB_CHECK(t_ids.size() == 8u);
    HASEEB_CHECK(t_ids[0] == 0x06u && t_ids[1] == 0x00u); // BUS_VIRTUAL
    HASEEB_CHECK(t_ids[2] == 0x53u && t_ids[3] == 0x48u); // vendor 0x4853
    HASEEB_CHECK(t_ids[4] == 0x01u && t_ids[5] == 0x00u); // product 1

    std::vector<uint8_t> t_prop = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgPropBits, 0u);
    HASEEB_CHECK(HasBit(t_prop, 1u)); // INPUT_PROP_DIRECT

    std::vector<uint8_t> t_keys = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgEvBits, VirtioInputDevice::kEvKey);
    HASEEB_CHECK(HasBit(t_keys, VirtioInputDevice::kBtnTouch));

    std::vector<uint8_t> t_abs = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgEvBits, VirtioInputDevice::kEvAbs);
    HASEEB_CHECK(HasBit(t_abs, VirtioInputDevice::kAbsMtPositionX));
    HASEEB_CHECK(HasBit(t_abs, VirtioInputDevice::kAbsMtPositionY));
    HASEEB_CHECK(HasBit(t_abs, VirtioInputDevice::kAbsMtSlot));
    HASEEB_CHECK(HasBit(t_abs, VirtioInputDevice::kAbsMtTrackingId));

    std::vector<uint8_t> abs_x = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgAbsInfo, VirtioInputDevice::kAbsMtPositionX);
    std::vector<uint8_t> abs_y = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgAbsInfo, VirtioInputDevice::kAbsMtPositionY);
    std::vector<uint8_t> abs_slot = ReadInputConfig(vm.Bus(), touch_base, VirtioInputDevice::kCfgAbsInfo, VirtioInputDevice::kAbsMtSlot);
    HASEEB_CHECK(abs_x.size() == 20u && ReadLe32(abs_x.data() + 4u) == 799u);
    HASEEB_CHECK(abs_y.size() == 20u && ReadLe32(abs_y.data() + 4u) == 599u);
    HASEEB_CHECK(abs_slot.size() == 20u && ReadLe32(abs_slot.data() + 4u) == 15u);

    // Keyboard & gamepad config checks
    std::vector<uint8_t> k_name = ReadInputConfig(vm.Bus(), kbd_base, VirtioInputDevice::kCfgIdName, 0u);
    HASEEB_CHECK(std::string(k_name.begin(), k_name.end()) == "Haseeb Virtual Keyboard & Gamepad");
    std::vector<uint8_t> k_keys = ReadInputConfig(vm.Bus(), kbd_base, VirtioInputDevice::kCfgEvBits, VirtioInputDevice::kEvKey);
    HASEEB_CHECK(HasBit(k_keys, 17u)); // KEY_W
    HASEEB_CHECK(HasBit(k_keys, VirtioInputDevice::kBtnSouth));
    HASEEB_CHECK(HasBit(k_keys, VirtioInputDevice::kBtnThumbR));

    // Setup eventq on slot 6 & slot 7, plus statusq on slot 7
    VirtioMmioDevice& touch_mmio = vm.VirtioMmio(6u);
    VirtioMmioDevice& kbd_mmio   = vm.VirtioMmio(7u);
    touch_mmio.Write(0x070u, 4, 15u);
    kbd_mmio.Write(0x070u, 4, 15u);

    SplitQueueLayout touch_eq = SetupVirtq(vm.Ram(), touch_mmio, 0u, kGuestRamBase + 0x0100000ULL, 32u);
    SplitQueueLayout kbd_eq   = SetupVirtq(vm.Ram(), kbd_mmio,   0u, kGuestRamBase + 0x0110000ULL, 32u);
    SplitQueueLayout kbd_sq   = SetupVirtq(vm.Ram(), kbd_mmio,   1u, kGuestRamBase + 0x0120000ULL, 32u);

    const uint64_t touch_rx_pa = kGuestRamBase + 0x0200000ULL;
    const uint64_t kbd_rx_pa   = kGuestRamBase + 0x0210000ULL;
    PostRxBuffers(vm.Ram(), touch_mmio, touch_eq, 0u, touch_rx_pa, 24u);
    PostRxBuffers(vm.Ram(), kbd_mmio,   kbd_eq,   0u, kbd_rx_pa,   16u);

    vm.InjectTouch(0 /*ACTION_DOWN*/, 123, 456, 0);
    vm.InjectKey(96 /*KEYCODE_BUTTON_A*/, true);

    // Check GICv3 INTID 54 & INTID 55 fired
    HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
    uint32_t i0 = vm.Gic().ReadSysReg(0, GicV3::kIccIar1El1);
    HASEEB_CHECK(i0 == 54u || i0 == 55u);
    vm.Gic().WriteSysReg(0, GicV3::kIccEoir1El1, i0);
    uint32_t i1 = vm.Gic().ReadSysReg(0, GicV3::kIccIar1El1);
    HASEEB_CHECK((i1 == 54u || i1 == 55u) && i1 != i0);
    vm.Gic().WriteSysReg(0, GicV3::kIccEoir1El1, i1);
    touch_mmio.Write(0x064u, 4, touch_mmio.Read(0x060u, 4));
    kbd_mmio.Write(0x064u, 4, kbd_mmio.Read(0x060u, 4));

    auto t_evs = DrainUsedEvents(vm.Ram(), touch_eq, touch_rx_pa);
    HASEEB_CHECK(t_evs.size() >= 6u);
    bool saw_x = false, saw_y = false, saw_btn = false, saw_syn = false;
    for (const auto& ev : t_evs) {
        if (ev.type == VirtioInputDevice::kEvAbs && ev.code == VirtioInputDevice::kAbsMtPositionX && ev.value == 123) saw_x = true;
        if (ev.type == VirtioInputDevice::kEvAbs && ev.code == VirtioInputDevice::kAbsMtPositionY && ev.value == 456) saw_y = true;
        if (ev.type == VirtioInputDevice::kEvKey && ev.code == VirtioInputDevice::kBtnTouch && ev.value == 1) saw_btn = true;
        if (ev.type == VirtioInputDevice::kEvSyn && ev.code == VirtioInputDevice::kSynReport) saw_syn = true;
    }
    HASEEB_CHECK(saw_x && saw_y && saw_btn && saw_syn);

    auto k_evs = DrainUsedEvents(vm.Ram(), kbd_eq, kbd_rx_pa);
    HASEEB_CHECK(k_evs.size() == 2u);
    HASEEB_CHECK(k_evs[0].type == VirtioInputDevice::kEvKey &&
                 k_evs[0].code == VirtioInputDevice::kBtnSouth &&
                 k_evs[0].value == 1);
    HASEEB_CHECK(k_evs[1].type == VirtioInputDevice::kEvSyn &&
                 k_evs[1].code == VirtioInputDevice::kSynReport);

    // statusq LED test: set LED_CAPSL (code 1) = 1, then 0
    VirtioInputDevice::VirtioInputEvent led_on{VirtioInputDevice::kEvLed, 1u, 1};
    SubmitOutBuffer(vm.Ram(), kbd_mmio, kbd_sq, 1u, kGuestRamBase + 0x0220000ULL, &led_on, sizeof(led_on));
    HASEEB_CHECK(vm.VirtioKbd().LedStateMask() == (1u << 1));

    VirtioInputDevice::VirtioInputEvent led_off{VirtioInputDevice::kEvLed, 1u, 0};
    SubmitOutBuffer(vm.Ram(), kbd_mmio, kbd_sq, 1u, kGuestRamBase + 0x0220100ULL, &led_off, sizeof(led_off));
    HASEEB_CHECK(vm.VirtioKbd().LedStateMask() == 0u);

    vm.Shutdown();
    std::cout << "[PASS] Test 1: Virtio-MMIO slots 6 & 7 (ID=18), config space, SPI 22/23 IRQ & statusq LED\n";
}

// Test 2: Multi-touch Type-B slot lifecycle (2 fingers + move + pointer up + cancel + clamping)
void TestMultiTouchTypeBStateMachine() {
    VirtioInputDevice mt(VirtioInputDevice::Role::MultiTouch);
    mt.ConfigureDisplay(1080u, 2400u);

    auto pop_all = [&]() {
        std::vector<VirtioInputDevice::LinuxInputEvent> buf(64);
        size_t n = mt.PopEvdevEvents(buf.data(), buf.size());
        buf.resize(n);
        return buf;
    };

    // Finger 0 DOWN (negative coordinate clamps to 0, oversized clamps to 2399)
    mt.PushTouch(0 /*ACTION_DOWN*/, -50, 3000, 0);
    auto ev1 = pop_all();
    bool p0_x = false, p0_y = false, p0_tid = false, btn1 = false;
    int32_t tid0 = -1;
    for (const auto& e : ev1) {
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtTrackingId) {
            p0_tid = true;
            tid0 = e.value;
        }
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtPositionX && e.value == 0) p0_x = true;
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtPositionY && e.value == 2399) p0_y = true;
        if (e.type == VirtioInputDevice::kEvKey && e.code == VirtioInputDevice::kBtnTouch && e.value == 1) btn1 = true;
    }
    HASEEB_CHECK(p0_tid && tid0 > 0 && p0_x && p0_y && btn1);

    // Finger 1 POINTER_DOWN -> must switch ABS_MT_SLOT to 1 and allocate distinct tracking ID
    mt.PushTouch(5 /*ACTION_POINTER_DOWN*/, 500, 800, 7);
    auto ev2 = pop_all();
    bool switched_slot1 = false, p1_tid = false, dup_btn = false;
    int32_t tid1 = -1;
    for (const auto& e : ev2) {
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtSlot && e.value == 1) switched_slot1 = true;
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtTrackingId) {
            p1_tid = true;
            tid1 = e.value;
        }
        if (e.type == VirtioInputDevice::kEvKey && e.code == VirtioInputDevice::kBtnTouch) dup_btn = true;
    }
    HASEEB_CHECK(switched_slot1 && p1_tid && tid1 != tid0 && !dup_btn);

    // Finger 1 MOVE
    mt.PushTouch(2 /*ACTION_MOVE*/, 550, 820, 7);
    auto ev3 = pop_all();
    HASEEB_CHECK(ev3.size() == 3u); // ABS_MT_POSITION_X, ABS_MT_POSITION_Y, SYN_REPORT
    HASEEB_CHECK(ev3[0].code == VirtioInputDevice::kAbsMtPositionX && ev3[0].value == 550);
    HASEEB_CHECK(ev3[1].code == VirtioInputDevice::kAbsMtPositionY && ev3[1].value == 820);

    // Finger 1 POINTER_UP -> tracking ID becomes -1, BTN_TOUCH stays down
    mt.PushTouch(6 /*ACTION_POINTER_UP*/, 550, 820, 7);
    auto ev4 = pop_all();
    bool p1_released = false, touch_up_early = false;
    for (const auto& e : ev4) {
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtTrackingId && e.value == -1) p1_released = true;
        if (e.type == VirtioInputDevice::kEvKey && e.code == VirtioInputDevice::kBtnTouch) touch_up_early = true;
    }
    HASEEB_CHECK(p1_released && !touch_up_early);

    // Finger 0 UP -> switches back to slot 0, tracking ID -1, BTN_TOUCH=0
    mt.PushTouch(1 /*ACTION_UP*/, 0, 2399, 0);
    auto ev5 = pop_all();
    bool back_slot0 = false, p0_released = false, touch_up = false;
    for (const auto& e : ev5) {
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtSlot && e.value == 0) back_slot0 = true;
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtTrackingId && e.value == -1) p0_released = true;
        if (e.type == VirtioInputDevice::kEvKey && e.code == VirtioInputDevice::kBtnTouch && e.value == 0) touch_up = true;
    }
    HASEEB_CHECK(back_slot0 && p0_released && touch_up);

    // Two fingers down -> ACTION_CANCEL cleans up all slots + BTN_TOUCH=0
    mt.PushTouch(0, 100, 100, 10);
    mt.PushTouch(5, 200, 200, 11);
    pop_all();
    mt.PushTouch(3 /*ACTION_CANCEL*/, 0, 0, 0);
    auto ev6 = pop_all();
    int neg_one_count = 0;
    bool cancel_btn_up = false;
    for (const auto& e : ev6) {
        if (e.type == VirtioInputDevice::kEvAbs && e.code == VirtioInputDevice::kAbsMtTrackingId && e.value == -1) ++neg_one_count;
        if (e.type == VirtioInputDevice::kEvKey && e.code == VirtioInputDevice::kBtnTouch && e.value == 0) cancel_btn_up = true;
    }
    HASEEB_CHECK(neg_one_count == 2 && cancel_btn_up);
    HASEEB_CHECK(!mt.HasPendingEvdev());

    std::cout << "[PASS] Test 2: Type-B multi-touch 16-slot tracking, coordinate clamp & ACTION_CANCEL\n";
}

// Test 3: Android KeyEvent + Gamepad mapping and analog axes
void TestAndroidKeyAndGamepadTranslation() {
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(51) == 17u);   // KEYCODE_W -> KEY_W
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(66) == 28u);   // KEYCODE_ENTER -> KEY_ENTER
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(4) == 158u);   // KEYCODE_BACK -> KEY_BACK
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(19) == 103u);  // KEYCODE_DPAD_UP -> KEY_UP
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(96) == VirtioInputDevice::kBtnSouth);
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(97) == VirtioInputDevice::kBtnEast);
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(102) == VirtioInputDevice::kBtnTl);
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(103) == VirtioInputDevice::kBtnTr);
    HASEEB_CHECK(VirtioInputDevice::TranslateAndroidKeyCode(107) == VirtioInputDevice::kBtnThumbR);

    VirtioInputDevice kbd(VirtioInputDevice::Role::KeyboardGamepad);
    kbd.PushAndroidKey(108 /*BUTTON_START*/, true);
    kbd.PushAndroidKey(108 /*BUTTON_START*/, false);
    kbd.PushAbsAxis(VirtioInputDevice::kAbsX, 16384);

    std::vector<VirtioInputDevice::LinuxInputEvent> evs(8);
    size_t n = kbd.PopEvdevEvents(evs.data(), evs.size());
    HASEEB_CHECK(n == 6u);
    HASEEB_CHECK(evs[0].type == VirtioInputDevice::kEvKey && evs[0].code == VirtioInputDevice::kBtnStart && evs[0].value == 1);
    HASEEB_CHECK(evs[1].type == VirtioInputDevice::kEvSyn && evs[1].code == VirtioInputDevice::kSynReport);
    HASEEB_CHECK(evs[2].type == VirtioInputDevice::kEvKey && evs[2].code == VirtioInputDevice::kBtnStart && evs[2].value == 0);
    HASEEB_CHECK(evs[3].type == VirtioInputDevice::kEvSyn && evs[3].code == VirtioInputDevice::kSynReport);
    HASEEB_CHECK(evs[4].type == VirtioInputDevice::kEvAbs && evs[4].code == VirtioInputDevice::kAbsX && evs[4].value == 16384);
    HASEEB_CHECK(evs[5].type == VirtioInputDevice::kEvSyn && evs[5].code == VirtioInputDevice::kSynReport);

    std::cout << "[PASS] Test 3: Android KeyEvent + gamepad button & analog axis translation\n";
}

// Test 4: Real EL0 AArch64 guest ELF binary opening /dev/input/event0 & event1,
// verifying EVIOCGVERSION / EVIOCGNAME / EVIOCGABS, O_NONBLOCK -EAGAIN,
// blocking ppoll -> WfiWait yield, and live host InjectTouch + InjectKey wake-up.
void TestEl0EvdevSyscallAndWfiWake() {
    CodeBlobBuilder cb;
    const size_t path_ev0 = cb.AddString("/dev/input/event0");
    const size_t path_ev1 = cb.AddString("/dev/input/event1");

    // Stack frame layout (total 1024 bytes):
    //   sp +   0: ioctl temp / version / absinfo (32B)
    //   sp +  32: name buffer (64B)
    //   sp +  96: struct pollfd (8B: int32 fd, int16 events, int16 revents)
    //   sp + 128: input_event read buffer (512B = up to 21 * 24B events)
    cb.insns.push_back(SubImm64(31, 31, 1024u));

    auto emit_fail = [&](uint16_t code) {
        cb.insns.push_back(Movz(0, code, 0));
        cb.insns.push_back(Movz(8, 94u, 0)); // __NR_exit_group
        cb.insns.push_back(Svc(0));
    };

    // 1. x19 = openat(-100, "/dev/input/event0", O_RDONLY=0, 0)
    cb.insns.push_back(Movn(0, 99u, 0)); // -100
    cb.EmitAdrPlaceholder(1, path_ev0);
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0)); // __NR_openat
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));
    cb.insns.push_back(CmpImm64(19, 3u));
    const size_t br_fd0_ok = cb.EmitCondPlaceholder(10u /*GE*/);
    emit_fail(10u);
    cb.PatchBranchToHere(br_fd0_ok);

    // 2. x20 = openat(-100, "/dev/input/event1", O_RDONLY|O_NONBLOCK=0x800, 0)
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, path_ev1);
    cb.insns.push_back(Movz(2, 0x0800u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(20, 0));
    cb.insns.push_back(CmpImm64(20, 4u));
    const size_t br_fd1_ok = cb.EmitCondPlaceholder(10u /*GE*/);
    emit_fail(11u);
    cb.PatchBranchToHere(br_fd1_ok);

    // 3. ioctl(fd0, EVIOCGVERSION=0x80044501, sp) -> expect 0x010001
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4501u, 0));
    cb.insns.push_back(Movk(1, 0x8004u, 1));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0)); // __NR_ioctl
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(9, 31, 0u));
    cb.insns.push_back(Movz(10, 0x0001u, 0));
    cb.insns.push_back(Movk(10, 0x0001u, 1));
    cb.insns.push_back(CmpReg64(9, 10));
    const size_t br_ver_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(12u);
    cb.PatchBranchToHere(br_ver_ok);

    // 4. ioctl(fd0, EVIOCGNAME(64)=0x80404506, sp+32) -> expect first 4 bytes == "Hase" (0x65736148 LE)
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4506u, 0));
    cb.insns.push_back(Movk(1, 0x8040u, 1));
    cb.insns.push_back(AddImm64(2, 31, 32u));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(9, 31, 32u));
    cb.insns.push_back(Movz(10, 0x6148u, 0));
    cb.insns.push_back(Movk(10, 0x6573u, 1));
    cb.insns.push_back(CmpReg64(9, 10));
    const size_t br_name_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(13u);
    cb.PatchBranchToHere(br_name_ok);

    // 5. ioctl(fd0, EVIOCGABS(ABS_MT_POSITION_X=0x35)=0x80184575, sp) -> maximum at +8 == 799
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4575u, 0));
    cb.insns.push_back(Movk(1, 0x8018u, 1));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(9, 31, 8u));
    cb.insns.push_back(CmpImm64(9, 799u));
    const size_t br_abs_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(14u);
    cb.PatchBranchToHere(br_abs_ok);

    // 6. read(fd1, sp+128, 24) on empty non-blocking kbd -> expect -11 (-EAGAIN)
    cb.insns.push_back(Movr64(0, 20));
    cb.insns.push_back(AddImm64(1, 31, 128u));
    cb.insns.push_back(Movz(2, 24u, 0));
    cb.insns.push_back(Movz(8, 63u, 0)); // __NR_read
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movn(10, 10u, 0)); // -11
    cb.insns.push_back(CmpReg64(0, 10));
    const size_t br_eagain_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(15u);
    cb.PatchBranchToHere(br_eagain_ok);

    // 7. ppoll({fd0, POLLIN=1, 0}, 1, NULL, NULL) -> blocks in WfiWait until host injects touch
    cb.insns.push_back(StrW(19, 31, 96u)); // pollfd.fd = fd0
    cb.insns.push_back(Movz(9, 1u, 0));
    cb.insns.push_back(StrH(9, 31, 100u)); // pollfd.events = POLLIN
    cb.insns.push_back(StrH(31, 31, 102u)); // pollfd.revents = 0 (wzr=31)
    cb.insns.push_back(AddImm64(0, 31, 96u));
    cb.insns.push_back(Movz(1, 1u, 0));
    cb.insns.push_back(Movz(2, 0u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 73u, 0)); // __NR_ppoll
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 1u));
    const size_t br_poll_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(16u);
    cb.PatchBranchToHere(br_poll_ok);

    // 8. read(fd0, sp+128, 384) (up to 16 LinuxInputEvent structs) & scan for X==320 and Y==640
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(AddImm64(1, 31, 128u));
    cb.insns.push_back(Movz(2, 384u, 0));
    cb.insns.push_back(Movz(8, 63u, 0)); // __NR_read
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 24u));
    const size_t br_tread_ok = cb.EmitCondPlaceholder(10u /*GE*/);
    emit_fail(17u);
    cb.PatchBranchToHere(br_tread_ok);

    // x21 = bytes_read, x22 = cursor, x23 = found_flags (bit0: X==320, bit1: Y==640)
    cb.insns.push_back(Movr64(21, 0));
    cb.insns.push_back(Movz(22, 0u, 0));
    cb.insns.push_back(Movz(23, 0u, 0));

    const size_t loop_top = cb.insns.size();
    cb.insns.push_back(CmpReg64(22, 21));
    const size_t br_loop_done = cb.EmitCondPlaceholder(10u /*GE*/);
    // x11 = sp + 128 + x22
    cb.insns.push_back(AddImm64(11, 31, 128u));
    cb.insns.push_back(0x8B16016Bu); // ADD X11, X11, X22
    cb.insns.push_back(LdrH(12, 11, 16u)); // type
    cb.insns.push_back(LdrH(13, 11, 18u)); // code
    cb.insns.push_back(LdrW(14, 11, 20u)); // value
    cb.insns.push_back(CmpImm64(12, VirtioInputDevice::kEvAbs));
    const size_t br_not_abs = cb.EmitCondPlaceholder(1u /*NE*/);

    // Check ABS_MT_POSITION_X == 320
    cb.insns.push_back(CmpImm64(13, VirtioInputDevice::kAbsMtPositionX));
    const size_t br_not_x = cb.EmitCondPlaceholder(1u /*NE*/);
    cb.insns.push_back(CmpImm64(14, 320u));
    const size_t br_x_mismatch = cb.EmitCondPlaceholder(1u /*NE*/);
    cb.insns.push_back(0xB24002F7u); // ORR X23, X23, #1
    cb.PatchBranchToHere(br_x_mismatch);
    cb.PatchBranchToHere(br_not_x);

    // Check ABS_MT_POSITION_Y == 640
    cb.insns.push_back(CmpImm64(13, VirtioInputDevice::kAbsMtPositionY));
    const size_t br_not_y = cb.EmitCondPlaceholder(1u /*NE*/);
    cb.insns.push_back(CmpImm64(14, 640u));
    const size_t br_y_mismatch = cb.EmitCondPlaceholder(1u /*NE*/);
    cb.insns.push_back(0xB27F02F7u); // ORR X23, X23, #2
    cb.PatchBranchToHere(br_y_mismatch);
    cb.PatchBranchToHere(br_not_y);

    cb.PatchBranchToHere(br_not_abs);
    cb.insns.push_back(AddImm64(22, 22, 24u));
    cb.insns.push_back(BImm(static_cast<int32_t>(loop_top) - static_cast<int32_t>(cb.insns.size())));
    cb.PatchBranchToHere(br_loop_done);

    cb.insns.push_back(CmpImm64(23, 3u));
    const size_t br_xy_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(18u);
    cb.PatchBranchToHere(br_xy_ok);

    // 9. read(fd1, sp+128, 48) -> expect 48 bytes with BTN_SOUTH (0x130) == 1
    cb.insns.push_back(Movr64(0, 20));
    cb.insns.push_back(AddImm64(1, 31, 128u));
    cb.insns.push_back(Movz(2, 48u, 0));
    cb.insns.push_back(Movz(8, 63u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 48u));
    const size_t br_kread_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(19u);
    cb.PatchBranchToHere(br_kread_ok);

    cb.insns.push_back(LdrH(12, 31, 128u + 16u)); // type == 1 (EV_KEY)
    cb.insns.push_back(LdrH(13, 31, 128u + 18u)); // code == 0x130 (BTN_SOUTH)
    cb.insns.push_back(LdrW(14, 31, 128u + 20u)); // value == 1
    cb.insns.push_back(CmpImm64(12, VirtioInputDevice::kEvKey));
    const size_t br_ktype_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(20u);
    cb.PatchBranchToHere(br_ktype_ok);
    cb.insns.push_back(CmpImm64(13, VirtioInputDevice::kBtnSouth));
    const size_t br_kcode_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(21u);
    cb.PatchBranchToHere(br_kcode_ok);
    cb.insns.push_back(CmpImm64(14, 1u));
    const size_t br_kval_ok = cb.EmitCondPlaceholder(0u /*EQ*/);
    emit_fail(22u);
    cb.PatchBranchToHere(br_kval_ok);

    // Success -> exit_group(0)
    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movz(8, 94u, 0));
    cb.insns.push_back(Svc(0));

    const std::vector<uint8_t> init_elf = BuildElf64(cb.Finalize());
    CpioEntry e_init;
    e_init.name = "init";
    e_init.mode = 0100755u;
    e_init.nlink = 1u;
    e_init.data = init_elf;

    std::vector<uint8_t> boot_bytes = BuildBootImgV2(CpioArchive::Build({e_init}));
    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(boot_bytes, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    cfg.width = 800u;
    cfg.height = 1280u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);

    std::string target;
    HASEEB_CHECK(vm.BootGuest(false, target, err) == VmError::Ok);
    HASEEB_CHECK(target == "/init");

    // Step 1: EL0 binary probes evdev ioctls, verifies -EAGAIN, then blocks on ppoll()
    HASEEB_CHECK(vm.StepGuest(50000ULL) == VmError::Ok);
    HASEEB_CHECK(!vm.CpuState().halted);
    HASEEB_CHECK(vm.CpuState().waiting_for_interrupt);
    HASEEB_CHECK(vm.CpuState().stop_reason == CpuStopReason::WfiWait);

    // Step 2: Host injects touch down/up and gamepad BUTTON_A, then resumes guest
    vm.InjectTouch(0 /*ACTION_DOWN*/, 320, 640, 0);
    vm.InjectTouch(1 /*ACTION_UP*/, 320, 640, 0);
    vm.InjectKey(96 /*KEYCODE_BUTTON_A*/, true);

    HASEEB_CHECK(vm.StepGuest(100000ULL) == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);
    HASEEB_CHECK(vm.Supervisor()->Exited());
    HASEEB_CHECK(vm.Supervisor()->ExitStatus() == 0);

    vm.Shutdown();
    std::cout << "[PASS] Test 4: EL0 /dev/input/event0..1 ioctl/nonblock/ppoll WfiWait wake & touch+gamepad delivery\n";
}

} // namespace

int main() {
    TestVirtioInputProbeConfigAndIrq();
    TestMultiTouchTypeBStateMachine();
    TestAndroidKeyAndGamepadTranslation();
    TestEl0EvdevSyscallAndWfiWake();
    std::cout << "ALL M6 INPUT & EVDEV TESTS PASSED.\n";
    return 0;
}
