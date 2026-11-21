#include "haseeb/boot_image.hpp"
#include "haseeb/kernel_boot.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/virtio_gpu.hpp"
#include "haseeb/virtio_mmio.hpp"

#include <cassert>
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
    uint32_t qsize = 16;
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
                            uint32_t qsize = 16u) {
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

uint32_t SubmitControlReqResp(GuestRam& ram,
                              VirtioMmioDevice& dev,
                              SplitQueueLayout& q,
                              uint64_t req_pa,
                              const void* req_bytes,
                              uint32_t req_len,
                              uint64_t resp_pa,
                              void* out_resp,
                              uint32_t resp_cap) {
    HASEEB_CHECK(ram.WriteBytes(req_pa, req_bytes, req_len));
    std::vector<uint8_t> zeros(resp_cap, 0u);
    HASEEB_CHECK(ram.WriteBytes(resp_pa, zeros.data(), resp_cap));

    const uint16_t d0_idx = (q.next_avail * 2u) % q.qsize;
    const uint16_t d1_idx = static_cast<uint16_t>((d0_idx + 1u) % q.qsize);

    RawVringDesc d0{req_pa, req_len, 1u /*NEXT*/, d1_idx};
    RawVringDesc d1{resp_pa, resp_cap, 2u /*WRITE*/, 0u};
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d0_idx) * 16ULL, &d0, sizeof(d0)));
    HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d1_idx) * 16ULL, &d1, sizeof(d1)));

    const uint16_t slot = q.next_avail % q.qsize;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + slot * 2ULL, &d0_idx, sizeof(d0_idx)));
    ++q.next_avail;
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));

    dev.Write(0x050u, 4, 0u); // QueueNotify queue 0

    uint16_t used_idx = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 2ULL, &used_idx, sizeof(used_idx)));
    HASEEB_CHECK(used_idx != q.next_used_seen);
    const uint16_t u_slot = q.next_used_seen % q.qsize;
    uint32_t used_len = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + u_slot * 8ULL + 4ULL, &used_len, 4));
    ++q.next_used_seen;

    HASEEB_CHECK(used_len <= resp_cap);
    if (used_len > 0u) {
        HASEEB_CHECK(ram.ReadBytes(resp_pa, out_resp, used_len));
    }
    return used_len;
}

void SubmitSingleOutReq(GuestRam& ram,
                        VirtioMmioDevice& dev,
                        SplitQueueLayout& q,
                        uint32_t qidx,
                        uint64_t req_pa,
                        const void* req_bytes,
                        uint32_t req_len) {
    HASEEB_CHECK(ram.WriteBytes(req_pa, req_bytes, req_len));
    const uint16_t d_idx = q.next_avail % q.qsize;
    RawVringDesc d{req_pa, req_len, 0u, 0u};
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

#pragma pack(push, 1)
struct GpuCtrlHdr {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint8_t ring_idx;
    uint8_t padding[3];
};
struct GpuRect { uint32_t x, y, w, h; };
struct GpuDisplayOne { GpuRect r; uint32_t enabled, flags; };
struct GpuRespDisplayInfo { GpuCtrlHdr hdr; GpuDisplayOne pmodes[16]; };
struct GpuCmdCreate2d { GpuCtrlHdr hdr; uint32_t res_id, fmt, w, h; };
struct GpuCmdUnref { GpuCtrlHdr hdr; uint32_t res_id, pad; };
struct GpuCmdSetScanout { GpuCtrlHdr hdr; GpuRect r; uint32_t scanout_id, res_id; };
struct GpuCmdFlush { GpuCtrlHdr hdr; GpuRect r; uint32_t res_id, pad; };
struct GpuCmdTransfer2d { GpuCtrlHdr hdr; GpuRect r; uint64_t offset; uint32_t res_id, pad; };
struct GpuCmdAttachBacking { GpuCtrlHdr hdr; uint32_t res_id, nr_entries; };
struct GpuMemEntry { uint64_t addr; uint32_t len, pad; };
struct GpuCmdCursor {
    GpuCtrlHdr hdr;
    uint32_t scanout_id, x, y, pad0;
    uint32_t res_id, hot_x, hot_y, pad1;
};
#pragma pack(pop)

// Minimal AArch64 assembler for EL0 /dev/fb0 test
uint32_t Movz(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0xD2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
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
uint32_t LdrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9400000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t StrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0xB9000000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}
uint32_t Svc(uint16_t imm = 0) {
    return 0xD4000001u | (static_cast<uint32_t>(imm) << 5);
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
    std::vector<uint8_t> Finalize() {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : patches) {
            insns[p.insn_idx] = Adr(p.rd, static_cast<int32_t>(code_bytes + p.data_offset) -
                                          static_cast<int32_t>(p.insn_idx * 4u));
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

// Test 1: Virtio-MMIO slot 5 probe (DeviceID=16) + GET_DISPLAY_INFO
void TestVirtioGpuProbeAndDisplayInfo() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    cfg.width = 800u;
    cfg.height = 600u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    // Enable GICv3 distributor + CPU0 redistributor to observe SPI 21 (INTID 53)
    vm.Gic().WriteGicd(0x0000u, 4, 0x2u);
    vm.Gic().WriteGicr(0x0014u, 4, 0x0u);
    vm.Gic().WriteSysReg(0, GicV3::kIccPmrEl1, 0xFFu);
    vm.Gic().WriteSysReg(0, GicV3::kIccIgrpen1El1, 1u);
    vm.Gic().WriteGicd(0x0104u, 4, (1u << (53u - 32u)));
    vm.Gic().WriteGicd(0x6000u + 53u * 8u, 8, 0ULL);

    // Read Virtio-MMIO slot 5 through guest MmioBus at 0x0A000A00
    uint64_t val = 0;
    const uint64_t gpu_base = kVirtioMmioBase + 5ULL * kVirtioMmioStride;
    HASEEB_CHECK(vm.Bus().Read(gpu_base + 0x000u, 4, val) && val == 0x74726976u); // "virt"
    HASEEB_CHECK(vm.Bus().Read(gpu_base + 0x004u, 4, val) && val == 2u);          // version 2
    HASEEB_CHECK(vm.Bus().Read(gpu_base + 0x008u, 4, val) && val == 16u);         // GPU device ID
    HASEEB_CHECK(vm.Bus().Read(gpu_base + 0x108u, 4, val) && val == 1u);          // num_scanouts

    VirtioMmioDevice& gpu_mmio = vm.VirtioMmio(5u);
    gpu_mmio.Write(0x070u, 4, 15u); // ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK
    SplitQueueLayout ctrl_q = SetupVirtq(vm.Ram(), gpu_mmio, 0u, kGuestRamBase + 0x0100000ULL);

    GpuCtrlHdr req{};
    req.type = VirtioGpuDevice::kCmdGetDisplayInfo;
    req.flags = 1u;
    req.fence_id = 77ULL;
    GpuRespDisplayInfo resp{};
    uint32_t n = SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q,
                                      kGuestRamBase + 0x0200000ULL, &req, sizeof(req),
                                      kGuestRamBase + 0x0201000ULL, &resp, sizeof(resp));
    HASEEB_CHECK(n == sizeof(GpuRespDisplayInfo));
    HASEEB_CHECK(resp.hdr.type == VirtioGpuDevice::kRespOkDisplayInfo);
    HASEEB_CHECK(resp.hdr.fence_id == 77ULL);
    HASEEB_CHECK(resp.pmodes[0].enabled == 1u);
    HASEEB_CHECK(resp.pmodes[0].r.w == 800u && resp.pmodes[0].r.h == 600u);

    // GIC SPI 21 (INTID 53) must have fired
    HASEEB_CHECK(vm.Gic().HasPendingIrq(0));
    HASEEB_CHECK(vm.Gic().ReadSysReg(0, GicV3::kIccIar1El1) == 53u);
    gpu_mmio.Write(0x064u, 4, gpu_mmio.Read(0x060u, 4));
    vm.Gic().WriteSysReg(0, GicV3::kIccEoir1El1, 53u);

    vm.Shutdown();
    std::cout << "[PASS] Test 1: Virtio-MMIO slot 5 GPU probe (ID=16), SPI 21 IRQ & GET_DISPLAY_INFO\n";
}

// Test 2: Full 2D pipeline (CREATE_2D, multi-extent ATTACH_BACKING, TRANSFER_TO_HOST_2D,
// SET_SCANOUT, RESOURCE_FLUSH) + BGRA->RGBA conversion & ScanoutCallback
void TestVirtioGpu2dScanoutPipeline() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    cfg.width = 4u;
    cfg.height = 4u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    uint64_t cb_count = 0;
    std::vector<uint32_t> cb_pixels;
    vm.VirtioGpu().SetScanoutCallback(
        [&](const uint32_t* px, uint32_t w, uint32_t h, uint64_t idx) {
            ++cb_count;
            HASEEB_CHECK(w == 4u && h == 4u && idx == cb_count);
            cb_pixels.assign(px, px + static_cast<size_t>(w) * h);
        });

    VirtioMmioDevice& gpu_mmio = vm.VirtioMmio(5u);
    SplitQueueLayout ctrl_q = SetupVirtq(vm.Ram(), gpu_mmio, 0u, kGuestRamBase + 0x0100000ULL);
    const uint64_t req_pa = kGuestRamBase + 0x0200000ULL;
    const uint64_t resp_pa = kGuestRamBase + 0x0201000ULL;

    // 1. RESOURCE_CREATE_2D (id=10, B8G8R8A8_UNORM -> normalized to RGBA8888)
    GpuCmdCreate2d create{};
    create.hdr.type = VirtioGpuDevice::kCmdResourceCreate2d;
    create.res_id = 10u;
    create.fmt = VirtioGpuDevice::kFormatB8G8R8A8Unorm;
    create.w = 4u;
    create.h = 4u;
    GpuCtrlHdr resp{};
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &create, sizeof(create), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespOkNodata);

    // 2. Write BGRA pixels split across two non-contiguous GuestRam backing extents
    // Pixel BGRA bytes: [B=0x33, G=0x22, R=0x11, A=0xFF] -> RGBA8888 bytes [R=0x11, G=0x22, B=0x33, A=0xFF] = 0xFF332211u
    const uint64_t ext0_pa = kGuestRamBase + 0x0300000ULL;
    const uint64_t ext1_pa = kGuestRamBase + 0x0305000ULL;
    uint32_t row01[8];
    uint32_t row23[8];
    for (int i = 0; i < 8; ++i) {
        row01[i] = 0xFF112233u; // LE memory bytes [0x33(B), 0x22(G), 0x11(R), 0xFF(A)]
        row23[i] = 0xFF445566u; // LE memory bytes [0x66(B), 0x55(G), 0x44(R), 0xFF(A)]
    }
    HASEEB_CHECK(vm.Ram().WriteBytes(ext0_pa, row01, sizeof(row01)));
    HASEEB_CHECK(vm.Ram().WriteBytes(ext1_pa, row23, sizeof(row23)));

    std::vector<uint8_t> attach_buf(sizeof(GpuCmdAttachBacking) + 2u * sizeof(GpuMemEntry), 0u);
    GpuCmdAttachBacking ab{};
    ab.hdr.type = VirtioGpuDevice::kCmdResourceAttachBacking;
    ab.res_id = 10u;
    ab.nr_entries = 2u;
    std::memcpy(attach_buf.data(), &ab, sizeof(ab));
    GpuMemEntry me[2]{{ext0_pa, 32u, 0u}, {ext1_pa, 32u, 0u}};
    std::memcpy(attach_buf.data() + sizeof(ab), me, sizeof(me));
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, attach_buf.data(),
                         static_cast<uint32_t>(attach_buf.size()), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespOkNodata);

    // 3. TRANSFER_TO_HOST_2D (full 4x4)
    GpuCmdTransfer2d xfer{};
    xfer.hdr.type = VirtioGpuDevice::kCmdTransferToHost2d;
    xfer.r = {0u, 0u, 4u, 4u};
    xfer.offset = 0ULL;
    xfer.res_id = 10u;
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &xfer, sizeof(xfer), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespOkNodata);

    // 4. SET_SCANOUT
    GpuCmdSetScanout ss{};
    ss.hdr.type = VirtioGpuDevice::kCmdSetScanout;
    ss.r = {0u, 0u, 4u, 4u};
    ss.scanout_id = 0u;
    ss.res_id = 10u;
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &ss, sizeof(ss), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespOkNodata);
    HASEEB_CHECK(vm.VirtioGpu().ActiveScanoutResourceId() == 10u);

    // 5. RESOURCE_FLUSH -> triggers scanout + converts BGRA -> RGBA
    GpuCmdFlush fl{};
    fl.hdr.type = VirtioGpuDevice::kCmdResourceFlush;
    fl.r = {0u, 0u, 4u, 4u};
    fl.res_id = 10u;
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &fl, sizeof(fl), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespOkNodata);
    HASEEB_CHECK(cb_count == 1u);
    HASEEB_CHECK(vm.VirtioGpu().FrameCount() == 1u);
    HASEEB_CHECK(cb_pixels.size() == 16u);
    HASEEB_CHECK(cb_pixels[0] == 0xFF332211u);  // RGBA: R=0x11, G=0x22, B=0x33, A=0xFF
    HASEEB_CHECK(cb_pixels[15] == 0xFF665544u); // RGBA: R=0x44, G=0x55, B=0x66, A=0xFF

    vm.Shutdown();
    std::cout << "[PASS] Test 2: Virtio-GPU 2D scanout pipeline + scatter-gather backing & BGRA->RGBA\n";
}

// Test 3: cursorq (UPDATE_CURSOR / MOVE_CURSOR), RESOURCE_UNREF & error codes
void TestCursorQueueAndErrorHandling() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    VirtioMmioDevice& gpu_mmio = vm.VirtioMmio(5u);
    SplitQueueLayout ctrl_q = SetupVirtq(vm.Ram(), gpu_mmio, 0u, kGuestRamBase + 0x0100000ULL);
    SplitQueueLayout cur_q = SetupVirtq(vm.Ram(), gpu_mmio, 1u, kGuestRamBase + 0x0110000ULL);
    const uint64_t req_pa = kGuestRamBase + 0x0200000ULL;
    const uint64_t resp_pa = kGuestRamBase + 0x0201000ULL;

    GpuCmdCursor uc{};
    uc.hdr.type = VirtioGpuDevice::kCmdUpdateCursor;
    uc.scanout_id = 0u;
    uc.x = 120u;
    uc.y = 340u;
    uc.res_id = 5u;
    SubmitSingleOutReq(vm.Ram(), gpu_mmio, cur_q, 1u, req_pa, &uc, sizeof(uc));
    HASEEB_CHECK(vm.VirtioGpu().CursorVisible());
    HASEEB_CHECK(vm.VirtioGpu().CursorX() == 120 && vm.VirtioGpu().CursorY() == 340);

    GpuCmdCursor mc{};
    mc.hdr.type = VirtioGpuDevice::kCmdMoveCursor;
    mc.x = 250u;
    mc.y = 480u;
    SubmitSingleOutReq(vm.Ram(), gpu_mmio, cur_q, 1u, req_pa, &mc, sizeof(mc));
    HASEEB_CHECK(vm.VirtioGpu().CursorX() == 250 && vm.VirtioGpu().CursorY() == 480);

    // Invalid scanout ID must return ERR_INVALID_SCANOUT_ID
    GpuCmdSetScanout bad_ss{};
    bad_ss.hdr.type = VirtioGpuDevice::kCmdSetScanout;
    bad_ss.scanout_id = 3u;
    bad_ss.res_id = 1u;
    GpuCtrlHdr resp{};
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &bad_ss, sizeof(bad_ss), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespErrInvalidScanoutId);

    // Unref non-existent resource must return ERR_INVALID_RESOURCE_ID
    GpuCmdUnref bad_unref{};
    bad_unref.hdr.type = VirtioGpuDevice::kCmdResourceUnref;
    bad_unref.res_id = 999u;
    SubmitControlReqResp(vm.Ram(), gpu_mmio, ctrl_q, req_pa, &bad_unref, sizeof(bad_unref), resp_pa, &resp, sizeof(resp));
    HASEEB_CHECK(resp.type == VirtioGpuDevice::kRespErrInvalidResourceId);

    vm.Shutdown();
    std::cout << "[PASS] Test 3: cursorq UPDATE/MOVE + invalid scanout/resource error handling\n";
}

// Test 4: Real EL0 /dev/fb0 test binary querying FBIOGET_VSCREENINFO/FSCREENINFO,
// mmap'ing framebuffer, rendering 3 animated frames, and calling FBIOPAN_DISPLAY
void TestEl0FramebufferScanout() {
    CodeBlobBuilder cb;
    const size_t fb_path = cb.AddString("/dev/fb0");

    // Reserve stack space: sp + 0..255 for vinfo/finfo
    cb.insns.push_back(SubImm64(31, 31, 256u));

    // x19 = openat(-100, "/dev/fb0", O_RDWR=2, 0)
    cb.insns.push_back(Movz(0, 0, 0));
    cb.EmitAdrPlaceholder(1, fb_path);
    cb.insns.push_back(Movz(2, 2u, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0)); // __NR_openat
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(19, 0));

    // ioctl(fb_fd, FBIOGET_VSCREENINFO=0x4600, sp)
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4600u, 0));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0)); // __NR_ioctl
    cb.insns.push_back(Svc(0));

    // Verify xres == 16 (w20), yres == 16 (w21)
    cb.insns.push_back(LdrW(20, 31, 0u));
    cb.insns.push_back(LdrW(21, 31, 4u));

    // ioctl(fb_fd, FBIOGET_FSCREENINFO=0x4602, sp)
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4602u, 0));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));

    // w22 = finfo.smem_len at sp + 24 (16*16*4 = 1024)
    cb.insns.push_back(LdrW(22, 31, 24u));

    // x23 = mmap(0, smem_len, PROT_READ|PROT_WRITE=3, MAP_SHARED=1, fb_fd, 0)
    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movr64(1, 22));
    cb.insns.push_back(Movz(2, 3u, 0));
    cb.insns.push_back(Movz(3, 1u, 0));
    cb.insns.push_back(Movr64(4, 19));
    cb.insns.push_back(Movz(5, 0u, 0));
    cb.insns.push_back(Movz(8, 222u, 0)); // __NR_mmap
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movr64(23, 0));

    // Paint 3 frames: frame f in {0, 1, 2}, pixel = 0xFF000010 + frame*0x00101010
    auto emit_frame = [&](uint32_t rgba_pixel) {
        cb.insns.push_back(Movz(10, static_cast<uint16_t>(rgba_pixel & 0xFFFFu), 0));
        cb.insns.push_back(Movk(10, static_cast<uint16_t>(rgba_pixel >> 16), 1));
        cb.insns.push_back(Movr64(11, 23)); // ptr
        cb.insns.push_back(Movz(12, 0u, 0));  // i = 0
        const size_t fill_loop = cb.insns.size();
        cb.insns.push_back(StrW(10, 11, 0u));
        cb.insns.push_back(AddImm64(11, 11, 4u));
        cb.insns.push_back(AddImm64(12, 12, 1u));
        cb.insns.push_back(CmpImm64(12, 256u)); // 16*16 pixels
        cb.insns.push_back(BCond(11u /*LT*/, static_cast<int32_t>(fill_loop - cb.insns.size())));

        // ioctl(fb_fd, FBIOPAN_DISPLAY=0x4606, sp)
        cb.insns.push_back(Movr64(0, 19));
        cb.insns.push_back(Movz(1, 0x4606u, 0));
        cb.insns.push_back(Movr64(2, 31));
        cb.insns.push_back(Movz(8, 29u, 0));
        cb.insns.push_back(Svc(0));
    };

    emit_frame(0xFF0000AAu);
    emit_frame(0xFF00BB00u);
    emit_frame(0xFFCC2211u);

    // exit_group(0)
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
    cfg.width = 16u;
    cfg.height = 16u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);

    std::vector<uint32_t> observed_first_pixels;
    vm.VirtioGpu().SetScanoutCallback(
        [&](const uint32_t* px, uint32_t w, uint32_t h, uint64_t /*idx*/) {
            HASEEB_CHECK(w == 16u && h == 16u);
            observed_first_pixels.push_back(px[0]);
        });

    std::string target;
    HASEEB_CHECK(vm.BootGuest(false, target, err) == VmError::Ok);
    HASEEB_CHECK(target == "/init");
    HASEEB_CHECK(vm.StepGuest(100000ULL) == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);
    HASEEB_CHECK(vm.Supervisor()->Exited() && vm.Supervisor()->ExitStatus() == 0);

    HASEEB_CHECK(vm.VirtioGpu().FrameCount() == 3u);
    HASEEB_CHECK(observed_first_pixels.size() == 3u);
    HASEEB_CHECK(observed_first_pixels[0] == 0xFF0000AAu);
    HASEEB_CHECK(observed_first_pixels[1] == 0xFF00BB00u);
    HASEEB_CHECK(observed_first_pixels[2] == 0xFFCC2211u);

    std::vector<uint32_t> latest;
    uint32_t lw = 0, lh = 0;
    HASEEB_CHECK(vm.VirtioGpu().CopyLatestFrame(latest, lw, lh));
    HASEEB_CHECK(lw == 16u && lh == 16u && latest.size() == 256u);
    HASEEB_CHECK(latest[255] == 0xFFCC2211u);

    vm.Shutdown();
    std::cout << "[PASS] Test 4: EL0 /dev/fb0 ioctl/mmap/FBIOPAN_DISPLAY -> 3 animated VirtioGpu frames\n";
}

} // namespace

int main() {
    TestVirtioGpuProbeAndDisplayInfo();
    TestVirtioGpu2dScanoutPipeline();
    TestCursorQueueAndErrorHandling();
    TestEl0FramebufferScanout();
    std::cout << "ALL M5 DISPLAY & VIRTIO-GPU TESTS PASSED.\n";
    return 0;
}
