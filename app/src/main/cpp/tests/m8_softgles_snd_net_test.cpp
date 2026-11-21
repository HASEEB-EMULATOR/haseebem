#include "haseeb/boot_image.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/soft_gles.hpp"
#include "haseeb/virtio_mmio.hpp"
#include "haseeb/virtio_snd_net.hpp"

#include <array>
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
                   uint32_t stride_bytes) {
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

std::vector<std::vector<uint8_t>> DrainUsedRxFrames(GuestRam& ram,
                                                    SplitQueueLayout& q,
                                                    uint64_t buf_base_pa,
                                                    uint32_t stride_bytes) {
    uint16_t used_idx = 0;
    HASEEB_CHECK(ram.ReadBytes(q.used_pa + 2ULL, &used_idx, sizeof(used_idx)));
    std::vector<std::vector<uint8_t>> out;
    while (q.next_used_seen != used_idx) {
        const uint16_t u_slot = q.next_used_seen % q.qsize;
        uint32_t id = 0, len = 0;
        HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + u_slot * 8ULL, &id, 4));
        HASEEB_CHECK(ram.ReadBytes(q.used_pa + 4ULL + u_slot * 8ULL + 4ULL, &len, 4));
        std::vector<uint8_t> pkt(len);
        if (len > 0u) {
            HASEEB_CHECK(ram.ReadBytes(buf_base_pa + static_cast<uint64_t>(id) * stride_bytes,
                                       pkt.data(), len));
        }
        out.push_back(std::move(pkt));
        ++q.next_used_seen;
    }
    return out;
}

void SubmitOutChain(GuestRam& ram,
                    VirtioMmioDevice& dev,
                    SplitQueueLayout& q,
                    uint32_t qidx,
                    uint64_t out_pa,
                    const void* out_data,
                    uint32_t out_len,
                    uint64_t resp_pa = 0ULL,
                    uint32_t resp_len = 0u) {
    HASEEB_CHECK(ram.WriteBytes(out_pa, out_data, out_len));
    const uint16_t d0 = q.next_avail % q.qsize;
    if (resp_len > 0u) {
        const uint16_t d1 = (q.next_avail + 1u) % q.qsize;
        RawVringDesc desc0{out_pa, out_len, 1u /*NEXT*/, d1};
        RawVringDesc desc1{resp_pa, resp_len, 2u /*WRITE*/, 0u};
        HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d0) * 16ULL, &desc0, sizeof(desc0)));
        HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d1) * 16ULL, &desc1, sizeof(desc1)));
        const uint16_t slot = q.next_avail % q.qsize;
        HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + slot * 2ULL, &d0, sizeof(d0)));
        q.next_avail += 2u;
    } else {
        RawVringDesc desc0{out_pa, out_len, 0u, 0u};
        HASEEB_CHECK(ram.WriteBytes(q.desc_pa + static_cast<uint64_t>(d0) * 16ULL, &desc0, sizeof(desc0)));
        const uint16_t slot = q.next_avail % q.qsize;
        HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 4ULL + slot * 2ULL, &d0, sizeof(d0)));
        ++q.next_avail;
    }
    HASEEB_CHECK(ram.WriteBytes(q.avail_pa + 2ULL, &q.next_avail, sizeof(q.next_avail)));
    dev.Write(0x050u, 4, qidx);
}

// AArch64 assembler helpers
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
    size_t AddBytes(const void* ptr, size_t len) {
        size_t off = data.size();
        const auto* p = static_cast<const uint8_t*>(ptr);
        data.insert(data.end(), p, p + len);
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

void AppendCmd(std::vector<uint8_t>& pkt, uint32_t op, const void* payload, uint32_t len) {
    AppendLe32(pkt, op);
    AppendLe32(pkt, len);
    if (len > 0u && payload) {
        const auto* p = static_cast<const uint8_t*>(payload);
        pkt.insert(pkt.end(), p, p + len);
    }
}

void TestSoftGlesCpuRasterizerAndVirtioGpuScanout() {
    SoftGlesContext gl;
    VirtioGpuDevice gpu;
    gpu.ConfigureDisplay(64u, 64u);
    gl.Reset(64u, 64u);

    HASEEB_CHECK(std::string(gl.GlGetString(SoftGlesContext::kGlRenderer)) ==
                 "Haseeb SoftGLES 3.0 CPU (ARM64 No-EGL)");

    gl.ClearColor(0.05f, 0.05f, 0.1f, 1.0f);
    gl.Clear(SoftGlesContext::kClearColorBit | SoftGlesContext::kClearDepthBit);
    gl.SetCapability(SoftGlesContext::kCapDepthTest, true);
    gl.SetCapability(SoftGlesContext::kCapBlend, true);

    // 2x2 white & red/teal texture
    const uint32_t tex[4] = {0xFFFFFFFFu, 0xFF4FE6BBu, 0xFF4FE6BBu, 0xFFFFFFFFu};
    gl.UploadTextureRgba(1u, 2u, 2u, tex, true);
    gl.BindTexture(1u);

    // Near opaque-ish green/teal triangle (z = 0.0)
    SoftGlesContext::Vertex v0{-0.8f, -0.8f, 0.0f, 1.0f, 0.3f, 0.9f, 0.7f, 1.0f, 0.0f, 0.0f, 0, 0, 1};
    SoftGlesContext::Vertex v1{ 0.8f, -0.8f, 0.0f, 1.0f, 0.3f, 0.9f, 0.7f, 1.0f, 1.0f, 0.0f, 0, 0, 1};
    SoftGlesContext::Vertex v2{ 0.0f,  0.8f, 0.0f, 1.0f, 0.3f, 0.9f, 0.7f, 1.0f, 0.5f, 1.0f, 0, 0, 1};
    gl.DrawTriangles({v0, v1, v2});

    // Far red triangle behind it (z = 0.6) -> must be rejected by Z-buffer at center!
    gl.BindTexture(0u);
    SoftGlesContext::Vertex f0{-0.9f, -0.9f, 0.6f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0, 0, 0, 0, 1};
    SoftGlesContext::Vertex f1{ 0.9f, -0.9f, 0.6f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0, 0, 0, 0, 1};
    SoftGlesContext::Vertex f2{ 0.0f,  0.9f, 0.6f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0, 0, 0, 0, 1};
    gl.DrawTriangles({f0, f1, f2});

    HASEEB_CHECK(gl.DrawCalls() == 2u);
    HASEEB_CHECK(gl.TrianglesRasterized() >= 1u);
    HASEEB_CHECK(gl.SwapBuffers(&gpu));
    HASEEB_CHECK(gpu.FrameCount() == 1u);

    std::vector<uint32_t> frame;
    uint32_t fw = 0, fh = 0;
    HASEEB_CHECK(gpu.CopyLatestFrame(frame, fw, fh));
    HASEEB_CHECK(fw == 64u && fh == 64u && frame.size() == 64u * 64u);
    const uint32_t center = frame[32u * 64u + 32u];
    const uint8_t r = static_cast<uint8_t>(center & 0xFFu);
    const uint8_t g = static_cast<uint8_t>((center >> 8) & 0xFFu);
    HASEEB_CHECK(g > r); // Teal foreground survived depth test over far red!

    std::cout << "[PASS] Test 1: Pure CPU SoftGlesContext (no EGL, Z-buffer, texture, lighting) -> VirtioGpuDevice scanout\n";
}

void TestVirtioSndMmioPlaybackAndCapture() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    const uint64_t snd_base = kVirtioMmioBase + 8ULL * kVirtioMmioStride; // 0x0A001000
    uint64_t val = 0;
    HASEEB_CHECK(vm.Bus().Read(snd_base + 0x000u, 4, val) && val == 0x74726976u);
    HASEEB_CHECK(vm.Bus().Read(snd_base + 0x008u, 4, val) && val == VirtioSndDevice::kVirtioIdSnd);
    HASEEB_CHECK(vm.Bus().Read(snd_base + 0x100u, 4, val) && val == 1u); // jacks=1
    HASEEB_CHECK(vm.Bus().Read(snd_base + 0x104u, 4, val) && val == 2u); // streams=2

    VirtioMmioDevice& snd_mmio = vm.VirtioMmio(8u);
    snd_mmio.Write(0x070u, 4, 15u);
    SplitQueueLayout txq = SetupVirtq(vm.Ram(), snd_mmio, 2u, kGuestRamBase + 0x0100000ULL, 16u);
    SplitQueueLayout rxq = SetupVirtq(vm.Ram(), snd_mmio, 3u, kGuestRamBase + 0x0110000ULL, 16u);

    // Guest sends 8-byte header + 4 stereo S16 samples via txq (queue 2)
    struct { uint32_t stream_id; uint32_t pad; int16_t pcm[4]; } pkt{0u, 0u, {1200, -1200, 3400, -3400}};
    SubmitOutChain(vm.Ram(), snd_mmio, txq, 2u,
                   kGuestRamBase + 0x0200000ULL, &pkt, sizeof(pkt),
                   kGuestRamBase + 0x0201000ULL, 8u);
    int16_t out_pcm[8]{};
    HASEEB_CHECK(vm.VirtioSnd().PopPlaybackPcm(out_pcm, 8u) == 4u);
    HASEEB_CHECK(out_pcm[0] == 1200 && out_pcm[1] == -1200 && out_pcm[2] == 3400 && out_pcm[3] == -3400);

    // Host pushes capture PCM -> guest rxq (queue 3) pops it
    const int16_t mic_pcm[4] = {500, 600, -700, -800};
    vm.VirtioSnd().PushCapturePcm(mic_pcm, 4u);
    uint8_t dummy_hdr[8]{};
    SubmitOutChain(vm.Ram(), snd_mmio, rxq, 3u,
                   kGuestRamBase + 0x0210000ULL, dummy_hdr, 8u,
                   kGuestRamBase + 0x0211000ULL, 16u);
    uint8_t rx_buf[16]{};
    HASEEB_CHECK(vm.Ram().ReadBytes(kGuestRamBase + 0x0211000ULL, rx_buf, sizeof(rx_buf)));
    int16_t got_mic[4]{};
    std::memcpy(got_mic, rx_buf + 8u, 8u);
    HASEEB_CHECK(got_mic[0] == 500 && got_mic[3] == -800);

    vm.Shutdown();
    std::cout << "[PASS] Test 2: Virtio-Snd MMIO slot 8 (0x0A001000, ID=25, SPI 24) playback & capture PCM\n";
}

void TestUserNatRouterArpIcmpDhcpDns() {
    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 32u;
    std::string err;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, nullptr, err) == VmError::Ok);

    VirtioMmioDevice& net_mmio = vm.VirtioMmio(1u);
    net_mmio.Write(0x070u, 4, 15u);
    SplitQueueLayout rxq = SetupVirtq(vm.Ram(), net_mmio, 0u, kGuestRamBase + 0x0100000ULL, 16u);
    SplitQueueLayout txq = SetupVirtq(vm.Ram(), net_mmio, 1u, kGuestRamBase + 0x0110000ULL, 16u);
    const uint64_t rx_buf_base = kGuestRamBase + 0x0200000ULL;
    PostRxBuffers(vm.Ram(), net_mmio, rxq, 0u, rx_buf_base, 8u, 1536u);

    const std::array<uint8_t, 6> guest_mac{0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    auto send_tx_frame = [&](const std::vector<uint8_t>& eth) {
        std::vector<uint8_t> with_hdr(12u + eth.size(), 0u); // virtio_net_hdr_v1 (12 bytes)
        std::memcpy(with_hdr.data() + 12u, eth.data(), eth.size());
        SubmitOutChain(vm.Ram(), net_mmio, txq, 1u,
                       kGuestRamBase + 0x0250000ULL, with_hdr.data(),
                       static_cast<uint32_t>(with_hdr.size()));
    };

    // 1. ARP Request who-has 10.0.2.2
    {
        std::vector<uint8_t> arp(42u, 0u);
        std::memset(arp.data(), 0xFF, 6u);
        std::memcpy(arp.data() + 6u, guest_mac.data(), 6u);
        arp[12] = 0x08; arp[13] = 0x06;
        arp[15] = 1; arp[16] = 0x08; arp[18] = 6; arp[19] = 4; arp[21] = 1;
        std::memcpy(arp.data() + 22u, guest_mac.data(), 6u);
        arp[28] = 10; arp[29] = 0; arp[30] = 2; arp[31] = 15;
        arp[38] = 10; arp[39] = 0; arp[40] = 2; arp[41] = 2;
        send_tx_frame(arp);

        auto rxs = DrainUsedRxFrames(vm.Ram(), rxq, rx_buf_base, 1536u);
        HASEEB_CHECK(rxs.size() == 1u);
        HASEEB_CHECK(rxs[0].size() >= 12u + 42u);
        const uint8_t* f = rxs[0].data() + 12u;
        HASEEB_CHECK(f[12] == 0x08 && f[13] == 0x06 && f[21] == 2u);
        HASEEB_CHECK(f[22] == 0x52 && f[27] == 0x02);
    }

    // 2. ICMP Echo Request -> 10.0.2.2
    {
        std::vector<uint8_t> icmp(14u + 20u + 8u, 0u);
        icmp[0] = 0x52; icmp[1] = 0x55; icmp[2] = 10; icmp[3] = 0; icmp[4] = 2; icmp[5] = 2;
        std::memcpy(icmp.data() + 6u, guest_mac.data(), 6u);
        icmp[12] = 0x08; icmp[13] = 0x00;
        icmp[14] = 0x45; icmp[17] = 28; icmp[22] = 64; icmp[23] = 1;
        icmp[26] = 10; icmp[27] = 0; icmp[28] = 2; icmp[29] = 15;
        icmp[30] = 10; icmp[31] = 0; icmp[32] = 2; icmp[33] = 2;
        icmp[34] = 8; // ECHO_REQUEST
        send_tx_frame(icmp);

        auto rxs = DrainUsedRxFrames(vm.Ram(), rxq, rx_buf_base, 1536u);
        HASEEB_CHECK(rxs.size() == 1u);
        const uint8_t* f = rxs[0].data() + 12u;
        HASEEB_CHECK(f[23] == 1u && f[34] == 0u); // ECHO_REPLY
    }

    // 3. DHCP DISCOVER -> DHCPOFFER (10.0.2.15, DNS 10.0.2.3)
    {
        std::vector<uint8_t> dhcp(14u + 20u + 8u + 250u, 0u);
        std::memset(dhcp.data(), 0xFF, 6u);
        std::memcpy(dhcp.data() + 6u, guest_mac.data(), 6u);
        dhcp[12] = 0x08; dhcp[13] = 0x00;
        dhcp[14] = 0x45; dhcp[23] = 17; // UDP
        dhcp[34] = 0; dhcp[35] = 68; dhcp[36] = 0; dhcp[37] = 67;
        uint8_t* b = dhcp.data() + 42u;
        b[0] = 1; b[1] = 1; b[2] = 6;
        b[4] = 0x12; b[5] = 0x34; b[6] = 0x56; b[7] = 0x78;
        std::memcpy(b + 28u, guest_mac.data(), 6u);
        b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;
        b[240] = 53; b[241] = 1; b[242] = 1; b[243] = 255;
        send_tx_frame(dhcp);

        auto rxs = DrainUsedRxFrames(vm.Ram(), rxq, rx_buf_base, 1536u);
        HASEEB_CHECK(rxs.size() == 1u);
        const uint8_t* rb = rxs[0].data() + 12u + 42u;
        HASEEB_CHECK(rb[0] == 2u && rb[16] == 10 && rb[17] == 0 && rb[18] == 2 && rb[19] == 15);
    }

    // 4. DNS A query for haseeb.vm -> 10.0.2.2
    {
        std::vector<uint8_t> dns(14u + 20u + 8u + 12u + 11u + 4u, 0u);
        std::memcpy(dns.data() + 6u, guest_mac.data(), 6u);
        dns[12] = 0x08; dns[13] = 0x00;
        dns[14] = 0x45; dns[23] = 17;
        dns[26] = 10; dns[27] = 0; dns[28] = 2; dns[29] = 15;
        dns[30] = 10; dns[31] = 0; dns[32] = 2; dns[33] = 3;
        dns[34] = 0xD0; dns[35] = 0x00; dns[36] = 0; dns[37] = 53;
        uint8_t* q = dns.data() + 42u;
        q[0] = 0xAA; q[1] = 0xBB; q[2] = 0x01; q[5] = 1;
        // 6 "haseeb" 2 "vm" 0
        q[12] = 6; std::memcpy(q + 13, "haseeb", 6);
        q[19] = 2; std::memcpy(q + 20, "vm", 2);
        q[22] = 0;
        q[24] = 1; q[26] = 1; // QTYPE A, CLASS IN
        send_tx_frame(dns);

        auto rxs = DrainUsedRxFrames(vm.Ram(), rxq, rx_buf_base, 1536u);
        HASEEB_CHECK(rxs.size() == 1u);
        const uint8_t* ans = rxs[0].data() + 12u + 42u;
        HASEEB_CHECK(ans[0] == 0xAA && ans[7] == 1u);
        const size_t rsz = rxs[0].size();
        HASEEB_CHECK(rxs[0][rsz - 4u] == 10 && rxs[0][rsz - 3u] == 0 &&
                     rxs[0][rsz - 2u] == 2 && rxs[0][rsz - 1u] == 2);
    }

    HASEEB_CHECK(vm.NatRouter().TxPackets() == 4u);
    HASEEB_CHECK(vm.NatRouter().RxPackets() == 4u);
    HASEEB_CHECK(vm.NatRouter().DnsQueries() == 1u);
    vm.Shutdown();
    std::cout << "[PASS] Test 3: UserNatRouter ARP, ICMP Echo, DHCP Offer (10.0.2.15) & DNS A resolution\n";
}

void TestEl0SoftGlesAndAudioEndToEnd() {
    // Prepare SoftGLES binary command stream for guest EL0 submission to /dev/haseeb_gles
    std::vector<uint8_t> gles_pkt;
    const uint32_t dim[2]{64u, 64u};
    AppendCmd(gles_pkt, SoftGlesContext::kCmdResize, dim, sizeof(dim));
    const float bg[4]{0.0f, 0.0f, 0.0f, 1.0f};
    AppendCmd(gles_pkt, SoftGlesContext::kCmdClearColor, bg, sizeof(bg));
    const uint32_t clear_mask = SoftGlesContext::kClearColorBit | SoftGlesContext::kClearDepthBit;
    AppendCmd(gles_pkt, SoftGlesContext::kCmdClear, &clear_mask, sizeof(clear_mask));

    SoftGlesContext::Vertex verts[3]{
        {-0.9f, -0.9f, 0.0f, 1.0f, 0.2f, 0.9f, 0.7f, 1.0f, 0, 0, 0, 0, 1},
        { 0.9f, -0.9f, 0.0f, 1.0f, 0.2f, 0.9f, 0.7f, 1.0f, 0, 0, 0, 0, 1},
        { 0.0f,  0.9f, 0.0f, 1.0f, 0.2f, 0.9f, 0.7f, 1.0f, 0, 0, 0, 0, 1},
    };
    AppendCmd(gles_pkt, SoftGlesContext::kCmdDrawTriangles, verts, sizeof(verts));
    AppendCmd(gles_pkt, SoftGlesContext::kCmdSwapBuffers, nullptr, 0u);

    const int16_t pcm_samples[16]{100, -100, 200, -200, 300, -300, 400, -400,
                                  500, -500, 600, -600, 700, -700, 800, -800};

    CodeBlobBuilder cb;
    const size_t s_gles = cb.AddString("/dev/haseeb_gles");
    const size_t s_snd = cb.AddString("/dev/snd/pcmC0D0p");
    const size_t s_pkt = cb.AddBytes(gles_pkt.data(), gles_pkt.size());
    const size_t s_pcm = cb.AddBytes(pcm_samples, sizeof(pcm_samples));

    cb.insns.push_back(SubImm64(31, 31, 256u));
    auto emit_fail = [&](uint16_t code) {
        cb.insns.push_back(Movz(0, code, 0));
        cb.insns.push_back(Movz(8, 94u, 0));
        cb.insns.push_back(Svc(0));
    };

    // 1. Open /dev/haseeb_gles
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_gles);
    cb.insns.push_back(Movz(2, 2u /*O_RDWR*/, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    const size_t b_gfd = cb.EmitCondPlaceholder(10u);
    emit_fail(10u);
    cb.PatchBranchToHere(b_gfd);
    cb.insns.push_back(Movr64(19, 0));

    // 2. Query ioctl HASEEB_GLES_GET_RENDERER (0x484702) -> verify "Hase" (0x65736148)
    cb.insns.push_back(Movr64(0, 19));
    cb.insns.push_back(Movz(1, 0x4702u, 0));
    cb.insns.push_back(Movk(1, 0x0048u, 1));
    cb.insns.push_back(Movr64(2, 31));
    cb.insns.push_back(Movz(8, 29u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(9, 31, 0u));
    cb.insns.push_back(Movz(10, 0x6148u, 0));
    cb.insns.push_back(Movk(10, 0x6573u, 1));
    cb.insns.push_back(CmpReg64(9, 10));
    const size_t b_ren = cb.EmitCondPlaceholder(0u);
    emit_fail(11u);
    cb.PatchBranchToHere(b_ren);

    // 3. write(gles_fd, pkt, gles_pkt.size()) -> rasterizes & swaps to VirtioGpuDevice
    cb.insns.push_back(Movr64(0, 19));
    cb.EmitAdrPlaceholder(1, s_pkt);
    cb.insns.push_back(Movz(2, static_cast<uint16_t>(gles_pkt.size()), 0));
    cb.insns.push_back(Movz(8, 64u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, static_cast<uint16_t>(gles_pkt.size())));
    const size_t b_gwr = cb.EmitCondPlaceholder(0u);
    emit_fail(12u);
    cb.PatchBranchToHere(b_gwr);

    // 4. Open /dev/snd/pcmC0D0p & write 32 bytes (8 stereo frames)
    cb.insns.push_back(Movn(0, 99u, 0));
    cb.EmitAdrPlaceholder(1, s_snd);
    cb.insns.push_back(Movz(2, 1u /*O_WRONLY*/, 0));
    cb.insns.push_back(Movz(3, 0u, 0));
    cb.insns.push_back(Movz(8, 56u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 3u));
    const size_t b_sfd = cb.EmitCondPlaceholder(10u);
    emit_fail(13u);
    cb.PatchBranchToHere(b_sfd);
    cb.insns.push_back(Movr64(20, 0));
    cb.insns.push_back(Movr64(0, 20));
    cb.EmitAdrPlaceholder(1, s_pcm);
    cb.insns.push_back(Movz(2, sizeof(pcm_samples), 0));
    cb.insns.push_back(Movz(8, 64u, 0));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, sizeof(pcm_samples)));
    const size_t b_swr = cb.EmitCondPlaceholder(0u);
    emit_fail(14u);
    cb.PatchBranchToHere(b_swr);

    cb.insns.push_back(Movz(0, 0u, 0));
    cb.insns.push_back(Movz(8, 94u, 0));
    cb.insns.push_back(Svc(0));

    CpioEntry e_init;
    e_init.name = "init";
    e_init.mode = 0100755u;
    e_init.nlink = 1u;
    e_init.data = BuildElf64(cb.Finalize());

    std::vector<uint8_t> boot = BuildBootImgV2(CpioArchive::Build({e_init}));
    ParsedBootImage parsed;
    std::string err;
    HASEEB_CHECK(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    cfg.width = 64u;
    cfg.height = 64u;
    HASEEB_CHECK(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);

    std::string target;
    HASEEB_CHECK(vm.BootGuest(false, target, err) == VmError::Ok);
    HASEEB_CHECK(vm.StepGuest(100000ULL) == VmError::Ok);
    HASEEB_CHECK(vm.CpuState().halted);
    HASEEB_CHECK(vm.Supervisor()->Exited());
    HASEEB_CHECK(vm.Supervisor()->ExitStatus() == 0);

    HASEEB_CHECK(vm.SoftGles().TrianglesRasterized() >= 1u);
    HASEEB_CHECK(vm.VirtioGpu().FrameCount() >= 1u);
    std::vector<uint32_t> frame;
    uint32_t fw = 0, fh = 0;
    HASEEB_CHECK(vm.VirtioGpu().CopyLatestFrame(frame, fw, fh));
    HASEEB_CHECK(fw == 64u && fh == 64u && frame[32u * 64u + 32u] != 0xFF000000u);

    HASEEB_CHECK(vm.VirtioSnd().PlaybackFramesWritten() == 8u);
    vm.Shutdown();
    std::cout << "[PASS] Test 4: EL0 /dev/haseeb_gles CPU triangle scanout & /dev/snd/pcmC0D0p PCM\n";
}

} // namespace

int main() {
    TestSoftGlesCpuRasterizerAndVirtioGpuScanout();
    TestVirtioSndMmioPlaybackAndCapture();
    TestUserNatRouterArpIcmpDhcpDns();
    TestEl0SoftGlesAndAudioEndToEnd();
    std::cout << "ALL M8 SOFTGLES, VIRTIO-SND & USER-NAT TESTS PASSED.\n";
    return 0;
}
