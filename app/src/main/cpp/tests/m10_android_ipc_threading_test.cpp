#include "haseeb/binder_ipc.hpp"
#include "haseeb/boot_image.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/kernel_boot.hpp"
#include "haseeb/machine.hpp"
#include "haseeb/prop_area.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace haseeb::vm;

namespace {

CpioEntry MakeCpio(const std::string& name, uint32_t mode, std::vector<uint8_t> data = {}) {
    CpioEntry e;
    e.name = name;
    e.mode = mode;
    e.uid = 0;
    e.gid = 0;
    e.nlink = 1;
    e.mtime = 0;
    e.data = std::move(data);
    return e;
}

std::vector<uint8_t> BuildBootImgV2(const std::vector<uint8_t>& ramdisk, const std::string& cmdline) {
    constexpr uint32_t kPage = 4096u;
    auto align_up = [&](size_t v) { return (v + kPage - 1u) & ~static_cast<size_t>(kPage - 1u); };
    const size_t r_off = kPage;
    const size_t total = r_off + align_up(ramdisk.size());
    std::vector<uint8_t> img(total, 0u);
    auto put32 = [&](size_t off, uint32_t v) {
        img[off] = v & 0xFFu;
        img[off + 1] = (v >> 8) & 0xFFu;
        img[off + 2] = (v >> 16) & 0xFFu;
        img[off + 3] = (v >> 24) & 0xFFu;
    };
    std::memcpy(img.data(), "ANDROID!", 8);
    put32(16, static_cast<uint32_t>(ramdisk.size()));
    put32(36, kPage);
    put32(40, 2u);
    const size_t c_len = std::min<size_t>(cmdline.size(), 511u);
    std::memcpy(img.data() + 64, cmdline.data(), c_len);
    if (!ramdisk.empty()) std::memcpy(img.data() + r_off, ramdisk.data(), ramdisk.size());
    return img;
}

uint32_t Movz(uint8_t xd, uint16_t imm16, uint8_t hw = 0) {
    return 0xD2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}

uint32_t Movk(uint8_t xd, uint16_t imm16, uint8_t hw) {
    return 0xF2800000u | (static_cast<uint32_t>(hw & 3u) << 21) |
           (static_cast<uint32_t>(imm16) << 5) | (xd & 31u);
}

void EmitImm64(std::vector<uint32_t>& code, uint8_t xd, uint64_t val) {
    code.push_back(Movz(xd, static_cast<uint16_t>(val & 0xFFFFu), 0));
    if ((val >> 16) & 0xFFFFu) code.push_back(Movk(xd, static_cast<uint16_t>((val >> 16) & 0xFFFFu), 1));
    if ((val >> 32) & 0xFFFFu) code.push_back(Movk(xd, static_cast<uint16_t>((val >> 32) & 0xFFFFu), 2));
    if ((val >> 48) & 0xFFFFu) code.push_back(Movk(xd, static_cast<uint16_t>((val >> 48) & 0xFFFFu), 3));
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

uint32_t MovReg(uint8_t xd, uint8_t xm) {
    return 0xAA0003E0u | (static_cast<uint32_t>(xm & 31u) << 16) | (xd & 31u);
}

uint32_t LdrX(uint8_t xt, uint8_t xn, uint16_t imm_bytes = 0) {
    assert(imm_bytes % 8u == 0u);
    return 0xF9400000u | (static_cast<uint32_t>((imm_bytes / 8u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xt & 31u);
}

uint32_t StrX(uint8_t xt, uint8_t xn, uint16_t imm_bytes = 0) {
    assert(imm_bytes % 8u == 0u);
    return 0xF9000000u | (static_cast<uint32_t>((imm_bytes / 8u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (xt & 31u);
}

uint32_t LdrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    assert(imm_bytes % 4u == 0u);
    return 0xB9400000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t StrW(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    assert(imm_bytes % 4u == 0u);
    return 0xB9000000u | (static_cast<uint32_t>((imm_bytes / 4u) & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t Ldrb(uint8_t wt, uint8_t xn, uint16_t imm_bytes = 0) {
    return 0x39400000u | (static_cast<uint32_t>(imm_bytes & 0xFFFu) << 10) |
           (static_cast<uint32_t>(xn & 31u) << 5) | (wt & 31u);
}

uint32_t Svc(uint16_t imm = 0) {
    return 0xD4000001u | (static_cast<uint32_t>(imm) << 5);
}

uint32_t BCond(uint8_t cond, int32_t rel_insns) {
    return 0x54000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (cond & 0xFu);
}

uint32_t Cbz64(uint8_t xt, int32_t rel_insns) {
    return 0xB4000000u | ((static_cast<uint32_t>(rel_insns) & 0x7FFFFu) << 5) | (xt & 31u);
}

struct CodeBlobBuilder {
    std::vector<uint32_t> insns;
    std::vector<uint8_t> data;
    struct Patch {
        size_t insn_idx;
        uint8_t rd;
        size_t data_offset;
    };
    std::vector<Patch> patches;

    size_t AddBytes(const void* ptr, size_t len, size_t align = 8u) {
        while (data.size() % align != 0u) data.push_back(0u);
        size_t off = data.size();
        const auto* b = static_cast<const uint8_t*>(ptr);
        data.insert(data.end(), b, b + len);
        return off;
    }

    size_t AddString(const std::string& s) {
        return AddBytes(s.c_str(), s.size() + 1u, 1u);
    }

    size_t EmitAdrPlaceholder(uint8_t rd, size_t data_offset) {
        size_t idx = insns.size();
        insns.push_back(0);
        patches.push_back({idx, rd, data_offset});
        return idx;
    }

    std::vector<uint8_t> Finalize() {
        const size_t code_bytes = insns.size() * 4u;
        for (const auto& p : patches) {
            int32_t insn_byte_off = static_cast<int32_t>(p.insn_idx * 4u);
            int32_t target_byte_off = static_cast<int32_t>(code_bytes + p.data_offset);
            insns[p.insn_idx] = Adr(p.rd, target_byte_off - insn_byte_off);
        }
        std::vector<uint8_t> blob;
        blob.reserve(code_bytes + data.size());
        for (uint32_t v : insns) {
            blob.push_back(static_cast<uint8_t>(v & 0xFFu));
            blob.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
            blob.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
            blob.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
        }
        blob.insert(blob.end(), data.begin(), data.end());
        return blob;
    }
};

std::vector<uint8_t> BuildElf64(const std::vector<uint8_t>& code_and_data,
                                uint64_t base_va = 0x0000000000400000ULL) {
    constexpr uint64_t kCodeOffset = 0x100ULL;
    const uint64_t file_size = kCodeOffset + code_and_data.size();
    std::vector<uint8_t> elf(file_size, 0u);
    elf[0] = 0x7Fu; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2u; elf[5] = 1u; elf[6] = 1u;
    auto w16 = [&](size_t off, uint16_t v) {
        elf[off] = static_cast<uint8_t>(v & 0xFFu);
        elf[off + 1] = static_cast<uint8_t>(v >> 8);
    };
    auto w32 = [&](size_t off, uint32_t v) {
        for (int i = 0; i < 4; ++i) elf[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    auto w64 = [&](size_t off, uint64_t v) {
        for (int i = 0; i < 8; ++i) elf[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
    };
    w16(16, 2u); w16(18, 183u); w32(20, 1u);
    w64(24, base_va + kCodeOffset);
    w64(32, 64ULL);
    w16(52, 64u); w16(54, 56u); w16(56, 1u);
    w32(64 + 0, 1u); w32(64 + 4, 7u);
    w64(64 + 8, 0ULL); w64(64 + 16, base_va); w64(64 + 24, base_va);
    w64(64 + 32, file_size); w64(64 + 40, file_size + 16384ULL); w64(64 + 48, 4096ULL);
    std::memcpy(elf.data() + kCodeOffset, code_and_data.data(), code_and_data.size());
    return elf;
}

// Test 1: BinderIpcBroker unit test (context manager, transaction routing, mmap alloc, death notification)
void TestBinderIpcBrokerUnit() {
    GuestRam ram;
    assert(ram.Allocate(kGuestRamBase, 8ULL * 1024ULL * 1024ULL) == VmError::Ok);
    std::unordered_map<uint64_t, std::vector<uint8_t>> proc1_mem;
    std::unordered_map<uint64_t, std::vector<uint8_t>> proc2_mem;
    auto bind_mem = [&](std::unordered_map<uint64_t, std::vector<uint8_t>>& mem) {
        auto rd = [&mem](uint64_t uva, void* dst, size_t len) -> bool {
            for (const auto& kv : mem) {
                if (uva >= kv.first && (uva - kv.first) + len <= kv.second.size()) {
                    std::memcpy(dst, kv.second.data() + (uva - kv.first), len);
                    return true;
                }
            }
            return false;
        };
        auto wr = [&mem](uint64_t uva, const void* src, size_t len) -> bool {
            for (auto& kv : mem) {
                if (uva >= kv.first && (uva - kv.first) + len <= kv.second.size()) {
                    std::memcpy(kv.second.data() + (uva - kv.first), src, len);
                    return true;
                }
            }
            return false;
        };
        return std::make_pair(rd, wr);
    };

    proc1_mem[0x10000ULL].resize(8192u, 0u);
    proc2_mem[0x20000ULL].resize(8192u, 0u);
    proc1_mem[0x50000ULL].resize(8192u, 0u);
    proc2_mem[0x60000ULL].resize(8192u, 0u);
    auto io1 = bind_mem(proc1_mem);
    auto io2 = bind_mem(proc2_mem);

    BinderIpcBroker broker;
    uint32_t mgr = broker.OpenClient(BinderIpcBroker::Domain::Binder, 10, 0);
    uint32_t cli = broker.OpenClient(BinderIpcBroker::Domain::Binder, 20, 1000);
    broker.RegisterMmap(mgr, 0x50000ULL, 8192ULL, {kGuestRamBase + 0x100000ULL, kGuestRamBase + 0x101000ULL});
    broker.RegisterMmap(cli, 0x60000ULL, 8192ULL, {kGuestRamBase + 0x200000ULL, kGuestRamBase + 0x201000ULL});

    bool wb = false;
    assert(broker.HandleIoctl(mgr, 0x40046207u, 0ULL, ram, io1.first, io1.second, nullptr, nullptr, false, wb) == 0);

#pragma pack(push, 1)
    struct Bwr { uint64_t ws, wc, wb, rs, rc, rb; } bwr{};
    struct Tr { uint64_t target, cookie; uint32_t code, flags; int32_t sender_pid; uint32_t sender_euid; uint64_t data_size, offsets_size, data_buffer, data_offsets; } tr{};
#pragma pack(pop)
    std::memcpy(proc2_mem[0x20000ULL].data() + 0x400u, "HI", 2u);
    tr.target = 0ULL;
    tr.code = 7u;
    tr.data_size = 2u;
    tr.data_buffer = 0x20400ULL;
    uint8_t wcmd[68]{};
    const uint32_t bc_tx = 0x40406300u;
    std::memcpy(wcmd, &bc_tx, 4u);
    std::memcpy(wcmd + 4u, &tr, sizeof(tr));
    std::memcpy(proc2_mem[0x20000ULL].data() + 0x100u, wcmd, sizeof(wcmd));

    bwr = {sizeof(wcmd), 0ULL, 0x20100ULL, 0ULL, 0ULL, 0ULL};
    std::memcpy(proc2_mem[0x20000ULL].data(), &bwr, sizeof(bwr));
    bool woken_mgr = false;
    assert(broker.HandleIoctl(cli, 0xC0306201u, 0x20000ULL, ram, io2.first, io2.second,
                              nullptr, [&](int32_t pid) { woken_mgr = (pid == 10); }, false, wb) == 0);
    assert(woken_mgr);
    assert(broker.HasPendingRead(mgr));

    bwr = {0ULL, 0ULL, 0ULL, 256ULL, 0ULL, 0x10200ULL};
    std::memcpy(proc1_mem[0x10000ULL].data(), &bwr, sizeof(bwr));
    assert(broker.HandleIoctl(mgr, 0xC0306201u, 0x10000ULL, ram, io1.first, io1.second,
                              nullptr, nullptr, false, wb) == 0);
    assert(!wb);
    uint32_t noop = 0u, br_cmd = 0u;
    std::memcpy(&noop, proc1_mem[0x10000ULL].data() + 0x200u, 4u);
    std::memcpy(&br_cmd, proc1_mem[0x10000ULL].data() + 0x204u, 4u);
    assert(noop == 0x0000720Cu);
    assert(br_cmd == 0x80407202u);

    Tr rcv_tr{};
    std::memcpy(&rcv_tr, proc1_mem[0x10000ULL].data() + 0x208u, sizeof(rcv_tr));
    assert(rcv_tr.code == 7u && rcv_tr.sender_pid == 20);
    char payload[2]{};
    ram.ReadBytes(kGuestRamBase + 0x100000ULL + (rcv_tr.data_buffer - 0x50000ULL), payload, 2u);
    assert(payload[0] == 'H' && payload[1] == 'I');

    bool woken_cli = false;
    broker.CloseClient(mgr, [&](int32_t pid) { woken_cli = (pid == 20); });
    assert(woken_cli);
    assert(broker.HasPendingRead(cli));
    std::cout << "[PASS] Test 1: BinderIpcBroker transaction routing, mmap alloc & death notifications\n";
}

// Test 2: EL0 fork() parent/child live /dev/binder IPC with BinderWait + BC_REPLY + wait4()
void TestEl0MultiProcessBinderIpc() {
    CodeBlobBuilder cb;
    const size_t dev_binder = cb.AddString("/dev/binder");
    const size_t ping_str = cb.AddBytes("PING", 4u, 8u);
    const size_t pong_str = cb.AddBytes("PONG", 4u, 8u);
    const size_t ok_str = cb.AddString("[BINDER-EL0-OK]\n");

    // Workspace:
    // [sp+0..47] = bwr (6 x uint64)
    // [sp+60..127] = wbuf (cmd@60, BinderTransactionData64@64..127 -> all 8B fields aligned!)
    // [sp+256..511] = rbuf (BR_NOOP@256, BR_TRANSACTION@260, BinderTransactionData64@264 -> data_buffer@312!)
    // [sp+512..515] = wait4 wstatus
    cb.insns.push_back(SubImm64(31, 31, 1024u));
    cb.insns.push_back(Movz(29, 0u));

    // x20 = openat(AT_FDCWD, "/dev/binder", O_RDWR=2)
    EmitImm64(cb.insns, 0, static_cast<uint64_t>(-100));
    cb.EmitAdrPlaceholder(1, dev_binder);
    cb.insns.push_back(Movz(2, 2u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(8, 56u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(20, 0));

    // mmap(0, 8192, PROT_READ|PROT_WRITE=3, MAP_PRIVATE=2, x20, 0)
    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(1, 8192u));
    cb.insns.push_back(Movz(2, 3u));
    cb.insns.push_back(Movz(3, 2u));
    cb.insns.push_back(MovReg(4, 20));
    cb.insns.push_back(Movz(5, 0u));
    cb.insns.push_back(Movz(8, 222u));
    cb.insns.push_back(Svc(0));

    // BINDER_SET_CONTEXT_MGR (0x40046207) on x20 before fork
    cb.insns.push_back(MovReg(0, 20));
    EmitImm64(cb.insns, 1, 0x40046207ULL);
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 29u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t bf1 = cb.insns.size(); cb.insns.push_back(0);

    // clone(SIGCHLD=17, 0, 0, 0, 0)
    cb.insns.push_back(Movz(0, 17u));
    cb.insns.push_back(Movz(1, 0u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(4, 0u));
    cb.insns.push_back(Movz(8, 220u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Cbz64(0, 0));
    const size_t b_child = cb.insns.size() - 1u;

    // --- PARENT (context manager) ---
    cb.insns.push_back(MovReg(22, 0)); // child pid
    cb.insns.push_back(StrX(29, 31, 0u));
    cb.insns.push_back(StrX(29, 31, 8u));
    cb.insns.push_back(StrX(29, 31, 16u));
    cb.insns.push_back(Movz(10, 256u)); cb.insns.push_back(StrX(10, 31, 24u));
    cb.insns.push_back(StrX(29, 31, 32u));
    cb.insns.push_back(AddImm64(10, 31, 256u)); cb.insns.push_back(StrX(10, 31, 40u));

    cb.insns.push_back(MovReg(0, 20));
    EmitImm64(cb.insns, 1, 0xC0306201ULL);
    cb.insns.push_back(AddImm64(2, 31, 0u));
    cb.insns.push_back(Movz(8, 29u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t bf2 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(LdrW(10, 31, 260u));
    EmitImm64(cb.insns, 11, 0x80407202ULL);
    cb.insns.push_back(0x6B0B015Fu); // cmp w10, w11
    const size_t bf3 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(LdrX(10, 31, 312u)); // rcv_tr.data_buffer
    cb.insns.push_back(Ldrb(11, 10, 0u));
    cb.insns.push_back(CmpImm64(11, static_cast<uint16_t>('P')));
    const size_t bf4 = cb.insns.size(); cb.insns.push_back(0);

    // Build BC_REPLY @ sp+60
    EmitImm64(cb.insns, 10, 0x40406301ULL);
    cb.insns.push_back(StrW(10, 31, 60u));  // cmd
    cb.insns.push_back(StrX(29, 31, 64u));  // target
    cb.insns.push_back(StrX(29, 31, 72u));  // cookie
    cb.insns.push_back(StrX(29, 31, 80u));  // code, flags
    cb.insns.push_back(StrX(29, 31, 88u));  // pid, uid
    cb.insns.push_back(Movz(10, 4u));
    cb.insns.push_back(StrX(10, 31, 96u));  // data_size = 4
    cb.insns.push_back(StrX(29, 31, 104u)); // offsets_size = 0
    cb.EmitAdrPlaceholder(10, pong_str);
    cb.insns.push_back(StrX(10, 31, 112u)); // data_buffer = "PONG"
    cb.insns.push_back(StrX(29, 31, 120u)); // data_offsets = 0

    cb.insns.push_back(Movz(10, 68u)); cb.insns.push_back(StrX(10, 31, 0u));
    cb.insns.push_back(StrX(29, 31, 8u));
    cb.insns.push_back(AddImm64(10, 31, 60u)); cb.insns.push_back(StrX(10, 31, 16u));
    cb.insns.push_back(StrX(29, 31, 24u));
    cb.insns.push_back(MovReg(0, 20));
    EmitImm64(cb.insns, 1, 0xC0306201ULL);
    cb.insns.push_back(AddImm64(2, 31, 0u));
    cb.insns.push_back(Movz(8, 29u));
    cb.insns.push_back(Svc(0));

    // wait4(x22, sp+512, 0, 0)
    cb.insns.push_back(MovReg(0, 22));
    cb.insns.push_back(AddImm64(1, 31, 512u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(8, 260u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(10, 31, 512u));
    cb.insns.push_back(CmpImm64(10, 0u));
    const size_t bf5 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(Movz(0, 1u));
    cb.EmitAdrPlaceholder(1, ok_str);
    cb.insns.push_back(Movz(2, 16u));
    cb.insns.push_back(Movz(8, 64u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    // --- CHILD ---
    const size_t child_start = cb.insns.size();
    cb.insns.push_back(MovReg(0, 20));
    cb.insns.push_back(Movz(8, 57u)); // close parent fd
    cb.insns.push_back(Svc(0));

    EmitImm64(cb.insns, 0, static_cast<uint64_t>(-100));
    cb.EmitAdrPlaceholder(1, dev_binder);
    cb.insns.push_back(Movz(2, 2u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(8, 56u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(20, 0));

    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(1, 8192u));
    cb.insns.push_back(Movz(2, 3u));
    cb.insns.push_back(Movz(3, 2u));
    cb.insns.push_back(MovReg(4, 20));
    cb.insns.push_back(Movz(5, 0u));
    cb.insns.push_back(Movz(8, 222u));
    cb.insns.push_back(Svc(0));

    EmitImm64(cb.insns, 10, 0x40406300ULL);
    cb.insns.push_back(StrW(10, 31, 60u));
    cb.insns.push_back(StrX(29, 31, 64u)); // target=0
    cb.insns.push_back(StrX(29, 31, 72u));
    cb.insns.push_back(Movz(10, 0x42u)); cb.insns.push_back(StrW(10, 31, 80u));
    cb.insns.push_back(StrW(29, 31, 84u));
    cb.insns.push_back(StrX(29, 31, 88u));
    cb.insns.push_back(Movz(10, 4u)); cb.insns.push_back(StrX(10, 31, 96u));
    cb.insns.push_back(StrX(29, 31, 104u));
    cb.EmitAdrPlaceholder(10, ping_str); cb.insns.push_back(StrX(10, 31, 112u));
    cb.insns.push_back(StrX(29, 31, 120u));

    cb.insns.push_back(Movz(10, 68u)); cb.insns.push_back(StrX(10, 31, 0u));
    cb.insns.push_back(StrX(29, 31, 8u));
    cb.insns.push_back(AddImm64(10, 31, 60u)); cb.insns.push_back(StrX(10, 31, 16u));
    cb.insns.push_back(Movz(10, 256u)); cb.insns.push_back(StrX(10, 31, 24u));
    cb.insns.push_back(StrX(29, 31, 32u));
    cb.insns.push_back(AddImm64(10, 31, 256u)); cb.insns.push_back(StrX(10, 31, 40u));

    cb.insns.push_back(MovReg(0, 20));
    EmitImm64(cb.insns, 1, 0xC0306201ULL);
    cb.insns.push_back(AddImm64(2, 31, 0u));
    cb.insns.push_back(Movz(8, 29u));
    cb.insns.push_back(Svc(0));

    // Block reading BR_REPLY ("PONG")
    cb.insns.push_back(StrX(29, 31, 0u));
    cb.insns.push_back(StrX(29, 31, 8u));
    cb.insns.push_back(Movz(10, 256u)); cb.insns.push_back(StrX(10, 31, 24u));
    cb.insns.push_back(StrX(29, 31, 32u));
    cb.insns.push_back(MovReg(0, 20));
    EmitImm64(cb.insns, 1, 0xC0306201ULL);
    cb.insns.push_back(AddImm64(2, 31, 0u));
    cb.insns.push_back(Movz(8, 29u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(LdrW(10, 31, 260u));
    EmitImm64(cb.insns, 11, 0x80407203ULL);
    cb.insns.push_back(0x6B0B015Fu); // cmp w10, w11
    const size_t cf1 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(LdrX(10, 31, 312u));
    cb.insns.push_back(Ldrb(11, 10, 1u)); // 'O' in "PONG"
    cb.insns.push_back(CmpImm64(11, static_cast<uint16_t>('O')));
    const size_t cf2 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    const size_t fail_idx = cb.insns.size();
    cb.insns.push_back(Movz(0, 77u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    cb.insns[b_child] = Cbz64(0, static_cast<int32_t>(child_start - b_child));
    for (size_t f : {bf1, bf2, bf3, bf4, bf5, cf1, cf2}) {
        cb.insns[f] = BCond(1u, static_cast<int32_t>(fail_idx - f));
    }

    std::vector<uint8_t> rd = CpioArchive::Build({MakeCpio("init", 0100755u, BuildElf64(cb.Finalize()))});
    std::vector<uint8_t> boot = BuildBootImgV2(rd, "androidboot.selinux=permissive");
    ParsedBootImage parsed;
    std::string err;
    assert(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    assert(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    std::string target;
    assert(vm.BootGuest(false, target, err) == VmError::Ok);
    assert(vm.StepGuest(250000ULL) == VmError::Ok);
    assert(vm.Supervisor()->Exited());
    assert(vm.Supervisor()->ExitStatus() == 0);
    assert(vm.Uart().CapturedOutput().find("[BINDER-EL0-OK]") != std::string::npos);
    std::cout << "[PASS] Test 2: EL0 multi-process Binder IPC (BinderWait + BR_TRANSACTION + BC_REPLY + wait4)\n";
}

// Test 3: AF_UNIX /dev/socket/property_service + /dev/socket/logdw + socketpair SCM_RIGHTS FD passing
void TestUnixSocketsScmRightsPropAndLogd() {
    CodeBlobBuilder cb;
    uint8_t sa_prop[110]{};
    sa_prop[0] = 1u;
    std::memcpy(sa_prop + 2u, "/dev/socket/property_service", 28u);
    const size_t sa_prop_off = cb.AddBytes(sa_prop, sizeof(sa_prop), 8u);

    uint8_t prop_pkt[4 + 4 + 18 + 4 + 1]{};
    uint32_t pcmd = 0x00020001u, nlen = 18u, vlen = 1u;
    std::memcpy(prop_pkt + 0u, &pcmd, 4u);
    std::memcpy(prop_pkt + 4u, &nlen, 4u);
    std::memcpy(prop_pkt + 8u, "debug.haseeb.level", 18u);
    std::memcpy(prop_pkt + 26u, &vlen, 4u);
    prop_pkt[30] = '7';
    const size_t prop_pkt_off = cb.AddBytes(prop_pkt, sizeof(prop_pkt), 8u);

    uint8_t sa_logd[110]{};
    sa_logd[0] = 1u;
    std::memcpy(sa_logd + 2u, "/dev/socket/logdw", 17u);
    const size_t sa_logd_off = cb.AddBytes(sa_logd, sizeof(sa_logd), 8u);

    uint8_t log_hdr[12]{};
    log_hdr[11] = 4u;
    const size_t log_hdr_off = cb.AddBytes(log_hdr, sizeof(log_hdr), 4u);
    const size_t log_tag_off = cb.AddString("HaseebTest");
    const size_t log_msg_off = cb.AddString("UnixSocketReady");
    const size_t mfd_name = cb.AddString("passed_memfd");
    const size_t mfd_payload = cb.AddBytes("SHARED!", 7u, 8u);
    const size_t ok_str = cb.AddString("[UNIX-SCM-PROP-OK]\n");

    cb.insns.push_back(SubImm64(31, 31, 1024u));
    cb.insns.push_back(Movz(29, 0u));

    // 1. Property service
    cb.insns.push_back(Movz(0, 1u));
    cb.insns.push_back(Movz(1, 1u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 198u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(20, 0));

    cb.insns.push_back(MovReg(0, 20));
    cb.EmitAdrPlaceholder(1, sa_prop_off);
    cb.insns.push_back(Movz(2, sizeof(sa_prop)));
    cb.insns.push_back(Movz(8, 203u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t f1 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(MovReg(0, 20));
    cb.EmitAdrPlaceholder(1, prop_pkt_off);
    cb.insns.push_back(Movz(2, sizeof(prop_pkt)));
    cb.insns.push_back(Movz(8, 64u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(MovReg(0, 20));
    cb.insns.push_back(AddImm64(1, 31, 0u));
    cb.insns.push_back(Movz(2, 4u));
    cb.insns.push_back(Movz(8, 63u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 4u));
    const size_t f2 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(LdrW(10, 31, 0u));
    cb.insns.push_back(CmpImm64(10, 0u));
    const size_t f3 = cb.insns.size(); cb.insns.push_back(0);

    // 2. Logd writev
    cb.insns.push_back(Movz(0, 1u));
    cb.insns.push_back(Movz(1, 2u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 198u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(21, 0));

    cb.insns.push_back(MovReg(0, 21));
    cb.EmitAdrPlaceholder(1, sa_logd_off);
    cb.insns.push_back(Movz(2, sizeof(sa_logd)));
    cb.insns.push_back(Movz(8, 203u));
    cb.insns.push_back(Svc(0));

    cb.EmitAdrPlaceholder(10, log_hdr_off); cb.insns.push_back(StrX(10, 31, 64u));
    cb.insns.push_back(Movz(10, sizeof(log_hdr))); cb.insns.push_back(StrX(10, 31, 72u));
    cb.EmitAdrPlaceholder(10, log_tag_off); cb.insns.push_back(StrX(10, 31, 80u));
    cb.insns.push_back(Movz(10, 11u)); cb.insns.push_back(StrX(10, 31, 88u));
    cb.EmitAdrPlaceholder(10, log_msg_off); cb.insns.push_back(StrX(10, 31, 96u));
    cb.insns.push_back(Movz(10, 16u)); cb.insns.push_back(StrX(10, 31, 104u));

    cb.insns.push_back(MovReg(0, 21));
    cb.insns.push_back(AddImm64(1, 31, 64u));
    cb.insns.push_back(Movz(2, 3u));
    cb.insns.push_back(Movz(8, 66u));
    cb.insns.push_back(Svc(0));

    // 3. socketpair + SCM_RIGHTS
    cb.insns.push_back(Movz(0, 1u));
    cb.insns.push_back(Movz(1, 1u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(AddImm64(3, 31, 128u));
    cb.insns.push_back(Movz(8, 199u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(LdrW(22, 31, 128u));
    cb.insns.push_back(LdrW(23, 31, 132u));

    cb.EmitAdrPlaceholder(0, mfd_name);
    cb.insns.push_back(Movz(1, 0u));
    cb.insns.push_back(Movz(8, 279u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(24, 0));
    cb.EmitAdrPlaceholder(1, mfd_payload);
    cb.insns.push_back(Movz(2, 7u));
    cb.insns.push_back(Movz(8, 64u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(Movz(10, 20u)); cb.insns.push_back(StrX(10, 31, 256u));
    cb.insns.push_back(Movz(10, 1u));  cb.insns.push_back(StrW(10, 31, 264u));
    cb.insns.push_back(StrW(10, 31, 268u));
    cb.insns.push_back(StrW(24, 31, 272u));
    cb.EmitAdrPlaceholder(10, ok_str); cb.insns.push_back(StrX(10, 31, 288u));
    cb.insns.push_back(Movz(10, 1u));  cb.insns.push_back(StrX(10, 31, 296u));
    cb.insns.push_back(StrX(29, 31, 320u));
    cb.insns.push_back(StrX(29, 31, 328u));
    cb.insns.push_back(AddImm64(10, 31, 288u)); cb.insns.push_back(StrX(10, 31, 336u));
    cb.insns.push_back(Movz(10, 1u));           cb.insns.push_back(StrX(10, 31, 344u));
    cb.insns.push_back(AddImm64(10, 31, 256u)); cb.insns.push_back(StrX(10, 31, 352u));
    cb.insns.push_back(Movz(10, 24u));          cb.insns.push_back(StrX(10, 31, 360u));
    cb.insns.push_back(StrX(29, 31, 368u));

    cb.insns.push_back(MovReg(0, 22));
    cb.insns.push_back(AddImm64(1, 31, 320u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 211u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 1u));
    const size_t f4 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(AddImm64(10, 31, 400u)); cb.insns.push_back(StrX(10, 31, 288u));
    cb.insns.push_back(Movz(10, 16u));          cb.insns.push_back(StrX(10, 31, 296u));
    cb.insns.push_back(AddImm64(10, 31, 448u)); cb.insns.push_back(StrX(10, 31, 352u));
    cb.insns.push_back(Movz(10, 32u));          cb.insns.push_back(StrX(10, 31, 360u));

    cb.insns.push_back(MovReg(0, 23));
    cb.insns.push_back(AddImm64(1, 31, 320u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 212u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 1u));
    const size_t f5 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(LdrW(25, 31, 464u));
    cb.insns.push_back(MovReg(0, 25));
    cb.insns.push_back(Movz(1, 0u));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(8, 62u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(MovReg(0, 25));
    cb.insns.push_back(AddImm64(1, 31, 512u));
    cb.insns.push_back(Movz(2, 7u));
    cb.insns.push_back(Movz(8, 63u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 7u));
    const size_t f6 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(Ldrb(10, 31, 512u));
    cb.insns.push_back(CmpImm64(10, static_cast<uint16_t>('S')));
    const size_t f7 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(Movz(0, 1u));
    cb.EmitAdrPlaceholder(1, ok_str);
    cb.insns.push_back(Movz(2, 19u));
    cb.insns.push_back(Movz(8, 64u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    const size_t fail_idx = cb.insns.size();
    cb.insns.push_back(Movz(0, 88u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    for (size_t f : {f1, f2, f3, f4, f5, f6, f7}) {
        cb.insns[f] = BCond(1u, static_cast<int32_t>(fail_idx - f));
    }

    std::vector<uint8_t> rd = CpioArchive::Build({MakeCpio("init", 0100755u, BuildElf64(cb.Finalize()))});
    std::vector<uint8_t> boot = BuildBootImgV2(rd, "androidboot.selinux=permissive");
    ParsedBootImage parsed;
    std::string err;
    assert(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    vm.SetRuntimePaths("/tmp/haseeb_test_m10_props", "/tmp/haseeb_test_m10_storage");
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    assert(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    std::string target;
    assert(vm.BootGuest(false, target, err) == VmError::Ok);
    assert(vm.StepGuest(100000ULL) == VmError::Ok);
    assert(vm.Supervisor()->Exited());
    assert(vm.Supervisor()->ExitStatus() == 0);
    std::string prop_val;
    assert(vm.PropManager().GetProperty("debug.haseeb.level", prop_val));
    assert(prop_val == "7");
    const std::string uart = vm.Uart().CapturedOutput();
    assert(uart.find("[LOGD] HaseebTest: UnixSocketReady") != std::string::npos);
    assert(uart.find("[UNIX-SCM-PROP-OK]") != std::string::npos);
    std::cout << "[PASS] Test 3: AF_UNIX SCM_RIGHTS FD passing + property_service + logdw writev\n";
}

// Test 4: CLONE_VM|CLONE_FILES|CLONE_THREAD + FUTEX_WAIT/WAKE + timerfd + epoll_pwait (16B)
void TestThreadsFutexTimerfdAndEpoll() {
    CodeBlobBuilder cb;
    const size_t ok_str = cb.AddString("[THREAD-FUTEX-EPOLL-OK]\n");

    cb.insns.push_back(SubImm64(31, 31, 1024u));
    cb.insns.push_back(AddImm64(25, 31, 0u)); // X25 = shared main stack workspace base
    cb.insns.push_back(Movz(29, 0u));
    cb.insns.push_back(StrW(29, 31, 0u)); // futex = 0

    cb.insns.push_back(Movz(8, 172u)); // getpid
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(20, 0));

    // Allocate 16KB thread stack via mmap -> x21
    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(1, 16384u));
    cb.insns.push_back(Movz(2, 3u));
    cb.insns.push_back(Movz(3, 0x22u));
    EmitImm64(cb.insns, 4, static_cast<uint64_t>(-1));
    cb.insns.push_back(Movz(5, 0u));
    cb.insns.push_back(Movz(8, 222u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movz(10, 16384u));
    cb.insns.push_back(0x8B0A0015u); // ADD X21, X0, X10

    // clone(CLONE_VM|CLONE_FILES|CLONE_THREAD=0x10500, x21, 0, 0, 0)
    EmitImm64(cb.insns, 0, 0x10500ULL);
    cb.insns.push_back(MovReg(1, 21));
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(4, 0u));
    cb.insns.push_back(Movz(8, 220u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Cbz64(0, 0));
    const size_t b_worker = cb.insns.size() - 1u;

    // --- MAIN THREAD ---
    cb.insns.push_back(AddImm64(0, 31, 0u));
    cb.insns.push_back(Movz(1, 0u)); // FUTEX_WAIT
    cb.insns.push_back(Movz(2, 0u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(8, 98u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 0u));
    const size_t f1 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(LdrW(10, 31, 0u));
    cb.insns.push_back(CmpImm64(10, 1u));
    const size_t f2 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(LdrX(10, 31, 8u));
    cb.insns.push_back(0xEB14015Fu); // worker getpid == parent getpid
    const size_t f3 = cb.insns.size(); cb.insns.push_back(0);
    cb.insns.push_back(LdrX(10, 31, 16u));
    cb.insns.push_back(0xEB14015Fu); // worker gettid != parent getpid
    const size_t f4 = cb.insns.size(); cb.insns.push_back(0);

    // timerfd_create(CLOCK_MONOTONIC=1, 0) -> x22
    cb.insns.push_back(Movz(0, 1u));
    cb.insns.push_back(Movz(1, 0u));
    cb.insns.push_back(Movz(8, 85u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(22, 0));

    // Arm 1ms relative timer
    cb.insns.push_back(StrX(29, 31, 64u));
    cb.insns.push_back(StrX(29, 31, 72u));
    cb.insns.push_back(StrX(29, 31, 80u));
    EmitImm64(cb.insns, 10, 1000000ULL);
    cb.insns.push_back(StrX(10, 31, 88u));
    cb.insns.push_back(MovReg(0, 22));
    cb.insns.push_back(Movz(1, 0u));
    cb.insns.push_back(AddImm64(2, 31, 64u));
    cb.insns.push_back(Movz(3, 0u));
    cb.insns.push_back(Movz(8, 86u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 20u)); // epoll_create1
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(MovReg(23, 0));

    // struct epoll_event (16B @ sp+128): uint32 events=1, pad=0, uint64 data=0xCAFEBABE12345678
    cb.insns.push_back(Movz(10, 1u)); cb.insns.push_back(StrW(10, 31, 128u));
    cb.insns.push_back(StrW(29, 31, 132u));
    EmitImm64(cb.insns, 10, 0xCAFEBABE12345678ULL);
    cb.insns.push_back(StrX(10, 31, 136u));

    cb.insns.push_back(MovReg(0, 23));
    cb.insns.push_back(Movz(1, 1u));
    cb.insns.push_back(MovReg(2, 22));
    cb.insns.push_back(AddImm64(3, 31, 128u));
    cb.insns.push_back(Movz(8, 21u)); // epoll_ctl
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(MovReg(0, 23));
    cb.insns.push_back(AddImm64(1, 31, 160u));
    cb.insns.push_back(Movz(2, 2u));
    cb.insns.push_back(Movz(3, 1000u));
    cb.insns.push_back(Movz(4, 0u));
    cb.insns.push_back(Movz(5, 0u));
    cb.insns.push_back(Movz(8, 22u)); // epoll_pwait
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 1u));
    const size_t f5 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(LdrX(10, 31, 168u));
    EmitImm64(cb.insns, 11, 0xCAFEBABE12345678ULL);
    cb.insns.push_back(0xEB0B015Fu); // cmp x10, x11
    const size_t f6 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(MovReg(0, 22));
    cb.insns.push_back(AddImm64(1, 31, 200u));
    cb.insns.push_back(Movz(2, 8u));
    cb.insns.push_back(Movz(8, 63u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(CmpImm64(0, 8u));
    const size_t f7 = cb.insns.size(); cb.insns.push_back(0);

    cb.insns.push_back(Movz(0, 1u));
    cb.EmitAdrPlaceholder(1, ok_str);
    cb.insns.push_back(Movz(2, 24u));
    cb.insns.push_back(Movz(8, 64u));
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    // --- WORKER THREAD ---
    const size_t worker_start = cb.insns.size();
    cb.insns.push_back(Movz(8, 172u)); // getpid
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(StrX(0, 25, 8u));
    cb.insns.push_back(Movz(8, 178u)); // gettid
    cb.insns.push_back(Svc(0));
    cb.insns.push_back(StrX(0, 25, 16u));

    cb.insns.push_back(Movz(10, 1u));
    cb.insns.push_back(StrW(10, 25, 0u));
    cb.insns.push_back(AddImm64(0, 25, 0u));
    cb.insns.push_back(Movz(1, 1u)); // FUTEX_WAKE
    cb.insns.push_back(Movz(2, 1u));
    cb.insns.push_back(Movz(8, 98u));
    cb.insns.push_back(Svc(0));

    cb.insns.push_back(Movz(0, 0u));
    cb.insns.push_back(Movz(8, 93u)); // thread exit
    cb.insns.push_back(Svc(0));

    const size_t fail_idx = cb.insns.size();
    cb.insns.push_back(Movz(0, 66u));
    cb.insns.push_back(Movz(8, 94u));
    cb.insns.push_back(Svc(0));

    cb.insns[b_worker] = Cbz64(0, static_cast<int32_t>(worker_start - b_worker));
    cb.insns[f1] = BCond(1u, static_cast<int32_t>(fail_idx - f1));
    cb.insns[f2] = BCond(1u, static_cast<int32_t>(fail_idx - f2));
    cb.insns[f3] = BCond(1u, static_cast<int32_t>(fail_idx - f3));
    cb.insns[f4] = BCond(0u, static_cast<int32_t>(fail_idx - f4)); // BEQ -> fail
    cb.insns[f5] = BCond(1u, static_cast<int32_t>(fail_idx - f5));
    cb.insns[f6] = BCond(1u, static_cast<int32_t>(fail_idx - f6));
    cb.insns[f7] = BCond(1u, static_cast<int32_t>(fail_idx - f7));

    std::vector<uint8_t> rd = CpioArchive::Build({MakeCpio("init", 0100755u, BuildElf64(cb.Finalize()))});
    std::vector<uint8_t> boot = BuildBootImgV2(rd, "androidboot.selinux=permissive");
    ParsedBootImage parsed;
    std::string err;
    assert(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    assert(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    std::string target;
    assert(vm.BootGuest(false, target, err) == VmError::Ok);
    for (int iter = 0; iter < 50 && !vm.Supervisor()->Exited(); ++iter) {
        assert(vm.StepGuest(50000ULL) == VmError::Ok);
        if (!vm.Supervisor()->Exited()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    assert(vm.Supervisor()->Exited());
    assert(vm.Supervisor()->ExitStatus() == 0);
    assert(vm.Uart().CapturedOutput().find("[THREAD-FUTEX-EPOLL-OK]") != std::string::npos);
    std::cout << "[PASS] Test 4: CLONE_THREAD/VM/FILES + FUTEX_WAIT/WAKE + timerfd + epoll_pwait\n";
}

// Test 5: /dev/ashmem MAP_SHARED + /sys/fs/selinux/enforce + chdir/getcwd + execve envp & FD_CLOEXEC
void TestAshmemSharedSelinuxCwdAndExecveCloexec() {
    // 1. Next stage ELF (/system/bin/next): verifies FD_CLOEXEC fd(20) is closed (-EBADF) and envp preserved
    std::vector<uint8_t> next_elf;
    {
        CodeBlobBuilder cb;
        const size_t ok_str = cb.AddString("[ASHMEM-EXECVE-CLOEXEC-OK]\n");
        cb.insns.push_back(SubImm64(31, 31, 256u));

        // Save initial SP into X20 before subtracting stack! Wait: recover via AddImm64(20, 31, 256u)
        cb.insns.push_back(AddImm64(20, 31, 256u));
        // On initial stack: [x20]=argc(1), [x20+8]=argv[0], [x20+16]=0, [x20+24]=envp[0] -> "K=V"
        cb.insns.push_back(LdrX(10, 20, 24u));
        cb.insns.push_back(Ldrb(11, 10, 0u));
        cb.insns.push_back(CmpImm64(11, static_cast<uint16_t>('K')));
        const size_t nf1 = cb.insns.size(); cb.insns.push_back(0);

        // fstat(20, sp+0) -> must fail with -9 (EBADF) because FD_CLOEXEC closed fd 20 on execve!
        cb.insns.push_back(Movz(0, 20u));
        cb.insns.push_back(AddImm64(1, 31, 0u));
        cb.insns.push_back(Movz(8, 80u)); // fstat
        cb.insns.push_back(Svc(0));
        EmitImm64(cb.insns, 10, static_cast<uint64_t>(-9LL));
        cb.insns.push_back(0xEB0A001Fu); // cmp x0, x10
        const size_t nf2 = cb.insns.size(); cb.insns.push_back(0);

        cb.insns.push_back(Movz(0, 1u));
        cb.EmitAdrPlaceholder(1, ok_str);
        cb.insns.push_back(Movz(2, 27u));
        cb.insns.push_back(Movz(8, 64u));
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(Movz(0, 0u));
        cb.insns.push_back(Movz(8, 94u));
        cb.insns.push_back(Svc(0));

        const size_t fail_idx = cb.insns.size();
        cb.insns.push_back(Movz(0, 55u));
        cb.insns.push_back(Movz(8, 94u));
        cb.insns.push_back(Svc(0));

        cb.insns[nf1] = BCond(1u, static_cast<int32_t>(fail_idx - nf1));
        cb.insns[nf2] = BCond(1u, static_cast<int32_t>(fail_idx - nf2));
        next_elf = BuildElf64(cb.Finalize());
    }

    // 2. Init ELF (/init): tests /dev/ashmem MAP_SHARED two mappings share RAM, SELinux enforce=='0', chdir/getcwd, execve
    std::vector<uint8_t> init_elf;
    {
        CodeBlobBuilder cb;
        const size_t dev_ashmem = cb.AddString("/dev/ashmem");
        const size_t ash_name = cb.AddString("dalvik-heap");
        const size_t selinux_path = cb.AddString("/sys/fs/selinux/enforce");
        const size_t sys_dir = cb.AddString("/system/bin");
        const size_t next_path = cb.AddString("/system/bin/next");
        const size_t env_kv = cb.AddString("K=V");

        cb.insns.push_back(SubImm64(31, 31, 512u));
        cb.insns.push_back(Movz(29, 0u));

        // open /dev/ashmem -> x20
        EmitImm64(cb.insns, 0, static_cast<uint64_t>(-100));
        cb.EmitAdrPlaceholder(1, dev_ashmem);
        cb.insns.push_back(Movz(2, 2u));
        cb.insns.push_back(Movz(3, 0u));
        cb.insns.push_back(Movz(8, 56u));
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(MovReg(20, 0));

        // ioctl ASHMEM_SET_NAME (0x41007701), ASHMEM_SET_SIZE (0x40087703, 4096)
        cb.insns.push_back(MovReg(0, 20));
        EmitImm64(cb.insns, 1, 0x41007701ULL);
        cb.EmitAdrPlaceholder(2, ash_name);
        cb.insns.push_back(Movz(8, 29u));
        cb.insns.push_back(Svc(0));

        cb.insns.push_back(MovReg(0, 20));
        EmitImm64(cb.insns, 1, 0x40087703ULL);
        cb.insns.push_back(Movz(2, 4096u));
        cb.insns.push_back(Movz(8, 29u));
        cb.insns.push_back(Svc(0));

        // mmap MAP_SHARED (0x01) twice -> x21, x22
        for (uint8_t dst : {uint8_t(21), uint8_t(22)}) {
            cb.insns.push_back(Movz(0, 0u));
            cb.insns.push_back(Movz(1, 4096u));
            cb.insns.push_back(Movz(2, 3u));
            cb.insns.push_back(Movz(3, 1u)); // MAP_SHARED
            cb.insns.push_back(MovReg(4, 20));
            cb.insns.push_back(Movz(5, 0u));
            cb.insns.push_back(Movz(8, 222u));
            cb.insns.push_back(Svc(0));
            cb.insns.push_back(MovReg(dst, 0));
        }

        // Write 0xCAFE via x21, read back via x22!
        cb.insns.push_back(Movz(10, 0xCAFEu));
        cb.insns.push_back(StrW(10, 21, 0u));
        cb.insns.push_back(LdrW(11, 22, 0u));
        cb.insns.push_back(Movz(10, 0xCAFEu));
        cb.insns.push_back(0x6B0A017Fu); // cmp w11, w10
        const size_t f1 = cb.insns.size(); cb.insns.push_back(0);

        // open /sys/fs/selinux/enforce -> read -> '0'
        EmitImm64(cb.insns, 0, static_cast<uint64_t>(-100));
        cb.EmitAdrPlaceholder(1, selinux_path);
        cb.insns.push_back(Movz(2, 0u));
        cb.insns.push_back(Movz(3, 0u));
        cb.insns.push_back(Movz(8, 56u));
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(AddImm64(1, 31, 0u));
        cb.insns.push_back(Movz(2, 1u));
        cb.insns.push_back(Movz(8, 63u));
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(Ldrb(10, 31, 0u));
        cb.insns.push_back(CmpImm64(10, static_cast<uint16_t>('0')));
        const size_t f2 = cb.insns.size(); cb.insns.push_back(0);

        // chdir("/system/bin") + getcwd(sp+64, 64)
        cb.EmitAdrPlaceholder(0, sys_dir);
        cb.insns.push_back(Movz(8, 49u)); // chdir
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(CmpImm64(0, 0u));
        const size_t f3 = cb.insns.size(); cb.insns.push_back(0);

        cb.insns.push_back(AddImm64(0, 31, 64u));
        cb.insns.push_back(Movz(1, 64u));
        cb.insns.push_back(Movz(8, 17u)); // getcwd
        cb.insns.push_back(Svc(0));
        cb.insns.push_back(Ldrb(10, 31, 65u)); // 's' in "/system/bin"
        cb.insns.push_back(CmpImm64(10, static_cast<uint16_t>('s')));
        const size_t f4 = cb.insns.size(); cb.insns.push_back(0);

        // dup3(x20, 20, O_CLOEXEC=02000000=0x80000) so fd 20 MUST close on execve!
        cb.insns.push_back(MovReg(0, 20));
        cb.insns.push_back(Movz(1, 20u));
        EmitImm64(cb.insns, 2, 0x80000ULL);
        cb.insns.push_back(Movz(8, 24u)); // dup3
        cb.insns.push_back(Svc(0));

        // argv @ sp+128: {next_path, nullptr}; envp @ sp+144: {env_kv, nullptr}
        cb.EmitAdrPlaceholder(10, next_path); cb.insns.push_back(StrX(10, 31, 128u));
        cb.insns.push_back(StrX(29, 31, 136u));
        cb.EmitAdrPlaceholder(10, env_kv);    cb.insns.push_back(StrX(10, 31, 144u));
        cb.insns.push_back(StrX(29, 31, 152u));

        cb.EmitAdrPlaceholder(0, next_path);
        cb.insns.push_back(AddImm64(1, 31, 128u));
        cb.insns.push_back(AddImm64(2, 31, 144u));
        cb.insns.push_back(Movz(8, 221u)); // execve
        cb.insns.push_back(Svc(0));

        const size_t fail_idx = cb.insns.size();
        cb.insns.push_back(Movz(0, 44u));
        cb.insns.push_back(Movz(8, 94u));
        cb.insns.push_back(Svc(0));

        for (size_t f : {f1, f2, f3, f4}) {
            cb.insns[f] = BCond(1u, static_cast<int32_t>(fail_idx - f));
        }
        init_elf = BuildElf64(cb.Finalize());
    }

    std::vector<uint8_t> rd = CpioArchive::Build({
        MakeCpio("init", 0100755u, init_elf),
        MakeCpio("system", 0040755u),
        MakeCpio("system/bin", 0040755u),
        MakeCpio("system/bin/next", 0100755u, next_elf),
    });
    std::vector<uint8_t> boot = BuildBootImgV2(rd, "androidboot.selinux=permissive");
    ParsedBootImage parsed;
    std::string err;
    assert(BootImageParser::ParseBootBytes(boot, parsed, err) == VmError::Ok);

    VirtualMachineSkeleton vm;
    MachineBootConfig cfg;
    cfg.ram_mb = 64u;
    assert(vm.InitializeAndStage(cfg, &parsed, err) == VmError::Ok);
    std::string target;
    assert(vm.BootGuest(false, target, err) == VmError::Ok);
    assert(vm.StepGuest(100000ULL) == VmError::Ok);
    assert(vm.Supervisor()->Exited());
    assert(vm.Supervisor()->ExitStatus() == 0);
    assert(vm.Uart().CapturedOutput().find("[ASHMEM-EXECVE-CLOEXEC-OK]") != std::string::npos);
    std::cout << "[PASS] Test 5: /dev/ashmem MAP_SHARED page sharing + SELinux + chdir/getcwd + execve envp/FD_CLOEXEC\n";
}

} // namespace

int main() {
    TestBinderIpcBrokerUnit();
    TestEl0MultiProcessBinderIpc();
    TestUnixSocketsScmRightsPropAndLogd();
    TestThreadsFutexTimerfdAndEpoll();
    TestAshmemSharedSelinuxCwdAndExecveCloexec();
    std::cout << "ALL M10 ANDROID IPC & THREADING TESTS PASSED.\n";
    return 0;
}
