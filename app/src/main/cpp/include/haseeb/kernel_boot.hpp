#pragma once

#include "haseeb/binder_ipc.hpp"
#include "haseeb/boot_image.hpp"
#include "haseeb/cpio_reader.hpp"
#include "haseeb/cpu_core.hpp"
#include "haseeb/ext4_reader.hpp"
#include "haseeb/guest_ram.hpp"
#include "haseeb/phone_hardware.hpp"
#include "haseeb/pl011_uart.hpp"
#include "haseeb/prop_area.hpp"
#include "haseeb/psci.hpp"
#include "haseeb/soft_gles.hpp"
#include "haseeb/virtio_gpu.hpp"
#include "haseeb/virtio_input.hpp"
#include "haseeb/virtio_snd_net.hpp"
#include "haseeb/vm_types.hpp"

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace haseeb::vm {

struct Elf64LoadResult {
    bool ok = false;
    bool is_dynamic = false;
    bool has_tls = false;
    uint64_t entry_pc = 0;
    uint64_t phdr_va = 0;
    uint16_t phent_size = 0;
    uint16_t phnum = 0;
    uint64_t brk_start = 0;
    uint64_t stack_top = 0;
    uint64_t initial_sp = 0;
    uint64_t interp_base = 0;
    std::string interp_path;
    std::string error;
};

// Loads static, PIE, or dynamically linked (PT_INTERP) ELF64 AArch64 binaries
// into Stage-1 4 KiB page tables in GuestRam and sets up argc/argv/envp/auxv stack.
class Elf64GuestLoader {
public:
    using FileResolverFn = std::function<bool(const std::string& path, std::vector<uint8_t>& out_data)>;

    static bool IsValidAArch64Elf(const std::vector<uint8_t>& elf_bytes);

    static Elf64LoadResult LoadAndMap(GuestRam& ram,
                                      uint64_t ttbr0_pa,
                                      uint64_t& phys_alloc_cursor,
                                      uint64_t phys_alloc_limit,
                                      const std::vector<uint8_t>& elf_bytes,
                                      const std::vector<std::string>& argv,
                                      const std::vector<std::string>& envp);

    static Elf64LoadResult LoadAndMap(GuestRam& ram,
                                      uint64_t ttbr0_pa,
                                      uint64_t& phys_alloc_cursor,
                                      uint64_t phys_alloc_limit,
                                      const std::vector<uint8_t>& elf_bytes,
                                      const std::vector<std::string>& argv,
                                      const std::vector<std::string>& envp,
                                      const FileResolverFn& interp_resolver);

    static bool MapPage4K(GuestRam& ram,
                          uint64_t ttbr0_pa,
                          uint64_t& phys_alloc_cursor,
                          uint64_t phys_alloc_limit,
                          uint64_t va,
                          uint64_t pa,
                          bool el0_access,
                          bool writable,
                          bool executable);
};

// Multi-process EL1 supervisor + Linux AArch64 SVC ABI runtime for booting CPIO initramfs
// (/magiskinit, /init) and ext4 Android framework services (/system/bin/init, servicemanager,
// zygote64, system_server, surfaceflinger), plus /dev/fb0, /dev/input/event*, /dev/binder,
// /dev/ashmem, /dev/dma_heap/system, /dev/haseeb_sensors, /dev/video0, /dev/magisk_su,
// /dev/haseeb_gles, /dev/snd/pcmC0D0*, /dev/__properties__, and /storage/emulated/0.
class LinuxGuestSupervisor {
public:
    struct OpenFile;

    struct EpollWatch {
        int32_t fd = -1;
        uint32_t events = 0;
        uint64_t data = 0;
    };

    struct UnixSocketEndpoint {
        struct Chunk {
            std::vector<uint8_t> data;
            std::vector<std::shared_ptr<OpenFile>> passed_fds;
            std::string peer_addr;
        };

        int domain = 1;    // AF_UNIX
        int sock_type = 1; // SOCK_STREAM
        std::string bound_path;
        std::string peer_path;
        bool listening = false;
        int backlog = 128;
        bool peer_closed = false;
        bool shutdown_rd = false;
        bool shutdown_wr = false;
        std::weak_ptr<UnixSocketEndpoint> peer;
        std::deque<std::shared_ptr<UnixSocketEndpoint>> pending_accept;
        std::deque<Chunk> rx_chunks;

        ~UnixSocketEndpoint();
    };

    struct OpenFile {
        std::string path;
        std::string host_path;
        std::vector<uint8_t> data;
        size_t offset = 0;
        int host_fd = -1;
        int fd_flags = 0; // FD_CLOEXEC = 1
        bool is_dir = false;
        bool is_framebuffer = false;
        bool is_sensors = false;
        bool is_camera = false;
        bool is_gles = false;
        bool is_binder = false;
        uint32_t binder_client_id = 0;
        bool is_snd_play = false;
        bool is_snd_cap = false;
        bool is_magisk_su = false;
        bool is_host_storage = false;
        bool is_eventfd = false;
        uint64_t eventfd_counter = 0;
        bool is_timerfd = false;
        int timerfd_clockid = 1;
        int64_t timerfd_next_expire_ns = 0;
        int64_t timerfd_interval_ns = 0;
        uint64_t timerfd_expirations = 0;
        bool is_epoll = false;
        std::vector<int> epoll_fds;
        std::vector<EpollWatch> epoll_watches;
        bool is_memfd = false;
        bool is_ashmem = false;
        bool is_dma_heap = false;
        bool is_ion = false;
        std::string ashmem_name;
        size_t ashmem_size = 0;
        uint32_t ashmem_prot = 7u;
        bool ashmem_pinned = true;
        std::shared_ptr<std::vector<uint64_t>> shared_pages;
        bool is_writable_mem = false;
        bool is_runtime_vfs = false;
        bool is_dev_null = false;
        bool is_dev_zero = false;
        bool is_dev_urandom = false;
        bool is_kmsg = false;
        bool is_tty = false;
        bool is_stdio_out = false;
        bool nonblock = false;
        std::shared_ptr<UnixSocketEndpoint> unix_sock;
        bool is_host_inet_sock = false;
        int host_sock_domain = 0;
        int host_sock_type = 0;
        bool is_netlink = false;
        int netlink_protocol = 0;
        uint32_t netlink_pid = 0;
        uint32_t netlink_groups = 0;
        int32_t so_error = 0;
        VirtioInputDevice* input_dev = nullptr;
        std::vector<std::string> dir_children;
        size_t dir_cursor = 0;
        uint64_t st_dev = 1ULL;
        uint64_t st_ino = 1ULL;
    };

    struct VmSpace {
        uint64_t ttbr0_pa = 0;
        uint64_t current_brk = 0;
        uint64_t mmap_cursor = 0x0000001000000000ULL;
        std::vector<uint64_t> fb_mapped_pas;
        std::vector<std::pair<uint64_t, uint64_t>> lazy_prot_none_ranges;
        uint64_t tagged_addr_ctrl = 0;
    };

    struct FdTable {
        int next_fd = 3;
        std::unordered_map<int, OpenFile> fds;
    };

    struct SyscallTraceEntry {
        uint64_t nr = 0;
        uint64_t a0 = 0;
        uint64_t a1 = 0;
        uint64_t a2 = 0;
        int64_t ret = 0;
        uint64_t pc = 0;
        int32_t pid = 1;
        char note[48]{};
    };

    enum class TaskState : uint8_t {
        Runnable = 0,
        WaitingChild,
        Sleeping,
        FutexWait,
        PollWait,
        BinderWait,
        Zombie,
    };

    struct SavedTaskCpu {
        uint64_t x[31]{};
        uint64_t sp_el0 = 0;
        uint64_t elr_el1 = 0;
        uint64_t spsr_el1 = 0;
        uint64_t tpidr_el0 = 0;
        uint32_t fpcr = 0;
        uint32_t fpsr = 0;
        std::array<NeonReg, 32> v{};
    };

    struct GuestTask {
        int32_t pid = 1;  // TID in Linux kernel terms
        int32_t tgid = 1; // Thread group leader PID (returned by getpid)
        int32_t ppid = 0;
        uint32_t uid = 0;
        uint32_t gid = 0;
        std::string binary;
        std::string cwd = "/";
        uint64_t stack_top = 0x000000007FFF0000ULL;
        std::shared_ptr<VmSpace> vm = std::make_shared<VmSpace>();
        std::shared_ptr<FdTable> files = std::make_shared<FdTable>();
        SavedTaskCpu cpu{};
        TaskState state = TaskState::Runnable;
        int exit_status = 0;
        int32_t wait_target_pid = -1;
        uint64_t wait_status_uva = 0;
        int64_t wakeup_ns = 0;
        uint64_t futex_pa = 0;
        uint32_t futex_bitset = 0xFFFFFFFFu;
        bool futex_has_timeout = false;
        int64_t futex_deadline_ns = 0;
        int32_t poll_wait_epfd = -1;
        std::vector<EpollWatch> poll_wait_fds;
        uint64_t poll_events_uva = 0;
        int32_t poll_maxevents = 0;
        bool poll_has_timeout = false;
        int64_t poll_deadline_ns = 0;
        uint64_t clear_child_tid = 0;
        uint64_t sigaltstack_sp = 0ULL;
        int32_t sigaltstack_flags = 2; // SS_DISABLE
        uint64_t sigaltstack_size = 0ULL;
    };

    LinuxGuestSupervisor(GuestRam& ram,
                         Pl011Uart& uart,
                         PsciController& psci,
                         const loader::Ext4Reader* ext4 = nullptr,
                         VirtioGpuDevice* gpu = nullptr,
                         VirtioInputDevice* touch = nullptr,
                         VirtioInputDevice* kbd = nullptr);
    ~LinuxGuestSupervisor();

    void SetInitramfs(std::vector<CpioEntry> entries);
    void SetExt4Reader(const loader::Ext4Reader* ext4) { ext4_ = ext4; }
    void SetGpuDevice(VirtioGpuDevice* gpu) { gpu_ = gpu; }
    void SetInputDevices(VirtioInputDevice* touch, VirtioInputDevice* kbd) {
        touch_ = touch;
        kbd_ = kbd;
    }
    void SetHardwareHub(PhoneHardwareHub* hw) { hardware_ = hw; }
    void SetSoftGles(SoftGlesContext* gles) { soft_gles_ = gles; }
    void SetSndDevice(VirtioSndDevice* snd) { snd_ = snd; }
    void SetPropertyManager(haseeb::prop::PropertyAreaManager* mgr) { prop_mgr_ = mgr; }
    void SetSharedStorageRoot(const std::string& host_dir);
    const std::string& SharedStorageRoot() const { return shared_storage_root_; }

    void SetGuestIdentity(const std::string& cmdline, bool magisk_enabled);

    VmError PrepareBoot(AArch64CpuCore& cpu,
                        uint64_t ram_bytes,
                        uint64_t kernel_reserved_end,
                        const std::vector<std::string>& argv,
                        std::string& out_selected_binary,
                        std::string& out_error,
                        uint64_t arena_max_limit = 0);

    HypercallResult HandleHypercall(AArch64CpuCore& cpu,
                                    CpuState& state,
                                    uint16_t imm16,
                                    bool is_smc);

    int ExitStatus() const { return exit_status_; }
    bool Exited() const { return exited_; }
    const std::string& ActiveBinary() const { return active_binary_; }
    const std::string& LastTrapDetail() const { return last_trap_detail_; }
    std::vector<std::string> BinderServices() const { return binder_services_; }
    size_t ActiveTaskCount() const;
    void WakeSleepingTasks();
    void ResumeIfWaiting(AArch64CpuCore& cpu);
    void YieldTimeSlice(AArch64CpuCore& cpu);

private:
    static constexpr uint16_t kSyscallHypercallImm = 0x4C58u; // "LX"

    void CloseSingleOpenFile(OpenFile& of);
    void CloseTaskOpenFds(GuestTask& task);
    void CloseAllOpenFds();
    GuestTask* CurrentTask();
    const GuestTask* CurrentTask() const;
    void SaveTaskContext(const CpuState& st, GuestTask& task) const;
    void RestoreTaskContext(AArch64CpuCore& cpu, CpuState& st, const GuestTask& task) const;
    bool ScheduleNextTask(AArch64CpuCore& cpu, CpuState& st, bool& out_all_exited, bool& out_wfi_sleep);
    bool TryResolveElfForTask(const std::string& path, std::vector<uint8_t>& out_data) const;
    bool MapFreshAddressSpace(AArch64CpuCore& cpu,
                              const std::vector<uint8_t>& elf_bytes,
                              const std::vector<std::string>& argv,
                              std::string& out_error,
                              bool reset_phys_cursor,
                              const std::vector<std::string>* envp_override = nullptr);
    bool ResolveHostStoragePath(const std::string& norm_guest_path,
                                std::string& out_host_path,
                                std::string& out_rel) const;
    bool ResolveGuestPathWithDirfd(const std::unordered_map<int, OpenFile>& fds,
                                   int dirfd,
                                   const std::string& raw_path,
                                   std::string& out_norm) const;
    struct GuestStatMeta {
        uint64_t st_dev = 1ULL;
        uint64_t st_ino = 1ULL;
        uint32_t st_mode = 0100755u;
        uint64_t st_rdev = 0ULL;
        uint64_t st_size = 0ULL;
    };

    bool ResolveProcSymlinkTarget(const std::unordered_map<int, OpenFile>& fds,
                                  const std::string& norm_path,
                                  std::string& out_target) const;
    bool ResolveSymlinkTarget(const std::unordered_map<int, OpenFile>& fds,
                              const std::string& norm_path,
                              std::string& out_target) const;
    bool ResolveVfsFile(const std::string& path,
                        std::vector<uint8_t>& out_data,
                        bool& out_is_dir,
                        std::vector<std::string>& out_children,
                        std::string* out_resolved_path = nullptr,
                        const std::unordered_map<int, OpenFile>* fds = nullptr) const;
    int64_t StatFd(const std::unordered_map<int, OpenFile>& fds, int fd, GuestStatMeta& out) const;
    int64_t StatGuestPath(const std::unordered_map<int, OpenFile>& fds,
                          int dirfd,
                          const std::string& raw_path,
                          uint64_t flags,
                          std::string* out_note,
                          GuestStatMeta& out) const;
    bool LookupL3Pte(uint64_t va, uint64_t& out_l3_entry_pa, uint64_t& out_leaf) const;
    bool RangeHasAnyMapping(uint64_t addr, uint64_t len) const;
    void UnmapRange4K(AArch64CpuCore& cpu, uint64_t addr, uint64_t len);
    bool ProtectRange4K(AArch64CpuCore& cpu, uint64_t addr, uint64_t len, bool r, bool w, bool x);
    int64_t OpenGuestPath(std::unordered_map<int, OpenFile>& fds,
                          int& next_fd,
                          const std::string& norm,
                          uint64_t flags,
                          uint64_t mode,
                          bool check_access_only);
    uint32_t ComputeFdPollEvents(const OpenFile& of) const;
    uint32_t ComputeGuestFdPollEvents(const std::unordered_map<int, OpenFile>& fds, int fd) const;
    void WakeBinderWaitersForPid(int32_t target_pid);
    void WakePollWaiters();
    int WakeFutexWaiters(uint64_t pa, int max_wake, uint32_t bitset);
    void HandleBuiltInPropertyServicePacket(const std::shared_ptr<UnixSocketEndpoint>& client_ep,
                                            const std::vector<uint8_t>& pkt);
    void HandleBuiltInLogdPacket(const std::vector<uint8_t>& pkt);
    void RecordSyscall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                       int64_t ret, uint64_t pc, int32_t pid, const std::string& note = "");
    void LogToUart(const std::string& msg) const;
    std::string DumpRecentSyscalls(size_t max_entries = 16) const;
    void EmitFailureDiagnostics(AArch64CpuCore& cpu, const std::string& reason) const;
    bool ReadUserString(AArch64CpuCore& cpu, uint64_t uva, std::string& out_str) const;
    bool ReadUserBytes(AArch64CpuCore& cpu, uint64_t uva, void* dst, size_t len) const;
    bool WriteUserBytes(AArch64CpuCore& cpu, uint64_t uva, const void* src, size_t len) const;
    int64_t DispatchSyscall(AArch64CpuCore& cpu, CpuState& st, bool& out_halt, bool& out_retry, bool& out_yield, std::string* out_note = nullptr);
    std::string FormatExceptionTrap(AArch64CpuCore& cpu, const CpuState& state, uint32_t ec) const;

    GuestRam& ram_;
    Pl011Uart& uart_;
    PsciController& psci_;
    const loader::Ext4Reader* ext4_ = nullptr;
    VirtioGpuDevice* gpu_ = nullptr;
    VirtioInputDevice* touch_ = nullptr;
    VirtioInputDevice* kbd_ = nullptr;
    PhoneHardwareHub* hardware_ = nullptr;
    SoftGlesContext* soft_gles_ = nullptr;
    VirtioSndDevice* snd_ = nullptr;
    haseeb::prop::PropertyAreaManager* prop_mgr_ = nullptr;
    BinderIpcBroker binder_broker_;

    std::string shared_storage_root_;
    std::vector<CpioEntry> initramfs_;
    std::string cmdline_;
    bool magisk_enabled_ = false;
    std::string active_binary_;
    std::string last_trap_detail_;

    uint64_t ram_bytes_ = 0;
    uint64_t arena_base_ = 0;
    uint64_t arena_limit_ = 0;
    uint64_t phys_cursor_ = 0;
    uint64_t vbar_pa_ = 0;
    uint64_t ttbr0_pa_ = 0;
    uint64_t current_brk_ = 0;
    uint64_t mmap_cursor_ = 0x0000001000000000ULL;

    uint32_t uid_ = 0u;
    uint32_t gid_ = 0u;
    uint64_t sigaltstack_sp_ = 0ULL;
    int32_t sigaltstack_flags_ = 2; // SS_DISABLE
    uint64_t sigaltstack_size_ = 0ULL;

    std::vector<uint64_t> fb_mapped_pas_;
    bool FlushFramebufferToGpu();

    int next_fd_ = 3;
    std::unordered_map<int, OpenFile> open_fds_;
    std::unordered_map<std::string, std::weak_ptr<UnixSocketEndpoint>> unix_bound_sockets_;
    int32_t next_pid_ = 1;
    std::vector<std::unique_ptr<GuestTask>> tasks_;
    size_t current_task_idx_ = 0;
    std::vector<std::string> binder_services_;

    bool exited_ = false;
    int exit_status_ = 0;

    static constexpr size_t kSyscallTraceSize = 64;
    std::array<SyscallTraceEntry, kSyscallTraceSize> syscall_ring_{};
    size_t syscall_head_ = 0;
    uint64_t syscall_total_ = 0;
    std::unordered_set<uint64_t> logged_enosys_;
    std::unordered_set<std::string> runtime_dirs_;
    std::unordered_map<std::string, std::string> runtime_symlinks_;
    std::unordered_map<std::string, std::vector<uint8_t>> runtime_files_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::vector<uint8_t>>> runtime_xattrs_;
};

} // namespace haseeb::vm
