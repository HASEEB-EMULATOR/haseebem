#pragma once

#include "haseeb/guest_ram.hpp"

#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace haseeb::vm {

// Real multi-process Android Binder IPC broker supporting /dev/binder, /dev/hwbinder,
// and /dev/vndbinder with handle<->node translation, scatter-gather buffer objects,
// SCM_RIGHTS-style BINDER_TYPE_FD duplication, refcounting, death notifications,
// and mapped ring allocation inside each target process's binder_mmap physical pages.
class BinderIpcBroker {
public:
    enum class Domain : uint8_t {
        Binder = 0,
        HwBinder = 1,
        VndBinder = 2,
    };

    static Domain DomainFromPath(const std::string& path);

    struct AllocBlock {
        uint64_t offset = 0;
        uint64_t size = 0;
        bool in_use = false;
    };

    struct PendingMessage {
        uint32_t br_cmd = 0; // BR_TRANSACTION, BR_REPLY, BR_INCREFS, etc.
        std::vector<uint8_t> payload;
    };

    struct Node {
        uint64_t id = 0;
        uint32_t owner_client_id = 0;
        uint64_t ptr = 0;
        uint64_t cookie = 0;
        uint32_t strong_refs = 0;
        uint32_t weak_refs = 0;
        bool is_dead = false;
    };

    struct DeathEntry {
        uint32_t watcher_client_id = 0;
        uint64_t node_id = 0;
        uint64_t cookie = 0;
    };

    struct ClientState {
        uint32_t id = 0;
        Domain domain = Domain::Binder;
        int32_t pid = 1;
        uint32_t euid = 0;
        uint64_t mmap_uva = 0;
        uint64_t mmap_size = 0;
        std::vector<uint64_t> mmap_pa_pages;
        std::vector<AllocBlock> alloc_blocks;

        // Maps guest handle -> node_id (handle 0 is always context manager if registered)
        std::unordered_map<uint32_t, uint64_t> handle_to_node;
        std::unordered_map<uint64_t, uint32_t> node_to_handle;
        uint32_t next_handle = 1;

        // Global per-thread/client inbox and pending reply stack
        std::deque<PendingMessage> inbox;
        // Stack of {from_client_id, buffer_uva_to_free_not_needed} expecting BC_REPLY
        std::vector<uint32_t> reply_targets;
    };

    using ReadUserFn = std::function<bool(uint64_t uva, void* dst, size_t len)>;
    using WriteUserFn = std::function<bool(uint64_t uva, const void* src, size_t len)>;
    using DupFdFn = std::function<int32_t(int32_t sender_pid, int32_t target_pid, int32_t sender_fd)>;
    using WakeTaskFn = std::function<void(int32_t target_pid)>;

    uint32_t OpenClient(Domain domain, int32_t pid, uint32_t euid);
    void CloseClient(uint32_t client_id, const WakeTaskFn& wake_fn);
    void RegisterMmap(uint32_t client_id,
                      uint64_t mmap_uva,
                      uint64_t mmap_size,
                      std::vector<uint64_t> mmap_pa_pages);

    bool HasPendingRead(uint32_t client_id) const;

    // Handles BINDER_SET_MAX_THREADS, BINDER_VERSION, BINDER_SET_CONTEXT_MGR(_EXT),
    // BINDER_WRITE_READ, and BINDER_THREAD_EXIT. Sets out_would_block = true when a blocking
    // read buffer is provided with empty write_size and no pending incoming commands.
    int64_t HandleIoctl(uint32_t client_id,
                        uint32_t req32,
                        uint64_t arg,
                        GuestRam& ram,
                        const ReadUserFn& read_user,
                        const WriteUserFn& write_user,
                        const DupFdFn& dup_fd,
                        const WakeTaskFn& wake_fn,
                        bool nonblock,
                        bool& out_would_block);

    void Clear();

private:
    uint64_t AllocTargetBuffer(ClientState& target, uint64_t size, uint64_t align = 8ULL);
    void FreeTargetBuffer(ClientState& target, uint64_t uva);
    bool ReadFromTargetMmap(GuestRam& ram,
                            const ClientState& target,
                            uint64_t uva,
                            void* dst,
                            size_t len) const;
    bool WriteToTargetMmap(GuestRam& ram,
                           const ClientState& target,
                           uint64_t uva,
                           const void* src,
                           size_t len) const;

    uint64_t GetOrCreateNode(uint32_t owner_client_id, uint64_t ptr, uint64_t cookie);
    uint32_t GetOrAssignHandle(ClientState& client, uint64_t node_id);
    uint64_t LookupNodeForHandle(Domain domain, const ClientState& client, uint32_t handle) const;

    void QueueSimpleReply(ClientState& client, uint32_t br_cmd);
    void QueueNodeRefCmd(uint32_t target_client_id, uint32_t br_cmd, uint64_t ptr, uint64_t cookie,
                         const WakeTaskFn& wake_fn);

    uint32_t next_client_id_ = 1;
    uint64_t next_node_id_ = 1;
    uint64_t context_mgr_node_[3]{0, 0, 0};
    std::unordered_map<uint32_t, ClientState> clients_;
    std::unordered_map<uint64_t, Node> nodes_;
    std::vector<DeathEntry> death_watchers_;
};

} // namespace haseeb::vm
