#include "haseeb/binder_ipc.hpp"

#include <algorithm>
#include <cstring>

namespace haseeb::vm {

namespace {

constexpr uint32_t kIoctlBinderWriteRead = 0xC0306201u;
constexpr uint32_t kIoctlBinderSetIdleTimeout = 0x40086203u;
constexpr uint32_t kIoctlBinderSetMaxThreads = 0x40046205u;
constexpr uint32_t kIoctlBinderSetIdlePrio = 0x40046206u;
constexpr uint32_t kIoctlBinderSetContextMgr = 0x40046207u;
constexpr uint32_t kIoctlBinderThreadExit = 0x40046208u;
constexpr uint32_t kIoctlBinderVersion = 0xC0046209u;
constexpr uint32_t kIoctlBinderSetContextMgrExt = 0x4018620Du;
constexpr uint32_t kIoctlBinderFreeze = 0x400C620Eu;

constexpr uint32_t kBinderTypeBinder = 0x73622a85u;
constexpr uint32_t kBinderTypeWeakBinder = 0x77622a85u;
constexpr uint32_t kBinderTypeHandle = 0x73682a85u;
constexpr uint32_t kBinderTypeWeakHandle = 0x77682a85u;
constexpr uint32_t kBinderTypeFd = 0x66642a85u;
constexpr uint32_t kBinderTypePtr = 0x70742a85u;
constexpr uint32_t kBinderTypeFda = 0x66646185u;

constexpr uint32_t kBrTransaction = 0x80407202u;
constexpr uint32_t kBrReply = 0x80407203u;
constexpr uint32_t kBrDeadReply = 0x00007205u;
constexpr uint32_t kBrTransactionComplete = 0x00007206u;
constexpr uint32_t kBrIncrefs = 0x80107207u;
constexpr uint32_t kBrAcquire = 0x80107208u;
constexpr uint32_t kBrRelease = 0x80107209u;
constexpr uint32_t kBrDecrefs = 0x8010720Au;
constexpr uint32_t kBrNoop = 0x0000720Cu;
constexpr uint32_t kBrDeadBinder = 0x8008720Fu;
constexpr uint32_t kBrClearDeathNotificationDone = 0x80087210u;
constexpr uint32_t kBrFailedReply = 0x00007211u;

constexpr uint32_t kTfOneWay = 0x01u;

#pragma pack(push, 1)
struct BinderWriteRead64 {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer;
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};
static_assert(sizeof(BinderWriteRead64) == 48u);

struct BinderTransactionData64 {
    uint64_t target; // low 32b handle OR 64b ptr
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    uint64_t data_buffer;
    uint64_t data_offsets;
};
static_assert(sizeof(BinderTransactionData64) == 64u);

struct FlatBinderObject64 {
    uint32_t type;
    uint32_t flags;
    uint64_t binder_or_handle;
    uint64_t cookie;
};
static_assert(sizeof(FlatBinderObject64) == 24u);

struct BinderBufferObject64 {
    uint32_t type;
    uint32_t flags;
    uint64_t buffer;
    uint64_t length;
    uint64_t parent;
    uint64_t parent_offset;
};
static_assert(sizeof(BinderBufferObject64) == 40u);

struct BinderFdArrayObject64 {
    uint32_t type;
    uint32_t pad;
    uint64_t num_fds;
    uint64_t parent;
    uint64_t parent_offset;
};
static_assert(sizeof(BinderFdArrayObject64) == 32u);

struct BinderPtrCookie64 {
    uint64_t ptr;
    uint64_t cookie;
};
static_assert(sizeof(BinderPtrCookie64) == 16u);
#pragma pack(pop)

uint64_t AlignUp8(uint64_t v) { return (v + 7ULL) & ~7ULL; }

} // namespace

BinderIpcBroker::Domain BinderIpcBroker::DomainFromPath(const std::string& path) {
    if (path == "/dev/hwbinder") return Domain::HwBinder;
    if (path == "/dev/vndbinder") return Domain::VndBinder;
    return Domain::Binder;
}

void BinderIpcBroker::Clear() {
    next_client_id_ = 1;
    next_node_id_ = 1;
    context_mgr_node_[0] = 0;
    context_mgr_node_[1] = 0;
    context_mgr_node_[2] = 0;
    clients_.clear();
    nodes_.clear();
    death_watchers_.clear();
}

uint32_t BinderIpcBroker::OpenClient(Domain domain, int32_t pid, uint32_t euid) {
    const uint32_t id = next_client_id_++;
    ClientState st;
    st.id = id;
    st.domain = domain;
    st.pid = pid;
    st.euid = euid;
    clients_.emplace(id, std::move(st));
    return id;
}

void BinderIpcBroker::RegisterMmap(uint32_t client_id,
                                   uint64_t mmap_uva,
                                   uint64_t mmap_size,
                                   std::vector<uint64_t> mmap_pa_pages) {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) return;
    it->second.mmap_uva = mmap_uva;
    it->second.mmap_size = mmap_size;
    it->second.mmap_pa_pages = std::move(mmap_pa_pages);
    it->second.alloc_blocks.clear();
    if (mmap_size > 0ULL) {
        it->second.alloc_blocks.push_back(AllocBlock{0ULL, mmap_size, false});
    }
}

void BinderIpcBroker::CloseClient(uint32_t client_id, const WakeTaskFn& wake_fn) {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) return;
    const Domain dom = it->second.domain;
    const uint32_t dom_idx = static_cast<uint32_t>(dom);

    std::vector<uint64_t> dead_nodes;
    for (auto& kv : nodes_) {
        if (kv.second.owner_client_id == client_id) {
            kv.second.is_dead = true;
            dead_nodes.push_back(kv.first);
            if (context_mgr_node_[dom_idx] == kv.first) {
                context_mgr_node_[dom_idx] = 0;
            }
        }
    }

    for (const auto& d : death_watchers_) {
        if (std::find(dead_nodes.begin(), dead_nodes.end(), d.node_id) != dead_nodes.end() &&
            d.watcher_client_id != client_id) {
            auto wit = clients_.find(d.watcher_client_id);
            if (wit != clients_.end()) {
                PendingMessage msg;
                msg.br_cmd = kBrDeadBinder;
                msg.payload.resize(8u);
                std::memcpy(msg.payload.data(), &d.cookie, 8u);
                wit->second.inbox.push_back(std::move(msg));
                if (wake_fn) wake_fn(wit->second.pid);
            }
        }
    }

    death_watchers_.erase(
        std::remove_if(death_watchers_.begin(), death_watchers_.end(), [&](const DeathEntry& d) {
            return d.watcher_client_id == client_id ||
                   std::find(dead_nodes.begin(), dead_nodes.end(), d.node_id) != dead_nodes.end();
        }),
        death_watchers_.end());

    // Fail any transactions awaiting a reply from this closing client
    for (uint32_t waiter_id : it->second.reply_targets) {
        auto wit = clients_.find(waiter_id);
        if (wit != clients_.end()) {
            QueueSimpleReply(wit->second, kBrDeadReply);
            if (wake_fn) wake_fn(wit->second.pid);
        }
    }

    clients_.erase(it);
}

bool BinderIpcBroker::HasPendingRead(uint32_t client_id) const {
    auto it = clients_.find(client_id);
    return it != clients_.end() && !it->second.inbox.empty();
}

uint64_t BinderIpcBroker::AllocTargetBuffer(ClientState& target, uint64_t size, uint64_t align) {
    if (target.mmap_uva == 0ULL || target.mmap_size == 0ULL) return 0ULL;
    const uint64_t need = std::max<uint64_t>(8ULL, AlignUp8(size));
    for (size_t i = 0; i < target.alloc_blocks.size(); ++i) {
        AllocBlock& blk = target.alloc_blocks[i];
        if (blk.in_use) continue;
        const uint64_t aligned_off = (blk.offset + (align - 1ULL)) & ~(align - 1ULL);
        const uint64_t pad = aligned_off - blk.offset;
        if (blk.size < pad + need) continue;

        const uint64_t alloc_off = aligned_off;
        const uint64_t rem = blk.size - (pad + need);
        if (pad > 0ULL) {
            AllocBlock pre{blk.offset, pad, false};
            blk.offset = alloc_off;
            blk.size = need;
            blk.in_use = true;
            if (rem > 0ULL) {
                target.alloc_blocks.insert(target.alloc_blocks.begin() + static_cast<std::ptrdiff_t>(i + 1u),
                                           AllocBlock{alloc_off + need, rem, false});
            }
            target.alloc_blocks.insert(target.alloc_blocks.begin() + static_cast<std::ptrdiff_t>(i), pre);
        } else {
            blk.in_use = true;
            blk.size = need;
            if (rem > 0ULL) {
                target.alloc_blocks.insert(target.alloc_blocks.begin() + static_cast<std::ptrdiff_t>(i + 1u),
                                           AllocBlock{alloc_off + need, rem, false});
            }
        }
        return target.mmap_uva + alloc_off;
    }
    return 0ULL;
}

void BinderIpcBroker::FreeTargetBuffer(ClientState& target, uint64_t uva) {
    if (uva < target.mmap_uva || uva >= target.mmap_uva + target.mmap_size) return;
    const uint64_t off = uva - target.mmap_uva;
    for (size_t i = 0; i < target.alloc_blocks.size(); ++i) {
        if (target.alloc_blocks[i].offset == off && target.alloc_blocks[i].in_use) {
            target.alloc_blocks[i].in_use = false;
            // Coalesce adjacent free blocks
            if (i + 1u < target.alloc_blocks.size() && !target.alloc_blocks[i + 1u].in_use) {
                target.alloc_blocks[i].size += target.alloc_blocks[i + 1u].size;
                target.alloc_blocks.erase(target.alloc_blocks.begin() + static_cast<std::ptrdiff_t>(i + 1u));
            }
            if (i > 0u && !target.alloc_blocks[i - 1u].in_use) {
                target.alloc_blocks[i - 1u].size += target.alloc_blocks[i].size;
                target.alloc_blocks.erase(target.alloc_blocks.begin() + static_cast<std::ptrdiff_t>(i));
            }
            return;
        }
    }
}

bool BinderIpcBroker::ReadFromTargetMmap(GuestRam& ram,
                                         const ClientState& target,
                                         uint64_t uva,
                                         void* dst,
                                         size_t len) const {
    if (len == 0u) return true;
    if (uva < target.mmap_uva || (uva - target.mmap_uva) + len > target.mmap_size) {
        return false;
    }
    auto* bytes = static_cast<uint8_t*>(dst);
    uint64_t off = uva - target.mmap_uva;
    size_t done = 0u;
    while (done < len) {
        const size_t pg_idx = static_cast<size_t>(off / 4096ULL);
        const size_t pg_off = static_cast<size_t>(off % 4096ULL);
        if (pg_idx >= target.mmap_pa_pages.size()) return false;
        const size_t chunk = std::min(4096u - pg_off, len - done);
        if (!ram.ReadBytes(target.mmap_pa_pages[pg_idx] + pg_off, bytes + done, chunk)) {
            return false;
        }
        off += chunk;
        done += chunk;
    }
    return true;
}

bool BinderIpcBroker::WriteToTargetMmap(GuestRam& ram,
                                        const ClientState& target,
                                        uint64_t uva,
                                        const void* src,
                                        size_t len) const {
    if (len == 0u) return true;
    if (uva < target.mmap_uva || (uva - target.mmap_uva) + len > target.mmap_size) {
        return false;
    }
    const auto* bytes = static_cast<const uint8_t*>(src);
    uint64_t off = uva - target.mmap_uva;
    size_t done = 0u;
    while (done < len) {
        const size_t pg_idx = static_cast<size_t>(off / 4096ULL);
        const size_t pg_off = static_cast<size_t>(off % 4096ULL);
        if (pg_idx >= target.mmap_pa_pages.size()) return false;
        const size_t chunk = std::min(4096u - pg_off, len - done);
        if (!ram.WriteBytes(target.mmap_pa_pages[pg_idx] + pg_off, bytes + done, chunk)) {
            return false;
        }
        off += chunk;
        done += chunk;
    }
    return true;
}

uint64_t BinderIpcBroker::GetOrCreateNode(uint32_t owner_client_id, uint64_t ptr, uint64_t cookie) {
    for (const auto& kv : nodes_) {
        if (kv.second.owner_client_id == owner_client_id && kv.second.ptr == ptr && !kv.second.is_dead) {
            return kv.first;
        }
    }
    Node node;
    node.id = next_node_id_++;
    node.owner_client_id = owner_client_id;
    node.ptr = ptr;
    node.cookie = cookie;
    nodes_.emplace(node.id, node);
    return node.id;
}

uint32_t BinderIpcBroker::GetOrAssignHandle(ClientState& client, uint64_t node_id) {
    auto it = client.node_to_handle.find(node_id);
    if (it != client.node_to_handle.end()) return it->second;
    const uint32_t dom_idx = static_cast<uint32_t>(client.domain);
    if (context_mgr_node_[dom_idx] == node_id) return 0u;
    const uint32_t h = client.next_handle++;
    client.handle_to_node[h] = node_id;
    client.node_to_handle[node_id] = h;
    return h;
}

uint64_t BinderIpcBroker::LookupNodeForHandle(Domain domain, const ClientState& client, uint32_t handle) const {
    if (handle == 0u) {
        return context_mgr_node_[static_cast<uint32_t>(domain)];
    }
    auto it = client.handle_to_node.find(handle);
    return (it != client.handle_to_node.end()) ? it->second : 0ULL;
}

void BinderIpcBroker::QueueSimpleReply(ClientState& client, uint32_t br_cmd) {
    PendingMessage msg;
    msg.br_cmd = br_cmd;
    client.inbox.push_back(std::move(msg));
}

void BinderIpcBroker::QueueNodeRefCmd(uint32_t target_client_id,
                                      uint32_t br_cmd,
                                      uint64_t ptr,
                                      uint64_t cookie,
                                      const WakeTaskFn& wake_fn) {
    auto it = clients_.find(target_client_id);
    if (it == clients_.end()) return;
    BinderPtrCookie64 pc{ptr, cookie};
    PendingMessage msg;
    msg.br_cmd = br_cmd;
    msg.payload.resize(sizeof(pc));
    std::memcpy(msg.payload.data(), &pc, sizeof(pc));
    it->second.inbox.push_back(std::move(msg));
    if (wake_fn) wake_fn(it->second.pid);
}

int64_t BinderIpcBroker::HandleIoctl(uint32_t client_id,
                                     uint32_t req32,
                                     uint64_t arg,
                                     GuestRam& ram,
                                     const ReadUserFn& read_user,
                                     const WriteUserFn& write_user,
                                     const DupFdFn& dup_fd,
                                     const WakeTaskFn& wake_fn,
                                     bool nonblock,
                                     bool& out_would_block) {
    out_would_block = false;
    auto cit = clients_.find(client_id);
    if (cit == clients_.end()) return -9; // EBADF
    ClientState& client = cit->second;
    const uint32_t dom_idx = static_cast<uint32_t>(client.domain);

    if (req32 == kIoctlBinderVersion) {
        int32_t ver = 8;
        return write_user(arg, &ver, sizeof(ver)) ? 0 : -14;
    }
    if (req32 == kIoctlBinderSetMaxThreads ||
        req32 == kIoctlBinderSetIdleTimeout ||
        req32 == kIoctlBinderSetIdlePrio ||
        req32 == kIoctlBinderThreadExit ||
        req32 == kIoctlBinderFreeze) {
        return 0;
    }
    if (req32 == kIoctlBinderSetContextMgr || req32 == kIoctlBinderSetContextMgrExt) {
        FlatBinderObject64 fbo{};
        if (req32 == kIoctlBinderSetContextMgrExt) {
            if (!read_user(arg, &fbo, sizeof(fbo))) return -14;
        }
        if (context_mgr_node_[dom_idx] != 0ULL) {
            const auto& cur_node = nodes_.at(context_mgr_node_[dom_idx]);
            if (!cur_node.is_dead && cur_node.owner_client_id != client_id) {
                return -16; // EBUSY
            }
        }
        const uint64_t nid = GetOrCreateNode(client_id, fbo.binder_or_handle, fbo.cookie);
        context_mgr_node_[dom_idx] = nid;
        return 0;
    }
    if (req32 != kIoctlBinderWriteRead) {
        return -22; // EINVAL
    }

    BinderWriteRead64 bwr{};
    if (!read_user(arg, &bwr, sizeof(bwr))) return -14;

    // 1. Process outgoing write_buffer commands
    if (bwr.write_size > bwr.write_consumed) {
        const size_t wlen = static_cast<size_t>(bwr.write_size - bwr.write_consumed);
        if (wlen > 1024u * 1024u) return -22;
        std::vector<uint8_t> wbuf(wlen);
        if (!read_user(bwr.write_buffer + bwr.write_consumed, wbuf.data(), wlen)) return -14;

        size_t pos = 0;
        while (pos + sizeof(uint32_t) <= wlen) {
            uint32_t cmd = 0;
            std::memcpy(&cmd, wbuf.data() + pos, 4u);
            const uint32_t cmd_nr = cmd & 0xFFu;
            const uint32_t cmd_sz = (cmd >> 16) & 0x3FFFu;
            if (pos + 4u + cmd_sz > wlen) return -22;
            const uint8_t* pay = wbuf.data() + pos + 4u;
            pos += 4u + cmd_sz;

            if (cmd_nr == 0u || cmd_nr == 1u || cmd_nr == 17u || cmd_nr == 18u) {
                // BC_TRANSACTION(0) / BC_REPLY(1) / BC_TRANSACTION_SG(17) / BC_REPLY_SG(18)
                if (cmd_sz < sizeof(BinderTransactionData64)) return -22;
                BinderTransactionData64 tr{};
                std::memcpy(&tr, pay, sizeof(tr));
                const bool is_reply = (cmd_nr == 1u || cmd_nr == 18u);
                const bool is_sg = (cmd_nr == 17u || cmd_nr == 18u);
                uint64_t sg_extra = 0ULL;
                if (is_sg && cmd_sz >= sizeof(BinderTransactionData64) + 8u) {
                    std::memcpy(&sg_extra, pay + sizeof(BinderTransactionData64), 8u);
                }

                uint32_t target_client_id = 0;
                uint64_t target_ptr = 0;
                uint64_t target_cookie = 0;

                if (is_reply) {
                    if (client.reply_targets.empty()) {
                        QueueSimpleReply(client, kBrFailedReply);
                        continue;
                    }
                    target_client_id = client.reply_targets.back();
                    client.reply_targets.pop_back();
                } else {
                    const uint32_t handle = static_cast<uint32_t>(tr.target & 0xFFFFFFFFULL);
                    const uint64_t nid = LookupNodeForHandle(client.domain, client, handle);
                    auto nit = nodes_.find(nid);
                    if (nid == 0ULL || nit == nodes_.end() || nit->second.is_dead) {
                        QueueSimpleReply(client, kBrDeadReply);
                        continue;
                    }
                    target_client_id = nit->second.owner_client_id;
                    target_ptr = nit->second.ptr;
                    target_cookie = nit->second.cookie;
                }

                auto tit = clients_.find(target_client_id);
                if (tit == clients_.end()) {
                    QueueSimpleReply(client, kBrDeadReply);
                    continue;
                }
                ClientState& target = tit->second;

                // Read sender data & offsets buffers
                if (tr.data_size > 4ULL * 1024ULL * 1024ULL ||
                    tr.offsets_size > 256ULL * 1024ULL) {
                    QueueSimpleReply(client, kBrFailedReply);
                    continue;
                }
                std::vector<uint8_t> d_bytes(static_cast<size_t>(tr.data_size));
                std::vector<uint64_t> off_vec(static_cast<size_t>(tr.offsets_size / sizeof(uint64_t)));
                if (tr.data_size > 0ULL && !read_user(tr.data_buffer, d_bytes.data(), d_bytes.size())) {
                    return -14;
                }
                if (!off_vec.empty() && !read_user(tr.data_offsets, off_vec.data(),
                                                   off_vec.size() * sizeof(uint64_t))) {
                    return -14;
                }

                const uint64_t aligned_data = AlignUp8(tr.data_size);
                const uint64_t total_alloc = aligned_data + tr.offsets_size + AlignUp8(sg_extra);
                const uint64_t target_data_uva = AllocTargetBuffer(
                    target, std::max<uint64_t>(8ULL, total_alloc));
                if (target_data_uva == 0ULL) {
                    QueueSimpleReply(client, kBrFailedReply);
                    continue;
                }
                uint64_t sg_cursor_uva = target_data_uva + aligned_data + tr.offsets_size;

                // Translate binder objects inside offsets
                for (uint64_t obj_off : off_vec) {
                    if (obj_off + 4u > d_bytes.size()) continue;
                    uint32_t obj_type = 0;
                    std::memcpy(&obj_type, d_bytes.data() + obj_off, 4u);

                    if ((obj_type == kBinderTypeBinder || obj_type == kBinderTypeWeakBinder) &&
                        obj_off + sizeof(FlatBinderObject64) <= d_bytes.size()) {
                        FlatBinderObject64 fbo{};
                        std::memcpy(&fbo, d_bytes.data() + obj_off, sizeof(fbo));
                        const uint64_t nid = GetOrCreateNode(client_id, fbo.binder_or_handle, fbo.cookie);
                        const uint32_t new_handle = GetOrAssignHandle(target, nid);
                        fbo.type = (obj_type == kBinderTypeBinder) ? kBinderTypeHandle : kBinderTypeWeakHandle;
                        fbo.binder_or_handle = new_handle;
                        fbo.cookie = 0;
                        std::memcpy(d_bytes.data() + obj_off, &fbo, sizeof(fbo));
                    } else if ((obj_type == kBinderTypeHandle || obj_type == kBinderTypeWeakHandle) &&
                               obj_off + sizeof(FlatBinderObject64) <= d_bytes.size()) {
                        FlatBinderObject64 fbo{};
                        std::memcpy(&fbo, d_bytes.data() + obj_off, sizeof(fbo));
                        const uint32_t h = static_cast<uint32_t>(fbo.binder_or_handle & 0xFFFFFFFFULL);
                        const uint64_t nid = LookupNodeForHandle(client.domain, client, h);
                        auto nit = nodes_.find(nid);
                        if (nid != 0ULL && nit != nodes_.end()) {
                            if (nit->second.owner_client_id == target_client_id) {
                                fbo.type = (obj_type == kBinderTypeHandle) ? kBinderTypeBinder : kBinderTypeWeakBinder;
                                fbo.binder_or_handle = nit->second.ptr;
                                fbo.cookie = nit->second.cookie;
                            } else {
                                fbo.binder_or_handle = GetOrAssignHandle(target, nid);
                                fbo.cookie = 0;
                            }
                            std::memcpy(d_bytes.data() + obj_off, &fbo, sizeof(fbo));
                        }
                    } else if (obj_type == kBinderTypeFd &&
                               obj_off + sizeof(FlatBinderObject64) <= d_bytes.size()) {
                        FlatBinderObject64 fbo{};
                        std::memcpy(&fbo, d_bytes.data() + obj_off, sizeof(fbo));
                        const int32_t sfd = static_cast<int32_t>(fbo.binder_or_handle & 0xFFFFFFFFULL);
                        const int32_t tfd = dup_fd ? dup_fd(client.pid, target.pid, sfd) : -1;
                        if (tfd >= 0) {
                            fbo.binder_or_handle = static_cast<uint64_t>(static_cast<uint32_t>(tfd));
                            std::memcpy(d_bytes.data() + obj_off, &fbo, sizeof(fbo));
                        }
                    } else if (obj_type == kBinderTypePtr &&
                               obj_off + sizeof(BinderBufferObject64) <= d_bytes.size()) {
                        BinderBufferObject64 bbo{};
                        std::memcpy(&bbo, d_bytes.data() + obj_off, sizeof(bbo));
                        if (bbo.length > 0ULL && bbo.length <= 1024ULL * 1024ULL) {
                            std::vector<uint8_t> child_bytes(static_cast<size_t>(bbo.length));
                            if (read_user(bbo.buffer, child_bytes.data(), child_bytes.size()) &&
                                sg_cursor_uva + child_bytes.size() <= target.mmap_uva + target.mmap_size &&
                                WriteToTargetMmap(ram, target, sg_cursor_uva, child_bytes.data(), child_bytes.size())) {
                                const uint64_t new_child_uva = sg_cursor_uva;
                                sg_cursor_uva += AlignUp8(child_bytes.size());
                                bbo.buffer = new_child_uva;
                                std::memcpy(d_bytes.data() + obj_off, &bbo, sizeof(bbo));
                                // Fix up pointer inside parent buffer if HAS_PARENT (flag 1)
                                if ((bbo.flags & 1u) != 0u && bbo.parent < off_vec.size()) {
                                    const uint64_t p_off = off_vec[static_cast<size_t>(bbo.parent)];
                                    if (p_off + sizeof(BinderBufferObject64) <= d_bytes.size()) {
                                        BinderBufferObject64 parent_bbo{};
                                        std::memcpy(&parent_bbo, d_bytes.data() + p_off, sizeof(parent_bbo));
                                        if (parent_bbo.buffer >= target.mmap_uva) {
                                            WriteToTargetMmap(ram, target,
                                                              parent_bbo.buffer + bbo.parent_offset,
                                                              &new_child_uva, sizeof(new_child_uva));
                                        }
                                    }
                                }
                            }
                        }
                    } else if (obj_type == kBinderTypeFda &&
                               obj_off + sizeof(BinderFdArrayObject64) <= d_bytes.size()) {
                        BinderFdArrayObject64 fda{};
                        std::memcpy(&fda, d_bytes.data() + obj_off, sizeof(fda));
                        if (fda.num_fds > 0ULL && fda.num_fds <= 64ULL && fda.parent < off_vec.size()) {
                            const uint64_t p_off = off_vec[static_cast<size_t>(fda.parent)];
                            if (p_off + sizeof(BinderBufferObject64) <= d_bytes.size()) {
                                BinderBufferObject64 parent_bbo{};
                                std::memcpy(&parent_bbo, d_bytes.data() + p_off, sizeof(parent_bbo));
                                for (uint64_t fi = 0; fi < fda.num_fds; ++fi) {
                                    int32_t sfd = -1;
                                    const uint64_t fd_addr = parent_bbo.buffer + fda.parent_offset + fi * 4ULL;
                                    // Parent buffer was already copied to target mmap
                                    if (ReadFromTargetMmap(ram, target, fd_addr, &sfd, 4u)) {
                                        int32_t tfd = dup_fd ? dup_fd(client.pid, target.pid, sfd) : -1;
                                        if (tfd >= 0) {
                                            WriteToTargetMmap(ram, target, fd_addr, &tfd, 4u);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Write translated payload + offsets into target's binder_mmap ring
                const uint64_t target_off_uva = target_data_uva + aligned_data;
                if (!d_bytes.empty()) {
                    WriteToTargetMmap(ram, target, target_data_uva, d_bytes.data(), d_bytes.size());
                }
                if (!off_vec.empty()) {
                    WriteToTargetMmap(ram, target, target_off_uva, off_vec.data(),
                                      off_vec.size() * sizeof(uint64_t));
                }

                BinderTransactionData64 out_tr{};
                out_tr.target = target_ptr;
                out_tr.cookie = target_cookie;
                out_tr.code = tr.code;
                out_tr.flags = tr.flags;
                out_tr.sender_pid = client.pid;
                out_tr.sender_euid = client.euid;
                out_tr.data_size = tr.data_size;
                out_tr.offsets_size = tr.offsets_size;
                out_tr.data_buffer = target_data_uva;
                out_tr.data_offsets = target_off_uva;

                if (!is_reply && (tr.flags & kTfOneWay) == 0u) {
                    target.reply_targets.push_back(client_id);
                }

                PendingMessage target_msg;
                target_msg.br_cmd = is_reply ? kBrReply : kBrTransaction;
                target_msg.payload.resize(sizeof(out_tr));
                std::memcpy(target_msg.payload.data(), &out_tr, sizeof(out_tr));
                target.inbox.push_back(std::move(target_msg));
                if (wake_fn) wake_fn(target.pid);

                QueueSimpleReply(client, kBrTransactionComplete);
            } else if (cmd_nr == 3u && cmd_sz >= 8u) {
                // BC_FREE_BUFFER
                uint64_t ptr = 0;
                std::memcpy(&ptr, pay, 8u);
                FreeTargetBuffer(client, ptr);
            } else if ((cmd_nr >= 4u && cmd_nr <= 7u) && cmd_sz >= 4u) {
                // BC_INCREFS(4), BC_ACQUIRE(5), BC_RELEASE(6), BC_DECREFS(7)
                uint32_t handle = 0;
                std::memcpy(&handle, pay, 4u);
                const uint64_t nid = LookupNodeForHandle(client.domain, client, handle);
                auto nit = nodes_.find(nid);
                if (nit != nodes_.end() && !nit->second.is_dead) {
                    if (cmd_nr == 4u) {
                        if (++nit->second.weak_refs == 1u) {
                            QueueNodeRefCmd(nit->second.owner_client_id, kBrIncrefs,
                                            nit->second.ptr, nit->second.cookie, wake_fn);
                        }
                    } else if (cmd_nr == 5u) {
                        if (++nit->second.strong_refs == 1u) {
                            QueueNodeRefCmd(nit->second.owner_client_id, kBrAcquire,
                                            nit->second.ptr, nit->second.cookie, wake_fn);
                        }
                    } else if (cmd_nr == 6u) {
                        if (nit->second.strong_refs > 0u && --nit->second.strong_refs == 0u) {
                            QueueNodeRefCmd(nit->second.owner_client_id, kBrRelease,
                                            nit->second.ptr, nit->second.cookie, wake_fn);
                        }
                    } else if (cmd_nr == 7u) {
                        if (nit->second.weak_refs > 0u && --nit->second.weak_refs == 0u) {
                            QueueNodeRefCmd(nit->second.owner_client_id, kBrDecrefs,
                                            nit->second.ptr, nit->second.cookie, wake_fn);
                        }
                    }
                }
            } else if (cmd_nr == 14u && cmd_sz >= 12u) {
                // BC_REQUEST_DEATH_NOTIFICATION (handle@0, cookie@4 or cookie@8 depending on alignment)
                uint32_t handle = 0;
                uint64_t cookie = 0;
                std::memcpy(&handle, pay, 4u);
                std::memcpy(&cookie, pay + (cmd_sz >= 16u ? 8u : 4u), 8u);
                const uint64_t nid = LookupNodeForHandle(client.domain, client, handle);
                if (nid != 0ULL) {
                    auto nit = nodes_.find(nid);
                    if (nit != nodes_.end() && nit->second.is_dead) {
                        PendingMessage dmsg;
                        dmsg.br_cmd = kBrDeadBinder;
                        dmsg.payload.resize(8u);
                        std::memcpy(dmsg.payload.data(), &cookie, 8u);
                        client.inbox.push_back(std::move(dmsg));
                    } else {
                        death_watchers_.push_back(DeathEntry{client_id, nid, cookie});
                    }
                }
            } else if (cmd_nr == 15u && cmd_sz >= 12u) {
                // BC_CLEAR_DEATH_NOTIFICATION
                uint32_t handle = 0;
                uint64_t cookie = 0;
                std::memcpy(&handle, pay, 4u);
                std::memcpy(&cookie, pay + (cmd_sz >= 16u ? 8u : 4u), 8u);
                const uint64_t nid = LookupNodeForHandle(client.domain, client, handle);
                death_watchers_.erase(
                    std::remove_if(death_watchers_.begin(), death_watchers_.end(), [&](const DeathEntry& d) {
                        return d.watcher_client_id == client_id && d.node_id == nid && d.cookie == cookie;
                    }),
                    death_watchers_.end());
                PendingMessage dmsg;
                dmsg.br_cmd = kBrClearDeathNotificationDone;
                dmsg.payload.resize(8u);
                std::memcpy(dmsg.payload.data(), &cookie, 8u);
                client.inbox.push_back(std::move(dmsg));
            }
            // BC_INCREFS_DONE(8), BC_ACQUIRE_DONE(9), BC_REGISTER_LOOPER(11),
            // BC_ENTER_LOOPER(12), BC_EXIT_LOOPER(13), BC_DEAD_BINDER_DONE(16): accepted cleanly.
        }
        bwr.write_consumed = bwr.write_size;
    }

    // 2. Drain pending BR_* commands into read_buffer
    if (bwr.read_size > bwr.read_consumed) {
        if (client.inbox.empty()) {
            // Update write_consumed before returning/blocking
            write_user(arg, &bwr, sizeof(bwr));
            if (nonblock) return -11; // EAGAIN
            out_would_block = true;
            return 0;
        }

        // Emit BR_NOOP first if space permits (standard kernel binder behavior)
        if (bwr.read_size - bwr.read_consumed >= 4u) {
            const uint32_t noop = kBrNoop;
            if (!write_user(bwr.read_buffer + bwr.read_consumed, &noop, 4u)) return -14;
            bwr.read_consumed += 4u;
        }

        while (!client.inbox.empty()) {
            const PendingMessage& msg = client.inbox.front();
            const size_t need = 4u + msg.payload.size();
            if (bwr.read_consumed + need > bwr.read_size) break;
            if (!write_user(bwr.read_buffer + bwr.read_consumed, &msg.br_cmd, 4u)) return -14;
            if (!msg.payload.empty() &&
                !write_user(bwr.read_buffer + bwr.read_consumed + 4u,
                            msg.payload.data(), msg.payload.size())) {
                return -14;
            }
            bwr.read_consumed += need;
            client.inbox.pop_front();
        }
    }

    return write_user(arg, &bwr, sizeof(bwr)) ? 0 : -14;
}

} // namespace haseeb::vm
