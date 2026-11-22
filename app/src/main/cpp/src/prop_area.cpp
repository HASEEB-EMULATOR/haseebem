#include "haseeb/prop_area.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <linux/futex.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__linux__) && !defined(__ANDROID__)
#include <sys/syscall.h>
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace haseeb::prop {

namespace {

int CreateMemfd(const char* name) {
#if defined(__NR_memfd_create)
    int fd = static_cast<int>(::syscall(__NR_memfd_create, name, MFD_CLOEXEC));
    if (fd >= 0) return fd;
#endif
    return -1;
}

int FutexWait(std::atomic<uint32_t>* addr, uint32_t expected, uint32_t timeout_ms) {
    struct timespec ts {};
    struct timespec* ts_ptr = nullptr;
    if (timeout_ms > 0) {
        ts.tv_sec = static_cast<time_t>(timeout_ms / 1000u);
        ts.tv_nsec = static_cast<long>((timeout_ms % 1000u) * 1000000L);
        ts_ptr = &ts;
    }
    return static_cast<int>(::syscall(
        SYS_futex,
        reinterpret_cast<uint32_t*>(addr),
        FUTEX_WAIT,
        expected,
        ts_ptr,
        nullptr,
        0
    ));
}

void FutexWakeAll(std::atomic<uint32_t>* addr) {
    ::syscall(
        SYS_futex,
        reinterpret_cast<uint32_t*>(addr),
        FUTEX_WAKE,
        INT_MAX,
        nullptr,
        nullptr,
        0
    );
}

int ComparePropSegment(const char* a, size_t len_a, const char* b, size_t len_b) {
    if (len_a < len_b) return -1;
    if (len_a > len_b) return 1;
    if (len_a == 0) return 0;
    return std::memcmp(a, b, len_a);
}

bool EnsureDirectoriesRecursive(const std::string& path) {
    if (path.empty()) return false;
    std::string cur;
    if (path[0] == '/') cur = "/";
    std::istringstream iss(path);
    std::string part;
    while (std::getline(iss, part, '/')) {
        if (part.empty()) continue;
        if (cur.size() > 1 && cur.back() != '/') cur += '/';
        cur += part;
        if (::mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

std::string Trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

// Bionic PropertyInfoArea binary structures (AOSP property_info_parser ABI v1)
struct BinaryPropertyInfoHeader {
    uint32_t current_version;
    uint32_t minimum_supported_version;
    uint32_t size;
    uint32_t contexts_offset;
    uint32_t types_offset;
    uint32_t root_offset;
};
static_assert(sizeof(BinaryPropertyInfoHeader) == 24, "PropertyInfoHeader must be 24 bytes");

struct BinaryTrieNodeInternal {
    uint32_t property_entry;
    uint32_t num_child_nodes;
    uint32_t child_nodes;
    uint32_t num_prefixes;
    uint32_t prefix_entries;
    uint32_t num_exact_matches;
    uint32_t exact_match_entries;
};
static_assert(sizeof(BinaryTrieNodeInternal) == 28, "TrieNodeInternal must be 28 bytes");

struct BinaryPropertyEntry {
    uint32_t name_offset;
    uint32_t namelen;
    uint32_t context_index;
    uint32_t type_index;
};
static_assert(sizeof(BinaryPropertyEntry) == 16, "PropertyEntry must be 16 bytes");

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
    buf.insert(buf.end(), p, p + sizeof(v));
}

void WriteU32At(std::vector<uint8_t>& buf, size_t offset, uint32_t v) {
    std::memcpy(buf.data() + offset, &v, sizeof(v));
}

uint32_t AppendString(std::vector<uint8_t>& buf, const std::string& s) {
    uint32_t off = static_cast<uint32_t>(buf.size());
    buf.insert(buf.end(), s.begin(), s.end());
    buf.push_back('\0');
    return off;
}

void AlignBuffer4(std::vector<uint8_t>& buf) {
    while ((buf.size() & 3u) != 0u) buf.push_back(0);
}

} // namespace

MappedPropArena::~MappedPropArena() {
    if (mapping_ != nullptr && mapping_ != MAP_FAILED) {
        ::munmap(mapping_, area_size_);
    }
    mapping_ = nullptr;
    header_ = nullptr;
    if (mem_fd_ >= 0) {
        ::close(mem_fd_);
        mem_fd_ = -1;
    }
}

bool MappedPropArena::Initialize(const std::string& context_name,
                                 const std::string& file_path,
                                 size_t area_size) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (area_size < kPropAreaHeaderSize + sizeof(PropBt)) return false;

    area_size_ = AlignUp(area_size, kPageSize16K);
    context_name_ = context_name;
    file_path_ = file_path;
    read_only_ = false;

    int fd = -1;
    if (!file_path.empty()) {
        std::string parent = file_path.substr(0, file_path.find_last_of('/'));
        if (!parent.empty()) EnsureDirectoriesRecursive(parent);
        fd = ::open(file_path.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
    } else {
        fd = CreateMemfd(("haseeb_prop_" + context_name).c_str());
    }
    if (fd < 0) return false;

    if (::ftruncate(fd, static_cast<off_t>(area_size_)) != 0) {
        ::close(fd);
        return false;
    }

    void* map = ::mmap(nullptr, area_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        ::close(fd);
        return false;
    }

    std::memset(map, 0, area_size_);
    mem_fd_ = fd;
    mapping_ = static_cast<uint8_t*>(map);
    header_ = reinterpret_cast<PropAreaHeader*>(mapping_);

    header_->magic = kPropAreaMagic;
    header_->version = kPropAreaVersion;
    header_->serial.store(0u, std::memory_order_relaxed);
    // Reserve root PropBt node at data_[0]
    size_t root_sz = AlignUp(sizeof(PropBt) + 1u, 4u);
    header_->bytes_used.store(static_cast<uint32_t>(root_sz), std::memory_order_release);
    return true;
}

bool MappedPropArena::AttachExisting(const std::string& file_path, bool read_only) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    int flags = (read_only ? O_RDONLY : O_RDWR) | O_CLOEXEC;
    int fd = ::open(file_path.c_str(), flags);
    if (fd < 0) return false;

    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_size < static_cast<off_t>(kPropAreaHeaderSize)) {
        ::close(fd);
        return false;
    }

    size_t sz = static_cast<size_t>(st.st_size);
    int prot = read_only ? PROT_READ : (PROT_READ | PROT_WRITE);
    void* map = ::mmap(nullptr, sz, prot, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        ::close(fd);
        return false;
    }

    auto* hdr = reinterpret_cast<PropAreaHeader*>(map);
    if (hdr->magic != kPropAreaMagic || hdr->version != kPropAreaVersion) {
        ::munmap(map, sz);
        ::close(fd);
        return false;
    }

    mem_fd_ = fd;
    mapping_ = static_cast<uint8_t*>(map);
    header_ = hdr;
    area_size_ = sz;
    file_path_ = file_path;
    read_only_ = read_only;
    return true;
}

void* MappedPropArena::AllocData(size_t bytes) {
    size_t aligned = AlignUp(bytes, 4u);
    uint32_t used = header_->bytes_used.load(std::memory_order_relaxed);
    size_t data_cap = area_size_ - kPropAreaHeaderSize;
    if (static_cast<size_t>(used) + aligned > data_cap) {
        return nullptr;
    }
    void* ptr = header_->data + used;
    std::memset(ptr, 0, aligned);
    header_->bytes_used.store(used + static_cast<uint32_t>(aligned), std::memory_order_release);
    return ptr;
}

uint32_t MappedPropArena::OffsetOf(const void* ptr) const {
    const uint8_t* p = static_cast<const uint8_t*>(ptr);
    return static_cast<uint32_t>(p - header_->data);
}

const void* MappedPropArena::PtrAt(uint32_t offset) const {
    if (header_ == nullptr) return nullptr;
    size_t data_cap = area_size_ - kPropAreaHeaderSize;
    if (offset >= data_cap) return nullptr;
    return header_->data + offset;
}

void* MappedPropArena::MutablePtrAt(uint32_t offset) {
    if (header_ == nullptr || read_only_) return nullptr;
    size_t data_cap = area_size_ - kPropAreaHeaderSize;
    if (offset >= data_cap) return nullptr;
    return header_->data + offset;
}

const PropBt* MappedPropArena::FindChildConst(const PropBt* root, const char* seg, size_t seg_len) const {
    if (!root) return nullptr;
    uint32_t cur_off = root->children.load(std::memory_order_acquire);
    while (cur_off != 0u) {
        const auto* node = static_cast<const PropBt*>(PtrAt(cur_off));
        if (!node) return nullptr;
        int cmp = ComparePropSegment(seg, seg_len, node->name, node->namelen);
        if (cmp == 0) return node;
        cur_off = (cmp < 0)
            ? node->left.load(std::memory_order_acquire)
            : node->right.load(std::memory_order_acquire);
    }
    return nullptr;
}

PropBt* MappedPropArena::FindOrInsertChild(PropBt* root, const char* seg, size_t seg_len, bool create) {
    if (!root) return nullptr;
    std::atomic<uint32_t>* link = &root->children;
    uint32_t cur_off = link->load(std::memory_order_acquire);

    while (cur_off != 0u) {
        auto* node = static_cast<PropBt*>(MutablePtrAt(cur_off));
        if (!node) return nullptr;
        int cmp = ComparePropSegment(seg, seg_len, node->name, node->namelen);
        if (cmp == 0) return node;
        link = (cmp < 0) ? &node->left : &node->right;
        cur_off = link->load(std::memory_order_acquire);
    }

    if (!create) return nullptr;
    auto* created = static_cast<PropBt*>(AllocData(sizeof(PropBt) + seg_len + 1u));
    if (!created) return nullptr;
    created->namelen = static_cast<uint32_t>(seg_len);
    std::memcpy(created->name, seg, seg_len);
    created->name[seg_len] = '\0';

    uint32_t new_off = OffsetOf(created);
    link->store(new_off, std::memory_order_release);
    return created;
}

const PropBt* MappedPropArena::FindNodeConst(const std::string& name) const {
    if (!header_ || name.empty() || name.size() >= kPropNameMax) return nullptr;
    const auto* cur = reinterpret_cast<const PropBt*>(header_->data);
    size_t pos = 0;
    while (pos <= name.size()) {
        size_t dot = name.find('.', pos);
        size_t len = (dot == std::string::npos) ? (name.size() - pos) : (dot - pos);
        cur = FindChildConst(cur, name.data() + pos, len);
        if (!cur) return nullptr;
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    return cur;
}

PropBt* MappedPropArena::FindOrCreateNode(const std::string& name, bool create) {
    if (!header_ || read_only_ || name.empty() || name.size() >= kPropNameMax) return nullptr;
    auto* cur = reinterpret_cast<PropBt*>(header_->data);
    size_t pos = 0;
    while (pos <= name.size()) {
        size_t dot = name.find('.', pos);
        size_t len = (dot == std::string::npos) ? (name.size() - pos) : (dot - pos);
        cur = FindOrInsertChild(cur, name.data() + pos, len, create);
        if (!cur) return nullptr;
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    return cur;
}

bool MappedPropArena::Set(const std::string& name, const std::string& value) {
    if (read_only_ || !header_ || name.empty() || name.size() >= kPropNameMax) return false;
    std::lock_guard<std::mutex> lock(write_mutex_);

    PropBt* bt = FindOrCreateNode(name, true);
    if (!bt) return false;

    uint32_t prop_off = bt->prop.load(std::memory_order_acquire);
    const bool is_long = value.size() >= kPropValueMax;
    const size_t val_len = value.size();

    if (prop_off == 0u) {
        auto* info = static_cast<PropInfo*>(AllocData(sizeof(PropInfo) + name.size() + 1u));
        if (!info) return false;
        std::memcpy(info->name, name.data(), name.size());
        info->name[name.size()] = '\0';

        if (!is_long) {
            std::memcpy(info->value, value.data(), val_len);
            info->value[val_len] = '\0';
            uint32_t s = MakeSerial(2u, static_cast<uint8_t>(val_len), false);
            info->serial.store(s, std::memory_order_release);
        } else {
            void* long_buf = AllocData(val_len + 1u);
            if (!long_buf) return false;
            std::memcpy(long_buf, value.data(), val_len);
            static_cast<char*>(long_buf)[val_len] = '\0';

            const char* err_msg = "Must use __system_property_read_callback";
            std::memcpy(info->long_property.error_message, err_msg,
                        std::min(std::strlen(err_msg) + 1, size_t(kLongLegacyErrorLen)));
            info->long_property.offset =
                static_cast<uint32_t>(static_cast<const uint8_t*>(long_buf) -
                                      reinterpret_cast<const uint8_t*>(info));
            uint32_t s = MakeSerial(2u, 0u, true);
            info->serial.store(s, std::memory_order_release);
        }

        bt->prop.store(OffsetOf(info), std::memory_order_release);
    } else {
        auto* info = static_cast<PropInfo*>(MutablePtrAt(prop_off));
        if (!info) return false;

        uint32_t cur_serial = info->serial.load(std::memory_order_relaxed);
        info->serial.store(cur_serial | kDirtyFlag, std::memory_order_release);

        uint32_t next_seq = ((cur_serial & 0x0000FFFEu) + 2u) & 0x0000FFFEu;
        if (!is_long) {
            std::memset(info->value, 0, kPropValueMax);
            std::memcpy(info->value, value.data(), val_len);
            info->value[val_len] = '\0';
            uint32_t new_serial = MakeSerial(next_seq, static_cast<uint8_t>(val_len), false);
            info->serial.store(new_serial, std::memory_order_release);
        } else {
            void* long_buf = AllocData(val_len + 1u);
            if (!long_buf) {
                info->serial.store(cur_serial & ~kDirtyFlag, std::memory_order_release);
                return false;
            }
            std::memcpy(long_buf, value.data(), val_len);
            static_cast<char*>(long_buf)[val_len] = '\0';
            const char* err_msg = "Must use __system_property_read_callback";
            std::memcpy(info->long_property.error_message, err_msg,
                        std::min(std::strlen(err_msg) + 1, size_t(kLongLegacyErrorLen)));
            info->long_property.offset =
                static_cast<uint32_t>(static_cast<const uint8_t*>(long_buf) -
                                      reinterpret_cast<const uint8_t*>(info));
            uint32_t new_serial = MakeSerial(next_seq, 0u, true);
            info->serial.store(new_serial, std::memory_order_release);
        }
        FutexWakeAll(&info->serial);
    }

    header_->serial.fetch_add(1u, std::memory_order_release);
    FutexWakeAll(&header_->serial);
    return true;
}

bool MappedPropArena::ReadPropInfoValue(const PropInfo* info, std::string& out_value) const {
    if (!info) return false;
    for (int tries = 0; tries < 64; ++tries) {
        uint32_t s1 = info->serial.load(std::memory_order_acquire);
        if ((s1 & kDirtyFlag) != 0u) {
            continue;
        }
        std::string tmp;
        if (SerialIsLong(s1)) {
            const uint8_t* base = reinterpret_cast<const uint8_t*>(info);
            const uint8_t* end = mapping_ + area_size_;
            const uint8_t* target = base + info->long_property.offset;
            if (target < mapping_ + kPropAreaHeaderSize || target >= end) {
                return false;
            }
            size_t max_len = static_cast<size_t>(end - target);
            const char* cstr = reinterpret_cast<const char*>(target);
            size_t len = ::strnlen(cstr, max_len);
            tmp.assign(cstr, len);
        } else {
            uint8_t len = SerialValueLen(s1);
            if (len >= kPropValueMax) len = kPropValueMax - 1;
            tmp.assign(info->value, ::strnlen(info->value, len));
        }

        uint32_t s2 = info->serial.load(std::memory_order_acquire);
        if (s1 == s2) {
            out_value = std::move(tmp);
            return true;
        }
    }
    return false;
}

bool MappedPropArena::Get(const std::string& name, std::string& out_value) const {
    const PropBt* bt = FindNodeConst(name);
    if (!bt) return false;
    uint32_t prop_off = bt->prop.load(std::memory_order_acquire);
    if (prop_off == 0u) return false;
    const auto* info = static_cast<const PropInfo*>(PtrAt(prop_off));
    return ReadPropInfoValue(info, out_value);
}

bool MappedPropArena::Contains(const std::string& name) const {
    const PropBt* bt = FindNodeConst(name);
    return bt != nullptr && bt->prop.load(std::memory_order_acquire) != 0u;
}

void MappedPropArena::TraverseBt(
    uint32_t bt_offset,
    const std::function<void(const std::string&, const std::string&)>& cb
) const {
    const auto* bt = static_cast<const PropBt*>(PtrAt(bt_offset));
    if (!bt) return;

    uint32_t left = bt->left.load(std::memory_order_acquire);
    if (left != 0u) TraverseBt(left, cb);

    uint32_t prop_off = bt->prop.load(std::memory_order_acquire);
    if (prop_off != 0u) {
        const auto* info = static_cast<const PropInfo*>(PtrAt(prop_off));
        std::string val;
        if (info && ReadPropInfoValue(info, val)) {
            cb(info->name, val);
        }
    }

    uint32_t children = bt->children.load(std::memory_order_acquire);
    if (children != 0u) TraverseBt(children, cb);

    uint32_t right = bt->right.load(std::memory_order_acquire);
    if (right != 0u) TraverseBt(right, cb);
}

void MappedPropArena::ForEach(
    const std::function<void(const std::string&, const std::string&)>& cb
) const {
    if (!header_) return;
    const auto* root = reinterpret_cast<const PropBt*>(header_->data);
    uint32_t first_child = root->children.load(std::memory_order_acquire);
    if (first_child != 0u) {
        TraverseBt(first_child, cb);
    }
}

bool MappedPropArena::WaitForUpdate(const std::string& name,
                                    uint32_t old_serial,
                                    uint32_t timeout_ms) const {
    const PropBt* bt = FindNodeConst(name);
    if (!bt) return false;
    uint32_t prop_off = bt->prop.load(std::memory_order_acquire);
    if (prop_off == 0u) return false;
    auto* info = const_cast<PropInfo*>(static_cast<const PropInfo*>(PtrAt(prop_off)));
    if (!info) return false;

    uint32_t cur = info->serial.load(std::memory_order_acquire);
    if (cur != old_serial && (cur & kDirtyFlag) == 0u) return true;
    FutexWait(&info->serial, cur, timeout_ms);
    uint32_t after = info->serial.load(std::memory_order_acquire);
    return after != old_serial;
}

uint32_t MappedPropArena::GlobalSerial() const {
    if (!header_) return 0u;
    return header_->serial.load(std::memory_order_acquire);
}

size_t MappedPropArena::BytesUsed() const {
    if (!header_) return 0u;
    return header_->bytes_used.load(std::memory_order_acquire);
}

// ---------------- PropertyAreaManager ----------------

bool PropertyAreaManager::IsBlockedGpuOverride(const std::string& name) {
    // Hard rule: never misreport GPU/EGL/OpenGLES/QEMU hardware properties
    return name == "ro.hardware.egl" ||
           name == "ro.opengles.version" ||
           name == "ro.board.platform";
}

std::string PropertyAreaManager::SanitizeContextFilename(const std::string& context_name) {
    // Keep standard AOSP context strings cleanly mapped under /dev/__properties__/
    std::string out;
    out.reserve(context_name.size());
    for (char c : context_name) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == ':' || c == '_' || c == '-') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    return out.empty() ? "u:object_r:default_prop:s0" : out;
}

bool PropertyAreaManager::Initialize(const std::string& runtime_dir,
                                     const std::string& system_root_hint,
                                     size_t area_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    runtime_dir_ = runtime_dir;
    props_dir_ = runtime_dir_ + "/dev/__properties__";
    area_size_ = AlignUp(area_size, kPageSize16K);

    if (!EnsureDirectoriesRecursive(props_dir_)) {
        return false;
    }

    context_arenas_.clear();
    serial_arena_ = std::make_unique<MappedPropArena>();
    if (!serial_arena_->Initialize("properties_serial", props_dir_ + "/properties_serial", area_size_)) {
        return false;
    }

    // Default Android 10-16 split property contexts
    static const char* kDefaultPropertyContexts =
        "* u:object_r:default_prop:s0\n"
        "ro. u:object_r:default_prop:s0\n"
        "ro.build. u:object_r:build_prop:s0\n"
        "ro.product. u:object_r:build_prop:s0\n"
        "ro.system. u:object_r:system_prop:s0\n"
        "ro.vendor. u:object_r:vendor_default_prop:s0\n"
        "ro.boot. u:object_r:bootloader_boot_reason_prop:s0\n"
        "sys. u:object_r:system_prop:s0\n"
        "ctl. u:object_r:ctl_default_prop:s0\n"
        "persist. u:object_r:persist_debug_prop:s0\n"
        "persist.sys. u:object_r:system_prop:s0\n"
        "debug. u:object_r:debug_prop:s0\n"
        "ro.haseeb. u:object_r:exported_default_prop:s0\n";

    // Parse guest property_contexts if available, else install default rules
    bool loaded_contexts = false;
    if (!system_root_hint.empty()) {
        std::vector<std::string> candidates = {
            system_root_hint + "/etc/selinux/plat_property_contexts",
            system_root_hint + "/system/etc/selinux/plat_property_contexts",
        };
        for (const auto& path : candidates) {
            std::ifstream ifs(path);
            if (ifs.good()) {
                std::ostringstream ss;
                ss << ifs.rdbuf();
                if (!ss.str().empty()) {
                    context_rules_.clear();
                    std::istringstream lines(ss.str());
                    std::string line;
                    while (std::getline(lines, line)) {
                        line = Trim(line);
                        if (line.empty() || line[0] == '#') continue;
                        std::istringstream ls(line);
                        std::string prefix, ctx, match_kind;
                        if (ls >> prefix >> ctx) {
                            ls >> match_kind;
                            context_rules_.push_back({prefix, ctx, match_kind == "exact"});
                        }
                    }
                    loaded_contexts = !context_rules_.empty();
                    break;
                }
            }
        }
    }
    if (!loaded_contexts) {
        context_rules_.clear();
        std::istringstream lines(kDefaultPropertyContexts);
        std::string line;
        while (std::getline(lines, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == '#') continue;
            std::istringstream ls(line);
            std::string prefix, ctx, match_kind;
            if (ls >> prefix >> ctx) {
                ls >> match_kind;
                context_rules_.push_back({prefix, ctx, match_kind == "exact"});
            }
        }
    }

    // Pre-create arenas for all configured property contexts BEFORE guest reads anything
    GetOrCreateContextArenaLocked("u:object_r:default_prop:s0");
    GetOrCreateContextArenaLocked("u:object_r:build_prop:s0");
    GetOrCreateContextArenaLocked("u:object_r:system_prop:s0");
    GetOrCreateContextArenaLocked("u:object_r:vendor_default_prop:s0");
    GetOrCreateContextArenaLocked("u:object_r:exported_default_prop:s0");
    for (const auto& rule : context_rules_) {
        GetOrCreateContextArenaLocked(rule.context);
    }

    WritePropertyContextsFileLocked();
    WritePropertyInfoFileLocked();
    initialized_ = true;

    for (const auto& kv : overrides_) {
        if (IsBlockedGpuOverride(kv.first)) continue;
        std::string ctx = ResolveContextForProperty(kv.first);
        MappedPropArena* arena = GetOrCreateContextArenaLocked(ctx);
        if (arena) arena->Set(kv.first, kv.second);
        serial_arena_->Set(kv.first, kv.second);
    }

    return true;
}

void PropertyAreaManager::SetOverride(const std::string& name, const std::string& value) {
    if (IsBlockedGpuOverride(name) || name.empty()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    overrides_[name] = value;
    if (initialized_) {
        std::string ctx = ResolveContextForProperty(name);
        MappedPropArena* arena = GetOrCreateContextArenaLocked(ctx);
        if (arena) arena->Set(name, value);
        serial_arena_->Set(name, value);
    }
}

void PropertyAreaManager::ClearOverrides() {
    std::lock_guard<std::mutex> lock(mutex_);
    overrides_.clear();
}

bool PropertyAreaManager::LoadPropFile(const std::string& prop_file_path) {
    std::ifstream ifs(prop_file_path);
    if (!ifs.good()) return false;
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return LoadPropText(ss.str());
}

bool PropertyAreaManager::LoadPropText(const std::string& prop_text) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return false;

    std::istringstream iss(prop_text);
    std::string line;
    while (std::getline(iss, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;
        std::string key = Trim(line.substr(0, eq));
        std::string val = Trim(line.substr(eq + 1));
        if (key.empty() || IsBlockedGpuOverride(key)) continue;

        // Pre-registered overrides take precedence and cannot be overwritten by build.prop
        if (overrides_.find(key) != overrides_.end()) {
            continue;
        }

        std::string ctx = ResolveContextForProperty(key);
        MappedPropArena* arena = GetOrCreateContextArenaLocked(ctx);
        if (arena) arena->Set(key, val);
        serial_arena_->Set(key, val);
    }
    return true;
}

bool PropertyAreaManager::LoadPropertyContexts(const std::string& contexts_text) {
    std::lock_guard<std::mutex> lock(mutex_);
    context_rules_.clear();
    std::istringstream lines(contexts_text);
    std::string line;
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string prefix, ctx, match_kind;
        if (ls >> prefix >> ctx) {
            ls >> match_kind;
            context_rules_.push_back({prefix, ctx, match_kind == "exact"});
            if (initialized_) {
                GetOrCreateContextArenaLocked(ctx);
            }
        }
    }
    if (initialized_) {
        WritePropertyContextsFileLocked();
        WritePropertyInfoFileLocked();
    }
    return !context_rules_.empty();
}

std::string PropertyAreaManager::ResolveContextForProperty(const std::string& name) const {
    for (const auto& rule : context_rules_) {
        if (rule.exact && name == rule.prefix) {
            return rule.context;
        }
    }
    std::string best_ctx = "u:object_r:default_prop:s0";
    size_t best_len = 0;
    for (const auto& rule : context_rules_) {
        if (rule.exact) continue;
        if (rule.prefix == "*") {
            if (best_len == 0) best_ctx = rule.context;
            continue;
        }
        if (name.rfind(rule.prefix, 0) == 0 && rule.prefix.size() >= best_len) {
            best_len = rule.prefix.size();
            best_ctx = rule.context;
        }
    }
    return best_ctx;
}

MappedPropArena* PropertyAreaManager::GetOrCreateContextArenaLocked(const std::string& context_name) {
    auto it = context_arenas_.find(context_name);
    if (it != context_arenas_.end()) {
        return it->second.get();
    }
    auto arena = std::make_unique<MappedPropArena>();
    std::string path = props_dir_ + "/" + SanitizeContextFilename(context_name);
    if (!arena->Initialize(context_name, path, area_size_)) {
        return nullptr;
    }
    MappedPropArena* raw = arena.get();
    context_arenas_.emplace(context_name, std::move(arena));
    return raw;
}

bool PropertyAreaManager::SetProperty(const std::string& name,
                                      const std::string& value,
                                      bool force_override) {
    if (name.empty() || name.size() >= kPropNameMax || IsBlockedGpuOverride(name)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return false;

    if (!force_override && overrides_.find(name) != overrides_.end()) {
        // Override locked before guest reads anything
        return false;
    }
    if (force_override) {
        overrides_[name] = value;
    }

    std::string ctx = ResolveContextForProperty(name);
    MappedPropArena* arena = GetOrCreateContextArenaLocked(ctx);
    bool ok_ctx = arena ? arena->Set(name, value) : false;
    bool ok_ser = serial_arena_->Set(name, value);
    return ok_ctx && ok_ser;
}

bool PropertyAreaManager::GetProperty(const std::string& name, std::string& out_value) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) return false;

    std::string ctx = ResolveContextForProperty(name);
    auto it = context_arenas_.find(ctx);
    if (it != context_arenas_.end() && it->second->Get(name, out_value)) {
        return true;
    }
    return serial_arena_->Get(name, out_value);
}

std::vector<std::pair<std::string, std::string>> PropertyAreaManager::ListAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<std::string, std::string>> out;
    if (!initialized_ || !serial_arena_) return out;
    serial_arena_->ForEach([&](const std::string& k, const std::string& v) {
        out.emplace_back(k, v);
    });
    return out;
}

bool PropertyAreaManager::WaitForProperty(const std::string& name,
                                          const std::string& expected_or_empty,
                                          uint32_t timeout_ms) const {
    std::string current;
    if (GetProperty(name, current)) {
        if (expected_or_empty.empty() || current == expected_or_empty) {
            return true;
        }
    }
    if (!serial_arena_) return false;
    uint32_t old_serial = serial_arena_->GlobalSerial();
    return serial_arena_->WaitForUpdate(name, old_serial, timeout_ms);
}

const MappedPropArena* PropertyAreaManager::ArenaForContext(const std::string& ctx) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = context_arenas_.find(ctx);
    return (it != context_arenas_.end()) ? it->second.get() : nullptr;
}

bool PropertyAreaManager::WritePropertyContextsFileLocked() {
    std::string path = props_dir_ + "/property_contexts";
    std::ofstream ofs(path, std::ios::trunc);
    if (!ofs.good()) return false;
    for (const auto& rule : context_rules_) {
        ofs << rule.prefix << " " << rule.context;
        if (rule.exact) ofs << " exact";
        ofs << "\n";
    }
    return ofs.good();
}

bool PropertyAreaManager::WritePropertyInfoFileLocked() {
    // Serialize Bionic-compatible PropertyInfoArea binary blob into /dev/__properties__/property_info
    // matching AOSP libpropertyinfoserializer / libpropertyinfoparser ABI v1.
    std::vector<uint8_t> buf(sizeof(BinaryPropertyInfoHeader), 0);

    std::vector<std::string> unique_contexts;
    for (const auto& rule : context_rules_) {
        if (!rule.context.empty() &&
            std::find(unique_contexts.begin(), unique_contexts.end(), rule.context) == unique_contexts.end()) {
            unique_contexts.push_back(rule.context);
        }
    }
    if (unique_contexts.empty()) {
        unique_contexts.push_back("u:object_r:default_prop:s0");
    }
    std::sort(unique_contexts.begin(), unique_contexts.end());
    auto find_ctx_idx = [&](const std::string& c) -> uint32_t {
        auto it = std::lower_bound(unique_contexts.begin(), unique_contexts.end(), c);
        if (it != unique_contexts.end() && *it == c) {
            return static_cast<uint32_t>(it - unique_contexts.begin());
        }
        return ~0u;
    };

    AlignBuffer4(buf);
    uint32_t contexts_offset = static_cast<uint32_t>(buf.size());
    AppendU32(buf, static_cast<uint32_t>(unique_contexts.size()));
    std::vector<uint32_t> ctx_str_offsets(unique_contexts.size(), 0);
    size_t ctx_table_pos = buf.size();
    for (size_t i = 0; i < unique_contexts.size(); ++i) AppendU32(buf, 0);
    for (size_t i = 0; i < unique_contexts.size(); ++i) {
        ctx_str_offsets[i] = AppendString(buf, unique_contexts[i]);
    }
    for (size_t i = 0; i < unique_contexts.size(); ++i) {
        WriteU32At(buf, ctx_table_pos + i * 4u, ctx_str_offsets[i]);
    }

    AlignBuffer4(buf);
    uint32_t types_offset = static_cast<uint32_t>(buf.size());
    AppendU32(buf, 1u);
    uint32_t type_table_pos = static_cast<uint32_t>(buf.size());
    AppendU32(buf, 0u);
    uint32_t string_type_off = AppendString(buf, "string");
    WriteU32At(buf, type_table_pos, string_type_off);

    // Build AOSP hierarchical dot-separated Trie from context_rules_
    struct TrieBuildNode {
        std::string name;
        uint32_t context_index = ~0u;
        uint32_t type_index = ~0u;
        std::vector<std::unique_ptr<TrieBuildNode>> children;
        struct LeafRule {
            std::string name;
            uint32_t context_index;
            uint32_t type_index;
        };
        std::vector<LeafRule> prefixes;
        std::vector<LeafRule> exact_matches;

        TrieBuildNode* GetOrAddChild(const std::string& seg) {
            for (const auto& c : children) {
                if (c->name == seg) return c.get();
            }
            auto node = std::make_unique<TrieBuildNode>();
            node->name = seg;
            TrieBuildNode* raw = node.get();
            children.push_back(std::move(node));
            return raw;
        }
    };

    auto split_dots = [](const std::string& s) -> std::vector<std::string> {
        std::vector<std::string> parts;
        size_t pos = 0;
        while (pos <= s.size()) {
            size_t dot = s.find('.', pos);
            if (dot == std::string::npos) {
                if (pos < s.size()) parts.push_back(s.substr(pos));
                break;
            }
            if (dot > pos) parts.push_back(s.substr(pos, dot - pos));
            pos = dot + 1;
        }
        return parts;
    };

    TrieBuildNode root;
    root.name = "";
    for (const auto& rule : context_rules_) {
        const uint32_t ctx_idx = find_ctx_idx(rule.context);
        if (ctx_idx == ~0u) continue;
        const uint32_t type_idx = 0u;

        if (rule.prefix == "*") {
            root.context_index = ctx_idx;
            root.type_index = type_idx;
            continue;
        }
        if (!rule.exact && !rule.prefix.empty() && rule.prefix.back() == '.') {
            std::string stem = rule.prefix.substr(0, rule.prefix.size() - 1u);
            auto segs = split_dots(stem);
            TrieBuildNode* cur = &root;
            for (const auto& seg : segs) {
                cur = cur->GetOrAddChild(seg);
            }
            cur->context_index = ctx_idx;
            cur->type_index = type_idx;
        } else {
            auto segs = split_dots(rule.prefix);
            if (segs.empty()) continue;
            TrieBuildNode* cur = &root;
            for (size_t i = 0; i + 1u < segs.size(); ++i) {
                cur = cur->GetOrAddChild(segs[i]);
            }
            if (rule.exact) {
                cur->exact_matches.push_back({segs.back(), ctx_idx, type_idx});
            } else {
                cur->prefixes.push_back({segs.back(), ctx_idx, type_idx});
            }
        }
    }

    auto write_property_entry = [&](const std::string& name, uint32_t ctx_idx, uint32_t type_idx) -> uint32_t {
        uint32_t name_off = AppendString(buf, name);
        AlignBuffer4(buf);
        uint32_t off = static_cast<uint32_t>(buf.size());
        BinaryPropertyEntry pe{};
        pe.name_offset = name_off;
        pe.namelen = static_cast<uint32_t>(name.size());
        pe.context_index = ctx_idx;
        pe.type_index = type_idx;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&pe);
        buf.insert(buf.end(), p, p + sizeof(pe));
        return off;
    };

    auto serialize_node = [&](auto& self, TrieBuildNode& node) -> uint32_t {
        // AOSP binary-searches child_nodes lexicographically and exact_matches lexicographically;
        // prefixes are scanned longest-namelen first.
        std::sort(node.children.begin(), node.children.end(),
                  [](const auto& a, const auto& b) { return a->name < b->name; });
        std::sort(node.prefixes.begin(), node.prefixes.end(),
                  [](const auto& a, const auto& b) {
                      if (a.name.size() != b.name.size()) return a.name.size() > b.name.size();
                      return a.name < b.name;
                  });
        std::sort(node.exact_matches.begin(), node.exact_matches.end(),
                  [](const auto& a, const auto& b) { return a.name < b.name; });

        std::vector<uint32_t> child_offsets;
        child_offsets.reserve(node.children.size());
        for (auto& c : node.children) {
            child_offsets.push_back(self(self, *c));
        }

        std::vector<uint32_t> prefix_offsets;
        prefix_offsets.reserve(node.prefixes.size());
        for (const auto& pe : node.prefixes) {
            prefix_offsets.push_back(write_property_entry(pe.name, pe.context_index, pe.type_index));
        }

        std::vector<uint32_t> exact_offsets;
        exact_offsets.reserve(node.exact_matches.size());
        for (const auto& ee : node.exact_matches) {
            exact_offsets.push_back(write_property_entry(ee.name, ee.context_index, ee.type_index));
        }

        uint32_t node_prop_entry_off = write_property_entry(node.name, node.context_index, node.type_index);

        uint32_t child_nodes_off = 0u;
        if (!child_offsets.empty()) {
            AlignBuffer4(buf);
            child_nodes_off = static_cast<uint32_t>(buf.size());
            for (uint32_t o : child_offsets) AppendU32(buf, o);
        }

        uint32_t prefix_entries_off = 0u;
        if (!prefix_offsets.empty()) {
            AlignBuffer4(buf);
            prefix_entries_off = static_cast<uint32_t>(buf.size());
            for (uint32_t o : prefix_offsets) AppendU32(buf, o);
        }

        uint32_t exact_entries_off = 0u;
        if (!exact_offsets.empty()) {
            AlignBuffer4(buf);
            exact_entries_off = static_cast<uint32_t>(buf.size());
            for (uint32_t o : exact_offsets) AppendU32(buf, o);
        }

        AlignBuffer4(buf);
        uint32_t node_off = static_cast<uint32_t>(buf.size());
        BinaryTrieNodeInternal tn{};
        tn.property_entry = node_prop_entry_off;
        tn.num_child_nodes = static_cast<uint32_t>(child_offsets.size());
        tn.child_nodes = child_nodes_off;
        tn.num_prefixes = static_cast<uint32_t>(prefix_offsets.size());
        tn.prefix_entries = prefix_entries_off;
        tn.num_exact_matches = static_cast<uint32_t>(exact_offsets.size());
        tn.exact_match_entries = exact_entries_off;
        const uint8_t* np = reinterpret_cast<const uint8_t*>(&tn);
        buf.insert(buf.end(), np, np + sizeof(tn));
        return node_off;
    };

    uint32_t root_offset = serialize_node(serialize_node, root);

    BinaryPropertyInfoHeader hdr{};
    hdr.current_version = 1u;
    hdr.minimum_supported_version = 1u;
    hdr.size = static_cast<uint32_t>(buf.size());
    hdr.contexts_offset = contexts_offset;
    hdr.types_offset = types_offset;
    hdr.root_offset = root_offset;
    std::memcpy(buf.data(), &hdr, sizeof(hdr));

    std::string path = props_dir_ + "/property_info";
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.good()) return false;
    ofs.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    return ofs.good();
}

} // namespace haseeb::prop
