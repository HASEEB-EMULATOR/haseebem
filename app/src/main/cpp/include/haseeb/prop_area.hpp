#pragma once

#include "haseeb/prop_layout.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace haseeb::prop {

struct PropertyContextEntry {
    std::string prefix;
    std::string context;
    bool exact = false;
};

struct PropertyInfoEntry {
    std::string name;
    std::string context;
    std::string type;
    bool exact = false;
};

class MappedPropArena {
public:
    MappedPropArena() = default;
    ~MappedPropArena();

    MappedPropArena(const MappedPropArena&) = delete;
    MappedPropArena& operator=(const MappedPropArena&) = delete;

    // Creates or opens a 1 MiB shared memory arena backed by memfd and optionally linked at file_path.
    bool Initialize(const std::string& context_name,
                    const std::string& file_path,
                    size_t area_size = kPropAreaDefaultSize);

    // Attaches read-only/read-write to an existing mapped property file (used by guest readers/tests).
    bool AttachExisting(const std::string& file_path, bool read_only = true);

    bool Set(const std::string& name, const std::string& value);
    bool Get(const std::string& name, std::string& out_value) const;
    bool Contains(const std::string& name) const;
    void ForEach(const std::function<void(const std::string&, const std::string&)>& cb) const;
    bool WaitForUpdate(const std::string& name, uint32_t old_serial, uint32_t timeout_ms) const;

    uint32_t GlobalSerial() const;
    size_t BytesUsed() const;
    size_t AreaSize() const { return area_size_; }
    int MemFd() const { return mem_fd_; }
    const std::string& ContextName() const { return context_name_; }
    const PropAreaHeader* Header() const { return header_; }

private:
    PropBt* FindOrCreateNode(const std::string& name, bool create);
    const PropBt* FindNodeConst(const std::string& name) const;
    const PropBt* FindChildConst(const PropBt* root, const char* seg, size_t seg_len) const;
    PropBt* FindOrInsertChild(PropBt* root, const char* seg, size_t seg_len, bool create);
    void* AllocData(size_t bytes);
    uint32_t OffsetOf(const void* ptr) const;
    const void* PtrAt(uint32_t offset) const;
    void* MutablePtrAt(uint32_t offset);
    bool ReadPropInfoValue(const PropInfo* info, std::string& out_value) const;
    void TraverseBt(uint32_t bt_offset,
                    const std::function<void(const std::string&, const std::string&)>& cb) const;

    mutable std::mutex write_mutex_;
    std::string context_name_;
    std::string file_path_;
    int mem_fd_ = -1;
    uint8_t* mapping_ = nullptr;
    PropAreaHeader* header_ = nullptr;
    size_t area_size_ = 0;
    bool read_only_ = false;
};

class PropertyAreaManager {
public:
    PropertyAreaManager() = default;
    ~PropertyAreaManager() = default;

    // Initializes <runtime_dir>/dev/__properties__/ with properties_serial, property_contexts,
    // property_info, and per-context 1 MiB arenas.
    bool Initialize(const std::string& runtime_dir,
                    const std::string& system_root_hint = "",
                    size_t area_size = kPropAreaDefaultSize);

    // Registers an immutable override applied before guest boot/prop loads.
    void SetOverride(const std::string& name, const std::string& value);
    void ClearOverrides();

    // Loads a build.prop / default.prop file; pre-registered overrides take precedence.
    bool LoadPropFile(const std::string& prop_file_path);

    // Parses raw build.prop text (e.g. read mount-free from Ext4Reader); overrides take precedence.
    bool LoadPropText(const std::string& prop_text);

    // Parses Android property_contexts lines and writes serialized property_contexts + property_info.
    bool LoadPropertyContexts(const std::string& contexts_text);

    bool SetProperty(const std::string& name, const std::string& value, bool force_override = false);
    bool GetProperty(const std::string& name, std::string& out_value) const;
    std::vector<std::pair<std::string, std::string>> ListAll() const;
    std::string ResolveContextForProperty(const std::string& name) const;
    bool WaitForProperty(const std::string& name, const std::string& expected_or_empty, uint32_t timeout_ms) const;

    const std::string& PropertiesDir() const { return props_dir_; }
    const MappedPropArena* SerialArena() const { return serial_arena_.get(); }
    const MappedPropArena* ArenaForContext(const std::string& ctx) const;

    static std::string SanitizeContextFilename(const std::string& context_name);
    static bool IsBlockedGpuOverride(const std::string& name);

private:
    bool EnsureInitializedLocked();
    MappedPropArena* GetOrCreateContextArenaLocked(const std::string& context_name);
    bool WritePropertyContextsFileLocked();
    bool WritePropertyInfoFileLocked();

    mutable std::mutex mutex_;
    bool initialized_ = false;
    std::string runtime_dir_;
    std::string props_dir_;
    size_t area_size_ = kPropAreaDefaultSize;

    std::unique_ptr<MappedPropArena> serial_arena_;
    std::unordered_map<std::string, std::unique_ptr<MappedPropArena>> context_arenas_;
    std::vector<PropertyContextEntry> context_rules_;
    std::unordered_map<std::string, std::string> overrides_;
};

} // namespace haseeb::prop
