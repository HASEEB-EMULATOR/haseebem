#pragma once

#include "haseeb/ext4_reader.hpp"

#include <cstdint>
#include <elf.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace haseeb::loader {

struct LoadedElfImage {
    std::string guest_path;
    uintptr_t map_base = 0;
    size_t map_size = 0;
    uintptr_t load_bias = 0;
    uintptr_t entry_point = 0;
    uintptr_t phdr_addr = 0;
    uint16_t phdr_ent_size = 0;
    uint16_t phdr_count = 0;
    uintptr_t dynamic_addr = 0;
    std::string interp_path;
    std::vector<std::string> needed_libs;
    size_t relr_applied_count = 0;
    size_t rela_applied_count = 0;
    size_t host_page_size = 4096;
    size_t guest_page_size = 4096;
    std::unordered_map<std::string, uintptr_t> exported_symbols;

    ~LoadedElfImage();
    LoadedElfImage() = default;
    LoadedElfImage(const LoadedElfImage&) = delete;
    LoadedElfImage& operator=(const LoadedElfImage&) = delete;

    uintptr_t FindSymbol(const std::string& name) const;
};

struct GuestAuxvBuilder {
    static std::vector<uint64_t> BuildAuxv(
        const LoadedElfImage& main_exe,
        const LoadedElfImage* linker_img,
        uintptr_t execfn_addr,
        uintptr_t random_addr,
        size_t page_size
    );
};

// Virtualized /proc/self/exe and linker64 path resolver backed by Ext4Reader(s)
class GuestVfsResolver {
public:
    void AttachSystemExt4(const Ext4Reader* system_ext4, bool has_system_prefix);
    void AttachVendorExt4(const Ext4Reader* vendor_ext4);
    void SetHostFallbackRoot(const std::string& host_root);

    bool ReadGuestFile(const std::string& guest_path, std::vector<uint8_t>& out_bytes) const;
    bool Exists(const std::string& guest_path) const;

    // Resolves Android linker64 path across API 29-36 (/apex/com.android.runtime, /apex/com.android.art, /system/bin/linker64)
    std::string ResolveLinker64Path(int guest_api_level) const;

    // Builds standard linker64 search environment variables for guest processes
    std::vector<std::string> BuildLinker64Env(int guest_api_level,
                                              const std::string& runtime_dir) const;

    // Tracks active guest executable for /proc/self/exe readlink + memfd backing
    bool RegisterSelfExe(const std::string& guest_exe_path,
                         const std::vector<uint8_t>& exe_bytes);
    bool ReadLink(const std::string& guest_path, std::string& out_target) const;
    const std::string& SelfExeGuestPath() const { return self_exe_guest_path_; }
    int SelfExeMemFd() const { return self_exe_memfd_; }

    ~GuestVfsResolver();

private:
    const Ext4Reader* system_ext4_ = nullptr;
    bool system_has_prefix_ = false;
    const Ext4Reader* vendor_ext4_ = nullptr;
    std::string host_fallback_root_;
    std::string self_exe_guest_path_;
    int self_exe_memfd_ = -1;
};

class Elf64Loader {
public:
    explicit Elf64Loader(size_t forced_page_size = 0);

    // Loads an ELF64 executable or shared library from raw bytes into host memory.
    // Handles both 4 KiB and 16 KiB host/guest page sizes and applies RELR + RELA relocations.
    std::unique_ptr<LoadedElfImage> LoadFromBytes(
        const std::string& guest_path,
        const std::vector<uint8_t>& elf_bytes,
        const std::vector<const LoadedElfImage*>& dependency_images = {},
        bool enforce_native_machine = false
    );

    // Loads a guest executable + its PT_INTERP (e.g. linker64) via GuestVfsResolver
    bool LoadWithInterpreter(
        const std::string& guest_exe_path,
        GuestVfsResolver& vfs,
        int guest_api_level,
        std::unique_ptr<LoadedElfImage>& out_exe,
        std::unique_ptr<LoadedElfImage>& out_linker,
        std::string& out_error
    );

    size_t EffectivePageSize() const { return effective_page_size_; }

private:
    bool ApplyRelr(LoadedElfImage& img, uintptr_t relr_addr, size_t relr_bytes);
    bool ApplyRela(LoadedElfImage& img,
                   uintptr_t rela_addr,
                   size_t rela_bytes,
                   const Elf64_Sym* symtab,
                   size_t sym_count,
                   const char* strtab,
                   size_t strtab_size,
                   const std::vector<const LoadedElfImage*>& deps);
    void IndexDynamicSymbols(LoadedElfImage& img,
                             const Elf64_Sym* symtab,
                             size_t sym_count,
                             const char* strtab,
                             size_t strtab_size);

    size_t host_page_size_ = 4096;
    size_t effective_page_size_ = 16384;
};

} // namespace haseeb::loader
