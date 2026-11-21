#include "haseeb/elf64_loader.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif
#ifndef DT_ANDROID_RELR
#define DT_ANDROID_RELR 0x6fffe000
#endif
#ifndef DT_ANDROID_RELRSZ
#define DT_ANDROID_RELRSZ 0x6fffe001
#endif
#ifndef DT_ANDROID_RELRENT
#define DT_ANDROID_RELRENT 0x6fffe003
#endif
#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE 0
#endif
#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif
#ifndef R_X86_64_NONE
#define R_X86_64_NONE 0
#endif
#ifndef R_X86_64_64
#define R_X86_64_64 1
#endif
#ifndef R_X86_64_GLOB_DAT
#define R_X86_64_GLOB_DAT 6
#endif
#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT 7
#endif
#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE 8
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace haseeb::loader {

namespace {

inline uintptr_t PageAlignDown(uintptr_t v, size_t page) {
    return v & ~(static_cast<uintptr_t>(page) - 1u);
}

inline uintptr_t PageAlignUp(uintptr_t v, size_t page) {
    return (v + page - 1u) & ~(static_cast<uintptr_t>(page) - 1u);
}

int ProtFromElfFlags(uint32_t p_flags) {
    int prot = 0;
    if ((p_flags & PF_R) != 0u) prot |= PROT_READ;
    if ((p_flags & PF_W) != 0u) prot |= PROT_WRITE;
    if ((p_flags & PF_X) != 0u) prot |= PROT_EXEC;
    return prot;
}

int CreateMemfd(const char* name) {
#if defined(__NR_memfd_create)
    int fd = static_cast<int>(::syscall(__NR_memfd_create, name, MFD_CLOEXEC));
    if (fd >= 0) return fd;
#endif
    return -1;
}

} // namespace

LoadedElfImage::~LoadedElfImage() {
    if (map_base != 0 && map_size > 0) {
        ::munmap(reinterpret_cast<void*>(map_base), map_size);
    }
    map_base = 0;
    map_size = 0;
}

uintptr_t LoadedElfImage::FindSymbol(const std::string& name) const {
    auto it = exported_symbols.find(name);
    return (it != exported_symbols.end()) ? it->second : 0;
}

std::vector<uint64_t> GuestAuxvBuilder::BuildAuxv(
    const LoadedElfImage& main_exe,
    const LoadedElfImage* linker_img,
    uintptr_t execfn_addr,
    uintptr_t random_addr,
    size_t page_size
) {
    std::vector<uint64_t> auxv;
    auto push = [&](uint64_t k, uint64_t v) {
        auxv.push_back(k);
        auxv.push_back(v);
    };
    push(AT_PHDR, static_cast<uint64_t>(main_exe.phdr_addr));
    push(AT_PHENT, static_cast<uint64_t>(main_exe.phdr_ent_size));
    push(AT_PHNUM, static_cast<uint64_t>(main_exe.phdr_count));
    push(AT_PAGESZ, static_cast<uint64_t>(page_size));
    push(AT_BASE, linker_img ? static_cast<uint64_t>(linker_img->load_bias) : 0ull);
    push(AT_FLAGS, 0ull);
    push(AT_ENTRY, static_cast<uint64_t>(main_exe.entry_point));
    push(AT_UID, 2000ull);
    push(AT_EUID, 2000ull);
    push(AT_GID, 2000ull);
    push(AT_EGID, 2000ull);
    push(AT_SECURE, 0ull);
    push(AT_RANDOM, static_cast<uint64_t>(random_addr));
    push(AT_EXECFN, static_cast<uint64_t>(execfn_addr));
    push(AT_NULL, 0ull);
    return auxv;
}

// ---------------- GuestVfsResolver ----------------

GuestVfsResolver::~GuestVfsResolver() {
    if (self_exe_memfd_ >= 0) {
        ::close(self_exe_memfd_);
        self_exe_memfd_ = -1;
    }
}

void GuestVfsResolver::AttachSystemExt4(const Ext4Reader* system_ext4, bool has_system_prefix) {
    system_ext4_ = system_ext4;
    system_has_prefix_ = has_system_prefix;
}

void GuestVfsResolver::AttachVendorExt4(const Ext4Reader* vendor_ext4) {
    vendor_ext4_ = vendor_ext4;
}

void GuestVfsResolver::SetHostFallbackRoot(const std::string& host_root) {
    host_fallback_root_ = host_root;
}

bool GuestVfsResolver::ReadGuestFile(const std::string& guest_path,
                                     std::vector<uint8_t>& out_bytes) const {
    if (guest_path == "/proc/self/exe" && self_exe_memfd_ >= 0) {
        off_t sz = ::lseek(self_exe_memfd_, 0, SEEK_END);
        if (sz > 0) {
            out_bytes.resize(static_cast<size_t>(sz));
            ::pread(self_exe_memfd_, out_bytes.data(), out_bytes.size(), 0);
            return true;
        }
    }

    if (vendor_ext4_ && vendor_ext4_->IsOpen() && guest_path.rfind("/vendor/", 0) == 0) {
        std::string rel = guest_path.substr(7); // strip "/vendor"
        if (vendor_ext4_->ReadFile(rel, out_bytes)) return true;
        if (vendor_ext4_->ReadFile(guest_path, out_bytes)) return true;
    }

    if (system_ext4_ && system_ext4_->IsOpen()) {
        if (system_has_prefix_) {
            if (system_ext4_->ReadFile(guest_path, out_bytes)) return true;
        } else if (guest_path.rfind("/system/", 0) == 0) {
            std::string rel = guest_path.substr(7); // strip "/system"
            if (system_ext4_->ReadFile(rel, out_bytes)) return true;
        }
        if (system_ext4_->ReadFile(guest_path, out_bytes)) return true;
    }

    if (!host_fallback_root_.empty()) {
        std::string full = host_fallback_root_ + guest_path;
        std::ifstream ifs(full, std::ios::binary | std::ios::ate);
        if (ifs.good()) {
            std::streamsize sz = ifs.tellg();
            ifs.seekg(0, std::ios::beg);
            out_bytes.resize(static_cast<size_t>(sz));
            if (ifs.read(reinterpret_cast<char*>(out_bytes.data()), sz)) return true;
        }
    }
    return false;
}

bool GuestVfsResolver::Exists(const std::string& guest_path) const {
    if (vendor_ext4_ && vendor_ext4_->IsOpen() && guest_path.rfind("/vendor/", 0) == 0) {
        if (vendor_ext4_->Exists(guest_path.substr(7)) || vendor_ext4_->Exists(guest_path)) {
            return true;
        }
    }
    if (system_ext4_ && system_ext4_->IsOpen()) {
        if (system_has_prefix_ && system_ext4_->Exists(guest_path)) return true;
        if (!system_has_prefix_ && guest_path.rfind("/system/", 0) == 0 &&
            system_ext4_->Exists(guest_path.substr(7))) {
            return true;
        }
        if (system_ext4_->Exists(guest_path)) return true;
    }
    if (!host_fallback_root_.empty()) {
        std::string full = host_fallback_root_ + guest_path;
        return ::access(full.c_str(), F_OK) == 0;
    }
    return false;
}

std::string GuestVfsResolver::ResolveLinker64Path(int guest_api_level) const {
    // Android 10 (API 29) uses /apex/com.android.runtime/bin/linker64 or /system/bin/linker64
    // Android 11+ (API 30-36) uses /apex/com.android.art/bin/linker64 or /system/bin/linker64
    std::vector<std::string> candidates;
    if (guest_api_level >= 30) {
        candidates.push_back("/apex/com.android.art/bin/linker64");
        candidates.push_back("/system/bin/linker64");
        candidates.push_back("/apex/com.android.runtime/bin/linker64");
    } else {
        candidates.push_back("/system/bin/linker64");
        candidates.push_back("/apex/com.android.runtime/bin/linker64");
    }
    for (const auto& c : candidates) {
        if (Exists(c)) return c;
    }
    return "/system/bin/linker64";
}

std::vector<std::string> GuestVfsResolver::BuildLinker64Env(int guest_api_level,
                                                            const std::string& runtime_dir) const {
    std::vector<std::string> env;
    env.emplace_back("ANDROID_ROOT=/system");
    env.emplace_back("ANDROID_DATA=/data");
    env.emplace_back("ANDROID_STORAGE=/storage");
    env.emplace_back("HASEEB_RUNTIME_DIR=" + runtime_dir);
    env.emplace_back("LD_LIBRARY_PATH=/system/lib64:/vendor/lib64:/system/lib64/vndk-sp:/apex/com.android.runtime/lib64");
    if (guest_api_level >= 30) {
        env.emplace_back("ANDROID_ART_ROOT=/apex/com.android.art");
        env.emplace_back("ANDROID_I18N_ROOT=/apex/com.android.i18n");
        env.emplace_back("ANDROID_TZDATA_ROOT=/apex/com.android.tzdata");
    } else {
        env.emplace_back("ANDROID_RUNTIME_ROOT=/apex/com.android.runtime");
        env.emplace_back("ANDROID_TZDATA_ROOT=/apex/com.android.tzdata");
    }
    return env;
}

bool GuestVfsResolver::RegisterSelfExe(const std::string& guest_exe_path,
                                       const std::vector<uint8_t>& exe_bytes) {
    self_exe_guest_path_ = guest_exe_path;
    if (self_exe_memfd_ >= 0) {
        ::close(self_exe_memfd_);
        self_exe_memfd_ = -1;
    }
    int fd = CreateMemfd("haseeb_self_exe");
    if (fd >= 0 && !exe_bytes.empty()) {
        size_t done = 0;
        while (done < exe_bytes.size()) {
            ssize_t n = ::write(fd, exe_bytes.data() + done, exe_bytes.size() - done);
            if (n <= 0) break;
            done += static_cast<size_t>(n);
        }
        ::lseek(fd, 0, SEEK_SET);
        self_exe_memfd_ = fd;
    }
    return true;
}

bool GuestVfsResolver::ReadLink(const std::string& guest_path, std::string& out_target) const {
    if (guest_path == "/proc/self/exe" && !self_exe_guest_path_.empty()) {
        out_target = self_exe_guest_path_;
        return true;
    }
    if (vendor_ext4_ && vendor_ext4_->IsOpen() && guest_path.rfind("/vendor/", 0) == 0) {
        if (vendor_ext4_->ReadSymlink(guest_path.substr(7), out_target) ||
            vendor_ext4_->ReadSymlink(guest_path, out_target)) {
            return true;
        }
    }
    if (system_ext4_ && system_ext4_->IsOpen()) {
        if (system_has_prefix_ && system_ext4_->ReadSymlink(guest_path, out_target)) return true;
        if (!system_has_prefix_ && guest_path.rfind("/system/", 0) == 0 &&
            system_ext4_->ReadSymlink(guest_path.substr(7), out_target)) {
            return true;
        }
        if (system_ext4_->ReadSymlink(guest_path, out_target)) return true;
    }
    return false;
}

// ---------------- Elf64Loader ----------------

Elf64Loader::Elf64Loader(size_t forced_page_size) {
    long sys_pg = ::sysconf(_SC_PAGESIZE);
    host_page_size_ = (sys_pg > 0) ? static_cast<size_t>(sys_pg) : 4096u;
    // Always align reservations to at least 16 KiB for Android 15+ 16 KiB page compatibility
    effective_page_size_ = (forced_page_size > 0)
        ? forced_page_size
        : std::max<size_t>(host_page_size_, 16384u);
}

std::unique_ptr<LoadedElfImage> Elf64Loader::LoadFromBytes(
    const std::string& guest_path,
    const std::vector<uint8_t>& elf_bytes,
    const std::vector<const LoadedElfImage*>& dependency_images,
    bool enforce_native_machine
) {
    if (elf_bytes.size() < sizeof(Elf64_Ehdr)) return nullptr;

    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(elf_bytes.data());
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return nullptr;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB) return nullptr;

    if (enforce_native_machine) {
#if defined(__aarch64__)
        if (ehdr->e_machine != EM_AARCH64) return nullptr;
#elif defined(__x86_64__)
        if (ehdr->e_machine != EM_X86_64) return nullptr;
#endif
    }

    if (ehdr->e_phoff + static_cast<size_t>(ehdr->e_phnum) * ehdr->e_phentsize > elf_bytes.size()) {
        return nullptr;
    }

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(elf_bytes.data() + ehdr->e_phoff);
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    size_t max_p_align = 4096u;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if (phdrs[i].p_vaddr < min_vaddr) min_vaddr = phdrs[i].p_vaddr;
        uintptr_t end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (end > max_vaddr) max_vaddr = end;
        if (phdrs[i].p_align > max_p_align && phdrs[i].p_align <= 65536u) {
            max_p_align = static_cast<size_t>(phdrs[i].p_align);
        }
    }
    if (min_vaddr == UINTPTR_MAX || max_vaddr <= min_vaddr) return nullptr;

    size_t alloc_page = std::max(effective_page_size_, max_p_align);
    uintptr_t aligned_min = PageAlignDown(min_vaddr, alloc_page);
    uintptr_t aligned_max = PageAlignUp(max_vaddr, alloc_page);
    size_t span = static_cast<size_t>(aligned_max - aligned_min);

    // Reserve anonymous RWX-capable span aligned to 16 KiB; copy PT_LOAD bytes cleanly
    // so 4 KiB-aligned guest ELFs work safely even on 16 KiB page-size hosts.
    void* reservation = ::mmap(nullptr, span, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) return nullptr;

    auto img = std::make_unique<LoadedElfImage>();
    img->guest_path = guest_path;
    img->map_base = reinterpret_cast<uintptr_t>(reservation);
    img->map_size = span;
    img->load_bias = img->map_base - aligned_min;
    img->entry_point = img->load_bias + ehdr->e_entry;
    img->phdr_ent_size = ehdr->e_phentsize;
    img->phdr_count = ehdr->e_phnum;
    img->host_page_size = host_page_size_;
    img->guest_page_size = max_p_align;

    // Copy PT_LOAD segments
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type == PT_LOAD) {
            if (ph.p_offset + ph.p_filesz > elf_bytes.size()) return nullptr;
            uintptr_t seg_dst = img->load_bias + ph.p_vaddr;
            if (ph.p_filesz > 0) {
                std::memcpy(reinterpret_cast<void*>(seg_dst),
                            elf_bytes.data() + ph.p_offset,
                            static_cast<size_t>(ph.p_filesz));
            }
            if (ph.p_memsz > ph.p_filesz) {
                std::memset(reinterpret_cast<void*>(seg_dst + ph.p_filesz),
                            0,
                            static_cast<size_t>(ph.p_memsz - ph.p_filesz));
            }
            if (ph.p_offset <= ehdr->e_phoff &&
                ehdr->e_phoff < ph.p_offset + ph.p_filesz) {
                img->phdr_addr = img->load_bias + ph.p_vaddr + (ehdr->e_phoff - ph.p_offset);
            }
        } else if (ph.p_type == PT_INTERP && ph.p_filesz > 0 &&
                   ph.p_offset + ph.p_filesz <= elf_bytes.size()) {
            const char* interp = reinterpret_cast<const char*>(elf_bytes.data() + ph.p_offset);
            size_t len = ::strnlen(interp, static_cast<size_t>(ph.p_filesz));
            img->interp_path.assign(interp, len);
        } else if (ph.p_type == PT_DYNAMIC) {
            img->dynamic_addr = img->load_bias + ph.p_vaddr;
        }
    }

    if (img->phdr_addr == 0) {
        img->phdr_addr = img->map_base + ehdr->e_phoff;
    }

    // Parse PT_DYNAMIC and apply RELR + RELA relocations before tightening page protections
    if (img->dynamic_addr != 0) {
        const auto* dyn = reinterpret_cast<const Elf64_Dyn*>(img->dynamic_addr);
        uintptr_t relr_addr = 0;
        size_t relr_sz = 0;
        uintptr_t rela_addr = 0;
        size_t rela_sz = 0;
        uintptr_t jmprel_addr = 0;
        size_t jmprel_sz = 0;
        const Elf64_Sym* symtab = nullptr;
        const char* strtab = nullptr;
        size_t strtab_sz = 0;
        const uint32_t* sysv_hash = nullptr;
        std::vector<uint64_t> needed_offsets;

        for (size_t idx = 0; dyn[idx].d_tag != DT_NULL && idx < 4096; ++idx) {
            switch (dyn[idx].d_tag) {
                case DT_RELR:
                case DT_ANDROID_RELR:
                    relr_addr = img->load_bias + dyn[idx].d_un.d_ptr;
                    break;
                case DT_RELRSZ:
                case DT_ANDROID_RELRSZ:
                    relr_sz = dyn[idx].d_un.d_val;
                    break;
                case DT_RELA:
                    rela_addr = img->load_bias + dyn[idx].d_un.d_ptr;
                    break;
                case DT_RELASZ:
                    rela_sz = dyn[idx].d_un.d_val;
                    break;
                case DT_JMPREL:
                    jmprel_addr = img->load_bias + dyn[idx].d_un.d_ptr;
                    break;
                case DT_PLTRELSZ:
                    jmprel_sz = dyn[idx].d_un.d_val;
                    break;
                case DT_SYMTAB:
                    symtab = reinterpret_cast<const Elf64_Sym*>(img->load_bias + dyn[idx].d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    strtab = reinterpret_cast<const char*>(img->load_bias + dyn[idx].d_un.d_ptr);
                    break;
                case DT_STRSZ:
                    strtab_sz = dyn[idx].d_un.d_val;
                    break;
                case DT_HASH:
                    sysv_hash = reinterpret_cast<const uint32_t*>(img->load_bias + dyn[idx].d_un.d_ptr);
                    break;
                case DT_NEEDED:
                    needed_offsets.push_back(dyn[idx].d_un.d_val);
                    break;
                default:
                    break;
            }
        }

        if (strtab && strtab_sz > 0) {
            for (uint64_t off : needed_offsets) {
                if (off < strtab_sz) {
                    img->needed_libs.emplace_back(strtab + off);
                }
            }
        }

        // Determine symbol table count via DT_HASH nchain or contiguous .dynsym -> .dynstr span
        size_t sym_count = 0;
        if (sysv_hash && reinterpret_cast<uintptr_t>(sysv_hash) >= img->map_base &&
            reinterpret_cast<uintptr_t>(sysv_hash) + 8u <= img->map_base + img->map_size) {
            sym_count = sysv_hash[1];
        } else if (symtab && strtab &&
                   reinterpret_cast<uintptr_t>(strtab) > reinterpret_cast<uintptr_t>(symtab)) {
            sym_count = (reinterpret_cast<uintptr_t>(strtab) - reinterpret_cast<uintptr_t>(symtab)) /
                        sizeof(Elf64_Sym);
        }

        if (symtab && strtab && sym_count > 0) {
            IndexDynamicSymbols(*img, symtab, sym_count, strtab, strtab_sz);
        }

        if (relr_addr != 0 && relr_sz > 0) {
            ApplyRelr(*img, relr_addr, relr_sz);
        }
        if (rela_addr != 0 && rela_sz > 0) {
            ApplyRela(*img, rela_addr, rela_sz, symtab, sym_count, strtab, strtab_sz, dependency_images);
        }
        if (jmprel_addr != 0 && jmprel_sz > 0) {
            ApplyRela(*img, jmprel_addr, jmprel_sz, symtab, sym_count, strtab, strtab_sz, dependency_images);
        }
    }

    // Apply page protections (respecting host page boundaries; union permissions if 4K segments share a 16K page)
    size_t prot_page = host_page_size_;
    size_t num_pages = span / prot_page;
    std::vector<int> page_prots(num_pages, 0);
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;
        uintptr_t p_start = PageAlignDown(img->load_bias + ph.p_vaddr, prot_page);
        uintptr_t p_end = PageAlignUp(img->load_bias + ph.p_vaddr + ph.p_memsz, prot_page);
        int seg_prot = ProtFromElfFlags(ph.p_flags);
        for (uintptr_t addr = p_start; addr < p_end; addr += prot_page) {
            size_t pg_idx = static_cast<size_t>((addr - img->map_base) / prot_page);
            if (pg_idx < num_pages) {
                page_prots[pg_idx] |= seg_prot;
            }
        }
    }
    for (size_t pg = 0; pg < num_pages; ++pg) {
        if (page_prots[pg] != 0) {
            void* p = reinterpret_cast<void*>(img->map_base + pg * prot_page);
            ::mprotect(p, prot_page, page_prots[pg]);
            if ((page_prots[pg] & PROT_EXEC) != 0) {
                __builtin___clear_cache(static_cast<char*>(p), static_cast<char*>(p) + prot_page);
            }
        }
    }

    return img;
}

bool Elf64Loader::ApplyRelr(LoadedElfImage& img, uintptr_t relr_addr, size_t relr_bytes) {
    const auto* entries = reinterpret_cast<const uint64_t*>(relr_addr);
    size_t count = relr_bytes / sizeof(uint64_t);
    uint64_t* where = nullptr;
    const uintptr_t map_end = img.map_base + img.map_size;

    for (size_t i = 0; i < count; ++i) {
        uint64_t entry = entries[i];
        if ((entry & 1ull) == 0ull) {
            uintptr_t target = img.load_bias + static_cast<uintptr_t>(entry);
            if (target >= img.map_base && target + sizeof(uint64_t) <= map_end) {
                where = reinterpret_cast<uint64_t*>(target);
                *where += static_cast<uint64_t>(img.load_bias);
                img.relr_applied_count++;
                where++;
            } else {
                where = nullptr;
            }
        } else {
            if (!where) continue;
            uint64_t bitmap = entry >> 1;
            for (int bit = 0; bit < 63; ++bit) {
                if ((bitmap & (1ull << bit)) != 0ull) {
                    uintptr_t target = reinterpret_cast<uintptr_t>(where + bit);
                    if (target >= img.map_base && target + sizeof(uint64_t) <= map_end) {
                        where[bit] += static_cast<uint64_t>(img.load_bias);
                        img.relr_applied_count++;
                    }
                }
            }
            where += 63;
        }
    }
    return true;
}

bool Elf64Loader::ApplyRela(LoadedElfImage& img,
                            uintptr_t rela_addr,
                            size_t rela_bytes,
                            const Elf64_Sym* symtab,
                            size_t sym_count,
                            const char* strtab,
                            size_t strtab_size,
                            const std::vector<const LoadedElfImage*>& deps) {
    const auto* relas = reinterpret_cast<const Elf64_Rela*>(rela_addr);
    size_t count = rela_bytes / sizeof(Elf64_Rela);
    const uintptr_t map_end = img.map_base + img.map_size;

    auto resolve_sym = [&](uint32_t sym_idx) -> uintptr_t {
        if (!symtab || !strtab || sym_idx >= sym_count) return 0;
        const Elf64_Sym& s = symtab[sym_idx];
        if (s.st_shndx != SHN_UNDEF && s.st_value != 0) {
            return img.load_bias + s.st_value;
        }
        if (s.st_name < strtab_size) {
            std::string sym_name(strtab + s.st_name);
            uintptr_t local = img.FindSymbol(sym_name);
            if (local != 0) return local;
            for (const LoadedElfImage* dep : deps) {
                if (!dep) continue;
                uintptr_t found = dep->FindSymbol(sym_name);
                if (found != 0) return found;
            }
        }
        return 0;
    };

    for (size_t i = 0; i < count; ++i) {
        const Elf64_Rela& r = relas[i];
        uintptr_t target = img.load_bias + r.r_offset;
        if (target < img.map_base || target + sizeof(uint64_t) > map_end) continue;

        uint32_t type = ELF64_R_TYPE(r.r_info);
        uint32_t sym = ELF64_R_SYM(r.r_info);
        auto* slot = reinterpret_cast<uint64_t*>(target);

        if (type == R_AARCH64_RELATIVE || type == R_X86_64_RELATIVE) {
            *slot = static_cast<uint64_t>(img.load_bias + r.r_addend);
            img.rela_applied_count++;
        } else if (type == R_AARCH64_ABS64 || type == R_X86_64_64) {
            uintptr_t sym_addr = resolve_sym(sym);
            if (sym_addr != 0) {
                *slot = static_cast<uint64_t>(sym_addr + r.r_addend);
                img.rela_applied_count++;
            }
        } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT ||
                   type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT) {
            uintptr_t sym_addr = resolve_sym(sym);
            if (sym_addr != 0) {
                *slot = static_cast<uint64_t>(sym_addr);
                img.rela_applied_count++;
            }
        }
    }
    return true;
}

void Elf64Loader::IndexDynamicSymbols(LoadedElfImage& img,
                                      const Elf64_Sym* symtab,
                                      size_t sym_count,
                                      const char* strtab,
                                      size_t strtab_size) {
    for (size_t i = 1; i < sym_count; ++i) {
        const Elf64_Sym& s = symtab[i];
        if (s.st_shndx == SHN_UNDEF || s.st_value == 0) continue;
        if (s.st_name >= strtab_size) continue;
        const char* name = strtab + s.st_name;
        if (name[0] != '\0') {
            img.exported_symbols[name] = img.load_bias + s.st_value;
        }
    }
}

bool Elf64Loader::LoadWithInterpreter(
    const std::string& guest_exe_path,
    GuestVfsResolver& vfs,
    int guest_api_level,
    std::unique_ptr<LoadedElfImage>& out_exe,
    std::unique_ptr<LoadedElfImage>& out_linker,
    std::string& out_error
) {
    std::vector<uint8_t> exe_bytes;
    if (!vfs.ReadGuestFile(guest_exe_path, exe_bytes)) {
        out_error = "Failed to read guest executable: " + guest_exe_path;
        return false;
    }

    vfs.RegisterSelfExe(guest_exe_path, exe_bytes);
    out_exe = LoadFromBytes(guest_exe_path, exe_bytes, {}, false);
    if (!out_exe) {
        out_error = "Invalid ELF64 guest executable: " + guest_exe_path;
        return false;
    }

    std::string interp = out_exe->interp_path;
    if (interp.empty()) {
        interp = vfs.ResolveLinker64Path(guest_api_level);
    }

    std::vector<uint8_t> linker_bytes;
    if (vfs.ReadGuestFile(interp, linker_bytes)) {
        out_linker = LoadFromBytes(interp, linker_bytes, {}, false);
        if (!out_linker) {
            out_error = "Failed to load guest linker64: " + interp;
            return false;
        }
    } else {
        // Static or standalone ELF without external linker64 present in test image
        out_linker.reset();
    }

    return true;
}

} // namespace haseeb::loader
