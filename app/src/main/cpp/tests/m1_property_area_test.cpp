#include "haseeb/prop_area.hpp"
#include "haseeb/property_service.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define HASEEB_CHECK(cond)                                                              \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__              \
                      << ": " #cond << "\n";                                            \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

namespace fs = std::filesystem;
using namespace haseeb::prop;

namespace {

std::string MakeTempDir(const std::string& tag) {
    std::string dir = "/tmp/haseeb_" + tag + "_" + std::to_string(::getpid());
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

void TestArenaLayoutAndTrie() {
    std::string dir = MakeTempDir("arena_layout");
    MappedPropArena arena;
    HASEEB_CHECK(arena.Initialize("u:object_r:default_prop:s0", dir + "/default_prop", kPropAreaDefaultSize));
    HASEEB_CHECK(arena.AreaSize() == 1024u * 1024u);
    HASEEB_CHECK((arena.AreaSize() % kPageSize16K) == 0u);
    HASEEB_CHECK(arena.Header() != nullptr);
    HASEEB_CHECK(arena.Header()->magic == kPropAreaMagic);
    HASEEB_CHECK(arena.Header()->version == kPropAreaVersion);

    HASEEB_CHECK(arena.Set("ro.product.model", "SM-S938B"));
    HASEEB_CHECK(arena.Set("ro.product.brand", "samsung"));
    HASEEB_CHECK(arena.Set("sys.boot_completed", "0"));
    HASEEB_CHECK(arena.Set("sys.boot_completed", "1"));

    std::string val;
    HASEEB_CHECK(arena.Get("ro.product.model", val) && val == "SM-S938B");
    HASEEB_CHECK(arena.Get("ro.product.brand", val) && val == "samsung");
    HASEEB_CHECK(arena.Get("sys.boot_completed", val) && val == "1");
    HASEEB_CHECK(!arena.Get("non.existent.prop", val));

    // Long property (> 91 bytes) exercising kLongFlag
    std::string long_val(180, 'G');
    long_val = "haseeb_long_" + long_val;
    HASEEB_CHECK(arena.Set("ro.haseeb.long_fingerprint", long_val));
    HASEEB_CHECK(arena.Get("ro.haseeb.long_fingerprint", val) && val == long_val);

    fs::remove_all(dir);
    std::cout << "[PASS] TestArenaLayoutAndTrie\n";
}

void TestOverridesPrecedenceAndGpuGuard() {
    std::string dir = MakeTempDir("overrides");
    PropertyAreaManager mgr;

    // Register overrides BEFORE guest loads build.prop
    mgr.SetOverride("ro.product.model", "NX789J");
    mgr.SetOverride("ro.product.marketname", "RedMagic 10 Pro");
    // Hard rule: GPU spoofing must be rejected
    mgr.SetOverride("ro.hardware.egl", "fake_gpu");
    mgr.SetOverride("ro.opengles.version", "999999");

    HASEEB_CHECK(mgr.Initialize(dir));

    std::string prop_file = dir + "/build.prop";
    {
        std::ofstream ofs(prop_file);
        ofs << "ro.product.model=GenericAOSP\n";
        ofs << "ro.product.marketname=Generic\n";
        ofs << "ro.build.version.release=10\n";
        ofs << "ro.hardware.egl=adreno\n";
    }
    HASEEB_CHECK(mgr.LoadPropFile(prop_file));

    std::string val;
    HASEEB_CHECK(mgr.GetProperty("ro.product.model", val) && val == "NX789J");
    HASEEB_CHECK(mgr.GetProperty("ro.product.marketname", val) && val == "RedMagic 10 Pro");
    HASEEB_CHECK(mgr.GetProperty("ro.build.version.release", val) && val == "10");
    // Blocked GPU properties must not appear from overrides or build.prop override attempts
    HASEEB_CHECK(!mgr.GetProperty("ro.hardware.egl", val));
    HASEEB_CHECK(!mgr.GetProperty("ro.opengles.version", val));

    // Verify property_contexts and property_info binary header exist
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/property_contexts"));
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/property_info"));
    std::ifstream pinfo(dir + "/dev/__properties__/property_info", std::ios::binary);
    uint32_t ver = 0, min_ver = 0, total_sz = 0;
    pinfo.read(reinterpret_cast<char*>(&ver), 4);
    pinfo.read(reinterpret_cast<char*>(&min_ver), 4);
    pinfo.read(reinterpret_cast<char*>(&total_sz), 4);
    HASEEB_CHECK(ver == 1u && min_ver == 1u && total_sz > 24u);

    fs::remove_all(dir);
    std::cout << "[PASS] TestOverridesPrecedenceAndGpuGuard\n";
}

void TestPropertyServiceSocketRoundTrip() {
    std::string dir = MakeTempDir("prop_svc");
    PropertyAreaManager mgr;
    mgr.SetOverride("ro.haseeb.locked", "initial");
    HASEEB_CHECK(mgr.Initialize(dir));

    PropertyService svc(mgr);
    std::string sock_path = dir + "/property_service";
    HASEEB_CHECK(svc.Start(sock_path));

    auto send_setprop = [&](const std::string& k, const std::string& v) -> uint32_t {
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        HASEEB_CHECK(fd >= 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
        HASEEB_CHECK(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

        uint32_t cmd = kPropMsgSetProp2;
        uint32_t klen = static_cast<uint32_t>(k.size() + 1);
        uint32_t vlen = static_cast<uint32_t>(v.size() + 1);
        HASEEB_CHECK(::send(fd, &cmd, 4, 0) == 4);
        HASEEB_CHECK(::send(fd, &klen, 4, 0) == 4);
        HASEEB_CHECK(::send(fd, k.c_str(), klen, 0) == static_cast<ssize_t>(klen));
        HASEEB_CHECK(::send(fd, &vlen, 4, 0) == 4);
        HASEEB_CHECK(::send(fd, v.c_str(), vlen, 0) == static_cast<ssize_t>(vlen));

        uint32_t rc = 999u;
        HASEEB_CHECK(::recv(fd, &rc, 4, MSG_WAITALL) == 4);
        ::close(fd);
        return rc;
    };

    HASEEB_CHECK(send_setprop("sys.haseeb.fps", "120") == kPropSuccess);
    std::string val;
    HASEEB_CHECK(mgr.GetProperty("sys.haseeb.fps", val) && val == "120");

    // Read-only / overridden ro.* property cannot be mutated by guest shell
    HASEEB_CHECK(send_setprop("ro.haseeb.locked", "tampered") == kPropErrorReadOnlyProperty);
    HASEEB_CHECK(mgr.GetProperty("ro.haseeb.locked", val) && val == "initial");

    svc.Stop();
    fs::remove_all(dir);
    std::cout << "[PASS] TestPropertyServiceSocketRoundTrip\n";
}

void TestConcurrentReadersAndWriter() {
    std::string dir = MakeTempDir("concurrent");
    PropertyAreaManager mgr;
    HASEEB_CHECK(mgr.Initialize(dir));
    HASEEB_CHECK(mgr.SetProperty("debug.haseeb.counter", "0"));

    std::atomic<bool> stop{false};
    std::thread writer([&]() {
        for (int i = 1; i <= 500; ++i) {
            mgr.SetProperty("debug.haseeb.counter", std::to_string(i));
        }
        stop.store(true);
    });

    std::vector<std::thread> readers;
    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&]() {
            while (!stop.load()) {
                std::string val;
                if (mgr.GetProperty("debug.haseeb.counter", val)) {
                    for (char c : val) {
                        HASEEB_CHECK(c >= '0' && c <= '9');
                    }
                }
            }
        });
    }

    writer.join();
    for (auto& r : readers) r.join();

    std::string final_val;
    HASEEB_CHECK(mgr.GetProperty("debug.haseeb.counter", final_val) && final_val == "500");

    fs::remove_all(dir);
    std::cout << "[PASS] TestConcurrentReadersAndWriter\n";
}

void TestPropertyInfoBinaryAbiV1Parser() {
    struct AospHeader {
        uint32_t current_version;
        uint32_t minimum_supported_version;
        uint32_t size;
        uint32_t contexts_offset;
        uint32_t types_offset;
        uint32_t root_offset;
    };
    struct AospTrieNodeInternal {
        uint32_t property_entry;
        uint32_t num_child_nodes;
        uint32_t child_nodes;
        uint32_t num_prefixes;
        uint32_t prefix_entries;
        uint32_t num_exact_matches;
        uint32_t exact_match_entries;
    };
    struct AospPropertyEntry {
        uint32_t name_offset;
        uint32_t namelen;
        uint32_t context_index;
        uint32_t type_index;
    };

    std::string dir = MakeTempDir("prop_info_v1");
    PropertyAreaManager mgr;
    HASEEB_CHECK(mgr.Initialize(dir));

    auto parse_and_lookup = [](const std::vector<uint8_t>& blob, const std::string& prop_name) -> std::string {
        HASEEB_CHECK(blob.size() >= sizeof(AospHeader));
        const auto* hdr = reinterpret_cast<const AospHeader*>(blob.data());
        HASEEB_CHECK(hdr->current_version == 1u);
        HASEEB_CHECK(hdr->minimum_supported_version == 1u);
        HASEEB_CHECK(hdr->size == blob.size());

        auto read_u32 = [&](uint32_t off) -> uint32_t {
            HASEEB_CHECK(static_cast<size_t>(off) + 4u <= blob.size());
            uint32_t v = 0;
            std::memcpy(&v, blob.data() + off, 4u);
            return v;
        };
        auto read_cstr = [&](uint32_t off) -> const char* {
            HASEEB_CHECK(off > 0u && off < blob.size());
            const char* p = reinterpret_cast<const char*>(blob.data() + off);
            HASEEB_CHECK(std::memchr(p, '\0', blob.size() - off) != nullptr);
            return p;
        };

        const uint32_t num_ctx = read_u32(hdr->contexts_offset);
        HASEEB_CHECK(num_ctx >= 1u);
        auto get_ctx = [&](uint32_t idx) -> std::string {
            if (idx == ~0u || idx >= num_ctx) return "";
            uint32_t str_off = read_u32(hdr->contexts_offset + 4u + idx * 4u);
            return std::string(read_cstr(str_off));
        };

        auto read_entry = [&](uint32_t off) -> AospPropertyEntry {
            HASEEB_CHECK(static_cast<size_t>(off) + sizeof(AospPropertyEntry) <= blob.size());
            AospPropertyEntry e{};
            std::memcpy(&e, blob.data() + off, sizeof(e));
            return e;
        };
        auto read_node = [&](uint32_t off) -> AospTrieNodeInternal {
            HASEEB_CHECK(static_cast<size_t>(off) + sizeof(AospTrieNodeInternal) <= blob.size());
            AospTrieNodeInternal n{};
            std::memcpy(&n, blob.data() + off, sizeof(n));
            return n;
        };

        // Mirrors Bionic PropertyInfoArea::GetPropertyInfoIndexes
        uint32_t cur_off = hdr->root_offset;
        size_t pos = 0;
        uint32_t best_ctx = ~0u;

        while (true) {
            AospTrieNodeInternal node = read_node(cur_off);
            AospPropertyEntry node_entry = read_entry(node.property_entry);
            if (node_entry.context_index != ~0u) {
                best_ctx = node_entry.context_index;
            }

            // Check exact matches if at final segment
            size_t dot = prop_name.find('.', pos);
            const char* seg = prop_name.data() + pos;
            size_t seg_len = (dot == std::string::npos) ? (prop_name.size() - pos) : (dot - pos);

            if (dot == std::string::npos) {
                // Binary search exact_matches
                int lo = 0, hi = static_cast<int>(node.num_exact_matches) - 1;
                while (lo <= hi) {
                    int mid = (lo + hi) / 2;
                    uint32_t pe_off = read_u32(node.exact_match_entries + static_cast<uint32_t>(mid) * 4u);
                    AospPropertyEntry pe = read_entry(pe_off);
                    const char* pe_name = read_cstr(pe.name_offset);
                    HASEEB_CHECK(pe_name != nullptr);
                    int cmp = std::strncmp(pe_name, seg, seg_len);
                    if (cmp == 0 && pe.namelen == seg_len) {
                        return get_ctx(pe.context_index);
                    }
                    if (cmp == 0) cmp = (pe.namelen < seg_len) ? -1 : 1;
                    if (cmp < 0) lo = mid + 1;
                    else hi = mid - 1;
                }
            }

            // Scan prefixes (sorted longest first)
            const char* rem = prop_name.data() + pos;
            size_t rem_len = prop_name.size() - pos;
            for (uint32_t i = 0; i < node.num_prefixes; ++i) {
                uint32_t pe_off = read_u32(node.prefix_entries + i * 4u);
                AospPropertyEntry pe = read_entry(pe_off);
                const char* pe_name = read_cstr(pe.name_offset);
                HASEEB_CHECK(pe_name != nullptr);
                if (rem_len >= pe.namelen && std::strncmp(rem, pe_name, pe.namelen) == 0) {
                    best_ctx = pe.context_index;
                    break;
                }
            }

            if (dot == std::string::npos) break;

            // Binary search child_nodes using Bionic's strncmp check
            int lo = 0, hi = static_cast<int>(node.num_child_nodes) - 1;
            uint32_t next_child_off = 0;
            bool found_child = false;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                uint32_t child_off = read_u32(node.child_nodes + static_cast<uint32_t>(mid) * 4u);
                AospTrieNodeInternal child = read_node(child_off);
                AospPropertyEntry cpe = read_entry(child.property_entry);
                const char* cname = read_cstr(cpe.name_offset);
                HASEEB_CHECK(cname != nullptr);
                int cmp = std::strncmp(cname, seg, seg_len);
                if (cmp == 0) {
                    if (cname[seg_len] == '\0') {
                        next_child_off = child_off;
                        found_child = true;
                        break;
                    }
                    cmp = 1; // child name longer than seg
                }
                if (cmp < 0) lo = mid + 1;
                else hi = mid - 1;
            }
            if (!found_child) break;
            cur_off = next_child_off;
            pos = dot + 1u;
        }

        return get_ctx(best_ctx);
    };

    auto read_blob = [&]() {
        std::ifstream ifs(dir + "/dev/__properties__/property_info", std::ios::binary);
        HASEEB_CHECK(ifs.good());
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(ifs),
                                    std::istreambuf_iterator<char>());
    };

    std::vector<uint8_t> blob1 = read_blob();
    HASEEB_CHECK(parse_and_lookup(blob1, "ro.debuggable") == "u:object_r:default_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "ro.build.version.release") == "u:object_r:build_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "persist.sys.timezone") == "u:object_r:system_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "debug.ld.all") == "u:object_r:debug_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "dalvik.vm.heapsize") == "u:object_r:default_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "ro.haseeb.gpu") == "u:object_r:exported_default_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "ctl.start") == "u:object_r:ctl_default_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob1, "ro.boot.hardware") == "u:object_r:bootloader_boot_reason_prop:s0");

    // Verify all context arena files exist on disk (zero ENOENT gaps)
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/u:object_r:debug_prop:s0"));
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/u:object_r:ctl_default_prop:s0"));
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/u:object_r:persist_debug_prop:s0"));
    HASEEB_CHECK(fs::exists(dir + "/dev/__properties__/u:object_r:bootloader_boot_reason_prop:s0"));

    // Verify exact + multi-prefix LoadPropertyContexts serialization
    HASEEB_CHECK(mgr.LoadPropertyContexts(
        "* u:object_r:default_prop:s0\n"
        "sys.powerctl u:object_r:powerctl_prop:s0 exact\n"
        "persist.sys.usb. u:object_r:usb_prop:s0\n"
        "debug.atrace.tags.enableflags u:object_r:debug_prop:s0\n"));
    std::vector<uint8_t> blob2 = read_blob();
    HASEEB_CHECK(parse_and_lookup(blob2, "sys.powerctl") == "u:object_r:powerctl_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob2, "sys.powerctl.other") == "u:object_r:default_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob2, "persist.sys.usb.config") == "u:object_r:usb_prop:s0");
    HASEEB_CHECK(parse_and_lookup(blob2, "debug.atrace.tags.enableflags") == "u:object_r:debug_prop:s0");

    fs::remove_all(dir);
    std::cout << "[PASS] TestPropertyInfoBinaryAbiV1Parser\n";
}

} // namespace

int main() {
    TestArenaLayoutAndTrie();
    TestOverridesPrecedenceAndGpuGuard();
    TestPropertyServiceSocketRoundTrip();
    TestConcurrentReadersAndWriter();
    TestPropertyInfoBinaryAbiV1Parser();
    std::cout << "All M1 Property Area host unit tests passed.\n";
    return 0;
}
