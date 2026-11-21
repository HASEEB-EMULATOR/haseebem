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

} // namespace

int main() {
    TestArenaLayoutAndTrie();
    TestOverridesPrecedenceAndGpuGuard();
    TestPropertyServiceSocketRoundTrip();
    TestConcurrentReadersAndWriter();
    std::cout << "All M1 Property Area host unit tests passed.\n";
    return 0;
}
