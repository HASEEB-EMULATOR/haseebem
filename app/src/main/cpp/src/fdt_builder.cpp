#include "haseeb/fdt_builder.hpp"

#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace haseeb::vm {

namespace {

inline constexpr uint32_t kFdtMagic = 0xD00DFEEDu;
inline constexpr uint32_t kFdtBeginNode = 1u;
inline constexpr uint32_t kFdtEndNode = 2u;
inline constexpr uint32_t kFdtProp = 3u;
inline constexpr uint32_t kFdtEnd = 9u;

void PushBE32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void PushBE64(std::vector<uint8_t>& buf, uint64_t v) {
    PushBE32(buf, static_cast<uint32_t>(v >> 32));
    PushBE32(buf, static_cast<uint32_t>(v & 0xFFFFFFFFULL));
}

void Align4(std::vector<uint8_t>& buf) {
    while ((buf.size() & 3u) != 0u) {
        buf.push_back(0);
    }
}

class FdtWriter {
public:
    void BeginNode(const std::string& name) {
        PushBE32(struct_blk_, kFdtBeginNode);
        struct_blk_.insert(struct_blk_.end(), name.begin(), name.end());
        struct_blk_.push_back(0);
        Align4(struct_blk_);
    }

    void EndNode() {
        PushBE32(struct_blk_, kFdtEndNode);
    }

    void PropBytes(const std::string& key, const std::vector<uint8_t>& data) {
        PushBE32(struct_blk_, kFdtProp);
        PushBE32(struct_blk_, static_cast<uint32_t>(data.size()));
        PushBE32(struct_blk_, InternString(key));
        struct_blk_.insert(struct_blk_.end(), data.begin(), data.end());
        Align4(struct_blk_);
    }

    void PropEmpty(const std::string& key) {
        PropBytes(key, {});
    }

    void PropU32(const std::string& key, uint32_t val) {
        std::vector<uint8_t> d;
        PushBE32(d, val);
        PropBytes(key, d);
    }

    void PropU64(const std::string& key, uint64_t val) {
        std::vector<uint8_t> d;
        PushBE64(d, val);
        PropBytes(key, d);
    }

    void PropU32Array(const std::string& key, const std::vector<uint32_t>& vals) {
        std::vector<uint8_t> d;
        d.reserve(vals.size() * 4);
        for (uint32_t v : vals) PushBE32(d, v);
        PropBytes(key, d);
    }

    void PropRegPairs64(const std::string& key, const std::vector<std::pair<uint64_t, uint64_t>>& regs) {
        std::vector<uint8_t> d;
        d.reserve(regs.size() * 16);
        for (const auto& r : regs) {
            PushBE64(d, r.first);
            PushBE64(d, r.second);
        }
        PropBytes(key, d);
    }

    void PropString(const std::string& key, const std::string& val) {
        std::vector<uint8_t> d(val.begin(), val.end());
        d.push_back(0);
        PropBytes(key, d);
    }

    void PropStringList(const std::string& key, const std::vector<std::string>& vals) {
        std::vector<uint8_t> d;
        for (const auto& s : vals) {
            d.insert(d.end(), s.begin(), s.end());
            d.push_back(0);
        }
        PropBytes(key, d);
    }

    std::vector<uint8_t> Finish() {
        PushBE32(struct_blk_, kFdtEnd);

        // Header = 40 bytes, followed by 16-byte terminator mem_rsvmap (addr=0, size=0)
        constexpr uint32_t kRsvMapOffset = 40u;
        constexpr uint32_t kRsvMapSize = 16u;
        uint32_t struct_off = kRsvMapOffset + kRsvMapSize;
        uint32_t strings_off = struct_off + static_cast<uint32_t>(struct_blk_.size());
        uint32_t total_sz = strings_off + static_cast<uint32_t>(strings_blk_.size());

        std::vector<uint8_t> out;
        out.reserve(total_sz);
        PushBE32(out, kFdtMagic);
        PushBE32(out, total_sz);
        PushBE32(out, struct_off);
        PushBE32(out, strings_off);
        PushBE32(out, kRsvMapOffset);
        PushBE32(out, 17u); // version
        PushBE32(out, 16u); // last_comp_version
        PushBE32(out, 0u);  // boot_cpuid_phys
        PushBE32(out, static_cast<uint32_t>(strings_blk_.size()));
        PushBE32(out, static_cast<uint32_t>(struct_blk_.size()));

        // Empty mem_rsvmap terminator
        PushBE64(out, 0ull);
        PushBE64(out, 0ull);

        out.insert(out.end(), struct_blk_.begin(), struct_blk_.end());
        out.insert(out.end(), strings_blk_.begin(), strings_blk_.end());
        return out;
    }

private:
    uint32_t InternString(const std::string& s) {
        auto it = string_offsets_.find(s);
        if (it != string_offsets_.end()) return it->second;
        uint32_t off = static_cast<uint32_t>(strings_blk_.size());
        strings_blk_.insert(strings_blk_.end(), s.begin(), s.end());
        strings_blk_.push_back(0);
        string_offsets_.emplace(s, off);
        return off;
    }

    std::vector<uint8_t> struct_blk_;
    std::vector<uint8_t> strings_blk_;
    std::unordered_map<std::string, uint32_t> string_offsets_;
};

} // namespace

bool FdtBuilder::Build(const FdtBuildParams& params,
                       std::vector<uint8_t>& out_dtb,
                       std::string& out_error) {
    if (params.vcpu_count == 0 || params.vcpu_count > 8) {
        out_error = "Invalid vCPU count for FDT";
        return false;
    }
    if (params.ram_size_bytes < 16ULL * 1024ULL * 1024ULL) {
        out_error = "RAM size too small for FDT";
        return false;
    }

    FdtWriter w;
    constexpr uint32_t kIntcPhandle = 1u;
    constexpr uint32_t kClkPhandle = 2u;

    w.BeginNode("");
    w.PropU32("#address-cells", 2u);
    w.PropU32("#size-cells", 2u);
    w.PropString("compatible", "linux,dummy-virt");
    w.PropString("model", "Haseeb Virtual ARM64 Board");
    w.PropU32("interrupt-parent", kIntcPhandle);

    // /chosen
    w.BeginNode("chosen");
    w.PropString("stdout-path", "/pl011@9000000");
    w.PropString("bootargs", params.bootargs);
    if (params.initrd_end > params.initrd_start) {
        w.PropU64("linux,initrd-start", params.initrd_start);
        w.PropU64("linux,initrd-end", params.initrd_end);
    }
    w.EndNode();

    // /firmware/android (identifies Android DT root; fstab intentionally supplied via /fstab.<hw>)
    w.BeginNode("firmware");
    w.BeginNode("android");
    w.PropString("compatible", "android,firmware");
    w.PropString("name", "android");
    w.EndNode();
    w.EndNode();

    // /memory@40000000
    w.BeginNode("memory@40000000");
    w.PropString("device_type", "memory");
    w.PropRegPairs64("reg", {{params.ram_base, params.ram_size_bytes}});
    w.EndNode();

    // /cpus
    w.BeginNode("cpus");
    w.PropU32("#address-cells", 1u);
    w.PropU32("#size-cells", 0u);
    for (uint32_t i = 0; i < params.vcpu_count; ++i) {
        w.BeginNode("cpu@" + std::to_string(i));
        w.PropString("device_type", "cpu");
        w.PropString("compatible", "arm,arm-v8");
        w.PropString("enable-method", "psci");
        w.PropU32("reg", i);
        w.EndNode();
    }
    w.EndNode();

    // /psci
    w.BeginNode("psci");
    w.PropStringList("compatible", {"arm,psci-1.0", "arm,psci-0.2"});
    w.PropString("method", "hvc");
    w.EndNode();

    // Fixed apb_pclk clock
    w.BeginNode("apb-pclk");
    w.PropString("compatible", "fixed-clock");
    w.PropU32("#clock-cells", 0u);
    w.PropU32("clock-frequency", 24000000u);
    w.PropString("clock-output-names", "clk24mhz");
    w.PropU32("phandle", kClkPhandle);
    w.EndNode();

    // /intc@8000000 (GICv3)
    w.BeginNode("intc@8000000");
    w.PropString("compatible", "arm,gic-v3");
    w.PropEmpty("interrupt-controller");
    w.PropU32("#interrupt-cells", 3u);
    w.PropU32("#address-cells", 2u);
    w.PropU32("#size-cells", 2u);
    w.PropU32("phandle", kIntcPhandle);
    w.PropRegPairs64("reg", {
        {kGicDistBase, 0x10000ULL},
        {kGicRedistBase, static_cast<uint64_t>(params.vcpu_count) * 0x20000ULL},
    });
    w.EndNode();

    // /timer (ARMv8 generic timer)
    w.BeginNode("timer");
    w.PropString("compatible", "arm,armv8-timer");
    w.PropEmpty("always-on");
    w.PropU32Array("interrupts", {
        1u, 13u, 0xF04u, // secure phys
        1u, 14u, 0xF04u, // non-secure phys
        1u, 11u, 0xF04u, // virtual
        1u, 10u, 0xF04u, // hyp phys
    });
    w.EndNode();

    // /pl011@9000000
    w.BeginNode("pl011@9000000");
    w.PropStringList("compatible", {"arm,pl011", "arm,primecell"});
    w.PropRegPairs64("reg", {{kPl011UartBase, 0x1000ULL}});
    w.PropU32Array("interrupts", {0u, 1u, 4u}); // SPI 1 level-high
    w.PropU32Array("clocks", {kClkPhandle, kClkPhandle});
    w.PropStringList("clock-names", {"uartclk", "apb_pclk"});
    w.EndNode();

    // /rtc@9010000
    w.BeginNode("rtc@9010000");
    w.PropStringList("compatible", {"arm,pl031", "arm,primecell"});
    w.PropRegPairs64("reg", {{kPl031RtcBase, 0x1000ULL}});
    w.PropU32Array("interrupts", {0u, 2u, 4u});
    w.PropU32("clocks", kClkPhandle);
    w.PropString("clock-names", "apb_pclk");
    w.EndNode();

    // /watchdog@9020000
    w.BeginNode("watchdog@9020000");
    w.PropStringList("compatible", {"arm,sp805", "arm,primecell"});
    w.PropRegPairs64("reg", {{kSp805WdtBase, 0x1000ULL}});
    w.PropU32Array("interrupts", {0u, 3u, 4u});
    w.PropU32Array("clocks", {kClkPhandle, kClkPhandle});
    w.PropStringList("clock-names", {"wdogclk", "apb_pclk"});
    w.EndNode();

    // /virtio_mmio@a000000..a000e00 (8 slots for M3+ block/net/console/gpu/input/snd)
    for (uint32_t slot = 0; slot < kVirtioMmioCount; ++slot) {
        uint64_t addr = kVirtioMmioBase + static_cast<uint64_t>(slot) * kVirtioMmioStride;
        char node_name[32];
        std::snprintf(node_name, sizeof(node_name), "virtio_mmio@%llx", static_cast<unsigned long long>(addr));
        w.BeginNode(node_name);
        w.PropString("compatible", "virtio,mmio");
        w.PropRegPairs64("reg", {{addr, kVirtioMmioStride}});
        w.PropU32Array("interrupts", {0u, 16u + slot, 1u}); // SPI 16..23 edge-rising
        w.EndNode();
    }

    w.EndNode(); // root
    out_dtb = w.Finish();
    return true;
}

} // namespace haseeb::vm
