#pragma once

#include "haseeb/guest_ram.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace haseeb::vm {

namespace detail {
constexpr uint32_t PackGicSysRegKey(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
    return ((op0 & 3u) << 14) | ((op1 & 7u) << 11) | ((crn & 15u) << 7) |
           ((crm & 15u) << 3) | (op2 & 7u);
}
} // namespace detail

// ARM GICv3 Interrupt Controller:
//  - GICD Distributor at 0x08000000 (64 KiB): SPIs 32..255
//  - GICR Redistributor at 0x080A0000 (128 KiB * vCPUs): SGIs 0..15 & PPIs 16..31 per vCPU
//  - ICC_*_EL1 CPU Interface system register operations
class GicV3 {
public:
    static constexpr uint32_t kMaxCpus = 8;
    static constexpr uint32_t kMaxIrqs = 256; // 0..31 private (SGI/PPI), 32..255 shared (SPI)
    static constexpr uint32_t kSpuriousIrq = 1023u;

    explicit GicV3(uint32_t num_cpus = 4);

    void Reset(uint32_t num_cpus);
    uint32_t NumCpus() const { return num_cpus_; }

    // Peripheral interrupt assertion (SPI intid >= 32, PPI 16 <= intid < 32)
    void SetSpiLevel(uint32_t spi_num, bool high);   // spi_num = 0 -> INTID 32
    void SetPpiLevel(uint32_t cpu_id, uint32_t intid, bool high);
    void RaiseSpiPulse(uint32_t spi_num);

    // Check if CPU has an unmasked, enabled pending interrupt above current priority/PMR
    bool HasPendingIrq(uint32_t cpu_id) const;

    // CPU Interface (ICC_*_EL1) accessors
    uint64_t ReadSysReg(uint32_t cpu_id, uint32_t key);
    void WriteSysReg(uint32_t cpu_id, uint32_t key, uint64_t value);

    uint32_t ReadGicd(uint64_t offset, unsigned size_bytes);
    void WriteGicd(uint64_t offset, unsigned size_bytes, uint64_t value);

    uint64_t ReadGicr(uint64_t offset, unsigned size_bytes);
    void WriteGicr(uint64_t offset, unsigned size_bytes, uint64_t value);

    MmioDevice* DistributorMmio() { return &dist_mmio_; }
    MmioDevice* RedistributorMmio() { return &redist_mmio_; }

    // Packed ICC_*_EL1 keys (op0, op1, crn, crm, op2) matching cpu_sysregs.cpp
    static constexpr uint32_t PackKey(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
        return detail::PackGicSysRegKey(op0, op1, crn, crm, op2);
    }
    static inline constexpr uint32_t kIccPmrEl1     = detail::PackGicSysRegKey(3, 0, 4, 6, 0);
    static inline constexpr uint32_t kIccIar0El1    = detail::PackGicSysRegKey(3, 0, 12, 8, 0);
    static inline constexpr uint32_t kIccEoir0El1   = detail::PackGicSysRegKey(3, 0, 12, 8, 1);
    static inline constexpr uint32_t kIccHppir0El1  = detail::PackGicSysRegKey(3, 0, 12, 8, 2);
    static inline constexpr uint32_t kIccBpr0El1    = detail::PackGicSysRegKey(3, 0, 12, 8, 3);
    static inline constexpr uint32_t kIccDirEl1     = detail::PackGicSysRegKey(3, 0, 12, 11, 1);
    static inline constexpr uint32_t kIccRprEl1     = detail::PackGicSysRegKey(3, 0, 12, 11, 3);
    static inline constexpr uint32_t kIccSgi1rEl1   = detail::PackGicSysRegKey(3, 0, 12, 11, 5);
    static inline constexpr uint32_t kIccAsgi1rEl1  = detail::PackGicSysRegKey(3, 0, 12, 11, 6);
    static inline constexpr uint32_t kIccSgi0rEl1   = detail::PackGicSysRegKey(3, 0, 12, 11, 7);
    static inline constexpr uint32_t kIccIar1El1    = detail::PackGicSysRegKey(3, 0, 12, 12, 0);
    static inline constexpr uint32_t kIccEoir1El1   = detail::PackGicSysRegKey(3, 0, 12, 12, 1);
    static inline constexpr uint32_t kIccHppir1El1  = detail::PackGicSysRegKey(3, 0, 12, 12, 2);
    static inline constexpr uint32_t kIccBpr1El1    = detail::PackGicSysRegKey(3, 0, 12, 12, 3);
    static inline constexpr uint32_t kIccCtlrEl1    = detail::PackGicSysRegKey(3, 0, 12, 12, 4);
    static inline constexpr uint32_t kIccSreEl1     = detail::PackGicSysRegKey(3, 0, 12, 12, 5);
    static inline constexpr uint32_t kIccIgrpen0El1 = detail::PackGicSysRegKey(3, 0, 12, 12, 6);
    static inline constexpr uint32_t kIccIgrpen1El1 = detail::PackGicSysRegKey(3, 0, 12, 12, 7);

private:
    class DistMmio : public MmioDevice {
    public:
        explicit DistMmio(GicV3& owner) : owner_(owner) {}
        const char* Name() const override { return "gicv3-gicd"; }
        uint64_t Read(uint64_t offset, unsigned size_bytes) override {
            return owner_.ReadGicd(offset, size_bytes);
        }
        void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override {
            owner_.WriteGicd(offset, size_bytes, value);
        }
    private:
        GicV3& owner_;
    };

    class RedistMmio : public MmioDevice {
    public:
        explicit RedistMmio(GicV3& owner) : owner_(owner) {}
        const char* Name() const override { return "gicv3-gicr"; }
        uint64_t Read(uint64_t offset, unsigned size_bytes) override {
            return owner_.ReadGicr(offset, size_bytes);
        }
        void Write(uint64_t offset, unsigned size_bytes, uint64_t value) override {
            owner_.WriteGicr(offset, size_bytes, value);
        }
    private:
        GicV3& owner_;
    };

    struct IrqLineState {
        bool enabled = false;
        bool pending = false;
        bool active = false;
        bool level_high = false;
        bool edge_triggered = false;
        uint8_t group = 1;       // Group 1 NS default
        uint8_t priority = 0xA0; // Lower value = higher priority
        uint64_t router = 0;     // Target affinity for SPIs
    };

    struct CpuInterfaceState {
        std::array<IrqLineState, 32> private_irqs{}; // 0..15 SGIs, 16..31 PPIs
        uint32_t waker = 0;                          // GICR_WAKER (bit 1=ProcessorSleep, bit 2=ChildrenAsleep)
        uint8_t pmr = 0xFF;                          // ICC_PMR_EL1
        uint8_t bpr0 = 0;
        uint8_t bpr1 = 0;
        uint32_t ctlr = 0;
        bool igrpen0 = false;
        bool igrpen1 = false;
        uint32_t active_stack_count = 0;
        std::array<uint8_t, 32> running_priorities{};
    };

    uint32_t BestPendingIntidLocked(uint32_t cpu_id, uint8_t& out_prio) const;
    uint8_t RunningPriorityLocked(uint32_t cpu_id) const;
    uint32_t AcknowledgeIrqLocked(uint32_t cpu_id, uint8_t group);
    void EndOfIrqLocked(uint32_t cpu_id, uint32_t intid);

    mutable std::mutex mutex_;
    uint32_t num_cpus_ = 1;
    uint32_t gicd_ctlr_ = 0x10u; // ARE_NS = 1
    std::array<IrqLineState, kMaxIrqs> spis_{}; // slots 32..255 used
    std::array<CpuInterfaceState, kMaxCpus> cpus_{};

    DistMmio dist_mmio_;
    RedistMmio redist_mmio_;
};

} // namespace haseeb::vm
