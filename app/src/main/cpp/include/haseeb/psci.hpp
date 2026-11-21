#pragma once

#include "haseeb/cpu_core.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

namespace haseeb::vm {

// PSCI v1.0 hypercall controller (SMCCC / HVC / SMC)
class PsciController {
public:
    struct CpuBootRequest {
        uint32_t target_cpu = 0;
        uint64_t entry_pc = 0;
        uint64_t context_id = 0;
    };

    using CpuOnCallback = std::function<bool(const CpuBootRequest& req)>;
    using SystemActionCallback = std::function<void(bool is_reset)>;

    explicit PsciController(uint32_t max_cpus = 4);

    void Reset(uint32_t max_cpus);
    void SetCpuOnline(uint32_t cpu_id, bool online);
    bool IsCpuOnline(uint32_t cpu_id) const;

    void SetCpuOnCallback(CpuOnCallback cb) { cpu_on_cb_ = std::move(cb); }
    void SetSystemActionCallback(SystemActionCallback cb) { sys_action_cb_ = std::move(cb); }

    HypercallResult HandleHypercall(CpuState& cpu, uint16_t imm16, bool is_smc);

    bool SystemOffRequested() const { return system_off_requested_; }
    bool SystemResetRequested() const { return system_reset_requested_; }
    std::vector<CpuBootRequest> DrainPendingCpuBoots();

    // Standard PSCI 1.0 Function IDs
    static constexpr uint32_t kPsciVersion         = 0x84000000u;
    static constexpr uint32_t kCpuSuspend32        = 0x84000001u;
    static constexpr uint32_t kCpuSuspend64        = 0xC4000001u;
    static constexpr uint32_t kCpuOff              = 0x84000002u;
    static constexpr uint32_t kCpuOn32             = 0x84000003u;
    static constexpr uint32_t kCpuOn64             = 0xC4000003u;
    static constexpr uint32_t kAffinityInfo32      = 0x84000004u;
    static constexpr uint32_t kAffinityInfo64      = 0xC4000004u;
    static constexpr uint32_t kMigrateInfoType     = 0x84000006u;
    static constexpr uint32_t kSystemOff           = 0x84000008u;
    static constexpr uint32_t kSystemReset         = 0x84000009u;
    static constexpr uint32_t kPsciFeatures        = 0x8400000Au;

    static constexpr int64_t kRetSuccess           = 0;
    static constexpr int64_t kRetNotSupported      = -1;
    static constexpr int64_t kRetInvalidParams     = -2;
    static constexpr int64_t kRetAlreadyOn         = -4;

private:
    mutable std::mutex mutex_;
    uint32_t max_cpus_ = 4;
    uint32_t online_mask_ = 1u;
    bool system_off_requested_ = false;
    bool system_reset_requested_ = false;
    std::vector<CpuBootRequest> pending_boots_;
    CpuOnCallback cpu_on_cb_;
    SystemActionCallback sys_action_cb_;
};

} // namespace haseeb::vm
