#include "haseeb/psci.hpp"

#include <algorithm>

namespace haseeb::vm {

PsciController::PsciController(uint32_t max_cpus) {
    Reset(max_cpus);
}

void PsciController::Reset(uint32_t max_cpus) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_cpus_ = std::clamp(max_cpus, 1u, 8u);
    online_mask_ = 1u; // CPU0 online
    system_off_requested_ = false;
    system_reset_requested_ = false;
    pending_boots_.clear();
}

void PsciController::SetCpuOnline(uint32_t cpu_id, bool online) {
    if (cpu_id >= max_cpus_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (online) online_mask_ |= (1u << cpu_id);
    else online_mask_ &= ~(1u << cpu_id);
}

bool PsciController::IsCpuOnline(uint32_t cpu_id) const {
    if (cpu_id >= max_cpus_) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return (online_mask_ & (1u << cpu_id)) != 0;
}

std::vector<PsciController::CpuBootRequest> PsciController::DrainPendingCpuBoots() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CpuBootRequest> out;
    out.swap(pending_boots_);
    return out;
}

HypercallResult PsciController::HandleHypercall(CpuState& cpu, uint16_t /*imm16*/, bool /*is_smc*/) {
    const uint32_t fid = static_cast<uint32_t>(cpu.x[0] & 0xFFFFFFFFULL);
    HypercallResult res;
    res.handled = true;

    switch (fid) {
        case kPsciVersion: {
            cpu.x[0] = 0x00010000ULL; // PSCI v1.0
            return res;
        }
        case kPsciFeatures: {
            const uint32_t query = static_cast<uint32_t>(cpu.x[1] & 0xFFFFFFFFULL);
            bool supported = (query == kPsciVersion || query == kCpuSuspend32 ||
                              query == kCpuSuspend64 || query == kCpuOff ||
                              query == kCpuOn32 || query == kCpuOn64 ||
                              query == kAffinityInfo32 || query == kAffinityInfo64 ||
                              query == kMigrateInfoType || query == kSystemOff ||
                              query == kSystemReset || query == kPsciFeatures);
            cpu.x[0] = supported ? static_cast<uint64_t>(kRetSuccess)
                                 : static_cast<uint64_t>(kRetNotSupported);
            return res;
        }
        case kCpuSuspend32:
        case kCpuSuspend64: {
            cpu.x[0] = static_cast<uint64_t>(kRetSuccess);
            return res;
        }
        case kCpuOff: {
            SetCpuOnline(cpu.cpu_id, false);
            cpu.halted = true;
            cpu.x[0] = static_cast<uint64_t>(kRetSuccess);
            res.halt_vm = (cpu.cpu_id == 0);
            return res;
        }
        case kCpuOn32:
        case kCpuOn64: {
            const uint32_t target_cpu = static_cast<uint32_t>(cpu.x[1] & 0xFFULL);
            const uint64_t entry_pc = cpu.x[2];
            const uint64_t context_id = cpu.x[3];
            CpuOnCallback cb;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (target_cpu >= max_cpus_) {
                    cpu.x[0] = static_cast<uint64_t>(kRetInvalidParams);
                    return res;
                }
                if ((online_mask_ & (1u << target_cpu)) != 0) {
                    cpu.x[0] = static_cast<uint64_t>(kRetAlreadyOn);
                    return res;
                }
                CpuBootRequest req{target_cpu, entry_pc, context_id};
                pending_boots_.push_back(req);
                online_mask_ |= (1u << target_cpu);
                cb = cpu_on_cb_;
            }
            if (cb) {
                cb(CpuBootRequest{target_cpu, entry_pc, context_id});
            }
            cpu.x[0] = static_cast<uint64_t>(kRetSuccess);
            return res;
        }
        case kAffinityInfo32:
        case kAffinityInfo64: {
            const uint32_t target_cpu = static_cast<uint32_t>(cpu.x[1] & 0xFFULL);
            if (target_cpu >= max_cpus_) {
                cpu.x[0] = static_cast<uint64_t>(kRetInvalidParams);
            } else {
                // 0 = ON, 1 = OFF
                cpu.x[0] = IsCpuOnline(target_cpu) ? 0ULL : 1ULL;
            }
            return res;
        }
        case kMigrateInfoType: {
            cpu.x[0] = 2ULL; // Trusted OS not present / migration not required
            return res;
        }
        case kSystemOff: {
            SystemActionCallback cb;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                system_off_requested_ = true;
                cb = sys_action_cb_;
            }
            if (cb) cb(false);
            cpu.x[0] = static_cast<uint64_t>(kRetSuccess);
            res.halt_vm = true;
            return res;
        }
        case kSystemReset: {
            SystemActionCallback cb;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                system_reset_requested_ = true;
                cb = sys_action_cb_;
            }
            if (cb) cb(true);
            cpu.x[0] = static_cast<uint64_t>(kRetSuccess);
            res.halt_vm = true;
            return res;
        }
        default: {
            cpu.x[0] = static_cast<uint64_t>(kRetNotSupported);
            return res;
        }
    }
}

} // namespace haseeb::vm
