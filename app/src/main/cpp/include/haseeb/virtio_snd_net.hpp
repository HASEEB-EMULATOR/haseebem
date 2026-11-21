#pragma once

#include "haseeb/virtio_devices.hpp"
#include "haseeb/virtio_mmio.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace haseeb::vm {

// Virtio-Snd (Device ID = 25) + /dev/snd/pcmC0D0p / pcmC0D0c bridge
// Low-latency 48 kHz S16_LE PCM ring buffered to Android AudioTrack / AudioRecord.
class VirtioSndDevice : public VirtioDeviceBackend {
public:
    static constexpr uint32_t kVirtioIdSnd = 25u;

    static constexpr uint32_t kCmdPcmSetParams = 0x0101u;
    static constexpr uint32_t kCmdPcmPrepare   = 0x0102u;
    static constexpr uint32_t kCmdPcmRelease   = 0x0103u;
    static constexpr uint32_t kCmdPcmStart     = 0x0104u;
    static constexpr uint32_t kCmdPcmStop      = 0x0105u;
    static constexpr uint32_t kStatusOk        = 0x8000u;

    VirtioSndDevice() = default;

    void ResetAudio();
    void PushPlaybackPcm(const int16_t* samples, size_t sample_count);
    size_t PopPlaybackPcm(int16_t* out_samples, size_t max_samples);

    void PushCapturePcm(const int16_t* samples, size_t sample_count);
    size_t PopCapturePcm(int16_t* out_samples, size_t max_samples);

    uint32_t SampleRateHz() const { return sample_rate_; }
    uint32_t Channels() const { return channels_; }
    uint64_t PlaybackFramesWritten() const { return playback_samples_total_.load() / std::max(1u, channels_); }
    uint64_t CaptureFramesRead() const { return capture_samples_total_.load() / std::max(1u, channels_); }
    size_t PendingPlaybackSamples() const;

    // VirtioDeviceBackend overrides
    uint32_t DeviceId() const override { return kVirtioIdSnd; }
    uint64_t DeviceFeatures() const override;
    uint32_t NumQueues() const override { return 4u; } // 0=ctrl, 1=event, 2=tx(play), 3=rx(cap)
    uint32_t ReadConfig(uint64_t offset, unsigned size_bytes) override;
    void WriteConfig(uint64_t offset, unsigned size_bytes, uint64_t value) override;
    void OnReset() override;
    void HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) override;

private:
    mutable std::mutex mutex_;
    uint32_t sample_rate_ = 48000u;
    uint32_t channels_ = 2u;
    bool playback_active_ = false;
    std::deque<int16_t> playback_ring_;
    std::deque<int16_t> capture_ring_;
    static constexpr size_t kMaxRingSamples = 48000u * 2u; // 1 second stereo @ 48 kHz
    std::atomic<uint64_t> playback_samples_total_{0};
    std::atomic<uint64_t> capture_samples_total_{0};
};

// User-mode Ethernet/IPv4/ARP/DHCP/ICMP/DNS/NAT packet router over VirtioNetDevice.
// Assigns guest 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3, and resolves A records
// via host getaddrinfo (plus deterministic local resolution for haseeb.vm / localhost).
class UserNatRouter {
public:
    UserNatRouter();

    void Attach(VirtioNetDevice& net, VirtioMmioDevice* net_transport = nullptr);
    void SetTransport(VirtioMmioDevice* net_transport) { transport_ = net_transport; }

    // Processes an outgoing Ethernet frame transmitted by the guest; injects reply into RX if applicable
    void HandleGuestTxFrame(VirtioNetDevice& net, const std::vector<uint8_t>& frame);

    // Host DNS resolution helper shared by both UDP DNS packets and guest /etc/hosts / proxy
    bool ResolveHostIpv4(const std::string& hostname, std::array<uint8_t, 4>& out_ip);

    uint64_t TxPackets() const { return tx_packets_.load(); }
    uint64_t RxPackets() const { return rx_packets_.load(); }
    uint64_t DnsQueries() const { return dns_queries_.load(); }

private:
    void ReplyArp(VirtioNetDevice& net, const std::vector<uint8_t>& req);
    void HandleIpv4(VirtioNetDevice& net, const std::vector<uint8_t>& frame);
    void ReplyIcmpEcho(VirtioNetDevice& net, const std::vector<uint8_t>& req, size_t ihl);
    void ReplyDhcp(VirtioNetDevice& net, const std::vector<uint8_t>& req, size_t ip_off, size_t udp_off);
    void ReplyDns(VirtioNetDevice& net, const std::vector<uint8_t>& req, size_t ip_off, size_t udp_off);
    void EmitRxFrame(VirtioNetDevice& net, const std::vector<uint8_t>& eth_frame);

    std::array<uint8_t, 6> gw_mac_{0x52, 0x55, 0x0A, 0x00, 0x02, 0x02};
    std::array<uint8_t, 4> gw_ip_{10, 0, 2, 2};
    std::array<uint8_t, 4> dns_ip_{10, 0, 2, 3};
    std::array<uint8_t, 4> guest_ip_{10, 0, 2, 15};

    VirtioMmioDevice* transport_ = nullptr;
    std::atomic<uint64_t> tx_packets_{0};
    std::atomic<uint64_t> rx_packets_{0};
    std::atomic<uint64_t> dns_queries_{0};
};

} // namespace haseeb::vm
