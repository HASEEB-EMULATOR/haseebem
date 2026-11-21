#include "haseeb/virtio_snd_net.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace haseeb::vm {

namespace {

inline constexpr uint64_t kVirtioFVersion1 = (1ULL << 32);

uint16_t ReadBe16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

void WriteBe16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFFu);
}

void WriteBe32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    p[3] = static_cast<uint8_t>(v & 0xFFu);
}

uint16_t InetChecksum(const uint8_t* data, size_t len, uint32_t seed = 0u) {
    uint32_t sum = seed;
    for (size_t i = 0; i + 1u < len; i += 2u) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1u];
    }
    if ((len & 1u) != 0u) {
        sum += static_cast<uint32_t>(data[len - 1u]) << 8;
    }
    while ((sum >> 16) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xFFFFu);
}

} // namespace

// =========================================================================
// VirtioSndDevice
// =========================================================================

uint64_t VirtioSndDevice::DeviceFeatures() const {
    return kVirtioFVersion1;
}

void VirtioSndDevice::ResetAudio() {
    std::lock_guard<std::mutex> lock(mutex_);
    playback_ring_.clear();
    capture_ring_.clear();
    playback_active_ = false;
    sample_rate_ = 48000u;
    channels_ = 2u;
}

void VirtioSndDevice::OnReset() {
    ResetAudio();
}

void VirtioSndDevice::PushPlaybackPcm(const int16_t* samples, size_t sample_count) {
    if (!samples || sample_count == 0u) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < sample_count; ++i) {
        if (playback_ring_.size() >= kMaxRingSamples) {
            playback_ring_.pop_front();
        }
        playback_ring_.push_back(samples[i]);
    }
    playback_samples_total_.fetch_add(sample_count);
}

size_t VirtioSndDevice::PopPlaybackPcm(int16_t* out_samples, size_t max_samples) {
    if (!out_samples || max_samples == 0u) return 0u;
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t n = std::min(max_samples, playback_ring_.size());
    for (size_t i = 0; i < n; ++i) {
        out_samples[i] = playback_ring_.front();
        playback_ring_.pop_front();
    }
    return n;
}

void VirtioSndDevice::PushCapturePcm(const int16_t* samples, size_t sample_count) {
    if (!samples || sample_count == 0u) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < sample_count; ++i) {
        if (capture_ring_.size() >= kMaxRingSamples) {
            capture_ring_.pop_front();
        }
        capture_ring_.push_back(samples[i]);
    }
}

size_t VirtioSndDevice::PopCapturePcm(int16_t* out_samples, size_t max_samples) {
    if (!out_samples || max_samples == 0u) return 0u;
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t n = std::min(max_samples, capture_ring_.size());
    for (size_t i = 0; i < n; ++i) {
        out_samples[i] = capture_ring_.front();
        capture_ring_.pop_front();
    }
    capture_samples_total_.fetch_add(n);
    return n;
}

size_t VirtioSndDevice::PendingPlaybackSamples() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return playback_ring_.size();
}

uint32_t VirtioSndDevice::ReadConfig(uint64_t offset, unsigned /*size_bytes*/) {
    // virtio_snd_config: uint32_t jacks=1, streams=2, chmaps=1
    if (offset == 0u) return 1u;
    if (offset == 4u) return 2u;
    if (offset == 8u) return 1u;
    return 0u;
}

void VirtioSndDevice::WriteConfig(uint64_t /*offset*/, unsigned /*size_bytes*/, uint64_t /*value*/) {}

void VirtioSndDevice::HandleQueue(VirtioMmioDevice& transport, uint32_t queue_idx) {
    VirtqChain chain;
    if (queue_idx == 0u) {
        while (transport.PopAvailChain(0u, chain)) {
            const size_t rlen = transport.TotalReadBytes(chain);
            std::vector<uint8_t> req(rlen);
            if (rlen >= 4u && transport.CopyFromChain(chain, 0u, req.data(), rlen)) {
                uint32_t code = 0u;
                std::memcpy(&code, req.data(), 4u);
                std::lock_guard<std::mutex> lock(mutex_);
                if (code == kCmdPcmSetParams && req.size() >= 20u) {
                    const uint8_t ch = req[18];
                    if (ch == 1u || ch == 2u) channels_ = ch;
                } else if (code == kCmdPcmStart) {
                    playback_active_ = true;
                } else if (code == kCmdPcmStop || code == kCmdPcmRelease) {
                    playback_active_ = false;
                }
            }
            uint32_t status = kStatusOk;
            const uint32_t wlen = transport.TotalWriteBytes(chain);
            if (wlen >= 4u) {
                transport.CopyToChain(chain, rlen, &status, 4u);
            }
            transport.PushUsed(0u, chain.head_idx, std::min<uint32_t>(wlen, 4u));
        }
        return;
    }

    if (queue_idx == 2u) {
        // txq: guest PCM playback buffers (skip 8-byte virtio_snd_pcm_xfer header if present)
        while (transport.PopAvailChain(2u, chain)) {
            const size_t rlen = transport.TotalReadBytes(chain);
            std::vector<uint8_t> buf(rlen);
            if (rlen > 0u && transport.CopyFromChain(chain, 0u, buf.data(), rlen)) {
                const size_t pcm_off = (rlen > 8u && ((rlen - 8u) % 2u == 0u)) ? 8u : 0u;
                const size_t sample_cnt = (buf.size() - pcm_off) / sizeof(int16_t);
                if (sample_cnt > 0u) {
                    std::vector<int16_t> samples(sample_cnt);
                    std::memcpy(samples.data(), buf.data() + pcm_off, sample_cnt * sizeof(int16_t));
                    PushPlaybackPcm(samples.data(), samples.size());
                }
            }
            uint32_t status[2]{kStatusOk, 0u};
            const uint32_t wlen = transport.TotalWriteBytes(chain);
            const uint32_t ack = std::min<uint32_t>(wlen, sizeof(status));
            if (ack > 0u) transport.CopyToChain(chain, rlen, status, ack);
            transport.PushUsed(2u, chain.head_idx, ack);
        }
        return;
    }

    if (queue_idx == 3u) {
        // rxq: deliver host capture PCM samples to guest
        while (transport.PopAvailChain(3u, chain)) {
            const uint32_t rlen = transport.TotalReadBytes(chain);
            const uint32_t wlen = transport.TotalWriteBytes(chain);
            std::vector<uint8_t> out(wlen, 0u);
            if (wlen > 8u) {
                const size_t max_samp = (wlen - 8u) / sizeof(int16_t);
                std::vector<int16_t> cap(max_samp, 0);
                PopCapturePcm(cap.data(), max_samp);
                uint32_t ok = kStatusOk;
                std::memcpy(out.data(), &ok, 4u);
                std::memcpy(out.data() + 8u, cap.data(), max_samp * sizeof(int16_t));
            }
            if (wlen > 0u) transport.CopyToChain(chain, rlen, out.data(), wlen);
            transport.PushUsed(3u, chain.head_idx, wlen);
        }
    }
}

// =========================================================================
// UserNatRouter
// =========================================================================

UserNatRouter::UserNatRouter() = default;

void UserNatRouter::Attach(VirtioNetDevice& net, VirtioMmioDevice* net_transport) {
    transport_ = net_transport;
    net.SetTxCallback([this, &net](const std::vector<uint8_t>& frame) {
        HandleGuestTxFrame(net, frame);
    });
}

void UserNatRouter::EmitRxFrame(VirtioNetDevice& net, const std::vector<uint8_t>& eth_frame) {
    rx_packets_.fetch_add(1u);
    if (transport_) {
        net.InjectRxFrame(*transport_, eth_frame);
    }
}

bool UserNatRouter::ResolveHostIpv4(const std::string& hostname, std::array<uint8_t, 4>& out_ip) {
    if (hostname == "haseeb.vm" || hostname == "gateway.haseeb.vm") {
        out_ip = gw_ip_;
        return true;
    }
    if (hostname == "localhost" || hostname == "localhost.localdomain") {
        out_ip = {127, 0, 0, 1};
        return true;
    }
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0 || !res) {
        return false;
    }
    bool ok = false;
    for (auto* rp = res; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET && rp->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const auto* sin = reinterpret_cast<const struct sockaddr_in*>(rp->ai_addr);
            std::memcpy(out_ip.data(), &sin->sin_addr.s_addr, 4u);
            ok = true;
            break;
        }
    }
    ::freeaddrinfo(res);
    return ok;
}

void UserNatRouter::HandleGuestTxFrame(VirtioNetDevice& net, const std::vector<uint8_t>& frame) {
    if (frame.size() < 14u) return;
    tx_packets_.fetch_add(1u);
    const uint16_t ethertype = ReadBe16(frame.data() + 12u);
    if (ethertype == 0x0806u) {
        ReplyArp(net, frame);
    } else if (ethertype == 0x0800u) {
        HandleIpv4(net, frame);
    }
}

void UserNatRouter::ReplyArp(VirtioNetDevice& net, const std::vector<uint8_t>& req) {
    if (req.size() < 42u) return;
    const uint16_t oper = ReadBe16(req.data() + 20u);
    if (oper != 1u) return; // ARP Request only
    std::array<uint8_t, 4> target_ip{};
    std::memcpy(target_ip.data(), req.data() + 38u, 4u);
    if (target_ip != gw_ip_ && target_ip != dns_ip_) return;

    std::vector<uint8_t> reply(42u, 0u);
    std::memcpy(reply.data() + 0u, req.data() + 6u, 6u);   // dst MAC = guest MAC
    std::memcpy(reply.data() + 6u, gw_mac_.data(), 6u);    // src MAC = gateway MAC
    WriteBe16(reply.data() + 12u, 0x0806u);
    WriteBe16(reply.data() + 14u, 1u);      // Ethernet
    WriteBe16(reply.data() + 16u, 0x0800u); // IPv4
    reply[18] = 6u;
    reply[19] = 4u;
    WriteBe16(reply.data() + 20u, 2u);      // ARP Reply
    std::memcpy(reply.data() + 22u, gw_mac_.data(), 6u);
    std::memcpy(reply.data() + 28u, target_ip.data(), 4u);
    std::memcpy(reply.data() + 32u, req.data() + 22u, 6u);
    std::memcpy(reply.data() + 38u, req.data() + 28u, 4u);
    EmitRxFrame(net, reply);
}

void UserNatRouter::HandleIpv4(VirtioNetDevice& net, const std::vector<uint8_t>& frame) {
    constexpr size_t kIpOff = 14u;
    if (frame.size() < kIpOff + 20u) return;
    const uint8_t ihl = static_cast<uint8_t>((frame[kIpOff] & 0x0Fu) * 4u);
    if (ihl < 20u || frame.size() < kIpOff + ihl) return;
    const uint8_t proto = frame[kIpOff + 9u];

    if (proto == 1u) { // ICMP
        ReplyIcmpEcho(net, frame, ihl);
        return;
    }
    if (proto == 17u) { // UDP
        const size_t udp_off = kIpOff + ihl;
        if (frame.size() < udp_off + 8u) return;
        const uint16_t dst_port = ReadBe16(frame.data() + udp_off + 2u);
        if (dst_port == 67u) {
            ReplyDhcp(net, frame, kIpOff, udp_off);
        } else if (dst_port == 53u) {
            ReplyDns(net, frame, kIpOff, udp_off);
        }
    }
}

void UserNatRouter::ReplyIcmpEcho(VirtioNetDevice& net, const std::vector<uint8_t>& req, size_t ihl) {
    const size_t ip_off = 14u;
    const size_t icmp_off = ip_off + ihl;
    if (req.size() < icmp_off + 8u || req[icmp_off] != 8u /*ECHO_REQ*/) return;

    std::vector<uint8_t> reply = req;
    std::memcpy(reply.data() + 0u, req.data() + 6u, 6u);
    std::memcpy(reply.data() + 6u, gw_mac_.data(), 6u);
    std::memcpy(reply.data() + ip_off + 12u, req.data() + ip_off + 16u, 4u);
    std::memcpy(reply.data() + ip_off + 16u, req.data() + ip_off + 12u, 4u);
    WriteBe16(reply.data() + ip_off + 10u, 0u);
    WriteBe16(reply.data() + ip_off + 10u, InetChecksum(reply.data() + ip_off, ihl));

    reply[icmp_off] = 0u; // ECHO_REPLY
    WriteBe16(reply.data() + icmp_off + 2u, 0u);
    WriteBe16(reply.data() + icmp_off + 2u,
              InetChecksum(reply.data() + icmp_off, reply.size() - icmp_off));
    EmitRxFrame(net, reply);
}

void UserNatRouter::ReplyDhcp(VirtioNetDevice& net,
                              const std::vector<uint8_t>& req,
                              size_t /*ip_off*/,
                              size_t udp_off) {
    const size_t bootp_off = udp_off + 8u;
    if (req.size() < bootp_off + 240u) return;

    uint8_t msg_type = 1u; // DISCOVER -> OFFER (2), REQUEST -> ACK (5)
    for (size_t i = bootp_off + 240u; i + 1u < req.size();) {
        const uint8_t opt = req[i++];
        if (opt == 0u) continue;
        if (opt == 255u) break;
        const uint8_t olen = req[i++];
        if (i + olen > req.size()) break;
        if (opt == 53u && olen >= 1u) {
            msg_type = (req[i] == 3u) ? 5u : 2u; // REQUEST->DHCPACK, DISCOVER->DHCPOFFER
        }
        i += olen;
    }

    std::vector<uint8_t> pkt(14u + 20u + 8u + 300u, 0u);
    std::memcpy(pkt.data() + 0u, req.data() + 6u, 6u);
    std::memcpy(pkt.data() + 6u, gw_mac_.data(), 6u);
    WriteBe16(pkt.data() + 12u, 0x0800u);

    uint8_t* ip = pkt.data() + 14u;
    ip[0] = 0x45u;
    WriteBe16(ip + 2u, static_cast<uint16_t>(pkt.size() - 14u));
    ip[8] = 64u;
    ip[9] = 17u; // UDP
    std::memcpy(ip + 12u, gw_ip_.data(), 4u);
    std::memcpy(ip + 16u, guest_ip_.data(), 4u);
    WriteBe16(ip + 10u, InetChecksum(ip, 20u));

    uint8_t* udp = ip + 20u;
    WriteBe16(udp + 0u, 67u);
    WriteBe16(udp + 2u, 68u);
    WriteBe16(udp + 4u, static_cast<uint16_t>(8u + 300u));

    uint8_t* b = udp + 8u;
    b[0] = 2u; // BOOTREPLY
    b[1] = 1u;
    b[2] = 6u;
    std::memcpy(b + 4u, req.data() + bootp_off + 4u, 4u); // xid
    std::memcpy(b + 16u, guest_ip_.data(), 4u);           // yiaddr
    std::memcpy(b + 20u, gw_ip_.data(), 4u);              // siaddr
    std::memcpy(b + 28u, req.data() + bootp_off + 28u, 16u);
    WriteBe32(b + 236u, 0x63825363u); // DHCP magic cookie

    size_t o = 240u;
    b[o++] = 53u; b[o++] = 1u; b[o++] = msg_type;
    b[o++] = 54u; b[o++] = 4u; std::memcpy(b + o, gw_ip_.data(), 4u); o += 4u;
    b[o++] = 1u;  b[o++] = 4u; b[o++] = 255u; b[o++] = 255u; b[o++] = 255u; b[o++] = 0u;
    b[o++] = 3u;  b[o++] = 4u; std::memcpy(b + o, gw_ip_.data(), 4u); o += 4u;
    b[o++] = 6u;  b[o++] = 4u; std::memcpy(b + o, dns_ip_.data(), 4u); o += 4u;
    b[o++] = 255u;
    EmitRxFrame(net, pkt);
}

void UserNatRouter::ReplyDns(VirtioNetDevice& net,
                             const std::vector<uint8_t>& req,
                             size_t ip_off,
                             size_t udp_off) {
    const size_t dns_off = udp_off + 8u;
    if (req.size() < dns_off + 17u) return;
    dns_queries_.fetch_add(1u);

    // Parse QNAME starting at dns_off + 12
    std::string hostname;
    size_t pos = dns_off + 12u;
    while (pos < req.size()) {
        const uint8_t lab_len = req[pos++];
        if (lab_len == 0u) break;
        if (pos + lab_len > req.size()) return;
        if (!hostname.empty()) hostname.push_back('.');
        hostname.append(reinterpret_cast<const char*>(req.data() + pos), lab_len);
        pos += lab_len;
    }
    if (pos + 4u > req.size()) return;
    const size_t q_end = pos + 4u;

    std::array<uint8_t, 4> ans_ip{127, 0, 0, 1};
    const bool resolved = ResolveHostIpv4(hostname, ans_ip);

    const size_t ans_size = resolved ? 16u : 0u;
    const size_t dns_len = (q_end - dns_off) + ans_size;
    std::vector<uint8_t> pkt(14u + 20u + 8u + dns_len, 0u);
    std::memcpy(pkt.data() + 0u, req.data() + 6u, 6u);
    std::memcpy(pkt.data() + 6u, gw_mac_.data(), 6u);
    WriteBe16(pkt.data() + 12u, 0x0800u);

    uint8_t* ip = pkt.data() + 14u;
    ip[0] = 0x45u;
    WriteBe16(ip + 2u, static_cast<uint16_t>(20u + 8u + dns_len));
    ip[8] = 64u;
    ip[9] = 17u;
    std::memcpy(ip + 12u, req.data() + ip_off + 16u, 4u);
    std::memcpy(ip + 16u, req.data() + ip_off + 12u, 4u);
    WriteBe16(ip + 10u, InetChecksum(ip, 20u));

    uint8_t* udp = ip + 20u;
    WriteBe16(udp + 0u, ReadBe16(req.data() + udp_off + 2u));
    WriteBe16(udp + 2u, ReadBe16(req.data() + udp_off + 0u));
    WriteBe16(udp + 4u, static_cast<uint16_t>(8u + dns_len));

    uint8_t* dns = udp + 8u;
    std::memcpy(dns, req.data() + dns_off, q_end - dns_off);
    dns[2] = 0x81u; // QR=1, RD=1
    dns[3] = resolved ? 0x80u : 0x83u; // RA=1, NOERROR or NXDOMAIN
    WriteBe16(dns + 6u, resolved ? 1u : 0u);
    if (resolved) {
        uint8_t* a = dns + (q_end - dns_off);
        WriteBe16(a + 0u, 0xC00Cu); // Pointer to QNAME
        WriteBe16(a + 2u, 1u);      // TYPE A
        WriteBe16(a + 4u, 1u);      // CLASS IN
        WriteBe32(a + 6u, 60u);     // TTL 60s
        WriteBe16(a + 10u, 4u);
        std::memcpy(a + 12u, ans_ip.data(), 4u);
    }
    EmitRxFrame(net, pkt);
}

} // namespace haseeb::vm
