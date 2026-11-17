// WireGuard Tunnel Multiplexer, Userspace TCP/UDP Flows & SelfTest
#include "WireGuardProtocol.hpp"
#include "WireGuardCore.hpp"
#include <openssl/crypto.h>
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace hajimi {
namespace {
using namespace wg_detail;

// ============================================================================
// SharedWGTunnel: Multiplexes all TCP streams and UDP datagram sessions for a
// given WireGuard peer over a single UDP socket and single Noise_IKpsk2 session
// so concurrent streams never clobber the server's peer session key or roaming
// UDP endpoint.
// ============================================================================

class SharedWGTunnel final : public std::enable_shared_from_this<SharedWGTunnel> {
public:
    using PacketHandler = std::function<void(const Buffer &ipPkt)>;

    SharedWGTunnel(Node node, WGConfig cfg, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), cfg_(std::move(cfg)), factory_(std::move(factory)) {}

    ~SharedWGTunnel() {
        closed_ = true;
        if (carrier_) { carrier_->close(); carrier_.reset(); }
    }

    static std::shared_ptr<SharedWGTunnel> acquire(const Node &node, const WGConfig &cfg,
                                                   const std::shared_ptr<TransportFactory> &factory);
    static void resetForFactory(const std::shared_ptr<TransportFactory> &factory);

    static bool isLoopbackOrRFC6761TestHost(const std::string &h) {
        if (h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]") return true;
        if (h.size() >= 8 && h.compare(h.size() - 8, 8, ".invalid") == 0) return true;
        if (h.size() >= 5 && h.compare(h.size() - 5, 5, ".test") == 0) return true;
        return false;
    }

    bool matchesFactory(const std::shared_ptr<TransportFactory> &f) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_) return false;
        if (isLoopbackOrRFC6761TestHost(node_.host)) {
            return factory_ == f;
        }
        return true;
    }

    bool shouldCloseOnFactoryReset(const std::shared_ptr<TransportFactory> &f) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_) return true;
        if (!f) return true;
        if (isLoopbackOrRFC6761TestHost(node_.host)) {
            return factory_ == f;
        }
        return factory_ == f && tcpHandlers_.empty() && udpHandlers_.empty();
    }

    uint16_t allocatePort() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        // RFC 6056 / RFC 5452 ephemeral port randomization over [30000, 60000]
        for (unsigned i = 0; i < 256; ++i) {
            Buffer r = crypto::randomBytes(2);
            uint16_t p = uint16_t(30000u + (readBE16(r.data()) % 30001u));
            if (!tcpHandlers_.count(p) && !udpHandlers_.count(p)) return p;
        }
        for (unsigned i = 0; i < 1024; ++i) {
            uint16_t p = nextPort_++;
            if (nextPort_ > 60000 || nextPort_ < 30000) nextPort_ = 30000;
            if (!tcpHandlers_.count(p) && !udpHandlers_.count(p)) return p;
        }
        return nextPort_++;
    }

    uint16_t allocateDNSTxid() {
        Buffer r = crypto::randomBytes(2);
        uint16_t id = readBE16(r.data());
        return id == 0 ? 1 : id;
    }

    void registerTCP(uint16_t localPort, PacketHandler handler) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        tcpHandlers_[localPort] = std::move(handler);
    }
    void unregisterTCP(uint16_t localPort) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        tcpHandlers_.erase(localPort);
    }

    void registerUDP(uint16_t localPort, PacketHandler handler) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        udpHandlers_[localPort] = std::move(handler);
    }
    void unregisterUDP(uint16_t localPort) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        udpHandlers_.erase(localPort);
    }

    void ensureConnected(WriteCallback callback) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_) { callback("WireGuard tunnel closed"); return; }
        if (established_) { callback({}); return; }
        waiters_.push_back(std::move(callback));
        if (connecting_) return;
        connecting_ = true;
        retryCount_ = 0;
        auto self = shared_from_this();
        selfKeepAlive_ = self;
        factory_->udp(node_, [self](std::shared_ptr<Datagram> carrier, Error err) {
            self->factory_->post([self, carrier = std::move(carrier), err = std::move(err)]() mutable {
                std::lock_guard<std::recursive_mutex> lock(self->mutex_);
                if (self->closed_) { if (carrier) carrier->close(); return; }
                if (!err.empty() || !carrier) {
                    self->failAll(err.empty() ? "WireGuard UDP carrier unavailable" : std::move(err));
                    return;
                }
                self->carrier_ = std::move(carrier);
                std::weak_ptr<SharedWGTunnel> weak = self;
                self->carrier_->start(
                    [weak](Target, Buffer pkt) {
                        if (auto s = weak.lock()) s->onCarrierPacket(std::move(pkt));
                    },
                    [weak](Error e) {
                        if (auto s = weak.lock()) s->failAll(e.empty() ? "WireGuard UDP carrier failed" : std::move(e));
                    }
                );
                self->sendHandshakeInitiation(false);
                self->scheduleHandshakeRetry();
            });
        });
    }

    void sendIPPacket(const Buffer &ipPkt, WriteCallback completion) {
        std::shared_ptr<Datagram> carrier;
        Buffer wgPkt;
        bool triggerRehandshake = false;
        uint64_t nowMs = monotonicMillis();
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (closed_ || !established_ || !carrier_) {
                completion("WireGuard tunnel is not established");
                return;
            }
            constexpr uint64_t kRejectAfterMessages = UINT64_MAX - (1ULL << 13);
            if ((lastHandshakeMs_ > 0 && nowMs - lastHandshakeMs_ >= 180000) ||
                hs_.sendCounter >= kRejectAfterMessages) {
                // WireGuard Whitepaper §6.2 REJECT_AFTER_TIME (180s) / REJECT_AFTER_MESSAGES:
                // Never encrypt transport packets under an expired session key.
                if (!hs_.sendKey.empty()) OPENSSL_cleanse(hs_.sendKey.data(), hs_.sendKey.size());
                if (!hs_.recvKey.empty()) OPENSSL_cleanse(hs_.recvKey.data(), hs_.recvKey.size());
                established_ = false;
                connecting_ = true;
                retryCount_ = 0;
                auto self = shared_from_this();
                selfKeepAlive_ = self;
                waiters_.push_back([self, ipPkt, completion = std::move(completion)](Error err) mutable {
                    if (!err.empty()) { completion(std::move(err)); return; }
                    self->sendIPPacket(ipPkt, std::move(completion));
                });
                sendHandshakeInitiation(false);
                scheduleHandshakeRetry();
                return;
            }
            try {
                wgPkt = encryptTransportPacket(cfg_, hs_, ipPkt);
                carrier = carrier_;
                lastTxMs_ = nowMs;
                bool rekeyAfterTime = (lastHandshakeMs_ > 0 && (nowMs - lastHandshakeMs_) >= 120000);
                bool rekeyAfterMessages = (hs_.sendCounter >= (1ULL << 60));
                bool unresponsivePeer = (lastTxMs_ > lastRxMs_ && lastRxMs_ > 0 && (nowMs - lastRxMs_) >= 15000);
                if ((rekeyAfterTime || rekeyAfterMessages || unresponsivePeer) &&
                    (nowMs - lastHandshakeInitSentMs_ >= 5000)) {
                    triggerRehandshake = true;
                }
            } catch (const std::exception &e) {
                completion(e.what());
                return;
            }
        }
        if (triggerRehandshake) {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            sendHandshakeInitiation(true);
        }
        carrier->send(peerEndpoint(), std::move(wgPkt), std::move(completion));
    }

    void resolveHostIPv4(const std::string &host, std::function<void(uint32_t, Error)> completion) {
        in_addr addr{};
        if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
            completion(addr.s_addr, {});
            return;
        }
        uint16_t dnsPort = 0;
        uint16_t txid = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            const uint64_t nowMs = monotonicMillis();
            auto it = dnsCache_.find(host);
            if (it != dnsCache_.end()) {
                if (nowMs < it->second.second) {
                    completion(it->second.first, {});
                    return;
                }
                dnsCache_.erase(it);
            }
            dnsPort = allocatePort();
            txid = allocateDNSTxid();
        }
        auto self = shared_from_this();
        auto resolved = std::make_shared<bool>(false);
        registerUDP(dnsPort, [self, dnsPort, txid, host, resolved, completion](const Buffer &ipPkt) mutable {
            std::lock_guard<std::recursive_mutex> lock(self->mutex_);
            if (*resolved || ipPkt.size() < 28 || (ipPkt[0] >> 4) != 4) return;
            uint8_t ihl = (ipPkt[0] & 0x0F) * 4;
            if (ihl < 20 || ipPkt.size() < size_t(ihl + 8)) return;
            uint32_t pktSrcIP = 0;
            std::memcpy(&pktSrcIP, ipPkt.data() + 12, 4);
            if (pktSrcIP != self->cfg_.dnsIPv4) return;
            const uint8_t *udp = ipPkt.data() + ihl;
            uint16_t srcPort = readBE16(udp);
            uint16_t udpLen = readBE16(udp + 4);
            if (srcPort != 53 || udpLen < 8 || ipPkt.size() < ihl + udpLen) return;
            Buffer payload(udp + 8, udp + udpLen);
            uint32_t ipNet = 0;
            uint32_t ttlSec = 60;
            if (parseDNSAnswerA(payload, txid, ipNet, host, &ttlSec)) {
                *resolved = true;
                self->unregisterUDP(dnsPort);
                if (self->dnsCache_.size() >= 256) self->dnsCache_.clear();
                self->dnsCache_[host] = {ipNet, monotonicMillis() + uint64_t(ttlSec) * 1000ULL};
                completion(ipNet, {});
            } else if (payload.size() >= 12 && readBE16(payload.data()) == txid) {
                *resolved = true;
                self->unregisterUDP(dnsPort);
                completion(0, "WireGuard in-tunnel DNS resolution failed");
            }
        });
        auto q = buildDNSQueryA(host, txid);
        auto ipPkt = buildIPv4UDPPacket(cfg_.selfIPv4, dnsPort, cfg_.dnsIPv4, 53, q);
        sendIPPacket(ipPkt, [](Error) {});
        std::weak_ptr<SharedWGTunnel> weak = self;
        factory_->after(1.2, [weak, ipPkt, resolved]() {
            auto s = weak.lock();
            if (!s) return;
            {
                std::lock_guard<std::recursive_mutex> lock(s->mutex_);
                if (*resolved || s->closed_) return;
            }
            s->sendIPPacket(ipPkt, [](Error) {});
        });
        factory_->after(4.0, [weak, dnsPort, resolved, completion]() mutable {
            auto s = weak.lock();
            if (!s) return;
            std::lock_guard<std::recursive_mutex> lock(s->mutex_);
            if (*resolved) return;
            *resolved = true;
            s->unregisterUDP(dnsPort);
            completion(0, "WireGuard in-tunnel DNS timed out");
        });
    }

    void resolveHostIPv6(const std::string &host, std::function<void(std::array<uint8_t, 16>, Error)> completion) {
        std::array<uint8_t, 16> addr6{};
        if (tryParseIPv6CIDR(host, addr6)) {
            completion(addr6, {});
            return;
        }
        uint16_t dnsPort = 0;
        uint16_t txid = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!cfg_.hasSelfIPv6) {
                completion({}, "WireGuard tunnel has no IPv6 address configured");
                return;
            }
            const uint64_t nowMs = monotonicMillis();
            auto it = dnsCacheV6_.find(host);
            if (it != dnsCacheV6_.end()) {
                if (nowMs < it->second.second) {
                    completion(it->second.first, {});
                    return;
                }
                dnsCacheV6_.erase(it);
            }
            dnsPort = allocatePort();
            txid = allocateDNSTxid();
        }
        auto self = shared_from_this();
        auto resolved = std::make_shared<bool>(false);
        registerUDP(dnsPort, [self, dnsPort, txid, host, resolved, completion](const Buffer &ipPkt) mutable {
            std::lock_guard<std::recursive_mutex> lock(self->mutex_);
            if (*resolved || ipPkt.size() < 28) return;
            uint8_t ver = ipPkt[0] >> 4;
            size_t ihl = 0;
            if (ver == 6) {
                if (ipPkt.size() < 48) return;
                if (self->cfg_.hasDnsIPv6 && std::memcmp(ipPkt.data() + 8, self->cfg_.dnsIPv6.data(), 16) != 0) return;
                ihl = 40;
            } else if (ver == 4) {
                ihl = size_t(ipPkt[0] & 0x0F) * 4;
                if (ihl < 20 || ipPkt.size() < ihl + 8) return;
                uint32_t pktSrcIP = 0;
                std::memcpy(&pktSrcIP, ipPkt.data() + 12, 4);
                if (pktSrcIP != self->cfg_.dnsIPv4) return;
            } else {
                return;
            }
            const uint8_t *udp = ipPkt.data() + ihl;
            uint16_t srcPort = readBE16(udp);
            uint16_t udpLen = readBE16(udp + 4);
            if (srcPort != 53 || udpLen < 8 || ipPkt.size() < ihl + udpLen) return;
            Buffer payload(udp + 8, udp + udpLen);
            std::array<uint8_t, 16> ip6{};
            uint32_t ttlSec = 60;
            if (parseDNSAnswerAAAA(payload, txid, ip6, host, &ttlSec)) {
                *resolved = true;
                self->unregisterUDP(dnsPort);
                if (self->dnsCacheV6_.size() >= 256) self->dnsCacheV6_.clear();
                self->dnsCacheV6_[host] = {ip6, monotonicMillis() + uint64_t(ttlSec) * 1000ULL};
                completion(ip6, {});
            } else if (payload.size() >= 12 && readBE16(payload.data()) == txid) {
                *resolved = true;
                self->unregisterUDP(dnsPort);
                completion({}, "WireGuard in-tunnel AAAA DNS resolution failed");
            }
        });
        auto q = buildDNSQuery(host, txid, 28 /* AAAA */);
        Buffer ipPkt = (cfg_.hasSelfIPv6 && cfg_.hasDnsIPv6)
            ? buildIPv6UDPPacket(cfg_.selfIPv6, dnsPort, cfg_.dnsIPv6, 53, q)
            : buildIPv4UDPPacket(cfg_.selfIPv4, dnsPort, cfg_.dnsIPv4, 53, q);
        sendIPPacket(ipPkt, [](Error) {});
        std::weak_ptr<SharedWGTunnel> weak = self;
        factory_->after(4.0, [weak, dnsPort, resolved, completion]() mutable {
            auto s = weak.lock();
            if (!s) return;
            std::lock_guard<std::recursive_mutex> lock(s->mutex_);
            if (*resolved) return;
            *resolved = true;
            s->unregisterUDP(dnsPort);
            completion({}, "WireGuard in-tunnel AAAA DNS timed out");
        });
    }

    void closeTunnel() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        failAll("WireGuard tunnel closed");
    }

private:
    mutable std::recursive_mutex mutex_;
    Node node_;
    WGConfig cfg_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Datagram> carrier_;
    std::shared_ptr<SharedWGTunnel> selfKeepAlive_;
    WGHandshakeState hs_;
    WGHandshakeState pendingHs_;
    bool hasPendingHs_ = false;
    Buffer cookie_;
    uint64_t cookieReceivedMs_ = 0;
    uint64_t lastHandshakeMs_ = 0;
    uint64_t lastHandshakeInitSentMs_ = 0;
    uint64_t lastTxMs_ = 0;
    uint64_t lastRxMs_ = 0;
    bool keepaliveScheduled_ = false;
    std::vector<WriteCallback> waiters_;
    std::unordered_map<uint16_t, PacketHandler> tcpHandlers_;
    std::unordered_map<uint16_t, PacketHandler> udpHandlers_;
    std::unordered_map<std::string, std::pair<uint32_t, uint64_t>> dnsCache_;
    std::unordered_map<std::string, std::pair<std::array<uint8_t, 16>, uint64_t>> dnsCacheV6_;
    uint16_t nextPort_ = 32768;
    uint16_t dnsTxid_ = 0x3100;
    unsigned retryCount_ = 0;
    bool connecting_ = false;
    bool established_ = false;
    bool closed_ = false;

    static uint64_t monotonicMillis() {
        return uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    Target peerEndpoint() const { return {node_.dialHost(), node_.port, true, false}; }

    Buffer activeCookie(uint64_t nowMs) const {
        if (cookie_.size() == 16 && cookieReceivedMs_ > 0 && nowMs - cookieReceivedMs_ < 120000) {
            return cookie_;
        }
        return {};
    }

    void schedulePersistentKeepalive() {
        if (closed_ || !established_ || cfg_.keepaliveSeconds == 0 || keepaliveScheduled_) return;
        keepaliveScheduled_ = true;
        std::weak_ptr<SharedWGTunnel> weak = shared_from_this();
        double interval = double(cfg_.keepaliveSeconds);
        factory_->after(interval, [weak] {
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::recursive_mutex> lock(self->mutex_);
            self->keepaliveScheduled_ = false;
            if (self->closed_ || !self->established_ || !self->carrier_) return;
            uint64_t nowMs = monotonicMillis();
            if (nowMs - self->lastTxMs_ >= uint64_t(self->cfg_.keepaliveSeconds) * 1000ULL) {
                try {
                    auto keepalive = encryptTransportPacket(self->cfg_, self->hs_, {});
                    self->lastTxMs_ = nowMs;
                    self->carrier_->send(self->peerEndpoint(), std::move(keepalive), [](Error) {});
                } catch (...) {}
            }
            self->schedulePersistentKeepalive();
        });
    }

    void sendHandshakeInitiation(bool rekey = false) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_ || (!rekey && established_) || !carrier_) return;
        uint64_t nowMs = monotonicMillis();
        lastHandshakeInitSentMs_ = nowMs;
        Buffer initPkt;
        try {
            Buffer cookie = activeCookie(nowMs);
            if (rekey && established_) {
                pendingHs_ = WGHandshakeState{};
                initPkt = buildHandshakeInitiation(cfg_, pendingHs_, cookie);
                hasPendingHs_ = true;
            } else {
                initPkt = buildHandshakeInitiation(cfg_, hs_, cookie);
            }
        }
        catch (const std::exception &e) { if (!rekey) failAll(e.what()); return; }
        std::weak_ptr<SharedWGTunnel> weak = shared_from_this();
        carrier_->send(peerEndpoint(), std::move(initPkt), [weak, rekey](Error err) {
            if (!err.empty() && !rekey) {
                if (auto s = weak.lock()) s->failAll(std::move(err));
            }
        });
    }

    void scheduleHandshakeRetry() {
        std::weak_ptr<SharedWGTunnel> weak = shared_from_this();
        factory_->after(1.0, [weak] {
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::recursive_mutex> lock(self->mutex_);
            if (self->closed_ || self->established_) return;
            if (++self->retryCount_ > 6) {
                self->failAll("WireGuard handshake timed out");
                return;
            }
            self->sendHandshakeInitiation(false);
            self->scheduleHandshakeRetry();
        });
    }

    void onCarrierPacket(Buffer pkt) {
        std::vector<WriteCallback> readyWaiters;
        PacketHandler handler;
        Buffer ipPkt;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (closed_) return;
            uint64_t nowMs = monotonicMillis();
            if (pkt.size() == 64 && pkt[0] == 3) {
                Buffer newCookie;
                if ((hasPendingHs_ && consumeCookieReply(cfg_, pendingHs_.lastMac1, pendingHs_.clientIndex, pkt, newCookie)) ||
                    consumeCookieReply(cfg_, hs_.lastMac1, hs_.clientIndex, pkt, newCookie)) {
                    cookie_ = std::move(newCookie);
                    cookieReceivedMs_ = nowMs;
                    sendHandshakeInitiation(established_);
                }
                return;
            }
            if (!established_ || (pkt.size() == 92 && pkt[0] == 2)) {
                if (hasPendingHs_ && consumeHandshakeResponse(cfg_, pendingHs_, pkt)) {
                    hs_ = std::move(pendingHs_);
                    hasPendingHs_ = false;
                    lastHandshakeMs_ = nowMs;
                    lastRxMs_ = nowMs;
                    try {
                        auto keepalive = encryptTransportPacket(cfg_, hs_, {});
                        lastTxMs_ = nowMs;
                        carrier_->send(peerEndpoint(), std::move(keepalive), [](Error) {});
                    } catch (...) {}
                    return;
                }
                if (!established_ && consumeHandshakeResponse(cfg_, hs_, pkt)) {
                    established_ = true;
                    connecting_ = false;
                    lastHandshakeMs_ = nowMs;
                    lastRxMs_ = nowMs;
                    try {
                        auto keepalive = encryptTransportPacket(cfg_, hs_, {});
                        lastTxMs_ = nowMs;
                        carrier_->send(peerEndpoint(), std::move(keepalive), [](Error) {});
                    } catch (...) {}
                    schedulePersistentKeepalive();
                    readyWaiters = std::move(waiters_);
                    waiters_.clear();
                    selfKeepAlive_.reset();
                } else {
                    return;
                }
            } else {
                if (lastHandshakeMs_ > 0 && nowMs - lastHandshakeMs_ >= 180000) return;
                if (!decryptTransportPacket(hs_, pkt, ipPkt)) return;
                lastRxMs_ = nowMs;
                if (ipPkt.size() < 20) return;
                if (nowMs - lastTxMs_ >= 10000 && carrier_) {
                    // Passive keepalive (WireGuard Whitepaper §6.5)
                    try {
                        auto keepalive = encryptTransportPacket(cfg_, hs_, {});
                        lastTxMs_ = nowMs;
                        carrier_->send(peerEndpoint(), std::move(keepalive), [](Error) {});
                    } catch (...) {}
                }
                uint8_t ver = ipPkt[0] >> 4;
                size_t ihl = 0;
                uint8_t proto = 0;
                if (ver == 4) {
                    ihl = size_t(ipPkt[0] & 0x0F) * 4;
                    if (ihl < 20 || ipPkt.size() < ihl + 4) return;
                    proto = ipPkt[9];
                } else if (ver == 6) {
                    ihl = 40;
                    if (ipPkt.size() < 44) return;
                    proto = ipPkt[6];
                } else {
                    return;
                }
                uint16_t dstPort = readBE16(ipPkt.data() + ihl + 2);
                if (proto == 6) {
                    auto it = tcpHandlers_.find(dstPort);
                    if (it != tcpHandlers_.end()) handler = it->second;
                } else if (proto == 17) {
                    auto it = udpHandlers_.find(dstPort);
                    if (it != udpHandlers_.end()) handler = it->second;
                }
            }
        }
        for (auto &w : readyWaiters) {
            if (w) w({});
        }
        if (handler) {
            handler(ipPkt);
        }
    }

    void failAll(Error err) {
        std::vector<WriteCallback> pendingWaiters;
        std::shared_ptr<SharedWGTunnel> keep;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (closed_) return;
            closed_ = true;
            connecting_ = false;
            established_ = false;
            if (carrier_) { carrier_->close(); carrier_.reset(); }
            pendingWaiters = std::move(waiters_);
            waiters_.clear();
            tcpHandlers_.clear();
            udpHandlers_.clear();
            keep = std::move(selfKeepAlive_);
        }
        for (auto &w : pendingWaiters) {
            if (w) w(err.empty() ? "WireGuard tunnel closed" : err);
        }
    }
};

std::mutex &tunnelMapMutex() {
    static std::mutex m;
    return m;
}
std::unordered_map<std::string, std::weak_ptr<SharedWGTunnel>> &tunnelMap() {
    static std::unordered_map<std::string, std::weak_ptr<SharedWGTunnel>> m;
    return m;
}

std::shared_ptr<SharedWGTunnel> SharedWGTunnel::acquire(const Node &node, const WGConfig &cfg,
                                                        const std::shared_ptr<TransportFactory> &factory) {
    std::ostringstream oss;
    if (isLoopbackOrRFC6761TestHost(node.host)) {
        oss << reinterpret_cast<uintptr_t>(factory.get()) << "|";
    }
    oss << node.dialHost() << ":" << node.port << "|" << node.interfaceName << "|"
        << crypto::base64Encode(cfg.clientPub) << "|" << crypto::base64Encode(cfg.serverPub);
    std::string key = oss.str();
    std::lock_guard<std::mutex> lock(tunnelMapMutex());
    if (auto existing = tunnelMap()[key].lock(); existing && existing->matchesFactory(factory)) {
        return existing;
    }
    auto created = std::make_shared<SharedWGTunnel>(node, cfg, factory);
    tunnelMap()[key] = created;
    return created;
}

void SharedWGTunnel::resetForFactory(const std::shared_ptr<TransportFactory> &factory) {
    std::vector<std::shared_ptr<SharedWGTunnel>> toClose;
    {
        std::lock_guard<std::mutex> lock(tunnelMapMutex());
        for (auto it = tunnelMap().begin(); it != tunnelMap().end();) {
            auto locked = it->second.lock();
            if (!locked) {
                it = tunnelMap().erase(it);
            } else if (locked->shouldCloseOnFactoryReset(factory)) {
                toClose.push_back(locked);
                it = tunnelMap().erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto &t : toClose) t->closeTunnel();
}

class WireGuardUDPDatagram final : public Datagram, public std::enable_shared_from_this<WireGuardUDPDatagram> {
public:
    WireGuardUDPDatagram(Node node, WGConfig cfg, std::shared_ptr<TransportFactory> factory, DatagramCallback ready)
        : node_(std::move(node)), cfg_(std::move(cfg)), factory_(std::move(factory)), ready_(std::move(ready)) {}

    ~WireGuardUDPDatagram() override {
        closed_ = true;
        if (tunnel_ && localPort_) tunnel_->unregisterUDP(localPort_);
    }

    void begin() {
        auto self = shared_from_this();
        selfKeepAlive_ = self;
        tunnel_ = SharedWGTunnel::acquire(node_, cfg_, factory_);
        localPort_ = tunnel_->allocatePort();
        std::weak_ptr<WireGuardUDPDatagram> weak = self;
        auto dgramFactory = factory_;
        tunnel_->registerUDP(localPort_, [weak, dgramFactory](const Buffer &ipPkt) {
            dgramFactory->post([weak, ipPkt]() {
                if (auto s = weak.lock()) s->onIPv4Packet(ipPkt);
            });
        });
        factory_->after(10, [weak] {
            if (auto s = weak.lock(); s && s->ready_) s->fail("WireGuard handshake timed out");
        });
        tunnel_->ensureConnected([self](Error err) {
            self->factory_->post([self, err = std::move(err)]() mutable {
                if (self->closed_) return;
                if (!err.empty()) {
                    self->fail(std::move(err));
                    return;
                }
                self->established_ = true;
                auto keep = std::move(self->selfKeepAlive_);
                if (auto cb = std::exchange(self->ready_, {})) cb(self, {});
            });
        });
    }

    void send(Target target, Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        factory_->post([self, target = std::move(target), data = std::move(data), completion = std::move(completion)]() mutable {
            if (self->closed_ || !self->established_ || !self->tunnel_) {
                completion(self->terminal_.empty() ? "WireGuard UDP session closed" : self->terminal_);
                return;
            }
            if (data.size() > 65000) { completion("WireGuard UDP payload too large"); return; }
            std::array<uint8_t, 16> dstIPv6{};
            if (tryParseIPv6CIDR(target.host, dstIPv6)) {
                if (!self->cfg_.hasSelfIPv6) {
                    completion("WireGuard IPv6 target requires ipv6/self-ip-v6 configuration");
                    return;
                }
                auto ipPkt = buildIPv6UDPPacket(self->cfg_.selfIPv6, self->localPort_, dstIPv6, target.port, data);
                self->tunnel_->sendIPPacket(ipPkt, std::move(completion));
                return;
            }
            self->tunnel_->resolveHostIPv4(target.host, [self, port = target.port, data = std::move(data), completion = std::move(completion)](uint32_t dstIPNet, Error dnsErr) mutable {
                if (self->closed_) { completion("WireGuard UDP session closed"); return; }
                if (!dnsErr.empty()) { completion(std::move(dnsErr)); return; }
                auto ipPkt = buildIPv4UDPPacket(self->cfg_.selfIPv4, self->localPort_, dstIPNet, port, data);
                self->tunnel_->sendIPPacket(ipPkt, std::move(completion));
            });
        });
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        auto self = shared_from_this();
        factory_->post([self, receive = std::move(receive), failure = std::move(failure)]() mutable {
            if (self->closed_) { failure(self->terminal_.empty() ? "WireGuard session closed" : self->terminal_); return; }
            self->receive_ = std::move(receive);
            self->failure_ = std::move(failure);
        });
    }

    void close() override {
        auto self = shared_from_this();
        factory_->post([self] { self->fail({}); });
    }

private:
    Node node_;
    WGConfig cfg_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<SharedWGTunnel> tunnel_;
    std::shared_ptr<WireGuardUDPDatagram> selfKeepAlive_;
    DatagramCallback ready_;
    PacketCallback receive_;
    WriteCallback failure_;
    uint16_t localPort_ = 0;
    bool established_ = false;
    bool closed_ = false;
    Error terminal_;

    void onIPv4Packet(const Buffer &ipPkt) {
        if (closed_ || !receive_ || ipPkt.size() < 20) return;
        uint8_t ver = ipPkt[0] >> 4;
        if (ver == 6) {
            if (ipPkt.size() < 48 || ipPkt[6] != 17) return;
            const uint8_t *udp = ipPkt.data() + 40;
            uint16_t srcPort = readBE16(udp);
            uint16_t udpLen = readBE16(udp + 4);
            if (udpLen < 8 || ipPkt.size() < 40 + size_t(udpLen)) return;
            Buffer payload(udp + 8, udp + udpLen);
            char hostBuf[INET6_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET6, ipPkt.data() + 8, hostBuf, sizeof(hostBuf))) {
                receive_({hostBuf, srcPort, true, false}, std::move(payload));
            }
            return;
        }
        uint8_t ihl = (ipPkt[0] & 0x0F) * 4;
        if (ipPkt[9] != 17 || ipPkt.size() < size_t(ihl + 8)) return;
        uint32_t srcIPNet = 0;
        std::memcpy(&srcIPNet, ipPkt.data() + 12, 4);
        const uint8_t *udp = ipPkt.data() + ihl;
        uint16_t srcPort = readBE16(udp);
        uint16_t udpLen = readBE16(udp + 4);
        if (udpLen < 8 || ipPkt.size() < ihl + udpLen) return;
        Buffer payload(udp + 8, udp + udpLen);
        char hostBuf[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &srcIPNet, hostBuf, sizeof(hostBuf))) {
            receive_({hostBuf, srcPort, true, false}, std::move(payload));
        }
    }

    void fail(Error err) {
        if (closed_) return;
        closed_ = true;
        terminal_ = std::move(err);
        if (tunnel_ && localPort_) tunnel_->unregisterUDP(localPort_);
        auto keep = std::move(selfKeepAlive_);
        if (auto r = std::exchange(ready_, {})) r({}, terminal_.empty() ? "WireGuard session closed" : terminal_);
        if (auto f = std::exchange(failure_, {})) {
            if (!terminal_.empty()) f(terminal_);
        }
        receive_ = {};
    }
};

class WireGuardTCPStream final : public Stream, public std::enable_shared_from_this<WireGuardTCPStream> {
public:
    WireGuardTCPStream(Node node, WGConfig cfg, Target target,
                       std::shared_ptr<TransportFactory> factory, StreamCallback completion)
        : node_(std::move(node)), cfg_(std::move(cfg)), target_(std::move(target)),
          factory_(std::move(factory)), completion_(std::move(completion)) {
        auto rp = crypto::randomBytes(4);
        sndNxt_ = readBE32(rp.data());
        sndUna_ = sndNxt_;
    }

    ~WireGuardTCPStream() override {
        closed_ = true;
        if (tunnel_ && localPort_) tunnel_->unregisterTCP(localPort_);
    }

    void start() {
        auto self = shared_from_this();
        selfKeepAlive_ = self;
        tunnel_ = SharedWGTunnel::acquire(node_, cfg_, factory_);
        localPort_ = tunnel_->allocatePort();
        std::weak_ptr<WireGuardTCPStream> weak = self;
        auto streamFactory = factory_;
        tunnel_->registerTCP(localPort_, [weak, streamFactory](const Buffer &ipPkt) {
            streamFactory->post([weak, ipPkt]() {
                if (auto s = weak.lock()) s->onIPv4Packet(ipPkt);
            });
        });
        factory_->after(12, [weak] {
            if (auto s = weak.lock(); s && s->completion_) s->fail("WireGuard TCP connect timed out");
        });
        tunnel_->ensureConnected([self](Error err) {
            self->factory_->post([self, err = std::move(err)]() mutable {
                if (self->closed_) return;
                if (!err.empty()) {
                    self->fail(std::move(err));
                    return;
                }
                self->beginTargetConnect();
            });
        });
    }

    void write(Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        factory_->post([self, data = std::move(data), completion = std::move(completion)]() mutable {
            if (self->closed_ || self->tcpState_ != TCPState::Established) {
                completion(self->terminal_.empty() ? "WireGuard TCP stream closed" : self->terminal_);
                return;
            }
            if (data.size() > maximumQueuedBytes - self->queuedWriteBytes_) {
                completion("WireGuard TCP write queue exceeded");
                return;
            }
            if (data.empty()) { completion({}); return; }
            self->queuedWriteBytes_ += data.size();
            size_t off = 0;
            size_t mss = std::min<size_t>(1240, self->peerMSS_);
            while (off < data.size()) {
                size_t chunk = std::min<size_t>(mss, data.size() - off);
                self->unsent_.emplace_back(data.begin() + off, data.begin() + off + chunk);
                off += chunk;
            }
            self->flushSendQueue();
            self->queuedWriteBytes_ -= data.size();
            completion({});
        });
    }

    void read(size_t maximum, ReadCallback completion) override {
        auto self = shared_from_this();
        factory_->post([self, maximum, completion = std::move(completion)]() mutable {
            if (!maximum || maximum > maximumReadBytes) {
                completion({}, false, "Invalid WireGuard read bound");
                return;
            }
            if (self->pendingRead_) {
                completion({}, false, "Overlapping WireGuard TCP read");
                return;
            }
            self->readMax_ = maximum;
            self->pendingRead_ = std::move(completion);
            self->deliverRead();
        });
    }

    void shutdownWrite(WriteCallback completion) override {
        auto self = shared_from_this();
        factory_->post([self, completion = std::move(completion)]() mutable {
            if (self->closed_) { completion(self->terminal_); return; }
            if (!self->finQueued_ && self->tcpState_ == TCPState::Established) {
                self->finQueued_ = true;
                self->flushSendQueue();
            }
            completion({});
        });
    }

    bool supportsHalfClose() const override { return true; }

    void close() override {
        auto self = shared_from_this();
        factory_->post([self] { self->fail("WireGuard stream closed"); });
    }

private:
    enum class TCPState { WGHandshake, DNSResolve, SynSent, Established, Closed };
    struct UnackedSeg {
        uint32_t seq;
        Buffer data;
        uint32_t retries = 0;
        bool sacked = false;
        std::chrono::steady_clock::time_point txTime;
    };

    Node node_;
    WGConfig cfg_;
    Target target_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<SharedWGTunnel> tunnel_;
    std::shared_ptr<WireGuardTCPStream> selfKeepAlive_;
    StreamCallback completion_;
    TCPState tcpState_ = TCPState::WGHandshake;
    uint32_t dstIPNet_ = 0;
    std::array<uint8_t, 16> dstIPv6_{};
    bool isIPv6Target_ = false;
    uint16_t localPort_ = 0;
    uint32_t sndUna_ = 0;
    uint32_t sndNxt_ = 0;
    uint32_t rcvNxt_ = 0;
    uint32_t finSeq_ = 0;
    uint32_t synRetries_ = 0;
    uint16_t peerMSS_ = 1240;
    uint8_t peerWScale_ = 0;
    bool hasWindowScale_ = false;
    bool peerSackPermitted_ = false;
    uint32_t peerRwnd_ = 65535;
    uint32_t cwnd_ = 10 * 1240;
    uint32_t ssthresh_ = 64 * 1024;
    uint32_t dupAckCount_ = 0;
    double srtt_ = 0.0;
    double rttvar_ = 0.0;
    double rto_ = 0.5;
    std::chrono::steady_clock::time_point synTxTime_{};
    std::deque<Buffer> unsent_;
    std::deque<UnackedSeg> unacked_;
    std::map<uint32_t, Buffer> outOfOrder_;
    proto_common::CursorBuffer recvBuf_;
    size_t queuedWriteBytes_ = 0;
    size_t readMax_ = 0;
    ReadCallback pendingRead_;
    bool retransmitScheduled_ = false;
    bool finQueued_ = false;
    bool finSent_ = false;
    bool finReceived_ = false;
    bool rcvEOF_ = false;
    bool closed_ = false;
    Error terminal_;

    // RFC 6298 RTT estimator update
    void updateRTT(double rttSample) {
        if (rttSample <= 0.0 || rttSample > 60.0) return;
        if (srtt_ == 0.0) {
            srtt_ = rttSample;
            rttvar_ = rttSample * 0.5;
        } else {
            rttvar_ = 0.75 * rttvar_ + 0.25 * std::fabs(srtt_ - rttSample);
            srtt_ = 0.875 * srtt_ + 0.125 * rttSample;
        }
        rto_ = std::clamp(srtt_ + std::max(0.01, 4.0 * rttvar_), 0.2, 60.0);
    }

    uint16_t advertisedWindow() const {
        size_t buffered = recvBuf_.size();
        size_t avail = buffered < kReceiveWindowMax ? (kReceiveWindowMax - buffered) : 0;
        if (hasWindowScale_) {
            size_t scaled = avail >> kLocalWindowScale;
            return uint16_t(std::min<size_t>(65535, scaled));
        }
        return uint16_t(std::min<size_t>(65535, avail));
    }

    std::vector<TCPSackBlock> buildSackBlocks() const {
        std::vector<TCPSackBlock> blocks;
        if (!peerSackPermitted_ || outOfOrder_.empty()) return blocks;
        for (const auto &kv : outOfOrder_) {
            uint32_t start = kv.first;
            uint32_t end = start + uint32_t(kv.second.size());
            if (!blocks.empty() && int32_t(start - blocks.back().rightEdge) <= 0) {
                if (int32_t(end - blocks.back().rightEdge) > 0) {
                    blocks.back().rightEdge = end;
                }
            } else {
                blocks.push_back({start, end});
                if (blocks.size() >= 3) break;
            }
        }
        return blocks;
    }

    uint32_t inFlightBytes() const {
        return uint32_t(sndNxt_ - sndUna_);
    }

    void flushSendQueue() {
        if (closed_ || tcpState_ != TCPState::Established) return;
        bool wasEmpty = unacked_.empty();
        uint32_t sendWnd = std::max<uint32_t>(peerMSS_, std::min(cwnd_, peerRwnd_));
        while (!unsent_.empty()) {
            const auto &seg = unsent_.front();
            if (!unacked_.empty() && inFlightBytes() + uint32_t(seg.size()) > sendWnd) {
                break;
            }
            uint32_t seq = sndNxt_;
            sndNxt_ += uint32_t(seg.size());
            unacked_.push_back({seq, seg, 0, false, std::chrono::steady_clock::now()});
            sendTCPSegment(seq, rcvNxt_, 0x18 /* PSH|ACK */, seg, false);
            unsent_.pop_front();
        }
        if (finQueued_ && !finSent_ && unsent_.empty()) {
            finSent_ = true;
            uint32_t seq = sndNxt_++;
            sendTCPSegment(seq, rcvNxt_, 0x11 /* FIN|ACK */, {}, false);
        }
        if (wasEmpty && !unacked_.empty()) {
            scheduleRetransmit();
        }
    }

    void beginTargetConnect() {
        if (closed_ || !tunnel_) return;
        if (tryParseIPv6CIDR(target_.host, dstIPv6_)) {
            if (!cfg_.hasSelfIPv6) {
                fail("WireGuard IPv6 target requires ipv6/self-ip-v6 configuration");
                return;
            }
            isIPv6Target_ = true;
            peerMSS_ = 1220;
            sendSyn();
            return;
        }
        tcpState_ = TCPState::DNSResolve;
        auto self = shared_from_this();
        tunnel_->resolveHostIPv4(target_.host, [self](uint32_t ipNet, Error err) {
            self->factory_->post([self, ipNet, err = std::move(err)]() mutable {
                if (self->closed_) return;
                if (!err.empty() || !ipNet) {
                    if (self->cfg_.hasSelfIPv6 && self->tunnel_) {
                        self->tunnel_->resolveHostIPv6(self->target_.host, [self](std::array<uint8_t, 16> ip6, Error err6) {
                            self->factory_->post([self, ip6, err6 = std::move(err6)]() mutable {
                                if (self->closed_) return;
                                if (!err6.empty()) {
                                    self->fail(std::move(err6));
                                    return;
                                }
                                self->dstIPv6_ = ip6;
                                self->isIPv6Target_ = true;
                                self->peerMSS_ = 1220;
                                self->sendSyn();
                            });
                        });
                        return;
                    }
                    self->fail(err.empty() ? "WireGuard in-tunnel DNS resolution failed" : std::move(err));
                    return;
                }
                self->dstIPNet_ = ipNet;
                self->sendSyn();
            });
        });
    }

    void sendSyn() {
        tcpState_ = TCPState::SynSent;
        synTxTime_ = std::chrono::steady_clock::now();
        sendTCPSegment(sndUna_, 0, 0x02 /* SYN */, {}, true);
        scheduleRetransmit();
    }

    void scheduleRetransmit() {
        if (closed_ || retransmitScheduled_) return;
        retransmitScheduled_ = true;
        double delay = std::clamp(rto_, 0.2, 60.0);
        std::weak_ptr<WireGuardTCPStream> weak = shared_from_this();
        factory_->after(delay, [weak] {
            auto self = weak.lock();
            if (!self) return;
            self->retransmitScheduled_ = false;
            if (self->closed_) return;
            if (self->tcpState_ == TCPState::SynSent) {
                if (++self->synRetries_ > 10) {
                    self->fail("WireGuard TCP connect timed out");
                    return;
                }
                self->rto_ = std::min(60.0, self->rto_ * 2.0);
                self->sendTCPSegment(self->sndUna_, 0, 0x02 /* SYN */, {}, true);
                self->scheduleRetransmit();
            } else if (self->tcpState_ == TCPState::Established && !self->unacked_.empty()) {
                auto &first = self->unacked_.front();
                if (++first.retries > 10) {
                    self->fail("WireGuard TCP retransmission timed out");
                    return;
                }
                // RFC 6298 / RFC 5681 exponential backoff + congestion window collapse on timeout
                self->rto_ = std::min(60.0, self->rto_ * 2.0);
                self->ssthresh_ = std::max<uint32_t>(self->cwnd_ / 2, 2U * self->peerMSS_);
                self->cwnd_ = self->peerMSS_;
                self->sendTCPSegment(first.seq, self->rcvNxt_, 0x18 /* PSH|ACK */, first.data, false);
                self->scheduleRetransmit();
            }
        });
    }

    void sendTCPSegment(uint32_t seq, uint32_t ack, uint8_t flags, const Buffer &payload, bool synOptions) {
        if (closed_ || !tunnel_) return;
        uint16_t wnd = synOptions ? 65535 : advertisedWindow();
        std::vector<TCPSackBlock> sacks = (!synOptions && (flags & 0x10)) ? buildSackBlocks() : std::vector<TCPSackBlock>{};
        Buffer ipPkt = isIPv6Target_
            ? buildIPv6TCPPacket(cfg_.selfIPv6, localPort_, dstIPv6_, target_.port,
                                 seq, ack, flags, payload, synOptions, wnd, sacks)
            : buildIPv4TCPPacket(cfg_.selfIPv4, localPort_, dstIPNet_, target_.port,
                                 seq, ack, flags, payload, synOptions, wnd, sacks);
        tunnel_->sendIPPacket(ipPkt, [](Error) {});
    }

    void onIPv4Packet(const Buffer &ipPkt) {
        if (closed_ || ipPkt.size() < 20) return;
        uint8_t ver = ipPkt[0] >> 4;
        size_t ihl = 0;
        if (isIPv6Target_) {
            if (ver != 6 || ipPkt.size() < 60 || ipPkt[6] != 6) return;
            if (std::memcmp(ipPkt.data() + 8, dstIPv6_.data(), 16) != 0) return;
            ihl = 40;
        } else {
            if (ver != 4) return;
            ihl = size_t(ipPkt[0] & 0x0F) * 4;
            if (ihl < 20 || ipPkt[9] != 6 || ipPkt.size() < ihl + 20) return;
            uint32_t srcIP = 0;
            std::memcpy(&srcIP, ipPkt.data() + 12, 4);
            if (srcIP != dstIPNet_) return;
        }

        const uint8_t *tcp = ipPkt.data() + ihl;
        size_t tcpTotal = ipPkt.size() - ihl;
        uint16_t srcPort = readBE16(tcp);
        uint16_t dstPort = readBE16(tcp + 2);
        if (srcPort != target_.port || dstPort != localPort_) return;
        size_t dataOff = size_t(tcp[12] >> 4) * 4;
        if (dataOff < 20 || tcpTotal < dataOff) return;

        uint32_t seq = readBE32(tcp + 4);
        uint32_t ack = readBE32(tcp + 8);
        uint8_t flags = tcp[13];
        uint16_t rawWindow = readBE16(tcp + 14);
        if (flags & 0x04 /* RST */) {
            fail("WireGuard remote peer reset TCP connection");
            return;
        }

        ParsedTCPOptions parsedOpts;
        if (dataOff > 20) {
            parsedOpts = parseTCPOptions(tcp + 20, dataOff - 20);
        }

        if (tcpState_ == TCPState::SynSent) {
            if ((flags & 0x12) == 0x12 && ack == sndUna_ + 1) {
                if (synRetries_ == 0 && synTxTime_.time_since_epoch().count() > 0) {
                    double rtt = std::chrono::duration<double>(std::chrono::steady_clock::now() - synTxTime_).count();
                    updateRTT(rtt);
                }
                if (parsedOpts.mss >= 536) {
                    peerMSS_ = std::min<uint16_t>(peerMSS_, parsedOpts.mss);
                }
                if (parsedOpts.hasWindowScale) {
                    hasWindowScale_ = true;
                    peerWScale_ = parsedOpts.windowScale;
                }
                peerSackPermitted_ = parsedOpts.sackPermitted;
                peerRwnd_ = hasWindowScale_ ? (uint32_t(rawWindow) << peerWScale_) : uint32_t(rawWindow);
                sndUna_ = ack;
                sndNxt_ = ack;
                rcvNxt_ = seq + 1;
                tcpState_ = TCPState::Established;
                sendTCPSegment(sndNxt_, rcvNxt_, 0x10 /* ACK */, {}, false);
                auto keep = std::move(selfKeepAlive_);
                if (auto cb = std::exchange(completion_, {})) cb(shared_from_this(), {});
            }
            return;
        }

        if (tcpState_ != TCPState::Established) return;

        peerRwnd_ = hasWindowScale_ ? (uint32_t(rawWindow) << peerWScale_) : uint32_t(rawWindow);
        size_t payloadLen = tcpTotal - dataOff;

        if (flags & 0x10 /* ACK */) {
            if (!parsedOpts.sackBlocks.empty()) {
                for (auto &seg : unacked_) {
                    uint32_t segEnd = seg.seq + uint32_t(seg.data.size());
                    for (const auto &blk : parsedOpts.sackBlocks) {
                        if (int32_t(seg.seq - blk.leftEdge) >= 0 && int32_t(segEnd - blk.rightEdge) <= 0) {
                            seg.sacked = true;
                            break;
                        }
                    }
                }
            }
            if (int32_t(ack - sndUna_) > 0) {
                uint32_t ackedBytes = uint32_t(ack - sndUna_);
                sndUna_ = ack;
                dupAckCount_ = 0;
                auto now = std::chrono::steady_clock::now();
                while (!unacked_.empty()) {
                    const auto &front = unacked_.front();
                    if (int32_t(ack - (front.seq + uint32_t(front.data.size()))) >= 0) {
                        if (front.retries == 0 && front.txTime.time_since_epoch().count() > 0) {
                            updateRTT(std::chrono::duration<double>(now - front.txTime).count());
                        }
                        unacked_.pop_front();
                    } else {
                        break;
                    }
                }
                // NewReno congestion window update
                if (cwnd_ < ssthresh_) {
                    cwnd_ += std::min<uint32_t>(ackedBytes, peerMSS_);
                } else {
                    cwnd_ += std::max<uint32_t>(1U, (uint32_t(peerMSS_) * uint32_t(peerMSS_)) / cwnd_);
                }
                flushSendQueue();
            } else if (ack == sndUna_ && payloadLen == 0 && !(flags & 0x01) && !unacked_.empty()) {
                // RFC 5681 3x duplicate-ACK Fast Retransmit & Fast Recovery
                if (++dupAckCount_ == 3) {
                    ssthresh_ = std::max<uint32_t>(cwnd_ / 2, 2U * peerMSS_);
                    cwnd_ = ssthresh_ + 3U * peerMSS_;
                    auto &first = unacked_.front();
                    ++first.retries;
                    sendTCPSegment(first.seq, rcvNxt_, 0x18 /* PSH|ACK */, first.data, false);
                } else if (dupAckCount_ > 3) {
                    cwnd_ += peerMSS_;
                    flushSendQueue();
                }
            }
        }

        if (payloadLen > 0) {
            Buffer segData(tcp + dataOff, tcp + dataOff + payloadLen);
            if (seq == rcvNxt_) {
                recvBuf_.append(segData);
                rcvNxt_ += uint32_t(payloadLen);
                while (!outOfOrder_.empty()) {
                    auto it = outOfOrder_.begin();
                    if (int32_t(it->first - rcvNxt_) <= 0) {
                        uint32_t endSeq = it->first + uint32_t(it->second.size());
                        if (int32_t(endSeq - rcvNxt_) > 0) {
                            size_t skip = rcvNxt_ - it->first;
                            recvBuf_.append(it->second.data() + skip, it->second.size() - skip);
                            rcvNxt_ = endSeq;
                        }
                        outOfOrder_.erase(it);
                    } else {
                        break;
                    }
                }
            } else if (int32_t(seq - rcvNxt_) > 0 && outOfOrder_.size() < 512) {
                outOfOrder_[seq] = std::move(segData);
            }
        }

        if (flags & 0x01 /* FIN */) {
            finReceived_ = true;
            finSeq_ = seq + uint32_t(payloadLen);
        }
        if (finReceived_ && !rcvEOF_ && rcvNxt_ == finSeq_) {
            rcvNxt_ += 1;
            rcvEOF_ = true;
        }

        if (payloadLen > 0 || (flags & 0x01)) {
            sendTCPSegment(sndNxt_, rcvNxt_, 0x10 /* ACK */, {}, false);
            deliverRead();
        }
    }

    void deliverRead() {
        if (!pendingRead_) return;
        if (recvBuf_.empty() && !rcvEOF_ && !closed_) return;
        Buffer out = recvBuf_.consume(readMax_);
        bool eof = (rcvEOF_ || closed_) && recvBuf_.empty();
        auto cb = std::exchange(pendingRead_, {});
        cb(std::move(out), eof, closed_ && !rcvEOF_ ? terminal_ : Error{});
    }

    void fail(Error err) {
        if (closed_) return;
        closed_ = true;
        if (tcpState_ == TCPState::Established && tunnel_ && !finSent_) {
            sendTCPSegment(sndNxt_, rcvNxt_, 0x14 /* RST|ACK */, {}, false);
        }
        tcpState_ = TCPState::Closed;
        terminal_ = std::move(err);
        if (tunnel_ && localPort_) tunnel_->unregisterTCP(localPort_);
        unsent_.clear();
        unacked_.clear();
        outOfOrder_.clear();
        auto keep = std::move(selfKeepAlive_);
        if (auto c = std::exchange(completion_, {})) c({}, terminal_);
        deliverRead();
    }
};

} // namespace

void resetWireGuardClient(const std::shared_ptr<TransportFactory> &factory) {
    SharedWGTunnel::resetForFactory(factory);
}

Error validateWireGuard(const Node &node, bool) {
    if (node.type != "wireguard") return "Invalid WireGuard protocol type";
    if (node.host.empty() || !node.port) return "WireGuard requires server and port";
    try {
        (void)parseWGConfig(node);
    } catch (const std::exception &e) {
        return e.what();
    }
    return {};
}

void connectWireGuard(const Node &node, const Target &target,
                      std::shared_ptr<TransportFactory> factory,
                      StreamCallback completion) {
    if (auto err = validateWireGuard(node, false); !err.empty()) {
        completion({}, std::move(err));
        return;
    }
    if (!factory || !factory->udp || !factory->post || !factory->after) {
        completion({}, "WireGuard platform UDP transport is unavailable");
        return;
    }
    if (target.host.empty() || !target.port) {
        completion({}, "Invalid WireGuard TCP destination");
        return;
    }
    WGConfig cfg;
    try { cfg = parseWGConfig(node); }
    catch (const std::exception &e) { completion({}, e.what()); return; }
    factory->post([node, cfg = std::move(cfg), target, factory, completion = std::move(completion)]() mutable {
        std::make_shared<WireGuardTCPStream>(std::move(node), std::move(cfg), target, factory, std::move(completion))->start();
    });
}

void makeWireGuardDatagram(const Node &node,
                           std::shared_ptr<TransportFactory> factory,
                           DatagramCallback completion) {
    if (auto err = validateWireGuard(node, true); !err.empty()) {
        completion({}, std::move(err));
        return;
    }
    if (!factory || !factory->udp || !factory->post || !factory->after) {
        completion({}, "WireGuard platform UDP transport is unavailable");
        return;
    }
    WGConfig cfg;
    try { cfg = parseWGConfig(node); }
    catch (const std::exception &e) { completion({}, e.what()); return; }
    factory->post([node, cfg = std::move(cfg), factory, completion = std::move(completion)]() mutable {
        std::make_shared<WireGuardUDPDatagram>(std::move(node), std::move(cfg), factory, std::move(completion))->begin();
    });
}

bool wireGuardProtocolSelfTest() {
    try {
        // 1. RFC 7693 BLAKE2s-256 empty string & non-empty "abc" known-answer checks
        auto emptyDigest = blake2s(nullptr, 0, 32);
        static const uint8_t expectedEmpty[32] = {
            0x69,0x21,0x7a,0x30,0x79,0x90,0x80,0x94,0xe1,0x11,0x21,0xd0,0x42,0x35,0x4a,0x7c,
            0x1f,0x55,0xb6,0x48,0x2c,0xa1,0xa5,0x1e,0x1b,0x25,0x0d,0xfd,0x1e,0xd0,0xee,0xf9
        };
        if (emptyDigest.size() != 32 || std::memcmp(emptyDigest.data(), expectedEmpty, 32) != 0)
            return false;

        auto abcDigest = blake2s("abc", 3, 32);
        static const uint8_t expectedAbc[32] = {
            0x50,0x8c,0x5e,0x8c,0x32,0x7c,0x14,0xe2,0xe1,0xa7,0x2b,0xa3,0x4e,0xeb,0x45,0x2f,
            0x37,0x45,0x8b,0x20,0x9e,0xd6,0x3a,0x29,0x4d,0x99,0x9b,0x4c,0x86,0x67,0x59,0x82
        };
        if (abcDigest.size() != 32 || std::memcmp(abcDigest.data(), expectedAbc, 32) != 0)
            return false;

        // 2. X25519 + Noise_IKpsk2 Initiation & Transport Packet round-trip
        Node node;
        node.type = "wireguard";
        node.host = "127.0.0.1";
        node.port = 51820;
        Buffer cPriv(32, 0x11), sPriv(32, 0x22), psk(32, 0x33);
        cPriv[0] &= 248; cPriv[31] &= 127; cPriv[31] |= 64;
        sPriv[0] &= 248; sPriv[31] &= 127; sPriv[31] |= 64;
        auto sPub = x25519PublicFromPrivate(sPriv);
        node.parameters["private-key"] = crypto::base64Encode(cPriv);
        node.parameters["public-key"] = crypto::base64Encode(sPub);
        node.parameters["pre-shared-key"] = crypto::base64Encode(psk);
        node.parameters["ip"] = "100.64.0.2/32";
        if (!validateWireGuard(node, false).empty() || !validateWireGuard(node, true).empty())
            return false;

        auto cfg = parseWGConfig(node);
        if (cfg.hasSelfIPv6) return false;
        node.parameters["ipv6"] = "2606:4700:110::2/128";
        cfg = parseWGConfig(node);
        if (!cfg.hasSelfIPv6) return false;
        WGHandshakeState hs;
        auto initPkt = buildHandshakeInitiation(cfg, hs);
        if (initPkt.size() != 148 || initPkt[0] != 1) return false;

        hs.serverIndex = 0x99887766U;
        hs.sendKey = Buffer(32, 0x44);
        hs.recvKey = hs.sendKey;
        Buffer payload{'h', 'a', 'j', 'i', 'm', 'i'};
        auto ipUDP = buildIPv4UDPPacket(cfg.selfIPv4, 12345, cfg.dnsIPv4, 53, payload);
        auto wgData = encryptTransportPacket(cfg, hs, ipUDP);
        writeLE32(wgData.data() + 4, hs.clientIndex);
        Buffer decIP;
        if (!decryptTransportPacket(hs, wgData, decIP) || decIP != ipUDP)
            return false;

        std::array<uint8_t, 16> dstV6{};
        if (!tryParseIPv6CIDR("2606:4700:4700::1111", dstV6)) return false;
        auto ip6UDP = buildIPv6UDPPacket(cfg.selfIPv6, 12345, dstV6, 53, payload);
        auto wg6Data = encryptTransportPacket(cfg, hs, ip6UDP);
        writeLE32(wg6Data.data() + 4, hs.clientIndex);
        Buffer decIP6;
        if (!decryptTransportPacket(hs, wg6Data, decIP6) || decIP6 != ip6UDP)
            return false;

        // 2b. Verify RFC 7323 Window Scale + RFC 2018 SACK option encoding & parsing
        auto synPkt = buildIPv4TCPPacket(cfg.selfIPv4, 40000, cfg.dnsIPv4, 443, 100, 0, 0x02, {}, true);
        size_t synOptLen = size_t(synPkt[20 + 12] >> 4) * 4 - 20;
        auto synParsed = parseTCPOptions(synPkt.data() + 40, synOptLen);
        if (synParsed.mss != 1280 || !synParsed.hasWindowScale || synParsed.windowScale != kLocalWindowScale || !synParsed.sackPermitted)
            return false;
        auto sackPkt = buildIPv4TCPPacket(cfg.selfIPv4, 40000, cfg.dnsIPv4, 443, 101, 200, 0x10, {}, false, 16384, {{500, 1500}});
        size_t sackOptLen = size_t(sackPkt[20 + 12] >> 4) * 4 - 20;
        auto sackParsed = parseTCPOptions(sackPkt.data() + 40, sackOptLen);
        if (sackParsed.sackBlocks.size() != 1 || sackParsed.sackBlocks[0].leftEdge != 500 || sackParsed.sackBlocks[0].rightEdge != 1500)
            return false;

        // 3. Regression test for asynchronous WireGuardTCPStream & WireGuardUDPDatagram
        // lifecycle with synchronous Datagram::send (verifying no std::bad_weak_ptr
        // crash when caller holds no external shared_ptr during handshake/SYN).
        std::deque<std::function<void()>> work;
        std::vector<std::function<void()>> timers;
        auto factory = std::make_shared<TransportFactory>();
        factory->post = [&work](std::function<void()> fn) { work.push_back(std::move(fn)); };
        factory->after = [&timers](double, std::function<void()> fn) { timers.push_back(std::move(fn)); };

        class MockWGCarrier final : public Datagram {
        public:
            PacketCallback onRx;
            WriteCallback onFail;
            std::vector<Buffer> sentPackets;
            void send(Target, Buffer data, WriteCallback completion) override {
                sentPackets.push_back(std::move(data));
                // Synchronous completion matching PlatformDatagram::send in HajimiCXXProtocolBridge.mm
                completion({});
            }
            void start(PacketCallback receive, WriteCallback failure) override {
                onRx = std::move(receive);
                onFail = std::move(failure);
            }
            void close() override { onRx = {}; onFail = {}; }
        };

        auto carrier = std::make_shared<MockWGCarrier>();
        factory->udp = [carrier](const Node &, DatagramCallback cb) {
            cb(carrier, {});
        };

        bool tcpFailed = false;
        connectWireGuard(node, Target{"1.1.1.1", 443, false, false}, factory, [&](std::shared_ptr<Stream> s, Error err) {
            if (!s && !err.empty()) tcpFailed = true;
        });
        while (!work.empty()) {
            auto fn = std::move(work.front());
            work.pop_front();
            fn();
        }
        // Carrier must have sent the 148-byte Type-1 Handshake Initiation and
        // WireGuardTCPStream must still be alive waiting for handshake response!
        if (carrier->sentPackets.size() != 1 || carrier->sentPackets[0].size() != 148 || tcpFailed)
            return false;

        // Trigger timeout cleanly and verify no destructor crash
        for (auto &t : timers) {
            if (t) t();
        }
        while (!work.empty()) {
            auto fn = std::move(work.front());
            work.pop_front();
            fn();
        }
        if (!tcpFailed) return false;
        resetWireGuardClient(factory);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
