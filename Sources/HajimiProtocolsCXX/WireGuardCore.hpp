#pragma once
// WireGuard Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s Crypto, Packet & DNS Helpers
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include "Crypto.hpp"
#include <openssl/crypto.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hajimi::wg_detail {

inline uint16_t readBE16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
inline uint32_t readBE32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline uint32_t readLE32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t readLE64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
inline void writeBE16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline void writeBE32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
inline void writeLE32(uint8_t *p, uint8_t v0, uint8_t v1, uint8_t v2, uint8_t v3) {
    p[0] = v0; p[1] = v1; p[2] = v2; p[3] = v3;
}
inline void writeLE32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}
inline void writeLE64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = uint8_t(v >> (8 * i));
}

struct WGConfig {
    Buffer clientPriv;
    Buffer clientPub;
    Buffer serverPub;
    Buffer psk;
    uint32_t selfIPv4 = 0; // Network byte order
    uint32_t dnsIPv4 = 0;  // Network byte order
    std::array<uint8_t, 16> selfIPv6{};
    bool hasSelfIPv6 = false;
    std::array<uint8_t, 16> dnsIPv6{};
    bool hasDnsIPv6 = false;
    std::array<uint8_t, 3> reserved{0, 0, 0};
    size_t mtu = 1420;
    uint32_t keepaliveSeconds = 0;
    ~WGConfig() {
        if (!clientPriv.empty()) OPENSSL_cleanse(clientPriv.data(), clientPriv.size());
        if (!psk.empty()) OPENSSL_cleanse(psk.data(), psk.size());
    }
};

struct WGHandshakeState {
    uint32_t clientIndex = 0;
    uint32_t serverIndex = 0;
    Buffer ephemeralPriv;
    Buffer ephemeralPub;
    Buffer chainingKey;
    Buffer hash;
    Buffer sendKey;
    Buffer recvKey;
    Buffer lastMac1;
    uint64_t sendCounter = 0;
    uint64_t replayMax = 0;
    uint64_t replayBitmap = 0;
    bool replayInit = false;

    bool acceptReplay(uint64_t counter) {
        if (counter >= (1ULL << 60)) return false;
        if (!replayInit) {
            replayInit = true;
            replayMax = counter;
            replayBitmap = 1ULL;
            return true;
        }
        if (counter > replayMax) {
            uint64_t shift = counter - replayMax;
            replayBitmap = (shift >= 64) ? 1ULL : ((replayBitmap << shift) | 1ULL);
            replayMax = counter;
            return true;
        }
        uint64_t diff = replayMax - counter;
        if (diff >= 64) return false;
        uint64_t mask = 1ULL << diff;
        if (replayBitmap & mask) return false;
        replayBitmap |= mask;
        return true;
    }

    ~WGHandshakeState() {
        if (!ephemeralPriv.empty()) OPENSSL_cleanse(ephemeralPriv.data(), ephemeralPriv.size());
        if (!chainingKey.empty()) OPENSSL_cleanse(chainingKey.data(), chainingKey.size());
        if (!sendKey.empty()) OPENSSL_cleanse(sendKey.data(), sendKey.size());
        if (!recvKey.empty()) OPENSSL_cleanse(recvKey.data(), recvKey.size());
    }
};

struct TCPSackBlock {
    uint32_t leftEdge = 0;
    uint32_t rightEdge = 0;
};

struct ParsedTCPOptions {
    uint16_t mss = 0;
    uint8_t windowScale = 0;
    bool hasWindowScale = false;
    bool sackPermitted = false;
    std::vector<TCPSackBlock> sackBlocks;
};

constexpr uint8_t kLocalWindowScale = 7;
constexpr size_t kReceiveWindowMax = 2 * 1024 * 1024;

Buffer blake2s(const void *inData, size_t inLen, size_t outLen = 32,
               const void *keyData = nullptr, size_t keyLen = 0);
Buffer wgHash2(const Buffer &a, const Buffer &b);
Buffer wgMac(const Buffer &key, const uint8_t *data, size_t len);
Buffer hmacBlake2s(const Buffer &key, const Buffer &input);
std::array<Buffer, 3> wgHKDF(const Buffer &chainingKey, const Buffer &input, size_t outputs);
Buffer x25519PublicFromPrivate(const Buffer &priv);
Buffer x25519SharedSecret(const Buffer &priv, const Buffer &peerPub);
Buffer wgNonce(uint64_t counter);
Buffer tai64nNow();
bool tryParseIPv6CIDR(std::string text, std::array<uint8_t, 16> &out);
uint32_t parseIPv4CIDR(std::string text);
std::array<uint8_t, 3> parseReserved(const std::string &raw);
WGConfig parseWGConfig(const Node &node);
Buffer buildHandshakeInitiation(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &cookie = {});
bool consumeCookieReply(const WGConfig &cfg, const Buffer &lastMac1, uint32_t expectedIndex,
                        const Buffer &msg, Buffer &cookieOut);
bool consumeHandshakeResponse(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &msg);
Buffer encryptTransportPacket(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &ipPacket);
bool decryptTransportPacket(WGHandshakeState &hs, const Buffer &pkt, Buffer &ipPacketOut);
uint32_t accumulateChecksumSWAR(const uint8_t *data, size_t len, uint64_t acc = 0) noexcept;
uint16_t ipv4Checksum(const uint8_t *data, size_t len);
uint16_t l4Checksum(uint32_t srcIPNet, uint32_t dstIPNet, uint8_t proto, const uint8_t *seg, size_t segLen);
Buffer buildIPv4UDPPacket(uint32_t srcIPNet, uint16_t srcPort, uint32_t dstIPNet, uint16_t dstPort, const Buffer &payload);
Buffer buildTCPOptions(bool synOptions, uint16_t synMSSValue, const std::vector<TCPSackBlock> &sackBlocks);
ParsedTCPOptions parseTCPOptions(const uint8_t *opts, size_t optLen);
Buffer buildIPv4TCPPacket(uint32_t srcIPNet, uint16_t srcPort, uint32_t dstIPNet, uint16_t dstPort,
                          uint32_t seq, uint32_t ack, uint8_t flags, const Buffer &payload,
                          bool synOptions = false, uint16_t windowSize = 65535,
                          const std::vector<TCPSackBlock> &sackBlocks = {});
uint16_t l4ChecksumIPv6(const std::array<uint8_t, 16> &srcIP, const std::array<uint8_t, 16> &dstIP,
                        uint8_t nextHdr, const uint8_t *seg, size_t segLen);
Buffer buildIPv6UDPPacket(const std::array<uint8_t, 16> &srcIP, uint16_t srcPort,
                          const std::array<uint8_t, 16> &dstIP, uint16_t dstPort, const Buffer &payload);
Buffer buildIPv6TCPPacket(const std::array<uint8_t, 16> &srcIP, uint16_t srcPort,
                          const std::array<uint8_t, 16> &dstIP, uint16_t dstPort,
                          uint32_t seq, uint32_t ack, uint8_t flags, const Buffer &payload,
                          bool synOptions = false, uint16_t windowSize = 65535,
                          const std::vector<TCPSackBlock> &sackBlocks = {});
Buffer buildDNSQuery(const std::string &domain, uint16_t txid, uint16_t qtype);
Buffer buildDNSQueryA(const std::string &domain, uint16_t txid);
bool decodeDNSName(const Buffer &resp, size_t &pos, std::string &nameOut);
std::string normalizeDNSQueryHost(const std::string &host);
bool parseDNSAnswerAAAA(const Buffer &resp, uint16_t expectedTxid, std::array<uint8_t, 16> &ipv6Out,
                        const std::string &expectedHost = {}, uint32_t *ttlOut = nullptr);
bool parseDNSAnswerA(const Buffer &resp, uint16_t expectedTxid, uint32_t &ipv4NetOut,
                     const std::string &expectedHost = {}, uint32_t *ttlOut = nullptr);

} // namespace hajimi::wg_detail
