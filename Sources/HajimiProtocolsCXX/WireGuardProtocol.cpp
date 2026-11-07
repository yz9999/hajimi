#include "WireGuardProtocol.hpp"
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include "Crypto.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
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

uint16_t readBE16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
uint32_t readBE32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
uint32_t readLE32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
uint64_t readLE64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
void writeBE16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
void writeBE32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
void writeLE32(uint8_t *p, uint8_t v0, uint8_t v1, uint8_t v2, uint8_t v3) {
    p[0] = v0; p[1] = v1; p[2] = v2; p[3] = v3;
}
void writeLE32(uint8_t *p, uint32_t v) {
    writeLE32(p, uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24));
}
void writeLE64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = uint8_t(v >> (i * 8));
}
uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

// RFC 7693 BLAKE2s (1..32 byte output, optional 0..32 byte key)
Buffer blake2s(const void *inData, size_t inLen, size_t outLen = 32,
               const void *keyData = nullptr, size_t keyLen = 0) {
    static const uint32_t iv[8] = {
        0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
        0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
    };
    static const uint8_t sigma[10][16] = {
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
    };
    if (outLen == 0 || outLen > 32 || keyLen > 32)
        throw std::runtime_error("Invalid BLAKE2s parameters");
    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = iv[i];
    h[0] ^= 0x01010000U ^ (uint32_t(keyLen) << 8) ^ uint32_t(outLen);
    uint64_t t = 0;

    auto compress = [&](const uint8_t *block, bool last) {
        uint32_t v[16], m[16];
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[i + 8] = iv[i]; }
        v[12] ^= uint32_t(t);
        v[13] ^= uint32_t(t >> 32);
        if (last) v[14] = ~v[14];
        for (int i = 0; i < 16; ++i) m[i] = readLE32(block + i * 4);
        auto G = [&](int a, int b, int c, int d, uint32_t x, uint32_t y) {
            v[a] = v[a] + v[b] + x; v[d] = rotr32(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];     v[b] = rotr32(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y; v[d] = rotr32(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];     v[b] = rotr32(v[b] ^ v[c], 7);
        };
        for (int r = 0; r < 10; ++r) {
            const uint8_t *s = sigma[r];
            G(0, 4,  8, 12, m[s[0]],  m[s[1]]);
            G(1, 5,  9, 13, m[s[2]],  m[s[3]]);
            G(2, 6, 10, 14, m[s[4]],  m[s[5]]);
            G(3, 7, 11, 15, m[s[6]],  m[s[7]]);
            G(0, 5, 10, 15, m[s[8]],  m[s[9]]);
            G(1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(2, 7,  8, 13, m[s[12]], m[s[13]]);
            G(3, 4,  9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
    };

    const auto *inBytes = static_cast<const uint8_t *>(inData);
    if (keyLen > 0) {
        uint8_t keyBlock[64]{};
        std::memcpy(keyBlock, keyData, keyLen);
        if (inLen == 0) {
            t = 64;
            compress(keyBlock, true);
            uint8_t raw[32];
            for (int i = 0; i < 8; ++i) writeLE32(raw + i * 4, h[i]);
            return Buffer(raw, raw + outLen);
        }
        t = 64;
        compress(keyBlock, false);
    }

    size_t offset = 0;
    while (inLen - offset > 64) {
        t += 64;
        compress(inBytes + offset, false);
        offset += 64;
    }
    uint8_t lastBlock[64]{};
    size_t rem = inLen - offset;
    if (rem > 0 && inBytes) std::memcpy(lastBlock, inBytes + offset, rem);
    t += rem;
    compress(lastBlock, true);

    uint8_t raw[32];
    for (int i = 0; i < 8; ++i) writeLE32(raw + i * 4, h[i]);
    return Buffer(raw, raw + outLen);
}

Buffer wgHash(const Buffer &a) { return blake2s(a.data(), a.size(), 32); }
Buffer wgHash2(const Buffer &a, const Buffer &b) {
    const size_t total = a.size() + b.size();
    if (total <= 192) {
        uint8_t stackBuf[192];
        if (!a.empty()) std::memcpy(stackBuf, a.data(), a.size());
        if (!b.empty()) std::memcpy(stackBuf + a.size(), b.data(), b.size());
        auto out = blake2s(stackBuf, total, 32);
        OPENSSL_cleanse(stackBuf, total);
        return out;
    }
    Buffer m; m.reserve(total);
    m.insert(m.end(), a.begin(), a.end());
    m.insert(m.end(), b.begin(), b.end());
    return wgHash(m);
}
Buffer wgMac(const Buffer &key, const uint8_t *data, size_t len) {
    return blake2s(data, len, 16, key.data(), key.size());
}

// RFC 2104 HMAC-BLAKE2s (64-byte block size, 32-byte output) using stack buffers
Buffer hmacBlake2s(const Buffer &key, const Buffer &input) {
    uint8_t kPad[64]{};
    if (key.size() > 64) {
        auto hashed = wgHash(key);
        std::memcpy(kPad, hashed.data(), hashed.size());
        OPENSSL_cleanse(hashed.data(), hashed.size());
    } else if (!key.empty()) {
        std::memcpy(kPad, key.data(), key.size());
    }
    Buffer innerHash;
    if (input.size() <= 128) {
        uint8_t innerStack[192];
        for (size_t i = 0; i < 64; ++i) innerStack[i] = kPad[i] ^ 0x36;
        if (!input.empty()) std::memcpy(innerStack + 64, input.data(), input.size());
        innerHash = blake2s(innerStack, 64 + input.size(), 32);
        OPENSSL_cleanse(innerStack, 64 + input.size());
    } else {
        Buffer inner(64 + input.size());
        for (size_t i = 0; i < 64; ++i) inner[i] = kPad[i] ^ 0x36;
        std::memcpy(inner.data() + 64, input.data(), input.size());
        innerHash = wgHash(inner);
        OPENSSL_cleanse(inner.data(), inner.size());
    }
    uint8_t outerStack[96];
    for (size_t i = 0; i < 64; ++i) outerStack[i] = kPad[i] ^ 0x5c;
    std::memcpy(outerStack + 64, innerHash.data(), 32);
    auto result = blake2s(outerStack, 96, 32);
    OPENSSL_cleanse(kPad, sizeof(kPad));
    OPENSSL_cleanse(outerStack, sizeof(outerStack));
    OPENSSL_cleanse(innerHash.data(), innerHash.size());
    return result;
}

std::array<Buffer, 3> wgHKDF(const Buffer &chainingKey, const Buffer &input, size_t outputs) {
    auto temp = hmacBlake2s(chainingKey, input);
    auto out1 = hmacBlake2s(temp, Buffer{0x01});
    if (outputs == 1) return {out1, {}, {}};
    Buffer in2 = out1; in2.push_back(0x02);
    auto out2 = hmacBlake2s(temp, in2);
    if (outputs == 2) return {out1, out2, {}};
    Buffer in3 = out2; in3.push_back(0x03);
    auto out3 = hmacBlake2s(temp, in3);
    return {out1, out2, out3};
}

Buffer x25519PublicFromPrivate(const Buffer &priv) {
    if (priv.size() != 32) throw std::runtime_error("Invalid X25519 private key length");
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    if (!pkey) throw std::runtime_error("Cannot create X25519 private key");
    Buffer pub(32);
    size_t pubLen = 32;
    bool ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pubLen) == 1 && pubLen == 32;
    EVP_PKEY_free(pkey);
    if (!ok) throw std::runtime_error("Cannot derive X25519 public key");
    return pub;
}

Buffer x25519SharedSecret(const Buffer &priv, const Buffer &peerPub) {
    if (priv.size() != 32 || peerPub.size() != 32)
        throw std::runtime_error("Invalid X25519 key size");
    EVP_PKEY *myKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    EVP_PKEY *theirKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPub.data(), 32);
    if (!myKey || !theirKey) {
        if (myKey) EVP_PKEY_free(myKey);
        if (theirKey) EVP_PKEY_free(theirKey);
        throw std::runtime_error("Cannot load X25519 keys");
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(myKey, nullptr);
    Buffer shared(32);
    size_t sharedLen = 32;
    bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, theirKey) == 1 &&
              EVP_PKEY_derive(ctx, shared.data(), &sharedLen) == 1 && sharedLen == 32;
    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(myKey);
    EVP_PKEY_free(theirKey);
    if (!ok) throw std::runtime_error("X25519 DH failed");
    bool allZero = std::all_of(shared.begin(), shared.end(), [](uint8_t b) { return b == 0; });
    if (allZero) throw std::runtime_error("X25519 rejected low-order public key");
    return shared;
}

Buffer wgNonce(uint64_t counter) {
    Buffer n(12, 0);
    writeLE64(n.data() + 4, counter);
    return n;
}

// Monotonically increasing TAI64N timestamp so rapid handshakes are never
// dropped by Linux kernel WireGuard's peer->latest_timestamp anti-replay check.
Buffer tai64nNow() {
    static std::mutex tsMutex;
    static uint64_t lastSecs = 0;
    static uint32_t lastNano = 0;
    using namespace std::chrono;
    auto now = system_clock::now().time_since_epoch();
    auto secs = duration_cast<seconds>(now);
    auto nsecs = duration_cast<nanoseconds>(now - secs);
    uint64_t taiSecs = 0x400000000000000aULL + uint64_t(secs.count());
    uint32_t taiNano = uint32_t(nsecs.count());
    {
        std::lock_guard<std::mutex> lock(tsMutex);
        if (taiSecs < lastSecs || (taiSecs == lastSecs && taiNano <= lastNano)) {
            taiSecs = lastSecs;
            taiNano = lastNano + 1;
            if (taiNano >= 1000000000U) {
                taiNano = 0;
                ++taiSecs;
            }
        }
        lastSecs = taiSecs;
        lastNano = taiNano;
    }
    Buffer out(12);
    writeBE32(out.data(), uint32_t(taiSecs >> 32));
    writeBE32(out.data() + 4, uint32_t(taiSecs));
    writeBE32(out.data() + 8, taiNano);
    return out;
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
    std::array<uint8_t, 3> reserved{0, 0, 0};
    size_t mtu = 1420;
    ~WGConfig() {
        if (!clientPriv.empty()) OPENSSL_cleanse(clientPriv.data(), clientPriv.size());
        if (!psk.empty()) OPENSSL_cleanse(psk.data(), psk.size());
    }
};

bool tryParseIPv6CIDR(std::string text, std::array<uint8_t, 16> &out) {
    auto slash = text.find('/');
    if (slash != std::string::npos) text = text.substr(0, slash);
    auto semi = text.find(';');
    if (semi != std::string::npos) text = text.substr(0, semi);
    auto comma = text.find(',');
    if (comma != std::string::npos) text = text.substr(0, comma);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    text = unbracketAndStripZone(std::move(text));
    in6_addr addr6{};
    if (inet_pton(AF_INET6, text.c_str(), &addr6) != 1) return false;
    std::memcpy(out.data(), &addr6, 16);
    return true;
}

uint32_t parseIPv4CIDR(std::string text) {
    auto slash = text.find('/');
    if (slash != std::string::npos) text = text.substr(0, slash);
    auto semi = text.find(';');
    if (semi != std::string::npos) text = text.substr(0, semi);
    auto comma = text.find(',');
    if (comma != std::string::npos) text = text.substr(0, comma);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1)
        throw std::runtime_error("Invalid WireGuard IPv4 address: " + text);
    return addr.s_addr;
}

std::array<uint8_t, 3> parseReserved(const std::string &raw) {
    if (raw.empty()) return {0, 0, 0};
    if (raw.find(',') != std::string::npos) {
        std::istringstream ss(raw);
        std::string part;
        std::vector<int> vals;
        while (std::getline(ss, part, ',')) {
            vals.push_back(std::stoi(part));
        }
        if (vals.size() != 3 || vals[0] < 0 || vals[0] > 255 ||
            vals[1] < 0 || vals[1] > 255 || vals[2] < 0 || vals[2] > 255)
            throw std::runtime_error("Invalid WireGuard reserved bytes");
        return {uint8_t(vals[0]), uint8_t(vals[1]), uint8_t(vals[2])};
    }
    auto decoded = crypto::base64Decode(raw);
    if (decoded.size() != 3) throw std::runtime_error("WireGuard reserved must be 3 bytes");
    return {decoded[0], decoded[1], decoded[2]};
}

WGConfig parseWGConfig(const Node &node) {
    WGConfig cfg;
    auto privStr = node.option("private-key");
    auto pubStr = node.option("public-key");
    auto ipStr = node.option("ip", node.option("self-ip"));
    if (privStr.empty()) throw std::runtime_error("WireGuard requires private-key");
    if (pubStr.empty()) throw std::runtime_error("WireGuard requires public-key");
    if (ipStr.empty()) throw std::runtime_error("WireGuard requires ip/self-ip");
    cfg.clientPriv = crypto::base64Decode(privStr);
    if (cfg.clientPriv.size() != 32) throw std::runtime_error("WireGuard private-key must be 32 bytes");
    cfg.clientPub = x25519PublicFromPrivate(cfg.clientPriv);
    cfg.serverPub = crypto::base64Decode(pubStr);
    if (cfg.serverPub.size() != 32) throw std::runtime_error("WireGuard public-key must be 32 bytes");
    auto pskStr = node.option("pre-shared-key", node.option("preshared-key"));
    if (!pskStr.empty()) {
        cfg.psk = crypto::base64Decode(pskStr);
        if (cfg.psk.size() != 32) throw std::runtime_error("WireGuard pre-shared-key must be 32 bytes");
    } else {
        cfg.psk = Buffer(32, 0);
    }
    cfg.selfIPv4 = parseIPv4CIDR(ipStr);
    auto ipv6Str = node.option("ipv6", node.option("self-ip-v6"));
    if (!ipv6Str.empty() && tryParseIPv6CIDR(ipv6Str, cfg.selfIPv6)) {
        cfg.hasSelfIPv6 = true;
    } else {
        tryParseIPv6CIDR("fd00:6861:6a69:66::2", cfg.selfIPv6);
    }
    auto dnsStr = node.option("dns", node.option("dns-server", "223.5.5.5"));
    try { cfg.dnsIPv4 = parseIPv4CIDR(dnsStr); }
    catch (...) { cfg.dnsIPv4 = parseIPv4CIDR("223.5.5.5"); }
    cfg.reserved = parseReserved(node.option("reserved"));
    auto mtuStr = node.option("mtu", "1420");
    if (!mtuStr.empty()) {
        int m = std::stoi(mtuStr);
        if (m < 576 || m > 65535) throw std::runtime_error("Invalid WireGuard mtu");
        cfg.mtu = size_t(m);
    }
    return cfg;
}

struct WGHandshakeState {
    uint32_t clientIndex = 0;
    uint32_t serverIndex = 0;
    Buffer ephemeralPriv;
    Buffer ephemeralPub;
    Buffer chainingKey;
    Buffer hash;
    Buffer sendKey;
    Buffer recvKey;
    uint64_t sendCounter = 0;
    ~WGHandshakeState() {
        if (!ephemeralPriv.empty()) OPENSSL_cleanse(ephemeralPriv.data(), ephemeralPriv.size());
        if (!chainingKey.empty()) OPENSSL_cleanse(chainingKey.data(), chainingKey.size());
        if (!sendKey.empty()) OPENSSL_cleanse(sendKey.data(), sendKey.size());
        if (!recvKey.empty()) OPENSSL_cleanse(recvKey.data(), recvKey.size());
    }
};

Buffer buildHandshakeInitiation(const WGConfig &cfg, WGHandshakeState &hs) {
    static const std::string kConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static const std::string kIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    static const std::string kLabelMac1 = "mac1----";

    hs.chainingKey = blake2s(kConstruction.data(), kConstruction.size(), 32);
    auto idHash = wgHash2(hs.chainingKey, Buffer(kIdentifier.begin(), kIdentifier.end()));
    hs.hash = wgHash2(idHash, cfg.serverPub);

    auto randIdx = crypto::randomBytes(4);
    hs.clientIndex = readLE32(randIdx.data());
    if (hs.clientIndex == 0) hs.clientIndex = 1;

    hs.ephemeralPriv = crypto::randomBytes(32);
    hs.ephemeralPriv[0] &= 248;
    hs.ephemeralPriv[31] &= 127;
    hs.ephemeralPriv[31] |= 64;
    hs.ephemeralPub = x25519PublicFromPrivate(hs.ephemeralPriv);

    hs.chainingKey = wgHKDF(hs.chainingKey, hs.ephemeralPub, 1)[0];
    hs.hash = wgHash2(hs.hash, hs.ephemeralPub);

    auto ssES = x25519SharedSecret(hs.ephemeralPriv, cfg.serverPub);
    auto hkdfES = wgHKDF(hs.chainingKey, ssES, 2);
    hs.chainingKey = hkdfES[0];
    auto encStatic = crypto::seal(crypto::AEAD::ChaCha20Poly1305, hkdfES[1], wgNonce(0), cfg.clientPub, hs.hash);
    hs.hash = wgHash2(hs.hash, encStatic);

    auto ssSS = x25519SharedSecret(cfg.clientPriv, cfg.serverPub);
    auto hkdfSS = wgHKDF(hs.chainingKey, ssSS, 2);
    hs.chainingKey = hkdfSS[0];
    auto encTimestamp = crypto::seal(crypto::AEAD::ChaCha20Poly1305, hkdfSS[1], wgNonce(0), tai64nNow(), hs.hash);
    hs.hash = wgHash2(hs.hash, encTimestamp);

    Buffer msg(148, 0);
    msg[0] = 1;
    msg[1] = cfg.reserved[0];
    msg[2] = cfg.reserved[1];
    msg[3] = cfg.reserved[2];
    writeLE32(msg.data() + 4, hs.clientIndex);
    std::memcpy(msg.data() + 8, hs.ephemeralPub.data(), 32);
    std::memcpy(msg.data() + 40, encStatic.data(), 48);
    std::memcpy(msg.data() + 88, encTimestamp.data(), 28);

    auto mac1Key = wgHash2(Buffer(kLabelMac1.begin(), kLabelMac1.end()), cfg.serverPub);
    auto mac1 = wgMac(mac1Key, msg.data(), 116);
    std::memcpy(msg.data() + 116, mac1.data(), 16);
    return msg;
}

bool consumeHandshakeResponse(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &msg) {
    static const std::string kLabelMac1 = "mac1----";
    if (msg.size() != 92 || msg[0] != 2) return false;
    uint32_t recvIdx = readLE32(msg.data() + 8);
    if (recvIdx != hs.clientIndex) return false;

    auto mac1Key = wgHash2(Buffer(kLabelMac1.begin(), kLabelMac1.end()), cfg.clientPub);
    auto expectedMac1 = wgMac(mac1Key, msg.data(), 60);
    if (!crypto::constantTimeEqual(expectedMac1, Buffer(msg.begin() + 60, msg.begin() + 76)))
        return false;

    uint32_t srvIdx = readLE32(msg.data() + 4);
    Buffer sePub(msg.begin() + 12, msg.begin() + 44);
    Buffer encEmpty(msg.begin() + 44, msg.begin() + 60);

    try {
        auto ck = wgHKDF(hs.chainingKey, sePub, 1)[0];
        auto h = wgHash2(hs.hash, sePub);
        auto ssEE = x25519SharedSecret(hs.ephemeralPriv, sePub);
        ck = wgHKDF(ck, ssEE, 1)[0];
        auto ssSE = x25519SharedSecret(cfg.clientPriv, sePub);
        ck = wgHKDF(ck, ssSE, 1)[0];
        auto hkdfPSK = wgHKDF(ck, cfg.psk, 3);
        ck = hkdfPSK[0];
        h = wgHash2(h, hkdfPSK[1]);
        auto plainEmpty = crypto::open(crypto::AEAD::ChaCha20Poly1305, hkdfPSK[2], wgNonce(0), encEmpty, h);
        if (!plainEmpty.empty()) return false;
        auto keys = wgHKDF(ck, {}, 2);
        hs.serverIndex = srvIdx;
        hs.sendKey = keys[0];
        hs.recvKey = keys[1];
        hs.sendCounter = 0;
        if (!hs.ephemeralPriv.empty()) {
            OPENSSL_cleanse(hs.ephemeralPriv.data(), hs.ephemeralPriv.size());
            hs.ephemeralPriv.clear();
        }
        if (!hs.chainingKey.empty()) {
            OPENSSL_cleanse(hs.chainingKey.data(), hs.chainingKey.size());
            hs.chainingKey.clear();
        }
        return true;
    } catch (...) {
        return false;
    }
}

Buffer encryptTransportPacket(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &ipPacket) {
    size_t paddedLen = ipPacket.empty() ? 0 : ((ipPacket.size() + 15) / 16) * 16;
    Buffer padded(paddedLen, 0);
    if (!ipPacket.empty()) std::memcpy(padded.data(), ipPacket.data(), ipPacket.size());
    uint64_t counter = hs.sendCounter++;
    auto cipher = crypto::seal(crypto::AEAD::ChaCha20Poly1305, hs.sendKey, wgNonce(counter), padded);
    Buffer out(16 + cipher.size(), 0);
    out[0] = 4;
    out[1] = cfg.reserved[0];
    out[2] = cfg.reserved[1];
    out[3] = cfg.reserved[2];
    writeLE32(out.data() + 4, hs.serverIndex);
    writeLE64(out.data() + 8, counter);
    std::memcpy(out.data() + 16, cipher.data(), cipher.size());
    return out;
}

bool decryptTransportPacket(const WGHandshakeState &hs, const Buffer &pkt, Buffer &ipPacketOut) {
    if (pkt.size() < 32 || pkt[0] != 4) return false;
    uint32_t recvIdx = readLE32(pkt.data() + 4);
    if (recvIdx != hs.clientIndex) return false;
    uint64_t counter = readLE64(pkt.data() + 8);
    try {
        auto plain = crypto::openSlice(crypto::AEAD::ChaCha20Poly1305, hs.recvKey, wgNonce(counter),
                                       pkt.data() + 16, pkt.size() - 16);
        if (plain.empty()) {
            ipPacketOut.clear();
            return true; // Keepalive packet
        }
        if ((plain[0] >> 4) == 4 && plain.size() >= 20) {
            uint16_t totalLen = readBE16(plain.data() + 2);
            if (totalLen >= 20 && totalLen <= plain.size()) {
                plain.resize(totalLen);
                ipPacketOut = std::move(plain);
                return true;
            }
        } else if ((plain[0] >> 4) == 6 && plain.size() >= 40) {
            uint16_t payloadLen = readBE16(plain.data() + 4);
            size_t totalLen = 40 + size_t(payloadLen);
            if (totalLen <= plain.size()) {
                plain.resize(totalLen);
                ipPacketOut = std::move(plain);
                return true;
            }
        }
        return false;
    } catch (...) {
        return false;
    }
}

// 64-bit SWAR parallel ones'-complement accumulation (RFC 1071)
uint32_t accumulateChecksumSWAR(const uint8_t *data, size_t len, uint64_t acc = 0) noexcept {
    size_t i = 0;
    for (; i + 16 <= len; i += 16) {
        acc += uint64_t(readBE32(data + i)) +
               uint64_t(readBE32(data + i + 4)) +
               uint64_t(readBE32(data + i + 8)) +
               uint64_t(readBE32(data + i + 12));
    }
    for (; i + 4 <= len; i += 4) {
        acc += uint64_t(readBE32(data + i));
    }
    for (; i + 2 <= len; i += 2) {
        acc += uint64_t(readBE16(data + i));
    }
    if (len & 1) {
        acc += uint64_t(data[len - 1]) << 8;
    }
    acc = (acc & 0xFFFFFFFFULL) + (acc >> 32);
    acc = (acc & 0xFFFFFFFFULL) + (acc >> 32);
    uint32_t sum = uint32_t(acc & 0xFFFFULL) + uint32_t(acc >> 16);
    sum = (sum & 0xFFFFU) + (sum >> 16);
    return sum;
}

uint16_t ipv4Checksum(const uint8_t *data, size_t len) {
    return uint16_t(~accumulateChecksumSWAR(data, len));
}

uint16_t l4Checksum(uint32_t srcIPNet, uint32_t dstIPNet, uint8_t proto, const uint8_t *seg, size_t segLen) {
    const auto *s = reinterpret_cast<const uint8_t *>(&srcIPNet);
    const auto *d = reinterpret_cast<const uint8_t *>(&dstIPNet);
    uint64_t pseudo = uint64_t(readBE32(s)) + uint64_t(readBE32(d)) +
                      uint64_t(proto) + uint64_t(segLen);
    uint16_t res = uint16_t(~accumulateChecksumSWAR(seg, segLen, pseudo));
    return (proto == 17 && res == 0) ? 0xFFFF : res;
}

Buffer buildIPv4UDPPacket(uint32_t srcIPNet, uint16_t srcPort, uint32_t dstIPNet, uint16_t dstPort, const Buffer &payload) {
    size_t udpLen = 8 + payload.size();
    size_t totalLen = 20 + udpLen;
    Buffer pkt(totalLen, 0);
    pkt[0] = 0x45;
    writeBE16(pkt.data() + 2, uint16_t(totalLen));
    pkt[6] = 0x40; // DF
    pkt[8] = 64;   // TTL
    pkt[9] = 17;   // UDP
    std::memcpy(pkt.data() + 12, &srcIPNet, 4);
    std::memcpy(pkt.data() + 16, &dstIPNet, 4);
    writeBE16(pkt.data() + 10, ipv4Checksum(pkt.data(), 20));

    writeBE16(pkt.data() + 20, srcPort);
    writeBE16(pkt.data() + 22, dstPort);
    writeBE16(pkt.data() + 24, uint16_t(udpLen));
    if (!payload.empty()) std::memcpy(pkt.data() + 28, payload.data(), payload.size());
    writeBE16(pkt.data() + 26, l4Checksum(srcIPNet, dstIPNet, 17, pkt.data() + 20, udpLen));
    return pkt;
}

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

constexpr uint8_t kLocalWindowScale = 7; // 2^7 = 128 -> up to 8 MiB window
constexpr size_t kReceiveWindowMax = 2 * 1024 * 1024; // 2 MiB receive buffer

Buffer buildTCPOptions(bool synOptions, uint16_t synMSSValue, const std::vector<TCPSackBlock> &sackBlocks) {
    Buffer opts;
    if (synOptions) {
        // MSS (4B) + SACK-Permitted (2B) + Window Scale (3B) + NOP (1B) + NOP (1B) + EOL/NOP (1B) = 12B
        opts.resize(12, 1); // fill with NOP (1)
        opts[0] = 2; opts[1] = 4; writeBE16(opts.data() + 2, synMSSValue);
        opts[4] = 4; opts[5] = 2; // SACK-Permitted (RFC 2018)
        opts[6] = 3; opts[7] = 3; opts[8] = kLocalWindowScale; // Window Scale (RFC 7323)
        return opts;
    }
    if (!sackBlocks.empty()) {
        size_t count = std::min<size_t>(3, sackBlocks.size());
        opts.resize(4 + 8 * count, 1);
        opts[0] = 1; // NOP
        opts[1] = 1; // NOP
        opts[2] = 5; // SACK option kind
        opts[3] = uint8_t(2 + 8 * count);
        for (size_t i = 0; i < count; ++i) {
            writeBE32(opts.data() + 4 + i * 8, sackBlocks[i].leftEdge);
            writeBE32(opts.data() + 8 + i * 8, sackBlocks[i].rightEdge);
        }
    }
    return opts;
}

ParsedTCPOptions parseTCPOptions(const uint8_t *opts, size_t optLen) {
    ParsedTCPOptions out;
    size_t i = 0;
    while (i < optLen) {
        uint8_t kind = opts[i];
        if (kind == 0) break; // EOL
        if (kind == 1) { ++i; continue; } // NOP
        if (i + 1 >= optLen) break;
        uint8_t len = opts[i + 1];
        if (len < 2 || i + len > optLen) break;
        if (kind == 2 && len == 4) {
            out.mss = readBE16(opts + i + 2);
        } else if (kind == 3 && len == 3) {
            out.windowScale = std::min<uint8_t>(14, opts[i + 2]);
            out.hasWindowScale = true;
        } else if (kind == 4 && len == 2) {
            out.sackPermitted = true;
        } else if (kind == 5 && len >= 10 && ((len - 2) % 8 == 0)) {
            size_t blocks = (len - 2) / 8;
            for (size_t b = 0; b < blocks; ++b) {
                uint32_t left = readBE32(opts + i + 2 + b * 8);
                uint32_t right = readBE32(opts + i + 6 + b * 8);
                out.sackBlocks.push_back({left, right});
            }
        }
        i += len;
    }
    return out;
}

Buffer buildIPv4TCPPacket(uint32_t srcIPNet, uint16_t srcPort, uint32_t dstIPNet, uint16_t dstPort,
                          uint32_t seq, uint32_t ack, uint8_t flags, const Buffer &payload,
                          bool synOptions = false, uint16_t windowSize = 65535,
                          const std::vector<TCPSackBlock> &sackBlocks = {}) {
    Buffer opts = buildTCPOptions(synOptions, 1280, sackBlocks);
    size_t tcpHdrLen = 20 + opts.size();
    size_t tcpLen = tcpHdrLen + payload.size();
    size_t totalLen = 20 + tcpLen;
    Buffer pkt(totalLen, 0);
    pkt[0] = 0x45;
    writeBE16(pkt.data() + 2, uint16_t(totalLen));
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 6; // TCP
    std::memcpy(pkt.data() + 12, &srcIPNet, 4);
    std::memcpy(pkt.data() + 16, &dstIPNet, 4);
    writeBE16(pkt.data() + 10, ipv4Checksum(pkt.data(), 20));

    uint8_t *tcp = pkt.data() + 20;
    writeBE16(tcp, srcPort);
    writeBE16(tcp + 2, dstPort);
    writeBE32(tcp + 4, seq);
    writeBE32(tcp + 8, ack);
    tcp[12] = uint8_t((tcpHdrLen / 4) << 4);
    tcp[13] = flags;
    writeBE16(tcp + 14, windowSize);
    if (!opts.empty()) {
        std::memcpy(tcp + 20, opts.data(), opts.size());
    }
    if (!payload.empty()) std::memcpy(tcp + tcpHdrLen, payload.data(), payload.size());
    writeBE16(tcp + 16, l4Checksum(srcIPNet, dstIPNet, 6, tcp, tcpLen));
    return pkt;
}

uint16_t l4ChecksumIPv6(const std::array<uint8_t, 16> &srcIP, const std::array<uint8_t, 16> &dstIP,
                        uint8_t nextHdr, const uint8_t *seg, size_t segLen) {
    uint64_t pseudo = accumulateChecksumSWAR(srcIP.data(), 16, 0);
    pseudo = accumulateChecksumSWAR(dstIP.data(), 16, pseudo);
    pseudo += uint64_t(segLen) + uint64_t(nextHdr);
    uint16_t res = uint16_t(~accumulateChecksumSWAR(seg, segLen, pseudo));
    return (nextHdr == 17 && res == 0) ? 0xFFFF : res;
}

Buffer buildIPv6UDPPacket(const std::array<uint8_t, 16> &srcIP, uint16_t srcPort,
                          const std::array<uint8_t, 16> &dstIP, uint16_t dstPort, const Buffer &payload) {
    size_t udpLen = 8 + payload.size();
    size_t totalLen = 40 + udpLen;
    Buffer pkt(totalLen, 0);
    pkt[0] = 0x60; // Version 6
    writeBE16(pkt.data() + 4, uint16_t(udpLen));
    pkt[6] = 17;   // Next Header: UDP
    pkt[7] = 64;   // Hop Limit
    std::memcpy(pkt.data() + 8, srcIP.data(), 16);
    std::memcpy(pkt.data() + 24, dstIP.data(), 16);

    uint8_t *udp = pkt.data() + 40;
    writeBE16(udp, srcPort);
    writeBE16(udp + 2, dstPort);
    writeBE16(udp + 4, uint16_t(udpLen));
    if (!payload.empty()) std::memcpy(udp + 8, payload.data(), payload.size());
    writeBE16(udp + 6, l4ChecksumIPv6(srcIP, dstIP, 17, udp, udpLen));
    return pkt;
}

Buffer buildIPv6TCPPacket(const std::array<uint8_t, 16> &srcIP, uint16_t srcPort,
                          const std::array<uint8_t, 16> &dstIP, uint16_t dstPort,
                          uint32_t seq, uint32_t ack, uint8_t flags, const Buffer &payload,
                          bool synOptions = false, uint16_t windowSize = 65535,
                          const std::vector<TCPSackBlock> &sackBlocks = {}) {
    Buffer opts = buildTCPOptions(synOptions, 1220, sackBlocks);
    size_t tcpHdrLen = 20 + opts.size();
    size_t tcpLen = tcpHdrLen + payload.size();
    size_t totalLen = 40 + tcpLen;
    Buffer pkt(totalLen, 0);
    pkt[0] = 0x60; // Version 6
    writeBE16(pkt.data() + 4, uint16_t(tcpLen));
    pkt[6] = 6;    // Next Header: TCP
    pkt[7] = 64;   // Hop Limit
    std::memcpy(pkt.data() + 8, srcIP.data(), 16);
    std::memcpy(pkt.data() + 24, dstIP.data(), 16);

    uint8_t *tcp = pkt.data() + 40;
    writeBE16(tcp, srcPort);
    writeBE16(tcp + 2, dstPort);
    writeBE32(tcp + 4, seq);
    writeBE32(tcp + 8, ack);
    tcp[12] = uint8_t((tcpHdrLen / 4) << 4);
    tcp[13] = flags;
    writeBE16(tcp + 14, windowSize);
    if (!opts.empty()) {
        std::memcpy(tcp + 20, opts.data(), opts.size());
    }
    if (!payload.empty()) std::memcpy(tcp + tcpHdrLen, payload.data(), payload.size());
    writeBE16(tcp + 16, l4ChecksumIPv6(srcIP, dstIP, 6, tcp, tcpLen));
    return pkt;
}

Buffer buildDNSQueryA(const std::string &domain, uint16_t txid) {
    Buffer q;
    q.resize(12, 0);
    writeBE16(q.data(), txid);
    q[2] = 0x01; // RD=1
    q[5] = 0x01; // QDCOUNT=1
    size_t start = 0;
    while (start < domain.size()) {
        auto dot = domain.find('.', start);
        if (dot == std::string::npos) dot = domain.size();
        size_t len = dot - start;
        if (len > 0 && len <= 63) {
            q.push_back(uint8_t(len));
            q.insert(q.end(), domain.begin() + start, domain.begin() + dot);
        }
        start = dot + 1;
    }
    q.push_back(0);
    q.push_back(0); q.push_back(1); // QTYPE A
    q.push_back(0); q.push_back(1); // QCLASS IN
    return q;
}

bool parseDNSAnswerA(const Buffer &resp, uint16_t expectedTxid, uint32_t &ipv4NetOut) {
    if (resp.size() < 12 || readBE16(resp.data()) != expectedTxid) return false;
    if ((resp[2] & 0x80) == 0 || (resp[3] & 0x0F) != 0) return false;
    uint16_t qdCount = readBE16(resp.data() + 4);
    uint16_t anCount = readBE16(resp.data() + 6);
    if (anCount == 0) return false;
    size_t pos = 12;
    auto skipName = [&](size_t &p) -> bool {
        size_t jumps = 0;
        while (p < resp.size() && ++jumps < 64) {
            uint8_t c = resp[p];
            if (c == 0) { ++p; return true; }
            if ((c & 0xC0) == 0xC0) {
                if (p + 2 > resp.size()) return false;
                p += 2;
                return true;
            }
            p += 1 + c;
        }
        return false;
    };
    for (uint16_t i = 0; i < qdCount; ++i) {
        if (!skipName(pos) || pos + 4 > resp.size()) return false;
        pos += 4;
    }
    for (uint16_t i = 0; i < anCount; ++i) {
        if (!skipName(pos) || pos + 10 > resp.size()) return false;
        uint16_t rtype = readBE16(resp.data() + pos);
        uint16_t rdlen = readBE16(resp.data() + pos + 8);
        pos += 10;
        if (pos + rdlen > resp.size()) return false;
        if (rtype == 1 && rdlen == 4) {
            std::memcpy(&ipv4NetOut, resp.data() + pos, 4);
            return true;
        }
        pos += rdlen;
    }
    return false;
}

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

    bool matchesFactory(const std::shared_ptr<TransportFactory> &f) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_) return false;
        if (node_.host == "127.0.0.1" || node_.host == "localhost" || node_.host == "::1" ||
            node_.host == "[::1]" || node_.host == "fixture.invalid") {
            return factory_ == f;
        }
        return true;
    }

    bool shouldCloseOnFactoryReset(const std::shared_ptr<TransportFactory> &f) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_) return true;
        if (!f) return true;
        if (node_.host == "127.0.0.1" || node_.host == "localhost" || node_.host == "::1" ||
            node_.host == "[::1]" || node_.host == "fixture.invalid") {
            return factory_ == f;
        }
        return factory_ == f && tcpHandlers_.empty() && udpHandlers_.empty();
    }

    uint16_t allocatePort() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        for (unsigned i = 0; i < 1024; ++i) {
            uint16_t p = nextPort_++;
            if (nextPort_ > 60000 || nextPort_ < 30000) nextPort_ = 30000;
            if (!tcpHandlers_.count(p) && !udpHandlers_.count(p)) return p;
        }
        return nextPort_++;
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
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (closed_ || !established_ || !carrier_) {
                completion("WireGuard tunnel is not established");
                return;
            }
            try {
                wgPkt = encryptTransportPacket(cfg_, hs_, ipPkt);
                carrier = carrier_;
                if (++unansweredTxPackets_ > 8) {
                    unansweredTxPackets_ = 0;
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
            auto it = dnsCache_.find(host);
            if (it != dnsCache_.end()) {
                completion(it->second, {});
                return;
            }
            dnsPort = allocatePort();
            txid = ++dnsTxid_;
            if (txid == 0) txid = ++dnsTxid_;
        }
        auto self = shared_from_this();
        auto resolved = std::make_shared<bool>(false);
        registerUDP(dnsPort, [self, dnsPort, txid, host, resolved, completion](const Buffer &ipPkt) mutable {
            std::lock_guard<std::recursive_mutex> lock(self->mutex_);
            if (*resolved) return;
            uint8_t ihl = (ipPkt[0] & 0x0F) * 4;
            if (ipPkt.size() < size_t(ihl + 8)) return;
            const uint8_t *udp = ipPkt.data() + ihl;
            uint16_t srcPort = readBE16(udp);
            uint16_t udpLen = readBE16(udp + 4);
            if (srcPort != 53 || udpLen < 8 || ipPkt.size() < ihl + udpLen) return;
            Buffer payload(udp + 8, udp + udpLen);
            uint32_t ipNet = 0;
            if (parseDNSAnswerA(payload, txid, ipNet)) {
                *resolved = true;
                self->unregisterUDP(dnsPort);
                if (self->dnsCache_.size() >= 256) self->dnsCache_.clear();
                self->dnsCache_[host] = ipNet;
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
    std::vector<WriteCallback> waiters_;
    std::unordered_map<uint16_t, PacketHandler> tcpHandlers_;
    std::unordered_map<uint16_t, PacketHandler> udpHandlers_;
    std::unordered_map<std::string, uint32_t> dnsCache_;
    uint16_t nextPort_ = 32768;
    uint16_t dnsTxid_ = 0x3100;
    unsigned retryCount_ = 0;
    unsigned unansweredTxPackets_ = 0;
    bool connecting_ = false;
    bool established_ = false;
    bool closed_ = false;

    Target peerEndpoint() const { return {node_.dialHost(), node_.port, true, false}; }

    void sendHandshakeInitiation(bool rekey = false) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (closed_ || (!rekey && established_) || !carrier_) return;
        Buffer initPkt;
        try {
            if (rekey && established_) {
                pendingHs_ = WGHandshakeState{};
                initPkt = buildHandshakeInitiation(cfg_, pendingHs_);
                hasPendingHs_ = true;
            } else {
                initPkt = buildHandshakeInitiation(cfg_, hs_);
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
            if (!established_ || (pkt.size() == 92 && pkt[0] == 2)) {
                if (hasPendingHs_ && consumeHandshakeResponse(cfg_, pendingHs_, pkt)) {
                    hs_ = std::move(pendingHs_);
                    hasPendingHs_ = false;
                    unansweredTxPackets_ = 0;
                    try {
                        auto keepalive = encryptTransportPacket(cfg_, hs_, {});
                        carrier_->send(peerEndpoint(), std::move(keepalive), [](Error) {});
                    } catch (...) {}
                    return;
                }
                if (!established_ && consumeHandshakeResponse(cfg_, hs_, pkt)) {
                    established_ = true;
                    connecting_ = false;
                    unansweredTxPackets_ = 0;
                    try {
                        auto keepalive = encryptTransportPacket(cfg_, hs_, {});
                        carrier_->send(peerEndpoint(), std::move(keepalive), [](Error) {});
                    } catch (...) {}
                    readyWaiters = std::move(waiters_);
                    waiters_.clear();
                    selfKeepAlive_.reset();
                } else {
                    return;
                }
            } else {
                if (!decryptTransportPacket(hs_, pkt, ipPkt)) return;
                unansweredTxPackets_ = 0;
                if (ipPkt.size() < 20) return;
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
    if (node.host == "127.0.0.1" || node.host == "localhost" || node.host == "::1" ||
        node.host == "[::1]" || node.host == "fixture.invalid") {
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
