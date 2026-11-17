// WireGuard Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s Crypto, Packet & DNS Helpers
#include "WireGuardCore.hpp"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace hajimi::wg_detail {

Buffer blake2s(const void *inData, size_t inLen, size_t outLen,
               const void *keyData, size_t keyLen)  {
    if (outLen == 0 || outLen > 32 || keyLen > 32)
        throw std::runtime_error("Invalid BLAKE2s parameters");
    static const uint8_t emptyByte = 0;
    const auto *inPtr = (inLen > 0 && inData) ? static_cast<const uint8_t *>(inData) : &emptyByte;
    if (keyLen == 0) {
        if (outLen == 32) {
            Buffer out(32);
            unsigned written = 0;
            if (EVP_Digest(inPtr, inLen, out.data(), &written, EVP_blake2s256(), nullptr) != 1 || written != 32)
                throw std::runtime_error("OpenSSL EVP_blake2s256 failed");
            return out;
        }
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) throw std::runtime_error("OpenSSL EVP_MD_CTX allocation failed");
        size_t sizeParam = outLen;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &sizeParam),
            OSSL_PARAM_construct_end()
        };
        Buffer out(outLen);
        unsigned written = 0;
        if (EVP_DigestInit_ex2(ctx.get(), EVP_blake2s256(), params) != 1 ||
            EVP_DigestUpdate(ctx.get(), inPtr, inLen) != 1 ||
            EVP_DigestFinal_ex(ctx.get(), out.data(), &written) != 1 || written != outLen) {
            throw std::runtime_error("OpenSSL variable-length BLAKE2s failed");
        }
        return out;
    }
    static EVP_MAC *const blake2sMac = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    if (!blake2sMac) throw std::runtime_error("OpenSSL BLAKE2SMAC algorithm unavailable");
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(blake2sMac), EVP_MAC_CTX_free);
    if (!ctx) throw std::runtime_error("OpenSSL BLAKE2SMAC context allocation failed");
    size_t sizeParam = outLen;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sizeParam),
        OSSL_PARAM_construct_end()
    };
    Buffer out(outLen);
    size_t written = 0;
    if (EVP_MAC_init(ctx.get(), static_cast<const uint8_t *>(keyData), keyLen, params) != 1 ||
        EVP_MAC_update(ctx.get(), inPtr, inLen) != 1 ||
        EVP_MAC_final(ctx.get(), out.data(), &written, out.size()) != 1 || written != outLen) {
        throw std::runtime_error("OpenSSL BLAKE2SMAC computation failed");
    }
    return out;
}

Buffer wgHash2(const Buffer &a, const Buffer &b)  {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("OpenSSL EVP_MD_CTX allocation failed");
    Buffer out(32);
    unsigned written = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_blake2s256(), nullptr) != 1 ||
        (!a.empty() && EVP_DigestUpdate(ctx.get(), a.data(), a.size()) != 1) ||
        (!b.empty() && EVP_DigestUpdate(ctx.get(), b.data(), b.size()) != 1) ||
        EVP_DigestFinal_ex(ctx.get(), out.data(), &written) != 1 || written != 32) {
        throw std::runtime_error("OpenSSL wgHash2 failed");
    }
    return out;
}
Buffer wgMac(const Buffer &key, const uint8_t *data, size_t len)  {
    return blake2s(data, len, 16, key.data(), key.size());
}

// Standard OpenSSL 3 EVP_MAC HMAC-BLAKE2S-256
Buffer hmacBlake2s(const Buffer &key, const Buffer &input)  {
    static EVP_MAC *const hmacAlg = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!hmacAlg) throw std::runtime_error("OpenSSL HMAC algorithm unavailable");
    thread_local std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> tlsCtx(
        EVP_MAC_CTX_new(hmacAlg), EVP_MAC_CTX_free);
    if (!tlsCtx) throw std::runtime_error("OpenSSL HMAC context allocation failed");
    static const uint8_t emptyByte = 0;
    char digestName[] = "BLAKE2S-256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digestName, 0),
        OSSL_PARAM_construct_end()
    };
    Buffer out(32);
    size_t written = 0;
    if (EVP_MAC_init(tlsCtx.get(), key.empty() ? &emptyByte : key.data(), key.size(), params) != 1 ||
        EVP_MAC_update(tlsCtx.get(), input.empty() ? &emptyByte : input.data(), input.size()) != 1 ||
        EVP_MAC_final(tlsCtx.get(), out.data(), &written, out.size()) != 1 || written != 32) {
        throw std::runtime_error("OpenSSL HMAC-BLAKE2S-256 failed");
    }
    return out;
}

std::array<Buffer, 3> wgHKDF(const Buffer &chainingKey, const Buffer &input, size_t outputs)  {
    auto temp = hmacBlake2s(chainingKey, input);
    auto out1 = hmacBlake2s(temp, Buffer{0x01});
    if (outputs == 1) {
        OPENSSL_cleanse(temp.data(), temp.size());
        return {out1, {}, {}};
    }
    Buffer in2 = out1; in2.push_back(0x02);
    auto out2 = hmacBlake2s(temp, in2);
    OPENSSL_cleanse(in2.data(), in2.size());
    if (outputs == 2) {
        OPENSSL_cleanse(temp.data(), temp.size());
        return {out1, out2, {}};
    }
    Buffer in3 = out2; in3.push_back(0x03);
    auto out3 = hmacBlake2s(temp, in3);
    OPENSSL_cleanse(in3.data(), in3.size());
    OPENSSL_cleanse(temp.data(), temp.size());
    return {out1, out2, out3};
}

Buffer x25519PublicFromPrivate(const Buffer &priv)  {
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

Buffer x25519SharedSecret(const Buffer &priv, const Buffer &peerPub)  {
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

Buffer wgNonce(uint64_t counter)  {
    Buffer n(12, 0);
    writeLE64(n.data() + 4, counter);
    return n;
}

// Monotonically increasing TAI64N timestamp so rapid handshakes are never
// dropped by Linux kernel WireGuard's peer->latest_timestamp anti-replay check.
Buffer tai64nNow()  {
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


bool tryParseIPv6CIDR(std::string text, std::array<uint8_t, 16> &out)  {
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

uint32_t parseIPv4CIDR(std::string text)  {
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

std::array<uint8_t, 3> parseReserved(const std::string &raw)  {
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

WGConfig parseWGConfig(const Node &node)  {
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
    if (ipv6Str.empty()) {
        auto comma = ipStr.find_first_of(",;");
        if (comma != std::string::npos) {
            ipv6Str = ipStr.substr(comma + 1);
        }
    }
    if (!ipv6Str.empty() && tryParseIPv6CIDR(ipv6Str, cfg.selfIPv6)) {
        cfg.hasSelfIPv6 = true;
    } else {
        cfg.hasSelfIPv6 = false;
        cfg.selfIPv6.fill(0);
    }
    auto dnsStr = node.option("dns", node.option("dns-server", "223.5.5.5"));
    try { cfg.dnsIPv4 = parseIPv4CIDR(dnsStr); }
    catch (...) {
        cfg.dnsIPv4 = parseIPv4CIDR("223.5.5.5");
        if (tryParseIPv6CIDR(dnsStr, cfg.dnsIPv6)) {
            cfg.hasDnsIPv6 = true;
        }
    }
    if (!cfg.hasDnsIPv6) {
        auto comma = dnsStr.find_first_of(",;");
        if (comma != std::string::npos && tryParseIPv6CIDR(dnsStr.substr(comma + 1), cfg.dnsIPv6)) {
            cfg.hasDnsIPv6 = true;
        }
    }
    cfg.reserved = parseReserved(node.option("reserved"));
    auto mtuStr = node.option("mtu", "1420");
    if (!mtuStr.empty()) {
        int m = std::stoi(mtuStr);
        if (m < 576 || m > 65535) throw std::runtime_error("Invalid WireGuard mtu");
        cfg.mtu = size_t(m);
    }
    auto kaStr = node.option("persistent-keepalive", node.option("keepalive"));
    if (!kaStr.empty()) {
        try {
            int ka = std::stoi(kaStr);
            if (ka > 0 && ka <= 3600) cfg.keepaliveSeconds = uint32_t(ka);
        } catch (...) {}
    }
    return cfg;
}


Buffer buildHandshakeInitiation(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &cookie)  {
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
    hs.lastMac1 = mac1;
    if (cookie.size() == 16) {
        auto mac2 = wgMac(cookie, msg.data(), 132);
        std::memcpy(msg.data() + 132, mac2.data(), 16);
    }
    return msg;
}

bool consumeCookieReply(const WGConfig &cfg, const Buffer &lastMac1, uint32_t expectedIndex,
                        const Buffer &msg, Buffer &cookieOut)  {
    static const std::string kLabelCookie = "cookie--";
    if (msg.size() != 64 || msg[0] != 3 || lastMac1.size() != 16) return false;
    uint32_t recvIdx = readLE32(msg.data() + 4);
    if (recvIdx != expectedIndex) return false;
    try {
        auto cookieKey = wgHash2(Buffer(kLabelCookie.begin(), kLabelCookie.end()), cfg.serverPub);
        Buffer nonce(msg.begin() + 8, msg.begin() + 32);
        Buffer cipher(msg.begin() + 32, msg.begin() + 64);
        cookieOut = crypto::open(crypto::AEAD::XChaCha20Poly1305, cookieKey, nonce, cipher, lastMac1);
        return cookieOut.size() == 16;
    } catch (...) {
        return false;
    }
}

bool consumeHandshakeResponse(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &msg)  {
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

Buffer encryptTransportPacket(const WGConfig &cfg, WGHandshakeState &hs, const Buffer &ipPacket)  {
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

bool decryptTransportPacket(WGHandshakeState &hs, const Buffer &pkt, Buffer &ipPacketOut)  {
    if (pkt.size() < 32 || pkt[0] != 4) return false;
    uint32_t recvIdx = readLE32(pkt.data() + 4);
    if (recvIdx != hs.clientIndex) return false;
    uint64_t counter = readLE64(pkt.data() + 8);
    if (hs.replayInit && counter + 64 <= hs.replayMax) return false;
    try {
        auto plain = crypto::openSlice(crypto::AEAD::ChaCha20Poly1305, hs.recvKey, wgNonce(counter),
                                       pkt.data() + 16, pkt.size() - 16);
        if (!hs.acceptReplay(counter)) return false;
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
uint32_t accumulateChecksumSWAR(const uint8_t *data, size_t len, uint64_t acc) noexcept  {
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

uint16_t ipv4Checksum(const uint8_t *data, size_t len)  {
    return uint16_t(~accumulateChecksumSWAR(data, len));
}

uint16_t l4Checksum(uint32_t srcIPNet, uint32_t dstIPNet, uint8_t proto, const uint8_t *seg, size_t segLen)  {
    const auto *s = reinterpret_cast<const uint8_t *>(&srcIPNet);
    const auto *d = reinterpret_cast<const uint8_t *>(&dstIPNet);
    uint64_t pseudo = uint64_t(readBE32(s)) + uint64_t(readBE32(d)) +
                      uint64_t(proto) + uint64_t(segLen);
    uint16_t res = uint16_t(~accumulateChecksumSWAR(seg, segLen, pseudo));
    return (proto == 17 && res == 0) ? 0xFFFF : res;
}

Buffer buildIPv4UDPPacket(uint32_t srcIPNet, uint16_t srcPort, uint32_t dstIPNet, uint16_t dstPort, const Buffer &payload)  {
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




Buffer buildTCPOptions(bool synOptions, uint16_t synMSSValue, const std::vector<TCPSackBlock> &sackBlocks)  {
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

ParsedTCPOptions parseTCPOptions(const uint8_t *opts, size_t optLen)  {
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
                          bool synOptions, uint16_t windowSize,
                          const std::vector<TCPSackBlock> &sackBlocks)  {
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
                        uint8_t nextHdr, const uint8_t *seg, size_t segLen)  {
    uint64_t pseudo = accumulateChecksumSWAR(srcIP.data(), 16, 0);
    pseudo = accumulateChecksumSWAR(dstIP.data(), 16, pseudo);
    pseudo += uint64_t(segLen) + uint64_t(nextHdr);
    uint16_t res = uint16_t(~accumulateChecksumSWAR(seg, segLen, pseudo));
    return (nextHdr == 17 && res == 0) ? 0xFFFF : res;
}

Buffer buildIPv6UDPPacket(const std::array<uint8_t, 16> &srcIP, uint16_t srcPort,
                          const std::array<uint8_t, 16> &dstIP, uint16_t dstPort, const Buffer &payload)  {
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
                          bool synOptions, uint16_t windowSize,
                          const std::vector<TCPSackBlock> &sackBlocks)  {
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

Buffer buildDNSQuery(const std::string &domain, uint16_t txid, uint16_t qtype)  {
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
    q.push_back(uint8_t(qtype >> 8)); q.push_back(uint8_t(qtype & 0xff));
    q.push_back(0); q.push_back(1); // QCLASS IN
    return q;
}

Buffer buildDNSQueryA(const std::string &domain, uint16_t txid)  {
    return buildDNSQuery(domain, txid, 1);
}

bool decodeDNSName(const Buffer &resp, size_t &pos, std::string &nameOut)  {
    nameOut.clear();
    size_t cur = pos;
    bool jumped = false;
    size_t jumps = 0;
    while (cur < resp.size() && ++jumps < 64) {
        uint8_t c = resp[cur];
        if (c == 0) {
            if (!jumped) pos = cur + 1;
            return true;
        }
        if ((c & 0xC0) == 0xC0) {
            if (cur + 2 > resp.size()) return false;
            uint16_t ptr = uint16_t(((c & 0x3F) << 8) | resp[cur + 1]);
            if (ptr >= resp.size()) return false;
            if (!jumped) { pos = cur + 2; jumped = true; }
            cur = ptr;
            continue;
        }
        if ((c & 0xC0) != 0 || cur + 1 + c > resp.size()) return false;
        if (!nameOut.empty()) nameOut.push_back('.');
        for (size_t i = 0; i < c; ++i) {
            char ch = char(resp[cur + 1 + i]);
            if (ch >= 'A' && ch <= 'Z') ch = char(ch - 'A' + 'a');
            nameOut.push_back(ch);
        }
        cur += 1 + c;
    }
    return false;
}

std::string normalizeDNSQueryHost(const std::string &host)  {
    std::string out;
    out.reserve(host.size());
    for (char ch : host) {
        if (ch >= 'A' && ch <= 'Z') out.push_back(char(ch - 'A' + 'a'));
        else out.push_back(ch);
    }
    while (!out.empty() && out.back() == '.') out.pop_back();
    return out;
}

bool parseDNSAnswerAAAA(const Buffer &resp, uint16_t expectedTxid, std::array<uint8_t, 16> &ipv6Out,
                        const std::string &expectedHost, uint32_t *ttlOut)  {
    if (resp.size() < 12 || readBE16(resp.data()) != expectedTxid) return false;
    if ((resp[2] & 0x80) == 0 || (resp[3] & 0x0F) != 0) return false;
    uint16_t qdCount = readBE16(resp.data() + 4);
    uint16_t anCount = readBE16(resp.data() + 6);
    if (qdCount == 0 || anCount == 0) return false;
    size_t pos = 12;
    const std::string normExpected = normalizeDNSQueryHost(expectedHost);
    for (uint16_t i = 0; i < qdCount; ++i) {
        std::string qname;
        if (!decodeDNSName(resp, pos, qname) || pos + 4 > resp.size()) return false;
        if (i == 0 && !normExpected.empty() && qname != normExpected) return false;
        pos += 4;
    }
    for (uint16_t i = 0; i < anCount; ++i) {
        std::string rname;
        if (!decodeDNSName(resp, pos, rname) || pos + 10 > resp.size()) return false;
        uint16_t rtype = readBE16(resp.data() + pos);
        uint32_t ttl = readBE32(resp.data() + pos + 4);
        uint16_t rdlen = readBE16(resp.data() + pos + 8);
        pos += 10;
        if (pos + rdlen > resp.size()) return false;
        if (rtype == 28 && rdlen == 16) {
            std::memcpy(ipv6Out.data(), resp.data() + pos, 16);
            if (ttlOut) *ttlOut = std::clamp<uint32_t>(ttl, 10u, 3600u);
            return true;
        }
        pos += rdlen;
    }
    return false;
}

bool parseDNSAnswerA(const Buffer &resp, uint16_t expectedTxid, uint32_t &ipv4NetOut,
                     const std::string &expectedHost, uint32_t *ttlOut)  {
    if (resp.size() < 12 || readBE16(resp.data()) != expectedTxid) return false;
    if ((resp[2] & 0x80) == 0 || (resp[3] & 0x0F) != 0) return false;
    uint16_t qdCount = readBE16(resp.data() + 4);
    uint16_t anCount = readBE16(resp.data() + 6);
    if (qdCount == 0 || anCount == 0) return false;
    size_t pos = 12;
    const std::string normExpected = normalizeDNSQueryHost(expectedHost);
    for (uint16_t i = 0; i < qdCount; ++i) {
        std::string qname;
        if (!decodeDNSName(resp, pos, qname) || pos + 4 > resp.size()) return false;
        if (i == 0 && !normExpected.empty() && qname != normExpected) return false;
        pos += 4;
    }
    for (uint16_t i = 0; i < anCount; ++i) {
        std::string rname;
        if (!decodeDNSName(resp, pos, rname) || pos + 10 > resp.size()) return false;
        uint16_t rtype = readBE16(resp.data() + pos);
        uint32_t ttl = readBE32(resp.data() + pos + 4);
        uint16_t rdlen = readBE16(resp.data() + pos + 8);
        pos += 10;
        if (pos + rdlen > resp.size()) return false;
        if (rtype == 1 && rdlen == 4) {
            std::memcpy(&ipv4NetOut, resp.data() + pos, 4);
            if (ttlOut) *ttlOut = std::clamp<uint32_t>(ttl, 10u, 3600u);
            return true;
        }
        pos += rdlen;
    }
    return false;
}


} // namespace hajimi::wg_detail
