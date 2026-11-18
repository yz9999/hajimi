// Mieru v3 Key Schedule, AEAD Metadata Framing & Low-Entropy Codec
#include "MieruCore.hpp"
#include <algorithm>
#include <mutex>
#include <unordered_map>

namespace hajimi::mieru_detail {
using namespace proto_common;

Error parseMieruConfig(const Node &node, MieruConfig &cfg) {
    cfg.username = node.option("username", node.option("user"));
    cfg.password = node.option("password");
    if (cfg.username.empty() || cfg.password.empty()) {
        return "Mieru requires both username and password";
    }
    if (cfg.username.size() > 1024 || cfg.password.size() > 1024) {
        return "Mieru credential length exceeds limit";
    }
    cfg.transport = upperAscii(node.option("transport", node.option("network", "TCP")));
    if (cfg.transport != "TCP" && cfg.transport != "UDP") {
        return "Mieru transport must be TCP or UDP";
    }
    cfg.multiplexing = upperAscii(node.option("multiplexing", "MULTIPLEXING_HIGH"));
    if (cfg.multiplexing == "MULTIPLEXING_DEFAULT") cfg.multiplexing = "MULTIPLEXING_LOW";
    if (cfg.multiplexing != "MULTIPLEXING_OFF" &&
        cfg.multiplexing != "MULTIPLEXING_LOW" &&
        cfg.multiplexing != "MULTIPLEXING_MIDDLE" &&
        cfg.multiplexing != "MULTIPLEXING_HIGH") {
        return "Mieru multiplexing must be MULTIPLEXING_OFF, MULTIPLEXING_LOW, MULTIPLEXING_MIDDLE, or MULTIPLEXING_HIGH";
    }
    cfg.handshakeMode = upperAscii(node.option("handshake-mode", "HANDSHAKE_STANDARD"));
    if (cfg.handshakeMode == "HANDSHAKE_DEFAULT") cfg.handshakeMode = "HANDSHAKE_STANDARD";
    if (cfg.handshakeMode != "HANDSHAKE_STANDARD" && cfg.handshakeMode != "HANDSHAKE_NO_WAIT") {
        return "Mieru handshake-mode must be HANDSHAKE_STANDARD or HANDSHAKE_NO_WAIT";
    }
    auto mtuStr = node.option("mtu", "1400");
    if (!parseUint32(mtuStr, 576, 9000, cfg.mtu)) {
        return "Mieru mtu must be between 576 and 9000";
    }
    auto portRange = node.option("port-range");
    if (!portRange.empty()) {
        auto dash = portRange.find('-');
        uint32_t p1 = 0, p2 = 0;
        if (dash == std::string::npos) {
            if (!parseUint32(portRange, 1, 65535, p1)) return "Invalid Mieru port-range";
            p2 = p1;
        } else {
            if (!parseUint32(portRange.substr(0, dash), 1, 65535, p1) ||
                !parseUint32(portRange.substr(dash + 1), 1, 65535, p2) ||
                p1 > p2) {
                return "Invalid Mieru port-range bounds";
            }
        }
        cfg.portStart = uint16_t(p1);
        cfg.portEnd = uint16_t(p2);
    }
    return {};
}

// PBKDF2-HMAC-SHA256 (64 iterations, 32-byte output) per Mieru KDF specification.
Buffer mieruDeriveKeyForBucket(const std::string &username, const std::string &password, uint64_t roundedBucketSec) {
    Buffer cred;
    cred.reserve(password.size() + 1 + username.size());
    cred.insert(cred.end(), password.begin(), password.end());
    cred.push_back(0x00);
    cred.insert(cred.end(), username.begin(), username.end());
    Buffer hashedPass = crypto::digest("SHA256", cred);

    uint64_t bucket = roundedBucketSec;
    Buffer timeBytes(8);
    for (int i = 7; i >= 0; --i) {
        timeBytes[size_t(i)] = uint8_t(bucket & 0xff);
        bucket >>= 8;
    }
    Buffer salt = crypto::digest("SHA256", timeBytes);

    Buffer saltBlock;
    saltBlock.reserve(salt.size() + 4);
    saltBlock.insert(saltBlock.end(), salt.begin(), salt.end());
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(0);
    saltBlock.push_back(1);

    Buffer u = crypto::hmac("SHA256", hashedPass, saltBlock);
    Buffer out = u;
    for (int iter = 1; iter < 64; ++iter) {
        u = crypto::hmac("SHA256", hashedPass, u);
        for (size_t j = 0; j < out.size(); ++j) out[j] ^= u[j];
    }
    return out;
}

Buffer mieruDeriveSessionKey(const std::string &username, const std::string &password, uint64_t unixTimeSec) {
    uint64_t rounded = ((unixTimeSec + 60) / 120) * 120;
    return mieruDeriveKeyForBucket(username, password, rounded);
}

std::vector<Buffer> mieruCandidateKeys(const std::string &username, const std::string &password, uint64_t unixTimeSec) {
    uint64_t rounded = ((unixTimeSec + 60) / 120) * 120;
    std::string cacheKey = username + "\0" + password + "\0" + std::to_string(rounded);
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, std::vector<Buffer>> cache;
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(cacheKey);
        if (it != cache.end()) return it->second;
        if (cache.size() > 64) cache.clear();
    }
    std::vector<Buffer> keys;
    keys.reserve(3);
    keys.push_back(mieruDeriveKeyForBucket(username, password, rounded));
    if (rounded >= 120) keys.push_back(mieruDeriveKeyForBucket(username, password, rounded - 120));
    keys.push_back(mieruDeriveKeyForBucket(username, password, rounded + 120));
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[cacheKey] = keys;
    }
    return keys;
}

namespace {
void fillMieruNonce24(const std::string &username, const uint8_t *prefix20, uint8_t dstNonce24[24]) {
    std::memcpy(dstNonce24, prefix20, 20);
    for (size_t i = 0; i < 16; ++i) {
        if (dstNonce24[i] < 0x20 || dstNonce24[i] > 0x7e) {
            dstNonce24[i] = uint8_t(0x20 + (dstNonce24[i] % 0x5f));
        }
    }
    if (username.size() <= 240) {
        uint8_t tagInput[256];
        if (!username.empty()) std::memcpy(tagInput, username.data(), username.size());
        std::memcpy(tagInput + username.size(), dstNonce24, 16);
        Buffer digest = crypto::digestSlice("SHA256", tagInput, username.size() + 16);
        std::memcpy(dstNonce24 + 20, digest.data(), 4);
    } else {
        Buffer tagInput;
        tagInput.reserve(username.size() + 16);
        tagInput.insert(tagInput.end(), username.begin(), username.end());
        tagInput.insert(tagInput.end(), dstNonce24, dstNonce24 + 16);
        Buffer digest = crypto::digest("SHA256", tagInput);
        std::memcpy(dstNonce24 + 20, digest.data(), 4);
    }
}
} // namespace

// Mieru 24-byte XChaCha20-Poly1305 nonce with printable ASCII prefix (NONCE_TYPE_PRINTABLE) and 4-byte user tag
Buffer mieruMakeNonce(const std::string &username, const Buffer &randomPrefix20) {
    if (randomPrefix20.size() < 20) throw std::runtime_error("Invalid Mieru nonce prefix");
    Buffer nonce(24);
    fillMieruNonce24(username, randomPrefix20.data(), nonce.data());
    return nonce;
}

Buffer sealMieruUDPSegmentWithKey(const std::string &username, const Buffer &key,
                                  const Buffer &meta32, const Buffer &payload) {
    if (meta32.size() != 32) throw std::runtime_error("Invalid Mieru metadata size");
    const size_t totalLen = 24 + 48 + (payload.empty() ? 0 : (payload.size() + 16));
    Buffer wire(totalLen);
    Buffer rnd20 = crypto::randomBytes(20);
    fillMieruNonce24(username, rnd20.data(), wire.data());
    if (!crypto::sealInto(crypto::AEAD::XChaCha20Poly1305, key.data(), key.size(),
                          wire.data(), 24, meta32.data(), 32, wire.data() + 24)) {
        throw std::runtime_error("Mieru AEAD metadata encryption failed");
    }
    if (!payload.empty()) {
        if (!crypto::sealInto(crypto::AEAD::XChaCha20Poly1305, key.data(), key.size(),
                              wire.data(), 24, payload.data(), payload.size(), wire.data() + 72)) {
            throw std::runtime_error("Mieru AEAD payload encryption failed");
        }
    }
    return wire;
}

Buffer buildMieruSessionMetadata(uint8_t protoType, uint32_t sessionID, uint32_t seq,
                                 uint8_t statusCode, uint16_t payloadLen, uint8_t suffixLen) {
    Buffer meta(32, 0);
    meta[0] = protoType;
    writeBE32At(meta, 2, uint32_t(unixSeconds() / 60));
    writeBE32At(meta, 6, sessionID);
    writeBE32At(meta, 10, seq);
    meta[14] = statusCode;
    writeBE16At(meta, 15, payloadLen);
    meta[17] = suffixLen;
    return meta;
}

Buffer buildMieruDataMetadata(uint8_t protoType, uint32_t sessionID, uint32_t seq,
                              uint32_t unackSeq, uint16_t windowSize,
                              uint8_t prefixLen, uint16_t payloadLen, uint8_t suffixLen) {
    Buffer meta(32, 0);
    meta[0] = protoType;
    writeBE32At(meta, 2, uint32_t(unixSeconds() / 60));
    writeBE32At(meta, 6, sessionID);
    writeBE32At(meta, 10, seq);
    writeBE32At(meta, 14, unackSeq);
    writeBE16At(meta, 18, windowSize);
    meta[20] = 0; // fragment number
    meta[21] = prefixLen;
    writeBE16At(meta, 22, payloadLen);
    meta[24] = suffixLen;
    return meta;
}


ParsedMieruMetadata parseMieruMetadata(const Buffer &meta) {
    if (meta.size() != 32) throw std::runtime_error("Invalid Mieru metadata size");
    ParsedMieruMetadata out;
    out.protoType = meta[0];
    out.lowEntropyMode = meta[1];
    out.timestampMin = readBE32(meta.data() + 2);
    out.sessionID = readBE32(meta.data() + 6);
    out.seq = readBE32(meta.data() + 10);
    if (out.protoType >= kMieruOpenSessionReq && out.protoType <= kMieruCloseSessionResp) {
        out.statusCode = meta[14];
        out.payloadLen = readBE16(meta.data() + 15);
        out.suffixLen = meta[17];
    } else if (out.protoType >= kMieruDataClientToServer && out.protoType <= kMieruDataServerToClientLE) {
        out.unackSeq = readBE32(meta.data() + 14);
        out.windowSize = readBE16(meta.data() + 18);
        out.prefixLen = meta[21];
        out.payloadLen = readBE16(meta.data() + 22);
        out.suffixLen = meta[24];
        if (out.protoType == kMieruDataClientToServerLE || out.protoType == kMieruDataServerToClientLE) {
            out.lowEntropyMask = readBE32(meta.data() + 25);
            out.extractedPayloadLen = readBE16(meta.data() + 29);
            out.lowEntropyMaskRot = meta[31];
        }
    } else {
        throw std::runtime_error("Unknown Mieru metadata protocol type");
    }
    return out;
}

uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63u;
    return n == 0 ? x : ((x << n) | (x >> (64u - n)));
}

uint64_t rotr64(uint64_t x, unsigned n) {
    n &= 63u;
    return n == 0 ? x : ((x >> n) | (x << (64u - n)));
}

// Encodes standard AEAD ciphertext + 16B tag into Mieru v3 low-entropy payload (protoType 10: kMieruDataClientToServerLE)
Buffer encodeMieruLowEntropyPayload(uint8_t lowEntropyMode, uint32_t lowEntropyMask, uint8_t lowEntropyMaskRot,
                                    const Buffer &cipherPlusTag, Buffer &outMeta32) {
    if (lowEntropyMode < 1 || lowEntropyMode > 4 || cipherPlusTag.size() < 16) {
        throw std::runtime_error("Invalid Mieru low entropy encoding parameters");
    }
    const size_t C = size_t(lowEntropyMode) + 3; // 4..7 bytes per 8-byte chunk
    const size_t N = cipherPlusTag.size() - 16;
    const size_t numChunks = (N + C - 1) / C;
    const size_t encodedLen = numChunks * 8;
    if (encodedLen > 65535 || N > 65535) {
        throw std::runtime_error("Mieru low entropy payload exceeds 16-bit bound");
    }
    uint64_t mask0 = (uint64_t(lowEntropyMask) << 32) | uint64_t(lowEntropyMask);
    bool rotLeft = false;
    unsigned rotStep = 0;
    if ((lowEntropyMaskRot & 0x0f) != 0 && (lowEntropyMaskRot & 0xf0) == 0) {
        rotLeft = false;
        rotStep = lowEntropyMaskRot & 0x0f;
    } else if ((lowEntropyMaskRot & 0xf0) != 0 && (lowEntropyMaskRot & 0x0f) == 0) {
        rotLeft = true;
        rotStep = (lowEntropyMaskRot >> 4) & 0x0f;
    }

    Buffer out;
    out.reserve(encodedLen + 16);
    size_t pos = 0;
    for (size_t i = 0; i < numChunks; ++i) {
        unsigned shift = unsigned((i * rotStep) & 63u);
        uint64_t mask = rotLeft ? rotl64(mask0, shift) : rotr64(mask0, shift);
        size_t take = std::min(C, N - pos);
        uint64_t val = 0;
        for (size_t b = 0; b < take; ++b) {
            val = (val << 8) | uint64_t(cipherPlusTag[pos + b]);
        }
        pos += take;
        uint64_t chunk = 0;
        uint64_t subMask = mask;
        const size_t totalMaskBits = size_t(__builtin_popcountll(subMask));
        const size_t skipHighBits = totalMaskBits > take * 8 ? (totalMaskBits - take * 8) : 0;
        for (size_t s = 0; s < skipHighBits; ++s) {
            const int hiBit = 63 - __builtin_clzll(subMask);
            subMask &= ~(1ULL << hiBit);
        }
        for (int bitIdx = int(take * 8) - 1; bitIdx >= 0; --bitIdx) {
            if (subMask == 0) break;
            const int hiBit = 63 - __builtin_clzll(subMask);
            if ((val >> bitIdx) & 1ULL) {
                chunk |= (1ULL << hiBit);
            }
            subMask &= ~(1ULL << hiBit);
        }
        appendBE64(out, chunk);
    }
    out.insert(out.end(), cipherPlusTag.end() - 16, cipherPlusTag.end());

    outMeta32[0] = kMieruDataClientToServerLE;
    outMeta32[1] = lowEntropyMode;
    writeBE16At(outMeta32, 22, uint16_t(encodedLen));
    writeBE32At(outMeta32, 25, lowEntropyMask);
    writeBE16At(outMeta32, 29, uint16_t(N));
    outMeta32[31] = lowEntropyMaskRot;
    return out;
}

// Decodes Mieru low-entropy expanded ciphertext body (protoType 10 or 11) back into standard AEAD ciphertext + 16B tag
Buffer decodeMieruLowEntropyPayload(const ParsedMieruMetadata &parsed, const Buffer &encodedPlusTag) {
    if (parsed.protoType != kMieruDataClientToServerLE && parsed.protoType != kMieruDataServerToClientLE) {
        return encodedPlusTag;
    }
    if (parsed.lowEntropyMode < 1 || parsed.lowEntropyMode > 4) {
        throw std::runtime_error("Invalid Mieru low entropy mode");
    }
    if (encodedPlusTag.size() != size_t(parsed.payloadLen) + 16 || (parsed.payloadLen % 8) != 0) {
        throw std::runtime_error("Invalid Mieru low entropy payload length");
    }
    size_t C = size_t(parsed.lowEntropyMode) + 3; // 4, 5, 6, or 7 bytes per 8-byte chunk
    size_t N = size_t(parsed.extractedPayloadLen);
    size_t numChunks = size_t(parsed.payloadLen) / 8;
    if ((N + C - 1) / C != numChunks) {
        throw std::runtime_error("Inconsistent Mieru low entropy extracted payload length");
    }
    uint64_t mask0 = (uint64_t(parsed.lowEntropyMask) << 32) | uint64_t(parsed.lowEntropyMask);
    bool rotLeft = false;
    unsigned rotStep = 0;
    if ((parsed.lowEntropyMaskRot & 0x0f) != 0 && (parsed.lowEntropyMaskRot & 0xf0) == 0) {
        rotLeft = false;
        rotStep = parsed.lowEntropyMaskRot & 0x0f;
    } else if ((parsed.lowEntropyMaskRot & 0xf0) != 0 && (parsed.lowEntropyMaskRot & 0x0f) == 0) {
        rotLeft = true;
        rotStep = (parsed.lowEntropyMaskRot >> 4) & 0x0f;
    } else if (parsed.lowEntropyMaskRot != 0) {
        throw std::runtime_error("Invalid Mieru low entropy mask rotation");
    }

    Buffer out;
    out.reserve(N + 16);
    for (size_t i = 0; i < numChunks; ++i) {
        unsigned shift = unsigned((i * rotStep) & 63u);
        uint64_t mask = rotLeft ? rotl64(mask0, shift) : rotr64(mask0, shift);
        uint64_t chunk = readBE64(encodedPlusTag.data() + i * 8);
#if defined(__BMI2__) && (defined(__x86_64__) || defined(_M_X64))
        uint64_t extracted = _pext_u64(chunk, mask);
#else
        uint64_t extracted = 0;
        uint64_t remMask = mask;
        while (remMask != 0) {
            const int bit = 63 - __builtin_clzll(remMask);
            extracted = (extracted << 1) | ((chunk >> bit) & 1ULL);
            remMask &= ~(1ULL << bit);
        }
#endif
        size_t take = std::min(C, N - out.size());
        for (int b = int(take) - 1; b >= 0; --b) {
            out.push_back(uint8_t((extracted >> (b * 8)) & 0xff));
        }
    }
    out.insert(out.end(), encodedPlusTag.begin() + parsed.payloadLen, encodedPlusTag.end());
    return out;
}

// Strips SOCKS5 reply (0x05, 0x00, 0x00, ATYP, BND.ADDR, BND.PORT) from initial session payload
bool consumeSocks5ReplyIfComplete(Buffer &buf, Error &outError) {
    if (buf.size() < 4) return false;
    if (buf[0] != 0x05) {
        return true;
    }
    if (buf[1] != 0x00) {
        outError = "Mieru SOCKS5 target connect rejected (status " + std::to_string(buf[1]) + ")";
        return true;
    }
    size_t headerLen = 0;
    if (buf[3] == 0x01) {
        headerLen = 10;
    } else if (buf[3] == 0x04) {
        headerLen = 22;
    } else if (buf[3] == 0x03) {
        if (buf.size() < 5) return false;
        headerLen = 5 + size_t(buf[4]) + 2;
    } else {
        outError = "Mieru invalid SOCKS5 reply address type";
        return true;
    }
    if (buf.size() < headerLen) return false;
    buf.erase(buf.begin(), buf.begin() + headerLen);
    return true;
}

} // namespace hajimi::mieru_detail
