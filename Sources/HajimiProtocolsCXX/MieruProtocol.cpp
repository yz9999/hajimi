// Mieru Outbound Protocol (Official v3 Wire Specification: TCP & UDP Underlays)
#include "MieruProtocol.hpp"
#include "ProtocolStream.hpp"
#include "ProtocolCommon.hpp"
#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <unordered_map>

namespace hajimi {
namespace {
using namespace proto_common;

// ============================================================================
// 2. MIERU PROTOCOL (Official v3 Wire Specification: TCP & UDP Underlays)
// ============================================================================

constexpr uint8_t kMieruOpenSessionReq       = 2;
constexpr uint8_t kMieruOpenSessionResp      = 3;
constexpr uint8_t kMieruCloseSessionReq      = 4;
constexpr uint8_t kMieruCloseSessionResp     = 5;
constexpr uint8_t kMieruDataClientToServer   = 6;
constexpr uint8_t kMieruDataServerToClient   = 7;
constexpr uint8_t kMieruAckClientToServer    = 8;
constexpr uint8_t kMieruAckServerToClient    = 9;
constexpr uint8_t kMieruDataClientToServerLE = 10;
constexpr uint8_t kMieruDataServerToClientLE = 11;

uint64_t monotonicMillis() noexcept {
    return uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct MieruConfig {
    std::string username;
    std::string password;
    std::string transport = "TCP";
    std::string multiplexing = "MULTIPLEXING_HIGH";
    std::string handshakeMode = "HANDSHAKE_STANDARD";
    uint32_t mtu = 1400;
    uint16_t portStart = 0;
    uint16_t portEnd = 0;
};

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

// Mieru 24-byte XChaCha20-Poly1305 nonce with printable ASCII prefix (NONCE_TYPE_PRINTABLE) and 4-byte user tag
Buffer mieruMakeNonce(const std::string &username, const Buffer &randomPrefix20) {
    if (randomPrefix20.size() < 20) throw std::runtime_error("Invalid Mieru nonce prefix");
    Buffer nonce;
    nonce.reserve(24);
    nonce.insert(nonce.end(), randomPrefix20.begin(), randomPrefix20.begin() + 20);
    for (size_t i = 0; i < 16; ++i) {
        if (nonce[i] < 0x20 || nonce[i] > 0x7e) {
            nonce[i] = uint8_t(0x20 + (nonce[i] % 0x5f));
        }
    }
    Buffer tagInput;
    tagInput.reserve(username.size() + 16);
    tagInput.insert(tagInput.end(), username.begin(), username.end());
    tagInput.insert(tagInput.end(), nonce.begin(), nonce.begin() + 16);
    Buffer digest = crypto::digest("SHA256", tagInput);
    nonce.insert(nonce.end(), digest.begin(), digest.begin() + 4);
    return nonce;
}

Buffer sealMieruUDPSegmentWithKey(const std::string &username, const Buffer &key,
                                  const Buffer &meta32, const Buffer &payload,
                                  bool incrementNonceForPayload = false) {
    Buffer nonce = mieruMakeNonce(username, crypto::randomBytes(20));
    Buffer wire;
    wire.reserve(24 + 48 + (payload.empty() ? 0 : payload.size() + 16));
    wire.insert(wire.end(), nonce.begin(), nonce.end());
    Buffer sealedMeta = crypto::seal(crypto::AEAD::XChaCha20Poly1305, key, nonce, meta32);
    wire.insert(wire.end(), sealedMeta.begin(), sealedMeta.end());
    if (!payload.empty()) {
        Buffer payloadNonce = nonce;
        if (incrementNonceForPayload) {
            incrementNonceBE(payloadNonce);
        }
        Buffer sealedPayload = crypto::seal(crypto::AEAD::XChaCha20Poly1305, key, payloadNonce, payload);
        wire.insert(wire.end(), sealedPayload.begin(), sealedPayload.end());
    }
    return wire;
}

Buffer buildMieruSessionMetadata(uint8_t protoType, uint32_t sessionID, uint32_t seq,
                                 uint8_t statusCode, uint16_t payloadLen, uint8_t suffixLen = 0) {
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
                              uint8_t prefixLen, uint16_t payloadLen, uint8_t suffixLen = 0) {
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

struct ParsedMieruMetadata {
    uint8_t protoType = 0;
    uint8_t lowEntropyMode = 0;
    uint32_t timestampMin = 0;
    uint32_t sessionID = 0;
    uint32_t seq = 0;
    uint32_t unackSeq = 0;
    uint16_t windowSize = 4096;
    uint8_t statusCode = 0;
    uint8_t prefixLen = 0;
    uint16_t payloadLen = 0;
    uint8_t suffixLen = 0;
    uint32_t lowEntropyMask = 0;
    uint8_t lowEntropyMaskRot = 0;
    uint16_t extractedPayloadLen = 0;
};

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

class MieruTCPStream final : public Stream, public std::enable_shared_from_this<MieruTCPStream> {
public:
    MieruTCPStream(std::shared_ptr<Stream> raw, std::vector<Buffer> candidateKeys,
                   Buffer txNonce, uint32_t sessionID, uint32_t initialTxSeq)
        : raw_(std::move(raw)), reader_(std::make_shared<Reader>(raw_)),
          writer_(std::make_shared<OrderedWriter>(raw_)),
          candidateKeys_(std::move(candidateKeys)), txKey_(candidateKeys_.front()),
          rxKey_(candidateKeys_.front()), txNonce_(std::move(txNonce)),
          sessionID_(sessionID), txSeq_(initialTxSeq) {}

    void writeInitialHandshake(Buffer wire, WriteCallback completion) {
        if (closed_) { completion("Stream closed"); return; }
        writer_->write(std::move(wire), std::move(completion));
    }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        if (data.empty()) { completion({}); return; }
        try {
            Buffer wire;
            wire.reserve(data.size() + ((data.size() + 16383) / 16384) * 64);
            size_t offset = 0;
            while (offset < data.size()) {
                size_t chunkLen = std::min<size_t>(16384, data.size() - offset);
                Buffer meta = buildMieruDataMetadata(kMieruDataClientToServer, sessionID_,
                                                     txSeq_++, rxHighestSeq_, 4096,
                                                     0, uint16_t(chunkLen), 0);
                Buffer sealedMeta = crypto::sealSlice(crypto::AEAD::XChaCha20Poly1305, txKey_, txNonce_, meta.data(), meta.size());
                incrementNonceBE(txNonce_);
                wire.insert(wire.end(), sealedMeta.begin(), sealedMeta.end());

                Buffer sealedPayload = crypto::sealSlice(crypto::AEAD::XChaCha20Poly1305, txKey_, txNonce_,
                                                         data.data() + offset, chunkLen);
                incrementNonceBE(txNonce_);
                wire.insert(wire.end(), sealedPayload.begin(), sealedPayload.end());
                offset += chunkLen;
            }
            writer_->write(std::move(wire), std::move(completion));
        } catch (const std::exception &e) {
            completion(e.what());
        }
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) { completion({}, true, "Stream closed"); return; }
        if (socksReplyConsumed_ && !pending_.empty()) {
            completion(pending_.consume(maximum), false, {});
            return;
        }
        auto self = shared_from_this();
        if (!rxNonceInitialized_) {
            reader_->exactly(24, [self, maximum, completion = std::move(completion)](Buffer nonce, Error err) mutable {
                if (!err.empty()) {
                    if (err == "EOF") completion({}, true, {});
                    else completion({}, true, err);
                    return;
                }
                self->rxNonce_ = std::move(nonce);
                self->rxNonceInitialized_ = true;
                self->readNextSegment(maximum, std::move(completion));
            });
            return;
        }
        readNextSegment(maximum, std::move(completion));
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        if (writer_) {
            try {
                Buffer closeMeta = buildMieruSessionMetadata(kMieruCloseSessionReq, sessionID_, txSeq_++, 0, 0, 0);
                Buffer sealedMeta = crypto::sealSlice(crypto::AEAD::XChaCha20Poly1305, txKey_, txNonce_, closeMeta.data(), closeMeta.size());
                incrementNonceBE(txNonce_);
                writer_->write(std::move(sealedMeta), [](Error) {});
            } catch (...) {}
            writer_->close();
        }
        reader_->close();
    }

private:
    void readNextSegment(size_t maximum, ReadCallback completion) {
        auto self = shared_from_this();
        reader_->exactly(48, [self, maximum, completion = std::move(completion)](Buffer encMeta, Error err) mutable {
            if (!err.empty()) {
                if (err == "EOF") completion({}, true, {});
                else completion({}, true, err);
                return;
            }
            ParsedMieruMetadata parsed;
            try {
                Buffer plainMeta = self->openMetadataBlock(encMeta);
                parsed = parseMieruMetadata(plainMeta);
            } catch (const std::exception &e) {
                self->close();
                completion({}, true, e.what());
                return;
            }
            if (parsed.protoType == kMieruOpenSessionResp && parsed.statusCode != 0) {
                self->close();
                completion({}, true, "Mieru openSessionResponse rejected (status " + std::to_string(parsed.statusCode) + ")");
                return;
            }
            if (parsed.protoType == kMieruCloseSessionReq || parsed.protoType == kMieruCloseSessionResp) {
                self->close();
                completion({}, true, {});
                return;
            }
            if (parsed.seq >= self->rxHighestSeq_) {
                self->rxHighestSeq_ = parsed.seq + 1;
            }
            size_t tailBytes = size_t(parsed.prefixLen) +
                (parsed.payloadLen > 0 ? size_t(parsed.payloadLen) + 16 : 0) +
                size_t(parsed.suffixLen);
            if (tailBytes == 0) {
                self->readNextSegment(maximum, std::move(completion));
                return;
            }
            self->reader_->exactly(tailBytes, [self, parsed, maximum, completion = std::move(completion)](Buffer tail, Error readErr) mutable {
                if (!readErr.empty()) {
                    completion({}, true, readErr);
                    return;
                }
                try {
                    if (parsed.payloadLen > 0) {
                        Buffer plain;
                        if (parsed.protoType == kMieruDataServerToClientLE) {
                            Buffer cipherPayload(tail.begin() + parsed.prefixLen,
                                                 tail.begin() + parsed.prefixLen + parsed.payloadLen + 16);
                            cipherPayload = decodeMieruLowEntropyPayload(parsed, cipherPayload);
                            plain = self->openPayloadSlice(cipherPayload.data(), cipherPayload.size());
                        } else {
                            plain = self->openPayloadSlice(tail.data() + parsed.prefixLen, size_t(parsed.payloadLen) + 16);
                        }
                        if (!self->socksReplyConsumed_) {
                            self->handshakePending_.insert(self->handshakePending_.end(), plain.begin(), plain.end());
                        } else {
                            self->pending_.append(plain);
                        }
                    }
                    if (!self->socksReplyConsumed_) {
                        Error socksErr;
                        if (!consumeSocks5ReplyIfComplete(self->handshakePending_, socksErr)) {
                            self->readNextSegment(maximum, std::move(completion));
                            return;
                        }
                        if (!socksErr.empty()) {
                            self->close();
                            completion({}, true, socksErr);
                            return;
                        }
                        self->socksReplyConsumed_ = true;
                        if (!self->handshakePending_.empty()) {
                            self->pending_.append(self->handshakePending_);
                            self->handshakePending_.clear();
                        }
                    }
                    if (self->pending_.empty()) {
                        self->readNextSegment(maximum, std::move(completion));
                        return;
                    }
                    completion(self->pending_.consume(maximum), false, {});
                } catch (const std::exception &e) {
                    self->close();
                    completion({}, true, e.what());
                }
            });
        });
    }

    Buffer openMetadataBlock(const Buffer &encMeta) {
        if (!rxKeyLocked_) {
            for (const auto &cand : candidateKeys_) {
                try {
                    Buffer plain = crypto::open(crypto::AEAD::XChaCha20Poly1305, cand, rxNonce_, encMeta);
                    rxKey_ = cand;
                    rxKeyLocked_ = true;
                    lastRxNonceBeforeInc_ = rxNonce_;
                    incrementNonceBE(rxNonce_);
                    return plain;
                } catch (...) {}
            }
            throw std::runtime_error("Mieru metadata authentication failed (check username/password or system clock)");
        }
        try {
            Buffer plain = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, rxNonce_, encMeta);
            lastRxNonceBeforeInc_ = rxNonce_;
            if (useLittleEndianRxNonce_) incrementNonceLE(rxNonce_);
            else incrementNonceBE(rxNonce_);
            return plain;
        } catch (...) {
            if (!rxEndianLocked_) {
                Buffer altNonce = lastRxNonceBeforeInc_;
                incrementNonceLE(altNonce);
                Buffer plain = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, altNonce, encMeta);
                useLittleEndianRxNonce_ = true;
                rxEndianLocked_ = true;
                lastRxNonceBeforeInc_ = altNonce;
                rxNonce_ = altNonce;
                incrementNonceLE(rxNonce_);
                return plain;
            }
            throw;
        }
    }

    Buffer openPayloadSlice(const uint8_t *cipherPtr, size_t cipherLen) {
        try {
            Buffer plain = crypto::openSlice(crypto::AEAD::XChaCha20Poly1305, rxKey_, rxNonce_, cipherPtr, cipherLen);
            rxEndianLocked_ = true;
            lastRxNonceBeforeInc_ = rxNonce_;
            if (useLittleEndianRxNonce_) incrementNonceLE(rxNonce_);
            else incrementNonceBE(rxNonce_);
            return plain;
        } catch (...) {
            if (!rxEndianLocked_) {
                Buffer altNonce = lastRxNonceBeforeInc_;
                incrementNonceLE(altNonce);
                Buffer plain = crypto::openSlice(crypto::AEAD::XChaCha20Poly1305, rxKey_, altNonce, cipherPtr, cipherLen);
                useLittleEndianRxNonce_ = true;
                rxEndianLocked_ = true;
                lastRxNonceBeforeInc_ = altNonce;
                rxNonce_ = altNonce;
                incrementNonceLE(rxNonce_);
                return plain;
            }
            throw;
        }
    }

    std::shared_ptr<Stream> raw_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
    std::vector<Buffer> candidateKeys_;
    Buffer txKey_, rxKey_, txNonce_, rxNonce_, lastRxNonceBeforeInc_;
    Buffer handshakePending_;
    CursorBuffer pending_;
    uint32_t sessionID_ = 0;
    uint32_t txSeq_ = 0;
    uint32_t rxHighestSeq_ = 0;
    bool rxNonceInitialized_ = false;
    bool rxKeyLocked_ = false;
    bool rxEndianLocked_ = false;
    bool useLittleEndianRxNonce_ = false;
    bool socksReplyConsumed_ = false;
    bool closed_ = false;
};

// Mieru UDP Underlay Stream (Each UDP packet has its own 24-byte nonce + 48-byte encrypted metadata + optional encrypted payload)
class MieruUDPStream final : public Stream, public std::enable_shared_from_this<MieruUDPStream> {
public:
    MieruUDPStream(std::shared_ptr<Datagram> raw, std::shared_ptr<TransportFactory> factory,
                   Node dialNode, Target serverTarget, MieruConfig cfg,
                   std::vector<Buffer> candidateKeys, uint32_t sessionID, Buffer initialSocksReq)
        : raw_(std::move(raw)), factory_(std::move(factory)),
          dialNode_(std::move(dialNode)), serverTarget_(std::move(serverTarget)), cfg_(std::move(cfg)),
          candidateKeys_(std::move(candidateKeys)), txKey_(candidateKeys_.front()),
          rxKey_(candidateKeys_.front()), sessionID_(sessionID),
          initialSessionID_(sessionID), validSessionIDs_{sessionID},
          currentKeyBucket_(((unixSeconds() + 60) / 120) * 120),
          handshakeStartMs_(monotonicMillis()),
          lastRxMs_(monotonicMillis()), lastTxMs_(monotonicMillis()),
          initialSocksReq_(std::move(initialSocksReq)) {}

    ~MieruUDPStream() override {
        for (auto &sock : handshakeSockets_) {
            if (sock) sock->close();
        }
        handshakeSockets_.clear();
        if (raw_) {
            raw_->close();
            raw_ = nullptr;
        }
        if (readyCallback_) {
            auto cb = std::move(readyCallback_);
            readyCallback_ = {};
            cb(nullptr, terminal_.empty() ? Error("Mieru UDP stream destroyed before ready") : terminal_);
        }
    }

    void start(StreamCallback ready) {
        readyCallback_ = std::move(ready);
        auto self = shared_from_this();
        auto initialSock = raw_;
        if (initialSock) {
            handshakeSockets_.push_back(initialSock);
        }
        std::weak_ptr<Datagram> weakSock = initialSock;
        raw_->start([self, weakSock](Target, Buffer packet) {
            if (auto sock = weakSock.lock()) {
                if (!self->sessionOpened_) {
                    self->raw_ = sock;
                }
            }
            self->onPacket(std::move(packet));
        }, [self, weakSock](Error err) {
            auto sock = weakSock.lock();
            if (sock) {
                self->handshakeSockets_.erase(
                    std::remove(self->handshakeSockets_.begin(), self->handshakeSockets_.end(), sock),
                    self->handshakeSockets_.end());
            }
            if (self->sessionOpened_) {
                if (sock && sock != self->raw_) return;
            } else {
                if (err != "Native UDP connection cancelled" && !self->handshakeSockets_.empty()) return;
            }
            self->failAll(err.empty() ? Error("Mieru UDP socket error") : err);
        });
        sendOpenSessionPacket();
        scheduleOpenRetry(1);
    }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_) { completion(terminal_.empty() ? Error("Stream closed") : terminal_); return; }
        if (data.empty()) { completion({}); return; }
        if (txUnacked_.size() >= 8192) {
            completion("Mieru UDP unacknowledged send window full");
            return;
        }
        try {
            size_t maxPayload = std::min<size_t>(1350, std::max<size_t>(512, cfg_.mtu > 88 ? cfg_.mtu - 88 : 1287));
            size_t offset = 0;
            uint64_t nowMs = monotonicMillis();
            lastTxMs_ = nowMs;
            std::vector<Buffer> packets;
            packets.reserve((data.size() + maxPayload - 1) / maxPayload);
            while (offset < data.size()) {
                size_t chunkLen = std::min<size_t>(maxPayload, data.size() - offset);
                Buffer plain(data.begin() + offset, data.begin() + offset + chunkLen);
                offset += chunkLen;
                uint32_t seq = txSeq_++;
                packets.push_back(sealSegment(
                    buildMieruDataMetadata(kMieruDataClientToServer, sessionID_,
                                           seq, rxNextSeq_, currentWindowSize(),
                                           0, uint16_t(plain.size()), 0),
                    plain));
                txUnacked_.try_emplace(seq, UnackedSegment{std::move(plain), nowMs, nowMs, 0});
            }
            scheduleRetransmitTimer();
            if (packets.empty()) {
                completion({});
                return;
            }
            for (size_t i = 0; i + 1 < packets.size(); ++i) {
                raw_->send(serverTarget_, std::move(packets[i]), {});
            }
            raw_->send(serverTarget_, std::move(packets.back()), std::move(completion));
        } catch (const std::exception &e) {
            completion(e.what());
        }
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) {
            completion({}, true, terminal_);
            return;
        }
        if (socksReplyConsumed_ && !pending_.empty()) {
            const uint16_t prevWin = currentWindowSize();
            Buffer out = pending_.consume(maximum);
            const uint16_t nextWin = currentWindowSize();
            if (nextWin >= prevWin + 32 || (prevWin <= 256 && nextWin > prevWin)) {
                sendAckNow();
            }
            completion(std::move(out), false, {});
            return;
        }
        pendingReadMax_ = maximum;
        pendingRead_ = std::move(completion);
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        txUnacked_.clear();
        reorderBuf_.clear();
        if (sessionOpened_ && raw_) {
            try {
                uint32_t closeSeq = txSeq_++;
                Buffer closeMeta = buildMieruSessionMetadata(kMieruCloseSessionReq, sessionID_, closeSeq, 0, 0, 0);
                Buffer closePkt1 = sealSegment(closeMeta, {});
                raw_->send(serverTarget_, std::move(closePkt1), {});
                // Send a second redundant closeSessionRequest when tearing down an
                // active video/data stream so packet loss during a high-rate burst
                // cannot leave the server retransmitting dead segments.
                if (rxNextSeq_ > 4 || closeSeq > 4) {
                    Buffer closePkt2 = sealSegment(closeMeta, {});
                    raw_->send(serverTarget_, std::move(closePkt2), {});
                }
            } catch (...) {}
        }
        for (auto &sock : handshakeSockets_) {
            if (sock) sock->close();
        }
        handshakeSockets_.clear();
        if (raw_) {
            raw_->close();
            raw_ = nullptr;
        }
        if (readyCallback_) {
            auto cb = std::move(readyCallback_);
            readyCallback_ = {};
            cb(nullptr, terminal_.empty() ? Error("Stream closed") : terminal_);
        }
        if (pendingRead_) {
            auto cb = std::move(pendingRead_);
            pendingRead_ = {};
            cb({}, true, terminal_.empty() ? Error("Stream closed") : terminal_);
        }
    }

private:
    struct UnackedSegment {
        Buffer payload;
        uint64_t firstSentAtMs = 0;
        uint64_t sentAtMs = 0;
        int retries = 0;
    };

    void refreshKeysIfNeeded() {
        uint64_t nowSec = unixSeconds();
        uint64_t bucket = ((nowSec + 60) / 120) * 120;
        if (bucket != currentKeyBucket_) {
            currentKeyBucket_ = bucket;
            auto fresh = mieruCandidateKeys(cfg_.username, cfg_.password, nowSec);
            if (!fresh.empty()) {
                candidateKeys_ = std::move(fresh);
                txKey_ = candidateKeys_.front();
            }
        }
    }

    Buffer sealSegment(const Buffer &meta32, const Buffer &payload) {
        refreshKeysIfNeeded();
        return sealMieruUDPSegmentWithKey(cfg_.username, txKey_, meta32, payload);
    }

    Buffer openPacketMeta(const Buffer &nonce, const Buffer &encMeta) {
        if (rxKeyLocked_) {
            try {
                return crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, nonce, encMeta);
            } catch (...) {
                // Server may have rotated its 2-minute key bucket on a long-lived
                // stream (e.g. Spotify track playback, long YouTube video, or pooled DoH).
            }
        }
        for (const auto &cand : candidateKeys_) {
            try {
                Buffer plain = crypto::open(crypto::AEAD::XChaCha20Poly1305, cand, nonce, encMeta);
                rxKey_ = cand;
                if (!rxKeyLocked_) {
                    txKey_ = cand;
                }
                rxKeyLocked_ = true;
                return plain;
            } catch (...) {}
        }
        uint64_t nowSec = unixSeconds();
        currentKeyBucket_ = ((nowSec + 60) / 120) * 120;
        auto fresh = mieruCandidateKeys(cfg_.username, cfg_.password, nowSec);
        if (!fresh.empty()) {
            candidateKeys_ = std::move(fresh);
        }
        for (const auto &cand : candidateKeys_) {
            try {
                Buffer plain = crypto::open(crypto::AEAD::XChaCha20Poly1305, cand, nonce, encMeta);
                rxKey_ = cand;
                txKey_ = candidateKeys_.front();
                rxKeyLocked_ = true;
                return plain;
            } catch (...) {}
        }
        throw std::runtime_error("Mieru UDP metadata authentication failed");
    }

    uint32_t allocateFreshSessionID() {
        for (int tries = 0; tries < 8; ++tries) {
            Buffer r = crypto::randomBytes(4);
            uint32_t cand = readBE32(r.data());
            if (cand == 0) cand = 1;
            if (std::find(validSessionIDs_.begin(), validSessionIDs_.end(), cand) == validSessionIDs_.end()) {
                validSessionIDs_.push_back(cand);
                return cand;
            }
        }
        uint32_t fallback = sessionID_ + 1;
        if (fallback == 0) fallback = 1;
        if (std::find(validSessionIDs_.begin(), validSessionIDs_.end(), fallback) == validSessionIDs_.end()) {
            validSessionIDs_.push_back(fallback);
        }
        return fallback;
    }

    void appendIncomingBytes(const Buffer &bytes) {
        if (bytes.empty()) return;
        if (!socksReplyConsumed_) {
            handshakePending_.insert(handshakePending_.end(), bytes.begin(), bytes.end());
        } else {
            pending_.append(bytes);
        }
    }

    // Dynamic flow-control window (in segments): advertises up to 2048 segments
    // (~2.6 MB, matching high-BDP 4K YouTube seek bursts within the 4 MB kernel
    // UDP socket buffer) and scales back smoothly if unread bytes accumulate.
    uint16_t currentWindowSize() const noexcept {
        const int used = int(reorderBuf_.size()) + int(pending_.size() / 1280);
        const int avail = 2048 - used;
        return uint16_t(std::max<int>(64, std::min<int>(2048, avail)));
    }

    void sendAckNow() {
        if (closed_ || !raw_) return;
        unackedRxCount_ = 0;
        uint64_t nowMs = monotonicMillis();
        lastImmediateAckMs_ = nowMs;
        lastTxMs_ = nowMs;
        uint32_t ackSeq = txSeq_ > 0 ? txSeq_ - 1 : 0;
        Buffer ackPkt = sealSegment(
            buildMieruDataMetadata(kMieruAckClientToServer, sessionID_, ackSeq, rxNextSeq_, currentWindowSize(), 0, 0, 0),
            {});
        raw_->send(serverTarget_, std::move(ackPkt), {});
    }

    void requestCoalescedAck(bool outOfOrder, uint32_t newlyAcked = 1) {
        if (closed_) return;
        if (outOfOrder) {
            if (lastDupAckSeq_ != rxNextSeq_) {
                lastDupAckSeq_ = rxNextSeq_;
                dupAckSentCount_ = 0;
            }
            ++dupAckSentCount_;
            if (dupAckSentCount_ <= 4 ||
                ((dupAckSentCount_ % 8) == 0 && monotonicMillis() >= lastImmediateAckMs_ + 3)) {
                sendAckNow();
                return;
            }
        } else {
            lastDupAckSeq_ = 0;
            dupAckSentCount_ = 0;
            unackedRxCount_ += newlyAcked;
            if (newlyAcked > 1 || (rxNextSeq_ <= 16 && unackedRxCount_ >= 2) || unackedRxCount_ >= 4) {
                sendAckNow();
                return;
            }
        }
        if (ackTimerScheduled_ || !factory_ || !factory_->after) {
            if (!factory_ || !factory_->after) sendAckNow();
            return;
        }
        ackTimerScheduled_ = true;
        auto self = shared_from_this();
        factory_->after(0.002, [self]() {
            self->ackTimerScheduled_ = false;
            if (self->closed_) return;
            if (self->unackedRxCount_ > 0 || !self->reorderBuf_.empty()) {
                self->sendAckNow();
            }
        });
    }

    void scheduleGapAckTimer() {
        if (closed_ || gapTimerScheduled_ || reorderBuf_.empty() || !factory_ || !factory_->after) return;
        gapTimerScheduled_ = true;
        auto self = shared_from_this();
        factory_->after(0.025, [self]() {
            self->gapTimerScheduled_ = false;
            if (self->closed_ || self->reorderBuf_.empty()) return;
            self->sendAckNow();
            self->scheduleGapAckTimer();
        });
    }

    void scheduleKeepaliveTimer() {
        if (closed_ || keepaliveScheduled_ || !sessionOpened_ || !factory_ || !factory_->after) return;
        keepaliveScheduled_ = true;
        auto self = shared_from_this();
        // 10s keepalive heartbeat keeps CGNAT UDP mappings and mita's PacketUnderlay
        // alive ahead of the 15s DoH/DoT connection pool idle timeout.
        factory_->after(10.0, [self]() {
            self->keepaliveScheduled_ = false;
            if (self->closed_ || !self->sessionOpened_ || !self->raw_) return;
            uint64_t nowMs = monotonicMillis();
            if (nowMs >= self->lastTxMs_ + 9500 && self->txUnacked_.empty()) {
                self->sendAckNow();
            }
            self->scheduleKeepaliveTimer();
        });
    }

    void closeHandshakeSocketsExcept(const std::shared_ptr<Datagram> &winner) {
        for (auto &sock : handshakeSockets_) {
            if (sock && sock != winner) {
                sock->close();
            }
        }
        handshakeSockets_.clear();
    }

    void scheduleRetransmitTimer() {
        if (closed_ || retransmitScheduled_ || txUnacked_.empty() || !factory_ || !factory_->after) return;
        retransmitScheduled_ = true;
        auto self = shared_from_this();
        factory_->after(0.04, [self]() {
            self->retransmitScheduled_ = false;
            if (self->closed_ || self->txUnacked_.empty() || !self->raw_) return;
            // Once sessionOpened_ is true, the stream is published and owned by HJCppByteStream;
            // setup-scope cancellation must only abort pre-ready handshakes (!sessionOpened_).
            if (!self->sessionOpened_ && self->factory_ && self->factory_->cancelled && self->factory_->cancelled()) {
                self->close();
                return;
            }
            uint64_t nowMs = monotonicMillis();
            // Before the server's 10-byte SOCKS5 target reply is received (!socksReplyConsumed_),
            // mita may still be completing its outbound TCP handshake to the target host (e.g. 1.1.1.1:443).
            // Use a conservative minimum RTO (260ms) and a 5.5s silence budget during target connect
            // so a 24-connection burst cannot prematurely abort freshly opened sessions at ~1.7s.
            uint64_t minRto = self->socksReplyConsumed_ ? 120 : 260;
            uint64_t baseRto = std::clamp<uint64_t>((self->srttMs_ * 3) / 2, minRto, 420);
            size_t count = 0;
            for (auto it = self->txUnacked_.begin(); it != self->txUnacked_.end() && count < 24; ) {
                uint64_t rtoMs = std::min<uint64_t>(850, baseRto + uint64_t(it->second.retries) * 110);
                if (nowMs >= it->second.sentAtMs && (nowMs - it->second.sentAtMs) < rtoMs) {
                    ++it;
                    continue;
                }
                ++it->second.retries;
                // Fast-fail (~1.1s, 3 retries) ONLY if this stream had ALREADY completed its
                // SOCKS5 target handshake earlier, went idle for >= 1.5s, and received zero packets
                // since this write, so EncryptedDNSRequest.recoverIdle quickly redials dead NAT mappings.
                const bool staleIdleSilent =
                    self->socksReplyConsumed_ &&
                    (it->second.firstSentAtMs >= self->lastRxMs_ + 1500) &&
                    (nowMs >= it->second.firstSentAtMs + 1100) &&
                    (it->second.retries >= 3);
                const int maxRetries = self->socksReplyConsumed_ ? 8 : 10;
                const uint64_t maxSilenceMs = self->socksReplyConsumed_ ? 3800 : 5500;
                if (it->second.retries > maxRetries || staleIdleSilent ||
                    (it->second.retries >= (maxRetries - 2) && nowMs >= self->lastRxMs_ + maxSilenceMs)) {
                    self->failAll("Mieru UDP retransmission limit exceeded");
                    return;
                }
                it->second.sentAtMs = nowMs;
                self->lastTxMs_ = nowMs;
                uint32_t seq = it->first;
                const Buffer &plain = it->second.payload;
                Buffer pkt = self->sealSegment(
                    buildMieruDataMetadata(kMieruDataClientToServer, self->sessionID_,
                                           seq, self->rxNextSeq_, self->currentWindowSize(),
                                           0, uint16_t(plain.size()), 0),
                    plain);
                self->raw_->send(self->serverTarget_, std::move(pkt), {});
                ++it;
                ++count;
            }
            if (!self->txUnacked_.empty()) {
                self->scheduleRetransmitTimer();
            }
        });
    }

    void sendOpenSessionPacketForSid(uint32_t sid, bool incrementPayloadNonce = false) {
        if (closed_ || sessionOpened_ || !raw_) return;
        try {
            lastTxMs_ = monotonicMillis();
            refreshKeysIfNeeded();
            Buffer openPkt = sealMieruUDPSegmentWithKey(
                cfg_.username, txKey_,
                buildMieruSessionMetadata(kMieruOpenSessionReq, sid, 0, 0,
                                          uint16_t(initialSocksReq_.size()), 0),
                initialSocksReq_, incrementPayloadNonce);
            auto self = shared_from_this();
            raw_->send(serverTarget_, std::move(openPkt), [self](Error err) {
                if (!err.empty() && !self->sessionOpened_) {
                    self->failAll(err);
                }
            });
        } catch (const std::exception &e) {
            failAll(e.what());
        }
    }

    void sendOpenSessionPacket() {
        sendOpenSessionPacketForSid(sessionID_, false);
    }

    void rotateUnderlyingSocketAndSendOpen() {
        if (closed_ || sessionOpened_ || !factory_ || !factory_->udp) {
            sessionID_ = allocateFreshSessionID();
            sendOpenSessionPacketForSid(sessionID_, false);
            return;
        }
        Node nextNode = dialNode_;
        if (cfg_.portStart > 0 && cfg_.portEnd >= cfg_.portStart) {
            Buffer r = crypto::randomBytes(2);
            uint16_t span = uint16_t(cfg_.portEnd - cfg_.portStart + 1);
            nextNode.port = uint16_t(cfg_.portStart + (readBE16(r.data()) % span));
        }
        Target nextTarget{nextNode.dialHost(), nextNode.port, true, false};
        auto self = shared_from_this();
        factory_->udp(nextNode, [self, nextTarget = std::move(nextTarget)](std::shared_ptr<Datagram> freshDgram, Error err) mutable {
            if (self->closed_ || self->sessionOpened_) {
                if (freshDgram) freshDgram->close();
                return;
            }
            if (!err.empty() || !freshDgram) {
                self->sessionID_ = self->allocateFreshSessionID();
                self->sendOpenSessionPacketForSid(self->sessionID_, false);
                return;
            }
            // Keep previous handshake sockets open in handshakeSockets_ until sessionOpened_
            // becomes true so a delayed openSessionResponse arriving on Socket #0 is never dropped.
            if (self->raw_ && std::find(self->handshakeSockets_.begin(), self->handshakeSockets_.end(), self->raw_) == self->handshakeSockets_.end()) {
                self->handshakeSockets_.push_back(self->raw_);
            }
            self->handshakeSockets_.push_back(freshDgram);
            self->raw_ = freshDgram;
            self->serverTarget_ = std::move(nextTarget);
            std::weak_ptr<Datagram> weakFresh = freshDgram;
            freshDgram->start([self, weakFresh](Target, Buffer packet) {
                if (auto sock = weakFresh.lock()) {
                    if (!self->sessionOpened_) {
                        self->raw_ = sock;
                    }
                }
                self->onPacket(std::move(packet));
            }, [self, weakFresh](Error sockErr) {
                auto sock = weakFresh.lock();
                if (sock) {
                    self->handshakeSockets_.erase(
                        std::remove(self->handshakeSockets_.begin(), self->handshakeSockets_.end(), sock),
                        self->handshakeSockets_.end());
                }
                if (self->sessionOpened_) {
                    if (sock && sock != self->raw_) return;
                } else {
                    if (sockErr != "Native UDP connection cancelled" && !self->handshakeSockets_.empty()) return;
                }
                self->failAll(sockErr.empty() ? Error("Mieru UDP socket error") : sockErr);
            });
            self->sessionID_ = self->allocateFreshSessionID();
            self->sendOpenSessionPacketForSid(self->sessionID_, false);
        });
    }

    void scheduleOpenRetry(int attempt) {
        if (closed_ || sessionOpened_ || !factory_ || !factory_->after) return;
        if (factory_->cancelled && factory_->cancelled()) {
            failAll("Native UDP connection cancelled");
            return;
        }
        if (attempt > 6) {
            failAll("Mieru UDP session handshake timed out");
            return;
        }
        auto self = shared_from_this();
        const double jitter = (attempt >= 2)
            ? (double((initialSessionID_ ^ uint32_t(attempt * 2654435761u)) % 45) * 0.001)
            : 0.0;
        const double delay = ((attempt == 1) ? 0.32
                           : ((attempt == 2) ? 0.52
                           : ((attempt == 3) ? 0.75
                           : ((attempt == 4) ? 1.00
                           : ((attempt == 5) ? 1.25 : 1.45))))) + jitter;
        factory_->after(delay, [self, attempt]() {
            if (self->closed_ || self->sessionOpened_) return;
            if (self->factory_ && self->factory_->cancelled && self->factory_->cancelled()) {
                self->failAll("Native UDP connection cancelled");
                return;
            }
            self->openRetryAttempt_ = attempt;
            uint64_t nowSec = unixSeconds();
            if (!self->rxKeyLocked_) {
                self->currentKeyBucket_ = ((nowSec + 60) / 120) * 120;
                self->candidateKeys_ = mieruCandidateKeys(self->cfg_.username, self->cfg_.password, nowSec);
                if (!self->candidateKeys_.empty()) {
                    // Always keep txKey_ locked to the current 2-minute bucket key (index 0).
                    self->txKey_ = self->candidateKeys_.front();
                }
            }
            if (attempt == 1) {
                // First fast retry: re-send original sessionID_ in case the
                // initial uplink UDP datagram was dropped.
                self->sendOpenSessionPacketForSid(self->initialSessionID_, false);
            } else if (attempt == 2 || attempt == 4) {
                // Add a fresh ephemeral UDP socket in parallel (while keeping earlier
                // handshake sockets open) to escape ISP UDP 5-tuple QoS blackholes without
                // dropping late responses arriving on the initial socket.
                self->rotateUnderlyingSocketAndSendOpen();
            } else {
                // Allocate a fresh sessionID so that if an earlier openSessionReq reached
                // the server and its downlink openSessionResp was lost during a burst,
                // the server's KnownSession anti-replay filter will not reject our retry.
                self->sessionID_ = self->allocateFreshSessionID();
                self->sendOpenSessionPacketForSid(self->sessionID_, (attempt % 2) == 1);
            }
            // If within ±20s of a 2-minute bucket boundary on attempt >= 3, send an
            // additional probe packet encrypted with the adjacent bucket key without
            // mutating txKey_.
            const uint64_t mod120 = (nowSec + 60) % 120;
            if (attempt >= 3 && (mod120 <= 20 || mod120 >= 100) && self->candidateKeys_.size() > 1 && self->raw_) {
                const size_t adjIdx = (mod120 <= 20) ? 1 : (self->candidateKeys_.size() > 2 ? 2 : 1);
                try {
                    Buffer openMeta = buildMieruSessionMetadata(
                        kMieruOpenSessionReq, self->sessionID_, 0, 0, uint16_t(self->initialSocksReq_.size()), 0);
                    Buffer adjPkt = sealMieruUDPSegmentWithKey(
                        self->cfg_.username, self->candidateKeys_[adjIdx], openMeta, self->initialSocksReq_, false);
                    self->raw_->send(self->serverTarget_, std::move(adjPkt), {});
                } catch (...) {}
            }
            self->scheduleOpenRetry(attempt + 1);
        });
    }

    void onPacket(Buffer packet) {
        if (closed_ || packet.size() < 24 + 48) return;
        try {
            Buffer nonce(packet.begin(), packet.begin() + 24);
            Buffer encMeta(packet.begin() + 24, packet.begin() + 72);
            Buffer plainMeta = openPacketMeta(nonce, encMeta);
            ParsedMieruMetadata parsed = parseMieruMetadata(plainMeta);
            uint64_t nowMs = monotonicMillis();
            lastRxMs_ = nowMs;

            if (!sessionOpened_) {
                if (std::find(validSessionIDs_.begin(), validSessionIDs_.end(), parsed.sessionID) == validSessionIDs_.end()) {
                    return;
                }
                if (parsed.protoType == kMieruOpenSessionResp && parsed.statusCode != 0) {
                    // An earlier retried sessionID collided with KnownSession on the
                    // server after a lost downlink response. Immediately rotate to a
                    // fresh sessionID instead of aborting the handshake.
                    validSessionIDs_.erase(
                        std::remove(validSessionIDs_.begin(), validSessionIDs_.end(), parsed.sessionID),
                        validSessionIDs_.end());
                    if (openRetryAttempt_ < 6) {
                        ++openRetryAttempt_;
                        sessionID_ = allocateFreshSessionID();
                        sendOpenSessionPacketForSid(sessionID_);
                        return;
                    }
                    failAll("Mieru UDP openSessionResponse rejected");
                    return;
                }
            } else if (parsed.sessionID != sessionID_) {
                return;
            }

            if (parsed.protoType == kMieruCloseSessionReq || parsed.protoType == kMieruCloseSessionResp) {
                if (parsed.protoType == kMieruCloseSessionReq && raw_) {
                    try {
                        Buffer resp = sealSegment(
                            buildMieruSessionMetadata(kMieruCloseSessionResp, sessionID_, txSeq_++, 0, 0, 0),
                            {});
                        raw_->send(serverTarget_, std::move(resp), {});
                    } catch (...) {}
                }
                if (!socksReplyConsumed_) {
                    failAll("Mieru UDP target connection closed by server");
                } else {
                    failAll({});
                }
                return;
            }
            if (parsed.protoType == kMieruOpenSessionResp && sessionOpened_) {
                // Ignore late/duplicate openSessionResponse packets triggered by
                // earlier openSessionRequest retries; never tear down an already
                // established UDP session if the server rejects a duplicate open.
                if (parsed.statusCode != 0 || openRespPayloadConsumed_) {
                    return;
                }
            }

            if (parsed.protoType >= kMieruDataClientToServer && parsed.protoType <= kMieruDataServerToClientLE) {
                if (!txUnacked_.empty() && txUnacked_.begin()->first < parsed.unackSeq) {
                    while (!txUnacked_.empty() && txUnacked_.begin()->first < parsed.unackSeq) {
                        if (txUnacked_.begin()->second.retries == 0 &&
                            nowMs >= txUnacked_.begin()->second.firstSentAtMs) {
                            uint64_t sample = nowMs - txUnacked_.begin()->second.firstSentAtMs;
                            if (sample >= 5 && sample <= 2000) {
                                srttMs_ = (srttMs_ * 7 + sample) / 8;
                            }
                        }
                        txUnacked_.erase(txUnacked_.begin());
                    }
                    txDupAckSeq_ = parsed.unackSeq;
                    txDupAckCount_ = 0;
                } else if (!txUnacked_.empty() && parsed.unackSeq == txUnacked_.begin()->first &&
                           (parsed.protoType == kMieruAckServerToClient ||
                            parsed.protoType == kMieruDataServerToClient ||
                            parsed.protoType == kMieruDataServerToClientLE)) {
                    if (txDupAckSeq_ != parsed.unackSeq) {
                        txDupAckSeq_ = parsed.unackSeq;
                        txDupAckCount_ = 1;
                    } else {
                        ++txDupAckCount_;
                    }
                    auto it = txUnacked_.begin();
                    if (txDupAckCount_ >= 3 && nowMs >= it->second.sentAtMs + 45 && raw_) {
                        txDupAckCount_ = 0;
                        it->second.sentAtMs = nowMs;
                        lastTxMs_ = nowMs;
                        const Buffer &plain = it->second.payload;
                        Buffer pkt = sealSegment(
                            buildMieruDataMetadata(kMieruDataClientToServer, sessionID_,
                                                   it->first, rxNextSeq_, currentWindowSize(),
                                                   0, uint16_t(plain.size()), 0),
                            plain);
                        raw_->send(serverTarget_, std::move(pkt), {});
                    }
                }
            }

            Buffer plainPayload;
            size_t offset = 72 + size_t(parsed.prefixLen);
            if (parsed.payloadLen > 0) {
                if (packet.size() < offset + size_t(parsed.payloadLen) + 16) return;
                Buffer cipherPayload(packet.begin() + offset,
                                     packet.begin() + offset + size_t(parsed.payloadLen) + 16);
                if (parsed.protoType == kMieruDataServerToClientLE) {
                    cipherPayload = decodeMieruLowEntropyPayload(parsed, cipherPayload);
                }
                try {
                    plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, nonce, cipherPayload);
                } catch (...) {
                    Buffer beNonce = nonce;
                    incrementNonceBE(beNonce);
                    try {
                        plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, beNonce, cipherPayload);
                    } catch (...) {
                        Buffer leNonce = nonce;
                        incrementNonceLE(leNonce);
                        plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, leNonce, cipherPayload);
                    }
                }
            }

            bool justOpened = false;
            if (!sessionOpened_) {
                uint32_t winningSid = parsed.sessionID;
                sessionID_ = winningSid;
                sessionOpened_ = true;
                justOpened = true;
                if (openRetryAttempt_ == 0 && nowMs > handshakeStartMs_) {
                    uint64_t hsRtt = nowMs - handshakeStartMs_;
                    if (hsRtt >= 10 && hsRtt <= 1500) {
                        srttMs_ = std::clamp<uint64_t>(hsRtt, 50, 500);
                    }
                }
                if (raw_ && validSessionIDs_.size() > 1) {
                    for (uint32_t sid : validSessionIDs_) {
                        if (sid != winningSid) {
                            try {
                                Buffer closeMeta = buildMieruSessionMetadata(kMieruCloseSessionReq, sid, 1, 0, 0, 0);
                                raw_->send(serverTarget_, sealSegment(closeMeta, {}), {});
                            } catch (...) {}
                        }
                    }
                }
                closeHandshakeSocketsExcept(raw_);
                validSessionIDs_.assign(1, winningSid);
                scheduleKeepaliveTimer();
            }

            bool needCoalescedAck = false;
            bool ackOutOfOrder = false;
            uint32_t newlyAckedCount = 0;
            bool needImmediateAck = false;
            bool needGapTimer = false;

            if (parsed.protoType == kMieruOpenSessionResp) {
                if (!plainPayload.empty() && !openRespPayloadConsumed_) {
                    openRespPayloadConsumed_ = true;
                    appendIncomingBytes(plainPayload);
                }
                needCoalescedAck = true;
                ackOutOfOrder = false;
                newlyAckedCount = 1;
            } else if (parsed.protoType == kMieruDataServerToClient || parsed.protoType == kMieruDataServerToClientLE) {
                if (parsed.seq == 0 && rxNextSeq_ == 1 && !openRespPayloadConsumed_) {
                    rxNextSeq_ = 0;
                }
                if (parsed.seq == rxNextSeq_) {
                    dupAckSentCount_ = 0;
                    if (!plainPayload.empty()) {
                        appendIncomingBytes(plainPayload);
                    }
                    rxNextSeq_++;
                    uint32_t newlyAcked = 1;
                    while (true) {
                        auto it = reorderBuf_.find(rxNextSeq_);
                        if (it == reorderBuf_.end()) break;
                        appendIncomingBytes(it->second);
                        reorderBuf_.erase(it);
                        rxNextSeq_++;
                        newlyAcked++;
                    }
                    needCoalescedAck = true;
                    ackOutOfOrder = !reorderBuf_.empty();
                    newlyAckedCount = newlyAcked;
                    if (!reorderBuf_.empty()) {
                        needGapTimer = true;
                    }
                } else if (parsed.seq > rxNextSeq_ && reorderBuf_.size() < 4096) {
                    reorderBuf_.try_emplace(parsed.seq, std::move(plainPayload));
                    needCoalescedAck = true;
                    ackOutOfOrder = true;
                    newlyAckedCount = 0;
                    needGapTimer = true;
                } else {
                    // Duplicate segment (parsed.seq < rxNextSeq_): the server missed our ACK
                    // and is retransmitting. Immediately send an ACK (rate-limited to 4ms).
                    if (nowMs >= lastImmediateAckMs_ + 4) {
                        needImmediateAck = true;
                    } else {
                        needCoalescedAck = true;
                        ackOutOfOrder = false;
                        newlyAckedCount = 1;
                    }
                }
            }

            // Deliver any newly assembled contiguous bytes to the waiting read()
            // callback BEFORE computing currentWindowSize() for the outgoing ACK,
            // so the server always sees the freshly freed receive window during
            // high-rate YouTube seek bursts.
            if (!socksReplyConsumed_ && !handshakePending_.empty()) {
                Error socksErr;
                if (!consumeSocks5ReplyIfComplete(handshakePending_, socksErr)) {
                    if (needImmediateAck) sendAckNow();
                    else if (needCoalescedAck) requestCoalescedAck(ackOutOfOrder, newlyAckedCount);
                    if (needGapTimer) scheduleGapAckTimer();
                    if (justOpened && !closed_ && readyCallback_) {
                        auto cb = std::move(readyCallback_);
                        readyCallback_ = {};
                        cb(shared_from_this(), {});
                    }
                    return;
                }
                if (!socksErr.empty()) {
                    failAll(socksErr);
                    return;
                }
                socksReplyConsumed_ = true;
                if (!handshakePending_.empty()) {
                    pending_.append(handshakePending_);
                    handshakePending_.clear();
                }
            }

            if (needImmediateAck) {
                sendAckNow();
            } else if (needCoalescedAck) {
                requestCoalescedAck(ackOutOfOrder, newlyAckedCount);
            }
            if (needGapTimer) {
                scheduleGapAckTimer();
            }

            if (justOpened && !closed_ && readyCallback_) {
                auto cb = std::move(readyCallback_);
                readyCallback_ = {};
                cb(shared_from_this(), {});
            }

            if (socksReplyConsumed_ && !pending_.empty() && pendingRead_) {
                auto cb = std::move(pendingRead_);
                pendingRead_ = {};
                cb(pending_.consume(pendingReadMax_), false, {});
            }
        } catch (...) {
            // Ignore malformed/unauthenticated UDP packets per datagram security rules
        }
    }

    void failAll(Error err) {
        if (closed_) return;
        closed_ = true;
        txUnacked_.clear();
        reorderBuf_.clear();
        terminal_ = std::move(err);
        for (auto &sock : handshakeSockets_) {
            if (sock) sock->close();
        }
        handshakeSockets_.clear();
        if (raw_) {
            raw_->close();
            raw_ = nullptr;
        }
        if (readyCallback_) {
            auto cb = std::move(readyCallback_);
            readyCallback_ = {};
            cb(nullptr, terminal_.empty() ? Error("Mieru UDP session closed") : terminal_);
        }
        if (pendingRead_) {
            auto cb = std::move(pendingRead_);
            pendingRead_ = {};
            cb({}, true, terminal_);
        }
    }

    std::shared_ptr<Datagram> raw_;
    std::vector<std::shared_ptr<Datagram>> handshakeSockets_;
    std::shared_ptr<TransportFactory> factory_;
    Node dialNode_;
    Target serverTarget_;
    MieruConfig cfg_;
    std::vector<Buffer> candidateKeys_;
    Buffer txKey_, rxKey_;
    uint32_t sessionID_ = 0;
    uint32_t initialSessionID_ = 0;
    std::vector<uint32_t> validSessionIDs_;
    uint64_t currentKeyBucket_ = 0;
    uint64_t handshakeStartMs_ = 0;
    uint64_t lastRxMs_ = 0;
    uint64_t lastTxMs_ = 0;
    uint64_t srttMs_ = 140;
    int openRetryAttempt_ = 0;
    uint32_t txSeq_ = 1;
    uint32_t rxNextSeq_ = 1;
    uint32_t unackedRxCount_ = 0;
    uint32_t lastDupAckSeq_ = 0;
    uint32_t dupAckSentCount_ = 0;
    uint32_t txDupAckSeq_ = 0;
    uint32_t txDupAckCount_ = 0;
    uint64_t lastImmediateAckMs_ = 0;
    std::map<uint32_t, Buffer> reorderBuf_;
    std::map<uint32_t, UnackedSegment> txUnacked_;
    Buffer initialSocksReq_;
    Buffer handshakePending_;
    CursorBuffer pending_;
    StreamCallback readyCallback_;
    ReadCallback pendingRead_;
    size_t pendingReadMax_ = 0;
    Error terminal_;
    bool rxKeyLocked_ = false;
    bool sessionOpened_ = false;
    bool openRespPayloadConsumed_ = false;
    bool socksReplyConsumed_ = false;
    bool ackTimerScheduled_ = false;
    bool gapTimerScheduled_ = false;
    bool keepaliveScheduled_ = false;
    bool retransmitScheduled_ = false;
    bool closed_ = false;
};

// Mieru UDP Associate Datagram (uses marker 0x00 | BE16(len) | socks5_udp_pkt | 0xff)
class MieruUDPAssociateDatagram final : public Datagram, public std::enable_shared_from_this<MieruUDPAssociateDatagram> {
public:
    MieruUDPAssociateDatagram(Node node, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), factory_(std::move(factory)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram closed"); return; }
        if (data.size() > 65000 || target.host.empty() || !target.port) {
            completion("Invalid Mieru UDP datagram target or size");
            return;
        }
        Buffer encapsulated;
        try {
            Buffer addr = socksAddress(target);
            uint16_t socksUDPLen = uint16_t(3 + addr.size() + data.size());
            encapsulated.reserve(4 + socksUDPLen);
            encapsulated.push_back(0x00); // marker 1
            appendBE16(encapsulated, socksUDPLen);
            encapsulated.push_back(0x00);
            encapsulated.push_back(0x00);
            encapsulated.push_back(0x00);
            encapsulated.insert(encapsulated.end(), addr.begin(), addr.end());
            encapsulated.insert(encapsulated.end(), data.begin(), data.end());
            encapsulated.push_back(0xff); // marker 2
        } catch (const std::exception &e) {
            completion(e.what());
            return;
        }

        auto self = shared_from_this();
        sendPacketWithRetry(target, std::move(encapsulated), std::move(completion), true);
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        receive_ = std::move(receive);
        failure_ = std::move(failure);
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        resetActiveStream();
    }

private:
    void resetActiveStream() {
        auto r = std::move(reader_);
        auto s = std::move(stream_);
        streamUsed_ = false;
        if (r) r->close();
        else if (s) s->close();
    }

    void sendPacketWithRetry(Target target, Buffer packet, WriteCallback completion, bool allowRetry) {
        auto self = shared_from_this();
        ensureStream(target, [self, target, packet = std::move(packet), completion = std::move(completion), allowRetry](Error err) mutable {
            if (!err.empty() || !self->stream_) {
                completion(err.empty() ? Error("Mieru UDP associate stream unavailable") : err);
                return;
            }
            auto active = self->stream_;
            const bool wasUsed = self->streamUsed_;
            self->streamUsed_ = true;
            active->write(packet, [self, target, packet, completion = std::move(completion), active, wasUsed, allowRetry](Error writeErr) mutable {
                if (!writeErr.empty() && !self->closed_ && wasUsed && allowRetry) {
                    if (self->stream_ == active) self->resetActiveStream();
                    self->sendPacketWithRetry(std::move(target), std::move(packet), std::move(completion), false);
                    return;
                }
                completion(std::move(writeErr));
            });
        });
    }

    void ensureStream(const Target &initialTarget, WriteCallback ready) {
        if (stream_) { ready({}); return; }
        pendingReady_.push_back(std::move(ready));
        if (connecting_) return;
        connecting_ = true;

        Target assocTarget = initialTarget;
        assocTarget.udp = true;
        auto self = shared_from_this();
        connectMieru(node_, assocTarget, factory_, [self](std::shared_ptr<Stream> stream, Error err) {
            self->connecting_ = false;
            auto callbacks = std::move(self->pendingReady_);
            self->pendingReady_.clear();
            if (self->closed_ || !err.empty() || !stream) {
                Error finalErr = !err.empty() ? err : Error("Mieru UDP associate closed");
                for (auto &cb : callbacks) cb(finalErr);
                return;
            }
            self->stream_ = std::move(stream);
            self->reader_ = std::make_shared<Reader>(self->stream_);
            self->streamUsed_ = false;
            for (auto &cb : callbacks) cb({});
            self->readLoop();
        });
    }

    void readLoop() {
        if (closed_ || !reader_) return;
        auto self = shared_from_this();
        auto activeReader = reader_;
        activeReader->exactly(3, [self, activeReader](Buffer hdr, Error err) {
            if (self->closed_ || self->reader_ != activeReader) return;
            if (!err.empty()) {
                const bool wasUsed = self->streamUsed_;
                self->resetActiveStream();
                if (self->failure_ && err != "EOF" && !wasUsed) self->failure_(err);
                return;
            }
            if (hdr[0] != 0x00) {
                if (self->failure_) self->failure_("Invalid Mieru UDP associate start marker");
                return;
            }
            uint16_t dataLen = readBE16(hdr.data() + 1);
            activeReader->exactly(size_t(dataLen) + 1, [self, activeReader, dataLen](Buffer body, Error berr) {
                if (self->closed_ || self->reader_ != activeReader) return;
                if (!berr.empty()) {
                    self->resetActiveStream();
                    if (self->failure_) self->failure_(berr);
                    return;
                }
                if (body.back() != 0xff || dataLen < 7) {
                    if (self->failure_) self->failure_("Invalid Mieru UDP associate end marker");
                    return;
                }
                try {
                    Buffer addrAndData(body.begin() + 3, body.begin() + dataLen);
                    size_t consumed = 0;
                    Target source = parseSocksAddress(addrAndData, consumed);
                    Buffer payload(addrAndData.begin() + consumed, addrAndData.end());
                    if (self->receive_) self->receive_(source, std::move(payload));
                    self->readLoop();
                } catch (const std::exception &e) {
                    if (self->failure_) self->failure_(e.what());
                }
            });
        });
    }

    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
    std::vector<WriteCallback> pendingReady_;
    PacketCallback receive_;
    WriteCallback failure_;
    bool streamUsed_ = false;
    bool connecting_ = false;
    bool closed_ = false;
};

} // namespace

Error validateMieru(const Node &node, bool) {
    MieruConfig cfg;
    return parseMieruConfig(node, cfg);
}

void connectMieru(const Node &node, const Target &target,
                  std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    MieruConfig cfg;
    auto err = parseMieruConfig(node, cfg);
    if (!err.empty()) { completion(nullptr, err); return; }

    Node dialNode = node;
    if (cfg.portStart > 0 && cfg.portEnd >= cfg.portStart) {
        Buffer r = crypto::randomBytes(2);
        uint16_t span = uint16_t(cfg.portEnd - cfg.portStart + 1);
        dialNode.port = uint16_t(cfg.portStart + (readBE16(r.data()) % span));
    }

    Buffer sidBytes = crypto::randomBytes(4);
    uint32_t sessionID = readBE32(sidBytes.data());
    if (sessionID == 0) sessionID = 1;

    Buffer addr;
    try {
        addr = socksAddress(target);
    } catch (const std::exception &e) {
        completion(nullptr, e.what());
        return;
    }
    Buffer openReq;
    openReq.reserve(3 + addr.size());
    openReq.push_back(0x05);
    openReq.push_back(uint8_t(target.udp ? 0x03 : 0x01));
    openReq.push_back(0x00);
    openReq.insert(openReq.end(), addr.begin(), addr.end());

    // UDP Transport Path (Per-stream isolated Datagram socket)
    if (cfg.transport == "UDP") {
        if (!factory || !factory->udp) {
            completion(nullptr, "Mieru UDP transport unavailable");
            return;
        }
        Target serverTarget{dialNode.dialHost(), dialNode.port, true, false};
        factory->udp(dialNode, [factory, dialNode, serverTarget = std::move(serverTarget),
                                cfg = std::move(cfg), sessionID, openReq = std::move(openReq),
                                completion = std::move(completion)]
                     (std::shared_ptr<Datagram> dgram, Error dialErr) mutable {
            if (!dialErr.empty() || !dgram) {
                completion(nullptr, dialErr.empty() ? Error("Mieru UDP dial failed") : dialErr);
                return;
            }
            try {
                auto candKeys = mieruCandidateKeys(cfg.username, cfg.password, unixSeconds());
                auto udpStream = std::make_shared<MieruUDPStream>(
                    std::move(dgram), factory, std::move(dialNode), std::move(serverTarget), std::move(cfg),
                    std::move(candKeys), sessionID, std::move(openReq));
                udpStream->start(std::move(completion));
            } catch (const std::exception &e) {
                if (dgram) dgram->close();
                completion(nullptr, e.what());
            }
        });
        return;
    }

    // TCP Transport Path
    auto tls = tlsOptions(dialNode, false);
    factory->tcp(dialNode, tls, [cfg = std::move(cfg), sessionID, openReq = std::move(openReq),
                                 completion = std::move(completion)]
                 (std::shared_ptr<Stream> raw, Error dialErr) mutable {
        if (!dialErr.empty() || !raw) {
            completion(nullptr, dialErr.empty() ? Error("Mieru TCP dial failed") : dialErr);
            return;
        }
        try {
            auto candKeys = mieruCandidateKeys(cfg.username, cfg.password, unixSeconds());
            const Buffer &sessionKey = candKeys.front();
            Buffer nonce = mieruMakeNonce(cfg.username, crypto::randomBytes(20));
            Buffer nextNonce = nonce;

            Buffer wire;
            wire.reserve(24 + 48 + openReq.size() + 16);
            wire.insert(wire.end(), nonce.begin(), nonce.end());
            // Segment 0: openSessionRequest carrying the SOCKS5 target request
            Buffer openMeta = buildMieruSessionMetadata(
                kMieruOpenSessionReq, sessionID, 0, 0, uint16_t(openReq.size()), 0);
            Buffer sealedMeta = crypto::seal(crypto::AEAD::XChaCha20Poly1305, sessionKey, nextNonce, openMeta);
            incrementNonceBE(nextNonce);
            wire.insert(wire.end(), sealedMeta.begin(), sealedMeta.end());

            Buffer sealedPayload = crypto::seal(crypto::AEAD::XChaCha20Poly1305, sessionKey, nextNonce, openReq);
            incrementNonceBE(nextNonce);
            wire.insert(wire.end(), sealedPayload.begin(), sealedPayload.end());

            auto mieruStream = std::make_shared<MieruTCPStream>(
                raw, std::move(candKeys), std::move(nextNonce), sessionID, 1);
            mieruStream->writeInitialHandshake(std::move(wire), [mieruStream, completion = std::move(completion)](Error writeErr) mutable {
                if (!writeErr.empty()) {
                    mieruStream->close();
                    completion(nullptr, writeErr);
                    return;
                }
                completion(mieruStream, {});
            });
        } catch (const std::exception &e) {
            raw->close();
            completion(nullptr, e.what());
        }
    });
}

void makeMieruDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                       DatagramCallback completion) {
    auto err = validateMieru(node, true);
    if (!err.empty()) { completion(nullptr, err); return; }
    completion(std::make_shared<MieruUDPAssociateDatagram>(node, std::move(factory)), {});
}

bool mieruProtocolSelfTest() {
    try {
        Buffer key1 = mieruDeriveSessionKey("alice", "secret123", 1700000040);
        Buffer key2 = mieruDeriveSessionKey("alice", "secret123", 1700000050);
        if (key1.size() != 32 || key1 != key2) return false;
        Buffer nonce = mieruMakeNonce("alice", Buffer(20, 0x05));
        if (nonce.size() != 24) return false;
        for (size_t i = 0; i < 16; ++i) {
            if (nonce[i] < 0x20 || nonce[i] > 0x7e) return false;
        }

        Buffer meta = buildMieruSessionMetadata(kMieruOpenSessionReq, 0x12345678, 0, 0, 10, 0);
        if (meta.size() != 32) return false;
        Buffer ct = crypto::seal(crypto::AEAD::XChaCha20Poly1305, key1, nonce, meta);
        Buffer pt = crypto::open(crypto::AEAD::XChaCha20Poly1305, key1, nonce, ct);
        ParsedMieruMetadata parsed = parseMieruMetadata(pt);
        if (parsed.protoType != kMieruOpenSessionReq || parsed.sessionID != 0x12345678 || parsed.payloadLen != 10) {
            return false;
        }

        Node mieruNode;
        mieruNode.type = "mieru"; mieruNode.host = "127.0.0.1"; mieruNode.port = 2012;
        mieruNode.parameters["username"] = "alice";
        mieruNode.parameters["password"] = "pass123";
        mieruNode.parameters["transport"] = "UDP";
        if (!validateMieru(mieruNode, true).empty()) return false;

        // 1. Multi-stream isolation + duplicate openSessionResp rejection tolerance + 2-minute key rotation mid-stream
        struct LoopbackMieruDatagram final : public Datagram {
            PacketCallback rx;
            Buffer serverKey;
            Buffer rotatedServerKey;
            size_t closeReqReceived = 0;
            uint32_t lastAckUnackSeq = 0;
            uint16_t lastAckWinSize = 0;
            void send(Target target, Buffer data, WriteCallback completion) override {
                if (completion) completion({});
                if (data.size() < 72 || !rx) return;
                Buffer pktNonce(data.begin(), data.begin() + 24);
                Buffer encM(data.begin() + 24, data.begin() + 72);
                Buffer plainM = crypto::open(crypto::AEAD::XChaCha20Poly1305, serverKey, pktNonce, encM);
                ParsedMieruMetadata pm = parseMieruMetadata(plainM);
                if (pm.protoType == kMieruOpenSessionReq) {
                    Buffer respMeta = buildMieruSessionMetadata(kMieruOpenSessionResp, pm.sessionID, 0, 0, 0, 0);
                    Buffer respPkt = sealMieruUDPSegmentWithKey("alice", serverKey, respMeta, {});
                    rx(target, std::move(respPkt));
                    // Simulate a late duplicate openSessionResponse with status != 0 from a retried openSessionReq
                    Buffer dupRejMeta = buildMieruSessionMetadata(kMieruOpenSessionResp, pm.sessionID, 0, 1, 0, 0);
                    Buffer dupRejPkt = sealMieruUDPSegmentWithKey("alice", serverKey, dupRejMeta, {});
                    rx(target, std::move(dupRejPkt));
                    Buffer socksOk{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50, 'O', 'K'};
                    Buffer dataMeta = buildMieruDataMetadata(
                        kMieruDataServerToClient, pm.sessionID, 1, 1, 4096, 0, uint16_t(socksOk.size()), 0);
                    Buffer dataPkt = sealMieruUDPSegmentWithKey("alice", serverKey, dataMeta, socksOk);
                    rx(target, std::move(dataPkt));
                    // Simulate 2-minute key bucket rotation mid-song (Spotify) + out-of-order burst (seq 3 before seq 2)
                    if (!rotatedServerKey.empty()) {
                        Buffer chunk3{'B', 'U', 'R', 'S', 'T', '3'};
                        Buffer meta3 = buildMieruDataMetadata(
                            kMieruDataServerToClient, pm.sessionID, 3, 1, 4096, 0, uint16_t(chunk3.size()), 0);
                        rx(target, sealMieruUDPSegmentWithKey("alice", rotatedServerKey, meta3, chunk3));

                        Buffer chunk2{'R', 'O', 'T', '2', '_'};
                        Buffer meta2 = buildMieruDataMetadata(
                            kMieruDataServerToClient, pm.sessionID, 2, 1, 4096, 0, uint16_t(chunk2.size()), 0);
                        rx(target, sealMieruUDPSegmentWithKey("alice", rotatedServerKey, meta2, chunk2));
                    }
                } else if (pm.protoType == kMieruAckClientToServer) {
                    lastAckUnackSeq = pm.unackSeq;
                    lastAckWinSize = pm.windowSize;
                } else if (pm.protoType == kMieruCloseSessionReq) {
                    ++closeReqReceived;
                }
            }
            void start(PacketCallback receive, WriteCallback) override { rx = std::move(receive); }
            void close() override { rx = nullptr; }
        };

        auto allCandKeys = mieruCandidateKeys("alice", "pass123", unixSeconds());
        auto serverKey = allCandKeys.front();
        auto rotatedKey = allCandKeys.size() > 1 ? allCandKeys.back() : serverKey;
        auto factory = std::make_shared<TransportFactory>();
        size_t udpDialCount = 0;
        size_t totalCloseReqs = 0;
        std::vector<std::shared_ptr<LoopbackMieruDatagram>> dgrams;
        factory->udp = [&](const Node &, DatagramCallback cb) {
            ++udpDialCount;
            auto dgram = std::make_shared<LoopbackMieruDatagram>();
            dgram->serverKey = serverKey;
            dgram->rotatedServerKey = rotatedKey;
            dgrams.push_back(dgram);
            cb(dgram, {});
        };
        factory->post = [](std::function<void()> work) { work(); };
        factory->after = [](double, std::function<void()>) {};

        std::shared_ptr<Stream> s1, s2;
        connectMieru(mieruNode, Target{"1.1.1.1", 443, false, false}, factory,
                     [&](std::shared_ptr<Stream> s, Error err) { if (err.empty()) s1 = std::move(s); });
        connectMieru(mieruNode, Target{"8.8.8.8", 443, false, false}, factory,
                     [&](std::shared_ptr<Stream> s, Error err) { if (err.empty()) s2 = std::move(s); });
        if (!s1 || !s2 || udpDialCount != 2) return false;

        Buffer r1, r2;
        s1->read(64, [&](Buffer d, bool, Error err) { if (err.empty()) r1 = std::move(d); });
        s2->read(64, [&](Buffer d, bool, Error err) { if (err.empty()) r2 = std::move(d); });
        const Buffer expectedPayload{'O', 'K', 'R', 'O', 'T', '2', '_', 'B', 'U', 'R', 'S', 'T', '3'};
        if (r1 != expectedPayload || r2 != expectedPayload) return false;
        if (dgrams[0]->lastAckUnackSeq != 4 || dgrams[0]->lastAckWinSize < 1024) return false;

        s1->close();
        s2->close();
        for (const auto &dg : dgrams) totalCloseReqs += dg->closeReqReceived;
        if (totalCloseReqs < 2) return false;

        // 2. Handshake KnownSession replay rejection recovery via validSessionIDs_
        struct ReplayRejectingDatagram final : public Datagram {
            PacketCallback rx;
            Buffer serverKey;
            uint32_t firstSid = 0;
            size_t openAttempts = 0;
            void send(Target target, Buffer data, WriteCallback completion) override {
                if (completion) completion({});
                if (data.size() < 72 || !rx) return;
                Buffer pktNonce(data.begin(), data.begin() + 24);
                Buffer encM(data.begin() + 24, data.begin() + 72);
                Buffer plainM = crypto::open(crypto::AEAD::XChaCha20Poly1305, serverKey, pktNonce, encM);
                ParsedMieruMetadata pm = parseMieruMetadata(plainM);
                if (pm.protoType == kMieruOpenSessionReq) {
                    ++openAttempts;
                    if (openAttempts == 1) {
                        // First openSessionReq reaches server, server records firstSid in KnownSession,
                        // but the downlink openSessionResp(status=0) is lost in transit, and a retry
                        // with firstSid triggers status=1 rejection.
                        firstSid = pm.sessionID;
                        Buffer rejMeta = buildMieruSessionMetadata(kMieruOpenSessionResp, pm.sessionID, 0, 1, 0, 0);
                        rx(target, sealMieruUDPSegmentWithKey("alice", serverKey, rejMeta, {}));
                    } else if (pm.sessionID != firstSid) {
                        Buffer okMeta = buildMieruSessionMetadata(kMieruOpenSessionResp, pm.sessionID, 0, 0, 0, 0);
                        rx(target, sealMieruUDPSegmentWithKey("alice", serverKey, okMeta, {}));
                    }
                }
            }
            void start(PacketCallback receive, WriteCallback) override { rx = std::move(receive); }
            void close() override { rx = nullptr; }
        };

        auto replayFactory = std::make_shared<TransportFactory>();
        replayFactory->udp = [&](const Node &, DatagramCallback cb) {
            auto dg = std::make_shared<ReplayRejectingDatagram>();
            dg->serverKey = serverKey;
            cb(dg, {});
        };
        replayFactory->post = [](std::function<void()> work) { work(); };
        replayFactory->after = [](double, std::function<void()>) {};

        std::shared_ptr<Stream> recoveredStream;
        connectMieru(mieruNode, Target{"1.1.1.1", 443, false, false}, replayFactory,
                     [&](std::shared_ptr<Stream> s, Error err) { if (err.empty()) recoveredStream = std::move(s); });
        if (!recoveredStream) return false;
        recoveredStream->close();

        // 3. Handshake 5-tuple blackhole recovery via rotateUnderlyingSocketAndSendOpen on attempt == 2
        struct SilentDatagram final : public Datagram {
            bool closed = false;
            void send(Target, Buffer, WriteCallback completion) override {
                if (completion) completion({});
            }
            void start(PacketCallback, WriteCallback) override {}
            void close() override { closed = true; }
        };
        auto rotateFactory = std::make_shared<TransportFactory>();
        size_t rotateDialCount = 0;
        std::shared_ptr<SilentDatagram> firstBlackholeDgram;
        std::vector<std::function<void()>> scheduledTimers;
        rotateFactory->udp = [&](const Node &, DatagramCallback cb) {
            ++rotateDialCount;
            if (rotateDialCount == 1) {
                firstBlackholeDgram = std::make_shared<SilentDatagram>();
                cb(firstBlackholeDgram, {});
            } else {
                auto dg = std::make_shared<LoopbackMieruDatagram>();
                dg->serverKey = serverKey;
                cb(dg, {});
            }
        };
        rotateFactory->post = [](std::function<void()> work) { work(); };
        rotateFactory->after = [&](double, std::function<void()> work) {
            scheduledTimers.push_back(std::move(work));
        };

        std::shared_ptr<Stream> rotatedStream;
        connectMieru(mieruNode, Target{"1.1.1.1", 443, false, false}, rotateFactory,
                     [&](std::shared_ptr<Stream> s, Error err) { if (err.empty()) rotatedStream = std::move(s); });
        // Fire attempt 1 (250ms on socket #1, still silent) and attempt 2 (400ms -> rotates to socket #2)
        for (size_t idx = 0; idx < scheduledTimers.size() && !rotatedStream && idx < 4; ++idx) {
            auto fn = scheduledTimers[idx];
            fn();
        }
        if (!rotatedStream || rotateDialCount < 2 || !firstBlackholeDgram || !firstBlackholeDgram->closed) {
            return false;
        }
        rotatedStream->close();

        // 4. Late openSessionResp arriving on Socket #1 AFTER Socket #2 was rotated on attempt == 2
        // must still be received on Socket #1, promote Socket #1 as winner, and close Socket #2.
        struct DelayedSocketDatagram final : public Datagram {
            PacketCallback rx;
            bool closed = false;
            uint32_t capturedSid = 0;
            Target capturedTarget;
            Buffer serverKey;
            void send(Target target, Buffer data, WriteCallback completion) override {
                if (completion) completion({});
                if (data.size() < 72) return;
                Buffer pktNonce(data.begin(), data.begin() + 24);
                Buffer encM(data.begin() + 24, data.begin() + 72);
                try {
                    Buffer plainM = crypto::open(crypto::AEAD::XChaCha20Poly1305, serverKey, pktNonce, encM);
                    ParsedMieruMetadata pm = parseMieruMetadata(plainM);
                    if (pm.protoType == kMieruOpenSessionReq && capturedSid == 0) {
                        capturedSid = pm.sessionID;
                        capturedTarget = target;
                    }
                } catch (...) {}
            }
            void start(PacketCallback receive, WriteCallback) override { rx = std::move(receive); }
            void close() override { closed = true; rx = nullptr; }
        };
        auto lateSockFactory = std::make_shared<TransportFactory>();
        std::vector<std::shared_ptr<DelayedSocketDatagram>> parallelSocks;
        std::vector<std::function<void()>> lateTimers;
        lateSockFactory->udp = [&](const Node &, DatagramCallback cb) {
            auto dg = std::make_shared<DelayedSocketDatagram>();
            dg->serverKey = serverKey;
            parallelSocks.push_back(dg);
            cb(dg, {});
        };
        lateSockFactory->post = [](std::function<void()> work) { work(); };
        lateSockFactory->after = [&](double, std::function<void()> work) {
            lateTimers.push_back(std::move(work));
        };
        std::shared_ptr<Stream> lateWinStream;
        connectMieru(mieruNode, Target{"1.1.1.1", 443, false, false}, lateSockFactory,
                     [&](std::shared_ptr<Stream> s, Error err) { if (err.empty()) lateWinStream = std::move(s); });
        // Fire attempt 1 and attempt 2 (rotates to Socket #2, while Socket #1 MUST remain open!)
        for (size_t idx = 0; idx < lateTimers.size() && idx < 2; ++idx) {
            auto fn = lateTimers[idx];
            fn();
        }
        if (parallelSocks.size() < 2 || parallelSocks[0]->closed || parallelSocks[1]->closed) {
            return false;
        }
        // Now deliver openSessionResp on Socket #1 (simulating 700ms burst RTT on the initial socket)
        Buffer lateRespMeta = buildMieruSessionMetadata(kMieruOpenSessionResp, parallelSocks[0]->capturedSid, 0, 0, 0, 0);
        parallelSocks[0]->rx(parallelSocks[0]->capturedTarget,
                             sealMieruUDPSegmentWithKey("alice", serverKey, lateRespMeta, {}));
        // Socket #1 must win and remain open; Socket #2 must be automatically closed!
        if (!lateWinStream || parallelSocks[0]->closed || !parallelSocks[1]->closed) {
            return false;
        }
        // 5. Verify established MieruUDPStream survives 40ms retransmit timer even if setup
        // factory->cancelled() returns true after readyCallback_ (post-setup scope detachment).
        bool scopeFlagAfterReady = true;
        lateSockFactory->cancelled = [&]() { return scopeFlagAfterReady; };
        Error writeAfterReadyErr = "unset";
        lateWinStream->write({0x16, 0x03, 0x01, 0x02, 0x00}, [&](Error e) { writeAfterReadyErr = std::move(e); });
        if (!writeAfterReadyErr.empty() || parallelSocks[0]->closed) {
            return false;
        }
        // Trigger the scheduled 40ms retransmit timer
        if (!lateTimers.empty()) {
            auto retransmitFn = lateTimers.back();
            retransmitFn();
        }
        if (parallelSocks[0]->closed) {
            return false;
        }
        lateWinStream->close();

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
