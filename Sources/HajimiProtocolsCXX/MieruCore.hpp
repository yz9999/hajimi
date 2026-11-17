#pragma once
// Mieru v3 Key Schedule, AEAD Metadata Framing & Low-Entropy Codec
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace hajimi::mieru_detail {

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

inline uint64_t monotonicMillis() noexcept {
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

Error parseMieruConfig(const Node &node, MieruConfig &cfg);
Buffer mieruDeriveKeyForBucket(const std::string &username, const std::string &password, uint64_t roundedBucketSec);
Buffer mieruDeriveSessionKey(const std::string &username, const std::string &password, uint64_t unixTimeSec);
std::vector<Buffer> mieruCandidateKeys(const std::string &username, const std::string &password, uint64_t unixTimeSec);
Buffer mieruMakeNonce(const std::string &username, const Buffer &randomPrefix20);
Buffer sealMieruUDPSegmentWithKey(const std::string &username, const Buffer &key,
                                  const Buffer &meta32, const Buffer &payload);
Buffer buildMieruSessionMetadata(uint8_t protoType, uint32_t sessionID, uint32_t seq,
                                 uint8_t statusCode, uint16_t payloadLen, uint8_t suffixLen = 0);
Buffer buildMieruDataMetadata(uint8_t protoType, uint32_t sessionID, uint32_t seq,
                              uint32_t unackSeq, uint16_t windowSize,
                              uint8_t prefixLen, uint16_t payloadLen, uint8_t suffixLen = 0);
ParsedMieruMetadata parseMieruMetadata(const Buffer &meta);
Buffer encodeMieruLowEntropyPayload(uint8_t lowEntropyMode, uint32_t lowEntropyMask, uint8_t lowEntropyMaskRot,
                                    const Buffer &cipherPlusTag, Buffer &outMeta32);
Buffer decodeMieruLowEntropyPayload(const ParsedMieruMetadata &parsed, const Buffer &encodedPlusTag);
bool consumeSocks5ReplyIfComplete(Buffer &buf, Error &outError);

} // namespace hajimi::mieru_detail
