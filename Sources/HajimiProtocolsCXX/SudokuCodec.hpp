#pragma once
// Sudoku Protocol Codec, Key Schedule, O(1) 4x4 Puzzle Table & KIP Framing
#include "ProtocolCommon.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace hajimi::sudoku_detail {
using namespace proto_common;

struct SudokuConfig {
    std::string key;
    std::string aeadMethod = "chacha20-poly1305";
    std::string tableType = "prefer_ascii";
    std::string customTable;
    uint32_t paddingMin = 2;
    uint32_t paddingMax = 7;
    bool enablePureDownlink = true;
    bool disableHttpMask = false;
    std::string httpMaskMode = "auto";
    bool httpMaskTls = false;
    std::string httpMaskHost;
    std::string pathRoot;
    std::string multiplex = "off";
};

using SudokuGrid = std::array<uint8_t, 16>;
struct SudokuBitset288 {
    uint64_t w[5]{0, 0, 0, 0, 0};
    void set(uint16_t b) { w[b >> 6] |= (1ULL << (b & 63)); }
};

struct SudokuLayout {
    bool isAscii = true;
    bool isCustom = false;
    uint8_t xMask = 0;
    uint8_t xBits[2]{0, 0};
    uint8_t pBits[2]{0, 0};
    uint8_t vBits[4]{0, 0, 0, 0};
    std::array<uint8_t, 64> groupToByteLut{};
    std::array<uint8_t, 256> byteToGroupLut{}; // 0..63 for valid hint, 0xff for non-hint padding
    std::vector<uint8_t> paddingPool;

    uint8_t encodeHint(uint8_t val, uint8_t pos) const noexcept {
        return groupToByteLut[((val & 0x03) << 4) | (pos & 0x0f)];
    }

    uint8_t encodeGroup(uint8_t group) const noexcept {
        return groupToByteLut[group & 0x3f];
    }

    bool isHint(uint8_t b) const noexcept {
        return byteToGroupLut[b] < 64;
    }

    bool decodeGroup(uint8_t b, uint8_t &outGroup) const noexcept {
        uint8_t g = byteToGroupLut[b];
        if (g >= 64) return false;
        outGroup = g;
        return true;
    }

    uint8_t computeGroupByteRaw(uint8_t group) const noexcept {
        uint8_t val = (group >> 4) & 0x03;
        uint8_t pos = group & 0x0f;
        if (isAscii) {
            uint8_t b = uint8_t(0x40 | (val << 4) | pos);
            return (b == 0x7f) ? uint8_t('\n') : b;
        }
        if (isCustom) {
            uint8_t out = xMask;
            if ((val & 0x02) != 0) out |= uint8_t(1u << pBits[0]);
            if ((val & 0x01) != 0) out |= uint8_t(1u << pBits[1]);
            if ((pos & 0x08) != 0) out |= uint8_t(1u << vBits[0]);
            if ((pos & 0x04) != 0) out |= uint8_t(1u << vBits[1]);
            if ((pos & 0x02) != 0) out |= uint8_t(1u << vBits[2]);
            if ((pos & 0x01) != 0) out |= uint8_t(1u << vBits[3]);
            return out;
        }
        return uint8_t((val << 5) | pos);
    }

    void populateLookupTables() noexcept {
        byteToGroupLut.fill(0xff);
        for (uint8_t g = 0; g < 64; ++g) {
            uint8_t b = computeGroupByteRaw(g);
            groupToByteLut[g] = b;
            byteToGroupLut[b] = g;
        }
    }
};

struct SudokuTable {
    SudokuLayout layout;
    std::array<std::vector<std::array<uint8_t, 4>>, 256> encodeTable;
    std::array<SudokuBitset288, 64> hintSets;

    bool solve4Hints(const uint8_t wireHints[4], uint8_t &outByte) const {
        uint8_t g0, g1, g2, g3;
        if (!layout.decodeGroup(wireHints[0], g0) ||
            !layout.decodeGroup(wireHints[1], g1) ||
            !layout.decodeGroup(wireHints[2], g2) ||
            !layout.decodeGroup(wireHints[3], g3)) {
            return false;
        }
        const auto &s0 = hintSets[g0 & 0x3f];
        const auto &s1 = hintSets[g1 & 0x3f];
        const auto &s2 = hintSets[g2 & 0x3f];
        const auto &s3 = hintSets[g3 & 0x3f];
        uint64_t r0 = s0.w[0] & s1.w[0] & s2.w[0] & s3.w[0];
        uint64_t r1 = s0.w[1] & s1.w[1] & s2.w[1] & s3.w[1];
        uint64_t r2 = s0.w[2] & s1.w[2] & s2.w[2] & s3.w[2];
        uint64_t r3 = s0.w[3] & s1.w[3] & s2.w[3] & s3.w[3];
        uint64_t r4 = s0.w[4] & s1.w[4] & s2.w[4] & s3.w[4];
        if ((r0 | r1 | r2 | r3) == 0) return false;
        uint64_t multi = (r0 & (r0 - 1)) | (r1 & (r1 - 1)) | (r2 & (r2 - 1)) | (r3 & (r3 - 1)) | r4;
        if (multi != 0) return false;
        int seen = (r0 != 0 ? 1 : 0) + (r1 != 0 ? 1 : 0) + (r2 != 0 ? 1 : 0) + (r3 != 0 ? 1 : 0);
        if (seen != 1) return false;
        if (r0 != 0) { outByte = uint8_t(__builtin_ctzll(r0)); return true; }
        if (r1 != 0) { outByte = uint8_t(64 + __builtin_ctzll(r1)); return true; }
        if (r2 != 0) { outByte = uint8_t(128 + __builtin_ctzll(r2)); return true; }
        outByte = uint8_t(192 + __builtin_ctzll(r3));
        return true;
    }
};

constexpr uint8_t kKIPTypeClientHello = 0x01;
constexpr uint8_t kKIPTypeServerHello = 0x02;
constexpr uint8_t kKIPTypeOpenTCP     = 0x10;
constexpr uint8_t kKIPTypeStartMux    = 0x11;
constexpr uint8_t kKIPTypeStartUoT    = 0x12;
constexpr uint8_t kKIPTypeKeepAlive   = 0x14;
constexpr uint32_t kKIPFeatureAll     = 0x1F;

// SUDOKU-ASCII/sudoku pkg/mux/session.go frame types:
// Header: [1B frameType][4B streamID (BE)][2B payloadLen (BE)][payload]
constexpr uint8_t kSudokuMuxFrameOpen  = 0x01;
constexpr uint8_t kSudokuMuxFrameData  = 0x02;
constexpr uint8_t kSudokuMuxFrameClose = 0x03;
constexpr uint8_t kSudokuMuxFrameReset = 0x04;

bool isValidCustomTablePattern(const std::string &pattern);
Error parseSudokuConfig(const Node &node, SudokuConfig &cfg);
bool sudokuRecoverMasterPublicKey(const std::string &keyHex, std::string &outMasterPubHex, Buffer &outUserHash8);
SudokuLayout buildSudokuLayout(bool preferAscii, const std::string &customPattern);
std::shared_ptr<const SudokuTable> getSudokuTable(const std::string &masterKey, bool preferAscii, const std::string &customPattern);
void sudokuAppendEncodedBytes(Buffer &out, const Buffer &input, const SudokuTable &table, uint32_t paddingMin = 0, uint32_t paddingMax = 0);
Buffer sudokuEncodeBytes(const Buffer &input, const SudokuTable &table, uint32_t paddingMin = 0, uint32_t paddingMax = 0);
Buffer sudokuEncodeTable(const Buffer &input, bool preferAscii, const std::string &customTable = "");
Buffer sudokuDecodeTable(const Buffer &input, bool preferAscii, const std::string &customTable = "");
Buffer hkdfExpandSHA256(const Buffer &prk, const std::string &infoStr, size_t outLen);
void deriveSudokuPSKDirectionalBases(const std::string &masterPubKey, Buffer &outC2S, Buffer &outS2C);
void deriveSudokuSessionDirectionalBases(const std::string &masterPubKey, const Buffer &shared32,
                                         const Buffer &nonce16, Buffer &outC2S, Buffer &outS2C);
Buffer deriveSudokuEpochKey(const Buffer &baseKey32, const std::string &aeadMethod, uint32_t epoch);
uint32_t randomNonZeroUint32();
uint64_t randomNonZeroUint64();
void generateX25519KeyPair(Buffer &outPriv32, Buffer &outPub32);
Buffer computeX25519Shared(const Buffer &priv32, const Buffer &peerPub32);
Buffer buildKIPMessage(uint8_t type, const Buffer &payload);

} // namespace hajimi::sudoku_detail
