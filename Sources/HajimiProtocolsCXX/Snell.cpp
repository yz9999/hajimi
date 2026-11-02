#include "Snell.hpp"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <utility>

#ifndef OSSL_KDF_PARAM_ARGON2_MEMCOST
#define OSSL_KDF_PARAM_ARGON2_MEMCOST "memcost"
#endif
#ifndef OSSL_KDF_PARAM_ARGON2_LANES
#define OSSL_KDF_PARAM_ARGON2_LANES "lanes"
#endif
#ifndef OSSL_KDF_PARAM_ARGON2_VERSION
#define OSSL_KDF_PARAM_ARGON2_VERSION "version"
#endif
#ifndef OSSL_KDF_PARAM_THREADS
#define OSSL_KDF_PARAM_THREADS "threads"
#endif

namespace hajimi {
namespace {
uint16_t snellWord(const uint8_t *bytes) { return uint16_t(bytes[0]) << 8 | bytes[1]; }
void snellPut16(Buffer &bytes, size_t number) { bytes.push_back(uint8_t(number >> 8)); bytes.push_back(uint8_t(number)); }
void nextNonce(Buffer &nonce) {
    for (auto &byte : nonce) if (++byte) return;
    throw std::runtime_error("Snell AEAD nonce exhausted");
}
crypto::AEAD snellCipher(unsigned version) {
    return version == 1 ? crypto::AEAD::ChaCha20Poly1305 : crypto::AEAD::AES128GCM;
}
unsigned snellVersion(const Node &node) {
    auto raw = node.option("version", "4");
    if (raw.size() != 1 || raw[0] < '1' || raw[0] > '4')
        throw std::runtime_error("Snell native wire versions are 1 through 4");
    return unsigned(raw[0] - '0');
}
void swapPadding(Buffer &bytes, size_t padding, size_t payload) {
    for (size_t i = 0; i < std::min(padding, payload); i += 2) std::swap(bytes[i], bytes[padding + i]);
}
}
namespace {
void putLE32(uint8_t *dst, uint32_t v) {
    dst[0] = uint8_t(v);
    dst[1] = uint8_t(v >> 8);
    dst[2] = uint8_t(v >> 16);
    dst[3] = uint8_t(v >> 24);
}
uint64_t loadLE64(const uint8_t *src) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | src[i];
    return v;
}
void storeLE64(uint8_t *dst, uint64_t v) {
    for (int i = 0; i < 8; ++i) dst[i] = uint8_t(v >> (i * 8));
}
uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}
// RFC 7693 BLAKE2b with arbitrary digest length (1..64) for Argon2id fallback on OpenSSL < 3.2
void blake2bHash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    static const uint8_t sigma[12][16] = {
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
    };
    uint64_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = iv[i];
    h[0] ^= 0x01010000ULL ^ uint64_t(outlen);
    uint64_t t0 = 0, t1 = 0;
    auto compress = [&](const uint8_t *block, bool last) {
        uint64_t v[16], m[16];
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[i + 8] = iv[i]; }
        v[12] ^= t0; v[13] ^= t1;
        if (last) v[14] = ~v[14];
        for (int i = 0; i < 16; ++i) m[i] = loadLE64(block + i * 8);
        auto G = [&](int a, int b, int c, int d, uint64_t x, uint64_t y) {
            v[a] = v[a] + v[b] + x; v[d] = rotr64(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];     v[b] = rotr64(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y; v[d] = rotr64(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];     v[b] = rotr64(v[b] ^ v[c], 63);
        };
        for (int r = 0; r < 12; ++r) {
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
    size_t offset = 0;
    while (inlen - offset > 128) {
        t0 += 128; if (t0 < 128) ++t1;
        compress(in + offset, false);
        offset += 128;
    }
    uint8_t lastBlock[128]{};
    size_t rem = inlen - offset;
    if (rem) std::memcpy(lastBlock, in + offset, rem);
    t0 += rem; if (t0 < rem) ++t1;
    compress(lastBlock, true);
    uint8_t digest[64];
    for (int i = 0; i < 8; ++i) storeLE64(digest + i * 8, h[i]);
    std::memcpy(out, digest, outlen);
}
void argon2HPrime(uint8_t *out, uint32_t outlen, const uint8_t *in, size_t inlen) {
    Buffer buf(4 + inlen);
    putLE32(buf.data(), outlen);
    std::memcpy(buf.data() + 4, in, inlen);
    if (outlen <= 64) {
        blake2bHash(out, outlen, buf.data(), buf.size());
        return;
    }
    uint8_t v[64];
    blake2bHash(v, 64, buf.data(), buf.size());
    std::memcpy(out, v, 32);
    size_t pos = 32;
    uint32_t r = (outlen + 31) / 32 - 2;
    for (uint32_t i = 1; i < r; ++i) {
        blake2bHash(v, 64, v, 64);
        std::memcpy(out + pos, v, 32);
        pos += 32;
    }
    uint32_t lastLen = outlen - 32 * r;
    blake2bHash(out + pos, lastLen, v, 64);
}
using ArgonBlock = std::array<uint64_t, 128>;
void argon2GB(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d) {
    auto fBlaMka = [](uint64_t x, uint64_t y) {
        return x + y + 2ULL * uint64_t(uint32_t(x)) * uint64_t(uint32_t(y));
    };
    a = fBlaMka(a, b); d = rotr64(d ^ a, 32);
    c = fBlaMka(c, d); b = rotr64(b ^ c, 24);
    a = fBlaMka(a, b); d = rotr64(d ^ a, 16);
    c = fBlaMka(c, d); b = rotr64(b ^ c, 63);
}
void argon2PermuteP(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3,
                    uint64_t *v4, uint64_t *v5, uint64_t *v6, uint64_t *v7,
                    uint64_t *v8, uint64_t *v9, uint64_t *v10, uint64_t *v11,
                    uint64_t *v12, uint64_t *v13, uint64_t *v14, uint64_t *v15) {
    argon2GB(*v0, *v4,  *v8, *v12); argon2GB(*v1, *v5,  *v9, *v13);
    argon2GB(*v2, *v6, *v10, *v14); argon2GB(*v3, *v7, *v11, *v15);
    argon2GB(*v0, *v5, *v10, *v15); argon2GB(*v1, *v6, *v11, *v12);
    argon2GB(*v2, *v7,  *v8, *v13); argon2GB(*v3, *v4,  *v9, *v14);
}
ArgonBlock argon2CompressG(const ArgonBlock &x, const ArgonBlock &y) {
    ArgonBlock r, z;
    for (size_t i = 0; i < 128; ++i) { r[i] = x[i] ^ y[i]; z[i] = r[i]; }
    for (size_t i = 0; i < 8; ++i) {
        size_t base = i * 16;
        argon2PermuteP(&z[base + 0], &z[base + 1], &z[base + 2], &z[base + 3],
                       &z[base + 4], &z[base + 5], &z[base + 6], &z[base + 7],
                       &z[base + 8], &z[base + 9], &z[base + 10], &z[base + 11],
                       &z[base + 12], &z[base + 13], &z[base + 14], &z[base + 15]);
    }
    for (size_t i = 0; i < 8; ++i) {
        size_t col = i * 2;
        argon2PermuteP(&z[col + 0],   &z[col + 1],   &z[col + 16],  &z[col + 17],
                       &z[col + 32],  &z[col + 33],  &z[col + 48],  &z[col + 49],
                       &z[col + 64],  &z[col + 65],  &z[col + 80],  &z[col + 81],
                       &z[col + 96],  &z[col + 97],  &z[col + 112], &z[col + 113]);
    }
    for (size_t i = 0; i < 128; ++i) z[i] ^= r[i];
    return z;
}
Buffer deriveSnellArgon2idFallback(const std::string &psk, const Buffer &salt) {
    // RFC 9106 Argon2id: p=1, T=32, m=8 KiB (8 blocks, segment length=2), t=3, v=0x13, y=2
    Buffer h0Input(4 * 10 + psk.size() + salt.size(), 0);
    size_t pos = 0;
    auto push32 = [&](uint32_t v) { putLE32(h0Input.data() + pos, v); pos += 4; };
    push32(1); // lanes = 1
    push32(32); // taglen = 32
    push32(8); // memory = 8 KiB
    push32(3); // passes = 3
    push32(0x13); // version = 0x13
    push32(2); // Argon2id = 2
    push32(uint32_t(psk.size()));
    std::memcpy(h0Input.data() + pos, psk.data(), psk.size()); pos += psk.size();
    push32(uint32_t(salt.size()));
    std::memcpy(h0Input.data() + pos, salt.data(), salt.size()); pos += salt.size();
    push32(0); // secret len = 0
    push32(0); // ad len = 0
    uint8_t h0[72]{};
    blake2bHash(h0, 64, h0Input.data(), h0Input.size());

    std::array<ArgonBlock, 8> memory{};
    for (uint32_t j = 0; j < 2; ++j) {
        putLE32(h0 + 64, j);
        putLE32(h0 + 68, 0);
        uint8_t raw[1024];
        argon2HPrime(raw, 1024, h0, 72);
        for (size_t k = 0; k < 128; ++k) memory[j][k] = loadLE64(raw + k * 8);
    }

    constexpr uint32_t q = 8, sl = 2;
    ArgonBlock zero{};
    for (uint32_t pass = 0; pass < 3; ++pass) {
        for (uint32_t slice = 0; slice < 4; ++slice) {
            ArgonBlock addresses{};
            if (pass == 0 && slice < 2) {
                ArgonBlock input{};
                input[0] = pass; input[1] = 0; input[2] = slice;
                input[3] = q; input[4] = 3; input[5] = 2; input[6] = 1;
                addresses = argon2CompressG(zero, argon2CompressG(zero, input));
            }
            uint32_t startIndex = (pass == 0 && slice == 0) ? 2 : 0;
            for (uint32_t idx = startIndex; idx < sl; ++idx) {
                uint32_t curr = slice * sl + idx;
                uint32_t prev = (curr == 0) ? (q - 1) : (curr - 1);
                uint64_t pseudoRand = (pass == 0 && slice < 2) ? addresses[idx] : memory[prev][0];
                uint32_t j1 = uint32_t(pseudoRand);
                uint32_t refAreaSize = (pass == 0)
                    ? ((slice == 0) ? (idx - 1) : (slice * sl + idx - 1))
                    : (q - sl + idx - 1);
                uint64_t relPos = (uint64_t(j1) * uint64_t(j1)) >> 32;
                relPos = refAreaSize - 1 - ((uint64_t(refAreaSize) * relPos) >> 32);
                uint32_t startPos = (pass == 0) ? 0 : (((slice + 1) % 4) * sl);
                uint32_t refIdx = (startPos + uint32_t(relPos)) % q;
                ArgonBlock nextBlock = argon2CompressG(memory[prev], memory[refIdx]);
                if (pass == 0) memory[curr] = nextBlock;
                else for (size_t k = 0; k < 128; ++k) memory[curr][k] ^= nextBlock[k];
            }
        }
    }
    uint8_t finalBlock[1024];
    for (size_t k = 0; k < 128; ++k) storeLE64(finalBlock + k * 8, memory[q - 1][k]);
    Buffer key(32);
    argon2HPrime(key.data(), 32, finalBlock, 1024);
    return key;
}
} // namespace

namespace snell {
Buffer deriveKey(const std::string &psk, const Buffer &salt, unsigned version) {
    if (salt.size() != 16 || psk.empty() || !version || version > 4)
        throw std::runtime_error("Invalid Snell key parameters");
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> algorithm(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
    Buffer key(32);
    if (algorithm) {
        std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> context(EVP_KDF_CTX_new(algorithm.get()), EVP_KDF_CTX_free);
        if (!context) throw std::runtime_error("Cannot create Snell Argon2id context");
        uint32_t iterations = 3, memory = 8, lanes = 1, threads = 1, argonVersion = 0x13;
        OSSL_PARAM parameters[] = {
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char *>(psk.data()), psk.size()),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt.data()), salt.size()),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &argonVersion),
            OSSL_PARAM_construct_end()
        };
        if (EVP_KDF_derive(context.get(), key.data(), key.size(), parameters) != 1)
            throw std::runtime_error("Cannot derive Snell Argon2id key");
    } else {
        key = deriveSnellArgon2idFallback(psk, salt);
    }
    if (version >= 2) key.resize(16);
    return key;
}
Encoder::Encoder(const std::string &psk, unsigned version, Buffer salt, size_t firstPadding)
    : version_(version), salt_(salt.empty() ? crypto::randomBytes(16) : std::move(salt)),
      key_(deriveKey(psk, salt_, version)), padding_(firstPadding) {
    if (padding_ == std::numeric_limits<size_t>::max()) padding_ = 256 + crypto::randomBytes(1)[0];
    if (padding_ > maximumFrame) throw std::runtime_error("Snell first padding exceeds its bound");
}
size_t Encoder::payloadLimit() const {
    return version_ >= 4 && !saltSent_ ? std::max<size_t>(1, 1460 > 55 + padding_ ? 1460 - 55 - padding_ : 1) : maximumFrame;
}
Buffer Encoder::frame(const Buffer &payload) {
    if (payload.size() > maximumFrame) throw std::runtime_error("Snell payload exceeds its bound");
    Buffer output;
    if (!saltSent_) output = salt_;
    if (version_ < 4) {
        Buffer length; snellPut16(length, payload.size());
        auto header = crypto::seal(snellCipher(version_), key_, nonce_, length); nextNonce(nonce_);
        output.insert(output.end(), header.begin(), header.end());
        // Snell's zero chunk is only a sealed length. Sealing a second empty
        // body would leave a stray tag and advance the reusable stream nonce.
        if (!payload.empty()) {
            auto body = crypto::seal(snellCipher(version_), key_, nonce_, payload); nextNonce(nonce_);
            output.insert(output.end(), body.begin(), body.end());
        }
    } else {
        size_t padding = !saltSent_ && !payload.empty() ? padding_ : 0;
        Buffer header{4, 0, 0}; snellPut16(header, padding); snellPut16(header, payload.size());
        auto encryptedHeader = crypto::seal(snellCipher(version_), key_, nonce_, header); nextNonce(nonce_);
        output.insert(output.end(), encryptedHeader.begin(), encryptedHeader.end());
        Buffer body;
        if (!payload.empty()) { body = crypto::seal(snellCipher(version_), key_, nonce_, payload); nextNonce(nonce_); }
        Buffer padded = crypto::randomBytes(padding);
        padded.insert(padded.end(), body.begin(), body.end()); swapPadding(padded, padding, body.size());
        output.insert(output.end(), padded.begin(), padded.end());
    }
    saltSent_ = true;
    return output;
}
Decoder::Decoder(const std::string &psk, unsigned version, const Buffer &salt)
    : version_(version), key_(deriveKey(psk, salt, version)) {}
Lengths Decoder::header(const Buffer &sealed) {
    if (sealed.size() != headerSize()) throw std::runtime_error("Invalid Snell header size");
    auto plain = crypto::open(snellCipher(version_), key_, nonce_, sealed); nextNonce(nonce_);
    Lengths result;
    if (version_ < 4) result.payload = snellWord(plain.data());
    else {
        if (plain.size() != 7 || plain[0] != 4) throw std::runtime_error("Invalid Snell v4 header");
        result.padding = snellWord(plain.data() + 3); result.payload = snellWord(plain.data() + 5);
    }
    if (result.padding > maximumFrame || result.payload > maximumFrame)
        throw std::runtime_error("Snell encrypted frame exceeds its bound");
    return result;
}
Buffer Decoder::body(Buffer sealed, Lengths lengths) {
    size_t payloadCipher = lengths.payload ? lengths.payload + 16 : 0;
    if (sealed.size() != lengths.padding + payloadCipher) throw std::runtime_error("Truncated Snell body");
    swapPadding(sealed, lengths.padding, payloadCipher);
    if (!payloadCipher) return {};
    Buffer body(sealed.begin() + lengths.padding, sealed.end());
    auto plain = crypto::open(snellCipher(version_), key_, nonce_, body); nextNonce(nonce_);
    if (plain.size() != lengths.payload) throw std::runtime_error("Invalid Snell payload size");
    return plain;
}
Buffer udpRequest(const Target &target, const Buffer &payload) {
    if (target.host.empty() || !target.port || target.host.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid Snell UDP destination");
    uint8_t address[16];
    Buffer packet{1};
    if (inet_pton(AF_INET, target.host.c_str(), address) == 1) {
        packet.insert(packet.end(), {0, 4}); packet.insert(packet.end(), address, address + 4);
    } else if (inet_pton(AF_INET6, target.host.c_str(), address) == 1) {
        packet.insert(packet.end(), {0, 6}); packet.insert(packet.end(), address, address + 16);
    } else {
        if (target.host.size() > 255) throw std::runtime_error("Snell UDP domain is too long");
        packet.push_back(uint8_t(target.host.size())); packet.insert(packet.end(), target.host.begin(), target.host.end());
    }
    snellPut16(packet, target.port);
    if (payload.size() > maximumFrame - packet.size()) throw std::runtime_error("Snell UDP packet is too large");
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}
void udpResponse(const Buffer &packet, Target &target, Buffer &payload) {
    if (packet.empty()) throw std::runtime_error("Empty Snell UDP response");
    size_t size = packet[0] == 4 ? 4 : packet[0] == 6 ? 16 : 0;
    if (!size || packet.size() < size + 3) throw std::runtime_error("Invalid Snell UDP response address");
    char host[INET6_ADDRSTRLEN];
    if (!inet_ntop(size == 4 ? AF_INET : AF_INET6, packet.data() + 1, host, sizeof(host)))
        throw std::runtime_error("Invalid Snell UDP response IP");
    target = {host, snellWord(packet.data() + 1 + size), true, false};
    if (!target.port) throw std::runtime_error("Invalid Snell UDP response port");
    payload.assign(packet.begin() + size + 3, packet.end());
}
} // namespace snell

namespace {
class SnellStream final : public Stream, public std::enable_shared_from_this<SnellStream> {
public:
    SnellStream(std::shared_ptr<Stream> carrier, std::shared_ptr<TransportFactory> factory,
                const std::string &psk, unsigned version)
        : carrier_(std::move(carrier)), reader_(std::make_shared<Reader>(carrier_)),
          factory_(std::move(factory)), psk_(psk), version_(version), encoder_(psk, version) {}
    ~SnellStream() override { carrier_->close(); }
    void write(Buffer data, WriteCallback completion) override;
    void read(size_t maximum, ReadCallback completion) override;
    void close() override;
    void shutdownWrite(WriteCallback completion) override;
    bool supportsHalfClose() const override { return version_ == 2; }
    void writePacket(Buffer, WriteCallback);
    void readPacket(ReadCallback, bool rawReply = false);
    void replyAccepted() { replied_ = true; }
    void prepend(Buffer bytes) { input_ = std::move(bytes); offset_ = 0; }
    void post(std::function<void()> work) { factory_->post(std::move(work)); }
private:
    struct PendingWrite { Buffer data; size_t offset = 0; bool packet = false, end = false; WriteCallback completion; };
    std::shared_ptr<Stream> carrier_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<TransportFactory> factory_;
    std::string psk_;
    unsigned version_;
    snell::Encoder encoder_;
    std::unique_ptr<snell::Decoder> decoder_;
    std::deque<PendingWrite> writes_;
    Buffer input_, reply_;
    size_t offset_ = 0, queued_ = 0, readMaximum_ = 0;
    bool closed_ = false, eof_ = false, writing_ = false, reading_ = false, writeEnd_ = false, packetRead_ = false;
    bool replied_ = false, rawReply_ = false;
    Error terminal_;
    ReadCallback pendingRead_;
    void enqueue(Buffer, bool packet, bool end, WriteCallback);
    void pumpWrites();
    void pumpRead();
    void readFrame(ReadCallback);
    void deliver();
    bool consumeReply(Buffer &);
    void fail(Error);
};
void SnellStream::write(Buffer data, WriteCallback completion) {
    auto self = shared_from_this();
    post([self, data = std::move(data), completion = std::move(completion)]() mutable {
        self->enqueue(std::move(data), false, false, std::move(completion));
    });
}
void SnellStream::writePacket(Buffer data, WriteCallback completion) {
    auto self = shared_from_this();
    post([self, data = std::move(data), completion = std::move(completion)]() mutable {
        self->enqueue(std::move(data), true, false, std::move(completion));
    });
}
void SnellStream::enqueue(Buffer data, bool packet, bool end, WriteCallback completion) {
    if (closed_ || writeEnd_) { completion(terminal_.empty() ? "Snell write side closed" : terminal_); return; }
    if ((packet && data.size() > snell::maximumFrame) || data.size() > maximumQueuedBytes - queued_ || writes_.size() >= 256) {
        completion("Snell write queue or packet exceeds its bound"); return;
    }
    if (data.empty() && !end) { completion({}); return; }
    if (end) writeEnd_ = true;
    queued_ += data.size(); writes_.push_back({std::move(data), 0, packet, end, std::move(completion)}); pumpWrites();
}
void SnellStream::pumpWrites() {
    if (closed_ || writing_ || writes_.empty()) return;
    auto &pending = writes_.front();
    size_t count = pending.packet ? pending.data.size() : std::min(pending.data.size() - pending.offset, encoder_.payloadLimit());
    Buffer frame;
    try {
        if (pending.offset == 0 && count == pending.data.size()) {
            frame = encoder_.frame(pending.data);
        } else {
            frame = encoder_.frame(Buffer(pending.data.begin() + pending.offset, pending.data.begin() + pending.offset + count));
        }
    }
    catch (const std::exception &error) { fail(error.what()); return; }
    writing_ = true;
    auto self = shared_from_this();
    carrier_->write(std::move(frame), [self, count](Error error) {
        self->post([self, count, error = std::move(error)]() mutable {
            self->writing_ = false;
            if (self->closed_) return;
            if (!error.empty()) { self->fail(std::move(error)); return; }
            auto &pending = self->writes_.front(); pending.offset += count;
            if (pending.offset == pending.data.size()) {
                self->queued_ -= pending.data.size(); auto callback = std::exchange(pending.completion, {});
                self->writes_.pop_front(); callback({});
            }
            self->pumpWrites();
        });
    });
}
void SnellStream::read(size_t maximum, ReadCallback completion) {
    auto self = shared_from_this();
    post([self, maximum, completion = std::move(completion)]() mutable {
        if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid Snell read bound"); return; }
        if (self->pendingRead_) { completion({}, false, "A Snell read is already pending"); return; }
        self->packetRead_ = false; self->rawReply_ = false; self->readMaximum_ = maximum; self->pendingRead_ = std::move(completion); self->pumpRead();
    });
}
void SnellStream::readPacket(ReadCallback completion, bool rawReply) {
    auto self = shared_from_this();
    post([self, rawReply, completion = std::move(completion)]() mutable {
        if (self->pendingRead_) { completion({}, false, "A Snell read is already pending"); return; }
        self->packetRead_ = true; self->rawReply_ = rawReply; self->pendingRead_ = std::move(completion); self->pumpRead();
    });
}
void SnellStream::deliver() {
    if (!pendingRead_ || (offset_ == input_.size() && !eof_ && !closed_)) return;
    size_t count = input_.size() - offset_;
    if (!packetRead_) count = std::min(count, readMaximum_);
    Buffer data(input_.begin() + offset_, input_.begin() + offset_ + count); offset_ += count;
    if (offset_ == input_.size()) { input_.clear(); offset_ = 0; }
    auto callback = std::exchange(pendingRead_, {});
    callback(std::move(data), (eof_ || closed_) && input_.empty(), terminal_);
}
void SnellStream::pumpRead() {
    deliver();
    if (!pendingRead_ || reading_ || eof_ || closed_) return;
    reading_ = true;
    auto self = shared_from_this();
    readFrame([self](Buffer data, bool eof, Error error) {
        self->post([self, data = std::move(data), eof, error = std::move(error)]() mutable {
            self->reading_ = false;
            if (self->closed_) return;
            if (!error.empty()) { self->fail(std::move(error)); return; }
            if (!self->replied_ && !self->rawReply_) {
                if (eof) { self->fail("Snell peer closed before its reply"); return; }
                bool ready;
                try { ready = self->consumeReply(data); }
                catch (const std::exception &failure) { self->fail(failure.what()); return; }
                if (!ready) { self->post([self] { self->pumpRead(); }); return; }
            }
            self->input_ = std::move(data); self->offset_ = 0; self->eof_ = eof; self->deliver();
        });
    });
}
bool SnellStream::consumeReply(Buffer &data) {
    if (reply_.empty() && !data.empty() && data[0] == 0) {
        replied_ = true; data.erase(data.begin()); return !data.empty();
    }
    if (data.size() > 258 - reply_.size()) throw std::runtime_error("Invalid Snell reply size");
    reply_.insert(reply_.end(), data.begin(), data.end());
    if (reply_.empty() || reply_[0] != 2) throw std::runtime_error("Invalid Snell reply command");
    if (reply_.size() < 3 || reply_.size() < size_t(reply_[2]) + 3) return false;
    throw std::runtime_error("Snell server rejected request (code " + std::to_string(reply_[1]) + ")");
}
void SnellStream::readFrame(ReadCallback completion) {
    auto self = shared_from_this();
    if (!decoder_) {
        reader_->exactly(16, [self, completion = std::move(completion)](Buffer salt, Error error) mutable {
            if (self->closed_) return;
            if (!error.empty()) { completion({}, true, error == "EOF" ? Error{} : std::move(error)); return; }
            try { self->decoder_ = std::make_unique<snell::Decoder>(self->psk_, self->version_, salt); }
            catch (const std::exception &failure) { completion({}, true, failure.what()); return; }
            self->readFrame(std::move(completion));
        });
        return;
    }
    reader_->exactly(decoder_->headerSize(), [self, completion = std::move(completion)](Buffer header, Error error) mutable {
        if (self->closed_) return;
        if (!error.empty()) { completion({}, true, error == "EOF" ? Error{} : std::move(error)); return; }
        snell::Lengths lengths;
        try { lengths = self->decoder_->header(header); }
        catch (const std::exception &failure) { completion({}, true, failure.what()); return; }
        size_t size = lengths.padding + (lengths.payload ? lengths.payload + 16 : 0);
        self->reader_->exactly(size, [self, lengths, completion = std::move(completion)](Buffer body, Error error) mutable {
            if (self->closed_) return;
            if (!error.empty()) { completion({}, true, error == "EOF" ? "Truncated Snell body" : std::move(error)); return; }
            Buffer plain;
            try { plain = self->decoder_->body(std::move(body), lengths); }
            catch (const std::exception &failure) { completion({}, true, failure.what()); return; }
            completion(std::move(plain), lengths.payload == 0, {});
        });
    });
}
void SnellStream::fail(Error error) {
    if (closed_) return;
    closed_ = true; eof_ = true; terminal_ = std::move(error); reader_->close(); input_.clear(); offset_ = 0;
    auto writes = std::move(writes_); writes_.clear(); queued_ = 0;
    for (auto &pending : writes) if (auto callback = std::exchange(pending.completion, {})) callback(terminal_);
    deliver();
}
void SnellStream::close() {
    auto self = shared_from_this(); post([self] { self->fail("Snell stream closed"); });
}
void SnellStream::shutdownWrite(WriteCallback completion) {
    auto self = shared_from_this();
    post([self, completion = std::move(completion)]() mutable {
        if (!self->supportsHalfClose()) { completion("Snell half-close requires the v2 reuse command"); return; }
        self->enqueue({}, false, true, std::move(completion));
    });
}

class SnellDatagram final : public Datagram, public std::enable_shared_from_this<SnellDatagram> {
public:
    explicit SnellDatagram(std::shared_ptr<SnellStream> stream) : stream_(std::move(stream)) {}
    ~SnellDatagram() override { stream_->close(); }
    void send(Target target, Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        stream_->post([self, target = std::move(target), data = std::move(data), completion = std::move(completion)]() mutable {
            if (self->closed_) { completion("Snell UDP association closed"); return; }
            Buffer packet;
            try { packet = snell::udpRequest(target, data); }
            catch (const std::exception &error) { completion(error.what()); return; }
            self->stream_->writePacket(std::move(packet), std::move(completion));
        });
    }
    void start(PacketCallback receive, WriteCallback failure) override {
        auto self = shared_from_this();
        stream_->post([self, receive = std::move(receive), failure = std::move(failure)]() mutable {
            if (self->closed_) { failure("Snell UDP association closed"); return; }
            if (self->receive_) { failure("Snell UDP receive is already active"); return; }
            self->receive_ = std::move(receive); self->failure_ = std::move(failure); self->next();
        });
    }
    void close() override {
        auto self = shared_from_this(); stream_->post([self] { self->finish({}); });
    }
private:
    std::shared_ptr<SnellStream> stream_;
    PacketCallback receive_;
    WriteCallback failure_;
    bool closed_ = false;
    void next() {
        if (closed_) return;
        std::weak_ptr<SnellDatagram> weak = shared_from_this();
        stream_->readPacket([weak](Buffer packet, bool eof, Error error) {
            auto self = weak.lock(); if (!self || self->closed_) return;
            if (!error.empty() || eof) { self->finish(error.empty() ? "Snell UDP peer closed" : std::move(error)); return; }
            Target target; Buffer payload;
            try { snell::udpResponse(packet, target, payload); }
            catch (const std::exception &failure) { self->finish(failure.what()); return; }
            self->receive_(std::move(target), std::move(payload)); self->next();
        });
    }
    void finish(Error error) {
        if (closed_) return;
        closed_ = true; receive_ = {}; auto failure = std::exchange(failure_, {}); stream_->close();
        if (failure && !error.empty()) failure(std::move(error));
    }
};

class SnellSetup final : public std::enable_shared_from_this<SnellSetup> {
public:
    SnellSetup(Node node, Buffer request, std::shared_ptr<TransportFactory> factory, StreamCallback completion, bool waitReply = false)
        : node_(std::move(node)), request_(std::move(request)), factory_(std::move(factory)), completion_(std::move(completion)), waitReply_(waitReply) {}
    void start() {
        auto self = shared_from_this();
        factory_->after(12, [weak = std::weak_ptr<SnellSetup>(self)] {
            if (auto pending = weak.lock()) pending->finish("Snell handshake timed out");
        });
        factory_->tcp(node_, {}, [self](std::shared_ptr<Stream> raw, Error error) {
            self->factory_->post([self, raw = std::move(raw), error = std::move(error)]() mutable {
                if (!self->completion_) { if (raw) raw->close(); return; }
                if (!error.empty() || !raw) { self->finish(error.empty() ? "Snell TCP transport failed" : std::move(error)); return; }
                try { self->stream_ = std::make_shared<SnellStream>(raw, self->factory_, self->node_.option("psk"), snellVersion(self->node_)); }
                catch (const std::exception &failure) { raw->close(); self->finish(failure.what()); return; }
                self->stream_->write(std::move(self->request_), [self](Error error) {
                    if (!error.empty()) self->finish(std::move(error));
                    else if (self->completion_) { if (self->waitReply_) self->readReply(); else self->finish({}); }
                });
            });
        });
    }
private:
    Node node_;
    Buffer request_, reply_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<SnellStream> stream_;
    StreamCallback completion_;
    bool waitReply_;
    void readReply() {
        auto self = shared_from_this();
        stream_->readPacket([self](Buffer data, bool eof, Error error) {
            if (!self->completion_) return;
            if (!error.empty() || eof) { self->finish(error.empty() ? "Snell peer closed during handshake" : std::move(error)); return; }
            if (self->reply_.empty() && !data.empty() && data[0] == 0) {
                self->stream_->replyAccepted(); self->stream_->prepend(Buffer(data.begin() + 1, data.end())); self->finish({}); return;
            }
            if (data.size() > 258 - self->reply_.size()) { self->finish("Invalid Snell reply size"); return; }
            self->reply_.insert(self->reply_.end(), data.begin(), data.end());
            if (self->reply_.empty()) { self->finish("Empty Snell reply"); return; }
            if (self->reply_[0] != 2) { self->finish("Invalid Snell reply command"); return; }
            if (self->reply_.size() < 3 || self->reply_.size() < size_t(self->reply_[2]) + 3) { self->readReply(); return; }
            self->finish("Snell server rejected request (code " + std::to_string(self->reply_[1]) + ")");
        }, true);
    }
    void finish(Error error) {
        auto completion = std::exchange(completion_, {}); if (!completion) return;
        if (!error.empty()) { if (stream_) stream_->close(); completion({}, std::move(error)); }
        else completion(stream_, {});
    }
};
} // namespace

Error validateSnell(const Node &node, bool udp) {
    auto psk = node.option("psk");
    if (psk.empty()) return "Snell requires psk";
    if (psk.size() > 4096) return "Snell psk exceeds its bound";
    unsigned version;
    try { version = snellVersion(node); }
    catch (const std::exception &error) { return error.what(); }
    if (udp && version < 3) return "Snell v1/v2 do not support UDP relay";
    if (node.flag("tls")) return "Snell does not use an outer TLS transport";
    if (!node.option("security").empty() && node.option("security") != "none") return "Snell outer security transports are not implemented";
    if (node.option("network", "tcp") != "tcp") return "Snell requires TCP transport";
    if (node.flag("reuse")) return "Snell explicit connection pooling is not implemented";
    for (const auto &key : {"obfs", "obfs-opts", "obfs-mode"}) {
        auto value = node.option(key);
        if (!value.empty() && value != "none" && value != "plain") return "Snell option is not implemented: " + std::string(key);
    }
    for (const auto &key : {"plugin", "obfs-host", "obfs-param", "underlying-proxy", "dialer-proxy", "alpn", "certificate", "private-key",
                            "client-fingerprint", "fingerprint", "ca-str", "ca"})
        if (!node.option(key).empty()) return "Snell option is not implemented: " + std::string(key);
    return {};
}
void connectSnell(const Node &node, const Target &target, std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    if (auto error = validateSnell(node, false); !error.empty()) { completion({}, std::move(error)); return; }
    if (!factory || !factory->tcp || !factory->post || !factory->after) { completion({}, "Snell platform transport is unavailable"); return; }
    if (target.host.empty() || target.host.size() > 255 || !target.port || target.host.find('\0') != std::string::npos) {
        completion({}, "Invalid Snell TCP destination"); return;
    }
    Buffer request{1, uint8_t(snellVersion(node) == 2 ? 5 : 1), 0, uint8_t(target.host.size())};
    request.insert(request.end(), target.host.begin(), target.host.end()); snellPut16(request, target.port);
    factory->post([node, request = std::move(request), factory, completion = std::move(completion)]() mutable {
        std::make_shared<SnellSetup>(node, std::move(request), factory, std::move(completion))->start();
    });
}
void makeSnellDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    if (auto error = validateSnell(node, true); !error.empty()) { completion({}, std::move(error)); return; }
    if (!factory || !factory->tcp || !factory->post || !factory->after) { completion({}, "Snell platform transport is unavailable"); return; }
    factory->post([node, factory, completion = std::move(completion)]() mutable {
        auto deliver = [completion = std::move(completion)](std::shared_ptr<Stream> stream, Error error) mutable {
            if (!error.empty()) completion({}, std::move(error));
            else completion(std::make_shared<SnellDatagram>(std::static_pointer_cast<SnellStream>(stream)), {});
        };
        std::make_shared<SnellSetup>(node, Buffer{1, 6, 0}, factory, std::move(deliver), snellVersion(node) >= 4)->start();
    });
}
} // namespace hajimi
