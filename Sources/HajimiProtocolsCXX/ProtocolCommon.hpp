#pragma once
#include "Runtime.hpp"
#include "Crypto.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <string>

namespace hajimi::proto_common {

inline std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return char(std::tolower(ch)); });
    return value;
}

inline std::string upperAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return char(std::toupper(ch)); });
    return value;
}

inline std::string trimAscii(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

inline bool parseUint32(const std::string &text, uint32_t minVal, uint32_t maxVal, uint32_t &out) {
    if (text.empty()) return false;
    uint64_t acc = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') return false;
        acc = acc * 10 + uint64_t(ch - '0');
        if (acc > maxVal) return false;
    }
    if (acc < minVal) return false;
    out = static_cast<uint32_t>(acc);
    return true;
}

inline void appendBE16(Buffer &buf, uint16_t val) {
    buf.push_back(uint8_t(val >> 8));
    buf.push_back(uint8_t(val & 0xff));
}

inline void appendBE32(Buffer &buf, uint32_t val) {
    buf.push_back(uint8_t((val >> 24) & 0xff));
    buf.push_back(uint8_t((val >> 16) & 0xff));
    buf.push_back(uint8_t((val >> 8) & 0xff));
    buf.push_back(uint8_t(val & 0xff));
}

inline void appendBE64(Buffer &buf, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf.push_back(uint8_t((val >> (i * 8)) & 0xff));
    }
}

inline uint16_t readBE16(const uint8_t *p) noexcept {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

inline uint32_t readBE32(const uint8_t *p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint64_t readBE64(const uint8_t *p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | uint64_t(p[i]);
    return v;
}

inline void writeBE16At(Buffer &buf, size_t offset, uint16_t val) noexcept {
    buf[offset] = uint8_t(val >> 8);
    buf[offset + 1] = uint8_t(val & 0xff);
}

inline void writeBE32At(Buffer &buf, size_t offset, uint32_t val) noexcept {
    buf[offset] = uint8_t((val >> 24) & 0xff);
    buf[offset + 1] = uint8_t((val >> 16) & 0xff);
    buf[offset + 2] = uint8_t((val >> 8) & 0xff);
    buf[offset + 3] = uint8_t(val & 0xff);
}

inline void incrementNonceLE(Buffer &nonce) noexcept {
    for (size_t i = 0; i < nonce.size(); ++i) {
        if (++nonce[i] != 0) break;
    }
}

inline void incrementNonceBE(Buffer &nonce) noexcept {
    for (int i = int(nonce.size()) - 1; i >= 0; --i) {
        if (++nonce[size_t(i)] != 0) break;
    }
}

inline bool decodeHexBytes(const std::string &hex, Buffer &out) {
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
}

inline std::string encodeHexLower(const Buffer &in) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (uint8_t b : in) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

inline uint64_t fastWyRand() noexcept {
    thread_local uint64_t state = []() {
        Buffer b = crypto::randomBytes(8);
        uint64_t s = readBE64(b.data());
        return s ? s : 0x9e3779b97f4a7c15ULL;
    }();
    state += 0xa0761d6478bd642fULL;
    __uint128_t r = __uint128_t(state) * __uint128_t(state ^ 0xe7037ed1a0b428dbULL);
    return uint64_t(r >> 64) ^ uint64_t(r);
}

// O(1) cursor-based byte buffer that eliminates O(N) std::vector::erase(begin) memmoves
// on protocol receive hot paths.
class CursorBuffer {
public:
    bool empty() const noexcept { return offset_ >= buf_.size(); }
    size_t size() const noexcept { return buf_.size() - offset_; }
    const uint8_t *data() const noexcept { return buf_.data() + offset_; }
    uint8_t operator[](size_t idx) const noexcept { return buf_[offset_ + idx]; }

    void clear() noexcept {
        buf_.clear();
        offset_ = 0;
    }

    void push_back(uint8_t b) {
        buf_.push_back(b);
    }

    void append(const uint8_t *ptr, size_t len) {
        if (!len) return;
        if (offset_ == buf_.size()) {
            buf_.clear();
            offset_ = 0;
        } else if (offset_ >= 65536 && offset_ * 2 >= buf_.size()) {
            buf_.erase(buf_.begin(), buf_.begin() + offset_);
            offset_ = 0;
        }
        buf_.insert(buf_.end(), ptr, ptr + len);
    }

    void append(const Buffer &other) {
        if (!other.empty()) append(other.data(), other.size());
    }

    Buffer consume(size_t maxBytes) {
        size_t avail = size();
        size_t n = std::min(maxBytes, avail);
        Buffer out(buf_.begin() + offset_, buf_.begin() + offset_ + n);
        advance(n);
        return out;
    }

    Buffer sliceAndAdvance(size_t skipHeader, size_t takeBytes) {
        Buffer out(buf_.begin() + offset_ + skipHeader,
                   buf_.begin() + offset_ + skipHeader + takeBytes);
        advance(skipHeader + takeBytes);
        return out;
    }

    void advance(size_t n) noexcept {
        offset_ += n;
        if (offset_ >= buf_.size()) {
            buf_.clear();
            offset_ = 0;
        } else if (offset_ >= 65536 && offset_ * 2 >= buf_.size()) {
            buf_.erase(buf_.begin(), buf_.begin() + offset_);
            offset_ = 0;
        }
    }

private:
    Buffer buf_;
    size_t offset_ = 0;
};

class PrefixedStream final : public Stream {
public:
    PrefixedStream(std::shared_ptr<Stream> raw, std::shared_ptr<Reader> reader)
        : raw_(std::move(raw)), reader_(std::move(reader)) {}

    void write(Buffer data, WriteCallback completion) override {
        raw_->write(std::move(data), std::move(completion));
    }

    void read(size_t maximum, ReadCallback completion) override {
        reader_->some(maximum, std::move(completion));
    }

    void close() override {
        reader_->close();
    }

private:
    std::shared_ptr<Stream> raw_;
    std::shared_ptr<Reader> reader_;
};

} // namespace hajimi::proto_common
