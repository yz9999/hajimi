#pragma once
#include "Runtime.hpp"
#include "Crypto.hpp"
#include <limits>

namespace hajimi {
Error validateSnell(const Node &, bool udp);
namespace snell {
constexpr size_t maximumFrame = 0x3fff;

enum class CompatMode : uint8_t {
    Standard = 0,
    Compat16Pool7 = 1,
    Compat16RFC = 2
};

Buffer deriveKey(const std::string &psk, const Buffer &salt, unsigned version);
Buffer deriveKeyWithTagLen(const std::string &psk, const Buffer &salt, unsigned version, size_t tagLen);
Buffer deriveKeyWithMode(const std::string &psk, const Buffer &salt, unsigned version, CompatMode mode);

class Encoder {
public:
    Encoder(const std::string &psk, unsigned version, Buffer salt = {},
            size_t firstPadding = std::numeric_limits<size_t>::max(),
            CompatMode mode = CompatMode::Standard);
    Buffer frame(const Buffer &payload);
    size_t payloadLimit() const;
    const Buffer &salt() const { return salt_; }
    CompatMode mode() const { return mode_; }
private:
    unsigned version_;
    Buffer salt_, key_, nonce_ = Buffer(12, 0);
    size_t padding_;
    CompatMode mode_ = CompatMode::Standard;
    bool saltSent_ = false;
};

struct Lengths { size_t padding = 0, payload = 0; };

class Decoder {
public:
    Decoder(const std::string &psk, unsigned version, const Buffer &salt,
            CompatMode mode = CompatMode::Standard);
    size_t headerSize() const { return (version_ >= 4 && mode_ == CompatMode::Standard) ? 23 : 18; }
    Lengths header(const Buffer &);
    Buffer body(Buffer bytes, Lengths lengths);
private:
    unsigned version_;
    Buffer key_, keyPool7_, keyRFC16_, keyStd_, nonce_ = Buffer(12, 0);
    CompatMode mode_ = CompatMode::Standard;
    bool locked_ = false;
};

Buffer udpRequest(const Target &, const Buffer &);
void udpResponse(const Buffer &, Target &, Buffer &);
} // namespace snell
} // namespace hajimi
