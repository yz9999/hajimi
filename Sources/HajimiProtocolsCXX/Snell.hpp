#pragma once
#include "Runtime.hpp"
#include "Crypto.hpp"
#include <limits>

namespace hajimi {
Error validateSnell(const Node &, bool udp);
namespace snell {
constexpr size_t maximumFrame = 0x3fff;
Buffer deriveKey(const std::string &psk, const Buffer &salt, unsigned version);
class Encoder {
public:
    Encoder(const std::string &psk, unsigned version, Buffer salt = {},
            size_t firstPadding = std::numeric_limits<size_t>::max());
    Buffer frame(const Buffer &payload);
    size_t payloadLimit() const;
    const Buffer &salt() const { return salt_; }
private:
    unsigned version_;
    Buffer salt_, key_, nonce_ = Buffer(12, 0);
    size_t padding_;
    bool saltSent_ = false;
};
struct Lengths { size_t padding = 0, payload = 0; };
class Decoder {
public:
    Decoder(const std::string &psk, unsigned version, const Buffer &salt);
    size_t headerSize() const { return version_ >= 4 ? 23 : 18; }
    Lengths header(const Buffer &);
    Buffer body(Buffer bytes, Lengths lengths);
private:
    unsigned version_;
    Buffer key_, nonce_ = Buffer(12, 0);
};
Buffer udpRequest(const Target &, const Buffer &);
void udpResponse(const Buffer &, Target &, Buffer &);
} // namespace snell
} // namespace hajimi
