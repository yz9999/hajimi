#pragma once
#include "Runtime.hpp"
#include <map>

namespace hajimi {
Error validateAnyTLS(const Node &, bool udp);
void resetAnyTLSClients();
void resetAnyTLSClient(const std::shared_ptr<TransportFactory> &factory);

namespace anytls {
enum Command : uint8_t {
    Waste = 0, SYN = 1, PSH = 2, FIN = 3, Settings = 4, Alert = 5,
    UpdatePadding = 6, SYNACK = 7, HeartRequest = 8, HeartResponse = 9, ServerSettings = 10
};
Buffer frame(uint8_t command, uint32_t stream, const Buffer &data = {});
struct PaddingRule { uint32_t minimum = 0, maximum = 0; bool check = false; };
class PaddingScheme {
public:
    static PaddingScheme defaults();
    static PaddingScheme parse(const Buffer &raw);
    const Buffer &raw() const { return raw_; }
    std::string md5() const;
    size_t authenticationPadding() const;
    std::vector<Buffer> apply(Buffer bytes, uint64_t packet) const;
private:
    Buffer raw_;
    uint32_t stop_ = 0;
    std::map<uint32_t, std::vector<PaddingRule>> rules_;
};
Buffer encodeUoTPacket(const Target &, const Buffer &);
// Returns false only for incomplete input; invalid framing throws.
bool decodeUoTPacket(const Buffer &, size_t &consumed, Target &, Buffer &);
} // namespace anytls
} // namespace hajimi
