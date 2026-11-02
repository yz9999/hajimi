#pragma once
#include "Runtime.hpp"

namespace hajimi {
struct VisionTraffic {
    unsigned packetBudget = 8;
    bool tls = false, tls12 = false, direct = false;
    Buffer serverHello;
    void uplink(const Buffer &);
    void downlink(const Buffer &);
};
class VisionCodec {
    Buffer uuid_, input_;
    std::shared_ptr<VisionTraffic> traffic_;
    bool canDirect_, firstWrite_ = true, paddingWrite_ = true, directWrite_ = false;
    bool firstRead_ = true, paddingRead_ = true;
    Buffer frame(const Buffer &, uint8_t command, bool longPadding);
public:
    VisionCodec(Buffer uuid, bool canDirect);
    Buffer initialPadding();
    Buffer encode(const Buffer &, bool &switchDirect);
    Buffer decode(const Buffer &, bool &switchDirect);
    bool truncated() const { return !input_.empty(); }
};
} // namespace hajimi
