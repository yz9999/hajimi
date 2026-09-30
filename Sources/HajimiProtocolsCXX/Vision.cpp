#include "Vision.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include <algorithm>
#include <stdexcept>

namespace hajimi {
void VisionTraffic::uplink(const Buffer &data) {
    if (!packetBudget) return;
    --packetBudget;
    if (data.size() >= 6 && data[0] == 0x16 && data[1] == 3 && data[5] == 1) tls = true;
}
void VisionTraffic::downlink(const Buffer &data) {
    if (!packetBudget || direct) return;
    --packetBudget;
    size_t room = 65540 - serverHello.size();
    serverHello.insert(serverHello.end(), data.begin(), data.begin() + std::min(room, data.size()));
    auto &b = serverHello;
    if (b.size() < 6 || b[0] != 0x16 || b[1] != 3 || b[2] != 3 || b[5] != 2) return;
    tls = true; tls12 = true;
    size_t recordEnd = 5 + read16(b, 3);
    if (recordEnd < 49 || b.size() < recordEnd) return;
    size_t suiteOffset = 44 + b[43];
    if (suiteOffset + 5 > recordEnd) { packetBudget = 0; return; }
    uint16_t suite = read16(b, suiteOffset);
    size_t extensionStart = suiteOffset + 5;
    size_t extensionEnd = extensionStart + read16(b, suiteOffset + 3);
    if (extensionEnd > recordEnd) { packetBudget = 0; return; }
    for (size_t offset = extensionStart; offset + 4 <= extensionEnd;) {
        uint16_t type = read16(b, offset); size_t length = read16(b, offset+2); offset += 4;
        if (length > extensionEnd - offset) break;
        if (type == 0x2b && length == 2 && b[offset] == 3 && b[offset+1] == 4)
            direct = suite >= 0x1301 && suite <= 0x1304;
        offset += length;
    }
    packetBudget = 0;
}
VisionCodec::VisionCodec(Buffer uuid, bool canDirect)
    : uuid_(std::move(uuid)), traffic_(std::make_shared<VisionTraffic>()), canDirect_(canDirect) {
    if (uuid_.size() != 16) throw std::runtime_error("Invalid Vision UUID");
}
Buffer VisionCodec::frame(const Buffer &content, uint8_t command, bool longPadding) {
    if (content.size() > 8171) throw std::runtime_error("Vision content too large");
    auto random = crypto::randomBytes(2);
    size_t padding = longPadding && content.size() < 900
        ? read16(random) % 500 + 900 - content.size() : read16(random) % 256;
    padding = std::min(padding, 8171 - content.size());
    Buffer output;
    if (firstWrite_) { output = uuid_; firstWrite_ = false; }
    output.push_back(command); append16(output, uint16_t(content.size())); append16(output, uint16_t(padding));
    output.insert(output.end(), content.begin(), content.end()); output.resize(output.size()+padding);
    return output;
}
Buffer VisionCodec::initialPadding() { return frame({}, 0, true); }
static bool completeTLSRecords(const Buffer &data) {
    if (data.empty()) return false;
    for (size_t offset=0; offset<data.size();) {
        if (data.size()-offset < 5 || data[offset] != 0x17 || data[offset+1] != 3 || data[offset+2] != 3) return false;
        size_t length = read16(data, offset+3);
        if (!length || length > data.size()-offset-5) return false;
        offset += 5 + length;
    }
    return true;
}
Buffer VisionCodec::encode(const Buffer &data, bool &switchDirect) {
    switchDirect = false;
    if (directWrite_) return data;
    traffic_->uplink(data);
    if (!paddingWrite_) return data;
    bool tlsBoundary = traffic_->tls && completeTLSRecords(data);
    bool shouldDirect = canDirect_ && traffic_->direct && tlsBoundary;
    bool shouldEnd = tlsBoundary || (!traffic_->tls12 && traffic_->packetBudget <= 1);
    uint8_t finalCommand = shouldDirect ? 2 : shouldEnd ? 1 : 0;
    Buffer output;
    if (data.empty()) output = frame({}, finalCommand, traffic_->tls);
    else {
        for (size_t offset=0; offset<data.size();) {
            size_t end = std::min(data.size(), offset+8171);
            Buffer content(data.begin()+offset, data.begin()+end);
            auto encoded = frame(content, end == data.size() ? finalCommand : 0, traffic_->tls);
            output.insert(output.end(), encoded.begin(), encoded.end()); offset = end;
        }
    }
    if (shouldEnd) paddingWrite_ = false;
    if (shouldDirect) directWrite_ = switchDirect = true;
    return output;
}
Buffer VisionCodec::decode(const Buffer &data, bool &switchDirect) {
    switchDirect = false;
    if (!paddingRead_) { traffic_->downlink(data); return data; }
    if (data.size() > maximumQueuedBytes - input_.size()) throw std::runtime_error("Vision buffer limit exceeded");
    input_.insert(input_.end(), data.begin(), data.end());
    if (firstRead_) {
        if (input_.size() < 16) return {};
        if (!std::equal(uuid_.begin(), uuid_.end(), input_.begin())) throw std::runtime_error("Vision response UUID mismatch");
        input_.erase(input_.begin(), input_.begin()+16); firstRead_ = false;
    }
    Buffer output;
    while (paddingRead_ && input_.size() >= 5) {
        uint8_t command = input_[0]; size_t length = read16(input_,1), padding = read16(input_,3);
        if (command > 2 || length + padding > 8171) throw std::runtime_error("Invalid Vision padding frame");
        size_t total = 5+length+padding;
        if (input_.size() < total) break;
        Buffer content(input_.begin()+5, input_.begin()+5+length);
        if (!content.empty()) traffic_->downlink(content);
        output.insert(output.end(), content.begin(), content.end()); input_.erase(input_.begin(), input_.begin()+total);
        if (command) {
            paddingRead_ = false; switchDirect = command == 2;
            if (!input_.empty()) { traffic_->downlink(input_); output.insert(output.end(), input_.begin(), input_.end()); input_.clear(); }
        }
    }
    return output;
}
} // namespace hajimi
