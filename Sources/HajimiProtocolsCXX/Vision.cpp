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
void VisionTraffic::downlink(const uint8_t *data, size_t len) {
    if (!packetBudget || direct || !data || len == 0) return;
    --packetBudget;
    size_t room = 65540 - serverHello.size();
    serverHello.insert(serverHello.end(), data, data + std::min(room, len));
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
Buffer VisionCodec::frameSlice(const uint8_t *content, size_t contentLen, uint8_t command, bool longPadding) {
    if (contentLen > 8171) throw std::runtime_error("Vision content too large");
    auto random = crypto::randomBytes(2);
    size_t padding = longPadding && contentLen < 900
        ? read16(random) % 500 + 900 - contentLen : read16(random) % 256;
    padding = std::min(padding, 8171 - contentLen);
    Buffer output;
    output.reserve((firstWrite_ ? 16 : 0) + 5 + contentLen + padding);
    if (firstWrite_) { output = uuid_; firstWrite_ = false; }
    output.push_back(command); append16(output, uint16_t(contentLen)); append16(output, uint16_t(padding));
    if (contentLen > 0 && content) output.insert(output.end(), content, content + contentLen);
    output.resize(output.size() + padding);
    return output;
}
Buffer VisionCodec::initialPadding() { return frameSlice(nullptr, 0, 0, true); }
static bool completeTLSRecords(const Buffer &data) {
    if (data.empty()) return false;
    size_t offset = 0;
    // TLS 1.3 middlebox compatibility mode prepends a dummy ChangeCipherSpec
    // record (14 03 03 00 01 01) ahead of the encrypted ClientFinished record.
    if (data.size() >= 11 && data[0] == 0x14 && data[1] == 3 && data[2] == 3 &&
        data[3] == 0 && data[4] == 1 && data[5] == 1 && data[6] == 0x17) {
        offset = 6;
    }
    bool sawAppData = false;
    while (offset < data.size()) {
        if (data.size() - offset < 5 || data[offset] != 0x17 || data[offset+1] != 3 || data[offset+2] != 3) return false;
        size_t length = read16(data, offset+3);
        if (!length || length > data.size() - offset - 5) return false;
        offset += 5 + length;
        sawAppData = true;
    }
    return sawAppData && offset == data.size();
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
    if (data.empty()) output = frameSlice(nullptr, 0, finalCommand, traffic_->tls);
    else if (data.size() <= 8171) {
        output = frameSlice(data.data(), data.size(), finalCommand, traffic_->tls);
    } else {
        output.reserve(data.size() + ((data.size() + 8170) / 8171) * 512 + 16);
        for (size_t offset = 0; offset < data.size();) {
            size_t end = std::min(data.size(), offset + 8171);
            auto encoded = frameSlice(data.data() + offset, end - offset,
                                      end == data.size() ? finalCommand : 0, traffic_->tls);
            output.insert(output.end(), encoded.begin(), encoded.end());
            offset = end;
        }
    }
    if (shouldEnd) paddingWrite_ = false;
    if (shouldDirect) directWrite_ = switchDirect = true;
    return output;
}
Buffer VisionCodec::decode(const Buffer &data, bool &switchDirect) {
    switchDirect = false;
    if (!paddingRead_) { traffic_->downlink(data.data(), data.size()); return data; }
    if (data.size() > maximumQueuedBytes - input_.size()) throw std::runtime_error("Vision buffer limit exceeded");
    input_.insert(input_.end(), data.begin(), data.end());
    size_t cursor = 0;
    if (firstRead_) {
        if (input_.size() < 16) return {};
        if (!std::equal(uuid_.begin(), uuid_.end(), input_.begin())) throw std::runtime_error("Vision response UUID mismatch");
        cursor = 16; firstRead_ = false;
    }
    Buffer output;
    output.reserve(input_.size() - cursor);
    while (paddingRead_ && input_.size() - cursor >= 5) {
        uint8_t command = input_[cursor];
        size_t length = read16(input_, cursor + 1), padding = read16(input_, cursor + 3);
        if (command > 2) throw std::runtime_error("Invalid Vision padding frame");
        size_t total = 5 + length + padding;
        if (input_.size() - cursor < total) break;
        const uint8_t *contentPtr = input_.data() + cursor + 5;
        if (length > 0) {
            traffic_->downlink(contentPtr, length);
            output.insert(output.end(), contentPtr, contentPtr + length);
        }
        cursor += total;
        if (command) {
            paddingRead_ = false; switchDirect = command == 2;
            if (cursor < input_.size()) {
                const size_t tailLen = input_.size() - cursor;
                traffic_->downlink(input_.data() + cursor, tailLen);
                output.insert(output.end(), input_.begin() + cursor, input_.end());
                cursor = input_.size();
            }
        }
    }
    if (cursor > 0) {
        if (cursor >= input_.size()) input_.clear();
        else input_.erase(input_.begin(), input_.begin() + cursor);
    }
    return output;
}
} // namespace hajimi
