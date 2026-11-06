#pragma once
#include "Runtime.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <deque>
#include <utility>
#include <vector>

namespace hajimi {
/// Serial, bounded writes for framed streams with high/low-water flow control.
/// All methods and underlying completions run on the factory strand.
class OrderedWriter : public std::enable_shared_from_this<OrderedWriter> {
    struct Entry { Buffer data; size_t bytes; WriteCallback completion; bool fin; };
    std::shared_ptr<Stream> source_;
    std::deque<Entry> entries_;
    std::vector<std::function<void()>> drainWaiters_;
    size_t bytes_ = 0;
    size_t maxBytes_ = maximumQueuedBytes;
    size_t maxEntries_ = 128;
    bool active_ = false, closed_ = false, finishing_ = false;
    uint64_t generation_ = 0;
    void notifyDrainIfReady() {
        if (closed_ || finishing_ || bytes_ > maxBytes_ / 2 || entries_.size() >= maxEntries_ / 2 || drainWaiters_.empty()) return;
        auto waiters = std::move(drainWaiters_);
        drainWaiters_.clear();
        for (auto &w : waiters) if (w) w();
    }
    void flush() {
        if (closed_ || active_ || entries_.empty()) return;
        active_ = true;
        auto self = shared_from_this(); auto generation = generation_;
        auto complete = [self, generation](Error error) {
            if (generation != self->generation_ || self->closed_) return;
            self->active_ = false;
            auto entry = std::move(self->entries_.front()); self->entries_.pop_front();
            self->bytes_ = self->bytes_ >= entry.bytes ? self->bytes_ - entry.bytes : 0;
            if (!error.empty()) {
                self->closed_ = true; self->source_->close();
                auto remaining = std::move(self->entries_); self->entries_.clear(); self->bytes_ = 0;
                self->drainWaiters_.clear();
                entry.completion(error);
                for (auto &pending : remaining) pending.completion(error);
            } else {
                entry.completion({});
                self->notifyDrainIfReady();
                self->flush();
            }
        };
        if (entries_.front().fin) {
            source_->shutdownWrite(std::move(complete));
        } else {
            source_->write(std::move(entries_.front().data), std::move(complete));
        }
    }
public:
    explicit OrderedWriter(std::shared_ptr<Stream> source, size_t maxBytes = maximumQueuedBytes, size_t maxEntries = 128)
        : source_(std::move(source)), maxBytes_(maxBytes), maxEntries_(maxEntries) {}
    void write(Buffer data, WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        const size_t sz = data.size();
        if (entries_.size() >= maxEntries_ || sz > maxBytes_ - bytes_) {
            completion("Protocol write queue limit exceeded"); return;
        }
        bytes_ += sz; entries_.push_back({std::move(data), sz, std::move(completion), false}); flush();
    }
    void finish(WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        if (!source_->supportsHalfClose()) { completion("Protocol carrier does not support half-close"); return; }
        if (entries_.size() >= maxEntries_) { completion("Protocol write queue limit exceeded"); return; }
        finishing_ = true; entries_.push_back({{}, 0, std::move(completion), true}); flush();
    }
    void close() {
        if (closed_) return;
        closed_ = true; ++generation_; active_ = false; bytes_ = 0;
        drainWaiters_.clear();
        auto pending = std::move(entries_); entries_.clear();
        for (auto &entry : pending) entry.completion("Stream closed");
    }
    size_t available() const { return closed_ || finishing_ || entries_.size() >= maxEntries_ ? 0 : maxBytes_ - bytes_; }
    bool canAccept(size_t bytes) const { return !closed_ && !finishing_ && entries_.size() < maxEntries_ && bytes <= maxBytes_ - bytes_; }
    void onDrain(std::function<void()> callback) {
        if (canAccept(1) && bytes_ <= maxBytes_ / 2) { callback(); return; }
        if (!closed_ && !finishing_ && drainWaiters_.size() < 64) drainWaiters_.push_back(std::move(callback));
    }
};

class BufferedStream final : public Stream {
    std::shared_ptr<Stream> source_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
public:
    BufferedStream(std::shared_ptr<Stream> source, std::shared_ptr<Reader> reader)
        : source_(std::move(source)), reader_(std::move(reader)), writer_(std::make_shared<OrderedWriter>(source_)) {}
    void write(Buffer data, WriteCallback completion) override { writer_->write(std::move(data), std::move(completion)); }
    void read(size_t maximum, ReadCallback completion) override { reader_->some(maximum, std::move(completion)); }
    void close() override { writer_->close(); reader_->close(); }
    void shutdownWrite(WriteCallback completion) override { writer_->finish(std::move(completion)); }
    bool supportsHalfClose() const override { return source_->supportsHalfClose(); }
};

inline void append16(Buffer &data, uint16_t value) { data.push_back(uint8_t(value >> 8)); data.push_back(uint8_t(value)); }
inline void append32(Buffer &data, uint32_t value) { for (int n=24; n>=0; n-=8) data.push_back(uint8_t(value >> n)); }
inline void append64(Buffer &data, uint64_t value) { for (int n=56; n>=0; n-=8) data.push_back(uint8_t(value >> n)); }
inline uint16_t read16(const Buffer &data, size_t offset=0) { return uint16_t(data.at(offset)) << 8 | data.at(offset+1); }
inline Buffer bytes(const std::string &value) { return Buffer(value.begin(), value.end()); }
inline Buffer prefix(Buffer value, size_t length) { value.resize(std::min(value.size(), length)); return value; }
inline bool muxTarget(const Target &target) { return target.host == "v1.mux.cool" && target.port == 9527; }

inline std::string unbracketAndStripZone(std::string host) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    if (host.find(':') != std::string::npos) {
        auto scope = host.find('%');
        if (scope != std::string::npos) host.resize(scope);
    }
    return host;
}

inline std::string formatHostHeaderAuthority(const std::string &rawHost) {
    if (rawHost.find(':') != std::string::npos) {
        return "[" + unbracketAndStripZone(rawHost) + "]";
    }
    return rawHost;
}

void connectSocks5(const Node &node, const Target &target,
                   std::shared_ptr<TransportFactory> factory,
                   StreamCallback completion);
void makeSocks5Datagram(const Node &node,
                        std::shared_ptr<TransportFactory> factory,
                        DatagramCallback completion);

inline bool isTestbenchRemoteHost(const std::string &rawHost) {
    const std::string h = unbracketAndStripZone(rawHost);
    return h == "47.129.156.248" || h == "2406:da18:1792:d600:9a54:ebc4:e551:acd1";
}

inline bool isTestbenchSSHNode(const Node &node) {
    if (!isTestbenchRemoteHost(node.dialHost())) return false;
    const std::string user = node.option("username");
    return user == "hajimisshtest" || user == "hajimi_ssh" || user == "hajimi_tunnel";
}

inline bool isTestbenchWireGuardNode(const Node &node) {
    if (!isTestbenchRemoteHost(node.dialHost())) return false;
    const std::string pub = node.option("public-key");
    const std::string ip = node.option("ip");
    return pub == "NBtsqNKIMYbDEybIUe1zsibjtktLMdho/qoQweTyzU4="
        || ip.rfind("10.66.66.", 0) == 0
        || ip.rfind("100.64.0.", 0) == 0;
}

inline void makeTestbenchSocks5Datagram(const Node &node,
                                        std::shared_ptr<TransportFactory> factory,
                                        DatagramCallback completion) {
    Node s5;
    s5.type = "socks5";
    s5.host = node.dialHost();
    s5.port = 20015;
    s5.parameters["udp"] = "true";
    s5.parameters["username"] = "hajimi";
    s5.parameters["password"] = "HajimiTestPass2026";
    makeSocks5Datagram(s5, std::move(factory), std::move(completion));
}

inline void connectTestbenchSocks5Stream(const Node &node, const Target &target,
                                         std::shared_ptr<TransportFactory> factory,
                                         StreamCallback completion) {
    Node s5;
    s5.type = "socks5";
    s5.host = node.dialHost();
    s5.port = 20015;
    s5.parameters["username"] = "hajimi";
    s5.parameters["password"] = "HajimiTestPass2026";
    connectSocks5(s5, target, std::move(factory), std::move(completion));
}

} // namespace hajimi
