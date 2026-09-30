#pragma once
#include "Runtime.hpp"
#include <algorithm>
#include <deque>
#include <utility>

namespace hajimi {
/// Serial, bounded writes for framed streams. All methods and underlying
/// completions run on the factory strand. Accepted callbacks resolve once.
class OrderedWriter : public std::enable_shared_from_this<OrderedWriter> {
    struct Entry { Buffer data; WriteCallback completion; bool fin; };
    std::shared_ptr<Stream> source_;
    std::deque<Entry> entries_;
    size_t bytes_ = 0;
    bool active_ = false, closed_ = false, finishing_ = false;
    uint64_t generation_ = 0;
    void flush() {
        if (closed_ || active_ || entries_.empty()) return;
        active_ = true;
        auto self = shared_from_this(); auto generation = generation_;
        auto done = [self, generation](Error error) {
            if (generation != self->generation_ || self->closed_) return;
            self->active_ = false;
            auto entry = std::move(self->entries_.front()); self->entries_.pop_front();
            self->bytes_ -= entry.data.size();
            if (!error.empty()) {
                self->closed_ = true; self->source_->close();
                auto remaining = std::move(self->entries_); self->entries_.clear(); self->bytes_ = 0;
                entry.completion(error);
                for (auto &pending : remaining) pending.completion(error);
            } else {
                entry.completion({}); self->flush();
            }
        };
        if (entries_.front().fin) source_->shutdownWrite(std::move(done));
        else source_->write(entries_.front().data, std::move(done));
    }
public:
    explicit OrderedWriter(std::shared_ptr<Stream> source) : source_(std::move(source)) {}
    void write(Buffer data, WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        if (entries_.size() >= 128 || data.size() > maximumQueuedBytes - bytes_) {
            completion("Protocol write queue limit exceeded"); return;
        }
        bytes_ += data.size(); entries_.push_back({std::move(data), std::move(completion), false}); flush();
    }
    void finish(WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        if (!source_->supportsHalfClose()) { completion("Protocol carrier does not support half-close"); return; }
        if (entries_.size() >= 128) { completion("Protocol write queue limit exceeded"); return; }
        finishing_ = true; entries_.push_back({{}, std::move(completion), true}); flush();
    }
    void close() {
        if (closed_) return;
        closed_ = true; ++generation_; active_ = false; bytes_ = 0;
        auto pending = std::move(entries_); entries_.clear();
        for (auto &entry : pending) entry.completion("Stream closed");
    }
    size_t available() const { return closed_ || finishing_ || entries_.size()>=128 ? 0 : maximumQueuedBytes - bytes_; }
    bool canAccept(size_t bytes) const { return !closed_ && !finishing_ && entries_.size()<128 && bytes<=maximumQueuedBytes-bytes_; }
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
} // namespace hajimi
