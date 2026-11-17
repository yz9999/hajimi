#pragma once
#include "Runtime.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <deque>
#include <utility>
#include <vector>

namespace hajimi {
/// Serial, bounded writes for framed streams with high/low-water flow control
/// and automatic 32 KiB write coalescing across queued non-FIN chunks.
/// All methods and underlying completions run on the factory strand.
class OrderedWriter : public std::enable_shared_from_this<OrderedWriter> {
    static constexpr size_t kMaxCoalescedWriteBytes = 32768;
    struct Entry { Buffer data; size_t bytes; WriteCallback completion; bool fin; };
    std::shared_ptr<Stream> source_;
    std::deque<Entry> entries_;
    std::vector<std::function<void()>> drainWaiters_;
    size_t bytes_ = 0;
    size_t maxBytes_ = maximumQueuedBytes;
    size_t maxEntries_ = 128;
    size_t coalesceMaxBytes_ = 0;
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
        if (entries_.front().fin) {
            source_->shutdownWrite([self, generation](Error error) {
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
            });
            return;
        }
        size_t batchCount = 1;
        size_t batchBytes = entries_.front().bytes;
        while (coalesceMaxBytes_ > 0 &&
               batchCount < entries_.size() &&
               !entries_[batchCount].fin &&
               batchBytes + entries_[batchCount].bytes <= coalesceMaxBytes_) {
            batchBytes += entries_[batchCount].bytes;
            ++batchCount;
        }
        Buffer payload;
        if (batchCount == 1) {
            payload = std::move(entries_.front().data);
        } else {
            payload.reserve(batchBytes);
            for (size_t i = 0; i < batchCount; ++i) {
                payload.insert(payload.end(), entries_[i].data.begin(), entries_[i].data.end());
                Buffer().swap(entries_[i].data);
            }
        }
        source_->write(std::move(payload), [self, generation, batchCount, batchBytes](Error error) {
            if (generation != self->generation_ || self->closed_) return;
            self->active_ = false;
            std::vector<WriteCallback> done;
            done.reserve(batchCount);
            const size_t popCount = std::min(batchCount, self->entries_.size());
            for (size_t i = 0; i < popCount; ++i) {
                done.push_back(std::move(self->entries_.front().completion));
                self->entries_.pop_front();
            }
            self->bytes_ = self->bytes_ >= batchBytes ? self->bytes_ - batchBytes : 0;
            if (!error.empty()) {
                self->closed_ = true; self->source_->close();
                auto remaining = std::move(self->entries_); self->entries_.clear(); self->bytes_ = 0;
                self->drainWaiters_.clear();
                for (auto &cb : done) if (cb) cb(error);
                for (auto &pending : remaining) if (pending.completion) pending.completion(error);
            } else {
                for (auto &cb : done) if (cb) cb({});
                self->notifyDrainIfReady();
                self->flush();
            }
        });
    }
public:
    explicit OrderedWriter(std::shared_ptr<Stream> source, size_t maxBytes = maximumQueuedBytes,
                           size_t maxEntries = 128, size_t coalesceMaxBytes = 0)
        : source_(std::move(source)), maxBytes_(maxBytes), maxEntries_(maxEntries),
          coalesceMaxBytes_(coalesceMaxBytes) {}
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
        : source_(std::move(source)), reader_(std::move(reader)), writer_(std::make_shared<OrderedWriter>(source_, maximumQueuedBytes, 128, 32768)) {}
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

} // namespace hajimi
