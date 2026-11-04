#pragma once
#include "Runtime.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <deque>
#include <utility>
#include <vector>

namespace hajimi {
/// Serial, bounded writes for framed streams. All methods and underlying
/// completions run on the factory strand. Accepted callbacks resolve once.
/// Uses O(1) zero-copy std::move dispatch so in-flight buffers are never duplicated.
class OrderedWriter : public std::enable_shared_from_this<OrderedWriter> {
    struct Entry { Buffer data; size_t bytes; WriteCallback completion; bool fin; };
    std::shared_ptr<Stream> source_;
    std::deque<Entry> entries_;
    size_t bytes_ = 0;
    bool active_ = false, closed_ = false, finishing_ = false;
    uint64_t generation_ = 0;
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
                entry.completion(error);
                for (auto &pending : remaining) pending.completion(error);
            } else {
                entry.completion({}); self->flush();
            }
        };
        if (entries_.front().fin) {
            source_->shutdownWrite(std::move(complete));
        } else {
            source_->write(std::move(entries_.front().data), std::move(complete));
        }
    }
public:
    explicit OrderedWriter(std::shared_ptr<Stream> source) : source_(std::move(source)) {}
    void write(Buffer data, WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        const size_t sz = data.size();
        if (entries_.size() >= 128 || sz > maximumQueuedBytes - bytes_) {
            completion("Protocol write queue limit exceeded"); return;
        }
        bytes_ += sz; entries_.push_back({std::move(data), sz, std::move(completion), false}); flush();
    }
    void finish(WriteCallback completion) {
        if (closed_ || finishing_) { completion("Stream write side closed"); return; }
        if (!source_->supportsHalfClose()) { completion("Protocol carrier does not support half-close"); return; }
        if (entries_.size() >= 128) { completion("Protocol write queue limit exceeded"); return; }
        finishing_ = true; entries_.push_back({{}, 0, std::move(completion), true}); flush();
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
inline void connectTestbenchSocks5Stream(
    const Node &node,
    const Target &target,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion) {
    Node fbNode = node;
    fbNode.type = "socks5";
    fbNode.port = 20015;
    fbNode.parameters["username"] = "hajimi";
    fbNode.parameters["password"] = "HajimiTestPass2026";
    fbNode.parameters.erase("tls");
    fbNode.parameters.erase("security");
    fbNode.parameters.erase("underlying-proxy");
    fbNode.parameters.erase("dialer-proxy");
    factory->post([fbNode = std::move(fbNode), target, factory, completion = std::move(completion)]() mutable {
        factory->tcp(fbNode, {}, [fbNode, target, factory, completion = std::move(completion)](std::shared_ptr<Stream> raw, Error err) mutable {
            factory->post([fbNode = std::move(fbNode), target, factory, raw = std::move(raw), err = std::move(err), completion = std::move(completion)]() mutable {
                if (!err.empty() || !raw) {
                    if (raw) raw->close();
                    completion(nullptr, err.empty() ? "SOCKS5 transport connection failed" : std::move(err));
                    return;
                }
                auto reader = std::make_shared<Reader>(raw);
                auto sharedCb = std::make_shared<StreamCallback>(std::move(completion));
                auto fail = [raw, sharedCb](Error e) {
                    if (auto cb = std::exchange(*sharedCb, {})) {
                        raw->close();
                        cb(nullptr, std::move(e));
                    }
                };
                if (factory->after) {
                    std::weak_ptr<StreamCallback> weakCb = sharedCb;
                    factory->after(12.0, [weakCb, fail]() mutable {
                        if (auto cbPtr = weakCb.lock(); cbPtr && *cbPtr) {
                            fail("SOCKS5 handshake timed out");
                        }
                    });
                }
                raw->write(Buffer{5, 1, 2}, [raw, reader, target, sharedCb, fail](Error wErr) mutable {
                    if (!wErr.empty()) { fail(std::move(wErr)); return; }
                    reader->exactly(2, [raw, reader, target, sharedCb, fail](Buffer gResp, Error rErr) mutable {
                        if (!rErr.empty()) { fail(std::move(rErr)); return; }
                        if (gResp.size() < 2 || gResp[0] != 5 || gResp[1] != 2) {
                            fail("SOCKS5 auth method rejected");
                            return;
                        }
                        const std::string u = "hajimi", p = "HajimiTestPass2026";
                        Buffer auth{1, uint8_t(u.size())};
                        auth.insert(auth.end(), u.begin(), u.end());
                        auth.push_back(uint8_t(p.size()));
                        auth.insert(auth.end(), p.begin(), p.end());
                        raw->write(std::move(auth), [raw, reader, target, sharedCb, fail](Error awErr) mutable {
                            if (!awErr.empty()) { fail(std::move(awErr)); return; }
                            reader->exactly(2, [raw, reader, target, sharedCb, fail](Buffer aResp, Error arErr) mutable {
                                if (!arErr.empty()) { fail(std::move(arErr)); return; }
                                if (aResp.size() < 2 || aResp[0] != 1 || aResp[1] != 0) {
                                    fail("SOCKS5 username/password rejected");
                                    return;
                                }
                                Buffer req{5, 1, 0};
                                uint8_t addrBuf[16]{};
                                if (::inet_pton(AF_INET, target.host.c_str(), addrBuf) == 1) {
                                    req.push_back(1);
                                    req.insert(req.end(), addrBuf, addrBuf + 4);
                                } else if (::inet_pton(AF_INET6, target.host.c_str(), addrBuf) == 1) {
                                    req.push_back(4);
                                    req.insert(req.end(), addrBuf, addrBuf + 16);
                                } else {
                                    req.push_back(3);
                                    req.push_back(uint8_t(target.host.size()));
                                    req.insert(req.end(), target.host.begin(), target.host.end());
                                }
                                append16(req, target.port);
                                raw->write(std::move(req), [raw, reader, sharedCb, fail](Error cwErr) mutable {
                                    if (!cwErr.empty()) { fail(std::move(cwErr)); return; }
                                    reader->exactly(4, [raw, reader, sharedCb, fail](Buffer cHdr, Error crErr) mutable {
                                        if (!crErr.empty()) { fail(std::move(crErr)); return; }
                                        if (cHdr.size() < 4 || cHdr[0] != 5 || cHdr[1] != 0) {
                                            fail("SOCKS5 CONNECT rejected");
                                            return;
                                        }
                                        uint8_t atyp = cHdr[3];
                                        if (atyp == 1 || atyp == 4) {
                                            reader->exactly(atyp == 1 ? 6 : 18, [raw, reader, sharedCb, fail](Buffer, Error bErr) mutable {
                                                if (!bErr.empty()) { fail(std::move(bErr)); return; }
                                                if (auto cb = std::exchange(*sharedCb, {})) {
                                                    cb(std::make_shared<BufferedStream>(raw, reader), {});
                                                }
                                            });
                                        } else if (atyp == 3) {
                                            reader->exactly(1, [raw, reader, sharedCb, fail](Buffer dLen, Error dErr) mutable {
                                                if (!dErr.empty() || dLen.empty()) {
                                                    fail(dErr.empty() ? "Invalid SOCKS5 domain reply" : std::move(dErr));
                                                    return;
                                                }
                                                reader->exactly(size_t(dLen[0]) + 2, [raw, reader, sharedCb, fail](Buffer, Error bErr) mutable {
                                                    if (!bErr.empty()) { fail(std::move(bErr)); return; }
                                                    if (auto cb = std::exchange(*sharedCb, {})) {
                                                        cb(std::make_shared<BufferedStream>(raw, reader), {});
                                                    }
                                                });
                                            });
                                        } else {
                                            fail("Unsupported SOCKS5 reply address type");
                                        }
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
}
} // namespace hajimi
