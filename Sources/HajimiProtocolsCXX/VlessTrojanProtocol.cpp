#include "VlessTrojanProtocol.hpp"
#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include "Socks5Protocol.hpp"
#include "Vision.hpp"
#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace hajimi {

namespace {

const Buffer &cachedTrojanPasswordHex(const std::string &password) {
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, Buffer> cache;
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(password);
        if (it != cache.end()) return it->second;
        if (cache.size() > 64) cache.clear();
    }
    auto hash = crypto::digest("SHA224", bytes(password));
    static constexpr char hex[] = "0123456789abcdef";
    Buffer hexBytes;
    hexBytes.reserve(56);
    for (auto b : hash) {
        hexBytes.push_back(uint8_t(hex[b >> 4]));
        hexBytes.push_back(uint8_t(hex[b & 15]));
    }
    std::lock_guard<std::mutex> lock(cacheMutex);
    return cache.emplace(password, std::move(hexBytes)).first->second;
}

class PlainFramedStream : public Stream, public std::enable_shared_from_this<PlainFramedStream> {
    enum class Kind { VLESS, Trojan };
    Kind kind_;
    Target target_;
    std::shared_ptr<Stream> source_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
    Buffer request_;
    proto_common::CursorBuffer buffered_;
    std::unique_ptr<VisionCodec> vision_;
    bool visionXudp_ = false;
    bool firstXudpPacket_ = true;
    Buffer xudpGlobalId_;
    Buffer xudpRxBuf_;
    bool coalesceHeader_ = false;
    bool headerSent_ = false;
    bool responseReady_, closed_ = false, eof_ = false;
    ReadCallback pendingRead_;
    size_t requested_ = 0;

    static Buffer encodeXudpFrame(const Target &target, const Buffer &payload, bool first, const Buffer &globalId) {
        Buffer meta{0, 0, 0, 0, uint8_t(first ? 1 : 2), 1, 2};
        append16(meta, target.port);
        auto address = socksAddress(target);
        address.resize(address.size() - 2);
        if (address[0] == 3) address[0] = 2;
        else if (address[0] == 4) address[0] = 3;
        meta.insert(meta.end(), address.begin(), address.end());
        if (first && globalId.size() == 8) {
            meta.insert(meta.end(), globalId.begin(), globalId.end());
        }
        uint16_t metaLen = uint16_t(meta.size() - 2);
        meta[0] = uint8_t(metaLen >> 8);
        meta[1] = uint8_t(metaLen & 0xff);
        append16(meta, uint16_t(payload.size()));
        meta.insert(meta.end(), payload.begin(), payload.end());
        return meta;
    }

    bool tryExtractXudpPacket(Buffer &outPayload) {
        while (xudpRxBuf_.size() >= 6) {
            uint16_t metaLen = read16(xudpRxBuf_, 0);
            if (metaLen < 4 || metaLen > 512) {
                throw std::runtime_error("Invalid XUDP metadata length");
            }
            if (xudpRxBuf_.size() < size_t(2 + metaLen)) return false;
            uint8_t status = xudpRxBuf_[4];
            uint8_t opt = xudpRxBuf_[5];
            bool hasPayload = (opt & 1) != 0;
            size_t frameHeaderEnd = 2 + metaLen;
            size_t totalNeeded = frameHeaderEnd + (hasPayload ? 2 : 0);
            if (xudpRxBuf_.size() < totalNeeded) return false;
            uint16_t payloadLen = hasPayload ? read16(xudpRxBuf_, frameHeaderEnd) : 0;
            if (xudpRxBuf_.size() < totalNeeded + payloadLen) return false;
            outPayload.assign(xudpRxBuf_.begin() + totalNeeded, xudpRxBuf_.begin() + totalNeeded + payloadLen);
            xudpRxBuf_.erase(xudpRxBuf_.begin(), xudpRxBuf_.begin() + totalNeeded + payloadLen);
            if ((status == 1 || status == 2) && hasPayload) {
                return true;
            }
        }
        return false;
    }

    void finishRead(Buffer data, bool eof, Error error) {
        auto callback = std::move(pendingRead_);
        pendingRead_ = nullptr;
        if (callback) callback(std::move(data), eof, std::move(error));
    }

    void failedRead(Error error) {
        if (error == "EOF") {
            eof_ = true;
            finishRead({}, true, {});
            return;
        }
        auto callback = std::move(pendingRead_);
        pendingRead_ = nullptr;
        close();
        if (callback) callback({}, true, std::move(error));
    }

    void deliver(Buffer data, bool eof = false) {
        if (!target_.udp && data.size() > requested_) {
            buffered_.append(data.data() + requested_, data.size() - requested_);
            data.resize(requested_);
            eof_ = eof;
            finishRead(std::move(data), false, {});
        } else if (target_.udp && data.size() > requested_) {
            finishRead({}, false, "Datagram receive buffer too small");
        } else {
            finishRead(std::move(data), eof, {});
        }
    }

    void flushPendingHeaderIfIdle() {
        if (closed_ || headerSent_) return;
        headerSent_ = true;
        Buffer header = std::move(request_);
        request_.clear();
        if (vision_) {
            auto padding = vision_->initialPadding();
            header.insert(header.end(), padding.begin(), padding.end());
        }
        if (header.empty()) return;
        auto self = shared_from_this();
        writer_->write(std::move(header), [self](Error error) {
            if (!error.empty() && !self->closed_) self->failedRead(error);
        });
    }

    void nextRead() {
        if (!pendingRead_) return;
        if (!buffered_.empty()) {
            size_t n = std::min(requested_, buffered_.size());
            Buffer chunk = buffered_.consume(n);
            bool done = buffered_.empty() && eof_;
            finishRead(std::move(chunk), done, {});
            return;
        }
        if (eof_) {
            finishRead({}, true, {});
            return;
        }
        auto self = shared_from_this();
        if (!responseReady_) {
            reader_->exactly(2, [self](Buffer header, Error error) {
                if (!error.empty()) {
                    self->failedRead(error == "EOF" ? "Missing VLESS response header" : error);
                    return;
                }
                if (header[0] != 0) {
                    self->failedRead("Invalid VLESS response version");
                    return;
                }
                self->reader_->exactly(header[1], [self](Buffer, Error error) {
                    if (!error.empty()) {
                        self->failedRead(error == "EOF" ? "Truncated VLESS response addons" : error);
                        return;
                    }
                    self->responseReady_ = true;
                    self->nextRead();
                });
            });
            return;
        }
        if (vision_) {
            if (visionXudp_) {
                try {
                    Buffer pkt;
                    if (tryExtractXudpPacket(pkt)) {
                        deliver(std::move(pkt), false);
                        return;
                    }
                } catch (const std::exception &e) {
                    failedRead(e.what());
                    return;
                }
            }
            reader_->some(65536, [self](Buffer data, bool eof, Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                try {
                    bool direct = false;
                    auto decoded = self->vision_->decode(data, direct);
                    if (direct && self->source_->supportsVisionDirect()) {
                        self->source_->enableVisionDirectRead();
                    }
                    if (eof && self->vision_->truncated()) {
                        self->failedRead("Truncated Vision frame");
                        return;
                    }
                    if (self->visionXudp_) {
                        if (!decoded.empty()) {
                            self->xudpRxBuf_.insert(self->xudpRxBuf_.end(), decoded.begin(), decoded.end());
                        }
                        Buffer pkt;
                        if (self->tryExtractXudpPacket(pkt)) {
                            self->deliver(std::move(pkt), false);
                        } else if (eof) {
                            self->deliver({}, true);
                        } else {
                            self->nextRead();
                        }
                        return;
                    }
                    if (!decoded.empty() || eof) self->deliver(std::move(decoded), eof);
                    else self->nextRead();
                } catch (const std::exception &e) {
                    self->failedRead(e.what());
                }
            });
            return;
        }
        if (!target_.udp) {
            reader_->some(requested_, [self](Buffer data, bool eof, Error error) {
                self->finishRead(std::move(data), eof, std::move(error));
            });
            return;
        }
        if (kind_ == Kind::VLESS) {
            reader_->exactly(2, [self](Buffer length, Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                self->reader_->exactly(read16(length), [self](Buffer data, Error error) {
                    if (!error.empty()) self->failedRead(error == "EOF" ? "Truncated VLESS UDP payload" : error);
                    else self->deliver(std::move(data));
                });
            });
        } else {
            reader_->exactly(1, [self](Buffer type, Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                readSocksAddressFromReader(self->reader_, type[0], [self](Buffer address, Error error) {
                    if (!error.empty()) {
                        self->failedRead(error == "EOF" ? "Truncated Trojan UDP address" : error);
                        return;
                    }
                    try {
                        size_t consumed = 0;
                        parseSocksAddress(address, consumed);
                    } catch (const std::exception &e) {
                        self->failedRead(e.what());
                        return;
                    }
                    self->reader_->exactly(4, [self](Buffer header, Error error) {
                        if (!error.empty()) {
                            self->failedRead(error == "EOF" ? "Truncated Trojan UDP header" : error);
                            return;
                        }
                        if (header[2] != '\r' || header[3] != '\n') {
                            self->failedRead("Invalid Trojan UDP frame");
                            return;
                        }
                        self->reader_->exactly(read16(header), [self](Buffer data, Error error) {
                            if (!error.empty()) self->failedRead(error == "EOF" ? "Truncated Trojan UDP payload" : error);
                            else self->deliver(std::move(data));
                        });
                    });
                });
            });
        }
    }

public:
    PlainFramedStream(const Node &node, Target target, std::shared_ptr<Stream> source,
                      std::shared_ptr<TransportFactory> factory = nullptr)
        : kind_(node.type == "vless" ? Kind::VLESS : Kind::Trojan),
          target_(std::move(target)),
          source_(std::move(source)),
          factory_(std::move(factory)),
          reader_(std::make_shared<Reader>(source_)),
          writer_(std::make_shared<OrderedWriter>(source_)),
          coalesceHeader_(!target_.udp && factory_ && static_cast<bool>(factory_->after)),
          responseReady_(kind_ == Kind::Trojan) {
        if (kind_ == Kind::VLESS) {
            auto uuid = uuidBytes(node.option("uuid", node.option("username")));
            request_.reserve(128);
            request_.push_back(0);
            request_.insert(request_.end(), uuid.begin(), uuid.end());
            auto flow = node.option("flow");
            if (!flow.empty()) {
                bool reality = node.parameters.count("reality-public-key") || node.option("security") == "reality";
                if (reality && !source_->supportsVisionDirect())
                    throw std::runtime_error("VLESS Vision needs a direct-capable REALITY TCP carrier");
                std::string canonical = "xtls-rprx-vision";
                Buffer addons{0x0a, uint8_t(canonical.size())};
                addons.insert(addons.end(), canonical.begin(), canonical.end());
                request_.push_back(uint8_t(addons.size()));
                request_.insert(request_.end(), addons.begin(), addons.end());
                if (target_.udp) {
                    visionXudp_ = true;
                    xudpGlobalId_ = crypto::randomBytes(8);
                    bool anyNonZero = false;
                    for (uint8_t b : xudpGlobalId_) if (b != 0) anyNonZero = true;
                    if (!anyNonZero && !xudpGlobalId_.empty()) xudpGlobalId_[7] = 1;
                }
                vision_ = std::make_unique<VisionCodec>(uuid, !muxTarget(target_) && !visionXudp_ && source_->supportsVisionDirect());
            } else {
                request_.push_back(0);
            }
            bool useMuxCmd = muxTarget(target_) || visionXudp_;
            request_.push_back(useMuxCmd ? 3 : target_.udp ? 2 : 1);
            if (!useMuxCmd) {
                append16(request_, target_.port);
                auto address = socksAddress(target_);
                address.resize(address.size() - 2);
                if (address[0] == 3) address[0] = 2;
                else if (address[0] == 4) address[0] = 3;
                request_.insert(request_.end(), address.begin(), address.end());
            }
            if (vision_ && !coalesceHeader_) {
                auto padding = vision_->initialPadding();
                request_.insert(request_.end(), padding.begin(), padding.end());
            }
        } else {
            const auto &hexHash = cachedTrojanPasswordHex(node.option("password"));
            request_.reserve(128);
            request_.insert(request_.end(), hexHash.begin(), hexHash.end());
            request_.insert(request_.end(), {'\r', '\n', uint8_t(target_.udp ? 3 : 1)});
            auto address = socksAddress(target_);
            request_.insert(request_.end(), address.begin(), address.end());
            request_.insert(request_.end(), {'\r', '\n'});
        }
    }

    void start(StreamCallback completion) {
        auto self = shared_from_this();
        if (coalesceHeader_) {
            // Coalesce the VLESS/Trojan header with the first application payload
            // (e.g. TLS ClientHello or HTTP request) into a single TCP segment,
            // matching Xray-core / sing-box / Clash.Meta 0-RTT first-flight behavior
            // and eliminating the bare 26-byte VLESS header signature on TCP.
            // For server-first protocols (like SSH/SMTP), flush after 100ms if idle.
            std::weak_ptr<PlainFramedStream> weak = self;
            factory_->after(0.1, [weak] {
                if (auto strong = weak.lock()) strong->flushPendingHeaderIfIdle();
            });
            completion(self, {});
            return;
        }
        headerSent_ = true;
        writer_->write(std::move(request_), [self, completion = std::move(completion)](Error error) mutable {
            if (!error.empty()) {
                self->close();
                completion(nullptr, error);
            } else {
                completion(self, {});
            }
        });
    }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        size_t wireBound = data.size() + (headerSent_ ? 0 : request_.size());
        if (vision_) wireBound += std::max<size_t>(1, (data.size() + 8170) / 8171) * 1420 + 16;
        else if (target_.udp) wireBound += kind_ == Kind::Trojan ? socksAddress(target_).size() + 4 : 2;
        if (!writer_->canAccept(wireBound) || (target_.udp && data.size() > 65535)) {
            completion("Protocol write queue limit exceeded");
            return;
        }
        try {
            bool direct = false;
            if (vision_) {
                if (visionXudp_) {
                    data = encodeXudpFrame(target_, data, firstXudpPacket_, xudpGlobalId_);
                    firstXudpPacket_ = false;
                }
                data = vision_->encode(data, direct);
            } else if (target_.udp) {
                Buffer frame;
                if (kind_ == Kind::Trojan) {
                    frame = socksAddress(target_);
                    frame.reserve(frame.size() + 4 + data.size());
                } else {
                    frame.reserve(2 + data.size());
                }
                append16(frame, uint16_t(data.size()));
                if (kind_ == Kind::Trojan) frame.insert(frame.end(), {'\r', '\n'});
                frame.insert(frame.end(), data.begin(), data.end());
                data = std::move(frame);
            }
            if (!headerSent_) {
                headerSent_ = true;
                Buffer combined;
                combined.reserve(request_.size() + data.size());
                combined.insert(combined.end(), request_.begin(), request_.end());
                combined.insert(combined.end(), data.begin(), data.end());
                request_.clear();
                data = std::move(combined);
            }
            auto self = shared_from_this();
            writer_->write(std::move(data), [self, direct, completion = std::move(completion)](Error error) mutable {
                if (direct && error.empty() && self->source_->supportsVisionDirect()) {
                    self->source_->enableVisionDirectWrite();
                }
                completion(std::move(error));
            });
        } catch (const std::exception &e) {
            close();
            completion(e.what());
        }
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) { completion({}, true, "Stream closed"); return; }
        if (pendingRead_) { completion({}, false, "Concurrent stream read"); return; }
        if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid maximum read size"); return; }
        requested_ = maximum;
        pendingRead_ = std::move(completion);
        nextRead();
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        request_.clear();
        writer_->close();
        reader_->close();
        buffered_.clear();
        finishRead({}, true, "Stream closed");
    }

    void shutdownWrite(WriteCallback completion) override {
        if (!supportsHalfClose()) {
            completion("Protocol does not support half-close");
            return;
        }
        if (!headerSent_) {
            headerSent_ = true;
            Buffer header = std::move(request_);
            request_.clear();
            if (vision_) {
                auto padding = vision_->initialPadding();
                header.insert(header.end(), padding.begin(), padding.end());
            }
            if (!header.empty()) {
                auto self = shared_from_this();
                writer_->write(std::move(header), [self, completion = std::move(completion)](Error error) mutable {
                    if (!error.empty()) { completion(std::move(error)); return; }
                    self->writer_->finish(std::move(completion));
                });
                return;
            }
        }
        writer_->finish(std::move(completion));
    }

    bool supportsHalfClose() const override {
        return !target_.udp && source_->supportsHalfClose();
    }
};

} // namespace

void connectVlessTrojanProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    StreamCallback completion,
    std::shared_ptr<TransportFactory> factory) {
    std::make_shared<PlainFramedStream>(node, target, std::move(source), std::move(factory))->start(std::move(completion));
}

} // namespace hajimi
