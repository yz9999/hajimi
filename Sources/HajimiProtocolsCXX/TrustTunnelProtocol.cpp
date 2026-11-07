// TrustTunnel Outbound Protocol (HTTP/1.1 TLS, HTTP/2 & HTTP/3 QUIC VPN Tunnel)
#include "TrustTunnelProtocol.hpp"
#include "ProtocolCommon.hpp"
#include "QUICTransport.hpp"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include <nghttp3/nghttp3.h>

namespace hajimi {
namespace {
using namespace proto_common;
using Fields = std::vector<std::pair<std::string, std::string>>;

Buffer encodeVarint(uint64_t value) {
    uint8_t out[8]{};
    auto res = hajimi_quic_varint_encode(value, out, sizeof(out));
    if (res.status != HAJIMI_CODEC_OK) throw std::runtime_error("Varint encode failed");
    return Buffer(out, out + res.written);
}

void readQuicVarint(std::shared_ptr<Reader> reader, std::function<void(uint64_t, Error)> completion) {
    reader->exactly(1, [reader, completion](Buffer first, Error error) {
        if (!error.empty()) { completion(0, error); return; }
        size_t length = size_t(1) << (first[0] >> 6);
        reader->exactly(length - 1, [first, completion](Buffer rest, Error error) mutable {
            if (!error.empty()) { completion(0, error); return; }
            first.insert(first.end(), rest.begin(), rest.end());
            uint64_t value = 0;
            auto result = hajimi_quic_varint_decode(first.data(), first.size(), &value);
            completion(value, result.status == HAJIMI_CODEC_OK ? Error{} : "Invalid QUIC varint");
        });
    });
}

Buffer encodeQpack(const Fields &fields) {
    const auto *memory = nghttp3_mem_default();
    nghttp3_qpack_encoder *encoder = nullptr;
    if (nghttp3_qpack_encoder_new(&encoder, 0, memory)) throw std::runtime_error("QPACK encoder creation failed");
    nghttp3_buf prefix, block, instructions;
    nghttp3_buf_init(&prefix); nghttp3_buf_init(&block); nghttp3_buf_init(&instructions);
    std::vector<nghttp3_nv> values;
    for (auto &field : fields) values.push_back({
        reinterpret_cast<uint8_t *>(const_cast<char *>(field.first.data())),
        reinterpret_cast<uint8_t *>(const_cast<char *>(field.second.data())),
        field.first.size(), field.second.size(), NGHTTP3_NV_FLAG_NEVER_INDEX});
    int code = nghttp3_qpack_encoder_encode(encoder, &prefix, &block, &instructions, 0, values.data(), values.size());
    Buffer output;
    if (!code) {
        output.insert(output.end(), prefix.pos, prefix.last);
        output.insert(output.end(), block.pos, block.last);
    }
    nghttp3_buf_free(&prefix, memory); nghttp3_buf_free(&block, memory); nghttp3_buf_free(&instructions, memory);
    nghttp3_qpack_encoder_del(encoder);
    if (code) throw std::runtime_error("QPACK encoding failed");
    return output;
}

Fields decodeQpack(const Buffer &input) {
    const auto *memory = nghttp3_mem_default();
    nghttp3_qpack_decoder *decoder = nullptr;
    nghttp3_qpack_stream_context *context = nullptr;
    if (nghttp3_qpack_decoder_new(&decoder, 0, 0, memory)) throw std::runtime_error("QPACK decoder creation failed");
    if (nghttp3_qpack_stream_context_new(&context, 0, memory)) {
        nghttp3_qpack_decoder_del(decoder);
        throw std::runtime_error("QPACK context creation failed");
    }
    Fields fields; size_t offset = 0, size = 0; bool valid = false;
    for (size_t iteration = 0; iteration < 256; ++iteration) {
        nghttp3_qpack_nv value{}; uint8_t flags = 0;
        auto count = nghttp3_qpack_decoder_read_request(decoder, context, &value, &flags,
            input.data() + offset, input.size() - offset, 1);
        if (count < 0 || (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED)) break;
        offset += static_cast<size_t>(count);
        if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
            auto name = nghttp3_rcbuf_get_buf(value.name), content = nghttp3_rcbuf_get_buf(value.value);
            fields.push_back({std::string(reinterpret_cast<char *>(name.base), name.len),
                              std::string(reinterpret_cast<char *>(content.base), content.len)});
            size += name.len + content.len;
            nghttp3_rcbuf_decref(value.name); nghttp3_rcbuf_decref(value.value);
            if (size > 65536 || fields.size() > 128) break;
        }
        if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) { valid = offset == input.size(); break; }
        if (count == 0 && !(flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT)) break;
    }
    nghttp3_qpack_stream_context_del(context);
    nghttp3_qpack_decoder_del(decoder);
    if (!valid) throw std::runtime_error("Invalid QPACK response");
    return fields;
}

class HTTP3ConnectStream final : public Stream, public std::enable_shared_from_this<HTTP3ConnectStream> {
public:
    HTTP3ConnectStream(std::shared_ptr<quic::Connection> connection, std::shared_ptr<Stream> stream, std::shared_ptr<Reader> reader)
        : connection_(std::move(connection)), stream_(std::move(stream)), reader_(std::move(reader)),
          writer_(std::make_shared<OrderedWriter>(stream_)) {}
    ~HTTP3ConnectStream() override { close(); }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        if (data.empty()) { completion({}); return; }
        try {
            Buffer frame{0x00};
            auto lenVar = encodeVarint(data.size());
            frame.insert(frame.end(), lenVar.begin(), lenVar.end());
            frame.insert(frame.end(), data.begin(), data.end());
            writer_->write(std::move(frame), std::move(completion));
        } catch (const std::exception &e) {
            completion(e.what());
        }
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) { completion({}, true, "Stream closed"); return; }
        if (pendingRead_) { completion({}, false, "Concurrent HTTP/3 read"); return; }
        if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid maximum read size"); return; }
        requested_ = maximum;
        pendingRead_ = std::move(completion);
        pumpRead();
    }

    void shutdownWrite(WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        writer_->finish(std::move(completion));
    }

    bool supportsHalfClose() const override { return true; }

    void close() override {
        if (closed_) return;
        closed_ = true;
        writer_->close();
        reader_->close();
        if (stream_) { stream_->close(); stream_.reset(); }
        if (connection_) { connection_->close(); connection_.reset(); }
        buffered_.clear();
        if (auto cb = std::exchange(pendingRead_, {})) cb({}, true, "Stream closed");
    }

private:
    void pumpRead() {
        if (!pendingRead_) return;
        if (!buffered_.empty()) {
            size_t n = std::min(requested_, buffered_.size());
            Buffer chunk = buffered_.consume(n);
            bool done = buffered_.empty() && eof_;
            auto cb = std::exchange(pendingRead_, {});
            cb(std::move(chunk), done, {});
            return;
        }
        if (eof_) {
            auto cb = std::exchange(pendingRead_, {});
            cb({}, true, {});
            return;
        }
        auto self = shared_from_this();
        readQuicVarint(reader_, [self](uint64_t frameType, Error typeErr) {
            if (self->closed_) return;
            if (!typeErr.empty()) {
                if (typeErr == "EOF") {
                    self->eof_ = true;
                    self->pumpRead();
                    return;
                }
                auto cb = std::exchange(self->pendingRead_, {});
                self->close();
                if (cb) cb({}, true, typeErr);
                return;
            }
            readQuicVarint(self->reader_, [self, frameType](uint64_t frameLen, Error lenErr) {
                if (self->closed_) return;
                if (!lenErr.empty() || frameLen > 16 * 1024 * 1024) {
                    auto cb = std::exchange(self->pendingRead_, {});
                    self->close();
                    if (cb) cb({}, true, lenErr.empty() ? "Oversized HTTP/3 frame" : lenErr);
                    return;
                }
                self->reader_->exactly(static_cast<size_t>(frameLen), [self, frameType](Buffer payload, Error payErr) {
                    if (self->closed_) return;
                    if (!payErr.empty()) {
                        auto cb = std::exchange(self->pendingRead_, {});
                        self->close();
                        if (cb) cb({}, true, payErr);
                        return;
                    }
                    if (frameType == 0x00 && !payload.empty()) {
                        self->buffered_.append(payload.data(), payload.size());
                    }
                    self->pumpRead();
                });
            });
        });
    }

    std::shared_ptr<quic::Connection> connection_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
    CursorBuffer buffered_;
    ReadCallback pendingRead_;
    size_t requested_ = 0;
    bool closed_ = false, eof_ = false;
};

void connectTrustTunnelQUIC(const Node &node, const Target &target,
                            const std::string &username, const std::string &password,
                            std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    quic::Connection::connect(node, factory, [node, target, username, password, completion = std::move(completion)](std::shared_ptr<quic::Connection> connection, Error err) mutable {
        if (!err.empty() || !connection || connection->isClosed()) {
            if (connection) connection->close();
            completion(nullptr, err.empty() ? "TrustTunnel QUIC connection failed" : err);
            return;
        }
        // Open HTTP/3 control stream (uni stream type 0x00 + SETTINGS frame 0x04)
        connection->open(true, [connection](std::shared_ptr<Stream> ctrl, Error ctrlErr) {
            if (!ctrlErr.empty() || !ctrl) return;
            Buffer settings{0x00, 0x04, 0x00};
            ctrl->write(std::move(settings), [](Error) {});
        });
        connection->open(false, [connection, target, username, password, completion = std::move(completion)](std::shared_ptr<Stream> stream, Error openErr) mutable {
            if (!openErr.empty() || !stream || connection->isClosed()) {
                connection->close();
                completion(nullptr, openErr.empty() ? "TrustTunnel QUIC stream open failed" : openErr);
                return;
            }
            try {
                Buffer cred(username.begin(), username.end());
                cred.push_back(':');
                cred.insert(cred.end(), password.begin(), password.end());
                std::string auth = "Basic " + crypto::base64Encode(cred);

                std::string authority = target.udp
                    ? "_trusttunnel_udp_:443"
                    : ((target.host.find(':') != std::string::npos && target.host.front() != '[')
                        ? ("[" + target.host + "]:" + std::to_string(target.port))
                        : (target.host + ":" + std::to_string(target.port)));

                Buffer qpackBlock = encodeQpack({
                    {":method", "CONNECT"},
                    {":authority", authority},
                    {"proxy-authorization", auth},
                    {"user-agent", "TrustTunnel-Client/1.0"}
                });
                Buffer h3Req{0x01};
                auto lenVar = encodeVarint(qpackBlock.size());
                h3Req.insert(h3Req.end(), lenVar.begin(), lenVar.end());
                h3Req.insert(h3Req.end(), qpackBlock.begin(), qpackBlock.end());

                auto reader = std::make_shared<Reader>(stream);
                stream->write(std::move(h3Req), [connection, stream, reader, completion = std::move(completion)](Error writeErr) mutable {
                    if (!writeErr.empty() || connection->isClosed()) {
                        connection->close();
                        completion(nullptr, writeErr.empty() ? "TrustTunnel QUIC cancelled" : writeErr);
                        return;
                    }
                    readQuicVarint(reader, [connection, stream, reader, completion = std::move(completion)](uint64_t fType, Error tErr) mutable {
                        if (!tErr.empty() || fType != 0x01) {
                            connection->close();
                            completion(nullptr, tErr.empty() ? "Expected HTTP/3 HEADERS frame" : tErr);
                            return;
                        }
                        readQuicVarint(reader, [connection, stream, reader, completion = std::move(completion)](uint64_t fLen, Error lErr) mutable {
                            if (!lErr.empty() || fLen > 65536) {
                                connection->close();
                                completion(nullptr, lErr.empty() ? "Oversized HTTP/3 HEADERS frame" : lErr);
                                return;
                            }
                            reader->exactly(static_cast<size_t>(fLen), [connection, stream, reader, completion = std::move(completion)](Buffer block, Error bErr) mutable {
                                if (!bErr.empty()) {
                                    connection->close();
                                    completion(nullptr, bErr);
                                    return;
                                }
                                try {
                                    auto fields = decodeQpack(block);
                                    std::string status;
                                    for (auto &f : fields) {
                                        if (f.first == ":status") status = f.second;
                                    }
                                    if (status != "200") {
                                        connection->close();
                                        completion(nullptr, "TrustTunnel HTTP/3 CONNECT rejected");
                                        return;
                                    }
                                    connection->authenticated();
                                    completion(std::make_shared<HTTP3ConnectStream>(connection, stream, reader), {});
                                } catch (const std::exception &e) {
                                    connection->close();
                                    completion(nullptr, e.what());
                                }
                            });
                        });
                    });
                });
            } catch (const std::exception &e) {
                connection->close();
                completion(nullptr, e.what());
            }
        });
    });
}

// ============================================================================
// 3. TRUSTTUNNEL PROTOCOL
// ============================================================================

Error parseTrustTunnelConfig(const Node &node, std::string &username, std::string &password) {
    username = node.option("username", node.option("user"));
    password = node.option("password");
    if (username.empty() || password.empty()) {
        return "TrustTunnel requires both username and password";
    }
    if (username.size() > 2048 || password.size() > 2048) {
        return "TrustTunnel credential limit exceeded";
    }
    if (!node.flag("tls", true)) {
        return "TrustTunnel requires TLS encryption";
    }
    auto quicOpt = lowerAscii(node.option("quic", "false"));
    if (!quicOpt.empty() &&
        quicOpt != "true" && quicOpt != "false" &&
        quicOpt != "1" && quicOpt != "0" &&
        quicOpt != "yes" && quicOpt != "no" &&
        quicOpt != "on" && quicOpt != "off") {
        return "Invalid TrustTunnel quic boolean option";
    }
    return {};
}



// Stream-backed UDP datagram session for TrustTunnel
class StreamPacketDatagram final : public Datagram, public std::enable_shared_from_this<StreamPacketDatagram> {
public:
    StreamPacketDatagram(Node node, std::shared_ptr<TransportFactory> factory,
                         std::function<void(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback)> dialer)
        : node_(std::move(node)), factory_(std::move(factory)), dialer_(std::move(dialer)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram closed"); return; }
        if (data.size() > 65535 || target.host.empty() || !target.port) {
            completion("Invalid UDP datagram target or payload size");
            return;
        }
        Buffer packet;
        try {
            packet = socksAddress(target);
            appendBE16(packet, uint16_t(data.size()));
            packet.insert(packet.end(), data.begin(), data.end());
        } catch (const std::exception &e) {
            completion(e.what());
            return;
        }

        auto self = shared_from_this();
        sendPacketWithRetry(target, std::move(packet), std::move(completion), true);
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        receive_ = std::move(receive);
        failure_ = std::move(failure);
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        resetActiveStream();
    }

private:
    void resetActiveStream() {
        auto r = std::move(reader_);
        auto s = std::move(stream_);
        streamUsed_ = false;
        if (r) r->close();
        else if (s) s->close();
    }

    void sendPacketWithRetry(Target target, Buffer packet, WriteCallback completion, bool allowRetry) {
        auto self = shared_from_this();
        ensureStream(target, [self, target, packet = std::move(packet), completion = std::move(completion), allowRetry](Error err) mutable {
            if (!err.empty()) { completion(err); return; }
            if (!self->stream_) { completion("UDP stream unavailable"); return; }
            auto active = self->stream_;
            const bool wasUsed = self->streamUsed_;
            self->streamUsed_ = true;
            active->write(packet, [self, target, packet, completion = std::move(completion), active, wasUsed, allowRetry](Error writeErr) mutable {
                if (!writeErr.empty() && !self->closed_ && wasUsed && allowRetry) {
                    if (self->stream_ == active) self->resetActiveStream();
                    self->sendPacketWithRetry(std::move(target), std::move(packet), std::move(completion), false);
                    return;
                }
                completion(std::move(writeErr));
            });
        });
    }

    void ensureStream(const Target &initialTarget, WriteCallback ready) {
        if (stream_) { ready({}); return; }
        pendingReady_.push_back(std::move(ready));
        if (connecting_) return;
        connecting_ = true;

        Target udpTarget = initialTarget;
        udpTarget.udp = true;
        auto self = shared_from_this();
        dialer_(node_, udpTarget, factory_, [self](std::shared_ptr<Stream> stream, Error err) {
            self->connecting_ = false;
            auto callbacks = std::move(self->pendingReady_);
            self->pendingReady_.clear();
            if (self->closed_ || !err.empty() || !stream) {
                Error finalErr = !err.empty() ? err : Error("UDP carrier closed");
                for (auto &cb : callbacks) cb(finalErr);
                return;
            }
            self->stream_ = std::move(stream);
            self->reader_ = std::make_shared<Reader>(self->stream_);
            self->streamUsed_ = false;
            for (auto &cb : callbacks) cb({});
            self->readLoop();
        });
    }

    void readLoop() {
        if (closed_ || !reader_) return;
        auto self = shared_from_this();
        auto activeReader = reader_;
        activeReader->exactly(1, [self, activeReader](Buffer atyp, Error err) {
            if (self->closed_ || self->reader_ != activeReader) return;
            if (!err.empty()) {
                const bool wasUsed = self->streamUsed_;
                self->resetActiveStream();
                if (self->failure_ && err != "EOF" && !wasUsed) self->failure_(err);
                return;
            }
            size_t addrTail = 0;
            if (atyp[0] == 1) addrTail = 6;
            else if (atyp[0] == 4) addrTail = 18;
            else if (atyp[0] == 3) {
                self->reader_->exactly(1, [self](Buffer dlen, Error derr) {
                    if (self->closed_ || !derr.empty() || dlen.empty() || !dlen[0]) {
                        if (self->failure_ && !derr.empty()) self->failure_(derr);
                        return;
                    }
                    size_t rest = size_t(dlen[0]) + 4;
                    self->reader_->exactly(rest, [self, dlen](Buffer tail, Error terr) {
                        if (self->closed_ || !terr.empty()) {
                            if (self->failure_ && !terr.empty()) self->failure_(terr);
                            return;
                        }
                        Buffer full{3, dlen[0]};
                        full.insert(full.end(), tail.begin(), tail.begin() + dlen[0] + 2);
                        uint16_t payLen = readBE16(tail.data() + dlen[0] + 2);
                        self->readPayload(std::move(full), payLen);
                    });
                });
                return;
            } else {
                if (self->failure_) self->failure_("Invalid UDP address family");
                return;
            }
            self->reader_->exactly(addrTail + 2, [self, atyp](Buffer tail, Error terr) {
                if (self->closed_ || !terr.empty()) {
                    if (self->failure_ && !terr.empty()) self->failure_(terr);
                    return;
                }
                Buffer full{atyp[0]};
                full.insert(full.end(), tail.begin(), tail.end() - 2);
                uint16_t payLen = readBE16(tail.data() + tail.size() - 2);
                self->readPayload(std::move(full), payLen);
            });
        });
    }

    void readPayload(Buffer encodedAddress, uint16_t payLen) {
        auto self = shared_from_this();
        reader_->exactly(payLen, [self, encodedAddress = std::move(encodedAddress)](Buffer payload, Error err) mutable {
            if (self->closed_) return;
            if (!err.empty()) {
                if (self->failure_) self->failure_(err);
                return;
            }
            try {
                size_t consumed = 0;
                Target source = parseSocksAddress(encodedAddress, consumed);
                if (self->receive_) self->receive_(source, std::move(payload));
                self->readLoop();
            } catch (const std::exception &e) {
                if (self->failure_) self->failure_(e.what());
            }
        });
    }

    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::function<void(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback)> dialer_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
    std::vector<WriteCallback> pendingReady_;
    PacketCallback receive_;
    WriteCallback failure_;
    bool streamUsed_ = false;
    bool connecting_ = false;
    bool closed_ = false;
};

} // namespace


Error validateTrustTunnel(const Node &node, bool) {
    std::string user, pass;
    return parseTrustTunnelConfig(node, user, pass);
}

void connectTrustTunnel(const Node &node, const Target &target,
                        std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    std::string username, password;
    auto err = parseTrustTunnelConfig(node, username, password);
    if (!err.empty()) { completion(nullptr, err); return; }

    if (node.flag("quic", false)) {
        connectTrustTunnelQUIC(node, target, username, password, std::move(factory), std::move(completion));
        return;
    }

    auto tls = tlsOptions(node, true);
    if (tls.alpn.empty()) {
        tls.alpn.push_back("http/1.1");
    }

    factory->tcp(node, tls, [factory, username = std::move(username), password = std::move(password),
                             target, rawCompletion = std::move(completion)]
                 (std::shared_ptr<Stream> raw, Error dialErr) mutable {
        auto doneFlag = std::make_shared<bool>(false);
        StreamCallback completion = [rawCompletion = std::move(rawCompletion), doneFlag](std::shared_ptr<Stream> s, Error e) mutable {
            if (*doneFlag) {
                if (s) s->close();
                return;
            }
            *doneFlag = true;
            if (rawCompletion) rawCompletion(std::move(s), std::move(e));
        };
        if (!dialErr.empty() || !raw) {
            completion(nullptr, dialErr.empty() ? Error("TrustTunnel TLS dial failed") : dialErr);
            return;
        }
        if (factory && factory->after) {
            factory->after(10.0, [raw, doneFlag, completion]() mutable {
                if (!*doneFlag) {
                    raw->close();
                    completion(nullptr, "TrustTunnel handshake timed out");
                }
            });
        }
        try {
            Buffer cred(username.begin(), username.end());
            cred.push_back(':');
            cred.insert(cred.end(), password.begin(), password.end());
            std::string auth = crypto::base64Encode(cred);

            std::string authority = target.udp
                ? "_trusttunnel_udp_:443"
                : ((target.host.find(':') != std::string::npos && target.host.front() != '[')
                    ? ("[" + target.host + "]:" + std::to_string(target.port))
                    : (target.host + ":" + std::to_string(target.port)));

            std::string request = "CONNECT " + authority + " HTTP/1.1\r\n"
                "Host: " + authority + "\r\n"
                "Proxy-Authorization: Basic " + auth + "\r\n"
                "User-Agent: TrustTunnel-Client/1.0\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n";

            auto reader = std::make_shared<Reader>(raw);
            raw->write(Buffer(request.begin(), request.end()),
                       [raw, reader, completion = std::move(completion)](Error writeErr) mutable {
                if (!writeErr.empty()) {
                    raw->close();
                    completion(nullptr, writeErr);
                    return;
                }
                reader->until(Buffer{'\r', '\n', '\r', '\n'}, 16384,
                              [raw, reader, completion = std::move(completion)](Buffer header, Error readErr) mutable {
                    if (!readErr.empty()) {
                        raw->close();
                        completion(nullptr, readErr);
                        return;
                    }
                    std::string statusLine(header.begin(), header.end());
                    auto eol = statusLine.find("\r\n");
                    if (eol != std::string::npos) statusLine.resize(eol);
                    if (statusLine.find(" 200") == std::string::npos) {
                        raw->close();
                        completion(nullptr, "TrustTunnel CONNECT rejected by endpoint");
                        return;
                    }
                    completion(std::make_shared<PrefixedStream>(raw, reader), {});
                });
            });
        } catch (const std::exception &e) {
            raw->close();
            completion(nullptr, e.what());
        }
    });
}

void makeTrustTunnelDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                             DatagramCallback completion) {
    auto err = validateTrustTunnel(node, true);
    if (!err.empty()) { completion(nullptr, err); return; }
    completion(std::make_shared<StreamPacketDatagram>(node, std::move(factory), connectTrustTunnel), {});
}

bool trustTunnelProtocolSelfTest() {
    try {
        Node ttNode;
        ttNode.type = "trusttunnel"; ttNode.host = "127.0.0.1"; ttNode.port = 443;
        ttNode.parameters["username"] = "bob";
        ttNode.parameters["password"] = "pass456";
        if (!validateTrustTunnel(ttNode, true).empty()) return false;

        // 1. Verify PrefixedStream OrderedWriter serializes concurrent writes
        struct SingleFlightStream final : public Stream {
            bool writing = false;
            size_t writeCalls = 0;
            bool failAfterFirstWrite = false;
            std::vector<WriteCallback> pendingWrites;
            void write(Buffer, WriteCallback completion) override {
                if (writing) {
                    completion("Concurrent write violation");
                    return;
                }
                ++writeCalls;
                if (failAfterFirstWrite && writeCalls > 1) {
                    completion("Simulated stale idle stream reset");
                    return;
                }
                writing = true;
                pendingWrites.push_back(std::move(completion));
            }
            void flushAll() {
                while (!pendingWrites.empty()) {
                    writing = false;
                    auto cb = std::move(pendingWrites.front());
                    pendingWrites.erase(pendingWrites.begin());
                    cb({});
                }
            }
            void read(size_t, ReadCallback) override {}
            void close() override { writing = false; pendingWrites.clear(); }
        };
        auto raw = std::make_shared<SingleFlightStream>();
        auto prefixed = std::make_shared<PrefixedStream>(raw, std::make_shared<Reader>(raw));
        Error err1 = "unset", err2 = "unset";
        prefixed->write({1, 2, 3}, [&](Error e) { err1 = std::move(e); });
        prefixed->write({4, 5, 6}, [&](Error e) { err2 = std::move(e); });
        raw->flushAll();
        if (!err1.empty() || !err2.empty() || raw->writeCalls != 2) return false;
        prefixed->close();

        // 2. Verify StreamPacketDatagram auto-reconnects when a previously used stream fails on write
        size_t dialCount = 0;
        auto dgram = std::make_shared<StreamPacketDatagram>(
            ttNode, nullptr,
            [&](const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback cb) {
                ++dialCount;
                auto s = std::make_shared<SingleFlightStream>();
                s->failAfterFirstWrite = (dialCount == 1);
                cb(s, {});
                s->flushAll();
            });
        // Dialer above flushes synchronously on creation; let's use an immediate-complete stream for datagram test
        struct ImmediateStream final : public Stream {
            size_t writes = 0;
            bool failSecondWrite = false;
            void write(Buffer, WriteCallback cb) override {
                ++writes;
                if (failSecondWrite && writes >= 2) {
                    cb("Simulated NAT rebinding broken pipe");
                    return;
                }
                cb({});
            }
            void read(size_t, ReadCallback) override {}
            void close() override {}
        };
        size_t reconnectDials = 0;
        auto autoRetryDgram = std::make_shared<StreamPacketDatagram>(
            ttNode, nullptr,
            [&](const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback cb) {
                ++reconnectDials;
                auto s = std::make_shared<ImmediateStream>();
                s->failSecondWrite = (reconnectDials == 1);
                cb(s, {});
            });
        Error pktErr1 = "unset", pktErr2 = "unset";
        autoRetryDgram->send(Target{"8.8.8.8", 53, true, false}, {0xaa, 0xbb}, [&](Error e) { pktErr1 = std::move(e); });
        autoRetryDgram->send(Target{"8.8.8.8", 53, true, false}, {0xcc, 0xdd}, [&](Error e) { pktErr2 = std::move(e); });
        if (!pktErr1.empty() || !pktErr2.empty() || reconnectDials != 2) return false;
        autoRetryDgram->close();

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
