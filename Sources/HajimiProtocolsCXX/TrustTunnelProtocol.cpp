// TrustTunnel Outbound Protocol (RFC 9298 MASQUE connect-udp Capsule Protocol, HTTP/1.1 TLS, HTTP/2 & HTTP/3 QUIC VPN Tunnel)
#include "TrustTunnelProtocol.hpp"
#include "ProtocolCommon.hpp"
#include "QUICTransport.hpp"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include <nghttp3/nghttp3.h>
#include <cctype>
#include <mutex>
#include <openssl/crypto.h>
#include <unordered_map>

namespace hajimi {
namespace {
using namespace proto_common;
using Fields = std::vector<std::pair<std::string, std::string>>;

void appendVarint(Buffer &buf, uint64_t value) {
    uint8_t out[8]{};
    auto res = hajimi_quic_varint_encode(value, out, sizeof(out));
    if (res.status != HAJIMI_CODEC_OK) throw std::runtime_error("Varint encode failed");
    buf.insert(buf.end(), out, out + res.written);
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

// RFC 9298 Section 3: URI Template /.well-known/masque/udp/{target_host}/{target_port}/
// IPv6 literals have colons percent-encoded as %3A per RFC 9298 Section 3.
std::string buildMasqueUdpPath(const Target &target) {
    std::string cleanHost = unbracketAndStripZone(target.host);
    std::string encodedHost;
    encodedHost.reserve(cleanHost.size() * 3);
    for (char ch : cleanHost) {
        if (ch == ':') {
            encodedHost += "%3A";
        } else {
            encodedHost.push_back(ch);
        }
    }
    return "/.well-known/masque/udp/" + encodedHost + "/" + std::to_string(target.port) + "/";
}

std::string formatAuthorityHostPort(const std::string &host, uint16_t port) {
    std::string clean = unbracketAndStripZone(host);
    if (clean.find(':') != std::string::npos) {
        return "[" + clean + "]:" + std::to_string(port);
    }
    return clean + ":" + std::to_string(port);
}

// RFC 9297 Section 3.2 & RFC 9298 Section 5:
// HTTP Capsule Protocol DATAGRAM Capsule:
//   Capsule Type = 0x00 (DATAGRAM, varint)
//   Capsule Length = varint(1 + payload.size())
//   Context ID = 0x00 (varint, 1 byte)
//   UDP Proxying Payload = raw UDP payload bytes
Buffer encodeMasqueDatagramCapsule(const Buffer &payload) {
    Buffer capsule;
    capsule.reserve(10 + payload.size());
    appendVarint(capsule, 0x00); // Capsule Type: DATAGRAM (0x00)
    appendVarint(capsule, 1 + uint64_t(payload.size())); // Length: Context ID (1B) + payload
    appendVarint(capsule, 0x00); // Context ID = 0
    capsule.insert(capsule.end(), payload.begin(), payload.end());
    return capsule;
}

Buffer encodeQpack(const Fields &fields) {
    const auto *memory = nghttp3_mem_default();
    nghttp3_qpack_encoder *encoder = nullptr;
    if (nghttp3_qpack_encoder_new(&encoder, 0, memory)) throw std::runtime_error("QPACK encoder creation failed");
    nghttp3_buf prefix, block, instructions;
    nghttp3_buf_init(&prefix); nghttp3_buf_init(&block); nghttp3_buf_init(&instructions);
    std::vector<nghttp3_nv> values;
    values.reserve(fields.size());
    for (auto &field : fields) values.push_back({
        reinterpret_cast<uint8_t *>(const_cast<char *>(field.first.data())),
        reinterpret_cast<uint8_t *>(const_cast<char *>(field.second.data())),
        field.first.size(), field.second.size(), NGHTTP3_NV_FLAG_NEVER_INDEX});
    int code = nghttp3_qpack_encoder_encode(encoder, &prefix, &block, &instructions, 0, values.data(), values.size());
    Buffer output;
    if (!code) {
        output.reserve((prefix.last - prefix.pos) + (block.last - block.pos));
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
            Buffer frame;
            frame.reserve(9 + data.size());
            frame.push_back(0x00);
            appendVarint(frame, data.size());
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
        connection_.reset();
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
                // RFC 9114 §7.2: Reject control/HTTP2-reserved frames on request streams.
                const bool forbiddenOnRequestStream =
                    frameType == 0x02 || frameType == 0x03 || frameType == 0x04 ||
                    frameType == 0x06 || frameType == 0x07 || frameType == 0x08 ||
                    frameType == 0x09 || frameType == 0x0d;
                const uint64_t maxAllowed = (frameType == 0x00) ? (16ULL * 1024 * 1024) : 65536ULL;
                if (!lenErr.empty() || forbiddenOnRequestStream || frameLen > maxAllowed) {
                    auto cb = std::exchange(self->pendingRead_, {});
                    self->close();
                    if (cb) cb({}, true, !lenErr.empty() ? lenErr :
                               (forbiddenOnRequestStream ? "Unexpected HTTP/3 control frame on request stream"
                                                         : "Oversized HTTP/3 frame"));
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
                    // RFC 9114 §7.2.8: Unknown/GREASE frames and trailing HEADERS are cleanly ignored.
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

// Pooled HTTP/3 QUIC connection manager for TrustTunnel so concurrent TCP/UDP
// streams multiplex over a single established HTTP/3 connection.
struct PooledTrustTunnelQUIC : std::enable_shared_from_this<PooledTrustTunnelQUIC> {
    std::mutex mtx;
    std::shared_ptr<TransportFactory> factory;
    std::shared_ptr<quic::Connection> connection;
    std::vector<std::function<void(std::shared_ptr<quic::Connection>, Error)>> waiters;
    bool connecting = false;
    bool settingsSent = false;
    void closeEntry() {
        std::shared_ptr<quic::Connection> oldConn;
        std::vector<std::function<void(std::shared_ptr<quic::Connection>, Error)>> pending;
        {
            std::lock_guard<std::mutex> lock(mtx);
            connecting = false;
            settingsSent = false;
            oldConn = std::move(connection);
            pending = std::move(waiters);
            waiters.clear();
        }
        if (oldConn) oldConn->close();
        for (auto &w : pending) w(nullptr, "TrustTunnel QUIC client reset");
    }
};

std::mutex &trustTunnelQuicPoolMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, std::shared_ptr<PooledTrustTunnelQUIC>> &trustTunnelQuicPool() {
    static std::unordered_map<std::string, std::shared_ptr<PooledTrustTunnelQUIC>> pool;
    return pool;
}

std::string trustTunnelPoolKey(const Node &node, const std::string &username, const std::string &password,
                               const std::shared_ptr<TransportFactory> &factory) {
    std::string credMaterial = username + ":" + password;
    Buffer credDigest = crypto::digestSlice("SHA256", reinterpret_cast<const uint8_t *>(credMaterial.data()), credMaterial.size());
    OPENSSL_cleanse(credMaterial.data(), credMaterial.size());
    return std::to_string(reinterpret_cast<uintptr_t>(factory.get())) + "|" +
           node.dialHost() + ":" + std::to_string(node.port) + "|" +
           node.interfaceName + "|" + crypto::base64Encode(credDigest) + "|" +
           node.option("sni") + "|" + (node.flag("skip-cert-verify") ? "1" : "0") + "|" +
           node.option("alpn");
}

void readHttp3ResponseHeaders(std::shared_ptr<quic::Connection> connection,
                              std::shared_ptr<Stream> stream,
                              std::shared_ptr<Reader> reader,
                              unsigned skippedFrames,
                              StreamCallback completion) {
    if (skippedFrames > 16) {
        stream->close();
        completion(nullptr, "Too many HTTP/3 frames before HEADERS");
        return;
    }
    readQuicVarint(reader, [connection, stream, reader, skippedFrames, completion = std::move(completion)](uint64_t fType, Error tErr) mutable {
        if (!tErr.empty() || connection->isClosed()) {
            stream->close();
            completion(nullptr, tErr.empty() ? "TrustTunnel QUIC cancelled" : tErr);
            return;
        }
        // RFC 9114 §7.2: Reject DATA (before HEADERS) and control/HTTP2-reserved frames on request streams.
        const bool forbiddenBeforeHeaders =
            fType == 0x00 || fType == 0x02 || fType == 0x03 || fType == 0x04 ||
            fType == 0x06 || fType == 0x07 || fType == 0x08 || fType == 0x09 || fType == 0x0d;
        if (forbiddenBeforeHeaders) {
            stream->close();
            completion(nullptr, "Unexpected HTTP/3 frame before HEADERS");
            return;
        }
        readQuicVarint(reader, [connection, stream, reader, skippedFrames, fType, completion = std::move(completion)](uint64_t fLen, Error lErr) mutable {
            if (!lErr.empty() || fLen > 65536) {
                stream->close();
                completion(nullptr, lErr.empty() ? "Oversized HTTP/3 frame" : lErr);
                return;
            }
            reader->exactly(static_cast<size_t>(fLen), [connection, stream, reader, skippedFrames, fType, completion = std::move(completion)](Buffer block, Error bErr) mutable {
                if (!bErr.empty()) {
                    stream->close();
                    completion(nullptr, bErr);
                    return;
                }
                // RFC 9114 §7.2.8: Unknown and GREASE frame types MUST be ignored.
                if (fType != 0x01) {
                    readHttp3ResponseHeaders(std::move(connection), std::move(stream), std::move(reader),
                                             skippedFrames + 1, std::move(completion));
                    return;
                }
                try {
                    auto fields = decodeQpack(block);
                    std::string status;
                    for (auto &f : fields) {
                        if (f.first == ":status") {
                            if (!status.empty()) throw std::runtime_error("Duplicate HTTP/3 :status pseudo-header");
                            status = f.second;
                        }
                    }
                    // RFC 9114 §4.1: Skip 1xx informational responses prior to final status.
                    if (status.size() == 3 && status[0] == '1') {
                        readHttp3ResponseHeaders(std::move(connection), std::move(stream), std::move(reader),
                                                 skippedFrames + 1, std::move(completion));
                        return;
                    }
                    if (status != "200") {
                        stream->close();
                        completion(nullptr, "TrustTunnel HTTP/3 CONNECT rejected");
                        return;
                    }
                    connection->authenticated();
                    completion(std::make_shared<HTTP3ConnectStream>(connection, stream, reader), {});
                } catch (const std::exception &e) {
                    stream->close();
                    completion(nullptr, e.what());
                }
            });
        });
    });
}

void acquireTrustTunnelQUIC(const Node &node, const std::string &username, const std::string &password,
                            std::shared_ptr<TransportFactory> factory,
                            std::function<void(std::shared_ptr<quic::Connection>, Error)> completion) {
    std::string key = trustTunnelPoolKey(node, username, password, factory);
    std::shared_ptr<PooledTrustTunnelQUIC> entry;
    std::vector<std::shared_ptr<PooledTrustTunnelQUIC>> evicted;
    {
        std::lock_guard<std::mutex> lock(trustTunnelQuicPoolMutex());
        if (trustTunnelQuicPool().size() >= 64 && !trustTunnelQuicPool().count(key)) {
            for (auto &kv : trustTunnelQuicPool()) {
                if (kv.second) evicted.push_back(kv.second);
            }
            trustTunnelQuicPool().clear();
        }
        auto &slot = trustTunnelQuicPool()[key];
        if (!slot) {
            slot = std::make_shared<PooledTrustTunnelQUIC>();
            slot->factory = factory;
        }
        entry = slot;
    }
    for (auto &old : evicted) old->closeEntry();

    std::shared_ptr<quic::Connection> readyConn;
    bool startDial = false;
    {
        std::lock_guard<std::mutex> entryLock(entry->mtx);
        if (entry->connection && !entry->connection->isClosed()) {
            readyConn = entry->connection;
        } else {
            entry->connection.reset();
            entry->settingsSent = false;
            entry->waiters.push_back(std::move(completion));
            if (!entry->connecting) {
                entry->connecting = true;
                startDial = true;
            }
        }
    }
    if (readyConn) {
        completion(std::move(readyConn), {});
        return;
    }
    if (!startDial) return;

    quic::Connection::connect(node, factory, [entry](std::shared_ptr<quic::Connection> conn, Error err) {
        std::vector<std::function<void(std::shared_ptr<quic::Connection>, Error)>> pending;
        bool needSettings = false;
        if (!err.empty() || !conn || conn->isClosed()) {
            if (conn) conn->close();
            {
                std::lock_guard<std::mutex> entryLock(entry->mtx);
                entry->connecting = false;
                pending = std::move(entry->waiters);
                entry->waiters.clear();
            }
            Error finalErr = err.empty() ? Error("TrustTunnel QUIC connection failed") : err;
            for (auto &w : pending) w(nullptr, finalErr);
            return;
        }
        {
            std::lock_guard<std::mutex> entryLock(entry->mtx);
            entry->connecting = false;
            entry->connection = conn;
            if (!entry->settingsSent) {
                entry->settingsSent = true;
                needSettings = true;
            }
            pending = std::move(entry->waiters);
            entry->waiters.clear();
        }
        if (needSettings) {
            // Open HTTP/3 control stream (uni stream type 0x00 + SETTINGS frame 0x04 with RFC 9220/9297 SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08 : 1)
            conn->open(true, [conn](std::shared_ptr<Stream> ctrl, Error ctrlErr) {
                if (!ctrlErr.empty() || !ctrl) return;
                Buffer settings{0x00, 0x04, 0x02, 0x08, 0x01};
                ctrl->write(std::move(settings), [](Error) {});
            });
        }
        for (auto &w : pending) w(conn, {});
    });
}

void connectTrustTunnelQUIC(const Node &node, const Target &target,
                            const std::string &username, const std::string &password,
                            std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    acquireTrustTunnelQUIC(node, username, password, factory, [node, target, username, password, completion = std::move(completion)](std::shared_ptr<quic::Connection> connection, Error err) mutable {
        if (!err.empty() || !connection || connection->isClosed()) {
            completion(nullptr, err.empty() ? "TrustTunnel QUIC connection failed" : err);
            return;
        }
        connection->open(false, [node, connection, target, username, password, completion = std::move(completion)](std::shared_ptr<Stream> stream, Error openErr) mutable {
            if (!openErr.empty() || !stream || connection->isClosed()) {
                completion(nullptr, openErr.empty() ? "TrustTunnel QUIC stream open failed" : openErr);
                return;
            }
            try {
                Buffer cred(username.begin(), username.end());
                cred.push_back(':');
                cred.insert(cred.end(), password.begin(), password.end());
                std::string auth = "Basic " + crypto::base64Encode(cred);
                OPENSSL_cleanse(cred.data(), cred.size());

                Fields headers;
                if (target.udp) {
                    // RFC 9298 Extended CONNECT for Proxying UDP in HTTP/3
                    std::string proxyAuthority = formatAuthorityHostPort(
                        node.option("sni").empty() ? node.host : node.option("sni"), node.port);
                    headers = {
                        {":method", "CONNECT"},
                        {":protocol", "connect-udp"},
                        {":scheme", "https"},
                        {":authority", proxyAuthority},
                        {":path", buildMasqueUdpPath(target)},
                        {"capsule-protocol", "?1"},
                        {"proxy-authorization", auth},
                        {"user-agent", "TrustTunnel-Client/1.0"}
                    };
                } else {
                    std::string authority = formatAuthorityHostPort(target.host, target.port);
                    headers = {
                        {":method", "CONNECT"},
                        {":authority", authority},
                        {"proxy-authorization", auth},
                        {"user-agent", "TrustTunnel-Client/1.0"}
                    };
                }

                Buffer qpackBlock = encodeQpack(headers);
                Buffer h3Req{0x01};
                appendVarint(h3Req, qpackBlock.size());
                h3Req.insert(h3Req.end(), qpackBlock.begin(), qpackBlock.end());

                OPENSSL_cleanse(auth.data(), auth.size());
                auto reader = std::make_shared<Reader>(stream);
                stream->write(std::move(h3Req), [connection, stream, reader, completion = std::move(completion)](Error writeErr) mutable {
                    if (!writeErr.empty() || connection->isClosed()) {
                        stream->close();
                        completion(nullptr, writeErr.empty() ? "TrustTunnel QUIC cancelled" : writeErr);
                        return;
                    }
                    readHttp3ResponseHeaders(std::move(connection), std::move(stream), std::move(reader), 0, std::move(completion));
                });
            } catch (const std::exception &e) {
                stream->close();
                completion(nullptr, e.what());
            }
        });
    });
}

// ============================================================================
// 3. TRUSTTUNNEL PROTOCOL (RFC 9298 MASQUE connect-udp & HTTP CONNECT)
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

// RFC 9298 (Proxying UDP in HTTP) Capsule Protocol Datagram Session
class MasqueCapsuleDatagram final : public Datagram, public std::enable_shared_from_this<MasqueCapsuleDatagram> {
public:
    MasqueCapsuleDatagram(Node node, std::shared_ptr<TransportFactory> factory,
                          std::function<void(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback)> dialer)
        : node_(std::move(node)), factory_(std::move(factory)), dialer_(std::move(dialer)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram closed"); return; }
        if (data.size() > 65535 || target.host.empty() || !target.port) {
            completion("Invalid UDP datagram target or payload size");
            return;
        }
        Buffer capsule;
        try {
            capsule = encodeMasqueDatagramCapsule(data);
        } catch (const std::exception &e) {
            completion(e.what());
            return;
        }
        sendCapsuleWithRetry(std::move(target), std::move(capsule), std::move(completion), true);
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

    void sendCapsuleWithRetry(Target target, Buffer capsule, WriteCallback completion, bool allowRetry) {
        auto self = shared_from_this();
        ensureStream(target, [self, target, capsule = std::move(capsule), completion = std::move(completion), allowRetry](Error err) mutable {
            if (!err.empty()) { completion(err); return; }
            if (!self->stream_) { completion("UDP stream unavailable"); return; }
            auto active = self->stream_;
            const bool wasUsed = self->streamUsed_;
            self->streamUsed_ = true;
            active->write(capsule, [self, target, capsule, completion = std::move(completion), active, wasUsed, allowRetry](Error writeErr) mutable {
                if (!writeErr.empty() && !self->closed_ && wasUsed && allowRetry) {
                    if (self->stream_ == active) self->resetActiveStream();
                    self->sendCapsuleWithRetry(std::move(target), std::move(capsule), std::move(completion), false);
                    return;
                }
                completion(std::move(writeErr));
            });
        });
    }

    void ensureStream(const Target &target, WriteCallback ready) {
        if (stream_ && boundTarget_.host == target.host && boundTarget_.port == target.port) {
            ready({});
            return;
        }
        if (stream_ && (boundTarget_.host != target.host || boundTarget_.port != target.port)) {
            resetActiveStream();
        }
        pendingReady_.push_back(std::move(ready));
        if (connecting_) return;
        connecting_ = true;

        Target udpTarget = target;
        udpTarget.udp = true;
        boundTarget_ = udpTarget;
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
            self->readCapsuleLoop();
        });
    }

    // RFC 9297 Section 3.2 Capsule Stream Reader:
    //   Capsule {
    //     Capsule Type (i),
    //     Capsule Length (i),
    //     Capsule Value (..),
    //   }
    // For Capsule Type 0x00 (DATAGRAM, RFC 9298 Section 5):
    //   Datagram Capsule {
    //     Context ID (i) = 0x00,
    //     UDP Proxying Payload (..),
    //   }
    void readCapsuleLoop() {
        if (closed_ || !reader_) return;
        auto self = shared_from_this();
        auto activeReader = reader_;
        readQuicVarint(activeReader, [self, activeReader](uint64_t capsuleType, Error typeErr) {
            if (self->closed_ || self->reader_ != activeReader) return;
            if (!typeErr.empty()) {
                const bool wasUsed = self->streamUsed_;
                self->resetActiveStream();
                if (self->failure_ && typeErr != "EOF" && !wasUsed) self->failure_(typeErr);
                return;
            }
            readQuicVarint(activeReader, [self, activeReader, capsuleType](uint64_t capsuleLen, Error lenErr) {
                if (self->closed_ || self->reader_ != activeReader) return;
                if (!lenErr.empty() || capsuleLen > 65536) {
                    if (self->failure_) self->failure_(lenErr.empty() ? Error("Oversized RFC 9298 capsule") : lenErr);
                    return;
                }
                activeReader->exactly(static_cast<size_t>(capsuleLen), [self, activeReader, capsuleType](Buffer value, Error valErr) {
                    if (self->closed_ || self->reader_ != activeReader) return;
                    if (!valErr.empty()) {
                        if (self->failure_) self->failure_(valErr);
                        return;
                    }
                    if (capsuleType == 0x00 && !value.empty()) {
                        uint64_t contextId = 0;
                        auto dec = hajimi_quic_varint_decode(value.data(), value.size(), &contextId);
                        if (dec.status != HAJIMI_CODEC_OK || dec.consumed > value.size()) {
                            if (self->failure_) self->failure_("Invalid RFC 9298 Context ID varint");
                            return;
                        }
                        if (contextId == 0) {
                            Buffer payload(value.begin() + dec.consumed, value.end());
                            if (self->receive_) self->receive_(self->boundTarget_, std::move(payload));
                        }
                    }
                    self->readCapsuleLoop();
                });
            });
        });
    }

    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::function<void(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback)> dialer_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
    Target boundTarget_{};
    std::vector<WriteCallback> pendingReady_;
    PacketCallback receive_;
    WriteCallback failure_;
    bool streamUsed_ = false;
    bool connecting_ = false;
    bool closed_ = false;
};

} // namespace

void resetTrustTunnelClients() {
    std::vector<std::shared_ptr<PooledTrustTunnelQUIC>> entries;
    {
        std::lock_guard<std::mutex> lock(trustTunnelQuicPoolMutex());
        for (auto &kv : trustTunnelQuicPool()) {
            if (kv.second) entries.push_back(kv.second);
        }
        trustTunnelQuicPool().clear();
    }
    for (auto &e : entries) e->closeEntry();
}

void resetTrustTunnelClient(const std::shared_ptr<TransportFactory> &factory) {
    if (!factory) {
        resetTrustTunnelClients();
        return;
    }
    std::vector<std::shared_ptr<PooledTrustTunnelQUIC>> entries;
    {
        std::lock_guard<std::mutex> lock(trustTunnelQuicPoolMutex());
        for (auto it = trustTunnelQuicPool().begin(); it != trustTunnelQuicPool().end();) {
            if (!it->second || it->second->factory == factory) {
                if (it->second) entries.push_back(it->second);
                it = trustTunnelQuicPool().erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto &e : entries) e->closeEntry();
}

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

    factory->tcp(node, tls, [node, factory, username = std::move(username), password = std::move(password),
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
            auto hasInvalidHeaderChar = [](const std::string &s) {
                return s.find_first_of("\r\n\0") != std::string::npos;
            };
            if (hasInvalidHeaderChar(target.host) || hasInvalidHeaderChar(node.host) || hasInvalidHeaderChar(node.option("sni"))) {
                throw std::runtime_error("Invalid control character in TrustTunnel target/host");
            }
            Buffer cred(username.begin(), username.end());
            cred.push_back(':');
            cred.insert(cred.end(), password.begin(), password.end());
            std::string auth = crypto::base64Encode(cred);
            OPENSSL_cleanse(cred.data(), cred.size());

            std::string request;
            if (target.udp) {
                // RFC 9298 Section 3.1 HTTP/1.1 Upgrade to connect-udp with Capsule-Protocol: ?1
                std::string proxyHost = formatAuthorityHostPort(
                    node.option("sni").empty() ? node.host : node.option("sni"), node.port);
                std::string path = buildMasqueUdpPath(target);
                request = "GET " + path + " HTTP/1.1\r\n"
                    "Host: " + proxyHost + "\r\n"
                    "Connection: Upgrade\r\n"
                    "Upgrade: connect-udp\r\n"
                    "Capsule-Protocol: ?1\r\n"
                    "Proxy-Authorization: Basic " + auth + "\r\n"
                    "User-Agent: TrustTunnel-Client/1.0\r\n\r\n";
            } else {
                std::string authority = formatAuthorityHostPort(target.host, target.port);
                request = "CONNECT " + authority + " HTTP/1.1\r\n"
                    "Host: " + authority + "\r\n"
                    "Proxy-Authorization: Basic " + auth + "\r\n"
                    "User-Agent: TrustTunnel-Client/1.0\r\n"
                    "Proxy-Connection: keep-alive\r\n\r\n";
            }
            OPENSSL_cleanse(auth.data(), auth.size());

            Buffer reqWire(request.begin(), request.end());
            OPENSSL_cleanse(request.data(), request.size());
            auto reader = std::make_shared<Reader>(raw);
            raw->write(std::move(reqWire),
                       [raw, reader, target, completion = std::move(completion)](Error writeErr) mutable {
                if (!writeErr.empty()) {
                    raw->close();
                    completion(nullptr, writeErr);
                    return;
                }
                reader->until(Buffer{'\r', '\n', '\r', '\n'}, 16384,
                              [raw, reader, target, completion = std::move(completion)](Buffer header, Error readErr) mutable {
                    if (!readErr.empty()) {
                        raw->close();
                        completion(nullptr, readErr);
                        return;
                    }
                    // Strict RFC 9112 §4 status-line parsing: HTTP-version SP status-code SP
                    std::string statusLine(header.begin(), header.end());
                    auto eol = statusLine.find("\r\n");
                    if (eol != std::string::npos) statusLine.resize(eol);
                    int statusCode = -1;
                    if ((statusLine.compare(0, 9, "HTTP/1.1 ") == 0 || statusLine.compare(0, 9, "HTTP/1.0 ") == 0) &&
                        statusLine.size() >= 12 &&
                        std::isdigit(static_cast<unsigned char>(statusLine[9])) &&
                        std::isdigit(static_cast<unsigned char>(statusLine[10])) &&
                        std::isdigit(static_cast<unsigned char>(statusLine[11])) &&
                        (statusLine.size() == 12 || statusLine[12] == ' ')) {
                        statusCode = (statusLine[9] - '0') * 100 + (statusLine[10] - '0') * 10 + (statusLine[11] - '0');
                    }
                    const bool accepted = target.udp
                        ? (statusCode == 101 || statusCode == 200)
                        : (statusCode == 200);
                    if (!accepted) {
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
    completion(std::make_shared<MasqueCapsuleDatagram>(node, std::move(factory), connectTrustTunnel), {});
}

bool trustTunnelProtocolSelfTest() {
    try {
        Node ttNode;
        ttNode.type = "trusttunnel"; ttNode.host = "127.0.0.1"; ttNode.port = 443;
        ttNode.parameters["username"] = "bob";
        ttNode.parameters["password"] = "pass456";
        if (!validateTrustTunnel(ttNode, true).empty()) return false;

        // Verify RFC 9298 URI template and Capsule encoding
        if (buildMasqueUdpPath(Target{"8.8.8.8", 53, true, false}) != "/.well-known/masque/udp/8.8.8.8/53/") return false;
        if (buildMasqueUdpPath(Target{"[2001:4860:4860::8888]", 53, true, false}) != "/.well-known/masque/udp/2001%3A4860%3A4860%3A%3A8888/53/") return false;
        Buffer cap = encodeMasqueDatagramCapsule({0xde, 0xad, 0xbe, 0xef});
        if (cap != Buffer{0x00, 0x05, 0x00, 0xde, 0xad, 0xbe, 0xef}) return false;

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

        // 2. Verify MasqueCapsuleDatagram auto-reconnects when a previously used stream fails on write
        struct ImmediateStream final : public Stream {
            size_t writes = 0;
            bool failSecondWrite = false;
            Buffer lastWritten;
            void write(Buffer data, WriteCallback cb) override {
                ++writes;
                lastWritten = std::move(data);
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
        std::shared_ptr<ImmediateStream> lastStream;
        auto autoRetryDgram = std::make_shared<MasqueCapsuleDatagram>(
            ttNode, nullptr,
            [&](const Node &, const Target &t, std::shared_ptr<TransportFactory>, StreamCallback cb) {
                if (!t.udp || t.host != "8.8.8.8" || t.port != 53) {
                    cb(nullptr, "Unexpected target");
                    return;
                }
                ++reconnectDials;
                auto s = std::make_shared<ImmediateStream>();
                s->failSecondWrite = (reconnectDials == 1);
                lastStream = s;
                cb(s, {});
            });
        Error pktErr1 = "unset", pktErr2 = "unset";
        autoRetryDgram->send(Target{"8.8.8.8", 53, true, false}, {0xaa, 0xbb}, [&](Error e) { pktErr1 = std::move(e); });
        autoRetryDgram->send(Target{"8.8.8.8", 53, true, false}, {0xcc, 0xdd}, [&](Error e) { pktErr2 = std::move(e); });
        if (!pktErr1.empty() || !pktErr2.empty() || reconnectDials != 2) return false;
        if (!lastStream || lastStream->lastWritten != Buffer{0x00, 0x03, 0x00, 0xcc, 0xdd}) return false;
        autoRetryDgram->close();

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
