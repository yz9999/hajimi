#include "QUICTransport.hpp"
#include "Crypto.hpp"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include <nghttp3/nghttp3.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cctype>
#include <deque>
#include <chrono>
#include <unordered_set>
#include <stdexcept>

namespace hajimi {
namespace {
using Connection = quic::Connection;
using Fields = std::vector<std::pair<std::string, std::string>>;
uint16_t be16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
uint32_t be32(const uint8_t *p) { return (uint32_t(be16(p)) << 16) | be16(p + 2); }
std::string auth(const Node &node) {
    return node.type == "hysteria" ? node.option("auth-str", node.option("auth", node.option("password"))) :
           node.option("password", node.option("auth", node.option("auth-str")));
}
std::pair<Buffer, std::string> credentials(const Node &node) {
    auto uuid = node.option("uuid"), password = node.option("password");
    if (uuid.empty()) {
        auto token = node.option("token"); auto colon = token.find(':');
        if (colon != std::string::npos) { uuid = token.substr(0, colon); password = token.substr(colon + 1); }
    }
    Buffer bytes; int nibble = -1;
    for (auto ch : uuid) {
        if (ch == '-') continue;
        int digit = ch >= '0' && ch <= '9' ? ch - '0' :
                    ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (digit < 0) return {};
        if (nibble < 0) nibble = digit;
        else { bytes.push_back(static_cast<uint8_t>((nibble << 4) | digit)); nibble = -1; }
    }
    if (bytes.size() != 16 || nibble >= 0) return {};
    return {bytes, password};
}
uint64_t bandwidth(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c); }), value.end());
    if (value.empty()) return 0;
    char *end = nullptr; double number = std::strtod(value.c_str(), &end);
    if (end == value.c_str() || !std::isfinite(number) || number <= 0) return 0;
    std::string unit(end); double multiplier = 125000; // Bare value: Mbps.
    if (!unit.empty()) {
        multiplier = 1;
        auto power = std::string("KMGT").find(static_cast<char>(std::toupper(unit[0])));
        if (power != std::string::npos) { multiplier = std::pow(1024, power + 1); unit.erase(0, 1); }
        if (unit.empty() || (unit[0] != 'b' && unit[0] != 'B')) return 0;
        if (unit[0] == 'b') multiplier /= 8;
        unit.erase(0, 1); if (!unit.empty() && unit != "ps" && unit != "/s") return 0;
    }
    double bytes = number * multiplier;
    return bytes < static_cast<double>(UINT64_MAX) && bytes >= 1 ? static_cast<uint64_t>(bytes) : 0;
}
uint64_t upload(const Node &n) { return bandwidth(n.option("up", n.option("up-speed", n.option("upload-bandwidth")))); }
uint64_t download(const Node &n) { return bandwidth(n.option("down", n.option("down-speed", n.option("download-bandwidth")))); }
hajimi_address address(const Target &target) {
    hajimi_address value{};
    if (hajimi_address_from_host(reinterpret_cast<const uint8_t *>(target.host.data()),
                                target.host.size(), target.port, &value).status != HAJIMI_CODEC_OK)
        throw std::runtime_error("Invalid QUIC target address");
    return value;
}
template<class Encode> Buffer encoded(Encode encode) {
    auto result = encode(nullptr, 0);
    if (result.status != HAJIMI_CODEC_OUTPUT_TOO_SMALL || result.needed > 65535)
        throw std::runtime_error("Invalid QUIC protocol frame");
    Buffer value(result.needed); result = encode(value.data(), value.size());
    if (result.status != HAJIMI_CODEC_OK) throw std::runtime_error("QUIC frame encoding failed");
    value.resize(result.written); return value;
}
Buffer varint(uint64_t value) {
    return encoded([value](uint8_t *output, size_t capacity) { return hajimi_quic_varint_encode(value, output, capacity); });
}
void append(Buffer &output, const Buffer &value) { output.insert(output.end(), value.begin(), value.end()); }
void readVarint(std::shared_ptr<Reader> reader, std::function<void(uint64_t, Error)> completion) {
    reader->exactly(1, [reader, completion](Buffer first, Error error) {
        if (!error.empty()) { completion(0, error); return; }
        size_t length = size_t(1) << (first[0] >> 6);
        reader->exactly(length - 1, [first, completion](Buffer rest, Error error) mutable {
            if (!error.empty()) { completion(0, error); return; }
            append(first, rest); uint64_t value = 0;
            auto result = hajimi_quic_varint_decode(first.data(), first.size(), &value);
            completion(value, result.status == HAJIMI_CODEC_OK ? Error{} : "Invalid QUIC varint");
        });
    });
}

Buffer qpack(const Fields &fields) {
    const auto *memory = nghttp3_mem_default(); nghttp3_qpack_encoder *encoder = nullptr;
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
    if (!code) { output.insert(output.end(), prefix.pos, prefix.last); output.insert(output.end(), block.pos, block.last); }
    nghttp3_buf_free(&prefix, memory); nghttp3_buf_free(&block, memory); nghttp3_buf_free(&instructions, memory);
    nghttp3_qpack_encoder_del(encoder);
    if (code) throw std::runtime_error("QPACK encoding failed");
    return output;
}

Fields unpack(const Buffer &input) {
    const auto *memory = nghttp3_mem_default(); nghttp3_qpack_decoder *decoder = nullptr;
    nghttp3_qpack_stream_context *context = nullptr;
    if (nghttp3_qpack_decoder_new(&decoder, 0, 0, memory)) throw std::runtime_error("QPACK decoder creation failed");
    if (nghttp3_qpack_stream_context_new(&context, 0, memory)) {
        nghttp3_qpack_decoder_del(decoder); throw std::runtime_error("QPACK context creation failed");
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
    nghttp3_qpack_stream_context_del(context); nghttp3_qpack_decoder_del(decoder);
    if (!valid) throw std::runtime_error("Invalid/oversized QPACK response");
    return fields;
}

void drain(std::shared_ptr<Stream> stream, size_t total = 0) {
    stream->read(32768, [stream, total](Buffer data, bool eof, Error error) {
        if (!error.empty() || eof) return;
        if (total + data.size() > 65536) { stream->close(); return; }
        drain(stream, total + data.size());
    });
}

struct HTTP3Auth : std::enable_shared_from_this<HTTP3Auth> {
    std::shared_ptr<Connection> connection; std::shared_ptr<Stream> stream;
    std::shared_ptr<Reader> reader; std::function<void(bool, Error)> completion;
    size_t frames = 0; bool finished = false;
    void finish(bool udp, Error error) {
        if (finished) return; finished = true;
        if (error.empty() && connection->isClosed()) error = "QUIC connection cancelled";
        auto callback = std::move(completion);
        if (!error.empty()) connection->close();
        callback(udp, error);
    }
    bool abort() {
        if (finished) return true;
        if (connection->isClosed()) { finish(false, "QUIC connection cancelled"); return true; }
        return false;
    }
    void response() {
        if (abort()) return;
        auto self = shared_from_this();
        if (++frames > 8) { finish(false, "Too many HTTP/3 authentication frames"); return; }
        readVarint(reader, [self](uint64_t type, Error error) {
            if (self->abort()) return;
            if (!error.empty()) { self->finish(false, error); return; }
            readVarint(self->reader, [self, type](uint64_t length, Error error) {
                if (self->abort()) return;
                if (!error.empty() || length > 65536 || type == 0) {
                    self->finish(false, error.empty() ? "Invalid HTTP/3 authentication response" : error); return;
                }
                self->reader->exactly(static_cast<size_t>(length), [self, type](Buffer block, Error error) {
                    if (self->abort()) return;
                    if (!error.empty()) { self->finish(false, error); return; }
                    if (type != 1) { self->response(); return; }
                    try {
                        auto fields = unpack(block); std::string status, udp;
                        for (auto &field : fields) {
                            if (field.first == ":status") {
                                if (!status.empty()) throw std::runtime_error("Duplicate HTTP/3 status");
                                status = field.second;
                            } else if (field.first == "hysteria-udp") udp = field.second;
                        }
                        if (status.size() == 3 && status[0] == '1') { self->response(); return; }
                        self->finish(udp == "true" || udp == "1", status == "233" ? Error{} : "Hysteria2 authentication rejected");
                    } catch (const std::exception &e) { self->finish(false, e.what()); }
                });
            });
        });
    }
};

using AuthCallback = std::function<void(std::shared_ptr<Connection>, bool, Error)>;
struct Authentication : std::enable_shared_from_this<Authentication> {
    Node node; std::shared_ptr<Connection> connection; AuthCallback completion;
    bool done = false;
    void finish(bool udp, Error error) {
        if (done) return;
        if (error.empty() && connection->isClosed()) error = "QUIC connection cancelled";
        done = true; auto callback = std::move(completion);
        if (!error.empty()) connection->close();
        callback(error.empty() ? connection : nullptr, udp, error);
    }
    bool abort() {
        if (done) return true;
        if (connection->isClosed()) { finish(false, "QUIC connection cancelled"); return true; }
        return false;
    }
    void hysteria1() {
        if (abort()) return;
        auto self = shared_from_this(); connection->open(false, [self](std::shared_ptr<Stream> stream, Error error) {
            if (self->abort()) return;
            if (!error.empty()) { self->finish(false, error); return; }
            auto secret = auth(self->node);
            try {
                auto hello = encoded([&](uint8_t *out, size_t size) {
                    return hajimi_hysteria1_encode_hello(upload(self->node), download(self->node),
                        reinterpret_cast<const uint8_t *>(secret.data()), secret.size(), out, size);
                });
                stream->write(std::move(hello), [self, stream](Error error) {
                    if (self->abort()) return;
                    if (!error.empty()) { self->finish(false, error); return; }
                    auto reader = std::make_shared<Reader>(stream);
                    reader->exactly(19, [self, reader](Buffer response, Error error) {
                        if (self->abort()) return;
                        if (!error.empty()) { self->finish(false, error); return; }
                        auto length = be16(response.data() + 17); bool accepted = response[0] != 0;
                        reader->exactly(length, [self, reader, accepted](Buffer, Error error) {
                            if (self->abort()) return;
                            self->finish(accepted, !error.empty() ? error : accepted ? Error{} : "Hysteria authentication rejected");
                        });
                    });
                });
            } catch (const std::exception &e) { self->finish(false, e.what()); }
        });
    }
    void hysteria2(unsigned index = 0) {
        if (abort()) return;
        auto self = shared_from_this();
        if (index < 3) {
            connection->open(true, [self, index](std::shared_ptr<Stream> stream, Error error) {
                if (self->abort()) return;
                if (!error.empty()) { self->finish(false, error); return; }
                Buffer bytes{static_cast<uint8_t>(index == 0 ? 0 : index + 1)};
                if (index == 0) {
                    Buffer settings{1, 0, 7, 0, 6}; append(settings, varint(65536));
                    bytes.push_back(4); append(bytes, varint(settings.size())); append(bytes, settings);
                }
                stream->write(std::move(bytes), [self, index](Error error) {
                    if (self->abort()) return;
                    if (!error.empty()) self->finish(false, error); else self->hysteria2(index + 1);
                });
            });
            return;
        }
        connection->receivePeerStreams([](std::shared_ptr<Stream> stream) { drain(stream); });
        connection->open(false, [self](std::shared_ptr<Stream> stream, Error error) {
            if (self->abort()) return;
            if (!error.empty()) { self->finish(false, error); return; }
            try {
                auto padding = crypto::base64Encode(crypto::randomBytes(192));
                Buffer header = qpack({{":method", "POST"}, {":scheme", "https"},
                    {":authority", "hysteria"}, {":path", "/auth"},
                    {"hysteria-auth", auth(self->node)}, {"hysteria-cc-rx", std::to_string(download(self->node))},
                    {"hysteria-padding", padding}, {"content-length", "0"}});
                Buffer request{1}; append(request, varint(header.size())); append(request, header);
                auto response = std::make_shared<HTTP3Auth>(); response->connection = self->connection;
                response->stream = stream; response->reader = std::make_shared<Reader>(stream, 65536);
                response->completion = [self](bool udp, Error error) { self->finish(udp, error); };
                stream->write(std::move(request), [self, stream, response](Error error) {
                    if (self->abort()) return;
                    if (!error.empty()) { self->finish(false, error); return; }
                    stream->shutdownWrite([response](Error error) {
                        if (response->abort()) return;
                        if (!error.empty()) response->finish(false, error); else response->response();
                    });
                });
            } catch (const std::exception &e) { self->finish(false, e.what()); }
        });
    }
    void tuic() {
        if (abort()) return;
        auto self = shared_from_this(); auto credential = credentials(node);
        Buffer password(credential.second.begin(), credential.second.end());
        connection->exportKey(credential.first, password, [self, uuid = credential.first](Buffer token, Error error) {
            if (self->abort()) return;
            if (!error.empty()) { self->finish(false, error); return; }
            self->connection->open(true, [self, uuid, token](std::shared_ptr<Stream> stream, Error error) {
                if (self->abort()) return;
                if (!error.empty()) { self->finish(false, error); return; }
                try {
                    auto command = encoded([&](uint8_t *out, size_t size) {
                        return hajimi_tuic5_encode_authenticate(uuid.data(), token.data(), out, size);
                    });
                    stream->write(std::move(command), [self, stream](Error error) {
                        if (self->abort()) return;
                        if (!error.empty()) { self->finish(false, error); return; }
                        stream->shutdownWrite([self](Error error) { self->finish(true, error); });
                    });
                } catch (const std::exception &e) { self->finish(false, e.what()); }
            });
        });
    }
};

void authenticate(const Node &node, std::shared_ptr<TransportFactory> factory, AuthCallback callback) {
    Connection::connect(node, factory, [node, callback](std::shared_ptr<Connection> connection, Error error) {
        if (!error.empty()) { callback(nullptr, false, error); return; }
        if (!connection || connection->isClosed()) {
            if (connection) connection->close();
            callback(nullptr, false, "QUIC connection cancelled"); return;
        }
        auto authentication = std::make_shared<Authentication>(); authentication->node = node;
        authentication->connection = connection; authentication->completion = callback;
        if (node.type == "hysteria") authentication->hysteria1();
        else if (node.type == "hysteria2") authentication->hysteria2();
        else authentication->tuic();
    });
}

void hysteria1Request(std::shared_ptr<Connection> connection, Target target, bool udp,
    std::function<void(std::shared_ptr<Stream>, std::shared_ptr<Reader>, uint32_t, Error)> completion) {
    connection->open(false, [connection, target, udp, completion](std::shared_ptr<Stream> stream, Error error) {
        if (connection->isClosed()) { completion(nullptr, nullptr, 0, "QUIC connection cancelled"); return; }
        if (!error.empty()) { completion(nullptr, nullptr, 0, error); return; }
        try {
            hajimi_address destination = udp ? hajimi_address{} : address(target);
            auto request = encoded([&](uint8_t *out, size_t size) {
                return hajimi_hysteria1_encode_request(udp ? 1 : 0, udp ? nullptr : &destination, out, size);
            });
            stream->write(std::move(request), [stream, connection, completion](Error error) {
                if (connection->isClosed()) { completion(nullptr, nullptr, 0, "QUIC connection cancelled"); return; }
                if (!error.empty()) { completion(nullptr, nullptr, 0, error); return; }
                auto reader = std::make_shared<Reader>(stream);
                reader->exactly(7, [stream, reader, connection, completion](Buffer response, Error error) {
                    if (connection->isClosed()) { completion(nullptr, nullptr, 0, "QUIC connection cancelled"); return; }
                    if (!error.empty()) { completion(nullptr, nullptr, 0, error); return; }
                    bool accepted = response[0] != 0; uint32_t session = be32(response.data() + 1);
                    reader->exactly(be16(response.data() + 5), [stream, reader, connection, completion, accepted, session](Buffer, Error error) {
                        if (connection->isClosed()) { completion(nullptr, nullptr, 0, "QUIC connection cancelled"); return; }
                        if (!accepted && error.empty()) error = "Hysteria connection rejected";
                        completion(error.empty() ? stream : nullptr, error.empty() ? reader : nullptr, session, error);
                    });
                });
            });
        } catch (const std::exception &e) { completion(nullptr, nullptr, 0, e.what()); }
    });
}

void hysteria2Response(std::shared_ptr<Reader> reader, WriteCallback completion) {
    reader->exactly(1, [reader, completion](Buffer status, Error error) {
        if (!error.empty()) { completion(error); return; }
        readVarint(reader, [reader, completion, status](uint64_t length, Error error) {
            if (!error.empty() || length > 2048) { completion(error.empty() ? "Invalid Hysteria2 response length" : error); return; }
            reader->exactly(static_cast<size_t>(length), [reader, completion, status](Buffer, Error error) {
                if (!error.empty()) { completion(error); return; }
                readVarint(reader, [reader, completion, status](uint64_t length, Error error) {
                    if (!error.empty() || length > 4096) { completion(error.empty() ? "Invalid Hysteria2 response padding" : error); return; }
                    reader->exactly(static_cast<size_t>(length), [completion, status](Buffer, Error error) {
                        completion(!error.empty() ? error : status[0] == 0 ? Error{} : "Hysteria2 connection rejected");
                    });
                });
            });
        });
    });
}

void heartbeat(std::weak_ptr<Connection> connection, std::shared_ptr<TransportFactory> factory, double interval) {
    if (!factory->after) return;
    factory->after(interval, [connection, factory, interval] {
        auto current = connection.lock(); if (!current || current->isClosed()) return;
        if (current->datagramLimit() >= 2) current->sendDatagrams({Buffer{5, 4}}, [](Error) {});
        heartbeat(connection, factory, interval);
    });
}
double heartbeatInterval(const Node &node) {
    auto value = node.option("heartbeat-interval", "10"); char *end = nullptr;
    double interval = std::strtod(value.c_str(), &end);
    return std::isfinite(interval) && interval > 0 && *end == 0 ? std::max(3.0, interval) : 10;
}
} // namespace

void connectQUICProtocol(const Node &node, const Target &target,
                         std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    auto validation = validateQUICProtocol(node, false);
    if (!validation.empty()) { completion(nullptr, validation); return; }
    authenticate(node, factory, [node, target, factory, completion](std::shared_ptr<Connection> connection, bool, Error error) {
        if (!error.empty()) { completion(nullptr, error); return; }
        if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
        if (node.type == "tuic") heartbeat(connection, factory, heartbeatInterval(node));
        if (node.type == "hysteria") {
            hysteria1Request(connection, target, false, [connection, completion](std::shared_ptr<Stream> stream,
                std::shared_ptr<Reader> reader, uint32_t, Error error) {
                if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
                if (!error.empty()) { connection->close(); completion(nullptr, error); return; }
                connection->authenticated();
                completion(std::make_shared<quic::OwnedStream>(connection, stream, reader), {});
            });
            return;
        }
        connection->open(false, [node, target, connection, completion](std::shared_ptr<Stream> stream, Error error) {
            if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
            if (!error.empty()) { connection->close(); completion(nullptr, error); return; }
            try {
                auto destination = address(target); Buffer request;
                if (node.type == "tuic") request = encoded([&](uint8_t *out, size_t size) {
                    return hajimi_tuic5_encode_connect(&destination, out, size);
                });
                else {
                    auto padding = crypto::randomBytes(64);
                    request = encoded([&](uint8_t *out, size_t size) {
                        return hajimi_hysteria2_encode_request(&destination, padding.data(), padding.size(), out, size);
                    });
                }
                stream->write(std::move(request), [node, stream, connection, completion](Error error) {
                    if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
                    if (!error.empty()) { connection->close(); completion(nullptr, error); return; }
                    if (node.type == "tuic") {
                        connection->authenticated(); completion(std::make_shared<quic::OwnedStream>(connection, stream), {}); return;
                    }
                    auto reader = std::make_shared<Reader>(stream);
                    hysteria2Response(reader, [reader, stream, connection, completion](Error error) {
                        if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
                        if (!error.empty()) { connection->close(); completion(nullptr, error); return; }
                        connection->authenticated(); completion(std::make_shared<quic::OwnedStream>(connection, stream, reader), {});
                    });
                });
            } catch (const std::exception &e) { connection->close(); completion(nullptr, e.what()); }
        });
    });
}

namespace {
class QUICDatagram final : public Datagram, public std::enable_shared_from_this<QUICDatagram> {
    struct Fragments {
        std::vector<Buffer> parts; std::vector<bool> seen; Target target;
        size_t bytes = 0, received = 0; uint64_t expiry = 0; bool hasTarget = false;
    };
    Node node_; std::shared_ptr<Connection> connection_; std::shared_ptr<Stream> hold_;
    uint32_t session_; uint16_t packet_ = 0;
    std::unordered_map<uint16_t, Fragments> fragments_;
    std::deque<std::pair<uint16_t, uint64_t>> completed_;
    std::unordered_set<uint16_t> completedIDs_;
    size_t fragmentBytes_ = 0, queuedBytes_ = 0;
    std::deque<std::pair<Target, Buffer>> queued_;
    PacketCallback receive_; WriteCallback failure_; Error terminal_; bool closed_ = false;
public:
    QUICDatagram(Node node, std::shared_ptr<Connection> connection, uint32_t session,
                 std::shared_ptr<Stream> hold = {})
        : node_(std::move(node)), connection_(std::move(connection)), hold_(std::move(hold)), session_(session) {
        auto random = crypto::randomBytes(2); packet_ = be16(random.data());
    }
    ~QUICDatagram() override { close(); }
    void initialize() {
        auto weak = weak_from_this();
        connection_->receiveDatagrams([weak](Buffer bytes) { if (auto self = weak.lock()) self->feed(std::move(bytes)); },
            [weak](Error error) { if (auto self = weak.lock()) self->fail(error); });
        if (node_.type == "tuic") connection_->receivePeerStreams([weak](std::shared_ptr<Stream> stream) {
            if (auto self = weak.lock()) self->readPeer(stream, {}); else stream->close();
        });
        if (hold_) monitorHold();
    }
    void start(PacketCallback receive, WriteCallback failure) override {
        if (closed_ || !connection_ || connection_->isClosed()) { failure("QUIC connection cancelled"); return; }
        if (receive_) { failure("QUIC UDP receiver already started"); return; }
        receive_ = std::move(receive); failure_ = std::move(failure);
        if (!terminal_.empty()) { failure_(terminal_); return; }
        while (!queued_.empty() && !closed_) {
            auto packet = std::move(queued_.front()); queued_.pop_front(); queuedBytes_ -= packet.second.size();
            receive_(std::move(packet.first), std::move(packet.second));
        }
    }
    void send(Target, Buffer, WriteCallback) override;
    void close() override {
        if (closed_) return; closed_ = true;
        if (hold_) { hold_->close(); hold_.reset(); }
        if (connection_) { connection_->close(); connection_.reset(); }
        fragments_.clear(); completed_.clear(); completedIDs_.clear();
        queued_.clear(); fragmentBytes_ = queuedBytes_ = 0;
        receive_ = {}; failure_ = {};
    }
private:
    void fail(Error error) {
        if (closed_ || !terminal_.empty()) return; terminal_ = std::move(error);
        if (failure_) failure_(terminal_);
    }
    void monitorHold() {
        auto weak = weak_from_this(); hold_->read(1024, [weak](Buffer, bool eof, Error error) {
            auto self = weak.lock(); if (!self || self->closed_) return;
            if (eof || !error.empty()) self->fail(error.empty() ? "Hysteria UDP association closed" : error);
            else self->monitorHold();
        });
    }
    void readPeer(std::shared_ptr<Stream> stream, Buffer buffer) {
        auto weak = weak_from_this(); stream->read(65535, [weak, stream, buffer = std::move(buffer)](Buffer bytes, bool eof, Error error) mutable {
            auto self = weak.lock();
            if (!self || self->closed_ || !self->connection_ || self->connection_->isClosed()) { stream->close(); return; }
            if (!error.empty()) return;
            if (bytes.size() > 65535 - buffer.size()) { stream->close(); return; }
            append(buffer, bytes);
            if (eof) self->feed(std::move(buffer)); else self->readPeer(stream, std::move(buffer));
        });
    }
    void feed(Buffer);
    void deliver(Target target, Buffer value) {
        if (closed_ || !terminal_.empty() || !connection_ || connection_->isClosed()) return;
        if (receive_) receive_(std::move(target), std::move(value));
        else if (queued_.size() < 128 && value.size() <= maximumQueuedBytes - queuedBytes_) {
            queuedBytes_ += value.size(); queued_.push_back({std::move(target), std::move(value)});
        }
    }
};

void QUICDatagram::send(Target target, Buffer data, WriteCallback completion) {
    if (closed_ || !terminal_.empty() || !connection_ || connection_->isClosed() || data.size() > 65535) {
        completion(terminal_.empty() ? "QUIC UDP session is closed or packet is too large" : terminal_); return;
    }
    try {
        auto destination = address(target); bool streamRelay = node_.type == "tuic" && node_.option("udp-relay-mode", "native") == "quic";
        size_t limit = streamRelay ? 65535 : connection_->datagramLimit();
        if (limit < 32) { completion("QUIC peer did not negotiate DATAGRAM support"); return; }
        ++packet_; if (!packet_) ++packet_;
        auto frame = [&](size_t offset, size_t size, uint8_t index, uint8_t count) {
            return encoded([&](uint8_t *out, size_t capacity) {
                const uint8_t *payload = size ? data.data() + offset : nullptr;
                if (node_.type == "hysteria") return hajimi_hysteria1_encode_udp(session_, packet_, index, count,
                    &destination, payload, size, out, capacity);
                if (node_.type == "hysteria2") return hajimi_hysteria2_encode_udp(session_, packet_, index, count,
                    &destination, payload, size, out, capacity);
                return hajimi_tuic5_encode_udp(static_cast<uint16_t>(session_), packet_, index, count,
                    index == 0 ? &destination : nullptr, payload, size, out, capacity);
            });
        };
        size_t firstHeader = frame(0, 0, 0, 1).size();
        size_t laterHeader = node_.type == "tuic" ? frame(0, 0, 1, 2).size() : firstHeader;
        if (firstHeader >= limit || laterHeader >= limit) { completion("QUIC UDP address exceeds datagram maximum"); return; }
        size_t firstCapacity = limit - firstHeader, laterCapacity = limit - laterHeader;
        size_t count = data.size() <= firstCapacity ? 1 : 1 + (data.size() - firstCapacity + laterCapacity - 1) / laterCapacity;
        if (count > 255) { completion("QUIC UDP packet requires too many fragments"); return; }
        std::vector<Buffer> packets; size_t offset = 0;
        for (size_t index = 0; index < count; ++index) {
            size_t size = std::min(index == 0 ? firstCapacity : laterCapacity, data.size() - offset);
            packets.push_back(frame(offset, size, static_cast<uint8_t>(index), static_cast<uint8_t>(count))); offset += size;
        }
        auto connection = connection_;
        if (!streamRelay) {
            connection->sendDatagrams(std::move(packets), [connection, completion](Error error) {
                if (error.empty() && connection->isClosed()) error = "QUIC connection cancelled";
                completion(error);
            });
            return;
        }
        auto remaining = std::make_shared<size_t>(packets.size()); auto failed = std::make_shared<bool>(false);
        auto finish = [remaining, failed, connection, completion](Error error) {
            if (error.empty() && connection->isClosed()) error = "QUIC connection cancelled";
            if (!error.empty() && !*failed) { *failed = true; completion(error); }
            if (--*remaining == 0 && !*failed) completion({});
        };
        for (auto &packet : packets) connection->open(true, [packet = std::move(packet), connection, finish](std::shared_ptr<Stream> stream, Error error) mutable {
            if (connection->isClosed()) { finish("QUIC connection cancelled"); return; }
            if (!error.empty()) { finish(error); return; }
            stream->write(std::move(packet), [stream, connection, finish](Error error) {
                if (connection->isClosed()) { finish("QUIC connection cancelled"); return; }
                if (!error.empty()) finish(error); else stream->shutdownWrite(finish);
            });
        });
    } catch (const std::exception &e) { completion(e.what()); }
}

void QUICDatagram::feed(Buffer bytes) {
    if (closed_ || !terminal_.empty() || !connection_ || connection_->isClosed()) return;
    hajimi_udp_frame frame{}; hajimi_codec_result result;
    if (node_.type == "hysteria") result = hajimi_hysteria1_parse_udp(bytes.data(), bytes.size(), &frame);
    else if (node_.type == "hysteria2") result = hajimi_hysteria2_parse_udp(bytes.data(), bytes.size(), &frame);
    else result = hajimi_tuic5_parse_udp(bytes.data(), bytes.size(), &frame);
    if (result.status != HAJIMI_CODEC_OK || frame.session_id != session_) return;
    Target target{std::string(reinterpret_cast<char *>(frame.target.host), frame.target.host_length), frame.target.port, true};
    Buffer payload(bytes.begin() + frame.payload_offset, bytes.begin() + frame.payload_offset + frame.payload_length);
    if (frame.fragment_count == 1) { if (frame.has_address) deliver(std::move(target), std::move(payload)); return; }
    uint64_t seconds = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    while (!completed_.empty() && (completed_.front().second <= seconds || completed_.size() >= 256)) {
        completedIDs_.erase(completed_.front().first); completed_.pop_front();
    }
    if (completedIDs_.count(frame.packet_id)) return;
    for (auto iterator = fragments_.begin(); iterator != fragments_.end();) {
        if (iterator->second.expiry <= seconds) { fragmentBytes_ -= iterator->second.bytes; iterator = fragments_.erase(iterator); }
        else ++iterator;
    }
    auto found = fragments_.find(frame.packet_id);
    if (found == fragments_.end()) {
        if (fragments_.size() >= 64 || payload.size() > maximumQueuedBytes - fragmentBytes_) return;
        Fragments value; value.parts.resize(frame.fragment_count); value.seen.resize(frame.fragment_count);
        value.expiry = seconds + 10; found = fragments_.emplace(frame.packet_id, std::move(value)).first;
    }
    auto &value = found->second;
    bool bad = value.parts.size() != frame.fragment_count ||
        (frame.has_address && value.hasTarget && (target.host != value.target.host || target.port != value.target.port));
    if (bad) { fragmentBytes_ -= value.bytes; fragments_.erase(found); return; }
    if (frame.has_address) { value.target = target; value.hasTarget = true; }
    if (!value.seen[frame.fragment_index]) {
        if (payload.size() > 65535 - value.bytes || payload.size() > maximumQueuedBytes - fragmentBytes_) return;
        value.seen[frame.fragment_index] = true; value.bytes += payload.size(); fragmentBytes_ += payload.size();
        value.parts[frame.fragment_index] = std::move(payload); ++value.received;
    }
    if (value.received != value.parts.size() || !value.hasTarget) return;
    Buffer packet; packet.reserve(value.bytes); target = value.target;
    for (auto &part : value.parts) append(packet, part);
    fragmentBytes_ -= value.bytes; fragments_.erase(found);
    completed_.push_back({frame.packet_id, static_cast<uint64_t>(seconds) + 10}); completedIDs_.insert(frame.packet_id);
    deliver(std::move(target), std::move(packet));
}
} // namespace

void makeQUICDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    auto validation = validateQUICProtocol(node, true);
    if (!validation.empty()) { completion(nullptr, validation); return; }
    authenticate(node, factory, [node, factory, completion](std::shared_ptr<Connection> connection, bool udp, Error error) {
        if (!error.empty()) { completion(nullptr, error); return; }
        if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
        bool streamRelay = node.type == "tuic" && node.option("udp-relay-mode", "native") == "quic";
        if (!udp || (!streamRelay && !connection->datagramLimit())) {
            connection->close(); completion(nullptr, "QUIC server disabled UDP/DATAGRAM relay"); return;
        }
        auto finish = [node, connection, factory, completion](std::shared_ptr<Stream> hold, uint32_t session, Error error) {
            if (connection->isClosed()) { connection->close(); completion(nullptr, "QUIC connection cancelled"); return; }
            if (!error.empty()) { connection->close(); completion(nullptr, error); return; }
            try {
                auto result = std::make_shared<QUICDatagram>(node, connection, session, hold);
                result->initialize(); connection->authenticated();
                if (connection->isClosed()) { result->close(); completion(nullptr, "QUIC connection cancelled"); return; }
                if (node.type == "tuic") heartbeat(connection, factory, heartbeatInterval(node));
                completion(result, {});
            } catch (const std::exception &e) { connection->close(); completion(nullptr, e.what()); }
        };
        if (node.type == "hysteria") {
            hysteria1Request(connection, {}, true, [finish](std::shared_ptr<Stream> stream, std::shared_ptr<Reader>, uint32_t session, Error error) {
                finish(stream, session, error);
            });
        } else {
            auto random = crypto::randomBytes(node.type == "tuic" ? 2 : 4);
            uint32_t session = node.type == "tuic" ? be16(random.data()) : be32(random.data());
            finish(nullptr, session ? session : 1, {});
        }
    });
}

Error validateQUICProtocol(const Node &node, bool) {
    if (node.type != "hysteria" && node.type != "hysteria2" && node.type != "tuic") return "Unknown C++ QUIC protocol";
    if (node.host.empty() || !node.port) return "QUIC node requires server and port";
    auto network = node.option("network");
    std::transform(network.begin(), network.end(), network.begin(), [](unsigned char ch) { return char(std::tolower(ch)); });
    if (!network.empty() && network != "udp" && network != "quic")
        return "QUIC protocols require native UDP/QUIC transport (not TCP/WebSocket/HTTP/gRPC)";
    for (const auto *key : {"ws-path", "ws-headers", "ws-opts", "grpc-service-name", "grpc-opts", "http-opts",
                            "http-path", "http-headers", "h2-opts"})
        if (!node.option(key).empty()) return std::string("QUIC does not use carrier option ") + key;
    if (node.flag("ws")) return "QUIC protocols cannot use a WebSocket carrier";
    for (const auto *key : {"ports", "underlying-proxy", "dialer-proxy", "ech-opts", "ech-config",
                            "client-fingerprint", "certificate", "private-key", "ca-str", "bbr-profile"})
        if (!node.option(key).empty()) return std::string("C++ QUIC does not support option ") + key;
    for (const auto *key : {"fast-open", "reduce-rtt", "zero-rtt-handshake"})
        if (node.flag(key)) return std::string("C++ QUIC does not enable ") + key;
    if (!node.option("fingerprint").empty()) return "C++ QUIC certificate fingerprint pinning is not implemented";
    auto congestion = node.option("congestion-controller", node.option("congestion", "bbr"));
    if (congestion != "bbr" && congestion != "cubic" && congestion != "reno")
        return "C++ QUIC congestion-controller must be bbr, cubic or reno";
    auto tls = tlsOptions(node, true);
    if (!tls.enabled) return "QUIC requires TLS 1.3";
    if (node.flag("skip-common-name-verify") && !node.flag("skip-cert-verify"))
        return "Use skip-cert-verify explicitly; partial QUIC certificate bypass is not supported";
    if (tls.serverName.size() > 253 || tls.serverName.find('\0') != std::string::npos)
        return "Invalid QUIC TLS server name";
    if (tls.alpn.size() > 16) return "Too many QUIC ALPN values";
    for (auto &value : tls.alpn)
        if (value.empty() || value.size() > 255 || value.find('\0') != std::string::npos) return "Invalid QUIC ALPN";
    if (node.type == "hysteria2" && !tls.alpn.empty() &&
        std::find(tls.alpn.begin(), tls.alpn.end(), "h3") == tls.alpn.end()) return "Hysteria2 requires h3 ALPN";
    if (node.type == "tuic") {
        auto value = credentials(node);
        if (value.first.size() != 16 || value.second.empty()) return "TUIC v5 requires valid uuid and password";
        if (!node.option("version").empty() && node.option("version") != "5") return "Only TUIC version 5 is supported";
        auto mode = node.option("udp-relay-mode", "native");
        if (mode != "native" && mode != "quic") return "TUIC udp-relay-mode must be native or quic";
        if (!node.option("obfs").empty() || !node.option("obfs-password").empty()) return "TUIC does not use Hysteria obfuscation";
        auto interval = node.option("heartbeat-interval", "10"); char *end = nullptr;
        auto seconds = std::strtod(interval.c_str(), &end);
        if (!std::isfinite(seconds) || seconds <= 0 || seconds > 600 || *end)
            return "Invalid TUIC heartbeat-interval (seconds, 0 < value <= 600)";
    } else {
        auto secret = auth(node);
        if (secret.empty() || secret.size() > (node.type == "hysteria" ? 65535 : 8192))
            return "Hysteria requires a bounded nonempty auth/password";
        if (node.type == "hysteria") {
            if (!upload(node) || !download(node)) return "Hysteria v1 requires valid up/down bandwidth";
            if (node.option("obfs-protocol", "udp") != "udp") return "Hysteria v1 supports UDP QUIC with optional XPlus only";
            if (!node.option("obfs-password").empty()) return "Hysteria v1 uses obfs as XPlus password";
        } else {
            if (secret.find_first_of("\r\n") != std::string::npos) return "Invalid Hysteria2 authentication header";
            auto obfs = node.option("obfs"), password = node.option("obfs-password");
            if (!obfs.empty() && obfs != "salamander") return "Hysteria2 supports salamander obfuscation only";
            if (obfs == "salamander" && password.size() < 4) return "Hysteria2 salamander requires obfs-password of at least 4 bytes";
            if (obfs.empty() && !password.empty()) return "Set obfs=salamander when using obfs-password";
        }
    }
    return {};
}
} // namespace hajimi
