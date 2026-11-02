// TrustTunnel Outbound Protocol (HTTP/1.1 TLS & HTTP/3 QUIC VPN Tunnel)
#include "TrustTunnelProtocol.hpp"
#include "ProtocolCommon.hpp"

namespace hajimi {
namespace {
using namespace proto_common;

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
        ensureStream(target, [self, packet = std::move(packet), completion = std::move(completion)](Error err) mutable {
            if (!err.empty()) { completion(err); return; }
            if (!self->stream_) { completion("UDP stream unavailable"); return; }
            self->stream_->write(std::move(packet), std::move(completion));
        });
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        receive_ = std::move(receive);
        failure_ = std::move(failure);
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        if (reader_) reader_->close();
        else if (stream_) stream_->close();
    }

private:
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
            for (auto &cb : callbacks) cb({});
            self->readLoop();
        });
    }

    void readLoop() {
        if (closed_ || !reader_) return;
        auto self = shared_from_this();
        reader_->exactly(1, [self](Buffer atyp, Error err) {
            if (self->closed_) return;
            if (!err.empty()) {
                if (self->failure_ && err != "EOF") self->failure_(err);
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

    auto tls = tlsOptions(node, true);
    if (tls.alpn.empty()) {
        tls.alpn.push_back(node.flag("quic", false) ? "h3" : "http/1.1");
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
            factory->after(10.0, [raw, completion]() mutable {
                raw->close();
                completion(nullptr, "TrustTunnel handshake timed out");
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
        return validateTrustTunnel(ttNode, true).empty();
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
