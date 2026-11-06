#include "Socks5Protocol.hpp"
#include "BasicProtocols.hpp"
#include <stdexcept>
#include <utility>

namespace hajimi {

void readSocksAddressFromReader(
    std::shared_ptr<Reader> reader,
    uint8_t type,
    std::function<void(Buffer, Error)> completion) {
    if (type == 1 || type == 4) {
        reader->exactly(type == 1 ? 6 : 18, [type, completion = std::move(completion)](Buffer tail, Error error) mutable {
            if (!error.empty()) { completion({}, error); return; }
            tail.insert(tail.begin(), type);
            completion(std::move(tail), {});
        });
    } else if (type == 3) {
        reader->exactly(1, [reader, completion = std::move(completion)](Buffer length, Error error) mutable {
            if (!error.empty() || !length[0]) {
                completion({}, error.empty() ? "Invalid domain address" : error);
                return;
            }
            uint8_t count = length[0];
            reader->exactly(size_t(count) + 2, [count, completion = std::move(completion)](Buffer tail, Error error) mutable {
                if (!error.empty()) { completion({}, error); return; }
                tail.insert(tail.begin(), {3, count});
                completion(std::move(tail), {});
            });
        });
    } else {
        completion({}, "Unsupported SOCKS address type");
    }
}

namespace {

class SocksHandshake : public std::enable_shared_from_this<SocksHandshake> {
    Node node_;
    Target target_;
    std::shared_ptr<Stream> source_;
    std::shared_ptr<Reader> reader_;
    StreamCallback completion_;
    uint8_t command_ = 1;
    std::function<void(Target)> bound_;
    std::shared_ptr<TransportFactory> factory_;

    void fail(Error error) {
        source_->close();
        auto callback = std::exchange(completion_, {});
        if (callback) callback(nullptr, std::move(error));
    }

    void request() {
        auto address = socksAddress(target_);
        Buffer data;
        data.reserve(3 + address.size());
        data.push_back(5);
        data.push_back(command_);
        data.push_back(0);
        data.insert(data.end(), address.begin(), address.end());
        auto self = shared_from_this();
        source_->write(std::move(data), [self](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(4, [self](Buffer header, Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (header[0] != 5 || header[1] != 0 || header[2] != 0) {
                    self->fail("SOCKS5 CONNECT rejected");
                    return;
                }
                readSocksAddressFromReader(self->reader_, header[3], [self](Buffer address, Error error) {
                    if (!error.empty()) { self->fail(error); return; }
                    try {
                        size_t consumed = 0;
                        auto target = parseSocksAddress(address, consumed);
                        if (self->bound_) self->bound_(target);
                    } catch (const std::exception &e) {
                        self->fail(e.what());
                        return;
                    }
                    auto callback = std::exchange(self->completion_, {});
                    if (callback) callback(std::make_shared<BufferedStream>(self->source_, self->reader_), {});
                });
            });
        });
    }

    void authenticate() {
        auto username = node_.option("username"), password = node_.option("password");
        Buffer req;
        req.reserve(3 + username.size() + password.size());
        req.push_back(1);
        req.push_back(uint8_t(username.size()));
        req.insert(req.end(), username.begin(), username.end());
        req.push_back(uint8_t(password.size()));
        req.insert(req.end(), password.begin(), password.end());
        auto self = shared_from_this();
        source_->write(std::move(req), [self](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(2, [self](Buffer response, Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (response[0] != 1 || response[1] != 0) {
                    self->fail("SOCKS5 authentication rejected");
                    return;
                }
                self->request();
            });
        });
    }

public:
    SocksHandshake(
        Node node,
        Target target,
        std::shared_ptr<Stream> stream,
        StreamCallback completion,
        uint8_t command = 1,
        std::function<void(Target)> bound = {},
        std::shared_ptr<TransportFactory> factory = nullptr)
        : node_(std::move(node)),
          target_(std::move(target)),
          source_(std::move(stream)),
          reader_(std::make_shared<Reader>(source_)),
          completion_(std::move(completion)),
          command_(command),
          bound_(std::move(bound)),
          factory_(std::move(factory)) {}

    void start() {
        const uint8_t method = !node_.option("username").empty() ? 2 : 0;
        auto self = shared_from_this();
        if (factory_ && factory_->after) {
            std::weak_ptr<SocksHandshake> weak = self;
            factory_->after(15, [weak] {
                if (auto s = weak.lock()) {
                    if (s->completion_) s->fail("SOCKS5 handshake timed out");
                }
            });
        }
        source_->write({5, 1, method}, [self, method](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(2, [self, method](Buffer response, Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (response[0] != 5 || response[1] != method) {
                    self->fail("SOCKS5 authentication method mismatch");
                    return;
                }
                if (method == 2) self->authenticate();
                else self->request();
            });
        });
    }
};

} // namespace

void connectSocks5Protocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion) {
    std::make_shared<SocksHandshake>(
        node, target, std::move(source), std::move(completion), 1, std::function<void(Target)>{}, std::move(factory)
    )->start();
}

void connectSocksAssociation(
    const Node &node,
    std::shared_ptr<TransportFactory> factory,
    std::function<void(std::shared_ptr<Stream>, Target, Error)> completion,
    std::function<void(std::shared_ptr<Stream>)> transportReady) {
    factory->tcp(node, tlsOptions(node, node.type == "socks5-tls"), [node, factory, completion = std::move(completion), transportReady = std::move(transportReady)](std::shared_ptr<Stream> stream, Error error) mutable {
        if (!error.empty() || !stream) {
            completion(nullptr, {}, error.empty() ? "SOCKS5 control connection failed" : error);
            return;
        }
        if (transportReady) transportReady(stream);
        auto bound = std::make_shared<Target>();
        auto handshake = std::make_shared<SocksHandshake>(
            node,
            Target{node.dialHost().find(':') != std::string::npos ? "::" : "0.0.0.0", 0, false, false},
            stream,
            [bound, completion = std::move(completion)](std::shared_ptr<Stream> s, Error err) mutable {
                completion(std::move(s), *bound, std::move(err));
            },
            3,
            [bound](Target target) { *bound = std::move(target); },
            factory);
        handshake->start();
    });
}

} // namespace hajimi
