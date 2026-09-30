#include "ServerProtocols.hpp"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace hajimi {
Buffer socksReply(uint8_t reply, const Target &bound) {
    if (reply > 8) throw std::invalid_argument("Invalid SOCKS5 reply code");
    Target value = bound;
    if (value.host.empty()) value.host = "0.0.0.0";
    hajimi_address address{};
    auto result = hajimi_address_from_host(reinterpret_cast<const uint8_t *>(value.host.data()),
                                          value.host.size(), value.port, &address);
    if (result.status != HAJIMI_CODEC_OK) throw std::invalid_argument("Invalid SOCKS5 bound address");
    result = hajimi_socks5_encode_address(&address, nullptr, 0);
    if (result.status != HAJIMI_CODEC_OUTPUT_TOO_SMALL) throw std::invalid_argument("Invalid SOCKS5 bound address");
    Buffer output(3 + result.needed); output[0] = 5; output[1] = reply; output[2] = 0;
    result = hajimi_socks5_encode_address(&address, output.data() + 3, output.size() - 3);
    if (result.status != HAJIMI_CODEC_OK) throw std::invalid_argument("SOCKS5 reply encoding failed");
    return output;
}

namespace {
class SocksServer final : public std::enable_shared_from_this<SocksServer> {
    std::shared_ptr<Stream> source_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Reader> reader_;
    SocksAcceptCallback completion_;
    bool done_ = false, rejecting_ = false;
    Buffer request_;
public:
    SocksServer(std::shared_ptr<Stream> source, std::shared_ptr<TransportFactory> factory,
                SocksAcceptCallback completion)
        : source_(std::move(source)), factory_(std::move(factory)),
          reader_(std::make_shared<Reader>(source_, 65536)), completion_(std::move(completion)) {}
    void start() {
        auto weak = weak_from_this();
        factory_->after(20, [weak] {
            if (auto self = weak.lock()) self->finish({}, 0, {}, "SOCKS5 handshake timed out");
        });
        greeting();
    }
private:
    void finish(Target target, uint8_t command, Buffer initial, Error error) {
        if (done_) return; done_ = true;
        auto completion = std::exchange(completion_, {});
        if (!error.empty()) reader_->close();
        completion(std::move(target), command, std::move(initial), std::move(error));
    }
    void reject(Buffer response, Error error) {
        if (done_ || rejecting_) return; rejecting_ = true;
        auto self = shared_from_this();
        source_->write(std::move(response), [self, error](Error writeError) {
            self->finish({}, 0, {}, writeError.empty() ? error : "SOCKS5 rejection reply could not be sent");
        });
    }
    void requestFailure(uint8_t reply, Error error) { reject(socksReply(reply, {}), std::move(error)); }
    void greeting() {
        auto self = shared_from_this();
        reader_->exactly(2, [self](Buffer header, Error error) {
            if (self->done_) return;
            if (!error.empty()) { self->finish({}, 0, {}, error); return; }
            if (header[0] != 5 || header[1] == 0) {
                self->reject({5, 255}, "Invalid SOCKS5 greeting"); return;
            }
            self->reader_->exactly(header[1], [self](Buffer methods, Error error) {
                if (self->done_) return;
                if (!error.empty()) { self->finish({}, 0, {}, error); return; }
                if (std::find(methods.begin(), methods.end(), 0) == methods.end()) {
                    self->reject({5, 255}, "SOCKS5 no supported authentication method"); return;
                }
                self->source_->write({5, 0}, [self](Error error) {
                    if (self->done_) return;
                    if (!error.empty()) { self->finish({}, 0, {}, "SOCKS5 method reply failed"); return; }
                    self->requestHeader();
                });
            });
        });
    }
    void requestHeader() {
        auto self = shared_from_this();
        reader_->exactly(4, [self](Buffer header, Error error) {
            if (self->done_) return;
            if (!error.empty()) { self->finish({}, 0, {}, error); return; }
            if (header[0] != 5 || header[2] != 0) { self->requestFailure(1, "Invalid SOCKS5 request header"); return; }
            if (header[1] != 1 && header[1] != 3) { self->requestFailure(7, "SOCKS5 command not supported"); return; }
            self->request_ = std::move(header);
            if (self->request_[3] == 1) self->addressBody(6);
            else if (self->request_[3] == 4) self->addressBody(18);
            else if (self->request_[3] == 3) self->domainLength();
            else self->requestFailure(8, "SOCKS5 address type not supported");
        });
    }
    void domainLength() {
        auto self = shared_from_this();
        reader_->exactly(1, [self](Buffer length, Error error) {
            if (self->done_) return;
            if (!error.empty()) { self->finish({}, 0, {}, error); return; }
            if (!length[0]) { self->requestFailure(8, "SOCKS5 empty domain"); return; }
            self->request_.push_back(length[0]); self->addressBody(static_cast<size_t>(length[0]) + 2);
        });
    }
    void addressBody(size_t count) {
        auto self = shared_from_this();
        reader_->exactly(count, [self](Buffer body, Error error) {
            if (self->done_) return;
            if (!error.empty()) { self->finish({}, 0, {}, error); return; }
            self->request_.insert(self->request_.end(), body.begin(), body.end());
            hajimi_address address{}; uint8_t command = 0;
            auto result = hajimi_socks5_parse_request(self->request_.data(), self->request_.size(), &command, &address);
            if (result.status != HAJIMI_CODEC_OK || result.consumed != self->request_.size()) {
                self->requestFailure(8, "Invalid SOCKS5 target address"); return;
            }
            if (command == 1 && address.port == 0) { self->requestFailure(1, "SOCKS5 CONNECT requires a nonzero port"); return; }
            Target target{std::string(reinterpret_cast<const char *>(address.host), address.host_length), address.port, command == 3};
            self->finish(std::move(target), command, self->reader_->take(), {});
        });
    }
};
} // namespace

void acceptSOCKS5(std::shared_ptr<Stream> source, std::shared_ptr<TransportFactory> factory,
                  SocksAcceptCallback completion) {
    if (!source || !factory || !factory->post || !factory->after || !completion) {
        if (source) source->close();
        if (completion) completion({}, 0, {}, "Missing SOCKS5 stream/queue/timer callback");
        return;
    }
    auto server = std::make_shared<SocksServer>(std::move(source), factory, std::move(completion));
    factory->post([server] { server->start(); });
}
} // namespace hajimi
