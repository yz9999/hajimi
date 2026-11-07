#include "BasicProtocols.hpp"
#include "HttpProxyProtocol.hpp"
#include "Socks5Protocol.hpp"
#include "VlessTrojanProtocol.hpp"
#include <cctype>
#include <deque>
#include <stdexcept>
#include <unordered_map>

namespace hajimi {

Buffer uuidBytes(const std::string &text) {
    if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-')
        throw std::runtime_error("Invalid protocol UUID");
    Buffer result;
    result.reserve(16);
    int high = -1;
    for (size_t i = 0; i < text.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        char ch = char(std::tolower(static_cast<unsigned char>(text[i])));
        int value = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
        if (value < 0) throw std::runtime_error("Invalid protocol UUID");
        if (high < 0) high = value;
        else { result.push_back(uint8_t(high * 16 + value)); high = -1; }
    }
    if (result.size() != 16) throw std::runtime_error("Invalid protocol UUID");
    return result;
}

void connectBasicProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion) {
    if (node.type == "vmess") {
        connectVMessProtocol(node, target, std::move(factory), std::move(completion));
        return;
    }
    bool tlsDefault = node.type == "https" || node.type == "socks5-tls" || node.type == "trojan";
    auto tls = tlsOptions(node, tlsDefault);
    if ((node.type == "http" || node.type == "https") && tls.enabled && tls.alpn.empty())
        tls.alpn = {"http/1.1"};
    factory->tcp(node, tls, [node, target, factory, completion = std::move(completion)](std::shared_ptr<Stream> source, Error error) mutable {
        if (!error.empty() || !source) {
            completion(nullptr, error.empty() ? "Transport did not return a stream" : error);
            return;
        }
        try {
            if (node.type == "direct") {
                completion(source, {});
            } else if (node.type == "http" || node.type == "https") {
                connectHttpProxyProtocol(node, target, source, factory, std::move(completion));
            } else if (node.type == "socks5" || node.type == "socks5-tls") {
                connectSocks5Protocol(node, target, source, factory, std::move(completion));
            } else if (node.type == "vless" || node.type == "trojan") {
                connectVlessTrojanProtocol(node, target, source, std::move(completion), factory);
            } else {
                source->close();
                completion(nullptr, "Unsupported C++ protocol");
            }
        } catch (const std::exception &e) {
            source->close();
            if (completion) completion(nullptr, e.what());
        }
    });
}

namespace {

class StreamDatagrams final : public Datagram, public std::enable_shared_from_this<StreamDatagrams> {
    struct Pending { Buffer data; WriteCallback completion; uint8_t retries = 0; };
    struct Flow {
        Target target;
        std::shared_ptr<Stream> stream;
        std::deque<Pending> pending;
        bool connecting = false, sending = false, established = false;
        uint64_t activity = 0;
    };
    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::unordered_map<std::string, std::shared_ptr<Flow>> flows_;
    PacketCallback receive_;
    WriteCallback failure_;
    size_t queued_ = 0, requests_ = 0;
    bool closed_ = false, started_ = false;

    void failFlow(const std::string &key, std::shared_ptr<Flow> flow, Error error) {
        auto found = flows_.find(key);
        if (found == flows_.end() || found->second != flow) return;
        const bool idleBackgroundClose = flow->established && flow->pending.empty() && !flow->sending;
        flows_.erase(found);
        if (flow->stream) flow->stream->close();
        auto pending = std::move(flow->pending);
        flow->pending.clear();
        for (auto &entry : pending) {
            queued_ -= entry.data.size();
            --requests_;
            entry.completion(error);
        }
        if (!closed_ && failure_ && error != "EOF" && !idleBackgroundClose) failure_(error);
    }

    void connectFlow(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || flow->connecting || flow->stream) return;
        flow->connecting = true;
        auto self = shared_from_this();
        connectProtocol(node_, flow->target, factory_, [self, key, flow](std::shared_ptr<Stream> stream, Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow) {
                if (stream) stream->close();
                return;
            }
            flow->connecting = false;
            if (!error.empty() || !stream) {
                self->failFlow(key, flow, error.empty() ? "UDP stream connect failed" : error);
                return;
            }
            flow->stream = std::move(stream);
            self->flush(key, flow);
            self->read(key, flow);
        });
    }

    void flush(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || !flow->stream || flow->sending || flow->pending.empty()) return;
        flow->sending = true;
        auto self = shared_from_this();
        auto activeStream = flow->stream;
        activeStream->write(flow->pending.front().data, [self, key, flow, activeStream](Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow) return;
            flow->sending = false;
            if (!error.empty()) {
                if (flow->established && !flow->pending.empty() && flow->pending.front().retries == 0) {
                    flow->pending.front().retries = 1;
                    if (flow->stream == activeStream) {
                        flow->stream->close();
                        flow->stream.reset();
                    }
                    flow->established = false;
                    self->connectFlow(key, flow);
                    return;
                }
                self->failFlow(key, flow, error);
                return;
            }
            flow->established = true;
            auto entry = std::move(flow->pending.front());
            flow->pending.pop_front();
            self->queued_ -= entry.data.size();
            --self->requests_;
            flow->activity = unixSeconds();
            entry.completion({});
            self->flush(key, flow);
        });
    }

    void read(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || !started_ || !flow->stream) return;
        auto self = shared_from_this();
        auto activeStream = flow->stream;
        activeStream->read(65535, [self, key, flow, activeStream](Buffer data, bool eof, Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow || flow->stream != activeStream) return;
            if (!error.empty()) { self->failFlow(key, flow, error); return; }
            if ((!data.empty() || !eof) && self->receive_) {
                flow->established = true;
                flow->activity = unixSeconds();
                self->receive_(flow->target, std::move(data));
            }
            if (eof) self->failFlow(key, flow, "EOF");
            else self->factory_->post([self, key, flow] { self->read(key, flow); });
        });
    }

    void reap() {
        if (closed_) return;
        auto now = unixSeconds();
        std::vector<std::pair<std::string, std::shared_ptr<Flow>>> stale;
        for (auto &entry : flows_) {
            if (!entry.second->connecting && entry.second->pending.empty() && now - entry.second->activity >= 120)
                stale.push_back(entry);
        }
        for (auto &entry : stale) failFlow(entry.first, entry.second, "EOF");
        if (factory_->after) {
            std::weak_ptr<StreamDatagrams> weak = shared_from_this();
            factory_->after(30, [weak] { if (auto self = weak.lock()) self->reap(); });
        }
    }

public:
    StreamDatagrams(Node node, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), factory_(std::move(factory)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram session closed"); return; }
        if (data.size() > 65535 || data.size() > maximumQueuedBytes - queued_ || requests_ >= 512) {
            completion("Datagram queue limit exceeded");
            return;
        }
        target.udp = true;
        std::string key = formatHostHeaderAuthority(target.host) + ":" + std::to_string(target.port);
        std::shared_ptr<Flow> flow;
        if (auto found = flows_.find(key); found != flows_.end()) {
            flow = found->second;
        } else {
            if (flows_.size() >= 128) { completion("Datagram flow limit exceeded"); return; }
            flow = std::make_shared<Flow>();
            flow->target = target;
            flow->activity = unixSeconds();
            flows_[key] = flow;
        }
        queued_ += data.size();
        ++requests_;
        flow->pending.push_back({std::move(data), std::move(completion), 0});
        if (flow->stream) { flush(key, flow); return; }
        connectFlow(key, flow);
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        if (started_) { failure("Datagram receiver already started"); return; }
        if (closed_) { failure("Datagram session closed"); return; }
        receive_ = std::move(receive);
        failure_ = std::move(failure);
        started_ = true;
        for (auto &entry : flows_) {
            if (entry.second->stream) read(entry.first, entry.second);
        }
        reap();
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        auto flows = std::move(flows_);
        flows_.clear();
        for (auto &entry : flows) {
            auto flow = entry.second;
            if (flow->stream) flow->stream->close();
            for (auto &pending : flow->pending) pending.completion("Datagram session closed");
        }
        queued_ = requests_ = 0;
        receive_ = nullptr;
        failure_ = nullptr;
    }
};

} // namespace

void makeBasicDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    if (node.type == "socks5" || node.type == "socks5-tls") {
        makeSocksDatagram(node, std::move(factory), std::move(completion));
        return;
    }
    completion(std::make_shared<StreamDatagrams>(node, std::move(factory)), {});
}

} // namespace hajimi
