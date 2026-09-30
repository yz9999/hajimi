// Independently authored implementation of the documented AnyTLS v1/v2 wire
// protocol and sing-box UoT v2. Reference protocol: anytls/anytls-go docs.
#include "AnyTLS.hpp"
#include "Crypto.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <deque>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace hajimi {
namespace {
double monotonicSeconds() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
uint32_t number(const std::string &text, uint32_t maximum) {
    if (text.empty()) throw std::runtime_error("AnyTLS setting is missing a number");
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') throw std::runtime_error("AnyTLS setting has an invalid number");
        value = value * 10 + static_cast<unsigned>(c - '0');
        if (value > maximum) throw std::runtime_error("AnyTLS setting exceeds its bound");
    }
    return static_cast<uint32_t>(value);
}
uint32_t durationOption(const Node &node, const std::string &key, uint32_t fallback) {
    auto value = node.option(key);
    if (value.empty()) return fallback;
    if (value.back() == 's') value.pop_back();
    auto seconds = number(value, 86400);
    return seconds > 5 ? seconds : fallback;
}
std::map<std::string, std::string> settings(const Buffer &raw) {
    if (raw.size() > 16384) throw std::runtime_error("AnyTLS settings exceed their bound");
    std::map<std::string, std::string> result;
    std::istringstream input(std::string(raw.begin(), raw.end()));
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto split = line.find('=');
        if (split == std::string::npos || !split || result.size() >= 128)
            throw std::runtime_error("Invalid AnyTLS settings");
        if (!result.emplace(line.substr(0, split), line.substr(split + 1)).second)
            throw std::runtime_error("Duplicate AnyTLS setting");
    }
    return result;
}
size_t choose(const anytls::PaddingRule &rule) {
    if (rule.minimum == rule.maximum) return rule.minimum;
    const uint32_t span = rule.maximum - rule.minimum;
    uint32_t value = 0;
    const uint32_t cutoff = uint32_t(-span) % span;
    do {
        Buffer random = crypto::randomBytes(4);
        value = (uint32_t(random[0]) << 24) | (uint32_t(random[1]) << 16) |
                (uint32_t(random[2]) << 8) | random[3];
    } while (value < cutoff);
    return rule.minimum + value % span;
}
void append16(Buffer &bytes, size_t value) {
    bytes.push_back(uint8_t(value >> 8)); bytes.push_back(uint8_t(value));
}
uint16_t get16(const uint8_t *bytes) { return (uint16_t(bytes[0]) << 8) | bytes[1]; }
uint32_t get32(const uint8_t *bytes) {
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
           (uint32_t(bytes[2]) << 8) | bytes[3];
}
}

namespace anytls {
Buffer frame(uint8_t command, uint32_t stream, const Buffer &data) {
    if (data.size() > UINT16_MAX) throw std::runtime_error("AnyTLS frame is too large");
    Buffer bytes{command, uint8_t(stream >> 24), uint8_t(stream >> 16), uint8_t(stream >> 8), uint8_t(stream)};
    append16(bytes, data.size());
    bytes.insert(bytes.end(), data.begin(), data.end());
    return bytes;
}
PaddingScheme PaddingScheme::defaults() {
    const std::string scheme = "stop=8\n0=30-30\n1=100-400\n"
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
    return parse(Buffer(scheme.begin(), scheme.end()));
}
PaddingScheme PaddingScheme::parse(const Buffer &raw) {
    PaddingScheme result;
    auto values = settings(raw);
    auto stop = values.find("stop");
    if (stop == values.end()) throw std::runtime_error("AnyTLS padding has no stop setting");
    result.stop_ = number(stop->second, 4096);
    result.raw_ = raw;
    for (const auto &entry : values) {
        if (entry.first == "stop") continue;
        uint32_t packet = number(entry.first, 4096);
        std::istringstream tokens(entry.second);
        std::string token;
        auto &rules = result.rules_[packet];
        while (std::getline(tokens, token, ',')) {
            if (rules.size() >= 32) throw std::runtime_error("AnyTLS padding has too many fragments");
            if (token == "c") { rules.push_back({0, 0, true}); continue; }
            auto dash = token.find('-');
            if (dash == std::string::npos) throw std::runtime_error("Invalid AnyTLS padding range");
            auto low = number(token.substr(0, dash), UINT16_MAX);
            auto high = number(token.substr(dash + 1), UINT16_MAX);
            if (!low || !high) throw std::runtime_error("AnyTLS padding sizes must be positive");
            if (low > high) std::swap(low, high);
            rules.push_back({low, high, false});
        }
    }
    return result;
}
std::string PaddingScheme::md5() const {
    static const char hex[] = "0123456789abcdef";
    auto digest = crypto::digest("MD5", raw_);
    std::string result;
    for (uint8_t byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
size_t PaddingScheme::authenticationPadding() const {
    auto found = rules_.find(0);
    return found != rules_.end() && !found->second.empty() && !found->second.front().check
        ? choose(found->second.front()) : 0;
}
std::vector<Buffer> PaddingScheme::apply(Buffer bytes, uint64_t packet) const {
    auto found = packet <= UINT32_MAX ? rules_.find(uint32_t(packet)) : rules_.end();
    if (packet >= stop_ || found == rules_.end()) return {std::move(bytes)};
    std::vector<Buffer> result;
    size_t offset = 0;
    for (const auto &rule : found->second) {
        size_t remaining = bytes.size() - offset;
        if (rule.check) { if (!remaining) break; else continue; }
        size_t desired = choose(rule);
        if (remaining > desired) {
            result.emplace_back(bytes.begin() + offset, bytes.begin() + offset + desired);
            offset += desired;
        } else if (remaining) {
            Buffer tail(bytes.begin() + offset, bytes.end());
            if (desired > remaining + 7) {
                Buffer waste = frame(Waste, 0, Buffer(desired - remaining - 7, 0));
                tail.insert(tail.end(), waste.begin(), waste.end());
            }
            result.push_back(std::move(tail)); offset = bytes.size();
        } else { result.push_back(frame(Waste, 0, Buffer(desired, 0))); }
    }
    if (offset < bytes.size()) result.emplace_back(bytes.begin() + offset, bytes.end());
    return result;
}
Buffer encodeUoTPacket(const Target &target, const Buffer &payload) {
    if (payload.size() > UINT16_MAX || target.host.empty() || !target.port)
        throw std::runtime_error("Invalid AnyTLS UDP destination or payload length");
    Buffer address = socksAddress(target);
    switch (address.at(0)) {
        case 1: address[0] = 0; break;
        case 4: address[0] = 1; break;
        case 3: address[0] = 2; break;
        default: throw std::runtime_error("Unsupported UoT address family");
    }
    append16(address, payload.size());
    address.insert(address.end(), payload.begin(), payload.end());
    return address;
}
bool decodeUoTPacket(const Buffer &bytes, size_t &consumed, Target &target, Buffer &payload) {
    consumed = 0;
    if (bytes.empty()) return false;
    size_t addressLength;
    uint8_t socksType;
    switch (bytes[0]) {
        case 0: addressLength = 7; socksType = 1; break;
        case 1: addressLength = 19; socksType = 4; break;
        case 2:
            if (bytes.size() < 2) return false;
            if (!bytes[1]) throw std::runtime_error("Empty AnyTLS UoT domain");
            addressLength = 4 + bytes[1]; socksType = 3; break;
        default: throw std::runtime_error("Invalid AnyTLS UoT address family");
    }
    if (bytes.size() < addressLength + 2) return false;
    size_t length = get16(bytes.data() + addressLength);
    if (bytes.size() < addressLength + 2 + length) return false;
    Buffer address(bytes.begin(), bytes.begin() + addressLength);
    address[0] = socksType;
    size_t parsed = 0;
    target = parseSocksAddress(address, parsed);
    if (parsed != addressLength || target.host.empty() || !target.port)
        throw std::runtime_error("Invalid AnyTLS UoT destination");
    target.udp = true;
    consumed = addressLength + 2 + length;
    payload.assign(bytes.begin() + addressLength + 2, bytes.begin() + consumed);
    return true;
}
} // namespace anytls

namespace {
class AnyTLSClient;
class AnyTLSSession;
class AnyTLSStream final : public Stream, public std::enable_shared_from_this<AnyTLSStream> {
public:
    AnyTLSStream(std::shared_ptr<AnyTLSSession> session, uint32_t id) : session_(std::move(session)), id_(id) {}
    ~AnyTLSStream() override;
    void write(Buffer, WriteCallback) override;
    void read(size_t, ReadCallback) override;
    void close() override;
private:
    friend class AnyTLSSession;
    std::shared_ptr<AnyTLSSession> session_;
    uint32_t id_;
    std::deque<Buffer> input_;
    size_t offset_ = 0, bytes_ = 0, readMaximum_ = 0;
    ReadCallback pendingRead_;
    bool closed_ = false, acknowledged_ = false;
    Error terminal_;
    double openedAt_ = monotonicSeconds();
    void deliver();
    void receive(Buffer);
    void finish(Error, bool discard = false);
};
class AnyTLSSession final : public std::enable_shared_from_this<AnyTLSSession> {
public:
    AnyTLSSession(std::weak_ptr<AnyTLSClient> client, std::shared_ptr<Stream> carrier,
                  std::shared_ptr<TransportFactory> factory, uint64_t sequence)
        : client_(std::move(client)), carrier_(std::move(carrier)),
          reader_(std::make_shared<Reader>(carrier_)), factory_(std::move(factory)), sequence_(sequence) {}
    void initialize(const Buffer &passwordHash, const anytls::PaddingScheme &, WriteCallback);
    void open(const Target &, StreamCallback);
    void write(uint32_t, Buffer, WriteCallback);
    void drop(uint32_t, bool sendFIN);
    void fail(Error);
    bool idle() const { return !closed_ && streams_.empty() && !reserved_ && !writing_ && writes_.empty(); }
    bool closed() const { return closed_; }
    void reserve() { reserved_ = true; }
    uint64_t sequence() const { return sequence_; }
    double idleSince() const { return idleSince_; }
    void releaseInput(size_t bytes) { inputBytes_ -= std::min(bytes, inputBytes_); }
    void post(std::function<void()> operation) { factory_->post(std::move(operation)); }
private:
    friend class AnyTLSClient;
    struct WireWrite { std::vector<Buffer> packets; size_t next = 0, bytes = 0; uint32_t stream = 0; WriteCallback completion; };
    std::weak_ptr<AnyTLSClient> client_;
    std::shared_ptr<Stream> carrier_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<TransportFactory> factory_;
    uint64_t sequence_, packet_ = 0;
    uint32_t nextStream_ = 0, heartbeat_ = 0;
    unsigned peerVersion_ = 1;
    bool closed_ = false, reserved_ = true, settingsSent_ = false, writing_ = false, waitingHeart_ = false;
    double idleSince_ = 0, lastActivity_ = monotonicSeconds(), heartSent_ = 0;
    size_t inputBytes_ = 0, queuedBytes_ = 0;
    std::unordered_map<uint32_t, std::weak_ptr<AnyTLSStream>> streams_;
    std::deque<WireWrite> writes_;
    void queue(Buffer, WriteCallback, bool authentication = false, uint32_t stream = 0);
    void pumpWrites();
    void readFrame();
    void processFrame(uint8_t, uint32_t, Buffer);
    void tick();
};
class AnyTLSClient final : public std::enable_shared_from_this<AnyTLSClient> {
public:
    AnyTLSClient(Node node, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), factory_(std::move(factory)), padding_(anytls::PaddingScheme::defaults()) {
        auto password = node_.option("password");
        passwordHash_ = crypto::digest("SHA256", Buffer(password.begin(), password.end()));
        idleTimeout_ = durationOption(node_, "idle-session-timeout", 30);
        idleCheckInterval_ = durationOption(node_, "idle-session-check-interval", 30);
        minIdle_ = number(node_.option("min-idle-session", "0"), 64);
    }
    void open(Target, StreamCallback);
    void remove(uint64_t sequence) {
        if (sessions_.erase(sequence)) retained_.fetch_sub(1, std::memory_order_relaxed);
    }
    void updatePadding(anytls::PaddingScheme padding) { padding_ = std::move(padding); }
    const anytls::PaddingScheme &padding() const { return padding_; }
    void reset();
    bool unused() const { return retained_.load(std::memory_order_relaxed) == 0; }
    bool ownedBy(const std::shared_ptr<TransportFactory> &factory) const { return factory_.get() == factory.get(); }
    void cleanupIdle(double);
private:
    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    anytls::PaddingScheme padding_;
    Buffer passwordHash_;
    uint64_t nextSession_ = 0;
    size_t connecting_ = 0;
    bool stopped_ = false;
    std::atomic<size_t> retained_{0};
    uint32_t idleTimeout_ = 30, idleCheckInterval_ = 30, minIdle_ = 0;
    double lastIdleCheck_ = 0;
    std::map<uint64_t, std::shared_ptr<AnyTLSSession>> sessions_;
};
std::mutex clientsMutex;
std::map<std::string, std::shared_ptr<AnyTLSClient>> clients;

AnyTLSStream::~AnyTLSStream() {
    if (!session_) return;
    auto session = session_;
    auto id = id_;
    auto bytes = bytes_;
    session->post([session, id, bytes] { session->releaseInput(bytes); session->drop(id, true); });
}
void AnyTLSStream::write(Buffer data, WriteCallback completion) {
    auto self = shared_from_this();
    session_->post([self, data = std::move(data), completion = std::move(completion)]() mutable {
        if (self->closed_) { completion(self->terminal_.empty() ? "AnyTLS stream closed" : self->terminal_); return; }
        self->session_->write(self->id_, std::move(data), std::move(completion));
    });
}
void AnyTLSStream::read(size_t maximum, ReadCallback completion) {
    auto self = shared_from_this();
    session_->post([self, maximum, completion = std::move(completion)]() mutable {
        if (!maximum || maximum > maximumReadBytes || self->pendingRead_) {
            completion({}, false, "Invalid or concurrent AnyTLS read"); return;
        }
        self->readMaximum_ = maximum;
        self->pendingRead_ = std::move(completion);
        self->deliver();
    });
}
void AnyTLSStream::close() {
    auto self = shared_from_this();
    session_->post([self] {
        if (!self->closed_) { self->session_->drop(self->id_, true); self->finish("AnyTLS stream closed", true); }
        else if (self->bytes_) { self->finish(self->terminal_, true); }
    });
}
void AnyTLSStream::deliver() {
    if (!pendingRead_ || (!bytes_ && !closed_)) return;
    Buffer output;
    const size_t wanted = std::min(readMaximum_, bytes_);
    output.reserve(wanted);
    while (output.size() < wanted) {
        const size_t count = std::min(wanted - output.size(), input_.front().size() - offset_);
        output.insert(output.end(), input_.front().begin() + offset_, input_.front().begin() + offset_ + count);
        offset_ += count;
        if (offset_ == input_.front().size()) { input_.pop_front(); offset_ = 0; }
    }
    bytes_ -= wanted;
    session_->releaseInput(wanted);
    auto callback = std::exchange(pendingRead_, {});
    bool eof = closed_ && !bytes_;
    callback(std::move(output), eof, eof ? terminal_ : Error{});
}
void AnyTLSStream::receive(Buffer data) {
    if (closed_ || data.empty()) return;
    bytes_ += data.size(); input_.push_back(std::move(data)); deliver();
}
void AnyTLSStream::finish(Error error, bool discard) {
    closed_ = true;
    if (!error.empty()) terminal_ = std::move(error);
    if (discard) { session_->releaseInput(bytes_); bytes_ = 0; offset_ = 0; input_.clear(); }
    deliver();
}
void AnyTLSSession::initialize(const Buffer &passwordHash, const anytls::PaddingScheme &padding,
                               WriteCallback completion) {
    try {
        size_t count = padding.authenticationPadding();
        Buffer authentication = passwordHash;
        append16(authentication, count); authentication.resize(authentication.size() + count, 0);
        queue(std::move(authentication), [self = shared_from_this(), completion](Error error) {
            if (error.empty()) { self->readFrame(); self->tick(); }
            completion(std::move(error));
        }, true);
    } catch (const std::exception &) { completion("Cannot initialize AnyTLS authentication/padding"); }
}
void AnyTLSSession::open(const Target &target, StreamCallback completion) {
    if (closed_ || !reserved_ || nextStream_ == UINT32_MAX) {
        completion(nullptr, "AnyTLS session cannot open another stream"); return;
    }
    reserved_ = false;
    uint32_t id = ++nextStream_;
    auto stream = std::make_shared<AnyTLSStream>(shared_from_this(), id);
    streams_[id] = stream;
    idleSince_ = 0;
    try {
        Buffer bytes;
        if (!settingsSent_) {
            auto client = client_.lock();
            if (!client) throw std::runtime_error("AnyTLS client stopped");
            const std::string config = "v=2\nclient=hajimi-native/1\npadding-md5=" + client->padding().md5();
            bytes = anytls::frame(anytls::Settings, 0, Buffer(config.begin(), config.end()));
            settingsSent_ = true;
        }
        auto syn = anytls::frame(anytls::SYN, id);
        bytes.insert(bytes.end(), syn.begin(), syn.end());
        Buffer address;
        if (target.host == "sp.v2.udp-over-tcp.arpa" && !target.port) {
            address = {3, uint8_t(target.host.size())};
            address.insert(address.end(), target.host.begin(), target.host.end()); append16(address, 0);
        } else { address = socksAddress(target); }
        auto psh = anytls::frame(anytls::PSH, id, address);
        bytes.insert(bytes.end(), psh.begin(), psh.end());
        queue(std::move(bytes), [stream, completion](Error error) {
            if (!error.empty()) { stream->session_->fail(error); }
            if (error.empty() && stream->closed_) error = stream->terminal_.empty()
                ? "AnyTLS stream closed during setup" : stream->terminal_;
            completion(error.empty() ? stream : nullptr, std::move(error));
        });
    } catch (const std::exception &) {
        drop(id, true); stream->finish("Invalid AnyTLS proxy request", true);
        completion(nullptr, "Invalid AnyTLS proxy request");
    }
}
void AnyTLSSession::write(uint32_t id, Buffer data, WriteCallback completion) {
    if (closed_ || !streams_.count(id)) { completion("AnyTLS stream closed"); return; }
    if (data.size() > maximumQueuedBytes) { completion("AnyTLS write exceeds its bound"); return; }
    try {
        Buffer bytes;
        for (size_t offset = 0; offset < data.size();) {
            size_t count = std::min<size_t>(UINT16_MAX, data.size() - offset);
            auto part = anytls::frame(anytls::PSH, id, Buffer(data.begin() + offset, data.begin() + offset + count));
            bytes.insert(bytes.end(), part.begin(), part.end()); offset += count;
        }
        if (bytes.empty()) { completion({}); return; }
        queue(std::move(bytes), completion, false, id);
    } catch (const std::exception &) { completion("Cannot encode AnyTLS data frame"); }
}
void AnyTLSSession::queue(Buffer bytes, WriteCallback completion, bool authentication, uint32_t stream) {
    if (closed_) { completion("AnyTLS session closed"); return; }
    bool queued = false;
    try {
        WireWrite item; item.stream = stream;
        if (authentication) item.packets.push_back(std::move(bytes));
        else {
            auto client = client_.lock();
            if (!client) { completion("AnyTLS client stopped"); return; }
            item.packets = client->padding().apply(std::move(bytes), packet_ + 1);
        }
        for (const auto &packet : item.packets) {
            if (packet.size() > maximumQueuedBytes - item.bytes)
                throw std::runtime_error("AnyTLS padding exceeds write bound");
            item.bytes += packet.size();
        }
        if (item.bytes > maximumQueuedBytes - queuedBytes_ || writes_.size() >= 256) {
            completion("AnyTLS write queue reached its bound"); return;
        }
        item.completion = completion;
        writes_.push_back(std::move(item));
        queuedBytes_ += writes_.back().bytes;
        queued = true;
        if (!authentication) ++packet_;
        pumpWrites();
    } catch (const std::exception &) {
        if (queued) fail("AnyTLS queued transport write failed");
        else completion("Cannot construct bounded AnyTLS write");
    }
}
void AnyTLSSession::pumpWrites() {
    if (closed_ || writing_ || writes_.empty()) return;
    auto &item = writes_.front();
    if (item.next == item.packets.size()) {
        auto completion = std::exchange(item.completion, {});
        queuedBytes_ -= item.bytes;
        writes_.pop_front();
        if (idle() && !idleSince_) idleSince_ = monotonicSeconds();
        if (completion) completion({});
        factory_->post([self = shared_from_this()] { self->pumpWrites(); });
        return;
    }
    writing_ = true;
    Buffer packet = std::move(item.packets[item.next++]);
    carrier_->write(std::move(packet), [self = shared_from_this()](Error error) {
        self->factory_->post([self, error = std::move(error)] {
            if (self->closed_) return;
            self->writing_ = false;
            if (!error.empty()) { self->fail("AnyTLS carrier write failed"); return; }
            self->lastActivity_ = monotonicSeconds();
            self->pumpWrites();
        });
    });
}
void AnyTLSSession::readFrame() {
    if (closed_) return;
    reader_->exactly(7, [self = shared_from_this()](Buffer header, Error error) {
        if (self->closed_) return;
        if (!error.empty()) { self->fail(error == "EOF" ? "AnyTLS session closed" : "Truncated AnyTLS frame"); return; }
        uint8_t command = header[0];
        uint32_t id = get32(header.data() + 1);
        size_t length = get16(header.data() + 5);
        self->reader_->exactly(length, [self, command, id](Buffer payload, Error bodyError) {
            if (self->closed_) return;
            if (!bodyError.empty()) { self->fail("Truncated AnyTLS frame payload"); return; }
            try { self->processFrame(command, id, std::move(payload)); }
            catch (const std::exception &) { self->fail("Invalid AnyTLS control/frame settings"); }
            self->factory_->post([self] { self->readFrame(); });
        });
    });
}
void AnyTLSSession::processFrame(uint8_t command, uint32_t id, Buffer payload) {
    lastActivity_ = monotonicSeconds();
    auto found = streams_.find(id);
    auto stream = found == streams_.end() ? nullptr : found->second.lock();
    switch (command) {
        case anytls::Waste: return;
        case anytls::PSH:
            if (!id) throw std::runtime_error("Invalid stream zero");
            if (stream && !stream->closed_) {
                if (payload.size() > maximumQueuedBytes - inputBytes_)
                    throw std::runtime_error("AnyTLS input queue exceeded its bound");
                inputBytes_ += payload.size(); stream->receive(std::move(payload));
            }
            return; // Consume late frames for already-closed streams.
        case anytls::FIN:
            if (!id || !payload.empty()) throw std::runtime_error("Invalid FIN");
            drop(id, false);
            if (stream) stream->finish({});
            return;
        case anytls::SYNACK:
            if (!id) throw std::runtime_error("Invalid SYNACK");
            if (stream) {
                stream->acknowledged_ = true;
                if (!payload.empty()) { drop(id, true); stream->finish("AnyTLS upstream rejected the stream", true); }
            }
            return;
        case anytls::Alert: fail("AnyTLS server rejected the session"); return;
        case anytls::UpdatePadding:
            if (id) throw std::runtime_error("Invalid padding stream ID");
            if (auto client = client_.lock()) client->updatePadding(anytls::PaddingScheme::parse(payload));
            return;
        case anytls::ServerSettings: {
            if (id) throw std::runtime_error("Invalid settings stream ID");
            auto values = settings(payload);
            auto version = values.find("v");
            if (version == values.end()) throw std::runtime_error("Missing server version");
            peerVersion_ = std::min<uint32_t>(number(version->second, 255), 2);
            if (!peerVersion_) throw std::runtime_error("Invalid server version");
            return;
        }
        case anytls::HeartRequest:
            if (!payload.empty()) throw std::runtime_error("Invalid heartbeat");
            queue(anytls::frame(anytls::HeartResponse, id), [self = shared_from_this()](Error error) {
                if (!error.empty()) self->fail("Cannot send AnyTLS heartbeat response");
            });
            return;
        case anytls::HeartResponse:
            if (!payload.empty()) throw std::runtime_error("Invalid heartbeat");
            if (waitingHeart_ && id == heartbeat_) waitingHeart_ = false;
            return;
        case anytls::SYN: case anytls::Settings:
            throw std::runtime_error("Unexpected client-only AnyTLS command");
        default:
            if (!payload.empty()) throw std::runtime_error("Unknown AnyTLS command contains data");
            return;
    }
}
void AnyTLSSession::drop(uint32_t id, bool sendFIN) {
    if (!streams_.erase(id)) return;
    std::vector<WriteCallback> canceled;
    for (auto write = writes_.begin(); write != writes_.end();) {
        // A padding packet may split an AnyTLS frame: never remove the tail of
        // a partially sent item, which would corrupt this reusable session.
        if (write->stream != id) { ++write; continue; }
        if (write->completion) canceled.push_back(std::exchange(write->completion, {}));
        if (!write->next) { queuedBytes_ -= write->bytes; write = writes_.erase(write); }
        else ++write;
    }
    if (!closed_ && sendFIN) queue(anytls::frame(anytls::FIN, id), [self = shared_from_this()](Error error) {
        if (!error.empty()) self->fail("Cannot send AnyTLS FIN");
    });
    if (streams_.empty()) idleSince_ = idle() ? monotonicSeconds() : 0;
    for (auto &callback : canceled) if (callback) callback("AnyTLS stream closed before queued write");
}
void AnyTLSSession::fail(Error error) {
    if (closed_) return;
    closed_ = true; reserved_ = false;
    reader_->close();
    auto streams = std::move(streams_);
    streams_.clear();
    for (auto &entry : streams) if (auto stream = entry.second.lock()) stream->finish(error, true);
    auto writes = std::move(writes_);
    writes_.clear(); queuedBytes_ = 0; writing_ = false;
    for (auto &write : writes) {
        auto completion = std::exchange(write.completion, {});
        if (completion) completion(error);
    }
    if (auto client = client_.lock()) client->remove(sequence_);
}
void AnyTLSSession::tick() {
    if (closed_) return;
    double now = monotonicSeconds();
    if (auto client = client_.lock()) client->cleanupIdle(now);
    if (closed_) return;
    if (peerVersion_ >= 2) {
        for (const auto &entry : streams_) if (auto stream = entry.second.lock()) {
            if (!stream->acknowledged_ && now - stream->openedAt_ > 3) {
                fail("AnyTLS stream SYNACK timed out"); return;
            }
        }
        if (waitingHeart_ && now - heartSent_ > 12) { fail("AnyTLS heartbeat timed out"); return; }
        if (!waitingHeart_ && now - lastActivity_ > 30) {
            waitingHeart_ = true; heartSent_ = now; ++heartbeat_;
            queue(anytls::frame(anytls::HeartRequest, heartbeat_), [self = shared_from_this()](Error error) {
                if (!error.empty()) self->fail("Cannot send AnyTLS heartbeat request");
            });
        }
    }
    std::weak_ptr<AnyTLSSession> weak = shared_from_this();
    factory_->after(1, [weak] { if (auto self = weak.lock()) self->tick(); });
}
void AnyTLSClient::open(Target target, StreamCallback completion) {
    auto self = shared_from_this();
    retained_.fetch_add(1, std::memory_order_relaxed);
    factory_->post([self, target = std::move(target), completion = std::move(completion)]() mutable {
        StreamCallback done = [self, completion = std::move(completion)](std::shared_ptr<Stream> stream, Error error) {
            self->retained_.fetch_sub(1, std::memory_order_relaxed);
            completion(std::move(stream), std::move(error));
        };
        if (self->stopped_) { done(nullptr, "AnyTLS client stopped"); return; }
        for (auto it = self->sessions_.rbegin(); it != self->sessions_.rend(); ++it) {
            if (it->second->idle() && it->second->nextStream_ != UINT32_MAX) {
                it->second->reserve(); it->second->open(target, std::move(done)); return;
            }
        }
        if (self->sessions_.size() + self->connecting_ >= 64) {
            done(nullptr, "AnyTLS session capacity reached"); return;
        }
        ++self->connecting_;
        self->factory_->tcp(self->node_, tlsOptions(self->node_, true),
            [self, target = std::move(target), done](std::shared_ptr<Stream> carrier, Error error) mutable {
                self->factory_->post([self, target = std::move(target), done, carrier = std::move(carrier), error]() mutable {
                    --self->connecting_;
                    if (!error.empty() || !carrier || self->stopped_) {
                        if (carrier) carrier->close();
                        done(nullptr, self->stopped_ ? "AnyTLS client stopped" : "AnyTLS TLS connection failed"); return;
                    }
                    auto session = std::make_shared<AnyTLSSession>(self, std::move(carrier), self->factory_, ++self->nextSession_);
                    self->sessions_[session->sequence()] = session;
                    self->retained_.fetch_add(1, std::memory_order_relaxed);
                    session->initialize(self->passwordHash_, self->padding_, [session, target, done](Error authError) {
                        if (!authError.empty()) { session->fail(authError); done(nullptr, std::move(authError)); return; }
                        session->open(target, done);
                    });
                });
            });
    });
}
void AnyTLSClient::cleanupIdle(double now) {
    if (now - lastIdleCheck_ < idleCheckInterval_) return;
    lastIdleCheck_ = now;
    std::vector<std::shared_ptr<AnyTLSSession>> expired;
    uint32_t kept = 0;
    for (auto it = sessions_.rbegin(); it != sessions_.rend(); ++it) {
        auto session = it->second;
        if (!session->idle()) continue;
        if (kept++ < minIdle_) continue;
        if (session->idleSince() && now - session->idleSince() >= idleTimeout_) expired.push_back(session);
    }
    for (auto &session : expired) session->fail("AnyTLS idle session expired");
}
void AnyTLSClient::reset() {
    factory_->post([self = shared_from_this()] {
        self->stopped_ = true;
        auto sessions = self->sessions_;
        for (auto &entry : sessions) entry.second->fail("AnyTLS runtime reset");
    });
}

class AnyTLSDatagram final : public Datagram, public std::enable_shared_from_this<AnyTLSDatagram> {
public:
    AnyTLSDatagram(std::shared_ptr<Stream> stream, std::shared_ptr<TransportFactory> factory)
        : stream_(std::move(stream)), factory_(std::move(factory)) {}
    ~AnyTLSDatagram() override { if (stream_) stream_->close(); }
    void send(Target target, Buffer payload, WriteCallback completion) override {
        auto self = shared_from_this();
        factory_->post([self, target = std::move(target), payload = std::move(payload), completion]() mutable {
            if (self->closed_) { completion("AnyTLS datagram session closed"); return; }
            try { self->stream_->write(anytls::encodeUoTPacket(target, payload), completion); }
            catch (const std::exception &) { completion("Invalid AnyTLS UoT packet"); }
        });
    }
    void start(PacketCallback receive, WriteCallback failure) override {
        auto self = shared_from_this();
        factory_->post([self, receive = std::move(receive), failure = std::move(failure)]() mutable {
            if (self->started_ || self->closed_) { failure("AnyTLS datagram start is invalid"); return; }
            self->started_ = true; self->receive_ = std::move(receive); self->failure_ = std::move(failure);
            self->readPacket();
        });
    }
    void close() override {
        auto self = shared_from_this();
        factory_->post([self] {
            self->closed_ = true; self->input_.clear(); self->receive_ = {}; self->failure_ = {};
            self->stream_->close();
        });
    }
private:
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<TransportFactory> factory_;
    Buffer input_;
    bool closed_ = false, started_ = false;
    PacketCallback receive_;
    WriteCallback failure_;
    void fail(Error error) {
        if (closed_) return;
        closed_ = true; input_.clear(); stream_->close();
        receive_ = {};
        auto failure = std::exchange(failure_, {});
        if (failure) failure(std::move(error));
    }
    void readPacket() {
        if (closed_) return;
        std::weak_ptr<AnyTLSDatagram> weak = shared_from_this();
        stream_->read(64 * 1024, [weak](Buffer data, bool eof, Error error) {
            auto self = weak.lock(); if (!self || self->closed_) return;
            if (data.size() > maximumQueuedBytes - self->input_.size()) {
                self->fail("AnyTLS UoT input reached its bound"); return;
            }
            self->input_.insert(self->input_.end(), data.begin(), data.end());
            try {
                for (;;) {
                    size_t consumed = 0;
                    Target target;
                    Buffer payload;
                    if (!anytls::decodeUoTPacket(self->input_, consumed, target, payload)) break;
                    self->input_.erase(self->input_.begin(), self->input_.begin() + consumed);
                    self->receive_(std::move(target), std::move(payload));
                    if (self->closed_) return;
                }
            } catch (const std::exception &) { self->fail("Invalid AnyTLS UoT response"); return; }
            if (eof || !error.empty()) { self->fail("AnyTLS UoT carrier closed"); return; }
            self->factory_->post([weak] { if (auto current = weak.lock()) current->readPacket(); });
        });
    }
};
std::string clientKey(const Node &node, const std::shared_ptr<TransportFactory> &factory) {
    Buffer raw;
    auto append = [&raw](const std::string &value) {
        uint64_t size = value.size();
        for (unsigned shift = 64; shift; shift -= 8) raw.push_back(uint8_t(size >> (shift - 8)));
        raw.insert(raw.end(), value.begin(), value.end());
    };
    append("hajimi-anytls-client-v1"); append(node.type); append(node.name); append(node.host);
    append(std::to_string(node.port)); append(node.interfaceName);
    std::map<std::string, std::string> sorted(node.parameters.begin(), node.parameters.end());
    for (const auto &entry : sorted) { append(entry.first); append(entry.second); }
    auto key = crypto::digest("SHA256", raw);
    return crypto::base64Encode(key) + ":" + std::to_string(reinterpret_cast<uintptr_t>(factory.get()));
}
}

Error validateAnyTLS(const Node &node, bool udp) {
    if (node.host.empty() || !node.port || node.option("password").empty()) return "AnyTLS requires server, port and password";
    if (node.option("password").size() > 4096) return "AnyTLS password exceeds its bound";
    if (node.option("network", "tcp") != "tcp") return "AnyTLS requires TCP/TLS transport";
    if (!node.option("tls").empty() && !node.flag("tls")) return "AnyTLS cannot disable TLS";
    if (!node.option("security").empty() && node.option("security") != "tls") return "AnyTLS requires standard TLS security";
    if (node.flag("skip-common-name-verify") && !node.flag("skip-cert-verify"))
        return "AnyTLS partial certificate bypass is unavailable; use explicit skip-cert-verify";
    if (!node.option("underlying-proxy").empty() || !node.option("dialer-proxy").empty())
        return "AnyTLS proxy chaining is not configured for this native transport";
    if (!node.option("certificate").empty() || !node.option("private-key").empty()) return "AnyTLS client-certificate TLS is not implemented";
    if (!node.option("ca-str").empty() || !node.option("ca").empty()) return "AnyTLS custom CA stores are not implemented by this transport";
    if (!node.option("client-fingerprint").empty() || !node.option("fingerprint").empty())
        return "AnyTLS custom TLS fingerprints are not implemented by this transport";
    if (udp && !node.option("udp-over-stream-version").empty() && node.option("udp-over-stream-version") != "2")
        return "AnyTLS UDP relay requires UDP-over-TCP version 2";
    if (udp && !node.option("udp-over-stream").empty() && !node.flag("udp-over-stream"))
        return "AnyTLS UDP relay cannot disable UDP-over-TCP framing";
    try {
        durationOption(node, "idle-session-timeout", 30);
        durationOption(node, "idle-session-check-interval", 30);
        number(node.option("min-idle-session", "0"), 64);
    } catch (const std::exception &) { return "AnyTLS idle-session settings are invalid"; }
    return {};
}
void connectAnyTLS(const Node &node, const Target &target, std::shared_ptr<TransportFactory> factory,
                   StreamCallback completion) {
    Error validation = validateAnyTLS(node, false);
    if (!validation.empty()) { completion(nullptr, std::move(validation)); return; }
    if (!factory || !factory->tcp || !factory->post || !factory->after) {
        completion(nullptr, "AnyTLS requires a serialized TCP/TLS transport and timers"); return;
    }
    try {
        auto key = clientKey(node, factory);
        std::shared_ptr<AnyTLSClient> client;
        {
            std::lock_guard<std::mutex> guard(clientsMutex);
            auto found = clients.find(key);
            if (found != clients.end()) client = found->second;
            else {
                for (auto it = clients.begin(); it != clients.end();) {
                    if (it->second.use_count() == 1 && it->second->unused()) it = clients.erase(it);
                    else ++it;
                }
                if (clients.size() < 128) { client = std::make_shared<AnyTLSClient>(node, factory); clients.emplace(key, client); }
            }
        }
        if (!client) { completion(nullptr, "AnyTLS client cache reached its bound"); return; }
        client->open(target, std::move(completion));
    } catch (const std::exception &) { completion(nullptr, "Cannot construct AnyTLS native client"); }
}
void makeAnyTLSDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    if (auto error = validateAnyTLS(node, true); !error.empty()) { completion(nullptr, std::move(error)); return; }
    Target magic{"sp.v2.udp-over-tcp.arpa", 0, false, false};
    connectAnyTLS(node, magic, factory, [factory, completion](std::shared_ptr<Stream> stream, Error error) {
        if (!stream || !error.empty()) { completion(nullptr, std::move(error)); return; }
        // UoT v2: isConnect=false followed by SOCKS 0.0.0.0:0.
        stream->write({0, 1, 0, 0, 0, 0, 0, 0}, [stream, factory, completion](Error writeError) {
            if (!writeError.empty()) { stream->close(); completion(nullptr, std::move(writeError)); return; }
            completion(std::make_shared<AnyTLSDatagram>(stream, factory), {});
        });
    });
}
void resetAnyTLSClients() {
    std::map<std::string, std::shared_ptr<AnyTLSClient>> old;
    { std::lock_guard<std::mutex> guard(clientsMutex); old.swap(clients); }
    for (auto &entry : old) entry.second->reset();
}
void resetAnyTLSClient(const std::shared_ptr<TransportFactory> &factory) {
    std::vector<std::shared_ptr<AnyTLSClient>> old;
    {
        std::lock_guard<std::mutex> guard(clientsMutex);
        for (auto it = clients.begin(); it != clients.end();) {
            if (it->second->ownedBy(factory)) { old.push_back(it->second); it = clients.erase(it); }
            else ++it;
        }
    }
    for (auto &client : old) client->reset();
}
} // namespace hajimi
