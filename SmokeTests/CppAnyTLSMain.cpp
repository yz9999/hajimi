#include "AnyTLS.hpp"
#include "Crypto.hpp"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <queue>
#include <stdexcept>
#include <thread>

using namespace hajimi;
namespace {
struct Loop {
    std::queue<std::function<void()>> work;
    std::vector<std::function<void()>> timers;
    void post(std::function<void()> action) { work.push(std::move(action)); }
    void drain() {
        size_t count = 0;
        while (!work.empty()) {
            if (++count > 1000000) throw std::runtime_error("Test event loop did not quiesce");
            auto next = std::move(work.front()); work.pop(); next();
        }
    }
};
uint16_t word(const uint8_t *p) { return uint16_t(p[0]) << 8 | p[1]; }
uint32_t dword(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
std::string text(const Buffer &bytes) { return std::string(bytes.begin(), bytes.end()); }
Buffer bytes(const std::string &value) { return Buffer(value.begin(), value.end()); }
const std::string updatedPadding = "stop=8\n0=11-11\n1=71-71\n2=15-15,c,31-31";

// The fake peer independently consumes actual client wire bytes, including
// cross-write padding/header fragments. The production C++ engine is exercised
// through its normal Stream/TransportFactory interfaces, not a codec substitute.
class Peer final : public Stream, public std::enable_shared_from_this<Peer> {
public:
    explicit Peer(Loop &loop) : loop_(loop) {}
    size_t authPadding = 0, settingsCount = 0, finReceived = 0, heartbeatResponses = 0;
    uint32_t lastStream = 0;
    bool version2 = true, acknowledgements = true, pauseWrites = false;
    std::vector<Target> destinations;
    void write(Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        std::function<void()> action = [self, data = std::move(data), completion]() mutable {
            if (self->closed_) { completion("Peer closed"); return; }
            self->input_.insert(self->input_.end(), data.begin(), data.end());
            try { self->consume(); completion(self->closed_ ? "Authentication rejected" : Error{}); }
            catch (const std::exception &) { self->close(); completion("Peer rejected malformed frame"); }
        };
        loop_.post([self, action = std::move(action)]() mutable {
            if (self->pauseWrites) self->paused_.push_back(std::move(action)); else action();
        });
    }
    void read(size_t maximum, ReadCallback completion) override {
        assert(!pending_);
        maximum_ = maximum; pending_ = std::move(completion); deliver();
    }
    void close() override { closed_ = true; resumeWrites(); deliver(); }
    void resumeWrites() {
        pauseWrites = false; auto pending = std::move(paused_); paused_.clear();
        for (auto &action : pending) loop_.post(std::move(action));
    }
    void emit(uint8_t command, uint32_t id, Buffer payload = {}) {
        auto output = anytls::frame(command, id, payload);
        output_.insert(output_.end(), output.begin(), output.end()); deliver();
    }
private:
    Loop &loop_;
    Buffer input_, output_;
    bool authenticated_ = false, closed_ = false;
    size_t maximum_ = 0;
    ReadCallback pending_;
    std::vector<std::function<void()>> paused_;
    struct Remote { bool addressed = false, uot = false, uotRequest = false; Buffer input; };
    std::map<uint32_t, Remote> streams_;
    void deliver() {
        if (!pending_ || (output_.empty() && !closed_)) return;
        size_t count = std::min({maximum_, output_.size(), size_t(11)});
        Buffer result(output_.begin(), output_.begin() + count);
        output_.erase(output_.begin(), output_.begin() + count);
        auto completion = std::move(pending_); pending_ = {};
        bool eof = closed_ && output_.empty();
        loop_.post([completion, result = std::move(result), eof]() mutable { completion(std::move(result), eof, {}); });
    }
    void consume() {
        if (!authenticated_) {
            if (input_.size() < 34) return;
            authPadding = word(input_.data() + 32);
            if (input_.size() < 34 + authPadding) return;
            const Buffer expected{0x5e,0x88,0x48,0x98,0xda,0x28,0x04,0x71,0x51,0xd0,0xe5,0x6f,0x8d,0xc6,0x29,0x27,
                0x73,0x60,0x3d,0x0d,0x6a,0xab,0xbd,0xd6,0x2a,0x11,0xef,0x72,0x1d,0x15,0x42,0xd8};
            if (!std::equal(expected.begin(), expected.end(), input_.begin())) { close(); return; }
            input_.erase(input_.begin(), input_.begin() + 34 + authPadding); authenticated_ = true;
        }
        while (input_.size() >= 7) {
            uint8_t command = input_[0]; uint32_t id = dword(input_.data() + 1); size_t length = word(input_.data() + 5);
            if (input_.size() < 7 + length) return;
            Buffer payload(input_.begin() + 7, input_.begin() + 7 + length);
            input_.erase(input_.begin(), input_.begin() + 7 + length);
            switch (command) {
                case anytls::Waste: break;
                case anytls::Settings:
                    assert(id == 0 && text(payload).find("v=2\nclient=hajimi-native/1\npadding-md5=") == 0);
                    ++settingsCount;
                    if (version2) emit(anytls::ServerSettings, 0, bytes("v=2"));
                    emit(anytls::UpdatePadding, 0, bytes(updatedPadding)); break;
                case anytls::SYN:
                    assert(settingsCount == 1 && id > lastStream && payload.empty());
                    lastStream = id; streams_.emplace(id, Remote{}); break;
                case anytls::PSH: push(id, std::move(payload)); break;
                case anytls::FIN: ++finReceived; streams_.erase(id); break;
                case anytls::HeartRequest: emit(anytls::HeartResponse, id); break;
                case anytls::HeartResponse: assert(id == 0x12345678); ++heartbeatResponses; break;
                default: throw std::runtime_error("Unexpected client command");
            }
        }
    }
    void push(uint32_t id, Buffer payload) {
        auto found = streams_.find(id);
        if (found == streams_.end()) throw std::runtime_error("Data before SYN");
        auto &stream = found->second;
        if (!stream.addressed) {
            size_t consumed = 0; Target destination = parseSocksAddress(payload, consumed);
            assert(consumed == payload.size());
            stream.addressed = true; stream.uot = destination.host == "sp.v2.udp-over-tcp.arpa";
            destinations.push_back(destination);
            if (version2 && acknowledgements) emit(anytls::SYNACK, id);
            return;
        }
        if (!stream.uot) { emit(anytls::PSH, id, std::move(payload)); return; }
        stream.input.insert(stream.input.end(), payload.begin(), payload.end());
        if (!stream.uotRequest) {
            if (stream.input.size() < 8) return;
            const Buffer request{0, 1, 0, 0, 0, 0, 0, 0};
            assert(std::equal(request.begin(), request.end(), stream.input.begin()));
            stream.input.erase(stream.input.begin(), stream.input.begin() + 8); stream.uotRequest = true;
        }
        // Echo the UoT byte stream, potentially across AnyTLS frame boundaries.
        if (!stream.input.empty()) { emit(anytls::PSH, id, std::move(stream.input)); stream.input.clear(); }
    }
};
}

int main() {
    Loop loop;
    std::vector<std::shared_ptr<Peer>> peers;
    auto factory = std::make_shared<TransportFactory>();
    factory->post = [&loop](std::function<void()> work) { loop.post(std::move(work)); };
    factory->after = [&loop](double, std::function<void()> work) { loop.timers.push_back(std::move(work)); };
    factory->tcp = [&loop, &peers](const Node &node, const TLSOptions &tls, StreamCallback completion) {
        assert(tls.enabled && !tls.skipVerify);
        auto peer = std::make_shared<Peer>(loop); peers.push_back(peer);
        peer->version2 = node.name != "version1";
        peer->acknowledgements = node.name != "missing-synack";
        loop.post([peer, completion] { completion(peer, {}); });
    };
    Node node; node.type = "anytls"; node.name = "test"; node.host = "fixture.invalid"; node.port = 443;
    node.parameters["password"] = "password";
    Target target{"example.test", 443, false, false};
    std::shared_ptr<Stream> first;
    connectAnyTLS(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); first = stream; });
    loop.drain(); assert(first && peers.size() == 1 && peers[0]->authPadding == 30 && peers[0]->settingsCount == 1);
    bool written = false;
    first->write(bytes("hello"), [&](Error error) { assert(error.empty()); written = true; });
    Buffer received;
    first->read(3, [&](Buffer data, bool eof, Error error) { assert(!eof && error.empty()); received = std::move(data); });
    loop.drain(); assert(written && text(received) == "hel");
    first->read(10, [&](Buffer data, bool eof, Error error) { assert(!eof && error.empty()); received = std::move(data); });
    loop.drain(); assert(text(received) == "lo");
    peers[0]->emit(anytls::HeartRequest, 0x12345678);
    loop.drain(); assert(peers[0]->heartbeatResponses == 1);
    peers[0]->emit(anytls::FIN, 1);
    bool eofReceived = false;
    first->read(10, [&](Buffer data, bool eof, Error error) { assert(data.empty() && error.empty()); eofReceived = eof; });
    loop.drain(); assert(eofReceived && peers[0]->finReceived == 0);

    std::shared_ptr<Stream> second, third, newest;
    connectAnyTLS(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); second = stream; });
    loop.drain(); assert(second && peers.size() == 1 && peers[0]->lastStream == 2);
    connectAnyTLS(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); third = stream; });
    loop.drain(); assert(third && peers.size() == 2 && peers[1]->authPadding == 11);
    second->close(); third->close(); loop.drain();
    connectAnyTLS(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); newest = stream; });
    loop.drain(); assert(newest && peers.size() == 2 && peers[1]->lastStream == 2);
    peers[1]->emit(255, 0, {1});
    bool invalidRejected = false;
    newest->read(10, [&](Buffer, bool eof, Error error) { invalidRejected = eof && !error.empty(); });
    loop.drain(); assert(invalidRejected);

    std::shared_ptr<Datagram> datagram;
    makeAnyTLSDatagram(node, factory, [&](std::shared_ptr<Datagram> session, Error error) {
        assert(error.empty()); datagram = session;
    });
    loop.drain(); assert(datagram && peers.size() == 2 && peers[0]->destinations.back().host == "sp.v2.udp-over-tcp.arpa");
    std::vector<Target> addresses;
    std::vector<Buffer> payloads;
    datagram->start([&](Target address, Buffer payload) {
        addresses.push_back(std::move(address)); payloads.push_back(std::move(payload));
    }, [](Error error) { assert(error.empty()); });
    Target v4{"127.0.0.1", 9000, true, false}, v6{"2001:db8::1", 53, true, false}, domain{"udp.example", 5353, true, false};
    for (const auto &address : {v4, v6, domain}) datagram->send(address, bytes("udp"), [](Error error) { assert(error.empty()); });
    loop.drain(); assert(addresses.size() == 3 && addresses[0].host == v4.host && addresses[1].host == v6.host && addresses[2].host == domain.host);
    for (const auto &payload : payloads) assert(text(payload) == "udp");
    Buffer large(65535, 0x5a);
    datagram->send(v4, large, [](Error error) { assert(error.empty()); });
    loop.drain(); assert(payloads.size() == 4 && payloads.back() == large);
    bool overflowRejected = false;
    datagram->send(v4, Buffer(65536, 0), [&](Error error) { overflowRejected = !error.empty(); });
    loop.drain(); assert(overflowRejected);
    datagram->close(); loop.drain();

    auto encoded = anytls::encodeUoTPacket(v4, bytes("udp"));
    assert((encoded == Buffer{0,127,0,0,1,0x23,0x28,0,3,'u','d','p'}));
    auto padding = anytls::PaddingScheme::parse(bytes(updatedPadding));
    assert(padding.authenticationPadding() == 11 && padding.md5().size() == 32);
    auto padded = padding.apply(Buffer(20, 0), 1);
    assert(padded.size() == 1 && padded[0].size() == 71);
    auto split = padding.apply(Buffer(38, 0), 2);
    assert(split.size() == 2 && split[0].size() == 15 && split[1].size() == 31);
    bool malformedPadding = false;
    try { anytls::PaddingScheme::parse(bytes("stop=999999")); }
    catch (const std::exception &) { malformedPadding = true; }
    assert(malformedPadding);

    Node wrong = node; wrong.parameters["password"] = "wrong";
    bool badAuth = false;
    connectAnyTLS(wrong, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { badAuth = !stream && !error.empty(); });
    loop.drain(); assert(badAuth);
    Node version1 = node; version1.name = "version1";
    std::shared_ptr<Stream> legacy;
    connectAnyTLS(version1, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); legacy = stream; });
    loop.drain(); assert(legacy);
    legacy->write(bytes("v1"), [](Error error) { assert(error.empty()); });
    legacy->read(10, [&](Buffer data, bool eof, Error error) { assert(!eof && error.empty() && text(data) == "v1"); });
    loop.drain(); legacy->close(); loop.drain();

    // A closed stream must not make its still-draining carrier appear idle.
    // Unsent writes are canceled, and partially sent padding fragments retain
    // their complete frame tails before FIN so later session reuse stays valid.
    Node pausedNode = node; pausedNode.name = "paused-wire"; std::shared_ptr<Stream> pausedStream, replacement;
    connectAnyTLS(pausedNode, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); pausedStream = stream; });
    loop.drain(); auto pausedPeer = peers.back(); pausedPeer->pauseWrites = true; size_t carrierCount = peers.size();
    unsigned canceledWrites = 0;
    pausedStream->write(Buffer(1024, 0xab), [&](Error error) { assert(!error.empty()); ++canceledWrites; });
    pausedStream->write(Buffer(2048, 0xcd), [&](Error error) { assert(!error.empty()); ++canceledWrites; });
    pausedStream->close();
    connectAnyTLS(pausedNode, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); replacement = stream; });
    loop.drain(); assert(canceledWrites == 2 && replacement && peers.size() == carrierCount + 1 && pausedPeer->finReceived == 0);
    pausedPeer->resumeWrites(); loop.drain(); assert(pausedPeer->finReceived == 1 && canceledWrites == 2);
    replacement->close(); loop.drain(); pausedStream.reset(); replacement.reset(); loop.drain();

    // Length prefixes isolate full node configs even when a value contains the
    // separator bytes used by older pool-key concatenation schemes.
    Node keyA = node; keyA.name = "pool-key"; keyA.parameters["a"] = std::string("b\0c\0d", 5);
    Node keyB = node; keyB.name = "pool-key"; keyB.parameters["a"] = "b"; keyB.parameters["c"] = "d";
    std::shared_ptr<Stream> keyed; carrierCount = peers.size();
    connectAnyTLS(keyA, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); keyed = stream; });
    loop.drain(); keyed->close(); loop.drain(); keyed.reset(); loop.drain();
    connectAnyTLS(keyB, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); keyed = stream; });
    loop.drain(); assert(peers.size() == carrierCount + 2); keyed->close(); loop.drain(); keyed.reset(); loop.drain();

    Node droppedUDP = node; droppedUDP.name = "drop-udp-handle"; std::shared_ptr<Datagram> ephemeral;
    makeAnyTLSDatagram(droppedUDP, factory, [&](std::shared_ptr<Datagram> session, Error error) { assert(error.empty()); ephemeral = session; });
    loop.drain(); auto droppedPeer = peers.back(); assert(ephemeral);
    ephemeral->start([](Target, Buffer) { assert(false); }, [](Error) { assert(false); }); loop.drain();
    std::weak_ptr<Datagram> ephemeralWeak = ephemeral; ephemeral.reset(); assert(ephemeralWeak.expired());
    loop.drain(); assert(droppedPeer->finReceived == 1);
    Node uotV1 = node; uotV1.parameters["udp-over-stream-version"] = "1";
    bool wrongUoT = false; makeAnyTLSDatagram(uotV1, factory, [&](std::shared_ptr<Datagram> session, Error error) { wrongUoT = !session && !error.empty(); });
    assert(wrongUoT);

    Node noAck = node; noAck.name = "missing-synack";
    std::shared_ptr<Stream> timed;
    connectAnyTLS(noAck, target, factory, [&](std::shared_ptr<Stream> stream, Error error) { assert(error.empty()); timed = stream; });
    loop.drain(); assert(timed);
    bool timedOut = false;
    timed->read(10, [&](Buffer, bool eof, Error error) { timedOut = eof && !error.empty(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(3200));
    auto timers = std::move(loop.timers); loop.timers.clear();
    for (auto &timer : timers) timer();
    loop.drain(); assert(timedOut);
    Node noTLS = node; noTLS.parameters["tls"] = "false";
    assert(!validateAnyTLS(noTLS, false).empty());
    resetAnyTLSClient(factory); loop.drain();
    first.reset(); second.reset(); third.reset(); newest.reset(); legacy.reset(); timed.reset(); datagram.reset();
    loop.drain(); resetAnyTLSClients(); loop.drain();
    std::puts("C++ AnyTLS auth/settings/padding/pool/SYNACK/heartbeats/FIN/UoT v2 tests passed");
    return 0;
}
