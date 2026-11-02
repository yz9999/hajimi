#include "Snell.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <queue>
#include <stdexcept>
#include <utility>

using namespace hajimi;
namespace {
struct Loop {
    std::queue<std::function<void()>> work;
    std::vector<std::function<void()>> timers;
    void post(std::function<void()> action) { work.push(std::move(action)); }
    void drain() {
        size_t count = 0;
        while (!work.empty()) {
            assert(++count < 1000000); auto next = std::move(work.front()); work.pop(); next();
        }
    }
};
uint16_t word(const uint8_t *p) { return uint16_t(p[0]) << 8 | p[1]; }
void put16(Buffer &data, size_t value) { data.push_back(uint8_t(value >> 8)); data.push_back(uint8_t(value)); }
void nonceNext(Buffer &nonce) { for (auto &byte : nonce) if (++byte) return; }
Buffer bytes(const std::string &text) { return Buffer(text.begin(), text.end()); }
std::string hex(const Buffer &data) {
    static const char alphabet[] = "0123456789abcdef"; std::string result;
    for (auto byte : data) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; } return result;
}

// Manual record layout and independent nonce/padding code exercise the actual
// async engine; this peer does not call the production Encoder or Decoder.
class Peer final : public Stream, public std::enable_shared_from_this<Peer> {
public:
    Peer(Loop &loop, unsigned version) : loop_(loop), version_(version) {}
    bool reject = false, udp = false, ended = false, lazyTCPAck = false;
    size_t firstPadding = 0, records = 0;
    Target destination;
    std::vector<Target> udpTargets;
    void write(Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        loop_.post([self, data = std::move(data), completion = std::move(completion)]() mutable {
            if (self->closed_) { completion("Peer closed"); return; }
            self->input_.insert(self->input_.end(), data.begin(), data.end());
            try { self->consume(); completion({}); }
            catch (const std::exception &) { self->close(); completion("Peer rejected Snell encryption"); }
        });
    }
    void read(size_t maximum, ReadCallback completion) override {
        assert(!pending_); maximum_ = maximum; pending_ = std::move(completion); deliver();
    }
    void close() override { closed_ = true; deliver(); }
    void emit(Buffer plain) {
        if (sendKey_.empty()) {
            Buffer salt(16); for (size_t i = 0; i < salt.size(); ++i) salt[i] = uint8_t(0xa0 + i);
            sendKey_ = snell::deriveKey("testpsk", salt, version_); output_.insert(output_.end(), salt.begin(), salt.end());
        }
        Buffer header;
        if (version_ < 4) put16(header, plain.size());
        else { header = {4, 0, 0, 0, 0}; put16(header, plain.size()); }
        auto sealed = crypto::seal(method(), sendKey_, sendNonce_, header); nonceNext(sendNonce_);
        output_.insert(output_.end(), sealed.begin(), sealed.end());
        if (!plain.empty()) {
            sealed = crypto::seal(method(), sendKey_, sendNonce_, plain); nonceNext(sendNonce_);
            output_.insert(output_.end(), sealed.begin(), sealed.end());
        }
        deliver();
    }
private:
    Loop &loop_;
    unsigned version_;
    bool closed_ = false, addressed_ = false, pendingAck_ = false;
    Buffer input_, output_, key_, sendKey_, nonce_ = Buffer(12, 0), sendNonce_ = Buffer(12, 0);
    ReadCallback pending_;
    size_t maximum_ = 0;
    crypto::AEAD method() { return version_ == 1 ? crypto::AEAD::ChaCha20Poly1305 : crypto::AEAD::AES128GCM; }
    void deliver() {
        if (!pending_ || (output_.empty() && !closed_)) return;
        size_t count = std::min({maximum_, output_.size(), size_t(7)});
        Buffer result(output_.begin(), output_.begin() + count); output_.erase(output_.begin(), output_.begin() + count);
        auto callback = std::exchange(pending_, {}); bool eof = closed_ && output_.empty();
        loop_.post([callback = std::move(callback), result = std::move(result), eof]() mutable { callback(std::move(result), eof, {}); });
    }
    void consume() {
        if (key_.empty()) {
            if (input_.size() < 16) return;
            key_ = snell::deriveKey("testpsk", Buffer(input_.begin(), input_.begin() + 16), version_);
            input_.erase(input_.begin(), input_.begin() + 16);
        }
        size_t headerSize = version_ < 4 ? 18 : 23;
        while (input_.size() >= headerSize) {
            auto header = crypto::open(method(), key_, nonce_, Buffer(input_.begin(), input_.begin() + headerSize));
            size_t padding = version_ < 4 ? 0 : word(header.data() + 3);
            size_t length = word(header.data() + (version_ < 4 ? 0 : 5));
            size_t bodySize = length ? length + 16 : 0;
            if (input_.size() < headerSize + padding + bodySize) return;
            assert(length <= snell::maximumFrame && padding <= snell::maximumFrame);
            if (!records++ && version_ >= 4) { firstPadding = padding; assert(padding >= 256 && padding <= 511); }
            nonceNext(nonce_);
            Buffer body(input_.begin() + headerSize, input_.begin() + headerSize + padding + bodySize);
            for (size_t i = 0; i < std::min(padding, bodySize); i += 2) std::swap(body[i], body[padding + i]);
            Buffer plain;
            if (bodySize) { plain = crypto::open(method(), key_, nonce_, Buffer(body.begin() + padding, body.end())); nonceNext(nonce_); }
            input_.erase(input_.begin(), input_.begin() + headerSize + padding + bodySize);
            if (!length) { ended = true; emit({}); return; }
            if (!addressed_) address(plain); else if (udp) packet(plain);
            else { if (pendingAck_) { emit({0}); pendingAck_ = false; } emit(std::move(plain)); }
        }
    }
    void address(const Buffer &plain) {
        assert(plain.size() >= 3 && plain[0] == 1 && plain[2] == 0); addressed_ = true;
        if (plain[1] == 6) { assert(version_ >= 3 && plain.size() == 3); udp = true; }
        else {
            assert(plain[1] == (version_ == 2 ? 5 : 1)); assert(plain.size() == size_t(plain[3]) + 6);
            destination = {std::string(plain.begin() + 4, plain.end() - 2), word(plain.data() + plain.size() - 2), false, false};
        }
        if (!reject && ((udp && version_ == 3) || lazyTCPAck)) pendingAck_ = true;
        else emit(reject ? Buffer{2, 7, 14, 's','e','r','v','e','r','-','p','a','s','s','w','d','!'} : Buffer{0});
    }
    void packet(const Buffer &plain) {
        if (pendingAck_) { emit({0}); pendingAck_ = false; }
        assert(plain.size() >= 5 && plain[0] == 1); size_t offset = 2; Target target; uint8_t raw[16]{}; size_t size = 4;
        if (plain[1]) { target.host = std::string(plain.begin() + 2, plain.begin() + 2 + plain[1]); offset += plain[1]; raw[0] = 127; raw[3] = 7; }
        else {
            size = plain[2] == 4 ? 4 : 16; offset = 3 + size; char host[INET6_ADDRSTRLEN];
            assert(inet_ntop(size == 4 ? AF_INET : AF_INET6, plain.data() + 3, host, sizeof(host))); target.host = host;
            std::copy_n(plain.data() + 3, size, raw);
        }
        target.port = word(plain.data() + offset); target.udp = true; udpTargets.push_back(target);
        Buffer reply{uint8_t(size == 4 ? 4 : 6)}; reply.insert(reply.end(), raw, raw + size); put16(reply, target.port);
        reply.insert(reply.end(), plain.begin() + offset + 2, plain.end()); emit(std::move(reply));
    }
};
} // namespace

int main() {
    Buffer salt(16); for (size_t i = 0; i < salt.size(); ++i) salt[i] = uint8_t(i);
    // Independently generated with argon2-cffi's reference Argon2id v0x13,
    // time_cost=3, memory_cost=8 KiB, parallelism=1, hash_len=32.
    assert(hex(snell::deriveKey("testpsk", salt, 1)) == "f85ab318206e5601081d4256eeae70a0104aa45a85dbc25bfed366cc0ee73ac4");
    assert(hex(snell::deriveKey("testpsk", salt, 4)) == "f85ab318206e5601081d4256eeae70a0");
    for (unsigned version = 1; version <= 4; ++version) {
        snell::Encoder encoder("testpsk", version, salt, 8); snell::Decoder decoder("testpsk", version, salt);
        Buffer plain = bytes("record-vector"); auto frame = encoder.frame(plain); size_t headerSize = decoder.headerSize();
        auto lengths = decoder.header(Buffer(frame.begin() + 16, frame.begin() + 16 + headerSize));
        assert(lengths.payload == plain.size() && lengths.padding == (version == 4 ? 8 : 0));
        assert(decoder.body(Buffer(frame.begin() + 16 + headerSize, frame.end()), lengths) == plain);
        auto second = encoder.frame(bytes("next")); lengths = decoder.header(Buffer(second.begin(), second.begin() + headerSize));
        assert(decoder.body(Buffer(second.begin() + headerSize, second.end()), lengths) == bytes("next"));
        auto end = encoder.frame({}); assert(end.size() == headerSize); lengths = decoder.header(end);
        assert(!lengths.payload && decoder.body({}, lengths).empty());
        auto afterZero = encoder.frame(bytes("nonce-after-zero")); lengths = decoder.header(Buffer(afterZero.begin(), afterZero.begin() + headerSize));
        assert(decoder.body(Buffer(afterZero.begin() + headerSize, afterZero.end()), lengths) == bytes("nonce-after-zero"));
        snell::Decoder tampered("testpsk", version, salt); frame[16] ^= 1; bool rejected = false;
        try { tampered.header(Buffer(frame.begin() + 16, frame.begin() + 16 + headerSize)); }
        catch (const std::exception &) { rejected = true; } assert(rejected);

        Loop loop; std::vector<std::shared_ptr<Peer>> peers;
        auto factory = std::make_shared<TransportFactory>();
        factory->post = [&loop](std::function<void()> work) { loop.post(std::move(work)); };
        factory->after = [&loop](double, std::function<void()> work) { loop.timers.push_back(std::move(work)); };
        factory->tcp = [&loop, &peers, version](const Node &node, const TLSOptions &tls, StreamCallback completion) {
            assert(!tls.enabled); auto peer = std::make_shared<Peer>(loop, version); peers.push_back(peer);
            peer->reject = node.name == "reject"; peer->lazyTCPAck = node.name == "lazy-tcp-ack";
            loop.post([peer, completion] { completion(peer, {}); });
        };
        Node node; node.type = "snell"; node.host = "fixture.invalid"; node.port = 443;
        node.parameters["psk"] = "testpsk"; node.parameters["version"] = std::to_string(version);
        Target target{"target.test", 8443, false, false}; std::shared_ptr<Stream> stream;
        connectSnell(node, target, factory, [&](std::shared_ptr<Stream> connected, Error error) { assert(error.empty()); stream = std::move(connected); });
        loop.drain(); assert(stream && peers[0]->destination.host == target.host && peers[0]->destination.port == target.port);
        Buffer payload(70001); for (size_t i = 0; i < payload.size(); ++i) payload[i] = uint8_t(i);
        bool sent = false; Buffer received;
        stream->write(payload, [&](Error error) { assert(error.empty()); sent = true; });
        std::function<void()> more;
        more = [&] { stream->read(503, [&](Buffer data, bool eof, Error error) {
            assert(error.empty() && !eof); received.insert(received.end(), data.begin(), data.end()); if (received.size() < payload.size()) more();
        }); };
        more(); loop.drain(); assert(sent && received == payload);
        bool overflow = false;
        stream->write(Buffer(maximumQueuedBytes + 1, 0), [&](Error error) { overflow = !error.empty(); }); loop.drain(); assert(overflow);
        if (version == 2) {
            assert(stream->supportsHalfClose()); bool halfClosed = false, eof = false;
            stream->shutdownWrite([&](Error error) { assert(error.empty()); halfClosed = true; });
            stream->read(1, [&](Buffer data, bool end, Error error) { assert(data.empty() && error.empty()); eof = end; });
            loop.drain(); assert(halfClosed && peers[0]->ended && eof);
        } else {
            assert(!stream->supportsHalfClose()); bool unsupportedHalfClose = false;
            stream->shutdownWrite([&](Error error) { unsupportedHalfClose = !error.empty(); }); loop.drain(); assert(unsupportedHalfClose && !peers[0]->ended);
        }
        stream->close(); loop.drain();

        Node reject = node; reject.name = "reject"; bool denied = false; std::shared_ptr<Stream> rejectedStream;
        connectSnell(reject, target, factory, [&](std::shared_ptr<Stream> connected, Error error) {
            assert(connected && error.empty()); rejectedStream = std::move(connected);
        }); loop.drain();
        rejectedStream->read(32, [&](Buffer data, bool eof, Error error) {
            assert(data.empty() && eof && error.find("server-passwd") == std::string::npos); denied = !error.empty();
        }); loop.drain(); assert(denied); rejectedStream.reset(); loop.drain();
        Node lazyTCP = node; lazyTCP.name = "lazy-tcp-ack"; std::shared_ptr<Stream> lazyStream;
        connectSnell(lazyTCP, target, factory, [&](std::shared_ptr<Stream> connected, Error error) { assert(error.empty()); lazyStream = std::move(connected); });
        loop.drain(); assert(lazyStream); bool lazyReceived = false;
        lazyStream->write(bytes("lazy"), [](Error error) { assert(error.empty()); });
        lazyStream->read(32, [&](Buffer data, bool eof, Error error) { assert(error.empty() && !eof && data == bytes("lazy")); lazyReceived = true; });
        loop.drain(); assert(lazyReceived); lazyStream->close(); lazyStream.reset(); loop.drain();
        Node wrong = node; wrong.parameters["psk"] = "wrong"; bool badKey = false;
        connectSnell(wrong, target, factory, [&](std::shared_ptr<Stream> connected, Error error) { badKey = !connected && !error.empty(); });
        loop.drain(); assert(badKey);

        if (version >= 3) {
            std::shared_ptr<Datagram> datagram;
            makeSnellDatagram(node, factory, [&](std::shared_ptr<Datagram> session, Error error) { assert(error.empty()); datagram = std::move(session); });
            loop.drain(); assert(datagram && peers.back()->udp);
            std::vector<Buffer> packets; std::vector<Target> sources;
            datagram->start([&](Target source, Buffer packet) { sources.push_back(source); packets.push_back(std::move(packet)); }, [](Error error) { assert(error.empty()); });
            Target v4{"127.0.0.1", 9000, true, false}, v6{"2001:db8::2", 53, true, false}, domain{"udp.test", 5353, true, false};
            datagram->send(v4, bytes("one"), [](Error error) { assert(error.empty()); });
            datagram->send(v6, bytes("two"), [](Error error) { assert(error.empty()); });
            Buffer large(16000, 0xa7); datagram->send(domain, large, [](Error error) { assert(error.empty()); });
            loop.drain(); assert(packets.size() == 3 && packets[0] == bytes("one") && packets[1] == bytes("two") && packets[2] == large);
            assert(sources[0].host == v4.host && sources[1].host == v6.host && sources[2].host == "127.0.0.7");
            assert(peers.back()->udpTargets[2].host == domain.host);
            bool largeRejected = false; datagram->send(v4, Buffer(snell::maximumFrame, 0), [&](Error error) { largeRejected = !error.empty(); });
            loop.drain(); assert(largeRejected); datagram->close(); loop.drain();
        } else assert(!validateSnell(node, true).empty());
        Node unsupported = node; unsupported.parameters["version"] = "5"; assert(!validateSnell(unsupported, false).empty());
        unsupported = node; unsupported.parameters["obfs"] = "tls"; assert(!validateSnell(unsupported, false).empty());
        stream.reset(); loop.drain();
    }
    Target target; Buffer payload; bool malformed = false;
    try { snell::udpResponse(Buffer{4, 127, 0}, target, payload); } catch (const std::exception &) { malformed = true; }
    assert(malformed);
    std::puts("C++ Snell: v1-v4 records, Argon2id vector, stream EOF, UDP boundaries, and negative paths passed");
}
