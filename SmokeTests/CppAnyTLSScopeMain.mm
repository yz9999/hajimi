#import <HajimiCXXProtocolBridge.h>
#include "AnyTLS.hpp"
#include "Runtime.hpp"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// This executable is memory-only. Every physical dial returns a callback
// stream; it never starts Network.framework, a socket, a resolver or a helper.
using namespace hajimi;
namespace {
std::atomic<unsigned> checks{0};
void expect(bool value, const char *message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
void post(dispatch_queue_t queue, std::function<void()> work) {
    dispatch_async(queue, ^{ @autoreleasepool { work(); } });
}
void wait(dispatch_semaphore_t signal, const char *message) {
    expect(dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0, message);
}
Buffer bytes(const std::string &value) { return {value.begin(), value.end()}; }
Buffer buffer(NSData *value) {
    if (!value.length) return {};
    const auto begin = static_cast<const uint8_t *>(value.bytes);
    return {begin, begin + value.length};
}
NSData *nativeData(const Buffer &value) { return [NSData dataWithBytes:value.data() length:value.size()]; }
NSError *fixtureError(const std::string &value) {
    return [NSError errorWithDomain:@"app.hajimi.anytls-scope-memory" code:1
        userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:value.c_str()]}];
}
class Failures {
    mutable std::mutex mutex_;
    std::string first_;
public:
    void record(const std::string &value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (first_.empty()) first_ = value;
    }
    void check() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!first_.empty()) throw std::runtime_error(first_);
    }
};
uint16_t word(const uint8_t *value) { return uint16_t(value[0]) << 8 | value[1]; }
uint32_t dword(const uint8_t *value) {
    return uint32_t(value[0]) << 24 | uint32_t(value[1]) << 16 | uint32_t(value[2]) << 8 | value[3];
}
Buffer peerFrame(uint8_t command, uint32_t stream, const Buffer &payload = {}) {
    if (payload.size() > 65535) throw std::runtime_error("Memory peer frame exceeds wire bound");
    Buffer wire{command, uint8_t(stream >> 24), uint8_t(stream >> 16), uint8_t(stream >> 8), uint8_t(stream),
        uint8_t(payload.size() >> 8), uint8_t(payload.size())};
    wire.insert(wire.end(), payload.begin(), payload.end());
    return wire;
}

// Independently consume the real C++ engine's auth, padded/split frames and
// UoT-v2 preface. Replies are fragmented across native callback-stream reads.
class Peer : public std::enable_shared_from_this<Peer> {
    struct Remote { bool addressed = false, uot = false, preface = false; Buffer input; };
    dispatch_queue_t queue_;
    std::shared_ptr<Failures> failures_;
    Buffer input_, output_;
    std::map<uint32_t, Remote> streams_;
    HJDataReadCompletion pending_ = nil;
    NSUInteger maximum_ = 0;
    bool authenticated_ = false, closed_ = false;
    void emit(uint8_t command, uint32_t id, const Buffer &payload = {}) {
        const auto wire = peerFrame(command, id, payload);
        output_.insert(output_.end(), wire.begin(), wire.end());
        deliver();
    }
    void deliver() {
        if (!pending_ || output_.empty()) return;
        const auto count = std::min({size_t(maximum_), output_.size(), size_t(11)});
        Buffer result(output_.begin(), output_.begin() + count);
        output_.erase(output_.begin(), output_.begin() + count);
        HJDataReadCompletion done = pending_; pending_ = nil;
        done(nativeData(result), NO, nil);
    }
    void push(uint32_t id, Buffer payload) {
        auto found = streams_.find(id);
        if (found == streams_.end()) throw std::runtime_error("Memory peer received PSH before SYN");
        auto &remote = found->second;
        if (!remote.addressed) {
            size_t consumed = 0;
            const auto target = parseSocksAddress(payload, consumed);
            if (consumed != payload.size()) throw std::runtime_error("Memory peer destination framing changed");
            remote.addressed = true; remote.uot = target.host == "sp.v2.udp-over-tcp.arpa";
            emit(anytls::SYNACK, id);
            return;
        }
        if (!remote.uot) { emit(anytls::PSH, id, payload); return; }
        remote.input.insert(remote.input.end(), payload.begin(), payload.end());
        if (!remote.preface) {
            if (remote.input.size() < 8) return;
            const Buffer preface{0, 1, 0, 0, 0, 0, 0, 0};
            if (!std::equal(preface.begin(), preface.end(), remote.input.begin()))
                throw std::runtime_error("Memory peer UoT-v2 preface changed");
            remote.input.erase(remote.input.begin(), remote.input.begin() + 8); remote.preface = true;
        }
        if (!remote.input.empty()) { emit(anytls::PSH, id, remote.input); remote.input.clear(); }
    }
    void consume() {
        if (!authenticated_) {
            if (input_.size() < 34) return;
            const size_t padding = word(input_.data() + 32);
            if (input_.size() < 34 + padding) return;
            const Buffer expected{0x5e,0x88,0x48,0x98,0xda,0x28,0x04,0x71,0x51,0xd0,0xe5,0x6f,0x8d,0xc6,0x29,0x27,
                0x73,0x60,0x3d,0x0d,0x6a,0xab,0xbd,0xd6,0x2a,0x11,0xef,0x72,0x1d,0x15,0x42,0xd8};
            if (!std::equal(expected.begin(), expected.end(), input_.begin()))
                throw std::runtime_error("Memory peer AnyTLS authentication changed");
            input_.erase(input_.begin(), input_.begin() + 34 + padding); authenticated_ = true;
            authCount.fetch_add(1);
        }
        while (input_.size() >= 7) {
            const auto command = input_[0]; const auto id = dword(input_.data() + 1);
            const size_t length = word(input_.data() + 5);
            if (input_.size() < 7 + length) return;
            Buffer payload(input_.begin() + 7, input_.begin() + 7 + length);
            input_.erase(input_.begin(), input_.begin() + 7 + length);
            switch (command) {
                case anytls::Waste: break;
                case anytls::Settings:
                    if (id || settingsCount.load() || std::string(payload.begin(), payload.end()).find(
                        "v=2\nclient=hajimi-native/1\npadding-md5=") != 0)
                        throw std::runtime_error("Memory peer AnyTLS settings changed");
                    settingsCount.fetch_add(1);
                    emit(anytls::ServerSettings, 0, bytes("v=2"));
                    emit(anytls::UpdatePadding, 0, bytes("stop=8\n0=11-11\n1=71-71\n2=15-15,c,31-31"));
                    break;
                case anytls::SYN:
                    if (settingsCount.load() != 1 || id <= lastStream.load() || !payload.empty())
                        throw std::runtime_error("Memory peer AnyTLS SYN changed");
                    lastStream.store(id); streams_.emplace(id, Remote{}); break;
                case anytls::PSH: push(id, std::move(payload)); break;
                case anytls::FIN:
                    if (!payload.empty()) throw std::runtime_error("Memory peer FIN contains a payload");
                    streams_.erase(id); finCount.fetch_add(1); dispatch_semaphore_signal(fin); break;
                case anytls::HeartRequest: emit(anytls::HeartResponse, id); break;
                case anytls::HeartResponse: break;
                default: throw std::runtime_error("Memory peer received an unexpected AnyTLS command");
            }
        }
    }
public:
    std::atomic<unsigned> authCount{0}, settingsCount{0}, finCount{0}, closes{0}, writes{0};
    std::atomic<uint32_t> lastStream{0};
    dispatch_semaphore_t fin = dispatch_semaphore_create(0), closed = dispatch_semaphore_create(0);
    Peer(dispatch_queue_t queue, std::shared_ptr<Failures> failures) : failures_(std::move(failures)) {
        queue_ = dispatch_queue_create_with_target("app.hajimi.anytls-scope-memory.peer", DISPATCH_QUEUE_SERIAL, queue);
    }
    void receive(NSUInteger maximum, HJDataReadCompletion completion) {
        auto self = shared_from_this(); HJDataReadCompletion done = [completion copy];
        post(queue_, [self, maximum, done] {
            if (self->pending_) { self->failures_->record("Memory peer concurrent native read");
                done(nil, NO, fixtureError("Concurrent memory read")); return; }
            self->maximum_ = maximum; self->pending_ = done; self->deliver();
        });
    }
    void send(NSData *payload, BOOL complete, HJStreamWriteCompletion completion) {
        auto self = shared_from_this(); auto wire = buffer(payload); HJStreamWriteCompletion done = [completion copy];
        post(queue_, [self, wire = std::move(wire), complete, done] {
            try {
                if (self->closed_ || complete) throw std::runtime_error("Memory peer was closed or half-closed");
                self->writes.fetch_add(1);
                if (wire.size() > maximumQueuedBytes - self->input_.size())
                    throw std::runtime_error("Memory peer receive limit exceeded");
                self->input_.insert(self->input_.end(), wire.begin(), wire.end()); self->consume(); done(nil);
            } catch (const std::exception &error) { self->failures_->record(error.what()); done(fixtureError(error.what())); }
        });
    }
    void cancel() {
        auto self = shared_from_this(); post(queue_, [self] {
            if (self->closed_) return;
            self->closed_ = true; self->pending_ = nil; self->input_.clear(); self->output_.clear(); self->streams_.clear();
            self->closes.fetch_add(1); dispatch_semaphore_signal(self->closed);
        });
    }
    void finishRemoteStream(uint32_t id) {
        auto self = shared_from_this(); post(queue_, [self, id] {
            self->streams_.erase(id); self->emit(anytls::FIN, id);
        });
    }
    HJCallbackStream *carrier(dispatch_queue_t queue) {
        auto self = shared_from_this();
        return [[HJCallbackStream alloc] initWithQueue:queue supportsHalfClose:NO
            receiveHandler:^(NSUInteger maximum, HJDataReadCompletion done) { self->receive(maximum, done); }
            sendHandler:^(NSData *payload, BOOL complete, HJStreamWriteCompletion done) { self->send(payload, complete, done); }
            cancelHandler:^{ self->cancel(); }];
    }
};
bool metadata(NSString *host, uint16_t port, BOOL tls, NSString *serverName, BOOL skip,
              NSArray<NSString *> *alpn, NSString *interface) {
    return [host isEqualToString:@"203.0.113.201"] && port == 443 && tls && !skip
        && [serverName isEqualToString:@"sni.anytls.scope.invalid"]
        && [alpn isEqualToArray:@[@"h2", @"http/1.1"]] && [interface isEqualToString:@"en-memory-only"];
}
struct ReadyCarrier { std::shared_ptr<Peer> peer; dispatch_block_t cancel; std::shared_ptr<std::atomic<unsigned>> tokenCalls; };
class Factory : public std::enable_shared_from_this<Factory> {
    std::mutex mutex_;
    std::vector<ReadyCarrier> carriers_;
public:
    std::shared_ptr<Failures> failures = std::make_shared<Failures>();
    std::atomic<unsigned> dials{0};
    ReadyCarrier at(size_t index) { std::lock_guard<std::mutex> lock(mutex_); return carriers_.at(index); }
    HJCppPhysicalTransportDialer dialer(dispatch_queue_t queue) {
        auto self = shared_from_this();
        return ^dispatch_block_t(NSString *host, uint16_t port, BOOL tls, NSString *serverName, BOOL skip,
            NSArray<NSString *> *alpn, NSString *interface, void (^done)(id<HJByteStream>, NSError *)) {
            if (!metadata(host, port, tls, serverName, skip, alpn, interface))
                self->failures->record("Physical hook lost numeric pin, TLS identity, ALPN or interface");
            auto peer = std::make_shared<Peer>(queue, self->failures);
            auto tokenCalls = std::make_shared<std::atomic<unsigned>>(0);
            // The pending-only token is inert after the synchronous ready handoff.
            dispatch_block_t cancel = ^{ tokenCalls->fetch_add(1); };
            { std::lock_guard<std::mutex> lock(self->mutex_); self->carriers_.push_back({peer, cancel, tokenCalls}); }
            self->dials.fetch_add(1); done(peer->carrier(queue), nil); return cancel;
        };
    }
};
class Pending : public std::enable_shared_from_this<Pending> {
    std::mutex mutex_;
    void (^ready_)(id<HJByteStream>, NSError *) = nil;
public:
    std::shared_ptr<Failures> failures = std::make_shared<Failures>();
    std::atomic<unsigned> cancels{0}, dials{0};
    dispatch_semaphore_t started = dispatch_semaphore_create(0), canceled = dispatch_semaphore_create(0);
    HJCppPhysicalTransportDialer dialer() {
        auto self = shared_from_this();
        return ^dispatch_block_t(NSString *host, uint16_t port, BOOL tls, NSString *serverName, BOOL skip,
            NSArray<NSString *> *alpn, NSString *interface, void (^done)(id<HJByteStream>, NSError *)) {
            if (!metadata(host, port, tls, serverName, skip, alpn, interface)) self->failures->record("Pending physical metadata changed");
            { std::lock_guard<std::mutex> lock(self->mutex_); self->ready_ = [done copy]; }
            self->dials.fetch_add(1); dispatch_semaphore_signal(self->started);
            // Hold the native acknowledgment deliberately, then inject a late
            // ready result after the real bridge has canceled its operation.
            return ^{ self->cancels.fetch_add(1); dispatch_semaphore_signal(self->canceled); };
        };
    }
    void deliver(id<HJByteStream> stream) {
        void (^ready)(id<HJByteStream>, NSError *);
        { std::lock_guard<std::mutex> lock(mutex_); ready = ready_; ready_ = nil; }
        expect(ready != nil, "Pending physical callback was not retained"); ready(stream, nil);
    }
};
NSData *configuration(NSString *name) {
    NSError *error = nil;
    NSData *result = [NSJSONSerialization dataWithJSONObject:@{@"type":@"anytls", @"name":name,
        @"host":@"original.anytls.scope.invalid", @"connectHost":@"203.0.113.201", @"port":@443,
        @"parameters":@{@"password":@"password", @"sni":@"sni.anytls.scope.invalid", @"alpn":@"h2,http/1.1"}}
        options:0 error:&error];
    expect(result && !error, "AnyTLS memory configuration encoding failed"); return result;
}
HJCppProtocolClient *client(NSString *name, dispatch_queue_t queue, HJCppPhysicalTransportDialer dialer, bool scoped, bool prepared=false) {
    NSError *error = nil; HJCppProtocolClient *result = nil;
    if(prepared){
        HJCppScopedPreparedTransportDialer carrier=^dispatch_block_t(NSUUID *scope,void (^done)(id<HJByteStream>,NSError *)){
            if(scope){done(nil,fixtureError("AnyTLS prepared carrier lost shared factory identity"));return ^{};}
            return dialer(@"203.0.113.201",443,YES,@"sni.anytls.scope.invalid",NO,@[@"h2",@"http/1.1"],@"en-memory-only",done);
        };
        result=[[HJCppProtocolClient alloc]initWithConfiguration:configuration(name) interfaceName:@"en-memory-only"
            queue:queue preparedTransportDialer:nil scopedPreparedTransportDialer:carrier scopedPhysicalTransportDialer:nil error:&error];
    }else if (scoped) {
        HJCppScopedPhysicalTransportDialer physical = ^dispatch_block_t(NSString *host, uint16_t port, BOOL tls,
            NSString *serverName, BOOL skip, NSArray<NSString *> *alpn, NSString *interface, NSUUID *scope,
            void (^done)(id<HJByteStream>, NSError *)) {
            if (scope) { done(nil, fixtureError("AnyTLS lost its shared physical factory scope")); return ^{}; }
            return dialer(host, port, tls, serverName, skip, alpn, interface, done);
        };
        result = [[HJCppProtocolClient alloc] initWithConfiguration:configuration(name) interfaceName:@"en-memory-only"
            queue:queue preparedTransportDialer:nil scopedPhysicalTransportDialer:physical error:&error];
    } else {
        result = [[HJCppProtocolClient alloc] initWithConfiguration:configuration(name) interfaceName:@"en-memory-only"
            queue:queue preparedTransportDialer:nil physicalTransportDialer:dialer error:&error];
    }
    expect(result && !error, "AnyTLS memory client creation failed"); return result;
}
HJCppByteStream *connect(HJCppProtocolClient *value, NSString *host, dispatch_queue_t queue, bool scoped) {
    auto signal = dispatch_semaphore_create(0); __block HJCppByteStream *stream = nil; __block NSError *error = nil;
    void (^done)(HJCppByteStream *, NSError *) = ^(HJCppByteStream *result, NSError *failure) {
        stream = result; error = failure; dispatch_semaphore_signal(signal);
    };
    if (scoped) [value connectToHost:host port:443 udp:NO plainHTTP:NO callbackQueue:queue connectionScope:NSUUID.UUID completion:done];
    else [value connectToHost:host port:443 udp:NO plainHTTP:NO completion:done];
    wait(signal, "AnyTLS logical connect timed out"); expect(stream && !error, "AnyTLS logical connect failed"); return stream;
}
void echo(HJCppByteStream *stream, const std::string &value) {
    auto sent = dispatch_semaphore_create(0); __block NSError *sendError = nil;
    [stream sendData:nativeData(bytes(value)) completion:^(NSError *error) { sendError = error; dispatch_semaphore_signal(sent); }];
    wait(sent, "AnyTLS logical write timed out"); expect(!sendError, "AnyTLS logical write failed");
    Buffer received;
    while (received.size() < value.size()) {
        auto read = dispatch_semaphore_create(0); __block NSData *payload = nil; __block NSError *error = nil; __block BOOL eof = NO;
        [stream receiveDataWithMaximum:std::min<size_t>(3, value.size() - received.size())
            completion:^(NSData *result, BOOL ended, NSError *failure) { payload = result; eof = ended; error = failure; dispatch_semaphore_signal(read); }];
        wait(read, "AnyTLS logical echo timed out"); expect(!error && !eof && payload.length, "AnyTLS logical echo closed unexpectedly");
        const auto part = buffer(payload); received.insert(received.end(), part.begin(), part.end());
    }
    expect(received == bytes(value), "AnyTLS logical echo payload changed");
}
void run(dispatch_queue_t queue, bool scoped, bool prepared=false) {
    auto factory = std::make_shared<Factory>(); auto owner = client(@"ready-anytls-scope", queue, factory->dialer(queue), scoped, prepared);
    auto first = connect(owner, @"first.application.invalid", queue, scoped); auto ready = factory->at(0);
    echo(first, "first"); expect(factory->dials.load() == 1 && ready.peer->authCount.load() == 1, "First AnyTLS carrier was not authenticated once");
    ready.cancel(); ready.cancel(); echo(first, "after-ready-cancel");
    expect(ready.peer->closes.load() == 0, "A completed physical cancel closed the ready AnyTLS carrier");

    // The current pool reuses idle sessions, not two simultaneously-active
    // logical streams. A remote FIN gives an exact acknowledgment that the
    // first session is idle, with no sleeps or queue-drain timing assumptions.
    auto ended = dispatch_semaphore_create(0); __block BOOL eof = NO; __block NSError *endError = nil; __block NSUInteger tail = 0;
    [first receiveDataWithMaximum:1 completion:^(NSData *payload, BOOL finished, NSError *error) {
        eof = finished; endError = error; tail = payload.length; dispatch_semaphore_signal(ended);
    }];
    ready.peer->finishRemoteStream(1); wait(ended, "AnyTLS remote FIN was not delivered");
    expect(eof && !endError && !tail, "AnyTLS remote FIN changed logical EOF");
    auto survivor = connect(owner, @"second.application.invalid", queue, scoped);
    expect(factory->dials.load() == 1 && ready.peer->lastStream.load() == 2 && ready.peer->settingsCount.load() == 1,
        "The second logical stream did not reuse its authenticated idle carrier");
    [first cancel]; [first cancel]; first = nil;
    echo(survivor, "after-old-logical-cancel"); expect(ready.peer->closes.load() == 0, "Old wrapper cancellation closed the reused carrier");

    auto udpReady = dispatch_semaphore_create(0), udpReply = dispatch_semaphore_create(0), udpSent = dispatch_semaphore_create(0);
    __block HJCppDatagramSession *udp = nil; __block NSError *udpError = nil; __block NSError *udpSendError = nil;
    __block NSString *replyHost = nil; __block uint16_t replyPort = 0; __block NSData *replyPayload = nil;
    auto udpFailures = std::make_shared<std::atomic<unsigned>>(0);
    HJCppPacketHandler receive = ^(NSString *host, uint16_t port, NSData *payload) {
        replyHost = host; replyPort = port; replyPayload = payload; dispatch_semaphore_signal(udpReply);
    };
    HJStreamWriteCompletion failedUDP = ^(NSError *) { udpFailures->fetch_add(1); dispatch_semaphore_signal(udpReply); };
    void (^createdUDP)(HJCppDatagramSession *, NSError *) = ^(HJCppDatagramSession *result, NSError *error) {
        udp = result; udpError = error; dispatch_semaphore_signal(udpReady);
    };
    if (scoped) [owner createDatagramSessionWithCallbackQueue:queue connectionScope:NSUUID.UUID receive:receive failure:failedUDP completion:createdUDP];
    else [owner createDatagramSessionWithReceive:receive failure:failedUDP completion:createdUDP];
    wait(udpReady, "AnyTLS UoT session create timed out"); expect(udp && !udpError && factory->dials.load() == 2,
        "An active logical stream was incorrectly reused for another active UoT session");
    auto udpCarrier = factory->at(1);
    [udp sendPayload:nativeData(bytes("udp-memory-query")) host:@"dns.scope.invalid" port:53
        completion:^(NSError *error) { udpSendError = error; dispatch_semaphore_signal(udpSent); }];
    wait(udpSent, "AnyTLS UoT write timed out"); wait(udpReply, "AnyTLS UoT reply timed out");
    expect(!udpSendError && !udpFailures->load() && [replyHost isEqualToString:@"dns.scope.invalid"] && replyPort == 53
        && buffer(replyPayload) == bytes("udp-memory-query"), "AnyTLS UoT destination or echo payload changed");
    [udp cancel]; [udp cancel]; wait(udpCarrier.peer->fin, "Closing UoT did not close its own logical stream");
    echo(survivor, "after-udp-cancel");
    expect(ready.peer->closes.load() == 0 && udpCarrier.peer->closes.load() == 0 && udpFailures->load() == 0,
        "A logical/UoT cancellation reset ready AnyTLS sessions");

    // A different factory's pending client must not reset this ready client's
    // AnyTLS pool. Its late native ready value is closed before any auth write.
    auto pending = std::make_shared<Pending>(); auto pendingOwner = client(@"pending-anytls-scope", queue, pending->dialer(), scoped, prepared);
    auto failed = dispatch_semaphore_create(0); auto callbacks = std::make_shared<std::atomic<unsigned>>(0);
    auto validFailure = std::make_shared<std::atomic<bool>>(true);
    void (^pendingReady)(HJCppByteStream *, NSError *) = ^(HJCppByteStream *stream, NSError *error) {
        if (stream || !error) validFailure->store(false); callbacks->fetch_add(1); dispatch_semaphore_signal(failed);
    };
    if (scoped) [pendingOwner connectToHost:@"pending.application.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:queue connectionScope:NSUUID.UUID completion:pendingReady];
    else [pendingOwner connectToHost:@"pending.application.invalid" port:443 udp:NO plainHTTP:NO completion:pendingReady];
    wait(pending->started, "Pending AnyTLS physical hook did not start"); [pendingOwner cancel]; [pendingOwner cancel];
    wait(failed, "Pending AnyTLS logical callback did not resolve"); wait(pending->canceled, "Pending physical attempt was not canceled");
    auto late = std::make_shared<Peer>(queue, pending->failures); pending->deliver(late->carrier(queue));
    wait(late->closed, "Late native AnyTLS carrier was not closed");
    expect(pending->dials.load() == 1 && pending->cancels.load() == 1 && callbacks->load() == 1 && validFailure->load()
        && late->closes.load() == 1 && late->writes.load() == 0, "Pending cancel or late-result ownership was not exactly once");
    echo(survivor, "after-other-client-cancel");
    expect(ready.peer->closes.load() == 0 && factory->dials.load() == 2, "Canceling a pending factory reset another ready client's pool");
    [udp cancel]; udp = nil; [survivor cancel]; [owner cancel]; [owner cancel];
    wait(ready.peer->closed, "Ready client teardown did not close its first carrier");
    wait(udpCarrier.peer->closed, "Ready client teardown did not close its UoT carrier");
    expect(ready.peer->closes.load() == 1 && udpCarrier.peer->closes.load() == 1 && ready.tokenCalls->load() == 2
        && udpCarrier.tokenCalls->load() == 0, "Client teardown re-canceled delivered physical attempts");
    factory->failures->check(); pending->failures->check();
}
}
int main(int argc, char **argv) {
    @autoreleasepool {
        try {
            expect(argc == 1 || (argc == 2 && std::string(argv[1]) == "memory"), "Only the memory selector is supported");
            auto queue = dispatch_queue_create("app.hajimi.anytls-scope-memory.output", DISPATCH_QUEUE_SERIAL);
            run(queue, false); run(queue, true); run(queue, true, true);
            std::printf("C++ AnyTLS bridge scope memory tests passed (%u checks)\n", checks.load());
            return 0;
        } catch (const std::exception &error) { std::fprintf(stderr, "AnyTLS bridge scope memory test failed: %s\n", error.what()); return 1; }
    }
}
