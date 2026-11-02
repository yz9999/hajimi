#import <HajimiCXXProtocolBridge.h>
#include "Runtime.hpp"
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

// All physical transports below are HJCallbackStream memory peers. The
// documentation-range address and nonexistent interface are metadata only;
// this fixture never creates a socket, resolves a name or evaluates TLS trust.
using namespace hajimi;
namespace {
unsigned checks = 0;
char deliveryKey, transportMarker, dnsMarker, webMarker;
void expect(bool value, const char *message) {
    ++checks; if (!value) throw std::runtime_error(message);
}
void wait(dispatch_semaphore_t signal, const char *message) {
    expect(dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0, message);
}
NSData *nsdata(const Buffer &value) { return [NSData dataWithBytes:value.data() length:value.size()]; }
Buffer buffer(NSData *value) {
    if (!value.length) return {};
    auto start = static_cast<const uint8_t *>(value.bytes); return {start, start + value.length};
}
dispatch_queue_t queue(const char *label, qos_class_t qos, void *marker) {
    auto value = dispatch_queue_create(label, dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, qos, 0));
    dispatch_queue_set_specific(value, &deliveryKey, marker, nullptr); return value;
}
struct HeldQueue {
    dispatch_semaphore_t release = dispatch_semaphore_create(0);
    bool released = false;
    explicit HeldQueue(dispatch_queue_t value) {
        auto entered = dispatch_semaphore_create(0); auto resume = release;
        dispatch_async(value, ^{
            dispatch_semaphore_signal(entered);
            dispatch_semaphore_wait(resume, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        });
        wait(entered, "Caller queue fixture never became busy");
    }
    void resume() { if (!released) { released = true; dispatch_semaphore_signal(release); } }
    ~HeldQueue() { resume(); }
};
struct CallbackLog {
    std::atomic<unsigned> count{0}; std::atomic<bool> valid{true};
    void record(void *marker, NSError *error, bool expectingError = false) {
        if (dispatch_get_specific(&deliveryKey) != marker || bool(error) != expectingError) valid = false;
        ++count;
    }
};
struct Peer : std::enable_shared_from_this<Peer> {
    std::string type;
    std::mutex lock; Buffer bytes; bool initial = true;
    HJDataReadCompletion pending = nil; NSUInteger maximum = 0;
    std::atomic<unsigned> cancellations{0};
    dispatch_semaphore_t payloadWritten = dispatch_semaphore_create(0);
    dispatch_semaphore_t readPending = dispatch_semaphore_create(0);
    dispatch_semaphore_t closed = dispatch_semaphore_create(0);
    explicit Peer(std::string value) : type(std::move(value)) {}
    HJCallbackStream *native(dispatch_queue_t transport) {
        auto self = shared_from_this();
        return [[HJCallbackStream alloc] initWithQueue:transport supportsHalfClose:YES
            receiveHandler:^(NSUInteger limit, HJDataReadCompletion done) { self->read(limit, done); }
            sendHandler:^(NSData *payload, BOOL complete, HJStreamWriteCompletion done) { self->write(payload, complete, done); }
            cancelHandler:^{ ++self->cancellations; dispatch_semaphore_signal(self->closed); }];
    }
    void read(NSUInteger limit, HJDataReadCompletion done) {
        Buffer out;
        {
            std::lock_guard<std::mutex> guard(lock);
            if (bytes.empty()) { pending = [done copy]; maximum = limit; dispatch_semaphore_signal(readPending); return; }
            auto count = std::min<size_t>(bytes.size(), limit);
            out.assign(bytes.begin(), bytes.begin() + count); bytes.erase(bytes.begin(), bytes.begin() + count);
        }
        done(nsdata(out), NO, nil);
    }
    void write(NSData *payload, BOOL complete, HJStreamWriteCompletion done) {
        HJDataReadCompletion read = nil; Buffer out; bool applicationPayload = false;
        {
            std::lock_guard<std::mutex> guard(lock);
            if (initial) {
                initial = false;
                if (type == "vless") bytes = {0, 0};
            } else if (!complete) {
                auto value = buffer(payload); bytes.insert(bytes.end(), value.begin(), value.end()); applicationPayload = true;
            }
            if (pending && !bytes.empty()) {
                read = pending; pending = nil;
                auto count = std::min<size_t>(bytes.size(), maximum);
                out.assign(bytes.begin(), bytes.begin() + count); bytes.erase(bytes.begin(), bytes.begin() + count);
            }
        }
        done(nil); if (read) read(nsdata(out), NO, nil);
        if (applicationPayload) dispatch_semaphore_signal(payloadWritten);
    }
    void failPendingRead() {
        HJDataReadCompletion read = nil;
        { std::lock_guard<std::mutex> guard(lock); read = pending; pending = nil; }
        expect(read != nil, "Memory peer had no read to fail");
        read(nil, NO, [NSError errorWithDomain:@"memory-scheduling" code:1 userInfo:nil]);
    }
};
struct Factory : std::enable_shared_from_this<Factory> {
    dispatch_queue_t transport;
    std::string type;
    std::mutex lock; std::vector<std::shared_ptr<Peer>> peers;
    std::atomic<bool> valid{true};
    Factory(dispatch_queue_t value, std::string protocol) : transport(value), type(std::move(protocol)) {}
    HJCppPhysicalTransportDialer dialer() {
        auto self = shared_from_this();
        return ^dispatch_block_t(NSString *host, uint16_t port, BOOL tls, NSString *serverName, BOOL skip,
            NSArray<NSString *> *alpn, NSString *interface, void (^done)(id<HJByteStream>, NSError *)) {
            if (dispatch_get_specific(&deliveryKey) != &transportMarker || ![host isEqualToString:@"203.0.113.41"]
                || port != 443 || tls != (self->type == "trojan") || skip || alpn.count
                || ![serverName isEqualToString:@"identity.schedule.invalid"]
                || ![interface isEqualToString:@"en-memory-scheduling"]) self->valid = false;
            auto peer = std::make_shared<Peer>(self->type);
            { std::lock_guard<std::mutex> guard(self->lock); self->peers.push_back(peer); }
            done(peer->native(self->transport), nil);
            return ^{}; // A ready physical attempt's cancel token is a no-op.
        };
    }
    std::shared_ptr<Peer> peer(size_t index) { std::lock_guard<std::mutex> guard(lock); return peers.at(index); }
    size_t count() { std::lock_guard<std::mutex> guard(lock); return peers.size(); }
};
NSData *configuration(NSString *type) {
    return [NSJSONSerialization dataWithJSONObject:@{@"type":type, @"name":@"memory-scheduling",
        @"host":@"node.schedule.invalid", @"connectHost":@"203.0.113.41", @"port":@443,
        @"parameters":@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff", @"password":@"memory-only",
            @"sni":@"identity.schedule.invalid"}} options:0 error:nil];
}
HJCppProtocolClient *client(NSString *type, dispatch_queue_t transport, HJCppPhysicalTransportDialer physical) {
    NSError *error = nil;
    auto result = [[HJCppProtocolClient alloc] initWithConfiguration:configuration(type)
        interfaceName:@"en-memory-scheduling" queue:transport preparedTransportDialer:nil physicalTransportDialer:physical error:&error];
    expect(result && !error, "Memory scheduling client construction failed"); return result;
}
HJCppByteStream *connect(HJCppProtocolClient *value, dispatch_queue_t output, void *marker) {
    auto signal = dispatch_semaphore_create(0); auto log = std::make_shared<CallbackLog>();
    __block HJCppByteStream *stream = nil;
    [value connectToHost:@"destination.schedule.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:output
        completion:^(HJCppByteStream *result, NSError *error) {
            log->record(marker, error); stream = result; dispatch_semaphore_signal(signal);
        }];
    wait(signal, "Unrelated connection stalled behind the first callback queue");
    expect(stream && log->valid && log->count == 1, "Connection callback used the wrong queue/result"); return stream;
}
void echo(HJCppByteStream *stream, void *marker, const Buffer &payload) {
    auto written = dispatch_semaphore_create(0), received = dispatch_semaphore_create(0);
    auto log = std::make_shared<CallbackLog>(); auto valid = std::make_shared<std::atomic<bool>>(true);
    [stream receiveDataWithMaximum:65536 completion:^(NSData *value, BOOL eof, NSError *error) {
        log->record(marker, error); if (eof || buffer(value) != payload) *valid = false; dispatch_semaphore_signal(received);
    }];
    [stream sendData:nsdata(payload) completion:^(NSError *error) { log->record(marker, error); dispatch_semaphore_signal(written); }];
    wait(written, "Unrelated write stalled behind the first caller"); wait(received, "Unrelated read stalled behind the first caller");
    expect(log->valid && log->count == 2 && *valid, "Stream read/write lost caller queue or payload");
}
void streamIsolation(NSString *type) {
    auto transport = queue("memory.protocol.transport", QOS_CLASS_USER_INITIATED, &transportMarker);
    auto dns = queue("memory.first.dns", QOS_CLASS_UTILITY, &dnsMarker);
    auto web = queue("memory.next.web", QOS_CLASS_USER_INITIATED, &webMarker);
    auto factory = std::make_shared<Factory>(transport, std::string(type.UTF8String));
    auto value = client(type, transport, factory->dialer());
    auto first = connect(value, dns, &dnsMarker);
    auto written = dispatch_semaphore_create(0), received = dispatch_semaphore_create(0);
    auto log = std::make_shared<CallbackLog>(); auto valid = std::make_shared<std::atomic<bool>>(true);
    Buffer payload{'f','i','r','s','t'};
    HeldQueue busy(dns);
    [first receiveDataWithMaximum:65536 completion:^(NSData *result, BOOL eof, NSError *error) {
        log->record(&dnsMarker, error); if (eof || buffer(result) != payload) *valid = false; dispatch_semaphore_signal(received);
    }];
    [first sendData:nsdata(payload) completion:^(NSError *error) { log->record(&dnsMarker, error); dispatch_semaphore_signal(written); }];
    wait(factory->peer(0)->payloadWritten, "Native I/O inherited the blocked DNS caller queue");
    auto start = std::chrono::steady_clock::now();
    auto second = connect(value, web, &webMarker); echo(second, &webMarker, {'w','e','b'});
    auto milliseconds = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    expect(log->count == 0 && factory->count() == 2 && factory->valid,
        "The blocked caller received callbacks, split client ownership, or changed physical metadata");
    busy.resume(); wait(written, "Original write callback disappeared"); wait(received, "Original read callback disappeared");
    expect(log->valid && log->count == 2 && *valid, "Delayed original callbacks changed identity/payload/count");

    // Cancellation must close physical I/O without waiting for a busy logical
    // output queue, and must not close a sibling session of this same client.
    auto peer = factory->peer(0);
    while (dispatch_semaphore_wait(peer->readPending, DISPATCH_TIME_NOW) == 0) {}
    HeldQueue cancelBusy(dns); auto canceled = dispatch_semaphore_create(0); auto cancelLog = std::make_shared<CallbackLog>();
    [first receiveDataWithMaximum:64 completion:^(NSData *, BOOL, NSError *error) {
        cancelLog->record(&dnsMarker, error, true); dispatch_semaphore_signal(canceled);
    }];
    wait(peer->readPending, "Cancellation fixture had no pending native read");
    [first cancel]; wait(peer->closed, "Native cancellation waited for the logical caller queue");
    echo(second, &webMarker, {'s','i','b','l','i','n','g'});
    expect(cancelLog->count == 0, "Canceled read escaped its caller queue");
    cancelBusy.resume(); wait(canceled, "Canceled read callback missing");
    expect(cancelLog->valid && cancelLog->count == 1 && peer->cancellations == 1, "Cancellation acknowledgment was not exactly once/on caller");

    auto immediate = dispatch_semaphore_create(0); auto errorLog = std::make_shared<CallbackLog>();
    [first receiveDataWithMaximum:0 completion:^(NSData *, BOOL, NSError *error) {
        errorLog->record(&dnsMarker, error, true); dispatch_semaphore_signal(immediate);
    }];
    wait(immediate, "Invalid read did not acknowledge on caller queue");
    [first sendData:nsdata({'x'}) completion:^(NSError *error) { errorLog->record(&dnsMarker, error, true); dispatch_semaphore_signal(immediate); }];
    wait(immediate, "Closed write did not acknowledge on caller queue");
    expect(errorLog->valid && errorLog->count == 2, "Immediate validation/closed errors used the transport queue");
    auto fin = dispatch_semaphore_create(0); auto finLog = std::make_shared<CallbackLog>();
    [second sendContent:nil isComplete:YES completion:^(NSError *error) { finLog->record(&webMarker, error); dispatch_semaphore_signal(fin); }];
    wait(fin, "Half-close callback missing"); expect(finLog->valid && finLog->count == 1, "Half-close used a different caller queue");
    [second cancel]; [value cancel]; wait(factory->peer(1)->closed, "Sibling cleanup lost physical ownership");
    std::cout << type.UTF8String << " blocked-first-caller connect+echo: " << milliseconds << "ms\n";
}
struct DatagramLog {
    std::shared_ptr<CallbackLog> callbacks = std::make_shared<CallbackLog>();
    dispatch_semaphore_t received = dispatch_semaphore_create(0), failure = dispatch_semaphore_create(0);
    void *marker; std::atomic<bool> valid{true};
    explicit DatagramLog(void *value) : marker(value) {}
};
HJCppDatagramSession *datagram(HJCppProtocolClient *value, dispatch_queue_t output, std::shared_ptr<DatagramLog> log) {
    auto ready = dispatch_semaphore_create(0); __block HJCppDatagramSession *session = nil;
    [value createDatagramSessionWithCallbackQueue:output receive:^(NSString *host, uint16_t port, NSData *payload) {
        log->callbacks->record(log->marker, nil);
        if (![host isEqualToString:@"198.51.100.7"] || port != 53 || buffer(payload) != Buffer({'d','n','s'})) log->valid = false;
        dispatch_semaphore_signal(log->received);
    } failure:^(NSError *error) {
        log->callbacks->record(log->marker, error, true); dispatch_semaphore_signal(log->failure);
    } completion:^(HJCppDatagramSession *result, NSError *error) {
        log->callbacks->record(log->marker, error); session = result; dispatch_semaphore_signal(ready);
    }];
    wait(ready, "Datagram creation inherited another caller queue");
    expect(session && log->callbacks->valid && log->callbacks->count == 1, "Datagram creation used wrong queue/result"); return session;
}
void send(HJCppDatagramSession *session, std::shared_ptr<DatagramLog> log, dispatch_semaphore_t written) {
    [session sendPayload:nsdata({'d','n','s'}) host:@"198.51.100.7" port:53 completion:^(NSError *error) {
        log->callbacks->record(log->marker, error); dispatch_semaphore_signal(written);
    }];
}
void datagramIsolation(NSString *type) {
    auto transport = queue("memory.datagram.transport", QOS_CLASS_USER_INITIATED, &transportMarker);
    auto dns = queue("memory.datagram.first", QOS_CLASS_UTILITY, &dnsMarker);
    auto web = queue("memory.datagram.next", QOS_CLASS_USER_INITIATED, &webMarker);
    auto factory = std::make_shared<Factory>(transport, std::string(type.UTF8String));
    auto value = client(type, transport, factory->dialer());
    auto one = std::make_shared<DatagramLog>(&dnsMarker), two = std::make_shared<DatagramLog>(&webMarker);
    auto first = datagram(value, dns, one);
    expect(factory->count() == 0, "Queue separation changed lazy datagram physical setup");
    auto firstWrite = dispatch_semaphore_create(0), secondWrite = dispatch_semaphore_create(0);
    HeldQueue busy(dns); send(first, one, firstWrite);
    auto second = datagram(value, web, two); send(second, two, secondWrite);
    wait(secondWrite, "Unrelated UDP write stalled"); wait(two->received, "Unrelated UDP receive stalled");
    expect(one->callbacks->count == 1 && factory->count() == 2 && factory->valid,
        "UDP callbacks escaped the busy caller or altered client-wide physical factory identity");
    busy.resume(); wait(firstWrite, "First UDP write callback disappeared"); wait(one->received, "First UDP receive callback disappeared");
    expect(one->callbacks->valid && one->callbacks->count == 3 && one->valid && two->callbacks->valid && two->valid,
        "UDP receive/send delivery lost caller queue, payload or target");
    auto firstPeer = factory->peer(0);
    // readPending belongs to the first flow; after a round trip its continued
    // receive loop must be waiting on the same ready physical carrier.
    wait(firstPeer->readPending, "UDP failure fixture never awaited another packet");
    HeldQueue failureBusy(dns); firstPeer->failPendingRead();
    wait(firstPeer->closed, "UDP native failure waited for logical delivery");
    send(second, two, secondWrite); wait(secondWrite, "One flow's failure closed another logical session");
    wait(two->received, "Sibling UDP downlink stopped after unrelated failure");
    expect(one->callbacks->count == 3, "UDP failure escaped the original output queue");
    failureBusy.resume(); wait(one->failure, "UDP failure callback disappeared");
    expect(one->callbacks->valid && one->callbacks->count == 4 && factory->count() == 2,
        "UDP failure delivery or ready connection reuse changed");
    [first cancel]; [second cancel]; [value cancel]; wait(factory->peer(1)->closed, "UDP sibling cleanup leaked carrier");
}
void pendingCancellation() {
    auto transport = queue("memory.cancel.transport", QOS_CLASS_USER_INITIATED, &transportMarker);
    auto dns = queue("memory.cancel.first", QOS_CLASS_UTILITY, &dnsMarker);
    auto web = queue("memory.cancel.next", QOS_CLASS_USER_INITIATED, &webMarker);
    auto started = dispatch_semaphore_create(0), done = dispatch_semaphore_create(0);
    auto callbacks = std::make_shared<CallbackLog>(); auto cancels = std::make_shared<std::atomic<unsigned>>(0);
    auto metadata = std::make_shared<std::atomic<bool>>(true);
    struct PendingDials { void (^first)(id<HJByteStream>, NSError *) = nil;
        void (^second)(id<HJByteStream>, NSError *) = nil; unsigned index = 0; };
    auto pending = std::make_shared<PendingDials>();
    auto value = client(@"vless", transport, ^dispatch_block_t(NSString *, uint16_t, BOOL, NSString *, BOOL,
        NSArray<NSString *> *, NSString *, void (^ready)(id<HJByteStream>, NSError *)) {
        if (dispatch_get_specific(&deliveryKey) != &transportMarker || pending->index >= 2) *metadata = false;
        if (pending->index == 0) pending->first = [ready copy];
        else if (pending->index == 1) pending->second = [ready copy];
        ++pending->index; dispatch_semaphore_signal(started);
        // A native cancel request does not fabricate physical completion.
        return ^{ ++*cancels; };
    });
    HeldQueue busy(dns);
    [value connectToHost:@"first.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:dns completion:^(HJCppByteStream *stream, NSError *error) {
        callbacks->record(&dnsMarker, error, true); if (stream) *metadata = false; dispatch_semaphore_signal(done);
    }];
    [value connectToHost:@"second.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:web completion:^(HJCppByteStream *stream, NSError *error) {
        callbacks->record(&webMarker, error, true); if (stream) *metadata = false; dispatch_semaphore_signal(done);
    }];
    wait(started, "First pending physical attempt never started"); wait(started, "Second pending physical attempt never started");
    [value cancel]; [value cancel]; wait(done, "Client cancellation was coupled to its first caller queue");
    expect(callbacks->count == 1 && callbacks->valid && *cancels == 2 && *metadata,
        "Client cancel did not separate logical delivery from exactly-once physical cancellation");
    busy.resume(); wait(done, "Canceled first connection callback missing");
    expect(callbacks->count == 2 && callbacks->valid, "Canceled connections lost original caller identity");
    for (unsigned i = 0; i < 2; ++i) {
        auto late = i == 0 ? pending->first : pending->second;
        auto peer = std::make_shared<Peer>("vless"); auto carrier = peer->native(transport);
        late(carrier, nil); wait(peer->closed, "Canceled client leaked a late physical result");
        late(carrier, nil); late(nil, [NSError errorWithDomain:@"late-memory" code:1 userInfo:nil]);
        expect(peer->cancellations == 1, "Late/duplicate physical readiness closed a carrier more than once");
    }
    dispatch_sync(transport, ^{}); dispatch_sync(dns, ^{}); dispatch_sync(web, ^{});
    expect(callbacks->count == 2 && callbacks->valid && *cancels == 2, "Late acknowledgment repeated logical cancellation");
    auto rejected = dispatch_semaphore_create(0); auto closedLog = std::make_shared<CallbackLog>();
    [value connectToHost:@"closed.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:web completion:^(HJCppByteStream *stream, NSError *error) {
        closedLog->record(&webMarker, error, true); if (stream) *metadata = false; dispatch_semaphore_signal(rejected);
    }];
    wait(rejected, "Closed client did not reject on the new caller queue");
    [value createDatagramSessionWithCallbackQueue:dns receive:^(NSString *, uint16_t, NSData *) { *metadata = false; }
        failure:^(NSError *) { *metadata = false; } completion:^(HJCppDatagramSession *session, NSError *error) {
            closedLog->record(&dnsMarker, error, true); if (session) *metadata = false; dispatch_semaphore_signal(rejected);
        }];
    wait(rejected, "Closed client UDP rejection missed its caller queue");
    expect(closedLog->valid && closedLog->count == 2 && *metadata, "Closed client rejection used stale/default output");
}
void legacyDefaultQueue() {
    auto transport = queue("memory.legacy.transport", QOS_CLASS_USER_INITIATED, &transportMarker);
    auto factory = std::make_shared<Factory>(transport, "vless"); auto value = client(@"vless", transport, factory->dialer());
    auto signal = dispatch_semaphore_create(0); auto log = std::make_shared<CallbackLog>();
    __block HJCppByteStream *stream = nil;
    [value connectToHost:@"legacy.invalid" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *result, NSError *error) {
        log->record(&transportMarker, error); stream = result; dispatch_semaphore_signal(signal);
    }];
    wait(signal, "Legacy bridge connect callback missing"); expect(stream && log->valid, "Legacy initializer default queue changed");
    echo(stream, &transportMarker, {'l','e','g','a','c','y'}); [stream cancel]; [value cancel];
    auto udpLog = std::make_shared<CallbackLog>();
    [value createDatagramSessionWithReceive:^(NSString *, uint16_t, NSData *) { udpLog->valid = false; }
        failure:^(NSError *) { udpLog->valid = false; } completion:^(HJCppDatagramSession *session, NSError *error) {
            udpLog->record(&transportMarker, error, true); if (session) udpLog->valid = false; dispatch_semaphore_signal(signal);
        }];
    wait(signal, "Legacy default UDP callback missing"); expect(udpLog->valid && udpLog->count == 1, "Legacy UDP output queue changed");
}
}
int main() {
    @autoreleasepool {
        try {
            for (NSString *type in @[@"vless", @"trojan"]) { streamIsolation(type); datagramIsolation(type); }
            pendingCancellation(); legacyDefaultQueue();
            std::cout << "C++ stable transport/per-session callback queues: " << checks << " checks passed (memory-only)\n";
            return 0;
        } catch (const std::exception &error) {
            std::cerr << "C++ scheduling fixture failed: " << error.what() << '\n'; return 1;
        }
    }
}
