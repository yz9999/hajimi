// clang++ -fobjc-arc -fblocks -std=c++17 -mmacosx-version-min=13.0 \
//   -I Sources/HajimiProxyRuntime/include \
//   Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm SmokeTests/NativeRuntimeMain.mm \
//   -framework Foundation -framework Network -framework Security -o /tmp/hajimi-native-runtime
#import "HajimiProxyRuntime.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static void Check(bool value, const char *message) {
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
static void Wait(dispatch_semaphore_t semaphore, const char *message) {
    Check(dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0, message);
}
static NSData *Pattern(NSUInteger size, unsigned salt) {
    NSMutableData *data = [NSMutableData dataWithLength:size];
    auto *bytes = static_cast<uint8_t *>(data.mutableBytes);
    for (NSUInteger i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>((i * 31 + salt) & 255);
    return [data copy];
}
static NSData *Joined(NSData *a, NSData *b) {
    NSMutableData *data = [a mutableCopy]; [data appendData:b]; return data;
}

@interface TestPeer : NSObject
@property(nonatomic, strong) HJCallbackStream *stream;
@property(nonatomic, strong) NSData *input;
@property(nonatomic, strong) NSMutableData *output;
@property(nonatomic) NSUInteger offset;
@property(nonatomic) NSUInteger reads;
@property(nonatomic) NSUInteger writes;
@property(nonatomic) NSUInteger activeWrites;
@property(nonatomic) NSUInteger maximumWrites;
@property(nonatomic) NSUInteger finals;
@property(nonatomic) NSUInteger cancels;
@property(nonatomic) unsigned emptyReads;
@property(nonatomic) BOOL holdEOF;
@property(nonatomic) BOOL oversizedRead;
@property(nonatomic, copy) HJDataReadCompletion pendingRead;
@property(nonatomic, weak) TestPeer *other;
@end
@implementation TestPeer
@end

static TestPeer *Peer(dispatch_queue_t queue, NSData *input, BOOL holdEOF,
                      NSTimeInterval writeDelay, dispatch_semaphore_t cancelled) {
    TestPeer *peer = [[TestPeer alloc] init];
    peer.input = input; peer.output = [NSMutableData data]; peer.holdEOF = holdEOF;
    __weak TestPeer *weakPeer = peer;
    peer.stream = [[HJCallbackStream alloc] initWithQueue:queue supportsHalfClose:YES
        receiveHandler:^(NSUInteger maximum, HJDataReadCompletion completion) {
            TestPeer *p = weakPeer;
            Check(p != nil, "test peer retained");
            Check(p.other.activeWrites == 0, "read scheduled before destination write completed");
            p.reads += 1;
            if (p.oversizedRead) { completion(Pattern(maximum + 1, 0), NO, nil); return; }
            if (p.emptyReads) { p.emptyReads -= 1; completion(nil, NO, nil); return; }
            if (p.offset < p.input.length) {
                NSUInteger count = std::min(maximum, p.input.length - p.offset);
                NSData *data = [p.input subdataWithRange:NSMakeRange(p.offset, count)];
                p.offset += count;
                completion(data, !p.holdEOF && p.offset == p.input.length, nil);
                // Duplicate completion must not deliver bytes twice.
                completion(data, !p.holdEOF && p.offset == p.input.length, nil);
            } else if (p.holdEOF) { p.pendingRead = completion; }
            else { completion(nil, YES, nil); }
        }
        sendHandler:^(NSData *data, BOOL final, HJStreamWriteCompletion completion) {
            TestPeer *p = weakPeer;
            p.activeWrites += 1; p.writes += 1;
            p.maximumWrites = std::max(p.maximumWrites, p.activeWrites);
            Check(p.activeWrites == 1, "more than one destination write in flight");
            if (data) [p.output appendData:data];
            if (final) { p.finals += 1; Check(p.finals == 1, "write half-closed twice"); }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                static_cast<int64_t>(writeDelay * NSEC_PER_SEC)), queue, ^{
                p.activeWrites -= 1;
                completion(nil); completion(nil);
            });
        }
        cancelHandler:^{
            TestPeer *p = weakPeer;
            p.cancels += 1;
            Check(p.cancels == 1, "transport cancelled more than once");
            p.pendingRead = nil;
            if (cancelled) dispatch_semaphore_signal(cancelled);
        }];
    return peer;
}

static void ForwardingTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.forward", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0), cancelled = dispatch_semaphore_create(0);
    TestPeer *client = Peer(queue, Pattern(240'001, 7), NO, 0.001, cancelled);
    TestPeer *remote = Peer(queue, Pattern(180'003, 19), NO, 0.001, cancelled);
    client.other = remote; remote.other = client;
    NSData *clientInitial = Pattern(41'003, 23), *remoteInitial = Pattern(32'101, 11);
    __block uint64_t upload = 0, download = 0;
    __block NSUInteger reports = 0, completions = 0;
    HJStreamPump *pump = [[HJStreamPump alloc] initWithClient:client.stream remote:remote.stream
        queue:queue chunkSize:8'192 idleTimeout:2 trafficInterval:1
        trafficHandler:^(uint64_t u, uint64_t d) { upload += u; download += d; reports += 1; }
        completion:^(NSError *error) {
            Check(error == nil, "forwarding completion error");
            Check(upload == clientInitial.length + client.input.length, "traffic flushed before completion");
            completions += 1; dispatch_semaphore_signal(done);
        }];
    [pump startWithClientInitial:clientInitial remoteInitial:remoteInitial];
    Wait(done, "forwarding completion timed out"); Wait(cancelled, "client cancellation"); Wait(cancelled, "remote cancellation");
    Check([remote.output isEqualToData:Joined(clientInitial, client.input)], "upload data/order mismatch");
    Check([client.output isEqualToData:Joined(remoteInitial, remote.input)], "download data/order mismatch");
    Check(pump.uploadedBytes == upload && pump.downloadedBytes == download, "total traffic mismatch");
    Check(reports == 1 && completions == 1, "coalesced traffic/exactly-once completion");
    Check(client.finals == 1 && remote.finals == 1, "both half closes propagated");
    Check(client.maximumWrites == 1 && remote.maximumWrites == 1, "bounded in-flight writes");
}

static void FailureTest(BOOL oversized, BOOL explicitlyCancel) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.failure", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0), cancelled = dispatch_semaphore_create(0);
    TestPeer *client = Peer(queue, [NSData data], YES, 0, cancelled);
    TestPeer *remote = Peer(queue, [NSData data], YES, 0, cancelled);
    client.other = remote; remote.other = client; client.oversizedRead = oversized;
    __block NSUInteger completions = 0;
    HJStreamPump *pump = [[HJStreamPump alloc] initWithClient:client.stream remote:remote.stream
        queue:queue chunkSize:64 idleTimeout:0.025 trafficInterval:0.01 trafficHandler:nil
        completion:^(NSError *error) {
            if (explicitlyCancel) Check(error == nil, "explicit cancellation reports no error");
            else Check([error.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                error.code == (oversized ? HJProxyRuntimeErrorContractViolation : HJProxyRuntimeErrorIdleTimeout),
                "correct idle/oversized-read error");
            completions += 1; dispatch_semaphore_signal(done);
        }];
    [pump startWithClientInitial:nil remoteInitial:nil];
    if (explicitlyCancel) { [pump cancel]; [pump cancel]; }
    Wait(done, "failure/cancellation timed out"); Wait(cancelled, "client cancellation"); Wait(cancelled, "remote cancellation");
    dispatch_sync(queue, ^{});
    Check(completions == 1, "failure completion exactly once");
    Check(pump.uploadedBytes == 0 && pump.downloadedBytes == 0, "failure does not count unwritten bytes");
}

static void EmptyReadTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.empty-read", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0), cancelled = dispatch_semaphore_create(0);
    TestPeer *client = Peer(queue, Pattern(1'027, 3), NO, 0, cancelled);
    TestPeer *remote = Peer(queue, Pattern(331, 17), NO, 0, cancelled);
    client.other = remote; remote.other = client; client.emptyReads = 5;
    HJStreamPump *pump = [[HJStreamPump alloc] initWithClient:client.stream remote:remote.stream
        queue:queue chunkSize:4 idleTimeout:2 trafficInterval:0.1 trafficHandler:nil
        completion:^(NSError *error) { Check(error == nil, "empty read retry failed"); dispatch_semaphore_signal(done); }];
    [pump startWithClientInitial:nil remoteInitial:nil];
    Wait(done, "empty read retry timed out"); Wait(cancelled, "client cancellation"); Wait(cancelled, "remote cancellation");
    Check([client.output isEqualToData:remote.input] && [remote.output isEqualToData:client.input],
          "synchronous callback/empty retry byte preservation");
}

@interface LoopbackReader : NSObject
@property(nonatomic, strong) HJNetworkStream *stream;
@property(nonatomic, strong) NSMutableData *received;
@property(nonatomic, strong) dispatch_semaphore_t done;
- (void)read;
@end
@implementation LoopbackReader
- (void)read {
    [self.stream receiveDataWithMaximum:4'096 completion:^(NSData *content, BOOL atEOF, NSError *error) {
        if (error) std::fprintf(stderr, "native read error after %lu bytes: %s (%s %ld)\n",
                                static_cast<unsigned long>(self.received.length), error.localizedDescription.UTF8String,
                                error.domain.UTF8String, static_cast<long>(error.code));
        Check(!error, "native Network.framework receive error");
        if (content) [self.received appendData:content];
        if (atEOF) dispatch_semaphore_signal(self.done); else [self read];
    }];
}
@end

static uint16_t LocalServer(NSData *expectedRequest, NSData *response, dispatch_semaphore_t done) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    Check(listener >= 0, "create local test socket");
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 && listen(listener, 1) == 0,
          "bind/listen loopback test socket");
    socklen_t length = sizeof(address);
    Check(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == 0, "discover local test port");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            int client = accept(listener, nullptr, nullptr);
            Check(client >= 0, "accept native test connection");
            close(listener);
            timeval timeout{5, 0};
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            int enabled = 1; setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
            NSMutableData *request = [NSMutableData data];
            uint8_t buffer[4'096];
            for (;;) {
                ssize_t count = read(client, buffer, sizeof(buffer));
                if (count == 0) break;
                if (count < 0 && !expectedRequest) break; // Cancellation may reset TCP.
                Check(count > 0, "native write half-close did not reach loopback server");
                [request appendBytes:buffer length:static_cast<NSUInteger>(count)];
            }
            if (expectedRequest) Check([request isEqualToData:expectedRequest], "native loopback request bytes");
            size_t offset = 0;
            while (offset < response.length) {
                ssize_t count = write(client, static_cast<const uint8_t *>(response.bytes) + offset,
                                      response.length - offset);
                Check(count > 0, "native loopback server response write"); offset += static_cast<size_t>(count);
            }
            shutdown(client, SHUT_WR); close(client);
            dispatch_semaphore_signal(done);
        }
    });
    return ntohs(address.sin_port);
}

static void SendFIN(HJNetworkStream *stream) {
    [stream sendContent:nil isComplete:YES completion:^(NSError *error) {
        Check(!error, "native TCP write half-close after compatibility queue drains");
    }];
}

static void NetworkLoopbackTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.network", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t serverDone = dispatch_semaphore_create(0), connected = dispatch_semaphore_create(0);
    NSArray<NSData *> *parts = @[Pattern(144'031, 37), Pattern(91'007, 13), Pattern(8'192, 97), Pattern(97, 11)];
    NSMutableData *request = [NSMutableData data];
    for (NSData *part in parts) [request appendData:part];
    NSData *response = Pattern(202'071, 43);
    uint16_t port = LocalServer(request, response, serverDone);
    __block HJNetworkStream *stream;
    __block NSUInteger writes = 0, submitted = 0, blockedFIN = 0;
    [HJNetworkStream connectToHost:@"127.0.0.1" port:port tls:NO serverName:nil
        skipCertificateVerification:NO alpn:@[] interfaceName:nil queue:queue timeout:2
        completion:^(HJNetworkStream *value, NSError *error) {
            Check(value != nil && error == nil, "native TCP connect"); stream = value;
            // The callback occupies the serial target. All submissions arrive
            // before the first native completion, forcing overlapping writes.
            for (NSUInteger i = 0; i < parts.count; ++i) {
                [value sendData:parts[i] completion:^(NSError *writeError) {
                    Check(!writeError && submitted == parts.count, "concurrent compatibility sends admitted");
                    Check(writes == i, "compatibility completion FIFO order");
                    writes += 1;
                    if (writes == parts.count) SendFIN(value);
                }];
                submitted += 1;
            }
            [value sendContent:nil isComplete:YES completion:^(NSError *busyError) {
                Check([busyError.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                    busyError.code == HJProxyRuntimeErrorBusy, "direct FIN remains strict during queued writes");
                blockedFIN += 1;
            }];
            dispatch_semaphore_signal(connected);
        }];
    Wait(connected, "native TCP connection timed out");
    LoopbackReader *reader = [[LoopbackReader alloc] init];
    reader.stream = stream; reader.received = [NSMutableData data]; reader.done = dispatch_semaphore_create(0);
    [reader read];
    Wait(reader.done, "native half-close response timed out"); Wait(serverDone, "native loopback server completion");
    Check([reader.received isEqualToData:response], "native read survives opposite write half-close");
    Check(writes == parts.count && blockedFIN == 1, "queued native send completions exactly once and strict FIN");
    [stream cancel];
}

static void MissingInterfaceTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.interface", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    [HJNetworkStream connectToHost:@"127.0.0.1" port:9 tls:NO serverName:nil
        skipCertificateVerification:NO alpn:@[] interfaceName:@"hajimi_missing_interface"
        queue:queue timeout:0.1 completion:^(HJNetworkStream *stream, NSError *error) {
            Check(!stream && [error.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                  error.code == HJProxyRuntimeErrorInterfaceUnavailable, "missing interface never dials unbound");
            dispatch_semaphore_signal(done);
        }];
    Wait(done, "missing interface completion");
}

static void PendingOperationCancellationTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.pending-cancel", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t started = dispatch_semaphore_create(0), finished = dispatch_semaphore_create(0);
    __block HJDataReadCompletion oldRead;
    __block HJStreamWriteCompletion oldWrite;
    __block NSUInteger readCalls = 0, writeCalls = 0, cancels = 0;
    HJCallbackStream *stream = [[HJCallbackStream alloc] initWithQueue:queue supportsHalfClose:YES
        receiveHandler:^(NSUInteger, HJDataReadCompletion done) {
            oldRead = done; dispatch_semaphore_signal(started);
        } sendHandler:^(NSData *, BOOL, HJStreamWriteCompletion done) {
            oldWrite = done; dispatch_semaphore_signal(started);
        } cancelHandler:^{ cancels += 1; }];
    [stream receiveWithMaximum:8 completion:^(dispatch_data_t, BOOL, NSError *error) {
        Check(error.code == HJProxyRuntimeErrorCancelled, "pending receive cancellation error");
        readCalls += 1; dispatch_semaphore_signal(finished);
    }];
    [stream sendContent:dispatch_data_empty isComplete:YES completion:^(NSError *error) {
        Check(error.code == HJProxyRuntimeErrorCancelled, "pending write cancellation error");
        writeCalls += 1; dispatch_semaphore_signal(finished);
    }];
    Wait(started, "read handler started"); Wait(started, "write handler started");
    [stream cancel]; [stream cancel];
    Wait(finished, "pending read cancellation"); Wait(finished, "pending write cancellation");
    // A transport may still race its old completions after cancellation.
    oldRead(Pattern(2, 0), YES, nil); oldWrite(nil);
    oldRead = nil; oldWrite = nil;
    dispatch_sync(queue, ^{});
    Check(readCalls == 1 && writeCalls == 1 && cancels == 1, "late completions after cancellation ignored");
}

static void CompatibilityLimitTest(BOOL byteLimit) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.queue-limit", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t connected = dispatch_semaphore_create(0), serverDone = dispatch_semaphore_create(0);
    NSUInteger count = byteLimit ? 8 : HJNetworkStreamMaximumQueuedRequests;
    NSMutableArray<NSData *> *parts = [NSMutableArray array];
    NSMutableData *request = [NSMutableData data];
    for (NSUInteger i = 0; i < count; ++i) {
        NSData *part = Pattern(byteLimit ? HJNetworkStreamMaximumQueuedBytes / count : 0,
                               static_cast<unsigned>(i));
        [parts addObject:part]; [request appendData:part];
    }
    NSData *response = Pattern(127, 41);
    uint16_t port = LocalServer(request, response, serverDone);
    __block HJNetworkStream *stream;
    __block NSUInteger written = 0, rejected = 0;
    [HJNetworkStream connectToHost:@"127.0.0.1" port:port tls:NO serverName:nil
        skipCertificateVerification:NO alpn:@[] interfaceName:nil queue:queue timeout:2
        completion:^(HJNetworkStream *value, NSError *error) {
            Check(value && !error, "queue-limit native connect"); stream = value;
            for (NSUInteger i = 0; i < count; ++i) {
                NSMutableData *mutablePart = [parts[i] mutableCopy];
                [value sendData:mutablePart completion:^(NSError *writeError) {
                    Check(!writeError && written == i, "accepted writes complete in FIFO order at hard limit");
                    written += 1;
                    if (written == count && rejected == 1) SendFIN(value);
                }];
                // The accepted queue must own an immutable snapshot, not this
                // caller's mutable buffer after sendData returns.
                if (mutablePart.length) std::memset(mutablePart.mutableBytes, 0xF7, mutablePart.length);
            }
            [value sendData:Pattern(1, 99) completion:^(NSError *limitError) {
                Check([limitError.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                    limitError.code == HJProxyRuntimeErrorQueueLimit, "byte/request cap rejects explicitly");
                rejected += 1;
                if (written == count && rejected == 1) SendFIN(value);
            }];
            dispatch_semaphore_signal(connected);
        }];
    Wait(connected, "queue-limit connection");
    LoopbackReader *reader = [[LoopbackReader alloc] init];
    reader.stream = stream; reader.received = [NSMutableData data]; reader.done = dispatch_semaphore_create(0);
    [reader read];
    Wait(reader.done, "queue-limit response"); Wait(serverDone, "queue-limit server completion");
    Check(written == count && rejected == 1 && [reader.received isEqualToData:response],
          "hard queue caps and immutable snapshots preserve accepted bytes");
    [stream cancel];
}

static void NativeQueuedCancellationTest(void) {
    dispatch_queue_t queue = dispatch_queue_create("hajimi.test.native-queue-cancel", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t connected = dispatch_semaphore_create(0), serverDone = dispatch_semaphore_create(0);
    dispatch_semaphore_t callbacks = dispatch_semaphore_create(0);
    uint16_t port = LocalServer(nil, [NSData data], serverDone);
    __block HJNetworkStream *stream;
    __block NSUInteger reads = 0, writes = 0;
    [HJNetworkStream connectToHost:@"127.0.0.1" port:port tls:NO serverName:nil
        skipCertificateVerification:NO alpn:@[] interfaceName:nil queue:queue timeout:2
        completion:^(HJNetworkStream *value, NSError *error) {
            Check(value && !error, "native cancellation connect"); stream = value;
            [value receiveDataWithMaximum:16 completion:^(NSData *, BOOL, NSError *readError) {
                Check([readError.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                      readError.code == HJProxyRuntimeErrorCancelled, "native pending read cancelled");
                reads += 1; dispatch_semaphore_signal(callbacks);
            }];
            for (NSUInteger i = 0; i < 8; ++i) {
                [value sendData:Pattern(262'144, static_cast<unsigned>(i)) completion:^(NSError *writeError) {
                    Check([writeError.domain isEqualToString:HJProxyRuntimeErrorDomain] &&
                          writeError.code == HJProxyRuntimeErrorCancelled && writes == i,
                          "all queued native writes cancelled once in order");
                    writes += 1; dispatch_semaphore_signal(callbacks);
                }];
            }
            [value cancel]; [value cancel];
            dispatch_semaphore_signal(connected);
        }];
    Wait(connected, "native cancellation connection");
    for (NSUInteger i = 0; i < 9; ++i) Wait(callbacks, "native queued cancellation callback");
    Wait(serverDone, "native cancelled server completion");
    Check(reads == 1 && writes == 8, "native queued cancellation completion counts");
    Check(dispatch_semaphore_wait(callbacks, DISPATCH_TIME_NOW) != 0, "no duplicate native cancellation callbacks");
    [stream sendData:Pattern(HJNetworkStreamMaximumQueuedBytes, 73) completion:^(NSError *error) {
        Check(error.code == HJProxyRuntimeErrorCancelled, "cancelled queue released all byte reservations");
        dispatch_semaphore_signal(callbacks);
    }];
    Wait(callbacks, "cancelled queue reservation accounting");
    [stream cancel];
}

int main(void) {
    @autoreleasepool {
        ForwardingTest(); FailureTest(NO, NO); FailureTest(YES, NO); FailureTest(NO, YES);
        EmptyReadTest(); NetworkLoopbackTest(); MissingInterfaceTest(); PendingOperationCancellationTest();
        CompatibilityLimitTest(YES); CompatibilityLimitTest(NO); NativeQueuedCancellationTest();
        std::puts("native runtime: bounded forwarding, ordered write FIFO/caps, immutable snapshots, cancellation, idle timeout, half-close and loopback passed");
    }
    return 0;
}
