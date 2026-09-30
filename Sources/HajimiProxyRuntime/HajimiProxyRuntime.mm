#import "HajimiProxyRuntime.h"
#import <Security/SecProtocolOptions.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <deque>
#include <limits>
#include <mutex>
#include <net/if.h>

#if !__has_feature(objc_arc)
#error HajimiProxyRuntime requires Objective-C ARC (not tracing garbage collection).
#endif

NSErrorDomain const HJProxyRuntimeErrorDomain = @"app.hajimi.native-stream";
NSUInteger const HJStreamPumpDefaultChunkSize = 65'536;
NSUInteger const HJStreamPumpMaximumChunkSize = 262'144;
NSUInteger const HJStreamPumpMaximumInitialBytes = 1'048'576;
NSUInteger const HJNetworkStreamMaximumQueuedBytes = 2'097'152;
NSUInteger const HJNetworkStreamMaximumQueuedRequests = 128;

namespace {
NSError *RuntimeError(HJProxyRuntimeErrorCode code, NSString *message) {
    return [NSError errorWithDomain:HJProxyRuntimeErrorDomain code:code
                          userInfo:@{NSLocalizedDescriptionKey: message}];
}
NSError *CancelledError() {
    return RuntimeError(HJProxyRuntimeErrorCancelled, @"Stream cancelled");
}
NSError *NetworkError(nw_error_t error) {
    if (!error) return RuntimeError(HJProxyRuntimeErrorContractViolation, @"Network transport failed");
    NSError *value = CFBridgingRelease(nw_error_copy_cf_error(error));
    return value ?: RuntimeError(HJProxyRuntimeErrorContractViolation, @"Network transport failed");
}
dispatch_queue_t SerialQueue(const char *label, dispatch_queue_t target) {
    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_autorelease_frequency(
        DISPATCH_QUEUE_SERIAL, DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM);
    return dispatch_queue_create_with_target(label, attr, target);
}
uint64_t Now() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
uint64_t DurationNanos(NSTimeInterval seconds) {
    return static_cast<uint64_t>(std::min(seconds, 86'400.0) * NSEC_PER_SEC);
}
bool ValidString(NSString *value, bool emptyAllowed = false) {
    if (!value || (!emptyAllowed && value.length == 0) || value.length > 4096) return false;
    return [value rangeOfCharacterFromSet:
        [NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location == NSNotFound;
}
dispatch_data_t DispatchData(NSData *data) {
    if (!data.length) return dispatch_data_empty;
    NSData *owner = [data copy];
    return dispatch_data_create(owner.bytes, owner.length,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ (void)owner.length; });
}
NSData *FoundationData(dispatch_data_t content) {
    if (!content || !dispatch_data_get_size(content)) return [NSData data];
    const void *bytes = nullptr;
    size_t size = 0;
    dispatch_data_t owner = dispatch_data_create_map(content, &bytes, &size);
    return [[NSData alloc] initWithBytesNoCopy:const_cast<void *>(bytes) length:size
        deallocator:^(void *, NSUInteger) { (void)dispatch_data_get_size(owner); }];
}
struct Direction {
    uint64_t readGeneration = 0;
    uint64_t writeGeneration = 0;
    size_t initialOffset = 0;
    unsigned emptyReads = 0;
    bool reading = false;
    bool writing = false;
    bool done = false;
};
struct DataWrite {
    NSData *__strong data;
    HJStreamWriteCompletion __strong completion;
};
}

@implementation HJCallbackStream {
    dispatch_queue_t _queue;
    BOOL _supportsHalfClose;
    BOOL _cancelled;
    BOOL _readEOF;
    BOOL _writeClosed;
    uint64_t _readGeneration;
    uint64_t _writeGeneration;
    HJDataReceiveHandler _receiveHandler;
    HJDataSendHandler _sendHandler;
    dispatch_block_t _cancelHandler;
    HJStreamReadCompletion _pendingRead;
    HJStreamWriteCompletion _pendingWrite;
}
- (instancetype)initWithQueue:(dispatch_queue_t)queue supportsHalfClose:(BOOL)supportsHalfClose
                receiveHandler:(HJDataReceiveHandler)receiveHandler
                   sendHandler:(HJDataSendHandler)sendHandler
                 cancelHandler:(dispatch_block_t)cancelHandler {
    if ((self = [super init])) {
        _queue = SerialQueue("app.hajimi.native.callback-stream", queue);
        _supportsHalfClose = supportsHalfClose;
        _receiveHandler = [receiveHandler copy];
        _sendHandler = [sendHandler copy];
        _cancelHandler = [cancelHandler copy];
    }
    return self;
}
- (BOOL)supportsHalfClose { return _supportsHalfClose; }
- (void)receiveWithMaximum:(NSUInteger)maximum completion:(HJStreamReadCompletion)completion {
    dispatch_async(_queue, ^{
        if (self->_cancelled) { completion(nil, NO, CancelledError()); return; }
        if (!maximum || maximum > UINT32_MAX) {
            completion(nil, NO, RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Invalid receive size")); return;
        }
        if (self->_pendingRead) {
            completion(nil, NO, RuntimeError(HJProxyRuntimeErrorBusy, @"A stream read is already in flight")); return;
        }
        if (self->_readEOF) { completion(nil, YES, nil); return; }
        self->_pendingRead = [completion copy];
        uint64_t generation = ++self->_readGeneration;
        __weak HJCallbackStream *weakSelf = self;
        self->_receiveHandler(maximum, ^(NSData *data, BOOL atEOF, NSError *error) {
            HJCallbackStream *strongSelf = weakSelf;
            if (!strongSelf) return;
            dispatch_async(strongSelf->_queue, ^{
                if (!strongSelf->_pendingRead || strongSelf->_readGeneration != generation) return;
                HJStreamReadCompletion callback = strongSelf->_pendingRead;
                strongSelf->_pendingRead = nil;
                if (data.length > maximum) {
                    callback(nil, NO, RuntimeError(HJProxyRuntimeErrorContractViolation,
                                                  @"Receive handler exceeded its requested buffer limit"));
                } else {
                    if (!error && atEOF) strongSelf->_readEOF = YES;
                    callback(data ? DispatchData(data) : nil, atEOF, error);
                }
            });
        });
    });
}
- (void)sendContent:(dispatch_data_t)content isComplete:(BOOL)isComplete
         completion:(HJStreamWriteCompletion)completion {
    dispatch_async(_queue, ^{
        if (self->_cancelled) { completion(CancelledError()); return; }
        if (self->_writeClosed) {
            completion(RuntimeError(HJProxyRuntimeErrorContractViolation, @"Write side is closed")); return;
        }
        if (self->_pendingWrite) {
            completion(RuntimeError(HJProxyRuntimeErrorBusy, @"A stream write is already in flight")); return;
        }
        if (isComplete && !self->_supportsHalfClose) {
            completion(RuntimeError(HJProxyRuntimeErrorUnsupportedHalfClose, @"This codec cannot half-close")); return;
        }
        if ((!content || !dispatch_data_get_size(content)) && !isComplete) { completion(nil); return; }
        self->_pendingWrite = [completion copy];
        uint64_t generation = ++self->_writeGeneration;
        __weak HJCallbackStream *weakSelf = self;
        self->_sendHandler(content ? FoundationData(content) : nil, isComplete, ^(NSError *error) {
            HJCallbackStream *strongSelf = weakSelf;
            if (!strongSelf) return;
            dispatch_async(strongSelf->_queue, ^{
                if (!strongSelf->_pendingWrite || strongSelf->_writeGeneration != generation) return;
                HJStreamWriteCompletion callback = strongSelf->_pendingWrite;
                strongSelf->_pendingWrite = nil;
                if (!error && isComplete) strongSelf->_writeClosed = YES;
                callback(error);
            });
        });
    });
}
- (void)cancel {
    dispatch_async(_queue, ^{
        if (self->_cancelled) return;
        self->_cancelled = YES;
        HJStreamReadCompletion read = self->_pendingRead;
        HJStreamWriteCompletion write = self->_pendingWrite;
        dispatch_block_t cancel = self->_cancelHandler;
        self->_pendingRead = nil; self->_pendingWrite = nil;
        self->_receiveHandler = nil; self->_sendHandler = nil; self->_cancelHandler = nil;
        if (cancel) cancel();
        if (read) read(nil, NO, CancelledError());
        if (write) write(CancelledError());
    });
}
- (void)dealloc {
    if (!_cancelled && _cancelHandler) dispatch_async(_queue, _cancelHandler);
}
@end

@interface HJNetworkConnectAttempt : NSObject
- (instancetype)initWithHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
                   serverName:(NSString *)serverName skipVerify:(BOOL)skipVerify
                         alpn:(NSArray<NSString *> *)alpn interfaceName:(NSString *)interfaceName
                        queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
                   completion:(void (^)(HJNetworkStream *, NSError *))completion;
- (void)start;
- (void)cancel;
@end

@implementation HJNetworkStream {
    nw_connection_t _connection;
    dispatch_queue_t _queue;
    NSError *_terminalError;
    BOOL _readEOF;
    BOOL _writeClosed;
    uint64_t _readGeneration;
    uint64_t _writeGeneration;
    HJStreamReadCompletion _pendingRead;
    HJStreamWriteCompletion _pendingWrite;
    std::deque<DataWrite> _dataWrites;
    NSUInteger _dataWriteBytes;
    BOOL _dataWriteInFlight;
    uint64_t _dataWriteGeneration;
    std::mutex _dataAdmissionLock;
    NSUInteger _reservedDataWriteBytes;
    NSUInteger _reservedDataWriteCount;
}
+ (void)connectToHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
           serverName:(NSString *)serverName skipCertificateVerification:(BOOL)skipVerify
                 alpn:(NSArray<NSString *> *)alpn interfaceName:(NSString *)interfaceName
                queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
           completion:(void (^)(HJNetworkStream *, NSError *))completion {
    (void)[self beginConnectToHost:host port:port tls:tls serverName:serverName
        skipCertificateVerification:skipVerify alpn:alpn interfaceName:interfaceName
        queue:queue timeout:timeout completion:completion];
}
+ (dispatch_block_t)beginConnectToHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
           serverName:(NSString *)serverName skipCertificateVerification:(BOOL)skipVerify
                 alpn:(NSArray<NSString *> *)alpn interfaceName:(NSString *)interfaceName
                queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
           completion:(void (^)(HJNetworkStream *,NSError *))completion {
    HJNetworkConnectAttempt *attempt = [[HJNetworkConnectAttempt alloc]
        initWithHost:host port:port tls:tls serverName:serverName skipVerify:skipVerify
        alpn:alpn interfaceName:interfaceName queue:queue timeout:timeout completion:completion];
    [attempt start];
    __weak HJNetworkConnectAttempt *weak=attempt;
    return ^{[weak cancel];};
}
- (instancetype)initWithReadyConnection:(nw_connection_t)connection queue:(dispatch_queue_t)queue {
    if ((self = [super init])) {
        _connection = connection;
        _queue = SerialQueue("app.hajimi.native.network-stream", queue);
        // After readiness, the I/O completions are authoritative. A state
        // failure can race already-buffered receives (notably after both TCP
        // FINs); eagerly cancelling here would discard that buffered tail.
        nw_connection_set_state_changed_handler(connection, nil);
    }
    return self;
}
- (BOOL)supportsHalfClose { return YES; }
- (void)sendData:(NSData *)data completion:(HJStreamWriteCompletion)completion {
    // Admission precedes both the immutable snapshot and dispatch enqueue.
    // Otherwise a caller could allocate an unbounded backlog of captured data
    // in dispatch blocks before our serial queue ever checked its byte limit.
    BOOL admitted = NO;
    NSUInteger size = data.length;
    {
        std::lock_guard<std::mutex> lock(_dataAdmissionLock);
        if (_reservedDataWriteCount < HJNetworkStreamMaximumQueuedRequests &&
            size <= HJNetworkStreamMaximumQueuedBytes - _reservedDataWriteBytes) {
            ++_reservedDataWriteCount;
            _reservedDataWriteBytes += size;
            admitted = YES;
        }
    }
    if (!admitted) {
        dispatch_async(_queue, ^{
            completion(RuntimeError(HJProxyRuntimeErrorQueueLimit, @"Native compatibility write queue is full (2 MiB / 128 requests)"));
        });
        return;
    }
    NSData *snapshot = [data copy];
    dispatch_async(_queue, ^{
        if (self->_terminalError) {
            [self releaseDataReservation:size]; completion(self->_terminalError); return;
        }
        if (self->_writeClosed) {
            [self releaseDataReservation:size];
            completion(RuntimeError(HJProxyRuntimeErrorContractViolation, @"Write side is closed")); return;
        }
        if (self->_pendingWrite && !self->_dataWriteInFlight) {
            [self releaseDataReservation:size];
            completion(RuntimeError(HJProxyRuntimeErrorBusy, @"A direct stream write is already in flight")); return;
        }
        if (self->_dataWrites.size() >= HJNetworkStreamMaximumQueuedRequests ||
            snapshot.length > HJNetworkStreamMaximumQueuedBytes - self->_dataWriteBytes) {
            [self releaseDataReservation:size];
            completion(RuntimeError(HJProxyRuntimeErrorQueueLimit, @"Native compatibility write queue is full")); return;
        }
        self->_dataWrites.push_back({snapshot, [completion copy]});
        self->_dataWriteBytes += snapshot.length;
        [self flushDataWrites];
    });
}
- (void)releaseDataReservation:(NSUInteger)bytes {
    std::lock_guard<std::mutex> lock(_dataAdmissionLock);
    --_reservedDataWriteCount; _reservedDataWriteBytes -= bytes;
}
- (void)receiveDataWithMaximum:(NSUInteger)maximum completion:(HJDataReadCompletion)completion {
    [self receiveWithMaximum:maximum completion:^(dispatch_data_t content, BOOL atEOF, NSError *error) {
        completion(content ? FoundationData(content) : nil, atEOF, error);
    }];
}
- (void)receiveWithMaximum:(NSUInteger)maximum completion:(HJStreamReadCompletion)completion {
    dispatch_async(_queue, ^{
        if (self->_terminalError) { completion(nil, NO, self->_terminalError); return; }
        if (self->_pendingRead) {
            completion(nil, NO, RuntimeError(HJProxyRuntimeErrorBusy, @"A stream read is already in flight")); return;
        }
        if (!maximum || maximum > UINT32_MAX) {
            completion(nil, NO, RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Invalid receive size")); return;
        }
        if (self->_readEOF) { completion(nil, YES, nil); return; }
        self->_pendingRead = [completion copy];
        uint64_t generation = ++self->_readGeneration;
        __weak HJNetworkStream *weakSelf = self;
        nw_connection_receive(self->_connection, 1, static_cast<uint32_t>(maximum),
            ^(dispatch_data_t content, nw_content_context_t, bool atEOF, nw_error_t error) {
                HJNetworkStream *strongSelf = weakSelf;
                if (!strongSelf) return;
                dispatch_async(strongSelf->_queue, ^{
                    if (!strongSelf->_pendingRead || strongSelf->_readGeneration != generation) return;
                    if (error) { [strongSelf fail:NetworkError(error)]; return; }
                    HJStreamReadCompletion callback = strongSelf->_pendingRead;
                    strongSelf->_pendingRead = nil;
                    if (atEOF) strongSelf->_readEOF = YES;
                    callback(content, atEOF, nil);
                });
            });
    });
}
- (void)sendContent:(dispatch_data_t)content isComplete:(BOOL)isComplete
         completion:(HJStreamWriteCompletion)completion {
    dispatch_async(_queue, ^{
        if (self->_terminalError) { completion(self->_terminalError); return; }
        if (self->_dataWriteInFlight || !self->_dataWrites.empty()) {
            completion(RuntimeError(HJProxyRuntimeErrorBusy, @"Compatibility writes must finish before a direct send")); return;
        }
        [self beginWrite:content isComplete:isComplete completion:completion];
    });
}
- (void)beginWrite:(dispatch_data_t)content isComplete:(BOOL)isComplete
        completion:(HJStreamWriteCompletion)completion {
    // Private queue-confined primitive, also used by the ordered NSData FIFO.
    if (_terminalError) { completion(_terminalError); return; }
    if (_writeClosed) {
        completion(RuntimeError(HJProxyRuntimeErrorContractViolation, @"Write side is closed")); return;
    }
    if (_pendingWrite) {
        completion(RuntimeError(HJProxyRuntimeErrorBusy, @"A stream write is already in flight")); return;
    }
    if ((!content || !dispatch_data_get_size(content)) && !isComplete) { completion(nil); return; }
    _pendingWrite = [completion copy];
    uint64_t generation = ++_writeGeneration;
    __weak HJNetworkStream *weakSelf = self;
    nw_connection_send(_connection, content, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, isComplete,
        ^(nw_error_t error) {
            HJNetworkStream *strongSelf = weakSelf;
            if (!strongSelf) return;
            dispatch_async(strongSelf->_queue, ^{
                if (!strongSelf->_pendingWrite || strongSelf->_writeGeneration != generation) return;
                if (error) { [strongSelf fail:NetworkError(error)]; return; }
                HJStreamWriteCompletion callback = strongSelf->_pendingWrite;
                strongSelf->_pendingWrite = nil;
                if (isComplete) strongSelf->_writeClosed = YES;
                callback(nil);
            });
        });
}
- (void)flushDataWrites {
    if (_terminalError || _dataWriteInFlight || _dataWrites.empty()) return;
    _dataWriteInFlight = YES;
    uint64_t generation = ++_dataWriteGeneration;
    __weak HJNetworkStream *weakSelf = self;
    [self beginWrite:DispatchData(_dataWrites.front().data) isComplete:NO completion:^(NSError *error) {
        HJNetworkStream *strongSelf = weakSelf;
        if (!strongSelf || !strongSelf->_dataWriteInFlight ||
            strongSelf->_dataWriteGeneration != generation) return;
        DataWrite request = std::move(strongSelf->_dataWrites.front());
        strongSelf->_dataWrites.pop_front();
        strongSelf->_dataWriteBytes -= request.data.length;
        strongSelf->_dataWriteInFlight = NO;
        [strongSelf releaseDataReservation:request.data.length];
        request.completion(error);
        if (error) [strongSelf fail:error]; else [strongSelf flushDataWrites];
    }];
}
- (void)fail:(NSError *)error {
    if (_terminalError) return;
    _terminalError = error;
    HJStreamReadCompletion read = _pendingRead;
    HJStreamWriteCompletion write = _pendingWrite;
    _pendingRead = nil; _pendingWrite = nil;
    std::deque<DataWrite> dataWrites;
    dataWrites.swap(_dataWrites);
    _dataWriteBytes = 0; _dataWriteInFlight = NO; ++_dataWriteGeneration;
    nw_connection_set_state_changed_handler(_connection, nil);
    nw_connection_cancel(_connection);
    if (read) read(nil, NO, error);
    if (write) write(error);
    for (const DataWrite &request : dataWrites) {
        [self releaseDataReservation:request.data.length]; request.completion(error);
    }
}
- (void)cancel { dispatch_async(_queue, ^{ [self fail:CancelledError()]; }); }
- (void)dealloc {
    nw_connection_set_state_changed_handler(_connection, nil);
    nw_connection_cancel(_connection);
}
@end

@implementation HJNetworkConnectAttempt {
    dispatch_queue_t _queue;
    NSString *_host;
    NSString *_serverName;
    NSString *_interfaceName;
    NSArray<NSString *> *_alpn;
    uint16_t _port;
    BOOL _tls;
    BOOL _skipVerify;
    BOOL _resolvingInterface;
    NSTimeInterval _timeout;
    uint64_t _deadline;
    nw_parameters_t _parameters;
    nw_connection_t _connection;
    nw_path_monitor_t _monitor;
    dispatch_source_t _timer;
    void (^_completion)(HJNetworkStream *, NSError *);
    HJNetworkConnectAttempt *_keepAlive;
}
- (instancetype)initWithHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
                   serverName:(NSString *)serverName skipVerify:(BOOL)skipVerify
                         alpn:(NSArray<NSString *> *)alpn interfaceName:(NSString *)interfaceName
                        queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
                   completion:(void (^)(HJNetworkStream *, NSError *))completion {
    if ((self = [super init])) {
        _queue = SerialQueue("app.hajimi.native.connect", queue);
        _host = [host copy]; _port = port; _tls = tls; _skipVerify = skipVerify;
        _serverName = [serverName copy]; _alpn = [alpn copy];
        _interfaceName = [interfaceName copy]; _completion = [completion copy];
        _timeout = std::isfinite(timeout) && timeout > 0 ? std::min(timeout, 86'400.0) : 10;
    }
    return self;
}
- (void)start { dispatch_async(_queue, ^{ [self begin]; }); }
- (void)cancel { dispatch_async(_queue, ^{ [self finish:nil error:CancelledError()]; }); }
- (void)begin {
    _keepAlive = self;
    if (!ValidString(_host) || !_port ||
        (_tls && _serverName.length && !ValidString(_serverName)) ||
        (_interfaceName && !ValidString(_interfaceName))) {
        [self finish:nil error:RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Invalid TCP/TLS endpoint or interface")];
        return;
    }
    if (_tls) {
        for (NSString *protocol in _alpn) {
            if (![protocol isKindOfClass:[NSString class]] || !ValidString(protocol) ||
                [protocol lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 255) {
                [self finish:nil error:RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Invalid TLS ALPN identifier")];
                return;
            }
        }
    }
    nw_parameters_configure_protocol_block_t tlsConfiguration = NW_PARAMETERS_DISABLE_PROTOCOL;
    if (_tls) {
        NSString *name = _serverName.length ? _serverName : _host;
        NSArray<NSString *> *protocols = _alpn;
        BOOL skip = _skipVerify;
        dispatch_queue_t queue = _queue;
        tlsConfiguration = ^(nw_protocol_options_t options) {
            sec_protocol_options_t security = nw_tls_copy_sec_protocol_options(options);
            sec_protocol_options_set_tls_server_name(security, name.UTF8String);
            for (NSString *protocol in protocols)
                sec_protocol_options_add_tls_application_protocol(security, protocol.UTF8String);
            if (skip) sec_protocol_options_set_verify_block(security,
                ^(sec_protocol_metadata_t, sec_trust_t, sec_protocol_verify_complete_t verify) { verify(true); }, queue);
        };
    }
    _parameters = nw_parameters_create_secure_tcp(tlsConfiguration, ^(nw_protocol_options_t tcp) {
        nw_tcp_options_set_no_delay(tcp, true);
        nw_tcp_options_set_enable_keepalive(tcp, true);
        nw_tcp_options_set_keepalive_idle_time(tcp, 30);
        nw_tcp_options_set_keepalive_interval(tcp, 10);
        nw_tcp_options_set_keepalive_count(tcp, 3);
    });
    if (!_parameters) {
        [self finish:nil error:RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Cannot create TCP/TLS parameters")];
        return;
    }
    _deadline = Now() + DurationNanos(_timeout);
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    __weak HJNetworkConnectAttempt *weakSelf = self;
    dispatch_source_set_event_handler(_timer, ^{
        HJNetworkConnectAttempt *strongSelf = weakSelf;
        if (!strongSelf || !strongSelf->_completion) return;
        NSError *error = strongSelf->_resolvingInterface
            ? RuntimeError(HJProxyRuntimeErrorInterfaceUnavailable, @"Required network interface is not available")
            : RuntimeError(HJProxyRuntimeErrorConnectTimeout, @"TCP/TLS connection timed out");
        [strongSelf finish:nil error:error];
    });
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW,
        static_cast<int64_t>(DurationNanos(_interfaceName ? std::min(3.0, _timeout) : _timeout))),
        DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
    dispatch_resume(_timer);
    if (!_interfaceName) { [self dial]; return; }
    if (!if_nametoindex(_interfaceName.UTF8String)) {
        [self finish:nil error:RuntimeError(HJProxyRuntimeErrorInterfaceUnavailable, @"Required network interface does not exist")];
        return;
    }
    _resolvingInterface = YES;
    _monitor = nw_path_monitor_create();
    nw_path_monitor_set_queue(_monitor, _queue);
    nw_path_monitor_set_update_handler(_monitor, ^(nw_path_t path) {
        HJNetworkConnectAttempt *strongSelf = weakSelf;
        if (!strongSelf || !strongSelf->_completion || !strongSelf->_resolvingInterface) return;
        __block nw_interface_t selected = nil;
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
            const char *name = nw_interface_get_name(interface);
            if (name && [strongSelf->_interfaceName isEqualToString:[NSString stringWithUTF8String:name]]) {
                selected = interface; return false;
            }
            return true;
        });
        if (!selected) return;
        nw_parameters_require_interface(strongSelf->_parameters, selected);
        strongSelf->_resolvingInterface = NO;
        [strongSelf stopMonitor];
        uint64_t now = Now();
        uint64_t remaining = strongSelf->_deadline > now ? strongSelf->_deadline - now : 1;
        dispatch_source_set_timer(strongSelf->_timer, dispatch_time(DISPATCH_TIME_NOW,
            static_cast<int64_t>(remaining)), DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
        [strongSelf dial];
    });
    nw_path_monitor_start(_monitor);
}
- (void)dial {
    NSString *port = [NSString stringWithFormat:@"%u", _port];
    nw_endpoint_t endpoint = nw_endpoint_create_host(_host.UTF8String, port.UTF8String);
    _connection = nw_connection_create(endpoint, _parameters);
    if (!_connection) {
        [self finish:nil error:RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Cannot create network connection")]; return;
    }
    __weak HJNetworkConnectAttempt *weakSelf = self;
    nw_connection_set_queue(_connection, _queue);
    nw_connection_set_state_changed_handler(_connection, ^(nw_connection_state_t state, nw_error_t error) {
        HJNetworkConnectAttempt *strongSelf = weakSelf;
        if (!strongSelf || !strongSelf->_completion) return;
        if (state == nw_connection_state_ready) {
            HJNetworkStream *stream = [[HJNetworkStream alloc]
                initWithReadyConnection:strongSelf->_connection queue:strongSelf->_queue];
            [strongSelf finish:stream error:nil];
        } else if (state == nw_connection_state_failed) {
            [strongSelf finish:nil error:NetworkError(error)];
        } else if (state == nw_connection_state_waiting && error &&
                   nw_error_get_error_domain(error) == nw_error_domain_tls) {
            // TLS authentication errors are terminal, unlike a temporarily
            // unavailable network path. Preserve the certificate/handshake
            // error instead of hiding it behind the connection deadline.
            [strongSelf finish:nil error:NetworkError(error)];
        } else if (state == nw_connection_state_cancelled) { [strongSelf finish:nil error:CancelledError()]; }
    });
    nw_connection_start(_connection);
}
- (void)stopMonitor {
    if (!_monitor) return;
    nw_path_monitor_cancel(_monitor); _monitor = nil;
}
- (void)finish:(HJNetworkStream *)stream error:(NSError *)error {
    if (!_completion) return;
    void (^callback)(HJNetworkStream *, NSError *) = _completion;
    _completion = nil;
    [self stopMonitor];
    if (_timer) { dispatch_source_cancel(_timer); _timer = nil; }
    if (!stream && _connection) {
        nw_connection_set_state_changed_handler(_connection, nil); nw_connection_cancel(_connection);
    }
    _connection = nil; _parameters = nil; _keepAlive = nil;
    callback(stream, error);
}
@end

@implementation HJStreamPump {
    id<HJByteStream> _client;
    id<HJByteStream> _remote;
    dispatch_queue_t _queue;
    dispatch_source_t _timer;
    dispatch_data_t _uploadInitial;
    dispatch_data_t _downloadInitial;
    NSUInteger _chunkSize;
    uint64_t _idleNanos;
    uint64_t _trafficNanos;
    uint64_t _lastActivity;
    uint64_t _lastTrafficFlush;
    uint64_t _pendingUploaded;
    uint64_t _pendingDownloaded;
    std::atomic<uint64_t> _uploaded;
    std::atomic<uint64_t> _downloaded;
    Direction _directions[2];
    BOOL _started;
    BOOL _finished;
    NSError *_configurationError;
    HJStreamTrafficHandler _trafficHandler;
    HJStreamWriteCompletion _completion;
}
- (instancetype)initWithClient:(id<HJByteStream>)client remote:(id<HJByteStream>)remote
                          queue:(dispatch_queue_t)queue chunkSize:(NSUInteger)chunkSize
                    idleTimeout:(NSTimeInterval)idleTimeout trafficInterval:(NSTimeInterval)trafficInterval
                 trafficHandler:(HJStreamTrafficHandler)trafficHandler
                     completion:(HJStreamWriteCompletion)completion {
    if ((self = [super init])) {
        _client = client; _remote = remote;
        _queue = SerialQueue("app.hajimi.native.stream-pump", queue);
        _chunkSize = chunkSize ?: HJStreamPumpDefaultChunkSize;
        if (_chunkSize > HJStreamPumpMaximumChunkSize || !client || !remote || client == remote) {
            _configurationError = RuntimeError(HJProxyRuntimeErrorInvalidArgument,
                                               @"Invalid pump chunk size or identical streams");
        }
        _idleNanos = std::isfinite(idleTimeout) && idleTimeout > 0 ? DurationNanos(idleTimeout) : 0;
        NSTimeInterval interval = std::isfinite(trafficInterval) && trafficInterval > 0
            ? std::clamp(trafficInterval, 0.01, 10.0) : 0.2;
        _trafficNanos = DurationNanos(interval);
        _trafficHandler = [trafficHandler copy]; _completion = [completion copy];
        _uploaded.store(0, std::memory_order_relaxed);
        _downloaded.store(0, std::memory_order_relaxed);
    }
    return self;
}
- (uint64_t)uploadedBytes { return _uploaded.load(std::memory_order_relaxed); }
- (uint64_t)downloadedBytes { return _downloaded.load(std::memory_order_relaxed); }
- (void)startWithClientInitial:(NSData *)clientInitial remoteInitial:(NSData *)remoteInitial {
    NSData *upload = [clientInitial copy];
    NSData *download = [remoteInitial copy];
    dispatch_async(_queue, ^{
        if (self->_started || self->_finished) return;
        self->_started = YES;
        if (self->_configurationError) { [self finish:self->_configurationError]; return; }
        if (upload.length > HJStreamPumpMaximumInitialBytes || download.length > HJStreamPumpMaximumInitialBytes) {
            [self finish:RuntimeError(HJProxyRuntimeErrorInvalidArgument, @"Initial proxy data exceeds the 1 MiB limit")]; return;
        }
        self->_uploadInitial = upload.length ? DispatchData(upload) : nil;
        self->_downloadInitial = download.length ? DispatchData(download) : nil;
        self->_lastActivity = self->_lastTrafficFlush = Now();
        [self startTimer];
        [self advance:0]; [self advance:1];
    });
}
- (void)startTimer {
    if (!_idleNanos && !_trafficHandler) return;
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    uint64_t interval = _trafficHandler ? _trafficNanos : NSEC_PER_SEC;
    if (_idleNanos) interval = std::min(interval, std::max<uint64_t>(NSEC_PER_MSEC, _idleNanos / 4));
    __weak HJStreamPump *weakSelf = self;
    dispatch_source_set_event_handler(_timer, ^{
        HJStreamPump *strongSelf = weakSelf;
        if (!strongSelf || strongSelf->_finished) return;
        uint64_t now = Now();
        if (strongSelf->_idleNanos && now - strongSelf->_lastActivity >= strongSelf->_idleNanos) {
            [strongSelf finish:RuntimeError(HJProxyRuntimeErrorIdleTimeout, @"Proxy stream idle timeout")]; return;
        }
        if (now - strongSelf->_lastTrafficFlush >= strongSelf->_trafficNanos) [strongSelf flushTraffic];
    });
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(interval)),
                              interval, std::min<uint64_t>(NSEC_PER_MSEC * 5, interval / 10));
    dispatch_resume(_timer);
}
- (id<HJByteStream>)source:(NSUInteger)direction { return direction == 0 ? _client : _remote; }
- (id<HJByteStream>)destination:(NSUInteger)direction { return direction == 0 ? _remote : _client; }
- (void)advance:(NSUInteger)index {
    Direction &direction = _directions[index];
    if (_finished || direction.done || direction.reading || direction.writing) return;
    dispatch_data_t initial = index == 0 ? _uploadInitial : _downloadInitial;
    if (initial) {
        size_t size = dispatch_data_get_size(initial);
        size_t count = std::min<size_t>(_chunkSize, size - direction.initialOffset);
        dispatch_data_t content = dispatch_data_create_subrange(initial, direction.initialOffset, count);
        direction.initialOffset += count;
        if (direction.initialOffset == size) {
            if (index == 0) _uploadInitial = nil; else _downloadInitial = nil;
        }
        [self write:content direction:index atEOF:NO];
        return;
    }
    direction.reading = true;
    uint64_t generation = ++direction.readGeneration;
    __weak HJStreamPump *weakSelf = self;
    [[self source:index] receiveWithMaximum:_chunkSize
        completion:^(dispatch_data_t content, BOOL atEOF, NSError *error) {
            HJStreamPump *strongSelf = weakSelf;
            if (!strongSelf) return;
            // Always trampoline: codecs may complete synchronously. This avoids
            // recursive stacks and serializes callbacks from arbitrary queues.
            dispatch_async(strongSelf->_queue, ^{
                Direction &state = strongSelf->_directions[index];
                if (strongSelf->_finished || !state.reading || state.readGeneration != generation) return;
                state.reading = false;
                [strongSelf received:content direction:index atEOF:atEOF error:error];
            });
        }];
}
- (void)received:(dispatch_data_t)content direction:(NSUInteger)index atEOF:(BOOL)atEOF
           error:(NSError *)error {
    if (error) { [self finish:error]; return; }
    size_t count = content ? dispatch_data_get_size(content) : 0;
    if (count > _chunkSize) {
        [self finish:RuntimeError(HJProxyRuntimeErrorContractViolation,
                                 @"Byte stream exceeded the pump's requested buffer limit")]; return;
    }
    if (count || atEOF) {
        _directions[index].emptyReads = 0;
        _lastActivity = Now();
        [self write:content direction:index atEOF:atEOF];
        return;
    }
    // Empty non-EOF callbacks do not count as activity. Bound their CPU cost
    // even for a buggy/malicious adapter; the idle timer still expires normally.
    unsigned empty = _directions[index].emptyReads = std::min(_directions[index].emptyReads + 1, 6u);
    uint64_t delay = (uint64_t(1) << (empty - 1)) * NSEC_PER_MSEC;
    uint64_t generation = _directions[index].readGeneration;
    __weak HJStreamPump *weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(delay)), _queue, ^{
        HJStreamPump *strongSelf = weakSelf;
        if (strongSelf && !strongSelf->_finished &&
            strongSelf->_directions[index].readGeneration == generation) [strongSelf advance:index];
    });
}
- (void)write:(dispatch_data_t)content direction:(NSUInteger)index atEOF:(BOOL)atEOF {
    id<HJByteStream> destination = [self destination:index];
    BOOL halfClose = destination.supportsHalfClose;
    size_t count = content ? dispatch_data_get_size(content) : 0;
    if (!count && atEOF && !halfClose) { [self finish:nil]; return; }
    Direction &direction = _directions[index];
    direction.writing = true;
    uint64_t generation = ++direction.writeGeneration;
    __weak HJStreamPump *weakSelf = self;
    [destination sendContent:content isComplete:atEOF && halfClose completion:^(NSError *error) {
        HJStreamPump *strongSelf = weakSelf;
        if (!strongSelf) return;
        dispatch_async(strongSelf->_queue, ^{
            Direction &state = strongSelf->_directions[index];
            if (strongSelf->_finished || !state.writing || state.writeGeneration != generation) return;
            state.writing = false;
            if (error) { [strongSelf finish:error]; return; }
            if (count) {
                if (index == 0) {
                    strongSelf->_uploaded.fetch_add(count, std::memory_order_relaxed);
                    strongSelf->_pendingUploaded += count;
                } else {
                    strongSelf->_downloaded.fetch_add(count, std::memory_order_relaxed);
                    strongSelf->_pendingDownloaded += count;
                }
                strongSelf->_lastActivity = Now();
            }
            if (atEOF) {
                state.done = true;
                if (!halfClose || strongSelf->_directions[1 - index].done) [strongSelf finish:nil];
            } else { [strongSelf advance:index]; }
        });
    }];
}
- (void)flushTraffic {
    uint64_t upload = _pendingUploaded;
    uint64_t download = _pendingDownloaded;
    _pendingUploaded = _pendingDownloaded = 0;
    _lastTrafficFlush = Now();
    if (_trafficHandler && (upload || download)) _trafficHandler(upload, download);
}
- (void)finish:(NSError *)error {
    if (_finished) return;
    _finished = YES;
    if (_timer) { dispatch_source_cancel(_timer); _timer = nil; }
    _uploadInitial = nil; _downloadInitial = nil;
    [self flushTraffic];
    HJStreamWriteCompletion completion = _completion;
    _completion = nil; _trafficHandler = nil;
    [_client cancel]; [_remote cancel];
    if (completion) completion(error);
}
- (void)cancel { dispatch_async(_queue, ^{ [self finish:nil]; }); }
- (void)dealloc {
    if (_timer) dispatch_source_cancel(_timer);
    if (!_finished) { [_client cancel]; [_remote cancel]; }
}
@end
