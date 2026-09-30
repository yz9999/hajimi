#pragma once

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <dispatch/dispatch.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const HJProxyRuntimeErrorDomain;
typedef NS_ERROR_ENUM(HJProxyRuntimeErrorDomain, HJProxyRuntimeErrorCode) {
    HJProxyRuntimeErrorInvalidArgument = 1,
    HJProxyRuntimeErrorCancelled,
    HJProxyRuntimeErrorBusy,
    HJProxyRuntimeErrorIdleTimeout,
    HJProxyRuntimeErrorInterfaceUnavailable,
    HJProxyRuntimeErrorConnectTimeout,
    HJProxyRuntimeErrorContractViolation,
    HJProxyRuntimeErrorUnsupportedHalfClose,
    HJProxyRuntimeErrorQueueLimit,
};

typedef void (^HJStreamReadCompletion)(dispatch_data_t _Nullable content, BOOL atEOF,
                                      NSError * _Nullable error);
typedef void (^HJStreamWriteCompletion)(NSError * _Nullable error);
typedef void (^HJDataReadCompletion)(NSData * _Nullable content, BOOL atEOF,
                                    NSError * _Nullable error);
typedef void (^HJDataReceiveHandler)(NSUInteger maximum, HJDataReadCompletion completion);
typedef void (^HJDataSendHandler)(NSData * _Nullable content, BOOL isComplete,
                                HJStreamWriteCompletion completion);
typedef void (^HJStreamTrafficHandler)(uint64_t uploaded, uint64_t downloaded);

/// One concurrent read and one concurrent write are permitted. A successful
/// read returns at most maximum bytes; EOF may accompany the final bytes.
/// A write completion is the backpressure signal, not a remote acknowledgment.
/// isComplete closes only the write side when supportsHalfClose is true.
@protocol HJByteStream <NSObject>
@property(nonatomic, readonly) BOOL supportsHalfClose;
- (void)receiveWithMaximum:(NSUInteger)maximum completion:(HJStreamReadCompletion)completion
    NS_SWIFT_NAME(receive(maximum:completion:));
- (void)sendContent:(nullable dispatch_data_t)content isComplete:(BOOL)isComplete
         completion:(HJStreamWriteCompletion)completion
    NS_SWIFT_NAME(send(content:isComplete:completion:));
- (void)cancel;
@end

/// A compatibility boundary for existing Swift protocol codecs. The handlers
/// run on a private serial queue targeting queue. Completions may arrive on
/// any queue (including synchronously); duplicate/late completions are ignored.
/// Cancellation invokes cancelHandler once and resolves pending operations.
/// Immutable NSData/dispatch_data ownership is retained without a buffer copy;
/// mapping non-contiguous dispatch_data can still allocate a contiguous buffer.
@interface HJCallbackStream : NSObject <HJByteStream>
- (instancetype)initWithQueue:(dispatch_queue_t)queue
             supportsHalfClose:(BOOL)supportsHalfClose
                receiveHandler:(HJDataReceiveHandler)receiveHandler
                   sendHandler:(HJDataSendHandler)sendHandler
                 cancelHandler:(dispatch_block_t)cancelHandler
    NS_DESIGNATED_INITIALIZER
    NS_SWIFT_NAME(init(queue:supportsHalfClose:receiveHandler:sendHandler:cancelHandler:));
- (instancetype)init NS_UNAVAILABLE;
@end

/// A Network.framework TCP/TLS transport implemented through its C API.
/// TLS validates the trust chain and serverName (or host) unless the caller
/// explicitly requests skipCertificateVerification. Requested interfaceName
/// must resolve to an available exact interface; failure never dials unbound.
/// TLS-specific options are ignored when tls is false (e.g. a Reality carrier).
@interface HJNetworkStream : NSObject <HJByteStream>
/// Same dial as connect, with a thread-safe cancellation closure. Cancelling
/// before readiness terminates the native connection/DNS/TLS attempt and its
/// completion once. Calling it after readiness does not cancel the stream.
+ (dispatch_block_t)beginConnectToHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
           serverName:(nullable NSString *)serverName
    skipCertificateVerification:(BOOL)skipCertificateVerification
                 alpn:(NSArray<NSString *> *)alpn
        interfaceName:(nullable NSString *)interfaceName
                queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
           completion:(void (^)(HJNetworkStream * _Nullable stream,NSError * _Nullable error))completion
    NS_SWIFT_NAME(beginConnect(host:port:tls:serverName:skipCertificateVerification:alpn:interfaceName:queue:timeout:completion:));
+ (void)connectToHost:(NSString *)host port:(uint16_t)port tls:(BOOL)tls
           serverName:(nullable NSString *)serverName
    skipCertificateVerification:(BOOL)skipCertificateVerification
                 alpn:(NSArray<NSString *> *)alpn
        interfaceName:(nullable NSString *)interfaceName
                queue:(dispatch_queue_t)queue timeout:(NSTimeInterval)timeout
           completion:(void (^)(HJNetworkStream * _Nullable stream, NSError * _Nullable error))completion
    NS_SWIFT_NAME(connect(host:port:tls:serverName:skipCertificateVerification:alpn:interfaceName:queue:timeout:completion:));
/// Ordered compatibility writes for codecs with concurrent control/data sends.
/// Immutable snapshots are queued FIFO: at most 2 MiB and 128 requests including
/// the native write in flight. Exceeding either limit reports QueueLimit; no bytes
/// from the rejected request are sent. Cancellation/failure resolves the queue.
/// sendContent remains strict; wait for all sendData completions before issuing
/// a direct sendContent or its final FIN. Concurrently mixing both APIs is Busy.
- (void)sendData:(NSData *)data completion:(HJStreamWriteCompletion)completion
    NS_SWIFT_NAME(sendData(_:completion:));
- (void)receiveDataWithMaximum:(NSUInteger)maximum completion:(HJDataReadCompletion)completion
    NS_SWIFT_NAME(receiveData(maximum:completion:));
/// Adopts a ready native connection and its cancellation/state-handler ownership.
/// The caller must stop issuing reads/writes. No private Swift NWConnection
/// handle extraction is used; wrap a Swift NWConnection with HJCallbackStream.
- (instancetype)initWithReadyConnection:(nw_connection_t)connection queue:(dispatch_queue_t)queue
    NS_DESIGNATED_INITIALIZER
    NS_SWIFT_UNAVAILABLE("Wrap Swift NWConnection with HJCallbackStream instead.");
- (instancetype)init NS_UNAVAILABLE;
@end

FOUNDATION_EXPORT NSUInteger const HJNetworkStreamMaximumQueuedBytes;
FOUNDATION_EXPORT NSUInteger const HJNetworkStreamMaximumQueuedRequests;

FOUNDATION_EXPORT NSUInteger const HJStreamPumpDefaultChunkSize;
FOUNDATION_EXPORT NSUInteger const HJStreamPumpMaximumChunkSize;
FOUNDATION_EXPORT NSUInteger const HJStreamPumpMaximumInitialBytes;

/// Two independent, bounded forwarding directions, each with at most one
/// read OR write outstanding. No subsequent read occurs until the preceding
/// write completes. Caller-owned initial buffers (at most 1 MiB each) are
/// chunked before normal receives; initial bytes are included in traffic.
/// Native half-close keeps the opposite direction alive until its EOF. If a
/// destination cannot half-close, the session closes on that direction's EOF
/// after its final buffered bytes have been written, matching legacy codecs.
/// Traffic counts report successfully processed writes, coalesced by timer,
/// and are flushed before the exactly-once completion. Explicit cancel has
/// a nil completion error. idleTimeout <= 0 disables idle expiration.
/// Retain the pump until completion; deallocation cancels its transports.
@interface HJStreamPump : NSObject
@property(nonatomic, readonly) uint64_t uploadedBytes;
@property(nonatomic, readonly) uint64_t downloadedBytes;
- (instancetype)initWithClient:(id<HJByteStream>)client remote:(id<HJByteStream>)remote
                          queue:(dispatch_queue_t)queue chunkSize:(NSUInteger)chunkSize
                    idleTimeout:(NSTimeInterval)idleTimeout
                trafficInterval:(NSTimeInterval)trafficInterval
                 trafficHandler:(nullable HJStreamTrafficHandler)trafficHandler
                     completion:(HJStreamWriteCompletion)completion
    NS_DESIGNATED_INITIALIZER
    NS_SWIFT_NAME(init(client:remote:queue:chunkSize:idleTimeout:trafficInterval:trafficHandler:completion:));
- (instancetype)init NS_UNAVAILABLE;
- (void)startWithClientInitial:(nullable NSData *)clientInitial
                 remoteInitial:(nullable NSData *)remoteInitial
    NS_SWIFT_NAME(start(clientInitial:remoteInitial:));
- (void)cancel;
@end

NS_ASSUME_NONNULL_END
