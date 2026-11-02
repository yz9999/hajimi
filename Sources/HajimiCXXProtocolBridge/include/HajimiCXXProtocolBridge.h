#pragma once
#import <Foundation/Foundation.h>
#import <HajimiProxyRuntime.h>

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT NSErrorDomain const HJCppProtocolErrorDomain;
FOUNDATION_EXPORT void HJFlushCachedBridgeInterfaces(void);

/// Optional handoff hooks used by the C++ XTLS Vision framing engine. The
/// platform carrier must preserve unread bytes when changing record mode.
@protocol HJCppVisionCarrier <HJByteStream>
- (void)enableVisionDirectWrite;
- (void)enableVisionDirectRead;
@end

typedef void (^HJCppTransportDialer)(void (^completion)(id<HJByteStream> _Nullable, NSError * _Nullable));
/// Cancellable prepared carrier. Independent operations carry their immutable
/// scope; nil is reserved for a genuinely shared factory. Cancellation must
/// close pending resources and deliver the carrier's real terminal callback,
/// not manufacture an acknowledgement while a child dial is still pending.
typedef dispatch_block_t _Nonnull (^HJCppScopedPreparedTransportDialer)(NSUUID * _Nullable connectionScope,
    void (^completion)(id<HJByteStream> _Nullable, NSError * _Nullable));
/// Optional literal-only physical TCP/TLS dial. TLS options come from the C++
/// protocol engine unchanged. The returned closure cancels only this pending
/// attempt; after readiness it must not close the delivered/reused transport.
typedef dispatch_block_t _Nonnull (^HJCppPhysicalTransportDialer)(NSString *host, uint16_t port, BOOL tls,
    NSString *serverName, BOOL skipCertificateVerification, NSArray<NSString *> *alpn,
    NSString * _Nullable interfaceName,
    void (^completion)(id<HJByteStream> _Nullable, NSError * _Nullable));
/// Scope-aware additive hook. Independent TCP/stream-UDP operations carry
/// their immutable logical scope, including later asynchronous/lazy dials.
/// A nil scope denotes a truly shared AnyTLS/SSH/QUIC factory. Independent
/// operations without a scope fail before invoking this hook.
typedef dispatch_block_t _Nonnull (^HJCppScopedPhysicalTransportDialer)(NSString *host, uint16_t port, BOOL tls,
    NSString *serverName, BOOL skipCertificateVerification, NSArray<NSString *> *alpn,
    NSString * _Nullable interfaceName, NSUUID * _Nullable connectionScope,
    void (^completion)(id<HJByteStream> _Nullable, NSError * _Nullable));
typedef void (^HJCppPacketHandler)(NSString *host, uint16_t port, NSData *payload);

/// Thin Objective-C ownership boundary. Authentication, encryption, framing,
/// stream/session state and UDP packet construction are implemented in C++.
@interface HJCppByteStream : NSObject <HJByteStream>
- (void)sendData:(NSData *)data completion:(HJStreamWriteCompletion)completion
    NS_SWIFT_NAME(sendData(_:completion:));
- (void)receiveDataWithMaximum:(NSUInteger)maximum completion:(HJDataReadCompletion)completion
    NS_SWIFT_NAME(receiveData(maximum:completion:));
- (instancetype)init NS_UNAVAILABLE;
@end

@interface HJCppDatagramSession : NSObject
- (void)sendPayload:(NSData *)payload host:(NSString *)host port:(uint16_t)port
         completion:(HJStreamWriteCompletion)completion
    NS_SWIFT_NAME(send(_:host:port:completion:));
- (void)cancel;
- (instancetype)init NS_UNAVAILABLE;
@end

/// JSON schema: {type,name,host,port,parameters:{string:string}}. Only config
/// decoding and platform TCP/TLS/UDP I/O are performed in this adapter. A
/// preparedTransportDialer is optional for externally composed carriers;
/// protocol credentials and payloads never go through a Swift wire codec.
/// Each client owns one stable, serialized native transport factory for AnyTLS
/// reuse and QUIC connection ownership. Cancelling resolves pending callbacks
/// and closes native attempts and delivered transports. An external prepared
/// dialer has no attempt-cancellation token: any late result is closed, but its
/// not-yet-delivered resources remain the external dialer's responsibility.
/// The initializer queue targets the transport factory and is the legacy
/// default callback queue. Cached clients should use a caller-independent
/// transport queue and provide each logical session's callbackQueue below.
@interface HJCppProtocolClient : NSObject
+ (nullable NSError *)validationErrorForConfiguration:(NSData *)configuration udp:(BOOL)udp
    NS_SWIFT_NAME(validationError(configuration:udp:));
- (nullable instancetype)initWithConfiguration:(NSData *)configuration
                                interfaceName:(nullable NSString *)interfaceName
                                        queue:(dispatch_queue_t)queue
                      preparedTransportDialer:(nullable HJCppTransportDialer)preparedTransportDialer
                                        error:(NSError * _Nullable * _Nullable)error
    NS_DESIGNATED_INITIALIZER
    NS_SWIFT_NAME(init(configuration:interfaceName:queue:preparedTransportDialer:));
/// Additive initializer. Prepared carriers retain precedence over the physical
/// hook, so chaining/Reality/WebSocket behavior is identical to the old API.
- (nullable instancetype)initWithConfiguration:(NSData *)configuration
                                interfaceName:(nullable NSString *)interfaceName
                                        queue:(dispatch_queue_t)queue
                      preparedTransportDialer:(nullable HJCppTransportDialer)preparedTransportDialer
                      physicalTransportDialer:(nullable HJCppPhysicalTransportDialer)physicalTransportDialer
                                        error:(NSError * _Nullable * _Nullable)error
    NS_SWIFT_NAME(init(configuration:interfaceName:queue:preparedTransportDialer:physicalTransportDialer:));
/// The old initializers and methods remain source-compatible. Prepared
/// carriers still take precedence; shared factories keep their pointer
/// identity and client-wide lifecycle rather than being cloned per request.
- (nullable instancetype)initWithConfiguration:(NSData *)configuration
                                interfaceName:(nullable NSString *)interfaceName
                                        queue:(dispatch_queue_t)queue
                      preparedTransportDialer:(nullable HJCppTransportDialer)preparedTransportDialer
                scopedPhysicalTransportDialer:(nullable HJCppScopedPhysicalTransportDialer)scopedPhysicalTransportDialer
                                        error:(NSError * _Nullable * _Nullable)error
    NS_SWIFT_NAME(init(configuration:interfaceName:queue:preparedTransportDialer:scopedPhysicalTransportDialer:));
/// Additive prepared-carrier ownership API. Legacy prepared dialers retain
/// their existing precedence and source compatibility. The cancellable hook
/// is used only when no legacy prepared dialer is provided.
- (nullable instancetype)initWithConfiguration:(NSData *)configuration
                                interfaceName:(nullable NSString *)interfaceName
                                        queue:(dispatch_queue_t)queue
                      preparedTransportDialer:(nullable HJCppTransportDialer)preparedTransportDialer
                scopedPreparedTransportDialer:(nullable HJCppScopedPreparedTransportDialer)scopedPreparedTransportDialer
                scopedPhysicalTransportDialer:(nullable HJCppScopedPhysicalTransportDialer)scopedPhysicalTransportDialer
                                        error:(NSError * _Nullable * _Nullable)error
    NS_SWIFT_NAME(init(configuration:interfaceName:queue:preparedTransportDialer:scopedPreparedTransportDialer:scopedPhysicalTransportDialer:));
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP
           completion:(void (^)(HJCppByteStream * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(connect(host:port:udp:plainHTTP:completion:));
/// Connect and all returned stream read/write completions are delivered on
/// callbackQueue. This does not retarget the shared native transport factory.
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP
        callbackQueue:(dispatch_queue_t)callbackQueue
           completion:(void (^)(HJCppByteStream * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(connect(host:port:udp:plainHTTP:callbackQueue:completion:));
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP
        callbackQueue:(dispatch_queue_t)callbackQueue
      connectionScope:(nullable NSUUID *)connectionScope
           completion:(void (^)(HJCppByteStream * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(connect(host:port:udp:plainHTTP:callbackQueue:connectionScope:completion:));
- (void)createDatagramSessionWithReceive:(HJCppPacketHandler)receive
                                 failure:(HJStreamWriteCompletion)failure
                              completion:(void (^)(HJCppDatagramSession * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(createDatagramSession(receive:failure:completion:));
/// Creation, packet/failure handlers and all returned session send completions
/// use callbackQueue; UDP/QUIC/AnyTLS transport ownership remains client-wide.
- (void)createDatagramSessionWithCallbackQueue:(dispatch_queue_t)callbackQueue
                                       receive:(HJCppPacketHandler)receive
                                       failure:(HJStreamWriteCompletion)failure
                                    completion:(void (^)(HJCppDatagramSession * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(createDatagramSession(callbackQueue:receive:failure:completion:));
- (void)createDatagramSessionWithCallbackQueue:(dispatch_queue_t)callbackQueue
                               connectionScope:(nullable NSUUID *)connectionScope
                                       receive:(HJCppPacketHandler)receive
                                       failure:(HJStreamWriteCompletion)failure
                                    completion:(void (^)(HJCppDatagramSession * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(createDatagramSession(callbackQueue:connectionScope:receive:failure:completion:));
- (void)cancelConnectionScope:(NSUUID *)connectionScope
    NS_SWIFT_NAME(cancel(connectionScope:));
- (void)cancel;
- (instancetype)init NS_UNAVAILABLE;
@end

/// Listener access policy and routing stay with the app. This C++ engine
/// handles the complete local SOCKS5 wire negotiation and preserves read-ahead.
@interface HJCppServerProtocols : NSObject
+ (void)acceptSOCKS5FromStream:(id<HJByteStream>)stream queue:(dispatch_queue_t)queue
                    completion:(void (^)(NSString * _Nullable host,uint16_t port,uint8_t command,
                                         NSData * _Nullable initial,NSError * _Nullable error))completion
    NS_SWIFT_NAME(acceptSOCKS5(stream:queue:completion:));
@end
NS_ASSUME_NONNULL_END
