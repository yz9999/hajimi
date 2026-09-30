#pragma once
#import <Foundation/Foundation.h>
#import <HajimiProxyRuntime.h>

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT NSErrorDomain const HJCppProtocolErrorDomain;

/// Optional handoff hooks used by the C++ XTLS Vision framing engine. The
/// platform carrier must preserve unread bytes when changing record mode.
@protocol HJCppVisionCarrier <HJByteStream>
- (void)enableVisionDirectWrite;
- (void)enableVisionDirectRead;
@end

typedef void (^HJCppTransportDialer)(void (^completion)(id<HJByteStream> _Nullable, NSError * _Nullable));
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
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP
          completion:(void (^)(HJCppByteStream * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(connect(host:port:udp:plainHTTP:completion:));
- (void)createDatagramSessionWithReceive:(HJCppPacketHandler)receive
                                failure:(HJStreamWriteCompletion)failure
                             completion:(void (^)(HJCppDatagramSession * _Nullable, NSError * _Nullable))completion
    NS_SWIFT_NAME(createDatagramSession(receive:failure:completion:));
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
