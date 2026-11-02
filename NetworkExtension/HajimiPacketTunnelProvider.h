#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

/// Packet-flow adapter for a linked shared native engine. The standalone
/// development template has no engine and refuses to capture any traffic.
@interface HajimiPacketTunnelProvider : NEPacketTunnelProvider
@end

NS_ASSUME_NONNULL_END
