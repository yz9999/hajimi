#import <AppKit/AppKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Objective-C dashboard renderer with a fixed-size, allocation-free history
/// ring. Feed aggregated rates, not individual packets. Updates are thread-safe
/// and coalesced to at most ten main-thread redraws per second.
@interface HJTrafficDashboardView : NSView

- (void)updateWithUploadBytesPerSecond:(double)upload
              downloadBytesPerSecond:(double)download
                   activeConnections:(NSInteger)connections
    NS_SWIFT_NAME(update(uploadBytesPerSecond:downloadBytesPerSecond:activeConnections:));
- (void)reset NS_SWIFT_NAME(reset());

@end

NS_ASSUME_NONNULL_END
