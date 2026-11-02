#import <AppKit/AppKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Objective-C status-bar header telemetry card rendered directly into
/// an NSMenuItem.view with a premium native design, supporting light and dark modes.
@interface HJStatusBarHeaderView : NSView

- (void)updateWithRunning:(BOOL)running
             enhancedMode:(BOOL)enhancedMode
              systemProxy:(BOOL)systemProxy
                modeTitle:(nullable NSString *)modeTitle
           activeNodeName:(nullable NSString *)activeNodeName
            latencyMillis:(NSInteger)latencyMillis
     uploadBytesPerSecond:(double)uploadBytesPerSecond
   downloadBytesPerSecond:(double)downloadBytesPerSecond
       totalUploadedBytes:(uint64_t)totalUploadedBytes
     totalDownloadedBytes:(uint64_t)totalDownloadedBytes
        activeConnections:(NSInteger)activeConnections
NS_SWIFT_NAME(update(running:enhancedMode:systemProxy:modeTitle:activeNodeName:latencyMillis:uploadBytesPerSecond:downloadBytesPerSecond:totalUploadedBytes:totalDownloadedBytes:activeConnections:));

@end

NS_ASSUME_NONNULL_END

