#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const HJPacketTunnelProviderBundleIdentifier;
FOUNDATION_EXPORT NSErrorDomain const HJNetworkExtensionErrorDomain;

typedef NS_ERROR_ENUM(HJNetworkExtensionErrorDomain, HJNetworkExtensionError) {
    HJNetworkExtensionErrorMissingEntitlement = 1,
    HJNetworkExtensionErrorProviderNotInstalled = 2,
    HJNetworkExtensionErrorNotConfigured = 3,
    HJNetworkExtensionErrorInvalidConfiguration = 4,
    HJNetworkExtensionErrorLoadFailed = 5,
    HJNetworkExtensionErrorSaveFailed = 6,
    HJNetworkExtensionErrorStartFailed = 7,
    HJNetworkExtensionErrorBusy = 8,
    HJNetworkExtensionErrorAmbiguousConfiguration = 9,
};

/// Manages only app.hajimi.PacketTunnel. Creating this object has no network
/// side effects. All completions and status notifications run on the main queue.
/// Saving and starting are separate, explicit operations; no on-demand VPN is
/// enabled. A successful start completion means the request was accepted, not
/// that the tunnel has finished connecting: observe statusDidChangeHandler.
@interface HJNetworkExtensionController : NSObject

@property (nonatomic, readonly) NEVPNStatus status;
@property (nonatomic, readonly, copy) NSString *statusDescription;
@property (nonatomic, readonly) BOOL hasSavedConfiguration;
/// Checks the running host's entitlement and its bundled, scoped .appex. This
/// is a preflight only; macOS still verifies provisioning and signing on use.
@property (nonatomic, readonly, nullable) NSError *availabilityError;
@property (nonatomic, copy, nullable) void (^statusDidChangeHandler)(NEVPNStatus status,
                                                                   NSString *description);

- (void)loadWithCompletion:(void (^)(NSError * _Nullable error))completion
    NS_SWIFT_NAME(load(completion:));
- (void)saveConfiguration:(NSDictionary<NSString *, id> *)configuration
    localizedDescription:(NSString *)description
               completion:(void (^)(NSError * _Nullable error))completion
    NS_SWIFT_NAME(save(configuration:description:completion:));
- (void)startWithCompletion:(void (^)(NSError * _Nullable error))completion
    NS_SWIFT_NAME(start(completion:));
- (void)stopWithCompletion:(void (^)(NSError * _Nullable error))completion
    NS_SWIFT_NAME(stop(completion:));

@end

NS_ASSUME_NONNULL_END
