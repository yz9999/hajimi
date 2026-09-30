#import "HJNetworkExtensionController.h"
#import <Security/SecTask.h>

NSString * const HJPacketTunnelProviderBundleIdentifier = @"app.hajimi.PacketTunnel";
NSErrorDomain const HJNetworkExtensionErrorDomain = @"app.hajimi.NetworkExtension";

static void HJOnMain(dispatch_block_t block) {
    if (NSThread.isMainThread) { block(); }
    else { dispatch_async(dispatch_get_main_queue(), block); }
}

static NSError *HJNEError(HJNetworkExtensionError code, NSString *message,
                          NSError * _Nullable underlying) {
    NSMutableDictionary *info = [@{NSLocalizedDescriptionKey: message} mutableCopy];
    if (underlying) { info[NSUnderlyingErrorKey] = underlying; }
    if (code == HJNetworkExtensionErrorMissingEntitlement ||
        code == HJNetworkExtensionErrorProviderNotInstalled) {
        info[NSLocalizedRecoverySuggestionErrorKey] =
            @"请使用具有 packet-tunnel-provider 授权的 Apple 签名与描述文件，"
             "将 app.hajimi.PacketTunnel 扩展嵌入哈基米应用；普通本地签名无法授予此权限。";
    }
    return [NSError errorWithDomain:HJNetworkExtensionErrorDomain code:code userInfo:info];
}

static NSError * _Nullable HJHostEntitlementError(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    CFErrorRef copyError = NULL;
    id entitlement = task ? CFBridgingRelease(SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.developer.networking.networkextension"), &copyError)) : nil;
    if (task) { CFRelease(task); }
    NSError *underlying = CFBridgingRelease(copyError);
    if (![entitlement isKindOfClass:NSArray.class] ||
        ![(NSArray *)entitlement containsObject:@"packet-tunnel-provider"]) {
        return HJNEError(HJNetworkExtensionErrorMissingEntitlement,
                         @"当前应用缺少 Network Extension 的 packet-tunnel-provider 授权。",
                         underlying);
    }
    return nil;
}

static NSError * _Nullable HJBundledProviderError(void) {
    NSURL *pluginsURL = NSBundle.mainBundle.builtInPlugInsURL;
    NSArray<NSURL *> *URLs = pluginsURL ? [NSFileManager.defaultManager
        contentsOfDirectoryAtURL:pluginsURL includingPropertiesForKeys:nil options:0 error:nil] : nil;
    for (NSURL *URL in URLs) {
        if (![URL.pathExtension isEqualToString:@"appex"]) { continue; }
        NSBundle *bundle = [NSBundle bundleWithURL:URL];
        if (![bundle.bundleIdentifier isEqualToString:HJPacketTunnelProviderBundleIdentifier]) {
            continue;
        }
        NSDictionary *extension = [bundle objectForInfoDictionaryKey:@"NSExtension"];
        NSString *point = [extension isKindOfClass:NSDictionary.class]
            ? extension[@"NSExtensionPointIdentifier"] : nil;
        NSString *principal = [extension isKindOfClass:NSDictionary.class]
            ? extension[@"NSExtensionPrincipalClass"] : nil;
        if ([point isKindOfClass:NSString.class] &&
            [point isEqualToString:@"com.apple.networkextension.packet-tunnel"] &&
            [principal isKindOfClass:NSString.class] && principal.length > 0 &&
            bundle.executableURL && [NSFileManager.defaultManager
                isExecutableFileAtPath:bundle.executableURL.path]) { return nil; }
    }
    return HJNEError(HJNetworkExtensionErrorProviderNotInstalled,
                     @"应用中未找到可用的 app.hajimi.PacketTunnel 扩展。", nil);
}

@interface HJNetworkExtensionController ()
@property (nonatomic, strong, nullable) NETunnelProviderManager *manager;
@property (nonatomic) BOOL operationInFlight;
@property (nonatomic, strong) id statusObserver;
@end

@implementation HJNetworkExtensionController

- (instancetype)init {
    self = [super init];
    if (self) {
        __weak typeof(self) weakSelf = self;
        _statusObserver = [NSNotificationCenter.defaultCenter
            addObserverForName:NEVPNStatusDidChangeNotification object:nil
                         queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
            HJNetworkExtensionController *strongSelf = weakSelf;
            if (strongSelf.manager && note.object == strongSelf.manager.connection) {
                [strongSelf publishStatus];
            }
        }];
    }
    return self;
}

- (void)dealloc {
    if (_statusObserver) { [NSNotificationCenter.defaultCenter removeObserver:_statusObserver]; }
    // Releasing a dashboard/controller never stops a user-owned VPN session.
}

- (NEVPNStatus)status { return self.manager ? self.manager.connection.status : NEVPNStatusInvalid; }
- (BOOL)hasSavedConfiguration { return self.manager != nil; }

- (NSString *)statusDescription {
    switch (self.status) {
        case NEVPNStatusInvalid: return @"未配置";
        case NEVPNStatusDisconnected: return @"未连接";
        case NEVPNStatusConnecting: return @"正在连接";
        case NEVPNStatusConnected: return @"已连接";
        case NEVPNStatusReasserting: return @"正在重连";
        case NEVPNStatusDisconnecting: return @"正在断开";
    }
    return @"未知状态";
}

- (NSError *)availabilityError { return HJHostEntitlementError() ?: HJBundledProviderError(); }

- (void)publishStatus {
    if (self.statusDidChangeHandler) { self.statusDidChangeHandler(self.status, self.statusDescription); }
}

- (BOOL)beginOperation:(void (^)(NSError * _Nullable))completion {
    if (self.operationInFlight) {
        completion(HJNEError(HJNetworkExtensionErrorBusy, @"另一项 Network Extension 操作尚未完成。", nil));
        return NO;
    }
    self.operationInFlight = YES;
    return YES;
}

- (void)finishOperation:(NSError * _Nullable)error completion:(void (^)(NSError * _Nullable))completion {
    self.operationInFlight = NO;
    [self publishStatus];
    completion(error);
}

- (void)loadOwnedManager:(void (^)(NETunnelProviderManager * _Nullable,
                                 NSError * _Nullable))completion {
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray *managers,
                                                                          NSError *error) {
        HJOnMain(^{
            if (error) {
                completion(nil, HJNEError(HJNetworkExtensionErrorLoadFailed,
                                          @"无法读取哈基米 Network Extension 配置。", error));
                return;
            }
            NETunnelProviderManager *owned = nil;
            for (NETunnelProviderManager *candidate in managers) {
                NEVPNProtocol *protocol = candidate.protocolConfiguration;
                if (![protocol isKindOfClass:NETunnelProviderProtocol.class] ||
                    ![((NETunnelProviderProtocol *)protocol).providerBundleIdentifier
                        isEqualToString:HJPacketTunnelProviderBundleIdentifier]) { continue; }
                if (owned) {
                    completion(nil, HJNEError(HJNetworkExtensionErrorAmbiguousConfiguration,
                        @"存在多个哈基米隧道配置；请在系统设置中确认保留哪一个。", nil));
                    return;
                }
                owned = candidate;
            }
            completion(owned, nil);
        });
    }];
}

- (void)loadWithCompletion:(void (^)(NSError * _Nullable))completion {
    HJOnMain(^{
        NSError *availability = self.availabilityError;
        if (availability) { completion(availability); return; }
        if (![self beginOperation:completion]) { return; }
        [self loadOwnedManager:^(NETunnelProviderManager *manager, NSError *error) {
            if (!error) { self.manager = manager; }
            [self finishOperation:error completion:completion];
        }];
    });
}

- (void)saveConfiguration:(NSDictionary<NSString *,id> *)configuration
    localizedDescription:(NSString *)description
               completion:(void (^)(NSError * _Nullable))completion {
    // Deep-copy as an immutable property list before dispatch. A top-level
    // NSDictionary copy would still retain caller-owned mutable nested arrays.
    NSError *snapshotError = nil;
    NSData *serialized = [configuration isKindOfClass:NSDictionary.class] && configuration.count
        ? [NSPropertyListSerialization dataWithPropertyList:configuration
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:&snapshotError] : nil;
    NSDictionary *snapshot = serialized ? [NSPropertyListSerialization propertyListWithData:serialized
        options:NSPropertyListImmutable format:NULL error:&snapshotError] : nil;
    NSString *descriptionSnapshot = [description copy];
    HJOnMain(^{
        NSError *availability = self.availabilityError;
        if (availability) { completion(availability); return; }
        if (![snapshot isKindOfClass:NSDictionary.class] || snapshot.count == 0) {
            completion(HJNEError(HJNetworkExtensionErrorInvalidConfiguration,
                                 @"隧道配置必须是非空的属性列表字典。", snapshotError));
            return;
        }
        if (![self beginOperation:completion]) { return; }
        [self loadOwnedManager:^(NETunnelProviderManager *manager, NSError *error) {
            if (error) { [self finishOperation:error completion:completion]; return; }
            if (manager && manager.connection.status != NEVPNStatusDisconnected &&
                manager.connection.status != NEVPNStatusInvalid) {
                [self finishOperation:HJNEError(HJNetworkExtensionErrorBusy,
                    @"请先断开哈基米隧道，再保存配置。", nil) completion:completion];
                return;
            }
            NETunnelProviderManager *owned = manager ?: [[NETunnelProviderManager alloc] init];
            NETunnelProviderProtocol *protocol = [[NETunnelProviderProtocol alloc] init];
            protocol.providerBundleIdentifier = HJPacketTunnelProviderBundleIdentifier;
            protocol.providerConfiguration = snapshot;
            protocol.serverAddress = @"Hajimi";
            owned.protocolConfiguration = protocol;
            owned.localizedDescription = descriptionSnapshot.length ? descriptionSnapshot : @"哈基米";
            owned.enabled = YES;
            owned.onDemandEnabled = NO;
            owned.onDemandRules = nil;
            [owned saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
                HJOnMain(^{
                    if (saveError) {
                        [self finishOperation:HJNEError(HJNetworkExtensionErrorSaveFailed,
                            @"无法保存哈基米隧道配置；请检查签名授权与系统许可。", saveError)
                                   completion:completion];
                        return;
                    }
                    [owned loadFromPreferencesWithCompletionHandler:^(NSError *reloadError) {
                        HJOnMain(^{
                            if (!reloadError) { self.manager = owned; }
                            [self finishOperation:reloadError ? HJNEError(HJNetworkExtensionErrorLoadFailed,
                                @"配置已保存，但无法重新加载。", reloadError) : nil completion:completion];
                        });
                    }];
                });
            }];
        }];
    });
}

- (void)startWithCompletion:(void (^)(NSError * _Nullable))completion {
    HJOnMain(^{
        NSError *availability = self.availabilityError;
        if (availability) { completion(availability); return; }
        if (![self beginOperation:completion]) { return; }
        [self loadOwnedManager:^(NETunnelProviderManager *manager, NSError *error) {
            if (error) { [self finishOperation:error completion:completion]; return; }
            self.manager = manager;
            if (!manager || !manager.enabled) {
                [self finishOperation:HJNEError(HJNetworkExtensionErrorNotConfigured,
                    @"请先显式保存并启用哈基米隧道配置。", nil) completion:completion];
                return;
            }
            if (manager.connection.status != NEVPNStatusDisconnected) {
                [self finishOperation:HJNEError(HJNetworkExtensionErrorBusy,
                    @"哈基米隧道当前不是可启动的断开状态。", nil) completion:completion];
                return;
            }
            NSError *startError = nil;
            BOOL accepted = [manager.connection startVPNTunnelAndReturnError:&startError];
            [self finishOperation:accepted ? nil : HJNEError(HJNetworkExtensionErrorStartFailed,
                @"macOS 拒绝启动哈基米隧道；请检查扩展签名、授权与引擎集成。", startError)
                       completion:completion];
        }];
    });
}

- (void)stopWithCompletion:(void (^)(NSError * _Nullable))completion {
    HJOnMain(^{
        // Stopping an owned session is still possible if its bundled extension
        // was removed. Do not require an installed provider for this operation.
        NSError *entitlement = HJHostEntitlementError();
        if (entitlement) { completion(entitlement); return; }
        if (![self beginOperation:completion]) { return; }
        [self loadOwnedManager:^(NETunnelProviderManager *manager, NSError *error) {
            if (error) { [self finishOperation:error completion:completion]; return; }
            self.manager = manager;
            if (!manager) {
                [self finishOperation:HJNEError(HJNetworkExtensionErrorNotConfigured,
                    @"未找到哈基米自己的隧道配置。", nil) completion:completion];
                return;
            }
            [manager.connection stopVPNTunnel];
            [self finishOperation:nil completion:completion];
        }];
    });
}

@end
