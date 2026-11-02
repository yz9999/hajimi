#import "HajimiPacketTunnelProvider.h"
#include "HJPacketEngineBridge.h"
#include <arpa/inet.h>
#include <math.h>
#include <string.h>

static NSString * const HJPacketTunnelErrorDomain = @"app.hajimi.PacketTunnel";
static const NSUInteger HJMaximumConfigurationBytes = 8 * 1024 * 1024;
static const NSUInteger HJMaximumQueuedPacketBytes = 8 * 1024 * 1024;
static const NSUInteger HJMaximumQueuedPackets = 256;

typedef NS_ENUM(NSInteger, HJPacketTunnelError) {
    HJPacketTunnelErrorMissingEngine = 1,
    HJPacketTunnelErrorInvalidConfiguration = 2,
    HJPacketTunnelErrorEngineFailure = 3,
    HJPacketTunnelErrorInvalidPacket = 4,
    HJPacketTunnelErrorCanceled = 5,
    HJPacketTunnelErrorSettingsFailed = 6,
    HJPacketTunnelErrorBackpressure = 7,
};

static NSError *HJPacketError(HJPacketTunnelError code, NSString *description,
                             NSError * _Nullable underlying) {
    NSMutableDictionary *info = [@{NSLocalizedDescriptionKey: description} mutableCopy];
    if (underlying) { info[NSUnderlyingErrorKey] = underlying; }
    return [NSError errorWithDomain:HJPacketTunnelErrorDomain code:code userInfo:info];
}

static NSString *HJEngineErrorMessage(const char *message, NSString *fallback) {
    if (!message || !message[0]) { return fallback; }
    return [[NSString alloc] initWithBytes:message length:strnlen(message, 1024)
                                 encoding:NSUTF8StringEncoding] ?: fallback;
}

static BOOL HJIPv4Address(id value, struct in_addr *output) {
    struct in_addr address;
    BOOL valid = [value isKindOfClass:NSString.class] &&
        inet_pton(AF_INET, [value UTF8String], &address) == 1;
    if (valid && output) { *output = address; }
    return valid;
}

static BOOL HJIPv6Address(id value, struct in6_addr *output) {
    struct in6_addr address;
    BOOL valid = [value isKindOfClass:NSString.class] &&
        inet_pton(AF_INET6, [value UTF8String], &address) == 1;
    if (valid && output) { *output = address; }
    return valid;
}

static BOOL HJNumberInRange(id value, NSInteger minimum, NSInteger maximum) {
    if (![value isKindOfClass:NSNumber.class]) { return NO; }
    double number = [value doubleValue];
    return isfinite(number) && number == trunc(number) && number >= (double)minimum &&
        number <= (double)maximum;
}

static BOOL HJSubnetMask(id value, struct in_addr *output) {
    struct in_addr mask;
    if (!HJIPv4Address(value, &mask)) { return NO; }
    uint32_t inverted = ~ntohl(mask.s_addr);
    if ((inverted & (inverted + 1u)) != 0) { return NO; }
    if (output) { *output = mask; }
    return YES;
}

static NSArray<NEIPv4Route *> * _Nullable HJIPv4Routes(id value, BOOL required) {
    if (!value && !required) { return @[]; }
    if (![value isKindOfClass:NSArray.class] || [value count] > 256 ||
        (required && [value count] == 0)) { return nil; }
    NSMutableArray *routes = [NSMutableArray array];
    for (id raw in value) {
        if (![raw isKindOfClass:NSDictionary.class]) { return nil; }
        struct in_addr address, mask;
        if (!HJIPv4Address(raw[@"destination"], &address) ||
            !HJSubnetMask(raw[@"subnetMask"], &mask) ||
            (ntohl(address.s_addr) & ~ntohl(mask.s_addr)) != 0) { return nil; }
        [routes addObject:[[NEIPv4Route alloc] initWithDestinationAddress:raw[@"destination"]
                                                             subnetMask:raw[@"subnetMask"]]];
    }
    return routes;
}

static NSArray<NEIPv6Route *> * _Nullable HJIPv6Routes(id value, BOOL required) {
    if (!value && !required) { return @[]; }
    if (![value isKindOfClass:NSArray.class] || [value count] > 256 ||
        (required && [value count] == 0)) { return nil; }
    NSMutableArray *routes = [NSMutableArray array];
    for (id raw in value) {
        if (![raw isKindOfClass:NSDictionary.class]) { return nil; }
        struct in6_addr address;
        if (!HJIPv6Address(raw[@"destination"], &address) ||
            !HJNumberInRange(raw[@"prefixLength"], 0, 128)) { return nil; }
        NSInteger prefix = [raw[@"prefixLength"] integerValue];
        for (NSInteger i = 0; i < 16; ++i) {
            NSInteger remaining = MAX(0, MIN(8, prefix - i * 8));
            uint8_t hostMask = (uint8_t)(0xffu >> remaining);
            if ((address.s6_addr[i] & hostMask) != 0) { return nil; }
        }
        [routes addObject:[[NEIPv6Route alloc] initWithDestinationAddress:raw[@"destination"]
                                                   networkPrefixLength:raw[@"prefixLength"]]];
    }
    return routes;
}

static NEPacketTunnelNetworkSettings * _Nullable HJNetworkSettings(NSDictionary *configuration,
                                                                  NSError **error) {
    NSString *remote = configuration[@"tunnelRemoteAddress"];
    NSDictionary *v4 = configuration[@"ipv4"];
    NSDictionary *v6 = configuration[@"ipv6"];
    NSArray *dns = configuration[@"dnsServers"];
    NSNumber *mtu = configuration[@"mtu"] ?: @1500;
    if ((!HJIPv4Address(remote, NULL) && !HJIPv6Address(remote, NULL)) ||
        ![v4 isKindOfClass:NSDictionary.class] || !HJIPv4Address(v4[@"address"], NULL) ||
        !HJSubnetMask(v4[@"subnetMask"], NULL) || ![dns isKindOfClass:NSArray.class] ||
        dns.count == 0 || dns.count > 16 || !HJNumberInRange(mtu, v6 ? 1280 : 576, 9000)) {
        *error = HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
            @"隧道需要有效的 remote 地址、IPv4 地址/掩码、DNS 与 MTU。", nil);
        return nil;
    }
    for (id server in dns) {
        if (!HJIPv4Address(server, NULL) && !HJIPv6Address(server, NULL)) {
            *error = HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                   @"dnsServers 只能包含 IP 地址。", nil);
            return nil;
        }
    }
    NSArray *included4 = HJIPv4Routes(v4[@"includedRoutes"], YES);
    NSArray *excluded4 = HJIPv4Routes(v4[@"excludedRoutes"], NO);
    if (!included4 || !excluded4) {
        *error = HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                               @"IPv4 路由必须显式提供且使用规范网络地址和连续掩码。", nil);
        return nil;
    }
    NEPacketTunnelNetworkSettings *settings = [[NEPacketTunnelNetworkSettings alloc]
        initWithTunnelRemoteAddress:remote];
    NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:@[v4[@"address"]]
                                                       subnetMasks:@[v4[@"subnetMask"]]];
    ipv4.includedRoutes = included4;
    ipv4.excludedRoutes = excluded4;
    settings.IPv4Settings = ipv4;
    if (v6) {
        if (![v6 isKindOfClass:NSDictionary.class] || !HJIPv6Address(v6[@"address"], NULL) ||
            !HJNumberInRange(v6[@"prefixLength"], 0, 128)) {
            *error = HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                   @"IPv6 地址或前缀无效。", nil);
            return nil;
        }
        NSArray *included6 = HJIPv6Routes(v6[@"includedRoutes"], YES);
        NSArray *excluded6 = HJIPv6Routes(v6[@"excludedRoutes"], NO);
        if (!included6 || !excluded6) {
            *error = HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                   @"IPv6 路由必须显式提供且使用规范网络地址。", nil);
            return nil;
        }
        NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:@[v6[@"address"]]
                                                 networkPrefixLengths:@[v6[@"prefixLength"]]];
        ipv6.includedRoutes = included6;
        ipv6.excludedRoutes = excluded6;
        settings.IPv6Settings = ipv6;
    }
    NEDNSSettings *dnsSettings = [[NEDNSSettings alloc] initWithServers:dns];
    dnsSettings.matchDomains = @[@""];
    settings.DNSSettings = dnsSettings;
    settings.MTU = mtu;
    return settings;
}

static BOOL HJValidPacket(const uint8_t *packet, size_t length, int32_t family) {
    if (!packet || length == 0 || length > 65575) { return NO; }
    if (family == AF_INET) {
        if (length < 20 || (packet[0] >> 4) != 4) { return NO; }
        size_t header = (size_t)(packet[0] & 0x0f) * 4;
        size_t total = ((size_t)packet[2] << 8) | packet[3];
        return header >= 20 && header <= length && total == length;
    }
    if (family == AF_INET6) {
        if (length < 40 || (packet[0] >> 4) != 6) { return NO; }
        size_t payload = ((size_t)packet[4] << 8) | packet[5];
        return payload + 40 == length; // IPv6 jumbograms are deliberately unsupported.
    }
    return NO;
}

@interface HJPacketEngineCallbackContext : NSObject
@property (nonatomic, weak) HajimiPacketTunnelProvider *provider;
@property (nonatomic) NSUInteger generation;
@property (nonatomic, strong) NSLock *lock;
@property (nonatomic) BOOL accepting;
@property (nonatomic) NSUInteger queuedBytes;
@end
@implementation HJPacketEngineCallbackContext
@end

@interface HajimiPacketTunnelProvider ()
- (int32_t)acceptEnginePacket:(const uint8_t *)bytes length:(size_t)length
                      family:(int32_t)family context:(HJPacketEngineCallbackContext *)context;
- (void)acceptEngineFailure:(NSError *)error generation:(NSUInteger)generation;
@end

static int32_t HJEngineEmit(void *opaque, const uint8_t *bytes, size_t length, int32_t family) {
    HJPacketEngineCallbackContext *context = (__bridge HJPacketEngineCallbackContext *)opaque;
    HajimiPacketTunnelProvider *provider = context.provider;
    return provider ? [provider acceptEnginePacket:bytes length:length family:family context:context] : -1;
}

static void HJEngineFailure(void *opaque, int32_t code, const char *message) {
    HJPacketEngineCallbackContext *context = (__bridge HJPacketEngineCallbackContext *)opaque;
    NSError *underlying = [NSError errorWithDomain:@"app.hajimi.NativePacketEngine" code:code userInfo:nil];
    [context.provider acceptEngineFailure:HJPacketError(HJPacketTunnelErrorEngineFailure,
        HJEngineErrorMessage(message, @"原生报文引擎报告失败。"), underlying)
                                generation:context.generation];
}

@implementation HajimiPacketTunnelProvider {
    dispatch_queue_t _packetQueue;
    const hj_packet_engine_api_v1 *_engineAPI;
    void *_engine;
    HJPacketEngineCallbackContext *_callbackContext;
    NSUInteger _generation;
    BOOL _starting;
    BOOL _running;
    BOOL _flushScheduled;
    BOOL _hasIPv6;
    BOOL _applyingSettings;
    void (^_startCompletion)(NSError * _Nullable);
    void (^_deferredStartCompletion)(NSError * _Nullable);
    NSError *_deferredStartError;
    NSMutableArray *_stopCompletions;
    NSMutableArray<NSData *> *_outputPackets;
    NSMutableArray<NSNumber *> *_outputFamilies;
    NSUInteger _outputBytes;
    uint64_t _packetsSubmitted;
    uint64_t _packetsWritten;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _packetQueue = dispatch_queue_create("app.hajimi.PacketTunnel.packets", DISPATCH_QUEUE_SERIAL);
        _outputPackets = [NSMutableArray array];
        _outputFamilies = [NSMutableArray array];
        _stopCompletions = [NSMutableArray array];
    }
    return self;
}

- (void)dealloc { [self tearDownEngine]; }

- (void)completeDeferredLifecycle {
    if (_applyingSettings) { return; }
    void (^startCompletion)(NSError *) = _deferredStartCompletion;
    NSError *startError = _deferredStartError;
    _deferredStartCompletion = nil;
    _deferredStartError = nil;
    if (startCompletion) { startCompletion(startError); }
    NSArray *stops = [_stopCompletions copy];
    [_stopCompletions removeAllObjects];
    for (dispatch_block_t stopCompletion in stops) { stopCompletion(); }
}

- (void)tearDownEngine {
    [_callbackContext.lock lock];
    _callbackContext.accepting = NO;
    [_callbackContext.lock unlock];
    if (_engine) {
        // The ABI explicitly requires synchronous callback quiescence. No
        // callback context is released before stop/destroy have returned.
        _engineAPI->stop(_engine);
        _engineAPI->destroy(_engine);
        _engine = NULL;
    }
    _callbackContext = nil;
    _engineAPI = NULL;
    [_outputPackets removeAllObjects];
    [_outputFamilies removeAllObjects];
    _outputBytes = 0;
    _flushScheduled = NO;
}

- (void)failTunnel:(NSError *)error {
    BOOL wasStarting = _starting;
    _running = NO;
    _starting = NO;
    ++_generation;
    void (^completion)(NSError *) = _startCompletion;
    _startCompletion = nil;
    [self tearDownEngine];
    if (wasStarting && completion && _applyingSettings) {
        // Do not signal a stopped/failed lifecycle while a settings request
        // could still complete afterwards and reinstall its routes.
        _deferredStartCompletion = completion;
        _deferredStartError = error;
    }
    else if (wasStarting && completion) { completion(error); }
    else { [self cancelTunnelWithError:error]; }
}

- (void)startTunnelWithOptions:(NSDictionary<NSString *,NSObject *> *)options
            completionHandler:(void (^)(NSError * _Nullable))completionHandler {
    (void)options;
    dispatch_async(_packetQueue, ^{
        if (self->_running || self->_starting || self->_applyingSettings) {
            completionHandler(HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                             @"隧道已经启动或正在启动。", nil));
            return;
        }
        self->_starting = YES;
        self->_startCompletion = [completionHandler copy];
        NSUInteger generation = ++self->_generation;
        NEVPNProtocol *base = self.protocolConfiguration;
        if (![base isKindOfClass:NETunnelProviderProtocol.class] ||
            ![((NETunnelProviderProtocol *)base).providerBundleIdentifier
                isEqualToString:@"app.hajimi.PacketTunnel"]) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                           @"隧道配置不属于 app.hajimi.PacketTunnel。", nil)];
            return;
        }
        NSDictionary *configuration = ((NETunnelProviderProtocol *)base).providerConfiguration;
        NSData *engineConfiguration = [configuration isKindOfClass:NSDictionary.class]
            ? configuration[@"engineConfiguration"] : nil;
        if (!configuration ||
            ![engineConfiguration isKindOfClass:NSData.class] || engineConfiguration.length == 0 ||
            engineConfiguration.length > HJMaximumConfigurationBytes) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorInvalidConfiguration,
                                           @"缺少有效的原生引擎配置数据。", nil)];
            return;
        }
        NSError *settingsError = nil;
        NEPacketTunnelNetworkSettings *settings = HJNetworkSettings(configuration, &settingsError);
        if (!settings) { [self failTunnel:settingsError]; return; }
        self->_hasIPv6 = settings.IPv6Settings != nil;
        uint32_t required = HJ_PACKET_ENGINE_CAP_IPV4 | HJ_PACKET_ENGINE_CAP_TCP | HJ_PACKET_ENGINE_CAP_UDP;
        if (self->_hasIPv6) { required |= HJ_PACKET_ENGINE_CAP_IPV6; }
        const hj_packet_engine_api_v1 *api = hajimi_packet_engine_get_api_v1
            ? hajimi_packet_engine_get_api_v1() : NULL;
        if (!api || api->abi_version != HJ_PACKET_ENGINE_ABI_VERSION ||
            api->struct_size < sizeof(hj_packet_engine_api_v1) ||
            (api->capabilities & required) != required || !api->create || !api->start ||
            !api->submit_packet || !api->stop || !api->destroy) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorMissingEngine,
                @"扩展未链接兼容的共享 TCP/UDP 报文引擎；为避免截断网络，未安装隧道路由。", nil)];
            return;
        }
        self->_engineAPI = api;
        HJPacketEngineCallbackContext *context = [[HJPacketEngineCallbackContext alloc] init];
        context.provider = self;
        context.generation = generation;
        context.lock = [[NSLock alloc] init];
        context.accepting = YES;
        self->_callbackContext = context;
        hj_packet_engine_callbacks_v1 callbacks = {
            .struct_size = sizeof(hj_packet_engine_callbacks_v1),
            .context = (__bridge void *)context,
            .emit_packet = HJEngineEmit,
            .report_failure = HJEngineFailure,
        };
        char message[512] = {0};
        self->_engine = api->create(engineConfiguration.bytes, engineConfiguration.length,
                                    &callbacks, message, sizeof(message));
        message[sizeof(message) - 1] = '\0';
        if (!self->_engine) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorEngineFailure,
                HJEngineErrorMessage(message, @"无法创建共享报文引擎。"), nil)];
            return;
        }
        memset(message, 0, sizeof(message));
        int32_t started = api->start(self->_engine, message, sizeof(message));
        message[sizeof(message) - 1] = '\0';
        if (started != 0) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorEngineFailure,
                HJEngineErrorMessage(message, @"共享报文引擎启动失败。"), nil)];
            return;
        }
        // This is the first operation that may capture traffic. Both a valid
        // engine and an explicitly described route set must be ready first.
        self->_applyingSettings = YES;
        __weak typeof(self) weakSelf = self;
        [self setTunnelNetworkSettings:settings completionHandler:^(NSError *error) {
            HajimiPacketTunnelProvider *provider = weakSelf;
            if (!provider) { return; }
            dispatch_async(provider->_packetQueue, ^{
                provider->_applyingSettings = NO;
                if (generation != provider->_generation || !provider->_starting) {
                    [provider completeDeferredLifecycle];
                    return;
                }
                if (error) {
                    [provider failTunnel:HJPacketError(HJPacketTunnelErrorSettingsFailed,
                                                  @"macOS 无法应用隧道网络设置。", error)];
                    return;
                }
                provider->_starting = NO;
                provider->_running = YES;
                provider->_packetsSubmitted = 0;
                provider->_packetsWritten = 0;
                void (^completion)(NSError *) = provider->_startCompletion;
                provider->_startCompletion = nil;
                completion(nil);
                [provider flushOutput:generation];
                [provider readPacketBatch:generation];
            });
        }];
    });
}

- (void)readPacketBatch:(NSUInteger)generation {
    if (!_running || generation != _generation) { return; }
    __weak typeof(self) weakSelf = self;
    [self.packetFlow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets,
                                                        NSArray<NSNumber *> *protocols) {
        HajimiPacketTunnelProvider *provider = weakSelf;
        if (!provider) { return; }
        dispatch_async(provider->_packetQueue, ^{
            if (!provider->_running || generation != provider->_generation) { return; }
            if (packets.count != protocols.count) {
                [provider failTunnel:HJPacketError(HJPacketTunnelErrorInvalidPacket,
                                                   @"packetFlow 返回的报文/地址族数量不一致。", nil)];
                return;
            }
            for (NSUInteger i = 0; i < packets.count; ++i) {
                NSData *packet = packets[i];
                int32_t family = protocols[i].intValue;
                if (!HJValidPacket(packet.bytes, packet.length, family) ||
                    (family == AF_INET6 && !provider->_hasIPv6)) {
                    [provider failTunnel:HJPacketError(HJPacketTunnelErrorInvalidPacket,
                                                       @"packetFlow 返回了无效或未启用的 IP 报文。", nil)];
                    return;
                }
                char message[512] = {0};
                int32_t result = provider->_engineAPI->submit_packet(provider->_engine,
                    packet.bytes, packet.length, family, message, sizeof(message));
                message[sizeof(message) - 1] = '\0';
                if (result != 0) {
                    [provider failTunnel:HJPacketError(HJPacketTunnelErrorEngineFailure,
                        HJEngineErrorMessage(message, @"原生引擎未能处理 IP 报文；隧道已停止。"), nil)];
                    return;
                }
                ++provider->_packetsSubmitted;
            }
            [provider readPacketBatch:generation];
        });
    }];
}

- (int32_t)acceptEnginePacket:(const uint8_t *)bytes length:(size_t)length
                      family:(int32_t)family context:(HJPacketEngineCallbackContext *)context {
    if (!HJValidPacket(bytes, length, family)) {
        [self acceptEngineFailure:HJPacketError(HJPacketTunnelErrorInvalidPacket,
            @"原生引擎输出了无效 IP 报文。", nil) generation:context.generation];
        return -1;
    }
    [context.lock lock];
    BOOL accepted = context.accepting && length <= HJMaximumQueuedPacketBytes - context.queuedBytes;
    if (accepted) { context.queuedBytes += length; }
    [context.lock unlock];
    if (!accepted) {
        [self acceptEngineFailure:HJPacketError(HJPacketTunnelErrorBackpressure,
            @"原生引擎报文输出队列已关闭或达到上限。", nil) generation:context.generation];
        return -1;
    }
    NSData *copy = [NSData dataWithBytes:bytes length:length];
    dispatch_async(_packetQueue, ^{
        [context.lock lock];
        context.queuedBytes -= length;
        [context.lock unlock];
        if (context.generation != self->_generation || (!self->_running && !self->_starting)) { return; }
        if ((family == AF_INET6 && !self->_hasIPv6) ||
            self->_outputPackets.count >= HJMaximumQueuedPackets ||
            length > HJMaximumQueuedPacketBytes - self->_outputBytes) {
            [self failTunnel:HJPacketError(HJPacketTunnelErrorBackpressure,
                                           @"待写入系统的报文达到上限或地址族未启用。", nil)];
            return;
        }
        [self->_outputPackets addObject:copy];
        [self->_outputFamilies addObject:@(family)];
        self->_outputBytes += length;
        if (self->_running && !self->_flushScheduled) {
            self->_flushScheduled = YES;
            dispatch_async(self->_packetQueue, ^{ [self flushOutput:context.generation]; });
        }
    });
    return 0;
}

- (void)flushOutput:(NSUInteger)generation {
    if (generation != _generation || !_running) { return; }
    _flushScheduled = NO;
    if (_outputPackets.count == 0) { return; }
    NSArray *packets = [_outputPackets copy];
    NSArray *families = [_outputFamilies copy];
    [_outputPackets removeAllObjects];
    [_outputFamilies removeAllObjects];
    _outputBytes = 0;
    if (![self.packetFlow writePackets:packets withProtocols:families]) {
        [self failTunnel:HJPacketError(HJPacketTunnelErrorEngineFailure,
                                       @"无法将引擎返回的 IP 报文写入系统。", nil)];
        return;
    }
    _packetsWritten += packets.count;
}

- (void)acceptEngineFailure:(NSError *)error generation:(NSUInteger)generation {
    dispatch_async(_packetQueue, ^{
        if (generation == self->_generation && (self->_starting || self->_running)) {
            [self failTunnel:error];
        }
    });
}

- (void)stopTunnelWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completionHandler {
    (void)reason;
    dispatch_async(_packetQueue, ^{
        self->_running = NO;
        self->_starting = NO;
        ++self->_generation;
        void (^startCompletion)(NSError *) = self->_startCompletion;
        self->_startCompletion = nil;
        [self tearDownEngine];
        if (startCompletion) {
            self->_deferredStartCompletion = startCompletion;
            self->_deferredStartError = HJPacketError(HJPacketTunnelErrorCanceled,
                                                      @"隧道启动已取消。", nil);
        }
        // NetworkExtension owns route/DNS teardown; no private utun descriptor
        // access or global networksetup/route commands are used here.
        [self->_stopCompletions addObject:[completionHandler copy]];
        [self completeDeferredLifecycle];
    });
}

- (void)handleAppMessage:(NSData *)messageData
      completionHandler:(void (^)(NSData * _Nullable))completionHandler {
    (void)messageData;
    if (!completionHandler) { return; }
    dispatch_async(_packetQueue, ^{
        const hj_packet_engine_api_v1 *api = hajimi_packet_engine_get_api_v1
            ? hajimi_packet_engine_get_api_v1() : NULL;
        NSDictionary *snapshot = @{@"running": @(self->_running),
            @"nativeEngineLinked": @(api != NULL),
            @"packetsSubmitted": @(self->_packetsSubmitted),
            @"packetsWritten": @(self->_packetsWritten)};
        completionHandler([NSJSONSerialization dataWithJSONObject:snapshot options:0 error:nil]);
    });
}

@end
