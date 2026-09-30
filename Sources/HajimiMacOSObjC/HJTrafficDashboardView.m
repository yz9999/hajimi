#import "HJTrafficDashboardView.h"
#include <math.h>

static const NSUInteger HJTrafficHistoryCapacity = 60;

static NSString *HJRateDescription(double bytes) {
    static NSArray<NSString *> *units;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ units = @[@"B/s", @"KiB/s", @"MiB/s", @"GiB/s", @"TiB/s"]; });
    NSUInteger unit = 0;
    while (bytes >= 1024.0 && unit + 1 < units.count) { bytes /= 1024.0; ++unit; }
    return [NSString stringWithFormat:unit == 0 ? @"%.0f %@" : @"%.1f %@", bytes, units[unit]];
}

@implementation HJTrafficDashboardView {
    NSLock *_snapshotLock;
    double _pendingUpload;
    double _pendingDownload;
    NSInteger _pendingConnections;
    BOOL _redrawScheduled;
    double _upload;
    double _download;
    NSInteger _connections;
    double _uploadHistory[60];
    double _downloadHistory[60];
    NSUInteger _historyHead;
    NSUInteger _historyCount;
}

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) { [self setUpTelemetry]; }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super initWithCoder:coder];
    if (self) { [self setUpTelemetry]; }
    return self;
}

- (void)setUpTelemetry {
    _snapshotLock = [[NSLock alloc] init];
    self.accessibilityElement = YES;
    self.accessibilityRole = NSAccessibilityGroupRole;
    self.accessibilityLabel = @"网络流量概览";
}

- (BOOL)isFlipped { return YES; }
- (NSSize)intrinsicContentSize { return NSMakeSize(NSViewNoIntrinsicMetric, 126); }

- (void)updateWithUploadBytesPerSecond:(double)upload
              downloadBytesPerSecond:(double)download
                   activeConnections:(NSInteger)connections {
    [_snapshotLock lock];
    _pendingUpload = isfinite(upload) && upload > 0 ? upload : 0;
    _pendingDownload = isfinite(download) && download > 0 ? download : 0;
    _pendingConnections = MAX(0, connections);
    BOOL schedule = !_redrawScheduled;
    _redrawScheduled = YES;
    [_snapshotLock unlock];
    if (!schedule) { return; }
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [weakSelf applyPendingSnapshot]; });
}

- (void)applyPendingSnapshot {
    [_snapshotLock lock];
    _upload = _pendingUpload;
    _download = _pendingDownload;
    _connections = _pendingConnections;
    _redrawScheduled = NO;
    [_snapshotLock unlock];
    _uploadHistory[_historyHead] = _upload;
    _downloadHistory[_historyHead] = _download;
    _historyHead = (_historyHead + 1) % HJTrafficHistoryCapacity;
    _historyCount = MIN(_historyCount + 1, HJTrafficHistoryCapacity);
    self.accessibilityValue = [NSString stringWithFormat:@"上传 %@，下载 %@，活动连接 %ld",
        HJRateDescription(_upload), HJRateDescription(_download), (long)_connections];
    self.needsDisplay = YES;
}

- (void)reset {
    [self updateWithUploadBytesPerSecond:0 downloadBytesPerSecond:0 activeConnections:0];
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        HJTrafficDashboardView *view = weakSelf;
        if (!view) { return; }
        memset(view->_uploadHistory, 0, sizeof(view->_uploadHistory));
        memset(view->_downloadHistory, 0, sizeof(view->_downloadHistory));
        view->_historyHead = 0;
        view->_historyCount = 0;
        view.needsDisplay = YES;
    });
}

- (void)drawHistory:(const double *)values color:(NSColor *)color
              rect:(NSRect)rect peak:(double)peak {
    if (_historyCount < 2 || rect.size.width <= 0 || rect.size.height <= 0) { return; }
    NSBezierPath *line = [NSBezierPath bezierPath];
    line.lineWidth = 1.5;
    for (NSUInteger i = 0; i < _historyCount; ++i) {
        NSUInteger index = (_historyHead + HJTrafficHistoryCapacity - _historyCount + i)
            % HJTrafficHistoryCapacity;
        CGFloat x = NSMinX(rect) + (CGFloat)i / (CGFloat)(_historyCount - 1) * NSWidth(rect);
        CGFloat y = NSMaxY(rect) - (CGFloat)(values[index] / peak) * NSHeight(rect);
        if (i == 0) { [line moveToPoint:NSMakePoint(x, y)]; }
        else { [line lineToPoint:NSMakePoint(x, y)]; }
    }
    [color setStroke];
    [line stroke];
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    [NSColor.controlBackgroundColor setFill];
    [[NSBezierPath bezierPathWithRoundedRect:self.bounds xRadius:12 yRadius:12] fill];
    CGFloat columnWidth = MAX(0, (NSWidth(self.bounds) - 32) / 3);
    NSArray<NSString *> *titles = @[@"上传", @"下载", @"活动连接"];
    NSArray<NSString *> *values = @[HJRateDescription(_upload), HJRateDescription(_download),
        [NSString stringWithFormat:@"%ld", (long)_connections]];
    NSDictionary *labelAttributes = @{NSFontAttributeName: [NSFont systemFontOfSize:11],
        NSForegroundColorAttributeName: NSColor.secondaryLabelColor};
    NSDictionary *valueAttributes = @{NSFontAttributeName:
        [NSFont monospacedDigitSystemFontOfSize:18 weight:NSFontWeightSemibold],
        NSForegroundColorAttributeName: NSColor.labelColor};
    for (NSUInteger i = 0; i < titles.count; ++i) {
        CGFloat x = 16 + (CGFloat)i * columnWidth;
        [titles[i] drawInRect:NSMakeRect(x, 13, MAX(0, columnWidth - 8), 16)
              withAttributes:labelAttributes];
        [values[i] drawInRect:NSMakeRect(x, 34, MAX(0, columnWidth - 8), 25)
              withAttributes:valueAttributes];
    }
    double peak = 1;
    for (NSUInteger i = 0; i < HJTrafficHistoryCapacity; ++i) {
        peak = MAX(peak, MAX(_uploadHistory[i], _downloadHistory[i]));
    }
    NSRect chart = NSMakeRect(16, 70, MAX(0, NSWidth(self.bounds) - 32),
                              MAX(0, NSHeight(self.bounds) - 84));
    [self drawHistory:_uploadHistory color:NSColor.systemBlueColor rect:chart peak:peak];
    [self drawHistory:_downloadHistory color:NSColor.systemGreenColor rect:chart peak:peak];
}

@end
