#import "HJStatusBarHeaderView.h"

static NSString *HJFormatRate(double bytesPerSec) {
    if (bytesPerSec <= 0.0 || !isfinite(bytesPerSec)) return @"0 B/s";
    if (bytesPerSec < 1024.0) return [NSString stringWithFormat:@"%.0f B/s", bytesPerSec];
    if (bytesPerSec < 1024.0 * 1024.0) return [NSString stringWithFormat:@"%.1f KB/s", bytesPerSec / 1024.0];
    if (bytesPerSec < 1024.0 * 1024.0 * 1024.0) return [NSString stringWithFormat:@"%.1f MB/s", bytesPerSec / (1024.0 * 1024.0)];
    return [NSString stringWithFormat:@"%.2f GB/s", bytesPerSec / (1024.0 * 1024.0 * 1024.0)];
}

static NSString *HJFormatBytes(uint64_t bytes) {
    if (bytes == 0) return @"0 B";
    double d = (double)bytes;
    if (d < 1024.0) return [NSString stringWithFormat:@"%llu B", (unsigned long long)bytes];
    if (d < 1024.0 * 1024.0) return [NSString stringWithFormat:@"%.1f KB", d / 1024.0];
    if (d < 1024.0 * 1024.0 * 1024.0) return [NSString stringWithFormat:@"%.1f MB", d / (1024.0 * 1024.0)];
    return [NSString stringWithFormat:@"%.2f GB", d / (1024.0 * 1024.0 * 1024.0)];
}

@implementation HJStatusBarHeaderView {
    BOOL _running;
    BOOL _enhancedMode;
    BOOL _systemProxy;
    NSString *_modeTitle;
    NSString *_activeNodeName;
    NSInteger _latencyMillis;
    double _uploadBytesPerSecond;
    double _downloadBytesPerSecond;
    uint64_t _totalUploadedBytes;
    uint64_t _totalDownloadedBytes;
    NSInteger _activeConnections;
}

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        self.wantsLayer = YES;
        _running = NO;
        _enhancedMode = NO;
        _systemProxy = NO;
        _modeTitle = @"规则判定";
        _activeNodeName = @"DIRECT";
        _latencyMillis = -1;
        _uploadBytesPerSecond = 0.0;
        _downloadBytesPerSecond = 0.0;
        _totalUploadedBytes = 0;
        _totalDownloadedBytes = 0;
        _activeConnections = 0;
    }
    return self;
}

- (BOOL)isFlipped {
    return YES;
}

- (BOOL)isOpaque {
    return NO;
}

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
        activeConnections:(NSInteger)activeConnections {
    _running = running;
    _enhancedMode = enhancedMode;
    _systemProxy = systemProxy;
    _modeTitle = modeTitle.length > 0 ? [modeTitle copy] : @"规则判定";
    _activeNodeName = activeNodeName.length > 0 ? [activeNodeName copy] : @"DIRECT";
    _latencyMillis = latencyMillis;
    _uploadBytesPerSecond = uploadBytesPerSecond;
    _downloadBytesPerSecond = downloadBytesPerSecond;
    _totalUploadedBytes = totalUploadedBytes;
    _totalDownloadedBytes = totalDownloadedBytes;
    _activeConnections = activeConnections;

    if ([NSThread isMainThread]) {
        [self setNeedsDisplay:YES];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setNeedsDisplay:YES];
        });
    }
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];

    BOOL dark = [[self.effectiveAppearance bestMatchFromAppearancesWithNames:@[
        NSAppearanceNameAqua,
        NSAppearanceNameDarkAqua
    ]] isEqualToString:NSAppearanceNameDarkAqua];

    NSColor *cardFill = dark ? [NSColor colorWithCalibratedRed:0.11 green:0.13 blue:0.14 alpha:0.96]
                             : [NSColor colorWithCalibratedRed:0.96 green:0.97 blue:0.98 alpha:0.96];
    NSColor *border = dark ? [NSColor colorWithCalibratedWhite:1.0 alpha:0.10]
                           : [NSColor colorWithCalibratedWhite:0.0 alpha:0.08];
    NSColor *highlight = dark ? [NSColor colorWithCalibratedWhite:1.0 alpha:0.06]
                              : [NSColor colorWithCalibratedWhite:1.0 alpha:0.65];

    NSColor *downloadColor = dark ? [NSColor colorWithCalibratedRed:0.20 green:0.83 blue:0.62 alpha:1.0]
                                  : [NSColor colorWithCalibratedRed:0.04 green:0.55 blue:0.41 alpha:1.0];
    NSColor *uploadColor = dark ? [NSColor colorWithCalibratedRed:0.36 green:0.68 blue:0.96 alpha:1.0]
                                : [NSColor colorWithCalibratedRed:0.12 green:0.46 blue:0.82 alpha:1.0];
    NSColor *stoppedColor = [NSColor secondaryLabelColor];

    NSRect card = NSInsetRect(self.bounds, 1.0, 1.0);
    NSBezierPath *bg = [NSBezierPath bezierPathWithRoundedRect:card xRadius:10 yRadius:10];
    [cardFill setFill];
    [bg fill];
    [border setStroke];
    bg.lineWidth = 1.0;
    [bg stroke];

    // Top highlight line
    if (NSWidth(card) > 20) {
        NSBezierPath *sheen = [NSBezierPath bezierPath];
        [sheen moveToPoint:NSMakePoint(NSMinX(card) + 8, NSMinY(card) + 1.0)];
        [sheen lineToPoint:NSMakePoint(NSMaxX(card) - 8, NSMinY(card) + 1.0)];
        sheen.lineWidth = 1.0;
        [highlight setStroke];
        [sheen stroke];
    }

    // Row 1: Status dot + Engine Status + Badges + Mode Title (Y: 10)
    CGFloat row1Y = NSMinY(card) + 10.0;
    CGFloat curX = NSMinX(card) + 12.0;

    // Status dot
    NSColor *statusDotColor = _running ? downloadColor : stoppedColor;
    NSRect dotRect = NSMakeRect(curX, row1Y + 3.0, 8.0, 8.0);
    NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:dotRect];
    [statusDotColor setFill];
    [dot fill];
    curX += 13.0;

    // Status text
    NSString *statusText = _running ? @"已连接" : @"未连接";
    NSDictionary *statusAttrs = @{
        NSFontAttributeName: [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold],
        NSForegroundColorAttributeName: _running ? [NSColor labelColor] : stoppedColor
    };
    [statusText drawAtPoint:NSMakePoint(curX, row1Y) withAttributes:statusAttrs];
    curX += [statusText sizeWithAttributes:statusAttrs].width + 8.0;

    // Badges (TUN, System Proxy)
    if (_enhancedMode) {
        NSString *tunBadge = @"TUN";
        NSDictionary *badgeAttrs = @{
            NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:9.0 weight:NSFontWeightBold],
            NSForegroundColorAttributeName: uploadColor
        };
        NSSize badgeSize = [tunBadge sizeWithAttributes:badgeAttrs];
        NSRect bRect = NSMakeRect(curX, row1Y + 1.0, badgeSize.width + 8.0, 14.0);
        NSBezierPath *bPath = [NSBezierPath bezierPathWithRoundedRect:bRect xRadius:4 yRadius:4];
        [([uploadColor colorWithAlphaComponent:0.18]) setFill];
        [bPath fill];
        [tunBadge drawAtPoint:NSMakePoint(NSMinX(bRect) + 4.0, NSMinY(bRect) + 1.5) withAttributes:badgeAttrs];
        curX += NSWidth(bRect) + 5.0;
    }

    if (_systemProxy) {
        NSString *sysBadge = @"系统代理";
        NSDictionary *badgeAttrs = @{
            NSFontAttributeName: [NSFont systemFontOfSize:9.0 weight:NSFontWeightMedium],
            NSForegroundColorAttributeName: downloadColor
        };
        NSSize badgeSize = [sysBadge sizeWithAttributes:badgeAttrs];
        NSRect bRect = NSMakeRect(curX, row1Y + 1.0, badgeSize.width + 8.0, 14.0);
        NSBezierPath *bPath = [NSBezierPath bezierPathWithRoundedRect:bRect xRadius:4 yRadius:4];
        [([downloadColor colorWithAlphaComponent:0.18]) setFill];
        [bPath fill];
        [sysBadge drawAtPoint:NSMakePoint(NSMinX(bRect) + 4.0, NSMinY(bRect) + 1.0) withAttributes:badgeAttrs];
    }

    // Mode title on the right
    if (_modeTitle.length > 0) {
        NSDictionary *modeAttrs = @{
            NSFontAttributeName: [NSFont systemFontOfSize:11.0 weight:NSFontWeightMedium],
            NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
        };
        NSSize modeSize = [_modeTitle sizeWithAttributes:modeAttrs];
        CGFloat modeX = NSMaxX(card) - modeSize.width - 12.0;
        [_modeTitle drawAtPoint:NSMakePoint(modeX, row1Y) withAttributes:modeAttrs];
    }

    // Row 2: Active Node + Latency Badge (Y: 32)
    CGFloat row2Y = NSMinY(card) + 32.0;
    CGFloat nodeLeftX = NSMinX(card) + 12.0;

    // Latency badge on right
    NSString *latencyText;
    NSColor *latencyColor;
    if (_latencyMillis > 0) {
        latencyText = [NSString stringWithFormat:@"%ld ms", (long)_latencyMillis];
        if (_latencyMillis <= 120) {
            latencyColor = downloadColor;
        } else if (_latencyMillis <= 300) {
            latencyColor = [NSColor systemOrangeColor];
        } else {
            latencyColor = [NSColor systemRedColor];
        }
    } else if (_latencyMillis == 0) {
        latencyText = @"超时";
        latencyColor = [NSColor systemRedColor];
    } else {
        latencyText = @"---";
        latencyColor = [NSColor tertiaryLabelColor];
    }

    NSDictionary *latAttrs = @{
        NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:9.5 weight:NSFontWeightBold],
        NSForegroundColorAttributeName: latencyColor
    };
    NSSize latSize = [latencyText sizeWithAttributes:latAttrs];
    CGFloat latBadgeW = latSize.width + 10.0;
    NSRect latRect = NSMakeRect(NSMaxX(card) - latBadgeW - 12.0, row2Y + 1.0, latBadgeW, 16.0);
    NSBezierPath *latPath = [NSBezierPath bezierPathWithRoundedRect:latRect xRadius:4 yRadius:4];
    [([latencyColor colorWithAlphaComponent:0.15]) setFill];
    [latPath fill];
    [latencyText drawAtPoint:NSMakePoint(NSMinX(latRect) + 5.0, NSMinY(latRect) + 1.5) withAttributes:latAttrs];

    // Node title (truncated if necessary to avoid overlapping latency badge)
    CGFloat maxNodeW = NSMinX(latRect) - nodeLeftX - 8.0;
    if (maxNodeW > 40.0) {
        NSMutableParagraphStyle *style = [[NSParagraphStyle defaultParagraphStyle] mutableCopy];
        style.lineBreakMode = NSLineBreakByTruncatingTail;
        NSDictionary *nodeAttrs = @{
            NSFontAttributeName: [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold],
            NSForegroundColorAttributeName: [NSColor labelColor],
            NSParagraphStyleAttributeName: style
        };
        NSRect nodeRect = NSMakeRect(nodeLeftX, row2Y, maxNodeW, 18.0);
        [_activeNodeName drawInRect:nodeRect withAttributes:nodeAttrs];
    }

    // Row 3: Live Rates (Upload blue, Download green) & Active connections (Y: 54)
    CGFloat row3Y = NSMinY(card) + 54.0;
    NSString *upStr = [NSString stringWithFormat:@"↑ %@", HJFormatRate(_uploadBytesPerSecond)];
    NSString *downStr = [NSString stringWithFormat:@"↓ %@", HJFormatRate(_downloadBytesPerSecond)];
    NSString *connStr = [NSString stringWithFormat:@"%ld 连接", (long)_activeConnections];

    NSDictionary *upAttrs = @{
        NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:10.5 weight:NSFontWeightSemibold],
        NSForegroundColorAttributeName: uploadColor
    };
    NSDictionary *downAttrs = @{
        NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:10.5 weight:NSFontWeightSemibold],
        NSForegroundColorAttributeName: downloadColor
    };
    NSDictionary *connAttrs = @{
        NSFontAttributeName: [NSFont systemFontOfSize:10.5 weight:NSFontWeightRegular],
        NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
    };

    [upStr drawAtPoint:NSMakePoint(nodeLeftX, row3Y) withAttributes:upAttrs];
    CGFloat afterUpX = nodeLeftX + [upStr sizeWithAttributes:upAttrs].width + 12.0;
    [downStr drawAtPoint:NSMakePoint(afterUpX, row3Y) withAttributes:downAttrs];

    NSSize connSize = [connStr sizeWithAttributes:connAttrs];
    [connStr drawAtPoint:NSMakePoint(NSMaxX(card) - connSize.width - 12.0, row3Y) withAttributes:connAttrs];

    // Row 4: Cumulative Traffic (Y: 74)
    CGFloat row4Y = NSMinY(card) + 74.0;
    NSString *totalStr = [NSString stringWithFormat:@"用量: ↑ %@   ↓ %@",
                          HJFormatBytes(_totalUploadedBytes),
                          HJFormatBytes(_totalDownloadedBytes)];
    NSDictionary *totalAttrs = @{
        NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:9.5 weight:NSFontWeightRegular],
        NSForegroundColorAttributeName: [NSColor secondaryLabelColor]
    };
    [totalStr drawAtPoint:NSMakePoint(nodeLeftX, row4Y) withAttributes:totalAttrs];
}

@end

