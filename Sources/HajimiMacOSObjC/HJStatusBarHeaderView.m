#import "HJStatusBarHeaderView.h"

static NSColor *HJHeaderColorFromHex(NSString *hex, CGFloat alpha) {
    if (!hex || hex.length == 0) {
        return nil;
    }
    NSString *cleaned = [[hex stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                         stringByReplacingOccurrencesOfString:@"#" withString:@""];
    if (cleaned.length == 3) {
        unichar c0 = [cleaned characterAtIndex:0];
        unichar c1 = [cleaned characterAtIndex:1];
        unichar c2 = [cleaned characterAtIndex:2];
        cleaned = [NSString stringWithFormat:@"%C%C%C%C%C%C", c0, c0, c1, c1, c2, c2];
    }
    if (cleaned.length != 6) {
        return nil;
    }
    unsigned int rgb = 0;
    NSScanner *scanner = [NSScanner scannerWithString:cleaned];
    if (![scanner scanHexInt:&rgb]) {
        return nil;
    }
    CGFloat r = ((rgb >> 16) & 0xFF) / 255.0;
    CGFloat g = ((rgb >> 8) & 0xFF) / 255.0;
    CGFloat b = (rgb & 0xFF) / 255.0;
    return [NSColor colorWithCalibratedRed:r green:g blue:b alpha:alpha];
}

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
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(handleThemeDidChange:)
                                                     name:@"HajimiThemeCenterDidChangeNotification"
                                                   object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)handleThemeDidChange:(NSNotification *) __unused notification {
    [self setNeedsDisplay:YES];
}

- (void)viewDidChangeEffectiveAppearance {
    [super viewDidChangeEffectiveAppearance];
    [self setNeedsDisplay:YES];
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
    NSString *resolvedMode = modeTitle.length > 0 ? modeTitle : @"规则判定";
    NSString *resolvedNode = activeNodeName.length > 0 ? activeNodeName : @"DIRECT";

    uint64_t oldUpQuant = (_uploadBytesPerSecond > 0.0 && isfinite(_uploadBytesPerSecond)) ? (uint64_t)_uploadBytesPerSecond : 0;
    uint64_t newUpQuant = (uploadBytesPerSecond > 0.0 && isfinite(uploadBytesPerSecond)) ? (uint64_t)uploadBytesPerSecond : 0;
    uint64_t oldDownQuant = (_downloadBytesPerSecond > 0.0 && isfinite(_downloadBytesPerSecond)) ? (uint64_t)_downloadBytesPerSecond : 0;
    uint64_t newDownQuant = (downloadBytesPerSecond > 0.0 && isfinite(downloadBytesPerSecond)) ? (uint64_t)downloadBytesPerSecond : 0;

    if (_running == running &&
        _enhancedMode == enhancedMode &&
        _systemProxy == systemProxy &&
        _latencyMillis == latencyMillis &&
        oldUpQuant == newUpQuant &&
        oldDownQuant == newDownQuant &&
        _totalUploadedBytes == totalUploadedBytes &&
        _totalDownloadedBytes == totalDownloadedBytes &&
        _activeConnections == activeConnections &&
        [_modeTitle isEqualToString:resolvedMode] &&
        [_activeNodeName isEqualToString:resolvedNode]) {
        return;
    }

    _running = running;
    _enhancedMode = enhancedMode;
    _systemProxy = systemProxy;
    if (![_modeTitle isEqualToString:resolvedMode]) {
        _modeTitle = [resolvedMode copy];
    }
    if (![_activeNodeName isEqualToString:resolvedNode]) {
        _activeNodeName = [resolvedNode copy];
    }
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

    static NSColor *darkCardFill, *lightCardFill;
    static NSColor *darkElevatedFill, *lightElevatedFill;
    static NSColor *darkBorder, *lightBorder;
    static NSColor *darkHighlight, *lightHighlight;
    static NSColor *darkDownload, *lightDownload;
    static NSColor *darkUpload, *lightUpload;
    static NSFont *statusFont, *tunFont, *sysFont, *rateFont, *latencyFont, *modeFont, *nodeFont, *connFont, *totalFont;
    static NSMutableParagraphStyle *truncStyle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        darkCardFill = [NSColor colorWithCalibratedRed:0.11 green:0.13 blue:0.14 alpha:0.96];
        lightCardFill = [NSColor colorWithCalibratedRed:0.96 green:0.97 blue:0.98 alpha:0.96];
        darkElevatedFill = [NSColor colorWithCalibratedRed:0.14 green:0.17 blue:0.19 alpha:0.98];
        lightElevatedFill = [NSColor colorWithCalibratedRed:0.99 green:0.99 blue:1.00 alpha:0.98];
        darkBorder = [NSColor colorWithCalibratedWhite:1.0 alpha:0.10];
        lightBorder = [NSColor colorWithCalibratedWhite:0.0 alpha:0.08];
        darkHighlight = [NSColor colorWithCalibratedWhite:1.0 alpha:0.06];
        lightHighlight = [NSColor colorWithCalibratedWhite:1.0 alpha:0.65];

        darkDownload = [NSColor colorWithCalibratedRed:0.20 green:0.83 blue:0.62 alpha:1.0];
        lightDownload = [NSColor colorWithCalibratedRed:0.04 green:0.55 blue:0.41 alpha:1.0];
        darkUpload = [NSColor colorWithCalibratedRed:0.36 green:0.68 blue:0.96 alpha:1.0];
        lightUpload = [NSColor colorWithCalibratedRed:0.12 green:0.46 blue:0.82 alpha:1.0];

        statusFont = [NSFont systemFontOfSize:11.5 weight:NSFontWeightSemibold];
        tunFont = [NSFont monospacedDigitSystemFontOfSize:9.0 weight:NSFontWeightBold];
        sysFont = [NSFont systemFontOfSize:9.0 weight:NSFontWeightMedium];
        rateFont = [NSFont monospacedDigitSystemFontOfSize:10.5 weight:NSFontWeightSemibold];
        latencyFont = [NSFont monospacedDigitSystemFontOfSize:9.5 weight:NSFontWeightBold];
        modeFont = [NSFont systemFontOfSize:10.5 weight:NSFontWeightSemibold];
        nodeFont = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
        connFont = [NSFont systemFontOfSize:10.5 weight:NSFontWeightRegular];
        totalFont = [NSFont monospacedDigitSystemFontOfSize:9.5 weight:NSFontWeightRegular];

        truncStyle = [[NSParagraphStyle defaultParagraphStyle] mutableCopy];
        truncStyle.lineBreakMode = NSLineBreakByTruncatingTail;
    });

    BOOL dark = [[self.effectiveAppearance bestMatchFromAppearancesWithNames:@[
        NSAppearanceNameAqua,
        NSAppearanceNameDarkAqua
    ]] isEqualToString:NSAppearanceNameDarkAqua];

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL customTheme = [defaults boolForKey:@"hajimi.theme.customActive"];
    if (customTheme && [defaults objectForKey:@"hajimi.theme.isDark"]) {
        dark = [defaults boolForKey:@"hajimi.theme.isDark"];
    }

    NSColor *cardFill = dark ? darkCardFill : lightCardFill;
    NSColor *elevatedFill = dark ? darkElevatedFill : lightElevatedFill;
    NSColor *border = dark ? darkBorder : lightBorder;
    NSColor *highlight = dark ? darkHighlight : lightHighlight;
    NSColor *downloadColor = dark ? darkDownload : lightDownload;
    NSColor *accentTextColor = downloadColor;
    NSColor *uploadColor = dark ? darkUpload : lightUpload;
    NSColor *textPrimary = dark ? [NSColor colorWithCalibratedWhite:0.96 alpha:1.0] : [NSColor colorWithCalibratedWhite:0.10 alpha:1.0];
    NSColor *textSecondary = dark ? [NSColor colorWithCalibratedWhite:0.72 alpha:0.92] : [NSColor colorWithCalibratedWhite:0.38 alpha:0.92];
    CGFloat cornerRadius = 10.0;

    if (customTheme) {
        NSColor *customPanel = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.panelHex"], 0.97);
        NSColor *customElevated = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.elevatedHex"], 0.98);
        NSColor *customAccent = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.accentHex"], 1.0);
        NSColor *customAccentText = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.accentTextHex"], 1.0);
        NSColor *customUpload = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.uploadHex"], 1.0);
        NSColor *customTextPrimary = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.textPrimaryHex"], 1.0);
        NSColor *customTextSecondary = HJHeaderColorFromHex([defaults stringForKey:@"hajimi.theme.textSecondaryHex"], 0.90);
        double borderAlpha = [defaults objectForKey:@"hajimi.theme.borderAlpha"] ? [defaults doubleForKey:@"hajimi.theme.borderAlpha"] : 0.22;
        double highlightAlpha = [defaults objectForKey:@"hajimi.theme.highlightAlpha"] ? [defaults doubleForKey:@"hajimi.theme.highlightAlpha"] : (dark ? 0.10 : 0.70);
        if ([defaults objectForKey:@"hajimi.theme.innerRadius"]) {
            cornerRadius = MAX(0.0, MIN(20.0, [defaults doubleForKey:@"hajimi.theme.innerRadius"]));
        }
        if (customPanel) cardFill = customPanel;
        if (customElevated) elevatedFill = customElevated;
        else if (customPanel) elevatedFill = customPanel;
        if (customAccent) downloadColor = customAccent;
        if (customAccentText) accentTextColor = customAccentText;
        else accentTextColor = downloadColor;
        if (customUpload) uploadColor = customUpload;
        if (customTextPrimary) textPrimary = customTextPrimary;
        if (customTextSecondary) textSecondary = customTextSecondary;
        border = [downloadColor colorWithAlphaComponent:MAX(0.14, MIN(0.85, borderAlpha + 0.06))];
        highlight = [NSColor colorWithCalibratedWhite:1.0 alpha:MAX(0.04, MIN(0.85, highlightAlpha))];
    }

    NSColor *uploadBadgeFill = [uploadColor colorWithAlphaComponent:0.18];
    NSColor *downloadBadgeFill = [downloadColor colorWithAlphaComponent:0.18];

    NSDictionary *connectedStatusAttrs = @{
        NSFontAttributeName: statusFont,
        NSForegroundColorAttributeName: textPrimary
    };
    NSDictionary *disconnectedStatusAttrs = @{
        NSFontAttributeName: statusFont,
        NSForegroundColorAttributeName: textSecondary
    };
    NSDictionary *modeAttrs = @{
        NSFontAttributeName: modeFont,
        NSForegroundColorAttributeName: accentTextColor
    };
    NSDictionary *nodeAttrs = @{
        NSFontAttributeName: nodeFont,
        NSForegroundColorAttributeName: textPrimary,
        NSParagraphStyleAttributeName: truncStyle
    };
    NSDictionary *connAttrs = @{
        NSFontAttributeName: connFont,
        NSForegroundColorAttributeName: textSecondary
    };
    NSDictionary *totalAttrs = @{
        NSFontAttributeName: totalFont,
        NSForegroundColorAttributeName: textSecondary
    };
    NSDictionary *tunBadgeAttrs = @{
        NSFontAttributeName: tunFont,
        NSForegroundColorAttributeName: uploadColor
    };
    NSDictionary *sysBadgeAttrs = @{
        NSFontAttributeName: sysFont,
        NSForegroundColorAttributeName: accentTextColor
    };
    NSDictionary *upAttrs = @{
        NSFontAttributeName: rateFont,
        NSForegroundColorAttributeName: uploadColor
    };
    NSDictionary *downAttrs = @{
        NSFontAttributeName: rateFont,
        NSForegroundColorAttributeName: accentTextColor
    };

    NSRect card = NSInsetRect(self.bounds, 1.0, 1.0);
    NSBezierPath *bg = [NSBezierPath bezierPathWithRoundedRect:card xRadius:cornerRadius yRadius:cornerRadius];
    [NSGraphicsContext saveGraphicsState];
    [bg addClip];
    NSGradient *cardGrad = [[NSGradient alloc] initWithStartingColor:elevatedFill endingColor:cardFill];
    if (cardGrad) {
        [cardGrad drawInRect:card angle:90.0];
    } else {
        [cardFill setFill];
        [bg fill];
    }
    NSRect topRibbon = NSMakeRect(NSMinX(card), NSMinY(card), NSWidth(card), 2.5);
    NSGradient *ribbonGrad = [[NSGradient alloc] initWithStartingColor:[downloadColor colorWithAlphaComponent:0.85]
                                                           endingColor:[uploadColor colorWithAlphaComponent:0.85]];
    if (ribbonGrad) {
        [ribbonGrad drawInRect:topRibbon angle:0.0];
    }
    [NSGraphicsContext restoreGraphicsState];

    [border setStroke];
    bg.lineWidth = 1.0;
    [bg stroke];

    if (NSWidth(card) > 20 && cornerRadius >= 4.0) {
        NSBezierPath *sheen = [NSBezierPath bezierPath];
        [sheen moveToPoint:NSMakePoint(NSMinX(card) + 8, NSMinY(card) + 1.0)];
        [sheen lineToPoint:NSMakePoint(NSMaxX(card) - 8, NSMinY(card) + 1.0)];
        sheen.lineWidth = 1.0;
        [highlight setStroke];
        [sheen stroke];
    }

    CGFloat row1Y = NSMinY(card) + 11.0;
    CGFloat curX = NSMinX(card) + 12.0;

    NSColor *statusDotColor = _running ? downloadColor : textSecondary;
    NSRect dotRect = NSMakeRect(curX, row1Y + 3.0, 8.0, 8.0);
    NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:dotRect];
    [statusDotColor setFill];
    [dot fill];
    curX += 13.0;

    NSString *statusText = _running ? @"已连接" : @"未连接";
    NSDictionary *statusAttrs = _running ? connectedStatusAttrs : disconnectedStatusAttrs;
    [statusText drawAtPoint:NSMakePoint(curX, row1Y) withAttributes:statusAttrs];
    curX += [statusText sizeWithAttributes:statusAttrs].width + 8.0;

    if (_enhancedMode) {
        NSString *tunBadge = @"TUN";
        NSSize tunSize = [tunBadge sizeWithAttributes:tunBadgeAttrs];
        NSRect bRect = NSMakeRect(curX, row1Y + 1.0, tunSize.width + 8.0, 14.0);
        NSBezierPath *bPath = [NSBezierPath bezierPathWithRoundedRect:bRect xRadius:4 yRadius:4];
        [uploadBadgeFill setFill];
        [bPath fill];
        [tunBadge drawAtPoint:NSMakePoint(NSMinX(bRect) + 4.0, NSMinY(bRect) + 1.5) withAttributes:tunBadgeAttrs];
        curX += NSWidth(bRect) + 5.0;
    }

    if (_systemProxy) {
        NSString *sysBadge = @"系统代理";
        NSSize sysSize = [sysBadge sizeWithAttributes:sysBadgeAttrs];
        NSRect bRect = NSMakeRect(curX, row1Y + 1.0, sysSize.width + 8.0, 14.0);
        NSBezierPath *bPath = [NSBezierPath bezierPathWithRoundedRect:bRect xRadius:4 yRadius:4];
        [downloadBadgeFill setFill];
        [bPath fill];
        [sysBadge drawAtPoint:NSMakePoint(NSMinX(bRect) + 4.0, NSMinY(bRect) + 1.0) withAttributes:sysBadgeAttrs];
    }

    if (_modeTitle.length > 0) {
        NSSize modeSize = [_modeTitle sizeWithAttributes:modeAttrs];
        CGFloat modeX = NSMaxX(card) - modeSize.width - 12.0;
        NSRect modePill = NSMakeRect(modeX - 5.0, row1Y, modeSize.width + 10.0, 15.0);
        NSBezierPath *modePath = [NSBezierPath bezierPathWithRoundedRect:modePill xRadius:4 yRadius:4];
        [downloadBadgeFill setFill];
        [modePath fill];
        [_modeTitle drawAtPoint:NSMakePoint(modeX, row1Y + 0.5) withAttributes:modeAttrs];
    }

    CGFloat row2Y = NSMinY(card) + 33.0;
    CGFloat nodeLeftX = NSMinX(card) + 12.0;

    NSString *latencyText;
    NSColor *latencyColor;
    if (_latencyMillis > 0) {
        latencyText = [NSString stringWithFormat:@"%ld ms", (long)_latencyMillis];
        if (_latencyMillis <= 120) {
            latencyColor = accentTextColor;
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
        latencyColor = textSecondary;
    }

    NSDictionary *latAttrs = @{
        NSFontAttributeName: latencyFont,
        NSForegroundColorAttributeName: latencyColor
    };
    NSSize latSize = [latencyText sizeWithAttributes:latAttrs];
    CGFloat latBadgeW = latSize.width + 10.0;
    NSRect latRect = NSMakeRect(NSMaxX(card) - latBadgeW - 12.0, row2Y + 1.0, latBadgeW, 16.0);
    NSBezierPath *latPath = [NSBezierPath bezierPathWithRoundedRect:latRect xRadius:4 yRadius:4];
    [([latencyColor colorWithAlphaComponent:0.16]) setFill];
    [latPath fill];
    [latencyText drawAtPoint:NSMakePoint(NSMinX(latRect) + 5.0, NSMinY(latRect) + 1.5) withAttributes:latAttrs];

    CGFloat maxNodeW = NSMinX(latRect) - nodeLeftX - 8.0;
    if (maxNodeW > 40.0) {
        NSRect nodeRect = NSMakeRect(nodeLeftX, row2Y, maxNodeW, 18.0);
        [_activeNodeName drawInRect:nodeRect withAttributes:nodeAttrs];
    }

    CGFloat row3Y = NSMinY(card) + 55.0;
    NSString *upStr = [NSString stringWithFormat:@"↑ %@", HJFormatRate(_uploadBytesPerSecond)];
    NSString *downStr = [NSString stringWithFormat:@"↓ %@", HJFormatRate(_downloadBytesPerSecond)];
    NSString *connStr = [NSString stringWithFormat:@"%ld 连接", (long)_activeConnections];

    [upStr drawAtPoint:NSMakePoint(nodeLeftX, row3Y) withAttributes:upAttrs];
    CGFloat afterUpX = nodeLeftX + [upStr sizeWithAttributes:upAttrs].width + 12.0;
    [downStr drawAtPoint:NSMakePoint(afterUpX, row3Y) withAttributes:downAttrs];

    NSSize connSize = [connStr sizeWithAttributes:connAttrs];
    [connStr drawAtPoint:NSMakePoint(NSMaxX(card) - connSize.width - 12.0, row3Y) withAttributes:connAttrs];

    CGFloat row4Y = NSMinY(card) + 75.0;
    NSString *totalStr = [NSString stringWithFormat:@"用量: ↑ %@   ↓ %@",
                          HJFormatBytes(_totalUploadedBytes),
                          HJFormatBytes(_totalDownloadedBytes)];
    [totalStr drawAtPoint:NSMakePoint(nodeLeftX, row4Y) withAttributes:totalAttrs];
}

@end
