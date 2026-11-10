#import "HJTrafficDashboardView.h"
#include "hj_ring_buffer.h"

static NSColor *HJTrafficColorFromHex(NSString *hex, CGFloat alpha) {
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

@implementation HJTrafficDashboardView {
    hj_traffic_ring_t _uploadHistory;
    hj_traffic_ring_t _downloadHistory;
    uint64_t _uploadTotal;
    uint64_t _downloadTotal;
    uint64_t _uploadRate;
    uint64_t _downloadRate;
    uint32_t _activeSessions;
    uint32_t _idleZeroTicks;
    NSString *_modeName;
    NSString *_policyName;
}

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        hj_traffic_ring_init(&_uploadHistory);
        hj_traffic_ring_init(&_downloadHistory);
        _idleZeroTicks = 0;
        _modeName = @"规则判定";
        _policyName = @"DIRECT";
        self.wantsLayer = YES;
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

- (void)updateWithUploadBytesPerSecond:(double)upload
               downloadBytesPerSecond:(double)download
                    activeConnections:(NSInteger)connections {
    uint64_t uploadRate = (upload > 0.0 && isfinite(upload)) ? (uint64_t)upload : 0;
    uint64_t downloadRate = (download > 0.0 && isfinite(download)) ? (uint64_t)download : 0;
    uint32_t sessions = connections > 0 ? (uint32_t)connections : 0;
    BOOL sessionsChanged = (_activeSessions != sessions);
    _uploadRate = uploadRate;
    _downloadRate = downloadRate;
    _activeSessions = sessions;
    hj_traffic_ring_push(&_uploadHistory, uploadRate);
    hj_traffic_ring_push(&_downloadHistory, downloadRate);
    if (uploadRate == 0 && downloadRate == 0) {
        if (_idleZeroTicks <= HJ_TRAFFIC_HISTORY_CAPACITY) {
            _idleZeroTicks++;
        }
    } else {
        _idleZeroTicks = 0;
    }
    if (_idleZeroTicks <= HJ_TRAFFIC_HISTORY_CAPACITY || sessionsChanged) {
        if (!self.window || (self.window.isVisible && !self.isHiddenOrHasHiddenAncestor)) {
            [self setNeedsDisplay:YES];
        }
    }
}

- (void)reset {
    [self resetHistory];
}

- (void)pushUploadBytes:(uint64_t)uploadBytes
          downloadBytes:(uint64_t)downloadBytes
         activeSessions:(uint32_t)activeSessions
               modeName:(NSString *)modeName
             policyName:(NSString *)policyName {
    uint64_t uploadDelta = uploadBytes >= _uploadTotal ? (uploadBytes - _uploadTotal) : uploadBytes;
    uint64_t downloadDelta = downloadBytes >= _downloadTotal ? (downloadBytes - _downloadTotal) : downloadBytes;
    _uploadTotal = uploadBytes;
    _downloadTotal = downloadBytes;
    _uploadRate = uploadDelta;
    _downloadRate = downloadDelta;
    _activeSessions = activeSessions;
    if (modeName && ![_modeName isEqualToString:modeName]) {
        _modeName = [modeName copy];
    }
    if (policyName && ![_policyName isEqualToString:policyName]) {
        _policyName = [policyName copy];
    }
    hj_traffic_ring_push(&_uploadHistory, uploadDelta);
    hj_traffic_ring_push(&_downloadHistory, downloadDelta);
    if (!self.window || (self.window.isVisible && !self.isHiddenOrHasHiddenAncestor)) {
        [self setNeedsDisplay:YES];
    }
}

- (void)resetHistory {
    hj_traffic_ring_init(&_uploadHistory);
    hj_traffic_ring_init(&_downloadHistory);
    _uploadTotal = 0;
    _downloadTotal = 0;
    _uploadRate = 0;
    _downloadRate = 0;
    _activeSessions = 0;
    _idleZeroTicks = 0;
    [self setNeedsDisplay:YES];
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];

    static NSColor *darkCardFill, *lightCardFill;
    static NSColor *darkBorder, *lightBorder;
    static NSColor *darkHighlight, *lightHighlight;
    static NSColor *darkWellFill, *lightWellFill;
    static NSColor *darkGrid, *lightGrid;
    static NSColor *darkDownload, *lightDownload;
    static NSColor *darkUpload, *lightUpload;
    static NSFont *eyebrowFont, *rateFont, *titleFont, *subtitleFont, *peakFont;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        darkCardFill = [NSColor colorWithCalibratedRed:0.102 green:0.122 blue:0.132 alpha:0.97];
        lightCardFill = [NSColor colorWithCalibratedRed:0.997 green:0.999 blue:0.998 alpha:0.98];
        darkBorder = [NSColor colorWithCalibratedRed:0.80 green:0.94 blue:0.88 alpha:0.12];
        lightBorder = [NSColor colorWithCalibratedRed:0.06 green:0.16 blue:0.12 alpha:0.10];
        darkHighlight = [NSColor colorWithCalibratedRed:0.84 green:0.96 blue:0.91 alpha:0.08];
        lightHighlight = [NSColor colorWithCalibratedWhite:1.0 alpha:0.76];
        darkWellFill = [NSColor colorWithCalibratedRed:0.072 green:0.088 blue:0.096 alpha:0.86];
        lightWellFill = [NSColor colorWithCalibratedRed:0.938 green:0.953 blue:0.948 alpha:0.90];
        darkGrid = [NSColor colorWithCalibratedWhite:0.92 alpha:0.06];
        lightGrid = [NSColor colorWithCalibratedWhite:0.12 alpha:0.06];
        darkDownload = [NSColor colorWithCalibratedRed:0.18 green:0.82 blue:0.61 alpha:0.98];
        lightDownload = [NSColor colorWithCalibratedRed:0.04 green:0.56 blue:0.41 alpha:0.98];
        darkUpload = [NSColor colorWithCalibratedRed:0.35 green:0.69 blue:0.98 alpha:0.95];
        lightUpload = [NSColor colorWithCalibratedRed:0.11 green:0.46 blue:0.84 alpha:0.93];

        eyebrowFont = [NSFont systemFontOfSize:9.0 weight:NSFontWeightBold];
        rateFont = [NSFont monospacedDigitSystemFontOfSize:10.5 weight:NSFontWeightSemibold];
        titleFont = [NSFont systemFontOfSize:13 weight:NSFontWeightBold];
        subtitleFont = [NSFont systemFontOfSize:11 weight:NSFontWeightMedium];
        peakFont = [NSFont monospacedDigitSystemFontOfSize:9.0 weight:NSFontWeightSemibold];
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
    NSColor *titleTextColor = [NSColor labelColor];
    NSColor *subtitleTextColor = [NSColor secondaryLabelColor];
    NSColor *peakTextColor = [NSColor tertiaryLabelColor];
    NSColor *border = dark ? darkBorder : lightBorder;
    NSColor *highlight = dark ? darkHighlight : lightHighlight;
    NSColor *chartWellFill = dark ? darkWellFill : lightWellFill;
    NSColor *grid = dark ? darkGrid : lightGrid;
    NSColor *downloadColor = dark ? darkDownload : lightDownload;
    NSColor *accentTextColor = downloadColor;
    NSColor *uploadColor = dark ? darkUpload : lightUpload;
    CGFloat cardRadius = 14.0;
    CGFloat wellRadius = 10.0;

    if (customTheme) {
        NSColor *customPanel = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.panelHex"], 0.98);
        NSColor *customWorkspace = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.workspaceHex"], 0.90);
        NSColor *customMuted = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.mutedHex"], 0.90);
        NSColor *customAccent = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.accentHex"], 0.98);
        NSColor *customAccentText = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.accentTextHex"], 1.0);
        NSColor *customUpload = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.uploadHex"], 0.95);
        double borderAlpha = [defaults objectForKey:@"hajimi.theme.borderAlpha"] ? [defaults doubleForKey:@"hajimi.theme.borderAlpha"] : 0.16;
        double highlightAlpha = [defaults objectForKey:@"hajimi.theme.highlightAlpha"] ? [defaults doubleForKey:@"hajimi.theme.highlightAlpha"] : (dark ? 0.08 : 0.75);
        if ([defaults objectForKey:@"hajimi.theme.cardRadius"]) {
            cardRadius = MAX(0.0, MIN(28.0, [defaults doubleForKey:@"hajimi.theme.cardRadius"]));
        }
        if ([defaults objectForKey:@"hajimi.theme.innerRadius"]) {
            wellRadius = MAX(0.0, MIN(22.0, [defaults doubleForKey:@"hajimi.theme.innerRadius"]));
        }
        if (customPanel) cardFill = customPanel;
        if (customWorkspace && customMuted) {
            NSColor *blended = [customWorkspace blendedColorWithFraction:0.45 ofColor:customMuted];
            chartWellFill = blended ?: customWorkspace;
        } else if (customWorkspace) {
            chartWellFill = customWorkspace;
        }
        if (customAccent) downloadColor = customAccent;
        if (customAccentText) accentTextColor = customAccentText;
        else accentTextColor = downloadColor;
        if (customUpload) uploadColor = customUpload;
        NSColor *customTextPrimary = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.textPrimaryHex"], 1.0);
        NSColor *customTextSecondary = HJTrafficColorFromHex([defaults stringForKey:@"hajimi.theme.textSecondaryHex"], 0.90);
        if (customTextPrimary) titleTextColor = customTextPrimary;
        if (customTextSecondary) {
            subtitleTextColor = customTextSecondary;
            peakTextColor = [customTextSecondary colorWithAlphaComponent:0.75];
        }
        border = [downloadColor colorWithAlphaComponent:MAX(0.08, MIN(0.85, borderAlpha))];
        highlight = [NSColor colorWithCalibratedWhite:1.0 alpha:MAX(0.04, MIN(0.90, highlightAlpha))];
        grid = [downloadColor colorWithAlphaComponent:dark ? 0.10 : 0.08];
    }

    NSColor *badgeFill = [downloadColor colorWithAlphaComponent:0.15];
    NSColor *upBadgeFill = [uploadColor colorWithAlphaComponent:0.15];

    NSDictionary *eyebrowAttrs = @{
        NSFontAttributeName: eyebrowFont,
        NSForegroundColorAttributeName: accentTextColor
    };
    NSDictionary *downRateAttrs = @{
        NSFontAttributeName: rateFont,
        NSForegroundColorAttributeName: accentTextColor
    };
    NSDictionary *upRateAttrs = @{
        NSFontAttributeName: rateFont,
        NSForegroundColorAttributeName: uploadColor
    };
    NSDictionary *titleAttrs = @{
        NSFontAttributeName: titleFont,
        NSForegroundColorAttributeName: titleTextColor
    };
    NSDictionary *subtitleAttrs = @{
        NSFontAttributeName: subtitleFont,
        NSForegroundColorAttributeName: subtitleTextColor
    };
    NSDictionary *peakAttrs = @{
        NSFontAttributeName: peakFont,
        NSForegroundColorAttributeName: peakTextColor
    };

    NSRect card = NSInsetRect(self.bounds, 0.5, 0.5);
    NSBezierPath *background = [NSBezierPath bezierPathWithRoundedRect:card xRadius:cardRadius yRadius:cardRadius];
    [cardFill setFill];
    [background fill];
    [border setStroke];
    background.lineWidth = 1.0;
    [background stroke];

    if (NSWidth(card) > 28 && cardRadius >= 6.0) {
        CGFloat inset = MAX(8.0, cardRadius * 0.75);
        NSBezierPath *topSheen = [NSBezierPath bezierPath];
        [topSheen moveToPoint:NSMakePoint(NSMinX(card) + inset, NSMinY(card) + 1.0)];
        [topSheen lineToPoint:NSMakePoint(NSMaxX(card) - inset, NSMinY(card) + 1.0)];
        topSheen.lineWidth = 1.0;
        [highlight setStroke];
        [topSheen stroke];
    }

    // Header Row: Eyebrow Pill + Title + Subtitle on left, Live Rate Pills on right
    NSString *eyebrowText = @"REALTIME TELEMETRY";
    NSSize eyebrowSize = [eyebrowText sizeWithAttributes:eyebrowAttrs];
    NSRect pillRect = NSMakeRect(16, NSMinY(card) + 11, eyebrowSize.width + 12, 16);
    NSBezierPath *pillPath = [NSBezierPath bezierPathWithRoundedRect:pillRect xRadius:MIN(5.0, wellRadius) yRadius:MIN(5.0, wellRadius)];
    [badgeFill setFill];
    [pillPath fill];
    [eyebrowText drawAtPoint:NSMakePoint(NSMinX(pillRect) + 6, NSMinY(pillRect) + 2.0) withAttributes:eyebrowAttrs];

    NSString *titleText = @"实时吞吐波形";
    [titleText drawAtPoint:NSMakePoint(NSMaxX(pillRect) + 8, NSMinY(card) + 10) withAttributes:titleAttrs];

    NSString *headline = [NSString stringWithFormat:@"%@ · %@ · %u 活跃连接", _modeName, _policyName, _activeSessions];
    [headline drawAtPoint:NSMakePoint(16, NSMinY(card) + 30) withAttributes:subtitleAttrs];

    NSString *upText = [NSString stringWithFormat:@"↑ %@", [self formatRate:_uploadRate]];
    NSString *downText = [NSString stringWithFormat:@"↓ %@", [self formatRate:_downloadRate]];
    NSSize upSize = [upText sizeWithAttributes:upRateAttrs];
    NSSize downSize = [downText sizeWithAttributes:downRateAttrs];

    CGFloat pillCorner = MIN(6.0, wellRadius);
    NSRect upPill = NSMakeRect(NSMaxX(card) - upSize.width - 30, NSMinY(card) + 14, upSize.width + 14, 20);
    NSBezierPath *upPillPath = [NSBezierPath bezierPathWithRoundedRect:upPill xRadius:pillCorner yRadius:pillCorner];
    [upBadgeFill setFill];
    [upPillPath fill];
    [upText drawAtPoint:NSMakePoint(NSMinX(upPill) + 7, NSMinY(upPill) + 3.0) withAttributes:upRateAttrs];

    NSRect downPill = NSMakeRect(NSMinX(upPill) - downSize.width - 22, NSMinY(card) + 14, downSize.width + 14, 20);
    NSBezierPath *downPillPath = [NSBezierPath bezierPathWithRoundedRect:downPill xRadius:pillCorner yRadius:pillCorner];
    [badgeFill setFill];
    [downPillPath fill];
    [downText drawAtPoint:NSMakePoint(NSMinX(downPill) + 7, NSMinY(downPill) + 3.0) withAttributes:downRateAttrs];

    NSRect chart = NSMakeRect(16, NSMinY(card) + 50, NSWidth(card) - 32, MAX(40.0, NSHeight(card) - 62));
    NSBezierPath *wellPath = [NSBezierPath bezierPathWithRoundedRect:chart xRadius:wellRadius yRadius:wellRadius];
    [chartWellFill setFill];
    [wellPath fill];

    [NSGraphicsContext saveGraphicsState];
    [wellPath addClip];

    [grid setStroke];
    CGFloat dashPattern[2] = {3.0, 3.0};
    NSBezierPath *gridLines = [NSBezierPath bezierPath];
    [gridLines setLineDash:dashPattern count:2 phase:0];
    gridLines.lineWidth = 1.0;
    for (NSInteger index = 1; index <= 3; index++) {
        CGFloat y = NSMinY(chart) + (NSHeight(chart) * index * 0.25);
        [gridLines moveToPoint:NSMakePoint(NSMinX(chart) + 6, y)];
        [gridLines lineToPoint:NSMakePoint(NSMaxX(chart) - 6, y)];
    }
    [gridLines stroke];

    uint64_t peak = MAX(MAX(hj_traffic_ring_peak(&_downloadHistory), hj_traffic_ring_peak(&_uploadHistory)), 1024ULL);
    NSRect plotRect = NSInsetRect(chart, 8, 5);
    [self drawRing:&_downloadHistory inRect:plotRect peak:peak stroke:downloadColor fillAlpha:0.26];
    [self drawRing:&_uploadHistory inRect:plotRect peak:peak stroke:uploadColor fillAlpha:0.17];

    NSString *peakText = [NSString stringWithFormat:@"PEAK %@", [self formatRate:peak]];
    [peakText drawAtPoint:NSMakePoint(NSMinX(chart) + 10, NSMinY(chart) + 4) withAttributes:peakAttrs];

    [NSGraphicsContext restoreGraphicsState];

    [border setStroke];
    wellPath.lineWidth = 1.0;
    [wellPath stroke];
}

- (void)drawRing:(const hj_traffic_ring_t *)ring
          inRect:(NSRect)rect
            peak:(uint64_t)peak
          stroke:(NSColor *)stroke
       fillAlpha:(CGFloat)fillAlpha {
    size_t count = ring->count;
    if (count < 2 || NSWidth(rect) <= 4 || NSHeight(rect) <= 4) {
        return;
    }

    NSPoint points[HJ_TRAFFIC_HISTORY_CAPACITY];
    const CGFloat invCapacity = 1.0 / (CGFloat)(HJ_TRAFFIC_HISTORY_CAPACITY - 1);
    const CGFloat invPeak = 1.0 / (CGFloat)peak;
    const CGFloat plotHeight = NSHeight(rect) - 4.0;
    const CGFloat bottomY = NSMaxY(rect) - 2.0;
    for (size_t index = 0; index < count; index++) {
        uint64_t value = hj_traffic_ring_at(ring, index);
        CGFloat x = NSMinX(rect) + (NSWidth(rect) * (CGFloat)index * invCapacity);
        CGFloat normalized = MIN(1.0, (CGFloat)value * invPeak);
        CGFloat y = bottomY - normalized * plotHeight;
        points[index] = NSMakePoint(x, y);
    }

    CGFloat delta[HJ_TRAFFIC_HISTORY_CAPACITY];
    CGFloat m[HJ_TRAFFIC_HISTORY_CAPACITY];
    const CGFloat h = (count > 1) ? (points[1].x - points[0].x) : 1.0;
    const CGFloat invH = (h > 1e-6) ? (1.0 / h) : 1.0;

    for (size_t k = 0; k + 1 < count; k++) {
        delta[k] = (points[k + 1].y - points[k].y) * invH;
    }
    m[0] = delta[0];
    m[count - 1] = delta[count - 2];
    for (size_t k = 1; k + 1 < count; k++) {
        if (delta[k - 1] * delta[k] <= 0.0) {
            m[k] = 0.0;
        } else {
            m[k] = (2.0 * delta[k - 1] * delta[k]) / (delta[k - 1] + delta[k]);
        }
    }
    for (size_t k = 0; k + 1 < count; k++) {
        if (fabs(delta[k]) < 1e-9) {
            m[k] = 0.0;
            m[k + 1] = 0.0;
        } else {
            CGFloat alpha = m[k] / delta[k];
            CGFloat beta = m[k + 1] / delta[k];
            CGFloat normSq = alpha * alpha + beta * beta;
            if (normSq > 9.0) {
                CGFloat tau = 3.0 / sqrt(normSq);
                m[k] = tau * alpha * delta[k];
                m[k + 1] = tau * beta * delta[k];
            }
        }
    }

    const CGFloat minY = NSMinY(rect) + 2.0;
    const CGFloat thirdH = h / 3.0;
    NSBezierPath *line = [NSBezierPath bezierPath];
    [line moveToPoint:points[0]];
    for (size_t k = 0; k + 1 < count; k++) {
        NSPoint p0 = points[k];
        NSPoint p1 = points[k + 1];
        CGFloat c1y = MIN(bottomY, MAX(minY, p0.y + thirdH * m[k]));
        CGFloat c2y = MIN(bottomY, MAX(minY, p1.y - thirdH * m[k + 1]));
        [line curveToPoint:p1
             controlPoint1:NSMakePoint(p0.x + thirdH, c1y)
             controlPoint2:NSMakePoint(p1.x - thirdH, c2y)];
    }

    NSBezierPath *fill = [line copy];
    NSPoint lastPoint = points[count - 1];
    [fill lineToPoint:NSMakePoint(lastPoint.x, NSMaxY(rect))];
    [fill lineToPoint:NSMakePoint(points[0].x, NSMaxY(rect))];
    [fill closePath];

    NSGradient *gradient = [[NSGradient alloc] initWithStartingColor:[stroke colorWithAlphaComponent:fillAlpha]
                                                         endingColor:[stroke colorWithAlphaComponent:0.01]];
    if (gradient) {
        [gradient drawInBezierPath:fill angle:90.0];
    } else {
        [[stroke colorWithAlphaComponent:fillAlpha] setFill];
        [fill fill];
    }

    line.lineWidth = 2.0;
    line.lineCapStyle = NSLineCapStyleRound;
    line.lineJoinStyle = NSLineJoinStyleRound;
    [stroke setStroke];
    [line stroke];

    NSRect haloRect = NSMakeRect(lastPoint.x - 5.5, lastPoint.y - 5.5, 11.0, 11.0);
    NSBezierPath *halo = [NSBezierPath bezierPathWithOvalInRect:haloRect];
    [[stroke colorWithAlphaComponent:0.22] setFill];
    [halo fill];

    NSRect dotRect = NSMakeRect(lastPoint.x - 3.2, lastPoint.y - 3.2, 6.4, 6.4);
    NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:dotRect];
    [stroke setFill];
    [dot fill];

    NSRect coreRect = NSMakeRect(lastPoint.x - 1.2, lastPoint.y - 1.2, 2.4, 2.4);
    NSBezierPath *core = [NSBezierPath bezierPathWithOvalInRect:coreRect];
    [[NSColor whiteColor] setFill];
    [core fill];
}

- (NSString *)formatRate:(uint64_t)bytesPerSecond {
    static NSString * const units[4] = {@"B/s", @"KB/s", @"MB/s", @"GB/s"};
    double value = (double)bytesPerSecond;
    NSInteger unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value *= (1.0 / 1024.0);
        unit++;
    }
    return unit == 0
        ? [NSString stringWithFormat:@"%.0f %@", value, units[unit]]
        : [NSString stringWithFormat:@"%.1f %@", value, units[unit]];
}

@end
