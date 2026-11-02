#import "HJTrafficDashboardView.h"
#include "hj_ring_buffer.h"

@implementation HJTrafficDashboardView {
    hj_traffic_ring_t _uploadHistory;
    hj_traffic_ring_t _downloadHistory;
    uint64_t _uploadTotal;
    uint64_t _downloadTotal;
    uint64_t _uploadRate;
    uint64_t _downloadRate;
    uint32_t _activeSessions;
    NSString *_modeName;
    NSString *_policyName;
}

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        hj_traffic_ring_init(&_uploadHistory);
        hj_traffic_ring_init(&_downloadHistory);
        _modeName = @"Rule";
        _policyName = @"DIRECT";
        self.wantsLayer = YES;
    }
    return self;
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
    _uploadRate = uploadRate;
    _downloadRate = downloadRate;
    _activeSessions = sessions;
    hj_traffic_ring_push(&_uploadHistory, uploadRate);
    hj_traffic_ring_push(&_downloadHistory, downloadRate);
    if (!self.window || (self.window.isVisible && !self.isHiddenOrHasHiddenAncestor)) {
        [self setNeedsDisplay:YES];
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
    static NSColor *darkBadge, *lightBadge;
    static NSColor *darkUploadBadge, *lightUploadBadge;
    static NSDictionary *darkEyebrowAttrs, *lightEyebrowAttrs;
    static NSDictionary *darkDownRateAttrs, *lightDownRateAttrs;
    static NSDictionary *darkUpRateAttrs, *lightUpRateAttrs;
    static NSDictionary *titleAttrs, *peakAttrs;
    static NSSize cachedEyebrowSize;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        darkCardFill = [NSColor colorWithCalibratedRed:0.106 green:0.126 blue:0.135 alpha:0.97];
        lightCardFill = [NSColor colorWithCalibratedRed:0.996 green:0.999 blue:0.998 alpha:0.98];
        darkBorder = [NSColor colorWithCalibratedRed:0.82 green:0.93 blue:0.88 alpha:0.12];
        lightBorder = [NSColor colorWithCalibratedRed:0.07 green:0.17 blue:0.13 alpha:0.10];
        darkHighlight = [NSColor colorWithCalibratedRed:0.85 green:0.96 blue:0.91 alpha:0.075];
        lightHighlight = [NSColor colorWithCalibratedWhite:1.0 alpha:0.72];
        darkWellFill = [NSColor colorWithCalibratedRed:0.078 green:0.094 blue:0.102 alpha:0.82];
        lightWellFill = [NSColor colorWithCalibratedRed:0.942 green:0.956 blue:0.950 alpha:0.88];
        darkGrid = [NSColor colorWithCalibratedWhite:0.92 alpha:0.065];
        lightGrid = [NSColor colorWithCalibratedWhite:0.12 alpha:0.065];
        darkDownload = [NSColor colorWithCalibratedRed:0.20 green:0.83 blue:0.62 alpha:0.98];
        lightDownload = [NSColor colorWithCalibratedRed:0.04 green:0.55 blue:0.41 alpha:0.98];
        darkUpload = [NSColor colorWithCalibratedRed:0.36 green:0.68 blue:0.96 alpha:0.94];
        lightUpload = [NSColor colorWithCalibratedRed:0.12 green:0.46 blue:0.82 alpha:0.92];
        darkBadge = [NSColor colorWithCalibratedRed:0.19 green:0.80 blue:0.60 alpha:0.16];
        lightBadge = [NSColor colorWithCalibratedRed:0.05 green:0.56 blue:0.42 alpha:0.11];
        darkUploadBadge = [NSColor colorWithCalibratedRed:0.36 green:0.68 blue:0.96 alpha:0.16];
        lightUploadBadge = [NSColor colorWithCalibratedRed:0.12 green:0.46 blue:0.82 alpha:0.11];

        NSFont *eyebrowFont = [NSFont systemFontOfSize:9.5 weight:NSFontWeightBold];
        NSFont *rateFont = [NSFont monospacedDigitSystemFontOfSize:10.5 weight:NSFontWeightSemibold];
        darkEyebrowAttrs = @{
            NSFontAttributeName: eyebrowFont,
            NSForegroundColorAttributeName: darkDownload
        };
        lightEyebrowAttrs = @{
            NSFontAttributeName: eyebrowFont,
            NSForegroundColorAttributeName: lightDownload
        };
        darkDownRateAttrs = @{
            NSFontAttributeName: rateFont,
            NSForegroundColorAttributeName: darkDownload
        };
        lightDownRateAttrs = @{
            NSFontAttributeName: rateFont,
            NSForegroundColorAttributeName: lightDownload
        };
        darkUpRateAttrs = @{
            NSFontAttributeName: rateFont,
            NSForegroundColorAttributeName: darkUpload
        };
        lightUpRateAttrs = @{
            NSFontAttributeName: rateFont,
            NSForegroundColorAttributeName: lightUpload
        };
        titleAttrs = @{
            NSFontAttributeName: [NSFont systemFontOfSize:13 weight:NSFontWeightSemibold],
            NSForegroundColorAttributeName: [NSColor labelColor]
        };
        peakAttrs = @{
            NSFontAttributeName: [NSFont monospacedDigitSystemFontOfSize:9.0 weight:NSFontWeightMedium],
            NSForegroundColorAttributeName: [NSColor tertiaryLabelColor]
        };
        cachedEyebrowSize = [@"THROUGHPUT TELEMETRY" sizeWithAttributes:darkEyebrowAttrs];
    });

    BOOL dark = [[self.effectiveAppearance bestMatchFromAppearancesWithNames:@[
        NSAppearanceNameAqua,
        NSAppearanceNameDarkAqua
    ]] isEqualToString:NSAppearanceNameDarkAqua];

    NSColor *cardFill = dark ? darkCardFill : lightCardFill;
    NSColor *border = dark ? darkBorder : lightBorder;
    NSColor *highlight = dark ? darkHighlight : lightHighlight;
    NSColor *chartWellFill = dark ? darkWellFill : lightWellFill;
    NSColor *grid = dark ? darkGrid : lightGrid;
    NSColor *downloadColor = dark ? darkDownload : lightDownload;
    NSColor *uploadColor = dark ? darkUpload : lightUpload;
    NSColor *badgeFill = dark ? darkBadge : lightBadge;
    NSColor *upBadgeFill = dark ? darkUploadBadge : lightUploadBadge;
    NSDictionary *eyebrowAttrs = dark ? darkEyebrowAttrs : lightEyebrowAttrs;
    NSDictionary *downRateAttrs = dark ? darkDownRateAttrs : lightDownRateAttrs;
    NSDictionary *upRateAttrs = dark ? darkUpRateAttrs : lightUpRateAttrs;

    NSRect card = NSInsetRect(self.bounds, 0.5, 0.5);
    NSBezierPath *background = [NSBezierPath bezierPathWithRoundedRect:card xRadius:14 yRadius:14];
    [cardFill setFill];
    [background fill];
    [border setStroke];
    background.lineWidth = 1.0;
    [background stroke];

    // Specular top highlight
    if (NSWidth(card) > 28) {
        NSBezierPath *topSheen = [NSBezierPath bezierPath];
        [topSheen moveToPoint:NSMakePoint(NSMinX(card) + 12, NSMinY(card) + 1.0)];
        [topSheen lineToPoint:NSMakePoint(NSMaxX(card) - 12, NSMinY(card) + 1.0)];
        topSheen.lineWidth = 1.0;
        [highlight setStroke];
        [topSheen stroke];
    }

    NSString *eyebrowText = @"THROUGHPUT TELEMETRY";
    NSRect pillRect = NSMakeRect(16, NSMinY(card) + 11, cachedEyebrowSize.width + 14, 18);
    NSBezierPath *pillPath = [NSBezierPath bezierPathWithRoundedRect:pillRect xRadius:6 yRadius:6];
    [badgeFill setFill];
    [pillPath fill];
    [eyebrowText drawAtPoint:NSMakePoint(NSMinX(pillRect) + 7, NSMinY(pillRect) + 2.5) withAttributes:eyebrowAttrs];

    NSString *headline = [NSString stringWithFormat:@"%@ · %@ · %u 活跃连接", _modeName, _policyName, _activeSessions];
    [headline drawAtPoint:NSMakePoint(16, NSMinY(card) + 33) withAttributes:titleAttrs];

    // Color-coded live rate pills on the right
    NSString *upText = [NSString stringWithFormat:@"↑ %@", [self formatRate:_uploadRate]];
    NSString *downText = [NSString stringWithFormat:@"↓ %@", [self formatRate:_downloadRate]];
    NSSize upSize = [upText sizeWithAttributes:upRateAttrs];
    NSSize downSize = [downText sizeWithAttributes:downRateAttrs];

    NSRect upPill = NSMakeRect(NSMaxX(card) - upSize.width - 30, NSMinY(card) + 31, upSize.width + 14, 20);
    NSBezierPath *upPillPath = [NSBezierPath bezierPathWithRoundedRect:upPill xRadius:6 yRadius:6];
    [upBadgeFill setFill];
    [upPillPath fill];
    [upText drawAtPoint:NSMakePoint(NSMinX(upPill) + 7, NSMinY(upPill) + 3.0) withAttributes:upRateAttrs];

    NSRect downPill = NSMakeRect(NSMinX(upPill) - downSize.width - 22, NSMinY(card) + 31, downSize.width + 14, 20);
    NSBezierPath *downPillPath = [NSBezierPath bezierPathWithRoundedRect:downPill xRadius:6 yRadius:6];
    [badgeFill setFill];
    [downPillPath fill];
    [downText drawAtPoint:NSMakePoint(NSMinX(downPill) + 7, NSMinY(downPill) + 3.0) withAttributes:downRateAttrs];

    NSRect chart = NSMakeRect(16, NSMinY(card) + 57, NSWidth(card) - 32, MAX(44.0, NSHeight(card) - 71));
    NSBezierPath *wellPath = [NSBezierPath bezierPathWithRoundedRect:chart xRadius:10 yRadius:10];
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
    NSRect plotRect = NSInsetRect(chart, 8, 6);
    [self drawRing:&_downloadHistory inRect:plotRect peak:peak stroke:downloadColor fillAlpha:0.24];
    [self drawRing:&_uploadHistory inRect:plotRect peak:peak stroke:uploadColor fillAlpha:0.15];

    // Peak scale watermark in top-left of chart well
    NSString *peakText = [NSString stringWithFormat:@"PEAK %@", [self formatRate:peak]];
    [peakText drawAtPoint:NSMakePoint(NSMinX(chart) + 10, NSMinY(chart) + 5) withAttributes:peakAttrs];

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

    // Fritsch-Carlson Monotone Cubic Hermite Spline (PCHIP C^1 interpolation):
    // Preserves monotonicity on every interval [x_k, x_{k+1}] with zero overshoot
    // while maintaining true non-zero C^1 tangents on rising and falling ramps.
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
            // Harmonic mean weighting (Brodlie / Fritsch-Butland formula)
            m[k] = (2.0 * delta[k - 1] * delta[k]) / (delta[k - 1] + delta[k]);
        }
    }
    // Trust-region radius-3 circle projection: alpha_k^2 + beta_k^2 <= 9
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

    // Outer halo + crisp endpoint dot
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
