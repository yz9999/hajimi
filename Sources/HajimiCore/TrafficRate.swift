import Foundation

/// Turns a cumulative byte counter into a rate.
///
/// The counters this reads are reported by two sources that update at very
/// different cadences — the in-process engine on every flush, the privileged
/// helper once every few seconds — so each source needs its own meter. Summing
/// the counters first and differencing the total would smear the helper's
/// updates into a spike every poll and zero in between, and would also make one
/// source restarting look like the other losing traffic.
public struct TrafficRateMeter {
    /// Deltas are accumulated until at least this much time has passed, so a
    /// source that reports every 200 ms yields a one-second average rather than
    /// a number that jumps by a factor of five between frames.
    private let aggregationWindow: TimeInterval

    private var previous: UInt64?
    private var accumulated: UInt64 = 0
    private var windowStart: TimeInterval = 0
    private var current: Double = 0

    public init(aggregationWindow: TimeInterval = 1) {
        self.aggregationWindow = max(0.05, aggregationWindow)
    }

    /// Bytes per second, as of the last completed window.
    public var bytesPerSecond: Double { current }

    /// Feeds the current value of the counter.
    ///
    /// Call this wherever the counter actually changes. Polling it faster than
    /// the source updates is harmless — the window simply spans several calls —
    /// but polling it *slower* than the source resets would lose traffic.
    public mutating func observe(_ cumulative: UInt64, at now: TimeInterval) {
        guard let previous else {
            self.previous = cumulative
            windowStart = now
            return
        }
        // A counter that went backwards means the source restarted, not that
        // traffic flowed in reverse. Re-baselining loses the bytes since the
        // last window, which is the honest outcome: the alternative is a
        // nonsensical spike of the entire new counter.
        if cumulative < previous {
            self.previous = cumulative
            accumulated = 0
            windowStart = now
            current = 0
            return
        }
        accumulated += cumulative - previous
        self.previous = cumulative

        let elapsed = now - windowStart
        guard elapsed >= aggregationWindow else { return }
        current = Double(accumulated) / elapsed
        accumulated = 0
        windowStart = now
    }

    /// Drops the rate to zero without disturbing the baseline, for when the
    /// source stops reporting entirely — a stopped engine still holds its
    /// counter, and continuing to show its last rate would be a lie.
    public mutating func idle(at now: TimeInterval) {
        accumulated = 0
        windowStart = now
        current = 0
    }

    public mutating func reset() {
        previous = nil
        accumulated = 0
        windowStart = 0
        current = 0
    }
}

/// Formats a rate for the menu bar.
///
/// The menu bar is a few dozen points wide and redraws once a second, so the
/// result is kept short and to a stable width: a value that changes between
/// `9.9K` and `10.0K` must not make everything after it shift sideways.
public enum TrafficRateFormatter {
    public static func compact(bytesPerSecond: Double) -> String {
        let value = bytesPerSecond.isFinite && bytesPerSecond > 0 ? bytesPerSecond : 0
        let units: [(threshold: Double, suffix: String)] = [
            (1_000_000_000, "G"), (1_000_000, "M"), (1_000, "K"),
        ]
        for unit in units where value >= unit.threshold {
            let scaled = value / unit.threshold
            // One decimal below ten keeps 1.2M readable; above ten the decimal
            // is noise and costs a character the menu bar cannot spare.
            return scaled >= 10
                ? String(format: "%.0f%@", scaled, unit.suffix)
                : String(format: "%.1f%@", scaled, unit.suffix)
        }
        return String(format: "%.0fB", value)
    }
}

// MARK: - Self-test

public enum TrafficRateSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "流量速率自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    public static func run() throws {
        try steadyRate()
        try aggregatesFastReports()
        try slowSourceKeepsItsOwnWindow()
        try counterResetDoesNotSpike()
        try idleReportsZero()
        try formatting()
    }

    private static func steadyRate() throws {
        var meter = TrafficRateMeter()
        meter.observe(0, at: 0)
        meter.observe(1_000, at: 1)
        try expect(abs(meter.bytesPerSecond - 1_000) < 0.001,
                   "稳定速率为 \(meter.bytesPerSecond)，应为 1000")
        meter.observe(3_000, at: 2)
        try expect(abs(meter.bytesPerSecond - 2_000) < 0.001,
                   "第二个窗口的速率为 \(meter.bytesPerSecond)，应为 2000")
    }

    /// A source reporting every 200 ms must not produce a rate computed over
    /// 200 ms — that is five times noisier than the display can show.
    private static func aggregatesFastReports() throws {
        var meter = TrafficRateMeter(aggregationWindow: 1)
        meter.observe(0, at: 0)
        var total: UInt64 = 0
        for step in 1...5 {
            total += 200
            meter.observe(total, at: Double(step) * 0.2)
            if step < 5 {
                try expect(meter.bytesPerSecond == 0,
                           "窗口未满时不应出数（第 \(step) 次）")
            }
        }
        try expect(abs(meter.bytesPerSecond - 1_000) < 0.001,
                   "聚合后的速率为 \(meter.bytesPerSecond)，应为 1000")
    }

    /// The helper reports once every five seconds. Its rate must be the average
    /// over those five seconds, not a spike followed by four seconds of zero —
    /// which is what summing both counters and differencing the total gives.
    private static func slowSourceKeepsItsOwnWindow() throws {
        var meter = TrafficRateMeter(aggregationWindow: 1)
        meter.observe(0, at: 0)
        meter.observe(5_000, at: 5)
        try expect(abs(meter.bytesPerSecond - 1_000) < 0.001,
                   "五秒窗口的速率为 \(meter.bytesPerSecond)，应为 1000")
        // No traffic in the next interval: the rate must fall to zero rather
        // than hold the previous value.
        meter.observe(5_000, at: 10)
        try expect(meter.bytesPerSecond == 0, "无新增流量时速率应归零")
    }

    /// Restarting the engine or the helper resets its counter. Treating the
    /// drop as negative traffic, or the next value as one huge delta, both put
    /// an absurd number in the menu bar.
    private static func counterResetDoesNotSpike() throws {
        var meter = TrafficRateMeter(aggregationWindow: 1)
        meter.observe(1_000_000, at: 0)
        meter.observe(2_000_000, at: 1)
        try expect(meter.bytesPerSecond > 0, "重置前应有速率")
        meter.observe(0, at: 2)                     // source restarted
        try expect(meter.bytesPerSecond == 0, "计数器重置后速率应归零而非出现尖峰")
        meter.observe(500, at: 3)
        try expect(abs(meter.bytesPerSecond - 500) < 0.001,
                   "重置后应基于新基线计算，实际 \(meter.bytesPerSecond)")
    }

    private static func idleReportsZero() throws {
        var meter = TrafficRateMeter(aggregationWindow: 1)
        meter.observe(0, at: 0)
        meter.observe(9_999, at: 1)
        try expect(meter.bytesPerSecond > 0, "应先有速率")
        meter.idle(at: 2)
        try expect(meter.bytesPerSecond == 0, "标记空闲后速率应为零")
        // The baseline survives, so a later report is not mistaken for a reset.
        meter.observe(10_999, at: 3)
        try expect(abs(meter.bytesPerSecond - 1_000) < 0.001,
                   "空闲后恢复计数的速率为 \(meter.bytesPerSecond)，应为 1000")
    }

    private static func formatting() throws {
        let cases: [(Double, String)] = [
            (0, "0B"), (999, "999B"),
            (1_000, "1.0K"), (9_949, "9.9K"), (10_000, "10K"), (999_000, "999K"),
            (1_000_000, "1.0M"), (12_300_000, "12M"),
            (2_500_000_000, "2.5G"),
        ]
        for (value, expected) in cases {
            let actual = TrafficRateFormatter.compact(bytesPerSecond: value)
            try expect(actual == expected, "\(value) 格式化为 \(actual)，应为 \(expected)")
        }
        // Negative and non-finite values come from a bad clock or a bad delta;
        // they must not reach the menu bar as "-1B" or "nanB".
        try expect(TrafficRateFormatter.compact(bytesPerSecond: -5) == "0B", "负值未归零")
        try expect(TrafficRateFormatter.compact(bytesPerSecond: .nan) == "0B", "NaN 未归零")
        try expect(TrafficRateFormatter.compact(bytesPerSecond: .infinity) == "0B", "无穷未归零")
    }
}
