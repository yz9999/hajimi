import Foundation
import HajimiFlowCXX

/// Control-plane ownership only. Storage, wraparound, growth, and coalescing
/// live in the bounded C++ ring, not an array of ARC-managed packet objects.
final class NativeByteQueue {
    private let handle: OpaquePointer?
    private let limit: Int
    init(limit: Int) { self.limit = limit; handle = hajimi_byte_queue_create(limit) }
    deinit { hajimi_byte_queue_destroy(handle) }
    var isValid: Bool { handle != nil }
    var count: Int { hajimi_byte_queue_size(handle) }
    var isEmpty: Bool { count == 0 }
    var residentCapacity: Int { hajimi_byte_queue_capacity(handle) }
    /// Growth reserves the entire new buffer before freeing the old one.
    /// Advertise only storage that can fit this shared-budget snapshot.
    var availableRoom: Int {
        let remaining = max(0, hajimi_flow_buffer_budget_limit() - hajimi_flow_buffer_budget_used())
        var growable = 0
        if remaining >= limit { growable = limit }
        else if remaining >= min(4_096, limit) {
            growable = min(4_096, limit)
            while growable <= remaining / 2 && growable <= limit / 2 { growable *= 2 }
        }
        return max(0, max(residentCapacity, growable) - count)
    }
    func append(_ data: Data) -> Bool {
        data.withUnsafeBytes { append($0) }
    }
    func append(_ bytes: UnsafeRawBufferPointer) -> Bool {
        hajimi_byte_queue_append(handle,
            bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count) != 0
    }
    func prefix(maximum: Int) -> Data {
        let count = min(maximum, self.count)
        guard count > 0 else { return Data() }
        var result = Data(count: count)
        result.withUnsafeMutableBytes { raw in
            _ = hajimi_byte_queue_copy(handle, raw.baseAddress?.assumingMemoryBound(to: UInt8.self), count)
        }
        return result
    }
    func consume(_ count: Int) { _ = hajimi_byte_queue_consume(handle, count) }
    func clear() { hajimi_byte_queue_clear(handle) }
    /// Releases idle ring-buffer backing storage back to the global 32 MiB budget when empty.
    func shrinkToFit() { hajimi_byte_queue_shrink_to_fit(handle) }
}

/// Bridges C++ out-of-order TCP reassembly intervals into RFC 2018 SACK option blocks.
enum NativeReassemblySACK {
    static func blocks(from receiveState: OpaquePointer?, maximum: Int = 4) -> [SACKBlock] {
        guard let receiveState, maximum > 0,
              hajimi_tcp_reassembly_buffered(receiveState) > 0 else {
            return []
        }
        let capped = min(maximum, 4)
        var ranges = (hajimi_sack_range(), hajimi_sack_range(),
                      hajimi_sack_range(), hajimi_sack_range())
        return withUnsafeMutablePointer(to: &ranges) { tuplePtr in
            tuplePtr.withMemoryRebound(to: hajimi_sack_range.self, capacity: 4) { base in
                let count = hajimi_tcp_reassembly_sack_blocks(receiveState, base, capped)
                guard count > 0 else { return [] }
                var result: [SACKBlock] = []
                result.reserveCapacity(count)
                for index in 0..<count {
                    result.append(SACKBlock(start: base[index].start, end: base[index].end))
                }
                return result
            }
        }
    }
}

/// Swift value wrapper around C++ BBRv3 / CoDel (`hajimi_bdp_estimator`) bandwidth-delay
/// product and standing-queue window bounding.
struct NativeBDPEstimator {
    private var native: hajimi_bdp_estimator

    init(windowSeconds: TimeInterval = 10.0) {
        var value = hajimi_bdp_estimator()
        hajimi_bdp_init(&value, windowSeconds)
        self.native = value
    }

    var isInitialized: Bool { native.initialized != 0 }
    var standingQueueRounds: UInt32 { native.standing_queue_rounds }
    var lossEvents: UInt32 { native.loss_events }

    var maxBandwidth: Double {
        var value = native
        return hajimi_bdp_max_bandwidth(&value)
    }

    mutating func observe(deliveredBytes: Int, rtt: TimeInterval, timestamp: TimeInterval) {
        guard deliveredBytes > 0 else { return }
        hajimi_bdp_observe(&native, deliveredBytes, rtt, timestamp)
    }

    mutating func observeLoss(inflightBytes: Int, lostBytes: Int, deliveredBytes: Int) {
        guard inflightBytes > 0 else { return }
        hajimi_bdp_observe_loss(&native, inflightBytes, max(0, lostBytes), max(0, deliveredBytes))
    }

    func recommendedWindow(mss: Int, minWindow: Int, maxWindow: Int) -> Int {
        var value = native
        return hajimi_bdp_recommended_window(&value, max(536, mss), max(0, minWindow), max(0, maxWindow))
    }
}
