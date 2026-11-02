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
}
