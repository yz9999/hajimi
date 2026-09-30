#include "HajimiFlowCXX.h"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <vector>

namespace {
constexpr size_t BufferBudgetLimit = 32U * 1024U * 1024U;
std::atomic<size_t> bufferBudgetUsed{0};
bool reserveBufferBytes(size_t bytes) {
    size_t used = bufferBudgetUsed.load(std::memory_order_relaxed);
    do {
        if (bytes > BufferBudgetLimit - used) return false;
    } while (!bufferBudgetUsed.compare_exchange_weak(used, used + bytes,
               std::memory_order_acq_rel, std::memory_order_relaxed));
    return true;
}
void releaseBufferBytes(size_t bytes) {
    if (bytes) bufferBudgetUsed.fetch_sub(bytes, std::memory_order_acq_rel);
}
struct BudgetDeleter {
    size_t bytes = 0;
    void operator()(uint8_t *buffer) const noexcept {
        delete[] buffer; // Free first: another thread may reserve immediately.
        releaseBufferBytes(bytes);
    }
};
using BudgetBuffer = std::unique_ptr<uint8_t[], BudgetDeleter>;
BudgetBuffer allocateBuffer(size_t bytes) {
    if (!bytes || !reserveBufferBytes(bytes)) return BudgetBuffer{};
    uint8_t *buffer = new (std::nothrow) uint8_t[bytes];
    if (!buffer) { releaseBufferBytes(bytes); return BudgetBuffer{}; }
    return BudgetBuffer(buffer, BudgetDeleter{bytes});
}
struct ScopedBudgetReservation {
    size_t bytes;
    bool accepted;
    explicit ScopedBudgetReservation(size_t count) : bytes(count), accepted(reserveBufferBytes(count)) {}
    ~ScopedBudgetReservation() { if (accepted) releaseBufferBytes(bytes); }
};
}

extern "C" size_t hajimi_flow_buffer_budget_used(void) {
    return bufferBudgetUsed.load(std::memory_order_relaxed);
}
extern "C" size_t hajimi_flow_buffer_budget_limit(void) { return BufferBudgetLimit; }

struct hajimi_byte_queue {
    explicit hajimi_byte_queue(size_t maximum) : limit(maximum) {}
    size_t limit, head = 0, count = 0, capacity = 0;
    BudgetBuffer storage;
};

extern "C" hajimi_byte_queue *hajimi_byte_queue_create(size_t limit) {
    if (!limit || limit > 64U * 1024U * 1024U) return nullptr;
    return new (std::nothrow) hajimi_byte_queue(limit);
}
extern "C" void hajimi_byte_queue_destroy(hajimi_byte_queue *q) { delete q; }
extern "C" size_t hajimi_byte_queue_size(const hajimi_byte_queue *q) { return q ? q->count : 0; }
extern "C" size_t hajimi_byte_queue_capacity(const hajimi_byte_queue *q) { return q ? q->capacity : 0; }
extern "C" size_t hajimi_byte_queue_copy(const hajimi_byte_queue *q, uint8_t *out, size_t maximum) {
    if (!q || !out) return 0;
    const size_t n = std::min(maximum, q->count);
    if (!n) return 0;
    const size_t first = std::min(n, q->capacity - q->head);
    std::memcpy(out, q->storage.get() + q->head, first);
    if (first < n) std::memcpy(out + first, q->storage.get(), n - first);
    return n;
}
extern "C" int hajimi_byte_queue_append(hajimi_byte_queue *q, const uint8_t *bytes, size_t n) {
    if (!q || (!bytes && n) || n > q->limit - q->count) return 0;
    if (!n) return 1;
    const size_t required = q->count + n;
    if (required > q->capacity) {
        size_t capacity = std::max<size_t>(4096, q->capacity);
        while (capacity < required) capacity = std::min(q->limit, capacity * 2);
        capacity = std::min(capacity, q->limit);
        // Reserve the complete new allocation while the old buffer remains
        // charged: growth must fit its temporary peak, not merely its delta.
        auto grown = allocateBuffer(capacity);
        if (!grown) return 0;
        hajimi_byte_queue_copy(q, grown.get(), q->count);
        q->storage.swap(grown);
        q->capacity = capacity;
        q->head = 0;
    }
    const size_t tail = (q->head + q->count) % q->capacity;
    const size_t first = std::min(n, q->capacity - tail);
    std::memcpy(q->storage.get() + tail, bytes, first);
    if (first < n) std::memcpy(q->storage.get(), bytes + first, n - first);
    q->count += n;
    return 1;
}
extern "C" const uint8_t *hajimi_byte_queue_peek(const hajimi_byte_queue *q, size_t maximum, size_t *length) {
    if (length) *length = 0;
    if (!q || !q->count || !length) return nullptr;
    *length = std::min({maximum, q->count, q->capacity - q->head});
    return q->storage.get() + q->head;
}
extern "C" int hajimi_byte_queue_consume(hajimi_byte_queue *q, size_t n) {
    if (!q || n > q->count) return 0;
    if (n) q->head = (q->head + n) % q->capacity;
    q->count -= n;
    if (!q->count) q->head = 0;
    return 1;
}
extern "C" void hajimi_byte_queue_clear(hajimi_byte_queue *q) {
    if (q) { q->head = 0; q->count = 0; }
}
extern "C" int hajimi_sequence_after(uint32_t a, uint32_t b) { return int32_t(a - b) > 0; }
extern "C" int hajimi_sequence_after_equal(uint32_t a, uint32_t b) { return int32_t(a - b) >= 0; }
extern "C" void hajimi_rto_init(hajimi_rto *t) {
    if (t) *t = {0, 0, 0.2, 0};
}
extern "C" void hajimi_rto_update(hajimi_rto *t, double sample) {
    if (!t || !std::isfinite(sample) || sample <= 0) return;
    if (t->sampled) {
        t->variation = 0.75 * t->variation + 0.25 * std::abs(t->smoothed_rtt - sample);
        t->smoothed_rtt = 0.875 * t->smoothed_rtt + 0.125 * sample;
    } else {
        t->smoothed_rtt = sample;
        t->variation = sample / 2;
        t->sampled = 1;
    }
    t->timeout = std::clamp(t->smoothed_rtt + std::max(0.001, 4 * t->variation), 0.02, 12.0);
}
extern "C" double hajimi_rto_timeout(const hajimi_rto *t, uint32_t retries) {
    if (!t) return 0.2;
    return std::min(12.0, std::ldexp(t->timeout, int(std::min<uint32_t>(retries, 16))));
}

struct PendingSegment {
    uint32_t sequence;
    size_t length;
    BudgetBuffer bytes;
};
struct hajimi_tcp_reassembly {
    uint32_t expected;
    size_t byteLimit, segmentLimit, buffered = 0;
    bool finPending = false, finished = false;
    uint32_t fin = 0;
    std::vector<PendingSegment> segments;
    void finishIfReady() {
        if (finPending && fin == expected) {
            ++expected; finished = true; finPending = false;
            segments.clear(); buffered = 0;
        }
    }
};
extern "C" hajimi_tcp_reassembly *hajimi_tcp_reassembly_create(uint32_t expected, size_t bytes, size_t segments) {
    if (!bytes || bytes > 16U * 1024U * 1024U || !segments || segments > 4096) return nullptr;
    auto *s = new (std::nothrow) hajimi_tcp_reassembly;
    if (!s) return nullptr;
    s->expected = expected; s->byteLimit = bytes; s->segmentLimit = segments;
    try { s->segments.reserve(segments); }
    catch (...) { delete s; return nullptr; }
    return s;
}
extern "C" void hajimi_tcp_reassembly_destroy(hajimi_tcp_reassembly *s) { delete s; }
extern "C" size_t hajimi_tcp_reassembly_drain(hajimi_tcp_reassembly *s, void *context, hajimi_tcp_consume consume) {
    if (!s || !consume || s->finished) return 0;
    size_t released = 0;
    for (;;) {
        if (s->finPending && s->fin == s->expected) break;
        auto found = s->segments.end();
        size_t skip = 0;
        for (auto it = s->segments.begin(); it != s->segments.end();) {
            // Trim retransmitted overlap, including ranges crossing UINT32_MAX.
            const int32_t distance = int32_t(s->expected - it->sequence);
            if (distance >= 0 && size_t(distance) >= it->length) {
                s->buffered -= it->length;
                it = s->segments.erase(it);
                continue;
            }
            if (distance >= 0) { found = it; skip = size_t(distance); break; }
            ++it;
        }
        if (found == s->segments.end()) break;
        size_t n = found->length - skip;
        if (s->finPending) {
            const int32_t untilFin = int32_t(s->fin - s->expected);
            if (untilFin <= 0) break;
            n = std::min(n, size_t(untilFin));
        }
        if (!consume(context, found->bytes.get() + skip, n)) break;
        s->expected += uint32_t(n); released += n;
        s->buffered -= found->length;
        s->segments.erase(found);
    }
    s->finishIfReady();
    return released;
}
extern "C" size_t hajimi_tcp_reassembly_ingest(hajimi_tcp_reassembly *s, uint32_t sequence,
                                               const uint8_t *bytes, size_t n,
                                               void *context, hajimi_tcp_consume consume) {
    if (!s || !consume || (!bytes && n) || !n || n > INT32_MAX || s->finished) return 0;
    if (s->finPending) {
        const int32_t untilFin = int32_t(s->fin - sequence);
        if (untilFin <= 0) return 0;
        n = std::min(n, size_t(untilFin));
    }
    size_t released = 0;
    const int32_t distance = int32_t(sequence - s->expected);
    if (distance <= 0) {
        const size_t skip = size_t(-int64_t(distance));
        if (skip >= n) return 0;
        if (!consume(context, bytes + skip, n - skip)) return 0;
        s->expected += uint32_t(n - skip);
        released = n - skip;
        released += hajimi_tcp_reassembly_drain(s, context, consume);
        s->finishIfReady();
        return released;
    }
    if (n > s->byteLimit - s->buffered || s->segments.size() >= s->segmentLimit) return 0;
    // Identical starts are retransmissions; keep the first accepted payload.
    for (const auto &segment : s->segments) if (segment.sequence == sequence) return 0;
    auto copy = allocateBuffer(n);
    if (!copy) return 0;
    std::memcpy(copy.get(), bytes, n);
    s->segments.push_back({sequence, n, std::move(copy)});
    s->buffered += n;
    return 0;
}
extern "C" void hajimi_tcp_reassembly_fin(hajimi_tcp_reassembly *s, uint32_t sequence) {
    if (!s || s->finished || hajimi_sequence_after(s->expected, sequence)) return;
    if (!s->finPending || hajimi_sequence_after(s->fin, sequence)) s->fin = sequence;
    s->finPending = true; s->finishIfReady();
}
extern "C" uint32_t hajimi_tcp_reassembly_expected(const hajimi_tcp_reassembly *s) { return s ? s->expected : 0; }
extern "C" size_t hajimi_tcp_reassembly_buffered(const hajimi_tcp_reassembly *s) { return s ? s->buffered : 0; }
extern "C" int hajimi_tcp_reassembly_finished(const hajimi_tcp_reassembly *s) { return s && s->finished; }

namespace {
int consumeQueue(void *context, const uint8_t *p, size_t n) {
    return hajimi_byte_queue_append(static_cast<hajimi_byte_queue *>(context), p, n);
}
}
static int flowSelfTestBody(void) {
    auto *q = hajimi_byte_queue_create(8192);
    if (!q) return 1;
    std::unique_ptr<hajimi_byte_queue, decltype(&hajimi_byte_queue_destroy)> owner(q, hajimi_byte_queue_destroy);
    uint8_t input[5000], output[8192];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = uint8_t(i);
    if (!hajimi_byte_queue_append(q, input, 4000) || !hajimi_byte_queue_consume(q, 3999)) return 2;
    if (!hajimi_byte_queue_append(q, input, sizeof(input)) || hajimi_byte_queue_size(q) != 5001) return 3;
    if (hajimi_byte_queue_copy(q, output, sizeof(output)) != 5001 || output[0] != input[3999] ||
        std::memcmp(output + 1, input, sizeof(input))) return 4;
    if (hajimi_byte_queue_append(q, input, sizeof(input)) || hajimi_byte_queue_consume(q, 5002)) return 5;
    const size_t warmed = hajimi_byte_queue_capacity(q);
    hajimi_byte_queue_clear(q);
    if (hajimi_byte_queue_capacity(q) != warmed) return 6;
    auto *s = hajimi_tcp_reassembly_create(UINT32_MAX - 1, 1024, 4);
    if (!s) return 7;
    std::unique_ptr<hajimi_tcp_reassembly, decltype(&hajimi_tcp_reassembly_destroy)> state(s, hajimi_tcp_reassembly_destroy);
    const uint8_t a[] = {'a', 'b'}, b[] = {'c', 'd'};
    hajimi_tcp_reassembly_ingest(s, 0, b, 2, q, consumeQueue);
    if (hajimi_tcp_reassembly_buffered(s) != 2) return 8;
    hajimi_tcp_reassembly_fin(s, 2);
    if (hajimi_tcp_reassembly_ingest(s, UINT32_MAX - 1, a, 2, q, consumeQueue) != 4 ||
        hajimi_tcp_reassembly_expected(s) != 3 || !hajimi_tcp_reassembly_finished(s)) return 9;
    if (hajimi_byte_queue_copy(q, output, sizeof(output)) != 4 || std::memcmp(output, "abcd", 4)) return 10;
    hajimi_rto t; hajimi_rto_init(&t);
    hajimi_rto_update(&t, 0.001);
    if (t.timeout != 0.02 || hajimi_rto_timeout(&t, 32) != 12.0) return 11;
    if (!hajimi_sequence_after(1, UINT32_MAX) || hajimi_sequence_after(UINT32_MAX, 1)) return 12;
    auto *overlap = hajimi_tcp_reassembly_create(100, 8, 2);
    if (!overlap) return 13;
    std::unique_ptr<hajimi_tcp_reassembly, decltype(&hajimi_tcp_reassembly_destroy)> second(overlap, hajimi_tcp_reassembly_destroy);
    hajimi_byte_queue_clear(q);
    hajimi_tcp_reassembly_ingest(overlap, 102, reinterpret_cast<const uint8_t *>("cdef"), 4, q, consumeQueue);
    if (hajimi_tcp_reassembly_ingest(overlap, 100, reinterpret_cast<const uint8_t *>("abcd"), 4, q, consumeQueue) != 6) return 14;
    if (hajimi_byte_queue_copy(q, output, 6) != 6 || std::memcmp(output, "abcdef", 6)) return 15;
    hajimi_tcp_reassembly_fin(overlap, 108);
    if (hajimi_tcp_reassembly_ingest(overlap, 106, reinterpret_cast<const uint8_t *>("ghij"), 4, q, consumeQueue) != 2 ||
        !hajimi_tcp_reassembly_finished(overlap) || hajimi_tcp_reassembly_expected(overlap) != 109) return 16;
    auto *blocked = hajimi_tcp_reassembly_create(100, 8, 2);
    if (!blocked) return 17;
    std::unique_ptr<hajimi_tcp_reassembly, decltype(&hajimi_tcp_reassembly_destroy)> third(blocked, hajimi_tcp_reassembly_destroy);
    if (hajimi_tcp_reassembly_ingest(blocked, 100, a, 2, nullptr, consumeQueue) != 0 ||
        hajimi_tcp_reassembly_expected(blocked) != 100) return 18;
    hajimi_tcp_reassembly_ingest(blocked, 102, b, 2, q, consumeQueue);
    if (hajimi_tcp_reassembly_drain(blocked, nullptr, consumeQueue) != 0 ||
        hajimi_tcp_reassembly_buffered(blocked) != 2) return 19;
    if (hajimi_tcp_reassembly_ingest(blocked, 100, a, 2, q, consumeQueue) != 4 ||
        hajimi_tcp_reassembly_buffered(blocked) != 0) return 20;
    auto *growth = hajimi_byte_queue_create(8192);
    if (!growth) return 21;
    std::unique_ptr<hajimi_byte_queue, decltype(&hajimi_byte_queue_destroy)> fourth(growth, hajimi_byte_queue_destroy);
    if (!hajimi_byte_queue_append(growth, input, 4000) || growth->capacity != 4096) return 22;
    const size_t available = BufferBudgetLimit - hajimi_flow_buffer_budget_used();
    if (available < 4096) return 23;
    {
        ScopedBudgetReservation held(available - 4096);
        // The net growth delta fits; the old+new temporary allocation does not.
        if (!held.accepted || hajimi_byte_queue_append(growth, input, 200) ||
            growth->count != 4000 || growth->capacity != 4096) return 24;
    }
    {
        ScopedBudgetReservation held(BufferBudgetLimit - hajimi_flow_buffer_budget_used());
        if (!held.accepted || hajimi_flow_buffer_budget_used() != BufferBudgetLimit) return 25;
        auto *empty = hajimi_byte_queue_create(1);
        auto *quota = hajimi_tcp_reassembly_create(100, 8, 2);
        std::unique_ptr<hajimi_byte_queue, decltype(&hajimi_byte_queue_destroy)> fifth(empty, hajimi_byte_queue_destroy);
        std::unique_ptr<hajimi_tcp_reassembly, decltype(&hajimi_tcp_reassembly_destroy)> sixth(quota, hajimi_tcp_reassembly_destroy);
        if (!empty || !quota || hajimi_byte_queue_append(empty, a, 1) || empty->count ||
            hajimi_tcp_reassembly_ingest(quota, 102, b, 2, empty, consumeQueue) || quota->buffered ||
            hajimi_tcp_reassembly_ingest(quota, 100, a, 2, empty, consumeQueue) || quota->expected != 100) return 26;
        hajimi_byte_queue_clear(q);
        // An exhausted global budget must not disable already-warmed buffers.
        if (hajimi_tcp_reassembly_ingest(quota, 100, a, 2, q, consumeQueue) != 2 ||
            quota->expected != 102 || q->count != 2) return 27;
    }
    auto *fin = hajimi_tcp_reassembly_create(100, 8, 2);
    if (!fin) return 28;
    std::unique_ptr<hajimi_tcp_reassembly, decltype(&hajimi_tcp_reassembly_destroy)> seventh(fin, hajimi_tcp_reassembly_destroy);
    const size_t beforeFin = hajimi_flow_buffer_budget_used();
    hajimi_tcp_reassembly_ingest(fin, 102, b, 2, q, consumeQueue);
    if (hajimi_flow_buffer_budget_used() != beforeFin + 2) return 29;
    hajimi_tcp_reassembly_fin(fin, 100);
    if (hajimi_flow_buffer_budget_used() != beforeFin || !fin->finished || fin->buffered) return 30;
    return 0;
}

extern "C" int hajimi_flow_self_test(void) {
    // Unit validation runs in a quiescent process. All local owners unwind on
    // every return path; accounting must return exactly to its entry value.
    const size_t before = hajimi_flow_buffer_budget_used();
    const int result = flowSelfTestBody();
    if (hajimi_flow_buffer_budget_used() != before) return 31;
    return result;
}
