#ifndef HAJIMI_FLOW_CXX_H
#define HAJIMI_FLOW_CXX_H

#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Queue-owned objects: callers serialize access. No GC or background threads.
 * Queues grow lazily within the configured budget and reuse their storage.
 * A pointer returned by peek is valid until the next mutating queue call. */
typedef struct hajimi_byte_queue hajimi_byte_queue;
hajimi_byte_queue *hajimi_byte_queue_create(size_t limit);
void hajimi_byte_queue_destroy(hajimi_byte_queue *queue);
int hajimi_byte_queue_append(hajimi_byte_queue *queue, const uint8_t *bytes, size_t length);
size_t hajimi_byte_queue_size(const hajimi_byte_queue *queue);
size_t hajimi_byte_queue_capacity(const hajimi_byte_queue *queue);
const uint8_t *hajimi_byte_queue_peek(const hajimi_byte_queue *queue, size_t maximum, size_t *length);
size_t hajimi_byte_queue_copy(const hajimi_byte_queue *queue, uint8_t *output, size_t maximum);
int hajimi_byte_queue_consume(hajimi_byte_queue *queue, size_t length);
void hajimi_byte_queue_clear(hajimi_byte_queue *queue);
/* Releases backing storage when the queue is empty to reclaim idle memory. */
void hajimi_byte_queue_shrink_to_fit(hajimi_byte_queue *queue);

/* Shared hard budget for queue backing capacity + copied out-of-order payload.
 * Thread-safe counters include reservations and the old+new growth peak. They
 * exclude object/vector metadata, allocator overhead, Swift buffers, and RSS.
 * Clearing a byte queue retains its charged capacity for reuse; destroying it
 * releases the charge. Reassembly erase/FIN-clear/destruction release copies.
 * Allocation/quota failure never advances a queue or TCP acknowledgment. */
size_t hajimi_flow_buffer_budget_used(void);
size_t hajimi_flow_buffer_budget_limit(void);

/* TCP sequence arithmetic is modulo 2^32, valid within the TCP half-space. */
int hajimi_sequence_after(uint32_t left, uint32_t right);
int hajimi_sequence_after_equal(uint32_t left, uint32_t right);

/* SACK range coverage primitive in modulo-2^32 TCP sequence space. */
typedef struct hajimi_sack_range {
    uint32_t start;
    uint32_t end;
} hajimi_sack_range;

int hajimi_sack_covers(const hajimi_sack_range *ranges, size_t range_count,
                       uint32_t sequence, uint32_t length);

typedef struct hajimi_rto {
    double smoothed_rtt;
    double variation;
    double timeout;
    uint8_t sampled;
} hajimi_rto;
void hajimi_rto_init(hajimi_rto *timer);
void hajimi_rto_update(hajimi_rto *timer, double seconds);
double hajimi_rto_timeout(const hajimi_rto *timer, uint32_t retries);

/* The synchronous consumer must return nonzero only after accepting ALL bytes.
 * The engine never acknowledges bytes rejected by a backpressured consumer.
 * In-order data is borrowed directly; only out-of-order data is copied. */
typedef int (*hajimi_tcp_consume)(void *context, const uint8_t *bytes, size_t length);
typedef struct hajimi_tcp_reassembly hajimi_tcp_reassembly;
hajimi_tcp_reassembly *hajimi_tcp_reassembly_create(uint32_t expected, size_t byte_limit, size_t segment_limit);
void hajimi_tcp_reassembly_destroy(hajimi_tcp_reassembly *state);
size_t hajimi_tcp_reassembly_ingest(hajimi_tcp_reassembly *state, uint32_t sequence,
                                  const uint8_t *bytes, size_t length,
                                  void *context, hajimi_tcp_consume consumer);
size_t hajimi_tcp_reassembly_drain(hajimi_tcp_reassembly *state,
                                 void *context, hajimi_tcp_consume consumer);
void hajimi_tcp_reassembly_fin(hajimi_tcp_reassembly *state, uint32_t sequence);
uint32_t hajimi_tcp_reassembly_expected(const hajimi_tcp_reassembly *state);
size_t hajimi_tcp_reassembly_buffered(const hajimi_tcp_reassembly *state);
int hajimi_tcp_reassembly_finished(const hajimi_tcp_reassembly *state);
/* Run only in a quiescent unit-test process: quota tests reserve all remaining
 * shared budget briefly, without allocating that artificial reservation. */
int hajimi_flow_self_test(void);

/* Kathleen Nichols 3-slot windowed Min-RTT / Max-Bandwidth filter,
 * Kleinrock BBR Bandwidth-Delay Product (BDP) window estimator, and
 * Nichols-Jacobson CoDel (RFC 8289) standing-queue bufferbloat drain control. */
typedef struct hajimi_window_sample {
    double value;
    double timestamp;
} hajimi_window_sample;

typedef struct hajimi_bdp_estimator {
    double window_seconds;
    double min_rtt;
    double min_rtt_timestamp;
    double last_rtt;
    hajimi_window_sample bw_samples[3];
    size_t inflight_hi;
    size_t inflight_lo;
    uint32_t loss_events;
    uint32_t standing_queue_rounds;
    uint8_t initialized;
} hajimi_bdp_estimator;

void hajimi_bdp_init(hajimi_bdp_estimator *est, double window_seconds);
void hajimi_bdp_observe(hajimi_bdp_estimator *est,
                        size_t delivered_bytes,
                        double rtt_seconds,
                        double timestamp_seconds);
/* BBRv3 (draft-ietf-ccwg-bbr-04) loss-headroom & inflight_hi/inflight_lo bounding:
 * clamps inflight_hi and scales inflight_lo by BBRBeta (0.70) when loss rate > 2%,
 * and probes upward on loss-free delivery rounds. */
void hajimi_bdp_observe_loss(hajimi_bdp_estimator *est,
                             size_t inflight_bytes,
                             size_t lost_bytes,
                             size_t delivered_bytes);
double hajimi_bdp_max_bandwidth(const hajimi_bdp_estimator *est);
size_t hajimi_bdp_recommended_window(const hajimi_bdp_estimator *est,
                                     size_t mss,
                                     size_t min_window,
                                     size_t max_window);

/* RFC 8985 RACK-TLP (Recent ACK & Tail Loss Probe) probe timeout (PTO) in seconds. */
double hajimi_rack_tlp_pto(const hajimi_rto *timer, size_t flight_size, size_t mss);

#ifdef __cplusplus
}
#endif
#endif
