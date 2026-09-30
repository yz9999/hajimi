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

#ifdef __cplusplus
}
#endif
#endif
