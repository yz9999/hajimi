#ifndef HJ_RING_BUFFER_H
#define HJ_RING_BUFFER_H

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HJ_TRAFFIC_HISTORY_CAPACITY 60

typedef struct {
    uint64_t values[HJ_TRAFFIC_HISTORY_CAPACITY];
    double smoothed_peak;
    double ewma_mean;
    double ewm_var;
    size_t head;
    size_t count;
} hj_traffic_ring_t;

static inline void hj_traffic_ring_init(hj_traffic_ring_t *ring) {
    if (!ring) return;
    memset(ring, 0, sizeof(*ring));
}

static inline void hj_traffic_ring_push(hj_traffic_ring_t *ring, uint64_t value) {
    if (!ring) return;
    ring->values[ring->head] = value;
    size_t next = ring->head + 1;
    ring->head = (next == HJ_TRAFFIC_HISTORY_CAPACITY) ? 0 : next;
    if (ring->count < HJ_TRAFFIC_HISTORY_CAPACITY) {
        ring->count++;
    }
    const double sample = (double)value;
    if (ring->count == 1) {
        ring->ewma_mean = sample;
        ring->ewm_var = 0.0;
        ring->smoothed_peak = sample;
    } else {
        // Welford-West online exponentially weighted mean & variance
        const double alpha = 0.20;
        const double delta = sample - ring->ewma_mean;
        ring->ewma_mean += alpha * delta;
        ring->ewm_var = (1.0 - alpha) * (ring->ewm_var + alpha * delta * delta);
        // Asymmetric attack/release envelope follower for smooth axis scaling
        if (sample >= ring->smoothed_peak) {
            ring->smoothed_peak = sample;
        } else {
            ring->smoothed_peak = ring->smoothed_peak * 0.92 + sample * 0.08;
        }
    }
}

static inline uint64_t hj_traffic_ring_at(const hj_traffic_ring_t *ring, size_t index) {
    if (!ring || index >= ring->count) return 0;
    size_t start = (ring->count == HJ_TRAFFIC_HISTORY_CAPACITY) ? ring->head : 0;
    size_t pos = start + index;
    if (pos >= HJ_TRAFFIC_HISTORY_CAPACITY) pos -= HJ_TRAFFIC_HISTORY_CAPACITY;
    return ring->values[pos];
}

static inline uint64_t hj_traffic_ring_peak(const hj_traffic_ring_t *ring) {
    if (!ring) return 0;
    uint64_t peak = 0;
    const size_t n = ring->count > HJ_TRAFFIC_HISTORY_CAPACITY ? HJ_TRAFFIC_HISTORY_CAPACITY : ring->count;
    for (size_t i = 0; i < n; i++) {
        uint64_t v = ring->values[i];
        if (v > peak) peak = v;
    }
    if ((uint64_t)ring->smoothed_peak > peak) {
        peak = (uint64_t)ring->smoothed_peak;
    }
    return peak;
}

/// Computes the 95th-percentile order statistic in O(N) stack space via insertion sort on <=60 elements.
static inline uint64_t hj_traffic_ring_p95(const hj_traffic_ring_t *ring) {
    if (!ring || ring->count == 0) return 0;
    uint64_t sorted[HJ_TRAFFIC_HISTORY_CAPACITY];
    const size_t n = ring->count > HJ_TRAFFIC_HISTORY_CAPACITY ? HJ_TRAFFIC_HISTORY_CAPACITY : ring->count;
    for (size_t i = 0; i < n; ++i) {
        uint64_t key = ring->values[i];
        size_t j = i;
        while (j > 0 && sorted[j - 1] > key) {
            sorted[j] = sorted[j - 1];
            --j;
        }
        sorted[j] = key;
    }
    const size_t idx = (n * 95) / 100;
    return sorted[idx < n ? idx : (n - 1)];
}

#endif /* HJ_RING_BUFFER_H */
