#ifndef HJ_PACKET_ENGINE_BRIDGE_H
#define HJ_PACKET_ENGINE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// An actual TCP/IP forwarding engine must implement this ABI. The C packet
/// codec alone, a byte-stream relay, or an engine that discards input does not
/// satisfy it. Packets are raw IPv4/IPv6, WITHOUT the four-byte utun prefix;
/// address_family is the Darwin AF_INET or AF_INET6 value, not 4 or 6.
enum {
    HJ_PACKET_ENGINE_ABI_VERSION = 1,
    HJ_PACKET_ENGINE_CAP_IPV4 = 1u << 0,
    HJ_PACKET_ENGINE_CAP_IPV6 = 1u << 1,
    HJ_PACKET_ENGINE_CAP_TCP = 1u << 2,
    HJ_PACKET_ENGINE_CAP_UDP = 1u << 3,
};

typedef struct {
    uint32_t struct_size;
    void *context;
    /// The receiver copies packet before returning. Zero means accepted;
    /// nonzero means closed/invalid/backpressured and MUST be handled by the
    /// engine, not silently ignored. Callbacks may execute on any thread.
    int32_t (*emit_packet)(void *context, const uint8_t *packet,
                           size_t length, int32_t address_family);
    void (*report_failure)(void *context, int32_t code, const char *message);
} hj_packet_engine_callbacks_v1;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t capabilities;
    /// Configuration is opaque to the provider (e.g. engine-owned JSON).
    /// Copy configuration and callbacks before returning. On a NULL return,
    /// no callback may remain in flight. Error buffers must be bounded/NUL
    /// terminated. Neither create nor start receives untrusted packet input.
    void *(*create)(const uint8_t *configuration, size_t configuration_length,
                    const hj_packet_engine_callbacks_v1 *callbacks,
                    char *error, size_t error_capacity);
    /// Zero means the shared routing/proxy engine is ready to accept packets.
    /// Its upstream sockets MUST escape the tunnel (physical-interface
    /// binding or explicit excluded routes) without using private utun APIs.
    int32_t (*start)(void *engine, char *error, size_t error_capacity);
    /// Zero means processed/queued; copy bytes before returning if queued.
    /// Implement TCP flow state, UDP routing, and return real response packets
    /// through emit_packet. Any unsupported/drop/backpressure condition must
    /// be explicit. The provider cancels a tunnel on a nonzero return.
    int32_t (*submit_packet)(void *engine, const uint8_t *packet, size_t length,
                             int32_t address_family,
                             char *error, size_t error_capacity);
    /// Safe even after a failed start. Synchronously quiesce ALL callbacks and
    /// cancel engine I/O/timers before returning. Never wait for the provider's
    /// packet queue, since stop is called on that queue.
    void (*stop)(void *engine);
    void (*destroy)(void *engine);
} hj_packet_engine_api_v1;

/// The returned table has process lifetime. This optional import is deliberate:
/// an unsigned development bundle can compile without a native engine, but it
/// MUST fail startTunnel before installing routes. Link a real implementation
/// with the signed provider to make this feature operational.
#if defined(__APPLE__) && !defined(HJ_PACKET_ENGINE_IMPLEMENTATION)
__attribute__((weak_import))
#endif
const hj_packet_engine_api_v1 *hajimi_packet_engine_get_api_v1(void);

#ifdef __cplusplus
}
#endif

#endif
