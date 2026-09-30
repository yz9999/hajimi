/// Zero-copy packet codec primitives for the Hajimi data plane.
///
/// Everything in this header is stateless and operates directly on
/// caller-owned buffers: no allocation, no copying, no ownership transfer.
/// Flow buffering/reassembly/timers are implemented by HajimiFlowCXX; policy
/// and platform adapters remain separate. This layer handles packet arithmetic.
///
/// Byte order: all multi-byte header fields are returned in host order.
/// Addresses are left in network order, since they are only ever compared,
/// hashed or copied back out verbatim.

#ifndef HAJIMI_DATAPLANE_H
#define HAJIMI_DATAPLANE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Result codes shared by every parser in this header.
typedef enum {
    HAJIMI_PARSE_OK = 0,
    /// The buffer is shorter than the fixed header it claims to carry.
    HAJIMI_PARSE_TRUNCATED = -1,
    /// The header is self-inconsistent, e.g. an IHL below the 20 byte minimum.
    HAJIMI_PARSE_MALFORMED = -2,
    /// A well-formed header the data plane does not handle.
    HAJIMI_PARSE_UNSUPPORTED = -3
} hajimi_parse_result;

/// TCP flag bits, in the order they appear in the header's 14th byte.
typedef enum {
    HAJIMI_TCP_FIN = 0x01,
    HAJIMI_TCP_SYN = 0x02,
    HAJIMI_TCP_RST = 0x04,
    HAJIMI_TCP_PSH = 0x08,
    HAJIMI_TCP_ACK = 0x10,
    HAJIMI_TCP_URG = 0x20,
    HAJIMI_TCP_ECE = 0x40,
    HAJIMI_TCP_CWR = 0x80
} hajimi_tcp_flag;

// MARK: - Checksums

/// The unfolded one's-complement 16-bit sum of a region.
///
/// Accumulates big-endian 32-bit words into a 64-bit register, four per loop
/// iteration. This is exact for any realistic packet: it would take 2^32
/// additions to overflow the accumulator.
///
/// Returning the sum unfolded is what lets callers combine regions - a pseudo
/// header and a segment, say - without concatenating them into a scratch
/// buffer first.
///
/// A NULL `data` is valid when `length` is zero and sums to zero.
uint64_t hajimi_checksum_sum(const uint8_t *data, size_t length);

/// Folds an accumulated sum into the final one's-complement value.
uint16_t hajimi_checksum_fold(uint64_t value);

/// Convenience wrapper: sum a single region and fold it.
uint16_t hajimi_checksum(const uint8_t *data, size_t length);

/// Header checksum of an IPv4 header, skipping the checksum field itself.
///
/// The caller does not need to zero bytes 10 and 11 first. Both halves that
/// are summed stay 16-bit aligned, so skipping the field is exact.
uint16_t hajimi_ipv4_header_checksum(const uint8_t *header, size_t length);

/// TCP or UDP checksum, computed without materialising the pseudo header.
///
/// The pseudo header's contribution reduces to the sum of the two addresses
/// plus the protocol number plus the transport length, identically for IPv4
/// and IPv6, because both layouts are even-length and place those fields on
/// 16-bit boundaries.
///
/// `address_length` is 4 for IPv4 and 16 for IPv6.
uint16_t hajimi_transport_checksum(const uint8_t *source,
                                  const uint8_t *destination,
                                  size_t address_length,
                                  uint8_t protocol,
                                  const uint8_t *transport,
                                  size_t transport_length);

// MARK: - Parsing

/// A parsed IP header. Offsets are relative to the start of the buffer that
/// was parsed, so the payload is never copied out.
typedef struct {
    /// 4 or 6.
    uint8_t version;
    /// Next-header / protocol number, e.g. 6 for TCP.
    uint8_t protocol;
    /// 4 for IPv4, 16 for IPv6. The leading bytes of the address fields.
    uint8_t address_length;
    /// Network order. IPv4 addresses occupy the first four bytes.
    uint8_t source[16];
    uint8_t destination[16];
    uint32_t header_length;
    uint32_t payload_offset;
    uint32_t payload_length;
} hajimi_ip_packet;

/// Parses an IPv4 or IPv6 header.
///
/// IPv6 extension headers are not walked; `protocol` is the next-header value
/// of the fixed header, matching the Swift implementation this replaces.
int hajimi_parse_ip(const uint8_t *bytes, size_t length, hajimi_ip_packet *out);

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    /// Bitwise OR of `hajimi_tcp_flag` values.
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint32_t options_offset;
    uint32_t options_length;
    uint32_t payload_offset;
    uint32_t payload_length;
} hajimi_tcp_segment;

int hajimi_parse_tcp(const uint8_t *bytes, size_t length, hajimi_tcp_segment *out);

typedef struct { uint32_t start; uint32_t end; } hajimi_sack_block;
typedef struct {
    uint8_t has_window_scale;
    uint8_t window_scale;
    uint8_t sack_permitted;
    uint8_t sack_count;
    hajimi_sack_block sacks[4];
} hajimi_tcp_options;
int hajimi_parse_tcp_options(const uint8_t *bytes, size_t length, hajimi_tcp_options *out);

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t checksum;
    uint32_t payload_offset;
    uint32_t payload_length;
} hajimi_udp_datagram;

int hajimi_parse_udp(const uint8_t *bytes, size_t length, hajimi_udp_datagram *out);

// MARK: - Framing

/// Number of bytes `hajimi_write_frame_prefix` writes.
#define HAJIMI_FRAME_PREFIX_LENGTH 4

/// Writes the four byte address-family header a utun device expects ahead of
/// every packet.
///
/// Writing it into the same buffer as the packet is what allows a single
/// `write` with no concatenation; `out` must have room for four bytes.
size_t hajimi_write_frame_prefix(uint8_t *out, uint8_t version);

/// Builds a no-option IPv4/TCP or IPv6/TCP data segment into `out`.
///
/// Used on the download path: every ACK+PSH toward the client used to
/// allocate a Swift `Data`, append a dozen header fields, checksum, then
/// wrap an IPv4 header. This writes the finished packet in one pass.
///
/// `out_capacity` must be at least 20 + 20 + payload_length (IPv4) or
/// 40 + 20 + payload_length (IPv6). Returns the written length, or 0
/// when the packet would not fit or the addresses are the wrong size.
size_t hajimi_build_ipv4_tcp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[4], uint16_t source_port,
                            const uint8_t destination[4], uint16_t destination_port,
                            uint32_t sequence, uint32_t acknowledgment,
                            uint8_t flags, uint16_t window,
                            const uint8_t *payload, size_t payload_length,
                            uint16_t identifier);

size_t hajimi_build_ipv6_tcp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[16], uint16_t source_port,
                            const uint8_t destination[16], uint16_t destination_port,
                            uint32_t sequence, uint32_t acknowledgment,
                            uint8_t flags, uint16_t window,
                            const uint8_t *payload, size_t payload_length);

/// Same idea for a UDP datagram. Returns 0 when the payload cannot be
/// framed inside a 16-bit length field or `out` is too small.
size_t hajimi_build_ipv4_udp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[4], uint16_t source_port,
                            const uint8_t destination[4], uint16_t destination_port,
                            const uint8_t *payload, size_t payload_length,
                            uint16_t identifier);

size_t hajimi_build_ipv6_udp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[16], uint16_t source_port,
                            const uint8_t destination[16], uint16_t destination_port,
                            const uint8_t *payload, size_t payload_length);

// MARK: - Self test

/// Validates the primitives above against known-good vectors.
///
/// Returns 0 on success, or a small positive code identifying the first check
/// that failed. Intended to be called from the build's verification step so a
/// broken checksum can never reach a release.
int hajimi_dataplane_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* HAJIMI_DATAPLANE_H */
