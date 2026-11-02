#ifndef HAJIMI_PROTOCOL_CXX_H
#define HAJIMI_PROTOCOL_CXX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stateless wire codecs, not transport/TLS/QUIC or authentication engines.
 * All storage belongs to the caller; these functions never allocate, retain
 * pointers, throw exceptions, or perform network I/O. Output buffers must not
 * overlap an input span. A NULL output with capacity zero is a size query.
 * NULL input pointers are permitted only for zero-length spans.
 */
#define HAJIMI_CODEC_OK 0
#define HAJIMI_CODEC_NEED_MORE 1
#define HAJIMI_CODEC_OUTPUT_TOO_SMALL 2
#define HAJIMI_CODEC_INVALID -1
#define HAJIMI_CODEC_LIMIT -2
#define HAJIMI_CODEC_UNSUPPORTED -3

#define HAJIMI_CODEC_MAX_HTTP_HEADER 65536u
#define HAJIMI_CODEC_MAX_HTTP_LINE 8192u
#define HAJIMI_CODEC_MAX_HTTP_FIELDS 128u
#define HAJIMI_CODEC_MAX_HOST 255u
#define HAJIMI_CODEC_MAX_DATAGRAM 65535u

/* On OK: consumed is the parsed prefix (not trailing application bytes),
 * written is the encoded size. On NEED_MORE: consumed/written are zero and
 * needed is the minimum TOTAL input size needed for another attempt. On
 * OUTPUT_TOO_SMALL: needed is the exact output capacity, nothing is written.
 * On other errors all sizes are zero. Out-parameters change only on OK.
 */
typedef struct hajimi_codec_result {
    int32_t status;
    size_t consumed;
    size_t needed;
    size_t written;
} hajimi_codec_result;

#define HAJIMI_ADDRESS_IPV4 1
#define HAJIMI_ADDRESS_DOMAIN 3
#define HAJIMI_ADDRESS_IPV6 4
#define HAJIMI_ADDRESS_NONE 255

typedef struct hajimi_address {
    uint8_t host[HAJIMI_CODEC_MAX_HOST + 1u]; /* NUL-terminated, no IPv6 brackets. */
    size_t host_length;
    uint16_t port;                         /* Host byte order; SOCKS permits 0. */
    uint8_t type;                         /* HAJIMI_ADDRESS_* (SOCKS tags). */
    uint8_t reserved;
} hajimi_address;

/* Copies and validates UTF-8 host bytes, classifying numeric IP literals.
 * IPv6 brackets are accepted and removed. Zone IDs are deliberately rejected
 * because none of these proxy address formats carries a scope identifier.
 */
hajimi_codec_result hajimi_address_from_host(const uint8_t *host,
                                             size_t host_length, uint16_t port,
                                             hajimi_address *address);
const char *hajimi_codec_status_string(int32_t status);

#define HAJIMI_HTTP_TARGET_ORIGIN 0
#define HAJIMI_HTTP_TARGET_ABSOLUTE 1
#define HAJIMI_HTTP_TARGET_AUTHORITY 2
#define HAJIMI_HTTP_TARGET_ASTERISK 3

typedef struct hajimi_http_request {
    hajimi_address target;
    size_t header_length;                 /* Includes the final CRLF CRLF. */
    size_t method_offset;
    size_t method_length;
    size_t target_offset;
    size_t target_length;
    size_t version_offset;
    size_t version_length;
    size_t path_offset;                   /* Absolute URI suffix, or origin target. */
    size_t path_length;                   /* 0 means use "/"; "?q" means "/?q". */
    uint8_t is_connect;
    uint8_t is_https;
    uint8_t target_form;
    uint8_t reserved;
} hajimi_http_request;

/* Incremental: pass the accumulated prefix again after NEED_MORE. 0 selects
 * the hard header limit; a nonzero header_limit may only lower that limit.
 * Supports HTTP/1.0 and HTTP/1.1 CONNECT authority, http(s) absolute URI,
 * origin form and OPTIONS *. Rejects ambiguous Host/framing, obs-fold,
 * malformed ports/IPv6, userinfo/fragments, and invalid header syntax.
 * CONNECT requires an explicit nonzero port. HTTP Host uses ASCII/IDNA names.
 */
hajimi_codec_result hajimi_http_parse_request(const uint8_t *input,
                                             size_t input_length,
                                             size_t header_limit,
                                             hajimi_http_request *request);

/* Rewrites a NON-CONNECT request for an origin (absolute_form=0) or HTTP
 * upstream proxy (absolute_form=1). Produces one canonical Host, strips
 * Proxy-Authorization/Proxy-Connection/Connection and Connection-nominated
 * fields, adds Connection: close, and preserves every body byte verbatim.
 * An optional validated upstream authorization VALUE (e.g. "Basic ...") is
 * emitted only in absolute form. No credentials from input are forwarded.
 * CONNECT returns UNSUPPORTED: its header must not enter a tunnel's payload.
 */
hajimi_codec_result hajimi_http_rewrite_request(
    const uint8_t *input, size_t input_length, size_t header_limit,
    int32_t absolute_form, const uint8_t *proxy_authorization,
    size_t proxy_authorization_length, uint8_t *output, size_t output_capacity,
    hajimi_http_request *request);

/* SOCKS5 greeting selects no-auth (0) if offered, otherwise 0xff. The caller
 * still owns access/authentication policy and sends the method-selection reply.
 */
hajimi_codec_result hajimi_socks5_parse_greeting(const uint8_t *input,
                                                size_t input_length,
                                                uint8_t *selected_method);
hajimi_codec_result hajimi_socks5_parse_address(const uint8_t *input,
                                               size_t input_length,
                                               hajimi_address *address);
hajimi_codec_result hajimi_socks5_encode_address(const hajimi_address *address,
                                                uint8_t *output,
                                                size_t output_capacity);
/* Commands 1 (CONNECT), 2 (BIND), 3 (UDP ASSOCIATE) are wire-valid. The
 * server's supported-command policy must be enforced separately. RSV must be 0.
 */
hajimi_codec_result hajimi_socks5_parse_request(const uint8_t *input,
                                               size_t input_length,
                                               uint8_t *command,
                                               hajimi_address *address);
hajimi_codec_result hajimi_socks5_encode_request(uint8_t command,
                                                const hajimi_address *address,
                                                uint8_t *output,
                                                size_t output_capacity);

typedef struct hajimi_udp_frame {
    hajimi_address target;
    size_t payload_offset;
    size_t payload_length;
    uint32_t session_id;                  /* HY1/HY2 session or TUIC association. */
    uint16_t packet_id;
    uint8_t fragment_index;
    uint8_t fragment_count;
    uint8_t has_address;
    uint8_t reserved;
} hajimi_udp_frame;

/* SOCKS FRAG != 0 returns UNSUPPORTED; no silent fragment forwarding. */
hajimi_codec_result hajimi_socks5_parse_udp(const uint8_t *input,
                                           size_t input_length,
                                           hajimi_udp_frame *frame);
hajimi_codec_result hajimi_socks5_encode_udp(const hajimi_address *address,
                                            const uint8_t *payload,
                                            size_t payload_length,
                                            uint8_t *output,
                                            size_t output_capacity);

/* VLESS v0, commands TCP=1 / UDP=2 / Mux=3. UUID is 16 raw network-order
 * bytes, addons are already-encoded protobuf bytes (at most 255). Mux has NO
 * destination or port, and permits address=NULL. This is not a Vision encoder.
 */
hajimi_codec_result hajimi_vless_encode_request(
    const uint8_t uuid[16], const uint8_t *addons, size_t addons_length,
    uint8_t command, const hajimi_address *address, uint8_t *output,
    size_t output_capacity);

/* Trojan: caller provides 56 hexadecimal SHA-224 password digest characters;
 * the codec validates/normalizes hex and adds CRLF + command + SOCKS address
 * + CRLF. TCP=1 / UDP ASSOCIATE=3; no hashing or TLS is performed here.
 */
hajimi_codec_result hajimi_trojan_encode_request(
    const uint8_t sha224_hex[56], uint8_t command,
    const hajimi_address *address, uint8_t *output, size_t output_capacity);
hajimi_codec_result hajimi_trojan_parse_udp(const uint8_t *input,
                                          size_t input_length,
                                          hajimi_udp_frame *frame);
hajimi_codec_result hajimi_trojan_encode_udp(const hajimi_address *address,
                                           const uint8_t *payload,
                                           size_t payload_length,
                                           uint8_t *output,
                                           size_t output_capacity);

/* RFC 9000 section 16, range 0...2^62-1; decoder accepts legal non-minimal
 * encodings as required by QUIC. No frame-type minimal-encoding policy here.
 */
hajimi_codec_result hajimi_quic_varint_decode(const uint8_t *input,
                                             size_t input_length,
                                             uint64_t *value);
hajimi_codec_result hajimi_quic_varint_encode(uint64_t value, uint8_t *output,
                                             size_t output_capacity);

/* Hysteria v1 wire headers, not QUIC, congestion control, or auth validation. */
hajimi_codec_result hajimi_hysteria1_encode_hello(
    uint64_t upload_bytes_per_second, uint64_t download_bytes_per_second,
    const uint8_t *auth, size_t auth_length, uint8_t *output,
    size_t output_capacity);
hajimi_codec_result hajimi_hysteria1_encode_request(
    int32_t udp, const hajimi_address *address, uint8_t *output,
    size_t output_capacity);
hajimi_codec_result hajimi_hysteria1_parse_udp(const uint8_t *input,
                                             size_t input_length,
                                             hajimi_udp_frame *frame);
hajimi_codec_result hajimi_hysteria1_encode_udp(
    uint32_t session_id, uint16_t packet_id, uint8_t fragment_index,
    uint8_t fragment_count, const hajimi_address *address,
    const uint8_t *payload, size_t payload_length, uint8_t *output,
    size_t output_capacity);

/* Hysteria2 TCPRequest=0x401. Padding <=4096, response message <=2048.
 * UDP functions encode/decode a single fragment; reassembly belongs to caller.
 */
hajimi_codec_result hajimi_hysteria2_encode_request(
    const hajimi_address *address, const uint8_t *padding, size_t padding_length,
    uint8_t *output, size_t output_capacity);
hajimi_codec_result hajimi_hysteria2_parse_response(
    const uint8_t *input, size_t input_length, uint8_t *status,
    size_t *message_offset, size_t *message_length);
hajimi_codec_result hajimi_hysteria2_parse_udp(const uint8_t *input,
                                             size_t input_length,
                                             hajimi_udp_frame *frame);
hajimi_codec_result hajimi_hysteria2_encode_udp(
    uint32_t session_id, uint16_t packet_id, uint8_t fragment_index,
    uint8_t fragment_count, const hajimi_address *address,
    const uint8_t *payload, size_t payload_length, uint8_t *output,
    size_t output_capacity);

/* TUIC v5 uses its OWN address tags: domain=0, IPv4=1, IPv6=2, none=0xff.
 * Token in Authenticate is 32 TLS-exporter bytes computed by the transport.
 * Packet fragments may omit address only when fragment_index != 0.
 */
hajimi_codec_result hajimi_tuic5_parse_address(const uint8_t *input,
                                             size_t input_length,
                                             hajimi_address *address);
hajimi_codec_result hajimi_tuic5_encode_address(const hajimi_address *address,
                                              uint8_t *output,
                                              size_t output_capacity);
hajimi_codec_result hajimi_tuic5_encode_authenticate(
    const uint8_t uuid[16], const uint8_t token[32], uint8_t *output,
    size_t output_capacity);
hajimi_codec_result hajimi_tuic5_encode_connect(const hajimi_address *address,
                                              uint8_t *output,
                                              size_t output_capacity);
hajimi_codec_result hajimi_tuic5_parse_udp(const uint8_t *input,
                                         size_t input_length,
                                         hajimi_udp_frame *frame);
hajimi_codec_result hajimi_tuic5_encode_udp(
    uint16_t association_id, uint16_t packet_id, uint8_t fragment_index,
    uint8_t fragment_count, const hajimi_address *address,
    const uint8_t *payload, size_t payload_length, uint8_t *output,
    size_t output_capacity);

/* WebSocket RFC 6455 wire framing and 64-bit word-strided XOR masking. */
void hajimi_ws_xor_mask(uint8_t *bytes, size_t length, const uint8_t mask[4]);
hajimi_codec_result hajimi_ws_encode_frame(
    uint8_t fin, uint8_t opcode, int32_t masked, const uint8_t mask[4],
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity);

/* Mux.Cool and XUDP wire framing (VMess/VLESS address layout). */
hajimi_codec_result hajimi_mux_encode_frame(
    uint16_t id, uint8_t status, uint8_t options, uint8_t network,
    const hajimi_address *address, const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity);
hajimi_codec_result hajimi_xudp_encode_frame(
    int32_t first_packet, const uint8_t global_id[8],
    const hajimi_address *address, const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity);

/* mKCP FNV-1a 32-bit digest and 64-bit word-strided SimpleAuthenticator XOR. */
uint32_t hajimi_mkcp_fnv1a(const uint8_t *data, size_t length);
hajimi_codec_result hajimi_mkcp_seal_simple(
    const uint8_t *plain, size_t plain_length,
    uint8_t *output, size_t output_capacity);
hajimi_codec_result hajimi_mkcp_open_simple(
    const uint8_t *cipher, size_t cipher_length,
    uint8_t *output, size_t output_capacity);

/* Fake-IP DNS wire question parser & zero-allocation DNS reply synthesizer. */
typedef struct hajimi_fakeip_question {
    uint8_t host[HAJIMI_CODEC_MAX_HOST + 1u]; /* Lowercased, NUL-terminated. */
    size_t host_length;
    size_t question_end;
    uint16_t qtype;
    uint16_t qclass;
} hajimi_fakeip_question;

hajimi_codec_result hajimi_fakeip_parse_question(
    const uint8_t *packet, size_t length, hajimi_fakeip_question *out);
hajimi_codec_result hajimi_fakeip_build_reply(
    const uint8_t *packet, size_t length,
    const hajimi_fakeip_question *question,
    int32_t has_ipv4, const uint8_t ipv4[4], uint32_t ttl,
    uint8_t *output, size_t output_capacity);

/* Zero-allocation windowed traffic rate meter & compact rate formatter. */
typedef struct hajimi_rate_meter {
    double aggregation_window;
    uint64_t previous;
    uint64_t accumulated;
    double window_start;
    double current_bps;
    uint8_t has_previous;
} hajimi_rate_meter;

void hajimi_rate_meter_init(hajimi_rate_meter *meter, double aggregation_window);
void hajimi_rate_meter_observe(hajimi_rate_meter *meter,
                               uint64_t cumulative_bytes,
                               double timestamp_seconds);
void hajimi_rate_meter_idle(hajimi_rate_meter *meter, double timestamp_seconds);
void hajimi_rate_meter_reset(hajimi_rate_meter *meter);
size_t hajimi_rate_format_compact(double bytes_per_second, char *out, size_t capacity);

/* Stafford Mix13 GF(2^64) bijective finalizer & Google Jump Consistent Hash. */
uint64_t hajimi_stafford_mix64(uint64_t z);
uint32_t hajimi_jump_consistent_hash(uint64_t key, uint32_t num_buckets);

/* Multi-factor Smart Node Scorer:
 * - Welford-West Exponentially Weighted Moving Average & Variance (EWMA/EWMVar)
 * - Cornish-Fisher 90th-percentile tail latency (mu + 1.28155 * sigma)
 * - Empirical Bayes Beta-Binomial conjugate posterior with exponential decay
 * - Mathis-Semke-Mahdavi TCP loss penalty (cost proportional to p_hat^-2)
 */
typedef struct hajimi_smart_node_stats {
    double ewma_rtt;
    double ewm_var;
    double success_weight;
    double failure_weight;
    double last_timestamp;
    uint32_t sample_count;
    uint8_t initialized;
} hajimi_smart_node_stats;

void hajimi_smart_stats_init(hajimi_smart_node_stats *stats);
void hajimi_smart_stats_observe(hajimi_smart_node_stats *stats,
                                int32_t success,
                                double latency_seconds,
                                double timestamp_seconds);
double hajimi_smart_stats_cost(const hajimi_smart_node_stats *stats,
                               double now_seconds);

/* Constant-time byte comparison immune to timing side-channel oracles.
 * Returns 1 if (a, a_len) and (b, b_len) are byte-for-byte identical, 0 otherwise.
 */
int32_t hajimi_constant_time_memcmp(const uint8_t *a, size_t a_len,
                                    const uint8_t *b, size_t b_len);

/* ============================================================================
 * Frontier Encrypted DNS Wire Codecs & Adaptive UCB1 Scorer
 * - RFC 9250 (DNS over Dedicated QUIC Connections, §4.2 & §4.2.1):
 *   2-octet length framing + mandatory Message ID = 0x0000 normalization.
 * - RFC 7830 / RFC 8467 (EDNS(0) Block-Length Padding, Option Code 12):
 *   128-byte query / 468-byte response block alignment against traffic analysis.
 * - RFC 7871 (EDNS Client Subnet Privacy Sanitization, Option Code 8):
 *   Strip, anonymize (/0 opt-out), or truncate (/24 IPv4, /56 IPv6) client prefixes.
 * - Multi-Armed Bandit UCB1 + Welford-West EWMA + Cornish-Fisher Tail Scorer.
 * ============================================================================ */

#define HAJIMI_ECS_MODE_STRIP 0
#define HAJIMI_ECS_MODE_ANONYMIZE_ZERO 1
#define HAJIMI_ECS_MODE_TRUNCATE_PRIVACY 2

/* Encodes a DNS wire message [12..65535] into an RFC 9250 DoQ stream frame:
 * prepends 2-byte big-endian length and sets the wire DNS ID to 0x0000 per
 * RFC 9250 §4.2.1. Stores the original client transaction ID in *original_id_out
 * (if non-NULL) so the caller can restore it upon response reception.
 */
hajimi_codec_result hajimi_dns_doq_encode_frame(
    const uint8_t *dns_message, size_t message_length,
    uint16_t *original_id_out,
    uint8_t *output, size_t output_capacity);

/* Decodes an RFC 9250 DoQ stream frame: verifies the 2-byte big-endian length
 * prefix, extracts the DNS payload [12..65535], requires the wire response ID
 * to be 0x0000 (RFC 9250 §4.2.1), and restores expected_client_id into output[0..1].
 */
hajimi_codec_result hajimi_dns_doq_decode_frame(
    const uint8_t *frame_input, size_t frame_length,
    uint16_t expected_client_id,
    uint8_t *output, size_t output_capacity);

/* Applies RFC 7830 / RFC 8467 Block-Length Padding (EDNS0 Option Code 12) to a
 * DNS message so its total wire length is a multiple of block_size (e.g. 128 for
 * queries, 468 for responses), bounded by max_payload (e.g. 1232 or 4096).
 * If ARCOUNT == 0, appends a root OPT RR (Type 41, UDP payload 1232, flags 0).
 * If ARCOUNT == 1 with an uncompressed root OPT RR at the tail, appends or
 * extends Option Code 12 with zero octets.
 */
hajimi_codec_result hajimi_dns_apply_edns_padding(
    const uint8_t *dns_message, size_t message_length,
    uint16_t block_size, uint16_t max_payload,
    uint8_t *output, size_t output_capacity);

/* Sanitizes EDNS0 Client Subnet (ECS, Option Code 8, RFC 7871) in a DNS query
 * to prevent client IP subnet leakage over encrypted or proxied DNS paths:
 * - mode 0 (HAJIMI_ECS_MODE_STRIP): removes Option 8 from the root OPT record.
 * - mode 1 (HAJIMI_ECS_MODE_ANONYMIZE_ZERO): sets SOURCE/SCOPE prefix-length to 0.
 * - mode 2 (HAJIMI_ECS_MODE_TRUNCATE_PRIVACY): clamps IPv4 prefix <= 24 and
 *   IPv6 prefix <= 56, zeroing all trailing bits.
 */
hajimi_codec_result hajimi_dns_sanitize_ecs(
    const uint8_t *dns_message, size_t message_length,
    int32_t mode,
    uint8_t *output, size_t output_capacity);

/* Computes the Multi-Armed Bandit UCB1 + Cornish-Fisher 95th-percentile tail
 * latency + Beta-Binomial failure penalty score (lower is better) for adaptive
 * DNS upstream selection.
 */
double hajimi_dns_ucb1_score(
    double ewma_ms, double ewm_var_ms2,
    double success_weight, double failure_weight,
    uint64_t total_scope_queries, uint64_t candidate_samples,
    int32_t has_reusable_connection);

/* ============================================================================
 * IETF MASQUE (RFC 9298 Proxying UDP in HTTP & RFC 9297 HTTP/3 Datagrams/Capsules)
 * - HTTP/3 Datagram format: Quarter-Stream-ID (varint, stream_id / 4) +
 *   Context-ID (varint, 0x00 for UDP payload) + UDP Proxying Payload.
 * - HTTP Capsule format: Capsule-Type (varint, 0x00 = DATAGRAM) +
 *   Capsule-Length (varint) + Context-ID (varint, 0x00) + UDP Payload.
 * ============================================================================ */
hajimi_codec_result hajimi_masque_encode_datagram(
    uint64_t stream_id,
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity);

hajimi_codec_result hajimi_masque_decode_datagram(
    const uint8_t *input, size_t input_length,
    uint64_t *stream_id_out,
    size_t *payload_offset_out,
    size_t *payload_length_out);

hajimi_codec_result hajimi_masque_encode_capsule(
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity);

hajimi_codec_result hajimi_masque_decode_capsule(
    const uint8_t *input, size_t input_length,
    size_t *payload_offset_out,
    size_t *payload_length_out);

#ifdef __cplusplus
}
#endif

#endif /* HAJIMI_PROTOCOL_CXX_H */
