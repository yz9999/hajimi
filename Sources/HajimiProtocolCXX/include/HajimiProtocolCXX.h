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

#ifdef __cplusplus
}
#endif

#endif /* HAJIMI_PROTOCOL_CXX_H */
