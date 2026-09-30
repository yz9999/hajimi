#include "hajimi_dataplane.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

// MARK: - Checksums

uint64_t hajimi_checksum_sum(const uint8_t *data, size_t length) {
    if (data == NULL || length == 0) {
        return 0;
    }

    uint64_t sum = 0;
    size_t index = 0;

    // Sixteen bytes per iteration. `memcpy` of a fixed size compiles to a
    // plain unaligned load, so this stays correct on buffers that are not
    // word aligned - which packet payloads routinely are not.
    while (index + 16 <= length) {
        uint32_t w0, w1, w2, w3;
        memcpy(&w0, data + index, 4);
        memcpy(&w1, data + index + 4, 4);
        memcpy(&w2, data + index + 8, 4);
        memcpy(&w3, data + index + 12, 4);
        sum += (uint64_t)ntohl(w0) + (uint64_t)ntohl(w1)
             + (uint64_t)ntohl(w2) + (uint64_t)ntohl(w3);
        index += 16;
    }

    while (index + 4 <= length) {
        uint32_t word;
        memcpy(&word, data + index, 4);
        sum += (uint64_t)ntohl(word);
        index += 4;
    }

    if (index + 2 <= length) {
        uint16_t word;
        memcpy(&word, data + index, 2);
        sum += (uint64_t)ntohs(word);
        index += 2;
    }

    // An odd trailing byte is the high half of a notional final word.
    if (index < length) {
        sum += (uint64_t)data[index] << 8;
    }

    return sum;
}

uint16_t hajimi_checksum_fold(uint64_t value) {
    uint64_t sum = value;
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xffff);
}

uint16_t hajimi_checksum(const uint8_t *data, size_t length) {
    return hajimi_checksum_fold(hajimi_checksum_sum(data, length));
}

uint16_t hajimi_ipv4_header_checksum(const uint8_t *header, size_t length) {
    if (header == NULL || length < 12) {
        return 0;
    }
    // Bytes 0..9 and 12..end. Both runs are even-length and 16-bit aligned
    // relative to the header, so omitting the checksum field is exact.
    uint64_t sum = hajimi_checksum_sum(header, 10)
                 + hajimi_checksum_sum(header + 12, length - 12);
    return hajimi_checksum_fold(sum);
}

uint16_t hajimi_transport_checksum(const uint8_t *source,
                                  const uint8_t *destination,
                                  size_t address_length,
                                  uint8_t protocol,
                                  const uint8_t *transport,
                                  size_t transport_length) {
    uint64_t sum = hajimi_checksum_sum(source, address_length)
                 + hajimi_checksum_sum(destination, address_length)
                 + (uint64_t)protocol
                 + (uint64_t)transport_length
                 + hajimi_checksum_sum(transport, transport_length);
    return hajimi_checksum_fold(sum);
}

// MARK: - Parsing

int hajimi_parse_ip(const uint8_t *bytes, size_t length, hajimi_ip_packet *out) {
    if (bytes == NULL || out == NULL || length < 1) {
        return HAJIMI_PARSE_TRUNCATED;
    }

    const uint8_t version = bytes[0] >> 4;

    if (version == 4) {
        if (length < 20) {
            return HAJIMI_PARSE_TRUNCATED;
        }
        const size_t header_length = (size_t)(bytes[0] & 0x0f) * 4;
        if (header_length < 20 || header_length > length) {
            return HAJIMI_PARSE_MALFORMED;
        }

        uint16_t total;
        memcpy(&total, bytes + 2, 2);
        size_t total_length = ntohs(total);
        if (total_length < header_length) {
            return HAJIMI_PARSE_MALFORMED;
        }
        // Tolerate a frame padded beyond its declared length rather than
        // rejecting it; trusting the header over the buffer would let a
        // crafted packet read past the end.
        if (total_length > length) {
            total_length = length;
        }

        memset(out->source, 0, sizeof(out->source));
        memset(out->destination, 0, sizeof(out->destination));
        memcpy(out->source, bytes + 12, 4);
        memcpy(out->destination, bytes + 16, 4);

        out->version = 4;
        out->protocol = bytes[9];
        out->address_length = 4;
        out->header_length = (uint32_t)header_length;
        out->payload_offset = (uint32_t)header_length;
        out->payload_length = (uint32_t)(total_length - header_length);
        return HAJIMI_PARSE_OK;
    }

    if (version == 6) {
        if (length < 40) {
            return HAJIMI_PARSE_TRUNCATED;
        }

        uint16_t declared;
        memcpy(&declared, bytes + 4, 2);
        size_t payload_length = ntohs(declared);
        if (payload_length > length - 40) {
            payload_length = length - 40;
        }

        memcpy(out->source, bytes + 8, 16);
        memcpy(out->destination, bytes + 24, 16);

        out->version = 6;
        out->protocol = bytes[6];
        out->address_length = 16;
        out->header_length = 40;
        out->payload_offset = 40;
        out->payload_length = (uint32_t)payload_length;
        return HAJIMI_PARSE_OK;
    }

    return HAJIMI_PARSE_UNSUPPORTED;
}

int hajimi_parse_tcp(const uint8_t *bytes, size_t length, hajimi_tcp_segment *out) {
    if (bytes == NULL || out == NULL) {
        return HAJIMI_PARSE_TRUNCATED;
    }
    if (length < 20) {
        return HAJIMI_PARSE_TRUNCATED;
    }

    const size_t data_offset = (size_t)(bytes[12] >> 4) * 4;
    if (data_offset < 20 || data_offset > length) {
        return HAJIMI_PARSE_MALFORMED;
    }

    uint16_t source_port, destination_port, window, checksum, urgent;
    uint32_t sequence, acknowledgment;
    memcpy(&source_port, bytes, 2);
    memcpy(&destination_port, bytes + 2, 2);
    memcpy(&sequence, bytes + 4, 4);
    memcpy(&acknowledgment, bytes + 8, 4);
    memcpy(&window, bytes + 14, 2);
    memcpy(&checksum, bytes + 16, 2);
    memcpy(&urgent, bytes + 18, 2);

    out->source_port = ntohs(source_port);
    out->destination_port = ntohs(destination_port);
    out->sequence = ntohl(sequence);
    out->acknowledgment = ntohl(acknowledgment);
    out->flags = bytes[13];
    out->window = ntohs(window);
    out->checksum = ntohs(checksum);
    out->urgent_pointer = ntohs(urgent);
    out->options_offset = 20;
    out->options_length = (uint32_t)(data_offset - 20);
    out->payload_offset = (uint32_t)data_offset;
    out->payload_length = (uint32_t)(length - data_offset);
    return HAJIMI_PARSE_OK;
}

int hajimi_parse_tcp_options(const uint8_t *bytes, size_t length, hajimi_tcp_options *out) {
    if (out == NULL || (bytes == NULL && length != 0)) return HAJIMI_PARSE_TRUNCATED;
    if (length > 40) return HAJIMI_PARSE_MALFORMED;
    memset(out, 0, sizeof(*out));
    size_t cursor = 0;
    while (cursor < length) {
        const uint8_t kind = bytes[cursor];
        if (kind == 0) break;
        if (kind == 1) { ++cursor; continue; }
        if (cursor + 2 > length) return HAJIMI_PARSE_MALFORMED;
        const uint8_t n = bytes[cursor + 1];
        if (n < 2 || n > length - cursor) return HAJIMI_PARSE_MALFORMED;
        if (kind == 3) {
            if (n != 3) return HAJIMI_PARSE_MALFORMED;
            out->has_window_scale = 1;
            out->window_scale = bytes[cursor + 2] > 14 ? 14 : bytes[cursor + 2];
        } else if (kind == 4) {
            if (n != 2) return HAJIMI_PARSE_MALFORMED;
            out->sack_permitted = 1;
        } else if (kind == 5) {
            if (n < 10 || (n - 2) % 8 != 0) return HAJIMI_PARSE_MALFORMED;
            for (size_t i = 2; i + 8 <= n; i += 8) {
                uint32_t a, b;
                memcpy(&a, bytes + cursor + i, 4);
                memcpy(&b, bytes + cursor + i + 4, 4);
                if (out->sack_count < 4) {
                    out->sacks[out->sack_count++] = (hajimi_sack_block){ntohl(a), ntohl(b)};
                }
            }
        }
        cursor += n;
    }
    return HAJIMI_PARSE_OK;
}

int hajimi_parse_udp(const uint8_t *bytes, size_t length, hajimi_udp_datagram *out) {
    if (bytes == NULL || out == NULL) {
        return HAJIMI_PARSE_TRUNCATED;
    }
    if (length < 8) {
        return HAJIMI_PARSE_TRUNCATED;
    }

    uint16_t source_port, destination_port, declared, checksum;
    memcpy(&source_port, bytes, 2);
    memcpy(&destination_port, bytes + 2, 2);
    memcpy(&declared, bytes + 4, 2);
    memcpy(&checksum, bytes + 6, 2);

    size_t total_length = ntohs(declared);
    if (total_length < 8 || total_length > length) {
        total_length = length;
    }

    out->source_port = ntohs(source_port);
    out->destination_port = ntohs(destination_port);
    out->checksum = ntohs(checksum);
    out->payload_offset = 8;
    out->payload_length = (uint32_t)(total_length - 8);
    return HAJIMI_PARSE_OK;
}

// MARK: - Framing

size_t hajimi_write_frame_prefix(uint8_t *out, uint8_t version) {
    if (out == NULL) {
        return 0;
    }
    const uint32_t family = htonl(version == 6 ? (uint32_t)AF_INET6
                                               : (uint32_t)AF_INET);
    memcpy(out, &family, 4);
    return HAJIMI_FRAME_PREFIX_LENGTH;
}

static void write16(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)(value & 0xff);
}

static void write32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)(value & 0xff);
}

static void write_tcp_header(uint8_t *tcp, uint16_t source_port,
                             uint16_t destination_port, uint32_t sequence,
                             uint32_t acknowledgment, uint8_t flags,
                             uint16_t window) {
    write16(tcp, source_port);
    write16(tcp + 2, destination_port);
    write32(tcp + 4, sequence);
    write32(tcp + 8, acknowledgment);
    tcp[12] = 0x50;
    tcp[13] = flags;
    write16(tcp + 14, window);
    tcp[16] = 0;
    tcp[17] = 0;
    tcp[18] = 0;
    tcp[19] = 0;
}

size_t hajimi_build_ipv4_tcp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[4], uint16_t source_port,
                            const uint8_t destination[4], uint16_t destination_port,
                            uint32_t sequence, uint32_t acknowledgment,
                            uint8_t flags, uint16_t window,
                            const uint8_t *payload, size_t payload_length,
                            uint16_t identifier) {
    if (out == NULL || source == NULL || destination == NULL) {
        return 0;
    }
    if (payload_length > 0 && payload == NULL) {
        return 0;
    }
    const size_t total = 40 + payload_length;
    if (total > 0xffff || total > out_capacity) {
        return 0;
    }

    out[0] = 0x45;
    out[1] = 0;
    write16(out + 2, (uint16_t)total);
    write16(out + 4, identifier);
    write16(out + 6, 0x4000);
    out[8] = 64;
    out[9] = 6;
    out[10] = 0;
    out[11] = 0;
    memcpy(out + 12, source, 4);
    memcpy(out + 16, destination, 4);
    const uint16_t ip_sum = hajimi_ipv4_header_checksum(out, 20);
    write16(out + 10, ip_sum);

    uint8_t *tcp = out + 20;
    write_tcp_header(tcp, source_port, destination_port, sequence,
                     acknowledgment, flags, window);
    if (payload_length > 0) {
        memcpy(tcp + 20, payload, payload_length);
    }
    const uint16_t tcp_sum = hajimi_transport_checksum(source, destination, 4, 6,
                                                      tcp, 20 + payload_length);
    write16(tcp + 16, tcp_sum);
    return total;
}

size_t hajimi_build_ipv6_tcp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[16], uint16_t source_port,
                            const uint8_t destination[16], uint16_t destination_port,
                            uint32_t sequence, uint32_t acknowledgment,
                            uint8_t flags, uint16_t window,
                            const uint8_t *payload, size_t payload_length) {
    if (out == NULL || source == NULL || destination == NULL) {
        return 0;
    }
    if (payload_length > 0 && payload == NULL) {
        return 0;
    }
    if (payload_length > 0xffff || 60 + payload_length > out_capacity) {
        return 0;
    }

    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    write16(out + 4, (uint16_t)(20 + payload_length));
    out[6] = 6;
    out[7] = 64;
    memcpy(out + 8, source, 16);
    memcpy(out + 24, destination, 16);

    uint8_t *tcp = out + 40;
    write_tcp_header(tcp, source_port, destination_port, sequence,
                     acknowledgment, flags, window);
    if (payload_length > 0) {
        memcpy(tcp + 20, payload, payload_length);
    }
    const uint16_t tcp_sum = hajimi_transport_checksum(source, destination, 16, 6,
                                                      tcp, 20 + payload_length);
    write16(tcp + 16, tcp_sum);
    return 60 + payload_length;
}

size_t hajimi_build_ipv4_udp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[4], uint16_t source_port,
                            const uint8_t destination[4], uint16_t destination_port,
                            const uint8_t *payload, size_t payload_length,
                            uint16_t identifier) {
    if (out == NULL || source == NULL || destination == NULL) {
        return 0;
    }
    if (payload_length > 0 && payload == NULL) {
        return 0;
    }
    if (payload_length > 0xffff - 8) {
        return 0;
    }
    const size_t total = 28 + payload_length;
    if (total > 0xffff || total > out_capacity) {
        return 0;
    }

    out[0] = 0x45;
    out[1] = 0;
    write16(out + 2, (uint16_t)total);
    write16(out + 4, identifier);
    write16(out + 6, 0x4000);
    out[8] = 64;
    out[9] = 17;
    out[10] = 0;
    out[11] = 0;
    memcpy(out + 12, source, 4);
    memcpy(out + 16, destination, 4);
    write16(out + 10, hajimi_ipv4_header_checksum(out, 20));

    uint8_t *udp = out + 20;
    write16(udp, source_port);
    write16(udp + 2, destination_port);
    write16(udp + 4, (uint16_t)(8 + payload_length));
    udp[6] = 0;
    udp[7] = 0;
    if (payload_length > 0) {
        memcpy(udp + 8, payload, payload_length);
    }
    uint16_t checksum = hajimi_transport_checksum(source, destination, 4, 17,
                                                 udp, 8 + payload_length);
    if (checksum == 0) {
        checksum = 0xffff;
    }
    write16(udp + 6, checksum);
    return total;
}

size_t hajimi_build_ipv6_udp(uint8_t *out, size_t out_capacity,
                            const uint8_t source[16], uint16_t source_port,
                            const uint8_t destination[16], uint16_t destination_port,
                            const uint8_t *payload, size_t payload_length) {
    if (out == NULL || source == NULL || destination == NULL) {
        return 0;
    }
    if (payload_length > 0 && payload == NULL) {
        return 0;
    }
    if (payload_length > 0xffff - 8 || 48 + payload_length > out_capacity) {
        return 0;
    }

    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    write16(out + 4, (uint16_t)(8 + payload_length));
    out[6] = 17;
    out[7] = 64;
    memcpy(out + 8, source, 16);
    memcpy(out + 24, destination, 16);

    uint8_t *udp = out + 40;
    write16(udp, source_port);
    write16(udp + 2, destination_port);
    write16(udp + 4, (uint16_t)(8 + payload_length));
    udp[6] = 0;
    udp[7] = 0;
    if (payload_length > 0) {
        memcpy(udp + 8, payload, payload_length);
    }
    uint16_t checksum = hajimi_transport_checksum(source, destination, 16, 17,
                                                 udp, 8 + payload_length);
    if (checksum == 0) {
        checksum = 0xffff;
    }
    write16(udp + 6, checksum);
    return 48 + payload_length;
}

// MARK: - Self test

int hajimi_dataplane_self_test(void) {
    // The canonical IPv4 header worked example. Its correct checksum is
    // 0xb1e6; the field itself is left non-zero here to prove that
    // hajimi_ipv4_header_checksum really does skip it.
    static const uint8_t header[20] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xff, 0xff, 0xac, 0x10, 0x0a, 0x63,
        0xac, 0x10, 0x0a, 0x0c
    };

    if (hajimi_ipv4_header_checksum(header, sizeof(header)) != 0xb1e6) {
        return 1;
    }

    // Splitting a region and adding the partial sums must equal summing the
    // whole. This is the property that lets the transport checksum skip
    // building a pseudo-header buffer, so it is worth asserting directly.
    static const uint8_t sample[19] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78
    };
    const uint64_t whole = hajimi_checksum_sum(sample, sizeof(sample));
    const uint64_t split = hajimi_checksum_sum(sample, 10)
                         + hajimi_checksum_sum(sample + 10, sizeof(sample) - 10);
    if (hajimi_checksum_fold(whole) != hajimi_checksum_fold(split)) {
        return 2;
    }

    // An empty region must be neutral, including through a NULL pointer.
    if (hajimi_checksum_sum(NULL, 0) != 0) {
        return 3;
    }

    hajimi_ip_packet packet;
    if (hajimi_parse_ip(header, sizeof(header), &packet) != HAJIMI_PARSE_OK) {
        return 4;
    }
    if (packet.version != 4 || packet.protocol != 6
        || packet.header_length != 20 || packet.address_length != 4) {
        return 5;
    }
    // Total length is 0x3c = 60, so 40 bytes sit past the header - even
    // though this buffer is only 20 bytes long. The parser must clamp to what
    // is actually present rather than trusting the header.
    if (packet.payload_length != 0) {
        return 6;
    }
    if (packet.source[0] != 0xac || packet.source[3] != 0x63) {
        return 7;
    }

    // A truncated header must be rejected, not read past.
    if (hajimi_parse_ip(header, 12, &packet) != HAJIMI_PARSE_TRUNCATED) {
        return 8;
    }

    // A SYN with a 24 byte data offset: four bytes of options, no payload.
    static const uint8_t segment[24] = {
        0xc0, 0x00, 0x01, 0xbb, 0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x23, 0x00
    };
    hajimi_tcp_segment tcp;
    if (hajimi_parse_tcp(segment, sizeof(segment), &tcp) != HAJIMI_PARSE_OK) {
        return 9;
    }
    if (tcp.source_port != 0xc000 || tcp.destination_port != 443) {
        return 10;
    }
    if (tcp.sequence != 0x11223344 || tcp.acknowledgment != 0) {
        return 11;
    }
    if ((tcp.flags & HAJIMI_TCP_SYN) == 0 || (tcp.flags & HAJIMI_TCP_ACK) != 0) {
        return 12;
    }
    if (tcp.options_length != 4 || tcp.payload_length != 0) {
        return 13;
    }

    // A data offset below the 20 byte minimum is malformed.
    static const uint8_t bad_offset[20] = {
        0xc0, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x30, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00
    };
    if (hajimi_parse_tcp(bad_offset, sizeof(bad_offset), &tcp)
        != HAJIMI_PARSE_MALFORMED) {
        return 14;
    }

    static const uint8_t datagram[12] = {
        0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00,
        0xde, 0xad, 0xbe, 0xef
    };
    hajimi_udp_datagram udp;
    if (hajimi_parse_udp(datagram, sizeof(datagram), &udp) != HAJIMI_PARSE_OK) {
        return 15;
    }
    if (udp.source_port != 12345 || udp.destination_port != 53
        || udp.payload_length != 4) {
        return 16;
    }

    uint8_t prefix[4] = { 0, 0, 0, 0 };
    if (hajimi_write_frame_prefix(prefix, 4) != 4) {
        return 17;
    }
    if (prefix[0] != 0 || prefix[1] != 0 || prefix[2] != 0
        || prefix[3] != (uint8_t)AF_INET) {
        return 18;
    }
    if (hajimi_write_frame_prefix(prefix, 6) != 4
        || prefix[3] != (uint8_t)AF_INET6) {
        return 19;
    }

    static const uint8_t src4[4] = {1, 1, 1, 1};
    static const uint8_t dst4[4] = {198, 18, 0, 2};
    static const uint8_t body[5] = {'l', 'u', 'r', 'g', 'e'};
    uint8_t built[128];
    const size_t tcp_len = hajimi_build_ipv4_tcp(built, sizeof(built), src4, 443,
                                                dst4, 51000, 1, 2,
                                                HAJIMI_TCP_ACK | HAJIMI_TCP_PSH,
                                                65535, body, sizeof(body), 12);
    if (tcp_len != 45) {
        return 20;
    }
    if (built[0] != 0x45 || built[9] != 6 || built[33] != (HAJIMI_TCP_ACK | HAJIMI_TCP_PSH)) {
        return 21;
    }
    if (hajimi_checksum(built, 20) != 0) {
        return 22;
    }
    if (hajimi_transport_checksum(src4, dst4, 4, 6, built + 20, 25) != 0) {
        return 23;
    }
    if (memcmp(built + 40, body, sizeof(body)) != 0) {
        return 24;
    }

    const size_t udp_len = hajimi_build_ipv4_udp(built, sizeof(built), src4, 53,
                                                dst4, 50000, body, sizeof(body), 7);
    if (udp_len != 33) {
        return 25;
    }
    if (built[9] != 17) {
        return 26;
    }
    if (hajimi_checksum(built, 20) != 0) {
        return 27;
    }
    if (hajimi_transport_checksum(src4, dst4, 4, 17, built + 20, 13) != 0) {
        return 28;
    }

    static const uint8_t options[] = {1, 3, 3, 20, 4, 2, 5, 10, 0, 0, 0, 1, 0, 0, 0, 8};
    hajimi_tcp_options parsed_options;
    if (hajimi_parse_tcp_options(options, sizeof(options), &parsed_options) != HAJIMI_PARSE_OK ||
        !parsed_options.has_window_scale || parsed_options.window_scale != 14 ||
        !parsed_options.sack_permitted || parsed_options.sack_count != 1 ||
        parsed_options.sacks[0].start != 1 || parsed_options.sacks[0].end != 8) return 29;
    if (hajimi_parse_tcp_options(options, sizeof(options) - 1, &parsed_options) != HAJIMI_PARSE_MALFORMED) return 30;
    if (hajimi_parse_tcp_options(NULL, 0, &parsed_options) != HAJIMI_PARSE_OK) return 31;

    return 0;
}
