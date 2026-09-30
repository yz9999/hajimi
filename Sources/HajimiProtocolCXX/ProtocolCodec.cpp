#include "HajimiProtocolCXX.h"

#include <arpa/inet.h>
#include <cstring>
#include <limits>

namespace {

hajimi_codec_result error(int32_t status) noexcept { return {status, 0, 0, 0}; }
hajimi_codec_result more(size_t needed) noexcept {
    return {HAJIMI_CODEC_NEED_MORE, 0, needed, 0};
}
hajimi_codec_result small(size_t needed) noexcept {
    return {HAJIMI_CODEC_OUTPUT_TOO_SMALL, 0, needed, 0};
}
hajimi_codec_result ok(size_t consumed = 0, size_t written = 0) noexcept {
    return {HAJIMI_CODEC_OK, consumed, 0, written};
}
bool span(const void *p, size_t n) noexcept { return p != nullptr || n == 0; }
bool add(size_t a, size_t b, size_t &sum) noexcept {
    if (b > std::numeric_limits<size_t>::max() - a) { return false; }
    sum = a + b; return true;
}
bool overlaps(const void *a, size_t an, const void *b, size_t bn) noexcept {
    if (an == 0 || bn == 0 || a == nullptr || b == nullptr) { return false; }
    const uintptr_t x = reinterpret_cast<uintptr_t>(a);
    const uintptr_t y = reinterpret_cast<uintptr_t>(b);
    return x <= y ? y - x < an : x - y < bn;
}
hajimi_codec_result outputReady(uint8_t *p, size_t capacity, size_t needed) noexcept {
    if (!span(p, capacity)) { return error(HAJIMI_CODEC_INVALID); }
    return capacity < needed ? small(needed) : ok();
}
uint8_t lower(uint8_t c) noexcept {
    return c >= 'A' && c <= 'Z' ? static_cast<uint8_t>(c + 32) : c;
}
bool equal(const uint8_t *p, size_t n, const char *s) noexcept {
    const size_t length = std::strlen(s);
    if (n != length) { return false; }
    for (size_t i = 0; i < n; ++i) {
        if (lower(p[i]) != static_cast<uint8_t>(s[i])) { return false; }
    }
    return true;
}
bool token(uint8_t c) noexcept {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) { return true; }
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default: return false;
    }
}
bool utf8(const uint8_t *p, size_t n) noexcept {
    size_t i = 0;
    while (i < n) {
        const uint8_t first = p[i++];
        if (first < 0x80) { continue; }
        size_t count; uint32_t value; uint32_t minimum;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1; value = first & 0x1f; minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2; value = first & 0x0f; minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3; value = first & 0x07; minimum = 0x10000;
        } else { return false; }
        if (count > n - i) { return false; }
        for (size_t j = 0; j < count; ++j) {
            const uint8_t c = p[i++];
            if ((c & 0xc0) != 0x80) { return false; }
            value = (value << 6) | (c & 0x3f);
        }
        if (value < minimum || value > 0x10ffff ||
            (value >= 0xd800 && value <= 0xdfff)) { return false; }
    }
    return true;
}
bool domain(const uint8_t *p, size_t n, bool asciiOnly = false) noexcept {
    if (n == 0 || n > HAJIMI_CODEC_MAX_HOST || !utf8(p, n)) { return false; }
    for (size_t i = 0; i < n; ++i) {
        const uint8_t c = p[i];
        if (c >= 0x80) { if (asciiOnly) { return false; } continue; }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) {
            return false;
        }
    }
    return true;
}
hajimi_codec_result makeAddress(const uint8_t *host, size_t length,
                               uint16_t port, hajimi_address &address) noexcept {
    if (!span(host, length) || length == 0) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_HOST + 2u) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t inputLength = length;
    const bool bracketed = host[0] == '[';
    if (bracketed) {
        if (length < 3 || host[length - 1] != ']') { return error(HAJIMI_CODEC_INVALID); }
        ++host; length -= 2;
    }
    if (length > HAJIMI_CODEC_MAX_HOST) { return error(HAJIMI_CODEC_LIMIT); }
    char text[HAJIMI_CODEC_MAX_HOST + 1u];
    std::memcpy(text, host, length); text[length] = 0;
    for (size_t i = 0; i < length; ++i) {
        /* Darwin inet_pton accepts and drops IPv6 zone suffixes. Proxy wire
         * address formats cannot represent that scope, so reject explicitly. */
        if (host[i] == 0 || host[i] == '%') { return error(HAJIMI_CODEC_INVALID); }
    }
    uint8_t binary[16]; uint8_t kind = HAJIMI_ADDRESS_DOMAIN;
    if (inet_pton(AF_INET, text, binary) == 1) { kind = HAJIMI_ADDRESS_IPV4; }
    else if (inet_pton(AF_INET6, text, binary) == 1) { kind = HAJIMI_ADDRESS_IPV6; }
    else if (!domain(host, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (bracketed && kind != HAJIMI_ADDRESS_IPV6) { return error(HAJIMI_CODEC_INVALID); }
    hajimi_address value{}; value.port = port; value.type = kind;
    if (kind == HAJIMI_ADDRESS_DOMAIN) {
        std::memcpy(value.host, host, length); value.host_length = length;
    } else {
        if (inet_ntop(kind == HAJIMI_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                      binary, reinterpret_cast<char *>(value.host),
                      sizeof(value.host)) == nullptr) { return error(HAJIMI_CODEC_INVALID); }
        value.host_length = std::strlen(reinterpret_cast<const char *>(value.host));
    }
    address = value; return ok(inputLength);
}
struct PreparedAddress { hajimi_address address; uint8_t binary[16]; };
hajimi_codec_result prepare(const hajimi_address *input, PreparedAddress &value,
                           bool zeroPort = true) noexcept {
    if (input == nullptr || input->host_length > HAJIMI_CODEC_MAX_HOST ||
        (!zeroPort && input->port == 0)) { return error(HAJIMI_CODEC_INVALID); }
    if (input->type == HAJIMI_ADDRESS_DOMAIN) {
        if (!domain(input->host, input->host_length)) { return error(HAJIMI_CODEC_INVALID); }
        value.address = {}; value.address.type = HAJIMI_ADDRESS_DOMAIN; value.address.port = input->port;
        value.address.host_length = input->host_length;
        std::memcpy(value.address.host, input->host, input->host_length); return ok();
    }
    const auto result = makeAddress(input->host, input->host_length, input->port, value.address);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (input->type != value.address.type) { return error(HAJIMI_CODEC_INVALID); }
    if (value.address.type != HAJIMI_ADDRESS_DOMAIN &&
        inet_pton(value.address.type == HAJIMI_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  reinterpret_cast<const char *>(value.address.host), value.binary) != 1) {
        return error(HAJIMI_CODEC_INVALID);
    }
    return ok();
}
struct Writer {
    uint8_t *p; size_t size = 0; bool valid = true;
    void bytes(const void *source, size_t n) noexcept {
        size_t next;
        if (!valid || !add(size, n, next)) { valid = false; return; }
        if (p != nullptr && n != 0) { std::memcpy(p + size, source, n); }
        size = next;
    }
    void byte(uint8_t c) noexcept { bytes(&c, 1); }
    void literal(const char *s) noexcept { bytes(s, std::strlen(s)); }
    void be(uint64_t v, size_t n) noexcept {
        for (size_t i = n; i > 0; --i) { byte(static_cast<uint8_t>(v >> ((i - 1) * 8))); }
    }
};
uint16_t read16(const uint8_t *p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
uint32_t read32(const uint8_t *p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

} // namespace

extern "C" const char *hajimi_codec_status_string(int32_t status) {
    switch (status) {
    case HAJIMI_CODEC_OK: return "ok";
    case HAJIMI_CODEC_NEED_MORE: return "truncated input";
    case HAJIMI_CODEC_OUTPUT_TOO_SMALL: return "output buffer too small";
    case HAJIMI_CODEC_INVALID: return "malformed protocol input";
    case HAJIMI_CODEC_LIMIT: return "protocol size limit exceeded";
    case HAJIMI_CODEC_UNSUPPORTED: return "unsupported protocol form";
    default: return "unknown codec status";
    }
}
extern "C" hajimi_codec_result hajimi_address_from_host(
    const uint8_t *host, size_t length, uint16_t port, hajimi_address *address) {
    if (address == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    hajimi_address value{};
    const auto result = makeAddress(host, length, port, value);
    if (result.status == HAJIMI_CODEC_OK) { *address = value; }
    return result;
}

namespace {

bool parsePort(const uint8_t *p, size_t n, uint16_t &port) noexcept {
    if (n == 0 || n > 5) { return false; }
    uint32_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] < '0' || p[i] > '9') { return false; }
        value = value * 10 + static_cast<uint32_t>(p[i] - '0');
    }
    if (value == 0 || value > 65535) { return false; }
    port = static_cast<uint16_t>(value); return true;
}
hajimi_codec_result authority(const uint8_t *p, size_t n, uint16_t defaultPort,
                              bool requirePort, hajimi_address &address) noexcept {
    if (n == 0) { return error(HAJIMI_CODEC_INVALID); }
    size_t hostStart = 0, hostLength = n, portStart = n;
    const bool bracketed = p[0] == '[';
    if (bracketed) {
        size_t closing = 1;
        while (closing < n && p[closing] != ']') { ++closing; }
        if (closing == n || closing == 1) { return error(HAJIMI_CODEC_INVALID); }
        hostStart = 1; hostLength = closing - 1;
        if (closing + 1 < n) {
            if (p[closing + 1] != ':') { return error(HAJIMI_CODEC_INVALID); }
            portStart = closing + 2;
        }
    } else {
        for (size_t i = 0; i < n; ++i) {
            if (p[i] == ':') {
                if (portStart != n) { return error(HAJIMI_CODEC_INVALID); }
                hostLength = i; portStart = i + 1;
            }
        }
    }
    const bool explicitPort = bracketed ? (hostLength + 2 < n) : (hostLength < n);
    uint16_t port = defaultPort;
    if (explicitPort) {
        if (!parsePort(p + portStart, n - portStart, port)) { return error(HAJIMI_CODEC_INVALID); }
    } else if (requirePort) { return error(HAJIMI_CODEC_INVALID); }
    for (size_t i = 0; i < hostLength; ++i) {
        if (p[hostStart + i] >= 0x80) { return error(HAJIMI_CODEC_INVALID); }
    }
    auto result = makeAddress(p + hostStart, hostLength, port, address);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (bracketed != (address.type == HAJIMI_ADDRESS_IPV6)) { return error(HAJIMI_CODEC_INVALID); }
    return ok();
}
size_t authorityText(const hajimi_address &address, uint8_t *output) noexcept {
    Writer w{output};
    if (address.type == HAJIMI_ADDRESS_IPV6) { w.byte('['); }
    w.bytes(address.host, address.host_length);
    if (address.type == HAJIMI_ADDRESS_IPV6) { w.byte(']'); }
    w.byte(':');
    uint8_t digits[5]; size_t count = 0; uint16_t port = address.port;
    do { digits[count++] = static_cast<uint8_t>('0' + port % 10); port /= 10; } while (port != 0);
    while (count > 0) { w.byte(digits[--count]); }
    return w.size;
}
struct HTTPField {
    size_t offset, length, nameLength, valueOffset, valueLength;
};
struct ParsedHTTP {
    hajimi_http_request request{};
    HTTPField fields[HAJIMI_CODEC_MAX_HTTP_FIELDS];
    size_t count = 0;
};
size_t lineEnd(const uint8_t *p, size_t offset, size_t end) noexcept {
    while (offset + 1 < end && !(p[offset] == '\r' && p[offset + 1] == '\n')) { ++offset; }
    return offset;
}
hajimi_codec_result headerEnd(const uint8_t *p, size_t n, size_t limit,
                              size_t &end) noexcept {
    if (!span(p, n) || limit > HAJIMI_CODEC_MAX_HTTP_HEADER) { return error(HAJIMI_CODEC_INVALID); }
    if (limit == 0) { limit = HAJIMI_CODEC_MAX_HTTP_HEADER; }
    const size_t length = n < limit ? n : limit;
    size_t offset = 0, lineLength = 0, lines = 0;
    while (offset < length) {
        const uint8_t c = p[offset];
        if (c == '\r') {
            if (offset + 1 == length) { break; }
            if (p[offset + 1] != '\n') { return error(HAJIMI_CODEC_INVALID); }
            if (lineLength == 0) {
                if (lines == 0) { return error(HAJIMI_CODEC_INVALID); }
                end = offset + 2; return ok(end);
            }
            ++lines;
            if (lines > HAJIMI_CODEC_MAX_HTTP_FIELDS + 1u) { return error(HAJIMI_CODEC_LIMIT); }
            lineLength = 0; offset += 2; continue;
        }
        if (c == '\n' || c == 0x7f || (c < 0x20 && c != '\t')) {
            return error(HAJIMI_CODEC_INVALID);
        }
        ++offset; ++lineLength;
        if (lineLength > HAJIMI_CODEC_MAX_HTTP_LINE) { return error(HAJIMI_CODEC_LIMIT); }
    }
    return n >= limit ? error(HAJIMI_CODEC_LIMIT) : more(n + 1);
}
bool contentLength(const uint8_t *p, size_t n) noexcept {
    if (n == 0) { return false; }
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] < '0' || p[i] > '9') { return false; }
        const uint8_t digit = p[i] - '0';
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10) { return false; }
        value = value * 10 + digit;
    }
    return true;
}
/* RFC comma-separated tokens. Connection may not nominate message framing. */
bool tokenList(const uint8_t *p, size_t n, bool transferEncoding) noexcept {
    size_t offset = 0; bool sawChunked = false;
    if (n == 0) { return false; }
    while (offset < n) {
        while (offset < n && (p[offset] == ' ' || p[offset] == '\t')) { ++offset; }
        const size_t start = offset;
        while (offset < n && token(p[offset])) { ++offset; }
        if (start == offset) { return false; }
        if (transferEncoding) {
            if (sawChunked) { return false; }
            sawChunked = equal(p + start, offset - start, "chunked");
        } else if (equal(p + start, offset - start, "host") ||
                   equal(p + start, offset - start, "content-length") ||
                   equal(p + start, offset - start, "transfer-encoding")) { return false; }
        while (offset < n && (p[offset] == ' ' || p[offset] == '\t')) { ++offset; }
        if (offset == n) { return !transferEncoding || sawChunked; }
        if (p[offset++] != ',' || offset == n) { return false; }
    }
    return false;
}

hajimi_codec_result parseHTTP(const uint8_t *p, size_t n, size_t limit,
                              ParsedHTTP &parsed) noexcept {
    size_t end = 0;
    auto result = headerEnd(p, n, limit, end);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t firstEnd = lineEnd(p, 0, end);
    size_t firstSpace = 0;
    while (firstSpace < firstEnd && p[firstSpace] != ' ') {
        if (!token(p[firstSpace])) { return error(HAJIMI_CODEC_INVALID); }
        ++firstSpace;
    }
    if (firstSpace == 0 || firstSpace > 32 || firstSpace == firstEnd) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const size_t targetStart = firstSpace + 1;
    size_t secondSpace = targetStart;
    while (secondSpace < firstEnd && p[secondSpace] != ' ') {
        if (p[secondSpace] < 0x21 || p[secondSpace] > 0x7e || p[secondSpace] == '#') {
            return error(HAJIMI_CODEC_INVALID);
        }
        ++secondSpace;
    }
    if (secondSpace == targetStart || secondSpace == firstEnd) { return error(HAJIMI_CODEC_INVALID); }
    const size_t versionStart = secondSpace + 1;
    const size_t versionLength = firstEnd - versionStart;
    const bool http10 = versionLength == 8 && std::memcmp(p + versionStart, "HTTP/1.0", 8) == 0;
    const bool http11 = versionLength == 8 && std::memcmp(p + versionStart, "HTTP/1.1", 8) == 0;
    if (!http10 && !http11) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    auto &request = parsed.request;
    request.header_length = end;
    request.method_offset = 0; request.method_length = firstSpace;
    request.target_offset = targetStart; request.target_length = secondSpace - targetStart;
    request.version_offset = versionStart; request.version_length = versionLength;
    request.is_connect = equal(p, firstSpace, "connect") ? 1 : 0;
    size_t hostIndex = HAJIMI_CODEC_MAX_HTTP_FIELDS;
    bool hasLength = false, hasEncoding = false;
    size_t offset = firstEnd + 2;
    while (offset < end - 2) {
        const size_t fieldEnd = lineEnd(p, offset, end);
        if (parsed.count == HAJIMI_CODEC_MAX_HTTP_FIELDS) { return error(HAJIMI_CODEC_LIMIT); }
        size_t colon = offset;
        while (colon < fieldEnd && p[colon] != ':') {
            if (!token(p[colon])) { return error(HAJIMI_CODEC_INVALID); }
            ++colon;
        }
        if (colon == offset || colon == fieldEnd) { return error(HAJIMI_CODEC_INVALID); }
        size_t valueStart = colon + 1, valueEnd = fieldEnd;
        while (valueStart < valueEnd && (p[valueStart] == ' ' || p[valueStart] == '\t')) { ++valueStart; }
        while (valueEnd > valueStart && (p[valueEnd - 1] == ' ' || p[valueEnd - 1] == '\t')) { --valueEnd; }
        HTTPField field{offset, fieldEnd + 2 - offset, colon - offset,
                        valueStart, valueEnd - valueStart};
        const auto *name = p + offset;
        if (equal(name, field.nameLength, "host")) {
            if (hostIndex != HAJIMI_CODEC_MAX_HTTP_FIELDS || field.valueLength == 0) {
                return error(HAJIMI_CODEC_INVALID);
            }
            hostIndex = parsed.count;
        } else if (equal(name, field.nameLength, "content-length")) {
            if (hasLength || !contentLength(p + valueStart, field.valueLength)) { return error(HAJIMI_CODEC_INVALID); }
            hasLength = true;
        } else if (equal(name, field.nameLength, "transfer-encoding")) {
            if (hasEncoding || http10 || !tokenList(p + valueStart, field.valueLength, true)) {
                return error(HAJIMI_CODEC_INVALID);
            }
            hasEncoding = true;
        } else if (equal(name, field.nameLength, "connection")) {
            if (!tokenList(p + valueStart, field.valueLength, false)) { return error(HAJIMI_CODEC_INVALID); }
        }
        parsed.fields[parsed.count++] = field; offset = fieldEnd + 2;
    }
    if (hasLength && hasEncoding) { return error(HAJIMI_CODEC_INVALID); }
    const uint8_t *raw = p + targetStart;
    const size_t rawLength = request.target_length;
    uint16_t defaultPort = 80;
    if (request.is_connect) {
        request.target_form = HAJIMI_HTTP_TARGET_AUTHORITY; request.is_https = 1;
        result = authority(raw, rawLength, 443, true, request.target);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
        defaultPort = request.target.port;
    } else if ((rawLength >= 7 && equal(raw, 7, "http://")) ||
               (rawLength >= 8 && equal(raw, 8, "https://"))) {
        request.target_form = HAJIMI_HTTP_TARGET_ABSOLUTE;
        request.is_https = rawLength >= 8 && equal(raw, 8, "https://") ? 1 : 0;
        const size_t authorityStart = request.is_https ? 8 : 7;
        defaultPort = request.is_https ? 443 : 80;
        size_t authorityEnd = authorityStart;
        while (authorityEnd < rawLength && raw[authorityEnd] != '/' && raw[authorityEnd] != '?') { ++authorityEnd; }
        result = authority(raw + authorityStart, authorityEnd - authorityStart,
                           defaultPort, false, request.target);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
        request.path_offset = targetStart + authorityEnd;
        request.path_length = rawLength - authorityEnd;
    } else if (raw[0] == '/') {
        request.target_form = HAJIMI_HTTP_TARGET_ORIGIN;
        request.path_offset = targetStart; request.path_length = rawLength;
    } else if (rawLength == 1 && raw[0] == '*' && equal(p, firstSpace, "options")) {
        request.target_form = HAJIMI_HTTP_TARGET_ASTERISK;
        request.path_offset = targetStart; request.path_length = 1;
    } else { return error(HAJIMI_CODEC_UNSUPPORTED); }
    if (hostIndex != HAJIMI_CODEC_MAX_HTTP_FIELDS) {
        const HTTPField &host = parsed.fields[hostIndex]; hajimi_address hostAddress{};
        result = authority(p + host.valueOffset, host.valueLength, defaultPort, false, hostAddress);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
        if (request.target_form == HAJIMI_HTTP_TARGET_ORIGIN ||
            request.target_form == HAJIMI_HTTP_TARGET_ASTERISK) { request.target = hostAddress; }
    } else if (request.target_form == HAJIMI_HTTP_TARGET_ORIGIN ||
               request.target_form == HAJIMI_HTTP_TARGET_ASTERISK) { return error(HAJIMI_CODEC_INVALID); }
    return ok(end);
}
bool connectionNominates(const uint8_t *p, const ParsedHTTP &parsed,
                         const HTTPField &candidate) noexcept {
    for (size_t i = 0; i < parsed.count; ++i) {
        const HTTPField &field = parsed.fields[i];
        if (!equal(p + field.offset, field.nameLength, "connection")) { continue; }
        size_t offset = field.valueOffset, end = offset + field.valueLength;
        while (offset < end) {
            while (offset < end && (p[offset] == ' ' || p[offset] == '\t' || p[offset] == ',')) { ++offset; }
            const size_t start = offset;
            while (offset < end && token(p[offset])) { ++offset; }
            const size_t length = offset - start;
            if (length == candidate.nameLength) {
                bool same = true;
                for (size_t j = 0; j < length; ++j) {
                    if (lower(p[start + j]) != lower(p[candidate.offset + j])) { same = false; break; }
                }
                if (same) { return true; }
            }
        }
    }
    return false;
}
void rewriteHTTP(Writer &w, const uint8_t *p, size_t n, const ParsedHTTP &parsed,
                 bool absolute, const uint8_t *auth, size_t authLength) noexcept {
    const auto &r = parsed.request;
    uint8_t host[HAJIMI_CODEC_MAX_HOST + 9u]; const size_t hostLength = authorityText(r.target, host);
    w.bytes(p + r.method_offset, r.method_length); w.byte(' ');
    if (r.target_form == HAJIMI_HTTP_TARGET_ASTERISK) { w.byte('*'); }
    else if (absolute && r.target_form == HAJIMI_HTTP_TARGET_ABSOLUTE) { w.bytes(p + r.target_offset, r.target_length); }
    else {
        if (absolute) { w.literal(r.is_https ? "https://" : "http://"); w.bytes(host, hostLength); }
        if (r.path_length == 0 || p[r.path_offset] == '?') { w.byte('/'); }
        if (r.path_length != 0) { w.bytes(p + r.path_offset, r.path_length); }
    }
    w.byte(' '); w.bytes(p + r.version_offset, r.version_length); w.literal("\r\nHost: ");
    w.bytes(host, hostLength); w.literal("\r\n");
    for (size_t i = 0; i < parsed.count; ++i) {
        const auto &f = parsed.fields[i]; const auto *name = p + f.offset;
        if (equal(name, f.nameLength, "host") || equal(name, f.nameLength, "proxy-authorization") ||
            equal(name, f.nameLength, "proxy-connection") || equal(name, f.nameLength, "connection") ||
            equal(name, f.nameLength, "keep-alive") || equal(name, f.nameLength, "te") ||
            equal(name, f.nameLength, "upgrade") || connectionNominates(p, parsed, f)) { continue; }
        w.bytes(p + f.offset, f.length);
    }
    if (absolute && authLength != 0) { w.literal("Proxy-Authorization: "); w.bytes(auth, authLength); w.literal("\r\n"); }
    w.literal("Connection: close\r\n\r\n");
    if (n != r.header_length) { w.bytes(p + r.header_length, n - r.header_length); }
}

} // namespace

extern "C" hajimi_codec_result hajimi_http_parse_request(
    const uint8_t *input, size_t length, size_t limit, hajimi_http_request *request) {
    if (request == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    ParsedHTTP parsed{}; const auto result = parseHTTP(input, length, limit, parsed);
    if (result.status == HAJIMI_CODEC_OK) { *request = parsed.request; }
    return result;
}
extern "C" hajimi_codec_result hajimi_http_rewrite_request(
    const uint8_t *input, size_t length, size_t limit, int32_t absolute,
    const uint8_t *auth, size_t authLength, uint8_t *output, size_t capacity,
    hajimi_http_request *request) {
    if ((absolute != 0 && absolute != 1) || !span(auth, authLength) || authLength > 4096) {
        return error(HAJIMI_CODEC_INVALID);
    }
    for (size_t i = 0; i < authLength; ++i) {
        if (auth[i] < 0x20 || auth[i] > 0x7e) { return error(HAJIMI_CODEC_INVALID); }
    }
    ParsedHTTP parsed{}; const auto result = parseHTTP(input, length, limit, parsed);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (parsed.request.is_connect) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    Writer measure{nullptr}; rewriteHTTP(measure, input, length, parsed, absolute != 0, auth, authLength);
    if (!measure.valid) { return error(HAJIMI_CODEC_LIMIT); }
    const auto ready = outputReady(output, capacity, measure.size);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, measure.size, input, length) || overlaps(output, measure.size, auth, authLength)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer writer{output}; rewriteHTTP(writer, input, length, parsed, absolute != 0, auth, authLength);
    if (request != nullptr) { *request = parsed.request; }
    return ok(parsed.request.header_length, writer.size);
}

namespace {

enum class AddressFormat { socks, vmess, tuic };
size_t addressSize(const PreparedAddress &p, AddressFormat format) noexcept {
    const size_t hostSize = p.address.type == HAJIMI_ADDRESS_DOMAIN ? 1 + p.address.host_length :
                            p.address.type == HAJIMI_ADDRESS_IPV4 ? 4 : 16;
    return 1 + hostSize + (format == AddressFormat::vmess ? 0 : 2);
}
void writeAddress(Writer &w, const PreparedAddress &p, AddressFormat format) noexcept {
    uint8_t tag = p.address.type;
    if (format == AddressFormat::vmess) {
        tag = tag == HAJIMI_ADDRESS_DOMAIN ? 2 : tag == HAJIMI_ADDRESS_IPV6 ? 3 : 1;
    } else if (format == AddressFormat::tuic) {
        tag = tag == HAJIMI_ADDRESS_DOMAIN ? 0 : tag == HAJIMI_ADDRESS_IPV6 ? 2 : 1;
    }
    w.byte(tag);
    if (p.address.type == HAJIMI_ADDRESS_DOMAIN) {
        w.byte(static_cast<uint8_t>(p.address.host_length)); w.bytes(p.address.host, p.address.host_length);
    } else { w.bytes(p.binary, p.address.type == HAJIMI_ADDRESS_IPV4 ? 4 : 16); }
    if (format != AddressFormat::vmess) { w.be(p.address.port, 2); }
}
hajimi_codec_result parseAddress(const uint8_t *p, size_t n, bool tuic,
                                 hajimi_address &address) noexcept {
    if (!span(p, n)) { return error(HAJIMI_CODEC_INVALID); }
    if (n == 0) { return more(1); }
    hajimi_address value{};
    if (tuic && p[0] == 0xff) { value.type = HAJIMI_ADDRESS_NONE; address = value; return ok(1); }
    uint8_t kind = p[0];
    if (tuic) {
        if (kind == 0) { kind = HAJIMI_ADDRESS_DOMAIN; }
        else if (kind == 2) { kind = HAJIMI_ADDRESS_IPV6; }
        else if (kind != 1) { return error(HAJIMI_CODEC_INVALID); }
    }
    size_t hostStart = 1, hostLength;
    if (kind == HAJIMI_ADDRESS_DOMAIN) {
        if (n < 2) { return more(2); }
        hostLength = p[1]; hostStart = 2;
        if (hostLength == 0) { return error(HAJIMI_CODEC_INVALID); }
    } else if (kind == HAJIMI_ADDRESS_IPV4) { hostLength = 4; }
    else if (kind == HAJIMI_ADDRESS_IPV6) { hostLength = 16; }
    else { return error(HAJIMI_CODEC_INVALID); }
    const size_t required = hostStart + hostLength + 2;
    if (n < required) { return more(required); }
    value.type = kind; value.port = read16(p + hostStart + hostLength);
    if (kind == HAJIMI_ADDRESS_DOMAIN) {
        if (!domain(p + hostStart, hostLength)) { return error(HAJIMI_CODEC_INVALID); }
        std::memcpy(value.host, p + hostStart, hostLength); value.host_length = hostLength;
    } else {
        if (inet_ntop(kind == HAJIMI_ADDRESS_IPV4 ? AF_INET : AF_INET6, p + hostStart,
                      reinterpret_cast<char *>(value.host), sizeof(value.host)) == nullptr) {
            return error(HAJIMI_CODEC_INVALID);
        }
        value.host_length = std::strlen(reinterpret_cast<const char *>(value.host));
    }
    address = value; return ok(required);
}
hajimi_codec_result encodeAddress(const hajimi_address *address, AddressFormat format,
                                  uint8_t *output, size_t capacity) noexcept {
    PreparedAddress prepared{}; auto result = prepare(address, prepared);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = addressSize(prepared, format);
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address))) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; writeAddress(w, prepared, format); return ok(0, w.size);
}

} // namespace

extern "C" hajimi_codec_result hajimi_socks5_parse_address(
    const uint8_t *input, size_t length, hajimi_address *address) {
    if (address == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    hajimi_address parsed{}; const auto result = parseAddress(input, length, false, parsed);
    if (result.status == HAJIMI_CODEC_OK) { *address = parsed; }
    return result;
}
extern "C" hajimi_codec_result hajimi_socks5_encode_address(
    const hajimi_address *address, uint8_t *output, size_t capacity) {
    return encodeAddress(address, AddressFormat::socks, output, capacity);
}
extern "C" hajimi_codec_result hajimi_socks5_parse_udp(
    const uint8_t *input, size_t length, hajimi_udp_frame *frame) {
    if (frame == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if ((length > 0 && input[0] != 0) || (length > 1 && input[1] != 0)) { return error(HAJIMI_CODEC_INVALID); }
    if (length < 3) { return more(3); }
    if (input[2] != 0) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    hajimi_udp_frame parsed{};
    auto result = parseAddress(input + 3, length - 3, false, parsed.target);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(result.needed + 3); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    parsed.payload_offset = 3 + result.consumed; parsed.payload_length = length - parsed.payload_offset;
    parsed.fragment_count = 1; parsed.has_address = 1;
    *frame = parsed; return ok(length);
}
extern "C" hajimi_codec_result hajimi_socks5_encode_udp(
    const hajimi_address *address, const uint8_t *payload, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(payload, length)) { return error(HAJIMI_CODEC_INVALID); }
    PreparedAddress prepared{}; auto result = prepare(address, prepared);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    size_t required;
    if (!add(3 + addressSize(prepared, AddressFormat::socks), length, required) ||
        required > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address)) || overlaps(output, required, payload, length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output}; w.be(0, 3); writeAddress(w, prepared, AddressFormat::socks); w.bytes(payload, length);
    return ok(0, w.size);
}

extern "C" hajimi_codec_result hajimi_socks5_parse_greeting(
    const uint8_t *input, size_t length, uint8_t *selected) {
    if (selected == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 0 && input[0] != 5) { return error(HAJIMI_CODEC_INVALID); }
    if (length < 2) { return more(2); }
    if (input[1] == 0) { return error(HAJIMI_CODEC_INVALID); }
    const size_t required = 2 + static_cast<size_t>(input[1]);
    if (length < required) { return more(required); }
    uint8_t method = 0xff;
    for (size_t i = 2; i < required; ++i) { if (input[i] == 0) { method = 0; break; } }
    *selected = method; return ok(required);
}
extern "C" hajimi_codec_result hajimi_socks5_parse_request(
    const uint8_t *input, size_t length, uint8_t *command, hajimi_address *address) {
    if (command == nullptr || address == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 0 && input[0] != 5) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 1 && (input[1] < 1 || input[1] > 3)) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    if (length > 2 && input[2] != 0) { return error(HAJIMI_CODEC_INVALID); }
    if (length < 3) { return more(4); }
    hajimi_address parsed{};
    auto result = parseAddress(input + 3, length - 3, false, parsed);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(result.needed + 3); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    *command = input[1]; *address = parsed; return ok(3 + result.consumed);
}
extern "C" hajimi_codec_result hajimi_socks5_encode_request(
    uint8_t command, const hajimi_address *address, uint8_t *output, size_t capacity) {
    if (command < 1 || command > 3) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    PreparedAddress prepared{}; auto result = prepare(address, prepared);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = 3 + addressSize(prepared, AddressFormat::socks);
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address))) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; w.byte(5); w.byte(command); w.byte(0); writeAddress(w, prepared, AddressFormat::socks);
    return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_vless_encode_request(
    const uint8_t uuid[16], const uint8_t *addons, size_t addonsLength,
    uint8_t command, const hajimi_address *address, uint8_t *output, size_t capacity) {
    if (uuid == nullptr || !span(addons, addonsLength)) { return error(HAJIMI_CODEC_INVALID); }
    if (addonsLength > 255) { return error(HAJIMI_CODEC_LIMIT); }
    if (command < 1 || command > 3) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    PreparedAddress prepared{}; size_t required = 19 + addonsLength;
    if (command != 3) {
        const auto result = prepare(address, prepared, false);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
        required += 2 + addressSize(prepared, AddressFormat::vmess);
    }
    const auto ready = outputReady(output, capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, uuid, 16) || overlaps(output, required, addons, addonsLength) ||
        (command != 3 && overlaps(output, required, address, sizeof(*address)))) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output}; w.byte(0); w.bytes(uuid, 16); w.byte(static_cast<uint8_t>(addonsLength));
    w.bytes(addons, addonsLength); w.byte(command);
    if (command != 3) { w.be(prepared.address.port, 2); writeAddress(w, prepared, AddressFormat::vmess); }
    return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_trojan_encode_request(
    const uint8_t digest[56], uint8_t command, const hajimi_address *address,
    uint8_t *output, size_t capacity) {
    if (digest == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    if (command != 1 && command != 3) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    for (size_t i = 0; i < 56; ++i) {
        const uint8_t c = lower(digest[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { return error(HAJIMI_CODEC_INVALID); }
    }
    PreparedAddress prepared{}; auto result = prepare(address, prepared, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = 61 + addressSize(prepared, AddressFormat::socks);
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, digest, 56) || overlaps(output, required, address, sizeof(*address))) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output}; for (size_t i = 0; i < 56; ++i) { w.byte(lower(digest[i])); }
    w.literal("\r\n"); w.byte(command); writeAddress(w, prepared, AddressFormat::socks); w.literal("\r\n");
    return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_trojan_parse_udp(
    const uint8_t *input, size_t length, hajimi_udp_frame *frame) {
    if (frame == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    hajimi_udp_frame parsed{}; auto result = parseAddress(input, length, false, parsed.target);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t offset = result.consumed;
    if (length < offset + 4) { return more(offset + 4); }
    if (input[offset + 2] != '\r' || input[offset + 3] != '\n') { return error(HAJIMI_CODEC_INVALID); }
    parsed.payload_offset = offset + 4; parsed.payload_length = read16(input + offset);
    if (length < parsed.payload_offset + parsed.payload_length) { return more(parsed.payload_offset + parsed.payload_length); }
    parsed.fragment_count = 1; parsed.has_address = 1; *frame = parsed;
    return ok(parsed.payload_offset + parsed.payload_length);
}
extern "C" hajimi_codec_result hajimi_trojan_encode_udp(
    const hajimi_address *address, const uint8_t *payload, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(payload, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 65535) { return error(HAJIMI_CODEC_LIMIT); }
    PreparedAddress prepared{}; auto result = prepare(address, prepared, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = addressSize(prepared, AddressFormat::socks) + 4 + length;
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address)) || overlaps(output, required, payload, length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output}; writeAddress(w, prepared, AddressFormat::socks); w.be(length, 2); w.literal("\r\n");
    w.bytes(payload, length); return ok(0, w.size);
}

namespace {

constexpr uint64_t quicMaximum = (uint64_t{1} << 62) - 1;
size_t varintSize(uint64_t value) noexcept {
    return value < 64 ? 1 : value < 16384 ? 2 : value < 1073741824 ? 4 : 8;
}
void writeVarint(Writer &w, uint64_t value) noexcept {
    const size_t length = varintSize(value);
    const uint8_t marker = length == 1 ? 0 : length == 2 ? 0x40 : length == 4 ? 0x80 : 0xc0;
    w.byte(static_cast<uint8_t>(marker | (value >> ((length - 1) * 8))));
    if (length != 1) { w.be(value, length - 1); }
}
bool fragments(uint8_t index, uint8_t count) noexcept { return count != 0 && index < count; }
hajimi_codec_result datagramOutput(uint8_t *output, size_t capacity, size_t required,
                                   const hajimi_address *address, const uint8_t *payload,
                                   size_t length) noexcept {
    if (required > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    const auto result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if ((address != nullptr && overlaps(output, required, address, sizeof(*address))) ||
        overlaps(output, required, payload, length)) { return error(HAJIMI_CODEC_INVALID); }
    return ok();
}

} // namespace

extern "C" hajimi_codec_result hajimi_quic_varint_decode(
    const uint8_t *input, size_t length, uint64_t *value) {
    if (value == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length == 0) { return more(1); }
    const size_t required = size_t{1} << (input[0] >> 6);
    if (length < required) { return more(required); }
    uint64_t result = input[0] & 0x3f;
    for (size_t i = 1; i < required; ++i) { result = (result << 8) | input[i]; }
    *value = result; return ok(required);
}
extern "C" hajimi_codec_result hajimi_quic_varint_encode(
    uint64_t value, uint8_t *output, size_t capacity) {
    if (value > quicMaximum) { return error(HAJIMI_CODEC_LIMIT); }
    const auto ready = outputReady(output, capacity, varintSize(value));
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    Writer w{output}; writeVarint(w, value); return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_hysteria1_encode_hello(
    uint64_t upload, uint64_t download, const uint8_t *auth, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(auth, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 65535) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t required = 19 + length;
    const auto ready = outputReady(output, capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, auth, length)) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; w.byte(3); w.be(upload, 8); w.be(download, 8); w.be(length, 2); w.bytes(auth, length);
    return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_hysteria1_encode_request(
    int32_t udp, const hajimi_address *address, uint8_t *output, size_t capacity) {
    if (udp != 0 && udp != 1) { return error(HAJIMI_CODEC_INVALID); }
    PreparedAddress prepared{};
    if (!udp) {
        const auto result = prepare(address, prepared, false);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
    }
    const size_t hostLength = udp ? 0 : prepared.address.host_length;
    const size_t required = 5 + hostLength;
    const auto ready = outputReady(output, capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (!udp && overlaps(output, required, address, sizeof(*address))) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; w.byte(static_cast<uint8_t>(udp)); w.be(hostLength, 2);
    w.bytes(prepared.address.host, hostLength); w.be(udp ? 0 : prepared.address.port, 2);
    return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_hysteria1_parse_udp(
    const uint8_t *input, size_t length, hajimi_udp_frame *frame) {
    if (frame == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if (length < 6) { return more(6); }
    const size_t hostLength = read16(input + 4);
    if (hostLength > HAJIMI_CODEC_MAX_HOST) { return error(HAJIMI_CODEC_LIMIT); }
    if (hostLength == 0) { return error(HAJIMI_CODEC_INVALID); }
    const size_t headerLength = 14 + hostLength;
    if (length < headerLength) { return more(headerLength); }
    hajimi_udp_frame parsed{};
    auto result = makeAddress(input + 6, hostLength, read16(input + 6 + hostLength), parsed.target);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    parsed.session_id = read32(input); parsed.packet_id = read16(input + 8 + hostLength);
    parsed.fragment_index = input[10 + hostLength]; parsed.fragment_count = input[11 + hostLength];
    if (!fragments(parsed.fragment_index, parsed.fragment_count)) { return error(HAJIMI_CODEC_INVALID); }
    parsed.payload_offset = headerLength; parsed.payload_length = read16(input + 12 + hostLength);
    const size_t required = headerLength + parsed.payload_length;
    if (required > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if (length < required) { return more(required); }
    if (length != required) { return error(HAJIMI_CODEC_INVALID); }
    parsed.has_address = 1; *frame = parsed; return ok(required);
}
extern "C" hajimi_codec_result hajimi_hysteria1_encode_udp(
    uint32_t session, uint16_t packet, uint8_t index, uint8_t count,
    const hajimi_address *address, const uint8_t *payload, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(payload, length) || !fragments(index, count)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 65535) { return error(HAJIMI_CODEC_LIMIT); }
    PreparedAddress p{}; auto result = prepare(address, p, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = 14 + p.address.host_length + length;
    result = datagramOutput(output, capacity, required, address, payload, length);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    Writer w{output}; w.be(session, 4); w.be(p.address.host_length, 2); w.bytes(p.address.host, p.address.host_length);
    w.be(p.address.port, 2); w.be(packet, 2); w.byte(index); w.byte(count); w.be(length, 2); w.bytes(payload, length);
    return ok(0, w.size);
}

extern "C" hajimi_codec_result hajimi_hysteria2_encode_request(
    const hajimi_address *address, const uint8_t *padding, size_t paddingLength,
    uint8_t *output, size_t capacity) {
    if (!span(padding, paddingLength)) { return error(HAJIMI_CODEC_INVALID); }
    if (paddingLength > 4096) { return error(HAJIMI_CODEC_LIMIT); }
    PreparedAddress prepared{}; auto result = prepare(address, prepared, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    uint8_t host[HAJIMI_CODEC_MAX_HOST + 9u]; const size_t hostLength = authorityText(prepared.address, host);
    const size_t required = 2 + varintSize(hostLength) + hostLength + varintSize(paddingLength) + paddingLength;
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address)) || overlaps(output, required, padding, paddingLength)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output}; writeVarint(w, 0x401); writeVarint(w, hostLength); w.bytes(host, hostLength);
    writeVarint(w, paddingLength); w.bytes(padding, paddingLength); return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_hysteria2_parse_response(
    const uint8_t *input, size_t length, uint8_t *status, size_t *messageOffset,
    size_t *messageLength) {
    if (status == nullptr || messageOffset == nullptr || messageLength == nullptr ||
        !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length == 0) { return more(1); }
    uint64_t count = 0; auto result = hajimi_quic_varint_decode(input + 1, length - 1, &count);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(1 + result.needed); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (count > 2048) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t start = 1 + result.consumed, end = start + static_cast<size_t>(count);
    if (length < end) { return more(end); }
    uint64_t padding = 0; result = hajimi_quic_varint_decode(input + end, length - end, &padding);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(end + result.needed); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (padding > 4096) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t required = end + result.consumed + static_cast<size_t>(padding);
    if (length < required) { return more(required); }
    *status = input[0]; *messageOffset = start; *messageLength = static_cast<size_t>(count);
    return ok(required);
}
extern "C" hajimi_codec_result hajimi_hysteria2_parse_udp(
    const uint8_t *input, size_t length, hajimi_udp_frame *frame) {
    if (frame == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if (length < 8) { return more(9); }
    hajimi_udp_frame parsed{};
    parsed.fragment_index = input[6]; parsed.fragment_count = input[7];
    if (!fragments(parsed.fragment_index, parsed.fragment_count)) { return error(HAJIMI_CODEC_INVALID); }
    uint64_t hostLength = 0; auto result = hajimi_quic_varint_decode(input + 8, length - 8, &hostLength);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(8 + result.needed); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (hostLength == 0) { return error(HAJIMI_CODEC_INVALID); }
    if (hostLength > 2048) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t start = 8 + result.consumed, headerLength = start + static_cast<size_t>(hostLength);
    if (length < headerLength) { return more(headerLength); }
    result = authority(input + start, static_cast<size_t>(hostLength), 0, true, parsed.target);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    parsed.session_id = read32(input); parsed.packet_id = read16(input + 4);
    parsed.payload_offset = headerLength; parsed.payload_length = length - headerLength; parsed.has_address = 1;
    *frame = parsed; return ok(length);
}
extern "C" hajimi_codec_result hajimi_hysteria2_encode_udp(
    uint32_t session, uint16_t packet, uint8_t index, uint8_t count,
    const hajimi_address *address, const uint8_t *payload, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(payload, length) || !fragments(index, count)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    PreparedAddress prepared{}; auto result = prepare(address, prepared, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    uint8_t host[HAJIMI_CODEC_MAX_HOST + 9u]; const size_t hostLength = authorityText(prepared.address, host);
    size_t required;
    if (!add(8 + varintSize(hostLength) + hostLength, length, required)) { return error(HAJIMI_CODEC_LIMIT); }
    result = datagramOutput(output, capacity, required, address, payload, length);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    Writer w{output}; w.be(session, 4); w.be(packet, 2); w.byte(index); w.byte(count);
    writeVarint(w, hostLength); w.bytes(host, hostLength); w.bytes(payload, length); return ok(0, w.size);
}

extern "C" hajimi_codec_result hajimi_tuic5_parse_address(
    const uint8_t *input, size_t length, hajimi_address *address) {
    if (address == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    hajimi_address parsed{}; const auto result = parseAddress(input, length, true, parsed);
    if (result.status == HAJIMI_CODEC_OK) { *address = parsed; }
    return result;
}
extern "C" hajimi_codec_result hajimi_tuic5_encode_address(
    const hajimi_address *address, uint8_t *output, size_t capacity) {
    if (address == nullptr || address->type == HAJIMI_ADDRESS_NONE) {
        if (address != nullptr && (address->host_length != 0 || address->port != 0)) {
            return error(HAJIMI_CODEC_INVALID);
        }
        const auto ready = outputReady(output, capacity, 1);
        if (ready.status != HAJIMI_CODEC_OK) { return ready; }
        if (address != nullptr && overlaps(output, 1, address, sizeof(*address))) { return error(HAJIMI_CODEC_INVALID); }
        output[0] = 0xff; return ok(0, 1);
    }
    return encodeAddress(address, AddressFormat::tuic, output, capacity);
}
extern "C" hajimi_codec_result hajimi_tuic5_encode_authenticate(
    const uint8_t uuid[16], const uint8_t tokenBytes[32], uint8_t *output, size_t capacity) {
    if (uuid == nullptr || tokenBytes == nullptr) { return error(HAJIMI_CODEC_INVALID); }
    const auto ready = outputReady(output, capacity, 50);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, 50, uuid, 16) || overlaps(output, 50, tokenBytes, 32)) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; w.byte(5); w.byte(0); w.bytes(uuid, 16); w.bytes(tokenBytes, 32); return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_tuic5_encode_connect(
    const hajimi_address *address, uint8_t *output, size_t capacity) {
    PreparedAddress prepared{}; auto result = prepare(address, prepared, false);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    const size_t required = 2 + addressSize(prepared, AddressFormat::tuic);
    result = outputReady(output, capacity, required);
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    if (overlaps(output, required, address, sizeof(*address))) { return error(HAJIMI_CODEC_INVALID); }
    Writer w{output}; w.byte(5); w.byte(1); writeAddress(w, prepared, AddressFormat::tuic); return ok(0, w.size);
}
extern "C" hajimi_codec_result hajimi_tuic5_parse_udp(
    const uint8_t *input, size_t length, hajimi_udp_frame *frame) {
    if (frame == nullptr || !span(input, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if ((length > 0 && input[0] != 5) || (length > 1 && input[1] != 2)) { return error(HAJIMI_CODEC_INVALID); }
    if (length < 10) { return more(11); }
    hajimi_udp_frame parsed{};
    parsed.fragment_count = input[6]; parsed.fragment_index = input[7];
    if (!fragments(parsed.fragment_index, parsed.fragment_count)) { return error(HAJIMI_CODEC_INVALID); }
    auto result = parseAddress(input + 10, length - 10, true, parsed.target);
    if (result.status == HAJIMI_CODEC_NEED_MORE) { return more(10 + result.needed); }
    if (result.status != HAJIMI_CODEC_OK) { return result; }
    parsed.has_address = parsed.target.type != HAJIMI_ADDRESS_NONE ? 1 : 0;
    if (parsed.fragment_index == 0 && !parsed.has_address) { return error(HAJIMI_CODEC_INVALID); }
    parsed.session_id = read16(input + 2); parsed.packet_id = read16(input + 4);
    parsed.payload_offset = 10 + result.consumed; parsed.payload_length = read16(input + 8);
    const size_t required = parsed.payload_offset + parsed.payload_length;
    if (required > HAJIMI_CODEC_MAX_DATAGRAM) { return error(HAJIMI_CODEC_LIMIT); }
    if (length < required) { return more(required); }
    if (length != required) { return error(HAJIMI_CODEC_INVALID); }
    *frame = parsed; return ok(required);
}
extern "C" hajimi_codec_result hajimi_tuic5_encode_udp(
    uint16_t association, uint16_t packet, uint8_t index, uint8_t count,
    const hajimi_address *address, const uint8_t *payload, size_t length,
    uint8_t *output, size_t capacity) {
    if (!span(payload, length) || !fragments(index, count)) { return error(HAJIMI_CODEC_INVALID); }
    if (length > 65535) { return error(HAJIMI_CODEC_LIMIT); }
    const bool absent = address == nullptr || address->type == HAJIMI_ADDRESS_NONE;
    if (absent && (index == 0 || (address != nullptr && (address->host_length != 0 || address->port != 0)))) {
        return error(HAJIMI_CODEC_INVALID);
    }
    PreparedAddress prepared{}; size_t addressLength = 1;
    if (!absent) {
        const auto result = prepare(address, prepared, false);
        if (result.status != HAJIMI_CODEC_OK) { return result; }
        addressLength = addressSize(prepared, AddressFormat::tuic);
    }
    const size_t required = 10 + addressLength + length;
    const auto ready = datagramOutput(output, capacity, required, address, payload, length);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    Writer w{output}; w.byte(5); w.byte(2); w.be(association, 2); w.be(packet, 2);
    w.byte(count); w.byte(index); w.be(length, 2);
    if (absent) { w.byte(0xff); } else { writeAddress(w, prepared, AddressFormat::tuic); }
    w.bytes(payload, length); return ok(0, w.size);
}
