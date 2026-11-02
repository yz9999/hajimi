#include "HajimiProtocolCXX.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <cstdio>
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
constexpr bool isTokenChar(uint8_t c) noexcept {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) { return true; }
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
        return true;
    default: return false;
    }
}
constexpr bool isDomainAsciiChar(uint8_t c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}
struct CharTables {
    bool token[256]{};
    bool domainAscii[256]{};
    constexpr CharTables() {
        for (int i = 0; i < 256; ++i) {
            token[i] = isTokenChar(static_cast<uint8_t>(i));
            domainAscii[i] = isDomainAsciiChar(static_cast<uint8_t>(i));
        }
    }
};
constexpr CharTables kTables{};

bool token(uint8_t c) noexcept { return kTables.token[c]; }

bool utf8(const uint8_t *p, size_t n) noexcept {
    size_t i = 0;
    while (i + 8 <= n) {
        uint64_t word = 0;
        std::memcpy(&word, p + i, 8);
        if ((word & 0x8080808080808080ULL) != 0) { break; }
        i += 8;
    }
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
    if (n == 0 || n > HAJIMI_CODEC_MAX_HOST) { return false; }
    bool hasNonAscii = false;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t c = p[i];
        if (c >= 0x80) {
            if (asciiOnly) { return false; }
            hasNonAscii = true;
            continue;
        }
        if (!kTables.domainAscii[c]) { return false; }
    }
    return !hasNonAscii || utf8(p, n);
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
    bool hasColon = false;
    bool onlyDigitsAndDots = true;
    for (size_t i = 0; i < length; ++i) {
        /* Darwin inet_pton accepts and drops IPv6 zone suffixes. Proxy wire
         * address formats cannot represent that scope, so reject explicitly. */
        const uint8_t c = host[i];
        if (c == 0 || c == '%') { return error(HAJIMI_CODEC_INVALID); }
        if (c == ':') { hasColon = true; }
        if ((c < '0' || c > '9') && c != '.') { onlyDigitsAndDots = false; }
    }
    uint8_t binary[16]; uint8_t kind = HAJIMI_ADDRESS_DOMAIN;
    if (!bracketed && !hasColon && !onlyDigitsAndDots) {
        if (!domain(host, length)) { return error(HAJIMI_CODEC_INVALID); }
    } else {
        char text[HAJIMI_CODEC_MAX_HOST + 1u];
        std::memcpy(text, host, length); text[length] = 0;
        if (!hasColon && onlyDigitsAndDots && inet_pton(AF_INET, text, binary) == 1) {
            kind = HAJIMI_ADDRESS_IPV4;
        } else if (hasColon && inet_pton(AF_INET6, text, binary) == 1) {
            kind = HAJIMI_ADDRESS_IPV6;
        } else if (!domain(host, length)) {
            return error(HAJIMI_CODEC_INVALID);
        }
    }
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
    while (offset + 1 < end) {
        const auto *found = static_cast<const uint8_t *>(std::memchr(p + offset, '\r', end - 1 - offset));
        if (!found) { return end - 1; }
        const size_t pos = static_cast<size_t>(found - p);
        if (p[pos + 1] == '\n') { return pos; }
        offset = pos + 1;
    }
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
        switch (field.nameLength) {
        case 4:
            if (equal(name, 4, "host")) {
                if (hostIndex != HAJIMI_CODEC_MAX_HTTP_FIELDS || field.valueLength == 0) {
                    return error(HAJIMI_CODEC_INVALID);
                }
                hostIndex = parsed.count;
            }
            break;
        case 10:
            if (equal(name, 10, "connection")) {
                if (!tokenList(p + valueStart, field.valueLength, false)) { return error(HAJIMI_CODEC_INVALID); }
            }
            break;
        case 14:
            if (equal(name, 14, "content-length")) {
                if (hasLength || !contentLength(p + valueStart, field.valueLength)) { return error(HAJIMI_CODEC_INVALID); }
                hasLength = true;
            }
            break;
        case 17:
            if (equal(name, 17, "transfer-encoding")) {
                if (hasEncoding || http10 || !tokenList(p + valueStart, field.valueLength, true)) {
                    return error(HAJIMI_CODEC_INVALID);
                }
                hasEncoding = true;
            }
            break;
        default:
            break;
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


extern "C" void hajimi_ws_xor_mask(uint8_t *bytes, size_t length, const uint8_t mask[4]) {
    if (bytes == nullptr || mask == nullptr || length == 0) { return; }
    uint64_t mask64 = 0;
    const uint8_t mask8[8] = {
        mask[0], mask[1], mask[2], mask[3],
        mask[0], mask[1], mask[2], mask[3]
    };
    std::memcpy(&mask64, mask8, 8);
    size_t i = 0;
    while (i + 32 <= length) {
        uint64_t w0, w1, w2, w3;
        std::memcpy(&w0, bytes + i, 8);
        std::memcpy(&w1, bytes + i + 8, 8);
        std::memcpy(&w2, bytes + i + 16, 8);
        std::memcpy(&w3, bytes + i + 24, 8);
        w0 ^= mask64; w1 ^= mask64; w2 ^= mask64; w3 ^= mask64;
        std::memcpy(bytes + i, &w0, 8);
        std::memcpy(bytes + i + 8, &w1, 8);
        std::memcpy(bytes + i + 16, &w2, 8);
        std::memcpy(bytes + i + 24, &w3, 8);
        i += 32;
    }
    while (i + 8 <= length) {
        uint64_t w;
        std::memcpy(&w, bytes + i, 8);
        w ^= mask64;
        std::memcpy(bytes + i, &w, 8);
        i += 8;
    }
    for (; i < length; ++i) {
        bytes[i] ^= mask[i & 3u];
    }
}

extern "C" hajimi_codec_result hajimi_ws_encode_frame(
    uint8_t fin, uint8_t opcode, int32_t masked, const uint8_t mask[4],
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity) {
    if (!span(payload, payload_length) || (masked != 0 && mask == nullptr) || (opcode & 0xf0u) != 0) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const size_t ext_len = payload_length < 126 ? 0 : (payload_length <= 0xffffu ? 2 : 8);
    const size_t mask_len = masked != 0 ? 4 : 0;
    const size_t header_len = 2 + ext_len + mask_len;
    size_t required = 0;
    if (!add(header_len, payload_length, required)) { return error(HAJIMI_CODEC_LIMIT); }
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, payload, payload_length) ||
        (masked != 0 && overlaps(output, required, mask, 4))) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output};
    w.byte(static_cast<uint8_t>((fin ? 0x80u : 0x00u) | (opcode & 0x0fu)));
    const uint8_t mask_bit = masked != 0 ? 0x80u : 0x00u;
    if (payload_length < 126) {
        w.byte(static_cast<uint8_t>(mask_bit | payload_length));
    } else if (payload_length <= 0xffffu) {
        w.byte(static_cast<uint8_t>(mask_bit | 126u));
        w.be(payload_length, 2);
    } else {
        w.byte(static_cast<uint8_t>(mask_bit | 127u));
        w.be(payload_length, 8);
    }
    if (masked != 0) {
        w.bytes(mask, 4);
    }
    const size_t payload_offset = w.size;
    w.bytes(payload, payload_length);
    if (masked != 0 && payload_length > 0) {
        hajimi_ws_xor_mask(output + payload_offset, payload_length, mask);
    }
    return ok(0, w.size);
}

extern "C" hajimi_codec_result hajimi_mux_encode_frame(
    uint16_t id, uint8_t status, uint8_t options, uint8_t network,
    const hajimi_address *address, const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity) {
    if (!span(payload, payload_length) || status < 1 || status > 4) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (payload_length > 0xffffu) { return error(HAJIMI_CODEC_LIMIT); }
    const bool has_target = (status == 1) || (status == 2 && network == 2);
    PreparedAddress prepared{};
    size_t metadata_len = 4;
    if (has_target) {
        if (network != 1 && network != 2) { return error(HAJIMI_CODEC_INVALID); }
        const auto res = prepare(address, prepared);
        if (res.status != HAJIMI_CODEC_OK) { return res; }
        metadata_len += 3 + addressSize(prepared, AddressFormat::vmess);
    }
    if (metadata_len > 0xffffu) { return error(HAJIMI_CODEC_LIMIT); }
    const uint8_t actual_options = payload_length > 0 ? static_cast<uint8_t>(options | 0x01u) : options;
    const bool include_data = (actual_options & 0x01u) != 0;
    const size_t required = 2 + metadata_len + (include_data ? (2 + payload_length) : 0);
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if ((address != nullptr && overlaps(output, required, address, sizeof(*address))) ||
        overlaps(output, required, payload, payload_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output};
    w.be(metadata_len, 2);
    w.be(id, 2);
    w.byte(status);
    w.byte(actual_options);
    if (has_target) {
        w.byte(network);
        w.be(prepared.address.port, 2);
        writeAddress(w, prepared, AddressFormat::vmess);
    }
    if (include_data) {
        w.be(payload_length, 2);
        w.bytes(payload, payload_length);
    }
    return ok(0, w.size);
}

extern "C" hajimi_codec_result hajimi_xudp_encode_frame(
    int32_t first_packet, const uint8_t global_id[8],
    const hajimi_address *address, const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity) {
    if (!span(payload, payload_length) || global_id == nullptr) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (payload_length > 0xffffu) { return error(HAJIMI_CODEC_LIMIT); }
    bool non_zero = false;
    for (size_t i = 0; i < 8; ++i) {
        if (global_id[i] != 0) { non_zero = true; break; }
    }
    if (!non_zero) { return error(HAJIMI_CODEC_INVALID); }
    PreparedAddress prepared{};
    const auto res = prepare(address, prepared);
    if (res.status != HAJIMI_CODEC_OK) { return res; }
    const size_t metadata_len = 4 + 3 + addressSize(prepared, AddressFormat::vmess) + (first_packet != 0 ? 8 : 0);
    if (metadata_len > 0xffffu) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t required = 2 + metadata_len + 2 + payload_length;
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, address, sizeof(*address)) ||
        overlaps(output, required, global_id, 8) ||
        overlaps(output, required, payload, payload_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    Writer w{output};
    w.be(metadata_len, 2);
    w.be(0, 2);
    w.byte(first_packet != 0 ? 1 : 2);
    w.byte(1);
    w.byte(2);
    w.be(prepared.address.port, 2);
    writeAddress(w, prepared, AddressFormat::vmess);
    if (first_packet != 0) {
        w.bytes(global_id, 8);
    }
    w.be(payload_length, 2);
    w.bytes(payload, payload_length);
    return ok(0, w.size);
}

extern "C" uint32_t hajimi_mkcp_fnv1a(const uint8_t *data, size_t length) {
    uint32_t hash = 0x811c9dc5u;
    if (data == nullptr || length == 0) { return hash; }
    for (size_t i = 0; i < length; ++i) {
        hash ^= static_cast<uint32_t>(data[i]);
        hash *= 0x01000193u;
    }
    return hash;
}

extern "C" hajimi_codec_result hajimi_mkcp_seal_simple(
    const uint8_t *plain, size_t plain_length,
    uint8_t *output, size_t output_capacity) {
    if (!span(plain, plain_length)) { return error(HAJIMI_CODEC_INVALID); }
    if (plain_length > 0xffffu) { return error(HAJIMI_CODEC_LIMIT); }
    const size_t required = 6 + plain_length;
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, plain, plain_length)) { return error(HAJIMI_CODEC_INVALID); }
    output[4] = static_cast<uint8_t>((plain_length >> 8) & 0xffu);
    output[5] = static_cast<uint8_t>(plain_length & 0xffu);
    if (plain_length > 0) {
        std::memcpy(output + 6, plain, plain_length);
    }
    const uint32_t fnv = hajimi_mkcp_fnv1a(output + 4, 2 + plain_length);
    output[0] = static_cast<uint8_t>((fnv >> 24) & 0xffu);
    output[1] = static_cast<uint8_t>((fnv >> 16) & 0xffu);
    output[2] = static_cast<uint8_t>((fnv >> 8) & 0xffu);
    output[3] = static_cast<uint8_t>(fnv & 0xffu);
    uint32_t prev = 0;
    std::memcpy(&prev, output, 4);
    size_t i = 4;
    while (i + 4 <= required) {
        uint32_t cur = 0;
        std::memcpy(&cur, output + i, 4);
        prev ^= cur;
        std::memcpy(output + i, &prev, 4);
        i += 4;
    }
    for (; i < required; ++i) {
        output[i] ^= output[i - 4];
    }
    return ok(0, required);
}

extern "C" hajimi_codec_result hajimi_mkcp_open_simple(
    const uint8_t *cipher, size_t cipher_length,
    uint8_t *output, size_t output_capacity) {
    if (!span(cipher, cipher_length) || cipher_length < 6) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const size_t plain_capacity = cipher_length - 6;
    const auto ready = outputReady(output, output_capacity, plain_capacity);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, plain_capacity, cipher, cipher_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const uint32_t expected_fnv = read32(cipher);
    const uint8_t len_hi = cipher[4] ^ cipher[0];
    const uint8_t len_lo = cipher[5] ^ cipher[1];
    const uint16_t declared_len = static_cast<uint16_t>((static_cast<uint16_t>(len_hi) << 8) | len_lo);
    if (declared_len != plain_capacity) {
        return error(HAJIMI_CODEC_INVALID);
    }
    size_t i = 0;
    while (i + 8 <= plain_capacity) {
        uint64_t c_cur, c_prev;
        std::memcpy(&c_cur, cipher + 6 + i, 8);
        std::memcpy(&c_prev, cipher + 2 + i, 8);
        const uint64_t p = c_cur ^ c_prev;
        std::memcpy(output + i, &p, 8);
        i += 8;
    }
    for (; i < plain_capacity; ++i) {
        output[i] = cipher[6 + i] ^ cipher[2 + i];
    }
    uint32_t hash = 0x811c9dc5u;
    hash = (hash ^ len_hi) * 0x01000193u;
    hash = (hash ^ len_lo) * 0x01000193u;
    for (size_t j = 0; j < plain_capacity; ++j) {
        hash = (hash ^ output[j]) * 0x01000193u;
    }
    if (hash != expected_fnv) {
        return error(HAJIMI_CODEC_INVALID);
    }
    return ok(cipher_length, declared_len);
}

extern "C" hajimi_codec_result hajimi_fakeip_parse_question(
    const uint8_t *packet, size_t length, hajimi_fakeip_question *out) {
    if (out == nullptr || !span(packet, length)) { return error(HAJIMI_CODEC_INVALID); }
    if (length < 17) { return error(HAJIMI_CODEC_INVALID); }
    const uint16_t flags = read16(packet + 2);
    if ((flags & 0x8000u) != 0) { return error(HAJIMI_CODEC_INVALID); }
    if ((flags & 0x7800u) != 0) { return error(HAJIMI_CODEC_UNSUPPORTED); }
    const uint16_t qdcount = read16(packet + 4);
    if (qdcount != 1) { return error(HAJIMI_CODEC_UNSUPPORTED); }

    hajimi_fakeip_question parsed{};
    size_t idx = 12;
    size_t host_len = 0;
    while (true) {
        if (idx >= length) { return error(HAJIMI_CODEC_INVALID); }
        const uint8_t label_len = packet[idx++];
        if (label_len == 0) { break; }
        if ((label_len & 0xc0u) != 0 || label_len > 63 || idx + label_len > length) {
            return error(HAJIMI_CODEC_INVALID);
        }
        if (!utf8(packet + idx, label_len)) {
            return error(HAJIMI_CODEC_INVALID);
        }
        if (host_len > 0) {
            if (host_len + 1 > HAJIMI_CODEC_MAX_HOST) { return error(HAJIMI_CODEC_LIMIT); }
            parsed.host[host_len++] = '.';
        }
        if (host_len + label_len > HAJIMI_CODEC_MAX_HOST) { return error(HAJIMI_CODEC_LIMIT); }
        for (size_t k = 0; k < label_len; ++k) {
            parsed.host[host_len + k] = lower(packet[idx + k]);
        }
        host_len += label_len;
        idx += label_len;
    }
    if (host_len == 0 || idx + 4 > length) { return error(HAJIMI_CODEC_INVALID); }
    parsed.host[host_len] = 0;
    parsed.host_length = host_len;
    parsed.qtype = read16(packet + idx);
    parsed.qclass = read16(packet + idx + 2);
    parsed.question_end = idx + 4;
    if (parsed.qclass != 1 || (parsed.qtype != 1 && parsed.qtype != 28)) {
        return error(HAJIMI_CODEC_UNSUPPORTED);
    }
    *out = parsed;
    return ok(parsed.question_end);
}

extern "C" hajimi_codec_result hajimi_fakeip_build_reply(
    const uint8_t *packet, size_t length,
    const hajimi_fakeip_question *question,
    int32_t has_ipv4, const uint8_t ipv4[4], uint32_t ttl,
    uint8_t *output, size_t output_capacity) {
    if (question == nullptr || !span(packet, length) ||
        question->question_end < 17 || question->question_end > length ||
        (has_ipv4 != 0 && ipv4 == nullptr)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const size_t q_len = question->question_end - 12;
    const size_t required = 12 + q_len + (has_ipv4 != 0 ? 16 : 0);
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, packet, length) ||
        (has_ipv4 != 0 && overlaps(output, required, ipv4, 4))) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const uint16_t req_flags = read16(packet + 2);
    const uint16_t resp_flags = static_cast<uint16_t>(0x8080u | (req_flags & 0x0100u));
    Writer w{output};
    w.bytes(packet, 2);
    w.be(resp_flags, 2);
    w.be(1, 2);
    w.be(has_ipv4 != 0 ? 1 : 0, 2);
    w.be(0, 2);
    w.be(0, 2);
    w.bytes(packet + 12, q_len);
    if (has_ipv4 != 0) {
        w.be(0xc00cu, 2);
        w.be(1, 2);
        w.be(1, 2);
        w.be(ttl, 4);
        w.be(4, 2);
        w.bytes(ipv4, 4);
    }
    return ok(question->question_end, w.size);
}

extern "C" void hajimi_rate_meter_init(hajimi_rate_meter *meter, double aggregation_window) {
    if (meter == nullptr) { return; }
    const double win = (std::isfinite(aggregation_window) && aggregation_window >= 0.05) ? aggregation_window : 0.05;
    *meter = {win, 0, 0, 0.0, 0.0, 0};
}

extern "C" void hajimi_rate_meter_observe(hajimi_rate_meter *meter,
                                          uint64_t cumulative_bytes,
                                          double timestamp_seconds) {
    if (meter == nullptr || !std::isfinite(timestamp_seconds)) { return; }
    if (!meter->has_previous) {
        meter->previous = cumulative_bytes;
        meter->window_start = timestamp_seconds;
        meter->has_previous = 1;
        return;
    }
    if (cumulative_bytes < meter->previous || timestamp_seconds < meter->window_start) {
        const bool counter_reset = (cumulative_bytes < meter->previous);
        meter->previous = cumulative_bytes;
        meter->accumulated = 0;
        meter->window_start = timestamp_seconds;
        if (counter_reset) {
            meter->current_bps = 0.0;
        }
        return;
    }
    meter->accumulated += (cumulative_bytes - meter->previous);
    meter->previous = cumulative_bytes;

    const double elapsed = timestamp_seconds - meter->window_start;
    if (elapsed < meter->aggregation_window) { return; }
    meter->current_bps = static_cast<double>(meter->accumulated) / elapsed;
    meter->accumulated = 0;
    meter->window_start = timestamp_seconds;
}

extern "C" void hajimi_rate_meter_idle(hajimi_rate_meter *meter, double timestamp_seconds) {
    if (meter == nullptr || !std::isfinite(timestamp_seconds)) { return; }
    meter->accumulated = 0;
    meter->window_start = timestamp_seconds;
    meter->current_bps = 0.0;
}

extern "C" void hajimi_rate_meter_reset(hajimi_rate_meter *meter) {
    if (meter == nullptr) { return; }
    meter->previous = 0;
    meter->accumulated = 0;
    meter->window_start = 0.0;
    meter->current_bps = 0.0;
    meter->has_previous = 0;
}

extern "C" size_t hajimi_rate_format_compact(double bytes_per_second, char *out, size_t capacity) {
    if (out == nullptr || capacity < 16) { return 0; }
    const double value = (std::isfinite(bytes_per_second) && bytes_per_second > 0.0) ? bytes_per_second : 0.0;
    struct Unit { double threshold; const char *suffix; };
    static constexpr Unit units[3] = {
        {1000000000.0, "G"},
        {1000000.0, "M"},
        {1000.0, "K"}
    };
    int n = 0;
    bool matched = false;
    for (const auto &unit : units) {
        if (value >= unit.threshold) {
            const double scaled = value / unit.threshold;
            n = scaled >= 10.0
                ? std::snprintf(out, capacity, "%.0f%s", scaled, unit.suffix)
                : std::snprintf(out, capacity, "%.1f%s", scaled, unit.suffix);
            matched = true;
            break;
        }
    }
    if (!matched) {
        n = std::snprintf(out, capacity, "%.0fB", value);
    }
    if (n <= 0 || static_cast<size_t>(n) >= capacity) {
        out[0] = '\0';
        return 0;
    }
    return static_cast<size_t>(n);
}

extern "C" uint64_t hajimi_stafford_mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

extern "C" uint32_t hajimi_jump_consistent_hash(uint64_t key, uint32_t num_buckets) {
    if (num_buckets <= 1) { return 0; }
    int64_t b = -1;
    int64_t j = 0;
    const int64_t buckets = static_cast<int64_t>(num_buckets);
    while (j < buckets) {
        b = j;
        key = key * 2862933555777941757ULL + 1ULL;
        j = static_cast<int64_t>(
            static_cast<double>(b + 1) * (static_cast<double>(1LL << 31) / static_cast<double>((key >> 33) + 1ULL))
        );
    }
    return static_cast<uint32_t>(b < 0 ? 0 : b);
}

extern "C" void hajimi_smart_stats_init(hajimi_smart_node_stats *stats) {
    if (stats == nullptr) { return; }
    *stats = {0.0, 0.0, 0.0, 0.0, 0.0, 0, 0};
}

extern "C" void hajimi_smart_stats_observe(hajimi_smart_node_stats *stats,
                                           int32_t success,
                                           double latency_seconds,
                                           double timestamp_seconds) {
    if (stats == nullptr || !std::isfinite(timestamp_seconds)) { return; }
    if (stats->initialized && timestamp_seconds > stats->last_timestamp) {
        const double elapsed = timestamp_seconds - stats->last_timestamp;
        // Continuous-time exponential forgetting with half-life tau = 300s
        const double decay = std::pow(0.5, std::fmin(elapsed, 3600.0) / 300.0);
        stats->success_weight *= decay;
        stats->failure_weight *= decay;
    }
    stats->last_timestamp = timestamp_seconds;
    if (success != 0 && std::isfinite(latency_seconds) && latency_seconds > 0.0) {
        const double clamped_rtt = std::fmin(std::fmax(latency_seconds, 0.0005), 30.0);
        stats->success_weight += 1.0;
        if (stats->sample_count == 0) {
            stats->ewma_rtt = clamped_rtt;
            stats->ewm_var = 0.0;
        } else {
            // Welford-West exponentially weighted online mean & variance recurrence
            constexpr double alpha = 0.25;
            const double delta = clamped_rtt - stats->ewma_rtt;
            stats->ewma_rtt += alpha * delta;
            stats->ewm_var = (1.0 - alpha) * (stats->ewm_var + alpha * delta * delta);
        }
        if (stats->sample_count < 0xffffffffu) {
            ++stats->sample_count;
        }
    } else {
        stats->failure_weight += 1.0;
    }
    stats->initialized = 1;
}

extern "C" double hajimi_smart_stats_cost(const hajimi_smart_node_stats *stats,
                                          double now_seconds) {
    if (stats == nullptr || !stats->initialized || stats->sample_count == 0) {
        return 1e9;
    }
    double decay = 1.0;
    if (now_seconds > stats->last_timestamp) {
        decay = std::pow(0.5, std::fmin(now_seconds - stats->last_timestamp, 3600.0) / 300.0);
    }
    const double s = stats->success_weight * decay;
    const double f = stats->failure_weight * decay;
    // Empirical Bayes Beta(2.0, 0.25) conjugate posterior reliability
    const double p_hat = (s + 2.0) / (s + f + 2.25);
    const double sigma = std::sqrt(std::fmax(0.0, stats->ewm_var));
    // Cornish-Fisher / Gaussian 90th-percentile upper quantile (z_0.90 = 1.2815515655)
    const double q90_rtt = stats->ewma_rtt + 1.2815515655 * sigma;
    // Mathis-Semke-Mahdavi inverse-square reliability scaling + failure penalty
    const double inv_p = 1.0 / std::fmax(0.05, p_hat);
    return q90_rtt * (inv_p * inv_p) + 0.15 * (inv_p - 1.0);
}

extern "C" int32_t hajimi_constant_time_memcmp(const uint8_t *a, size_t a_len,
                                               const uint8_t *b, size_t b_len) {
    if ((a_len != 0 && a == nullptr) || (b_len != 0 && b == nullptr)) {
        return 0;
    }
    volatile size_t len_diff = a_len ^ b_len;
    volatile uint8_t byte_diff = 0;
    if (b_len == 0) {
        return len_diff == 0 ? 1 : 0;
    }
    const uint8_t dummy = 0;
    const uint8_t *safe_a = (a != nullptr && a_len > 0) ? a : &dummy;
    const size_t limit_a = (a != nullptr && a_len > 0) ? a_len : 1;
    // Always iterate over expected secret length b_len so execution time
    // depends only on the configured secret length, never on attacker input.
    for (size_t i = 0; i < b_len; ++i) {
        const size_t idx_a = i < limit_a ? i : (limit_a - 1);
        byte_diff = static_cast<uint8_t>(byte_diff | (safe_a[idx_a] ^ b[i]));
    }
    return (len_diff == 0 && byte_diff == 0) ? 1 : 0;
}

/* ============================================================================
 * Frontier Encrypted DNS Wire Codecs & Adaptive UCB1 Scorer Implementation
 * ============================================================================ */

extern "C" hajimi_codec_result hajimi_dns_doq_encode_frame(
    const uint8_t *dns_message, size_t message_length,
    uint16_t *original_id_out,
    uint8_t *output, size_t output_capacity) {
    if (!span(dns_message, message_length) || message_length < 12 ||
        message_length > HAJIMI_CODEC_MAX_DATAGRAM) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const size_t required = 2 + message_length;
    const auto ready = outputReady(output, output_capacity, required);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, required, dns_message, message_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const uint16_t orig_id = read16(dns_message);
    if (output != nullptr) {
        output[0] = static_cast<uint8_t>((message_length >> 8) & 0xffu);
        output[1] = static_cast<uint8_t>(message_length & 0xffu);
        // RFC 9250 §4.2.1: DNS Message ID MUST be set to 0 on DoQ streams.
        output[2] = 0;
        output[3] = 0;
        std::memcpy(output + 4, dns_message + 2, message_length - 2);
    }
    if (original_id_out != nullptr) {
        *original_id_out = orig_id;
    }
    return ok(message_length, required);
}

extern "C" hajimi_codec_result hajimi_dns_doq_decode_frame(
    const uint8_t *frame_input, size_t frame_length,
    uint16_t expected_client_id,
    uint8_t *output, size_t output_capacity) {
    if (!span(frame_input, frame_length)) { return error(HAJIMI_CODEC_INVALID); }
    if (frame_length < 2) { return more(2); }
    const uint16_t declared = read16(frame_input);
    if (declared < 12) { return error(HAJIMI_CODEC_INVALID); }
    const size_t total_frame = 2 + static_cast<size_t>(declared);
    if (frame_length < total_frame) { return more(total_frame); }
    // RFC 9250 §4.2.1: DoQ wire message ID must be 0x0000.
    const uint16_t wire_id = read16(frame_input + 2);
    if (wire_id != 0) { return error(HAJIMI_CODEC_INVALID); }
    const auto ready = outputReady(output, output_capacity, declared);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, declared, frame_input, total_frame)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (output != nullptr) {
        output[0] = static_cast<uint8_t>((expected_client_id >> 8) & 0xffu);
        output[1] = static_cast<uint8_t>(expected_client_id & 0xffu);
        std::memcpy(output + 2, frame_input + 4, declared - 2);
    }
    return ok(total_frame, declared);
}

namespace {

bool skipDNSWireName(const uint8_t *bytes, size_t len, size_t &offset) noexcept {
    size_t pos = offset;
    size_t jumped_end = 0;
    bool jumped = false;
    size_t expanded = 1;
    for (size_t step = 0; step < 256; ++step) {
        if (pos >= len) { return false; }
        const uint8_t b = bytes[pos];
        if ((b & 0xc0u) == 0xc0u) {
            if (pos + 1 >= len) { return false; }
            const size_t ptr = (static_cast<size_t>(b & 0x3fu) << 8) | bytes[pos + 1];
            if (ptr < 12 || ptr >= pos) { return false; }
            if (!jumped) {
                jumped_end = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if (b > 63) { return false; }
        ++pos;
        if (b == 0) {
            offset = jumped ? jumped_end : pos;
            return true;
        }
        if (b > len - pos || expanded > static_cast<size_t>(255u - b - 1u)) { return false; }
        expanded += b + 1;
        pos += b;
    }
    return false;
}

bool locateTailRootOPT(const uint8_t *msg, size_t len,
                       size_t &opt_start_out, size_t &rdata_start_out,
                       uint16_t &rdlength_out, uint16_t &payload_out) noexcept {
    if (len < 12 || len > HAJIMI_CODEC_MAX_DATAGRAM) { return false; }
    const uint16_t qdcount = read16(msg + 4);
    const uint16_t ancount = read16(msg + 6);
    const uint16_t nscount = read16(msg + 8);
    const uint16_t arcount = read16(msg + 10);
    if (qdcount != 1 || static_cast<uint32_t>(ancount) + nscount + arcount > 512) {
        return false;
    }
    size_t offset = 12;
    if (!skipDNSWireName(msg, len, offset) || offset + 4 > len) { return false; }
    offset += 4; // QTYPE + QCLASS

    const uint32_t non_tail = static_cast<uint32_t>(ancount) + nscount + (arcount > 0 ? arcount - 1 : 0);
    for (uint32_t i = 0; i < non_tail; ++i) {
        if (!skipDNSWireName(msg, len, offset) || offset + 10 > len) { return false; }
        const uint16_t rtype = read16(msg + offset);
        if (rtype == 41) { return false; } // OPT must be unique and at the tail for safe in-place editing
        const uint16_t rdlen = read16(msg + offset + 8);
        offset += 10;
        if (rdlen > len - offset) { return false; }
        offset += rdlen;
    }
    if (arcount == 0) {
        if (offset != len) { return false; }
        opt_start_out = len;
        rdata_start_out = len;
        rdlength_out = 0;
        payload_out = 1232;
        return true;
    }
    // Check tail AR record is uncompressed root OPT (owner == 0x00, type == 41, version == 0)
    if (offset + 11 > len || msg[offset] != 0x00 || read16(msg + offset + 1) != 41) {
        return false;
    }
    const uint16_t payload = read16(msg + offset + 3);
    if (payload < 512 || msg[offset + 6] != 0) { return false; }
    const uint16_t rdlen = read16(msg + offset + 9);
    const size_t rdata_start = offset + 11;
    if (rdata_start + rdlen != len) { return false; }
    opt_start_out = offset;
    rdata_start_out = rdata_start;
    rdlength_out = rdlen;
    payload_out = payload;
    return true;
}

} // namespace

extern "C" hajimi_codec_result hajimi_dns_apply_edns_padding(
    const uint8_t *dns_message, size_t message_length,
    uint16_t block_size, uint16_t max_payload,
    uint8_t *output, size_t output_capacity) {
    if (!span(dns_message, message_length) || message_length < 12 ||
        message_length > HAJIMI_CODEC_MAX_DATAGRAM ||
        block_size == 0 || block_size > 4096 || max_payload < 512) {
        return error(HAJIMI_CODEC_INVALID);
    }
    size_t opt_start = 0, rdata_start = 0;
    uint16_t rdlen = 0, opt_payload = 1232;
    if (!locateTailRootOPT(dns_message, message_length, opt_start, rdata_start, rdlen, opt_payload)) {
        return error(HAJIMI_CODEC_UNSUPPORTED);
    }
    const bool has_opt = (opt_start < message_length);
    const uint16_t effective_max = std::min<uint16_t>(max_payload, has_opt ? opt_payload : max_payload);

    // Strip any existing Padding option (Code 12) from OPT RDATA so we emit a single canonical Option 12
    size_t clean_rdata_len = 0;
    if (has_opt) {
        size_t pos = rdata_start;
        while (pos < message_length) {
            if (message_length - pos < 4) { return error(HAJIMI_CODEC_INVALID); }
            const uint16_t code = read16(dns_message + pos);
            const uint16_t olen = read16(dns_message + pos + 2);
            pos += 4;
            if (olen > message_length - pos) { return error(HAJIMI_CODEC_INVALID); }
            if (code != 12) {
                clean_rdata_len += 4 + olen;
            }
            pos += olen;
        }
    }

    // Base size with OPT header (11 bytes) + non-padding options + 4-byte Option 12 header
    const size_t base_with_pad_hdr = opt_start + 11 + clean_rdata_len + 4;
    if (base_with_pad_hdr > effective_max) {
        return error(HAJIMI_CODEC_LIMIT);
    }
    const size_t remainder = base_with_pad_hdr % block_size;
    size_t pad_bytes = remainder == 0 ? 0 : (block_size - remainder);
    size_t target_size = base_with_pad_hdr + pad_bytes;
    if (target_size > effective_max) {
        target_size = (effective_max / block_size) * block_size;
        if (target_size < base_with_pad_hdr) {
            target_size = effective_max;
        }
        pad_bytes = target_size - base_with_pad_hdr;
    }
    const size_t new_rdlen = clean_rdata_len + 4 + pad_bytes;
    if (new_rdlen > 65535u) { return error(HAJIMI_CODEC_LIMIT); }

    const auto ready = outputReady(output, output_capacity, target_size);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, target_size, dns_message, message_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (output != nullptr) {
        std::memcpy(output, dns_message, opt_start);
        if (!has_opt) {
            const uint16_t ar = read16(dns_message + 10) + 1;
            output[10] = static_cast<uint8_t>((ar >> 8) & 0xffu);
            output[11] = static_cast<uint8_t>(ar & 0xffu);
            output[opt_start] = 0x00; // Root owner
            output[opt_start + 1] = 0x00;
            output[opt_start + 2] = 41; // OPT RR type
            output[opt_start + 3] = static_cast<uint8_t>((opt_payload >> 8) & 0xffu);
            output[opt_start + 4] = static_cast<uint8_t>(opt_payload & 0xffu);
            output[opt_start + 5] = 0; // Extended RCODE
            output[opt_start + 6] = 0; // EDNS Version 0
            output[opt_start + 7] = 0; // Flags hi
            output[opt_start + 8] = 0; // Flags lo
        } else {
            std::memcpy(output + opt_start, dns_message + opt_start, 9);
        }
        output[opt_start + 9] = static_cast<uint8_t>((new_rdlen >> 8) & 0xffu);
        output[opt_start + 10] = static_cast<uint8_t>(new_rdlen & 0xffu);
        size_t write_pos = opt_start + 11;
        if (has_opt && clean_rdata_len > 0) {
            size_t pos = rdata_start;
            while (pos < message_length) {
                const uint16_t code = read16(dns_message + pos);
                const uint16_t olen = read16(dns_message + pos + 2);
                if (code != 12) {
                    std::memcpy(output + write_pos, dns_message + pos, 4 + olen);
                    write_pos += 4 + olen;
                }
                pos += 4 + olen;
            }
        }
        // Append Option Code 12 (Padding) + zero bytes
        output[write_pos] = 0x00;
        output[write_pos + 1] = 12;
        output[write_pos + 2] = static_cast<uint8_t>((pad_bytes >> 8) & 0xffu);
        output[write_pos + 3] = static_cast<uint8_t>(pad_bytes & 0xffu);
        write_pos += 4;
        if (pad_bytes > 0) {
            std::memset(output + write_pos, 0, pad_bytes);
        }
    }
    return ok(message_length, target_size);
}

extern "C" hajimi_codec_result hajimi_dns_sanitize_ecs(
    const uint8_t *dns_message, size_t message_length,
    int32_t mode,
    uint8_t *output, size_t output_capacity) {
    if (!span(dns_message, message_length) || message_length < 12 ||
        message_length > HAJIMI_CODEC_MAX_DATAGRAM ||
        mode < HAJIMI_ECS_MODE_STRIP || mode > HAJIMI_ECS_MODE_TRUNCATE_PRIVACY) {
        return error(HAJIMI_CODEC_INVALID);
    }
    size_t opt_start = 0, rdata_start = 0;
    uint16_t rdlen = 0, opt_payload = 1232;
    if (!locateTailRootOPT(dns_message, message_length, opt_start, rdata_start, rdlen, opt_payload)) {
        return error(HAJIMI_CODEC_UNSUPPORTED);
    }
    if (opt_start == message_length) {
        // No OPT record present: copy unchanged
        const auto ready = outputReady(output, output_capacity, message_length);
        if (ready.status != HAJIMI_CODEC_OK) { return ready; }
        if (overlaps(output, message_length, dns_message, message_length)) {
            return error(HAJIMI_CODEC_INVALID);
        }
        if (output != nullptr) { std::memcpy(output, dns_message, message_length); }
        return ok(message_length, message_length);
    }

    // First pass: validate options inside OPT RDATA and calculate sanitized RDLENGTH
    size_t new_rdlen = 0;
    size_t pos = rdata_start;
    while (pos < message_length) {
        if (message_length - pos < 4) { return error(HAJIMI_CODEC_INVALID); }
        const uint16_t code = read16(dns_message + pos);
        const uint16_t olen = read16(dns_message + pos + 2);
        pos += 4;
        if (olen > message_length - pos) { return error(HAJIMI_CODEC_INVALID); }
        if (code == 8) {
            // Validate RFC 7871 ECS format: FAMILY(2) + SOURCE_PREFIX(1) + SCOPE_PREFIX(1) + ADDRESS
            if (olen < 4) { return error(HAJIMI_CODEC_INVALID); }
            const uint16_t family = read16(dns_message + pos);
            const uint8_t src_prefix = dns_message[pos + 2];
            const uint8_t max_bits = (family == 1) ? 32 : ((family == 2) ? 128 : 0);
            if (max_bits == 0 || src_prefix > max_bits) { return error(HAJIMI_CODEC_INVALID); }
            const size_t expected_addr_bytes = (src_prefix + 7u) / 8u;
            if (olen != 4 + expected_addr_bytes) { return error(HAJIMI_CODEC_INVALID); }
            if (mode == HAJIMI_ECS_MODE_STRIP) {
                // Omit option completely
            } else if (mode == HAJIMI_ECS_MODE_ANONYMIZE_ZERO) {
                new_rdlen += 4 + 4; // 4-byte option header + 4-byte /0 ECS body
            } else {
                const uint8_t clamped_prefix = std::min<uint8_t>(src_prefix, family == 1 ? 24 : 56);
                const size_t clamped_bytes = (clamped_prefix + 7u) / 8u;
                new_rdlen += 4 + 4 + clamped_bytes;
            }
        } else {
            new_rdlen += 4 + olen;
        }
        pos += olen;
    }

    const size_t target_size = opt_start + 11 + new_rdlen;
    const auto ready = outputReady(output, output_capacity, target_size);
    if (ready.status != HAJIMI_CODEC_OK) { return ready; }
    if (overlaps(output, target_size, dns_message, message_length)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (output != nullptr) {
        std::memcpy(output, dns_message, opt_start + 9);
        output[opt_start + 9] = static_cast<uint8_t>((new_rdlen >> 8) & 0xffu);
        output[opt_start + 10] = static_cast<uint8_t>(new_rdlen & 0xffu);
        size_t write_pos = opt_start + 11;
        pos = rdata_start;
        while (pos < message_length) {
            const uint16_t code = read16(dns_message + pos);
            const uint16_t olen = read16(dns_message + pos + 2);
            if (code == 8) {
                const uint16_t family = read16(dns_message + pos + 4);
                const uint8_t src_prefix = dns_message[pos + 6];
                if (mode == HAJIMI_ECS_MODE_ANONYMIZE_ZERO) {
                    output[write_pos] = 0; output[write_pos + 1] = 8;
                    output[write_pos + 2] = 0; output[write_pos + 3] = 4;
                    output[write_pos + 4] = static_cast<uint8_t>((family >> 8) & 0xffu);
                    output[write_pos + 5] = static_cast<uint8_t>(family & 0xffu);
                    output[write_pos + 6] = 0; // SOURCE PREFIX-LENGTH = 0
                    output[write_pos + 7] = 0; // SCOPE PREFIX-LENGTH = 0
                    write_pos += 8;
                } else if (mode == HAJIMI_ECS_MODE_TRUNCATE_PRIVACY) {
                    const uint8_t clamped_prefix = std::min<uint8_t>(src_prefix, family == 1 ? 24 : 56);
                    const size_t clamped_bytes = (clamped_prefix + 7u) / 8u;
                    const uint16_t body_len = static_cast<uint16_t>(4 + clamped_bytes);
                    output[write_pos] = 0; output[write_pos + 1] = 8;
                    output[write_pos + 2] = static_cast<uint8_t>((body_len >> 8) & 0xffu);
                    output[write_pos + 3] = static_cast<uint8_t>(body_len & 0xffu);
                    output[write_pos + 4] = static_cast<uint8_t>((family >> 8) & 0xffu);
                    output[write_pos + 5] = static_cast<uint8_t>(family & 0xffu);
                    output[write_pos + 6] = clamped_prefix;
                    output[write_pos + 7] = 0; // Reset scope prefix on outgoing query
                    write_pos += 8;
                    if (clamped_bytes > 0) {
                        std::memcpy(output + write_pos, dns_message + pos + 8, clamped_bytes);
                        const uint8_t rem_bits = clamped_prefix % 8u;
                        if (rem_bits != 0) {
                            const uint8_t mask = static_cast<uint8_t>(0xffu << (8u - rem_bits));
                            output[write_pos + clamped_bytes - 1] &= mask;
                        }
                        write_pos += clamped_bytes;
                    }
                }
            } else {
                std::memcpy(output + write_pos, dns_message + pos, 4 + olen);
                write_pos += 4 + olen;
            }
            pos += 4 + olen;
        }
    }
    return ok(message_length, target_size);
}

extern "C" double hajimi_dns_ucb1_score(
    double ewma_ms, double ewm_var_ms2,
    double success_weight, double failure_weight,
    uint64_t total_scope_queries, uint64_t candidate_samples,
    int32_t has_reusable_connection) {
    const double safe_ewma = (std::isfinite(ewma_ms) && ewma_ms >= 0.0) ? std::fmin(ewma_ms, 60000.0) : 500.0;
    const double safe_var = (std::isfinite(ewm_var_ms2) && ewm_var_ms2 >= 0.0) ? ewm_var_ms2 : 0.0;
    const double s = (std::isfinite(success_weight) && success_weight >= 0.0) ? success_weight : 0.0;
    const double f = (std::isfinite(failure_weight) && failure_weight >= 0.0) ? failure_weight : 0.0;

    // Empirical Bayes Beta(8, 2) conjugate posterior matching DNSAdaptiveUpstreamSelector
    const double p_success = (s + 8.0) / (s + f + 10.0);
    const double sigma_ms = std::sqrt(safe_var);
    // 95th-percentile upper tail estimate (z_0.95 = 1.6448536)
    const double tail_ms = safe_ewma + 1.6448536 * sigma_ms;
    // Hot reusable connection discount (eliminates TCP+TLS handshake RTTs)
    const double transport_factor = (has_reusable_connection != 0) ? 0.65 : 1.0;
    const double base_cost = tail_ms * transport_factor + (1.0 - p_success) * 8000.0;

    // UCB1 exploration bonus (subtracted from cost so under-sampled healthy candidates get explored)
    if (total_scope_queries > 1 && candidate_samples > 0) {
        const double ln_total = std::log(static_cast<double>(total_scope_queries));
        const double bonus = 18.0 * std::sqrt(ln_total / static_cast<double>(candidate_samples)) * p_success;
        return std::fmax(1.0, base_cost - bonus);
    }
    return std::fmax(1.0, base_cost);
}

extern "C" hajimi_codec_result hajimi_masque_encode_datagram(
    uint64_t stream_id,
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity) {
    if ((stream_id & 0x3u) != 0 || payload_length > 65535u || (payload == nullptr && payload_length > 0)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const uint64_t quarter_stream_id = stream_id >> 2;
    uint8_t qsid_buf[8]{};
    const auto qsid_res = hajimi_quic_varint_encode(quarter_stream_id, qsid_buf, sizeof(qsid_buf));
    if (qsid_res.status != HAJIMI_CODEC_OK) return qsid_res;
    const size_t total = qsid_res.written + 1u + payload_length; // +1 for Context-ID = 0x00
    const auto ready = outputReady(output, output_capacity, total);
    if (ready.status != HAJIMI_CODEC_OK) return ready;
    if (overlaps(output, total, payload, payload_length)) return error(HAJIMI_CODEC_INVALID);
    if (output != nullptr) {
        std::memcpy(output, qsid_buf, qsid_res.written);
        output[qsid_res.written] = 0x00u; // Context ID 0 (RFC 9298 §5)
        if (payload_length > 0) {
            std::memcpy(output + qsid_res.written + 1u, payload, payload_length);
        }
    }
    return ok(payload_length, total);
}

extern "C" hajimi_codec_result hajimi_masque_decode_datagram(
    const uint8_t *input, size_t input_length,
    uint64_t *stream_id_out,
    size_t *payload_offset_out,
    size_t *payload_length_out) {
    if (input == nullptr || stream_id_out == nullptr || payload_offset_out == nullptr || payload_length_out == nullptr) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (input_length < 2u) return more(2u);
    uint64_t quarter_stream_id = 0;
    const auto qsid_res = hajimi_quic_varint_decode(input, input_length, &quarter_stream_id);
    if (qsid_res.status != HAJIMI_CODEC_OK) return qsid_res;
    if (quarter_stream_id > (UINT64_MAX >> 2)) return error(HAJIMI_CODEC_INVALID);
    if (input_length <= qsid_res.consumed) return more(qsid_res.consumed + 1u);
    uint64_t context_id = 0;
    const auto ctx_res = hajimi_quic_varint_decode(
        input + qsid_res.consumed, input_length - qsid_res.consumed, &context_id);
    if (ctx_res.status != HAJIMI_CODEC_OK) return ctx_res;
    if (context_id != 0u) return error(HAJIMI_CODEC_UNSUPPORTED);
    const size_t header_len = qsid_res.consumed + ctx_res.consumed;
    *stream_id_out = quarter_stream_id << 2;
    *payload_offset_out = header_len;
    *payload_length_out = input_length - header_len;
    return ok(input_length, input_length - header_len);
}

extern "C" hajimi_codec_result hajimi_masque_encode_capsule(
    const uint8_t *payload, size_t payload_length,
    uint8_t *output, size_t output_capacity) {
    if (payload_length > 65535u || (payload == nullptr && payload_length > 0)) {
        return error(HAJIMI_CODEC_INVALID);
    }
    const uint64_t capsule_body_len = 1u + payload_length; // Context-ID (0x00) + payload
    uint8_t len_buf[8]{};
    const auto len_res = hajimi_quic_varint_encode(capsule_body_len, len_buf, sizeof(len_buf));
    if (len_res.status != HAJIMI_CODEC_OK) return len_res;
    const size_t total = 1u + len_res.written + 1u + payload_length; // Type(0x00) + Length + Context-ID(0x00) + Payload
    const auto ready = outputReady(output, output_capacity, total);
    if (ready.status != HAJIMI_CODEC_OK) return ready;
    if (overlaps(output, total, payload, payload_length)) return error(HAJIMI_CODEC_INVALID);
    if (output != nullptr) {
        output[0] = 0x00u; // Capsule Type = DATAGRAM (0x00, RFC 9297 §3.5)
        std::memcpy(output + 1u, len_buf, len_res.written);
        output[1u + len_res.written] = 0x00u; // Context-ID = 0x00 (RFC 9298 §5)
        if (payload_length > 0) {
            std::memcpy(output + 2u + len_res.written, payload, payload_length);
        }
    }
    return ok(payload_length, total);
}

extern "C" hajimi_codec_result hajimi_masque_decode_capsule(
    const uint8_t *input, size_t input_length,
    size_t *payload_offset_out,
    size_t *payload_length_out) {
    if (input == nullptr || payload_offset_out == nullptr || payload_length_out == nullptr) {
        return error(HAJIMI_CODEC_INVALID);
    }
    if (input_length < 3u) return more(3u);
    uint64_t capsule_type = 0;
    const auto type_res = hajimi_quic_varint_decode(input, input_length, &capsule_type);
    if (type_res.status != HAJIMI_CODEC_OK) return type_res;
    if (capsule_type != 0u) return error(HAJIMI_CODEC_UNSUPPORTED);
    if (input_length <= type_res.consumed) return more(type_res.consumed + 2u);
    uint64_t capsule_len = 0;
    const auto len_res = hajimi_quic_varint_decode(
        input + type_res.consumed, input_length - type_res.consumed, &capsule_len);
    if (len_res.status != HAJIMI_CODEC_OK) return len_res;
    if (capsule_len < 1u || capsule_len > 65536u) return error(HAJIMI_CODEC_INVALID);
    const size_t prefix = type_res.consumed + len_res.consumed;
    if (input_length < prefix + capsule_len) return more(prefix + static_cast<size_t>(capsule_len));
    uint64_t context_id = 0;
    const auto ctx_res = hajimi_quic_varint_decode(input + prefix, static_cast<size_t>(capsule_len), &context_id);
    if (ctx_res.status != HAJIMI_CODEC_OK) return ctx_res;
    if (context_id != 0u) return error(HAJIMI_CODEC_UNSUPPORTED);
    *payload_offset_out = prefix + ctx_res.consumed;
    *payload_length_out = static_cast<size_t>(capsule_len) - ctx_res.consumed;
    return ok(prefix + static_cast<size_t>(capsule_len), *payload_length_out);
}
