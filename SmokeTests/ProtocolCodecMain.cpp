#include "HajimiProtocolCXX.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

size_t checks = 0;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    std::fprintf(stderr, "protocol codec check failed at line %d: %s\n", __LINE__, #condition); \
    return false; } } while (false)
const uint8_t *bytes(const char *s) { return reinterpret_cast<const uint8_t *>(s); }
const uint8_t *bytes(const std::string &s) { return reinterpret_cast<const uint8_t *>(s.data()); }
bool unchanged(const uint8_t *p, size_t length, uint8_t value) {
    for (size_t i = 0; i < length; ++i) { if (p[i] != value) { return false; } }
    return true;
}
bool sameAddress(const hajimi_address &a, const hajimi_address &b) {
    return a.port == b.port && a.type == b.type && a.host_length == b.host_length &&
           std::memcmp(a.host, b.host, a.host_length) == 0;
}
bool make(const char *host, uint16_t port, hajimi_address &a) {
    return hajimi_address_from_host(bytes(host), std::strlen(host), port, &a).status == HAJIMI_CODEC_OK;
}

bool testAddresses() {
    hajimi_address a{};
    CHECK(make("127.0.0.1", 80, a)); CHECK(a.type == HAJIMI_ADDRESS_IPV4);
    CHECK(make("[2001:0db8::1]", 443, a)); CHECK(a.type == HAJIMI_ADDRESS_IPV6);
    CHECK(std::strcmp(reinterpret_cast<const char *>(a.host), "2001:db8::1") == 0);
    CHECK(make("example.com", 0, a)); CHECK(a.type == HAJIMI_ADDRESS_DOMAIN && a.port == 0);
    CHECK(make("\xe4\xbe\x8b\xe5\xad\x90.example", 80, a));
    const char *invalid[] = {"", "[example.com]", "example.com/evil", "user@host", "fe80::1%en0", "bad host"};
    for (const char *host : invalid) {
        a.port = 12345;
        const auto result = hajimi_address_from_host(bytes(host), std::strlen(host), 80, &a);
        if (result.status != HAJIMI_CODEC_INVALID) { std::fprintf(stderr, "Unexpected host acceptance: %s (%d)\n", host, result.status); }
        CHECK(result.status == HAJIMI_CODEC_INVALID);
        CHECK(a.port == 12345);
    }
    const uint8_t embedded[] = {'a', 0, 'b'};
    CHECK(hajimi_address_from_host(embedded, sizeof(embedded), 80, &a).status == HAJIMI_CODEC_INVALID);
    const uint8_t overlong[] = {0xc0, 0x80};
    CHECK(hajimi_address_from_host(overlong, sizeof(overlong), 80, &a).status == HAJIMI_CODEC_INVALID);
    std::string maxHost(255, 'a'); CHECK(hajimi_address_from_host(bytes(maxHost), maxHost.size(), 80, &a).status == HAJIMI_CODEC_OK);
    maxHost.push_back('a'); CHECK(hajimi_address_from_host(bytes(maxHost), maxHost.size(), 80, &a).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_address_from_host(nullptr, 1, 80, &a).status == HAJIMI_CODEC_INVALID);
    CHECK(hajimi_address_from_host(nullptr, 0, 80, &a).status == HAJIMI_CODEC_INVALID);
    return true;
}

bool testHTTP() {
    const std::string connect = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
    std::vector<uint8_t> input(connect.begin(), connect.end());
    const uint8_t tunnel[] = {0x16, 0x03, 0x01, 0x00, 0xff}; input.insert(input.end(), tunnel, tunnel + sizeof(tunnel));
    hajimi_http_request info{};
    for (size_t n = 0; n < connect.size(); ++n) {
        info.header_length = 999;
        const auto result = hajimi_http_parse_request(input.data(), n, 0, &info);
        CHECK(result.status == HAJIMI_CODEC_NEED_MORE && result.needed > n && result.consumed == 0);
        CHECK(info.header_length == 999);
    }
    auto result = hajimi_http_parse_request(input.data(), input.size(), 0, &info);
    CHECK(result.status == HAJIMI_CODEC_OK && result.consumed == connect.size());
    CHECK(info.is_connect == 1 && info.target.port == 443 && info.target.type == HAJIMI_ADDRESS_IPV6);
    CHECK(hajimi_http_rewrite_request(input.data(), input.size(), 0, 0, nullptr, 0, nullptr, 0, nullptr).status == HAJIMI_CODEC_UNSUPPORTED);
    const std::string head = "POST http://[2001:db8::1]:8080/a%2Fb?x=1 HTTP/1.1\r\n"
        "hOSt: poisoned.invalid\r\npRoXy-AuThOrIzAtIoN: Basic client-secret\r\n"
        "Proxy-Connection: keep-alive\r\nConnection: keep-alive, X-Hop\r\nX-Hop: remove-me\r\n"
        "X-Preserve: keep-me\r\nX-Proxy-Authorization: keep-too\r\nContent-Length: 5\r\n\r\n";
    input.assign(head.begin(), head.end());
    const uint8_t body[] = {0, 0xff, '\r', '\n', '*'}; input.insert(input.end(), body, body + sizeof(body));
    std::array<uint8_t, 8192> output; output.fill(0xcc);
    auto size = hajimi_http_rewrite_request(input.data(), input.size(), 0, 0, nullptr, 0, nullptr, 0, &info);
    CHECK(size.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && size.needed < output.size());
    result = hajimi_http_rewrite_request(input.data(), input.size(), 0, 0, nullptr, 0, output.data(), size.needed - 1, nullptr);
    CHECK(result.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && unchanged(output.data(), output.size(), 0xcc));
    result = hajimi_http_rewrite_request(input.data(), input.size(), 0, 0, nullptr, 0, output.data(), output.size(), &info);
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == size.needed && result.consumed == head.size());
    const std::string rewritten(reinterpret_cast<const char *>(output.data()), result.written - sizeof(body));
    CHECK(rewritten.find("POST /a%2Fb?x=1 HTTP/1.1\r\n") == 0);
    CHECK(rewritten.find("Host: [2001:db8::1]:8080\r\n") != std::string::npos);
    CHECK(rewritten.find("client-secret") == std::string::npos && rewritten.find("remove-me") == std::string::npos);
    CHECK(rewritten.find("Proxy-Connection:") == std::string::npos && rewritten.find("Connection: close\r\n") != std::string::npos);
    CHECK(rewritten.find("X-Preserve: keep-me") != std::string::npos && rewritten.find("X-Proxy-Authorization: keep-too") != std::string::npos);
    CHECK(std::memcmp(output.data() + result.written - sizeof(body), body, sizeof(body)) == 0);
    const char auth[] = "Basic upstream-secret";
    result = hajimi_http_rewrite_request(input.data(), input.size(), 0, 1, bytes(auth), sizeof(auth) - 1, output.data(), output.size(), nullptr);
    CHECK(result.status == HAJIMI_CODEC_OK);
    const std::string upstream(reinterpret_cast<const char *>(output.data()), result.written - sizeof(body));
    CHECK(upstream.find("POST http://[2001:db8::1]:8080/a%2Fb?x=1 HTTP/1.1\r\n") == 0);
    CHECK(upstream.find("Proxy-Authorization: Basic upstream-secret\r\n") != std::string::npos);
    CHECK(upstream.find("client-secret") == std::string::npos);
    const char injected[] = "Basic evil\r\nInjected: true";
    CHECK(hajimi_http_rewrite_request(input.data(), input.size(), 0, 1, bytes(injected), sizeof(injected) - 1, output.data(), output.size(), nullptr).status == HAJIMI_CODEC_INVALID);
    CHECK(hajimi_http_rewrite_request(input.data(), input.size(), 0, 0, nullptr, 0, input.data(), input.size(), nullptr).status == HAJIMI_CODEC_INVALID);
    const std::string query = "GET http://example.com?x=%2F HTTP/1.1\r\nHost: example.com\r\n\r\n";
    result = hajimi_http_rewrite_request(bytes(query), query.size(), 0, 0, nullptr, 0, output.data(), output.size(), &info);
    CHECK(result.status == HAJIMI_CODEC_OK && info.target.port == 80);
    CHECK(std::memcmp(output.data(), "GET /?x=%2F HTTP/1.1\r\n", 22) == 0);
    const std::string origin = "GET / HTTP/1.1\r\nHost: example.com:8123\r\n\r\n";
    result = hajimi_http_rewrite_request(bytes(origin), origin.size(), 0, 1, nullptr, 0, output.data(), output.size(), &info);
    CHECK(result.status == HAJIMI_CODEC_OK && info.target.port == 8123);
    CHECK(std::memcmp(output.data(), "GET http://example.com:8123/ HTTP/1.1\r\n", 38) == 0);
    const std::string https = "GET https://example.com HTTP/1.0\r\n\r\n";
    CHECK(hajimi_http_parse_request(bytes(https), https.size(), 0, &info).status == HAJIMI_CODEC_OK);
    CHECK(info.target.port == 443 && info.is_https && info.path_length == 0);
    const std::string star = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    CHECK(hajimi_http_rewrite_request(bytes(star), star.size(), 0, 1, nullptr, 0, output.data(), output.size(), &info).status == HAJIMI_CODEC_OK);
    CHECK(info.target_form == HAJIMI_HTTP_TARGET_ASTERISK && std::memcmp(output.data(), "OPTIONS * HTTP/1.1\r\n", 20) == 0);
    return true;
}

bool testMalformedHTTP() {
    const char *invalid[] = {
        "CONNECT example.com HTTP/1.1\r\n\r\n",
        "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
        "CONNECT example.com:65536 HTTP/1.1\r\n\r\n",
        "CONNECT example.com:+80 HTTP/1.1\r\n\r\n",
        "CONNECT example.com: HTTP/1.1\r\n\r\n",
        "CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n",
        "CONNECT [2001:db8::1]:443:80 HTTP/1.1\r\n\r\n",
        "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
        "GET http://example.com/#fragment HTTP/1.1\r\n\r\n",
        "GET http://[example.com]/ HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        "POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: content-length\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: HOST\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: close,,x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nProxy-Authorization: secret\r\n continuation\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nProxy-Authorization : secret\r\n\r\n",
        "GET / HTTP/1.1\r\nHost:\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\nHost: a\n\n",
        "GET / HTTP/1.1\rXHost: a\r\n\r\n",
        "\r\n"
    };
    hajimi_http_request info{};
    for (const char *text : invalid) {
        info.header_length = 999;
        CHECK(hajimi_http_parse_request(bytes(text), std::strlen(text), 0, &info).status == HAJIMI_CODEC_INVALID);
        CHECK(info.header_length == 999);
    }
    const char nullHeader[] = "GET / HTTP/1.1\r\nHost: a\r\nX: a\0b\r\n\r\n";
    CHECK(hajimi_http_parse_request(bytes(nullHeader), sizeof(nullHeader) - 1, 0, &info).status == HAJIMI_CODEC_INVALID);
    const std::string valid = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    CHECK(hajimi_http_parse_request(bytes(valid), valid.size(), 0, &info).status == HAJIMI_CODEC_OK);
    CHECK(hajimi_http_parse_request(bytes(valid), valid.size(), valid.size() - 1, &info).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_http_parse_request(bytes(valid), valid.size(), 65537, &info).status == HAJIMI_CODEC_INVALID);
    const std::string longLine = "GET /" + std::string(8192, 'a') + " HTTP/1.1\r\nHost: a\r\n\r\n";
    CHECK(hajimi_http_parse_request(bytes(longLine), longLine.size(), 0, &info).status == HAJIMI_CODEC_LIMIT);
    std::string fields = "GET / HTTP/1.1\r\nHost: a\r\n";
    for (size_t i = 0; i < 128; ++i) { fields += "X: a\r\n"; }
    fields += "\r\n";
    CHECK(hajimi_http_parse_request(bytes(fields), fields.size(), 0, &info).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_http_parse_request(nullptr, 1, 0, &info).status == HAJIMI_CODEC_INVALID);
    CHECK(hajimi_http_parse_request(nullptr, 0, 0, &info).status == HAJIMI_CODEC_NEED_MORE);
    return true;
}

bool testSOCKS() {
    std::array<uint8_t, 1024> output{};
    const char *hosts[] = {"192.0.2.1", "2001:db8::1", "example.com", "\xe4\xbe\x8b.example"};
    for (const char *host : hosts) {
        hajimi_address a{}, decoded{}; CHECK(make(host, 443, a));
        auto result = hajimi_socks5_encode_address(&a, output.data(), output.size());
        CHECK(result.status == HAJIMI_CODEC_OK);
        const size_t size = result.written;
        for (size_t n = 0; n < size; ++n) {
            decoded.port = 123;
            result = hajimi_socks5_parse_address(output.data(), n, &decoded);
            CHECK(result.status == HAJIMI_CODEC_NEED_MORE && result.needed > n && decoded.port == 123);
        }
        CHECK(hajimi_socks5_parse_address(output.data(), size, &decoded).status == HAJIMI_CODEC_OK);
        CHECK(sameAddress(a, decoded));
        for (uint8_t cmd = 1; cmd <= 3; ++cmd) {
            result = hajimi_socks5_encode_request(cmd, &a, output.data(), output.size()); CHECK(result.status == HAJIMI_CODEC_OK);
            const size_t count = result.written; uint8_t command = 0;
            CHECK(hajimi_socks5_parse_request(output.data(), count, &command, &decoded).status == HAJIMI_CODEC_OK);
            CHECK(command == cmd && sameAddress(a, decoded));
        }
        const uint8_t body[] = {0, 0xff, 1, 2}; hajimi_udp_frame frame{};
        result = hajimi_socks5_encode_udp(&a, body, sizeof(body), output.data(), output.size()); CHECK(result.status == HAJIMI_CODEC_OK);
        const size_t packetSize = result.written;
        CHECK(hajimi_socks5_parse_udp(output.data(), packetSize, &frame).status == HAJIMI_CODEC_OK);
        CHECK(sameAddress(a, frame.target) && frame.payload_length == sizeof(body));
        CHECK(std::memcmp(output.data() + frame.payload_offset, body, sizeof(body)) == 0);
        for (size_t n = 0; n < frame.payload_offset; ++n) {
            CHECK(hajimi_socks5_parse_udp(output.data(), n, &frame).status == HAJIMI_CODEC_NEED_MORE);
        }
        output[2] = 1; CHECK(hajimi_socks5_parse_udp(output.data(), packetSize, &frame).status == HAJIMI_CODEC_UNSUPPORTED);
        output[2] = 0; output[0] = 1; CHECK(hajimi_socks5_parse_udp(output.data(), packetSize, &frame).status == HAJIMI_CODEC_INVALID);
    }
    uint8_t selected = 1;
    const uint8_t greeting[] = {5, 2, 2, 0, 0xde, 0xad};
    auto result = hajimi_socks5_parse_greeting(greeting, sizeof(greeting), &selected);
    CHECK(result.status == HAJIMI_CODEC_OK && result.consumed == 4 && selected == 0);
    CHECK(hajimi_socks5_parse_greeting(greeting, 3, &selected).needed == 4);
    const uint8_t authOnly[] = {5, 1, 2}; CHECK(hajimi_socks5_parse_greeting(authOnly, sizeof(authOnly), &selected).status == HAJIMI_CODEC_OK && selected == 0xff);
    const uint8_t noMethods[] = {5, 0}; CHECK(hajimi_socks5_parse_greeting(noMethods, sizeof(noMethods), &selected).status == HAJIMI_CODEC_INVALID);
    const uint8_t badAddress[] = {3, 0, 0, 80}; hajimi_address a{};
    CHECK(hajimi_socks5_parse_address(badAddress, sizeof(badAddress), &a).status == HAJIMI_CODEC_INVALID);
    const uint8_t badUTF8[] = {3, 2, 0xc0, 0x80, 0, 80};
    CHECK(hajimi_socks5_parse_address(badUTF8, sizeof(badUTF8), &a).status == HAJIMI_CODEC_INVALID);
    const uint8_t numericDomain[] = {3, 9, '1','2','7','.','0','.','0','.','1',0,80};
    CHECK(hajimi_socks5_parse_address(numericDomain, sizeof(numericDomain), &a).status == HAJIMI_CODEC_OK && a.type == HAJIMI_ADDRESS_DOMAIN);
    CHECK(hajimi_socks5_encode_address(&a, output.data(), output.size()).status == HAJIMI_CODEC_OK);
    CHECK(std::memcmp(output.data(), numericDomain, sizeof(numericDomain)) == 0);
    const uint8_t reserved[] = {5, 1, 1, 1}; uint8_t command = 0;
    CHECK(hajimi_socks5_parse_request(reserved, sizeof(reserved), &command, &a).status == HAJIMI_CODEC_INVALID);
    return true;
}

bool testVLESSAndTrojan() {
    std::array<uint8_t, 2048> output; output.fill(0xcc);
    uint8_t uuid[16]; for (size_t i = 0; i < 16; ++i) { uuid[i] = static_cast<uint8_t>(i); }
    hajimi_address target{}; CHECK(make("example.com", 443, target));
    auto result = hajimi_vless_encode_request(uuid, nullptr, 0, 1, &target, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 34);
    CHECK(output[0] == 0 && std::memcmp(output.data() + 1, uuid, 16) == 0);
    CHECK(output[17] == 0 && output[18] == 1 && output[19] == 1 && output[20] == 0xbb);
    CHECK(output[21] == 2 && output[22] == 11 && std::memcmp(output.data() + 23, "example.com", 11) == 0);
    result = hajimi_vless_encode_request(uuid, nullptr, 0, 3, nullptr, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 19 && output[18] == 3);
    const uint8_t addons[] = {0x0a, 0x02, 'x', 'y'};
    result = hajimi_vless_encode_request(uuid, addons, sizeof(addons), 3, nullptr, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 23 && output[17] == 4 && output[22] == 3);
    CHECK(std::memcmp(output.data() + 18, addons, sizeof(addons)) == 0);
    CHECK(make("2001:db8::1", 53, target));
    result = hajimi_vless_encode_request(uuid, nullptr, 0, 2, &target, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 38 && output[18] == 2 && output[21] == 3);
    CHECK(hajimi_vless_encode_request(uuid, nullptr, 0, 4, &target, output.data(), output.size()).status == HAJIMI_CODEC_UNSUPPORTED);
    CHECK(hajimi_vless_encode_request(uuid, nullptr, 1, 1, &target, output.data(), output.size()).status == HAJIMI_CODEC_INVALID);
    uint8_t digest[56]; std::memset(digest, 'A', sizeof(digest));
    result = hajimi_trojan_encode_request(digest, 1, &target, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 80);
    CHECK(unchanged(output.data(), 56, 'a') && output[56] == '\r' && output[57] == '\n' && output[58] == 1);
    CHECK(output[59] == 4 && output[78] == '\r' && output[79] == '\n');
    digest[55] = 'G'; output.fill(0xcc);
    CHECK(hajimi_trojan_encode_request(digest, 1, &target, output.data(), output.size()).status == HAJIMI_CODEC_INVALID);
    CHECK(unchanged(output.data(), output.size(), 0xcc)); digest[55] = 'A';
    CHECK(hajimi_trojan_encode_request(digest, 2, &target, output.data(), output.size()).status == HAJIMI_CODEC_UNSUPPORTED);
    const uint8_t body[] = {0xde, 0xad, 0, 0xff}; hajimi_udp_frame frame{};
    result = hajimi_trojan_encode_udp(&target, body, sizeof(body), output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK); const size_t size = result.written;
    output[size] = 0x99; // A coalesced NEXT frame/application prefix must not be consumed.
    result = hajimi_trojan_parse_udp(output.data(), size + 1, &frame);
    CHECK(result.status == HAJIMI_CODEC_OK && result.consumed == size && sameAddress(target, frame.target));
    CHECK(frame.payload_length == sizeof(body) && std::memcmp(output.data() + frame.payload_offset, body, sizeof(body)) == 0);
    for (size_t n = 0; n < size; ++n) { CHECK(hajimi_trojan_parse_udp(output.data(), n, &frame).status == HAJIMI_CODEC_NEED_MORE); }
    output[frame.payload_offset - 1] = 'x';
    CHECK(hajimi_trojan_parse_udp(output.data(), size, &frame).status == HAJIMI_CODEC_INVALID);
    return true;
}

bool testVarints() {
    const uint64_t values[] = {0, 1, 37, 63, 64, 15293, 16383, 16384, 494878333,
        1073741823, 1073741824, 151288809941952652, (uint64_t{1} << 62) - 1};
    std::array<uint8_t, 16> output;
    for (uint64_t value : values) {
        auto result = hajimi_quic_varint_encode(value, output.data(), output.size());
        CHECK(result.status == HAJIMI_CODEC_OK); const size_t size = result.written;
        uint64_t decoded = 0;
        result = hajimi_quic_varint_decode(output.data(), size, &decoded);
        CHECK(result.status == HAJIMI_CODEC_OK && result.consumed == size && decoded == value);
        for (size_t n = 0; n < size; ++n) {
            decoded = 123;
            result = hajimi_quic_varint_decode(output.data(), n, &decoded);
            CHECK(result.status == HAJIMI_CODEC_NEED_MORE && result.needed > n && decoded == 123);
        }
        output.fill(0xcc); result = hajimi_quic_varint_encode(value, output.data(), size - 1);
        CHECK(result.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && result.needed == size);
        CHECK(unchanged(output.data(), output.size(), 0xcc));
    }
    const uint8_t nonminimal[] = {0x40, 0x01}; uint64_t decoded = 0;
    CHECK(hajimi_quic_varint_decode(nonminimal, sizeof(nonminimal), &decoded).status == HAJIMI_CODEC_OK && decoded == 1);
    const uint8_t rfc[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    CHECK(hajimi_quic_varint_decode(rfc, sizeof(rfc), &decoded).status == HAJIMI_CODEC_OK && decoded == 151288809941952652);
    CHECK(hajimi_quic_varint_encode(uint64_t{1} << 62, output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_quic_varint_decode(nullptr, 1, &decoded).status == HAJIMI_CODEC_INVALID);
    return true;
}

bool testHysteriaAndTUIC() {
    std::array<uint8_t, 8192> output{}; hajimi_address target{}; CHECK(make("2001:db8::1", 443, target));
    const uint8_t body[] = {0, 0xff, 0x03, 0x00};
    const char auth[] = "auth";
    auto result = hajimi_hysteria1_encode_hello(0x0102030405060708ULL, 0x090a0b0c0d0e0f10ULL,
        bytes(auth), sizeof(auth) - 1, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 23 && output[0] == 3);
    for (size_t i = 1; i <= 16; ++i) { CHECK(output[i] == i); }
    CHECK(output[17] == 0 && output[18] == 4 && std::memcmp(output.data() + 19, "auth", 4) == 0);
    result = hajimi_hysteria1_encode_request(1, nullptr, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 5 && output[0] == 1 && unchanged(output.data() + 1, 4, 0));
    result = hajimi_hysteria1_encode_request(0, &target, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && output[0] == 0 && result.written == target.host_length + 5);
    for (int kind = 0; kind < 3; ++kind) {
        hajimi_udp_frame frame{};
        if (kind == 0) { result = hajimi_hysteria1_encode_udp(0x01020304, 0x0506, 0, 2, &target, body, sizeof(body), output.data(), output.size()); }
        else if (kind == 1) { result = hajimi_hysteria2_encode_udp(0x01020304, 0x0506, 0, 2, &target, body, sizeof(body), output.data(), output.size()); }
        else { result = hajimi_tuic5_encode_udp(0x0102, 0x0506, 0, 2, &target, body, sizeof(body), output.data(), output.size()); }
        CHECK(result.status == HAJIMI_CODEC_OK); const size_t size = result.written;
        auto parse = kind == 0 ? hajimi_hysteria1_parse_udp : kind == 1 ? hajimi_hysteria2_parse_udp : hajimi_tuic5_parse_udp;
        CHECK(parse(output.data(), size, &frame).status == HAJIMI_CODEC_OK);
        CHECK(sameAddress(target, frame.target) && frame.packet_id == 0x0506 && frame.fragment_index == 0 && frame.fragment_count == 2);
        CHECK(frame.session_id == (kind == 2 ? 0x0102u : 0x01020304u));
        CHECK(frame.payload_length == sizeof(body) && std::memcmp(output.data() + frame.payload_offset, body, sizeof(body)) == 0);
        const size_t requiredPrefix = kind == 1 ? frame.payload_offset : size;
        for (size_t n = 0; n < requiredPrefix; ++n) { CHECK(parse(output.data(), n, &frame).status == HAJIMI_CODEC_NEED_MORE); }
        if (kind != 1) { output[size] = 0; CHECK(parse(output.data(), size + 1, &frame).status == HAJIMI_CODEC_INVALID); }
    }
    result = hajimi_hysteria2_encode_request(&target, body, sizeof(body), output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && output[0] == 0x44 && output[1] == 1);
    uint64_t addressLength = 0; const auto addressSize = hajimi_quic_varint_decode(output.data() + 2, result.written - 2, &addressLength);
    CHECK(addressSize.status == HAJIMI_CODEC_OK && addressLength == std::strlen("[2001:db8::1]:443"));
    CHECK(std::memcmp(output.data() + 2 + addressSize.consumed, "[2001:db8::1]:443", addressLength) == 0);
    const uint8_t response[] = {0, 2, 'o', 'k', 3, 'x', 'y', 'z', 0xee}; uint8_t status = 99; size_t messageOffset = 0, messageLength = 0;
    result = hajimi_hysteria2_parse_response(response, sizeof(response), &status, &messageOffset, &messageLength);
    CHECK(result.status == HAJIMI_CODEC_OK && result.consumed == 8 && status == 0 && messageOffset == 2 && messageLength == 2);
    for (size_t n = 0; n < 8; ++n) { CHECK(hajimi_hysteria2_parse_response(response, n, &status, &messageOffset, &messageLength).status == HAJIMI_CODEC_NEED_MORE); }
    result = hajimi_tuic5_encode_udp(1, 2, 1, 2, nullptr, body, sizeof(body), output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && output[6] == 2 && output[7] == 1 && output[10] == 0xff);
    hajimi_udp_frame frame{}; CHECK(hajimi_tuic5_parse_udp(output.data(), result.written, &frame).status == HAJIMI_CODEC_OK);
    CHECK(frame.has_address == 0 && frame.target.type == HAJIMI_ADDRESS_NONE);
    output[7] = 0; CHECK(hajimi_tuic5_parse_udp(output.data(), result.written, &frame).status == HAJIMI_CODEC_INVALID);
    CHECK(hajimi_tuic5_encode_udp(1, 2, 0, 2, nullptr, body, sizeof(body), output.data(), output.size()).status == HAJIMI_CODEC_INVALID);
    CHECK(hajimi_hysteria2_encode_udp(1, 2, 2, 2, &target, body, sizeof(body), output.data(), output.size()).status == HAJIMI_CODEC_INVALID);
    uint8_t uuid[16], token[32]; std::memset(uuid, 1, sizeof(uuid)); std::memset(token, 2, sizeof(token));
    result = hajimi_tuic5_encode_authenticate(uuid, token, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && result.written == 50 && output[0] == 5 && output[1] == 0);
    CHECK(std::memcmp(output.data() + 2, uuid, sizeof(uuid)) == 0 && std::memcmp(output.data() + 18, token, sizeof(token)) == 0);
    result = hajimi_tuic5_encode_connect(&target, output.data(), output.size());
    CHECK(result.status == HAJIMI_CODEC_OK && output[0] == 5 && output[1] == 1 && output[2] == 2);
    hajimi_address decoded{};
    CHECK(hajimi_tuic5_parse_address(output.data() + 2, result.written - 2, &decoded).status == HAJIMI_CODEC_OK && sameAddress(target, decoded));
    CHECK(hajimi_tuic5_encode_address(nullptr, output.data(), output.size()).status == HAJIMI_CODEC_OK && output[0] == 0xff);
    CHECK(hajimi_tuic5_parse_address(output.data(), 1, &decoded).status == HAJIMI_CODEC_OK && decoded.type == HAJIMI_ADDRESS_NONE);
    return true;
}

bool testLimitsAndFuzz() {
    std::array<uint8_t, 8192> output; output.fill(0xcc);
    hajimi_address a{}; CHECK(make("example.com", 443, a));
    std::vector<uint8_t> huge(65536, 1);
    CHECK(hajimi_socks5_encode_udp(&a, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_trojan_encode_udp(&a, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_hysteria1_encode_udp(1, 2, 0, 1, &a, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_hysteria2_encode_udp(1, 2, 0, 1, &a, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_tuic5_encode_udp(1, 2, 0, 1, &a, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_hysteria1_encode_hello(1, 1, huge.data(), huge.size(), output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(hajimi_hysteria2_encode_request(&a, huge.data(), 4097, output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    uint8_t uuid[16]{};
    CHECK(hajimi_vless_encode_request(uuid, huge.data(), 256, 1, &a, output.data(), output.size()).status == HAJIMI_CODEC_LIMIT);
    CHECK(unchanged(output.data(), output.size(), 0xcc));
    auto result = hajimi_socks5_encode_address(&a, nullptr, 0);
    CHECK(result.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && result.needed == 15);
    CHECK(hajimi_socks5_encode_address(&a, nullptr, 100).status == HAJIMI_CODEC_INVALID);
    result = hajimi_socks5_encode_address(&a, output.data(), result.needed - 1);
    CHECK(result.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && unchanged(output.data(), output.size(), 0xcc));
    CHECK(hajimi_socks5_encode_address(&a, reinterpret_cast<uint8_t *>(&a), sizeof(a)).status == HAJIMI_CODEC_INVALID);
    // A legal non-minimal varint containing a huge claimed address/message
    // length must hit the limit before integer conversion or buffer indexing.
    std::array<uint8_t, 20> claim{}; uint64_t hugeValue = (uint64_t{1} << 62) - 1;
    hajimi_quic_varint_encode(hugeValue, claim.data() + 1, 8);
    uint8_t status = 0; size_t mo = 0, ml = 0;
    CHECK(hajimi_hysteria2_parse_response(claim.data(), 9, &status, &mo, &ml).status == HAJIMI_CODEC_LIMIT);
    claim[6] = 0; claim[7] = 1; hajimi_quic_varint_encode(hugeValue, claim.data() + 8, 8);
    hajimi_udp_frame frame{};
    CHECK(hajimi_hysteria2_parse_udp(claim.data(), 16, &frame).status == HAJIMI_CODEC_LIMIT);
    // Deterministic malformed/truncated-byte fuzzing. No sockets, entropy,
    // configuration changes, external server, or unbounded allocations.
    std::array<uint8_t, 512> input{}; uint32_t state = 0x12345678;
    auto random = [&state]() {
        state = state * 1664525u + 1013904223u; return state;
    };
    auto validResult = [](hajimi_codec_result r, size_t n) {
        if (r.status == HAJIMI_CODEC_OK) { return r.consumed <= n && r.written == 0; }
        if (r.status == HAJIMI_CODEC_NEED_MORE) { return r.needed > n && r.consumed == 0 && r.written == 0; }
        return r.status < 0 && r.consumed == 0 && r.needed == 0 && r.written == 0;
    };
    for (size_t iteration = 0; iteration < 10000; ++iteration) {
        const size_t n = random() % (input.size() + 1);
        for (size_t i = 0; i < n; ++i) { input[i] = static_cast<uint8_t>(random() >> 24); }
        hajimi_http_request request{}; hajimi_address address{}; uint8_t command = 0; uint64_t value = 0;
        CHECK(validResult(hajimi_http_parse_request(input.data(), n, 0, &request), n));
        CHECK(validResult(hajimi_socks5_parse_greeting(input.data(), n, &command), n));
        CHECK(validResult(hajimi_socks5_parse_request(input.data(), n, &command, &address), n));
        CHECK(validResult(hajimi_socks5_parse_address(input.data(), n, &address), n));
        CHECK(validResult(hajimi_tuic5_parse_address(input.data(), n, &address), n));
        CHECK(validResult(hajimi_quic_varint_decode(input.data(), n, &value), n));
        CHECK(validResult(hajimi_hysteria2_parse_response(input.data(), n, &status, &mo, &ml), n));
        using Parse = hajimi_codec_result (*)(const uint8_t *, size_t, hajimi_udp_frame *);
        const Parse parsers[] = {hajimi_socks5_parse_udp, hajimi_trojan_parse_udp,
            hajimi_hysteria1_parse_udp, hajimi_hysteria2_parse_udp, hajimi_tuic5_parse_udp};
        for (Parse parse : parsers) {
            frame = {}; result = parse(input.data(), n, &frame); CHECK(validResult(result, n));
            if (result.status == HAJIMI_CODEC_OK) {
                CHECK(frame.payload_offset <= n && frame.payload_length <= n - frame.payload_offset);
                CHECK(frame.target.host_length <= HAJIMI_CODEC_MAX_HOST);
            }
        }
    }
    return true;
}

bool testCarrierAndFakeIPCodecs() {
    // 1. WebSocket frame encoding & 64-bit word-strided XOR masking
    const uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    const uint8_t *ws_payload = reinterpret_cast<const uint8_t *>("Hello, Hajimi C++17 WebSocket Fast!");
    const size_t ws_len = 35;
    uint8_t ws_out[64]{};
    auto res = hajimi_ws_encode_frame(1, 0x2, 1, mask, ws_payload, ws_len, ws_out, sizeof(ws_out));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 2 + 4 + ws_len);
    CHECK(ws_out[0] == 0x82 && ws_out[1] == (0x80 | 35));
    hajimi_ws_xor_mask(ws_out + 6, ws_len, mask);
    CHECK(std::memcmp(ws_out + 6, ws_payload, ws_len) == 0);

    // 2. Mux.Cool & XUDP encoding
    hajimi_address addr{};
    res = hajimi_address_from_host(reinterpret_cast<const uint8_t *>("example.com"), 11, 53, &addr);
    CHECK(res.status == HAJIMI_CODEC_OK);
    uint8_t mux_out[64]{};
    res = hajimi_mux_encode_frame(7, 1, 1, 1, &addr, reinterpret_cast<const uint8_t *>("abc"), 3, mux_out, sizeof(mux_out));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 2 + 20 + 2 + 3);
    const uint8_t gid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t xudp_out[64]{};
    res = hajimi_xudp_encode_frame(1, gid, &addr, reinterpret_cast<const uint8_t *>("dns"), 3, xudp_out, sizeof(xudp_out));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 2 + 28 + 2 + 3);

    // 2b. Windowed Traffic Rate Meter & Compact Formatter
    hajimi_rate_meter meter{};
    hajimi_rate_meter_init(&meter, 1.0);
    hajimi_rate_meter_observe(&meter, 0, 0.0);
    hajimi_rate_meter_observe(&meter, 1000, 1.0);
    char rate_buf[32]{};
    CHECK(hajimi_rate_format_compact(meter.current_bps, rate_buf, sizeof(rate_buf)) == 4);
    CHECK(std::strcmp(rate_buf, "1.0K") == 0);
    CHECK(hajimi_rate_format_compact(0.0, rate_buf, sizeof(rate_buf)) == 2 && std::strcmp(rate_buf, "0B") == 0);
    CHECK(hajimi_rate_format_compact(12300000.0, rate_buf, sizeof(rate_buf)) == 3 && std::strcmp(rate_buf, "12M") == 0);

    // 3. mKCP FNV-1a and SimpleAuthenticator rolling XOR round-trip + Xray known-answer vector
    const uint8_t xray_seg[23] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x05, 'h', 'e', 'l', 'l', 'o'
    };
    const uint8_t xray_expected[29] = {
        0x35, 0x9f, 0x08, 0x19, 0x35, 0x88, 0x1a, 0x2d,
        0x34, 0x88, 0x1a, 0x2d, 0x37, 0x60, 0x1a, 0x2d,
        0x37, 0x60, 0x1a, 0x2d, 0x37, 0x60, 0x1a, 0x28,
        0x5f, 0x05, 0x76, 0x44, 0x30
    };
    uint8_t xray_sealed[32]{}, xray_opened[32]{};
    res = hajimi_mkcp_seal_simple(xray_seg, sizeof(xray_seg), xray_sealed, sizeof(xray_sealed));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 29);
    CHECK(std::memcmp(xray_sealed, xray_expected, 29) == 0);
    res = hajimi_mkcp_open_simple(xray_sealed, 29, xray_opened, sizeof(xray_opened));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 23);
    CHECK(std::memcmp(xray_opened, xray_seg, 23) == 0);
    const uint8_t *plain = reinterpret_cast<const uint8_t *>("mKCP segment payload verified in C++17 native");
    const size_t plain_len = 45;
    uint8_t sealed[64]{}, opened[64]{};
    res = hajimi_mkcp_seal_simple(plain, plain_len, sealed, sizeof(sealed));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 6 + plain_len);
    res = hajimi_mkcp_open_simple(sealed, res.written, opened, sizeof(opened));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == plain_len);
    CHECK(std::memcmp(opened, plain, plain_len) == 0);
    sealed[10] ^= 0x01;
    CHECK(hajimi_mkcp_open_simple(sealed, 6 + plain_len, opened, sizeof(opened)).status == HAJIMI_CODEC_INVALID);

    // 4. Fake-IP DNS wire question parser & reply builder
    const uint8_t dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w', 0x07, 'y', 'o', 'u', 't', 'u', 'b', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    hajimi_fakeip_question q{};
    res = hajimi_fakeip_parse_question(dns_query, sizeof(dns_query), &q);
    CHECK(res.status == HAJIMI_CODEC_OK && q.qtype == 1 && q.qclass == 1);
    CHECK(q.host_length == 15 && std::memcmp(q.host, "www.youtube.com", 15) == 0);
    // Verify mixed-case QNAME normalization per HajimiProtocolCXX.h contract
    const uint8_t dns_query_mixed[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'W', 'w', 'W', 0x07, 'Y', 'o', 'U', 't', 'U', 'b', 'E', 0x03, 'C', 'o', 'M', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    hajimi_fakeip_question q_mixed{};
    res = hajimi_fakeip_parse_question(dns_query_mixed, sizeof(dns_query_mixed), &q_mixed);
    CHECK(res.status == HAJIMI_CODEC_OK && q_mixed.host_length == 15);
    CHECK(std::memcmp(q_mixed.host, "www.youtube.com", 15) == 0);
    const uint8_t fake_ip[4] = {198, 19, 0, 2};
    uint8_t dns_reply[64]{};
    res = hajimi_fakeip_build_reply(dns_query, sizeof(dns_query), &q, 1, fake_ip, 60, dns_reply, sizeof(dns_reply));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query) + 16);
    CHECK(dns_reply[2] == 0x81 && dns_reply[3] == 0x80 && dns_reply[7] == 1);
    CHECK(std::memcmp(dns_reply + res.written - 4, fake_ip, 4) == 0);

    // 5. Mathematical primitives: Stafford Mix13 bijection, Jump Consistent Hash, and Smart Node Scorer
    const uint64_t h1 = hajimi_stafford_mix64(1ULL);
    const uint64_t h2 = hajimi_stafford_mix64(2ULL);
    CHECK(h1 != h2 && h1 != 0 && h2 != 0);
    // Verify Jump Consistent Hash minimal disruption property: when bucket count grows from N to N+1,
    // an existing key either stays in its current bucket (< N) or moves to bucket N.
    for (uint64_t k = 1; k <= 256; ++k) {
        const uint64_t mixed = hajimi_stafford_mix64(k);
        const uint32_t b10 = hajimi_jump_consistent_hash(mixed, 10);
        const uint32_t b11 = hajimi_jump_consistent_hash(mixed, 11);
        CHECK(b10 < 10 && b11 < 11);
        CHECK(b11 == b10 || b11 == 10);
    }

    // Verify Welford-West EWMVar + Cornish-Fisher Q90 + Beta-Binomial + Mathis Smart Node Scorer:
    // A stable 55ms node (zero jitter, 100% reliability) must have strictly lower cost than
    // a jittery/flaky node that occasionally hits 40ms but spikes to 300ms or drops probes.
    hajimi_smart_node_stats stable_node{}, flaky_node{};
    hajimi_smart_stats_init(&stable_node);
    hajimi_smart_stats_init(&flaky_node);
    for (int i = 0; i < 6; ++i) {
        hajimi_smart_stats_observe(&stable_node, 1, 0.055, 10.0 + i);
    }
    hajimi_smart_stats_observe(&flaky_node, 1, 0.040, 10.0);
    hajimi_smart_stats_observe(&flaky_node, 1, 0.280, 11.0);
    hajimi_smart_stats_observe(&flaky_node, 0, 0.0, 12.0);
    hajimi_smart_stats_observe(&flaky_node, 1, 0.045, 13.0);
    const double stable_cost = hajimi_smart_stats_cost(&stable_node, 16.0);
    const double flaky_cost = hajimi_smart_stats_cost(&flaky_node, 16.0);
    CHECK(stable_cost > 0.050 && stable_cost < 0.080);
    CHECK(flaky_cost > stable_cost * 1.5);

    // 6. Constant-time authenticator & backward clock-jump resilience
    const uint8_t secret_a[] = "hajimi-commercial-secret-2026";
    const uint8_t secret_b[] = "hajimi-commercial-secret-2026";
    const uint8_t secret_c[] = "hajimi-commercial-secret-2027";
    const uint8_t secret_short[] = "hajimi";
    CHECK(hajimi_constant_time_memcmp(secret_a, sizeof(secret_a) - 1, secret_b, sizeof(secret_b) - 1) == 1);
    CHECK(hajimi_constant_time_memcmp(secret_a, sizeof(secret_a) - 1, secret_c, sizeof(secret_c) - 1) == 0);
    CHECK(hajimi_constant_time_memcmp(secret_short, sizeof(secret_short) - 1, secret_a, sizeof(secret_a) - 1) == 0);
    CHECK(hajimi_constant_time_memcmp(nullptr, 0, nullptr, 0) == 1);
    CHECK(hajimi_constant_time_memcmp(nullptr, 0, secret_a, sizeof(secret_a) - 1) == 0);

    hajimi_rate_meter clock_meter{};
    hajimi_rate_meter_init(&clock_meter, 0.25);
    hajimi_rate_meter_observe(&clock_meter, 1000, 100.0);
    // Simulate backward NTP step from t=100.0 to t=90.0: meter must re-anchor and not freeze
    hajimi_rate_meter_observe(&clock_meter, 2000, 90.0);
    hajimi_rate_meter_observe(&clock_meter, 4500, 90.5);
    CHECK(clock_meter.current_bps > 4900.0 && clock_meter.current_bps < 5100.0);
    // Simulate traffic counter reset (cumulative_bytes < previous): current_bps must immediately reset to 0.0
    hajimi_rate_meter_observe(&clock_meter, 100, 91.0);
    CHECK(clock_meter.current_bps == 0.0);

    // 7. RFC 9250 DoQ (DNS over Dedicated QUIC) 2-octet framing & Message ID = 0x0000 normalization
    uint8_t doq_frame[128]{}, doq_decoded[128]{};
    uint16_t saved_id = 0;
    res = hajimi_dns_doq_encode_frame(dns_query, sizeof(dns_query), &saved_id, doq_frame, sizeof(doq_frame));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query) + 2);
    CHECK(saved_id == 0x1234);
    CHECK(doq_frame[0] == 0 && doq_frame[1] == sizeof(dns_query));
    CHECK(doq_frame[2] == 0 && doq_frame[3] == 0); // RFC 9250 §4.2.1 ID=0 on wire
    res = hajimi_dns_doq_decode_frame(doq_frame, res.written, saved_id, doq_decoded, sizeof(doq_decoded));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query));
    CHECK(std::memcmp(doq_decoded, dns_query, sizeof(dns_query)) == 0);
    // Non-zero wire ID in DoQ frame must be rejected per RFC 9250 §4.2.1
    doq_frame[3] = 1;
    CHECK(hajimi_dns_doq_decode_frame(doq_frame, sizeof(dns_query) + 2, saved_id, doq_decoded, sizeof(doq_decoded)).status == HAJIMI_CODEC_INVALID);

    // 8. RFC 7830 / RFC 8467 EDNS(0) Block-Length Padding (128B query / 468B response alignment)
    uint8_t padded_q128[256]{};
    res = hajimi_dns_apply_edns_padding(dns_query, sizeof(dns_query), 128, 1232, padded_q128, sizeof(padded_q128));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 128);
    CHECK(padded_q128[11] == 1); // ARCOUNT incremented to 1
    uint8_t padded_r468[512]{};
    res = hajimi_dns_apply_edns_padding(dns_reply, sizeof(dns_query) + 16, 468, 1232, padded_r468, sizeof(padded_r468));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 468);
    // Re-padding an already padded 128B query to 256B replaces Option 12 cleanly without duplicate padding options
    uint8_t repadded_q256[512]{};
    res = hajimi_dns_apply_edns_padding(padded_q128, 128, 256, 1232, repadded_q256, sizeof(repadded_q256));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 256);
    // Verify EDNS OPT UDP payload limit smaller than caller max_payload is strictly respected
    uint8_t small_opt_msg[64]{};
    std::memcpy(small_opt_msg, dns_query, sizeof(dns_query));
    small_opt_msg[11] = 1; // ARCOUNT = 1
    const uint8_t opt_512[] = {0x00, 0x00, 41, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // UDP payload = 512
    std::memcpy(small_opt_msg + sizeof(dns_query), opt_512, sizeof(opt_512));
    uint8_t capped_out[1024]{};
    res = hajimi_dns_apply_edns_padding(small_opt_msg, sizeof(dns_query) + sizeof(opt_512), 1024, 1232, capped_out, sizeof(capped_out));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 512);

    // 9. RFC 7871 EDNS Client Subnet (ECS) Privacy Sanitization (Strip, /0 Anonymize, /24 Truncate)
    uint8_t query_with_ecs[128]{};
    std::memcpy(query_with_ecs, dns_query, sizeof(dns_query));
    query_with_ecs[11] = 1; // ARCOUNT = 1
    // Append root OPT with ECS Option 8: IPv4 (family=1), source prefix=32, scope=0, IP=203.0.113.45
    const uint8_t opt_ecs[] = {
        0x00, 0x00, 41, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 12,
        0x00, 8, 0x00, 8, 0x00, 1, 32, 0, 203, 0, 113, 45
    };
    std::memcpy(query_with_ecs + sizeof(dns_query), opt_ecs, sizeof(opt_ecs));
    const size_t ecs_msg_len = sizeof(dns_query) + sizeof(opt_ecs);

    uint8_t ecs_stripped[128]{}, ecs_anon[128]{}, ecs_trunc[128]{};
    res = hajimi_dns_sanitize_ecs(query_with_ecs, ecs_msg_len, HAJIMI_ECS_MODE_STRIP, ecs_stripped, sizeof(ecs_stripped));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query) + 11);
    CHECK(ecs_stripped[sizeof(dns_query) + 9] == 0 && ecs_stripped[sizeof(dns_query) + 10] == 0); // RDLENGTH == 0

    res = hajimi_dns_sanitize_ecs(query_with_ecs, ecs_msg_len, HAJIMI_ECS_MODE_ANONYMIZE_ZERO, ecs_anon, sizeof(ecs_anon));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query) + 11 + 8);
    CHECK(ecs_anon[res.written - 2] == 0 && ecs_anon[res.written - 1] == 0); // source=0, scope=0

    res = hajimi_dns_sanitize_ecs(query_with_ecs, ecs_msg_len, HAJIMI_ECS_MODE_TRUNCATE_PRIVACY, ecs_trunc, sizeof(ecs_trunc));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == sizeof(dns_query) + 11 + 11);
    CHECK(ecs_trunc[res.written - 5] == 24); // Clamped from /32 to /24
    CHECK(ecs_trunc[res.written - 3] == 203 && ecs_trunc[res.written - 2] == 0 && ecs_trunc[res.written - 1] == 113);

    // 10. Multi-Armed Bandit UCB1 + Cornish-Fisher Tail + Hot Connection Discount Scorer
    const double score_cold = hajimi_dns_ucb1_score(45.0, 25.0, 16.0, 0.0, 64, 16, 0);
    const double score_hot  = hajimi_dns_ucb1_score(45.0, 25.0, 16.0, 0.0, 64, 16, 1);
    const double score_unexplored = hajimi_dns_ucb1_score(45.0, 25.0, 16.0, 0.0, 64, 2, 0);
    const double score_failing = hajimi_dns_ucb1_score(45.0, 25.0, 2.0, 8.0, 64, 10, 0);
    CHECK(score_hot < score_cold);
    CHECK(score_unexplored < score_cold); // UCB1 exploration bonus favors under-sampled healthy candidate
    CHECK(score_failing > score_cold * 5.0);

    // 11. IETF MASQUE (RFC 9298 CONNECT-UDP & RFC 9297 HTTP/3 Datagram & Capsule)
    const uint8_t udp_payload[] = {0xde, 0xad, 0xbe, 0xef, 0x42};
    uint8_t masque_dgram[64]{};
    res = hajimi_masque_encode_datagram(44u, udp_payload, sizeof(udp_payload), masque_dgram, sizeof(masque_dgram));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 2 + sizeof(udp_payload));
    uint64_t decoded_sid = 0;
    size_t pay_off = 0, pay_len = 0;
    res = hajimi_masque_decode_datagram(masque_dgram, res.written, &decoded_sid, &pay_off, &pay_len);
    CHECK(res.status == HAJIMI_CODEC_OK && decoded_sid == 44u && pay_len == sizeof(udp_payload));
    CHECK(std::memcmp(masque_dgram + pay_off, udp_payload, sizeof(udp_payload)) == 0);
    // Non-multiple-of-4 stream ID must be rejected
    CHECK(hajimi_masque_encode_datagram(45u, udp_payload, sizeof(udp_payload), masque_dgram, sizeof(masque_dgram)).status == HAJIMI_CODEC_INVALID);

    uint8_t masque_cap[64]{};
    res = hajimi_masque_encode_capsule(udp_payload, sizeof(udp_payload), masque_cap, sizeof(masque_cap));
    CHECK(res.status == HAJIMI_CODEC_OK && res.written == 3 + sizeof(udp_payload));
    size_t cap_off = 0, cap_len = 0;
    res = hajimi_masque_decode_capsule(masque_cap, res.written, &cap_off, &cap_len);
    CHECK(res.status == HAJIMI_CODEC_OK && cap_len == sizeof(udp_payload));
    CHECK(std::memcmp(masque_cap + cap_off, udp_payload, sizeof(udp_payload)) == 0);
    return true;
}

} // namespace

int main() {
    if (!testAddresses() || !testHTTP() || !testMalformedHTTP() || !testSOCKS() ||
        !testVLESSAndTrojan() || !testVarints() || !testHysteriaAndTUIC() || !testCarrierAndFakeIPCodecs() || !testLimitsAndFuzz()) { return 1; }
    std::printf("Protocol C++ codecs: %zu checks passed\n", checks); return 0;
}
