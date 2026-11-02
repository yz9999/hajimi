#include "HajimiRoutingCXX.h"
#include <cstring>

namespace {

struct AsciiTables {
    uint8_t lower[256]{};
    bool valid[256]{};
    constexpr AsciiTables() {
        for (int i = 0; i < 256; ++i) {
            lower[i] = (i >= 'A' && i <= 'Z') ? static_cast<uint8_t>(i + ('a' - 'A')) : static_cast<uint8_t>(i);
            valid[i] = (i >= 0x20 && i <= 0x7e);
        }
    }
};
constexpr AsciiTables kAscii{};

constexpr uint8_t lower(uint8_t value) noexcept {
    return kAscii.lower[value];
}

bool validAscii(const uint8_t *bytes, size_t length) noexcept {
    if (length != 0 && bytes == nullptr) { return false; }
    size_t index = 0;
    // 64-bit SWAR parallel validator: checks 8 bytes per register operation
    // for printable ASCII [0x20, 0x7e] (no high bit, no byte < 0x20, no 0x7f).
    while (index + 8 <= length) {
        uint64_t w = 0;
        std::memcpy(&w, bytes + index, 8);
        const uint64_t high = w & 0x8080808080808080ULL;
        const uint64_t lt20 = (w - 0x2020202020202020ULL) & ~w & 0x8080808080808080ULL;
        const uint64_t x7f = w ^ 0x7f7f7f7f7f7f7f7fULL;
        const uint64_t eq7f = (x7f - 0x0101010101010101ULL) & ~x7f & 0x8080808080808080ULL;
        if ((high | lt20 | eq7f) != 0) {
            return false;
        }
        index += 8;
    }
    for (; index < length; ++index) {
        if (!kAscii.valid[bytes[index]]) { return false; }
    }
    return true;
}

void stripDots(const uint8_t *bytes, size_t &start, size_t &end) noexcept {
    while (start < end && bytes[start] == '.') { ++start; }
    while (start < end && bytes[end - 1] == '.') { --end; }
}

bool equalFolded(const uint8_t *left, const uint8_t *right,
                 size_t length) noexcept {
    size_t index = 0;
    // 64-bit SWAR fast path: 8-byte exact match in 1 register op, or early-exit
    // when differing bits lie outside the ASCII case bit (0x20).
    while (index + 8 <= length) {
        uint64_t w1 = 0, w2 = 0;
        std::memcpy(&w1, left + index, 8);
        std::memcpy(&w2, right + index, 8);
        const uint64_t diff = w1 ^ w2;
        if (diff != 0) {
            if ((diff & ~0x2020202020202020ULL) != 0) {
                return false;
            }
            const uint64_t f1 = w1 | (((w1 + 0x3f3f3f3f3f3f3f3fULL) & (0xdadadadadadadadaULL - w1) & 0x8080808080808080ULL) >> 2);
            const uint64_t f2 = w2 | (((w2 + 0x3f3f3f3f3f3f3f3fULL) & (0xdadadadadadadadaULL - w2) & 0x8080808080808080ULL) >> 2);
            if (f1 != f2) {
                return false;
            }
        }
        index += 8;
    }
    for (; index < length; ++index) {
        if (kAscii.lower[left[index]] != kAscii.lower[right[index]]) { return false; }
    }
    return true;
}

// A zero-length pattern matches even if the caller passed a NULL pointer;
// never perform pointer arithmetic on that pointer.
bool equalAt(const uint8_t *left, size_t leftOffset,
             const uint8_t *right, size_t rightOffset,
             size_t length) noexcept {
    if (length == 0) { return true; }
    return equalFolded(left + leftOffset, right + rightOffset, length);
}

struct TestVector {
    const char *host;
    size_t hostLength;
    const char *pattern;
    size_t patternLength;
    int32_t kind;
    int32_t expected;
};

#define TEST(h, p, kind, expected) \
    {h, sizeof(h) - 1, p, sizeof(p) - 1, kind, expected}

} // namespace

extern "C" int32_t hajimi_domain_match_ascii(
    const uint8_t *host, size_t hostLength,
    const uint8_t *pattern, size_t patternLength,
    int32_t kind) {
    if (kind != HAJIMI_DOMAIN_EXACT && kind != HAJIMI_DOMAIN_SUFFIX &&
        kind != HAJIMI_DOMAIN_KEYWORD) {
        return HAJIMI_DOMAIN_FALLBACK;
    }
    if (!validAscii(host, hostLength) || !validAscii(pattern, patternLength)) {
        return HAJIMI_DOMAIN_FALLBACK;
    }

    size_t hostStart = 0;
    size_t hostEnd = hostLength;
    stripDots(host, hostStart, hostEnd);
    const size_t normalizedHostLength = hostEnd - hostStart;

    if (kind == HAJIMI_DOMAIN_EXACT) {
        return normalizedHostLength == patternLength &&
               equalAt(host, hostStart, pattern, 0, patternLength);
    }

    if (kind == HAJIMI_DOMAIN_SUFFIX) {
        size_t patternStart = 0;
        size_t patternEnd = patternLength;
        stripDots(pattern, patternStart, patternEnd);
        const size_t normalizedPatternLength = patternEnd - patternStart;

        if (normalizedHostLength == normalizedPatternLength) {
            return equalAt(host, hostStart, pattern, patternStart,
                           normalizedPatternLength);
        }
        if (normalizedHostLength <= normalizedPatternLength) { return 0; }
        const size_t suffixStart = hostEnd - normalizedPatternLength;
        return host[suffixStart - 1] == '.' &&
               equalAt(host, suffixStart, pattern, patternStart,
                       normalizedPatternLength);
    }

    if (patternLength == 0) { return 1; } // String.contains("") is true.
    if (patternLength > normalizedHostLength) { return 0; }
    const uint8_t firstChar = lower(pattern[0]);
    const uint8_t lastChar = lower(pattern[patternLength - 1]);
    const size_t limit = hostEnd - patternLength;
    for (size_t offset = hostStart; offset <= limit; ++offset) {
        if (lower(host[offset]) == firstChar &&
            lower(host[offset + patternLength - 1]) == lastChar &&
            (patternLength <= 2 || equalFolded(host + offset + 1, pattern + 1, patternLength - 2))) {
            return 1;
        }
    }
    return 0;
}

extern "C" int32_t hajimi_domain_match_self_test(void) {
    static const TestVector vectors[] = {
        TEST("..MiXeD.Example.COM..", "mixed.example.com", HAJIMI_DOMAIN_EXACT, 1),
        TEST("www.example.com.", "www.example.com.", HAJIMI_DOMAIN_EXACT, 0),
        TEST("..EXAMPLE.COM..", ".example.com", HAJIMI_DOMAIN_EXACT, 0),
        TEST("..EXAMPLE.COM..", ".ExAmPlE.cOm.", HAJIMI_DOMAIN_SUFFIX, 1),
        TEST("www.Example.COM.", "example.com", HAJIMI_DOMAIN_SUFFIX, 1),
        TEST("notexample.com", "example.com", HAJIMI_DOMAIN_SUFFIX, 0),
        TEST("evil.example.com.au", "example.com", HAJIMI_DOMAIN_SUFFIX, 0),
        TEST("foo..example.com", "example.com", HAJIMI_DOMAIN_SUFFIX, 1),
        TEST("example.com", "", HAJIMI_DOMAIN_SUFFIX, 0),
        TEST("...", "", HAJIMI_DOMAIN_SUFFIX, 1),
        TEST("...", "", HAJIMI_DOMAIN_EXACT, 1),
        TEST("FOO.BAR..", ".bar", HAJIMI_DOMAIN_KEYWORD, 1),
        TEST("FOO.BAR..", "bar.", HAJIMI_DOMAIN_KEYWORD, 0),
        TEST("FOO.BAR..", "", HAJIMI_DOMAIN_KEYWORD, 1),
        TEST("", "", HAJIMI_DOMAIN_KEYWORD, 1),
        TEST("hello", "EL", HAJIMI_DOMAIN_KEYWORD, 1),
        TEST("HELLO", "llx", HAJIMI_DOMAIN_KEYWORD, 0),
        TEST("\xc3\xa9.example", "example", HAJIMI_DOMAIN_SUFFIX, HAJIMI_DOMAIN_FALLBACK),
        TEST("example.com", "\xc3\xa9", HAJIMI_DOMAIN_KEYWORD, HAJIMI_DOMAIN_FALLBACK),
        TEST("example\0.com", "example", HAJIMI_DOMAIN_KEYWORD, HAJIMI_DOMAIN_FALLBACK),
        TEST("example\x7f.com", "example", HAJIMI_DOMAIN_SUFFIX, HAJIMI_DOMAIN_FALLBACK),
    };

    for (size_t index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        const TestVector &vector = vectors[index];
        const auto *host = reinterpret_cast<const uint8_t *>(vector.host);
        const auto *pattern = reinterpret_cast<const uint8_t *>(vector.pattern);
        if (hajimi_domain_match_ascii(host, vector.hostLength, pattern,
                                      vector.patternLength, vector.kind) != vector.expected) {
            return static_cast<int32_t>(index + 1);
        }
    }
    const auto *example = reinterpret_cast<const uint8_t *>("example.com");
    constexpr size_t exampleLength = sizeof("example.com") - 1;
    if (hajimi_domain_match_ascii(nullptr, 1, example, exampleLength,
                                  HAJIMI_DOMAIN_EXACT) != HAJIMI_DOMAIN_FALLBACK) {
        return 22;
    }
    if (hajimi_domain_match_ascii(example, exampleLength, nullptr, 1,
                                  HAJIMI_DOMAIN_SUFFIX) != HAJIMI_DOMAIN_FALLBACK) {
        return 23;
    }
    if (hajimi_domain_match_ascii(example, exampleLength, example, exampleLength,
                                  12345) != HAJIMI_DOMAIN_FALLBACK) {
        return 24;
    }
    if (hajimi_domain_match_ascii(nullptr, 0, nullptr, 0,
                                  HAJIMI_DOMAIN_EXACT) != 1) {
        return 25;
    }
    return 0;
}
