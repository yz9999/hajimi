#include "HajimiRoutingCXX.h"

namespace {

// ASCII-only case folding avoids locale-dependent ctype calls and allocations.
constexpr uint8_t lower(uint8_t value) noexcept {
    return value >= 'A' && value <= 'Z'
               ? static_cast<uint8_t>(value + ('a' - 'A')) : value;
}

bool validAscii(const uint8_t *bytes, size_t length) noexcept {
    if (length != 0 && bytes == nullptr) { return false; }
    for (size_t index = 0; index < length; ++index) {
        // Swift's existing rule matcher is authoritative for control and
        // Unicode input; the fast path handles only printable ASCII.
        if (bytes[index] < 0x20 || bytes[index] > 0x7e) { return false; }
    }
    return true;
}

void stripDots(const uint8_t *bytes, size_t &start, size_t &end) noexcept {
    while (start < end && bytes[start] == '.') { ++start; }
    while (start < end && bytes[end - 1] == '.') { --end; }
}

bool equalFolded(const uint8_t *left, const uint8_t *right,
                 size_t length) noexcept {
    for (size_t index = 0; index < length; ++index) {
        if (lower(left[index]) != lower(right[index])) { return false; }
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
    for (size_t offset = hostStart; offset <= hostEnd - patternLength; ++offset) {
        if (equalAt(host, offset, pattern, 0, patternLength)) { return 1; }
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
