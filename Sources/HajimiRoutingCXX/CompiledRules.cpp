#include "HajimiRoutingCXX.h"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {
constexpr int32_t absent = std::numeric_limits<int32_t>::max();
constexpr size_t maximumNodes = 1'000'000;
constexpr size_t maximumEdges = 4'000'000;
constexpr size_t maximumText = 64 * 1024 * 1024;
constexpr size_t maximumSpan = 65'535;
constexpr size_t maximumSets = 16'384;
constexpr size_t maximumIndexNodes = 2'000'000;
constexpr size_t maximumIndexEntries = 4'000'000;
constexpr size_t maximumMatchWork = 4'000'000;

uint64_t fnv1a(std::string_view text) noexcept {
    uint64_t hash = 14695981039346656037ULL ^ static_cast<uint64_t>(text.size());
    const auto *ptr = reinterpret_cast<const uint8_t *>(text.data());
    size_t len = text.size();
    while (len >= 8) {
        uint64_t word = 0;
        std::memcpy(&word, ptr, 8);
        hash = (hash ^ word) * 0x9e3779b97f4a7c15ULL;
        hash ^= hash >> 32;
        ptr += 8;
        len -= 8;
    }
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(ptr[i]);
        hash *= 1099511628211ULL;
    }
    // Stafford Mix13 GF(2^64) bijective avalanche finalizer: diffuses all 64 bits
    // into low power-of-two mask bits to eliminate short-label clustering.
    hash = (hash ^ (hash >> 30)) * 0xbf58476d1ce4e5b9ULL;
    hash = (hash ^ (hash >> 27)) * 0x94d049bb133111ebULL;
    hash = hash ^ (hash >> 31);
    return hash ? hash : 1ULL;
}

// Flat open-addressed string map supporting zero-allocation std::string_view
// lookups in C++17 without per-entry heap nodes.
struct FlatStringMap {
    struct Entry {
        std::string key;
        int32_t value;
        uint64_t hash;
    };
    struct Slot {
        uint64_t hash = 0;
        uint32_t index = UINT32_MAX;
    };
    std::vector<Entry> entries;
    std::vector<Slot> slots;
    size_t mask = 0;

    void insert(const std::string &key, int32_t value) {
        entries.push_back({key, value, fnv1a(key)});
    }

    void finalize() {
        if (entries.empty()) return;
        std::sort(entries.begin(), entries.end(), [](const Entry &a, const Entry &b) {
            if (a.key != b.key) return a.key < b.key;
            return a.value < b.value;
        });
        size_t write = 0;
        for (size_t i = 0; i < entries.size(); ++i) {
            if (write == 0 || entries[i].key != entries[write - 1].key) {
                if (write != i) entries[write] = std::move(entries[i]);
                ++write;
            }
        }
        entries.resize(write);
        size_t capacity = 4;
        while (capacity < entries.size() * 2) capacity <<= 1;
        slots.assign(capacity, Slot{});
        mask = capacity - 1;
        for (uint32_t i = 0; i < static_cast<uint32_t>(entries.size()); ++i) {
            const uint64_t h = entries[i].hash;
            size_t pos = static_cast<size_t>(h) & mask;
            while (slots[pos].index != UINT32_MAX) pos = (pos + 1) & mask;
            slots[pos] = Slot{h, i};
        }
    }

    int32_t find(std::string_view key) const noexcept {
        if (slots.empty()) return absent;
        const uint64_t h = fnv1a(key);
        size_t pos = static_cast<size_t>(h) & mask;
        for (;;) {
            const Slot &s = slots[pos];
            if (s.index == UINT32_MAX) return absent;
            if (s.hash == h && entries[s.index].key == key) return entries[s.index].value;
            pos = (pos + 1) & mask;
        }
    }
};

bool readable(const uint8_t *bytes, size_t length) noexcept {
    return length <= maximumSpan && (length == 0 || bytes != nullptr);
}
bool ascii(const uint8_t *bytes, size_t length) noexcept {
    if (!readable(bytes, length)) return false;
    size_t i = 0;
    while (i + 8 <= length) {
        uint64_t w = 0;
        std::memcpy(&w, bytes + i, 8);
        const uint64_t high = w & 0x8080808080808080ULL;
        const uint64_t lt20 = (w - 0x2020202020202020ULL) & ~w & 0x8080808080808080ULL;
        const uint64_t x7f = w ^ 0x7f7f7f7f7f7f7f7fULL;
        const uint64_t eq7f = (x7f - 0x0101010101010101ULL) & ~x7f & 0x8080808080808080ULL;
        if ((high | lt20 | eq7f) != 0) return false;
        i += 8;
    }
    for (; i < length; ++i) if (bytes[i] < 0x20 || bytes[i] > 0x7e) return false;
    return true;
}
std::string copyBytes(const uint8_t *bytes, size_t length) {
    return length ? std::string(reinterpret_cast<const char *>(bytes), length) : std::string();
}
std::string folded(std::string value) {
    for (char &c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return value;
}
std::string stripDots(const std::string &value) {
    const auto first = value.find_first_not_of('.');
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of('.') - first + 1);
}

struct InlineAsciiBuffer {
    char inlineBuf[260];
    std::string heapFallback;
    std::string_view view{};

    static void foldAsciiSWAR(const uint8_t *src, char *dst, size_t n) noexcept {
        size_t i = 0;
        // 64-bit SWAR branchless parallel ASCII case folding (8 bytes/cycle):
        // Since src[k] is verified in [0x20, 0x7e] (bit 7 == 0), adding 0x3f
        // and subtracting from 0xda never carry/borrow across byte lanes.
        while (i + 8 <= n) {
            uint64_t w = 0;
            std::memcpy(&w, src + i, 8);
            const uint64_t geA = (w + 0x3f3f3f3f3f3f3f3fULL) & 0x8080808080808080ULL;
            const uint64_t leZ = (0xdadadadadadadadaULL - w) & 0x8080808080808080ULL;
            const uint64_t folded = w | ((geA & leZ) >> 2);
            std::memcpy(dst + i, &folded, 8);
            i += 8;
        }
        for (; i < n; ++i) {
            const uint8_t c = src[i];
            dst[i] = static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
    }

    bool assignNormalized(HJRuleByteSpan span, bool trimDots) {
        if (!ascii(span.bytes, span.length)) return false;
        size_t start = 0, end = span.length;
        if (trimDots) {
            while (start < end && span.bytes[start] == '.') ++start;
            while (start < end && span.bytes[end - 1] == '.') --end;
        }
        const size_t n = end - start;
        const uint8_t *src = span.bytes + start;
        if (n < sizeof(inlineBuf)) {
            foldAsciiSWAR(src, inlineBuf, n);
            inlineBuf[n] = '\0';
            view = std::string_view(inlineBuf, n);
        } else {
            heapFallback.resize(n);
            foldAsciiSWAR(src, heapFallback.data(), n);
            view = heapFallback;
        }
        return true;
    }
};

bool isLeaf(int32_t kind) noexcept { return kind <= HJ_RULE_NEVER || kind == HJ_RULE_FINAL; }

struct Limits {
    size_t nodes = 0, entries = 0;
    void node() { if (++nodes > maximumIndexNodes) throw std::length_error("rule index nodes"); }
    void entry() { if (++entries > maximumIndexEntries) throw std::length_error("rule index entries"); }
};
struct Budget {
    size_t left = maximumMatchWork;
    bool take() noexcept { if (!left) return false; --left; return true; }
};

struct Address {
    std::array<uint8_t, 16> bytes{};
    int width = 0;
};
Address parseAddress(std::string_view value) {
    Address result;
    if (value.empty()) return result;
    if (value.find(':') == std::string_view::npos) {
        if (value[0] < '0' || value[0] > '9' || value.size() > 15) return result;
        char buf[16];
        for (size_t i = 0; i < value.size(); ++i) {
            const char c = value[i];
            if ((c < '0' || c > '9') && c != '.') return result;
            buf[i] = c;
        }
        buf[value.size()] = '\0';
        if (inet_pton(AF_INET, buf, result.bytes.data()) == 1) result.width = 32;
        return result;
    }
    // Swift split(%, maxSplits: 1) omits empty leading pieces. Preserve that
    // behavior, including unusual leading-percent strings, rather than use a
    // platform zone parser that also changes the IPv6 identity or IPv4 form.
    const auto first = value.find_first_not_of('%');
    const auto end = first == std::string_view::npos ? std::string_view::npos : value.find('%', first);
    const std::string_view slice = first == std::string_view::npos ? value : value.substr(first, end - first);
    if (slice.size() < 64) {
        char buf[64];
        std::memcpy(buf, slice.data(), slice.size());
        buf[slice.size()] = '\0';
        if (inet_pton(AF_INET6, buf, result.bytes.data()) == 1) result.width = 128;
    } else {
        std::string v6(slice);
        if (inet_pton(AF_INET6, v6.c_str(), result.bytes.data()) == 1) result.width = 128;
    }
    return result;
}
struct CIDR {
    Address address;
    unsigned bits = 0;
};
CIDR parseCIDR(const std::string &value) {
    CIDR result;
    const auto first = value.find_first_not_of('/');
    if (first == std::string::npos) return result;
    const auto slash = value.find('/', first);
    if (slash == std::string::npos || slash + 1 == value.size()) return result;
    const auto network = value.substr(first, slash - first);
    size_t position = slash + 1;
    bool negative = false;
    if (value[position] == '+' || value[position] == '-') {
        negative = value[position] == '-';
        if (++position == value.size()) return result;
    }
    unsigned bits = 0;
    for (; position < value.size(); ++position) {
        const auto c = value[position];
        if (c < '0' || c > '9' || bits > 128) return result;
        bits = bits * 10 + static_cast<unsigned>(c - '0');
    }
    if (negative && bits != 0) return result;
    const int width = network.find(':') == std::string::npos ? 32 : 128;
    if (bits > static_cast<unsigned>(width)) return result;
    if (inet_pton(width == 32 ? AF_INET : AF_INET6, network.c_str(), result.address.bytes.data()) != 1) return result;
    result.address.width = width; result.bits = bits;
    return result;
}
bool contains(const CIDR &cidr, const Address &address) noexcept {
    if (!cidr.address.width || cidr.address.width != address.width) return false;
    const unsigned fullBytes = cidr.bits / 8;
    if (fullBytes && std::memcmp(cidr.address.bytes.data(), address.bytes.data(), fullBytes) != 0) return false;
    const unsigned rem = cidr.bits % 8;
    if (rem) {
        const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - rem));
        if ((cidr.address.bytes[fullBytes] & mask) != (address.bytes[fullBytes] & mask)) return false;
    }
    return true;
}

struct SparseTrie {
    struct Node {
        uint64_t maskLow = 0, maskHigh = 0;
        uint32_t edgeOffset = 0, edgeCount = 0;
        uint32_t singleTarget = UINT32_MAX;
        uint8_t singleChar = 0;
        int32_t value = absent;
        uint32_t failure = 0;
    };
    static constexpr size_t kDfaStride = 96;
    static constexpr size_t kMaxDfaNodes = 64;
    std::vector<Node> nodes{1};
    std::vector<std::vector<std::pair<uint8_t, uint32_t>>> buildEdges{1};
    std::vector<std::pair<uint8_t, uint32_t>> flatEdges;
    std::vector<uint32_t> dfa;
    std::vector<int32_t> nodeValues;
    std::array<uint32_t, 128> rootNext{};
    std::array<uint32_t, 128> rootAutomaton{};

    SparseTrie() {
        rootNext.fill(UINT32_MAX);
        rootAutomaton.fill(0);
    }

    static bool hasBit(const Node &node, uint8_t c) noexcept {
        if (c >= 128) return false;
        return c < 64 ? ((node.maskLow >> c) & 1u) != 0 : ((node.maskHigh >> (c - 64)) & 1u) != 0;
    }
    static void setBit(Node &node, uint8_t c) noexcept {
        if (c < 64) node.maskLow |= (uint64_t(1) << c);
        else if (c < 128) node.maskHigh |= (uint64_t(1) << (c - 64));
    }

    uint32_t child(uint32_t node, uint8_t c) const noexcept {
        if (node == 0 && c < 128) return rootNext[c];
        const auto &n = nodes[node];
        if (n.edgeCount <= 1) {
            return (n.edgeCount == 1 && n.singleChar == c) ? n.singleTarget : UINT32_MAX;
        }
        if (!hasBit(n, c)) return UINT32_MAX;
        const auto *begin = flatEdges.data() + n.edgeOffset;
        const auto *end = begin + n.edgeCount;
        if (n.edgeCount <= 8) {
            for (const auto *it = begin; it != end; ++it) if (it->first == c) return it->second;
            return UINT32_MAX;
        }
        const auto *found = std::lower_bound(begin, end, c,
            [](const auto &edge, uint8_t value) { return edge.first < value; });
        return found != end && found->first == c ? found->second : UINT32_MAX;
    }
    void insert(const std::string &text, int32_t value, bool reversed, Limits &limits) {
        uint32_t current = 0;
        for (size_t i = 0; i < text.size(); ++i) {
            const auto c = static_cast<uint8_t>(text[reversed ? text.size() - i - 1 : i]);
            uint32_t next = UINT32_MAX;
            for (const auto &edge : buildEdges[current]) if (edge.first == c) { next = edge.second; break; }
            if (next == UINT32_MAX) {
                limits.node();
                next = static_cast<uint32_t>(nodes.size());
                nodes.emplace_back();
                buildEdges.emplace_back();
                buildEdges[current].emplace_back(c, next);
                setBit(nodes[current], c);
            }
            current = next;
        }
        nodes[current].value = std::min(nodes[current].value, value);
    }
    void sortEdges() {
        rootNext.fill(UINT32_MAX);
        rootAutomaton.fill(0);
        size_t totalEdges = 0;
        for (auto &edges : buildEdges) {
            std::sort(edges.begin(), edges.end());
            totalEdges += edges.size();
        }
        flatEdges.clear();
        flatEdges.reserve(totalEdges);
        for (size_t i = 0; i < nodes.size(); ++i) {
            nodes[i].edgeOffset = static_cast<uint32_t>(flatEdges.size());
            nodes[i].edgeCount = static_cast<uint32_t>(buildEdges[i].size());
            if (buildEdges[i].size() == 1) {
                nodes[i].singleChar = buildEdges[i][0].first;
                nodes[i].singleTarget = buildEdges[i][0].second;
            }
            flatEdges.insert(flatEdges.end(), buildEdges[i].begin(), buildEdges[i].end());
        }
        for (uint32_t k = 0; k < nodes[0].edgeCount; ++k) {
            const auto &edge = flatEdges[nodes[0].edgeOffset + k];
            if (edge.first < 128) {
                rootNext[edge.first] = edge.second;
                rootAutomaton[edge.first] = edge.second;
            }
        }
        std::vector<std::vector<std::pair<uint8_t, uint32_t>>>().swap(buildEdges);
    }
    int32_t suffix(std::string_view host) const noexcept {
        if (nodes.size() == 1) return host.empty() ? nodes[0].value : absent;
        int32_t best = host.empty() ? nodes[0].value : absent;
        uint32_t current = 0;
        for (size_t i = 0; i < host.size(); ++i) {
            current = child(current, static_cast<uint8_t>(host[host.size() - i - 1]));
            if (current == UINT32_MAX) break;
            if (i + 1 == host.size() || host[host.size() - i - 2] == '.') best = std::min(best, nodes[current].value);
        }
        return best;
    }
    void buildFailures() {
        sortEdges();
        const bool useDfa = nodes.size() > 1 && nodes.size() <= kMaxDfaNodes;
        if (useDfa) {
            dfa.assign(nodes.size() * kDfaStride, 0);
            for (uint32_t k = 0; k < nodes[0].edgeCount; ++k) {
                const auto edge = flatEdges[nodes[0].edgeOffset + k];
                if (edge.first >= 0x20 && edge.first <= 0x7e) {
                    dfa[edge.first - 0x20] = edge.second;
                }
            }
        }
        std::queue<uint32_t> pending;
        for (uint32_t k = 0; k < nodes[0].edgeCount; ++k) {
            pending.push(flatEdges[nodes[0].edgeOffset + k].second);
        }
        while (!pending.empty()) {
            const auto current = pending.front(); pending.pop();
            const uint32_t fail = nodes[current].failure;
            nodes[current].value = std::min(nodes[current].value, nodes[fail].value);
            if (useDfa) {
                std::memcpy(dfa.data() + current * kDfaStride,
                            dfa.data() + fail * kDfaStride,
                            kDfaStride * sizeof(uint32_t));
            }
            const uint32_t offset = nodes[current].edgeOffset;
            const uint32_t count = nodes[current].edgeCount;
            for (uint32_t k = 0; k < count; ++k) {
                const auto edge = flatEdges[offset + k];
                if (useDfa && edge.first >= 0x20 && edge.first <= 0x7e) {
                    dfa[current * kDfaStride + (edge.first - 0x20)] = edge.second;
                    nodes[edge.second].failure = dfa[fail * kDfaStride + (edge.first - 0x20)];
                } else {
                    auto failure = fail;
                    auto next = child(failure, edge.first);
                    while (failure && next == UINT32_MAX) { failure = nodes[failure].failure; next = child(failure, edge.first); }
                    nodes[edge.second].failure = next == UINT32_MAX ? 0 : next;
                }
                pending.push(edge.second);
            }
        }
        nodeValues.resize(nodes.size());
        for (size_t i = 0; i < nodes.size(); ++i) nodeValues[i] = nodes[i].value;
    }
    int32_t keyword(std::string_view host) const noexcept {
        int32_t best = nodes[0].value;
        if (nodes.size() == 1) return best;
        uint32_t current = 0;
        if (!dfa.empty()) {
            const uint32_t * __restrict table = dfa.data();
            const int32_t * __restrict vals = nodeValues.data();
            for (char raw : host) {
                const auto c = static_cast<uint8_t>(raw);
                current = table[current * kDfaStride + (c - 0x20)];
                const int32_t v = vals[current];
                if (v < best) best = v;
            }
            return best;
        }
        for (char raw : host) {
            const auto c = static_cast<uint8_t>(raw);
            if (current == 0) {
                current = c < 128 ? rootAutomaton[c] : 0;
                if (current != 0) best = std::min(best, nodes[current].value);
                continue;
            }
            auto next = child(current, c);
            while (current && next == UINT32_MAX) {
                current = nodes[current].failure;
                next = current == 0 ? (c < 128 ? rootNext[c] : UINT32_MAX) : child(current, c);
            }
            current = next == UINT32_MAX ? 0 : next;
            best = std::min(best, nodes[current].value);
        }
        return best;
    }
};

struct PrefixIndex {
    struct Node { int32_t children[2]{-1, -1}; int32_t value = absent; };
    std::vector<Node> nodes{1};
    void add(const CIDR &cidr, int32_t value, Limits &limits) {
        uint32_t current = 0;
        for (unsigned bit = 0; bit < cidr.bits; ++bit) {
            const auto branch = (cidr.address.bytes[bit / 8] >> (7 - bit % 8)) & 1;
            auto next = nodes[current].children[branch];
            if (next < 0) {
                limits.node(); next = static_cast<int32_t>(nodes.size()); nodes.emplace_back();
                nodes[current].children[branch] = next;
            }
            current = static_cast<uint32_t>(next);
        }
        nodes[current].value = std::min(nodes[current].value, value);
    }
    int32_t match(const Address &address) const noexcept {
        int32_t best = nodes[0].value;
        if (nodes.size() == 1) return best;
        uint32_t current = 0;
        for (int bit = 0; bit < address.width; ++bit) {
            const auto next = nodes[current].children[(address.bytes[bit / 8] >> (7 - bit % 8)) & 1];
            if (next < 0) break;
            current = static_cast<uint32_t>(next); best = std::min(best, nodes[current].value);
        }
        return best;
    }
};

struct RangeIndex {
    struct Range { uint16_t lower, upper; int32_t value; };
    std::vector<Range> ranges;
    std::vector<std::pair<uint32_t, int32_t>> segments;
    void finalize() {
        std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) { return a.lower < b.lower; });
        std::vector<uint32_t> points;
        for (const auto &range : ranges) { points.push_back(range.lower); points.push_back(uint32_t(range.upper) + 1); }
        std::sort(points.begin(), points.end()); points.erase(std::unique(points.begin(), points.end()), points.end());
        using Item = std::pair<int32_t, uint16_t>;
        std::priority_queue<Item, std::vector<Item>, std::greater<Item>> active;
        size_t next = 0;
        for (auto point : points) {
            while (next < ranges.size() && ranges[next].lower <= point) {
                active.emplace(ranges[next].value, ranges[next].upper); ++next;
            }
            while (!active.empty() && active.top().second < point) active.pop();
            const int32_t value = active.empty() ? absent : active.top().first;
            if (segments.empty() || segments.back().second != value) segments.emplace_back(point, value);
        }
        ranges.clear(); ranges.shrink_to_fit();
    }
    int32_t match(uint16_t port) const noexcept {
        if (segments.empty()) return absent;
        const auto found = std::upper_bound(segments.begin(), segments.end(), uint32_t(port),
            [](uint32_t value, const auto &segment) { return value < segment.first; });
        return found == segments.begin() ? absent : (found - 1)->second;
    }
};

struct Node {
    int32_t kind;
    std::string text;
    std::vector<int32_t> children;
    uint16_t lower, upper;
    CIDR cidr;
    int32_t definition = -1;
};
struct Context {
    InlineAsciiBuffer hostBuf, altBuf, protoBuf;
    bool hasAlternateDomain = false;
    Address destination, source;
    const HJRuleMatchInput &input;
    Budget budget;
    explicit Context(const HJRuleMatchInput &value) : input(value) {}
    std::string_view domain() const noexcept { return hasAlternateDomain ? altBuf.view : hostBuf.view; }
    std::string_view originalDomain() const noexcept { return hostBuf.view; }
    std::string_view protocol() const noexcept { return protoBuf.view; }
};

// Greedy wildcard matching uses bounded local state and never recurses. Its
// work is also charged to the per-match budget, including adversarial input.
int glob(std::string_view pattern, std::string_view host, Budget &budget) noexcept {
    size_t p = 0, h = 0, star = std::string_view::npos, retry = 0;
    while (h < host.size()) {
        if (!budget.take()) return HJ_RULE_FALLBACK;
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == host[h])) { ++p; ++h; }
        else if (p < pattern.size() && pattern[p] == '*') { star = p++; retry = h; }
        else if (star != std::string_view::npos) { p = star + 1; h = ++retry; }
        else return 0;
    }
    while (p < pattern.size() && pattern[p] == '*') { if (!budget.take()) return HJ_RULE_FALLBACK; ++p; }
    return p == pattern.size();
}

struct LeafIndex {
    int32_t always = absent;
    FlatStringMap exact, protocols;
    SparseTrie suffixes, keywords;
    PrefixIndex destination4, destination6, source4, source6;
    RangeIndex destinationPorts, sourcePorts, inboundPorts;
    std::vector<std::pair<std::string, int32_t>> wildcards;
    void add(const Node &node, int32_t value, Limits &limits) {
        limits.entry();
        switch (node.kind) {
        case HJ_RULE_DOMAIN: exact.insert(node.text, value); break;
        case HJ_RULE_SUFFIX: suffixes.insert(node.text, value, true, limits); break;
        case HJ_RULE_KEYWORD: keywords.insert(node.text, value, false, limits); break;
        case HJ_RULE_WILDCARD: wildcards.emplace_back(node.text, value); break;
        case HJ_RULE_IP_CIDR:
            if (node.cidr.address.width) (node.cidr.address.width == 32 ? destination4 : destination6).add(node.cidr, value, limits);
            break;
        case HJ_RULE_SOURCE_CIDR:
            if (node.cidr.address.width) (node.cidr.address.width == 32 ? source4 : source6).add(node.cidr, value, limits);
            break;
        case HJ_RULE_DESTINATION_PORT: destinationPorts.ranges.push_back({node.lower, node.upper, value}); break;
        case HJ_RULE_SOURCE_PORT: sourcePorts.ranges.push_back({node.lower, node.upper, value}); break;
        case HJ_RULE_INBOUND_PORT: inboundPorts.ranges.push_back({node.lower, node.upper, value}); break;
        case HJ_RULE_PROTOCOL: protocols.insert(node.text, value); break;
        case HJ_RULE_FINAL: always = std::min(always, value); break;
        default: break;
        }
    }
    void finalize() {
        exact.finalize(); protocols.finalize();
        suffixes.sortEdges(); keywords.buildFailures();
        destinationPorts.finalize(); sourcePorts.finalize(); inboundPorts.finalize();
    }
    int32_t match(Context &context) const {
        int32_t best = always;
        const std::string_view dom = context.domain();
        best = std::min(best, exact.find(dom));
        best = std::min(best, suffixes.suffix(dom));
        best = std::min(best, keywords.keyword(dom));
        if (context.destination.width) best = std::min(best,
            (context.destination.width == 32 ? destination4 : destination6).match(context.destination));
        if (context.input.flags & HJ_RULE_HAS_SOURCE_HOST) {
            if (context.source.width) best = std::min(best, (context.source.width == 32 ? source4 : source6).match(context.source));
        }
        best = std::min(best, destinationPorts.match(context.input.destination_port));
        if (context.input.flags & HJ_RULE_HAS_SOURCE_PORT) best = std::min(best, sourcePorts.match(context.input.source_port));
        if (context.input.flags & HJ_RULE_HAS_INBOUND_PORT) best = std::min(best, inboundPorts.match(context.input.inbound_port));
        best = std::min(best, protocols.find(context.protocol()));
        for (const auto &wildcard : wildcards) if (wildcard.second < best) {
            const auto result = glob(wildcard.first, dom, context.budget);
            if (result == HJ_RULE_FALLBACK) return result;
            if (result) best = wildcard.second;
        }
        return best;
    }
};

struct Definition {
    std::vector<int32_t> children, complex;
    std::unique_ptr<LeafIndex> index;
    bool simple = true;
};
struct Root { int32_t node, ordinal; };

struct Program {
    bool failed = false, finalized = false;
    size_t textBytes = 0, edges = 0;
    std::vector<Node> nodes;
    std::unordered_map<std::string, int32_t> names;
    std::vector<Definition> definitions;
    std::vector<Root> roots, complexRoots;
    LeafIndex index;

    void finalize() {
        Limits limits;
        for (auto &definition : definitions) {
            definition.index = std::make_unique<LeafIndex>();
            for (size_t i = 0; i < definition.children.size(); ++i) {
                const auto &node = nodes[definition.children[i]];
                if (isLeaf(node.kind)) definition.index->add(node, static_cast<int32_t>(i), limits);
                else { definition.simple = false; definition.complex.push_back(static_cast<int32_t>(i)); }
            }
            definition.index->finalize();
        }
        for (auto &node : nodes) if (node.kind == HJ_RULE_SET) {
            const auto found = names.find(node.text);
            if (found != names.end()) node.definition = found->second;
        }
        std::unordered_set<int32_t> indexedNodes, indexedDefinitions;
        for (const auto &root : roots) {
            const auto &node = nodes[root.node];
            if (isLeaf(node.kind)) {
                if (indexedNodes.insert(root.node).second) index.add(node, root.ordinal, limits);
            } else if (node.kind == HJ_RULE_SET && node.definition < 0) {
                // Missing definitions are false in both interpreters.
            } else if (node.kind == HJ_RULE_SET && definitions[node.definition].simple) {
                if (indexedDefinitions.insert(node.definition).second) {
                    for (auto child : definitions[node.definition].children) index.add(nodes[child], root.ordinal, limits);
                }
            } else complexRoots.push_back(root);
        }
        index.finalize(); finalized = true;
    }

    int evaluate(int32_t id, Context &context, unsigned depth,
                 std::array<int32_t, 32> &activeSets, unsigned activeCount) const {
        const bool dns = context.input.mode == HJ_RULE_MODE_DNS;
        if (dns && depth >= 32) return HJ_RULE_DNS_RECURSION_ERROR;
        if (depth >= 256 || !context.budget.take()) return HJ_RULE_FALLBACK;
        const auto &node = nodes[id];
        const std::string_view domain = dns ? context.domain() : context.originalDomain();
        switch (node.kind) {
        case HJ_RULE_DOMAIN: return domain == node.text;
        case HJ_RULE_SUFFIX: return domain == node.text ||
            (domain.size() > node.text.size() && domain.compare(domain.size() - node.text.size(), node.text.size(), node.text) == 0 &&
             domain[domain.size() - node.text.size() - 1] == '.');
        case HJ_RULE_KEYWORD: return domain.find(node.text) != std::string_view::npos;
        case HJ_RULE_WILDCARD: return glob(node.text, domain, context.budget);
        case HJ_RULE_IP_CIDR: return contains(node.cidr, context.destination);
        case HJ_RULE_SOURCE_CIDR: return (context.input.flags & HJ_RULE_HAS_SOURCE_HOST) && contains(node.cidr, context.source);
        case HJ_RULE_DESTINATION_PORT: return context.input.destination_port >= node.lower && context.input.destination_port <= node.upper;
        case HJ_RULE_SOURCE_PORT: return (context.input.flags & HJ_RULE_HAS_SOURCE_PORT) &&
            context.input.source_port >= node.lower && context.input.source_port <= node.upper;
        case HJ_RULE_INBOUND_PORT: return (context.input.flags & HJ_RULE_HAS_INBOUND_PORT) &&
            context.input.inbound_port >= node.lower && context.input.inbound_port <= node.upper;
        case HJ_RULE_PROTOCOL: return context.protocol() == node.text;
        case HJ_RULE_NEVER: return 0;
        case HJ_RULE_FINAL: return 1;
        case HJ_RULE_AND:
            if (!dns && node.children.empty()) return 0;
            for (auto child : node.children) {
                const int result = evaluate(child, context, depth + 1, activeSets, activeCount);
                if (result != 1) return result;
            }
            return 1;
        case HJ_RULE_OR:
            for (auto child : node.children) {
                const int result = evaluate(child, context, depth + 1, activeSets, activeCount);
                if (result != 0) return result;
            }
            return 0;
        case HJ_RULE_NOT: {
            const int result = evaluate(node.children[0], context, depth + 1, activeSets, activeCount);
            return result < 0 ? result : !result;
        }
        case HJ_RULE_SET:
            return dns ? evaluateSet(node.definition, context, depth, activeSets, activeCount) : 0;
        default: return HJ_RULE_FALLBACK;
        }
    }

    int evaluateSet(int32_t definitionId, Context &context, unsigned depth,
                    std::array<int32_t, 32> &activeSets, unsigned activeCount) const {
        if (definitionId < 0) return 0;
        const bool dns = context.input.mode == HJ_RULE_MODE_DNS;
        if (dns) {
            for (unsigned i = 0; i < activeCount; ++i) if (activeSets[i] == definitionId) return HJ_RULE_DNS_RECURSION_ERROR;
            if (activeCount == activeSets.size()) return HJ_RULE_DNS_RECURSION_ERROR;
            activeSets[activeCount++] = definitionId;
        }
        const auto &definition = definitions[definitionId];
        if (dns && depth + 1 >= 32 && !definition.children.empty()) return HJ_RULE_DNS_RECURSION_ERROR;
        const auto candidate = definition.index->match(context);
        if (candidate == HJ_RULE_FALLBACK) return candidate;
        for (auto position : definition.complex) {
            if (position >= candidate) break;
            const auto result = evaluate(definition.children[position], context, depth + 1, activeSets, activeCount);
            if (result != 0) return result;
        }
        return candidate != absent;
    }

    int32_t match(Context &context) const {
        const auto candidate = index.match(context);
        if (candidate == HJ_RULE_FALLBACK) return candidate;
        std::array<int32_t, 32> activeSets{};
        for (const auto &root : complexRoots) {
            if (root.ordinal >= candidate) break;
            const auto &node = nodes[root.node];
            const int result = context.input.mode == HJ_RULE_MODE_ORDINARY && node.kind == HJ_RULE_SET
                ? evaluateSet(node.definition, context, 0, activeSets, 0)
                : evaluate(root.node, context, 0, activeSets, 0);
            if (result < 0) return result;
            if (result) return root.ordinal;
        }
        return candidate == absent ? HJ_RULE_NO_MATCH : candidate;
    }
};

bool prepareContext(Context &context) {
    const auto &input = context.input;
    const uint32_t validFlags = HJ_RULE_HAS_SOURCE_HOST | HJ_RULE_HAS_SOURCE_PORT | HJ_RULE_HAS_INBOUND_PORT |
        HJ_RULE_HAS_ALTERNATE_HOST | HJ_RULE_HAS_DNS_NAME;
    if ((input.mode != HJ_RULE_MODE_ORDINARY && input.mode != HJ_RULE_MODE_DNS) || (input.flags & ~validFlags)) return false;
    auto valid = [](HJRuleByteSpan span) { return ascii(span.bytes, span.length); };
    if (!context.hostBuf.assignNormalized(input.host, true) ||
        !context.protoBuf.assignNormalized(input.protocol_name, false)) return false;
    if ((input.flags & HJ_RULE_HAS_SOURCE_HOST) && !valid(input.source_host)) return false;
    if ((input.flags & HJ_RULE_HAS_ALTERNATE_HOST) && !valid(input.alternate_host)) return false;
    if ((input.flags & HJ_RULE_HAS_DNS_NAME) && !valid(input.dns_name)) return false;
    if (input.mode == HJ_RULE_MODE_DNS && (input.flags & HJ_RULE_HAS_DNS_NAME)) {
        if (!context.altBuf.assignNormalized(input.dns_name, true)) return false;
        context.hasAlternateDomain = true;
    } else if (input.mode == HJ_RULE_MODE_ORDINARY && (input.flags & HJ_RULE_HAS_ALTERNATE_HOST)) {
        if (!context.altBuf.assignNormalized(input.alternate_host, true)) return false;
        context.hasAlternateDomain = true;
    }
    context.destination = parseAddress(context.hostBuf.view);
    if (input.flags & HJ_RULE_HAS_SOURCE_HOST) {
        context.source = parseAddress(std::string_view(
            reinterpret_cast<const char *>(input.source_host.bytes), input.source_host.length));
    }
    return true;
}
} // namespace

struct HJCompiledRules { Program program; };

extern "C" HJCompiledRules *hajimi_rules_create(void) {
    try { return new HJCompiledRules; } catch (...) { return nullptr; }
}
extern "C" void hajimi_rules_destroy(HJCompiledRules *program) { delete program; }

extern "C" int32_t hajimi_rules_add_node(HJCompiledRules *owner, int32_t kind,
    const uint8_t *text, size_t textLength, const int32_t *children, size_t childCount,
    uint16_t lower, uint16_t upper) {
    if (!owner || owner->program.finalized || owner->program.failed) return -1;
    auto &program = owner->program;
    try {
        if (kind < HJ_RULE_DOMAIN || kind > HJ_RULE_FINAL || !readable(text, textLength) ||
            (kind != HJ_RULE_SET && !ascii(text, textLength)) ||
            childCount > maximumEdges || (childCount && !children) || program.nodes.size() >= maximumNodes ||
            program.edges > maximumEdges - childCount || program.textBytes > maximumText - textLength ||
            (kind == HJ_RULE_NOT ? childCount != 1 : (kind != HJ_RULE_AND && kind != HJ_RULE_OR && childCount != 0)) ||
            ((kind == HJ_RULE_DESTINATION_PORT || kind == HJ_RULE_SOURCE_PORT || kind == HJ_RULE_INBOUND_PORT) && lower > upper)) {
            program.failed = true; return -1;
        }
        for (size_t i = 0; i < childCount; ++i) if (children[i] < 0 || static_cast<size_t>(children[i]) >= program.nodes.size()) {
            program.failed = true; return -1;
        }
        Node node{kind, copyBytes(text, textLength), {}, lower, upper, {}, -1};
        if (childCount) node.children.assign(children, children + childCount);
        if (kind == HJ_RULE_IP_CIDR || kind == HJ_RULE_SOURCE_CIDR) node.cidr = parseCIDR(node.text);
        if (kind != HJ_RULE_SET) node.text = folded(std::move(node.text));
        if (kind == HJ_RULE_SUFFIX || kind == HJ_RULE_WILDCARD) node.text = stripDots(node.text);
        program.textBytes += textLength; program.edges += childCount;
        program.nodes.push_back(std::move(node));
        return static_cast<int32_t>(program.nodes.size() - 1);
    } catch (...) { program.failed = true; return -1; }
}

extern "C" int32_t hajimi_rules_set_rule_set(HJCompiledRules *owner,
    const uint8_t *name, size_t nameLength, const int32_t *children, size_t childCount) {
    if (!owner || owner->program.finalized || owner->program.failed) return 0;
    auto &program = owner->program;
    try {
        if (!readable(name, nameLength) || childCount > maximumEdges || (childCount && !children) ||
            program.edges > maximumEdges - childCount || program.textBytes > maximumText - nameLength ||
            program.definitions.size() >= maximumSets) { program.failed = true; return 0; }
        for (size_t i = 0; i < childCount; ++i) if (children[i] < 0 || static_cast<size_t>(children[i]) >= program.nodes.size()) {
            program.failed = true; return 0;
        }
        auto key = copyBytes(name, nameLength);
        if (program.names.count(key)) { program.failed = true; return 0; }
        Definition definition;
        if (childCount) definition.children.assign(children, children + childCount);
        program.names.emplace(std::move(key), static_cast<int32_t>(program.definitions.size()));
        program.definitions.push_back(std::move(definition));
        program.edges += childCount; program.textBytes += nameLength;
        return 1;
    } catch (...) { program.failed = true; return 0; }
}
extern "C" int32_t hajimi_rules_add_root(HJCompiledRules *owner, int32_t nodeId, int32_t ordinal) {
    if (!owner || owner->program.finalized || owner->program.failed) return 0;
    auto &program = owner->program;
    try {
        if (nodeId < 0 || static_cast<size_t>(nodeId) >= program.nodes.size() || ordinal < 0 || ordinal == absent ||
            program.roots.size() >= maximumNodes || (!program.roots.empty() && ordinal <= program.roots.back().ordinal)) {
            program.failed = true; return 0;
        }
        program.roots.push_back({nodeId, ordinal}); return 1;
    } catch (...) { program.failed = true; return 0; }
}
extern "C" int32_t hajimi_rules_finalize(HJCompiledRules *owner) {
    if (!owner || owner->program.failed) return 0;
    if (owner->program.finalized) return 1;
    try { owner->program.finalize(); return 1; }
    catch (...) { owner->program.failed = true; return 0; }
}
extern "C" int32_t hajimi_rules_match(const HJCompiledRules *owner, const HJRuleMatchInput *input) {
    if (!owner || !input || !owner->program.finalized || owner->program.failed) return HJ_RULE_FALLBACK;
    try {
        Context context(*input);
        if (!prepareContext(context)) return HJ_RULE_FALLBACK;
        return owner->program.match(context);
    } catch (...) { return HJ_RULE_FALLBACK; }
}
