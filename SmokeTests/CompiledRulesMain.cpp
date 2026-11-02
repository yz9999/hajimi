#include "HajimiRoutingCXX.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
size_t checks = 0;

void expect(bool condition, const std::string &message) {
    ++checks;
    if (!condition) {
        std::cerr << "Compiled rule check failed: " << message << '\n';
        std::exit(1);
    }
}

const uint8_t *bytes(const std::string &value) {
    return reinterpret_cast<const uint8_t *>(value.data());
}

struct Query {
    std::string host = "other.test", protocol = "TCP", source, alternate, dnsName;
    uint32_t flags = 0;
    int32_t mode = HJ_RULE_MODE_ORDINARY;
    uint16_t destinationPort = 443, sourcePort = 0, inboundPort = 0;

    HJRuleMatchInput input() const {
        return {{bytes(host), host.size()}, {bytes(protocol), protocol.size()},
                {bytes(source), source.size()}, {bytes(alternate), alternate.size()},
                {bytes(dnsName), dnsName.size()}, flags, mode,
                destinationPort, sourcePort, inboundPort};
    }
};

struct Program {
    std::unique_ptr<HJCompiledRules, decltype(&hajimi_rules_destroy)> value{
        hajimi_rules_create(), hajimi_rules_destroy};

    Program() { expect(value != nullptr, "allocate builder"); }
    int32_t node(int32_t kind, const std::string &text = {},
                 std::initializer_list<int32_t> children = {},
                 uint16_t lower = 0, uint16_t upper = 0) {
        const auto result = hajimi_rules_add_node(value.get(), kind, bytes(text), text.size(),
            children.begin(), children.size(), lower, upper);
        expect(result >= 0, "add node kind " + std::to_string(kind));
        return result;
    }
    int32_t port(int32_t kind, uint16_t lower, uint16_t upper) {
        return node(kind, {}, {}, lower, upper);
    }
    void define(const std::string &name, std::initializer_list<int32_t> children) {
        expect(hajimi_rules_set_rule_set(value.get(), bytes(name), name.size(),
            children.begin(), children.size()) == 1, "define set");
    }
    void root(int32_t id, int32_t ordinal) {
        expect(hajimi_rules_add_root(value.get(), id, ordinal) == 1, "add ordered root");
    }
    void finish() { expect(hajimi_rules_finalize(value.get()) == 1, "finalize program"); }
    int32_t match(const Query &query) const {
        auto input = query.input();
        return hajimi_rules_match(value.get(), &input);
    }
};

void expectMatch(const Program &program, Query query, int32_t expected, const std::string &message) {
    const auto actual = program.match(query);
    expect(actual == expected, message + ": expected " + std::to_string(expected) +
        ", got " + std::to_string(actual));
}

void domainAndOrderChecks() {
    Program program;
    const auto suffix = program.node(HJ_RULE_SUFFIX, ".EXAMPLE.TEST.");
    const auto keyword = program.node(HJ_RULE_KEYWORD, "needle");
    const auto exact = program.node(HJ_RULE_DOMAIN, "www.example.test");
    const auto wildcard = program.node(HJ_RULE_WILDCARD, ".a*?.wild.test.");
    const auto both = program.node(HJ_RULE_AND, {}, {keyword, program.port(HJ_RULE_DESTINATION_PORT, 443, 443)});
    program.root(suffix, 2);
    program.root(both, 7);
    program.root(exact, 11);
    program.root(wildcard, 19);
    program.root(program.node(HJ_RULE_FINAL), 29);
    program.finish();
    Query query;
    for (const auto &host : {"www.example.test", "..WWW.EXAMPLE.TEST..", "example.test", "a.b.example.test"}) {
        query.host = host;
        expectMatch(program, query, 2, "suffix boundary and earlier ordinal");
    }
    query.host = "badexample.test";
    expectMatch(program, query, 29, "suffix must start at a label boundary");
    query.host = "a-needle.test";
    expectMatch(program, query, 7, "complex root before later indexed root");
    query.destinationPort = 80;
    expectMatch(program, query, 29, "AND retains destination port");
    query.host = "ab.wild.test";
    expectMatch(program, query, 19, "star may consume zero characters");
    query.host = "a.wild.test";
    expectMatch(program, query, 29, "question mark consumes one character");

    Program keywords;
    keywords.root(keywords.node(HJ_RULE_KEYWORD, "abcd"), 3);
    keywords.root(keywords.node(HJ_RULE_KEYWORD, "bc"), 8);
    keywords.root(keywords.node(HJ_RULE_KEYWORD, "cd"), 12);
    keywords.finish();
    query.host = "xxabcdy";
    expectMatch(keywords, query, 3, "overlapping keyword earliest ordinal");
    query.host = "xxbcy";
    expectMatch(keywords, query, 8, "keyword failure transition");
    query.host = "none";
    expectMatch(keywords, query, HJ_RULE_NO_MATCH, "no match");

    for (const auto kind : {HJ_RULE_DOMAIN, HJ_RULE_SUFFIX, HJ_RULE_KEYWORD, HJ_RULE_WILDCARD}) {
        Program dots;
        dots.root(dots.node(kind, ".x."), 0);
        dots.root(dots.node(HJ_RULE_FINAL), 1);
        dots.finish();
        query.host = "..x..";
        expectMatch(dots, query, kind == HJ_RULE_SUFFIX || kind == HJ_RULE_WILDCARD ? 0 : 1,
            "only suffix and wildcard trim pattern dots");
    }
    for (const auto kind : {HJ_RULE_DOMAIN, HJ_RULE_SUFFIX, HJ_RULE_KEYWORD, HJ_RULE_WILDCARD}) {
        Program empty;
        empty.root(empty.node(kind), 0);
        empty.root(empty.node(HJ_RULE_FINAL), 1);
        empty.finish();
        query.host = "...";
        expectMatch(empty, query, 0, "empty domain pattern matches normalized empty host");
        query.host = "x.test";
        expectMatch(empty, query, kind == HJ_RULE_KEYWORD ? 0 : 1, "empty domain pattern with nonempty host");
    }
}

void alternateAndDNSChecks() {
    Query query;
    query.host = "192.0.2.9";
    query.alternate = "alternate.test";
    query.dnsName = "qname.test";
    query.source = "198.51.100.7";
    query.sourcePort = 0;
    query.inboundPort = 53;
    query.destinationPort = 53;
    query.flags = HJ_RULE_HAS_ALTERNATE_HOST | HJ_RULE_HAS_DNS_NAME |
        HJ_RULE_HAS_SOURCE_HOST | HJ_RULE_HAS_SOURCE_PORT | HJ_RULE_HAS_INBOUND_PORT;

    Program direct;
    direct.root(direct.node(HJ_RULE_DOMAIN, "alternate.test"), 0);
    direct.root(direct.node(HJ_RULE_DOMAIN, "qname.test"), 1);
    direct.root(direct.node(HJ_RULE_FINAL), 2);
    direct.finish();
    expectMatch(direct, query, 0, "ordinary root domain substitutes alternate host");
    query.mode = HJ_RULE_MODE_DNS;
    expectMatch(direct, query, 1, "DNS root domain substitutes QNAME");

    Program logical;
    const auto host = logical.node(HJ_RULE_DOMAIN, "192.0.2.9");
    const auto cidr = logical.node(HJ_RULE_IP_CIDR, "192.0.2.0/24");
    const auto source = logical.node(HJ_RULE_SOURCE_CIDR, "198.51.100.0/24");
    const auto destinationPort = logical.port(HJ_RULE_DESTINATION_PORT, 53, 53);
    const auto sourcePort = logical.port(HJ_RULE_SOURCE_PORT, 0, 0);
    const auto inboundPort = logical.port(HJ_RULE_INBOUND_PORT, 53, 53);
    logical.root(logical.node(HJ_RULE_AND, {}, {host, cidr, source, destinationPort, sourcePort, inboundPort}), 0);
    const auto qname = logical.node(HJ_RULE_DOMAIN, "qname.test");
    logical.root(logical.node(HJ_RULE_AND, {}, {qname, cidr, source, destinationPort, sourcePort, inboundPort}), 1);
    logical.root(logical.node(HJ_RULE_FINAL), 2);
    logical.finish();
    query.mode = HJ_RULE_MODE_ORDINARY;
    expectMatch(logical, query, 0, "ordinary logical domain retains original host");
    query.mode = HJ_RULE_MODE_DNS;
    expectMatch(logical, query, 1, "DNS replaces only domain leaves, retains address and metadata");
    query.flags &= ~HJ_RULE_HAS_SOURCE_PORT;
    expectMatch(logical, query, 2, "absent source port differs from explicit zero");
    query.flags |= HJ_RULE_HAS_SOURCE_PORT;
    query.flags &= ~HJ_RULE_HAS_INBOUND_PORT;
    expectMatch(logical, query, 2, "absent inbound port");
    query.flags |= HJ_RULE_HAS_INBOUND_PORT;

    Program sets;
    const auto alternate = sets.node(HJ_RULE_DOMAIN, "alternate.test");
    const auto original = sets.node(HJ_RULE_DOMAIN, "192.0.2.9");
    const auto originalLogical = sets.node(HJ_RULE_AND, {}, {original});
    const auto nested = sets.node(HJ_RULE_SET, "nested");
    const auto top = sets.node(HJ_RULE_SET, "top");
    sets.define("nested", {sets.node(HJ_RULE_DOMAIN, "qname.test")});
    sets.define("top", {originalLogical, alternate, nested});
    sets.root(top, 0);
    sets.root(sets.node(HJ_RULE_FINAL), 1);
    sets.finish();
    query.mode = HJ_RULE_MODE_ORDINARY;
    expectMatch(sets, query, 0, "mixed set logical member keeps original host");
    query.host = "unmatched.test";
    expectMatch(sets, query, 0, "direct set domain member substitutes alternate host");
    query.alternate = "unmatched.test";
    expectMatch(sets, query, 1, "ordinary nested set does not recurse");
    query.mode = HJ_RULE_MODE_DNS;
    expectMatch(sets, query, 0, "DNS nested set recurses with QNAME");
}

void addressAndPortChecks() {
    const std::vector<std::pair<std::string, std::string>> valid = {
        {"0.0.0.0/0", "203.0.113.3"}, {"128.0.0.0/1", "203.0.113.3"},
        {"203.0.113.0/31", "203.0.113.1"}, {"203.0.113.1/32", ".203.0.113.1."},
        {"::/0", "2001:db8::1"}, {"2001:db8::/127", "2001:db8::1"},
        {"2001:db8::1/128", "..2001:DB8::1%en1.."},
        {"2001:db8::1/+128", "2001:db8::1"}, {"::/-0", "::1"},
        {"/203.0.113.0/024", "203.0.113.255"},
        {"2001:db8::/32", "%2001:db8::1%en0"},
        {"2001:db8::/32", "%%2001:db8::1"}};
    Query query;
    for (const auto &item : valid) {
        Program program;
        program.root(program.node(HJ_RULE_IP_CIDR, item.first), 0);
        program.finish();
        query.host = item.second;
        expectMatch(program, query, 0, "CIDR boundary " + item.first + " / " + item.second);
    }
    for (const auto &cidr : {"203.0.113.0/33", "2001:db8::/129", "203.0.113.0/-1",
                             "203.0.113.0/24/", "203.0.113.0/", "203.0.113.0//24",
                             "203.0.113.0/ 24", "1.2.3/24"}) {
        Program program;
        program.root(program.node(HJ_RULE_IP_CIDR, cidr), 0);
        program.finish();
        query.host = "203.0.113.1";
        expectMatch(program, query, HJ_RULE_NO_MATCH, std::string("malformed CIDR never matches: ") + cidr);
        query.host = "2001:db8::1";
        expectMatch(program, query, HJ_RULE_NO_MATCH, std::string("malformed IPv6 CIDR never matches: ") + cidr);
    }
    Program source;
    source.root(source.node(HJ_RULE_SOURCE_CIDR, "203.0.113.0/24"), 0);
    source.root(source.node(HJ_RULE_IP_CIDR, "203.0.113.0/24"), 1);
    source.root(source.node(HJ_RULE_IP_CIDR, "::ffff:203.0.113.0/120"), 2);
    source.finish();
    query.host = ".203.0.113.1.";
    query.source = ".203.0.113.2.";
    query.flags = HJ_RULE_HAS_SOURCE_HOST;
    expectMatch(source, query, 1, "source address dots are not stripped");
    query.source = "203.0.113.2";
    expectMatch(source, query, 0, "source CIDR precedes destination CIDR");
    query.flags = 0;
    query.host = "::ffff:203.0.113.1";
    expectMatch(source, query, 2, "IPv4 mapped IPv6 remains IPv6");

    Program ports;
    ports.root(ports.port(HJ_RULE_DESTINATION_PORT, 100, 200), 0);
    ports.root(ports.port(HJ_RULE_DESTINATION_PORT, 150, 150), 1);
    ports.root(ports.port(HJ_RULE_DESTINATION_PORT, 0, 65535), 2);
    ports.finish();
    for (unsigned port = 0; port <= 65535; ++port) {
        query.destinationPort = static_cast<uint16_t>(port);
        expectMatch(ports, query, port >= 100 && port <= 200 ? 0 : 2, "inclusive ordered port interval");
    }
}

void recursionAndShortCircuitChecks() {
    Query query;
    query.host = "safe.test";
    for (bool isAnd : {false, true}) {
        Program empty;
        empty.root(empty.node(isAnd ? HJ_RULE_AND : HJ_RULE_OR), 0);
        empty.root(empty.node(HJ_RULE_FINAL), 1);
        empty.finish();
        query.mode = HJ_RULE_MODE_ORDINARY;
        expectMatch(empty, query, 1, "ordinary empty logical nodes are false");
        query.mode = HJ_RULE_MODE_DNS;
        expectMatch(empty, query, isAnd ? 0 : 1, "DNS empty AND uses allSatisfy semantics");
    }
    for (unsigned nesting : {30u, 31u, 32u, 33u}) {
        Program deep;
        auto node = deep.node(HJ_RULE_DOMAIN, "safe.test");
        for (unsigned i = 0; i < nesting; ++i) node = deep.node(HJ_RULE_NOT, {}, {node});
        deep.root(node, 0);
        deep.root(deep.node(HJ_RULE_FINAL), 1);
        deep.finish();
        query.mode = HJ_RULE_MODE_DNS;
        expectMatch(deep, query, nesting >= 32 ? HJ_RULE_DNS_RECURSION_ERROR : static_cast<int32_t>(nesting % 2),
            "DNS depth limit checks the visited leaf");
        query.mode = HJ_RULE_MODE_ORDINARY;
        expectMatch(deep, query, static_cast<int32_t>(nesting % 2), "ordinary logical tree preserves NOT");
    }
    for (unsigned count : {31u, 32u}) {
        Program chain;
        auto child = chain.node(HJ_RULE_DOMAIN, "safe.test");
        for (unsigned i = 0; i < count; ++i) {
            const auto name = "set" + std::to_string(i);
            chain.define(name, {child});
            child = chain.node(HJ_RULE_SET, name);
        }
        chain.root(child, 0);
        chain.root(chain.node(HJ_RULE_FINAL), 1);
        chain.finish();
        query.mode = HJ_RULE_MODE_DNS;
        expectMatch(chain, query, count == 31 ? 0 : HJ_RULE_DNS_RECURSION_ERROR, "DNS nested set depth boundary");
    }
    for (int scenario = 0; scenario < 6; ++scenario) {
        Program cycle;
        const auto self = cycle.node(HJ_RULE_SET, "cycle");
        const auto safe = cycle.node(HJ_RULE_DOMAIN, "safe.test");
        const auto never = cycle.node(HJ_RULE_NEVER);
        if (scenario == 0) cycle.define("cycle", {self});
        if (scenario == 1) cycle.define("cycle", {safe, self});
        if (scenario == 2) cycle.define("cycle", {self, safe});
        if (scenario == 3) cycle.define("cycle", {cycle.node(HJ_RULE_OR, {}, {safe, self})});
        if (scenario == 4) cycle.define("cycle", {cycle.node(HJ_RULE_AND, {}, {never, self})});
        if (scenario == 5) {
            cycle.define("cycle", {self});
            cycle.root(safe, 0);
        }
        cycle.root(self, 1);
        cycle.root(cycle.node(HJ_RULE_FINAL), 2);
        cycle.finish();
        query.mode = HJ_RULE_MODE_DNS;
        const int32_t expected = scenario == 0 || scenario == 2 ? HJ_RULE_DNS_RECURSION_ERROR :
            scenario == 4 ? 2 : scenario == 5 ? 0 : 1;
        expectMatch(cycle, query, expected, "cycles fail only when reached in order");
    }
}

void validationAndConcurrencyChecks() {
    Program program;
    const std::string key = std::string("memory.\xe5\x90\x8d\0\x01", 12);
    const auto set = program.node(HJ_RULE_SET, key);
    std::string pattern = "copied.test";
    program.define(key, {program.node(HJ_RULE_DOMAIN, pattern)});
    pattern.assign("changed.test");
    program.root(set, 3);
    program.finish();
    expect(hajimi_rules_finalize(program.value.get()) == 1, "finalize is idempotent");
    Query query;
    query.host = "copied.test";
    expectMatch(program, query, 3, "opaque Unicode/NUL set keys and copied text");
    expect(hajimi_rules_add_node(program.value.get(), HJ_RULE_FINAL, nullptr, 0, nullptr, 0, 0, 0) == -1,
        "immutable finalized builder");
    std::atomic<bool> failed{false};
    std::vector<std::thread> readers;
    for (int thread = 0; thread < 8; ++thread) readers.emplace_back([&, thread] {
        Query local;
        local.host = thread % 2 ? "copied.test" : "other.test";
        local.mode = thread % 3 ? HJ_RULE_MODE_ORDINARY : HJ_RULE_MODE_DNS;
        for (int i = 0; i < 5000; ++i) if (program.match(local) != (thread % 2 ? 3 : HJ_RULE_NO_MATCH)) failed = true;
    });
    for (auto &reader : readers) reader.join();
    expect(!failed, "immutable concurrent readers");

    query.host = "caf\xc3\xa9.test";
    expectMatch(program, query, HJ_RULE_FALLBACK, "Unicode input asks for whole-match fallback");
    query.host = std::string("copied\0.test", 12);
    expectMatch(program, query, HJ_RULE_FALLBACK, "embedded NUL input asks for fallback");
    query.host = "copied.test";
    query.source = "caf\xc3\xa9.test";
    expectMatch(program, query, 3, "absent optional spans are ignored");
    query.flags = HJ_RULE_HAS_SOURCE_HOST;
    expectMatch(program, query, HJ_RULE_FALLBACK, "present unsupported source asks for fallback");
    query.flags = 1u << 31;
    expectMatch(program, query, HJ_RULE_FALLBACK, "unknown flags ask for fallback");
    query.flags = 0;
    query.mode = 2;
    expectMatch(program, query, HJ_RULE_FALLBACK, "unknown mode asks for fallback");
    auto invalid = query.input();
    invalid.mode = HJ_RULE_MODE_ORDINARY;
    invalid.host.bytes = nullptr;
    expect(hajimi_rules_match(program.value.get(), &invalid) == HJ_RULE_FALLBACK, "null nonempty span");
    expect(hajimi_rules_match(nullptr, &invalid) == HJ_RULE_FALLBACK, "null program");

    Program rejected;
    expect(hajimi_rules_add_node(rejected.value.get(), HJ_RULE_DOMAIN, bytes(query.source), query.source.size(),
        nullptr, 0, 0, 0) == -1, "unsupported rule pattern rejects compilation");
    expect(hajimi_rules_finalize(rejected.value.get()) == 0, "failed builder cannot finalize");
    Program noFinalize;
    expectMatch(noFinalize, Query{}, HJ_RULE_FALLBACK, "unfinalized builder cannot execute");
}

void boundedWildcardCheck() {
    Program program;
    program.root(program.node(HJ_RULE_WILDCARD, "*" + std::string(4000, 'a') + "b"), 0);
    program.root(program.node(HJ_RULE_FINAL), 1);
    program.finish();
    Query query;
    query.host.assign(8000, 'a');
    const auto start = std::chrono::steady_clock::now();
    expectMatch(program, query, HJ_RULE_FALLBACK, "adversarial wildcard has bounded work");
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    std::cout << "Bounded wildcard: " << elapsed.count() << "ms\n";
}
} // namespace

int main() {
    domainAndOrderChecks();
    alternateAndDNSChecks();
    addressAndPortChecks();
    recursionAndShortCircuitChecks();
    validationAndConcurrencyChecks();
    boundedWildcardCheck();
    std::cout << "Compiled C++ routing checks passed: " << checks << " assertions, ordered indices, "
        "QNAME/source isolation, recursion short circuit, validation and concurrent readers\n";
}
