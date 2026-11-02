#ifndef HAJIMI_ROUTING_CXX_H
#define HAJIMI_ROUTING_CXX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Match types: exact domain, label-boundary domain suffix, substring keyword.
#define HAJIMI_DOMAIN_EXACT 0
#define HAJIMI_DOMAIN_SUFFIX 1
#define HAJIMI_DOMAIN_KEYWORD 2

// Results: 1 match, 0 no match, -1 ask Swift to use its Unicode implementation.
#define HAJIMI_DOMAIN_FALLBACK -1

// Reads caller-owned, non-NUL-terminated UTF-8 byte spans without allocating.
// NULL is permitted for an empty span; NULL with nonzero length, an unknown
// kind, non-ASCII, or ASCII control bytes return HAJIMI_DOMAIN_FALLBACK.
//
// Mirrors RuleKind.matches: strip *all* leading and trailing dots from host;
// strip pattern dots only for suffix matching. Exact and keyword patterns keep
// their dots. Empty patterns are valid and retain the existing Swift semantics.
int32_t hajimi_domain_match_ascii(const uint8_t *host, size_t host_length,
                                  const uint8_t *pattern, size_t pattern_length,
                                  int32_t kind);

// Returns zero on success, otherwise the 1-based index of the failing vector.
int32_t hajimi_domain_match_self_test(void);

// Immutable ordered rule program. Builder calls copy all supplied spans and
// node IDs; they are single-threaded. After successful finalize, match is
// read-only and may run concurrently. Destroy only after all matches finish.
typedef struct HJCompiledRules HJCompiledRules;

#define HJ_RULE_DOMAIN 0
#define HJ_RULE_SUFFIX 1
#define HJ_RULE_KEYWORD 2
#define HJ_RULE_WILDCARD 3
#define HJ_RULE_IP_CIDR 4
#define HJ_RULE_DESTINATION_PORT 5
#define HJ_RULE_SOURCE_CIDR 6
#define HJ_RULE_SOURCE_PORT 7
#define HJ_RULE_INBOUND_PORT 8
#define HJ_RULE_PROTOCOL 9
#define HJ_RULE_NEVER 10
#define HJ_RULE_AND 11
#define HJ_RULE_OR 12
#define HJ_RULE_NOT 13
#define HJ_RULE_SET 14
#define HJ_RULE_FINAL 15

#define HJ_RULE_MODE_ORDINARY 0
#define HJ_RULE_MODE_DNS 1
#define HJ_RULE_HAS_SOURCE_HOST (1u << 0)
#define HJ_RULE_HAS_SOURCE_PORT (1u << 1)
#define HJ_RULE_HAS_INBOUND_PORT (1u << 2)
#define HJ_RULE_HAS_ALTERNATE_HOST (1u << 3)
#define HJ_RULE_HAS_DNS_NAME (1u << 4)

#define HJ_RULE_NO_MATCH (-1)
#define HJ_RULE_FALLBACK (-2)
#define HJ_RULE_DNS_RECURSION_ERROR (-3)

typedef struct HJRuleByteSpan {
    const uint8_t *bytes;
    size_t length;
} HJRuleByteSpan;

typedef struct HJRuleMatchInput {
    HJRuleByteSpan host;
    HJRuleByteSpan protocol_name;
    HJRuleByteSpan source_host;
    HJRuleByteSpan alternate_host;
    HJRuleByteSpan dns_name;
    uint32_t flags;
    int32_t mode;
    uint16_t destination_port;
    uint16_t source_port;
    uint16_t inbound_port;
} HJRuleMatchInput;

HJCompiledRules *hajimi_rules_create(void);
void hajimi_rules_destroy(HJCompiledRules *program);

// Returns a nonnegative node ID, or -1 on allocation/validation failure.
// Child IDs must already exist. Text is used by domain/CIDR/protocol/set
// nodes. Port nodes use inclusive lower/upper bounds. AND/OR accept any
// number of children; NOT requires exactly one. NEVER represents the Swift
// geoIP/ipASN/processName kinds, which currently always return false.
int32_t hajimi_rules_add_node(HJCompiledRules *program, int32_t kind,
                              const uint8_t *text, size_t text_length,
                              const int32_t *children, size_t child_count,
                              uint16_t lower, uint16_t upper);

// Definitions may contain forward references and cycles through SET nodes.
// Cycles are checked only if actually evaluated in DNS mode, preserving
// ordered short circuit. Return 1 on success, 0 on failure.
int32_t hajimi_rules_set_rule_set(HJCompiledRules *program,
                                  const uint8_t *name, size_t name_length,
                                  const int32_t *children, size_t child_count);
int32_t hajimi_rules_add_root(HJCompiledRules *program, int32_t node_id,
                              int32_t ordinal);
int32_t hajimi_rules_finalize(HJCompiledRules *program);

// Returns the first matching root's original ordinal, or a result above.
// Ordinals must be nonnegative and added in strictly increasing order.
// Unsupported/non-ASCII/control inputs fall back for the whole match, never
// merely skip a rule. DNS mode substitutes QNAME only at domain leaves;
// ordinary mode substitutes alternate_host only for a root domain or the
// direct domain members of a root SET, exactly as Profile.matches does.
int32_t hajimi_rules_match(const HJCompiledRules *program,
                            const HJRuleMatchInput *input);

#ifdef __cplusplus
}
#endif

#endif // HAJIMI_ROUTING_CXX_H
