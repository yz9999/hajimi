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

#ifdef __cplusplus
}
#endif

#endif // HAJIMI_ROUTING_CXX_H
