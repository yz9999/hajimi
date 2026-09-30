import HajimiRoutingCXX

/// Non-allocating C++ fast path for ASCII domain rules. A nil result asks the
/// caller to preserve RuleKind.matches' existing Unicode/string semantics.
enum NativeDomainMatcher {
    enum Kind: Int32 {
        case exact = 0
        case suffix = 1
        case keyword = 2
    }

    @inline(__always)
    static func matches(host: String, pattern: String, kind: Kind) -> Bool? {
        // A bridged/noncontiguous string takes the Swift fallback too: this
        // keeps the common ASCII route free of temporary UTF-8 allocations.
        host.utf8.withContiguousStorageIfAvailable { hostBytes in
            pattern.utf8.withContiguousStorageIfAvailable { patternBytes -> Bool? in
                let outcome = hajimi_domain_match_ascii(
                    hostBytes.baseAddress, hostBytes.count,
                    patternBytes.baseAddress, patternBytes.count,
                    kind.rawValue)
                switch outcome {
                case 0: return false
                case 1: return true
                default: return nil
                }
            } ?? nil
        } ?? nil
    }

    static func selfTestResult() -> Int32 {
        hajimi_domain_match_self_test()
    }
}
