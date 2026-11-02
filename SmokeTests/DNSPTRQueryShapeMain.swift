import Foundation

@main private enum DNSPTRQueryShapeMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static var groups = 0, assertions = 0
    private static func require(_ value: @autoclosure () throws -> Bool, _ text: String) throws {
        assertions += 1
        if try !value() { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ work: () throws -> Void) throws {
        try work(); groups += 1; print("PASS", name)
    }
    private static func query(_ name: String, type: UInt16 = 12, dnsClass: UInt16 = 1) throws -> Data {
        guard var wire = DNSMessageInspection.query(for: name, type: type, id: 0x4141) else {
            throw Failure(text: "Invalid fixture question")
        }
        wire[wire.count - 2] = UInt8(dnsClass >> 8)
        wire[wire.count - 1] = UInt8(dnsClass & 255)
        return wire
    }
    private static func inspect(_ wire: Data) throws -> DNSQueryQuestion {
        guard let question = DNSMessageInspection.singleQuestion(in: wire) else {
            throw Failure(text: "Valid fixture rejected by production wire inspector")
        }
        return question
    }
    private static func expect(_ name: String, _ kind: DNSPTRQueryKind, dnsClass: UInt16 = 1) throws {
        let original = try query(name, dnsClass: dnsClass), question = try inspect(original)
        let previousCategory = DNSMessageInspection.ptrTargetCategory(for: question)
        let previousBytes = original
        try require(DNSMessageInspection.ptrQueryKind(for: question) == kind, "Unexpected fixed PTR shape")
        try require(DNSMessageInspection.ptrTargetCategory(for: question) == previousCategory && original == previousBytes,
                    "Shape inspection mutated wire or existing target category")
        guard let negative = DNSMessageInspection.errorResponse(to: original, code: .refused) else {
            throw Failure(text: "Wire error-response fixture unavailable")
        }
        try require(DNSMessageInspection.responseMatchesQuery(negative, query: original),
                    "PTR shape classification changed strict response acceptance")
        var wrongType = negative
        wrongType[wrongType.count - 4] = 0; wrongType[wrongType.count - 3] = 1
        try require(!DNSMessageInspection.responseMatchesQuery(wrongType, query: original),
                    "Shape metadata relaxed response QTYPE matching")
        var wrongClass = negative
        wrongClass[wrongClass.count - 1] ^= 1
        try require(!DNSMessageInspection.responseMatchesQuery(wrongClass, query: original),
                    "Shape metadata relaxed response QCLASS matching")
    }
    private static func reverse4(_ address: String) -> String {
        address.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
    }
    private static func reverse6(_ text: String) -> String {
        text.reversed().map(String.init).joined(separator: ".") + ".ip6.arpa"
    }

    private static func validServiceDiscovery() throws {
        try check("DNS-SD enumeration prefixes and reverse/local suffixes") {
            for prefix in ["b", "db", "r", "dr", "lb", "_services"] {
                for domain in ["local", "0.0.127.in-addr.arpa", "0.1.168.192.in-addr.arpa", "example.test"] {
                    try expect(prefix + "._dns-sd._udp." + domain, .dnsSDDomainEnumeration)
                }
            }
            try expect("B._DNS-SD._UDP.LOCAL.", .dnsSDDomainEnumeration)
            try expect("_services._dns-sd._udp", .dnsSDDomainEnumeration)
        }
        try check("service-type PTR questions use exact transport labels and valid service names") {
            for service in ["_http", "_ipp", "_airplay", "_sleep-proxy", "_companion-link", "_a1", "_a12345678901234"] {
                for transport in ["_tcp", "_udp"] {
                    try expect(service + "." + transport + ".local", .serviceType)
                    try expect(service + "." + transport + ".example.test", .serviceType)
                }
            }
            try expect("_HTTP._TCP.LOCAL.", .serviceType)
            try expect("_http._tcp", .serviceType)
        }
        try check("near-miss DNS-SD prefixes do not claim service-discovery enumeration") {
            for name in ["x._dns-sd._udp.local", "bb._dns-sd._udp.local", "_b._dns-sd._udp.local",
                         "_servicesx._dns-sd._udp.local", "b._dns-sdx._udp.local", "b._dns-sd._tcp.local",
                         "b._dns-sd._udp-fake.local", "prefix.b._dns-sd._udp.local"] {
                try expect(name, .localName)
            }
            try expect("b._dns-sd._udp-fake.example.test", .other)
            try expect("x._dns-sd._udp.example.test", .other)
            try expect("b._dns-sd._udp.0.0.127.in-addr.arpa.evil", .dnsSDDomainEnumeration)
        }
        try check("service-like malformed prefixes retain coarse local or other classification") {
            for name in ["http._tcp.local", "_._tcp.local", "_123._tcp.local", "_-http._tcp.local",
                         "_http-._tcp.local", "_http--test._tcp.local", "_a123456789012345._tcp.local",
                         "_http._tcp-fake.local", "_http._TCPx.local", "instance._http._tcp.local",
                         "_printer._sub._http._tcp.local", "_打印._tcp.local"] {
                try expect(name, .localName)
            }
            try expect("_http._tcp-fake.example.test", .other)
        }
    }

    private static func reverseShapesAndLegacyCategories() throws {
        try check("complete IPv4 reverse shape includes conservative special-use categories") {
            let samples: [(String, DNSPTRTargetCategory)] = [
                ("8.8.8.8", .ipv4Public), ("10.1.2.3", .ipv4Private), ("172.16.0.1", .ipv4Private),
                ("192.168.1.1", .ipv4Private), ("127.0.0.1", .ipv4Loopback), ("169.254.1.1", .ipv4LinkLocal),
                ("198.19.0.2", .ipv4FakeIP), ("198.18.16.1", .other), ("198.19.255.255", .other),
                ("0.0.0.1", .other), ("100.64.0.1", .other), ("192.0.2.1", .other),
                ("198.51.100.1", .other), ("203.0.113.1", .other), ("224.0.0.1", .other),
            ]
            for (address, category) in samples {
                let name = reverse4(address)
                try expect(name, .ipv4Reverse)
                try require(DNSMessageInspection.ptrTargetCategory(for: inspect(query(name))) == category,
                            "Existing IPv4 target category changed")
            }
        }
        try check("complete IPv6 reverse shape does not depend on public-address classification") {
            let samples: [(String, DNSPTRTargetCategory)] = [
                ("20014860000000000000000000008888", .ipv6Public),
                ("fc000000000000000000000000000001", .ipv6UniqueLocal),
                ("fe800000000000000000000000000001", .ipv6LinkLocal),
                ("00000000000000000000000000000001", .ipv6Loopback),
                ("00000000000000000000000000000000", .other),
                ("20010db8000000000000000000000001", .other),
                ("ff020000000000000000000000000001", .other),
                ("0064ff9b000000000000000008080808", .other),
            ]
            for (address, category) in samples {
                let name = reverse6(address)
                try expect(name, .ipv6Reverse)
                try require(DNSMessageInspection.ptrTargetCategory(for: inspect(query(name))) == category,
                            "Existing IPv6 target category changed")
            }
            try expect(reverse6("20014860000000000000000000008888").uppercased() + ".", .ipv6Reverse)
        }
        try check("partial reverse zones require complete terminal suffix labels") {
            for name in ["in-addr.arpa", "127.in-addr.arpa", "0.127.in-addr.arpa", "0.0.127.in-addr.arpa",
                         "ip6.arpa", "a.ip6.arpa", "0.0.0.ip6.arpa"] {
                try expect(name, .partialReverseZone)
            }
            for name in ["0.127.in-addr.arpa.evil", "0.127.fake-in-addr.arpa", "0.127.in-addr.fakearpa",
                         "a.ip6.arpa.evil", "a.fakeip6.arpa", "a.ip6.fakearpa"] {
                try expect(name, .other)
            }
        }
        try check("full-length malformed reverse targets are not partial addresses") {
            for name in ["256.0.0.127.in-addr.arpa", "01.0.0.127.in-addr.arpa", "x.0.0.127.in-addr.arpa",
                         "1.0.0.0.127.in-addr.arpa", "-1.0.0.127.in-addr.arpa",
                         Array(repeating: "g", count: 32).joined(separator: ".") + ".ip6.arpa",
                         Array(repeating: "0", count: 33).joined(separator: ".") + ".ip6.arpa"] {
                try expect(name, .other)
                try require(DNSMessageInspection.ptrTargetCategory(for: inspect(query(name))) == .other,
                            "Malformed reverse target changed its old conservative category")
            }
        }
    }

    private static func classAndTypeBoundaries() throws {
        try check("PTR shapes remain QCLASS-independent while old categories retain their IN guard") {
            let samples: [(String, DNSPTRQueryKind)] = [
                ("b._dns-sd._udp.local", .dnsSDDomainEnumeration), ("_http._tcp.local", .serviceType),
                (reverse4("192.0.2.1"), .ipv4Reverse),
                (reverse6("20010db8000000000000000000000001"), .ipv6Reverse),
                ("0.127.in-addr.arpa", .partialReverseZone), ("printer.local", .localName), ("example.test", .other),
            ]
            for dnsClass: UInt16 in [0, 3, 255, 0x8001, UInt16.max] {
                for (name, kind) in samples {
                    try expect(name, kind, dnsClass: dnsClass)
                    try require(DNSMessageInspection.ptrTargetCategory(for: inspect(query(name, dnsClass: dnsClass))) == nil,
                                "Shape diagnostic broadened old address-category QCLASS support")
                }
            }
        }
        try check("non-PTR queries never obtain a PTR shape") {
            for type: UInt16 in [0, 1, 2, 5, 16, 28, 33, 65, 255, UInt16.max] {
                for name in ["b._dns-sd._udp.local", reverse4("8.8.8.8"), "_http._tcp.local", "example.test"] {
                    let question = try inspect(query(name, type: type))
                    try require(DNSMessageInspection.ptrQueryKind(for: question) == nil
                                && DNSMessageInspection.ptrTargetCategory(for: question) == nil,
                                "Non-PTR question received PTR diagnostic metadata")
                }
            }
            try expect("printer.local", .localName)
            try expect("local", .localName)
            try expect("printer.notlocal", .other)
            try expect("printer.local.evil", .other)
            try expect(".", .other)
        }
        try check("malformed question rejection and response identity remain unchanged") {
            let valid = try query("b._dns-sd._udp.local")
            var multiple = valid; multiple[5] = 2
            var response = valid; response[2] |= 0x80
            var opcode = valid; opcode[2] |= 0x08
            var cycle = valid
            cycle[12] = 0xc0; cycle[13] = 12
            for wire in [Data(), Data(valid.prefix(11)), Data(valid.dropLast()), multiple, response, opcode, cycle] {
                try require(DNSMessageInspection.singleQuestion(in: wire) == nil,
                            "New diagnostics changed malformed question acceptance")
            }
            let question = try inspect(valid)
            _ = DNSMessageInspection.ptrQueryKind(for: question)
            guard var answer = DNSMessageInspection.errorResponse(to: valid, code: .servfail) else {
                throw Failure(text: "No strict response fixture")
            }
            answer[1] ^= 1
            try require(!DNSMessageInspection.responseMatchesQuery(answer, query: valid), "DNS ID matching was relaxed")
        }
    }

    private static func boundedPrivacyAndJSON() throws {
        try check("fixed shape enum and JSON roundtrip retain no names or prefixes") {
            let expected: Set<String> = ["dnsSDDomainEnumeration", "serviceType", "ipv4Reverse", "ipv6Reverse",
                                         "partialReverseZone", "localName", "other"]
            try require(Set(DNSPTRQueryKind.allCases.map(\.rawValue)) == expected,
                        "PTR shape enum changed or became data-dependent")
            let encoder = JSONEncoder(), decoder = JSONDecoder()
            for kind in DNSPTRQueryKind.allCases {
                let bytes = try encoder.encode(kind)
                try require(try decoder.decode(DNSPTRQueryKind.self, from: bytes) == kind,
                            "Fixed shape enum failed JSON roundtrip")
                try require(String(decoding: bytes, as: UTF8.self) == "\"\(kind.rawValue)\"",
                            "Shape encoding retained more than its fixed label")
            }
            var observed = Set<DNSPTRQueryKind>()
            for index in 0..<512 {
                let question = try inspect(query("private-\(index).name-\(index).example.test"))
                guard let kind = DNSMessageInspection.ptrQueryKind(for: question) else {
                    throw Failure(text: "Valid PTR shape omitted")
                }
                observed.insert(kind)
                let encoded = String(decoding: try encoder.encode(kind), as: UTF8.self)
                try require(!encoded.contains(question.name) && !encoded.contains("private-") && !encoded.contains("example.test"),
                            "Shape metadata disclosed a question name or prefix")
            }
            try require(observed == [.other], "Arbitrary names created additional classification labels")
        }
        try check("optional shape metadata permits older JSON without the field") {
            struct Envelope: Codable {
                let queryType: UInt16
                let ptrQueryKind: DNSPTRQueryKind?
            }
            let decoder = JSONDecoder(), encoder = JSONEncoder()
            let old = try decoder.decode(Envelope.self, from: Data("{\"queryType\":12}".utf8))
            try require(old.queryType == 12 && old.ptrQueryKind == nil, "Older diagnostic JSON requires new metadata")
            for kind in DNSPTRQueryKind.allCases {
                let value = Envelope(queryType: 12, ptrQueryKind: kind)
                let roundtrip = try decoder.decode(Envelope.self, from: encoder.encode(value))
                try require(roundtrip.queryType == 12 && roundtrip.ptrQueryKind == kind,
                            "Optional metadata changed existing query fields during roundtrip")
            }
        }
    }

    static func main() {
        do {
            try validServiceDiscovery()
            try reverseShapesAndLegacyCategories()
            try classAndTypeBoundaries()
            try boundedPrivacyAndJSON()
            let report: [String: Any] = ["groups": groups, "assertions": assertions, "failedGroups": [],
                                       "kindCount": DNSPTRQueryKind.allCases.count, "memoryOnly": true]
            print(String(data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!)
        } catch {
            fputs("FAIL PTR query shape: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}
