import Foundation

@main private enum DNSLocalServiceDiscoveryMain {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    private static var groups = 0, assertions = 0
    private static var failedGroups: [String] = []
    private static let responseGroups = ["local reverse domain enumeration", "exact response identity", "stateless independent callers"]
    private static func require(_ value: @autoclosure () throws -> Bool, _ text: String) throws {
        assertions += 1
        if try !value() { throw Failure(text: text) }
    }
    private static func check(_ name: String, _ work: () throws -> Void) {
        groups += 1
        do { try work(); print("PASS", name) }
        catch { failedGroups.append(name); print("FAIL", name, error.localizedDescription) }
    }
    private static func query(_ name: String, type: UInt16 = 12, dnsClass: UInt16 = 1,
                              id: UInt16 = 0x1234) throws -> Data {
        guard var wire = DNSMessageInspection.query(for: name, type: type, id: id) else {
            throw Failure(text: "Invalid memory query fixture")
        }
        wire[wire.count - 2] = UInt8(truncatingIfNeeded: dnsClass >> 8)
        wire[wire.count - 1] = UInt8(truncatingIfNeeded: dnsClass)
        return wire
    }
    private static func inspect(_ wire: Data) throws -> DNSQueryQuestion {
        guard let question = DNSMessageInspection.singleQuestion(in: wire) else {
            throw Failure(text: "Production inspector rejected a valid memory fixture")
        }
        return question
    }
    private static func answer(_ wire: Data, question: DNSQueryQuestion? = nil) throws -> Data? {
        let inspected = try question ?? inspect(wire)
        #if HAVE_LOCAL_SERVICE_DISCOVERY_RESPONSE
        return DNSMessageInspection.localServiceDiscoveryResponse(to: wire, question: inspected)
        #else
        _ = inspected
        return nil
        #endif
    }
    private static func enumeration(_ suffix: String, prefix: String = "b") -> String {
        prefix + "._dns-sd._udp." + suffix
    }
    private static func assertNoAnswer(_ name: String, type: UInt16 = 12, dnsClass: UInt16 = 1) throws {
        let wire = try query(name, type: type, dnsClass: dnsClass), original = wire
        try require(try answer(wire) == nil, "An excluded query was given a local answer")
        try require(wire == original, "A declined query was mutated")
    }

    private static func localResponses() {
        check(responseGroups[0]) {
            let zones = [
                "10.in-addr.arpa", "0.10.in-addr.arpa", "255.10.in-addr.arpa", "0.0.10.in-addr.arpa",
                "255.255.255.10.in-addr.arpa", "16.172.in-addr.arpa", "31.172.in-addr.arpa",
                "0.16.172.in-addr.arpa", "255.31.172.in-addr.arpa", "1.0.16.172.in-addr.arpa",
                "168.192.in-addr.arpa", "255.168.192.in-addr.arpa", "0.0.168.192.in-addr.arpa",
                "255.255.168.192.in-addr.arpa", "127.in-addr.arpa", "0.127.in-addr.arpa",
                "0.0.127.in-addr.arpa", "1.0.0.127.in-addr.arpa", "254.169.in-addr.arpa",
                "0.254.169.in-addr.arpa", "255.255.254.169.in-addr.arpa",
                "16.18.198.in-addr.arpa", "1.16.18.198.in-addr.arpa", "255.16.18.198.in-addr.arpa",
                "19.198.in-addr.arpa", "0.19.198.in-addr.arpa", "0.0.19.198.in-addr.arpa",
                "255.255.19.198.in-addr.arpa",
            ]
            for prefix in ["b", "db", "r", "dr", "lb"] {
                for zone in zones {
                    let wire = try query(enumeration(zone, prefix: prefix)), original = wire
                    guard let response = try answer(wire) else {
                        throw Failure(text: "A permitted local reverse enumeration did not receive an answer")
                    }
                    try require(DNSMessageInspection.responseMatchesQuery(response, query: wire), "Local response changed question identity")
                    try require(response.count == wire.count && Array(response[4..<12]) == [0, 1, 0, 0, 0, 0, 0, 0],
                                "Local answer created records or removed the question")
                    try require(response[2] == 0x81 && response[3] == 0x80, "Local response claimed an error, authority or DNSSEC validation")
                    try require(wire == original, "Local responder mutated its input")
                }
            }
        }
        check(responseGroups[1]) {
            for id: UInt16 in [0, 1, 0x1234, 0xffff] {
                let wire = try query("Lb._DNS-SD._UDP.42.1.168.192.IN-ADDR.ARPA.", id: id)
                guard let response = try answer(wire) else { throw Failure(text: "No identity-preserving local answer") }
                var expected = wire; expected[2] = 0x81; expected[3] = 0x80
                try require(response == expected, "Response did not preserve exact ID, QNAME case and question bytes")
                try require(DNSMessageInspection.responseMatchesQuery(response, query: wire), "Existing response matcher rejected the local answer")
                var wrongID = response; wrongID[1] ^= 1
                var wrongType = response; wrongType[wrongType.count - 3] = 1
                var wrongClass = response; wrongClass[wrongClass.count - 1] = 3
                for changed in [wrongID, wrongType, wrongClass] {
                    try require(!DNSMessageInspection.responseMatchesQuery(changed, query: wire), "Local response relaxed existing identity matching")
                }
                var framed = Data([0xaa, 0xbb]); framed.append(wire)
                let slice = framed.dropFirst(2)
                try require(slice.startIndex == 2 && (try answer(slice)) == expected,
                            "Nonzero Data indexing changed response identity or crashed the responder")
            }
        }
    }

    private static func excludedNames() {
        check("ordinary PTR and remote discovery retain resolver ownership") {
            let ordinary = ["1.0.0.127.in-addr.arpa", "1.1.168.192.in-addr.arpa", "1.16.18.198.in-addr.arpa",
                            "1.0.19.198.in-addr.arpa", "8.8.8.8.in-addr.arpa", "printer.local", "local",
                            "_http._tcp.local", "_services._dns-sd._udp.1.168.192.in-addr.arpa"]
            for name in ordinary { try assertNoAnswer(name) }
            for prefix in ["b", "db", "r", "dr", "lb"] {
                for suffix in ["local", "example.test", "8.8.8.8.in-addr.arpa", "2.0.192.in-addr.arpa", "ip6.arpa",
                               "in-addr.arpa", "10.in-addr.arpa.evil", "0.127.fake-in-addr.arpa"] {
                    try assertNoAnswer(enumeration(suffix, prefix: prefix))
                }
            }
            for prefix in ["x", "bb", "_b", "_services", "prefix.b"] {
                try assertNoAnswer(enumeration("1.168.192.in-addr.arpa", prefix: prefix))
            }
            for name in ["b._dns-sdx._udp.1.168.192.in-addr.arpa", "b._dns-sd._tcp.1.168.192.in-addr.arpa",
                         "b._dns-sd._udp-fake.1.168.192.in-addr.arpa"] { try assertNoAnswer(name) }
        }
        check("reverse zone boundaries and malformed octets are excluded") {
            for suffix in ["9.in-addr.arpa", "11.in-addr.arpa", "126.in-addr.arpa", "128.in-addr.arpa",
                           "172.in-addr.arpa", "15.172.in-addr.arpa", "32.172.in-addr.arpa",
                           "192.in-addr.arpa", "167.192.in-addr.arpa", "169.192.in-addr.arpa",
                           "169.in-addr.arpa", "253.169.in-addr.arpa", "255.169.in-addr.arpa",
                           "198.in-addr.arpa", "18.198.in-addr.arpa", "15.18.198.in-addr.arpa",
                           "17.18.198.in-addr.arpa", "20.198.in-addr.arpa", "19.199.in-addr.arpa",
                           "64.100.in-addr.arpa", "255.in-addr.arpa", "0.in-addr.arpa",
                           "01.10.in-addr.arpa", "256.10.in-addr.arpa", "-1.10.in-addr.arpa",
                           "1x.10.in-addr.arpa", "١.10.in-addr.arpa", "000.127.in-addr.arpa",
                           "1.2.3.4.10.in-addr.arpa", "x.168.192.in-addr.arpa"] {
                try assertNoAnswer(enumeration(suffix))
            }
        }
        check("QTYPE and QCLASS do not broaden local response support") {
            let name = enumeration("1.168.192.in-addr.arpa")
            for type: UInt16 in [0, 1, 2, 5, 16, 28, 33, 64, 65, 255, 0xffff] { try assertNoAnswer(name, type: type) }
            for dnsClass: UInt16 in [0, 3, 255, 0x8001, 0xffff] { try assertNoAnswer(name, dnsClass: dnsClass) }
        }
    }

    private static func strictWire() {
        check("flags records and malformed packets retain the ordinary wire path") {
            let wire = try query(enumeration("1.168.192.in-addr.arpa")), question = try inspect(wire)
            for flags: UInt16 in [0, 0x8000, 0x8100, 0x4100, 0x2100, 0x1100, 0x0900, 0x0500, 0x0300,
                                  0x0180, 0x0140, 0x0120, 0x0110, 0x0101, 0x0102, 0x010f, 0xffff] {
                var changed = wire
                changed[2] = UInt8(truncatingIfNeeded: flags >> 8); changed[3] = UInt8(truncatingIfNeeded: flags)
                try require(try answer(changed, question: question) == nil, "An unsupported DNS flag was answered locally")
            }
            for (offset, count): (Int, UInt8) in [(5, 0), (5, 2), (6, 1), (7, 1), (8, 1), (9, 1), (10, 1), (11, 1)] {
                var changed = wire; changed[offset] = count
                try require(try answer(changed, question: question) == nil, "An unsupported section count was answered locally")
            }
            for length in 0..<wire.count {
                try require(try answer(Data(wire.prefix(length)), question: question) == nil, "A truncated wire was answered locally")
            }
            var trailing = wire; trailing.append(contentsOf: [0, 0])
            try require(DNSMessageInspection.singleQuestion(in: trailing) == question, "Local helper changed general trailing-byte inspection")
            try require(try answer(trailing, question: question) == nil, "Trailing bytes were silently discarded")
            let oversized = wire + Data(repeating: 0, count: 512)
            let inventedEnd = DNSQueryQuestion(name: question.name, type: question.type, class: question.`class`, questionEnd: oversized.count)
            try require(try answer(oversized, question: inventedEnd) == nil, "A forged large question bypassed complete wire bounds")
            var edns = wire; edns[11] = 1
            // Root OPT, UDP size 1232, EDNS v0 + DO, no options.
            edns.append(contentsOf: [0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0])
            try require(DNSMessageInspection.singleQuestion(in: edns) == question, "EDNS stopped being inspectable by the existing general parser")
            try require(try answer(edns, question: question) == nil, "EDNS/DNSSEC was stripped by a local response")
            var unknownEDNS = edns; unknownEDNS[unknownEDNS.count - 6] = 1
            try require(try answer(unknownEDNS, question: question) == nil, "Unknown EDNS version was handled locally")
        }
        check("compression and forged inspection results cannot authorize answers") {
            let wire = try query(enumeration("1.168.192.in-addr.arpa")), question = try inspect(wire)
            // The existing general parser accepts a forward pointer to the
            // zero high byte of QTYPE. Keep its acceptance unchanged while
            // the deliberately narrower local helper rejects compression.
            let pointerOffset = wire.count - 5
            var compressed = Data(wire.prefix(pointerOffset))
            compressed.append(contentsOf: [0xc0, UInt8(pointerOffset + 2), 0, 12, 0, 1])
            let compressedQuestion = try inspect(compressed)
            try require(compressedQuestion.name == question.name && compressedQuestion.questionEnd == compressed.count,
                        "Existing compressed-question inspection changed")
            try require(try answer(compressed, question: compressedQuestion) == nil, "Compressed QNAME was answered locally")
            var cycle = wire; cycle[12] = 0xc0; cycle[13] = 12
            try require(DNSMessageInspection.singleQuestion(in: cycle) == nil, "Existing cyclic pointer rejection changed")
            try require(try answer(cycle, question: question) == nil, "Cyclic pointer was answered locally")
            let forged = [
                DNSQueryQuestion(name: enumeration("2.168.192.in-addr.arpa"), type: 12, class: 1, questionEnd: question.questionEnd),
                DNSQueryQuestion(name: question.name.uppercased(), type: 12, class: 1, questionEnd: question.questionEnd),
                DNSQueryQuestion(name: question.name, type: 1, class: 1, questionEnd: question.questionEnd),
                DNSQueryQuestion(name: question.name, type: 12, class: 3, questionEnd: question.questionEnd),
                DNSQueryQuestion(name: question.name, type: 12, class: 1, questionEnd: question.questionEnd - 1),
            ]
            for value in forged {
                try require(try answer(wire, question: value) == nil, "Caller-supplied metadata bypassed actual wire identity")
            }
            let remote = try query(enumeration("1.168.193.in-addr.arpa"))
            try require(remote.count == wire.count && (try answer(remote, question: question)) == nil,
                        "Forged local metadata took ownership of a public reverse zone")
        }
    }

    private static func statelessness() {
        check(responseGroups[2]) {
            let encoder = JSONEncoder()
            let before = try encoder.encode(DNSPTRQueryKind.allCases)
            for index in 0..<256 {
                let wire = try query(enumeration("\(index).0.10.in-addr.arpa"), id: UInt16(index)), original = wire
                let inspected = try inspect(wire)
                let category = DNSMessageInspection.ptrTargetCategory(for: inspected)
                guard let response = try answer(wire) else { throw Failure(text: "Independent local caller received no answer") }
                try assertNoAnswer("private-\(index).example.test")
                try require(DNSMessageInspection.responseMatchesQuery(response, query: wire) && wire == original,
                            "Interleaved callers retained another query's ID or bytes")
                try require(DNSMessageInspection.ptrQueryKind(for: inspected) == .dnsSDDomainEnumeration
                            && DNSMessageInspection.ptrTargetCategory(for: inspected) == category,
                            "Local answer changed existing metadata classification")
                try require(try encoder.encode(DNSPTRQueryKind.allCases) == before,
                            "Local processing introduced a name-dependent diagnostic label")
            }
            let json = String(decoding: before, as: UTF8.self)
            try require(!json.contains("in-addr") && !json.contains("private-") && !json.contains("example.test"),
                        "Fixed diagnostic values retained a question name or prefix")
        }
    }

    static func main() {
        localResponses()
        excludedNames()
        strictWire()
        statelessness()
        let report: [String: Any] = ["groups": groups, "assertions": assertions, "failedGroups": failedGroups,
                                   "responseGroups": responseGroups, "memoryOnly": true]
        do { print(String(data: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), encoding: .utf8)!) }
        catch { fputs("Unable to serialize fixture result\n", stderr); exit(1) }
        exit(failedGroups.isEmpty ? 0 : 1)
    }
}
