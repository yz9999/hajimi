import Foundation
import Darwin

@main
struct DNSSplitProfileChecks {
    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    private static var assertions = 0
    private static let doh = "https://dns.google/dns-query#8.8.8.8"
    private static let dot = "tls://dns.example.test:8853#2001:db8::7"

    private static func expect(_ condition: Bool, _ message: String) throws {
        assertions += 1
        if !condition { throw Failure(message: message) }
    }

    private static func rejects(_ message: String, _ action: () throws -> Void) throws {
        var failed = false
        do { try action() } catch { failed = true }
        try expect(failed, message)
    }

    private static func parsed(_ general: String) throws -> Profile {
        try ProfileParser.parse("[General]\n" + general + "\n[Rule]\nFINAL,DIRECT\n")
    }

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("FAILED DNS split profile: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func run() throws {
        var tests = 0
        func test(_ name: String, _ body: () throws -> Void) throws {
            try body()
            tests += 1
            print("PASS \(name)")
        }

        try test("defaults protect DNS without conflating configured lists") {
            let profile = try parsed("fake-ip = false")
            try expect(profile.dnsLeakProtectionEnabled && profile.shouldHijackSystemDNS,
                       "default protection must request the Helper DNS sink even without fake-IP")
            try expect(profile.dnsServers.isEmpty && profile.encryptedDNSServers.isEmpty &&
                       profile.traditionalDNSServers.isEmpty && profile.configuredEncryptedDNSServers.isEmpty,
                       "defaults must not fabricate user-configured DNS entries")
            try expect(!profile.dnsProxyFallbackEnabled && profile.dnsProxyFallbackServers.isEmpty,
                       "proxy-only ordinary DNS fallback must default off with no implicit approval list")
            try expect(profile.dnsSelectionMode == .balanced && profile.dnsPrewarmEnabled,
                       "legacy/default profiles must select balanced mode and connection-only prewarming")
            try expect(!Profile.defaultSecureDNSServers.isEmpty &&
                       profile.effectiveEncryptedDNSServers == Profile.defaultSecureDNSServers &&
                       profile.effectiveDNSServers == Profile.defaultSecureDNSServers,
                       "an empty protected profile must select default encrypted DNS")
            let optedOut = try parsed("dns-leak-protection = false")
            try expect(!optedOut.shouldHijackSystemDNS && optedOut.effectiveEncryptedDNSServers.isEmpty &&
                       optedOut.effectiveDNSServers.isEmpty,
                       "an empty explicitly unprotected profile must retain legacy empty configuration")
        }

        try test("traditional and encrypted options load independently") {
            let traditional = ["1.1.1.1", "udp://127.0.0.1:5300", "[::1]:5400"]
            let profile = try parsed("dns-server = \(traditional.joined(separator: ", "))\n" +
                                     "encrypted-dns-server = \(doh), \(dot)")
            try expect(profile.dnsServers == traditional && profile.traditionalDNSServers == traditional,
                       "traditional DNS storage was contaminated by encrypted settings")
            try expect(profile.encryptedDNSServers == [doh, dot] &&
                       profile.configuredEncryptedDNSServers == [doh, dot],
                       "encrypted DNS storage lost independent ordering or bootstrap pins")
            try expect(profile.effectiveDNSServers == [doh, dot],
                       "application queries must prefer encrypted DNS over traditional settings")
        }

        try test("selection modes retain independent lists and fallback approval") {
            for mode in DNSSelectionMode.allCases {
                let profile = try parsed("dns-selection-mode = \(mode.rawValue)\ndns-prewarm = false\n" +
                    "dns-server = 9.9.9.9\ndns-leak-protection = false\n" +
                    "dns-proxy-fallback = false\ndns-proxy-fallback-server = 1.1.1.1")
                try expect(profile.dnsSelectionMode == mode && !profile.dnsPrewarmEnabled &&
                           !profile.dnsProxyFallbackEnabled && profile.dnsProxyFallbackServers == ["1.1.1.1"],
                           "selecting a mode changed the independent fallback switch or approval list")
                try expect(profile.dnsServers == ["9.9.9.9"] && profile.encryptedDNSServers.isEmpty,
                           "mode selection rewrote raw traditional or encrypted configuration")
                let effective = mode == .balanced ? ["9.9.9.9"] : Profile.defaultSecureDNSServers
                try expect(profile.effectiveDNSServers == effective,
                           "explicit A/C mode inherited the old unprotected traditional-only application path")
                if mode == .mixedSpeed {
                    try expect(profile.warnings.contains { $0.contains("日常择优") && $0.contains("代理出口仍明文") },
                               "mixed mode did not disclose regular ordinary-DNS permission independently of fallback")
                }
            }
            let retained = try parsed("dns-selection-mode = encrypted-only\ndns-proxy-fallback = true\n" +
                                      "dns-proxy-fallback-server = 1.1.1.1")
            try expect(retained.dnsProxyFallbackEnabled && retained.dnsProxyFallbackServers == ["1.1.1.1"] &&
                       !retained.warnings.contains { $0.contains("已启用代理内普通 DNS 后备") },
                       "encrypted-only selection erased stored authorization or advertised an active ordinary fallback")
            try rejects("mixed mode must not inherit traditional DNS as approval") {
                _ = try parsed("dns-selection-mode = mixed-speed\ndns-server = 9.9.9.9")
            }
            for raw in ["fast", "mixedSpeed", "", "1"] {
                try rejects("unknown DNS selection mode was silently ignored: \(raw)") {
                    _ = try parsed("dns-selection-mode = \(raw)")
                }
            }
            for raw in ["false", "no", "off", "0"] {
                try expect(try !parsed("dns-prewarm = \(raw)").dnsPrewarmEnabled,
                           "explicit prewarm opt-out was ignored")
            }
            for raw in ["true", "yes", "on", "1"] {
                try expect(try parsed("dns-prewarm = \(raw)").dnsPrewarmEnabled,
                           "prewarm true flag was not enabled")
            }
            try rejects("invalid prewarm flag silently changed behavior") { _ = try parsed("dns-prewarm = maybe") }
        }

        try test("mode and prewarm edits preserve Surge document text and old approvals") {
            var document = SurgeProfileDocument("[General]\ndns-selection-mode = balanced # keep strategy\n" +
                "dns-prewarm = true # keep prewarm\ndns-proxy-fallback = true # keep consent\n" +
                "dns-proxy-fallback-server = 1.1.1.1 # keep approval\ncustom-option = unchanged\n" +
                "[Rule]\nFINAL,DIRECT # keep rule\n")
            try document.setGeneralOption("dns-selection-mode", value: "encrypted-only")
            try document.setGeneralOption("dns-prewarm", value: "false")
            let profile = try ProfileParser.parse(document.text)
            try expect(profile.dnsSelectionMode == .encryptedOnly && !profile.dnsPrewarmEnabled &&
                       profile.dnsProxyFallbackEnabled && profile.dnsProxyFallbackServers == ["1.1.1.1"],
                       "targeted mode/prewarm editing changed stored ordinary authorization")
            for original in ["# keep strategy", "# keep prewarm", "# keep consent", "# keep approval",
                             "custom-option = unchanged\n", "FINAL,DIRECT # keep rule\n"] {
                try expect(document.text.contains(original), "new DNS options lost original document text: \(original)")
            }
        }

        try test("legacy mixed DNS remains readable and separates by purpose") {
            let upper = "HTTPS://legacy.example.test/dns-query#203.0.113.7"
            let profile = try parsed("dns-server = 1.1.1.1, \(doh), udp://127.0.0.1:5300, \(dot), \(upper)")
            try expect(profile.traditionalDNSServers == ["1.1.1.1", "udp://127.0.0.1:5300"],
                       "legacy encrypted URIs leaked into the traditional resolver list")
            try expect(profile.encryptedDNSServers.isEmpty &&
                       profile.configuredEncryptedDNSServers == [doh, dot, upper],
                       "legacy encrypted DNS must be discovered without rewriting raw user text")
            try expect(profile.effectiveDNSServers == [doh, dot, upper],
                       "legacy mixed configuration fell back to plaintext DNS")
        }

        try test("new-first ordering and stable exact-value deduplication") {
            var profile = Profile()
            profile.dnsServers = [" 1.1.1.1 ", doh, "1.1.1.1", dot, doh, ""]
            profile.encryptedDNSServers = [" \(dot) ", dot, doh, "", doh]
            try expect(profile.traditionalDNSServers == ["1.1.1.1"],
                       "traditional duplicate removal was not stable or whitespace-aware")
            try expect(profile.configuredEncryptedDNSServers == [dot, doh],
                       "new encrypted option must come first with legacy duplicates removed")
            let fromText = try parsed("encrypted-dns-server = \(dot), \(dot), \(doh)\n" +
                                      "dns-server = \(doh), 1.1.1.1, \(dot), 1.1.1.1")
            try expect(fromText.configuredEncryptedDNSServers == [dot, doh] &&
                       fromText.traditionalDNSServers == ["1.1.1.1"],
                       "text loading and direct model construction disagree on DNS ordering")
        }

        try test("invalid encrypted option values remain visible for fail-closed runtime validation") {
            let bad = ["http:///plain", "https:///missing-host", "tls://"]
            let profile = try parsed("dns-server = 9.9.9.9\n" +
                                     "encrypted-dns-server = \(bad.joined(separator: ", "))")
            try expect(profile.encryptedDNSServers == bad && profile.configuredEncryptedDNSServers == bad,
                       "bad encrypted entries were silently filtered instead of reaching runtime validation")
            try expect(profile.effectiveEncryptedDNSServers == bad && profile.effectiveDNSServers == bad,
                       "invalid encrypted configuration must not silently choose traditional or default DNS")
        }

        try test("encrypted preference does not depend on the protection toggle") {
            for flag in ["true", "false"] {
                let profile = try parsed("dns-leak-protection = \(flag)\ndns-server = 9.9.9.9\n" +
                                         "encrypted-dns-server = \(doh)")
                try expect(profile.effectiveEncryptedDNSServers == [doh] && profile.effectiveDNSServers == [doh],
                           "protection=\(flag) changed explicitly configured encrypted query DNS")
            }
        }

        try test("pure traditional settings preserve compatibility and do not create a second list") {
            for flag in ["true", "false"] {
                let profile = try parsed("dns-leak-protection = \(flag)\ndns-server = 127.0.0.1:5300, [::1]:5400")
                try expect(profile.configuredEncryptedDNSServers.isEmpty && profile.effectiveEncryptedDNSServers.isEmpty,
                           "traditional-only settings invented a configured encrypted endpoint")
                try expect(profile.effectiveDNSServers == ["127.0.0.1:5300", "[::1]:5400"],
                           "traditional resolver IP/port semantics changed")
            }
        }

        try test("IPv6, custom ports, quoted pins and real trailing comments coexist") {
            let pinnedHTTPS = "https://dns.example.test:8443/dns-query#2001:db8::8"
            let quoted = "https://quoted.example.test/dns-query#203.0.113.8"
            let profile = try parsed("dns-server = udp://[2001:db8::53]:5353 # traditional comment\n" +
                                     "ENCRYPTED-DNS-SERVER = \(pinnedHTTPS), \(dot), \"\(quoted)\" # encrypted comment")
            try expect(profile.traditionalDNSServers == ["udp://[2001:db8::53]:5353"],
                       "traditional IPv6 port or comment parsing failed")
            try expect(profile.configuredEncryptedDNSServers == [pinnedHTTPS, dot, quoted],
                       "encrypted custom port, IPv6 bootstrap or quoted pin was stripped as a comment")
            let comment = try parsed("encrypted-dns-server = https://dns.google/dns-query #8.8.8.8 is a comment")
            try expect(comment.encryptedDNSServers == ["https://dns.google/dns-query"],
                       "a whitespace-separated hash must remain an ordinary comment")
            let nonIP = try parsed("encrypted-dns-server = https://dns.google/dns-query#ordinary-comment")
            try expect(nonIP.encryptedDNSServers == ["https://dns.google/dns-query"],
                       "a non-IP URI hash must remain an ordinary comment")
        }

        try test("bracketed IPv6 pins survive new and legacy options and targeted replacement") {
            let localPin = "https://dns.google/dns-query#[::1]"
            let remotePin = "tls://dns.example.test:8853#[2001:db8::8]"
            for key in ["dns-server", "encrypted-dns-server"] {
                let profile = try parsed("\(key) = \(localPin), \(remotePin) # keep IPv6")
                try expect(profile.configuredEncryptedDNSServers == [localPin, remotePin],
                           "\(key) stripped a bracketed IPv6 bootstrap as though it were a comment")
                try expect(profile.traditionalDNSServers.isEmpty,
                           "\(key) put bracketed IPv6-pinned encrypted URIs in the traditional list")
            }
            var document = SurgeProfileDocument(
                "[General]\ndns-server = \(localPin)  # keep old legacy comment\n" +
                "encrypted-dns-server = \(remotePin)  # keep old encrypted comment\ncustom = untouched\n")
            try document.setGeneralOption("dns-server", value: "127.0.0.1:5300")
            try document.setGeneralOption("encrypted-dns-server", value: doh)
            let reread = try ProfileParser.parse(document.text)
            try expect(reread.dnsServers == ["127.0.0.1:5300"] && reread.encryptedDNSServers == [doh],
                       "updating bracketed IPv6 pins did not produce the requested two DNS values")
            try expect(!document.text.contains("#[::1]") && !document.text.contains("#[2001:db8::8]") &&
                       document.text.contains("# keep old legacy comment") &&
                       document.text.contains("# keep old encrypted comment") &&
                       document.text.contains("custom = untouched\n"),
                       "old bracketed pins were appended as comments or real comments/unrelated text were lost")
        }

        try test("targeted document updates replace old pins and retain unrelated content") {
            for newline in ["\n", "\r\n"] {
                let original = """
                # profile comment
                [General]
                http-listen = 127.0.0.1:18062 # keep listener
                dns-server = https://old.example.test/dns-query#203.0.113.10  # keep traditional
                encrypted-dns-server = tls://old.example.test:853#2001:db8::10  # keep encrypted
                custom-option = untouched # keep custom
                [Proxy]
                Local = socks5, 127.0.0.1, 1080, password="p,a#ss" # keep node
                [Rule]
                FINAL,DIRECT # keep rule
                [Unknown]
                untouched = literal # keep unknown
                """.replacingOccurrences(of: "\n", with: newline) + newline
                var document = SurgeProfileDocument(original)
                try document.setGeneralOption("dns-server", value: "127.0.0.1:5400")
                try document.setGeneralOption("encrypted-dns-server", value: doh + ", " + dot)
                let reread = try ProfileParser.parse(document.text)
                try expect(reread.dnsServers == ["127.0.0.1:5400"] && reread.encryptedDNSServers == [doh, dot],
                           "saved two DNS options did not reparse independently")
                try expect(!document.text.contains("#203.0.113.10") && !document.text.contains("#2001:db8::10"),
                           "an old bootstrap pin was appended as though it were a real comment")
                for line in ["# profile comment", "http-listen = 127.0.0.1:18062 # keep listener",
                             "custom-option = untouched # keep custom",
                             "Local = socks5, 127.0.0.1, 1080, password=\"p,a#ss\" # keep node",
                             "FINAL,DIRECT # keep rule", "[Unknown]", "untouched = literal # keep unknown"] {
                    try expect(document.text.contains(line + newline), "unrelated text changed: \(line)")
                }
                try expect(document.text.contains("# keep traditional") && document.text.contains("# keep encrypted"),
                           "real DNS option comments were lost")
            }
        }

        try test("saving legacy mixed settings migrates URI pins exactly once") {
            let source = "[General]\ndns-server = 1.1.1.1, \(doh), \(dot)  # keep migrated comment\ncustom = unchanged\n"
            let legacy = try ProfileParser.parse(source)
            var document = SurgeProfileDocument(source)
            try document.setGeneralOption("dns-server", value: legacy.traditionalDNSServers.joined(separator: ", "))
            try document.setGeneralOption("encrypted-dns-server",
                                          value: legacy.configuredEncryptedDNSServers.joined(separator: ", "))
            let migrated = try ProfileParser.parse(document.text)
            try expect(migrated.dnsServers == ["1.1.1.1"] && migrated.encryptedDNSServers == [doh, dot],
                       "legacy DNS values were not saved to their purpose-specific options")
            let traditionalLine = document.text.components(separatedBy: .newlines)
                .first(where: { $0.hasPrefix("dns-server") }) ?? ""
            try expect(!traditionalLine.contains("https://") && !traditionalLine.contains("tls://") &&
                       !traditionalLine.contains("#8.8.8.8") && traditionalLine.contains("# keep migrated comment"),
                       "legacy URI/pin residue contaminated the traditional setting or displaced its real comment")
            try expect(document.text.components(separatedBy: doh).count == 2 &&
                       document.text.components(separatedBy: dot).count == 2 &&
                       document.text.contains("custom = unchanged\n"),
                       "migration duplicated bootstrap URIs or rewrote unrelated fields")
        }

        try test("document insertion/removal keeps the two settings independent") {
            var document = SurgeProfileDocument("[General]\ndns-server = 1.1.1.1 # keep\n[Rule]\nFINAL,DIRECT\n")
            try document.setGeneralOption("encrypted-dns-server", value: doh)
            let both = try ProfileParser.parse(document.text)
            try expect(both.dnsServers == ["1.1.1.1"] && both.encryptedDNSServers == [doh],
                       "adding the encrypted option replaced the traditional option")
            try document.setGeneralOption("encrypted-dns-server", value: nil)
            let traditional = try ProfileParser.parse(document.text)
            try expect(traditional.encryptedDNSServers.isEmpty && traditional.dnsServers == ["1.1.1.1"] &&
                       document.text.contains("dns-server = 1.1.1.1 # keep\n"),
                       "removing encrypted DNS changed the existing traditional value/comment")
        }

        try test("explicit proxy fallback settings stay independent from bootstrap and primary DNS") {
            let profile = try parsed("dns-server = 9.9.9.9\nencrypted-dns-server = \(doh)\n" +
                "dns-proxy-fallback = true\ndns-proxy-fallback-server = 1.1.1.1, [2606:4700:4700::1111]:5353")
            try expect(profile.dnsProxyFallbackEnabled &&
                       profile.dnsProxyFallbackServers == ["1.1.1.1", "[2606:4700:4700::1111]:5353"],
                       "explicit opt-in/list did not survive General parsing")
            try expect(profile.traditionalDNSServers == ["9.9.9.9"] && profile.effectiveDNSServers == [doh],
                       "fallback approval contaminated bootstrap settings or changed the primary encrypted resolver")
            try expect(profile.warnings.contains { $0.contains("代理出口仍明文") && $0.contains("节点可见") },
                       "opt-in profile must surface the exit/node privacy downgrade")
            let disabled = try parsed("dns-proxy-fallback = false\ndns-proxy-fallback-server = 1.1.1.1")
            try expect(!disabled.dnsProxyFallbackEnabled && disabled.dnsProxyFallbackServers == ["1.1.1.1"],
                       "disabling fallback erased the independent user-approved list")
            for flag in ["yes", "on", "1"] {
                try expect(try parsed("dns-proxy-fallback = \(flag)\ndns-proxy-fallback-server = 8.8.8.8").dnsProxyFallbackEnabled,
                           "accepted true flag was not enabled")
            }
            for flag in ["no", "off", "0"] {
                try expect(try !parsed("dns-proxy-fallback = \(flag)").dnsProxyFallbackEnabled,
                           "accepted false flag changed defaults")
            }
            try rejects("fallback flag must not silently accept malformed text") { _ = try parsed("dns-proxy-fallback = maybe") }
            try rejects("empty opt-in silently inherited traditional bootstrap servers") {
                _ = try parsed("dns-server = 9.9.9.9\ndns-proxy-fallback = true")
            }
            try rejects("more than 8 explicit entries bypassed the configuration bound") {
                _ = try parsed("dns-proxy-fallback-server = " + Array(repeating: "1.1.1.1", count: 9).joined(separator: ", "))
            }
        }

        try test("proxy fallback numeric parser normalizes allowed addresses and rejects unsafe sinks") {
            let positive: [(String, String, UInt16)] = [
                (" 8.8.8.8 ", "8.8.8.8", 53), ("1.1.1.1:5353", "1.1.1.1", 5353),
                ("[2606:4700:4700::1111]:65535", "2606:4700:4700::1111", 65535),
                ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888", 53),
                ("10.0.0.53", "10.0.0.53", 53), ("172.16.0.53", "172.16.0.53", 53),
                ("192.168.10.53", "192.168.10.53", 53), ("[fd12:3456::53]:53", "fd12:3456::53", 53),
                ("[::ffff:8.8.8.8]:53", "::ffff:8.8.8.8", 53)]
            for (raw, host, port) in positive {
                let value = DNSProxyFallbackServer(raw)
                try expect(value?.host == host && value?.port == port, "valid numeric fallback endpoint failed: \(raw)")
            }
            let invalid = ["", "system", "localhost", "dns.google", "udp://8.8.8.8:53", "tcp://8.8.8.8:53",
                "https://8.8.8.8/dns-query", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:bad", "1.1.1.1 :53",
                "127.1", "[1.1.1.1]:53", "0.0.0.0", "0.1.2.3", "127.0.0.1", "127.9.8.7", "169.254.1.53",
                "224.0.0.1", "239.1.2.3", "255.255.255.255", "198.18.0.53", "198.18.16.2", "198.19.255.53",
                "::", "::1", "[fe80::53]:53", "[febf::53]:53", "[fe80::1%en1]:53", "ff02::1",
                "[fd00:6861:6a69::2]:53", "[fd00:6861:6a69:ffff::53]:53", "[fd00:7162::53]:53",
                "[::ffff:127.0.0.1]:53", "[::ffff:169.254.1.53]:53", "[::ffff:198.18.16.2]:53",
                "[::ffff:198.19.0.53]:53", "[::ffff:224.0.0.1]:53"]
            for raw in invalid {
                try expect(DNSProxyFallbackServer(raw) == nil, "unsafe/non-numeric fallback endpoint was accepted: \(raw)")
                if !raw.isEmpty {
                    try rejects("invalid explicit server was retained as a usable approval: \(raw)") {
                        _ = try parsed("dns-proxy-fallback-server = \(raw)")
                    }
                }
            }
        }

        try test("fallback targeted updates preserve comments and disabling keeps approvals") {
            var document = SurgeProfileDocument("[General]\ndns-server = 9.9.9.9 # bootstrap only\n" +
                "dns-proxy-fallback = true # accepted downgrade\n" +
                "dns-proxy-fallback-server = 1.1.1.1 # explicit approval\ncustom = untouched\n[Rule]\nFINAL,DIRECT\n")
            try document.setGeneralOption("dns-proxy-fallback", value: "false")
            let disabled = try ProfileParser.parse(document.text)
            try expect(!disabled.dnsProxyFallbackEnabled && disabled.dnsProxyFallbackServers == ["1.1.1.1"] &&
                       disabled.traditionalDNSServers == ["9.9.9.9"], "turning the option off lost the explicit or bootstrap list")
            try expect(document.text.contains("# accepted downgrade") && document.text.contains("# explicit approval") &&
                       document.text.contains("custom = untouched\n"), "fallback General edits destroyed comments/unrelated text")
            try document.setGeneralOption("dns-proxy-fallback-server", value: nil)
            try expect(try ProfileParser.parse(document.text).dnsProxyFallbackServers.isEmpty,
                       "explicit clearing did not remove the fallback allowlist")
        }

        try test("Codable round-trip and legacy JSON missing the new field") {
            var profile = try parsed("dns-server = 1.1.1.1, \(dot)\nencrypted-dns-server = \(doh)\n" +
                                     "http-api = secret@127.0.0.1:9090\nfake-ip = true\nalways-real-ip = *.example.test")
            profile.warnings.append("fixture warning")
            let encoded = try JSONEncoder().encode(profile)
            let roundTrip = try JSONDecoder().decode(Profile.self, from: encoded)
            try expect(roundTrip == profile && roundTrip.effectiveDNSServers == [doh, dot],
                       "new DNS field or existing profile data did not survive Codable round-trip")
            guard var object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
                throw Failure(message: "encoded Profile was not a JSON object")
            }
            try expect(object["encryptedDNSServers"] != nil, "new encrypted DNS field was not encoded")
            object.removeValue(forKey: "encryptedDNSServers")
            let oldJSON = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            let old = try JSONDecoder().decode(Profile.self, from: oldJSON)
            var expected = profile
            expected.encryptedDNSServers = []
            try expect(old == expected && old.configuredEncryptedDNSServers == [dot] &&
                       old.traditionalDNSServers == ["1.1.1.1"],
                       "legacy JSON should default only the new field and keep mixed DNS compatibility")
            object["encryptedDNSServers"] = "not-an-array"
            let invalid = try JSONSerialization.data(withJSONObject: object)
            try rejects("malformed new JSON field was silently ignored") {
                _ = try JSONDecoder().decode(Profile.self, from: invalid)
            }
        }
        try test("fallback Codable fields round-trip and missing legacy fields default safely") {
            let profile = try parsed("dns-server = 9.9.9.9\nencrypted-dns-server = \(doh)\n" +
                "dns-proxy-fallback = true\ndns-proxy-fallback-server = 1.1.1.1, [2606:4700:4700::1111]:5353")
            let encoded = try JSONEncoder().encode(profile)
            try expect(try JSONDecoder().decode(Profile.self, from: encoded) == profile,
                       "fallback opt-in/raw approval list was lost during JSON round-trip")
            guard let initial = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
                throw Failure(message: "fallback Profile encoding is not a JSON object")
            }
            var old = initial; old.removeValue(forKey: "dnsProxyFallbackEnabled"); old.removeValue(forKey: "dnsProxyFallbackServers")
            let decoded = try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: old))
            try expect(!decoded.dnsProxyFallbackEnabled && decoded.dnsProxyFallbackServers.isEmpty &&
                       decoded.encryptedDNSServers == profile.encryptedDNSServers && decoded.dnsServers == profile.dnsServers,
                       "old JSON inherited bootstrap DNS as explicit fallback or changed primary settings")
            for mutation in ["wrong-enabled-type", "wrong-list-type", "unsafe-list", "empty-enabled-list"] {
                var object = initial
                switch mutation {
                case "wrong-enabled-type": object["dnsProxyFallbackEnabled"] = "true"
                case "wrong-list-type": object["dnsProxyFallbackServers"] = "1.1.1.1"
                case "unsafe-list": object["dnsProxyFallbackServers"] = ["198.18.16.2"]
                default: object["dnsProxyFallbackServers"] = [] as [String]
                }
                try rejects("malformed fallback JSON was silently accepted: \(mutation)") {
                    _ = try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: object))
                }
            }
        }
        try test("mode and prewarm Codable defaults preserve old calls and reject malformed data") {
            let baseline = try parsed("dns-server = 9.9.9.9\nencrypted-dns-server = \(doh)\n" +
                "dns-proxy-fallback-server = 1.1.1.1")
            for mode in DNSSelectionMode.allCases {
                var profile = baseline
                profile.dnsSelectionMode = mode
                profile.dnsPrewarmEnabled = false
                let bytes = try JSONEncoder().encode(profile)
                try expect(try JSONDecoder().decode(Profile.self, from: bytes) == profile,
                           "mode/prewarm JSON round-trip changed the profile or authorization")
                let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
                try expect(object["dnsSelectionMode"] as? String == mode.rawValue &&
                           object["dnsPrewarmEnabled"] as? Bool == false,
                           "synthesized encoding did not emit canonical mode/prewarm values")
            }
            let encoded = try JSONEncoder().encode(baseline)
            let initial = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            var legacy = initial
            legacy.removeValue(forKey: "dnsSelectionMode")
            legacy.removeValue(forKey: "dnsPrewarmEnabled")
            try expect(try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: legacy)) == baseline,
                       "old JSON without mode/prewarm fields changed legacy resolver or consent state")
            for mutation in ["unknown-mode", "wrong-mode-type", "wrong-prewarm-type", "mixed-without-approval"] {
                var object = initial
                switch mutation {
                case "unknown-mode": object["dnsSelectionMode"] = "automatic"
                case "wrong-mode-type": object["dnsSelectionMode"] = true
                case "wrong-prewarm-type": object["dnsPrewarmEnabled"] = "true"
                default:
                    object["dnsSelectionMode"] = "mixed-speed"
                    object["dnsProxyFallbackServers"] = [] as [String]
                }
                try rejects("malformed new DNS JSON was silently accepted: \(mutation)") {
                    _ = try JSONDecoder().decode(Profile.self, from: JSONSerialization.data(withJSONObject: object))
                }
            }
            var changedMode = baseline; changedMode.dnsSelectionMode = .encryptedOnly
            var changedPrewarm = baseline; changedPrewarm.dnsPrewarmEnabled = false
            try expect(changedMode != baseline && changedPrewarm != baseline,
                       "structural Profile equality omitted mode or prewarm from reload identity")
        }
        print("DNS split profile checks passed: \(tests) cases, \(assertions) assertions")
    }
}
