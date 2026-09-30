import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data("FAILED: \(message)\n".utf8))
        exit(1)
    }
}

do {
    let profile = try ProfileParser.parse(defaultProfileText)
    expect(profile.httpListen.port == 7262, "default HTTP port")
    expect(profile.socksListen.port == 7263, "default SOCKS port")

    let secureProxies = try ProfileParser.parse("""
    [Proxy]
    SecureHTTP = https, 127.0.0.1, 8443, username=alice, password="s,ec#ret", sni=proxy.example.test, alpn=http/1.1
    SecureSOCKS = socks5-tls, 127.0.0.1, 9443, username=bob, password="s,ocks", servername=socks.example.test, skip-cert-verify=true
    TLSFlagHTTP = http, proxy.example.test, 443, tls=true
    TLSFlagSOCKS = socks5, socks.example.test, 443, tls=on
    ChainedTLS = https, proxy.example.test, 443, underlying-proxy=SecureHTTP
    [Rule]
    FINAL,SecureHTTP
    """)
    let target = RequestTarget(host: "example.com", port: 443, protocolName: "TCP")
    if case .http(let policy, _) = secureProxies.route(for: target, mode: .proxy,
                                                      globalPolicy: "SecureHTTP") {
        expect(policy.parameters["tls"] == "true", "HTTPS route must require TLS")
        expect(policy.username == "alice" && policy.password == "s,ec#ret",
               "HTTPS retains Basic-auth credentials")
        expect(policy.parameters["sni"] == "proxy.example.test", "HTTPS retains SNI")
        expect(!policy.skipsCertificateVerification, "HTTPS validates certificates by default")
    } else {
        expect(false, "HTTPS must route as a real HTTP outbound")
    }
    if case .socks5(let policy, _) = secureProxies.route(for: target, mode: .proxy,
                                                        globalPolicy: "SecureSOCKS") {
        expect(policy.parameters["tls"] == "true", "SOCKS5-TLS route must require TLS")
        expect(policy.username == "bob" && policy.password == "s,ocks",
               "SOCKS5-TLS retains username/password")
        expect(policy.parameters["servername"] == "socks.example.test", "SOCKS5-TLS retains SNI")
        expect(policy.skipsCertificateVerification, "explicit skip-cert-verify remains visible")
    } else {
        expect(false, "SOCKS5-TLS must route as a real SOCKS outbound")
    }
    expect(secureProxies.proxies["TLSFlagHTTP"]?.kind == .http &&
           secureProxies.proxies["TLSFlagSOCKS"]?.kind == .socks5,
           "explicit tls=true HTTP/SOCKS proxies are usable too")
    expect(secureProxies.proxies["ChainedTLS"]?.kind == .external,
           "unimplemented proxy chaining stays explicitly unsupported")

    for name in ["SecureHTTP", "SecureSOCKS"] {
        guard let original = secureProxies.proxies[name] else {
            expect(false, "secure proxy must exist: \(name)")
            continue
        }
        let draft = SurgeProxyDraft(policy: original)
        expect(draft.type == (name == "SecureHTTP" ? "https" : "socks5-tls"),
               "profile editor must preserve secure proxy type: \(name)")
        var document = SurgeProfileDocument("[Proxy]\n")
        try document.upsertProxy(originalName: nil, draft: draft)
        let reparsed = try ProfileParser.parse(document.text)
        expect(reparsed.proxies[name]?.kind == original.kind &&
               reparsed.proxies[name]?.parameters["tls"] == "true",
               "editor save/load must preserve TLS routing: \(name)")
    }
    for definition in [
        "Downgrade = https, proxy.example.test, 443, tls=false",
        "DowngradeSOCKS = socks5-tls, proxy.example.test, 443, tls=off",
        "BadFlag = http, proxy.example.test, 443, tls=maybe"
    ] {
        do {
            _ = try ProfileParser.parse("[Proxy]\n\(definition)\n")
            expect(false, "invalid TLS configuration must be rejected: \(definition)")
        } catch let error as ProfileParseError {
            expect(error.message.contains("TLS") || error.message.contains("tls"),
                   "invalid TLS configuration must explain failure")
        }
    }

    let rules = try ProfileParser.parse("""
    [Proxy]
    Upstream = http, proxy.example.com, 8080, user, pass
    [Proxy Group]
    Proxy = select, Upstream, DIRECT
    [Rule]
    DOMAIN-SUFFIX,example.com,Proxy
    IP-CIDR,10.0.0.0/8,REJECT
    FINAL,DIRECT
    """)
    let domainRoute = rules.route(for: .init(host: "www.example.com", port: 443, protocolName: "HTTPS"),
                                  mode: .rule, globalPolicy: "DIRECT")
    if case .http(let proxy, _) = domainRoute {
        expect(proxy.host == "proxy.example.com", "HTTP proxy route")
        expect(proxy.username == "user", "HTTP proxy username")
    } else {
        expect(false, "domain suffix should select HTTP proxy")
    }
    expect(rules.route(for: .init(host: "notexample.com", port: 443, protocolName: "HTTPS"),
                       mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT",
           "domain suffix boundary")
    expect(rules.route(for: .init(host: "10.2.3.4", port: 80, protocolName: "TCP"),
                       mode: .rule, globalPolicy: "DIRECT").policyName == "REJECT",
           "IPv4 CIDR")
    expect(rules.route(for: .init(host: "93.184.216.34", port: 443, protocolName: "TCP"),
                       mode: .rule, globalPolicy: "DIRECT", alternateHost: "www.example.com").policyName == "Upstream",
           "DNS-mapped domain routing")

    let bootstrapDNS = try ProfileParser.parse("""
    [General]
    dns-server = udp://127.0.0.1:53, https://custom.doh.example/dns-query#203.0.113.15, tls://custom.dot.example#2001:db8::15 # ordinary comment
    [Proxy]
    Secret = trojan, proxy.example.com, 443, password="p#ss" # proxy comment
    [Rule]
    FINAL,DIRECT # rule comment
    """)
    expect(bootstrapDNS.dnsServers == [
        "udp://127.0.0.1:53", "https://custom.doh.example/dns-query#203.0.113.15",
        "tls://custom.dot.example#2001:db8::15"
    ], "DNS URL bootstrap and inline comment must coexist in one endpoint list")
    expect(bootstrapDNS.proxies["Secret"]?.parameters["password"] == "p#ss",
           "quoted proxy password '#' must not become a comment")
    expect(bootstrapDNS.rules.count == 1, "regular rule inline comment must still parse")
    let commentedDNS = try ProfileParser.parse("""
    [General]
    dns-server = https://custom.doh.example/dns-query#not-an-ip
    """)
    expect(commentedDNS.dnsServers == ["https://custom.doh.example/dns-query"],
           "non-IP DNS fragment remains an ordinary comment")
    let spacedDNS = try ProfileParser.parse("""
    [General]
    dns-server = https://custom.doh.example/dns-query #203.0.113.15
    """)
    expect(spacedDNS.dnsServers == ["https://custom.doh.example/dns-query"],
           "whitespace before '#' keeps DNS comments intact")

    let advanced = try ProfileParser.parse("""
    [Proxy]
    SS = Shadowsocks, 127.0.0.1, 10001, aes-128-gcm, "p,a#ss"
    SSR = ShadowsocksR, 127.0.0.1, 10002, chacha20-ietf, "YWJjZA==", origin, plain
    Snell = Snell, 127.0.0.1, 10003, psk, 4
    VMess = VMess, 127.0.0.1, 10004, 00000000-0000-0000-0000-000000000001
    VLESS = VLESS, 127.0.0.1, 10005, 00000000-0000-0000-0000-000000000001
    Trojan = Trojan, 127.0.0.1, 10006, pass
    AnyTLS = AnyTLS, 127.0.0.1, 10007, pass
    HY = hy, 127.0.0.1, 10008, auth, 10 Mbps, 50 Mbps
    HY2 = hy2, 127.0.0.1, 10009, pass, obfs=salamander, obfs-password="se,cr#et"
    TUIC = TUIC, 127.0.0.1, 10010, token
    SSH = SSH, 127.0.0.1, 10011, user, pass
    [Proxy Group]
    Proxy = select, SS, SSR, Snell, VMess, VLESS, Trojan, AnyTLS, HY, HY2, TUIC, SSH
    [Rule]
    FINAL,Proxy
    """)
    expect(advanced.adapterPolicies.count == 11, "all advanced protocols parsed")
    expect(advanced.proxies["SS"]?.adapterType == "ss", "Shadowsocks alias")
    expect(advanced.proxies["SSR"]?.adapterType == "ssr", "ShadowsocksR alias")
    expect(advanced.proxies["SSR"]?.parameters["password"] == "YWJjZA==",
           "positional base64 credential")
    expect(advanced.proxies["HY"]?.adapterType == "hysteria", "Hysteria alias")
    expect(advanced.proxies["HY2"]?.adapterType == "hysteria2", "Hysteria2 alias")
    expect(advanced.proxies["SS"]?.parameters["password"] == "p,a#ss",
           "quoted commas and comments in credentials")
    expect(advanced.proxies["HY2"]?.parameters["obfs-password"] == "se,cr#et",
           "advanced key/value parameters")
    if case .reject(let reason) = advanced.route(
        for: .init(host: "example.com", port: 443, protocolName: "TCP"),
        mode: .proxy, globalPolicy: "SS"
    ) {
        expect(reason.contains("Adapter not running"), "external policy requires runtime adapter")
    } else {
        expect(false, "unprepared external policy must reject")
    }

    var surge = try ProfileParser.parse("""
    [General]
    allow-wifi-access = true
    wifi-access-http-port = 6152
    wifi-access-socks5-port = 6153
    skip-proxy = localhost, *.local
    [Proxy]
    Base = vmess, 127.0.0.1, 10001, username=00000000-0000-0000-0000-000000000001, vmess-aead=true
    Nested = socks5, 127.0.0.1, 10002, username=user, password=pass, underlying-proxy=Base
    [Proxy Group]
    Select = select, Base, DIRECT, hidden=1
    Balance = load-balance, DIRECT, REJECT
    [Rule]
    RULE-SET,file:///tmp/hajimi.rules,DIRECT,update-interval=3600
    IP-CIDR6,2001:db8::/32,REJECT
    FINAL,Select
    [MITM]
    enable = true
    [WireGuard FixtureWG]
    private-key = eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    self-ip = 172.16.0.2
    peer = (public-key = Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = 127.0.0.1:51820)
    """)
    expect(surge.surgeCompatible, "Surge compatibility detected")
    expect(surge.httpListen == .init(host: "0.0.0.0", port: 6152), "Surge Wi-Fi HTTP port")
    expect(surge.socksListen == .init(host: "0.0.0.0", port: 6153), "Surge Wi-Fi SOCKS port")
    expect(surge.proxyBypassDomains == ["localhost", "*.local"], "Surge skip-proxy")
    expect(surge.groups["Select"]?.members == ["Base", "DIRECT"], "group options excluded")
    expect(surge.groups["Balance"]?.kind == .loadBalance, "load-balance group")
    expect(surge.proxies["Nested"]?.kind == .external, "underlying SOCKS promoted to adapter")
    expect(surge.proxies["FixtureWG"]?.adapterType == "wireguard", "WireGuard section")
    expect(surge.warnings.contains(where: { $0.contains("MITM") }), "ignored section warning")

    let insecure = try ProfileParser.parse("""
    [Proxy]
    Safe = trojan, 127.0.0.1, 443, password=pw, sni=example.com
    Risk = trojan, 127.0.0.1, 443, password=pw, skip-cert-verify=true
    Also = vmess, 127.0.0.1, 443, uuid=00000000-0000-0000-0000-000000000001, tls=true, skip-common-name-verify=true
    [Rule]
    FINAL,DIRECT
    """)
    expect(insecure.proxies["Risk"]?.skipsCertificateVerification == true,
           "skip-cert-verify should mark the policy")
    expect(insecure.proxiesSkippingCertificateVerification == ["Risk", "Also"],
           "skip-cert-verify names should keep profile order")
    expect(insecure.warnings.contains(where: { $0.contains("跳过服务器证书验证") }),
           "profile parse must surface a skip-cert-verify warning")
    expect(SkipCertificateWarning.lineDisablesVerification(
        "Risk = trojan, 127.0.0.1, 443, password=pw, skip-cert-verify=true"),
           "Surge line detector should see skip-cert-verify=true")
    expect(!SkipCertificateWarning.lineDisablesVerification(
        "Safe = trojan, 127.0.0.1, 443, password=pw, sni=example.com"),
           "Surge line detector must not flag a verified node")
    let ruleSet = SurgeRuleSetParser.parse("""
    DOMAIN-SUFFIX,surge.example
    IP-CIDR6,2001:db8:1::/48,no-resolve
    USER-AGENT,Fixture*
    """)
    expect(ruleSet.rules.count == 2, "Surge RULE-SET supported entries")
    expect(ruleSet.ignoredTypes["USER-AGENT"] == 1, "Surge RULE-SET ignored entry report")
    surge.ruleSetContents["file:///tmp/hajimi.rules"] = ruleSet.rules
    expect(surge.route(for: .init(host: "www.surge.example", port: 443, protocolName: "TCP"),
                       mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT",
           "Surge RULE-SET domain routing")
    expect(RuleKind.ipCIDR("2001:db8::/32").matches(
        .init(host: "2001:db8:abcd::1", port: 443, protocolName: "TCP")), "IPv6 CIDR")
    let balancedTarget = RequestTarget(host: "balance.example", port: 443, protocolName: "TCP")
    let firstBalanced = surge.route(for: balancedTarget, mode: .proxy, globalPolicy: "Balance")
    let secondBalanced = surge.route(for: balancedTarget, mode: .proxy, globalPolicy: "Balance")
    expect(firstBalanced.policyName == secondBalanced.policyName, "stable load-balance selection")

    let surgeControl = try ProfileParser.parse("""
    [General]
    fake-ip = true
    always-real-ip = *.apple.com, captive.apple.com
    hijack-dns = 8.8.8.8:53, *:53
    http-api = secret@127.0.0.1:6171
    external-controller-access = cli@127.0.0.1:6170
    tun-excluded-routes = 10.0.0.0/8, 192.168.0.0/16
    tun-included-routes = 1.1.1.0/24
    include-all-networks = false
    [Proxy]
    Node = socks5, 127.0.0.1, 1080
    Extra = socks5, 127.0.0.1, 1081
    [Proxy Group]
    Smart = smart, Node, DIRECT, url=http://www.gstatic.com/generate_204
    Subnet = subnet, Node, DIRECT
    All = select, include-all-proxies=true
    Combined = select, include-other-group=All
    [Rule]
    DOMAIN-WILDCARD,*.youtube.com,Node
    SRC-IP,10.0.0.0/8,DIRECT
    IN-PORT,7162,Node
    AND,((DOMAIN-SUFFIX,google.com),(DEST-PORT,443)),Node
    OR,((DOMAIN,a.example),(DOMAIN,b.example)),Node
    FINAL,DIRECT
    """)
    expect(surgeControl.fakeIPEnabled, "fake-ip general option")
    expect(surgeControl.shouldHijackSystemDNS, "hijack-dns should steal system DNS")
    expect(surgeControl.alwaysRealIP == ["*.apple.com", "captive.apple.com"], "always-real-ip list")
    expect(surgeControl.skipsFakeIP(for: "captive.apple.com"), "always-real-ip exact/suffix")
    expect(surgeControl.skipsFakeIP(for: "gsp64-ssl.ls.apple.com"), "always-real-ip wildcard")
    expect(!surgeControl.skipsFakeIP(for: "youtube.com"), "unrelated name is not always-real-ip")
    expect(surgeControl.httpAPI == .init(host: "127.0.0.1", port: 6171), "http-api listen")
    expect(surgeControl.httpAPIKey == "secret", "http-api key")
    expect(surgeControl.externalController == .init(host: "127.0.0.1", port: 6170),
           "external-controller listen")
    expect(surgeControl.tunExcludedRoutes == ["10.0.0.0/8", "192.168.0.0/16"],
           "tun-excluded-routes")
    expect(surgeControl.tunIncludedRoutes == ["1.1.1.0/24"], "tun-included-routes")
    expect(surgeControl.groups["Smart"]?.kind == .smart, "smart group")
    expect(surgeControl.groups["Subnet"]?.kind == .subnet, "subnet group")
    expect(surgeControl.groups["All"]?.members.contains("Node") == true,
           "include-all-proxies should copy every proxy")
    expect(surgeControl.groups["All"]?.members.contains("Extra") == true,
           "include-all-proxies should copy Extra")
    expect(surgeControl.groups["Combined"]?.members.contains("Node") == true,
           "include-other-group should copy All's members")
    expect(surgeControl.groups["Combined"]?.members.contains("Extra") == true,
           "include-other-group should copy Extra via All")
    expect(surgeControl.route(for: .init(host: "www.youtube.com", port: 443, protocolName: "TCP"),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "Node",
           "DOMAIN-WILDCARD")
    expect(surgeControl.route(for: .init(host: "example.com", port: 80, protocolName: "TCP",
                                         sourceHost: "10.1.2.3"),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT",
           "SRC-IP")
    expect(surgeControl.route(for: .init(host: "example.com", port: 80, protocolName: "TCP",
                                         inboundPort: 7162),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "Node",
           "IN-PORT")
    expect(surgeControl.route(for: .init(host: "mail.google.com", port: 443, protocolName: "TCP"),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "Node",
           "AND domain+port")
    expect(surgeControl.route(for: .init(host: "mail.google.com", port: 80, protocolName: "TCP"),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT",
           "AND should fail when port differs")
    expect(surgeControl.route(for: .init(host: "a.example", port: 80, protocolName: "TCP"),
                              mode: .rule, globalPolicy: "DIRECT").policyName == "Node",
           "OR first operand")

    let notRule = try ProfileParser.parse("""
    [Proxy]
    Node = socks5, 127.0.0.1, 1080
    [Rule]
    NOT,((DOMAIN,skip.example)),Node
    FINAL,DIRECT
    """)
    expect(notRule.route(for: .init(host: "keep.example", port: 80, protocolName: "TCP"),
                         mode: .rule, globalPolicy: "DIRECT").policyName == "Node",
           "NOT unmatched name")
    expect(notRule.route(for: .init(host: "skip.example", port: 80, protocolName: "TCP"),
                         mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT",
           "NOT matched name falls through")

    let editableText = """
    # keep this comment
    [General]
    http-listen = 127.0.0.1:7162
    socks5-listen = 127.0.0.1:7163
    [Proxy]
    Old Node = vmess, old.example, 443, uuid=old-id # keep node note
    Child = socks5, 127.0.0.1, 1080, underlying-proxy=Old Node
    [Proxy Group]
    Main = select, Old Node, Child, DIRECT, hidden=0
    [Rule]
    DOMAIN-SUFFIX,example.com,Old Node
    FINAL,Main
    [MITM]
    enable = true
    """
    var document = SurgeProfileDocument(editableText)
    try document.upsertProxy(originalName: "Old Node", draft: .init(
        name: "Renamed, Node", type: "vmess", host: "new.example", port: 8443,
        parameters: [
            "uuid": "new-id", "password": "p,a#ss", "network": "ws",
            "ws-path": "/socket", "unknown-option": "kept"
        ]
    ))
    var edited = try ProfileParser.parse(document.text)
    expect(edited.proxies["Renamed, Node"]?.host == "new.example", "structured proxy rename")
    expect(edited.proxies["Renamed, Node"]?.parameters["password"] == "p,a#ss",
           "structured editor credential quoting")
    expect(edited.groups["Main"]?.members.contains("Renamed, Node") == true,
           "rename updates group references")
    expect(edited.rules.first?.policy == "Renamed, Node", "rename updates rule references")
    expect(edited.proxies["Child"]?.parameters["underlying-proxy"] == "Renamed, Node",
           "rename updates underlying proxy")
    expect(document.text.contains("# keep node note"), "inline comment preserved")
    expect(document.text.contains("[MITM]\nenable = true"), "unknown section preserved")

    try document.deleteProxy(named: "Renamed, Node")
    edited = try ProfileParser.parse(document.text)
    expect(edited.proxies["Renamed, Node"] == nil, "structured proxy deletion")
    expect(edited.groups["Main"]?.members.contains("Renamed, Node") == false,
           "deletion removes group member")
    expect(edited.rules.first?.policy == "DIRECT", "deletion redirects rule references")
    expect(edited.proxies["Child"]?.parameters["underlying-proxy"] == "DIRECT",
           "deletion redirects dialer references")

    try document.upsertProxy(originalName: nil, draft: .init(
        name: "Added", type: "ss", host: "ss.example", port: 8388,
        parameters: ["cipher": "aes-128-gcm", "password": "secret"]
    ))
    edited = try ProfileParser.parse(document.text)
    expect(edited.proxies["Added"]?.adapterType == "ss", "structured proxy insertion")

    try document.upsertGroup(originalName: "Main", draft: .init(
        name: "Renamed Group", kind: .fallback,
        members: ["Child", "Added", "DIRECT"],
        parameters: ["url": "http://www.gstatic.com/generate_204", "interval": "300"]
    ))
    edited = try ProfileParser.parse(document.text)
    expect(edited.groups["Renamed Group"]?.kind == .fallback, "structured group type edit")
    expect(edited.groups["Renamed Group"]?.members == ["Child", "Added", "DIRECT"],
           "structured group member edit")
    expect(edited.rules.last?.policy == "Renamed Group", "group rename updates rules")
    try document.upsertGroup(originalName: nil, draft: .init(
        name: "New Group", kind: .select, members: ["Added", "DIRECT"]
    ))
    edited = try ProfileParser.parse(document.text)
    expect(edited.groups["New Group"]?.members == ["Added", "DIRECT"], "structured group insertion")
    try document.deleteGroup(named: "Renamed Group")
    edited = try ProfileParser.parse(document.text)
    expect(edited.groups["Renamed Group"] == nil, "structured group deletion")
    expect(edited.rules.last?.policy == "DIRECT", "group deletion redirects rules")
    try document.setGeneralOption("dns-server", value: "1.1.1.1, 8.8.8.8:53")
    edited = try ProfileParser.parse(document.text)
    expect(edited.dnsServers == ["1.1.1.1", "8.8.8.8:53"],
           "DNS settings targeted profile update")
    try document.setGeneralOption("dns-server", value: nil)
    edited = try ProfileParser.parse(document.text)
    expect(edited.dnsServers.isEmpty, "DNS settings removal")
    expect(document.text.contains("# keep this comment"), "DNS edit preserves comments")
    var largeProfile = Profile()
    for index in 0..<300 {
        let name = "VMess \(index)"
        largeProfile.proxies[name] = ProxyPolicy(name: name, kind: .native,
            host: "192.0.2.\(index % 250 + 1)", port: 443, adapterType: "vmess",
            parameters: ["uuid": "00000000-0000-0000-0000-000000000001",
                         "ws-path": "/profile-payload-\(index)"])
        largeProfile.proxyOrder.append(name)
    }
    let encodedProfile = try JSONEncoder().encode(largeProfile)
    expect(encodedProfile.count > 8_192, "helper profile fixture exceeds legacy IPC limit")
    let decodedProfile = try JSONDecoder().decode(Profile.self, from: encodedProfile)
    expect(decodedProfile == largeProfile,
           "large helper profile Codable round trip")
    print("Profile smoke tests passed")
} catch {
    FileHandle.standardError.write(Data("FAILED: \(error)\n".utf8))
    exit(1)
}
