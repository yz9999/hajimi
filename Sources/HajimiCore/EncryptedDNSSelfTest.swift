import Foundation
import HajimiDNS
import Network
import Security
import Darwin

// MARK: - Extracted Encrypted DNS & Protocol-Rule Self-Test Suites

extension EncryptedDNSSelfTest {
    static func frontierProtocolsAndWireExtensions() throws {
        // 1. RFC 9250 DoQ (DNS over Dedicated QUIC) endpoint & wire framing
        guard let doqLiteral = DoQEndpoint("quic://1.1.1.1"),
              let doqBuiltin = DoQEndpoint("quic://dns.adguard-dns.com"),
              let doqPinned = DoQEndpoint("quic://doq.custom.example:8853#203.0.113.53"),
              let doqIPv6 = DoQEndpoint("quic://[2606:4700:4700::1111]:853") else {
            throw Failure(text: "RFC 9250 DoQ 端点解析失败")
        }
        try expect(doqLiteral.host == "1.1.1.1" && doqLiteral.port == 853 && doqLiteral.alpn == ["doq"],
                   "DoQ 默认端口 853 或 ALPN doq 错误")
        try expect(doqBuiltin.connectHost == "94.140.14.14" && doqPinned.connectHost == "203.0.113.53"
                   && doqPinned.port == 8853 && doqIPv6.connectHost == "2606:4700:4700::1111",
                   "DoQ 内置 bootstrap、显式 #IP pin 或 IPv6 解析错误")
        try expect(DoQEndpoint("quic://unknown.doq.invalid") == nil
                   && DoQEndpoint("https://1.1.1.1/dns-query") == nil,
                   "缺少 bootstrap 的未知 DoQ 主机名或非 quic:// scheme 未被拒绝")

        let rawQuery = FakeIPSelfTest.query("doq.rfc9250.example", type: 1, id: 0xABCD)
        guard let encodedDoQ = doqLiteral.encodeFrame(rawQuery),
              let restoredDoQ = DoQEndpoint.decodeFrame(encodedDoQ.frame, expectedClientID: encodedDoQ.originalID) else {
            throw Failure(text: "RFC 9250 DoQ 2字节帧编码或 ID=0 还原失败")
        }
        try expect(encodedDoQ.originalID == 0xABCD
                   && encodedDoQ.frame.count == rawQuery.count + 2
                   && encodedDoQ.frame[2] == 0 && encodedDoQ.frame[3] == 0
                   && restoredDoQ == rawQuery,
                   "RFC 9250 §4.2.1 DoQ 线缆 ID 必须置 0 且解码后精确恢复客户端 ID")

        // 2. RFC 9230 ODoH (Oblivious DNS over HTTPS) proxy-target separation
        let proxyEP = DoHEndpoint("https://odoh-proxy.example/proxy#192.0.2.10")!
        let targetEP = DoHEndpoint("https://odoh-target.example/dns-query#198.51.100.20")!
        let sameHostTarget = DoHEndpoint("https://odoh-proxy.example/dns-query#198.51.100.20")!
        guard let validODoH = ODoHEndpoint(proxy: proxyEP, target: targetEP) else {
            throw Failure(text: "RFC 9230 ODoH 合法异源端点创建失败")
        }
        try expect(ODoHEndpoint(proxy: proxyEP, target: sameHostTarget) == nil,
                   "RFC 9230 ODoH 必须强制 Oblivious Proxy 与 Oblivious Target 异源隔离以防合谋关联")
        try expect(validODoH.proxyRequestPathWithTarget == "/proxy?targethost=odoh-target.example&targetpath=%2Fdns-query",
                   "RFC 9230 §4.1 ODoH Proxy URI 模板参数构造错误")
        guard let odohPlain = ODoHEndpoint.encodePlaintext(dnsMessage: rawQuery, paddingLength: 32),
              ODoHEndpoint.decodePlaintext(odohPlain) == rawQuery,
              let odohWire = ODoHEndpoint.encodeWireMessage(messageType: 0x01, keyIDOrNonce: Data([0xaa, 0xbb]), encryptedMessage: odohPlain),
              let decodedWire = ODoHEndpoint.decodeWireMessage(odohWire),
              decodedWire.messageType == 0x01, decodedWire.keyIDOrNonce == Data([0xaa, 0xbb]),
              decodedWire.encryptedMessage == odohPlain else {
            throw Failure(text: "RFC 9230 §6 ObliviousDoHMessage 报文封装往返自检失败")
        }

        // 3. RFC 7830 / RFC 8467 EDNS(0) Block-Length Padding (128B query / 468B response)
        guard let paddedQ = DNSMessageInspection.paddedQuery(rawQuery, blockSize: 128),
              let repaddedQ = DNSMessageInspection.paddedQuery(paddedQ, blockSize: 256) else {
            throw Failure(text: "RFC 8467 EDNS(0) 查询块填充失败")
        }
        try expect(paddedQ.count == 128 && repaddedQ.count == 256
                   && DNSMessageInspection.singleQuestion(in: paddedQ)?.name == "doq.rfc9250.example",
                   "RFC 8467 128B/256B 块对齐填充破坏了原始问题结构")

        // 4. RFC 7871 EDNS Client Subnet (ECS) Privacy Sanitization
        var ecsQuery = rawQuery
        ecsQuery[11] = 1
        ecsQuery.append(contentsOf: [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12,
                                     0, 8, 0, 8, 0, 1, 32, 0, 203, 0, 113, 99])
        guard let ecsMeta = DNSMessageInspection.inspectEDNSClientSubnet(in: ecsQuery),
              let stripped = DNSMessageInspection.sanitizingEDNSClientSubnet(in: ecsQuery, mode: .strip),
              let anonymized = DNSMessageInspection.sanitizingEDNSClientSubnet(in: ecsQuery, mode: .anonymizeZeroPrefix),
              let truncated = DNSMessageInspection.sanitizingEDNSClientSubnet(in: ecsQuery, mode: .truncatePrivacyBound) else {
            throw Failure(text: "RFC 7871 ECS 隐私检测或净化失败")
        }
        try expect(ecsMeta == DNSECSMetadata(family: 1, sourcePrefixLength: 32, scopePrefixLength: 0)
                   && DNSMessageInspection.inspectEDNSClientSubnet(in: stripped) == nil
                   && DNSMessageInspection.inspectEDNSClientSubnet(in: anonymized)?.sourcePrefixLength == 0
                   && DNSMessageInspection.inspectEDNSClientSubnet(in: truncated)?.sourcePrefixLength == 24,
                   "RFC 7871 ECS 剥离、/0 匿名化或 /24 隐私截断结果不符")

        // 5. RFC 8914 Extended DNS Error (EDE) semantic classification & RFC 9462 DDR
        try expect(DNSMessageInspection.classifyExtendedDNSError(6) == .dnssecValidationFailure
                   && DNSMessageInspection.classifyExtendedDNSError(15) == .policyBlockedOrCensored
                   && DNSMessageInspection.classifyExtendedDNSError(16) == .policyBlockedOrCensored
                   && DNSMessageInspection.classifyExtendedDNSError(13) == .staleOrCachedError
                   && DNSMessageInspection.classifyExtendedDNSError(23) == .resolverTransientOrNetwork,
                   "RFC 8914 EDE 语义分类映射错误")
        guard let ddr = DNSMessageInspection.ddrDiscoveryQuery(id: 0x4242),
              let ddrQ = DNSMessageInspection.singleQuestion(in: ddr) else {
            throw Failure(text: "RFC 9462 DDR 探测报文构造失败")
        }
        try expect(ddrQ.name == "_dns.resolver.arpa" && ddrQ.type == 64 && ddrQ.class == 1,
                   "RFC 9462 DDR 探测问题名称或 SVCB (64) 类型错误")
    }


    static func endpointParsing() throws {
        // An address literal is self-sufficient.
        guard let literal = DoHEndpoint("https://1.1.1.1/dns-query") else {
            throw Failure(text: "字面地址端点解析失败")
        }
        try expect(literal.host == "1.1.1.1" && literal.port == 443, "主机/端口解析错误")
        try expect(literal.connectHost == "1.1.1.1", "连接目标错误")
        try expect(literal.bootstrapAddress == nil, "字面地址不应需要 bootstrap")

        // A named endpoint is only accepted with an address to reach it at:
        // resolving it through the resolver it replaces would hand an attacker
        // the same control the feature exists to remove.
        try expect(DoHEndpoint("https://doh.example.org/dns-query") == nil,
                   "表外域名端点在无 bootstrap 时未被拒绝")
        guard let pending = DoHEndpoint("https://doh.example.org:8443/dns-query?key=test",
                                       allowUnresolvedHost: true),
              let pinned = pending.resolvingBootstrap(to: "203.0.113.53") else {
            throw Failure(text: "DoH 延后引导 API 未能固定 IP")
        }
        try expect(pending.needsBootstrap && pending.bootstrapAddress == nil
                   && pending.connectHost == "doh.example.org" && !pinned.needsBootstrap
                   && pinned.connectHost == "203.0.113.53" && pinned.url == pending.url
                   && pinned.host == pending.host && pinned.port == pending.port,
                   "DoH 延后引导改变 URL、端口或 TLS 身份")
        try expect(pending.resolvingBootstrap(to: "another.example") == nil,
                   "延后引导不应再次接受域名")
        var unresolvedDialed = false
        let unresolved = DoHResolver(endpoint: pending, streamDialer: { _, _, _, _, complete in
            unresolvedDialed = true; complete(.failure(Failure(text: "unresolved dial")))
        })
        var rejectedUnresolved = false
        let requestID = unresolved.resolve(query: FakeIPSelfTest.query("example.com", type: 1)) {
            rejectedUnresolved = $0 == nil
        }
        try expect(requestID == nil && rejectedUnresolved && !unresolvedDialed,
                   "DoH 未固定引导地址便创建了网络连接")
        guard let named = DoHEndpoint("https://doh.example.org/dns-query#8.8.8.8") else {
            throw Failure(text: "带 bootstrap 的端点解析失败")
        }
        try expect(named.host == "doh.example.org", "域名端点主机解析错误")
        try expect(named.connectHost == "8.8.8.8", "bootstrap 未生效")

        // Well-known providers carry their own address. Requiring the user to
        // type one for dns.google is correct and useless in equal measure.
        guard let builtIn = DoHEndpoint("https://dns.google/dns-query") else {
            throw Failure(text: "内置 bootstrap 的提供商未被接受")
        }
        try expect(builtIn.host == "dns.google", "内置端点主机错误")
        try expect(builtIn.connectHost == "8.8.8.8",
                   "内置 bootstrap 为 \(builtIn.connectHost)，应为 8.8.8.8")
        try expect(!builtIn.needsBootstrap
                   && builtIn.resolvingBootstrap(to: "203.0.113.53")?.connectHost == builtIn.connectHost,
                   "内置 bootstrap 不应被延后引导覆盖")
        try expect(DoHEndpoint("https://DNS.GOOGLE./dns-query", allowUnresolvedHost: true)?
                    .connectHost == "8.8.8.8", "具名端点尾随根点不应绕过内置固定地址")
        // The certificate is checked against the name, not the address, so the
        // host must survive; losing it would silently disable that check.
        try expect(builtIn.url.host == "dns.google", "内置 bootstrap 覆盖了 SNI 名称")
        try expect(builtIn.usesAutomaticBootstrapAddress
                   && builtIn.builtinAddressVariants.map(\.connectHost) == ["8.8.8.8", "8.8.4.4"]
                   && builtIn.builtinAddressVariants.allSatisfy({ $0.url == builtIn.url && $0.host == builtIn.host
                       && $0.port == builtIn.port && $0.usesAutomaticBootstrapAddress && !$0.needsBootstrap }),
                   "自动地址 variant 改变 URL/TLS 身份或没有保留同提供商地址")
        try expect(!literal.usesAutomaticBootstrapAddress && literal.builtinAddressVariants == [literal]
                   && !pending.usesAutomaticBootstrapAddress && pending.builtinAddressVariants == [pending]
                   && pinned.builtinAddressVariants == [pinned] && named.builtinAddressVariants == [named],
                   "literal/custom/传统引导的端点意外扩展到内置地址")
        guard let pub = DoHEndpoint("https://DOH.PUB.:8443/dns-query?key=test"),
              let quad = DoHEndpoint("https://dns.quad9.net/dns-query") else {
            throw Failure(text: "PUB/QUAD9 自动地址测试端点无效")
        }
        try expect(pub.builtinAddressVariants.map(\.connectHost) == ["1.12.12.12", "120.53.53.53"]
                   && pub.builtinAddressVariants.allSatisfy({ $0.url == pub.url && $0.port == 8443 && $0.host == pub.host })
                   && quad.builtinAddressVariants.map(\.connectHost) == ["9.9.9.9", "149.112.112.112"],
                   "已配置 PUB/QUAD9 的备用地址丢失或改写 URL/端口/查询参数")

        // An explicit address always wins: a user pinning their own resolver
        // must not be quietly redirected to ours.
        guard let overridden = DoHEndpoint("https://dns.google/dns-query#1.1.1.1") else {
            throw Failure(text: "显式 bootstrap 覆盖失败")
        }
        try expect(overridden.connectHost == "1.1.1.1", "显式 bootstrap 未覆盖内置值")
        guard let explicitDefault = DoHEndpoint("https://dns.google/dns-query#8.8.8.8") else {
            throw Failure(text: "显式内置首地址 pin 被拒绝")
        }
        try expect(!overridden.usesAutomaticBootstrapAddress && overridden.builtinAddressVariants == [overridden]
                   && !explicitDefault.usesAutomaticBootstrapAddress && explicitDefault.builtinAddressVariants == [explicitDefault],
                   "显式 #pin 被自动地址 variant 覆盖")
        var changedAddress = builtIn; changedAddress.bootstrapAddress = "203.0.113.53"
        var changedURL = builtIn; changedURL.url = URL(string: "https://doh.pub/dns-query")!
        try expect(!changedAddress.usesAutomaticBootstrapAddress && changedAddress.builtinAddressVariants == [changedAddress]
                   && !changedURL.usesAutomaticBootstrapAddress && changedURL.builtinAddressVariants == [changedURL],
                   "编程修改 endpoint 后仍沿用自动提供商授权")

        for raw in ["https://dns.google/dns-query# 127.0.0.1",
                    "https://dns.google/dns-query #127.0.0.1",
                    "https://dns.google/dns-query#\t127.0.0.1",
                    "https://dns.google/dns-query\n#127.0.0.1",
                    "https://dns.google/dns query#127.0.0.1"] {
            try expect(DoHEndpoint(raw) == nil
                       && DoHEndpoint(raw, allowUnresolvedHost: true) == nil,
                       "DoH 内部空白不得改变配置解析后的 pin 身份")
        }
        guard let encodedPath = DoHEndpoint("https://dns.google/dns%20query#127.0.0.1") else {
            throw Failure(text: "DoH percent-encoded 路径空格被误拒绝")
        }
        try expect(encodedPath.url.absoluteString == "https://dns.google/dns%20query"
                   && encodedPath.connectHost == "127.0.0.1",
                   "DoH encoded 路径或 pin 被改写")
        try expect(DoHEndpoint(" \t https://dns.google/dns%20query#127.0.0.1 \r\n") == encodedPath,
                   "DoH 外围空白仍应可 trim 且保持 pin")

        try expect(DoHEndpoint("https://DNS.GOOGLE/dns-query")?.connectHost == "8.8.8.8",
                   "内置表未做大小写归一")
        for host in EncryptedDNSBootstrap.knownHosts {
            try expect(DoHEndpoint("https://\(host)/dns-query") != nil,
                       "内置提供商 \(host) 未被接受")
            let addresses = EncryptedDNSBootstrap.addresses(for: host)
            try expect((1...2).contains(addresses.count) && addresses.allSatisfy(DoHEndpoint.isAddressLiteral),
                       "内置地址表破坏 16 配置/32 地址总预算或包含非 literal bootstrap")
        }

        try expect(DoHEndpoint("http://1.1.1.1/dns-query") == nil, "明文 HTTP 端点未被拒绝")
        try expect(DoHEndpoint("1.1.1.1") == nil, "普通 UDP 地址不应被当作 DoH")
        try expect(DoHEndpoint("https://1.1.1.1") == nil, "缺少路径的端点未被拒绝")
        try expect(DoHEndpoint("") == nil, "空字符串未被拒绝")
        try expect(DoHEndpoint("https://dns.google/dns-query#other.example") == nil,
                   "bootstrap 只能是 IP 地址，否则仍会递归解析")
        try expect(DoHEndpoint("https://dns.google:65536/dns-query") == nil,
                   "超出范围的 DoH 端口未被拒绝")
        try expect(DoHEndpoint("https://./dns-query#1.1.1.1") == nil,
                   "DNS 根名称不应作为 TLS 验证身份")

        guard let ported = DoHEndpoint("https://1.1.1.1:8443/dns-query") else {
            throw Failure(text: "带端口的端点解析失败")
        }
        try expect(ported.port == 8443, "自定义端口解析错误")
        guard let ipv6 = DoHEndpoint("https://[2606:4700:4700::1111]/dns-query") else {
            throw Failure(text: "DoH IPv6 字面地址解析失败")
        }
        try expect(ipv6.host == "2606:4700:4700::1111" && ipv6.connectHost == ipv6.host,
                   "DoH IPv6 连接地址不应带方括号")
    }

    static func dotEndpointParsing() throws {
        guard let literal = DoTEndpoint("tls://1.1.1.1") else {
            throw Failure(text: "字面地址 DoT 端点解析失败")
        }
        try expect(literal.host == "1.1.1.1" && literal.port == 853, "默认端口应为 853")
        guard let ported = DoTEndpoint("tls://1.1.1.1:8853") else {
            throw Failure(text: "带端口的 DoT 端点解析失败")
        }
        try expect(ported.port == 8853, "自定义端口解析错误")
        guard let v6 = DoTEndpoint("tls://[2606:4700:4700::1111]:853") else {
            throw Failure(text: "IPv6 字面地址端点解析失败")
        }
        try expect(v6.host == "2606:4700:4700::1111" && v6.port == 853,
                   "IPv6 端点解析错误：\(v6.host):\(v6.port)")

        // Same rule as DoH: a name must come with an address, or resolving the
        // resolver hands the attacker the same control.
        try expect(DoTEndpoint("tls://dot.example.org") == nil,
                   "表外域名端点在无 bootstrap 时未被拒绝")
        try expect(DoTEndpoint("tls://dns.google")?.connectHost == "8.8.8.8",
                   "DoT 未使用内置 bootstrap")
        guard let named = DoTEndpoint("tls://dns.google#8.8.8.8") else {
            throw Failure(text: "带 bootstrap 的 DoT 端点解析失败")
        }
        try expect(named.connectHost == "8.8.8.8" && named.host == "dns.google",
                   "bootstrap 未生效，或证书校验会失去正确的名称")
        for raw in ["tls://dns.google# 127.0.0.1", "tls://dns.google #127.0.0.1",
                    "tls://dns.google#\t127.0.0.1", "tls://dns.google\n#127.0.0.1"] {
            try expect(DoTEndpoint(raw) == nil, "DoT 内部空白不得改变配置解析后的 pin 身份")
        }
        try expect(DoTEndpoint(" \t tls://dns.google#127.0.0.1 \r\n")?.connectHost == "127.0.0.1",
                   "DoT 外围空白仍应可 trim 且保持 pin")
        try expect(DoTEndpoint("https://1.1.1.1/dns-query") == nil, "DoH 地址不应被当作 DoT")
        try expect(DoTEndpoint("1.1.1.1") == nil, "普通地址不应被当作 DoT")
        try expect(DoTEndpoint("tls://dns.google#other.example") == nil,
                   "DoT 域名 bootstrap 会触发系统 DNS，必须拒绝")
        try expect(DoTEndpoint("tls://dns.google:65536#8.8.8.8") == nil,
                   "DoT 超出范围端口未被拒绝")
        try expect(DoTEndpoint("tls://dns.google:invalid#8.8.8.8") == nil,
                   "DoT 非数字端口未被拒绝")
        try expect(DoTEndpoint("tls://.#1.1.1.1") == nil, "DNS 根名称不应作为 DoT 验证身份")
    }

    /// A DoH answer is an ordinary DNS message, so the parser that already
    /// populates the IP→domain map must read it unchanged.
    static func wireFormatCompatibility() throws {
        let request = FakeIPSelfTest.query("example.com", type: 1)
        guard let question = FakeIPResponder.question(in: request),
              let answer = FakeIPResponder.reply(to: request, question: question,
                                                 address: "93.184.216.34") else {
            throw Failure(text: "无法构造样本应答")
        }
        let records = DNSMessageProbe.addressRecords(in: answer)
        try expect(records.count == 1 && records[0].address == "93.184.216.34",
                   "DoH 线格式与既有解析器不兼容")
    }


    static func questionInspection() throws {
        for type in [UInt16(1), 28, 15, 16, 65, 255] {
            guard let query = DNSMessageInspection.query(for: "Example.COM", type: type),
                  let question = DNSMessageInspection.singleQuestion(in: query) else {
                throw Failure(text: "通用 DNS 问题解析失败")
            }
            try expect(question.name == "example.com" && question.type == type && question.class == 1,
                       "DNS 问题解析丢失名称、类型或类别")
        }
        let query = FakeIPSelfTest.query("example.com", type: 1)
        var compressed = Data(query.prefix(12))
        compressed.append(contentsOf: [0xC0, 18, 0, 1, 0, 1])
        compressed.append(query.dropFirst(12).dropLast(4))
        guard let question = DNSMessageInspection.singleQuestion(in: compressed),
              let error = DNSMessageInspection.errorResponse(to: compressed, code: .servfail) else {
            throw Failure(text: "压缩 DNS 问题未被安全解析")
        }
        try expect(question.name == "example.com" && question.questionEnd == 18
                   && DNSMessageInspection.responseMatchesQuery(error, query: compressed),
                   "压缩问题错误应答含悬空指针或错误事务")
        var cycle = Data(query.prefix(12))
        cycle.append(contentsOf: [0xC0, 12, 0, 1, 0, 1])
        try expect(DNSMessageInspection.singleQuestion(in: cycle) == nil, "压缩 DNS 指针循环未被拒绝")
        var multi = query
        multi[5] = 2
        try expect(DNSMessageInspection.singleQuestion(in: multi) == nil, "多问题 DNS 未被拒绝")
        guard let formerr = DNSMessageInspection.errorResponse(to: multi, code: .formerr) else {
            throw Failure(text: "非法 DNS 查询未生成 FORMERR")
        }
        try expect(formerr.count == 12 && formerr[5] == 0 && formerr[3] & 0x0F == 1,
                   "FORMERR 不应声称带有未解析的问题")
        guard let answer = FakeIPResponder.reply(to: query, question: FakeIPResponder.question(in: query)!,
                                                address: "93.184.216.34") else {
            throw Failure(text: "DNS 事务样本生成失败")
        }
        var wrongID = answer
        wrongID[1] ^= 1
        try expect(!DNSMessageInspection.responseMatchesQuery(wrongID, query: query),
                   "DNS 应答事务 ID 未被校验")
        try expect(DNSMessageInspection.addressAnswers(in: answer).first?.address == "93.184.216.34",
                   "安全 DNS 地址提取器未读到 A 答案")
        try expect(DNSMessageInspection.addressAnswers(in: Data(answer.dropLast())).isEmpty,
                   "截断的 DNS 地址记录未被拒绝")
        let otherQuery = FakeIPSelfTest.query("other.example.com", type: 1)
        guard let otherQuestion = FakeIPResponder.question(in: otherQuery),
              let otherAnswer = FakeIPResponder.reply(to: otherQuery, question: otherQuestion,
                                                     address: "93.184.216.35") else {
            throw Failure(text: "相同 ID 的不同问题样本生成失败")
        }
        try expect(!DNSMessageInspection.responseMatchesQuery(otherAnswer, query: query),
                   "相同事务 ID 的不同问题未被拒绝")
        guard let aliasQuery = DNSMessageInspection.query(for: "cdn.example.com", type: 1) else {
            throw Failure(text: "CNAME 样本生成失败")
        }
        let encodedAlias = Data(aliasQuery.dropFirst(12).dropLast(4))
        var cnameAnswer = query
        cnameAnswer[2] = 0x81; cnameAnswer[3] = 0x80; cnameAnswer[7] = 2
        cnameAnswer.append(contentsOf: [0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 10,
                                        0, UInt8(encodedAlias.count)])
        cnameAnswer.append(encodedAlias)
        cnameAnswer.append(encodedAlias)
        cnameAnswer.append(contentsOf: [0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34])
        let cname = DNSMessageInspection.addressAnswers(in: cnameAnswer).first
        try expect(cname?.domain == "example.com" && cname?.address == "93.184.216.34" && cname?.ttl == 10,
                   "CNAME 答案丢失原问题策略名称或 TTL 链上限")
    }


    static func injectedTransportTransactions() throws {
        let query = FakeIPSelfTest.query("example.com", type: 1)
        guard let question = FakeIPResponder.question(in: query),
              let answer = FakeIPResponder.reply(to: query, question: question, address: "93.184.216.34"),
              let dohEndpoint = DoHEndpoint("https://doh.selftest.invalid:18443/dns-query#203.0.113.53"),
              let dotEndpoint = DoTEndpoint("tls://dot.selftest.invalid#203.0.113.53") else {
            throw Failure(text: "注入 DNS 事务样本生成失败")
        }
        var httpWire = Data("HTTP/1.1 200 OK\r\nContent-Length: \(answer.count)\r\n\r\n".utf8)
        httpWire.append(answer)
        let httpStream = MemoryStream(response: httpWire)
        let httpDone = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var httpResult: Data?, dialIdentity: (String, UInt16, String)?
        let doh = DoHResolver(endpoint: dohEndpoint, streamDialer: { host, port, name, _, done in
            lock.lock(); dialIdentity = (host, port, name); lock.unlock()
            done(.success(httpStream))
        })
        doh.resolve(query: query) { lock.lock(); httpResult = $0; lock.unlock(); httpDone.signal() }
        try expect(httpDone.wait(timeout: .now() + 2) == .success, "注入 DoH 请求未完成")
        lock.lock(); let identity = dialIdentity; let httpAnswer = httpResult; lock.unlock()
        try expect(identity?.0 == "203.0.113.53" && identity?.1 == 18443
                   && identity?.2 == "doh.selftest.invalid" && httpAnswer == answer,
                   "DoH 注入传输丢失固定 IP、SNI 或 DNS 应答")
        try expect(httpStream.cancelled, "DoH 完成后未取消事务流")
        guard let boundary = httpStream.sent.range(of: Data("\r\n\r\n".utf8)) else {
            throw Failure(text: "DoH 注入传输未发送 HTTP 请求")
        }
        try expect(Data(httpStream.sent[boundary.upperBound...]) == query, "DoH 请求体不是原始 DNS 消息")

        func framed(_ message: Data) -> Data {
            var wire = Data([UInt8(truncatingIfNeeded: message.count >> 8),
                             UInt8(truncatingIfNeeded: message.count)])
            wire.append(message)
            return wire
        }
        let dotStream = MemoryStream(response: framed(answer))
        let dotDone = DispatchSemaphore(value: 0)
        var dotResult: Data?
        let dot = DoTResolver(endpoint: dotEndpoint, streamDialer: { _, _, _, _, done in
            done(.success(dotStream))
        })
        dot.resolve(query: query) { lock.lock(); dotResult = $0; lock.unlock(); dotDone.signal() }
        try expect(dotDone.wait(timeout: .now() + 2) == .success, "分片 DoT 应答未完成")
        lock.lock(); let dotAnswer = dotResult; lock.unlock()
        try expect(dotAnswer == answer && dotStream.sent == framed(query) && dotStream.cancelled,
                   "DoT 长度前缀、原始 DNS 或关闭行为错误")

        var wrong = answer
        wrong[1] ^= 1
        let wrongStream = MemoryStream(response: framed(wrong))
        let wrongDone = DispatchSemaphore(value: 0)
        var rejected = false
        let mismatch = DoTResolver(endpoint: dotEndpoint, streamDialer: { _, _, _, _, done in
            done(.success(wrongStream))
        })
        mismatch.resolve(query: query) { lock.lock(); rejected = $0 == nil; lock.unlock(); wrongDone.signal() }
        try expect(wrongDone.wait(timeout: .now() + 2) == .success, "错误 DoT 事务未结束")
        lock.lock(); let wasRejected = rejected; lock.unlock()
        try expect(wasRejected, "DoT 将另一事务的应答交给了客户端")

        let silentStream = MemoryStream(response: nil)
        let failed = DispatchSemaphore(value: 0)
        var failure: Data?
        let timeout = DoTResolver(endpoint: dotEndpoint, streamDialer: { _, _, _, _, done in
            done(.success(silentStream))
        }, requestTimeout: .milliseconds(25))
        let flow = DoTRoutedDatagram(resolver: timeout, receive: {
            lock.lock(); failure = $0; lock.unlock(); failed.signal()
        })
        flow.send(query)
        try expect(failed.wait(timeout: .now() + 2) == .success, "DoT 无应答未在 deadline 后返回 SERVFAIL")
        lock.lock(); let failedReply = failure; lock.unlock()
        try expect(failedReply?.prefix(2) == query.prefix(2)
                   && failedReply.map({ $0[3] & 0x0F == 2 }) == true
                   && silentStream.cancelled, "DoT 失败未保留事务 ID、SERVFAIL 或取消流")
        flow.cancel()
    }

    static func cancellationAndAdmission() throws {
        guard let endpoint = DoTEndpoint("tls://dot.selftest.invalid#203.0.113.53") else {
            throw Failure(text: "DoT 取消样本端点生成失败")
        }
        let query = FakeIPSelfTest.query("first.example", type: 1, id: 0x1234)
        let otherQuery = FakeIPSelfTest.query("second.example", type: 1, id: 0x4321)
        let first = MemoryStream(response: nil), second = MemoryStream(response: nil)
        let dialed = DispatchSemaphore(value: 0), completed = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var count = 0, unexpectedReply = false, remainingReply: Data?
        let shared = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            lock.lock(); let stream = count == 0 ? first : second; count += 1; lock.unlock()
            done(.success(stream))
            dialed.signal()
        }, requestTimeout: .milliseconds(75))
        let cancelledFlow = DoTRoutedDatagram(resolver: shared, receive: { _ in
            lock.lock(); unexpectedReply = true; lock.unlock()
        })
        let liveFlow = DoTRoutedDatagram(resolver: shared, receive: {
            lock.lock(); remainingReply = $0; lock.unlock(); completed.signal()
        })
        cancelledFlow.send(query)
        liveFlow.send(otherQuery)
        try expect(dialed.wait(timeout: .now() + 2) == .success
                   && dialed.wait(timeout: .now() + 2) == .success, "共享 DoT 未创建独立事务")
        cancelledFlow.cancel()
        try expect(completed.wait(timeout: .now() + 2) == .success, "关闭一条 DNS flow 误取消其他客户端")
        lock.lock(); let leakedReply = unexpectedReply; let reply = remainingReply; lock.unlock()
        try expect(!leakedReply && reply?.prefix(2) == otherQuery.prefix(2)
                   && first.cancelled && second.cancelled, "DNS flow 取消隔离或流资源回收失败")
        liveFlow.cancel()

        let pending = DispatchGroup()
        let saturated = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            done(.success(MemoryStream(response: nil)))
        })
        defer { saturated.cancel() }
        for _ in 0..<128 {
            pending.enter()
            guard saturated.resolve(query: query, completion: { _ in pending.leave() }) != nil else {
                throw Failure(text: "DoT admission 未允许有界请求")
            }
        }
        var rejectedImmediately = false
        let extra = saturated.resolve(query: query) { rejectedImmediately = $0 == nil }
        try expect(extra == nil && rejectedImmediately, "DoT 第 129 个未完成请求未被拒绝")
        saturated.cancel()
        try expect(pending.wait(timeout: .now() + 2) == .success, "DoT cancel 未结束所有待处理事务")
    }

    /// Only opens a TCP socket bound to loopback; it does not install a
    /// certificate or change DNS. The TLS ClientHello is enough to prove the
    /// resolver connects to the bootstrap IP and carries the URL host as SNI.

    static func pooledTransportFailureAdmission() throws {
        let endpoint = DoTEndpoint("tls://lease-failure.selftest.invalid#203.0.113.53")!
        let first = FakeIPSelfTest.query("first.lease-failure.example", type: 1, id: 0x6101)
        let second = FakeIPSelfTest.query("second.lease-failure.example", type: 1, id: 0x6102)
        let cases: [(Error, EncryptedDNSQueryFailure)] = [
            (NWError.tls(-9807), .authentication),
            (NSError(domain: "PooledNativeUnknownFixture", code: 73), .other),
            (NWError.posix(.ECONNRESET), .network)
        ]
        for (error, expected) in cases {
            for cancelBeforeApplicationRead in [false, true] {
                let sent = DispatchSemaphore(value: 0), entered = DispatchSemaphore(value: 0)
                let release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
                let lock = NSLock()
                var ownerQueue: DispatchQueue?, result: Result<Data, EncryptedDNSQueryFailure>?
                var barrier: DNSProxyFallbackBarrier?, dials = 0
                let peer = ReuseMemoryStream { stream, data, number, complete in
                    complete(nil)
                    if number == 1 { stream.emit(reuseWireReply(data, mode: 2)) }
                    else { sent.signal() }
                }
                let resolver = DoTResolver(endpoint: endpoint, metadataStreamDialer: { _, _, _, queue, _, _, complete in
                    lock.lock(); ownerQueue = queue; let index = dials; dials += 1; lock.unlock()
                    if index == 0 { complete(.success(peer)) }
                    else if expected == .other { complete(.failure(EncryptedDNSQueryFailure.network)) }
                    else { complete(.success(reuseAuto(2))) }
                    return nil
                }, requestTimeout: .seconds(2))
                defer { release.signal(); resolver.cancel() }
                try expect(try reuseAwait { resolver.resolve(query: first, completion: $0) } != nil,
                           "pooled failure fixture could not prime its reusable stream")
                guard let id = resolver.resolveResult(query: second, completion: {
                    lock.lock(); result = $0; lock.unlock(); done.signal()
                }, downgradeBarrier: { value in lock.lock(); barrier = value; lock.unlock() }) else {
                    throw Failure(text: "pooled failure fixture rejected its second request")
                }
                try expect(sent.wait(timeout: .now() + 1) == .success && peer.sendCount == 2,
                           "pooled failure fixture did not reuse the primed stream")
                lock.lock(); let queue = ownerQueue; lock.unlock()
                queue?.async { entered.signal(); _ = release.wait(timeout: .now() + 2) }
                try expect(entered.wait(timeout: .now() + 1) == .success,
                           "pooled failure fixture could not hold its owner queue")
                peer.emitTransportFailure(error)
                if cancelBeforeApplicationRead { resolver.cancel(id) }
                // Real Network.framework can produce this exact callback when
                // the raw bridge has already canceled its TLS connection.
                peer.emit(nil, complete: true)
                release.signal()
                try expect(done.wait(timeout: .now() + 1) == .success,
                           "pooled native failure did not retire its current request")
                resolver.drainQueueForSelfTest()
                lock.lock(); let observed = result, retainedBarrier = barrier, count = dials; lock.unlock()
                if expected.permitsProxyFallback {
                    // A network error may do its one same-endpoint idle retry;
                    // it must not manufacture an authentication/unknown deny.
                    if cancelBeforeApplicationRead {
                        try expect(retainedBarrier == nil, "pooled network cancellation manufactured a deny barrier")
                    } else {
                        guard case .success(let answer)? = observed else {
                            throw Failure(text: "pooled network failure did not allow its encrypted idle retry")
                        }
                        // A successful retry publishes its authenticated
                        // answer as a barrier against later provider-shopping.
                        guard case .answer(let barrierAnswer)? = retainedBarrier else {
                            throw Failure(text: "pooled network retry lost its answer barrier or manufactured a denial")
                        }
                        try expect(count == 2 && DNSMessageInspection.responseMatchesQuery(answer, query: second)
                                   && barrierAnswer == answer,
                                   "pooled network retry changed query identity or repeated its dial")
                    }
                } else {
                    guard case .failure(let saved)? = retainedBarrier else {
                        throw Failure(text: "reused TLS native denial was hidden by EOF/cancellation")
                    }
                    let expectedDials = expected == .other && !cancelBeforeApplicationRead ? 2 : 1
                    try expect(EncryptedDNSQueryFailure.classify(saved) == expected && count == expectedDials,
                               "reused TLS native denial changed type or lost its bounded retry policy")
                    if !cancelBeforeApplicationRead {
                        guard case .failure(let saved)? = observed else {
                            throw Failure(text: "nil EOF replaced the current request's native error")
                        }
                        try expect(saved == expected, "pooled request did not receive its original native error")
                    }
                }
            }
        }
        print("Pooled native failure checks passed: current lease error, nil EOF, native ingress and cancellation barrier")
    }

    static func reuseResourceBounds() throws {
        let endpoint = DoTEndpoint("tls://resource.reuse.selftest.invalid#203.0.113.53")!
        let budget = SOCKSUDPGlobalBudget(resources: 8, packets: 0, bytes: 0)
        let lock = NSLock(), sent = DispatchSemaphore(value: 0), completed = DispatchGroup()
        var held: [(ReuseMemoryStream, Data)] = [], invalid = false
        let probe = ReuseProbe { _ in
            ReuseMemoryStream { stream, wire, _, done in
                lock.lock(); held.append((stream, wire)); lock.unlock()
                done(nil); sent.signal()
            }
        }
        let resolver = DoTResolver(endpoint: endpoint, streamDialer: probe.dialer,
            requestTimeout: .seconds(3), idleLimit: 4, idleHandoffGrace: 0, resourceBudget: budget)
        defer { resolver.cancel() }
        for index in 0..<5 {
            let query = FakeIPSelfTest.query("resource-\(index).reuse.example", type: 1,
                                            id: UInt16(0x3000 + index))
            completed.enter()
            guard resolver.resolve(query: query, completion: { answer in
                if answer.map({ DNSMessageInspection.responseMatchesQuery($0, query: query) }) != true {
                    lock.lock(); invalid = true; lock.unlock()
                }
                completed.leave()
            }) != nil else { throw Failure(text: "resource fixture request was rejected") }
        }
        for _ in 0..<5 {
            try expect(sent.wait(timeout: .now() + 3) == .success, "held resource query did not send")
        }
        lock.lock(); let initial = held; lock.unlock()
        for (stream, wire) in initial { stream.emit(reuseWireReply(wire, mode: 2)) }
        try expect(completed.wait(timeout: .now() + 3) == .success, "resource replies did not finish")
        lock.lock(); let bad = invalid; lock.unlock()
        try expect(!bad && probe.count == 5 && budget.usage.resources == 4
                   && probe.streams.filter(\.cancelled).count == 1,
                   "idle cap four did not close the fifth stream or release its lease")

        let checkedOut = DispatchSemaphore(value: 0)
        var checkoutAnswer: Data?
        let query = FakeIPSelfTest.query("checkout.reuse.example", type: 1, id: 0x3100)
        guard resolver.resolve(query: query, completion: { answer in
            lock.lock(); checkoutAnswer = answer; lock.unlock(); checkedOut.signal()
        }) != nil else { throw Failure(text: "idle checkout was rejected") }
        try expect(sent.wait(timeout: .now() + 3) == .success && probe.count == 5
                   && budget.usage.resources == 3, "checkout retained its global idle reservation")
        resolver.cancel()
        try expect(checkedOut.wait(timeout: .now() + 3) == .success,
                   "pool cancellation did not finish its active resource query")
        // The active callback can precede the queued idle-pool teardown.
        resolver.drainQueueForSelfTest()
        lock.lock(); let cancelledAnswer = checkoutAnswer; lock.unlock()
        try expect(cancelledAnswer == nil, "pool cancellation returned an active query answer")
        let remainingResources = budget.usage.resources
        try expect(remainingResources == 0,
                   "pool cancellation leaked \(remainingResources) global resource leases")
        let unclosedStreams = probe.streams.filter { !$0.cancelled }.count
        try expect(unclosedStreams == 0,
                   "pool cancellation left \(unclosedStreams) idle/active streams open")

        let clock = ReuseClock()
        let clockBudget = SOCKSUDPGlobalBudget(resources: 4, packets: 0, bytes: 0)
        let clockProbe = ReuseProbe { _ in reuseAuto(2) }
        let clockResolver = DoTResolver(endpoint: endpoint, streamDialer: clockProbe.dialer,
            requestTimeout: .seconds(3), idleTimeout: 15, idleLimit: 4,
            clock: clock.read, resourceBudget: clockBudget)
        defer { clockResolver.cancel() }
        for index in 0..<3 {
            if index == 1 { clock.advance(16) }
            if index == 2 { clock.advance(-100) }
            let query = FakeIPSelfTest.query("clock-\(index).reuse.example", type: 1,
                                            id: UInt16(0x3200 + index))
            let answer = try reuseAwait { clockResolver.resolve(query: query, completion: $0) }
            try expect(answer.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                       "expiry/backwards-clock query lost its DNS identity")
            try expect(clockProbe.count == index + 1 && clockBudget.usage.resources == 1
                       && clockProbe.streams.dropLast().allSatisfy(\.cancelled),
                       "expired/backwards-clock idle stream or lease survived checkout")
        }

        let deniedBudget = SOCKSUDPGlobalBudget(resources: 0, packets: 0, bytes: 0)
        let deniedProbe = ReuseProbe { _ in reuseAuto(2) }
        let deniedResolver = DoTResolver(endpoint: endpoint, streamDialer: deniedProbe.dialer,
            requestTimeout: .seconds(3), resourceBudget: deniedBudget)
        defer { deniedResolver.cancel() }
        for index in 0..<2 {
            let query = FakeIPSelfTest.query("budget-denied-\(index).reuse.example", type: 1,
                                            id: UInt16(0x3300 + index))
            let answer = try reuseAwait { deniedResolver.resolve(query: query, completion: $0) }
            try expect(answer.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                       "idle budget denial incorrectly discarded a valid DNS answer")
        }
        try expect(deniedProbe.count == 2 && deniedProbe.streams.allSatisfy(\.cancelled)
                   && deniedBudget.usage.resources == 0, "denied idle resource was retained or leaked")
        try reusePendingDialBounds()
    }

    /// A governor backlog can be outside the resolver's own waiting queue.
    /// Return a complete batch before any subsequent checkout to reproduce
    /// that scheduling gap deterministically, without sleeping or dialing.

    static func reuseRetryAndCancellation() throws {
        let endpoint = DoTEndpoint("tls://reuse.selftest.invalid#203.0.113.53")!
        let first = FakeIPSelfTest.query("warm.retry.example", type: 1, id: 0x1111)
        let second = FakeIPSelfTest.query("next.retry.example", type: 1, id: 0x2222)
        for staleFailure in 0..<3 {
            let probe = ReuseProbe { index in
                if index > 0 { return reuseAuto(2) }
                return ReuseMemoryStream { stream, data, number, done in
                    if number == 1 { done(nil); stream.emit(reuseWireReply(data, mode: 2)) }
                    else if staleFailure == 0 { done(Failure(text: "stale idle send")) }
                    else if staleFailure == 1 { done(nil); stream.emit(nil, complete: true) }
                    else {
                        done(nil)
                        stream.emit(nil, complete: true,
                                    error: NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET)))
                    }
                }
            }
            let resolver = DoTResolver(endpoint: endpoint, streamDialer: probe.dialer)
            defer { resolver.cancel() }
            for query in [first, second, first] {
                let result = try reuseAwait { resolver.resolve(query: query, completion: $0) }
                try expect(result.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                           "stale idle retry did not preserve query identity")
            }
            try expect(probe.count == 2 && probe.streams[0].cancelled,
                       "stale idle transport was not replaced exactly once")
        }
        for wrongID in [false, true] {
            let probe = ReuseProbe { _ in
                ReuseMemoryStream { stream, data, number, done in
                    done(nil)
                    if number == 1 { stream.emit(reuseWireReply(data, mode: 2)) }
                    else if wrongID {
                        var reply = reuseWireReply(data, mode: 2); reply[2] ^= 1
                        stream.emit(reply)
                    } else { stream.emit(Data([0]), complete: true) }
                }
            }
            let resolver = DoTResolver(endpoint: endpoint, streamDialer: probe.dialer)
            defer { resolver.cancel() }
            _ = try reuseAwait { resolver.resolve(query: first, completion: $0) }
            let rejected = try reuseAwait { resolver.resolve(query: second, completion: $0) }
            try expect(rejected == nil && probe.count == 1 && probe.streams[0].cancelled,
                       "partial/wrong-ID response triggered an unsafe redial")
        }
        let twice = ReuseProbe { index in
            ReuseMemoryStream { stream, wire, number, done in
                if index == 0 && number == 1 { done(nil); stream.emit(reuseWireReply(wire, mode: 2)) }
                else { done(Failure(text: "both transports failed")) }
            }
        }
        let noLoop = DoTResolver(endpoint: endpoint, streamDialer: twice.dialer)
        defer { noLoop.cancel() }
        _ = try reuseAwait { noLoop.resolve(query: first, completion: $0) }
        try expect(try reuseAwait { noLoop.resolve(query: second, completion: $0) } == nil
                   && twice.count == 2, "failed fresh retry dialled a third transport")
        let httpEndpoint = DoHEndpoint("https://reuse.selftest.invalid/dns-query#203.0.113.53")!
        let resetHTTP = ReuseProbe { index in
            if index > 0 { return reuseAuto(0) }
            return ReuseMemoryStream { stream, data, number, done in
                done(nil)
                if number == 1 { stream.emit(reuseWireReply(data, mode: 0)) }
                else { stream.emit(nil, complete: true,
                                   error: NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))) }
            }
        }
        let recoveredHTTP = DoHResolver(endpoint: httpEndpoint, streamDialer: resetHTTP.dialer)
        defer { recoveredHTTP.cancel() }
        for query in [first, second, first] {
            let answer = try reuseAwait { recoveredHTTP.resolve(query: query, completion: $0) }
            try expect(answer.map { DNSMessageInspection.responseMatchesQuery($0, query: query) } == true,
                       "DoH stale idle receive reset did not recover its original query")
        }
        try expect(resetHTTP.count == 2 && resetHTTP.streams[0].cancelled,
                   "DoH stale receive reset redialled more than once")
        let redirect = ReuseProbe { _ in
            ReuseMemoryStream { stream, data, number, done in
                done(nil)
                stream.emit(number == 1 ? reuseWireReply(data, mode: 0)
                    : Data("HTTP/1.1 302 Found\r\nLocation: https://other.invalid/\r\nContent-Length: 0\r\n\r\n".utf8))
            }
        }
        let http = DoHResolver(endpoint: httpEndpoint, streamDialer: redirect.dialer)
        defer { http.cancel() }
        _ = try reuseAwait { http.resolve(query: first, completion: $0) }
        try expect(try reuseAwait { http.resolve(query: second, completion: $0) } == nil
                   && redirect.count == 1, "HTTP protocol failure was retried/followed")

        // Retry is deliberately delayed; a reset timer would finish at 1.6s,
        // while the original one must still finish at about 1.0s.
        let deadlineProbe = ReuseProbe { index in
            ReuseMemoryStream { stream, data, number, done in
                if index == 0 && number == 1 { done(nil); stream.emit(reuseWireReply(data, mode: 2)) }
                else if index == 0 {
                    DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) {
                        done(Failure(text: "delayed stale send"))
                    }
                } else { done(nil) }
            }
        }
        let deadline = DoTResolver(endpoint: endpoint, streamDialer: deadlineProbe.dialer, requestTimeout: .seconds(1))
        defer { deadline.cancel() }
        _ = try reuseAwait { deadline.resolve(query: first, completion: $0) }
        let ended = DispatchSemaphore(value: 0), lock = NSLock()
        var timedOut = false
        deadline.resolve(query: second) { lock.lock(); timedOut = $0 == nil; lock.unlock(); ended.signal() }
        try expect(ended.wait(timeout: .now() + 1.35) == .success, "stale retry reset the original deadline")
        lock.lock(); let failed = timedOut; lock.unlock()
        try expect(failed && deadlineProbe.count == 2 && deadlineProbe.streams.allSatisfy(\.cancelled),
                   "deadline did not clean up the retry transport")

        let started = DispatchSemaphore(value: 0)
        let isolation = ReuseProbe { _ in
            ReuseMemoryStream { _, _, _, done in done(nil); started.signal() }
        }
        let shared = DoTResolver(endpoint: endpoint, streamDialer: isolation.dialer)
        defer { shared.cancel() }
        let cancelled = DispatchSemaphore(value: 0), kept = DispatchSemaphore(value: 0)
        var result: Data?
        let id = shared.resolve(query: first) { _ in cancelled.signal() }!
        shared.resolve(query: second) { lock.lock(); result = $0; lock.unlock(); kept.signal() }
        try expect(started.wait(timeout: .now() + 2) == .success
                   && started.wait(timeout: .now() + 2) == .success, "isolated active streams not started")
        shared.cancel(id)
        try expect(cancelled.wait(timeout: .now() + 2) == .success && isolation.streams[0].cancelled,
                   "individual cancellation did not close its own active lease")
        let framedSecond = Data([UInt8(second.count >> 8), UInt8(second.count & 255)]) + second
        isolation.streams[1].emit(reuseWireReply(framedSecond, mode: 2))
        try expect(kept.wait(timeout: .now() + 2) == .success, "individual cancellation affected another query")
        lock.lock(); let answer = result; lock.unlock()
        try expect(answer.map { DNSMessageInspection.responseMatchesQuery($0, query: second) } == true,
                   "other active query lost its response")
        shared.cancel()
        try expect(isolation.streams[1].closedSignal.wait(timeout: .now() + 2) == .success,
                   "resolver cancellation failed to close idle stream")

        let offered = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        var callback: ((Result<any NativeOutboundByteStream, Error>) -> Void)?
        var completions = 0
        let late = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            lock.lock(); callback = done; lock.unlock(); offered.signal()
        })
        let lateID = late.resolve(query: first) { _ in
            lock.lock(); completions += 1; lock.unlock(); finished.signal()
        }!
        try expect(offered.wait(timeout: .now() + 2) == .success, "delayed dial not reserved")
        late.cancel(lateID)
        try expect(finished.wait(timeout: .now() + 2) == .success, "pending dial cancellation failed")
        let lateStream = reuseAuto(2)
        lock.lock(); let deliver = callback; lock.unlock()
        deliver?(.success(lateStream))
        try expect(lateStream.closedSignal.wait(timeout: .now() + 2) == .success
                   && lateStream.sendCount == 0, "late cancelled dial was used/pooled")
        lock.lock(); let once = completions; lock.unlock()
        try expect(once == 1, "late dial completed a cancelled request twice")
        late.cancel()
    }

    /// HTTP/1.1 and DoT do not multiplex this pool's streams. A burst must
    /// reuse a bounded number of live exchanges, not open one TLS dial per ID.
    static func boundedQueryScheduling() throws {
        let limit = DoHResolver.maximumConcurrentQueries
        let coldLimit = DoHResolver.maximumConcurrentConnectionAttempts
        try expect(limit == 16 && DoTResolver.maximumConcurrentQueries == limit
                   && coldLimit == 4 && DoTResolver.maximumConcurrentConnectionAttempts == coldLimit,
                   "encrypted query concurrency limit changed without its regression coverage")
        for mode in [0, 1, 2] {
            let probe = ReuseProbe { _ in reuseAuto(mode) }
            let coldLock = NSLock()
            var pendingCold = 0, peakCold = 0
            let delayed: EncryptedDNSStreamDialer = { host, port, name, queue, done in
                coldLock.lock(); pendingCold += 1; peakCold = max(peakCold, pendingCold); coldLock.unlock()
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + .milliseconds(30)) {
                    probe.dialer(host, port, name, queue) { result in
                        coldLock.lock(); pendingCold -= 1; coldLock.unlock()
                        done(result)
                    }
                }
            }
            let resolve: (Data, @escaping (Data?) -> Void) -> UUID?
            let cancel: () -> Void
            if mode == 2 {
                let resolver = DoTResolver(endpoint: DoTEndpoint("tls://bounded.selftest.invalid#203.0.113.53")!,
                                           streamDialer: delayed)
                resolve = { resolver.resolve(query: $0, completion: $1) }; cancel = resolver.cancel
            } else {
                let resolver = DoHResolver(endpoint: DoHEndpoint("https://bounded.selftest.invalid/dns-query#203.0.113.53")!,
                                           streamDialer: delayed)
                resolve = { resolver.resolve(query: $0, completion: $1) }; cancel = resolver.cancel
            }
            let finished = DispatchGroup(), lock = NSLock()
            var results = 0, invalid = false
            for index in 0..<96 {
                let query = FakeIPSelfTest.query("q-\(index).bounded.example", type: 1, id: UInt16(0x6000 + index))
                finished.enter()
                let id = resolve(query) { answer in
                    lock.lock()
                    results += 1
                    invalid = invalid || answer.map { !DNSMessageInspection.responseMatchesQuery($0, query: query) } != false
                    lock.unlock(); finished.leave()
                }
                try expect(id != nil, "bounded scheduling rejected an admitted burst query")
            }
            try expect(finished.wait(timeout: .now() + 3) == .success, "bounded burst did not drain")
            lock.lock(); let valid = results == 96 && !invalid; lock.unlock()
            let streams = probe.streams
            coldLock.lock(); let boundedCold = pendingCold == 0 && peakCold > 0 && peakCold <= coldLimit; coldLock.unlock()
            try expect(valid && boundedCold && probe.count > 0 && probe.count <= limit
                       && streams.reduce(0, { $0 + $1.sendCount }) == 96,
                       "burst exceeded its TLS concurrency limit, failed identity or did not reuse queued exchanges")
            cancel()
        }

        // Cancellation of a queued ID must not cancel the active lease or
        // create a replacement connection when that queued position retires.
        let endpoint = DoTEndpoint("tls://queued.selftest.invalid#203.0.113.53")!
        let first = FakeIPSelfTest.query("first.queued.example", type: 1, id: 0x6201)
        let cancelled = FakeIPSelfTest.query("cancelled.queued.example", type: 1, id: 0x6202)
        let last = FakeIPSelfTest.query("last.queued.example", type: 1, id: 0x6203)
        let started = DispatchSemaphore(value: 0), completed = DispatchGroup(), acknowledged = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var dialCount = 0, successful = 0, cancelledResults = 0, invalid = false
        let peer = ReuseMemoryStream { stream, wire, count, done in
            done(nil)
            if count == 1 { started.signal() }
            else { stream.emit(reuseWireReply(wire, mode: 2)) }
        }
        let resolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            lock.lock(); dialCount += 1; lock.unlock(); done(.success(peer))
        }, requestTimeout: .seconds(2), activeLimit: 1)
        defer { resolver.cancel() }
        func issue(_ query: Data, expectedCancellation: Bool = false) -> UUID? {
            completed.enter()
            return resolver.resolveResult(query: query) { result in
                lock.lock()
                switch result {
                case .success(let answer):
                    successful += 1
                    invalid = invalid || expectedCancellation || !DNSMessageInspection.responseMatchesQuery(answer, query: query)
                case .failure(let reason):
                    cancelledResults += 1
                    invalid = invalid || !expectedCancellation || reason != .cancelled
                }
                lock.unlock(); completed.leave()
            }
        }
        try expect(issue(first) != nil && started.wait(timeout: .now() + 2) == .success,
                   "queued cancellation fixture did not start its active lease")
        guard let cancelledID = issue(cancelled, expectedCancellation: true), issue(last) != nil else {
            throw Failure(text: "queued cancellation fixture was not admitted")
        }
        resolver.drainQueueForSelfTest()
        resolver.cancel(cancelledID) { acknowledged.signal() }
        try expect(acknowledged.wait(timeout: .now() + 2) == .success && !peer.cancelled && peer.sendCount == 1,
                   "queued cancellation dialed or revoked another query's lease")
        peer.emit(reuseWireReply(Data([UInt8(first.count >> 8), UInt8(first.count & 255)]) + first, mode: 2))
        try expect(completed.wait(timeout: .now() + 2) == .success, "queued cancellation left another query pending")
        lock.lock(); let isolated = dialCount == 1 && successful == 2 && cancelledResults == 1 && !invalid; lock.unlock()
        try expect(isolated && peer.sendCount == 2, "queued cancellation lost FIFO reuse or completed an ID twice")

        // Hold the first reply until the second request is visibly queued.
        // Compare the exact stored deadline across reused transport admission,
        // then let its real original timer fire with the second reply held.
        // This proves queue time is retained without a 90/150ms callback race.
        let early = FakeIPSelfTest.query("early.deadline.example", type: 1, id: 0x6301)
        let queued = FakeIPSelfTest.query("queued.deadline.example", type: 1, id: 0x6302)
        let firstSent = DispatchSemaphore(value: 0), secondSent = DispatchSemaphore(value: 0)
        let deadlineResults = DispatchGroup()
        var firstSucceeded = false, queuedTimedOut = false, deadlineDials = 0
        var firstResults = 0, queuedResults = 0, queuedFinishedAt: UInt64 = 0
        var firstWire = Data(), queuedWire = Data()
        let deadlinePeer = ReuseMemoryStream { _, wire, count, done in
            done(nil)
            lock.lock()
            if count == 1 { firstWire = wire } else { queuedWire = wire }
            lock.unlock()
            if count == 1 { firstSent.signal() } else { secondSent.signal() }
        }
        let deadlineResolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            lock.lock(); deadlineDials += 1; lock.unlock(); done(.success(deadlinePeer))
        }, requestTimeout: .seconds(1), activeLimit: 1)
        defer { deadlineResolver.cancel() }
        deadlineResults.enter()
        _ = deadlineResolver.resolveResult(query: early) { result in
            lock.lock()
            firstResults += 1
            if case .success(let answer) = result {
                firstSucceeded = DNSMessageInspection.responseMatchesQuery(answer, query: early)
            }
            lock.unlock(); deadlineResults.leave()
        }
        try expect(firstSent.wait(timeout: .now() + 2) == .success, "queued deadline fixture did not send")
        deadlineResults.enter()
        guard let queuedID = deadlineResolver.resolveResult(query: queued, completion: { result in
            lock.lock()
            queuedResults += 1
            queuedFinishedAt = DispatchTime.now().uptimeNanoseconds
            if case .failure(.timeout) = result { queuedTimedOut = true }
            lock.unlock(); deadlineResults.leave()
        }) else { throw Failure(text: "queued deadline fixture was not admitted") }
        deadlineResolver.drainQueueForSelfTest()
        guard let originalDeadline = deadlineResolver.originalDeadlineForSelfTest(queuedID) else {
            throw Failure(text: "queued deadline fixture lost its original request")
        }
        try expect(deadlinePeer.sendCount == 1, "queued request started before the first reply gate")
        lock.lock(); let releaseFirst = firstWire; lock.unlock()
        deadlinePeer.emit(reuseWireReply(releaseFirst, mode: 2))
        try expect(secondSent.wait(timeout: .now() + 2) == .success,
                   "queued deadline fixture did not reuse its admitted stream")
        let admittedDeadline = deadlineResolver.originalDeadlineForSelfTest(queuedID)
        try expect(admittedDeadline == originalDeadline && deadlinePeer.sendCount == 2,
                   "reused transport admission replaced the original queued deadline")
        try expect(deadlineResults.wait(timeout: .now() + 2) == .success, "queued deadline fixture did not finish")
        lock.lock()
        let lateWire = queuedWire
        let retainedDeadline = firstSucceeded && queuedTimedOut && deadlineDials == 1
            && firstResults == 1 && queuedResults == 1 && queuedFinishedAt >= originalDeadline.uptimeNanoseconds
        lock.unlock()
        try expect(retainedDeadline && deadlinePeer.cancelled, "queued exchange reset its original deadline or retained a late lease")
        deadlinePeer.emit(reuseWireReply(lateWire, mode: 2))
        deadlineResolver.drainQueueForSelfTest()
        lock.lock(); let once = firstResults == 1 && queuedResults == 1; lock.unlock()
        try expect(once && deadlinePeer.closedSignal.wait(timeout: .now()) == .success
                   && deadlinePeer.closedSignal.wait(timeout: .now()) == .timedOut,
                   "late queued reply completed twice or cleaned up its lease more than once")
        print("Encrypted DNS scheduling check passed: 96-query DoH/DoT bursts, four cold dials, 16 ready exchanges, FIFO TLS reuse, queued cancellation and exact original deadlines")
    }

    /// Cancellation requests transport teardown but only its callback may
    /// release admission. This catches both a missing cancel action and an
    /// unsafe early slot release; legacy noncancellable coverage stays above.
    static func cancellableDialCleanup() throws {
        let endpoint = DoTEndpoint("tls://cancel.reuse.selftest.invalid#203.0.113.53")!
        let lock = NSLock(), issued = DispatchSemaphore(value: 0), completed = DispatchGroup()
        var callbacks: [(Result<any NativeOutboundByteStream, Error>) -> Void] = []
        var dialCount = 0, cancelCount = 0, ready = false, invalid = false
        // Exercise the full physical reservation budget independently of the
        // foreground scheduling limit; neither layer may hide an early release.
        let resolver = DoTResolver(endpoint: endpoint, cancellableStreamDialer: { _, _, _, _, done in
            lock.lock()
            dialCount += 1
            let healthy = ready
            if !healthy { callbacks.append(done) }
            lock.unlock()
            issued.signal()
            if healthy { done(.success(reuseAuto(2))); return nil }
            return {
                lock.lock(); cancelCount += 1; lock.unlock()
                // The transport is closing, but intentionally has not
                // acknowledged its teardown to the completion yet.
            }
        }, requestTimeout: .seconds(3), activeLimit: 128, coldDialLimit: 128)
        defer { resolver.cancel() }
        var ids: [UUID] = []
        for index in 0..<128 {
            let query = FakeIPSelfTest.query("cancel-\(index).reuse.example", type: 1, id: UInt16(0x5100 + index))
            completed.enter()
            guard let id = resolver.resolve(query: query, completion: { answer in
                if answer != nil { lock.lock(); invalid = true; lock.unlock() }
                completed.leave()
            }) else { throw Failure(text: "cancellable DNS rejected an admitted query") }
            ids.append(id)
        }
        for _ in 0..<128 {
            try expect(issued.wait(timeout: .now() + 3) == .success, "cancellable DNS did not reserve its dial")
        }
        ids.forEach { resolver.cancel($0) }
        try expect(completed.wait(timeout: .now() + 3) == .success, "cancellable DNS did not finish canceled requests")
        let extra = FakeIPSelfTest.query("cancel-next.reuse.example", type: 1, id: 0x5200)
        let resumed = DispatchSemaphore(value: 0)
        var queuedAnswer: Data?, queuedResults = 0
        try expect(resolver.resolve(query: extra, completion: { answer in
            lock.lock(); queuedAnswer = answer; queuedResults += 1; lock.unlock(); resumed.signal()
        }) != nil, "physical saturation rejected a request within the registration bound")
        resolver.drainQueueForSelfTest()
        lock.lock()
        let canceled = cancelCount, count = dialCount, bad = invalid, delayed = callbacks
        let prematurelyCompleted = queuedResults != 0
        callbacks.removeAll(); ready = true
        lock.unlock()
        try expect(canceled == 128 && count == 128 && !bad && !prematurelyCompleted,
                   "physical backpressure released a dial early or completed its admitted waiter as capacity")
        for callback in delayed { callback(.failure(Failure(text: "transport cancellation acknowledged"))) }
        try expect(resumed.wait(timeout: .now() + 3) == .success,
                   "physical cancellation receipts did not resume the admitted waiter")
        lock.lock(); let recoveredCount = dialCount, answer = queuedAnswer, results = queuedResults; lock.unlock()
        try expect(recoveredCount == 129 && results == 1
                   && answer.map { DNSMessageInspection.responseMatchesQuery($0, query: extra) } == true,
                   "DNS did not recover capacity after acknowledged transport cancellation")
    }

    /// Exercise the production 16-query gate rather than filling all physical
    /// slots with an artificial 128-query foreground limit. Eight canceled
    /// waves retain their real dial receipts. New admitted clients must wait
    /// at physical 128, not be failed or allowed to make dial number 129.

    static func routedFailureCallbackPreservesCapacity() throws {
        let query = FakeIPSelfTest.query("routed-capacity.example.test", type: 1, id: 0x7500)
        for https in [false, true] {
            for metadata in [false, true] {
                let lock = NSLock(), completed = DispatchSemaphore(value: 0), acknowledged = DispatchSemaphore(value: 0)
                var dials = 0, replies = 0, failures = 0, invalid = false
                let dialer: CancellableEncryptedDNSStreamDialer = { _, _, _, _, done in
                    lock.lock(); dials += 1; lock.unlock()
                    done(.failure(NodeConnectionAdmissionError.capacityExceeded)); return nil
                }
                let metadataDialer: MetadataAwareEncryptedDNSStreamDialer = { _, _, _, _, _, observe, done in
                    lock.lock(); dials += 1; lock.unlock()
                    let error = NodeConnectionAdmissionError.capacityExceeded
                    observe(error); done(.failure(error)); return nil
                }
                let receive: (Data) -> Void = { _ in
                    lock.lock(); replies += 1; lock.unlock(); completed.signal()
                }
                let failure: (Error) -> Void = { error in
                    lock.lock()
                    failures += 1
                    invalid = invalid || (error as? EncryptedDNSQueryFailure) != .capacity
                    lock.unlock(); completed.signal()
                }
                let flow: NativeRoutedDatagram & DNSQueryCancellationAcknowledging
                let stop: () -> Void
                if https {
                    let endpoint = DoHEndpoint("https://routed-capacity.selftest.invalid/dns-query#203.0.113.53")!
                    let resolver = metadata
                        ? DoHResolver(endpoint: endpoint, metadataStreamDialer: metadataDialer)
                        : DoHResolver(endpoint: endpoint, cancellableStreamDialer: dialer)
                    flow = DoHRoutedDatagram(resolver: resolver, receive: receive, failure: failure)
                    stop = { resolver.cancel() }
                } else {
                    let endpoint = DoTEndpoint("tls://routed-capacity.selftest.invalid#203.0.113.53")!
                    let resolver = metadata
                        ? DoTResolver(endpoint: endpoint, metadataStreamDialer: metadataDialer)
                        : DoTResolver(endpoint: endpoint, cancellableStreamDialer: dialer)
                    flow = DoTRoutedDatagram(resolver: resolver, receive: receive, failure: failure)
                    stop = { resolver.cancel() }
                }
                defer { flow.cancel(); stop() }
                flow.send(query)
                try expect(completed.wait(timeout: .now() + 2) == .success,
                           "strict routed DNS did not report native capacity through its failure channel")
                flow.cancel { acknowledged.signal() }
                try expect(acknowledged.wait(timeout: .now() + 2) == .success,
                           "strict routed DNS capacity did not fence its logical cancellation")
                lock.lock(); let preserved = dials == 1 && replies == 0 && failures == 1 && !invalid; lock.unlock()
                try expect(preserved,
                           "DoH/DoT strict failure handler converted local capacity to SERVFAIL, lost its type or completed twice")
            }
        }
        print("DNS strict routed failure channels passed: DoH/DoT metadata/cancellable native capacity remains typed.capacity, no synthetic SERVFAIL or duplicate delivery")
    }

    static func reusePendingDialBounds() throws {
        let endpoint = DoTEndpoint("tls://pending.reuse.selftest.invalid#203.0.113.53")!
        let budget = SOCKSUDPGlobalBudget(resources: 4, packets: 0, bytes: 0)
        let lock = NSLock(), issued = DispatchSemaphore(value: 0), completed = DispatchGroup()
        var callbacks: [(Result<any NativeOutboundByteStream, Error>) -> Void] = []
        var holdDials = true, dialCount = 0, invalid = false
        let resolver = DoTResolver(endpoint: endpoint, streamDialer: { _, _, _, _, done in
            lock.lock()
            dialCount += 1
            let hold = holdDials
            if hold { callbacks.append(done) }
            lock.unlock()
            issued.signal()
            if !hold { done(.success(reuseAuto(2))) }
        }, requestTimeout: .seconds(3), activeLimit: 128, coldDialLimit: 128, resourceBudget: budget)
        defer { resolver.cancel() }
        var ids: [UUID] = []
        for index in 0..<128 {
            let query = FakeIPSelfTest.query("pending-\(index).reuse.example", type: 1,
                                            id: UInt16(0x4000 + index))
            completed.enter()
            guard let id = resolver.resolve(query: query, completion: { answer in
                if answer != nil { lock.lock(); invalid = true; lock.unlock() }
                completed.leave()
            }) else { throw Failure(text: "pending dial admission rejected one of the first 128 queries") }
            ids.append(id)
        }
        for _ in 0..<128 {
            try expect(issued.wait(timeout: .now() + 3) == .success, "pending dial fixture did not issue")
        }
        ids.forEach { resolver.cancel($0) }
        try expect(completed.wait(timeout: .now() + 3) == .success,
                   "legacy pending queries did not finish their logical cancellation")
        let extra = FakeIPSelfTest.query("pending-overflow.reuse.example", type: 1, id: 0x4100)
        let queuedCompletion = DispatchSemaphore(value: 0)
        var queuedReason: EncryptedDNSQueryFailure?
        guard let queuedID = resolver.resolveResult(query: extra, completion: { result in
            lock.lock()
            if case .failure(let reason) = result { queuedReason = reason }
            else { invalid = true }
            lock.unlock(); queuedCompletion.signal()
        }) else { throw Failure(text: "physical saturation rejected its bounded legacy waiter") }
        resolver.drainQueueForSelfTest()
        lock.lock(); let bounded = dialCount == 128 && callbacks.count == 128 && queuedReason == nil; lock.unlock()
        try expect(bounded && budget.usage.resources == 0,
                   "cancelled pending dials freed capacity or failed a waiter before their late callbacks")
        resolver.cancel(queuedID)
        try expect(queuedCompletion.wait(timeout: .now() + 3) == .success,
                   "a physical-capacity waiter did not acknowledge cancellation")
        lock.lock(); let cancelledWaiter = queuedReason == .cancelled && dialCount == 128; lock.unlock()
        try expect(cancelledWaiter, "canceling a physically queued legacy request created I/O or a false capacity error")

        lock.lock(); let delayed = callbacks; callbacks.removeAll(); holdDials = false; lock.unlock()
        var late: [ReuseMemoryStream] = []
        for callback in delayed {
            let stream = reuseAuto(2); late.append(stream); callback(.success(stream))
        }
        let next = FakeIPSelfTest.query("pending-recovered.reuse.example", type: 1, id: 0x4200)
        let answer = try reuseAwait { resolver.resolve(query: next, completion: $0) }
        try expect(completed.wait(timeout: .now() + 3) == .success,
                   "cancelled pending queries did not complete exactly once")
        lock.lock(); let count = dialCount, bad = invalid; lock.unlock()
        try expect(!bad && count == 129 && late.allSatisfy({ $0.cancelled && $0.sendCount == 0 })
                   && budget.usage.resources == 1
                   && answer.map({ DNSMessageInspection.responseMatchesQuery($0, query: next) }) == true,
                   "late cancelled dial was reused or its bounded slot/resource lease leaked")
    }

    static func bootstrapLoopbackDialAndSNI() throws {
        let queue = DispatchQueue(label: "app.hajimi.dns.bootstrap-selftest")
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        let listener = try NWListener(using: parameters, on: .any)
        defer { listener.cancel() }
        let ready = DispatchSemaphore(value: 0)
        let accepted = DispatchSemaphore(value: 0)
        let lock = NSLock()
        let serverName = "doh.selftest.invalid"
        var clientHello = Data()

        func capture(_ connection: NWConnection, _ partial: Data) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) {
                data, _, complete, error in
                var next = partial
                if let data { next.append(data) }
                if next.range(of: Data(serverName.utf8)) != nil || next.count >= 4096
                    || complete || error != nil {
                    lock.lock(); clientHello = next; lock.unlock()
                    accepted.signal()
                    connection.cancel()
                } else {
                    capture(connection, next)
                }
            }
        }

        listener.newConnectionHandler = { connection in
            connection.start(queue: queue)
            capture(connection, Data())
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready, .failed: ready.signal()
            default: break
            }
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 3) == .success,
              let port = listener.port else { throw Failure(text: "回环 DNS 监听器未启动") }
        guard let endpoint = DoHEndpoint(
            "https://\(serverName):\(port.rawValue)/dns-query#127.0.0.1") else {
            throw Failure(text: "回环 bootstrap 端点解析失败")
        }
        let resolver = DoHResolver(endpoint: endpoint, bootstrapTimeout: .seconds(2))
        let completed = DispatchSemaphore(value: 0)
        var result: Data?
        resolver.resolve(query: FakeIPSelfTest.query("example.com", type: 1)) {
            result = $0
            completed.signal()
        }
        guard accepted.wait(timeout: .now() + 5) == .success else {
            throw Failure(text: "具名 DoH 端点未连接 127.0.0.1 bootstrap")
        }
        lock.lock(); let hello = clientHello; lock.unlock()
        try expect(hello.range(of: Data(serverName.utf8)) != nil,
                   "DoH TLS ClientHello 缺少原 URL 域名 SNI")
        try expect(completed.wait(timeout: .now() + 5) == .success && result == nil,
                   "无证书的回环服务未被 TLS 拒绝或 DoH 查询未及时结束")
    }

    static func protocolRulesAndMieruUDPRecovery() throws {
        try DNSProtocolRouterAdapterSelfTest.run()
        // Verify C++ bridge Mieru-UDP timeout/reset errors classify as retriable network/timeout
        // rather than poisoning fallback barriers with .other, while genuine protocol errors remain .other.
        let mieruHandshakeTimeout = NSError(
            domain: "app.hajimi.cpp-protocol", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Mieru UDP session handshake timed out"])
        let mieruRetransmitTimeout = NSError(
            domain: "app.hajimi.cpp-protocol", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Mieru UDP retransmission limit exceeded"])
        let mieruSocketReset = NSError(
            domain: "app.hajimi.cpp-protocol", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Mieru UDP socket error"])
        let bareProtocolError = NSError(domain: "app.hajimi.cpp-protocol", code: 1)
        try expect(EncryptedDNSQueryFailure.classify(mieruHandshakeTimeout) == .timeout
                   && EncryptedDNSQueryFailure.classify(mieruRetransmitTimeout) == .timeout
                   && EncryptedDNSQueryFailure.classify(mieruSocketReset) == .network
                   && EncryptedDNSQueryFailure.classify(bareProtocolError) == .other,
                   "Mieru-UDP C++ 桥接超时/套接字重置错误分类不正确")
    }
}
