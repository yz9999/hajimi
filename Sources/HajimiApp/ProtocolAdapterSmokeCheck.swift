import Foundation
import Darwin
import HajimiCore

func runNativeQUICCodecCheck() -> Int32 {
    do {
        try NativeOutboundFactory.runQUICProtocolSelfTest()
        print("Native QUIC/Hysteria/Hysteria2/TUIC codec self-test passed")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Native QUIC codec self-test failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

func runNativePolicyListenerLiveCheck() -> Int32 {
    let environment = ProcessInfo.processInfo.environment
    do {
        let store = ConfigurationStore()
        let text = try environment["HAJIMI_TEST_PROFILE"].map {
            try String(contentsOfFile: $0, encoding: .utf8)
        } ?? store.loadText()
        let parsed = try ProfileParser.parse(text)
        let runtime = try ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: parsed)
        let policy = environment["HAJIMI_TEST_POLICY"] ?? "DIRECT"
        let mode = OutboundMode(rawValue: environment["HAJIMI_TEST_MODE"] ?? "proxy") ?? .proxy
        var selections: [String: String] = [:]
        if let group = environment["HAJIMI_TEST_GROUP"],
           let member = environment["HAJIMI_TEST_MEMBER"] {
            selections[group] = member
        }
        let targetPort = UInt16(environment["HAJIMI_TEST_TARGET_PORT"] ?? "80") ?? 80
        let engine = ProxyEngine()
        defer { engine.stop(); usleep(200_000) }
        let ready = DispatchSemaphore(value: 0)
        var startError: Error?
        engine.onStatus = { status in
            switch status {
            case .running: ready.signal()
            case .failed(let message): startError = SmokeCheckError(message); ready.signal()
            default: break
            }
        }
        let binding = DispatchSemaphore(value: 0)
        engine.setOutboundInterface(name: environment["HAJIMI_TEST_INTERFACE"]) { result in
            if case .failure(let error) = result { startError = error }
            binding.signal()
        }
        guard binding.wait(timeout: .now() + 5) == .success else {
            throw SmokeCheckError("策略模式物理接口设置超时")
        }
        if let startError { throw startError }
        try engine.start(profile: runtime, mode: mode, globalPolicy: policy,
                         groupSelections: selections)
        guard ready.wait(timeout: .now() + 5) == .success else {
            throw SmokeCheckError("策略模式监听器启动超时")
        }
        if let startError { throw startError }
        let body = try curlThroughHTTPProxy(
            proxyPort: engine.activeHTTPListen.port, targetPort: targetPort,
            host: environment["HAJIMI_TEST_TARGET_HOST"] ?? "127.0.0.1",
            path: environment["HAJIMI_TEST_TARGET_PATH"] ?? "/")
        guard !body.isEmpty else { throw SmokeCheckError("策略模式 HTTP 响应为空") }
        if let expected = environment["HAJIMI_TEST_EXPECT_BODY"], body != expected {
            throw SmokeCheckError("策略模式 HTTP 响应内容与预期不符")
        }
        if let rawUDPPort = environment["HAJIMI_TEST_UDP_PORT"], let udpPort = UInt16(rawUDPPort) {
            try testSOCKSUDPRelay(socksPort: engine.activeSOCKSListen.port, targetPort: udpPort,
                                  payload: Data("hajimi-policy-udp-\(UUID().uuidString)".utf8))
        }
        print("Native policy listener live check passed: \(mode.rawValue)/\(policy)")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Native policy listener live check failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

/// Reproduces the GUI's enhanced-mode START request without AppKit state.
/// Always sends STOP on exit so a failed response cannot leave routes behind.
func runEnhancedHelperIPCCheck() -> Int32 {
    let client = PrivilegedHelperClient()
    defer { _ = try? client.stop() }
    do {
        let store = ConfigurationStore()
        let parsed = try ProfileParser.parse(store.loadText())
        let resolved = try SurgeRuleSetManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: parsed)
        let runtime = try ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: resolved)
        let policy = ProcessInfo.processInfo.environment["HAJIMI_TEST_POLICY"] ??
            UserDefaults.standard.string(forKey: "globalPolicy") ?? "DIRECT"
        let selections = UserDefaults.standard.dictionary(forKey: "groupSelections") as? [String: String] ?? [:]
        let bypass = ProxyBypassAddresses.collect(profile: runtime, mode: .proxy,
                                                  globalPolicy: policy,
                                                  groupSelections: selections)
        let session = try client.start(fakeIPEnabled: runtime.shouldHijackSystemDNS,
                                       bypassAddresses: bypass,
                                       excludedRoutes: runtime.tunExcludedRoutes,
                                       includedRoutes: runtime.tunIncludedRoutes)
        Darwin.close(session.fileDescriptor)
        print("Enhanced Helper IPC check passed: \(session.state.dataPlane)")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Enhanced Helper IPC check failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

/// Maintenance entry points used to replace a running privileged data plane
/// without leaving routes behind.  They invoke the same parser, native-policy
/// promotion and verified installer as the GUI.
func runHelperInstallMaintenance() -> Int32 {
    do {
        try PrivilegedHelperClient().ensureInstalledSynchronously()
        print("Hajimi Helper install/update passed")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Hajimi Helper install/update failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

func runHelperStartCurrentMaintenance() -> Int32 {
    do {
        let store = ConfigurationStore()
        let parsed = try ProfileParser.parse(store.loadText())
        let resolved = try SurgeRuleSetManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: parsed)
        let runtime = try ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: resolved)
        let defaults = UserDefaults.standard
        let mode = defaults.string(forKey: "outboundMode").flatMap(OutboundMode.init) ?? .rule
        let policy = defaults.string(forKey: "globalPolicy") ?? "DIRECT"
        let selections = defaults.dictionary(forKey: "groupSelections")?.reduce(into: [String: String]()) {
            if let value = $1.value as? String { $0[$1.key] = value }
        } ?? [:]
        let bypass = ProxyBypassAddresses.collect(profile: runtime, mode: mode,
                                                  globalPolicy: policy,
                                                  groupSelections: selections)
        let session = try PrivilegedHelperClient().start(
            fakeIPEnabled: runtime.shouldHijackSystemDNS, bypassAddresses: bypass,
            excludedRoutes: runtime.tunExcludedRoutes,
            includedRoutes: runtime.tunIncludedRoutes)
        // Maintenance only re-installs routes; the GUI owns the data plane FD.
        Darwin.close(session.fileDescriptor)
        print("Hajimi Helper enhanced mode restored: \(session.state.tunnelInterface ?? "unknown")")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Hajimi Helper enhanced restore failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

func runHelperStopMaintenance() -> Int32 {
    do {
        _ = try PrivilegedHelperClient().stop()
        print("Hajimi Helper enhanced mode stopped")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Hajimi Helper stop failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

func runSelectedNativePolicyLiveCheck() -> Int32 {
    do {
        let store = ConfigurationStore()
        let environment = ProcessInfo.processInfo.environment
        let text: String
        if let path = environment["HAJIMI_TEST_PROFILE"] {
            text = try String(contentsOfFile: path, encoding: .utf8)
        } else {
            text = store.loadText()
        }
        let parsed = try ProfileParser.parse(text)
        let runtime = try ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: parsed)
        let policy = environment["HAJIMI_TEST_POLICY"] ??
            UserDefaults.standard.string(forKey: "globalPolicy") ?? "DIRECT"
        let mode = OutboundMode(rawValue: environment["HAJIMI_TEST_MODE"] ?? "proxy") ?? .proxy
        let interfaceReady = DispatchSemaphore(value: 0)
        var interfaceResult: Result<Void, Error>?
        NativePacketRouter.setOutboundInterface(name: environment["HAJIMI_TEST_INTERFACE"]) {
            interfaceResult = $0; interfaceReady.signal()
        }
        guard interfaceReady.wait(timeout: .now() + 5) == .success, let interfaceResult else {
            throw SmokeCheckError("物理接口绑定超时")
        }
        try interfaceResult.get()
        var liveSelections: [String: String] = [:]
        if let group = environment["HAJIMI_TEST_GROUP"],
           let member = environment["HAJIMI_TEST_MEMBER"] {
            liveSelections[group] = member
            liveSelections["🎯 总模式"] = group
        }
        let initialPolicy = environment["HAJIMI_INITIAL_POLICY"] ?? policy
        let router = NativePacketRouter(profile: runtime, mode: mode,
                                        globalPolicy: initialPolicy, groupSelections: liveSelections)
        if initialPolicy != policy {
            router.update(profile: runtime, mode: mode,
                          globalPolicy: policy, groupSelections: liveSelections)
        }
        let queue = DispatchQueue(label: "app.hajimi.native-policy-live",
                                  autoreleaseFrequency: .workItem)
        let connected = DispatchSemaphore(value: 0)
        var connection: Result<NativeOutboundByteStream, Error>?
        let targetHost = environment["HAJIMI_TEST_TARGET_HOST"] ?? "1.1.1.1"
        let targetPort = UInt16(environment["HAJIMI_TEST_TARGET_PORT"] ?? "80") ?? 80
        router.connectTCP(host: targetHost, port: targetPort, queue: queue) {
            connection = $0; connected.signal()
        }
        guard connected.wait(timeout: .now() + 15) == .success, let connection else {
            throw SmokeCheckError("原生策略连接超时")
        }
        let stream = try connection.get(); defer { stream.cancel() }
        if let rawIdle = environment["HAJIMI_TEST_IDLE_BEFORE_SEND"],
           let idle = Double(rawIdle), idle > 0 {
            Thread.sleep(forTimeInterval: min(idle, 120))
        }
        let requestPath = environment["HAJIMI_TEST_TARGET_PATH"] ?? "/"
        let uploadBytes = max(0, Int(environment["HAJIMI_TEST_UPLOAD_BYTES"] ?? "0") ?? 0)
        var request: Data
        if uploadBytes > 0 {
            // The upload direction is its own code path on carriers that split
            // the two — XHTTP sends it as a separate sequence of POSTs on a
            // separate connection — and a GET never exercises it.
            //
            // The inner protocol's AEAD is what makes this a real test: a lost,
            // duplicated or reordered upload chunk desynchronises the stream
            // cipher, so a body that arrives intact proves the carrier kept
            // ordering, not merely that bytes moved.
            let alphabet = [UInt8]("0123456789abcdefghijklmnopqrstuvwxyz".utf8)
            let body = Data((0..<uploadBytes).map { alphabet[$0 % alphabet.count] })
            request = Data(("POST \(requestPath) HTTP/1.1\r\nHost: \(targetHost)\r\n"
                + "Content-Type: application/octet-stream\r\n"
                + "Content-Length: \(uploadBytes)\r\nConnection: close\r\n\r\n").utf8)
            request.append(body)
        } else {
            request = Data("GET \(requestPath) HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n".utf8)
        }
        let sent = DispatchSemaphore(value: 0); var sendError: Error?
        let writeTimeout = max(10, uploadBytes / 20_000)
        stream.send(request) { sendError = $0; sent.signal() }
        guard sent.wait(timeout: .now() + .seconds(writeTimeout)) == .success, sendError == nil else {
            throw sendError ?? SmokeCheckError("原生策略写入超时")
        }
        let requestedBytes = max(1, Int(environment["HAJIMI_TEST_READ_BYTES"] ?? "1") ?? 1)
        let maximumSeconds = max(15, Int(environment["HAJIMI_TEST_MAX_SECONDS"] ?? "300") ?? 300)
        let receiveTimeout = max(5, min(Int(environment["HAJIMI_TEST_RECEIVE_TIMEOUT"] ?? "20") ?? 20,
                                        120))
        let downloadStarted = Date()
        let deadline = downloadStarted.addingTimeInterval(TimeInterval(maximumSeconds))
        var receivedBytes = 0
        var responsePrefix = Data()
        var responseComplete = false
        let expectedBody = environment["HAJIMI_TEST_EXPECT_BODY"].map { Data($0.utf8) }
        let headerSeparator = Data("\r\n\r\n".utf8)
        func receivedExpectedBody() -> Bool {
            guard let expectedBody else { return true }
            guard let separator = responsePrefix.range(of: headerSeparator) else { return false }
            return responsePrefix[separator.upperBound...].range(of: expectedBody) != nil
        }
        while (receivedBytes < requestedBytes || !receivedExpectedBody()),
              !responseComplete, Date() < deadline {
            let received = DispatchSemaphore(value: 0)
            var data: Data?; var receiveError: Error?
            stream.receive(maximum: 256 * 1_024) {
                data = $0; responseComplete = $1; receiveError = $2; received.signal()
            }
            guard received.wait(timeout: .now() + .seconds(receiveTimeout)) == .success else {
                throw SmokeCheckError("原生策略持续读取超时（已读取 \(receivedBytes) 字节）")
            }
            if let receiveError {
                throw SmokeCheckError("持续读取在 \(receivedBytes) 字节后失败：" +
                                      receiveError.localizedDescription)
            }
            if let data, !data.isEmpty {
                receivedBytes += data.count
                let prefixLimit = expectedBody == nil ? 4_096 : 65_536
                if responsePrefix.count < prefixLimit {
                    responsePrefix.append(data.prefix(prefixLimit - responsePrefix.count))
                }
            }
        }
        guard String(data: responsePrefix, encoding: .isoLatin1)?.contains("HTTP/") == true else {
            throw SmokeCheckError("原生策略没有返回 HTTP 响应")
        }
        guard receivedExpectedBody() else {
            throw SmokeCheckError("原生策略 HTTP 正文与预期不符")
        }
        guard receivedBytes >= requestedBytes else {
            throw SmokeCheckError("原生策略响应提前结束（\(receivedBytes)/\(requestedBytes) 字节）")
        }
        if let udpHost = environment["HAJIMI_TEST_UDP_HOST"],
           let rawPort = environment["HAJIMI_TEST_UDP_PORT"], let udpPort = UInt16(rawPort) {
            let received = DispatchSemaphore(value: 0)
            // Port 53 is checked with a real query rather than an echo. Public
            // UDP echo servers effectively do not exist, so requiring one made
            // this path unverifiable against any real node — and DNS is what
            // proxied UDP is overwhelmingly used for anyway.
            let isDNS = udpPort == 53
            let transaction = UInt16.random(in: 1...UInt16.max)
            let payload = isDNS
                ? dnsQuery(name: environment["HAJIMI_TEST_UDP_DNS"] ?? "example.com",
                           transaction: transaction)
                : Data("hajimi-native-udp-\(UUID().uuidString)".utf8)
            var response: Data?, udpError: Error?
            let flow = try router.makeUDPFlow(host: udpHost, port: udpPort, queue: queue,
                                              receive: { response = $0; received.signal() },
                                              failure: { udpError = $0; received.signal() })
            defer { flow.cancel() }
            flow.send(payload)
            guard received.wait(timeout: .now() + 15) == .success else {
                throw SmokeCheckError("原生 UDP 策略响应超时")
            }
            if let udpError { throw udpError }
            if isDNS {
                guard let answer = response, answer.count >= 12 else {
                    throw SmokeCheckError("原生 UDP 策略 DNS 响应过短")
                }
                let id = UInt16(answer[answer.startIndex]) << 8 | UInt16(answer[answer.startIndex + 1])
                guard id == transaction else {
                    throw SmokeCheckError("原生 UDP 策略 DNS 事务 ID 不符（\(id) ≠ \(transaction)）")
                }
                guard answer[answer.startIndex + 2] & 0x80 != 0 else {
                    throw SmokeCheckError("原生 UDP 策略 DNS 响应未置 QR 位")
                }
                let answers = UInt16(answer[answer.startIndex + 6]) << 8
                    | UInt16(answer[answer.startIndex + 7])
                guard answers >= 1 else {
                    throw SmokeCheckError("原生 UDP 策略 DNS 响应无应答记录")
                }
                print("Native UDP DNS check: \(answers) answers, \(answer.count) bytes")
            } else {
                guard response == payload else { throw SmokeCheckError("原生 UDP 策略响应不匹配") }
            }
        }
        let elapsed = max(0.001, Date().timeIntervalSince(downloadStarted))
        let rate = Double(receivedBytes) / elapsed / 1_048_576
        print(String(format: "Selected native policy live check passed: %@/%@, %d bytes, %.2f MiB/s",
                     mode.rawValue, policy, receivedBytes, rate))
        return 0
    } catch {
        FileHandle.standardError.write(Data("Selected native policy live check failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

/// Opens many simultaneous streams through one NativePacketRouter while its
/// outbound selection is repeatedly hot-reloaded.  This exercises the same
/// shared QUIC/AnyTLS/SSH pools and atomic profile snapshot used by enhanced
/// mode, without installing machine routes in a test process.
func runNativePolicyStressCheck() -> Int32 {
    let environment = ProcessInfo.processInfo.environment
    do {
        let store = ConfigurationStore()
        let text = try environment["HAJIMI_TEST_PROFILE"].map {
            try String(contentsOfFile: $0, encoding: .utf8)
        } ?? store.loadText()
        let parsed = try ProfileParser.parse(text)
        let runtime = try ProtocolAdapterManager(applicationSupportDirectory: store.directoryURL)
            .prepare(profile: parsed)
        let policy = environment["HAJIMI_TEST_POLICY"] ?? "DIRECT"
        let count = max(1, min(Int(environment["HAJIMI_TEST_CONCURRENCY"] ?? "32") ?? 32, 256))
        let targetHost = environment["HAJIMI_TEST_TARGET_HOST"] ?? "127.0.0.1"
        let targetPort = UInt16(environment["HAJIMI_TEST_TARGET_PORT"] ?? "80") ?? 80
        let router = NativePacketRouter(profile: runtime, mode: .proxy,
                                        globalPolicy: policy, groupSelections: [:])
        let work = DispatchQueue(label: "app.hajimi.native-stress", qos: .userInitiated,
                                 attributes: .concurrent)
        let group = DispatchGroup()
        let lock = NSLock()
        var failures: [String] = []

        for index in 0..<count {
            group.enter()
            work.async {
                router.connectTCP(host: targetHost, port: targetPort, queue: work) { result in
                    switch result {
                    case .failure(let error):
                        lock.lock(); failures.append("#\(index) connect: \(error.localizedDescription)"); lock.unlock()
                        group.leave()
                    case .success(let stream):
                        let request = Data("GET / HTTP/1.1\r\nHost: \(targetHost)\r\nConnection: close\r\n\r\n".utf8)
                        stream.send(request) { error in
                            if let error {
                                lock.lock(); failures.append("#\(index) send: \(error.localizedDescription)"); lock.unlock()
                                stream.cancel(); group.leave(); return
                            }
                            stream.receive(maximum: 4096) { data, _, error in
                                defer { stream.cancel(); group.leave() }
                                if let error {
                                    lock.lock(); failures.append("#\(index) receive: \(error.localizedDescription)"); lock.unlock()
                                } else if data.flatMap({ String(data: $0, encoding: .utf8) })?.contains("HTTP/") != true {
                                    lock.lock(); failures.append("#\(index) invalid HTTP response"); lock.unlock()
                                }
                            }
                        }
                    }
                }
            }
            if index % 4 == 3 {
                router.update(profile: runtime, mode: .proxy, globalPolicy: "DIRECT",
                              groupSelections: [:])
                router.update(profile: runtime, mode: .proxy, globalPolicy: policy,
                              groupSelections: [:])
            }
        }
        guard group.wait(timeout: .now() + 60) == .success else {
            throw SmokeCheckError("并发压力测试超时（\(count) 条流）")
        }
        if !failures.isEmpty {
            throw SmokeCheckError("并发压力测试失败 \(failures.count)/\(count)：" +
                                  failures.prefix(5).joined(separator: " | "))
        }
        print("Native policy concurrency/hot-reload stress check passed: \(policy), \(count) streams")
        return 0
    } catch {
        FileHandle.standardError.write(Data("Native policy stress check failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

/// Offline construction check: every advertised protocol must be promoted to
/// the in-process native core.  It deliberately launches no proxy process.
func runProtocolAdapterSmokeCheck() -> Int32 {
    let profileText = """
    [General]
    http-listen = 127.0.0.1:32162
    socks5-listen = 127.0.0.1:32163

    [Proxy]
    SS = ss, 127.0.0.1, 10001, cipher=aes-128-gcm, password=test
    SSR = ssr, 127.0.0.1, 10002, cipher=aes-128-cfb, password=test, protocol=origin, obfs=plain
    Snell = snell, 127.0.0.1, 10003, psk=test, version=4, udp=true
    VMess = vmess, 127.0.0.1, 10004, uuid=00000000-0000-0000-0000-000000000001, vmess-aead=true
    VLESS = vless, 127.0.0.1, 10005, uuid=00000000-0000-0000-0000-000000000001, encryption=none
    Trojan = trojan, 127.0.0.1, 10006, password=test, skip-cert-verify=true
    AnyTLS = anytls, 127.0.0.1, 10007, password=test, skip-cert-verify=true
    Hysteria = hysteria, 127.0.0.1, 10008, auth-str=test, up=10 Mbps, down=50 Mbps, skip-cert-verify=true
    Hysteria2 = hysteria2, 127.0.0.1, 10009, password=test, skip-cert-verify=true
    TUIC = tuic, 127.0.0.1, 10010, uuid=00000000-0000-0000-0000-000000000001, password=test, skip-cert-verify=true
    SSH = ssh, 127.0.0.1, 10011, username=test, password=test, skip-cert-verify=true

    [Proxy Group]
    Native = select, SS, SSR, Snell, VMess, VLESS, Trojan, AnyTLS, Hysteria, Hysteria2, TUIC, SSH

    [Rule]
    FINAL,Native
    """
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("hajimi-native-capability-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    do {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let profile = try ProfileParser.parse(profileText)
        guard profile.adapterPolicies.count == 11 else {
            throw SmokeCheckError("应解析 11 个原生协议，实际为 \(profile.adapterPolicies.count)")
        }
        let unsupported = profile.adapterPolicies.compactMap { policy in
            NativeOutboundFactory.supports(policy) ? nil :
                "\(policy.name): \(NativeOutboundFactory.validationError(for: policy) ?? "不支持")"
        }
        guard unsupported.isEmpty else {
            throw SmokeCheckError("存在未进入原生核心的节点：" + unsupported.joined(separator: " | "))
        }
        let manager = ProtocolAdapterManager(applicationSupportDirectory: root)
        let runtime = try manager.prepare(profile: profile)
        guard profile.proxyOrder.allSatisfy({ runtime.proxies[$0]?.kind == .native }) else {
            throw SmokeCheckError("部分协议没有被提升为原生出站")
        }
        let udpExpected: Set<String> = ["SS", "SSR", "Snell", "VMess", "VLESS", "Trojan",
                                        "AnyTLS", "Hysteria", "Hysteria2", "TUIC"]
        guard profile.adapterPolicies.filter(NativeOutboundFactory.supportsUDP)
                .reduce(into: Set<String>(), { $0.insert($1.name) }) == udpExpected else {
            throw SmokeCheckError("原生 UDP 能力矩阵不一致")
        }
        let streamUDPExpected: Set<String> = ["Snell", "VMess", "VLESS", "Trojan", "AnyTLS"]
        guard profile.adapterPolicies.filter(NativeOutboundFactory.carriesUDPOverReliableStream)
                .reduce(into: Set<String>(), { $0.insert($1.name) }) == streamUDPExpected else {
            throw SmokeCheckError("QUIC TCP 回退能力矩阵不一致")
        }
        let fallbackRouter = NativePacketRouter(profile: runtime, mode: .proxy,
                                                globalPolicy: "Native",
                                                groupSelections: ["Native": "VMess"])
        guard fallbackRouter.prefersTCPFallbackForQUIC(host: "203.0.113.10") else {
            throw SmokeCheckError("VMess UDP/443 没有触发 TCP 回退")
        }
        fallbackRouter.update(profile: runtime, mode: .proxy, globalPolicy: "Native",
                              groupSelections: ["Native": "Hysteria2"])
        guard !fallbackRouter.prefersTCPFallbackForQUIC(host: "203.0.113.10") else {
            throw SmokeCheckError("原生 QUIC 出站被错误禁用")
        }
        try NativeOutboundFactory.runWebSocketTransportSelfTest()
        try NativeOutboundFactory.runMuxSelfTest()
        try NativeOutboundFactory.runProxyChainSelfTest()
        try PolicyHealthSelfTest.run()
        try BLAKE3SelfTest.run()
        try Shadowsocks2022SelfTest.run()
        if let failure = UDPPrivacyPolicySelfTest.failure() {
            throw SmokeCheckError(failure)
        }
        try SubscriptionSelfTest.run()
        try bypassRefreshSelfTest()
        try sessionRestoreIntentSelfTest()
        try launchProfilePlanSelfTest()
        try profileApplySafetySelfTest()
        try subscriptionRefreshMergeSelfTest()
        try subscriptionManagerCommitSelfTest(root: root)
        try FakeIPSelfTest.run()
        try ExternalControllerSelfTest.run()
        try runIngressSecuritySelfTest()
        try EncryptedDNSSelfTest.run()
        try XChaCha20SelfTest.run()
        try HPACKSelfTest.run()
        try HTTP2SelfTest.run()
        try XHTTPSelfTest.run()
        try MKCPSegmentSelfTest.run()
        try MKCPTransportSelfTest.run()
        try TLS13SelfTest.run()
        try TLS13FingerprintSelfTest.run()
        try RealityTLSSelfTest.run()
        try VLESSVisionSelfTest.run()
        try MKCPOutboundSelfTest.run()
        try TrafficRateSelfTest.run()
        try AppDelegate.validateTrafficTitleMetrics()
        guard SystemProxyManager.ownershipSelfTest() else {
            throw SmokeCheckError("系统代理快照所有权检测失败")
        }
        try runLocalUDPPolicySwitchSelfTest()
        try validateSurgeCompatibilityFixture(root: root, adapters: manager)
        print("Native protocol capability/WebSocket/Mux control check passed " +
              "(11 protocols, no proxy subprocess)")
        return 0
    } catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

#if false
private func legacyProtocolAdapterSmokeCheck() -> Int32 {
    let ssServerPort: UInt16
    let vmessServerPort: UInt16
    let vlessServerPort: UInt16
    let trojanServerPort: UInt16
    let httpServerPort: UInt16
    let udpEchoPort: UInt16
    let hajimiHTTPPort: UInt16
    let hajimiSOCKSPort: UInt16
    do {
        var used = Set<UInt16>()
        func nextPort() throws -> UInt16 {
            var port = try availableTCPAndUDPPort()
            while used.contains(port) { port = try availableTCPAndUDPPort() }
            used.insert(port)
            return port
        }
        func nextNetworkFrameworkPort() -> UInt16 {
            var port = UInt16.random(in: 20_000...45_000)
            while used.contains(port) { port = UInt16.random(in: 20_000...45_000) }
            used.insert(port)
            return port
        }
        ssServerPort = try nextPort()
        vmessServerPort = try nextPort()
        vlessServerPort = try nextPort()
        trojanServerPort = try nextPort()
        httpServerPort = try nextPort()
        udpEchoPort = try nextPort()
        // Do not probe these with a BSD TCP bind: on macOS that briefly makes
        // a subsequent Network.framework listener report EADDRINUSE.
        hajimiHTTPPort = nextNetworkFrameworkPort()
        hajimiSOCKSPort = nextNetworkFrameworkPort()
    } catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        return 1
    }
    let profileText = """
    [General]
    http-listen = 127.0.0.1:\(hajimiHTTPPort)
    socks5-listen = 127.0.0.1:\(hajimiSOCKSPort)

    [Proxy]
    SS = Shadowsocks, 127.0.0.1, \(ssServerPort), cipher=aes-128-gcm, password=test
    SSR = ShadowsocksR, 127.0.0.1, 10002, cipher=chacha20-ietf, password=test, protocol=origin, obfs=plain, obfs-param=compat
    Snell = Snell, 127.0.0.1, 10003, psk=test, version=4, obfs-mode=http, obfs-host=example.com
    VMess = VMess, 127.0.0.1, \(vmessServerPort), uuid=00000000-0000-0000-0000-000000000001, network=ws, ws-path=/socket, ws-headers=Host:127.0.0.1|X-Hajimi:yes, tls=true, sni=localhost, skip-cert-verify=true
    VLESS = VLESS, 127.0.0.1, \(vlessServerPort), uuid=00000000-0000-0000-0000-000000000001, tls=true, sni=localhost, skip-cert-verify=true
    Trojan = Trojan, 127.0.0.1, \(trojanServerPort), password=test, tls=true, sni=localhost, skip-cert-verify=true, network=ws, ws-path=/trojan, ws-headers=Host:127.0.0.1
    AnyTLS = AnyTLS, 127.0.0.1, 10007, password=test, skip-cert-verify=true
    Hysteria = Hysteria, 127.0.0.1, 10008, auth-str=test, up=10 Mbps, down=50 Mbps, skip-cert-verify=true, obfs-protocol=udp
    Hysteria2 = Hysteria2, 127.0.0.1, 10009, password=test, skip-cert-verify=true, obfs=salamander, obfs-password=secret
    TUIC = TUIC, 127.0.0.1, 10010, token=test, skip-cert-verify=true
    SSH = SSH, 127.0.0.1, 10011, username=test, password=test

    [Proxy Group]
    Proxy = select, SS, SSR, Snell, VMess, VLESS, Trojan, AnyTLS, Hysteria, Hysteria2, TUIC, SSH

    [Rule]
    FINAL,Proxy
    """

    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("hajimi-protocol-check-\(UUID().uuidString)", isDirectory: true)
    let manager = ProtocolAdapterManager(applicationSupportDirectory: root)
    var ssServer: Process?
    var httpServer: Process?
    var udpEchoServer: Process?
    defer {
        manager.stop()
        stopProcess(udpEchoServer)
        stopProcess(httpServer)
        stopProcess(ssServer)
        try? FileManager.default.removeItem(at: root)
    }

    do {
        let webRoot = root.appendingPathComponent("www", isDirectory: true)
        try FileManager.default.createDirectory(at: webRoot, withIntermediateDirectories: true)
        let probe = "hajimi-ss-e2e-\(UUID().uuidString)"
        try probe.write(to: webRoot.appendingPathComponent("probe.txt"),
                        atomically: true, encoding: .utf8)
        httpServer = try launchHTTPServer(directory: webRoot, port: httpServerPort)
        guard waitForTCPPort(httpServerPort, timeout: 3) else {
            throw SmokeCheckError("本地 HTTP 测试服务启动超时")
        }
        udpEchoServer = try launchUDPEchoServer(port: udpEchoPort)
        usleep(100_000)

        ssServer = try launchShadowsocksServer(home: root.appendingPathComponent("ss-server"),
                                              port: ssServerPort,
                                              vmessPort: vmessServerPort,
                                              vlessPort: vlessServerPort,
                                              trojanPort: trojanServerPort)
        guard waitForTCPPort(ssServerPort, timeout: 3) else {
            throw SmokeCheckError("本地 Shadowsocks 测试服务启动超时")
        }
        guard waitForTCPPort(vmessServerPort, timeout: 3) else {
            throw SmokeCheckError("本地 VMess 测试服务启动超时")
        }
        guard waitForTCPPort(vlessServerPort, timeout: 3),
              waitForTCPPort(trojanServerPort, timeout: 3) else {
            throw SmokeCheckError("本地 VLESS/Trojan 测试服务启动超时")
        }

        let profile = try ProfileParser.parse(profileText)
        guard profile.adapterPolicies.count == 11 else {
            throw SmokeCheckError("应解析 11 个高级协议，实际为 \(profile.adapterPolicies.count)")
        }
        let runtime = try manager.prepare(profile: profile)
        for name in profile.proxyOrder {
            guard let original = profile.proxies[name], let prepared = runtime.proxies[name] else {
                throw SmokeCheckError("策略 \(name) 缺少运行时实例")
            }
            if NativeOutboundFactory.supports(original) {
                guard prepared.kind == .native else {
                    throw SmokeCheckError("策略 \(name) 没有进入第一方原生出站")
                }
            } else if prepared.kind != .socks5 || prepared.host != "127.0.0.1" {
                throw SmokeCheckError("策略 \(name) 没有转换为兼容 SOCKS5 适配器")
            }
        }

        let configURL = root.appendingPathComponent("mihomo/config.yaml")
        let config = try String(contentsOf: configURL, encoding: .utf8)
        let requiredFragments = [
            "type: \"ss\"", "type: \"ssr\"", "type: \"snell\"", "type: \"vmess\"",
            "type: \"vless\"", "type: \"trojan\"", "type: \"anytls\"",
            "type: \"hysteria\"", "type: \"hysteria2\"", "type: \"tuic\"",
            "type: \"ssh\"", "\"obfs-param\": \"compat\"", "ws-opts:",
            "\"X-Hajimi\": \"yes\"", "obfs-opts:",
            "\"obfs-password\": \"secret\"", "udp: false"
        ]
        for fragment in requiredFragments where !config.contains(fragment) {
            throw SmokeCheckError("生成的 Mihomo 配置缺少：\(fragment)")
        }
        try validateSurgeCompatibilityFixture(root: root, adapters: manager)

        let engine = ProxyEngine()
        let bindingReady = DispatchSemaphore(value: 0)
        var bindingFailure: String?
        engine.setOutboundInterface(name: try physicalDefaultInterface()) { result in
            if case .failure(let error) = result { bindingFailure = error.localizedDescription }
            bindingReady.signal()
        }
        guard bindingReady.wait(timeout: .now() + 4) == .success, bindingFailure == nil else {
            throw SmokeCheckError(bindingFailure ?? "增强模式物理接口绑定测试超时")
        }
        let ready = DispatchSemaphore(value: 0)
        let statusLock = NSLock()
        var engineFailure: String?
        var connectionFailures: [String] = []
        var receivedTerminalStatus = false
        engine.onStatus = { status in
            switch status {
            case .running, .failed:
                statusLock.lock()
                guard !receivedTerminalStatus else { statusLock.unlock(); return }
                receivedTerminalStatus = true
                if case .failed(let message) = status { engineFailure = message }
                statusLock.unlock()
                ready.signal()
            default: break
            }
        }
        engine.onEvent = { event in
            if case .closed(_, let error?) = event {
                statusLock.lock(); connectionFailures.append(error); statusLock.unlock()
            }
        }
        defer {
            engine.stop()
            // Give Network.framework time to remove listener NECP state before
            // this command-line smoke-test process exits via Darwin.exit().
            usleep(500_000)
        }
        try engine.start(profile: runtime, mode: .rule, globalPolicy: "DIRECT")
        let waitResult = ready.wait(timeout: .now() + 4)
        statusLock.lock()
        let failure = engineFailure
        statusLock.unlock()
        guard waitResult == .success, failure == nil else {
            let detail = failure ?? "Hajimi 测试监听器启动超时"
            throw SmokeCheckError("\(detail)（HTTP \(hajimiHTTPPort)，SOCKS \(hajimiSOCKSPort)）")
        }
        let response: String
        do {
            response = try curlThroughHTTPProxy(proxyPort: hajimiHTTPPort,
                                                targetPort: httpServerPort)
        } catch {
            statusLock.lock(); let details = connectionFailures; statusLock.unlock()
            throw SmokeCheckError("\(error.localizedDescription); engine=\(details.joined(separator: " | "))")
        }
        guard response == probe else {
            throw SmokeCheckError("Shadowsocks 端到端响应不匹配")
        }
        engine.updateRouting(mode: .proxy, globalPolicy: "VMess")
        let nativeVMessResponse: String
        do {
            nativeVMessResponse = try curlThroughHTTPProxy(proxyPort: hajimiHTTPPort,
                                                           targetPort: httpServerPort)
        } catch {
            statusLock.lock(); let details = connectionFailures; statusLock.unlock()
            throw SmokeCheckError("Native VMess: \(error.localizedDescription); engine=\(details.joined(separator: " | "))")
        }
        guard nativeVMessResponse == probe else {
            throw SmokeCheckError("第一方 VMess AEAD/WebSocket 端到端响应不匹配")
        }
        for policyName in ["VLESS", "Trojan"] {
            engine.updateRouting(mode: .proxy, globalPolicy: policyName)
            let response = try curlThroughHTTPProxy(proxyPort: hajimiHTTPPort,
                                                    targetPort: httpServerPort)
            guard response == probe else {
                throw SmokeCheckError("第一方 \(policyName) 端到端响应不匹配")
            }
        }
        engine.updateRouting(mode: .proxy, globalPolicy: "SS")
        let udpProbe = Data("hajimi-ss-udp-\(UUID().uuidString)".utf8)
        try testSOCKSUDPRelay(socksPort: hajimiSOCKSPort, targetPort: udpEchoPort,
                              payload: udpProbe)
        print("Advanced protocol adapter smoke tests passed (11 protocols)")
        print("Surge profile syntax/underlying-proxy/WireGuard/RULE-SET tests passed")
        print("Shadowsocks TCP/UDP rule-to-adapter end-to-end tests passed")
        print("Native VMess AEAD/WebSocket/TLS end-to-end test passed")
        print("Native VLESS and Trojan TCP/WebSocket/TLS tests passed")
        return 0
    } catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        return 1
    }
}
#endif

private func validateSurgeCompatibilityFixture(root: URL,
                                               adapters: ProtocolAdapterManager) throws {
    let rulesURL = root.appendingPathComponent("surge-fixture.rules")
    try """
    DOMAIN-SUFFIX,surge-fixture.example
    IP-CIDR6,2001:db8::/32,no-resolve
    USER-AGENT,HajimiFixture*
    """.write(to: rulesURL, atomically: true, encoding: .utf8)
    let profileText = """
    [General]
    allow-wifi-access = true
    wifi-access-http-port = 26152
    wifi-access-socks5-port = 26153
    skip-proxy = localhost, *.local

    [Proxy]
    Base = vmess, 127.0.0.1, 21001, username=00000000-0000-0000-0000-000000000001, ws=true, ws-path=/surge, vmess-aead=true, ip-version=v4-only
    Chained = trojan, 127.0.0.1, 21002, password=test, underlying-proxy=Base, skip-cert-verify=true
    ChainedWS = vmess, 127.0.0.1, 21004, username=00000000-0000-0000-0000-000000000002, ws=true, ws-path=/nested, underlying-proxy=Base, vmess-aead=true
    NestedSOCKS = socks5, 127.0.0.1, 21003, username=user, password=pass, udp-relay=true, underlying-proxy=Chained

    [Proxy Group]
    Select = select, Base, Chained, hidden=1
    Balance = load-balance, Base, Chained

    [Rule]
    RULE-SET,\(rulesURL.absoluteString),DIRECT,update-interval=3600
    FINAL,Select

    [MITM]
    enable = true

    [WireGuard FixtureWG]
    private-key = eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    self-ip = 172.16.0.2
    self-ip-v6 = 2001:db8::2
    mtu = 1280
    peer = (public-key = Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = 127.0.0.1:51820)
    """
    let parsed = try ProfileParser.parse(profileText)
    guard parsed.httpListen == ListenAddress(host: "0.0.0.0", port: 26152),
          parsed.socksListen == ListenAddress(host: "0.0.0.0", port: 26153),
          parsed.groups["Balance"]?.kind == .loadBalance,
          parsed.groups["Select"]?.members == ["Base", "Chained"],
          parsed.proxies["Base"].map(NativeOutboundFactory.supports) == true,
          parsed.proxies["Chained"].map(NativeOutboundFactory.supports) == true,
          parsed.proxies["ChainedWS"].map(NativeOutboundFactory.supports) == true,
          parsed.proxies["NestedSOCKS"]?.kind == .external,
          parsed.proxies["FixtureWG"]?.adapterType == "wireguard" else {
        throw SmokeCheckError("Surge Profile 基础兼容解析结果不正确")
    }
    let resolver = SurgeRuleSetManager(applicationSupportDirectory: root)
    let resolved = try resolver.prepare(profile: parsed)
    guard resolved.ruleSetContents[rulesURL.absoluteString]?.count == 2,
          resolved.route(for: RequestTarget(host: "www.surge-fixture.example", port: 443,
                                            protocolName: "TCP"),
                         mode: .rule, globalPolicy: "DIRECT").policyName == "DIRECT" else {
        throw SmokeCheckError("Surge RULE-SET 没有正确加载或匹配")
    }
    try adapters.validate(profile: resolved)
}

/// Validates a user-supplied Surge profile without printing endpoints or
/// credentials. Used during compatibility development and release checks.
func runSurgeProfileCompatibilityCheck(path: String) -> Int32 {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("hajimi-surge-check-\(UUID().uuidString)", isDirectory: true)
    let adapters = ProtocolAdapterManager(applicationSupportDirectory: root)
    let ruleSets = SurgeRuleSetManager(applicationSupportDirectory: root)
    defer {
        adapters.stop()
        try? FileManager.default.removeItem(at: root)
    }
    do {
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let profile = try ProfileParser.parse(text)
        let resolved = try ruleSets.prepare(profile: profile)
        let runtime = try adapters.prepare(profile: resolved)
        guard !profile.proxyOrder.isEmpty, !profile.groupOrder.isEmpty, !profile.rules.isEmpty else {
            throw SmokeCheckError("Surge 配置没有解析出代理、策略组或规则")
        }
        guard profile.ruleSetReferences.allSatisfy({ resolved.ruleSetContents[$0.location] != nil }) else {
            throw SmokeCheckError("部分 Surge RULE-SET 未完成解析")
        }
        guard resolved.adapterPolicies.allSatisfy({ policy in
            let expected: ProxyKind = NativeOutboundFactory.supports(policy) ? .native : .external
            return runtime.proxies[policy.name]?.kind == expected
        }) else {
            throw SmokeCheckError("部分 Surge 出站没有转换为运行时适配器")
        }
        let childRuleCount = resolved.ruleSetContents.values.reduce(0) { $0 + $1.count }
        let nativeCount = resolved.adapterPolicies.filter(NativeOutboundFactory.supports).count
        print("Surge profile compatibility check passed")
        print("Parsed \(profile.proxyOrder.count) proxies, \(profile.groupOrder.count) groups, " +
              "\(profile.rules.count) main rules and \(childRuleCount) RULE-SET entries")
        print("Prepared \(nativeCount) first-party native outbound policies")
        return 0
    } catch {
        FileHandle.standardError.write(Data("FAILED: \(error.localizedDescription)\n".utf8))
        return 1
    }
}

private func bypassRefreshSelfTest() throws {
    func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw SmokeCheckError(message) }
    }
    try expect(!EnhancedModeManager.shouldReplaceBypass(previous: ["1.1.1.1"],
                                                        next: ["1.1.1.1"]),
               "identical bypass set should not reload")
    try expect(!EnhancedModeManager.shouldReplaceBypass(previous: ["1.1.1.1", "8.8.8.8"],
                                                        next: ["1.1.1.1"]),
               "lost records must not drop working host routes")
    try expect(!EnhancedModeManager.shouldReplaceBypass(previous: ["1.1.1.1"],
                                                        next: []),
               "empty resolve must not wipe bypass routes")
    try expect(EnhancedModeManager.shouldReplaceBypass(previous: ["1.1.1.1"],
                                                       next: ["1.0.0.1"]),
               "replacement address must refresh routes")
    try expect(EnhancedModeManager.shouldReplaceBypass(previous: ["1.1.1.1"],
                                                       next: ["1.1.1.1", "1.0.0.1"]),
               "added address must refresh routes")
    try expect(EnhancedModeManager.shouldReplaceBypass(previous: [],
                                                       next: ["1.1.1.1"]),
               "first successful resolve must install routes")
    try expect(EnhancedModeManager.isCurrentBypassRefresh(
        capturedGeneration: 7, currentGeneration: 7, inFlightGeneration: 7),
        "current DNS refresh must be allowed")
    try expect(!EnhancedModeManager.isCurrentBypassRefresh(
        capturedGeneration: 7, currentGeneration: 8, inFlightGeneration: 8),
        "old DNS callback must not overwrite a new configuration")
    try expect(!EnhancedModeManager.isCurrentBypassRefresh(
        capturedGeneration: 7, currentGeneration: 8, inFlightGeneration: nil),
        "old DNS callback must not clear the next refresh state")
}

private func sessionRestoreIntentSelfTest() throws {
    func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw SmokeCheckError(message) }
    }
    let suiteName = "hajimi-session-restore-\(UUID().uuidString)"
    guard let suite = UserDefaults(suiteName: suiteName) else {
        throw SmokeCheckError("could not create isolated defaults suite")
    }
    defer { suite.removePersistentDomain(forName: suiteName) }
    suite.removePersistentDomain(forName: suiteName)

    let unset = SessionRestoreIntent.load(from: suite)
    try expect(unset.startEngine, "engine should default on when the key is missing")
    try expect(!unset.startEnhancedMode, "enhanced mode should default off")
    try expect(!unset.enableSystemProxy, "system proxy should default off")

    suite.set(false, forKey: "proxyEngineEnabled")
    suite.set(true, forKey: "enhancedModeEnabled")
    suite.set(true, forKey: "systemProxyEnabled")
    let saved = SessionRestoreIntent.load(from: suite)
    try expect(!saved.startEngine, "explicit engine-off must survive quit")
    try expect(saved.startEnhancedMode, "enhanced mode on must be restored after quit")
    try expect(saved.enableSystemProxy, "system proxy on must be restored after quit")

    suite.set(true, forKey: "proxyEngineEnabled")
    suite.set(false, forKey: "enhancedModeEnabled")
    suite.set(false, forKey: "systemProxyEnabled")
    let off = SessionRestoreIntent.load(from: suite)
    try expect(off.startEngine, "engine on must be restored after quit")
    try expect(!off.startEnhancedMode, "enhanced mode off must stay off")
    try expect(!off.enableSystemProxy, "system proxy off must stay off")
}

private func launchProfilePlanSelfTest() throws {
    let requested = SessionRestoreIntent(startEngine: true, startEnhancedMode: true,
                                         enableSystemProxy: true)
    let stopped = SessionRestoreIntent(startEngine: false, startEnhancedMode: false,
                                       enableSystemProxy: false)
    let invalid = LaunchProfilePlan(source: .success("[General]\nhttp-listen = invalid\n"))
    guard invalid.profile == nil,
          invalid.errorDescription?.contains("第 2 行") == true,
          invalid.safeRestoreIntent(requested) == stopped else {
        throw SmokeCheckError("无效配置仍允许自动启动或恢复系统代理/增强模式")
    }
    let unreadable = LaunchProfilePlan(source: .failure(URLError(.cannotOpenFile)))
    guard unreadable.profile == nil, unreadable.safeRestoreIntent(requested) == stopped else {
        throw SmokeCheckError("无法读取配置时仍允许自动启动")
    }
    let valid = LaunchProfilePlan(source: .success("""
    [Proxy]
    Upstream = http, proxy.example.com, 8080
    [Rule]
    FINAL,Upstream
    """))
    guard let profile = valid.profile, valid.safeRestoreIntent(requested) == requested,
          profile.route(for: .init(host: "example.com", port: 443, protocolName: "TCP"),
                        mode: .rule, globalPolicy: "DIRECT").policyName == "Upstream" else {
        throw SmokeCheckError("有效配置不能按用户意图恢复其上游")
    }
}

private func profileApplySafetySelfTest() throws {
    let configured = ListenAddress(host: "127.0.0.1", port: 7162)
    let relocated = ListenAddress(host: "127.0.0.1", port: 7288)
    guard SystemProxyListenerPlan.preferred(configured: configured, active: relocated,
                                            engineRunning: true,
                                            systemProxyEnabled: true) == relocated,
          SystemProxyListenerPlan.preferred(configured: configured, active: relocated,
                                            engineRunning: true,
                                            systemProxyEnabled: false) == configured,
          SystemProxyListenerPlan.needsRebind(applied: relocated, active: configured),
          !SystemProxyListenerPlan.needsRebind(applied: relocated, active: relocated),
          SystemProxyListenerPlan.protectsConfiguration(snapshotExists: false,
                                                         enableRequests: 1),
          !SystemProxyListenerPlan.protectsConfiguration(snapshotExists: false,
                                                          enableRequests: 0),
          SystemProxyListenerPlan.needsStaleSnapshotCleanup(
            snapshotExists: true,
            requested: SessionRestoreIntent(startEngine: true,
                                             startEnhancedMode: false,
                                             enableSystemProxy: false)),
          !SystemProxyListenerPlan.needsStaleSnapshotCleanup(
            snapshotExists: true,
            requested: SessionRestoreIntent(startEngine: true,
                                             startEnhancedMode: false,
                                             enableSystemProxy: true)) else {
        throw SmokeCheckError("代理监听端口迁移后未保留或更新系统代理目标")
    }
    let prepared = ProfileApplyCommitGuard(generation: 3, revision: 7,
                                            editorText: "[Rule]\nFINAL,DIRECT\n")
    guard prepared.isCurrent(generation: 3, revision: 7,
                              editorText: "[Rule]\nFINAL,DIRECT\n"),
          !prepared.isCurrent(generation: 3, revision: 7,
                               editorText: "[Rule]\nFINAL,REJECT\n"),
          !prepared.isCurrent(generation: 4, revision: 7,
                               editorText: "[Rule]\nFINAL,DIRECT\n"),
          !prepared.isCurrent(generation: 3, revision: 8,
                               editorText: "[Rule]\nFINAL,DIRECT\n"),
          ProfileApplyCommitGuard.diskTextMatches(expected: "saved", actual: "saved"),
          !ProfileApplyCommitGuard.diskTextMatches(expected: "saved",
                                                    actual: "external edit") else {
        throw SmokeCheckError("后台规则集结果会覆盖更新后的编辑器或配置")
    }
}

private func subscriptionRefreshMergeSelfTest() throws {
    let original = """
    [Proxy]
    #!hajimi-subscription-begin Provider
    Old = http, old.example.com, 8080
    #!hajimi-subscription-end Provider
    [Rule]
    FINAL,DIRECT
    """
    let contents = SubscriptionContents(format: .surge,
                                        proxyLines: ["New = http, new.example.com, 8080"],
                                        proxyNames: ["New"])
    var editor = original
    // Simulate the user editing the profile after a slow download started.
    editor = editor.replacingOccurrences(of: "FINAL,DIRECT",
                                         with: "# keep my change\nDOMAIN,manual.example,DIRECT\nFINAL,DIRECT")
    let merged = SubscriptionRefreshMerge.apply(
        [(name: "Provider", contents: contents)], toCurrentText: { editor })
    guard merged.contains("# keep my change"),
          merged.contains("DOMAIN,manual.example,DIRECT"),
          merged.contains("New = http, new.example.com, 8080"),
          !merged.contains("Old = http, old.example.com, 8080"),
          try ProfileParser.parse(merged).proxies["New"] != nil else {
        throw SmokeCheckError("订阅刷新丢失下载期间的手写规则或没有替换旧节点")
    }
}

private func subscriptionManagerCommitSelfTest(root: URL) throws {
    let directory = root.appendingPathComponent("subscription-commit", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let feed = directory.appendingPathComponent("feed.conf")
    try "[Proxy]\nFresh = http, proxy.example.com, 8080\n"
        .write(to: feed, atomically: true, encoding: .utf8)
    let manager = SubscriptionManager(applicationSupportDirectory: directory)
    try manager.add(name: "Provider", url: feed.absoluteString, updateInterval: 3600)
    let prepared = try manager.prepareUpdate(name: "Provider")
    guard prepared.contents.proxyNames == ["Fresh"],
          manager.all.first?.lastUpdated == nil else {
        throw SmokeCheckError("未提交订阅下载已被提前标记成功")
    }
    let merged = SubscriptionRefreshMerge.apply(
        [(name: prepared.name, contents: prepared.contents)],
        toCurrentText: { "[Rule]\nFINAL,DIRECT\n" })
    guard try ProfileParser.parse(merged).proxies["Fresh"] != nil else {
        throw SmokeCheckError("订阅合并后无法解析新节点")
    }
    manager.recordApplied(prepared)
    guard manager.all.first?.lastUpdated != nil,
          manager.all.first?.lastProxyCount == 1 else {
        throw SmokeCheckError("已提交订阅未更新最后成功时间")
    }
}

private struct SmokeCheckError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private func availableTCPAndUDPPort() throws -> UInt16 {
    // Stay below Darwin's ephemeral client-port range so readiness probes do
    // not leave a selected listener port in TIME_WAIT.
    for _ in 0..<100 {
        let port = UInt16.random(in: 20_000...45_000)
        let tcp = socket(AF_INET, SOCK_STREAM, 0)
        guard tcp >= 0 else { break }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(tcp, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        guard bound else { Darwin.close(tcp); continue }
        Darwin.close(tcp)

        let udp = socket(AF_INET, SOCK_DGRAM, 0)
        guard udp >= 0 else { continue }
        address.sin_port = port.bigEndian
        let udpBound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(udp, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        Darwin.close(udp)
        if udpBound { return port }
    }
    throw SmokeCheckError("无法分配端到端测试端口")
}

private func physicalDefaultInterface() throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/sbin/route")
    process.arguments = ["-n", "get", "default"]
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let output = String(data: data, encoding: .utf8) ?? ""
    for line in output.components(separatedBy: .newlines) {
        let fields = line.trimmingCharacters(in: .whitespaces)
            .split(separator: ":", maxSplits: 1)
        if fields.count == 2, fields[0] == "interface" {
            let name = fields[1].trimmingCharacters(in: .whitespaces)
            if !name.hasPrefix("utun") { return name }
        }
    }
    throw SmokeCheckError("无法获得端到端测试使用的物理接口")
}

private func launchHTTPServer(directory: URL, port: UInt16) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    process.arguments = ["-m", "http.server", String(port), "--bind", "127.0.0.1",
                         "--directory", directory.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    return process
}

private func launchUDPEchoServer(port: UInt16) throws -> Process {
    let script = """
    import socket, sys
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", int(sys.argv[1])))
    while True:
        data, address = sock.recvfrom(65535)
        sock.sendto(data, address)
    """
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    process.arguments = ["-u", "-c", script, String(port)]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    return process
}

#if false
private func launchShadowsocksServer(home: URL, port: UInt16,
                                     vmessPort: UInt16, vlessPort: UInt16,
                                     trojanPort: UInt16) throws -> Process {
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    let certificate = home.appendingPathComponent("vmess-test.crt")
    let privateKey = home.appendingPathComponent("vmess-test.key")
    let openssl = Process()
    openssl.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    openssl.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                         "-subj", "/CN=localhost", "-keyout", privateKey.path,
                         "-out", certificate.path]
    openssl.standardOutput = FileHandle.nullDevice
    openssl.standardError = FileHandle.nullDevice
    try openssl.run(); openssl.waitUntilExit()
    guard openssl.terminationStatus == 0 else {
        throw SmokeCheckError("无法生成 VMess TLS 测试证书")
    }
    let config = """
    log-level: warning
    ipv6: true
    mode: rule
    listeners:
      - name: "hajimi-ss-test"
        type: shadowsocks
        listen: "127.0.0.1"
        port: \(port)
        cipher: "aes-128-gcm"
        password: "test"
        udp: true
      - name: "hajimi-vmess-test"
        type: vmess
        listen: "127.0.0.1"
        port: \(vmessPort)
        users:
          - username: "hajimi"
            uuid: "00000000-0000-0000-0000-000000000001"
            alterId: 0
        ws-path: "/socket"
        certificate: \(yamlSmokeQuote(certificate.path))
        private-key: \(yamlSmokeQuote(privateKey.path))
      - name: "hajimi-vless-test"
        type: vless
        listen: "127.0.0.1"
        port: \(vlessPort)
        users:
          - username: "hajimi"
            uuid: "00000000-0000-0000-0000-000000000001"
        decryption: "none"
        certificate: \(yamlSmokeQuote(certificate.path))
        private-key: \(yamlSmokeQuote(privateKey.path))
      - name: "hajimi-trojan-test"
        type: trojan
        listen: "127.0.0.1"
        port: \(trojanPort)
        users:
          - username: "hajimi"
            password: "test"
        ws-path: "/trojan"
        certificate: \(yamlSmokeQuote(certificate.path))
        private-key: \(yamlSmokeQuote(privateKey.path))
    rules:
      - MATCH,DIRECT
    """
    let configURL = home.appendingPathComponent("config.yaml")
    try config.write(to: configURL, atomically: true, encoding: .utf8)
    let developmentBinary = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent("Vendor/mihomo/mihomo")
    let binary = Bundle.main.url(forResource: "mihomo", withExtension: nil) ?? developmentBinary
    guard FileManager.default.isExecutableFile(atPath: binary.path) else {
        throw SmokeCheckError("找不到 Mihomo 测试二进制")
    }
    let process = Process()
    process.executableURL = binary
    process.arguments = ["-d", home.path, "-f", configURL.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    return process
}

private func yamlSmokeQuote(_ value: String) -> String {
    "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"") + "\""
}

private func waitForTCPPort(_ port: UInt16, timeout: TimeInterval) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        if descriptor >= 0 {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.bigEndian
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
            let connected = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
            Darwin.close(descriptor)
            if connected { return true }
        }
        usleep(30_000)
    }
    return false
}
#endif

private func curlThroughHTTPProxy(proxyPort: UInt16, targetPort: UInt16,
                                  host: String = "127.0.0.1",
                                  path: String = "/probe.txt") throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = ["--fail", "--silent", "--show-error", "--max-time", "8",
                         "--noproxy", "",
                         "--proxy", "http://127.0.0.1:\(proxyPort)",
                         "http://\(host):\(targetPort)\(path)"]
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let output = String(data: data, encoding: .utf8) ?? ""
    guard process.terminationStatus == 0 else {
        throw SmokeCheckError("Shadowsocks 端到端请求失败：\(output)")
    }
    return output.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func testSOCKSUDPRelay(socksPort: UInt16, targetPort: UInt16, payload: Data) throws {
    let control = try connectedTCPDescriptor(port: socksPort)
    defer { Darwin.close(control) }
    try writeAll(Data([0x05, 0x01, 0x00]), to: control)
    guard try readExactly(2, from: control) == Data([0x05, 0x00]) else {
        throw SmokeCheckError("Hajimi SOCKS5 UDP 鉴权协商失败")
    }
    try writeAll(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), to: control)
    let association = try readExactly(10, from: control)
    guard association.prefix(4) == Data([0x05, 0x00, 0x00, 0x01]) else {
        throw SmokeCheckError("Hajimi SOCKS5 UDP ASSOCIATE 失败")
    }
    let relayPort = UInt16(association[8]) << 8 | UInt16(association[9])

    let udp = socket(AF_INET, SOCK_DGRAM, 0)
    guard udp >= 0 else { throw SmokeCheckError("无法创建 UDP 测试 Socket") }
    defer { Darwin.close(udp) }
    var timeout = timeval(tv_sec: 8, tv_usec: 0)
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var local = sockaddr_in()
    local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    local.sin_family = sa_family_t(AF_INET)
    local.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    guard withUnsafePointer(to: &local, { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(udp, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
        }
    }) else { throw SmokeCheckError("无法绑定 UDP 测试 Socket") }

    var packet = Data([0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1,
                       UInt8(targetPort >> 8), UInt8(targetPort & 0xff)])
    packet.append(payload)
    var relay = sockaddr_in()
    relay.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    relay.sin_family = sa_family_t(AF_INET)
    relay.sin_port = relayPort.bigEndian
    relay.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let sent = packet.withUnsafeBytes { bytes in
        withUnsafePointer(to: &relay) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.sendto(udp, bytes.baseAddress, bytes.count, 0, $0,
                              socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }
    guard sent == packet.count else { throw SmokeCheckError("发送 SOCKS5 UDP 测试包失败") }

    var buffer = [UInt8](repeating: 0, count: 65_535)
    let received = Darwin.recv(udp, &buffer, buffer.count, 0)
    guard received >= 10 else {
        throw SmokeCheckError("Shadowsocks UDP Relay 未收到响应（errno \(errno)）")
    }
    let response = Data(buffer.prefix(received))
    guard response.prefix(4) == Data([0x00, 0x00, 0x00, 0x01]),
          response.dropFirst(10) == payload else {
        throw SmokeCheckError("Shadowsocks UDP Relay 响应不匹配")
    }
}

private func connectedTCPDescriptor(port: UInt16) throws -> Int32 {
    let descriptor = socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw SmokeCheckError("无法创建 TCP 测试 Socket") }
    var timeout = timeval(tv_sec: 8, tv_usec: 0)
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               socklen_t(MemoryLayout<timeval>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
        }
    }
    guard connected else {
        Darwin.close(descriptor)
        throw SmokeCheckError("连接 Hajimi SOCKS5 测试端口失败")
    }
    return descriptor
}

private func writeAll(_ data: Data, to descriptor: Int32) throws {
    var offset = 0
    while offset < data.count {
        let written = data.withUnsafeBytes { bytes in
            Darwin.send(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset, 0)
        }
        guard written > 0 else { throw SmokeCheckError("写入 SOCKS5 控制连接失败") }
        offset += written
    }
}

private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: count)
    while result.count < count {
        let received = Darwin.recv(descriptor, &buffer, count - result.count, 0)
        guard received > 0 else { throw SmokeCheckError("读取 SOCKS5 控制响应失败") }
        result.append(contentsOf: buffer.prefix(received))
    }
    return result
}

private func stopProcess(_ process: Process?) {
    guard let process, process.isRunning else { return }
    process.terminate()
    let deadline = Date().addingTimeInterval(1)
    while process.isRunning && Date() < deadline { usleep(20_000) }
    if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
}

/// A minimal DNS A query, used to prove a proxied UDP path end to end.
private func dnsQuery(name: String, transaction: UInt16) -> Data {
    var out = Data()
    out.append(UInt8(truncatingIfNeeded: transaction >> 8))
    out.append(UInt8(truncatingIfNeeded: transaction))
    out.append(contentsOf: [0x01, 0x00])                    // recursion desired
    out.append(contentsOf: [0x00, 0x01])                    // one question
    out.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split(separator: ".") {
        out.append(UInt8(label.utf8.count))
        out.append(contentsOf: Array(label.utf8))
    }
    out.append(0)
    out.append(contentsOf: [0x00, 0x01])                    // type A
    out.append(contentsOf: [0x00, 0x01])                    // class IN
    return out
}
