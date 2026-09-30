import Foundation

/// Optional hook implemented by a TLS transport that can safely hand its raw
/// carrier to XTLS Vision after both peers have sent CommandPaddingDirect.
/// Network.framework intentionally does not implement this: it exposes neither
/// unread ciphertext nor the underlying connected socket.
protocol VisionDirectByteTransport: ByteTransport {
    func enableVisionDirectWrite()
    func enableVisionDirectRead()
}

enum VLESSVisionCommand: UInt8 {
    case continuePadding = 0
    case endPadding = 1
    case direct = 2
}

/// Shared observation state for the two directions of one Vision stream.
/// The client hello travels uplink; the server hello travels downlink. Only
/// after the latter proves TLS 1.3 may the uplink writer request direct-copy.
final class VLESSVisionTrafficState {
    private let lock = NSLock()
    private var packetBudget = 8
    private var serverHelloBuffer = Data()
    private(set) var isTLS = false
    private(set) var isTLS12OrAbove = false
    private(set) var enablesDirectCopy = false

    func observeUplink(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard packetBudget > 0 else { return }
        packetBudget -= 1
        let start = data.startIndex
        if data.count >= 6, data[start] == 0x16, data[start + 1] == 0x03,
           data[start + 5] == 0x01 {
            isTLS = true
        }
    }

    func observeDownlink(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard packetBudget > 0, !enablesDirectCopy else { return }
        packetBudget -= 1
        if serverHelloBuffer.count < 65_540 {
            serverHelloBuffer.append(data.prefix(65_540 - serverHelloBuffer.count))
        }
        parseServerHelloIfComplete()
    }

    func snapshot() -> (isTLS: Bool, isTLS12OrAbove: Bool,
                        fallbackBoundary: Bool, direct: Bool) {
        lock.lock(); defer { lock.unlock() }
        return (isTLS, isTLS12OrAbove, packetBudget <= 1, enablesDirectCopy)
    }

    private func parseServerHelloIfComplete() {
        guard serverHelloBuffer.count >= 6,
              serverHelloBuffer[0] == 0x16,
              serverHelloBuffer[1] == 0x03,
              serverHelloBuffer[2] == 0x03,
              serverHelloBuffer[5] == 0x02 else { return }
        isTLS = true; isTLS12OrAbove = true
        let recordLength = Int(serverHelloBuffer[3]) << 8 | Int(serverHelloBuffer[4])
        guard recordLength >= 74, recordLength <= 65_535,
              serverHelloBuffer.count >= 5 + recordLength else { return }
        let end = 5 + recordLength
        guard serverHelloBuffer.count > 44 else { return }
        let sessionLength = Int(serverHelloBuffer[43])
        let suiteOffset = 44 + sessionLength
        guard suiteOffset + 1 < end else { return }
        let suite = UInt16(serverHelloBuffer[suiteOffset]) << 8
            | UInt16(serverHelloBuffer[suiteOffset + 1])
        let tls13Marker = Data([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
        if serverHelloBuffer[..<end].range(of: tls13Marker) != nil {
            // Xray enables penetration only for suites it explicitly knows,
            // excluding TLS_AES_128_CCM_8_SHA256 (0x1305).
            enablesDirectCopy = [0x1301, 0x1302, 0x1303, 0x1304].contains(suite)
            packetBudget = 0
        } else {
            packetBudget = 0
        }
    }
}

/// Stateful encoder for the client-to-server Vision body.
final class VLESSVisionEncoder {
    struct Encoded {
        let bytes: Data
        let switchesToDirectAfterWrite: Bool
    }

    private let uuid: Data
    private let traffic: VLESSVisionTrafficState
    private let canDirect: Bool
    private var includeUUID = true
    private var padding = true
    private var direct = false

    init(uuid: Data, traffic: VLESSVisionTrafficState, canDirect: Bool) {
        self.uuid = uuid; self.traffic = traffic; self.canDirect = canDirect
    }

    var isDirect: Bool { direct }

    /// Xray inserts one empty long-padding frame when no first payload is
    /// available within 500 ms. Hajimi sends its header separately, so doing the
    /// same unconditionally prevents the bare VLESS header length signature.
    func initialPaddingFrame() -> Data {
        encodeFrame(Data(), command: .continuePadding, longPadding: true)
    }

    func encode(_ data: Data) -> Encoded {
        guard !direct else { return Encoded(bytes: data, switchesToDirectAfterWrite: false) }
        traffic.observeUplink(data)
        guard padding else { return Encoded(bytes: data, switchesToDirectAfterWrite: false) }
        let state = traffic.snapshot()
        let completeApplicationRecords = Self.isCompleteTLSApplicationRecords(data)
        let tlsBoundary = state.isTLS && completeApplicationRecords
        let shouldDirect = canDirect && state.direct && tlsBoundary
        let shouldEnd = tlsBoundary || (!state.isTLS12OrAbove && state.fallbackBoundary)
        let finalCommand: VLESSVisionCommand = shouldDirect ? .direct
            : (shouldEnd ? .endPadding : .continuePadding)
        var framed = Data()
        let maximumContent = 8_192 - 21
        if data.isEmpty {
            framed.append(encodeFrame(data, command: finalCommand, longPadding: state.isTLS))
        } else {
            var offset = 0
            let start = data.startIndex
            while offset < data.count {
                let end = min(data.count, offset + maximumContent)
                let command: VLESSVisionCommand = end == data.count
                    ? finalCommand : .continuePadding
                framed.append(encodeFrame(Data(data[(start + offset)..<(start + end)]), command: command,
                                          longPadding: state.isTLS))
                offset = end
            }
        }
        if shouldEnd { padding = false }
        if shouldDirect { direct = true }
        return Encoded(bytes: framed, switchesToDirectAfterWrite: shouldDirect)
    }

    private func encodeFrame(_ content: Data, command: VLESSVisionCommand,
                             longPadding: Bool) -> Data {
        let maximum = max(0, 8_192 - 21 - content.count)
        let paddingLength: Int
        if content.count < 900, longPadding {
            paddingLength = min(maximum, Int.random(in: 0..<500) + 900 - content.count)
        } else {
            paddingLength = min(maximum, Int.random(in: 0..<256))
        }
        var output = Data()
        if includeUUID { output.append(uuid); includeUUID = false }
        output.append(command.rawValue)
        output.append(UInt8(truncatingIfNeeded: content.count >> 8))
        output.append(UInt8(truncatingIfNeeded: content.count))
        output.append(UInt8(truncatingIfNeeded: paddingLength >> 8))
        output.append(UInt8(truncatingIfNeeded: paddingLength))
        output.append(content)
        if paddingLength > 0 { output.append(Data(repeating: 0, count: paddingLength)) }
        return output
    }

    static func isCompleteTLSApplicationRecords(_ data: Data) -> Bool {
        guard !data.isEmpty else { return false }
        let start = data.startIndex
        var offset = 0
        while offset < data.count {
            guard offset + 5 <= data.count,
                  data[start + offset] == 0x17, data[start + offset + 1] == 0x03,
                  data[start + offset + 2] == 0x03 else { return false }
            let length = Int(data[start + offset + 3]) << 8 | Int(data[start + offset + 4])
            guard length > 0, offset + 5 + length <= data.count else { return false }
            offset += 5 + length
        }
        return offset == data.count
    }
}

/// Incremental server-to-client Vision unpadder. A frame header or body may be
/// split at any byte; no assumption is made about Network.framework chunks.
final class VLESSVisionDecoder {
    struct Decoded {
        let chunks: [Data]
        let switchesToDirect: Bool
    }

    private let uuid: Data
    private let traffic: VLESSVisionTrafficState
    private var buffer = Data()
    private var expectsUUID = true
    private var framed = true
    private var direct = false

    init(uuid: Data, traffic: VLESSVisionTrafficState) {
        self.uuid = uuid; self.traffic = traffic
    }

    var isDirect: Bool { direct }

    func feed(_ data: Data) throws -> Decoded {
        guard framed else {
            traffic.observeDownlink(data)
            return Decoded(chunks: data.isEmpty ? [] : [data], switchesToDirect: false)
        }
        buffer.append(data)
        var output: [Data] = []
        var switched = false
        if expectsUUID {
            guard buffer.count >= 16 else { return Decoded(chunks: [], switchesToDirect: false) }
            guard Data(buffer.prefix(16)) == uuid else {
                throw NativeOutboundError.protocolError("VLESS Vision 响应缺少匹配的 UUID 帧前缀")
            }
            buffer = Data(buffer.dropFirst(16)); expectsUUID = false
        }
        while framed, buffer.count >= 5 {
            let start = buffer.startIndex
            guard let command = VLESSVisionCommand(rawValue: buffer[start]) else {
                throw NativeOutboundError.protocolError("VLESS Vision 未知 padding command \(buffer[start])")
            }
            let contentLength = Int(buffer[start + 1]) << 8 | Int(buffer[start + 2])
            let paddingLength = Int(buffer[start + 3]) << 8 | Int(buffer[start + 4])
            guard contentLength <= 8_192 - 21,
                  paddingLength <= 8_192 - 21,
                  contentLength + paddingLength <= 8_192 - 21 else {
                throw NativeOutboundError.protocolError("VLESS Vision 帧长度超出 8 KiB 上限")
            }
            let total = 5 + contentLength + paddingLength
            guard buffer.count >= total else { break }
            if contentLength > 0 {
                let content = Data(buffer[(start + 5)..<(start + 5 + contentLength)])
                traffic.observeDownlink(content); output.append(content)
            }
            buffer = Data(buffer.dropFirst(total))
            switch command {
            case .continuePadding: break
            case .endPadding:
                framed = false
                if !buffer.isEmpty { let tail = buffer; buffer.removeAll(); traffic.observeDownlink(tail); output.append(tail) }
            case .direct:
                framed = false; direct = true; switched = true
                if !buffer.isEmpty { let tail = buffer; buffer.removeAll(); traffic.observeDownlink(tail); output.append(tail) }
            }
        }
        return Decoded(chunks: output, switchesToDirect: switched)
    }
}

/// Minimal protobuf encoding of `encoding.Addons{Flow: "xtls-rprx-vision"}`.
/// Field 1 is a length-delimited string, so no protobuf dependency is needed.
enum VLESSVisionAddons {
    static let flow = "xtls-rprx-vision"
    static let udp443Flow = "xtls-rprx-vision-udp443"

    static func recognizes(_ value: String) -> Bool {
        let normalized = value.lowercased()
        return normalized == flow || normalized == udp443Flow
    }

    static var requestBytes: Data {
        let value = Data(flow.utf8)
        var encoded = Data([0x0a, UInt8(value.count)]); encoded.append(value)
        return encoded
    }
}

public enum VLESSVisionSelfTest {
    public static func run() throws {
        guard VLESSVisionAddons.requestBytes == Data([0x0a, 0x10]) + Data(VLESSVisionAddons.flow.utf8) else {
            throw NativeOutboundError.protocolError("Vision addons protobuf 编码错误")
        }
        let uuid = Data((0..<16).map(UInt8.init))
        let traffic = VLESSVisionTrafficState()
        let encoder = VLESSVisionEncoder(uuid: uuid, traffic: traffic, canDirect: false)
        let first = encoder.initialPaddingFrame()
        let payload = Data([0x16, 0x03, 0x01, 0, 1, 0x01])
        let second = encoder.encode(payload).bytes
        let decoder = VLESSVisionDecoder(uuid: uuid, traffic: VLESSVisionTrafficState())
        var decoded: [Data] = []
        for byte in first + second {
            decoded.append(contentsOf: try decoder.feed(Data([byte])).chunks)
        }
        guard decoded.reduce(Data(), +) == payload else {
            throw NativeOutboundError.protocolError("Vision 分片 padding/unpadding 自测失败")
        }
        let complete = Data([0x17, 0x03, 0x03, 0, 2, 0xaa, 0xbb,
                             0x17, 0x03, 0x03, 0, 1, 0xcc])
        guard VLESSVisionEncoder.isCompleteTLSApplicationRecords(complete),
              !VLESSVisionEncoder.isCompleteTLSApplicationRecords(complete.dropLast()) else {
            throw NativeOutboundError.protocolError("Vision TLS record 完整性自测失败")
        }

        // A fragmented TLS 1.3 ServerHello enables command=2 only after the
        // complete record and supported_versions marker have arrived.
        let directTraffic = VLESSVisionTrafficState()
        directTraffic.observeUplink(Data([0x16, 0x03, 0x01, 0, 1, 0x01]))
        var serverHello = Data(repeating: 0, count: 80)
        serverHello.replaceSubrange(0..<6, with: [0x16, 0x03, 0x03, 0, 75, 0x02])
        serverHello[43] = 0
        serverHello[44] = 0x13; serverHello[45] = 0x01
        serverHello.replaceSubrange(60..<66, with: [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
        directTraffic.observeDownlink(Data(serverHello.prefix(37)))
        guard !directTraffic.snapshot().direct else {
            throw NativeOutboundError.protocolError("Vision 在不完整 ServerHello 上过早开启 direct")
        }
        directTraffic.observeDownlink(Data(serverHello.dropFirst(37)))
        guard directTraffic.snapshot().direct else {
            throw NativeOutboundError.protocolError("Vision 未识别 TLS 1.3 AES-128-GCM")
        }
        for (suite, expected) in [(UInt16(0x1301), true), (0x1302, true),
                                  (0x1303, true), (0x1304, true),
                                  (0x1305, false), (0x9999, false)] {
            var fixture = serverHello
            fixture[44] = UInt8(truncatingIfNeeded: suite >> 8)
            fixture[45] = UInt8(truncatingIfNeeded: suite)
            let state = VLESSVisionTrafficState(); state.observeDownlink(fixture)
            guard state.snapshot().direct == expected else {
                throw NativeOutboundError.protocolError(
                    String(format: "Vision cipher 0x%04X direct 判定错误", suite))
            }
        }
        let directEncoder = VLESSVisionEncoder(uuid: uuid, traffic: directTraffic,
                                               canDirect: true)
        let directFrame = directEncoder.encode(complete)
        guard directFrame.switchesToDirectAfterWrite else {
            throw NativeOutboundError.protocolError("Vision TLS 1.3 未生成 command=2")
        }
        let directDecoder = VLESSVisionDecoder(uuid: uuid,
                                               traffic: VLESSVisionTrafficState())
        let directResult = try directDecoder.feed(directFrame.bytes)
        guard directResult.switchesToDirect,
              directResult.chunks.reduce(Data(), +) == complete else {
            throw NativeOutboundError.protocolError("Vision command=2 解码自测失败")
        }

        var noDirectHello = serverHello
        noDirectHello[44] = 0x13; noDirectHello[45] = 0x05
        let noDirectTraffic = VLESSVisionTrafficState()
        noDirectTraffic.observeDownlink(noDirectHello)
        let endEncoder = VLESSVisionEncoder(uuid: uuid, traffic: noDirectTraffic,
                                            canDirect: true)
        let endFrame = endEncoder.encode(complete)
        let endDecoder = VLESSVisionDecoder(uuid: uuid,
                                            traffic: VLESSVisionTrafficState())
        let endResult = try endDecoder.feed(endFrame.bytes)
        let afterEnd = try endDecoder.feed(Data([0xde, 0xad]))
        guard !endFrame.switchesToDirectAfterWrite, !endResult.switchesToDirect,
              endResult.chunks.reduce(Data(), +) == complete,
              afterEnd.chunks == [Data([0xde, 0xad])] else {
            throw NativeOutboundError.protocolError("Vision command=1 结束填充自测失败")
        }

        let parsedUUID = UUID(uuidString: "00010203-0405-0607-0809-0a0b0c0d0e0f")!
        let header = try vlessRequestHeader(
            uuid: parsedUUID,
            target: RequestTarget(host: "example.com", port: 443, protocolName: "TCP"),
            command: .tcp, flow: VLESSVisionAddons.flow)
        guard header.count > 36, header[17] == 0x12,
              Data(header[18..<36]) == VLESSVisionAddons.requestBytes else {
            throw NativeOutboundError.protocolError("VLESS Vision 请求头 addons 自测失败")
        }
        let xudpHeader = try vlessRequestHeader(
            uuid: parsedUUID, target: MuxApplicability.carrierTarget,
            command: .mux, flow: VLESSVisionAddons.flow)
        guard xudpHeader.count == 37, xudpHeader[17] == 0x12,
              Data(xudpHeader[18..<36]) == VLESSVisionAddons.requestBytes,
              xudpHeader[36] == VMessRequestCommand.mux.rawValue else {
            throw NativeOutboundError.protocolError("VLESS Vision XUDP 载体请求头自测失败")
        }
        let udpTarget = RequestTarget(host: "dns.example", port: 53,
                                      protocolName: "UDP")
        let udpPayload = Data([0x12, 0x34, 0x01, 0x00])
        let xudp = try XUDPCodec.encode(
            target: udpTarget, payload: udpPayload, first: true,
            globalID: Data([1, 2, 3, 4, 5, 6, 7, 8]))
        let xudpVisionEncoder = VLESSVisionEncoder(
            uuid: uuid, traffic: VLESSVisionTrafficState(), canDirect: false)
        let paddedXUDP = xudpVisionEncoder.initialPaddingFrame()
            + xudpVisionEncoder.encode(xudp).bytes
        let xudpVisionDecoder = VLESSVisionDecoder(
            uuid: uuid, traffic: VLESSVisionTrafficState())
        let unpadded = try xudpVisionDecoder.feed(paddedXUDP).chunks.reduce(Data(), +)
        var decodedXUDPBytes = unpadded
        let decodedXUDP = try XUDPCodec.decode(from: &decodedXUDPBytes)
        guard decodedXUDP?.target.host == udpTarget.host,
              decodedXUDP?.target.port == udpTarget.port,
              decodedXUDP?.payload == udpPayload,
              decodedXUDPBytes.isEmpty else {
            throw NativeOutboundError.protocolError("VLESS Vision XUDP 分层往返自测失败")
        }

        // Pin the read-ahead invariant used by Reality's raw handoff: after
        // consuming the outer record carrying command=2, bytes already read
        // from the socket must remain byte-exact for the direct reader.
        let outer = try TLS13.plaintextRecord(contentType: .applicationData,
                                              legacyVersion: TLS13.legacyRecordVersion,
                                              fragment: directFrame.bytes)
        let rawInner = Data([0x17, 0x03, 0x03, 0, 3, 1, 2, 3])
        var recordReader = TLS13.RecordReader()
        recordReader.append(outer + rawInner)
        guard try recordReader.next() != nil,
              recordReader.takePendingBytes() == rawInner else {
            throw NativeOutboundError.protocolError("Vision direct raw read-ahead 保留自测失败")
        }

        let publicKey = Data(repeating: 7, count: 32).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let link = "vless://00010203-0405-0607-0809-0a0b0c0d0e0f@example.com:443" +
            "?security=reality&flow=xtls-rprx-vision&sni=cover.example.com" +
            "&fp=chrome&pbk=\(publicKey)&sid=0123456789abcdef#vision"
        guard let imported = try ShareLinkSubscription.parse(link).proxies.first,
              imported.parameters["flow"] == VLESSVisionAddons.flow,
              NativeOutboundFactory.validationError(for: imported) == nil,
              NativeOutboundFactory.supportsUDP(imported),
              NativeOutboundFactory.usesVisionXUDP(imported),
              NativeOutboundFactory.carriesUDPOverReliableStream(imported) else {
            throw NativeOutboundError.protocolError("VLESS Vision 分享链接/能力校验自测失败")
        }
        let profile = try ProfileParser.parse("""
        [Proxy]
        Vision = vless, example.com, 443, 00010203-0405-0607-0809-0a0b0c0d0e0f, flow=xtls-rprx-vision, security=reality, servername=cover.example.com, reality-public-key=\(publicKey), reality-short-id=0123456789abcdef, client-fingerprint=chrome
        [Rule]
        FINAL,Vision
        """)
        guard profile.proxies["Vision"]?.parameters["security"] == "reality",
              profile.proxies["Vision"]?.parameters["flow"] == VLESSVisionAddons.flow else {
            throw NativeOutboundError.protocolError("Surge Vision security/flow 参数解析自测失败")
        }
    }
}
