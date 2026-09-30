import Foundation

// MARK: - HPACK (RFC 7541)

/// Header compression for HTTP/2.
///
/// Required by the gRPC and HTTP/2 transports: Network.framework offers HTTP/2
/// only through URLSession, which cannot carry an arbitrary bidirectional
/// stream, so the frame layer has to be written here and HPACK with it.
///
/// This is the one piece of the HTTP/2 stack with official test vectors
/// (RFC 7541 Appendix C), which is why it is built first — everything above it
/// can only be checked for self-consistency.
// Generated from RFC 7541 Appendix A.
let hpackStaticTable: [(name: String, value: String)] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]

public enum HPACK {
    public struct HeaderField: Equatable {
        public var name: String
        public var value: String
        public init(name: String, value: String) {
            self.name = name
            self.value = value
        }
    }

    public enum DecodeError: LocalizedError, Equatable {
        case truncated
        case invalidIndex(Int)
        case integerOverflow
        case invalidHuffman

        public var errorDescription: String? {
            switch self {
            case .truncated: return "HPACK 数据不完整"
            case .invalidIndex(let index): return "HPACK 索引 \(index) 越界"
            case .integerOverflow: return "HPACK 整数溢出"
            case .invalidHuffman: return "HPACK Huffman 编码无效"
            }
        }
    }


    // MARK: Integer representation (RFC 7541 §5.1)

    /// Encodes with `prefixBits` available in the first octet, whose high bits
    /// the caller has already set.
    static func encodeInteger(_ value: Int, prefixBits: Int, firstByte: UInt8) -> Data {
        let limit = (1 << prefixBits) - 1
        var out = Data()
        if value < limit {
            out.append(firstByte | UInt8(value))
            return out
        }
        out.append(firstByte | UInt8(limit))
        var remainder = value - limit
        while remainder >= 128 {
            out.append(UInt8(remainder % 128 + 128))
            remainder /= 128
        }
        out.append(UInt8(remainder))
        return out
    }

    static func decodeInteger(_ bytes: [UInt8], _ index: inout Int,
                              prefixBits: Int) throws -> Int {
        guard index < bytes.count else { throw DecodeError.truncated }
        let limit = (1 << prefixBits) - 1
        var value = Int(bytes[index] & UInt8(limit))
        index += 1
        guard value == limit else { return value }
        var shift = 0
        while true {
            guard index < bytes.count else { throw DecodeError.truncated }
            let byte = bytes[index]
            index += 1
            // A continuation run long enough to overflow is malformed input,
            // not a large header.
            guard shift <= 21 else { throw DecodeError.integerOverflow }
            value += Int(byte & 0x7F) << shift
            if byte & 0x80 == 0 { break }
            shift += 7
        }
        return value
    }

    // MARK: Dynamic table (RFC 7541 §2.3.2)

    /// Entries are evicted from the end as the table exceeds its size limit.
    /// Both peers must apply the same rule or every index after an eviction
    /// refers to a different header on each side.
    public final class DynamicTable {
        private var entries: [(name: String, value: String, size: Int)] = []
        private(set) var size = 0
        public private(set) var capacity: Int

        public init(capacity: Int = 4_096) { self.capacity = capacity }

        var count: Int { entries.count }

        func entry(at index: Int) -> (name: String, value: String)? {
            guard index >= 0, index < entries.count else { return nil }
            let item = entries[index]
            return (item.name, item.value)
        }

        func add(name: String, value: String) {
            // §4.1: the overhead of 32 accounts for the entry's bookkeeping and
            // is part of the wire contract, not an implementation detail.
            let cost = name.utf8.count + value.utf8.count + 32
            entries.insert((name, value, cost), at: 0)
            size += cost
            evict()
        }

        func setCapacity(_ newCapacity: Int) {
            capacity = newCapacity
            evict()
        }

        private func evict() {
            while size > capacity, let last = entries.last {
                size -= last.size
                entries.removeLast()
            }
        }
    }

    // MARK: Encoding

    /// Encodes without ever indexing into the dynamic table.
    ///
    /// A stateless encoder cannot desynchronise from the peer's table, and the
    /// header sets a proxy sends are short and highly repetitive anyway — the
    /// bytes saved by dynamic indexing are not worth a failure mode where a
    /// single mismatch corrupts every subsequent request on the connection.
    public static func encode(_ headers: [HeaderField], huffman: Bool = true) -> Data {
        var out = Data()
        for header in headers {
            let name = header.name.lowercased()
            if let index = staticIndex(name: name, value: header.value) {
                out.append(contentsOf: encodeInteger(index, prefixBits: 7, firstByte: 0x80))
                continue
            }
            if let index = staticIndex(name: name, value: nil) {
                // Literal without indexing, name taken from the static table.
                out.append(contentsOf: encodeInteger(index, prefixBits: 4, firstByte: 0x00))
            } else {
                out.append(0x00)
                out.append(encodeString(name, huffman: huffman))
            }
            out.append(encodeString(header.value, huffman: huffman))
        }
        return out
    }

    private static func staticIndex(name: String, value: String?) -> Int? {
        for (offset, entry) in hpackStaticTable.enumerated() {
            guard entry.name == name else { continue }
            if let value {
                if entry.value == value { return offset + 1 }
            } else {
                return offset + 1
            }
        }
        return nil
    }

    static func encodeString(_ value: String, huffman: Bool) -> Data {
        let raw = Data(value.utf8)
        if huffman {
            let encoded = Huffman.encode(raw)
            // Only worth it when it actually shrinks the field.
            if encoded.count < raw.count {
                var out = encodeInteger(encoded.count, prefixBits: 7, firstByte: 0x80)
                out.append(encoded)
                return out
            }
        }
        var out = encodeInteger(raw.count, prefixBits: 7, firstByte: 0x00)
        out.append(raw)
        return out
    }

    // MARK: Decoding

    public static func decode(_ data: Data, table: DynamicTable) throws -> [HeaderField] {
        let bytes = [UInt8](data)
        var index = 0
        var headers: [HeaderField] = []
        while index < bytes.count {
            let byte = bytes[index]
            if byte & 0x80 != 0 {
                // Indexed header field.
                let position = try decodeInteger(bytes, &index, prefixBits: 7)
                guard position > 0, let entry = lookup(position, table: table) else {
                    throw DecodeError.invalidIndex(position)
                }
                headers.append(HeaderField(name: entry.name, value: entry.value))
                continue
            }
            if byte & 0xE0 == 0x20 {
                // Dynamic table size update.
                let size = try decodeInteger(bytes, &index, prefixBits: 5)
                table.setCapacity(size)
                continue
            }
            let indexed = byte & 0x40 != 0
            let prefix = indexed ? 6 : 4
            let nameIndex = try decodeInteger(bytes, &index, prefixBits: prefix)
            let name: String
            if nameIndex == 0 {
                name = try decodeString(bytes, &index)
            } else {
                guard let entry = lookup(nameIndex, table: table) else {
                    throw DecodeError.invalidIndex(nameIndex)
                }
                name = entry.name
            }
            let value = try decodeString(bytes, &index)
            if indexed { table.add(name: name, value: value) }
            headers.append(HeaderField(name: name, value: value))
        }
        return headers
    }

    private static func lookup(_ index: Int, table: DynamicTable) -> (name: String, value: String)? {
        if index <= hpackStaticTable.count {
            let entry = hpackStaticTable[index - 1]
            return (entry.name, entry.value)
        }
        return table.entry(at: index - hpackStaticTable.count - 1)
    }

    static func decodeString(_ bytes: [UInt8], _ index: inout Int) throws -> String {
        guard index < bytes.count else { throw DecodeError.truncated }
        let huffman = bytes[index] & 0x80 != 0
        let length = try decodeInteger(bytes, &index, prefixBits: 7)
        guard index + length <= bytes.count else { throw DecodeError.truncated }
        let raw = Data(bytes[index..<(index + length)])
        index += length
        let decoded = huffman ? try Huffman.decode(raw) : raw
        guard let text = String(data: decoded, encoding: .utf8) else {
            throw DecodeError.invalidHuffman
        }
        return text
    }
}

// MARK: - Self-test

public enum HPACKSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "HPACK 自检失败：\(text)" }
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private static func bytes(_ hex: String) -> Data {
        var out = Data()
        let clean = hex.filter { !$0.isWhitespace }
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            out.append(UInt8(clean[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func run() throws {
        try integerRepresentation()
        try huffmanVectors()
        try appendixCDecoding()
        try dynamicTableEviction()
        try encodeDecodeRoundTrip()
        try rejectsMalformedInput()
    }

    /// RFC 7541 §5.1 worked examples.
    private static func integerRepresentation() throws {
        try expect(hex(HPACK.encodeInteger(10, prefixBits: 5, firstByte: 0)) == "0a",
                   "5 位前缀内的小整数编码错误")
        try expect(hex(HPACK.encodeInteger(1337, prefixBits: 5, firstByte: 0)) == "1f9a0a",
                   "跨字节整数编码错误")
        try expect(hex(HPACK.encodeInteger(42, prefixBits: 8, firstByte: 0)) == "2a",
                   "8 位前缀整数编码错误")
        for (value, prefix) in [(10, 5), (1337, 5), (42, 8), (0, 7), (127, 7), (16_383, 6)] {
            var index = 0
            let encoded = [UInt8](HPACK.encodeInteger(value, prefixBits: prefix, firstByte: 0))
            let decoded = try HPACK.decodeInteger(encoded, &index, prefixBits: prefix)
            try expect(decoded == value, "整数 \(value)/\(prefix) 往返得到 \(decoded)")
            try expect(index == encoded.count, "整数 \(value) 解码后偏移不正确")
        }
    }

    /// The Huffman-coded literals from Appendix C.4 and C.6.
    private static func huffmanVectors() throws {
        let cases: [(String, String)] = [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"),
            ("https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"),
        ]
        for (text, expected) in cases {
            let encoded = Huffman.encode(Data(text.utf8))
            try expect(hex(encoded) == expected,
                       "Huffman 编码 \"\(text)\" 得到 \(hex(encoded))，期望 \(expected)")
            let decoded = try Huffman.decode(bytes(expected))
            try expect(String(data: decoded, encoding: .utf8) == text,
                       "Huffman 解码 \"\(text)\" 失败")
        }
    }

    /// RFC 7541 Appendix C.3 and C.5: three consecutive request header sets
    /// decoded against one dynamic table, which is what proves the table is
    /// being maintained the way the peer expects rather than merely parsed.
    private static func appendixCDecoding() throws {
        let table = HPACK.DynamicTable(capacity: 4_096)
        let first = try HPACK.decode(bytes("828684410f7777772e6578616d706c652e636f6d"), table: table)
        try expect(first == [
            .init(name: ":method", value: "GET"),
            .init(name: ":scheme", value: "http"),
            .init(name: ":path", value: "/"),
            .init(name: ":authority", value: "www.example.com"),
        ], "C.3.1 首个请求解码错误：\(first)")

        let second = try HPACK.decode(bytes("828684be58086e6f2d6361636865"), table: table)
        try expect(second == [
            .init(name: ":method", value: "GET"),
            .init(name: ":scheme", value: "http"),
            .init(name: ":path", value: "/"),
            .init(name: ":authority", value: "www.example.com"),
            .init(name: "cache-control", value: "no-cache"),
        ], "C.3.2 第二个请求解码错误 —— 索引 0xbe 依赖动态表状态：\(second)")

        let third = try HPACK.decode(
            bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"), table: table)
        try expect(third.last == .init(name: "custom-key", value: "custom-value"),
                   "C.3.3 第三个请求解码错误：\(third)")

        // Huffman-coded variant of the same sequence, Appendix C.4.
        let huffTable = HPACK.DynamicTable(capacity: 4_096)
        let huff = try HPACK.decode(
            bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff"), table: huffTable)
        try expect(huff.last == .init(name: ":authority", value: "www.example.com"),
                   "C.4.1 Huffman 请求解码错误：\(huff)")
    }

    /// Eviction is a wire contract: both peers must drop the same entries or
    /// every later index means something different on each side.
    private static func dynamicTableEviction() throws {
        let table = HPACK.DynamicTable(capacity: 100)
        table.add(name: "aaaa", value: "bbbb")      // 4 + 4 + 32 = 40
        table.add(name: "cccc", value: "dddd")      // 80 total
        try expect(table.count == 2, "两条 40 字节表项应能共存")
        table.add(name: "eeee", value: "ffff")      // 120 > 100, evicts the oldest
        try expect(table.count == 2, "超出容量时未淘汰最旧表项")
        try expect(table.entry(at: 0)?.name == "eeee", "最新表项应在索引 0")
        try expect(table.entry(at: 1)?.name == "cccc", "淘汰顺序错误")
        table.setCapacity(0)
        try expect(table.count == 0, "容量归零时未清空")
    }

    private static func encodeDecodeRoundTrip() throws {
        let headers: [HPACK.HeaderField] = [
            .init(name: ":method", value: "POST"),
            .init(name: ":scheme", value: "https"),
            .init(name: ":path", value: "/GunService/Tun"),
            .init(name: ":authority", value: "example.com"),
            .init(name: "content-type", value: "application/grpc"),
            .init(name: "user-agent", value: "grpc-go/1.0"),
            .init(name: "te", value: "trailers"),
        ]
        for huffman in [true, false] {
            let encoded = HPACK.encode(headers, huffman: huffman)
            let decoded = try HPACK.decode(encoded, table: HPACK.DynamicTable())
            try expect(decoded == headers,
                       "huffman=\(huffman) 的往返结果不一致：\(decoded)")
        }
    }

    private static func rejectsMalformedInput() throws {
        let table = HPACK.DynamicTable()
        // Index 0 is reserved and must not resolve.
        do { _ = try HPACK.decode(bytes("80"), table: table)
             throw Failure(text: "索引 0 未被拒绝") } catch is HPACK.DecodeError {}
        // An index past the static and dynamic tables.
        do { _ = try HPACK.decode(bytes("ff00"), table: table)
             throw Failure(text: "越界索引未被拒绝") } catch is HPACK.DecodeError {}
        // A literal whose declared length runs past the buffer.
        do { _ = try HPACK.decode(bytes("00 0f 61 62"), table: table)
             throw Failure(text: "截断的字面量未被拒绝") } catch is HPACK.DecodeError {}
        // A continuation run long enough to overflow the accumulator.
        do { _ = try HPACK.decode(bytes("1fffffffffffffffffff"), table: table)
             throw Failure(text: "整数溢出未被拒绝") } catch is HPACK.DecodeError {}
        // Huffman padding must be the EOS prefix; zeros are invalid.
        do { _ = try Huffman.decode(bytes("00"))
             throw Failure(text: "非法 Huffman 填充未被拒绝") } catch is HPACK.DecodeError {}
    }
}
