import Compression
import CryptoKit
import Foundation
import HajimiProtocolsCXX

extension TLS13 {
    /// RFC 8879 §4 & §5: TLS Certificate Compression (`CompressedCertificate`, HandshakeType 25).
    /// Supports standard `zlib (1)` (RFC 1950 wrapper + Adler-32 check) and `brotli (2)` (RFC 7932)
    /// via Apple's system `Compression` framework, enforcing strict `uncompressed_length` bounds
    /// (`1 .. maximumHandshakeMessageLength`) to prevent decompression-bomb attacks.
    struct CompressedCertificate {
        enum Algorithm: UInt16 {
            case zlib = 0x0001
            case brotli = 0x0002
        }

        let algorithm: UInt16
        let uncompressedLength: Int
        let compressedData: Data
        let decompressedCertificateBody: Data

        init(_ body: Data) throws {
            var reader = ByteReader(body, describing: "CompressedCertificate")
            algorithm = try reader.uint16()
            uncompressedLength = try reader.uint24()
            guard uncompressedLength >= 4, uncompressedLength <= TLS13.maximumHandshakeMessageLength else {
                throw NativeOutboundError.protocolError(
                    "RFC 8879 CompressedCertificate uncompressed_length (\(uncompressedLength)) 超出安全边界")
            }
            compressedData = try reader.vector24()
            guard reader.isEmpty, !compressedData.isEmpty else {
                throw NativeOutboundError.protocolError("RFC 8879 CompressedCertificate 载荷为空或含多余尾部字节")
            }
            decompressedCertificateBody = try Self.decompress(
                compressedData,
                algorithm: algorithm,
                expectedLength: uncompressedLength
            )
        }

        static func decompress(_ input: Data, algorithm: UInt16, expectedLength: Int) throws -> Data {
            guard expectedLength > 0, expectedLength <= TLS13.maximumHandshakeMessageLength else {
                throw NativeOutboundError.protocolError("RFC 8879 证书解压目标长度非法")
            }
            switch algorithm {
            case Algorithm.brotli.rawValue:
                return try decodeRawStream(input, algorithm: COMPRESSION_BROTLI, expectedLength: expectedLength)
            case Algorithm.zlib.rawValue:
                // Apple COMPRESSION_ZLIB decodes raw RFC 1951 DEFLATE; strip and verify RFC 1950 header + Adler-32.
                guard input.count >= 6 else {
                    throw NativeOutboundError.protocolError("RFC 8879 zlib 压缩证书不足 6 字节")
                }
                let bytes = [UInt8](input)
                let cmf = bytes[0], flg = bytes[1]
                guard (cmf & 0x0F) == 8, (cmf >> 4) <= 7,
                      ((UInt16(cmf) << 8 | UInt16(flg)) % 31) == 0,
                      (flg & 0x20) == 0 else {
                    throw NativeOutboundError.protocolError("RFC 8879 zlib (RFC 1950) 头部无效或要求预设字典")
                }
                let rawDeflate = Data(bytes[2..<(bytes.count - 4)])
                let out = try decodeRawStream(rawDeflate, algorithm: COMPRESSION_ZLIB, expectedLength: expectedLength)
                let expectedAdler = UInt32(bytes[bytes.count - 4]) << 24
                    | UInt32(bytes[bytes.count - 3]) << 16
                    | UInt32(bytes[bytes.count - 2]) << 8
                    | UInt32(bytes[bytes.count - 1])
                guard adler32(out) == expectedAdler else {
                    throw NativeOutboundError.protocolError("RFC 8879 zlib Adler-32 完整性校验失败")
                }
                return out
            default:
                throw NativeOutboundError.protocolError(
                    String(format: "RFC 8879 收到未声明或不支持的证书压缩算法 0x%04X", algorithm))
            }
        }

        static func encodeBody(certificateBody: Data, algorithm: Algorithm = .brotli) throws -> Data {
            guard !certificateBody.isEmpty, certificateBody.count <= TLS13.maximumHandshakeMessageLength else {
                throw NativeOutboundError.protocolError("待压缩 Certificate 消息体长度越界")
            }
            let compressedPayload: Data
            switch algorithm {
            case .brotli:
                compressedPayload = try encodeRawStream(certificateBody, algorithm: COMPRESSION_BROTLI)
            case .zlib:
                let rawDeflate = try encodeRawStream(certificateBody, algorithm: COMPRESSION_ZLIB)
                var wrapped = Data([0x78, 0x9C]) // CMF=Deflate/32K, FLG=default (0x789C % 31 == 0)
                wrapped.append(rawDeflate)
                let checksum = adler32(certificateBody)
                wrapped.append(UInt8(truncatingIfNeeded: checksum >> 24))
                wrapped.append(UInt8(truncatingIfNeeded: checksum >> 16))
                wrapped.append(UInt8(truncatingIfNeeded: checksum >> 8))
                wrapped.append(UInt8(truncatingIfNeeded: checksum))
                compressedPayload = wrapped
            }
            var out = Data(capacity: 8 + compressedPayload.count)
            out.append(UInt8(truncatingIfNeeded: algorithm.rawValue >> 8))
            out.append(UInt8(truncatingIfNeeded: algorithm.rawValue))
            let ulen = certificateBody.count
            out.append(UInt8(truncatingIfNeeded: ulen >> 16))
            out.append(UInt8(truncatingIfNeeded: ulen >> 8))
            out.append(UInt8(truncatingIfNeeded: ulen))
            let clen = compressedPayload.count
            out.append(UInt8(truncatingIfNeeded: clen >> 16))
            out.append(UInt8(truncatingIfNeeded: clen >> 8))
            out.append(UInt8(truncatingIfNeeded: clen))
            out.append(compressedPayload)
            return out
        }

        private static func decodeRawStream(_ input: Data,
                                            algorithm: compression_algorithm,
                                            expectedLength: Int) throws -> Data {
            // Allocate expectedLength + 1 so any stream that expands past expectedLength
            // produces decoded == expectedLength + 1 and is rejected per RFC 8879 §5.
            let probeCap = expectedLength + 1
            var dst = [UInt8](repeating: 0, count: probeCap)
            let decoded = input.withUnsafeBytes { srcBuf -> Int in
                guard let srcBase = srcBuf.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(&dst, probeCap, srcBase, input.count, nil, algorithm)
            }
            guard decoded == expectedLength else {
                throw NativeOutboundError.protocolError(
                    "RFC 8879 证书解压长度 (\(decoded)) 与声明值 (\(expectedLength)) 不符")
            }
            return Data(dst.prefix(expectedLength))
        }

        private static func encodeRawStream(_ input: Data, algorithm: compression_algorithm) throws -> Data {
            let cap = max(256, input.count + (input.count / 8) + 64)
            var dst = [UInt8](repeating: 0, count: cap)
            let written = input.withUnsafeBytes { srcBuf -> Int in
                guard let srcBase = srcBuf.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_encode_buffer(&dst, cap, srcBase, input.count, nil, algorithm)
            }
            guard written > 0 else {
                throw NativeOutboundError.protocolError("RFC 8879 证书压缩编码失败")
            }
            return Data(dst.prefix(written))
        }

        private static func adler32(_ data: Data) -> UInt32 {
            var s1: UInt32 = 1
            var s2: UInt32 = 0
            let mod: UInt32 = 65_521
            data.withUnsafeBytes { raw in
                let bytes = raw.bindMemory(to: UInt8.self)
                var i = 0
                while i < bytes.count {
                    let end = min(bytes.count, i + 5_552)
                    while i < end {
                        s1 &+= UInt32(bytes[i])
                        s2 &+= s1
                        i += 1
                    }
                    s1 %= mod
                    s2 %= mod
                }
            }
            return (s2 << 16) | s1
        }
    }

    /// Just enough ASN.1 to walk a certificate. This is not a validator: it does
    /// not check dates, names, key usage, chains or signatures. REALITY replaces
    /// the signature of a self-signed throwaway certificate with an HMAC, so a
    /// real X.509 verifier would reject every honest connection; the trust
    /// decision belongs to the REALITY layer above.
    enum DER {
        struct Element {
            let tag: UInt8
            /// Offset of the tag byte.
            let start: Int
            let contentStart: Int
            let contentEnd: Int

            var end: Int { contentEnd }
        }

        static let sequence: UInt8 = 0x30
        static let objectIdentifier: UInt8 = 0x06
        static let bitString: UInt8 = 0x03
        static let contextConstructed0: UInt8 = 0xA0

        static func element(_ bytes: [UInt8], at offset: Int) throws -> Element {
            guard offset + 1 < bytes.count else {
                throw NativeOutboundError.protocolError("DER 解析越界：偏移 \(offset) 处没有完整的标签与长度")
            }
            let tag = bytes[offset]
            guard tag & 0x1F != 0x1F else {
                throw NativeOutboundError.protocolError("DER 解析不支持多字节标签")
            }
            let first = bytes[offset + 1]
            var contentStart = offset + 2
            var length = Int(first)
            if first & 0x80 != 0 {
                let count = Int(first & 0x7F)
                guard count >= 1, count <= 4 else {
                    throw NativeOutboundError.protocolError("DER 长度字节数 \(count) 不受支持（不定长或超过 4 字节）")
                }
                guard contentStart + count <= bytes.count else {
                    throw NativeOutboundError.protocolError("DER 长度字段越界")
                }
                length = 0
                for index in 0..<count { length = length << 8 | Int(bytes[contentStart + index]) }
                contentStart += count
            }
            guard length >= 0, contentStart + length <= bytes.count else {
                throw NativeOutboundError.protocolError("DER 元素长度 \(length) 超出缓冲区")
            }
            return Element(tag: tag, start: offset, contentStart: contentStart,
                           contentEnd: contentStart + length)
        }

        /// A hard cap keeps a malformed certificate from turning into an
        /// unbounded loop; no real certificate has anywhere near this many
        /// direct children.
        static let maximumChildren = 64

        static func children(_ bytes: [UInt8], of parent: Element) throws -> [Element] {
            var result: [Element] = []
            var cursor = parent.contentStart
            while cursor < parent.contentEnd {
                guard result.count < maximumChildren else {
                    throw NativeOutboundError.protocolError("DER 子元素数量超过 \(maximumChildren)")
                }
                let child = try element(bytes, at: cursor)
                guard child.contentEnd <= parent.contentEnd else {
                    throw NativeOutboundError.protocolError("DER 子元素越出父元素范围")
                }
                result.append(child)
                cursor = child.contentEnd
            }
            return result
        }

        /// BIT STRING content starts with an "unused bits" octet, which is
        /// always zero for keys and signatures and is not part of the value.
        static func bitStringBytes(_ bytes: [UInt8], of element: Element) throws -> Data {
            guard element.tag == bitString, element.contentEnd > element.contentStart,
                  bytes[element.contentStart] == 0 else {
                throw NativeOutboundError.protocolError("DER BIT STRING 格式异常（非零的 unused bits）")
            }
            return Data(bytes[(element.contentStart + 1)..<element.contentEnd])
        }
    }

    /// The three fields a REALITY client needs out of the leaf certificate: the
    /// SPKI algorithm, the raw public key, and the signature value.
    struct LeafCertificate {
        /// OID content octets of `SubjectPublicKeyInfo.algorithm.algorithm`.
        let publicKeyAlgorithm: Data
        /// The raw key bytes, i.e. the BIT STRING without its unused-bits octet
        /// and without any SPKI wrapping. For Ed25519 that is 32 bytes, and it
        /// is exactly what REALITY runs HMAC-SHA512 over.
        let publicKey: Data
        let signatureAlgorithm: Data
        /// `signatureValue`. For an Ed25519 self-signed certificate this is the
        /// last 64 bytes of the DER, which is the slot REALITY overwrites with
        /// HMAC-SHA512(AuthKey, ed25519_public_key).
        let signature: Data

        /// 1.3.101.112 encoded as OID content octets.
        static let ed25519OID = Data([0x2B, 0x65, 0x70])

        var isEd25519: Bool { publicKeyAlgorithm == LeafCertificate.ed25519OID && publicKey.count == 32 }

        init(der: Data) throws {
            let bytes = Array(der)
            let certificate = try DER.element(bytes, at: 0)
            guard certificate.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 证书最外层不是 SEQUENCE")
            }
            let top = try DER.children(bytes, of: certificate)
            guard top.count >= 3 else {
                throw NativeOutboundError.protocolError("X.509 证书顶层元素不足 3 个")
            }
            let tbs = top[0]
            guard tbs.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 tbsCertificate 不是 SEQUENCE")
            }
            signatureAlgorithm = try LeafCertificate.algorithmOID(bytes, of: top[1])
            signature = try DER.bitStringBytes(bytes, of: top[2])

            var fields = try DER.children(bytes, of: tbs)
            // The explicit [0] version tag is optional; v1 certificates omit it.
            if let first = fields.first, first.tag == DER.contextConstructed0 {
                fields.removeFirst()
            }
            // serialNumber, signature, issuer, validity, subject, then SPKI.
            guard fields.count >= 6 else {
                throw NativeOutboundError.protocolError("X.509 tbsCertificate 字段不足，找不到 subjectPublicKeyInfo")
            }
            let spki = fields[5]
            guard spki.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 subjectPublicKeyInfo 不是 SEQUENCE")
            }
            let spkiFields = try DER.children(bytes, of: spki)
            guard spkiFields.count >= 2 else {
                throw NativeOutboundError.protocolError("X.509 subjectPublicKeyInfo 字段不足")
            }
            publicKeyAlgorithm = try LeafCertificate.algorithmOID(bytes, of: spkiFields[0])
            publicKey = try DER.bitStringBytes(bytes, of: spkiFields[1])
        }

        private static func algorithmOID(_ bytes: [UInt8], of element: DER.Element) throws -> Data {
            guard element.tag == DER.sequence else {
                throw NativeOutboundError.protocolError("X.509 AlgorithmIdentifier 不是 SEQUENCE")
            }
            let fields = try DER.children(bytes, of: element)
            guard let oid = fields.first, oid.tag == DER.objectIdentifier else {
                throw NativeOutboundError.protocolError("X.509 AlgorithmIdentifier 缺少 OID")
            }
            return Data(bytes[oid.contentStart..<oid.contentEnd])
        }
    }
}
