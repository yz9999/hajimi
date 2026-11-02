// Standalone support for compiling the actual Mux/XUDP/mKCP production files.
// No socket implementation is linked. The unrelated VMess/VLESS header tests
// are intentionally unavailable here; run MuxSelfTest in the full Core build.
import Foundation
import Network
import Security

struct RequestTarget: Equatable {
    var host: String
    var port: UInt16
    var protocolName: String
}
enum ProxyKind { case native }
struct ProxyPolicy {
    var name: String
    var kind: ProxyKind
    var host: String = ""
    var port: UInt16 = 0
    var adapterType: String? = nil
    var parameters: [String: String] = [:]
}
protocol NativeOutboundByteStream: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}
typealias OutboundByteStream = NativeOutboundByteStream
protocol NativeOutboundDatagramSession: AnyObject {
    func send(_ payload: Data, to target: RequestTarget)
    func cancel()
}
protocol ByteTransport: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}
enum NativeOutboundError: LocalizedError {
    case connection(String), protocolError(String), crypto(String), unsupported(String)
    var errorDescription: String? {
        switch self {
        case .connection(let value), .protocolError(let value), .crypto(let value), .unsupported(let value): return value
        }
    }
}
final class KCPDatagramChannel {
    static func connect(host: String, port: UInt16, queue: DispatchQueue, timeout: TimeInterval,
                        completion: @escaping (Result<KCPDatagramChannel, Error>) -> Void) {
        completion(.failure(NativeOutboundError.unsupported("memory fixture forbids socket creation")))
    }
    func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        preconditionFailure("memory fixture cannot send datagrams to a socket")
    }
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        preconditionFailure("memory fixture cannot receive from a socket")
    }
    func cancel() {}
}
func secureRandom(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
    return Data(bytes)
}
enum VMessRequestCommand { case tcp, udp, mux }
func vlessRequestHeader(uuid: UUID, target: RequestTarget, command: VMessRequestCommand) throws -> Data {
    throw NativeOutboundError.unsupported("full Core header helper is outside this memory fixture")
}
func vmessCommandBlock(requestBodyIV: Data, requestBodyKey: Data, responseVerification: UInt8,
                       paddingLength: Int, target: RequestTarget, command: VMessRequestCommand) throws -> Data {
    throw NativeOutboundError.unsupported("full Core header helper is outside this memory fixture")
}
