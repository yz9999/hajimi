import Foundation
import HajimiProxyRuntime

/// Ownership/configuration adapter; TCP, TLS, I/O and cancellation are native
/// Objective-C through Network.framework's C API.
final class ObjCNetworkByteStream: NativeOutboundByteStream {
    let native: HJNetworkStream
    init(_ native: HJNetworkStream) { self.native = native }
    static func connect(host: String, port: UInt16, tls: Bool = false, serverName: String? = nil,
                        skipCertificateVerification: Bool = false, alpn: [String] = [],
                        interfaceName: String?, queue: DispatchQueue,
                        completion: @escaping (Result<ObjCNetworkByteStream, Error>) -> Void) {
        HJNetworkStream.connect(host: host, port: port, tls: tls, serverName: serverName,
            skipCertificateVerification: skipCertificateVerification, alpn: alpn,
            interfaceName: interfaceName, queue: queue, timeout: 12) { stream, error in
                if let error { completion(.failure(error)) }
                else if let stream { completion(.success(ObjCNetworkByteStream(stream))) }
                else { completion(.failure(NativeOutboundError.connection("原生 TCP/TLS 未返回连接"))) }
            }
    }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        native.sendData(data, completion: completion)
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        native.receiveData(maximum: UInt(clamping: maximum), completion: completion)
    }
    func cancel() { native.cancel() }
}
