import Foundation

// Only the surrounding protocol/error/logging surface is supplied here. All
// parsers, encoders and carrier state machines are the production source files.
protocol ByteTransport: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}

enum NativeOutboundError: Error {
    case connection(String)
    case protocolError(String)
}

struct ProxyPolicy {
    enum Kind { case native }
    let name: String
    let kind: Kind
    let host: String?
    let port: UInt16?
    let adapterType: String?
    let parameters: [String: String]
}

func nativeDebug(_ text: @autoclosure () -> String) {}
