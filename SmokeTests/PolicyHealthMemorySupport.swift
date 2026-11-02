import Foundation

// This support file is compiled only by the isolated policy-health memory
// fixture, never by HajimiCore or the application. It retains the production
// byte-stream contract while making any accidental real dial fail closed.
public protocol NativeOutboundByteStream: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}

public enum NodeConnectionAdmissionError: Error, LocalizedError, CustomNSError {
    case capacityExceeded
    public static var errorDomain: String { "app.hajimi.node-connection-admission" }
    public var errorCode: Int { 1 }
    public var errorDescription: String? { "fixture resource capacity exceeded" }
}

enum TunnelConnector {
    static func connect(route: ResolvedRoute, target: RequestTarget, plainHTTP: Bool,
                        queue: DispatchQueue,
                        completion: @escaping (Result<(any NativeOutboundByteStream, Data), Error>) -> Void) {
        preconditionFailure("A real network dial is forbidden in the policy-health in-memory fixture")
    }
}
