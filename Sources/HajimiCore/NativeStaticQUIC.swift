import Foundation

/// Compatibility name for callers of the retired Go bridge. This facade has
/// no foreign runtime/handle table; all operations enter the C++ engines.
enum NativeStaticQUICOutbound {
    static func configure(policies: [String: ProxyPolicy]) {
        NativeCXXOutbound.configure(policies: policies)
    }
    static func connect(policy: ProxyPolicy, target: RequestTarget,
                        completion: @escaping (Result<any NativeOutboundByteStream, Error>) -> Void) {
        NativeCXXOutbound.connect(policy: policy, target: target,
                                  queue: DispatchQueue.global(qos: .userInitiated), completion: completion)
    }
    static func makeDatagramSession(policy: ProxyPolicy,
                                    receive: @escaping (RequestTarget, Data) -> Void,
                                    failure: @escaping (Error) -> Void) throws -> NativeOutboundDatagramSession {
        try NativeCXXOutbound.makeDatagramSession(policy: policy,
            queue: DispatchQueue.global(qos: .userInitiated), receive: receive, failure: failure)
    }
}
