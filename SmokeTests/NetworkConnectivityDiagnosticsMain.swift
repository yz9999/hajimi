import Foundation

#if NETWORK_DIAGNOSTICS_STANDALONE
public protocol NativeOutboundByteStream: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}
#endif

@main
enum NetworkConnectivityDiagnosticsMain {
    static func main() throws {
        try NetworkConnectivityDiagnosticsSelfTest.run()
        #if NETWORK_DIAGNOSTICS_TRADITIONAL
        try TraditionalDNSBootstrapSelfTest.runOffline()
        print("Traditional DNS offline purpose/cancellation/revocation checks passed")
        #endif
    }
}
