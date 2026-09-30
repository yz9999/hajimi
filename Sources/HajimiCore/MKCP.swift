import Foundation
import Network

/// mKCP's unreliable datagram substrate.
///
/// KCP layers its own acknowledgement and retransmission on top of UDP, so this
/// deliberately provides nothing beyond "send one datagram, receive one
/// datagram". Everything above it — ordering, loss recovery, windowing — is the
/// ARQ's job, and any reliability quietly added here would hide the bugs in it.
final class KCPDatagramChannel {
    private let connection: NWConnection
    private let lock = NSLock()
    private var cancelled = false

    private init(connection: NWConnection) { self.connection = connection }

    /// The largest datagram this channel will hand upward. mKCP's own MTU is
    /// far smaller; this only bounds a hostile or misbehaving peer.
    static let maximumDatagram = 8 * 1024

    static func connect(host: String, port: UInt16, queue: DispatchQueue,
                        timeout: TimeInterval = 10,
                        completion: @escaping (Result<KCPDatagramChannel, Error>) -> Void) {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            completion(.failure(NativeOutboundError.connection("端口无效"))); return
        }
        let parameters = NWParameters.udp
        // Without this the datagrams leave over whatever route the system
        // prefers, which in enhanced mode is the tunnel this connection is
        // supposed to be carrying — a routing loop that presents as a dead
        // connection rather than an error.
        if !isLoopback(host) { parameters.requiredInterface = ProxyEngine.currentOutboundInterface }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort,
                                      using: parameters)
        var settled = false
        connection.stateUpdateHandler = { state in
            guard !settled else { return }
            switch state {
            case .ready:
                settled = true
                connection.stateUpdateHandler = nil
                completion(.success(KCPDatagramChannel(connection: connection)))
            case .failed(let error):
                settled = true; connection.cancel()
                completion(.failure(NativeOutboundError.connection(error.localizedDescription)))
            case .cancelled:
                settled = true
                completion(.failure(NativeOutboundError.connection("连接被取消")))
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            guard !settled else { return }
            settled = true; connection.cancel()
            completion(.failure(NativeOutboundError.connection("连接超时")))
        }
    }

    /// Sends one datagram. A UDP write that fails is not fatal to the session —
    /// the ARQ above will retransmit — so the error is reported, not raised.
    func send(_ datagram: Data, completion: ((Error?) -> Void)? = nil) {
        connection.send(content: datagram, completion: .contentProcessed { completion?($0) })
    }

    /// Receives exactly one datagram. `receiveMessage` is required here:
    /// the stream-oriented `receive` would coalesce datagrams and destroy the
    /// message boundaries every KCP segment header depends on.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        connection.receiveMessage { data, _, _, error in
            completion(data, error)
        }
    }

    func cancel() {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        cancelled = true
        lock.unlock()
        connection.cancel()
    }

    private static func isLoopback(_ host: String) -> Bool {
        host == "localhost" || host == "::1" || host.hasPrefix("127.")
    }
}
