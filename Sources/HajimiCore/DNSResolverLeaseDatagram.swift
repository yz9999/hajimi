import Foundation
import HajimiDNS

/// A physical resolver pool is shared only after the caller has authorized
/// its own question. Keep that pool leased until this query's logical cancel
/// fence has drained, so LRU pressure cannot cancel another live DNS client.
/// Native pending-dial reservations remain owned by their actual callbacks.
final class DNSResolverLeaseDatagram<Owner: AnyObject>: NativeRoutedDatagram,
    DNSQueryCancellationAcknowledging, DNSProxyFallbackBarrierProviding, DNSQueryTransportEvidenceProviding, DNSConnectionPrewarming, DNSQueryExecutionContextAccepting {
    private let transport: any NativeRoutedDatagram
    private let owner: BoundedConnectionOwnerLease<Owner>

    init(transport: any NativeRoutedDatagram, owner: BoundedConnectionOwnerLease<Owner>) {
        self.transport = transport
        self.owner = owner
    }

    func send(_ data: Data) { transport.send(data) }
    func setDNSQueryExecutionContext(_ context: DNSQueryExecutionContext) {
        (transport as? DNSQueryExecutionContextAccepting)?.setDNSQueryExecutionContext(context)
    }
    func cancel() { cancel(completion: {}) }
    func cancel(completion: @escaping () -> Void) {
        cancel(reason: .callerCancelled, completion: completion)
    }
    func cancel(reason: DNSAttemptCancellationReason, completion: @escaping () -> Void) {
        let owner = self.owner
        if let acknowledging = transport as? any DNSQueryCancellationAcknowledging {
            acknowledging.cancel(reason: reason) { owner.release(); completion() }
        } else {
            transport.cancel(); owner.release(); completion()
        }
    }
    func proxyFallbackBarrier() -> DNSProxyFallbackBarrier? {
        (transport as? any DNSProxyFallbackBarrierProviding)?.proxyFallbackBarrier()
    }
    func dnsQueryTransportEvidence() -> DNSQueryTransportEvidence {
        (transport as? DNSQueryTransportEvidenceProviding)?.dnsQueryTransportEvidence() ?? .unknown
    }
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void) {
        guard let preparation = transport as? DNSConnectionPrewarming else {
            completion(.failure(.configuration)); return
        }
        preparation.prewarm(absoluteDeadline: absoluteDeadline, completion: completion)
    }

    deinit {
        // Destruction is also a cancellation path. The ACK callback owns the
        // lease independently of this wrapper; dropping the wrapper must not
        // make its pool LRU-evictable while child registration/IO is unfenced.
        let owner = self.owner
        if let acknowledging = transport as? any DNSQueryCancellationAcknowledging {
            acknowledging.cancel(reason: .cleanup) { owner.release() }
        } else {
            transport.cancel(); owner.release()
        }
    }
}
