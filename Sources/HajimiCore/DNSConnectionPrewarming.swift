import Foundation

/// Prepare an already-authorized encrypted connection without a DNS message.
/// The same datagram cancellation fence owns registration and pool admission.
protocol DNSConnectionPrewarming: AnyObject {
    func prewarm(absoluteDeadline: TimeInterval,
                 completion: @escaping (Result<Void, EncryptedDNSQueryFailure>) -> Void)
}
