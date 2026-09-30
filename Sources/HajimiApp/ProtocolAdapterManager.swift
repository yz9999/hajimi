import Foundation
import HajimiCore

/// Promotes supported configurations into the in-process C++ protocol core.
/// Optional carriers retain their configuration/platform adapters; no Go
/// runtime or external proxy process is used by the native protocol path.
final class ProtocolAdapterManager {
    var onUnexpectedExit: ((String) -> Void)?

    enum AdapterError: LocalizedError {
        case unsupported([String])

        var errorDescription: String? {
            switch self {
            case .unsupported(let details):
                return "以下节点尚不受哈基米出站内核支持：\n" + details.joined(separator: "\n")
            }
        }
    }

    // A fresh Hajimi installation has no legacy adapter cache to migrate.
    // Never delete user files from Application Support just by opening the UI.
    init(applicationSupportDirectory _: URL) {}

    func validate(profile: Profile) throws {
        // A mixed Surge profile may contain nodes that are not selected by
        // any active rule. Do not prevent the entire local engine from
        // starting because one dormant node is not native yet. Unsupported
        // nodes remain `.external` and fail explicitly only when selected.
    }

    func prepare(profile: Profile) throws -> Profile {
        var runtime = profile
        for policy in profile.adapterPolicies {
            guard NativeOutboundFactory.supports(policy) else { continue }
            var native = policy
            native.kind = .native
            native.parameters.removeValue(forKey: "_hajimi-compat-socks-port")
            runtime.proxies[policy.name] = native
        }
        return runtime
    }

    func stop() {}
}
