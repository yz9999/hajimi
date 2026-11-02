import Foundation

/// Explicit, read-only inventory. Prints counts and a fixed set of transport
/// labels only; never emits node names, servers, credentials or raw parameters.
@main
enum ConfiguredCarrierInventoryMain {
    struct Failure: Error { let message: String }
    static func truth(_ value: String?) -> Bool {
        ["true", "yes", "on", "1"].contains(value?.lowercased() ?? "")
    }
    static func carrier(_ policy: ProxyPolicy) -> String {
        if truth(policy.parameters["ws"]) { return "ws" }
        let network = (policy.parameters["network"] ?? "tcp").lowercased()
        return ["tcp", "ws", "grpc", "xhttp", "splithttp", "kcp", "mkcp"].contains(network)
            ? network : "other"
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2,
              CommandLine.arguments[1] == "--inspect-saved-profile" else {
            throw Failure(message: "Requires explicit --inspect-saved-profile; performs no writes or network IO")
        }
        let manager = FileManager.default
        guard let directory = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw Failure(message: "Application support directory unavailable")
        }
        let url = directory.appendingPathComponent("Hajimi/profile.conf")
        guard let text = try? String(contentsOf: url, encoding: .utf8),
              let profile = try? ProfileParser.parse(text) else {
            throw Failure(message: "Saved profile could not be read or parsed")
        }
        var counts: [String: Int] = [:], muxRequested = 0
        for policy in profile.proxies.values where policy.host?.isEmpty == false {
            counts[carrier(policy), default: 0] += 1
            if truth(policy.parameters["mux"]) { muxRequested += 1 }
        }
        let defaults = UserDefaults(suiteName: "app.hajimi.mac")
        let rawMode = defaults?.string(forKey: "outboundMode") ?? "rule"
        let mode = ["rule", "direct", "proxy"].contains(rawMode) ? rawMode : "other"
        let saved = defaults?.string(forKey: "globalPolicy") ?? "DIRECT"
        var result: [String: Any] = ["configuredCarriers": counts, "muxRequested": muxRequested,
                                     "savedMode": mode, "scope": "saved configuration; not per-flow telemetry"]
        if let policy = profile.proxies[saved], policy.host?.isEmpty == false {
            result["savedGlobalCarrier"] = carrier(policy)
            result["savedGlobalMuxRequested"] = truth(policy.parameters["mux"])
        } else { result["savedGlobalCarrier"] = "group-or-special" }
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }
}
