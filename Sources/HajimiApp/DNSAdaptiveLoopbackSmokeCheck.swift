import Foundation
import HajimiCore

/// Reads only bounded, private temporary artifacts supplied by the explicit
/// fixture CLI. The Core entry validates the whole profile before any socket.
func runDNSAdaptiveLoopbackSmokeCheck() -> Int32 {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { text }
    }
    func require(_ value: Bool, _ text: String) throws {
        if !value { throw Failure(text: text) }
    }
    do {
        let arguments = CommandLine.arguments
        func option(_ flag: String) -> String? {
            guard arguments.filter({ $0 == flag }).count == 1,
                  let index = arguments.firstIndex(of: flag), index + 1 < arguments.count,
                  !arguments[index + 1].hasPrefix("--") else { return nil }
            return arguments[index + 1]
        }
        guard arguments.count == 6, arguments.filter({ $0 == "--dns-adaptive-loopback-test" }).count == 1,
              let path = option("--dns-adaptive-fixture-root"),
              let scenario = option("--dns-adaptive-fixture-scenario"),
              ["failure", "success", "identity-failure", "production-success", "production-identity-failure",
               "source-scope-burst", "multi-upstream-burst", "multi-upstream-connect-failure-burst",
               "third-candidate-rotation"].contains(scenario) else {
            throw Failure(text: "Adaptive DNS fixture requires its exact CLI flag, temporary root and fixed scenario")
        }
        let manager = FileManager.default
        let root = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
        let temporary = manager.temporaryDirectory.standardizedFileURL.resolvingSymlinksInPath()
        let rootAttributes = try manager.attributesOfItem(atPath: root.path)
        try require(root.deletingLastPathComponent() == temporary
                    && root.lastPathComponent.hasPrefix("hajimi-dns-adaptive-")
                    && rootAttributes[.type] as? FileAttributeType == .typeDirectory
                    && (rootAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700,
                    "Adaptive fixture artifacts must be in their private temporary directory")
        func readArtifact(_ name: String, maximum: Int) throws -> Data {
            let url = root.appendingPathComponent(name)
            let attributes = try manager.attributesOfItem(atPath: url.path)
            try require(url.resolvingSymlinksInPath() == url
                        && attributes[.type] as? FileAttributeType == .typeRegular
                        && (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600
                        && (attributes[.size] as? NSNumber).map({ $0.intValue > 0 && $0.intValue <= maximum }) == true,
                        "Adaptive fixture artifact is not a bounded private regular file")
            let data = try Data(contentsOf: url)
            try require(data.count <= maximum, "Adaptive fixture artifact exceeded its read limit")
            return data
        }
        guard let profile = String(data: try readArtifact("fixture.conf", maximum: 65_536), encoding: .utf8) else {
            throw Failure(text: "Adaptive fixture profile must be UTF-8")
        }
        let anchor = scenario == "failure" ? nil : try readArtifact("ca.der", maximum: 16_384)
        print(try NativePacketRouter.runDNSAdaptiveLoopbackFixture(profileText: profile, scenario: scenario,
                                                                  anchorDER: anchor))
        return 0
    } catch {
        FileHandle.standardError.write(Data("DNS adaptive loopback failed: \(error.localizedDescription)\n".utf8))
        return 1
    }
}
