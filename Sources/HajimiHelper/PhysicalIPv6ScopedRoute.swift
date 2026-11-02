import Foundation
import Darwin

/// A physical escape path for sockets explicitly bound to one interface.
/// It is never an unscoped default or a DNS-host bypass.
struct PhysicalIPv6ScopedRoute: Equatable {
    let interface: String
    let gateway: String

    struct Observation {
        let isUp: Bool
        let isDefault: Bool
        let isScoped: Bool
        let usesGateway: Bool
        let interface: String
        let gateway: String

        init(isUp: Bool = true, isDefault: Bool, isScoped: Bool, usesGateway: Bool,
             interface: String, gateway: String) {
            self.isUp = isUp
            self.isDefault = isDefault
            self.isScoped = isScoped
            self.usesGateway = usesGateway
            self.interface = interface
            self.gateway = gateway
        }
    }

    static func validInterface(_ name: String) -> Bool {
        validInterfaceName(name) && !name.hasPrefix("utun") && !name.hasPrefix("lo")
    }

    private static func validInterfaceName(_ name: String) -> Bool {
        !name.isEmpty && name.utf8.count < Int(IFNAMSIZ)
            && name.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0)
                || (97...122).contains($0) || $0 == 45 || $0 == 95 }
    }

    private static func addressBytes(_ text: String) -> [UInt8]? {
        var address = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: address) { Array($0) }
    }

    static func observation(_ output: String) throws -> Observation {
        var fields: [String: String] = [:]
        for line in output.split(separator: "\n") {
            let pair = line.split(separator: ":", maxSplits: 1).map {
                String($0).trimmingCharacters(in: .whitespaces)
            }
            if pair.count == 2, ["destination", "mask", "gateway", "interface", "flags"].contains(pair[0]) {
                guard fields[pair[0]] == nil else { throw failure("IPv6 路由字段重复") }
                fields[pair[0]] = pair[1]
            }
        }
        guard let destination = fields["destination"], let mask = fields["mask"],
              let gateway = fields["gateway"], !gateway.isEmpty,
              let interface = fields["interface"], validInterfaceName(interface),
              let flagText = fields["flags"] else { throw failure("IPv6 路由查询字段不完整") }
        let flags = Set(flagText.trimmingCharacters(in: CharacterSet(charactersIn: "<>"))
            .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).uppercased() })
        guard !flags.contains("REJECT"), !flags.contains("BLACKHOLE") else {
            throw failure("IPv6 路由不可用")
        }
        let addressField: (String) -> [UInt8]? = { value in
            addressBytes(value == "default" || value == "::/0" ? "::" : value)
        }
        guard let destinationBytes = addressField(destination), let maskBytes = addressField(mask) else {
            throw failure("IPv6 路由目标或掩码无效")
        }
        var sawZero = false
        for byte in maskBytes {
            for bit in stride(from: 7, through: 0, by: -1) {
                if byte & (1 << bit) == 0 { sawZero = true }
                else if sawZero { throw failure("IPv6 路由掩码不连续") }
            }
        }
        let gatewayParts = gateway.split(separator: "%", omittingEmptySubsequences: false)
        let gatewayIsIPv6 = (gatewayParts.count == 1 || (gatewayParts.count == 2 && gatewayParts[1] == interface))
            && addressBytes(String(gatewayParts[0])) != nil
        let linkSuffix = gateway.dropFirst(5)
        let gatewayIsLink = !flags.contains("GATEWAY") && gateway.hasPrefix("link#")
            && !linkSuffix.isEmpty && linkSuffix.allSatisfy { $0.isASCII && $0.isNumber }
        guard gatewayIsIPv6 || gatewayIsLink else { throw failure("IPv6 路由网关字段无效") }
        let isDefault = destinationBytes.allSatisfy { $0 == 0 } && maskBytes.allSatisfy { $0 == 0 }
            && !flags.contains("HOST")
        if isDefault, flags.contains("IFSCOPE"), flags.contains("GATEWAY"), validInterface(interface) {
            _ = try normalizedGateway(gateway, interface: interface)
        }
        return Observation(isUp: flags.contains("UP"), isDefault: isDefault,
            isScoped: flags.contains("IFSCOPE"), usesGateway: flags.contains("GATEWAY"),
            interface: interface, gateway: gateway)
    }

    static func physicalDefault(_ output: String, interface: String) throws -> Self? {
        guard validInterface(interface) else { throw failure("物理接口无效") }
        let observed = try observation(output)
        guard observed.isUp, observed.isDefault, observed.interface == interface else { return nil }
        guard observed.usesGateway else {
            let suffix = observed.gateway.dropFirst(5)
            if observed.gateway.hasPrefix("link#"), !suffix.isEmpty, suffix.allSatisfy({ $0.isASCII && $0.isNumber }) {
                return nil // A well-formed on-link default needs another strategy.
            }
            throw failure("物理 IPv6 默认路由缺少有效网关语义")
        }
        return try Self(interface: interface, gateway: normalizedGateway(observed.gateway, interface: interface))
    }

    func matches(_ observed: Observation) -> Bool {
        guard observed.isDefault, observed.isScoped, observed.usesGateway, observed.interface == interface,
              let normalized = try? Self.normalizedGateway(observed.gateway, interface: interface) else { return false }
        return normalized == gateway
    }

    private static func normalizedGateway(_ value: String, interface: String) throws -> String {
        let parts = value.split(separator: "%", omittingEmptySubsequences: false)
        guard parts.count == 1 || (parts.count == 2 && parts[1] == interface) else {
            throw failure("IPv6 网关 scope 与物理接口不匹配")
        }
        var address = in6_addr()
        guard String(parts[0]).withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
            throw failure("物理 IPv6 默认网关不是 IPv6 地址")
        }
        let bytes = withUnsafeBytes(of: address) { Array($0) }
        guard !bytes.allSatisfy({ $0 == 0 }), bytes[0] != 255,
              !(bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] == 1),
              !(bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255),
              !bytes.starts(with: [0xfd, 0, 0x68, 0x61, 0x6a, 0x69, 0, 0]) else {
            throw failure("物理 IPv6 默认网关不可用")
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else {
            throw failure("物理 IPv6 默认网关格式无效")
        }
        let host = String(cString: buffer)
        return bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 ? host + "%" + interface : host
    }

    var lookupArguments: [String] { ["-n", "get", "-inet6", "-ifscope", interface, "default"] }
    func mutationArguments(_ verb: String) -> [String] {
        ["-n", verb, "-inet6", "-ifscope", interface, "default", gateway]
    }
    private static func failure(_ text: String) -> HelperServiceError { .command(text) }
}

enum PhysicalIPv6ScopedRouteSelfTest {
    static func run() throws {
        var assertions = 0
        func expect(_ value: Bool, _ text: String) throws {
            assertions += 1
            if !value { throw HelperServiceError.command("physical IPv6 scoped route: " + text) }
        }
        func output(destination: String = "::", mask: String = "default", scope: Bool = true,
                    interface: String = "en1", gateway: String = "fe80::1%en1") -> String {
            "destination: \(destination)\nmask: \(mask)\ngateway: \(gateway)\ninterface: \(interface)\nflags: <UP,GATEWAY\(scope ? ",IFSCOPE" : ",GLOBAL")>\n"
        }
        let route = try PhysicalIPv6ScopedRoute.physicalDefault(output(scope: false), interface: "en1")!
        try expect(route.gateway == "fe80::1%en1", "link-local gateway lost independent scope")
        try expect(route.matches(PhysicalIPv6ScopedRoute.observation(output())), "exact scoped default not recognized")
        try expect(!route.matches(PhysicalIPv6ScopedRoute.observation(output(scope: false))),
                   "successful get-ifscope fallback was falsely borrowed")
        try expect(!route.matches(PhysicalIPv6ScopedRoute.observation(output().replacingOccurrences(of: ",GATEWAY", with: ""))),
                   "non-gateway route was claimed")
        let onLink = output(scope: false, gateway: "link#6").replacingOccurrences(of: ",GATEWAY", with: "")
        try expect(try PhysicalIPv6ScopedRoute.physicalDefault(onLink, interface: "en1") == nil,
                   "unsupported on-link default broke IPv4-only operation")
        for wrong in [output(mask: "8000::"), output(destination: "8000::", mask: "8000::"),
                      output(interface: "en2", gateway: "fe80::1%en2"), output(gateway: "fe80::2%en1")] {
            try expect(!route.matches(PhysicalIPv6ScopedRoute.observation(wrong)), "different identity claimed")
        }
        for bad in [output(gateway: "192.0.2.1"), output(gateway: "fe80::1%en2"),
                    output(gateway: "::"), output(gateway: "fd00:6861:6a69::1"), "gateway: fe80::1\n",
                    output(destination: "garbage"), output(mask: "garbage"), output(mask: "7fff::"),
                    output(interface: "en 1"), output(destination: "8000::", mask: "8000::", gateway: "garbage")] {
            var rejected = false
            do { _ = try PhysicalIPv6ScopedRoute.physicalDefault(bad, interface: "en1") } catch { rejected = true }
            try expect(rejected, "invalid default was silently accepted")
        }
        try expect(try PhysicalIPv6ScopedRoute.physicalDefault(output(interface: "en2", gateway: "fe80::1%en2"),
                                                              interface: "en1") == nil,
                   "another physical interface's default was copied")
        try expect(route.mutationArguments("add") == ["-n", "add", "-inet6", "-ifscope", "en1", "default", "fe80::1%en1"],
                   "mutation changed scope or address family")
        try expect(!route.matches(PhysicalIPv6ScopedRoute.observation(output(interface: "utun3", gateway: "fd00:6861:6a69::1"))),
                   "well-formed foreign tunnel route was misclassified as malformed")
        print("Physical IPv6 scoped route parsing self-test passed (\(assertions) assertions)")
    }
}
