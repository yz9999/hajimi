import Foundation
import Network

/// Live state the Surge-compatible controller can read and mutate.
public struct ExternalControllerSnapshot {
    public var mode: OutboundMode
    public var globalPolicy: String
    public var groupSelections: [String: String]
    public var profile: Profile
    public var engineStatus: ProxyEngineStatus
    public var httpListen: ListenAddress
    public var socksListen: ListenAddress
    public var uploaded: UInt64
    public var downloaded: UInt64
    public var startedAt: Date?
    public var active: [ConnectionSnapshot]
    public var recent: [ConnectionSnapshot]
    public var systemProxyEnabled: Bool
    public var enhancedModeEnabled: Bool
    public var fakeIP: [(domain: String, address: String)]
    public var policyLatencies: [String: [String: TimeInterval]]

    public init(mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String], profile: Profile,
                engineStatus: ProxyEngineStatus, httpListen: ListenAddress,
                socksListen: ListenAddress, uploaded: UInt64, downloaded: UInt64,
                startedAt: Date?, active: [ConnectionSnapshot],
                recent: [ConnectionSnapshot], systemProxyEnabled: Bool,
                enhancedModeEnabled: Bool,
                fakeIP: [(domain: String, address: String)] = [],
                policyLatencies: [String: [String: TimeInterval]] = [:]) {
        self.mode = mode
        self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        self.profile = profile
        self.engineStatus = engineStatus
        self.httpListen = httpListen
        self.socksListen = socksListen
        self.uploaded = uploaded
        self.downloaded = downloaded
        self.startedAt = startedAt
        self.active = active
        self.recent = recent
        self.systemProxyEnabled = systemProxyEnabled
        self.enhancedModeEnabled = enhancedModeEnabled
        self.fakeIP = fakeIP
        self.policyLatencies = policyLatencies
    }
}

public protocol ExternalControllerBackend: AnyObject {
    func controllerSnapshot() -> ExternalControllerSnapshot
    func controllerSetOutboundMode(_ mode: OutboundMode)
    func controllerSetGlobalPolicy(_ name: String) -> Bool
    func controllerSetGroupSelection(group: String, policy: String) -> Bool
    func controllerSetSystemProxy(_ enabled: Bool)
    func controllerSetEnhancedMode(_ enabled: Bool)
    func controllerReloadProfile()
    func controllerFlushDNS()
    func controllerFlushFakeIP()
    func controllerKillRequest(id: String) -> Bool
    func controllerTestGroup(_ name: String)
}

/// Surge `http-api` (`/v1/*`, `X-Key`) and `external-controller-access`
/// (4-byte big-endian length + JSON command) in one process.
public final class ExternalController {
    private let stateLock = NSLock()
    // Never queue.sync here: a controller callback may be waiting on the UI.
    private let lifecycleLock = NSRecursiveLock()
    private var httpAddress: ListenAddress?
    private var commandAddress: ListenAddress?
    public var httpListen: ListenAddress? {
        stateLock.lock(); defer { stateLock.unlock() }; return httpAddress
    }
    public var commandListen: ListenAddress? {
        stateLock.lock(); defer { stateLock.unlock() }; return commandAddress
    }

    private weak var attachedBackend: ExternalControllerBackend?
    private var backend: ExternalControllerBackend? {
        stateLock.lock(); defer { stateLock.unlock() }; return attachedBackend
    }
    private let queue = DispatchQueue(label: "app.hajimi.external-controller", qos: .utility)
    private let acceptQueue = DispatchQueue(label: "app.hajimi.external-controller.accept", qos: .utility)
    private let deadlineQueue = DispatchQueue(label: "app.hajimi.external-controller.deadline", qos: .utility)
    private var httpListener: NWListener?
    private var commandListener: NWListener?
    private var httpKey = ""
    private var commandKey = ""
    private var startDate = Date()
    private var startedAt: Date {
        stateLock.lock(); defer { stateLock.unlock() }; return startDate
    }
    private var generation = UUID()
    private struct AcceptedClient {
        let connection: NWConnection
        var expired = false
    }
    private var clients: [UUID: AcceptedClient] = [:]
    // Revoked generations keep their admission slots until a queued cleanup
    // callback runs. Canceling a socket must not let repeated reloads grow the
    // callback backlog while the backend queue is blocked. Both registries
    // participate in the same stateLock-protected admission check.
    private var retiredClients: [UUID: AcceptedClient] = [:]
    private let maximumClients: Int
    private let requestTimeout: TimeInterval
    private static let maximumCommandPayload = 1_048_576

    public init(maximumClients: Int = 64, requestTimeout: TimeInterval = 15) {
        self.maximumClients = max(1, min(maximumClients, 1_024))
        self.requestTimeout = requestTimeout.isFinite ? max(0.05, min(requestTimeout, 60)) : 15
    }

    public var activeClientCount: Int {
        // Current generation only; reload still revokes its visible clients
        // synchronously, even when older cleanup callbacks have not drained.
        stateLock.lock(); defer { stateLock.unlock() }; return clients.count
    }

    /// Read-only admission diagnostic: canceled clients awaiting queued cleanup.
    public var pendingCleanupClientCount: Int {
        stateLock.lock(); defer { stateLock.unlock() }; return retiredClients.count
    }

    /// Includes current and retired generations; never exceeds maximumClients.
    public var admittedClientCount: Int {
        stateLock.lock(); defer { stateLock.unlock() }
        return clients.count + retiredClients.count
    }

    deinit { stop() }

    public func attach(backend: ExternalControllerBackend) {
        stateLock.lock(); attachedBackend = backend; stateLock.unlock()
    }

    /// Test seam: set keys without binding sockets.
    public func applyKeys(http: String, command: String) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stop()
        stateLock.lock(); httpKey = http; commandKey = command; stateLock.unlock()
    }

    public func start(profile: Profile) {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stop()
        let httpKey = profile.httpAPIKey ?? ""
        let commandKey = profile.externalControllerKey ?? ""
        stateLock.lock()
        startDate = Date(); self.httpKey = httpKey; self.commandKey = commandKey
        let generation = self.generation
        stateLock.unlock()
        if let address = profile.httpAPI {
            if Self.canBind(address, key: httpKey) {
                if let listener = try? listen(address: address, handler: { [weak self] connection in
                    guard let self else { connection.cancel(); return }
                    self.acceptHTTP(connection, key: httpKey, generation: generation)
                }) {
                    stateLock.lock()
                    httpListener = listener
                    stateLock.unlock()
                    configureState(listener, address: address, role: .http, generation: generation)
                    listener.start(queue: acceptQueue)
                } else {
                    NSLog("Hajimi: could not construct http-api listener")
                }
            } else {
                NSLog("Hajimi: refused unauthenticated non-loopback http-api listener")
            }
        }
        if let address = profile.externalController {
            if Self.canBind(address, key: commandKey) {
                if let listener = try? listen(address: address, handler: { [weak self] connection in
                    guard let self else { connection.cancel(); return }
                    self.acceptCommand(connection, key: commandKey, generation: generation)
                }) {
                    stateLock.lock()
                    commandListener = listener
                    stateLock.unlock()
                    configureState(listener, address: address, role: .command, generation: generation)
                    listener.start(queue: acceptQueue)
                } else {
                    NSLog("Hajimi: could not construct external-controller listener")
                }
            } else {
                NSLog("Hajimi: refused unauthenticated non-loopback external-controller listener")
            }
        }
    }

    /// Defense in depth for profiles built in code without going through the parser.
    fileprivate static func canBind(_ address: ListenAddress, key: String) -> Bool {
        address.isLoopback || !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Revokes queued work without waiting on the backend/UI queue. A request
    /// already past its generation check may still enter or finish backend work;
    /// stop is neither a backend-entry barrier nor transactional rollback.
    public func stop() {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        stateLock.lock()
        // Revocation precedes cancellation, including accept/read callbacks
        // that were already queued by Network.framework.
        generation = UUID()
        let listeners = [httpListener, commandListener].compactMap { $0 }
        let accepted = clients.values.map { $0.connection }
        for (id, var client) in clients {
            client.expired = true
            retiredClients[id] = client
        }
        clients.removeAll(keepingCapacity: true)
        httpListener = nil; httpAddress = nil; httpKey = ""
        commandListener = nil; commandAddress = nil; commandKey = ""
        stateLock.unlock()
        listeners.forEach { $0.cancel() }
        accepted.forEach { $0.cancel() }
    }

    // MARK: - HTTP /v1

    public func handleHTTP(method: String, path: String, query: [String: String],
                           headers: [String: String], body: Data) -> (Int, Data, String) {
        stateLock.lock(); let key = httpKey; stateLock.unlock()
        return handleHTTP(method: method, path: path, query: query, headers: headers, body: body, key: key)
    }

    private func handleHTTP(method: String, path: String, query: [String: String],
                            headers: [String: String], body: Data, key: String) -> (Int, Data, String) {
        let presented = headers["x-key"] ?? query["x-key"] ?? ""
        if !key.isEmpty, presented != key {
            return json(401, ["error": "invalid key"])
        }
        let verb = method.uppercased()
        switch (verb, path) {
        case ("GET", "/v1/outbound"):
            return json(200, ["mode": snapshot().mode.rawValue])
        case ("POST", "/v1/outbound"):
            guard let mode = jsonObject(body)["mode"].flatMap(OutboundMode.init) else {
                return json(400, ["error": "missing mode"])
            }
            backend?.controllerSetOutboundMode(mode)
            return json(200, ["mode": mode.rawValue])
        case ("GET", "/v1/outbound/global"):
            return json(200, ["policy": snapshot().globalPolicy])
        case ("POST", "/v1/outbound/global"):
            guard let name = jsonObject(body)["policy"], !name.isEmpty else {
                return json(400, ["error": "missing policy"])
            }
            guard backend?.controllerSetGlobalPolicy(name) == true else {
                return json(404, ["error": "unknown policy"])
            }
            return json(200, ["policy": name])
        case ("GET", "/v1/policies"):
            return json(200, ["policies": snapshot().profile.selectablePolicies])
        case ("GET", "/v1/policies/detail"):
            guard let name = query["policy_name"],
                  let policy = snapshot().profile.proxies[name] else {
                return json(404, ["error": "unknown policy"])
            }
            return json(200, policyDetail(policy))
        case ("GET", "/v1/policy_groups"):
            return json(200, policyGroupsJSON(snapshot()))
        case ("GET", "/v1/policy_groups/select"):
            guard let name = query["group_name"] else {
                return json(400, ["error": "missing group_name"])
            }
            let current = snapshot()
            guard current.profile.groups[name] != nil else {
                return json(404, ["error": "unknown group"])
            }
            let selected = current.groupSelections[name]
                ?? current.profile.groups[name]?.members.first ?? ""
            return json(200, ["policy": selected])
        case ("POST", "/v1/policy_groups/select"):
            let object = jsonObject(body)
            guard let group = object["group_name"], let policy = object["policy"] else {
                return json(400, ["error": "missing group_name or policy"])
            }
            guard backend?.controllerSetGroupSelection(group: group, policy: policy) == true else {
                return json(404, ["error": "unknown group or policy"])
            }
            return json(200, ["policy": policy])
        case ("POST", "/v1/policy_groups/test"):
            guard let name = jsonObject(body)["group_name"] else {
                return json(400, ["error": "missing group_name"])
            }
            backend?.controllerTestGroup(name)
            return json(200, ["available": snapshot().profile.groups[name]?.members ?? []])
        case ("GET", "/v1/policy_groups/test_results"):
            return json(200, snapshot().policyLatencies.mapValues { latencies in
                latencies.mapValues { Int($0 * 1000) }
            })
        case ("GET", "/v1/traffic"):
            let current = snapshot()
            return json(200, [
                "startTime": Int((current.startedAt ?? startedAt).timeIntervalSince1970),
                "in": current.downloaded,
                "out": current.uploaded,
                "connector": current.active.count
            ] as [String: Any])
        case ("GET", "/v1/requests/active"):
            return json(200, ["requests": snapshot().active.map(requestJSON)])
        case ("GET", "/v1/requests/recent"):
            return json(200, ["requests": snapshot().recent.map(requestJSON)])
        case ("POST", "/v1/requests/kill"):
            let raw = jsonObject(body)["id"] ?? ""
            guard backend?.controllerKillRequest(id: raw) == true else {
                return json(404, ["error": "unknown request"])
            }
            return json(200, ["result": "killed"])
        case ("GET", "/v1/features/system_proxy"):
            return json(200, ["enabled": snapshot().systemProxyEnabled])
        case ("POST", "/v1/features/system_proxy"):
            backend?.controllerSetSystemProxy(jsonBool(body, key: "enabled"))
            return json(200, ["enabled": snapshot().systemProxyEnabled])
        case ("GET", "/v1/features/enhanced_mode"):
            return json(200, ["enabled": snapshot().enhancedModeEnabled])
        case ("POST", "/v1/features/enhanced_mode"):
            backend?.controllerSetEnhancedMode(jsonBool(body, key: "enabled"))
            return json(200, ["enabled": snapshot().enhancedModeEnabled])
        case ("GET", "/v1/profiles/current"):
            return json(200, currentProfileJSON(snapshot(), hideSecrets: query["sensitive"] != "1"))
        case ("POST", "/v1/profiles/reload"):
            backend?.controllerReloadProfile()
            return json(200, ["result": "reloaded"])
        case ("POST", "/v1/dns/flush"):
            backend?.controllerFlushDNS()
            backend?.controllerFlushFakeIP()
            return json(200, ["result": "flushed"])
        case ("GET", "/v1/dns"):
            return json(200, ["dnsCache": snapshot().fakeIP.map {
                ["domain": $0.domain, "address": $0.address, "source": "fake-ip"]
            }])
        case ("GET", "/v1/events"):
            return json(200, ["events": [] as [String]])
        case ("POST", "/v1/stop"):
            return json(200, ["result": "ignored"])
        default:
            return json(404, ["error": "unknown endpoint"])
        }
    }

    // MARK: - Length-prefixed JSON commands

    public func handleCommand(_ object: [String: Any]) -> [String: Any] {
        stateLock.lock(); let key = commandKey; stateLock.unlock()
        return handleCommand(object, key: key)
    }

    private func handleCommand(_ object: [String: Any], key: String) -> [String: Any] {
        if !key.isEmpty {
            let presented = (object["key"] as? String) ?? (object["password"] as? String) ?? ""
            if presented != key {
                return ["error": "invalid key"]
            }
        }
        let command = ((object["command"] as? String) ?? (object["cmd"] as? String) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let args = (object["args"] as? [String])
            ?? (object["arguments"] as? [String])
            ?? []
        switch command {
        case "environment":
            return ["environment": environment(snapshot())]
        case "set":
            applyEnvironment(args)
            return ["result": "ok"]
        case "dump":
            return dump(args.first ?? "summary", extra: args.dropFirst().first)
        case "reload":
            backend?.controllerReloadProfile()
            return ["result": "reloaded"]
        case "flush":
            if (args.first ?? "dns").lowercased() == "dns" {
                backend?.controllerFlushDNS()
                backend?.controllerFlushFakeIP()
            }
            return ["result": "flushed"]
        case "kill":
            guard let id = args.first, backend?.controllerKillRequest(id: id) == true else {
                return ["error": "unknown connection"]
            }
            return ["result": "killed"]
        case "test-group":
            guard let name = args.first else { return ["error": "missing group"] }
            backend?.controllerTestGroup(name)
            return ["result": "testing"]
        case "show-policy":
            guard let name = args.first,
                  let policy = snapshot().profile.proxies[name] else {
                return ["error": "unknown policy"]
            }
            return policyDetail(policy)
        case "stop":
            return ["result": "ignored"]
        default:
            return ["error": "unknown command \(command)"]
        }
    }

    public static func encodeFrame(_ object: [String: Any]) -> Data? {
        guard JSONSerialization.isValidJSONObject(object),
              let payload = try? JSONSerialization.data(withJSONObject: object),
              payload.count <= maximumCommandPayload else { return nil }
        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: 4)
        frame.append(payload)
        return frame
    }

    public static func decodeFrame(_ data: Data) -> (object: [String: Any], consumed: Int)? {
        guard data.count >= 4 else { return nil }
        let length = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length <= maximumCommandPayload, data.count >= 4 + length else { return nil }
        let payload = data.subdata(in: 4..<(4 + length))
        guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            return nil
        }
        return (object, 4 + length)
    }

    // MARK: - Listeners

    private enum ListenerRole: String { case http, command }

    private func configureState(_ listener: NWListener, address: ListenAddress,
                                role: ListenerRole, generation: UUID) {
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            guard let self, let listener else { return }
            self.stateLock.lock()
            let current = role == .http ? self.httpListener : self.commandListener
            guard self.generation == generation, current === listener else {
                self.stateLock.unlock(); return
            }
            // A configured endpoint is not proof that the asynchronous bind
            // succeeded. Publish only a listener that is actually ready.
            let bound: ListenAddress?
            switch state {
            case .ready:
                bound = listener.port.map { ListenAddress(host: address.host, port: $0.rawValue) }
            default: bound = nil
            }
            if role == .http { self.httpAddress = bound }
            else { self.commandAddress = bound }
            switch state {
            case .failed, .cancelled:
                if role == .http { self.httpListener = nil }
                else { self.commandListener = nil }
            default: break
            }
            self.stateLock.unlock()
            switch state {
            case .waiting(let error):
                NSLog("Hajimi: \(role.rawValue) controller listener waiting: \(error.localizedDescription)")
            case .failed(let error):
                NSLog("Hajimi: \(role.rawValue) controller listener failed: \(error.localizedDescription)")
                listener.cancel()
            default: break
            }
        }
    }

    private func listen(address: ListenAddress,
                        handler: @escaping (NWConnection) -> Void) throws -> NWListener {
        guard let port = NWEndpoint.Port(rawValue: address.port) else {
            throw ControllerError("无效端口")
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        if address.host == "127.0.0.1" || address.host == "::1" {
            parameters.requiredInterfaceType = .loopback
            if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
                ip.version = address.host == "::1" ? .v6 : .v4
            }
        } else if address.host != "0.0.0.0" && address.host != "::" && !address.host.isEmpty {
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(address.host),
                                                         port: port)
        }
        let listener: NWListener
        if address.host == "0.0.0.0" || address.host == "::" || address.host.isEmpty
            || address.host == "127.0.0.1" || address.host == "::1" {
            listener = try NWListener(using: parameters, on: port)
        } else {
            listener = try NWListener(using: parameters)
        }
        listener.newConnectionHandler = handler
        return listener
    }

    private func beginClient(_ connection: NWConnection, generation: UUID) -> (UUID, DispatchWorkItem)? {
        let id = UUID()
        let timeout = DispatchWorkItem { [weak self, weak connection] in
            guard let connection else { return }
            // This queue never calls the backend (which may wait on the UI).
            // Mark only an existing entry; late timers cannot leave tombstones.
            if let self {
                self.stateLock.lock()
                self.clients[id]?.expired = true
                self.stateLock.unlock()
            }
            connection.cancel()
        }
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                timeout.cancel()
                self?.removeClient(id)
            default: break
            }
        }
        stateLock.lock()
        guard self.generation == generation,
              clients.count + retiredClients.count < maximumClients else {
            stateLock.unlock(); timeout.cancel(); connection.cancel(); return nil
        }
        clients[id] = AcceptedClient(connection: connection)
        connection.start(queue: queue)
        stateLock.unlock()
        // One absolute deadline covers framing, authentication and sending the
        // reply; dripping a byte at a time must not renew it.
        deadlineQueue.asyncAfter(deadline: .now() + requestTimeout, execute: timeout)
        return (id, timeout)
    }

    private func isCurrentClient(_ id: UUID, generation: UUID) -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return self.generation == generation && clients[id]?.expired == false
    }

    private func removeClient(_ id: UUID) {
        stateLock.lock()
        clients.removeValue(forKey: id)
        retiredClients.removeValue(forKey: id)
        stateLock.unlock()
    }

    private func finishClient(_ id: UUID, connection: NWConnection) {
        removeClient(id); connection.cancel()
    }

    private func acceptHTTP(_ connection: NWConnection, key: String, generation: UUID) {
        guard let (id, timeout) = beginClient(connection, generation: generation) else { return }
        readHTTP(connection, buffer: Data(), id: id, key: key, generation: generation, timeout: timeout)
    }

    private func readHTTP(_ connection: NWConnection, buffer: Data, id: UUID, key: String,
                          generation: UUID, timeout: DispatchWorkItem) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, complete, error in
            guard let self, error == nil, self.isCurrentClient(id, generation: generation) else {
                timeout.cancel()
                self?.removeClient(id)
                connection.cancel()
                return
            }
            var next = buffer
            if let data { next.append(data) }
            switch HTTPAPIRequest.parse(next) {
            case .request(let request):
                let response = self.handleHTTP(method: request.method, path: request.path,
                                               query: request.query, headers: request.headers,
                                               body: request.body, key: key)
                self.replyHTTP(connection, status: response.0, body: response.1,
                               contentType: response.2, id: id, timeout: timeout)
            case .rejected(let status, let message):
                let response = self.json(status, ["error": message])
                self.replyHTTP(connection, status: response.0, body: response.1,
                               contentType: response.2, id: id, timeout: timeout)
            case .incomplete:
                if complete {
                    timeout.cancel()
                    self.finishClient(id, connection: connection)
                } else {
                    self.readHTTP(connection, buffer: next, id: id, key: key,
                                  generation: generation, timeout: timeout)
                }
            }
        }
    }

    private func replyHTTP(_ connection: NWConnection, status: Int, body: Data,
                           contentType: String, id: UUID, timeout: DispatchWorkItem) {
        let reason: String
        switch status {
        case 200: reason = "OK"
        case 400: reason = "Bad Request"
        case 401: reason = "Unauthorized"
        case 413: reason = "Content Too Large"
        case 431: reason = "Request Header Fields Too Large"
        default: reason = "Error"
        }
        var header = "HTTP/1.1 \(status) \(reason)\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Content-Length: \(body.count)\r\n"
        header += "Connection: close\r\n\r\n"
        var payload = Data(header.utf8)
        payload.append(body)
        connection.send(content: payload, completion: .contentProcessed { [weak self] _ in
            timeout.cancel()
            self?.finishClient(id, connection: connection)
            connection.cancel()
        })
    }

    private func acceptCommand(_ connection: NWConnection, key: String, generation: UUID) {
        guard let (id, timeout) = beginClient(connection, generation: generation) else { return }
        readCommand(connection, buffer: Data(), id: id, key: key, generation: generation, timeout: timeout)
    }

    private func readCommand(_ connection: NWConnection, buffer: Data, id: UUID, key: String,
                             generation: UUID, timeout: DispatchWorkItem) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, complete, error in
            guard let self, error == nil, self.isCurrentClient(id, generation: generation) else {
                timeout.cancel(); self?.removeClient(id); connection.cancel(); return
            }
            var next = buffer
            if let data { next.append(data) }
            var completeFrame = false
            if next.count > Self.maximumCommandPayload + 4 {
                timeout.cancel(); self.finishClient(id, connection: connection); return
            }
            if next.count >= 4 {
                let length = next.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
                guard length > 0, length <= Self.maximumCommandPayload else {
                    timeout.cancel(); self.finishClient(id, connection: connection); return
                }
                completeFrame = next.count >= length + 4
            }
            if let frame = Self.decodeFrame(next) {
                let reply = self.handleCommand(frame.object, key: key)
                if let encoded = Self.encodeFrame(reply) {
                    connection.send(content: encoded, completion: .contentProcessed { [weak self] _ in
                        timeout.cancel()
                        self?.finishClient(id, connection: connection)
                        connection.cancel()
                    })
                } else {
                    timeout.cancel(); self.finishClient(id, connection: connection)
                }
                return
            }
            // A complete malformed frame is not an incomplete request.
            if complete || completeFrame { timeout.cancel(); self.finishClient(id, connection: connection); return }
            self.readCommand(connection, buffer: next, id: id, key: key,
                             generation: generation, timeout: timeout)
        }
    }

    // MARK: - Encoding

    private func snapshot() -> ExternalControllerSnapshot {
        backend?.controllerSnapshot() ?? ExternalControllerSnapshot(
            mode: .rule, globalPolicy: "DIRECT", groupSelections: [:],
            profile: Profile(), engineStatus: .stopped,
            httpListen: ListenAddress(host: "127.0.0.1", port: 7162),
            socksListen: ListenAddress(host: "127.0.0.1", port: 7163),
            uploaded: 0, downloaded: 0, startedAt: nil, active: [], recent: [],
            systemProxyEnabled: false, enhancedModeEnabled: false)
    }

    private func json(_ status: Int, _ object: Any) -> (Int, Data, String) {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            ?? Data("{}".utf8)
        return (status, data, "application/json; charset=utf-8")
    }

    private func jsonObject(_ body: Data) -> [String: String] {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return [:]
        }
        var result: [String: String] = [:]
        for (key, value) in object {
            if let string = value as? String { result[key] = string }
            else { result[key] = "\(value)" }
        }
        return result
    }

    private func jsonBool(_ body: Data, key: String) -> Bool {
        if let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
           let value = object[key] as? Bool {
            return value
        }
        return ["true", "1", "yes", "on"].contains(jsonObject(body)[key]?.lowercased() ?? "")
    }

    private func policyDetail(_ policy: ProxyPolicy) -> [String: Any] {
        [
            "name": policy.name,
            "type": policy.adapterType ?? policy.kind.rawValue,
            "host": policy.host ?? "",
            "port": Int(policy.port ?? 0),
            "udp": policy.parameters["udp"] ?? "false"
        ]
    }

    private func policyGroupsJSON(_ snapshot: ExternalControllerSnapshot) -> [String: Any] {
        var result: [String: Any] = [:]
        for name in snapshot.profile.groupOrder {
            guard let group = snapshot.profile.groups[name] else { continue }
            result[name] = [
                "type": group.kind.rawValue,
                "proxies": group.members,
                "policy": snapshot.groupSelections[name] ?? group.members.first ?? ""
            ]
        }
        return result
    }

    private func requestJSON(_ snapshot: ConnectionSnapshot) -> [String: Any] {
        [
            "id": snapshot.id.uuidString,
            "remoteAddress": snapshot.client,
            "URL": "\(snapshot.host):\(snapshot.port)",
            "method": snapshot.method,
            "policy": snapshot.policy,
            "status": "active",
            "startDate": snapshot.openedAt.timeIntervalSince1970
        ]
    }

    private func currentProfileJSON(_ snapshot: ExternalControllerSnapshot,
                                    hideSecrets: Bool) -> [String: Any] {
        [
            "name": "profile.conf",
            "mode": snapshot.mode.rawValue,
            "http-listen": "\(snapshot.httpListen.host):\(snapshot.httpListen.port)",
            "socks5-listen": "\(snapshot.socksListen.host):\(snapshot.socksListen.port)",
            "sensitive": hideSecrets ? 0 : 1
        ]
    }

    private func environment(_ snapshot: ExternalControllerSnapshot) -> [String: String] {
        [
            "outbound-mode": snapshot.mode.rawValue,
            "global-policy": snapshot.globalPolicy,
            "system-proxy": snapshot.systemProxyEnabled ? "true" : "false",
            "enhanced-mode": snapshot.enhancedModeEnabled ? "true" : "false"
        ]
    }

    private func applyEnvironment(_ args: [String]) {
        for item in args {
            guard let equal = item.firstIndex(of: "=") else { continue }
            let key = item[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = item[item.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "outbound-mode":
                if let mode = OutboundMode(rawValue: value) {
                    backend?.controllerSetOutboundMode(mode)
                }
            case "global-policy":
                _ = backend?.controllerSetGlobalPolicy(value)
            case "system-proxy":
                backend?.controllerSetSystemProxy(["true", "1", "yes", "on"].contains(value.lowercased()))
            case "enhanced-mode":
                backend?.controllerSetEnhancedMode(["true", "1", "yes", "on"].contains(value.lowercased()))
            default:
                break
            }
        }
    }

    private func dump(_ type: String, extra: String?) -> [String: Any] {
        let current = snapshot()
        switch type.lowercased() {
        case "summary":
            return [
                "mode": current.mode.rawValue,
                "policy": current.globalPolicy,
                "active": current.active.count,
                "uploaded": current.uploaded,
                "downloaded": current.downloaded
            ]
        case "active":
            return ["requests": current.active.map(requestJSON)]
        case "recent", "request":
            return ["requests": current.recent.map(requestJSON)]
        case "traffic":
            return ["in": current.downloaded, "out": current.uploaded]
        case "policy":
            return ["policies": current.profile.selectablePolicies]
        case "policy-group-sub-policies":
            return policyGroupsJSON(current)
        case "rule":
            return ["count": current.profile.rules.count]
        case "virtual-ip-db":
            return ["entries": current.fakeIP.map {
                ["domain": $0.domain, "address": $0.address]
            }]
        case "profile":
            return currentProfileJSON(current, hideSecrets: extra != "original")
        case "dns":
            return ["dnsCache": current.fakeIP.map { $0.domain }]
        default:
            return ["error": "unknown dump \(type)"]
        }
    }
}

private struct HTTPAPIRequest {
    static let maximumHeaderBytes = 16_384
    static let maximumRequestBytes = 1_048_576

    enum ParseResult {
        case incomplete
        case rejected(Int, String)
        case request(HTTPAPIRequest)
    }

    var method: String
    var path: String
    var query: [String: String]
    var headers: [String: String]
    var body: Data

    static func parse(_ data: Data) -> ParseResult {
        guard data.count <= maximumRequestBytes else {
            return .rejected(413, "request too large")
        }
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else {
            return data.count > maximumHeaderBytes
                ? .rejected(431, "headers too large") : .incomplete
        }
        guard headerEnd.upperBound <= maximumHeaderBytes else {
            return .rejected(431, "headers too large")
        }
        let headerData = data.subdata(in: data.startIndex..<headerEnd.lowerBound)
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            return .rejected(400, "invalid request headers")
        }
        let lines = headerText.split(separator: "\r\n", omittingEmptySubsequences: false)
        guard let requestLine = lines.first else {
            return .rejected(400, "invalid request line")
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else { return .rejected(400, "invalid request line") }
        var headers: [String: String] = [:]
        var contentLength: Int?
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                return .rejected(400, "invalid request header")
            }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { return .rejected(400, "invalid request header") }
            if key == "content-length" {
                guard contentLength == nil, !value.isEmpty,
                      value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                      let length = Int(value) else {
                    return .rejected(400, "invalid Content-Length")
                }
                contentLength = length
            }
            headers[key] = value
        }
        guard headers["transfer-encoding"] == nil else {
            return .rejected(400, "Transfer-Encoding is not supported")
        }
        let length = contentLength ?? 0
        let bodyStart = headerEnd.upperBound
        // Subtract before comparing to avoid overflow with Content-Length=Int.max.
        guard length <= maximumRequestBytes - bodyStart else {
            return .rejected(413, "request body too large")
        }
        guard data.count - bodyStart >= length else { return .incomplete }
        let body = data.subdata(in: bodyStart..<(bodyStart + length))
        let rawTarget = String(parts[1])
        let split = rawTarget.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let path = String(split[0])
        var query: [String: String] = [:]
        if split.count == 2 {
            for pair in split[1].split(separator: "&") {
                let item = pair.split(separator: "=", maxSplits: 1)
                guard let key = item.first else { continue }
                query[urlDecode(String(key))] = item.count == 2 ? urlDecode(String(item[1])) : ""
            }
        }
        return .request(HTTPAPIRequest(method: String(parts[0]), path: path, query: query,
                                       headers: headers, body: body))
    }

    private static func urlDecode(_ value: String) -> String {
        value.replacingOccurrences(of: "+", with: " ")
            .removingPercentEncoding ?? value
    }
}

private struct ControllerError: LocalizedError {
    let text: String
    init(_ text: String) { self.text = text }
    var errorDescription: String? { text }
}

public enum ExternalControllerSelfTest {
    struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "控制器自检失败：\(text)" }
    }

    public static func run() throws {
        let controller = ExternalController()
        let backend = RecordingBackend()
        controller.attach(backend: backend)

        let unauthorized = controller.handleHTTP(method: "GET", path: "/v1/outbound",
                                                 query: [:], headers: [:], body: Data())
        // No key configured yet — the handler still answers.
        try expect(unauthorized.0 == 200, "无密钥时应放行")

        let keyed = ExternalController()
        keyed.attach(backend: backend)
        keyed.applyKeys(http: "secret", command: "secret")

        let denied = keyed.handleHTTP(method: "GET", path: "/v1/outbound",
                                      query: [:], headers: [:], body: Data())
        try expect(denied.0 == 401, "错误密钥应拒绝")
        let allowed = keyed.handleHTTP(method: "GET", path: "/v1/outbound",
                                       query: [:], headers: ["x-key": "secret"], body: Data())
        try expect(allowed.0 == 200, "X-Key 应放行")
        let body = try JSONSerialization.jsonObject(with: allowed.1) as? [String: String]
        try expect(body?["mode"] == "rule", "outbound 模式应为 rule")

        let posted = keyed.handleHTTP(method: "POST", path: "/v1/outbound",
                                      query: [:], headers: ["x-key": "secret"],
                                      body: Data("{\"mode\":\"proxy\"}".utf8))
        try expect(posted.0 == 200, "设置 outbound 失败")
        try expect(backend.snapshot.mode == .proxy, "backend 未收到 outbound 切换")

        let frame = ExternalController.encodeFrame(["command": "dump", "args": ["summary"]])
        try expect(frame != nil && (frame?.count ?? 0) > 4, "无法编码长度前缀帧")
        let decoded = ExternalController.decodeFrame(frame!)
        try expect(decoded?.object["command"] as? String == "dump", "长度前缀帧解码失败")
        try expect(ExternalController.decodeFrame(Data([255, 255, 255, 255])) == nil,
                   "超限帧长度必须立即拒绝")
        try expect(ExternalController.decodeFrame(Data([0, 0, 0, 0])) == nil,
                   "空 JSON 帧必须拒绝")
        try expect(ExternalController.encodeFrame(["fill": String(repeating: "a", count: 1_048_576)]) == nil,
                   "超限输出帧必须拒绝，不能截断长度")

        let reply = keyed.handleCommand(["command": "environment", "key": "secret"])
        try expect(reply["environment"] != nil, "environment 命令失败")
        let bad = keyed.handleCommand(["command": "environment", "key": "wrong"])
        try expect(bad["error"] as? String == "invalid key", "错误 CLI 密钥应拒绝")

        try testMalformedHTTPRequests()
        try testControllerListenSecurity()
    }

    /// Pure parsing tests: no listener is started and no system settings change.
    private static func testMalformedHTTPRequests() throws {
        for (value, status) in [
            ("-1", 400), ("+1", 400), ("garbage", 400),
            ("18446744073709551615", 400), ("\(Int.max)", 413),
            ("1048576", 413)
        ] {
            let raw = "POST /v1/outbound HTTP/1.1\r\nContent-Length: \(value)\r\n\r\n"
            guard case .rejected(let actual, _) = HTTPAPIRequest.parse(Data(raw.utf8)) else {
                throw Failure(text: "Content-Length=\(value) 未被拒绝")
            }
            try expect(actual == status, "Content-Length=\(value) 返回状态错误")
        }

        let duplicate = "POST /v1/outbound HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
        guard case .rejected(400, _) = HTTPAPIRequest.parse(Data(duplicate.utf8)) else {
            throw Failure(text: "重复 Content-Length 未被拒绝")
        }
        let chunked = "POST /v1/outbound HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        guard case .rejected(400, _) = HTTPAPIRequest.parse(Data(chunked.utf8)) else {
            throw Failure(text: "不支持的分块请求未被拒绝")
        }
        let longHeader = "GET /v1/outbound HTTP/1.1\r\nX-Fill: "
            + String(repeating: "a", count: HTTPAPIRequest.maximumHeaderBytes)
        guard case .rejected(431, _) = HTTPAPIRequest.parse(Data(longHeader.utf8)) else {
            throw Failure(text: "超长请求头未被拒绝")
        }
        let longRequest = Data(repeating: 0, count: HTTPAPIRequest.maximumRequestBytes + 1)
        guard case .rejected(413, _) = HTTPAPIRequest.parse(longRequest) else {
            throw Failure(text: "超长请求未被拒绝")
        }

        let partial = "POST /v1/outbound HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"
        guard case .incomplete = HTTPAPIRequest.parse(Data(partial.utf8)) else {
            throw Failure(text: "未收完的有效请求应等待剩余字节")
        }
        let complete = partial + "c"
        guard case .request(let parsed) = HTTPAPIRequest.parse(Data(complete.utf8)) else {
            throw Failure(text: "有效 HTTP 请求未被解析")
        }
        try expect(parsed.body == Data("abc".utf8), "有效 HTTP 请求正文错误")
    }

    private static func testControllerListenSecurity() throws {
        let local = try ProfileParser.parse("""
        [General]
        http-api = 127.0.0.2:6171
        external-controller-access = [::1]:6170
        """)
        try expect(local.httpAPIKey == "" && local.externalControllerKey == "",
                   "本机回环接口应保留无密钥兼容")
        let omittedHost = try ProfileParser.parse("[General]\nhttp-api = :6171\n")
        try expect(omittedHost.httpAPI?.host == "127.0.0.1" && omittedHost.httpAPIKey == "",
                   "省略 host 应仅监听本机回环")

        for (option, endpoint) in [
            ("http-api", "0.0.0.0:6171"),
            ("http-api", "@192.0.2.1:6171"),
            ("http-api", "localhost:6171"),
            ("external-controller-access", "[::]:6170"),
            ("external-controller", "@[::]:6170")
        ] {
            let text = "[General]\n\(option) = \(endpoint)\n"
            do {
                _ = try ProfileParser.parse(text)
                throw Failure(text: "\(option)=\(endpoint) 无密钥非回环接口未被拒绝")
            } catch let error as ProfileParseError {
                try expect(error.line == 2 && error.localizedDescription.contains("第 2 行")
                           && error.localizedDescription.contains("必须设置密钥"),
                           "无密钥非回环配置应在 UI 错误中指出行号和密钥要求")
            }
        }
        let keyed = try ProfileParser.parse("""
        [General]
        http-api = http-secret@0.0.0.0:6171
        external-controller-access = cli-secret@[::]:6170
        """)
        try expect(keyed.httpAPIKey == "http-secret" && keyed.externalControllerKey == "cli-secret",
                   "有密钥时应允许远程控制接口")
        try expect(!ExternalController.canBind(ListenAddress(host: "0.0.0.0", port: 6171), key: " ")
                   && ExternalController.canBind(ListenAddress(host: "127.0.0.1", port: 6171), key: ""),
                   "直接构造的 Profile 也不能绕过无密钥监听限制")
    }

    private static func expect(_ condition: Bool, _ message: String) throws {
        guard condition else { throw Failure(text: message) }
    }

    private final class RecordingBackend: ExternalControllerBackend {
        var snapshot = ExternalControllerSnapshot(
            mode: .rule, globalPolicy: "DIRECT", groupSelections: [:],
            profile: Profile(), engineStatus: .stopped,
            httpListen: ListenAddress(host: "127.0.0.1", port: 7162),
            socksListen: ListenAddress(host: "127.0.0.1", port: 7163),
            uploaded: 0, downloaded: 0, startedAt: nil, active: [], recent: [],
            systemProxyEnabled: false, enhancedModeEnabled: false)

        func controllerSnapshot() -> ExternalControllerSnapshot { snapshot }
        func controllerSetOutboundMode(_ mode: OutboundMode) { snapshot.mode = mode }
        func controllerSetGlobalPolicy(_ name: String) -> Bool {
            snapshot.globalPolicy = name; return true
        }
        func controllerSetGroupSelection(group: String, policy: String) -> Bool {
            snapshot.groupSelections[group] = policy; return true
        }
        func controllerSetSystemProxy(_ enabled: Bool) { snapshot.systemProxyEnabled = enabled }
        func controllerSetEnhancedMode(_ enabled: Bool) { snapshot.enhancedModeEnabled = enabled }
        func controllerReloadProfile() {}
        func controllerFlushDNS() {}
        func controllerFlushFakeIP() {}
        func controllerKillRequest(id: String) -> Bool { !id.isEmpty }
        func controllerTestGroup(_ name: String) { _ = name }
    }
}
