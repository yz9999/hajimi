import Foundation
import Network
import AppKit
import HajimiCore

/// Lightweight, physical-interface-bound Captive Portal detector.
/// Probes `http://captive.apple.com/hotspot-detect.html` directly over the
/// physical interface (bypassing `utun`) so hotel/airport/campus Wi-Fi login
/// portals are detected even while Enhanced Mode `utun` stays resident.
final class CaptivePortalDetector {
    enum Outcome: Equatable {
        case clear
        case portalRequired(URL)
        case unreachable
    }

    static let shared = CaptivePortalDetector()
    static let probeHost = "captive.apple.com"
    static let probePath = "/hotspot-detect.html"
    static let defaultPortalURL = URL(string: "http://captive.apple.com/hotspot-detect.html")!

    private let queue = DispatchQueue(label: "app.hajimi.captive-portal-detector", qos: .utility)
    private let lock = NSLock()
    private var inFlight = false
    private var lastPortalOpenedAt: TimeInterval = 0

    func checkPhysicalLink(interfaceName: String? = nil,
                           timeout: TimeInterval = 2.5,
                           completion: @escaping (Outcome) -> Void) {
        lock.lock()
        if inFlight {
            lock.unlock()
            return
        }
        inFlight = true
        lock.unlock()

        let parameters = NWParameters.tcp
        if let outbound = ProxyEngine.currentOutboundInterface,
           interfaceName == nil || outbound.name == interfaceName {
            parameters.requiredInterface = outbound
        } else {
            parameters.prohibitedInterfaceTypes = [.other]
        }

        let connection = NWConnection(host: NWEndpoint.Host(Self.probeHost),
                                      port: .http,
                                      using: parameters)
        var finished = false
        let finish: (Outcome) -> Void = { [weak self] outcome in
            guard !finished else { return }
            finished = true
            connection.stateUpdateHandler = nil
            connection.cancel()
            self?.lock.lock()
            self?.inFlight = false
            self?.lock.unlock()
            DispatchQueue.main.async {
                completion(outcome)
            }
        }

        queue.asyncAfter(deadline: .now() + max(0.5, timeout)) {
            finish(.unreachable)
        }

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                let request = "GET \(Self.probePath) HTTP/1.1\r\nHost: \(Self.probeHost)\r\nUser-Agent: CaptiveNetworkSupport-400.0.1 wispr\r\nConnection: close\r\n\r\n"
                connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                    if error != nil {
                        finish(.unreachable)
                        return
                    }
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { data, _, _, receiveError in
                        if receiveError != nil, (data == nil || data?.isEmpty == true) {
                            finish(.unreachable)
                            return
                        }
                        guard let data, !data.isEmpty else {
                            finish(.unreachable)
                            return
                        }
                        finish(Self.classifyHTTPResponse(data))
                    }
                })
            case .failed, .cancelled:
                finish(.unreachable)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func openPortalIfNeeded(_ url: URL, cooldown: TimeInterval = 45.0) -> Bool {
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        if lastPortalOpenedAt > 0, now - lastPortalOpenedAt < cooldown {
            lock.unlock()
            return false
        }
        lastPortalOpenedAt = now
        lock.unlock()
        NSWorkspace.shared.open(url)
        return true
    }

    /// Pure parser for captive portal HTTP responses; zero network I/O.
    static func classifyHTTPResponse(_ data: Data) -> Outcome {
        let text = String(decoding: data.prefix(16_384), as: UTF8.self)
        let separator = text.range(of: "\r\n\r\n") ?? text.range(of: "\n\n")
        let headerBlock = separator.map { String(text[..<$0.lowerBound]) } ?? text
        let bodyBlock = separator.map { String(text[$0.upperBound...]) } ?? ""
        let lines = headerBlock.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard let statusLine = lines.first, statusLine.uppercased().hasPrefix("HTTP/1.") else {
            return .unreachable
        }
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let statusCode = Int(parts[1]) else {
            return .unreachable
        }
        if (300...399).contains(statusCode) {
            for line in lines.dropFirst() {
                let pair = line.split(separator: ":", maxSplits: 1)
                if pair.count == 2, pair[0].trimmingCharacters(in: .whitespaces).lowercased() == "location" {
                    let rawURL = pair[1].trimmingCharacters(in: .whitespacesAndNewlines)
                    if let url = URL(string: rawURL), let scheme = url.scheme?.lowercased(),
                       scheme == "http" || scheme == "https" {
                        return .portalRequired(url)
                    }
                }
            }
            return .portalRequired(defaultPortalURL)
        }
        if statusCode == 200 {
            if bodyBlock.contains("<TITLE>Success</TITLE>") || bodyBlock.contains(">Success<")
                || bodyBlock.trimmingCharacters(in: .whitespacesAndNewlines) == "Success" {
                return .clear
            }
            if !bodyBlock.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return .portalRequired(defaultPortalURL)
            }
        }
        if statusCode == 511 {
            return .portalRequired(defaultPortalURL)
        }
        return .unreachable
    }

    static func selfTest() throws {
        struct Failure: LocalizedError {
            let text: String
            var errorDescription: String? { "CaptivePortalDetector self-test failed: \(text)" }
        }
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        let okResponse = Data("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>".utf8)
        try require(classifyHTTPResponse(okResponse) == .clear, "standard Apple captive Success body was not classified as clear")

        let redirectResponse = Data("HTTP/1.1 302 Found\r\nLocation: http://portal.hotel.example/login?mac=00\r\n\r\n".utf8)
        try require(classifyHTTPResponse(redirectResponse) == .portalRequired(URL(string: "http://portal.hotel.example/login?mac=00")!),
                    "302 captive redirect did not extract login URL")

        let hijack200Response = Data("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Please sign in to Wi-Fi</body></html>".utf8)
        try require(classifyHTTPResponse(hijack200Response) == .portalRequired(defaultPortalURL),
                    "hijacked 200 HTML portal page was not detected")

        let garbage = Data("NOT_HTTP\r\n\r\n".utf8)
        try require(classifyHTTPResponse(garbage) == .unreachable, "malformed response was not classified as unreachable")
    }
}
