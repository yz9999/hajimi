import AppKit
import Network
import HajimiCore
import HajimiUIComponents

final class PolicyCardFlowLayout: NSCollectionViewFlowLayout {
    override func layoutAttributesForElements(in rect: NSRect) -> [NSCollectionViewLayoutAttributes] {
        let attributes = super.layoutAttributesForElements(in: rect).map { $0.copy() as! NSCollectionViewLayoutAttributes }
        for attribute in attributes where attribute.representedElementCategory == .item {
            if let indexPath = attribute.indexPath, let aligned = layoutAttributesForItem(at: indexPath) {
                attribute.frame = aligned.frame
            }
        }
        return attributes
    }

    override func layoutAttributesForItem(at indexPath: IndexPath) -> NSCollectionViewLayoutAttributes? {
        guard let attribute = super.layoutAttributesForItem(at: indexPath)?.copy() as? NSCollectionViewLayoutAttributes,
              let collectionView else { return super.layoutAttributesForItem(at: indexPath) }
        let itemWidth = attribute.frame.width
        let spacing = minimumLineSpacing
        let availableWidth = max(0, collectionView.bounds.width - sectionInset.left - sectionInset.right)
        let columns = max(1, Int(floor((availableWidth + spacing) / (itemWidth + spacing))))
        let column = indexPath.item % columns
        var frame = attribute.frame
        frame.origin.x = sectionInset.left + CGFloat(column) * (itemWidth + spacing)
        attribute.frame = frame
        return attribute
    }
}

final class ContextCollectionView: NSCollectionView {
    var contextMenuProvider: ((IndexPath) -> NSMenu?)?
    private var fittingDocumentFrame = false

    override func layout() {
        if let flow = collectionViewLayout as? NSCollectionViewFlowLayout,
           bounds.width < flow.itemSize.width + flow.sectionInset.left + flow.sectionInset.right {
            return
        }
        super.layout()
        guard !fittingDocumentFrame, let scroll = enclosingScrollView, scroll.documentView === self,
              let collectionViewLayout else { return }
        let naturalHeight = collectionViewLayout.collectionViewContentSize.height
        guard naturalHeight.isFinite else { return }
        let height = max(scroll.contentView.bounds.height, ceil(naturalHeight))
        guard abs(frame.height - height) > 0.5 else { return }
        fittingDocumentFrame = true
        defer { fittingDocumentFrame = false }
        // A direct document retains AppKit's card reuse. Only its height
        // follows the layout; the clip view still owns the available width.
        setFrameSize(NSSize(width: frame.width, height: height))
        let clip = scroll.contentView
        clip.scroll(to: clip.constrainBoundsRect(clip.bounds).origin)
        scroll.reflectScrolledClipView(clip)
    }

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        guard let indexPath = indexPathForItem(at: point) else { return nil }
        selectionIndexPaths = [indexPath]
        return contextMenuProvider?(indexPath)
    }
}

final class PolicySectionHeaderView: NSView {
    static let identifier = NSUserInterfaceItemIdentifier("PolicySectionHeaderView")
    private let accentBar = HajimiSurfaceView(fill: HajimiAppearance.accent, cornerRadius: 2)
    private let titleLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(labelWithString: "")

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        accentBar.translatesAutoresizingMaskIntoConstraints = false
        addSubview(accentBar)

        titleLabel.font = .systemFont(ofSize: 13.5, weight: .semibold)
        detailLabel.font = .systemFont(ofSize: 10.5)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail
        for label in [titleLabel, detailLabel] {
            label.translatesAutoresizingMaskIntoConstraints = false
            addSubview(label)
        }
        NSLayoutConstraint.activate([
            accentBar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6),
            accentBar.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            accentBar.widthAnchor.constraint(equalToConstant: 3.5),
            accentBar.heightAnchor.constraint(equalToConstant: 14),
            titleLabel.leadingAnchor.constraint(equalTo: accentBar.trailingAnchor, constant: 6),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -10),
            titleLabel.topAnchor.constraint(equalTo: topAnchor, constant: 13),
            detailLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            detailLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -10),
            detailLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(title: String, detail: String) {
        titleLabel.stringValue = title
        detailLabel.stringValue = detail
    }
}

enum NodeLatency: Equatable {
    case untested
    case testing
    case queued
    case success(Int)
    case failed
    case unavailable(ProbeScheduler.Failure)

    var text: String {
        switch self {
        case .untested: return "未测试"
        case .testing: return "测试中…"
        case .queued: return "等待测试"
        case .success(let milliseconds): return "\(milliseconds) ms"
        case .failed: return "连接失败"
        case .unavailable(let failure):
            switch failure {
            case .capacityExceeded: return "队列已满"
            case .connectionBudgetExceeded: return "资源限额"
            case .queueWaitExpired: return "排队超时"
            case .requestExpired: return "测试超时"
            case .cancelled: return "已取消"
            }
        }
    }

    var color: NSColor {
        switch self {
        case .untested, .queued: return .tertiaryLabelColor
        case .testing: return .systemBlue
        case .success(let value):
            if value < 180 { return .systemGreen }
            if value < 500 { return .systemOrange }
            return .systemRed
        case .failed, .unavailable: return .systemRed
        }
    }

    var alignedText: String {
        if case .success(let milliseconds) = self {
            let digits = String(milliseconds)
            let padded = String(repeating: "\u{2007}", count: max(0, 3 - digits.count)) + digits
            return "\(padded) ms"
        }
        return text
    }

    var toolTip: String? {
        if case .unavailable(let failure) = self { return failure.localizedDescription }
        return nil
    }

    static func from(error: Error) -> NodeLatency {
        if let failure = error as? ProbeScheduler.Failure { return .unavailable(failure) }
        let value = error as NSError
        if value.domain == NodeConnectionAdmissionError.errorDomain,
           value.code == NodeConnectionAdmissionError.capacityExceeded.errorCode {
            return .unavailable(.connectionBudgetExceeded)
        }
        return .failed
    }
}

final class UDPNodeAddressProbe {
    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var timerSource: DispatchSourceTimer?
    private var cancelled = false

    static func start(addresses: [String], port: UInt16, queue: DispatchQueue,
                      completion: @escaping (Result<Void, Error>) -> Void) -> UDPNodeAddressProbe {
        let probe = UDPNodeAddressProbe()
        probe.begin(addresses: addresses, port: port, queue: queue, completion: completion)
        return probe
    }

    private func begin(addresses: [String], port: UInt16, queue: DispatchQueue,
                       completion: @escaping (Result<Void, Error>) -> Void) {
        guard let first = addresses.first else {
            completion(.failure(NWError.posix(.EHOSTUNREACH)))
            return
        }
        var addr4 = sockaddr_in()
        var addr6 = sockaddr_in6()
        var sockFD: Int32 = -1
        var connectResult: Int32 = -1

        let boundIfIndex: UInt32 = {
            let lower = first.lowercased()
            if lower.hasPrefix("127.") || lower == "::1" || lower == "localhost" { return 0 }
            guard let ifName = ProxyEngine.currentOutboundInterface?.name, !ifName.isEmpty else { return 0 }
            return ifName.withCString { if_nametoindex($0) }
        }()

        if first.withCString({ inet_pton(AF_INET, $0, &addr4.sin_addr) }) == 1 {
            addr4.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr4.sin_family = sa_family_t(AF_INET)
            addr4.sin_port = port.bigEndian
            sockFD = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            if sockFD >= 0 {
                _ = fcntl(sockFD, F_SETFD, FD_CLOEXEC)
                _ = fcntl(sockFD, F_SETFL, fcntl(sockFD, F_GETFL, 0) | O_NONBLOCK)
                if boundIfIndex > 0 {
                    var idx = boundIfIndex
                    _ = setsockopt(sockFD, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
                }
                connectResult = withUnsafePointer(to: &addr4) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(sockFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        } else if first.withCString({ inet_pton(AF_INET6, $0, &addr6.sin6_addr) }) == 1 {
            addr6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr6.sin6_family = sa_family_t(AF_INET6)
            addr6.sin6_port = port.bigEndian
            sockFD = Darwin.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
            if sockFD >= 0 {
                _ = fcntl(sockFD, F_SETFD, FD_CLOEXEC)
                _ = fcntl(sockFD, F_SETFL, fcntl(sockFD, F_GETFL, 0) | O_NONBLOCK)
                if boundIfIndex > 0 {
                    var idx = boundIfIndex
                    _ = setsockopt(sockFD, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size))
                }
                connectResult = withUnsafePointer(to: &addr6) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(sockFD, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
            }
        } else {
            completion(.failure(NWError.posix(.EINVAL)))
            return
        }

        guard sockFD >= 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            completion(.failure(NWError.posix(code)))
            return
        }
        self.fd = sockFD

        if connectResult != 0 && errno != EINPROGRESS {
            let code = POSIXErrorCode(rawValue: errno) ?? .EHOSTUNREACH
            cancel()
            completion(.failure(NWError.posix(code)))
            return
        }

        // Send a 72-byte high-entropy UDP probe frame; if the remote UDP port is
        // closed and returns ICMP Port Unreachable, recv() reports ECONNREFUSED.
        var payload = [UInt8](repeating: 0, count: 72)
        for i in 0..<payload.count { payload[i] = UInt8.random(in: 0...255) }
        let sent = payload.withUnsafeBytes { ptr in
            Darwin.send(sockFD, ptr.baseAddress, ptr.count, 0)
        }
        if sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
            let code = POSIXErrorCode(rawValue: errno) ?? .ECONNREFUSED
            cancel()
            completion(.failure(NWError.posix(code)))
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: sockFD, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, !self.cancelled, self.fd >= 0 else { return }
            var buf = [UInt8](repeating: 0, count: 256)
            let n = Darwin.recv(self.fd, &buf, buf.count, 0)
            if n >= 0 {
                self.cancel()
                completion(.success(()))
            } else if errno != EAGAIN && errno != EWOULDBLOCK {
                let code = POSIXErrorCode(rawValue: errno) ?? .ECONNREFUSED
                self.cancel()
                completion(.failure(NWError.posix(code)))
            }
        }
        self.readSource = source
        source.resume()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(95))
        timer.setEventHandler { [weak self] in
            guard let self, !self.cancelled, self.fd >= 0 else { return }
            var err: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            if getsockopt(self.fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0, err != 0 {
                let code = POSIXErrorCode(rawValue: err) ?? .ECONNREFUSED
                self.cancel()
                completion(.failure(NWError.posix(code)))
                return
            }
            self.cancel()
            completion(.success(()))
        }
        self.timerSource = timer
        timer.resume()
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        timerSource?.cancel()
        timerSource = nil
        readSource?.cancel()
        readSource = nil
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }
}

final class TCPNodeLatencyProbe {
    static let userScheduler = ProbeScheduler(maximumActive: 24, maximumQueued: 1024)

    static func usesUDPTransport(_ policy: ProxyPolicy) -> Bool {
        let type = (policy.adapterType ?? "").lowercased()
        if ["hysteria", "hysteria2", "tuic", "wireguard"].contains(type) { return true }
        if type == "mieru" {
            let transport = (policy.parameters["transport"] ?? policy.parameters["network"] ?? "TCP").uppercased()
            return transport == "UDP"
        }
        if type == "trusttunnel" {
            let quic = (policy.parameters["quic"] ?? "").lowercased()
            return ["true", "1", "yes", "on"].contains(quic)
        }
        let network = (policy.parameters["network"] ?? "").lowercased()
        return network == "kcp" || network == "mkcp"
    }

    @discardableResult
    static func measure(host: String, port: UInt16, udp: Bool = false, timeout: TimeInterval = 4,
                        scheduler: ProbeScheduler = userScheduler,
                        completion: @escaping (Result<Int, Error>) -> Void) -> ProbeScheduler.Ticket {
        let operation = Operation(host: host, port: port, udp: udp, completion: completion)
        return scheduler.submit(timeout: timeout, callbackQueue: .main, start: operation.start) {
            completion(.failure($0))
        }
    }

    /// All resource state belongs to the admitted lease's serial lane. Queue
    /// waiting is deliberately excluded from the displayed network latency.
    private final class Operation {
        let host: String
        let port: UInt16
        let udp: Bool
        let completion: (Result<Int, Error>) -> Void
        var connection: NodeTCPAddressProbe?
        var udpProbe: UDPNodeAddressProbe?
        var resolverID: UUID?
        var finished = false
        var lease: ProbeScheduler.Lease?
        var started: UInt64 = 0

        init(host: String, port: UInt16, udp: Bool, completion: @escaping (Result<Int, Error>) -> Void) {
            self.host = host; self.port = port; self.udp = udp; self.completion = completion
        }

        func start(_ lease: ProbeScheduler.Lease) {
            self.lease = lease
            guard lease.setCancellationHandler({ [self] in cancelResources() }) else { return }
            started = DispatchTime.now().uptimeNanoseconds
            guard port != 0 else {
                finish(.failure(NWError.posix(.EINVAL))); return
            }
            resolverID = SecureDNSHostResolver.shared.resolve(host: host, queue: lease.queue) { [self] result in
                resolverID = nil
                guard !finished, lease.isActive else { cancelResources(); return }
                switch result {
                case .failure(let error): finish(.failure(error))
                case .success(let addresses):
                    guard !addresses.isEmpty else {
                        finish(.failure(NWError.posix(.EHOSTUNREACH))); return
                    }
                    if udp {
                        udpProbe = UDPNodeAddressProbe.start(addresses: addresses, port: port, queue: lease.queue) { [self] udpResult in
                            guard !finished else { return }
                            switch udpResult {
                            case .success:
                                let nowNs = DispatchTime.now().uptimeNanoseconds; let elapsed = nowNs > started ? (nowNs - started) : 0
                                finish(.success(max(1, Int(Double(elapsed) / 1_000_000))))
                            case .failure(let error):
                                finish(.failure(error))
                            }
                        }
                        return
                    }
                    connection = NodeTCPAddressProbe.start(addresses: addresses, port: port, queue: lease.queue,
                                                           deadline: lease.deadline.uptimeNanoseconds,
                                                           permitted: { lease.isActive }) { [self] result in
                        guard !finished else { return }
                        switch result {
                        case .success:
                            let nowNs = DispatchTime.now().uptimeNanoseconds; let elapsed = nowNs > started ? (nowNs - started) : 0
                            finish(.success(max(1, Int(Double(elapsed) / 1_000_000))))
                        case .failure(let error): finish(.failure(error))
                        }
                    }
                }
            }
        }

        func cancelResources() {
            finished = true
            connection?.cancel()
            connection = nil
            udpProbe?.cancel()
            udpProbe = nil
            if let resolverID { SecureDNSHostResolver.shared.cancel(resolverID) }
            resolverID = nil
        }

        func finish(_ result: Result<Int, Error>) {
            guard !finished else { return }
            cancelResources()
            guard lease?.complete() == true else { return }
            DispatchQueue.main.async { [completion] in completion(result) }
        }
    }
}

enum NodeLatencyClassificationSelfTest {
    private struct Failure: LocalizedError {
        let text: String
        var errorDescription: String? { "节点测速结果自检失败：\(text)" }
    }

    static func run() throws {
        func require(_ condition: Bool, _ text: String) throws {
            guard condition else { throw Failure(text: text) }
        }
        try require(NodeLatency.from(error: ProbeScheduler.Failure.queueWaitExpired) == .unavailable(.queueWaitExpired),
                    "排队超时被误判为连接失败")
        try require(NodeLatency.from(error: NodeConnectionAdmissionError.capacityExceeded) == .unavailable(.connectionBudgetExceeded),
                    "节点资源限额被误判为连接失败")
        let bridged = NSError(domain: NodeConnectionAdmissionError.errorDomain,
                              code: NodeConnectionAdmissionError.capacityExceeded.errorCode)
        try require(NodeLatency.from(error: bridged) == .unavailable(.connectionBudgetExceeded),
                    "桥接资源错误丢失限额分类")
        try require(NodeLatency.from(error: NWError.posix(.ECONNREFUSED)) == .failed,
                    "真正的连接错误没有保留失败语义")
    }
}

private func protocolAccentColor(for rawType: String) -> NSColor {
    switch rawType.lowercased() {
    case "vless", "vmess", "mieru": return .systemIndigo
    case "trojan", "anytls", "trusttunnel": return HajimiAppearance.accentText
    case "hysteria", "hysteria2", "tuic": return .systemBlue
    case "ss", "ssr", "snell", "sudoku": return .systemPurple
    case "wireguard", "ssh": return .systemTeal
    default: return .secondaryLabelColor
    }
}

private final class PolicyCardSurface: NSView {
    var active = false { didSet { if active != oldValue { updateColors() } } }
    var selected = false { didSet { if selected != oldValue { updateColors() } } }
    private var hovered = false
    private var hoverArea: NSTrackingArea?
    private let topHighlightLayer = CALayer()
    private let activeBarLayer = CALayer()

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        layer?.cornerRadius = 12
        layer?.cornerCurve = .continuous
        activeBarLayer.cornerRadius = 1.5
        activeBarLayer.cornerCurve = .continuous
        layer?.addSublayer(topHighlightLayer)
        layer?.addSublayer(activeBarLayer)
        updateColors()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func layout() {
        super.layout()
        let y = isFlipped ? 1.0 : max(0, bounds.height - 1.5)
        topHighlightLayer.frame = CGRect(x: 9, y: y, width: max(0, bounds.width - 18), height: 1.0)
        activeBarLayer.frame = CGRect(x: 3.5, y: 12, width: 3.0, height: max(0, bounds.height - 24))
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverArea { removeTrackingArea(hoverArea) }
        let area = NSTrackingArea(rect: .zero,
            options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect], owner: self, userInfo: nil)
        addTrackingArea(area)
        hoverArea = area
    }

    override func mouseEntered(with event: NSEvent) { hovered = true; updateColors() }
    override func mouseExited(with event: NSEvent) { hovered = false; updateColors() }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateColors()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil { hovered = false }
        updateColors()
    }

    private func updateColors() {
        activeBarLayer.isHidden = !active
        effectiveAppearance.performAsCurrentDrawingAppearance {
            topHighlightLayer.backgroundColor = HajimiAppearance.specularHighlight.cgColor
            activeBarLayer.backgroundColor = HajimiAppearance.accent.cgColor
            layer?.backgroundColor = (active || selected ? HajimiAppearance.selection
                : hovered ? HajimiAppearance.elevatedPanel : HajimiAppearance.panel).cgColor
            layer?.borderColor = (active ? HajimiAppearance.accent.withAlphaComponent(0.82)
                : selected ? HajimiAppearance.accent.withAlphaComponent(0.60)
                : hovered ? HajimiAppearance.accent.withAlphaComponent(0.38)
                : HajimiAppearance.border).cgColor
            layer?.borderWidth = (active || selected) ? 1.4 : 1.0
        }
    }
}

private final class PolicyAddButton: NSButton {
    private var hovered = false
    private var hoverArea: NSTrackingArea?

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverArea { removeTrackingArea(hoverArea) }
        let area = NSTrackingArea(rect: .zero,
            options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect], owner: self, userInfo: nil)
        addTrackingArea(area)
        hoverArea = area
    }

    override func mouseEntered(with event: NSEvent) { hovered = true; updateColors() }
    override func mouseExited(with event: NSEvent) { hovered = false; updateColors() }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateColors()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil { hovered = false }
        updateColors()
    }

    private func updateColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = (hovered ? HajimiAppearance.selection : HajimiAppearance.mutedPanel).cgColor
            layer?.borderColor = (hovered ? HajimiAppearance.accent.withAlphaComponent(0.45) : HajimiAppearance.border).cgColor
            layer?.borderWidth = hovered ? 1.0 : 0.8
        }
    }
}

private func policyLatencyColor(_ latency: NodeLatency) -> NSColor {
    if case .success(let value) = latency, value < 180 { return HajimiAppearance.accentText }
    return latency.color
}

final class ProxyNodeCellView: NSTableCellView {
    private let card = PolicyCardSurface()
    private let iconBackground = NSView()
    private let icon = NSImageView()
    private let nameLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(labelWithString: "")
    private let latencyLabel = NSTextField(labelWithString: "")
    private let latencyBackdrop = NSView()
    private let useButton = NSButton(title: "使用", target: nil, action: nil)
    private var onUse: (() -> Void)?
    private var iconTint = NSColor.systemBlue
    private var latencyTint = NSColor.tertiaryLabelColor

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        card.translatesAutoresizingMaskIntoConstraints = false
        addSubview(card)

        iconBackground.translatesAutoresizingMaskIntoConstraints = false
        iconBackground.wantsLayer = true
        iconBackground.layer?.cornerRadius = 10
        iconBackground.layer?.cornerCurve = .continuous
        card.addSubview(iconBackground)
        icon.image = NSImage(systemSymbolName: "point.3.connected.trianglepath.dotted",
                             accessibilityDescription: "节点")
        icon.symbolConfiguration = .init(pointSize: 16, weight: .semibold)
        icon.translatesAutoresizingMaskIntoConstraints = false
        iconBackground.addSubview(icon)

        nameLabel.font = .systemFont(ofSize: 13.5, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        detailLabel.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingMiddle
        let labels = NSStackView(views: [nameLabel, detailLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 4
        labels.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(labels)

        latencyBackdrop.translatesAutoresizingMaskIntoConstraints = false
        latencyBackdrop.wantsLayer = true
        latencyBackdrop.layer?.cornerRadius = 7
        latencyBackdrop.layer?.cornerCurve = .continuous
        card.addSubview(latencyBackdrop)
        latencyLabel.font = .monospacedDigitSystemFont(ofSize: 10.5, weight: .semibold)
        latencyLabel.alignment = .center
        latencyLabel.translatesAutoresizingMaskIntoConstraints = false
        latencyBackdrop.addSubview(latencyLabel)

        useButton.bezelStyle = .rounded
        useButton.controlSize = .small
        useButton.font = .systemFont(ofSize: 11, weight: .medium)
        useButton.contentTintColor = HajimiAppearance.accentText
        useButton.target = self
        useButton.action = #selector(usePressed)
        useButton.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(useButton)

        NSLayoutConstraint.activate([
            card.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            card.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            card.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            card.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            iconBackground.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 14),
            iconBackground.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            iconBackground.widthAnchor.constraint(equalToConstant: 36),
            iconBackground.heightAnchor.constraint(equalToConstant: 36),
            icon.centerXAnchor.constraint(equalTo: iconBackground.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: iconBackground.centerYAnchor),
            labels.leadingAnchor.constraint(equalTo: iconBackground.trailingAnchor, constant: 13),
            labels.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            labels.trailingAnchor.constraint(lessThanOrEqualTo: latencyBackdrop.leadingAnchor, constant: -12),
            latencyBackdrop.trailingAnchor.constraint(equalTo: useButton.leadingAnchor, constant: -10),
            latencyBackdrop.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            latencyBackdrop.widthAnchor.constraint(equalToConstant: 78),
            latencyBackdrop.heightAnchor.constraint(equalToConstant: 24),
            latencyLabel.leadingAnchor.constraint(equalTo: latencyBackdrop.leadingAnchor, constant: 4),
            latencyLabel.trailingAnchor.constraint(equalTo: latencyBackdrop.trailingAnchor, constant: -4),
            latencyLabel.centerYAnchor.constraint(equalTo: latencyBackdrop.centerYAnchor),
            useButton.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -13),
            useButton.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            useButton.widthAnchor.constraint(equalToConstant: 58)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var backgroundStyle: NSView.BackgroundStyle {
        didSet { card.selected = backgroundStyle == .emphasized }
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateBadgeColors()
    }

    private func updateBadgeColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            iconBackground.layer?.backgroundColor = iconTint.withAlphaComponent(0.13).cgColor
            iconBackground.layer?.borderWidth = 1
            iconBackground.layer?.borderColor = iconTint.withAlphaComponent(0.22).cgColor
            latencyBackdrop.layer?.backgroundColor = latencyTint.withAlphaComponent(0.12).cgColor
        }
        icon.contentTintColor = iconTint
    }

    func configure(policy: ProxyPolicy, latency: NodeLatency, isActive: Bool,
                   onUse: @escaping () -> Void) {
        nameLabel.stringValue = policy.name
        let portText = policy.port.map { String($0) } ?? "—"
        let endpoint = policy.host.map { "\($0):\(portText)" } ?? "内建策略"
        if policy.skipsCertificateVerification {
            detailLabel.stringValue = "\(endpoint)  ·  跳过证书验证"
            detailLabel.textColor = .systemOrange
            detailLabel.toolTip = SkipCertificateWarning.headline
        } else {
            detailLabel.stringValue = endpoint
            detailLabel.textColor = .secondaryLabelColor
            detailLabel.toolTip = endpoint
        }
        latencyLabel.stringValue = "● " + latency.alignedText
        latencyLabel.textColor = policyLatencyColor(latency)
        latencyLabel.toolTip = latency.toolTip
        useButton.title = isActive ? "使用中" : "使用"
        useButton.isEnabled = !isActive
        self.onUse = onUse

        let palette: [NSColor] = [.systemIndigo, .systemBlue, .systemPurple, .systemTeal,
                                  .systemPink, .systemOrange]
        let hash = policy.name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0x7fffffff }
        iconTint = isActive ? HajimiAppearance.accent : palette[hash % palette.count]
        latencyTint = policyLatencyColor(latency)
        card.active = isActive
        updateBadgeColors()
    }

    @objc private func usePressed() { onUse?() }
}

final class PolicyGroupCellView: NSTableCellView {
    private let card = PolicyCardSurface()
    private let nameLabel = NSTextField(labelWithString: "")
    private let kindLabel = NSTextField(labelWithString: "")
    private let popup = NSPopUpButton()
    private var members: [String] = []
    private var onSelection: ((String?) -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        card.translatesAutoresizingMaskIntoConstraints = false
        addSubview(card)

        nameLabel.font = .systemFont(ofSize: 13.5, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        kindLabel.font = .systemFont(ofSize: 11)
        kindLabel.textColor = .secondaryLabelColor
        let labels = NSStackView(views: [nameLabel, kindLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 4
        labels.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(labels)

        popup.controlSize = .small
        popup.font = .systemFont(ofSize: 11)
        popup.target = self
        popup.action = #selector(selectionChanged)
        popup.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(popup)
        NSLayoutConstraint.activate([
            card.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            card.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            card.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            card.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            labels.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 15),
            labels.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            labels.trailingAnchor.constraint(lessThanOrEqualTo: popup.leadingAnchor, constant: -10),
            popup.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -14),
            popup.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            popup.widthAnchor.constraint(greaterThanOrEqualToConstant: 145)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var backgroundStyle: NSView.BackgroundStyle {
        didSet { card.selected = backgroundStyle == .emphasized }
    }

    func configure(group: PolicyGroup, selected: String?,
                   onSelection: @escaping (String?) -> Void) {
        nameLabel.stringValue = group.name
        switch group.kind {
        case .select: kindLabel.stringValue = "手动选择 · \(group.members.count) 个成员"
        case .loadBalance: kindLabel.stringValue = "负载均衡 · 可临时固定成员"
        case .urlTest: kindLabel.stringValue = "URL 测试 · 可临时固定成员"
        case .fallback: kindLabel.stringValue = "故障转移 · 可临时固定成员"
        case .smart: kindLabel.stringValue = "Smart · 按延迟自动选择"
        case .subnet: kindLabel.stringValue = "子网 · 可临时固定成员"
        }
        members = group.members
        popup.removeAllItems()
        popup.addItem(withTitle: group.kind == .select ? "配置默认" : "自动（按组策略）")
        popup.menu?.items.first?.representedObject = NSNull()
        for member in members {
            popup.addItem(withTitle: member)
            popup.lastItem?.representedObject = member
        }
        if let selected, let index = members.firstIndex(of: selected) {
            popup.selectItem(at: index + 1)
        } else {
            popup.selectItem(at: 0)
        }
        popup.isEnabled = !members.isEmpty
        self.onSelection = onSelection
    }

    @objc private func selectionChanged() {
        guard popup.indexOfSelectedItem > 0 else { onSelection?(nil); return }
        onSelection?(popup.selectedItem?.representedObject as? String)
    }
}

final class ProxyCardCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("ProxyCardCollectionItem")

    private let nameLabel = NSTextField(labelWithString: "")
    private let latencyBadge = NSView()
    private let latencyLabel = NSTextField(labelWithString: "")
    private let endpointLabel = NSTextField(labelWithString: "")
    private var latencyColor = NSColor.tertiaryLabelColor
    private var onEdit: (() -> Void)?

    override var isSelected: Bool {
        didSet { if isViewLoaded { (view as? PolicyCardSurface)?.selected = isSelected } }
    }

    override func loadView() {
        let card = PolicyCardSurface()
        card.selected = isSelected
        view = card

        nameLabel.font = .systemFont(ofSize: 13.0, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(nameLabel)

        endpointLabel.font = .monospacedSystemFont(ofSize: 10.0, weight: .regular)
        endpointLabel.textColor = .tertiaryLabelColor
        endpointLabel.lineBreakMode = .byTruncatingMiddle
        endpointLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(endpointLabel)

        latencyBadge.wantsLayer = true
        latencyBadge.layer?.cornerRadius = 5.0
        latencyBadge.layer?.cornerCurve = .continuous
        latencyBadge.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(latencyBadge)

        latencyLabel.font = .monospacedDigitSystemFont(ofSize: 10.0, weight: .semibold)
        latencyLabel.alignment = .left
        latencyLabel.translatesAutoresizingMaskIntoConstraints = false
        latencyBadge.addSubview(latencyLabel)

        let doubleClick = NSClickGestureRecognizer(target: self, action: #selector(doubleClicked))
        doubleClick.numberOfClicksRequired = 2
        card.addGestureRecognizer(doubleClick)

        NSLayoutConstraint.activate([
            nameLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            nameLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -12),
            nameLabel.topAnchor.constraint(equalTo: card.topAnchor, constant: 11),
            endpointLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            endpointLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -12),
            endpointLabel.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 3.5),
            latencyBadge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            latencyBadge.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -9),
            latencyBadge.widthAnchor.constraint(greaterThanOrEqualToConstant: 70),
            latencyLabel.leadingAnchor.constraint(equalTo: latencyBadge.leadingAnchor, constant: 6),
            latencyLabel.trailingAnchor.constraint(equalTo: latencyBadge.trailingAnchor, constant: -6),
            latencyLabel.topAnchor.constraint(equalTo: latencyBadge.topAnchor, constant: 2),
            latencyLabel.bottomAnchor.constraint(equalTo: latencyBadge.bottomAnchor, constant: -2)
        ])
    }

    func configure(policy: ProxyPolicy, latency: NodeLatency, active: Bool,
                   onEdit: @escaping () -> Void) {
        nameLabel.stringValue = policy.name
        let portText = policy.port.map { String($0) } ?? "—"
        let baseEndpoint = policy.host.map { "\($0):\(portText)" } ?? ""
        if policy.skipsCertificateVerification {
            endpointLabel.stringValue = baseEndpoint.isEmpty ? "跳过证书" : "\(baseEndpoint) · 跳过证书"
            endpointLabel.textColor = .systemOrange
            endpointLabel.toolTip = SkipCertificateWarning.headline
        } else {
            endpointLabel.stringValue = baseEndpoint
            endpointLabel.textColor = .tertiaryLabelColor
            endpointLabel.toolTip = baseEndpoint
        }
        latencyColor = policyLatencyColor(latency)
        latencyLabel.stringValue = "● " + latency.alignedText
        latencyLabel.textColor = latencyColor
        latencyLabel.toolTip = latency.toolTip
        self.onEdit = onEdit
        (view as? PolicyCardSurface)?.active = active
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            latencyBadge.layer?.backgroundColor = latencyColor.withAlphaComponent(0.10).cgColor
        }
    }

    @objc private func doubleClicked() { onEdit?() }
}

final class AddProxyCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("AddProxyCollectionItem")
    private var onAdd: (() -> Void)?

    override func loadView() {
        let button = PolicyAddButton(title: "新增节点", target: self, action: #selector(addPressed))
        button.image = NSImage(systemSymbolName: "plus.circle.fill", accessibilityDescription: "新增节点")
        button.imagePosition = .imageLeft
        button.alignment = .center
        button.imageHugsTitle = true
        button.font = .systemFont(ofSize: 11.5, weight: .semibold)
        button.contentTintColor = HajimiAppearance.accentText
        button.bezelStyle = .regularSquare
        button.isBordered = false
        button.wantsLayer = true
        button.layer?.cornerRadius = 12
        button.layer?.cornerCurve = .continuous
        button.layer?.borderWidth = 0.8
        button.layer?.borderColor = HajimiAppearance.border.cgColor
        button.layer?.backgroundColor = HajimiAppearance.mutedPanel.cgColor
        view = button
    }

    func configure(onAdd: @escaping () -> Void) { self.onAdd = onAdd }
    @objc private func addPressed() { onAdd?() }
}

final class AddGroupCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("AddGroupCollectionItem")
    private var onAdd: (() -> Void)?

    override func loadView() {
        let button = PolicyAddButton(title: "新增策略组", target: self, action: #selector(addPressed))
        button.image = NSImage(systemSymbolName: "plus.circle.fill", accessibilityDescription: "新增策略组")
        button.imagePosition = .imageLeft
        button.alignment = .center
        button.imageHugsTitle = true
        button.font = .systemFont(ofSize: 11.5, weight: .semibold)
        button.contentTintColor = HajimiAppearance.accentText
        button.bezelStyle = .regularSquare
        button.isBordered = false
        button.wantsLayer = true
        button.layer?.cornerRadius = 12
        button.layer?.cornerCurve = .continuous
        button.layer?.borderWidth = 0.8
        button.layer?.borderColor = HajimiAppearance.border.cgColor
        button.layer?.backgroundColor = HajimiAppearance.mutedPanel.cgColor
        view = button
    }

    func configure(onAdd: @escaping () -> Void) { self.onAdd = onAdd }
    @objc private func addPressed() { onAdd?() }
}

final class GroupCardCollectionItem: NSCollectionViewItem {
    static let identifier = NSUserInterfaceItemIdentifier("GroupCardCollectionItem")
    private let kindBadge = NSView()
    private let kindLabel = NSTextField(labelWithString: "")
    private let editButton = NSButton()
    private let nameLabel = NSTextField(labelWithString: "")
    private let popup = NSPopUpButton()
    private var onSelection: ((String?) -> Void)?
    private var onEdit: (() -> Void)?
    private var isConfiguring = false

    override var isSelected: Bool {
        didSet { if isViewLoaded { (view as? PolicyCardSurface)?.selected = isSelected } }
    }

    override func loadView() {
        let card = PolicyCardSurface()
        card.selected = isSelected
        view = card

        kindBadge.wantsLayer = true
        kindBadge.layer?.cornerRadius = 4.5
        kindBadge.layer?.cornerCurve = .continuous
        kindBadge.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(kindBadge)

        kindLabel.font = .systemFont(ofSize: 9.0, weight: .bold)
        kindLabel.textColor = HajimiAppearance.accentText
        kindLabel.translatesAutoresizingMaskIntoConstraints = false
        kindBadge.addSubview(kindLabel)

        editButton.bezelStyle = .inline
        editButton.isBordered = false
        editButton.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: "策略组设置")
        editButton.symbolConfiguration = .init(pointSize: 10.5, weight: .semibold)
        editButton.contentTintColor = .secondaryLabelColor
        editButton.toolTip = "策略组设置"
        editButton.target = self
        editButton.action = #selector(editPressed)
        editButton.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(editButton)

        nameLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(nameLabel)

        popup.controlSize = .small
        popup.font = .systemFont(ofSize: 11)
        popup.target = self
        popup.action = #selector(selectionChanged)
        popup.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(popup)

        let doubleClick = NSClickGestureRecognizer(target: self, action: #selector(editPressed))
        doubleClick.numberOfClicksRequired = 2
        card.addGestureRecognizer(doubleClick)

        NSLayoutConstraint.activate([
            kindBadge.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            kindBadge.trailingAnchor.constraint(lessThanOrEqualTo: editButton.leadingAnchor, constant: -6),
            kindBadge.topAnchor.constraint(equalTo: card.topAnchor, constant: 8),
            kindLabel.leadingAnchor.constraint(equalTo: kindBadge.leadingAnchor, constant: 5),
            kindLabel.trailingAnchor.constraint(equalTo: kindBadge.trailingAnchor, constant: -5),
            kindLabel.topAnchor.constraint(equalTo: kindBadge.topAnchor, constant: 1.5),
            kindLabel.bottomAnchor.constraint(equalTo: kindBadge.bottomAnchor, constant: -1.5),
            editButton.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -10),
            editButton.centerYAnchor.constraint(equalTo: kindBadge.centerYAnchor),
            editButton.widthAnchor.constraint(equalToConstant: 18),
            editButton.heightAnchor.constraint(equalToConstant: 18),
            nameLabel.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 12),
            nameLabel.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -12),
            nameLabel.topAnchor.constraint(equalTo: kindBadge.bottomAnchor, constant: 4),
            popup.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 9),
            popup.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -9),
            popup.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -9)
        ])
    }

    func configure(group: PolicyGroup, selected: String?,
                   onEdit: (() -> Void)? = nil,
                   onSelection: @escaping (String?) -> Void) {
        isConfiguring = true
        defer { isConfiguring = false }
        let kindTint: NSColor
        let statusSuffix = group.showsInStatusBar ? "" : " · 栏隐"
        switch group.kind {
        case .select:
            kindLabel.stringValue = "手动选择 · \(group.members.count)\(statusSuffix)"
            kindTint = HajimiAppearance.accentText
        case .loadBalance:
            kindLabel.stringValue = "负载均衡 · \(group.members.count)\(statusSuffix)"
            kindTint = .systemIndigo
        case .urlTest:
            kindLabel.stringValue = "URL 测速 · \(group.members.count)\(statusSuffix)"
            kindTint = .systemBlue
        case .fallback:
            kindLabel.stringValue = "故障转移 · \(group.members.count)\(statusSuffix)"
            kindTint = .systemOrange
        case .smart:
            kindLabel.stringValue = "Smart · \(group.members.count)\(statusSuffix)"
            kindTint = .systemPurple
        case .subnet:
            kindLabel.stringValue = "子网策略 · \(group.members.count)\(statusSuffix)"
            kindTint = .systemTeal
        }
        kindLabel.textColor = kindTint
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            kindBadge.layer?.backgroundColor = kindTint.withAlphaComponent(0.11).cgColor
        }
        nameLabel.stringValue = group.name
        popup.removeAllItems()
        popup.addItem(withTitle: group.kind == .select ? "配置默认" : "自动（按组策略）")
        popup.menu?.items.first?.representedObject = NSNull()
        for member in group.members {
            popup.addItem(withTitle: member)
            popup.lastItem?.representedObject = member
        }
        if let selected, let index = group.members.firstIndex(of: selected) {
            popup.selectItem(at: index + 1)
        } else {
            popup.selectItem(at: 0)
        }
        popup.isEnabled = !group.members.isEmpty
        self.onEdit = onEdit
        self.onSelection = onSelection
    }

    @objc private func editPressed() { onEdit?() }

    @objc private func selectionChanged() {
        guard !isConfiguring else { return }
        if popup.indexOfSelectedItem <= 0 { onSelection?(nil) }
        else { onSelection?(popup.selectedItem?.representedObject as? String) }
    }
}

final class ProxyEditorSheetController: NSWindowController {
    private let originalName: String?
    private let unavailableNames: Set<String>
    private let nameField = NSTextField()
    private let typePopup = NSPopUpButton()
    private let hostField = NSTextField()
    private let portField = NSTextField()
    private let parametersView = NSTextView()
    private let helpLabel = NSTextField(wrappingLabelWithString: "")
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let commit: (SurgeProxyDraft) throws -> Void

    private static let types: [(String, String)] = [
        ("HTTP", "http"), ("HTTPS", "https"), ("SOCKS5", "socks5"),
        ("SOCKS5 TLS", "socks5-tls"), ("Shadowsocks", "ss"),
        ("ShadowsocksR", "ssr"), ("Snell", "snell"), ("VMess", "vmess"),
        ("VLESS", "vless"), ("Trojan", "trojan"), ("AnyTLS", "anytls"),
        ("Sudoku", "sudoku"), ("Mieru", "mieru"), ("TrustTunnel", "trusttunnel"),
        ("Hysteria", "hysteria"), ("Hysteria 2", "hysteria2"),
        ("TUIC", "tuic"), ("SSH", "ssh"), ("WireGuard", "wireguard")
    ]

    init(draft: SurgeProxyDraft?, isNew: Bool = false, unavailableNames: Set<String>,
         commit: @escaping (SurgeProxyDraft) throws -> Void) {
        originalName = isNew ? nil : draft?.name
        self.unavailableNames = unavailableNames
        self.commit = commit
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 620, height: 610),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = isNew || draft == nil ? "新增代理节点" : "编辑代理节点"
        super.init(window: panel)
        buildUI(draft: draft, isNew: isNew)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(draft: SurgeProxyDraft?, isNew: Bool) {
        guard let window else { return }
        let root = HajimiSurfaceView(fill: HajimiAppearance.workspace, cornerRadius: 0)
        root.frame = window.contentView?.frame ?? NSRect(x: 0, y: 0, width: 620, height: 610)
        window.contentView = root

        let adding = isNew || draft == nil
        let eyebrow = HajimiAppearance.pillBadge(text: "PROXY NODE", fontSize: 9.5)
        let title = NSTextField(labelWithString: adding ? "添加节点" : "节点设置")
        title.font = .systemFont(ofSize: 21, weight: .bold)
        let subtitle = NSTextField(labelWithString: "直接写入 Surge [Proxy]，保存后立即热重载")
        subtitle.font = .systemFont(ofSize: 11.5)
        subtitle.textColor = .secondaryLabelColor
        let heading = NSStackView(views: [eyebrow, title, subtitle])
        heading.orientation = .vertical
        heading.alignment = .leading
        heading.spacing = 4
        heading.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(heading)

        nameField.placeholderString = "例如：东京 01"
        nameField.stringValue = draft?.name ?? ""
        typePopup.target = self
        typePopup.action = #selector(typeChanged)
        for item in Self.types {
            typePopup.addItem(withTitle: item.0)
            typePopup.lastItem?.representedObject = item.1
        }
        if let type = draft?.type,
           let index = Self.types.firstIndex(where: { $0.1 == type.lowercased() }) {
            typePopup.selectItem(at: index)
        } else {
            typePopup.selectItem(at: Self.types.firstIndex(where: { $0.1 == "vmess" }) ?? 0)
        }
        hostField.placeholderString = "server.example.com 或 IPv6"
        hostField.stringValue = draft?.host ?? ""
        portField.placeholderString = "443"
        portField.stringValue = draft.map { String($0.port) } ?? "443"

        let grid = NSGridView(views: [
            [formLabel("名称"), nameField],
            [formLabel("协议"), typePopup],
            [formLabel("服务器"), hostField],
            [formLabel("端口"), portField]
        ])
        grid.rowSpacing = 10
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 0).width = 70
        grid.column(at: 1).xPlacement = .fill
        grid.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(grid)

        let parameterTitle = NSTextField(labelWithString: "协议参数")
        parameterTitle.font = .systemFont(ofSize: 12.5, weight: .semibold)
        let template = NSButton(title: "填入参数模板", target: self, action: #selector(insertTemplate))
        template.controlSize = .small
        template.bezelStyle = .rounded
        let parameterHeader = NSStackView(views: [parameterTitle, NSView(), template])
        parameterHeader.orientation = .horizontal
        parameterHeader.alignment = .centerY
        parameterHeader.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(parameterHeader)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.wantsLayer = true
        scroll.layer?.cornerRadius = 8
        scroll.layer?.cornerCurve = .continuous
        scroll.translatesAutoresizingMaskIntoConstraints = false
        parametersView.isRichText = false
        parametersView.isAutomaticQuoteSubstitutionEnabled = false
        parametersView.isAutomaticDashSubstitutionEnabled = false
        parametersView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        parametersView.textContainerInset = NSSize(width: 8, height: 8)
        parametersView.string = draft.map { parameterText($0.parameters) } ?? ""
        scroll.documentView = parametersView
        root.addSubview(scroll)

        helpLabel.font = .systemFont(ofSize: 10.5)
        helpLabel.textColor = .secondaryLabelColor
        helpLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(helpLabel)
        errorLabel.font = .systemFont(ofSize: 11, weight: .medium)
        errorLabel.textColor = .systemRed
        errorLabel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(errorLabel)

        let cancel = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        cancel.bezelStyle = .rounded
        let save = NSButton(title: adding ? "添加并应用" : "保存并应用",
                            target: self, action: #selector(savePressed))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"
        let buttons = NSStackView(views: [cancel, save])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        buttons.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(buttons)

        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            heading.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            heading.topAnchor.constraint(equalTo: root.topAnchor, constant: 22),
            grid.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            grid.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            grid.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 18),
            parameterHeader.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            parameterHeader.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            parameterHeader.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 18),
            scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 26),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            scroll.topAnchor.constraint(equalTo: parameterHeader.bottomAnchor, constant: 7),
            scroll.heightAnchor.constraint(equalToConstant: 162),
            helpLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 27),
            helpLabel.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -27),
            helpLabel.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 7),
            errorLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 27),
            errorLabel.trailingAnchor.constraint(equalTo: buttons.leadingAnchor, constant: -12),
            errorLabel.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -26),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -22)
        ])
        updateHelp()
    }

    private func formLabel(_ value: String) -> NSTextField {
        let label = NSTextField(labelWithString: value)
        label.font = .systemFont(ofSize: 12, weight: .medium)
        label.textColor = .secondaryLabelColor
        return label
    }

    private func parameterText(_ parameters: [String: String]) -> String {
        parameters.keys.sorted().map { "\($0)=\(parameters[$0]!)" }.joined(separator: "\n")
    }

    private var selectedType: String {
        typePopup.selectedItem?.representedObject as? String ?? "vmess"
    }

    @objc private func typeChanged() { updateHelp() }

    private func updateHelp() {
        let required: String
        switch selectedType {
        case "http", "https", "socks5", "socks5-tls": required = "可选：username、password"
        case "ss": required = "必需：cipher、password"
        case "ssr": required = "必需：cipher、password、protocol、obfs"
        case "snell": required = "必需：psk；常用：version=4…6"
        case "vmess", "vless": required = "必需：uuid"
        case "trojan", "anytls", "hysteria2": required = "必需：password"
        case "hysteria": required = "必需：auth-str、up、down"
        case "tuic": required = "必需：token，或 uuid + password"
        case "sudoku": required = "必需：key；常用：aead-method=chacha20-poly1305、table-type=prefer_ascii"
        case "mieru": required = "必需：username、password；常用：transport=TCP、multiplexing=MULTIPLEXING_HIGH"
        case "trusttunnel": required = "必需：username、password；可选：quic=false、sni"
        case "ssh": required = "必需：username，以及 password 或 private-key"
        case "wireguard": required = "必需：private-key、ip、public-key"
        default: required = ""
        }
        helpLabel.stringValue = "每行 key=value，无需加引号。\(required)。可选 TLS、SNI、WebSocket、UDP 与 underlying-proxy 等 Surge 参数。"
    }

    @objc private func insertTemplate() {
        let templates: [String: [(String, String)]] = [
            "http": [("username", ""), ("password", "")],
            "https": [("username", ""), ("password", "")],
            "socks5": [("username", ""), ("password", ""), ("udp", "true")],
            "socks5-tls": [("username", ""), ("password", ""), ("udp", "true")],
            "ss": [("cipher", "aes-128-gcm"), ("password", ""), ("udp", "true")],
            "ssr": [("cipher", "chacha20-ietf"), ("password", ""), ("protocol", "origin"), ("obfs", "plain")],
            "snell": [("psk", ""), ("version", "4"), ("udp", "true")],
            "vmess": [("uuid", ""), ("tls", "true"), ("servername", hostField.stringValue), ("network", "ws"), ("ws-path", "/")],
            "vless": [("uuid", ""), ("tls", "true"), ("servername", hostField.stringValue), ("network", "tcp")],
            "trojan": [("password", ""), ("sni", hostField.stringValue), ("udp", "true")],
            "anytls": [("password", ""), ("sni", hostField.stringValue), ("udp", "true")],
            "hysteria": [("auth-str", ""), ("up", "10 Mbps"), ("down", "50 Mbps"), ("sni", hostField.stringValue)],
            "hysteria2": [("password", ""), ("sni", hostField.stringValue)],
            "tuic": [("token", ""), ("sni", hostField.stringValue), ("congestion-controller", "bbr")],
            "sudoku": [("key", ""), ("aead-method", "chacha20-poly1305"), ("table-type", "prefer_ascii"), ("padding-min", "2"), ("padding-max", "7"), ("enable-pure-downlink", "true")],
            "mieru": [("username", ""), ("password", ""), ("transport", "TCP"), ("multiplexing", "MULTIPLEXING_HIGH")],
            "trusttunnel": [("username", ""), ("password", ""), ("sni", hostField.stringValue), ("quic", "false"), ("udp", "true")],
            "ssh": [("username", ""), ("password", "")],
            "wireguard": [("private-key", ""), ("ip", "172.16.0.2/32"), ("public-key", ""), ("allowed-ips", "0.0.0.0/0;::/0")]
        ]
        var current = (try? parsedParameters()) ?? [:]
        for (key, value) in templates[selectedType] ?? [] where current[key] == nil { current[key] = value }
        parametersView.string = parameterText(current)
    }

    private func parsedParameters() throws -> [String: String] {
        var result: [String: String] = [:]
        for (offset, rawLine) in parametersView.string.components(separatedBy: .newlines).enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let equal = line.firstIndex(of: "=") else {
                throw EditorError.message("参数第 \(offset + 1) 行缺少 =")
            }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw EditorError.message("参数第 \(offset + 1) 行键名为空") }
            guard result[key] == nil else { throw EditorError.message("参数 \(key) 重复") }
            result[key] = value
        }
        return result
    }

    @objc private func savePressed() {
        do {
            let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if name != originalName, unavailableNames.contains(name) {
                throw EditorError.message("已经存在同名节点或策略组")
            }
            let params = try parsedParameters()
            let trimmedPort = portField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolvedPort: UInt16?
            if let directPort = UInt16(trimmedPort), directPort > 0 {
                resolvedPort = directPort
            } else if let rangeSpec = params["port-range"] ?? params["ports"] {
                let firstToken = rangeSpec.split(whereSeparator: { $0 == "," || $0 == ";" || $0 == "-" || $0 == ":" })
                    .first.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) } ?? ""
                resolvedPort = UInt16(firstToken)
            } else {
                resolvedPort = nil
            }
            guard let port = resolvedPort, port > 0 else {
                throw EditorError.message("端口必须为 1…65535（或填写有效端口范围）")
            }
            let draft = SurgeProxyDraft(name: name, type: selectedType,
                                        host: hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
                                        port: port,
                                        parameters: params)
            _ = try SurgeProfileDocument.definition(for: draft)
            try commit(draft)
            closeSheet(returnCode: .OK)
        } catch {
            errorLabel.stringValue = error.localizedDescription
        }
    }

    @objc private func cancelPressed() { closeSheet(returnCode: .cancel) }

    private func closeSheet(returnCode: NSApplication.ModalResponse) {
        guard let window else { return }
        if let parent = window.sheetParent { parent.endSheet(window, returnCode: returnCode) }
        else { window.close() }
    }

    private enum EditorError: LocalizedError {
        case message(String)
        var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
    }
}


// MARK: - Modern Share-Link Import Modal Sheet

final class ShareLinkImportSheetController: NSWindowController, NSTextViewDelegate {
    private let sheetTitle: String
    private let confirmTitle: String
    private let allowMultiple: Bool
    private let onConfirm: (String) -> Void
    private var retainedSelf: ShareLinkImportSheetController?

    private let editor = NSTextView()
    private let placeholderLabel = NSTextField(wrappingLabelWithString: "")
    private let statusDot = HajimiSurfaceView(fill: .tertiaryLabelColor, cornerRadius: 4)
    private let statusLabel = NSTextField(labelWithString: "")
    private let confirmButton = NSButton()

    static func present(on parentWindow: NSWindow,
                        title: String = "导入分享链接",
                        confirmTitle: String = "导入节点",
                        allowMultiple: Bool = true,
                        onConfirm: @escaping (String) -> Void) {
        let controller = ShareLinkImportSheetController(
            title: title,
            confirmTitle: confirmTitle,
            allowMultiple: allowMultiple,
            onConfirm: onConfirm
        )
        controller.retainedSelf = controller
        guard let sheet = controller.window else { return }
        parentWindow.beginSheet(sheet) { _ in
            controller.retainedSelf = nil
        }
    }

    private init(title: String, confirmTitle: String, allowMultiple: Bool, onConfirm: @escaping (String) -> Void) {
        self.sheetTitle = title
        self.confirmTitle = confirmTitle
        self.allowMultiple = allowMultiple
        self.onConfirm = onConfirm
        let width: CGFloat = allowMultiple ? 560 : 520
        let height: CGFloat = allowMultiple ? 380 : 320
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: height),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        super.init(window: window)
        buildUI(width: width, height: height)
        prefillFromClipboardIfValid()
        refreshValidationState()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI(width: CGFloat, height: CGFloat) {
        guard let window else { return }
        let root = HajimiSurfaceView(fill: HajimiAppearance.workspace, cornerRadius: 0)
        root.frame = NSRect(x: 0, y: 0, width: width, height: height)
        window.contentView = root

        // Header
        let iconBadge = HajimiAppearance.iconBadge(symbolName: "link.badge.plus", size: 38, symbolSize: 17)
        let titleLabel = NSTextField(labelWithString: sheetTitle)
        titleLabel.font = .systemFont(ofSize: 17, weight: .bold)
        titleLabel.textColor = .labelColor
        let pill = HajimiAppearance.pillBadge(text: "SHARE LINKS", fontSize: 9.0)

        let titleLine = NSStackView(views: [titleLabel, pill, NSView()])
        titleLine.orientation = .horizontal
        titleLine.alignment = .centerY
        titleLine.spacing = 8

        let subtitleLabel = NSTextField(labelWithString: "支持 sudoku:// · mieru:// · vless:// · vmess:// · trojan:// · hy2:// · tuic:// · ss:// · anytls:// · trusttunnel:// 及 Mieru JSON")
        subtitleLabel.font = .systemFont(ofSize: 11, weight: .regular)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.lineBreakMode = .byTruncatingTail

        let titleStack = NSStackView(views: [titleLine, subtitleLabel])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 3

        let headerRow = NSStackView(views: [iconBadge, titleStack])
        headerRow.orientation = .horizontal
        headerRow.alignment = .centerY
        headerRow.spacing = 12
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(headerRow)

        // Action & Live Recognition Toolbar
        statusDot.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            statusDot.widthAnchor.constraint(equalToConstant: 8),
            statusDot.heightAnchor.constraint(equalToConstant: 8)
        ])
        statusLabel.font = .systemFont(ofSize: 11.5, weight: .medium)
        statusLabel.textColor = .secondaryLabelColor

        let pasteBtn = NSButton(title: "从剪贴板粘贴", target: self, action: #selector(pasteFromClipboard))
        pasteBtn.bezelStyle = .rounded
        pasteBtn.controlSize = .small
        pasteBtn.font = .systemFont(ofSize: 11, weight: .medium)
        pasteBtn.image = NSImage(systemSymbolName: "doc.on.clipboard", accessibilityDescription: nil)
        pasteBtn.imagePosition = .imageLeading

        let clearBtn = NSButton(title: "清空", target: self, action: #selector(clearEditor))
        clearBtn.bezelStyle = .rounded
        clearBtn.controlSize = .small
        clearBtn.font = .systemFont(ofSize: 11, weight: .medium)

        let toolbarRow = NSStackView(views: [statusDot, statusLabel, NSView(), pasteBtn, clearBtn])
        toolbarRow.orientation = .horizontal
        toolbarRow.alignment = .centerY
        toolbarRow.spacing = 8
        toolbarRow.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(toolbarRow)

        // Editor Card
        let editorCard = HajimiSurfaceView(
            fill: HajimiAppearance.elevatedPanel,
            border: HajimiAppearance.border,
            cornerRadius: 11
        )
        editorCard.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(editorCard)

        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false

        editor.frame = NSRect(x: 0, y: 0, width: width - 56, height: height - 180)
        editor.minSize = NSSize(width: 0, height: 80)
        editor.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        editor.isVerticallyResizable = true
        editor.isHorizontallyResizable = false
        editor.autoresizingMask = [.width]
        editor.textContainer?.containerSize = NSSize(width: width - 56, height: CGFloat.greatestFiniteMagnitude)
        editor.textContainer?.widthTracksTextView = true
        editor.textContainerInset = NSSize(width: 10, height: 10)
        editor.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        editor.textColor = .labelColor
        editor.insertionPointColor = HajimiAppearance.accent
        editor.drawsBackground = false
        editor.isRichText = false
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.delegate = self

        scroll.documentView = editor
        editorCard.addSubview(scroll)

        placeholderLabel.stringValue = allowMultiple
            ? "在此粘贴一行或多行分享链接，或直接粘贴 Mieru 客户端 JSON 配置：\n\nsudoku://eyJoIjoi...\nmieru://...\nvless://...#节点名称"
            : "在此粘贴单条分享链接（如 sudoku://...、mieru://...、vless://...）或 Mieru 客户端 JSON 配置"
        placeholderLabel.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        placeholderLabel.textColor = .placeholderTextColor
        placeholderLabel.isEditable = false
        placeholderLabel.isBordered = false
        placeholderLabel.drawsBackground = false
        placeholderLabel.translatesAutoresizingMaskIntoConstraints = false
        editorCard.addSubview(placeholderLabel)

        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: editorCard.leadingAnchor, constant: 2),
            scroll.trailingAnchor.constraint(equalTo: editorCard.trailingAnchor, constant: -2),
            scroll.topAnchor.constraint(equalTo: editorCard.topAnchor, constant: 2),
            scroll.bottomAnchor.constraint(equalTo: editorCard.bottomAnchor, constant: -2),
            placeholderLabel.leadingAnchor.constraint(equalTo: editorCard.leadingAnchor, constant: 16),
            placeholderLabel.trailingAnchor.constraint(equalTo: editorCard.trailingAnchor, constant: -16),
            placeholderLabel.topAnchor.constraint(equalTo: editorCard.topAnchor, constant: 12)
        ])

        // Footer
        let tipLabel = NSTextField(labelWithString: allowMultiple
            ? "支持多协议混贴与批量去重导入"
            : "解析成功后将自动填充当前节点的服务器与协议参数")
        tipLabel.font = .systemFont(ofSize: 11)
        tipLabel.textColor = .tertiaryLabelColor

        let cancelButton = NSButton(title: "取消", target: self, action: #selector(cancelPressed))
        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}"
        cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 78).isActive = true

        confirmButton.title = confirmTitle
        confirmButton.target = self
        confirmButton.action = #selector(confirmPressed)
        confirmButton.bezelStyle = .rounded
        confirmButton.keyEquivalent = "\r"
        confirmButton.bezelColor = HajimiAppearance.accent
        confirmButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 96).isActive = true

        let footerRow = NSStackView(views: [tipLabel, NSView(), cancelButton, confirmButton])
        footerRow.orientation = .horizontal
        footerRow.alignment = .centerY
        footerRow.spacing = 10
        footerRow.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(footerRow)

        NSLayoutConstraint.activate([
            headerRow.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            headerRow.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            headerRow.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),

            toolbarRow.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            toolbarRow.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            toolbarRow.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 14),

            editorCard.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            editorCard.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            editorCard.topAnchor.constraint(equalTo: toolbarRow.bottomAnchor, constant: 8),
            editorCard.bottomAnchor.constraint(equalTo: footerRow.topAnchor, constant: -14),

            footerRow.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            footerRow.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            footerRow.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16)
        ])

        window.initialFirstResponder = editor
    }

    private func prefillFromClipboardIfValid() {
        guard let clip = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !clip.isEmpty,
              ShareLinkSubscription.looksLikeShareLinks(clip) else { return }
        editor.string = clip
        editor.selectAll(nil)
    }

    func textDidChange(_ notification: Notification) {
        refreshValidationState()
    }

    private func refreshValidationState() {
        let raw = editor.string
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        placeholderLabel.isHidden = !raw.isEmpty
        guard !trimmed.isEmpty else {
            statusDot.fillColor = .tertiaryLabelColor
            statusLabel.stringValue = allowMultiple ? "等待输入或粘贴分享链接…" : "等待粘贴节点分享链接…"
            statusLabel.textColor = .secondaryLabelColor
            confirmButton.isEnabled = false
            return
        }
        if let parsed = try? ShareLinkSubscription.parse(trimmed), !parsed.proxies.isEmpty {
            let protos = Array(Set(parsed.proxies.map { ($0.adapterType ?? $0.kind.rawValue).uppercased() })).sorted()
            let protoSummary = protos.prefix(4).joined(separator: " / ")
            statusDot.fillColor = HajimiAppearance.statusSuccess
            statusLabel.stringValue = "已识别 \(parsed.proxies.count) 个可用节点（\(protoSummary)）"
            statusLabel.textColor = HajimiAppearance.accentText
            confirmButton.isEnabled = true
        } else if ShareLinkSubscription.looksLikeShareLinks(trimmed) {
            statusDot.fillColor = HajimiAppearance.statusWarning
            statusLabel.stringValue = "检测到链接前缀，但参数尚不完整或格式有误"
            statusLabel.textColor = HajimiAppearance.statusWarning
            confirmButton.isEnabled = true
        } else {
            statusDot.fillColor = HajimiAppearance.statusWarning
            statusLabel.stringValue = "未识别到受支持的分享链接或 Mieru JSON 格式"
            statusLabel.textColor = HajimiAppearance.statusWarning
            confirmButton.isEnabled = false
        }
    }

    @objc private func pasteFromClipboard() {
        guard let clip = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !clip.isEmpty else { return }
        if editor.string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !allowMultiple {
            editor.string = clip
        } else {
            editor.string += (editor.string.hasSuffix("\n") ? "" : "\n") + clip
        }
        refreshValidationState()
    }

    @objc private func clearEditor() {
        editor.string = ""
        refreshValidationState()
        window?.makeFirstResponder(editor)
    }

    @objc private func confirmPressed() {
        let content = editor.string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !content.isEmpty else { return }
        closeSheet(returnCode: .OK)
        onConfirm(content)
    }

    @objc private func cancelPressed() {
        closeSheet(returnCode: .cancel)
    }

    private func closeSheet(returnCode: NSApplication.ModalResponse) {
        guard let window else { return }
        if let parent = window.sheetParent {
            parent.endSheet(window, returnCode: returnCode)
        } else {
            window.close()
        }
    }
}
