import AppKit

/// A width-fitted document for settings/diagnostics that may outgrow a small
/// window. Only its height scrolls; wrapped privacy text and the Save button
/// remain reachable without increasing the app's minimum window size.
public final class WidthFittingScrollContentView: NSView {
    private final class Document: NSView {
        override var isFlipped: Bool { true }
    }
    public let scrollView = NSScrollView()
    private let document = Document()
    private var viewportFrameObserver: NSObjectProtocol?
    private var contentFrameObserver: NSObjectProtocol?
    public let content: NSView

    public init(content: NSView) {
        self.content = content
        super.init(frame: .zero)
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        scrollView.borderType = .noBorder
        scrollView.autoresizingMask = [.width, .height]
        addSubview(scrollView)
        scrollView.documentView = document
        let clip = scrollView.contentView
        clip.postsFrameChangedNotifications = true
        viewportFrameObserver = NotificationCenter.default.addObserver(
            forName: NSView.frameDidChangeNotification, object: clip, queue: nil
        ) { [weak self] _ in
            // A late overlay/legacy change can resize only the clip view.
            // Scrolling changes its bounds and does not invalidate this host.
            self?.needsLayout = true
        }
        content.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(content)
        // Do not pin the content's bottom to the frame-sized document. Its
        // natural fitting height determines the document, not the viewport.
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 8),
            content.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -8),
            content.topAnchor.constraint(equalTo: document.topAnchor, constant: 8)
        ])
        content.postsFrameChangedNotifications = true
        contentFrameObserver = NotificationCenter.default.addObserver(
            forName: NSView.frameDidChangeNotification, object: content, queue: nil
        ) { [weak self] _ in
            // Async diagnostics can resize their Auto Layout content without
            // changing the viewport. Refit the document when that happens.
            self?.needsLayout = true
        }
    }

    public required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    deinit {
        if let viewportFrameObserver {
            NotificationCenter.default.removeObserver(viewportFrameObserver)
        }
        if let contentFrameObserver {
            NotificationCenter.default.removeObserver(contentFrameObserver)
        }
    }

    public override func layout() {
        super.layout()
        scrollView.frame = bounds
        // A legacy scroller can claim width after the document gains height.
        // Refit against that actual viewport within the same layout pass.
        for _ in 0..<3 {
            scrollView.layoutSubtreeIfNeeded()
            let viewport = scrollView.contentView.bounds.size
            let width = max(1, viewport.width)
            if abs(document.frame.width - width) > 0.5 {
                document.setFrameSize(NSSize(width: width, height: max(1, document.frame.height)))
            }
            document.layoutSubtreeIfNeeded()
            let natural = content.fittingSize.height
            // AppKit buttons can draw beyond their alignment rect. Include a
            // small inset on every edge rather than clipping the final row.
            let height = max(viewport.height, natural.isFinite ? natural + 16 : 0)
            if abs(document.frame.height - height) > 0.5 {
                document.setFrameSize(NSSize(width: width, height: height))
            }
            document.layoutSubtreeIfNeeded()
            let clip = scrollView.contentView
            clip.scroll(to: clip.constrainBoundsRect(clip.bounds).origin)
            scrollView.reflectScrolledClipView(scrollView.contentView)
            scrollView.layoutSubtreeIfNeeded()
            let updatedViewport = scrollView.contentView.bounds.size
            if abs(updatedViewport.width - viewport.width) <= 0.5
                && abs(updatedViewport.height - viewport.height) <= 0.5 {
                break
            }
        }
    }
}
