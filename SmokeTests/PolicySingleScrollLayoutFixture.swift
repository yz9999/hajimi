import AppKit
import HajimiCore
import HajimiUIComponents

// @THEME@

// Counts actual factory requests while leaving copied production methods intact.
private final class PolicyDataSourceRecorder: NSObject, NSCollectionViewDataSource {
    weak var owner: PolicyPageFixture?
    private(set) var itemRequests = 0
    init(owner: PolicyPageFixture) { self.owner = owner }
    func numberOfSections(in collectionView: NSCollectionView) -> Int {
        owner!.numberOfSections(in: collectionView)
    }
    func collectionView(_ collectionView: NSCollectionView, numberOfItemsInSection section: Int) -> Int {
        owner!.collectionView(collectionView, numberOfItemsInSection: section)
    }
    func collectionView(_ collectionView: NSCollectionView,
                        itemForRepresentedObjectAt indexPath: IndexPath) -> NSCollectionViewItem {
        itemRequests += 1
        return owner!.collectionView(collectionView, itemForRepresentedObjectAt: indexPath)
    }
    func collectionView(_ collectionView: NSCollectionView, viewForSupplementaryElementOfKind kind: String,
                        at indexPath: IndexPath) -> NSView {
        owner!.collectionView(collectionView, viewForSupplementaryElementOfKind: kind, at: indexPath)
    }
}

private final class PolicyPageFixture: NSObject, NSCollectionViewDataSource, NSCollectionViewDelegateFlowLayout {
    let policiesView = HajimiSurfaceView(fill: HajimiAppearance.workspace, cornerRadius: 0)
    private let policyCollectionView = ContextCollectionView()
    private let proxySearchField = NSSearchField()
    private let proxyCountLabel = NSTextField(labelWithString: "30 个节点")
    private let policyStatusLabel = NSTextField(labelWithString: "预览示例数据 · 延迟为服务器 TCP 建连耗时")
    private var filteredProxyNames: [String] = []
    private var profile = Profile()
    private var nodeLatencies: [String: NodeLatency] = [:]
    private var groupSelections: [String: String] = [:]
    private var selectedMode: OutboundMode = .proxy
    private var selectedPolicy = "新加坡 AWS IPV6"
    private var usedNames: [String] = []
    private var editedNames: [String] = []
    private var selectedMembers: [(String, String?)] = []
    private var addNodeCount = 0
    private var addGroupCount = 0
    private var sceneWidth: NSLayoutConstraint!
    private var offscreenWindow: NSWindow!
    private lazy var recorder = PolicyDataSourceRecorder(owner: self)

    // @PRODUCTION_METHODS@

    @objc private func proxySearchChanged() {}
    @objc private func testAllNodes() {}
    @objc private func importShareLinks() {}
    @objc private func addProxy() { addNodeCount += 1 }
    @objc private func addPolicyGroup() { addGroupCount += 1 }
    private func useProxy(named name: String) { usedNames.append(name) }
    private func editProxy(named name: String) { editedNames.append(name) }
    private func setGroupSelection(group: String, member: String?) { selectedMembers.append((group, member)) }
    private func makeProxyMenu(name: String) -> NSMenu { NSMenu(title: name) }
    private func makeGroupMenu(name: String) -> NSMenu { NSMenu(title: name) }

    init(size: NSSize, appearance: NSAppearance) {
        super.init()
        policiesView.appearance = appearance
        policiesView.frame = NSRect(origin: .zero, size: size)
        policiesView.translatesAutoresizingMaskIntoConstraints = false
        sceneWidth = policiesView.widthAnchor.constraint(equalToConstant: size.width)
        NSLayoutConstraint.activate([sceneWidth, policiesView.heightAnchor.constraint(equalToConstant: size.height)])
        for index in 0..<30 {
            let name = index == 0 ? "新加坡 AWS IPV6" : index == 1
                ? "香港 · 超长节点名称 / 跨境办公专用线路 0123456789" : "🇺🇸 美国 \(index + 1)"
            profile.proxyOrder.append(name)
            profile.proxies[name] = ProxyPolicy(name: name, kind: .external,
                host: index == 0 ? "2001:db8:45ac:1d02:0123:4567:89ab:cdef" : "203.0.113.\(index + 1)",
                port: 443, adapterType: "vmess", parameters: ["uuid": "11111111-2222-3333-4444-555555555555"])
            nodeLatencies[name] = .success(index == 0 ? 61 : 180 + index * 11)
        }
        let names = ["🎯 总模式", "Ⓜ️ 负载均衡", "♻️ 手动切换 1", "♻️ 手动切换 2", "🍎 苹果服务", "🧩 微软服务",
            "📱 聊天软件", "🤖 OpenAI", "📺 YouTube", "🎥 NETFLIX", "🔍 谷歌服务", "🎮 游戏平台",
            "🎬 日韩媒体", "🌐 国外媒体", "🐱 国内媒体", "工作 · 超长策略组名称 0123456789", "下载服务", "备用策略"]
        for (index, name) in names.enumerated() {
            profile.groupOrder.append(name)
            profile.groups[name] = PolicyGroup(name: name, kind: index == 1 ? .loadBalance : .select,
                members: ["新加坡 AWS IPV6", "香港 · 超长节点名称 / 跨境办公专用线路 0123456789", "DIRECT"])
        }
        filteredProxyNames = profile.proxyOrder
        buildPolicies()
        // Attach the native collection to an unshown test window so AppKit
        // drives its real viewport tiling. Never order, activate or run it.
        offscreenWindow = NSWindow(contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless], backing: .buffered, defer: false)
        offscreenWindow.isReleasedWhenClosed = false
        offscreenWindow.contentView = policiesView
        policyCollectionView.dataSource = recorder
        policyCollectionView.reloadData()
    }

    private func settle() {
        for _ in 0..<8 {
            policiesView.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
    }
    private func allViews(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(allViews) }
    private func require(_ condition: @autoclosure () -> Bool, _ text: String) throws {
        guard condition() else { throw NSError(domain: "PolicySingleScroll", code: 1,
            userInfo: [NSLocalizedDescriptionKey: text]) }
        assertionCount += 1
    }
    private(set) var assertionCount = 0
    private var scroll: NSScrollView { policyCollectionView.enclosingScrollView! }
    private var layout: NSCollectionViewLayout { policyCollectionView.collectionViewLayout! }
    private func attributes(_ item: Int, section: Int) throws -> NSCollectionViewLayoutAttributes {
        guard let value = layout.layoutAttributesForItem(at: IndexPath(item: item, section: section)) else {
            throw NSError(domain: "PolicySingleScroll", code: 4,
                userInfo: [NSLocalizedDescriptionKey: "缺少 section \(section) item \(item) 布局"])
        }
        return value
    }
    private func header(_ section: Int) throws -> NSCollectionViewLayoutAttributes {
        guard let value = layout.layoutAttributesForSupplementaryView(
            ofKind: NSCollectionView.elementKindSectionHeader, at: IndexPath(item: 0, section: section)) else {
            throw NSError(domain: "PolicySingleScroll", code: 5,
                userInfo: [NSLocalizedDescriptionKey: "缺少 section \(section) 标题布局"])
        }
        return value
    }
    private func reveal(_ path: IndexPath) throws -> NSCollectionViewItem {
        policyCollectionView.scrollToItems(at: [path], scrollPosition: .centeredVertically)
        settle()
        guard let item = policyCollectionView.item(at: path) else {
            throw NSError(domain: "PolicySingleScroll", code: 6,
                userInfo: [NSLocalizedDescriptionKey: "滚动后没有实例化 section \(path.section) item \(path.item)"])
        }
        return item
    }
    private func top() {
        scroll.contentView.scroll(to: .zero)
        scroll.reflectScrolledClipView(scroll.contentView)
        settle()
    }
    private func snapshot(_ destination: URL) throws {
        policiesView.displayIfNeeded()
        guard let bitmap = policiesView.bitmapImageRepForCachingDisplay(in: policiesView.bounds) else {
            throw NSError(domain: "PolicySingleScroll", code: 2)
        }
        policiesView.cacheDisplay(in: policiesView.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw NSError(domain: "PolicySingleScroll", code: 3)
        }
        try png.write(to: destination)
    }

    func verifyAndRender(_ destination: URL, scene: String) throws -> [String: Any] {
        settle()
        let scrolls = allViews(policiesView).compactMap { $0 as? NSScrollView }
        try require(scrolls.count == 1, "策略页面必须只有一个滚动区，实际 \(scrolls.count)")
        try require(scroll.documentView === policyCollectionView, "集合必须直接作为唯一滚动区文档以保留原生复用")
        try require(policyCollectionView.numberOfSections == 2, "节点和策略组没有使用两个原生 section")
        try require(policyCollectionView.numberOfItems(inSection: 0) == 31
                    && policyCollectionView.numberOfItems(inSection: 1) == 19, "节点/组或新增卡片数量错误")
        try require(abs(policiesView.bounds.width - sceneWidth.constant) < 1, "页面被工具栏撑宽")
        try require(policiesView.bounds.insetBy(dx: -1, dy: -1).contains(scroll.frame), "共享滚动区超过实际页宽")
        for button in policiesView.subviews.compactMap({ $0 as? NSStackView }).flatMap({ $0.arrangedSubviews })
            .compactMap({ $0 as? NSButton }) {
            try require(button.bounds.width + 1 >= button.fittingSize.width, "顶部操作按钮被压缩：\(button.title)")
        }
        try require(!scroll.hasHorizontalScroller, "意外出现横向滚动条")
        let toolbarFrame = policiesView.convert(proxySearchField.bounds, from: proxySearchField)
        let statusFrame = policiesView.convert(policyStatusLabel.bounds, from: policyStatusLabel)
        var styles: [[String: Any]] = []
        for style in [NSScroller.Style.overlay, .legacy] {
            scroll.scrollerStyle = style
            settle()
            try require(scroll.scrollerStyle == style, "未实际覆盖指定滚动条样式")
            let nodeFirst = try attributes(0, section: 0)
            let nodeSecond = try attributes(1, section: 0)
            let sameRowCount = (0..<10).prefix { ((try? attributes($0, section: 0).frame.minY) ?? -1) == nodeFirst.frame.minY }.count
            let nodeNextRow = try attributes(max(1, sameRowCount), section: 0)
            let horizontalGap = nodeSecond.frame.minX - nodeFirst.frame.maxX
            let verticalGap = nodeNextRow.frame.minY - nodeFirst.frame.maxY
            try require(abs(horizontalGap - verticalGap) < 0.5 && abs(horizontalGap - 8) < 0.5,
                        "卡片左右间距(\(horizontalGap))与上下间距(\(verticalGap))不一致")
            let nodeLast = try attributes(filteredProxyNames.count, section: 0)
            let groupFirst = try attributes(0, section: 1)
            let groupLast = try attributes(profile.groupOrder.count, section: 1)
            let groupHeader = try header(1)
            try require(groupHeader.frame.minY > nodeLast.frame.maxY && groupFirst.frame.minY >= groupHeader.frame.maxY,
                        "节点和策略组没有上下连续排列")
            try require(nodeLast.frame.height == 84 && groupLast.frame.height == 88, "节点和组卡片原始高度丢失")
            try require(policyCollectionView.bounds.insetBy(dx: -1, dy: -1).contains(groupLast.frame),
                        "最后组卡片被文档裁切：bounds=\(policyCollectionView.bounds), last=\(groupLast.frame), contentSize=\(layout.collectionViewContentSize), viewport=\(scroll.contentView.bounds)")
            _ = try reveal(IndexPath(item: profile.groupOrder.count, section: 1))
            let lastInClip = scroll.contentView.convert(groupLast.frame, from: policyCollectionView)
            try require(scroll.contentView.bounds.insetBy(dx: -1, dy: -1).contains(lastInClip), "最后新增组不能完整滚动到可见")
            try require(policyCollectionView.bounds.width <= scroll.contentView.bounds.width + 1, "文档宽度超出实际viewport")
            styles.append(["style": style == .legacy ? "legacy" : "overlay",
                           "viewportWidth": scroll.contentView.bounds.width,
                           "documentHeight": policyCollectionView.frame.height])
        }
        top()
        let oldHeight = policyCollectionView.frame.height
        let originalGroupY = try header(1).frame.minY
        try snapshot(destination.appendingPathComponent("\(scene)-top.png"))
        guard let wheelCG = CGEvent(scrollWheelEvent2Source: nil, units: .pixel,
                wheelCount: 1, wheel1: -240, wheel2: 0, wheel3: 0),
              let wheel = NSEvent(cgEvent: wheelCG) else { throw NSError(domain: "PolicySingleScroll", code: 7) }
        policyCollectionView.scrollWheel(with: wheel)
        settle()
        try require(scroll.contentView.bounds.minY > 0, "集合吞掉了滚轮")
        top()
        let handled = policyCollectionView.tryToPerform(#selector(NSResponder.pageDown(_:)), with: nil)
        settle()
        try require(handled && scroll.contentView.bounds.minY > 0, "集合没有向唯一滚动区传递原生翻页命令")
        let lastGroup = IndexPath(item: profile.groupOrder.count, section: 1)
        _ = try reveal(lastGroup)
        try require(scroll.contentView.bounds.minY > 0, "滚动动作没有移动视口")
        try require(policiesView.convert(proxySearchField.bounds, from: proxySearchField) == toolbarFrame, "滚动时搜索框跟随移动")
        try require(policiesView.convert(policyStatusLabel.bounds, from: policyStatusLabel) == statusFrame, "滚动时底部状态跟随移动")
        try snapshot(destination.appendingPathComponent("\(scene)-bottom.png"))
        let groupPath = IndexPath(item: 0, section: 1)
        let groupItem = try reveal(groupPath)
        let popup = allViews(groupItem.view).compactMap { $0 as? NSPopUpButton }.first!
        popup.selectItem(at: 2)
        _ = NSApp.sendAction(popup.action!, to: popup.target, from: popup)
        try require(selectedMembers.count == 1 && selectedMembers[0].0 == profile.groupOrder[0]
                    && selectedMembers[0].1 == profile.proxyOrder[1], "策略组下拉选择动作丢失或 section 映射错误")
        (try reveal(lastGroup).view as! NSButton).performClick(nil)
        try require(addGroupCount == 1, "新增策略组动作丢失")
        filteredProxyNames = Array(profile.proxyOrder.prefix(1))
        policyCollectionView.reloadData()
        settle()
        try require(policyCollectionView.frame.height < oldHeight - 150, "搜索后文档没有随节点数量收缩")
        let filteredGroupY = try header(1).frame.minY
        try require(filteredGroupY < originalGroupY - 150, "搜索后策略组位置未随节点数更新")
        try require(scroll.contentView.bounds.maxY <= policyCollectionView.bounds.maxY + 1, "搜索后滚动位置未约束到文档")
        let firstNode = IndexPath(item: 0, section: 0)
        let proxyItem = try reveal(firstNode)
        let allowed = collectionView(policyCollectionView, shouldSelectItemsAt: [firstNode, groupPath,
            IndexPath(item: 1, section: 0), lastGroup])
        try require(allowed == [firstNode], "组卡片或新增卡片进入节点选择路径")
        policyCollectionView.selectItems(at: [firstNode], scrollPosition: [])
        collectionView(policyCollectionView, didSelectItemsAt: [firstNode])
        try require(usedNames == [filteredProxyNames[0]], "节点选择动作丢失")
        let doubleClick = proxyItem.view.gestureRecognizers.first!
        _ = NSApp.sendAction(doubleClick.action!, to: doubleClick.target, from: doubleClick)
        try require(editedNames == [filteredProxyNames[0]], "节点双击编辑动作丢失")
        (try reveal(IndexPath(item: 1, section: 0)).view as! NSButton).performClick(nil)
        try require(addNodeCount == 1, "新增节点动作丢失")
        try require(policyCollectionView.contextMenuProvider?(firstNode)?.title == filteredProxyNames[0], "节点右键菜单映射丢失")
        try require(policyCollectionView.contextMenuProvider?(groupPath)?.title == profile.groupOrder[0], "策略组右键菜单 section 映射丢失")
        try require(policyCollectionView.contextMenuProvider?(IndexPath(item: 1, section: 0)) == nil
                    && policyCollectionView.contextMenuProvider?(lastGroup) == nil, "新增卡片错误映射至节点/组菜单")
        top()
        try snapshot(destination.appendingPathComponent("\(scene)-filtered.png"))
        filteredProxyNames = []
        policyCollectionView.reloadData()
        settle()
        try require(policyCollectionView.numberOfItems(inSection: 0) == 1, "空搜索结果丢失新增节点")
        _ = try reveal(IndexPath(item: 0, section: 0))
        filteredProxyNames = profile.proxyOrder
        policyCollectionView.reloadData()
        settle()
        try require(abs(policyCollectionView.frame.height - oldHeight) <= 1, "取消搜索后未恢复完整文档高度")
        let originalWidth = sceneWidth.constant
        sceneWidth.constant = originalWidth > 900 ? 740 : 1020
        offscreenWindow.setContentSize(NSSize(width: sceneWidth.constant, height: policiesView.bounds.height))
        policiesView.setFrameSize(NSSize(width: sceneWidth.constant, height: policiesView.bounds.height))
        settle()
        try require(abs(policyCollectionView.frame.height - oldHeight) > 100, "改变页宽后行数/文档高度未更新")
        try require(policyCollectionView.frame.width <= scroll.contentView.bounds.width + 1, "改变页宽后文档没有贴合viewport")
        sceneWidth.constant = originalWidth
        offscreenWindow.setContentSize(NSSize(width: originalWidth, height: policiesView.bounds.height))
        policiesView.setFrameSize(NSSize(width: originalWidth, height: policiesView.bounds.height))
        settle()
        try require(abs(policyCollectionView.frame.height - oldHeight) <= 1, "恢复页宽后文档高度未恢复")
        let originalGroups = profile.groupOrder
        let originalGroupDefinitions = profile.groups
        for index in 0..<18 {
            let name = "新策略组 \(index)"
            profile.groupOrder.append(name)
            profile.groups[name] = PolicyGroup(name: name, kind: .select, members: ["DIRECT"])
        }
        policyCollectionView.reloadData()
        settle()
        try require(policyCollectionView.frame.height > oldHeight + 150, "新增策略组后文档未增长")
        profile.groupOrder = originalGroups
        profile.groups = originalGroupDefinitions
        policyCollectionView.reloadData()
        settle()
        try require(abs(policyCollectionView.frame.height - oldHeight) <= 1, "删除策略组后文档高度未收缩")
        _ = try reveal(groupPath)
        let beforeReloadOffset = scroll.contentView.bounds.origin
        nodeLatencies[profile.proxyOrder[0]] = .success(123)
        groupSelections[profile.groupOrder[0]] = profile.proxyOrder[1]
        policyCollectionView.reloadItems(at: [firstNode, groupPath])
        settle()
        try require(abs(policyCollectionView.frame.height - oldHeight) <= 1
                    && scroll.contentView.bounds.origin == beforeReloadOffset, "局部刷新改变了文档高度或滚动位置")
        let refreshedNode = try reveal(firstNode)
        try require(allViews(refreshedNode.view).compactMap { $0 as? NSTextField }.contains { $0.stringValue == "123 ms" },
                    "局部节点刷新未显示新的延迟")
        let refreshedGroup = try reveal(groupPath)
        try require(allViews(refreshedGroup.view).compactMap { $0 as? NSPopUpButton }.first?.titleOfSelectedItem == profile.proxyOrder[1],
                    "局部组刷新未显示新的选择")
        profile.groupOrder = []
        profile.groups = [:]
        policyCollectionView.reloadData()
        settle()
        try require(policyCollectionView.numberOfItems(inSection: 1) == 1, "无策略组时丢失新增组卡片")
        _ = try reveal(IndexPath(item: 0, section: 1))
        return ["scene": scene, "assertions": assertionCount, "scrollViewCount": scrolls.count,
                "documentIsCollection": true, "scrollerStyles": styles,
                "documentHeightBeforeMutations": oldHeight, "shownProxyCount": 30, "shownGroupCount": 18]
    }

    func verifyProfileTransition() throws -> [String: Any] {
        settle()
        let oldPath = IndexPath(item: 0, section: 0)
        let oldName = filteredProxyNames[0]
        let newName = "新配置节点"
        profile.proxies = [newName: ProxyPolicy(name: newName, kind: .external,
            host: "203.0.113.44", port: 443, adapterType: "vmess")]
        profile.proxyOrder = [newName]
        profile.groupOrder = ["新配置组 A", "新配置组 B"]
        profile.groups = Dictionary(uniqueKeysWithValues: profile.groupOrder.map {
            ($0, PolicyGroup(name: $0, kind: .select, members: [newName, "DIRECT"]))
        })
        // Replays the real group refresh before asynchronous search commits.
        policyCollectionView.reloadSections(IndexSet(integer: 1))
        settle()
        let stale = collectionView(policyCollectionView, itemForRepresentedObjectAt: oldPath)
        try require(!(stale is ProxyCardCollectionItem), "跨配置待搜索期间强制创建了已删除节点")
        try require(collectionView(policyCollectionView, shouldSelectItemsAt: [oldPath]).isEmpty,
                    "跨配置待搜索期间允许选择已删除节点")
        collectionView(policyCollectionView, didSelectItemsAt: [oldPath])
        try require(!usedNames.contains(oldName), "跨配置待搜索期间使用了已删除节点")
        policyCollectionView.reloadItems(at: [oldPath])
        settle()
        try require(policyCollectionView.numberOfItems(inSection: 1) == 3, "组更新错误覆盖了节点 section")
        filteredProxyNames = profile.proxyOrder
        policyCollectionView.reloadSections(IndexSet(integer: 0))
        settle()
        try require(policyCollectionView.numberOfItems(inSection: 0) == 2
                    && policyCollectionView.numberOfItems(inSection: 1) == 3, "新搜索提交后节点/组数量错误")
        let node = try reveal(oldPath)
        try require(allViews(node.view).compactMap { $0 as? NSTextField }.contains { $0.stringValue == newName },
                    "跨配置搜索提交后仍呈现旧节点")
        collectionView(policyCollectionView, didSelectItemsAt: [oldPath])
        try require(usedNames == [newName], "跨配置节点选择没有对应新身份")
        let removedGroup = profile.groupOrder.removeFirst()
        profile.groups.removeValue(forKey: removedGroup)
        policyCollectionView.reloadSections(IndexSet(integer: 1))
        policyCollectionView.reloadItems(at: [oldPath])
        settle()
        try require(policyCollectionView.numberOfItems(inSection: 1) == 2, "组删除和节点局部刷新交错破坏组数量")
        let groupPath = IndexPath(item: 0, section: 1)
        let group = try reveal(groupPath)
        try require(allViews(group.view).compactMap { $0 as? NSTextField }.contains { $0.stringValue == "新配置组 B" },
                    "组删除和节点局部刷新交错后策略组身份错误")
        return ["assertions": assertionCount, "staleNodeLookupSafe": true,
                "removedNodeNotSelected": true, "sectionReloadsPreserveCurrentIdentities": true]
    }

    func verifyLargeSubscription() throws -> [String: Any] {
        settle()
        for index in profile.proxyOrder.count..<2000 {
            let name = "大订阅节点 \(index)"
            profile.proxyOrder.append(name)
            profile.proxies[name] = ProxyPolicy(name: name, kind: .external,
                host: "203.0.113.1", port: 443, adapterType: "vmess")
        }
        filteredProxyNames = profile.proxyOrder
        let requestsBefore = recorder.itemRequests
        policyCollectionView.reloadData()
        top()
        let initialRequests = recorder.itemRequests - requestsBefore
        let materialized = (0..<2001).filter { policyCollectionView.item(at: IndexPath(item: $0, section: 0)) != nil }.count
        try require(initialRequests < 120, "大订阅最初实际请求了全部卡片：\(initialRequests)")
        try require(materialized > 0 && materialized < 120, "大订阅最初维护了全部节点：\(materialized)/2001")
        try require(policyCollectionView.numberOfItems(inSection: 0) == 2001, "大订阅节点数不完整")
        let node = try reveal(IndexPath(item: 1999, section: 0))
        try require(allViews(node.view).compactMap { $0 as? NSTextField }.contains { $0.stringValue == "大订阅节点 1999" },
                    "滚动至最后节点后呈现了错误内容")
        let lastGroup = IndexPath(item: profile.groupOrder.count, section: 1)
        _ = try reveal(lastGroup)
        try require(scroll.contentView.bounds.origin.y > 20_000, "大订阅不能从节点连续滚动至策略组")
        let lastFrame = try attributes(lastGroup.item, section: 1).frame
        try require(scroll.contentView.bounds.insetBy(dx: -1, dy: -1).contains(lastFrame), "大订阅最后组卡片不可完整到达")
        top()
        let first = try reveal(IndexPath(item: 0, section: 0))
        try require(allViews(first.view).compactMap { $0 as? NSTextField }.contains { $0.stringValue == profile.proxyOrder[0] },
                    "返回顶部后没有恢复正确节点")
        try require(recorder.itemRequests - requestsBefore < 300, "三个视口触发了大订阅全量卡片创建")
        let beforePartial = recorder.itemRequests
        policyCollectionView.reloadItems(at: [IndexPath(item: 0, section: 0)])
        settle()
        try require(recorder.itemRequests - beforePartial < 120, "局部刷新重新请求了整个大订阅")
        return ["proxyCount": 2000, "materializedProxyCardsAtTop": materialized,
                "actualInitialProductionItemRequests": initialRequests,
                "actualRequestsAcrossTopBottomTopAndPartialReload": recorder.itemRequests - requestsBefore,
                "documentHeight": policyCollectionView.frame.height,
                "assertions": assertionCount, "noFullCardInstantiation": true]
    }
}

@main private enum PolicyPageRegression {
    static func main() throws {
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.02))
        let destination = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        var reports: [[String: Any]] = []
        for (mode, appearance) in [("light", NSAppearance(named: .aqua)!), ("dark", NSAppearance(named: .darkAqua)!)] {
            NSApp.appearance = appearance
            for width in [CGFloat(1020), 740] {
                let fixture = PolicyPageFixture(size: NSSize(width: width, height: 800), appearance: appearance)
                reports.append(try fixture.verifyAndRender(destination, scene: "\(mode)-\(Int(width))"))
            }
        }
        let large = PolicyPageFixture(size: NSSize(width: 1020, height: 800), appearance: NSAppearance(named: .aqua)!)
        let largeReport = try large.verifyLargeSubscription()
        let transition = PolicyPageFixture(size: NSSize(width: 740, height: 800), appearance: NSAppearance(named: .aqua)!)
        let transitionReport = try transition.verifyProfileTransition()
        try JSONSerialization.data(withJSONObject: ["scenes": reports, "largeSubscription": largeReport,
            "profileTransition": transitionReport,
            "actualProductionBuildersCollectionsAndCards": true, "memoryOnlyDataAndActions": true,
            "unshownTestWindowOnlyNoRealAppControllerNetworkOrUserConfiguration": true,
            "windowWasNeverOrderedActivatedOrRun": true,
            "keyboardScope": "synthetic native pageDown responder command; no real window focus or key binding"],
            options: [.prettyPrinted, .sortedKeys]).write(to: destination.appendingPathComponent("results.json"))
        print("PASS \(reports.count) actual AppKit policy scenes + 2000 nodes + profile transition; \(reports.reduce(0) { $0 + ($1["assertions"] as! Int) } + large.assertionCount + transition.assertionCount) assertions; direct native document, both scrollers, wheel/pageDown, resize/search/group/partial refresh/actions, bounded actual item requests")
    }
}
