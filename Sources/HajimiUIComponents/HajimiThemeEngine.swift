import AppKit
import Foundation

public extension NSColor {
    /// 动态保留主题颜色求值的透明度包装器（避免 AppKit withAlphaComponent 在初始化瞬间将动态 NSColor 固化为静态颜色）
    func themedAlpha(_ alpha: CGFloat) -> NSColor {
        let base = self
        return NSColor(name: nil) { appearance in
            var resolved: NSColor = base
            appearance.performAsCurrentDrawingAppearance {
                resolved = base.usingColorSpace(.deviceRGB) ?? base
            }
            return resolved.withAlphaComponent(alpha)
        }
    }
}

/// 哈基米 (Hajimi) 可序列化 UI 主题配置模型（支持单主题 `.hajimitheme` / `.json` 文件导入与 URL 远程导入）
public struct HajimiUITheme: Codable, Equatable, Identifiable {
    public var id: String
    public var code: String
    public var name: String
    public var englishName: String
    public var category: String
    public var layoutStyle: String
    /// `"system"` | `"dark"` | `"light"`
    public var appearanceMode: String
    public var cardCornerRadius: Double
    public var innerCornerRadius: Double
    public var workspaceHex: String
    public var sidebarHex: String
    public var panelHex: String
    public var elevatedPanelHex: String
    public var mutedPanelHex: String
    public var accentHex: String
    public var accentTextHex: String
    public var uploadAccentHex: String
    public var indigoAccentHex: String
    public var textPrimaryHex: String
    public var textSecondaryHex: String
    public var borderAlpha: Double
    public var highlightAlpha: Double
    public var featureSummary: String
    public var description: String
    public var sourceURL: String?
    public var isBuiltIn: Bool

    public init(
        id: String,
        code: String,
        name: String,
        englishName: String = "",
        category: String = "自定义与外部导入",
        layoutStyle: String = "L1 经典左栏+Bento",
        appearanceMode: String = "dark",
        cardCornerRadius: Double = 14.0,
        innerCornerRadius: Double? = nil,
        workspaceHex: String,
        sidebarHex: String,
        panelHex: String,
        elevatedPanelHex: String,
        mutedPanelHex: String? = nil,
        accentHex: String,
        accentTextHex: String? = nil,
        uploadAccentHex: String,
        indigoAccentHex: String? = nil,
        textPrimaryHex: String = "#F8FAFC",
        textSecondaryHex: String = "#94A3B8",
        borderAlpha: Double = 0.14,
        highlightAlpha: Double? = nil,
        featureSummary: String = "",
        description: String = "",
        sourceURL: String? = nil,
        isBuiltIn: Bool = false
    ) {
        self.id = id
        self.code = code
        self.name = name
        self.englishName = englishName.isEmpty ? name : englishName
        self.category = category
        self.layoutStyle = layoutStyle
        self.appearanceMode = appearanceMode.lowercased()
        self.cardCornerRadius = max(0, min(32, cardCornerRadius))
        self.innerCornerRadius = innerCornerRadius ?? max(0, round(self.cardCornerRadius * 0.72))
        self.workspaceHex = Self.normalizeHex(workspaceHex, fallback: "#0F1214")
        self.sidebarHex = Self.normalizeHex(sidebarHex, fallback: "#14181B")
        self.panelHex = Self.normalizeHex(panelHex, fallback: "#1A1F22")
        self.elevatedPanelHex = Self.normalizeHex(elevatedPanelHex, fallback: "#202629")
        self.mutedPanelHex = Self.normalizeHex(mutedPanelHex ?? sidebarHex, fallback: "#14181B")
        self.accentHex = Self.normalizeHex(accentHex, fallback: "#2ED19C")
        self.accentTextHex = Self.normalizeHex(accentTextHex ?? accentHex, fallback: "#2ED19C")
        self.uploadAccentHex = Self.normalizeHex(uploadAccentHex, fallback: "#59B0FA")
        self.indigoAccentHex = Self.normalizeHex(indigoAccentHex ?? uploadAccentHex, fallback: "#8A94FA")
        self.textPrimaryHex = Self.normalizeHex(textPrimaryHex, fallback: "#F8FAFC")
        self.textSecondaryHex = Self.normalizeHex(textSecondaryHex, fallback: "#94A3B8")
        self.borderAlpha = max(0.04, min(0.85, borderAlpha))
        self.highlightAlpha = highlightAlpha ?? (self.appearanceMode == "light" ? 0.75 : 0.08)
        self.featureSummary = featureSummary
        self.description = description
        self.sourceURL = sourceURL
        self.isBuiltIn = isBuiltIn
    }

    private enum CodingKeys: String, CodingKey {
        case id, code, name, englishName, en, category, catName, layoutStyle, layoutName, layout
        case appearanceMode, mode, cardCornerRadius, radius, innerCornerRadius
        case workspaceHex, bg, sidebarHex, sidebar, panelHex, panel, elevatedPanelHex, elevated
        case mutedPanelHex, accentHex, accent, accentTextHex, uploadAccentHex, accent2, indigoAccentHex
        case textPrimaryHex, text, textSecondaryHex, subtext
        case borderAlpha, highlightAlpha, featureSummary, feature, description, desc, sourceURL, isBuiltIn
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let rawName = (try? c.decode(String.self, forKey: .name)) ?? "自定义主题"
        let rawCode = (try? c.decode(String.self, forKey: .code)) ?? "CUSTOM"
        let rawId = (try? c.decode(String.self, forKey: .id))
            ?? "custom-\(rawCode.lowercased().replacingOccurrences(of: "#", with: ""))-\( abs(rawName.hashValue) % 10000 )"
        let en = (try? c.decode(String.self, forKey: .englishName))
            ?? (try? c.decode(String.self, forKey: .en)) ?? rawName
        let cat = (try? c.decode(String.self, forKey: .category))
            ?? (try? c.decode(String.self, forKey: .catName)) ?? "自定义与外部导入"
        let layout = (try? c.decode(String.self, forKey: .layoutStyle))
            ?? (try? c.decode(String.self, forKey: .layoutName))
            ?? (try? c.decode(String.self, forKey: .layout)) ?? "L1 经典左栏+Bento"
        let mode = (try? c.decode(String.self, forKey: .appearanceMode))
            ?? (try? c.decode(String.self, forKey: .mode)) ?? "dark"
        let radius = (try? c.decode(Double.self, forKey: .cardCornerRadius))
            ?? (try? c.decode(Double.self, forKey: .radius)) ?? 14.0
        let innerR = try? c.decode(Double.self, forKey: .innerCornerRadius)

        let ws = (try? c.decode(String.self, forKey: .workspaceHex))
            ?? (try? c.decode(String.self, forKey: .bg)) ?? "#0F1214"
        let sb = (try? c.decode(String.self, forKey: .sidebarHex))
            ?? (try? c.decode(String.self, forKey: .sidebar)) ?? ws
        let pn = (try? c.decode(String.self, forKey: .panelHex))
            ?? (try? c.decode(String.self, forKey: .panel)) ?? "#1A1F22"
        let el = (try? c.decode(String.self, forKey: .elevatedPanelHex))
            ?? (try? c.decode(String.self, forKey: .elevated)) ?? pn
        let mt = (try? c.decode(String.self, forKey: .mutedPanelHex)) ?? sb
        let ac = (try? c.decode(String.self, forKey: .accentHex))
            ?? (try? c.decode(String.self, forKey: .accent)) ?? "#2ED19C"
        let act = (try? c.decode(String.self, forKey: .accentTextHex)) ?? ac
        let up = (try? c.decode(String.self, forKey: .uploadAccentHex))
            ?? (try? c.decode(String.self, forKey: .accent2)) ?? "#59B0FA"
        let ind = (try? c.decode(String.self, forKey: .indigoAccentHex)) ?? up
        let tp = (try? c.decode(String.self, forKey: .textPrimaryHex))
            ?? (try? c.decode(String.self, forKey: .text)) ?? (mode == "light" ? "#0F172A" : "#F8FAFC")
        let ts = (try? c.decode(String.self, forKey: .textSecondaryHex))
            ?? (try? c.decode(String.self, forKey: .subtext)) ?? (mode == "light" ? "#475569" : "#94A3B8")
        let bAlpha = (try? c.decode(Double.self, forKey: .borderAlpha)) ?? 0.16
        let hAlpha = try? c.decode(Double.self, forKey: .highlightAlpha)
        let feat = (try? c.decode(String.self, forKey: .featureSummary))
            ?? (try? c.decode(String.self, forKey: .feature)) ?? ""
        let desc = (try? c.decode(String.self, forKey: .description))
            ?? (try? c.decode(String.self, forKey: .desc)) ?? ""
        let srcURL = try? c.decode(String.self, forKey: .sourceURL)
        let builtIn = (try? c.decode(Bool.self, forKey: .isBuiltIn)) ?? false

        self.init(
            id: rawId, code: rawCode, name: rawName, englishName: en,
            category: cat, layoutStyle: layout, appearanceMode: mode,
            cardCornerRadius: radius, innerCornerRadius: innerR,
            workspaceHex: ws, sidebarHex: sb, panelHex: pn, elevatedPanelHex: el,
            mutedPanelHex: mt, accentHex: ac, accentTextHex: act,
            uploadAccentHex: up, indigoAccentHex: ind,
            textPrimaryHex: tp, textSecondaryHex: ts,
            borderAlpha: bAlpha, highlightAlpha: hAlpha,
            featureSummary: feat, description: desc,
            sourceURL: srcURL, isBuiltIn: builtIn
        )
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(code, forKey: .code)
        try c.encode(name, forKey: .name)
        try c.encode(englishName, forKey: .englishName)
        try c.encode(category, forKey: .category)
        try c.encode(layoutStyle, forKey: .layoutStyle)
        try c.encode(appearanceMode, forKey: .appearanceMode)
        try c.encode(cardCornerRadius, forKey: .cardCornerRadius)
        try c.encode(innerCornerRadius, forKey: .innerCornerRadius)
        try c.encode(workspaceHex, forKey: .workspaceHex)
        try c.encode(sidebarHex, forKey: .sidebarHex)
        try c.encode(panelHex, forKey: .panelHex)
        try c.encode(elevatedPanelHex, forKey: .elevatedPanelHex)
        try c.encode(mutedPanelHex, forKey: .mutedPanelHex)
        try c.encode(accentHex, forKey: .accentHex)
        try c.encode(accentTextHex, forKey: .accentTextHex)
        try c.encode(uploadAccentHex, forKey: .uploadAccentHex)
        try c.encode(indigoAccentHex, forKey: .indigoAccentHex)
        try c.encode(textPrimaryHex, forKey: .textPrimaryHex)
        try c.encode(textSecondaryHex, forKey: .textSecondaryHex)
        try c.encode(borderAlpha, forKey: .borderAlpha)
        try c.encode(highlightAlpha, forKey: .highlightAlpha)
        try c.encode(featureSummary, forKey: .featureSummary)
        try c.encode(description, forKey: .description)
        try c.encodeIfPresent(sourceURL, forKey: .sourceURL)
        try c.encode(isBuiltIn, forKey: .isBuiltIn)
    }

    public static func normalizeHex(_ raw: String, fallback: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "#", with: "")
        guard trimmed.count == 6 || trimmed.count == 3 else { return fallback }
        let expanded: String
        if trimmed.count == 3 {
            expanded = trimmed.map { "\($0)\($0)" }.joined()
        } else {
            expanded = trimmed
        }
        guard UInt32(expanded, radix: 16) != nil else { return fallback }
        return "#" + expanded.uppercased()
    }

    public static func color(fromHex hex: String, alpha: CGFloat = 1.0) -> NSColor {
        let cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "#", with: "")
        let expanded = cleaned.count == 3 ? cleaned.map { "\($0)\($0)" }.joined() : cleaned
        guard let value = UInt32(expanded, radix: 16) else {
            return NSColor(calibratedRed: 0.18, green: 0.82, blue: 0.61, alpha: alpha)
        }
        let r = CGFloat((value >> 16) & 0xFF) / 255.0
        let g = CGFloat((value >> 8) & 0xFF) / 255.0
        let b = CGFloat(value & 0xFF) / 255.0
        return NSColor(calibratedRed: r, green: g, blue: b, alpha: alpha)
    }

    public var displayTitle: String {
        "\(code) \(name)"
    }

    public var isDark: Bool {
        appearanceMode.lowercased() != "light"
    }
}

/// 哈基米主题合集包模型（支持单次通过文件或 URL 导入多款主题）
public struct HajimiUIThemePack: Codable, Equatable {
    public var schemaVersion: String
    public var packName: String
    public var description: String
    public var themes: [HajimiUITheme]

    public init(schemaVersion: String = "1.0",
                packName: String = "哈基米 50款官方UI主题全集包",
                description: String = "支持在哈基米 (Hajimi) 设置 → UI 主题设置中通过本地文件或远程 URL 导入",
                themes: [HajimiUITheme]) {
        self.schemaVersion = schemaVersion
        self.packName = packName
        self.description = description
        self.themes = themes
    }
}

/// 哈基米全局 UI 主题管理器（负责 50 款预设主题管理、URL 下载导入、本地文件导入、持久化与 AppKit 实时热更新）
public final class HajimiThemeCenter {
    public static let shared = HajimiThemeCenter()
    public static let didChangeNotification = Notification.Name("HajimiThemeCenterDidChangeNotification")

    public enum ThemeError: LocalizedError {
        case invalidURL(String)
        case httpStatus(Int)
        case emptyData
        case invalidJSONFormat(String)
        case cannotDeleteBuiltIn

        public var errorDescription: String? {
            switch self {
            case .invalidURL(let url):
                return "无效的主题 URL 地址：\(url)（请使用 http:// 或 https://）"
            case .httpStatus(let code):
                return "远程主题服务器返回 HTTP 状态码 \(code)"
            case .emptyData:
                return "主题文件内容为空"
            case .invalidJSONFormat(let detail):
                return "无法解析主题 JSON 配置：\(detail)"
            case .cannotDeleteBuiltIn:
                return "内置预设主题不可删除"
            }
        }
    }

    private let lock = NSLock()
    private let defaultsKey = "hajimi.selectedUIThemeID"
    private let appearanceOverrideKey = "hajimi.appearanceModeOverride"
    private let session: URLSession
    private var customThemes: [HajimiUITheme] = []
    private var selectedThemeID: String

    public var themesDirectoryURL: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = appSupport.appendingPathComponent("Hajimi/themes", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private var customThemesStoreURL: URL {
        themesDirectoryURL.appendingPathComponent("custom-themes.json")
    }

    private init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 35
        config.httpAdditionalHeaders = ["User-Agent": "HajimiThemeImporter/1.0 macOS"]
        session = URLSession(configuration: config)
        selectedThemeID = UserDefaults.standard.string(forKey: defaultsKey) ?? Self.builtInThemes[0].id
        loadCustomThemesFromDisk()
        syncThemeToUserDefaults()
    }

    public var allThemes: [HajimiUITheme] {
        lock.withLock {
            Self.builtInThemes + customThemes
        }
    }

    public var importedThemes: [HajimiUITheme] {
        lock.withLock { customThemes }
    }

    public var currentTheme: HajimiUITheme {
        lock.withLock {
            if let custom = customThemes.first(where: { $0.id == selectedThemeID }) {
                return custom
            }
            if let builtIn = Self.builtInThemes.first(where: { $0.id == selectedThemeID }) {
                return builtIn
            }
            return Self.builtInThemes[0]
        }
    }

    public var isDefaultAdaptiveThemeActive: Bool {
        currentTheme.id == Self.builtInThemes[0].id
    }

    /// `"theme"` (跟随主题默认) | `"system"` | `"dark"` | `"light"`
    public var appearanceOverride: String {
        get { UserDefaults.standard.string(forKey: appearanceOverrideKey) ?? "theme" }
        set {
            UserDefaults.standard.set(newValue, forKey: appearanceOverrideKey)
            applyCurrentThemeToApplication()
        }
    }

    public var categories: [String] {
        var result: [String] = ["全部主题"]
        for theme in allThemes where !result.contains(theme.category) {
            result.append(theme.category)
        }
        return result
    }

    public func selectTheme(id: String) {
        lock.withLock {
            let exists = Self.builtInThemes.contains(where: { $0.id == id })
                || customThemes.contains(where: { $0.id == id })
            selectedThemeID = exists ? id : Self.builtInThemes[0].id
            UserDefaults.standard.set(selectedThemeID, forKey: defaultsKey)
        }
        applyCurrentThemeToApplication()
    }

    public func resetToDefaultTheme() {
        UserDefaults.standard.set("theme", forKey: appearanceOverrideKey)
        selectTheme(id: Self.builtInThemes[0].id)
    }

    // MARK: - Local File & Remote URL Theme Import / Export

    /// 解析单主题 JSON、主题包 `HajimiUIThemePack` JSON 或 `[HajimiUITheme]` 数组
    public static func parseThemes(from data: Data, sourceURL: String? = nil, customName: String? = nil) throws -> [HajimiUITheme] {
        guard !data.isEmpty else { throw ThemeError.emptyData }
        let decoder = JSONDecoder()
        var parsed: [HajimiUITheme] = []

        if let pack = try? decoder.decode(HajimiUIThemePack.self, from: data), !pack.themes.isEmpty {
            parsed = pack.themes
        } else if let array = try? decoder.decode([HajimiUITheme].self, from: data), !array.isEmpty {
            parsed = array
        } else if let single = try? decoder.decode(HajimiUITheme.self, from: data) {
            parsed = [single]
        } else {
            throw ThemeError.invalidJSONFormat("文件需为单个主题 JSON 对象或包含 themes 数组的主题包格式")
        }

        let trimmedCustomName = customName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return parsed.enumerated().map { idx, item in
            var copy = item
            copy.isBuiltIn = false
            if let sourceURL, !sourceURL.isEmpty {
                copy.sourceURL = sourceURL
            }
            if !trimmedCustomName.isEmpty {
                copy.name = parsed.count == 1 ? trimmedCustomName : "\(trimmedCustomName) (\(idx + 1))"
            }
            if copy.category.isEmpty || Self.builtInThemes.contains(where: { $0.id == copy.id }) {
                copy.id = "imported-\(copy.code.lowercased().replacingOccurrences(of: "#", with: ""))-\(abs(copy.name.hashValue) % 100000)"
            }
            return copy
        }
    }

    /// 从本地文件（`.hajimitheme` 或 `.json`）导入一个或多个主题
    @discardableResult
    public func importFromFile(url: URL, customName: String? = nil, autoApply: Bool = true) throws -> [HajimiUITheme] {
        let data = try Data(contentsOf: url)
        let fallbackName = customName?.trimmingCharacters(in: .whitespacesAndNewlines)
        let imported = try Self.parseThemes(from: data, sourceURL: nil, customName: fallbackName)
        upsertCustomThemes(imported)
        if autoApply, let first = imported.first {
            selectTheme(id: first.id)
        } else {
            NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
        }
        return imported
    }

    /// 从远程 HTTP / HTTPS URL 异步下载并导入主题配置或主题包
    public func importFromURL(urlString: String,
                              customName: String? = nil,
                              autoApply: Bool = true,
                              completion: @escaping (Result<[HajimiUITheme], Error>) -> Void) {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else {
            DispatchQueue.main.async {
                completion(.failure(ThemeError.invalidURL(urlString)))
            }
            return
        }

        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 20

        session.dataTask(with: request) { [weak self] data, response, error in
            if let error {
                DispatchQueue.main.async { completion(.failure(error)) }
                return
            }
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                DispatchQueue.main.async { completion(.failure(ThemeError.httpStatus(http.statusCode))) }
                return
            }
            guard let data, !data.isEmpty else {
                DispatchQueue.main.async { completion(.failure(ThemeError.emptyData)) }
                return
            }
            do {
                let imported = try Self.parseThemes(from: data, sourceURL: trimmed, customName: customName)
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.upsertCustomThemes(imported)
                    if autoApply, let first = imported.first {
                        self.selectTheme(id: first.id)
                    } else {
                        NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
                    }
                    completion(.success(imported))
                }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }.resume()
    }

    /// 导出单个主题为标准 `.hajimitheme.json` 文件
    public func exportTheme(_ theme: HajimiUITheme, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(theme)
        try data.write(to: url, options: .atomic)
    }

    /// 导出多款主题合集包为 `.hajimitheme.json` 文件
    public func exportAllThemesPack(to url: URL) throws {
        let pack = HajimiUIThemePack(themes: allThemes)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(pack)
        try data.write(to: url, options: .atomic)
    }

    public func removeCustomTheme(id: String) throws {
        var needsFallback = false
        try lock.withLock {
            guard !Self.builtInThemes.contains(where: { $0.id == id }) else {
                throw ThemeError.cannotDeleteBuiltIn
            }
            customThemes.removeAll { $0.id == id }
            if selectedThemeID == id {
                selectedThemeID = Self.builtInThemes[0].id
                UserDefaults.standard.set(selectedThemeID, forKey: defaultsKey)
                needsFallback = true
            }
        }
        saveCustomThemesToDisk()
        if needsFallback {
            applyCurrentThemeToApplication()
        } else {
            NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
        }
    }

    private func upsertCustomThemes(_ incoming: [HajimiUITheme]) {
        lock.withLock {
            for item in incoming {
                if let idx = customThemes.firstIndex(where: { $0.id == item.id || ($0.name == item.name && !$0.isBuiltIn) }) {
                    customThemes[idx] = item
                } else {
                    customThemes.append(item)
                }
            }
        }
        saveCustomThemesToDisk()
    }

    private func loadCustomThemesFromDisk() {
        guard FileManager.default.fileExists(atPath: customThemesStoreURL.path),
              let data = try? Data(contentsOf: customThemesStoreURL),
              let decoded = try? JSONDecoder().decode([HajimiUITheme].self, from: data) else {
            return
        }
        lock.withLock {
            customThemes = decoded
        }
    }

    private func saveCustomThemesToDisk() {
        let snapshot = lock.withLock { customThemes }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(snapshot) {
            try? data.write(to: customThemesStoreURL, options: .atomic)
        }
    }

    // MARK: - Live AppKit Theme Application & Objective-C Bridge Sync

    public var effectiveMenuAppearance: NSAppearance? {
        let theme = currentTheme
        let overrideMode = appearanceOverride
        let effectiveMode = overrideMode == "theme" ? theme.appearanceMode : overrideMode
        if isDefaultAdaptiveThemeActive && overrideMode == "theme" {
            return nil
        }
        switch effectiveMode {
        case "dark":
            return NSAppearance(named: .darkAqua)
        case "light":
            return NSAppearance(named: .aqua)
        default:
            return NSAppearance(named: theme.isDark ? .darkAqua : .aqua)
        }
    }

    public func syncThemeToUserDefaults() {
        let theme = currentTheme
        let defaults = UserDefaults.standard
        let isCustom = !isDefaultAdaptiveThemeActive
        defaults.set(isCustom, forKey: "hajimi.theme.customActive")
        defaults.set(theme.isDark, forKey: "hajimi.theme.isDark")
        defaults.set(theme.displayTitle, forKey: "hajimi.theme.displayTitle")
        defaults.set(theme.workspaceHex, forKey: "hajimi.theme.workspaceHex")
        defaults.set(theme.sidebarHex, forKey: "hajimi.theme.sidebarHex")
        defaults.set(theme.panelHex, forKey: "hajimi.theme.panelHex")
        defaults.set(theme.elevatedPanelHex, forKey: "hajimi.theme.elevatedHex")
        defaults.set(theme.mutedPanelHex, forKey: "hajimi.theme.mutedHex")
        defaults.set(theme.accentHex, forKey: "hajimi.theme.accentHex")
        defaults.set(theme.accentTextHex, forKey: "hajimi.theme.accentTextHex")
        defaults.set(theme.uploadAccentHex, forKey: "hajimi.theme.uploadHex")
        defaults.set(theme.indigoAccentHex, forKey: "hajimi.theme.indigoHex")
        defaults.set(theme.textPrimaryHex, forKey: "hajimi.theme.textPrimaryHex")
        defaults.set(theme.textSecondaryHex, forKey: "hajimi.theme.textSecondaryHex")
        defaults.set(theme.borderAlpha, forKey: "hajimi.theme.borderAlpha")
        defaults.set(theme.highlightAlpha, forKey: "hajimi.theme.highlightAlpha")
        defaults.set(theme.cardCornerRadius, forKey: "hajimi.theme.cardRadius")
        defaults.set(theme.innerCornerRadius, forKey: "hajimi.theme.innerRadius")
    }

    public func applyCurrentThemeToApplication() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.applyCurrentThemeToApplication() }
            return
        }
        syncThemeToUserDefaults()
        let theme = currentTheme
        let overrideMode = appearanceOverride
        let effectiveMode = overrideMode == "theme" ? theme.appearanceMode : overrideMode

        if isDefaultAdaptiveThemeActive && overrideMode == "theme" {
            NSApp?.appearance = nil
        } else {
            switch effectiveMode {
            case "dark":
                NSApp?.appearance = NSAppearance(named: .darkAqua)
            case "light":
                NSApp?.appearance = NSAppearance(named: .aqua)
            default:
                NSApp?.appearance = nil
            }
        }

        for window in NSApp?.windows ?? [] {
            window.appearance = NSApp?.appearance
            if window.backgroundColor != .clear {
                window.backgroundColor = HajimiAppearance.workspace
            }
            if let root = window.contentView {
                refreshViewHierarchy(root, theme: theme)
            }
        }
        NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
    }

    private func refreshViewHierarchy(_ view: NSView, theme: HajimiUITheme) {
        if let surface = view as? HajimiSurfaceView {
            surface.syncThemeCornerRadiusIfAppropriate()
            surface.updateLayer()
            surface.needsDisplay = true
            surface.layer?.setNeedsDisplay()
        } else if let navBtn = view as? HajimiNavigationButton {
            navBtn.contentTintColor = navBtn.isActivePage ? HajimiAppearance.accentText : .secondaryLabelColor
            navBtn.updateLayer()
            navBtn.needsDisplay = true
        } else if let table = view as? NSTableView {
            if table.backgroundColor != .clear {
                table.backgroundColor = HajimiAppearance.panel
            }
            table.reloadData()
            table.needsDisplay = true
        } else if let collection = view as? NSCollectionView {
            collection.reloadData()
            collection.needsDisplay = true
        } else if let textView = view as? NSTextView {
            textView.insertionPointColor = HajimiAppearance.accentText
            if textView.drawsBackground {
                textView.backgroundColor = HajimiAppearance.mutedPanel
            }
            if let scroll = textView.enclosingScrollView, scroll.drawsBackground {
                scroll.backgroundColor = HajimiAppearance.mutedPanel
            }
            textView.needsDisplay = true
        } else if let scroll = view as? NSScrollView {
            if scroll.drawsBackground {
                scroll.backgroundColor = HajimiAppearance.mutedPanel
            }
            if scroll.layer?.borderWidth ?? 0 > 0 {
                scroll.effectiveAppearance.performAsCurrentDrawingAppearance {
                    scroll.layer?.borderColor = HajimiAppearance.border.cgColor
                }
            }
            scroll.needsDisplay = true
        } else if let imageView = view as? NSImageView {
            if let tint = imageView.contentTintColor {
                imageView.contentTintColor = nil
                imageView.contentTintColor = tint
            }
            imageView.needsDisplay = true
        } else if let button = view as? NSButton {
            if let tint = button.contentTintColor {
                button.contentTintColor = nil
                button.contentTintColor = tint
            }
            if let bezel = button.bezelColor {
                button.bezelColor = nil
                button.bezelColor = bezel
            }
            button.needsDisplay = true
        } else if let textField = view as? NSTextField {
            if let color = textField.textColor {
                textField.textColor = nil
                textField.textColor = color
            }
            textField.needsDisplay = true
        }

        // Explicitly invoke viewDidChangeEffectiveAppearance so custom views (e.g. PolicyCardSurface,
        // DNSSettingsFormView, NetworkDiagnosticsView, HJTrafficDashboardView) update their layers
        // even when switching between two dark themes or two light themes.
        view.viewDidChangeEffectiveAppearance()
        view.needsDisplay = true
        view.layer?.setNeedsDisplay()

        for child in view.subviews {
            refreshViewHierarchy(child, theme: theme)
        }
    }

    // MARK: - Built-In 50 Curated UI Themes (#01 - #50)

    public static let builtInThemes: [HajimiUITheme] = [
        // 一、macOS 原生进化系列 (#01 - #07)
        HajimiUITheme(id: "theme-01-emerald-original", code: "#01", name: "翡翠原石 · 现版精修", englishName: "Hajimi Emerald Original Refined", category: "macOS 原生进化", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "system", cardCornerRadius: 14, workspaceHex: "#0F1214", sidebarHex: "#14181B", panelHex: "#1A1F22", elevatedPanelHex: "#202629", accentHex: "#2ED19C", uploadAccentHex: "#59B0FA", indigoAccentHex: "#8A94FA", featureSummary: "还原 HajimiAppearance.swift 1pt 镜面高光与翠玉自适应深浅色板", description: "100% 忠于项目现有 HajimiAppearance.swift 参数，支持随系统自动切换亮色/暗色。", isBuiltIn: true),
        HajimiUITheme(id: "theme-02-emerald-light", code: "#02", name: "翡翠白昼 · 现版亮色", englishName: "Hajimi Emerald Aqua Light", category: "macOS 原生进化", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "light", cardCornerRadius: 14, workspaceHex: "#F3F6F5", sidebarHex: "#EAEFED", panelHex: "#FFFFFF", elevatedPanelHex: "#F7FAF9", accentHex: "#0A8F69", uploadAccentHex: "#1C75D6", indigoAccentHex: "#545CD6", textPrimaryHex: "#0F291E", textSecondaryHex: "#526B61", featureSummary: "对应 HajimiAppearance.swift 的 .aqua 日间浅色标定参数", description: "温润护眼的白玉薄荷浅色基底 (#F3F6F5)，搭配深翠绿主色 (#0A8F69)。", isBuiltIn: true),
        HajimiUITheme(id: "theme-03-sequoia-vibrancy", code: "#03", name: "红杉冰晶 · Sequoia Vibrancy", englishName: "macOS 15 Sequoia Frosted Glass", category: "macOS 原生进化", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "dark", cardCornerRadius: 18, workspaceHex: "#0C1322", sidebarHex: "#111B2E", panelHex: "#162238", elevatedPanelHex: "#1E2D4A", accentHex: "#38BDF8", uploadAccentHex: "#34D399", indigoAccentHex: "#818CF8", featureSummary: "macOS 15 冰川蓝绿超透毛玻璃视觉", description: "冰川天青与深海蓝层次，带来通透轻盈的现代 macOS 质感。", isBuiltIn: true),
        HajimiUITheme(id: "theme-04-sonoma-pro", code: "#04", name: "深空钛金 · Sonoma Pro Studio", englishName: "Apple Pro Apps Carbon & Titanium", category: "macOS 原生进化", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "dark", cardCornerRadius: 10, workspaceHex: "#09090B", sidebarHex: "#111114", panelHex: "#16161A", elevatedPanelHex: "#1F1F24", accentHex: "#0A84FF", uploadAccentHex: "#30D158", indigoAccentHex: "#5E5CE6", featureSummary: "Final Cut / Logic Pro 级碳黑钛金面板", description: "纯正 Apple Pro Apps 工业级深空黑碳底色与高对比度系统蓝绿指示。", isBuiltIn: true),
        HajimiUITheme(id: "theme-05-visionos-glass", code: "#05", name: "空间视界 · visionOS Spatial Glass", englishName: "visionOS Spatial Computing Orbs", category: "macOS 原生进化", layoutStyle: "L9 visionOS空间景深窗", appearanceMode: "dark", cardCornerRadius: 24, workspaceHex: "#131620", sidebarHex: "#1D2230", panelHex: "#252B3D", elevatedPanelHex: "#30384F", accentHex: "#60A5FA", uploadAccentHex: "#C084FC", indigoAccentHex: "#818CF8", borderAlpha: 0.24, featureSummary: "24pt 大圆角空间计算磨砂玻璃窗体", description: "采用 visionOS 标志性的空间景深高光边框与大圆角容器。", isBuiltIn: true),
        HajimiUITheme(id: "theme-06-dynamic-island", code: "#06", name: "灵动猫耳 · Dynamic Island HUD", englishName: "MacBook Notch & MenuBar Companion", category: "macOS 原生进化", layoutStyle: "L6 状态栏灵动岛+弹窗", appearanceMode: "dark", cardCornerRadius: 16, workspaceHex: "#07090D", sidebarHex: "#0D1117", panelHex: "#141A23", elevatedPanelHex: "#1C2430", accentHex: "#10B981", uploadAccentHex: "#F59E0B", indigoAccentHex: "#38BDF8", featureSummary: "刘海屏灵动岛深邃黑与翡翠琥珀双色指示", description: "专为 MacBook 刘海屏与菜单栏常驻模式优化的深邃高对比配色。", isBuiltIn: true),
        HajimiUITheme(id: "theme-07-cupertino-silver", code: "#07", name: "雪山银铝合金 · Cupertino Silver", englishName: "Mac Studio Anodized Aluminum", category: "macOS 原生进化", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "light", cardCornerRadius: 12, workspaceHex: "#E8ECEF", sidebarHex: "#DDE3E8", panelHex: "#F8FAFC", elevatedPanelHex: "#FFFFFF", accentHex: "#2563EB", uploadAccentHex: "#059669", indigoAccentHex: "#4F46E5", textPrimaryHex: "#0F172A", textSecondaryHex: "#475569", featureSummary: "阳极氧化铝银灰质感 + 精密金属分割线", description: "契合 Mac Studio 与 Studio Display 银色铝合金外观。", isBuiltIn: true),

        // 二、哈基米橘猫萌宠系列 (#08 - #14)
        HajimiUITheme(id: "theme-08-ginger-tabby", code: "#08", name: "橘猫拍拍 · 哈基米官方吉祥物版", englishName: "Ginger Tabby Tap Official Edition", category: "哈基米橘猫萌宠", layoutStyle: "L8 萌宠猫抓板手账", appearanceMode: "light", cardCornerRadius: 22, workspaceHex: "#FFF8F0", sidebarHex: "#FFEEDB", panelHex: "#FFFFFF", elevatedPanelHex: "#FFF3E4", accentHex: "#F97316", uploadAccentHex: "#EA580C", indigoAccentHex: "#D97706", textPrimaryHex: "#431407", textSecondaryHex: "#9A3412", featureSummary: "提取 Resources/Hajimi.png 橘猫拍平板原画色板", description: "以项目吉祥物眨眼橘猫拍平板为核心视觉，奶油橘白配色温暖治愈。", isBuiltIn: true),
        HajimiUITheme(id: "theme-09-caramel-latte", code: "#09", name: "焦糖猫咖 · Caramel Oat Latte", englishName: "Cozy Cat Cafe Warm Dark", category: "哈基米橘猫萌宠", layoutStyle: "L8 萌宠猫抓板手账", appearanceMode: "dark", cardCornerRadius: 20, workspaceHex: "#1C1410", sidebarHex: "#261B15", panelHex: "#30221B", elevatedPanelHex: "#3D2C23", accentHex: "#FB923C", uploadAccentHex: "#FBBF24", indigoAccentHex: "#F59E0B", textPrimaryHex: "#FEF3C7", textSecondaryHex: "#D6BCFA", featureSummary: "烘焙咖啡豆暖棕暗色主题 + 琥珀橘猫耳徽章", description: "用深夜猫咖的暖棕与焦糖玛奇朵色调呵护夜间用眼。", isBuiltIn: true),
        HajimiUITheme(id: "theme-10-neko-arcade", code: "#10", name: "像素喵星 · 8-Bit Neko Arcade", englishName: "Retro Pixel Cat Gameboy HUD", category: "哈基米橘猫萌宠", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 6, workspaceHex: "#120E24", sidebarHex: "#1B1536", panelHex: "#241C47", elevatedPanelHex: "#2F255C", accentHex: "#F472B6", uploadAccentHex: "#38BDF8", indigoAccentHex: "#C084FC", featureSummary: "街机像素风紫粉电光蓝撞色", description: "将 19 种代理协议变成街机技能卡，充满复古游戏趣味。", isBuiltIn: true),
        HajimiUITheme(id: "theme-11-sakura-paw", code: "#11", name: "樱花猫爪 · Sakura Mochi Pastel", englishName: "Spring Sakura & Mint Cat Paw", category: "哈基米橘猫萌宠", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "light", cardCornerRadius: 22, workspaceHex: "#FFF5F7", sidebarHex: "#FFE4EA", panelHex: "#FFFFFF", elevatedPanelHex: "#FFF0F3", accentHex: "#FB7185", uploadAccentHex: "#10B981", indigoAccentHex: "#F43F5E", textPrimaryHex: "#4C0519", textSecondaryHex: "#9F1239", featureSummary: "樱花粉肉垫配色 + 薄荷绿低延迟点缀", description: "轻盈甜美的樱花麻薯与宇治薄荷撞色，拥有治愈系桌面颜值。", isBuiltIn: true),
        HajimiUITheme(id: "theme-12-midnight-kuro", code: "#12", name: "午夜黑猫 · Midnight Kuro Neko", englishName: "Velvet Obsidian & Golden Cat Eye", category: "哈基米橘猫萌宠", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 18, workspaceHex: "#0B0914", sidebarHex: "#120F21", panelHex: "#19152E", elevatedPanelHex: "#231D40", accentHex: "#FACC15", uploadAccentHex: "#A855F7", indigoAccentHex: "#C084FC", featureSummary: "丝绒暗夜紫黑底色 + 金色猫眼瞳孔聚焦", description: "灵感源自午夜黑猫发光的金色瞳孔，神秘而优雅。", isBuiltIn: true),
        HajimiUITheme(id: "theme-13-calico-craft", code: "#13", name: "三花手账 · Calico Craft Notebook", englishName: "Japanese Stationery & Washi Tape", category: "哈基米橘猫萌宠", layoutStyle: "L8 萌宠猫抓板手账", appearanceMode: "light", cardCornerRadius: 14, workspaceHex: "#FAF6EE", sidebarHex: "#F2EADB", panelHex: "#FFFDF9", elevatedPanelHex: "#F7F0E2", accentHex: "#D97706", uploadAccentHex: "#DC2626", indigoAccentHex: "#92400E", textPrimaryHex: "#292524", textSecondaryHex: "#78716C", featureSummary: "日系手账米白纸背景 + 三花猫暖橘焦糖色", description: "仿佛在一本精美的猫咪手账本上管理全球代理节点与分流规则。", isBuiltIn: true),
        HajimiUITheme(id: "theme-14-mecha-neko", code: "#14", name: "赛博机械喵 · Mecha-Neko 2077", englishName: "Cybernetic Ginger Cat Armor HUD", category: "哈基米橘猫萌宠", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 8, workspaceHex: "#090D16", sidebarHex: "#101726", panelHex: "#162033", elevatedPanelHex: "#1E2C47", accentHex: "#FF6B00", uploadAccentHex: "#00F0FF", indigoAccentHex: "#38BDF8", featureSummary: "机甲橘猫战术目镜：高能亮橙与电光青对撞", description: "当可爱哈基米穿上 C++20 零拷贝机甲外壳，兼具萌感与电竞张力。", isBuiltIn: true),

        // 三、网络极客与名作致敬系列 (#15 - #21)
        HajimiUITheme(id: "theme-15-surge-ponte", code: "#15", name: "疾风电涌 · Surge Ponte Pro", englishName: "Homage to Surge for Mac Engineering UI", category: "网络极客与名作致敬", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "dark", cardCornerRadius: 11, workspaceHex: "#11161F", sidebarHex: "#161C28", panelHex: "#1D2533", elevatedPanelHex: "#252F42", accentHex: "#3B82F6", uploadAccentHex: "#10B981", indigoAccentHex: "#6366F1", featureSummary: "致敬 Surge for Mac：严谨蓝灰工程卡片层次", description: "采用老牌网络瑞士军刀的经典深海蓝灰层次，信息密度极佳。", isBuiltIn: true),
        HajimiUITheme(id: "theme-16-clash-mihomo", code: "#16", name: "星河内核 · Clash Verge Mihomo", englishName: "Modern Mihomo Fluid Gradient Cards", category: "网络极客与名作致敬", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "dark", cardCornerRadius: 16, workspaceHex: "#0F1021", sidebarHex: "#15172E", panelHex: "#1C1F3B", elevatedPanelHex: "#25294D", accentHex: "#8B5CF6", uploadAccentHex: "#06B6D4", indigoAccentHex: "#A855F7", featureSummary: "流线型星河紫青策略组卡片", description: "融合 Clash Verge Rev 广受欢迎的星河紫青微光卡片与丝滑圆角。", isBuiltIn: true),
        HajimiUITheme(id: "theme-17-singbox-amber", code: "#17", name: "极光盒子 · Sing-box Minimalist", englishName: "Pure Sing-box Monospace & Amber", category: "网络极客与名作致敬", layoutStyle: "L10 极客命令流 ⌘K", appearanceMode: "dark", cardCornerRadius: 8, workspaceHex: "#0C0C0E", sidebarHex: "#121215", panelHex: "#18181C", elevatedPanelHex: "#202026", accentHex: "#F59E0B", uploadAccentHex: "#22C55E", indigoAccentHex: "#EAB308", featureSummary: "零废话极客黑底 + 琥珀金强调色", description: "面向钟爱 Sing-box 纯粹工程美学的硬核用户。", isBuiltIn: true),
        HajimiUITheme(id: "theme-18-wireguard-mesh", code: "#18", name: "雷霆隧道 · WireGuard & Tailscale Mesh", englishName: "Noise_IKpsk2 Mesh Topology View", category: "网络极客与名作致敬", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "light", cardCornerRadius: 10, workspaceHex: "#F4F5F7", sidebarHex: "#EBEDF0", panelHex: "#FFFFFF", elevatedPanelHex: "#F9FAFB", accentHex: "#88171A", uploadAccentHex: "#2563EB", indigoAccentHex: "#4F46E5", textPrimaryHex: "#111827", textSecondaryHex: "#6B7280", featureSummary: "WireGuard 龙血红与 Tailscale 极简灰白网格", description: "干净利落的北欧美学网络工具风格。", isBuiltIn: true),
        HajimiUITheme(id: "theme-19-xray-reality", code: "#19", name: "光学棱镜 · Xray REALITY Vision", englishName: "XTLS-rprx-Vision Zero-Copy Prism", category: "网络极客与名作致敬", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 16, workspaceHex: "#070B14", sidebarHex: "#0C1322", panelHex: "#111C30", elevatedPanelHex: "#172642", accentHex: "#00F2FE", uploadAccentHex: "#4FACFE", indigoAccentHex: "#38BDF8", featureSummary: "专为 VLESS + REALITY + Vision 打造的全息棱镜青蓝", description: "光学青蓝流光界面，呼应 XTLS-Vision 零拷贝直通。", isBuiltIn: true),
        HajimiUITheme(id: "theme-20-hysteria-brutal", code: "#20", name: "狂暴飞鱼 · Hysteria2 QUIC Brutal", englishName: "ngtcp2 QUIC & Salamander Speedometer", category: "网络极客与名作致敬", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 14, workspaceHex: "#0F0714", sidebarHex: "#190C21", panelHex: "#23112E", elevatedPanelHex: "#2E173D", accentHex: "#D946EF", uploadAccentHex: "#22D3EE", indigoAccentHex: "#E879F9", featureSummary: "超跑仪表盘电光品红与青色", description: "致敬 Hysteria 2 的极速爆发力，以高饱和电光品红展示满速吞吐。", isBuiltIn: true),
        HajimiUITheme(id: "theme-21-wireshark-inspector", code: "#21", name: "鲨鱼利刃 · Wireshark Packet Analyzer", englishName: "Deep Packet & Frame Inspector", category: "网络极客与名作致敬", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "light", cardCornerRadius: 4, workspaceHex: "#EEF2F6", sidebarHex: "#E2E8F0", panelHex: "#FFFFFF", elevatedPanelHex: "#F8FAFC", accentHex: "#0284C7", uploadAccentHex: "#16A34A", indigoAccentHex: "#2563EB", textPrimaryHex: "#0F172A", textSecondaryHex: "#475569", featureSummary: "报文分析器高对比蓝绿配色與紧凑直角框", description: "专为底层协议栈调试设计，清爽利落。", isBuiltIn: true),

        // 四、科研算法与硬核遥测系列 (#22 - #27)
        HajimiUITheme(id: "theme-22-kalman-ucb1", code: "#22", name: "卡尔曼实验室 · Kalman-Welford & UCB1 Lab", englishName: "Bandit & Bayesian Posterior Workbench", category: "科研算法与遥测实验室", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 8, workspaceHex: "#081018", sidebarHex: "#0D1824", panelHex: "#122233", elevatedPanelHex: "#182D42", accentHex: "#14B8A6", uploadAccentHex: "#F59E0B", indigoAccentHex: "#38BDF8", featureSummary: "科研蓝图青色与琥珀置信区间配色", description: "凸显 UCB1 + Cornish-Fisher 尾延迟与新息自适应卡尔曼滤波。", isBuiltIn: true),
        HajimiUITheme(id: "theme-23-kleinrock-bbrv3", code: "#23", name: "克莱因洛克示波器 · Kleinrock BDP & BBRv3", englishName: "BtlBw × RTprop & CoDel Oscilloscope", category: "科研算法与遥测实验室", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 6, workspaceHex: "#050B09", sidebarHex: "#091410", panelHex: "#0E1F19", elevatedPanelHex: "#142B23", accentHex: "#10B981", uploadAccentHex: "#38BDF8", indigoAccentHex: "#34D399", featureSummary: "数字示波器深绿荧光面板", description: "把 BBRv3 包络约束与 Kleinrock 最优工作点转化为精密示波器风格。", isBuiltIn: true),
        HajimiUITheme(id: "theme-24-odoh-padding", code: "#24", name: "零泄漏密码学盾 · ODoH & Padding Vault", englishName: "RFC 9230 HPKE & RFC 8467 Side-Channel Shield", category: "科研算法与遥测实验室", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "dark", cardCornerRadius: 12, workspaceHex: "#0B0F19", sidebarHex: "#111827", panelHex: "#1F2937", elevatedPanelHex: "#374151", accentHex: "#6366F1", uploadAccentHex: "#10B981", indigoAccentHex: "#818CF8", featureSummary: "密码学金库深石板蓝与防泄漏靛紫", description: "专为隐私安全极客打造的密码学金库视觉风格。", isBuiltIn: true),
        HajimiUITheme(id: "theme-25-sudoku-mieru", code: "#25", name: "数独与低熵矩阵 · Sudoku 4×4 & Mieru", englishName: "Fisher-Yates Bijection & Entropy Matrix", category: "科研算法与遥测实验室", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 8, workspaceHex: "#0D0D12", sidebarHex: "#14141D", panelHex: "#1C1C29", elevatedPanelHex: "#252538", accentHex: "#A78BFA", uploadAccentHex: "#34D399", indigoAccentHex: "#C084FC", featureSummary: "数独双射紫罗兰与低熵翡翠矩阵", description: "凸显哈基米抗审查协议的数学精髓。", isBuiltIn: true),
        HajimiUITheme(id: "theme-26-radix-trie", code: "#26", name: "双生基数树 · Radix Trie & Jump Hash", englishName: "Compact CIDR Radix & Stafford Mix13", category: "科研算法与遥测实验室", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "light", cardCornerRadius: 10, workspaceHex: "#F8FAFC", sidebarHex: "#F1F5F9", panelHex: "#FFFFFF", elevatedPanelHex: "#F8FAFC", accentHex: "#0F766E", uploadAccentHex: "#4F46E5", indigoAccentHex: "#0D9488", textPrimaryHex: "#0F172A", textSecondaryHex: "#64748B", featureSummary: "ACM SIGCOMM 学术论文白底青蓝图表配色", description: "如同翻阅一篇顶会论文的交互式实验附图，理性克制。", isBuiltIn: true),
        HajimiUITheme(id: "theme-27-cern-telemetry", code: "#27", name: "CERN 控制室 · High-Energy Telemetry", englishName: "LHC Accelerator Control Deck", category: "科研算法与遥测实验室", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 4, workspaceHex: "#090D11", sidebarHex: "#10171E", panelHex: "#16202A", elevatedPanelHex: "#1E2C3A", accentHex: "#0EA5E9", uploadAccentHex: "#EAB308", indigoAccentHex: "#38BDF8", featureSummary: "欧洲核子研究中心控制台蓝黄高对比遥测", description: "适合大屏全天候监控零拷贝流与 SWAR 校验和健康度。", isBuiltIn: true),

        // 五、现代先锋软件美学系列 (#28 - #34)
        HajimiUITheme(id: "theme-28-linear-dark", code: "#28", name: "线性精密 · Linear Precision Dark", englishName: "Linear App 1px Gradient Hairline", category: "现代先锋软件美学", layoutStyle: "L10 极客命令流 ⌘K", appearanceMode: "dark", cardCornerRadius: 10, workspaceHex: "#08090A", sidebarHex: "#0F1012", panelHex: "#141518", elevatedPanelHex: "#1C1D21", accentHex: "#5E6AD2", uploadAccentHex: "#26B5CE", indigoAccentHex: "#818CF8", borderAlpha: 0.10, featureSummary: "Linear 标志性极暗石墨底 + 1px 微光边框", description: "硅谷当代软件设计标杆风格，克制的靛紫微光与极致紧凑层次。", isBuiltIn: true),
        HajimiUITheme(id: "theme-29-raycast-ruby", code: "#29", name: "极速启动器 · Raycast Command Studio", englishName: "Raycast Ruby Glow & Keyboard First", category: "现代先锋软件美学", layoutStyle: "L10 极客命令流 ⌘K", appearanceMode: "dark", cardCornerRadius: 14, workspaceHex: "#0D090B", sidebarHex: "#161013", panelHex: "#1F161A", elevatedPanelHex: "#2B1F24", accentHex: "#FF6363", uploadAccentHex: "#FB923C", indigoAccentHex: "#F43F5E", featureSummary: "Raycast 标志性绯红暗夜光晕", description: "绯红与暖橙点缀的极速启动器风格，视觉张力十足。", isBuiltIn: true),
        HajimiUITheme(id: "theme-30-vercel-geist", code: "#30", name: "几何极简 · Vercel Geist Monochrome", englishName: "High-Contrast Pure Black & White Grid", category: "现代先锋软件美学", layoutStyle: "L7 瑞士网格/粗野分栏", appearanceMode: "dark", cardCornerRadius: 6, workspaceHex: "#000000", sidebarHex: "#0A0A0A", panelHex: "#111111", elevatedPanelHex: "#191919", accentHex: "#0070F3", uploadAccentHex: "#10B981", indigoAccentHex: "#38BDF8", borderAlpha: 0.18, featureSummary: "纯黑 #000000 OLED 基底 + 几何网格线", description: "剥离多余色彩干扰，呈现纯粹的工程秩序感。", isBuiltIn: true),
        HajimiUITheme(id: "theme-31-arc-canvas", code: "#31", name: "彩虹画框 · Arc Browser Boost Canvas", englishName: "Arc Framed Workspace & Soft Pastels", category: "现代先锋软件美学", layoutStyle: "L9 visionOS空间景深窗", appearanceMode: "light", cardCornerRadius: 20, workspaceHex: "#E0E7FF", sidebarHex: "#E0E7FF", panelHex: "#FFFFFF", elevatedPanelHex: "#F5F3FF", accentHex: "#4F46E5", uploadAccentHex: "#EC4899", indigoAccentHex: "#6366F1", textPrimaryHex: "#1E1B4B", textSecondaryHex: "#6366F1", featureSummary: "Arc 浏览器式薰衣草彩色画框包裹纯白内胆", description: "四周环绕柔和的薰衣草渐变画框，让主内容区宛如悬浮画布。", isBuiltIn: true),
        HajimiUITheme(id: "theme-32-stripe-fintech", code: "#32", name: "金融终端 · Stripe & Mercury Executive", englishName: "Fintech Precision Ledger & Sparklines", category: "现代先锋软件美学", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "light", cardCornerRadius: 12, workspaceHex: "#F6F8FA", sidebarHex: "#EEF1F5", panelHex: "#FFFFFF", elevatedPanelHex: "#F8FAFC", accentHex: "#635BFF", uploadAccentHex: "#00D4B6", indigoAccentHex: "#4F46E5", textPrimaryHex: "#0A2540", textSecondaryHex: "#425466", featureSummary: "Stripe 皇室蓝紫配色 + 银行账本级清爽层次", description: "像管理资产组合一样管理你的 19 种代理协议与分流规则。", isBuiltIn: true),
        HajimiUITheme(id: "theme-33-obsidian-graph", code: "#33", name: "黑曜石图谱 · Obsidian Neural Graph", englishName: "Knowledge Graph & Node Topology", category: "现代先锋软件美学", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 12, workspaceHex: "#110E1B", sidebarHex: "#181426", panelHex: "#201B33", elevatedPanelHex: "#2A2342", accentHex: "#A855F7", uploadAccentHex: "#EC4899", indigoAccentHex: "#C084FC", featureSummary: "Obsidian 暗夜紫知识图谱风格", description: "深邃舒适的暗夜紫罗兰配色，适合重度知识工作者。", isBuiltIn: true),
        HajimiUITheme(id: "theme-34-framer-bento", code: "#34", name: "流光巨幕 · Framer Motion Bento Pro", englishName: "Asymmetric Big-Type Bento Grid", category: "现代先锋软件美学", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "dark", cardCornerRadius: 22, workspaceHex: "#050508", sidebarHex: "#0B0B12", panelHex: "#12121E", elevatedPanelHex: "#1A1A2B", accentHex: "#38BDF8", uploadAccentHex: "#818CF8", indigoAccentHex: "#6366F1", featureSummary: "发布会级超大圆角与电光蓝靛紫渐变", description: "极具现代视觉冲击力的深邃蓝紫 Bento 风格。", isBuiltIn: true),

        // 六、赛博、复古与未来终端系列 (#35 - #40)
        HajimiUITheme(id: "theme-35-matrix-crt", code: "#35", name: "黑客帝国 · Matrix Phosphor CRT", englishName: "Green Phosphor Terminal & Scanlines", category: "赛博复古与未来终端", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 2, workspaceHex: "#020804", sidebarHex: "#041008", panelHex: "#071A0D", elevatedPanelHex: "#0B2614", accentHex: "#22C55E", uploadAccentHex: "#86EFAC", indigoAccentHex: "#4ADE80", borderAlpha: 0.35, featureSummary: "P1 荧光绿显像管终端风格", description: "纯正 90 年代 Hacker 终端美学，绿光盈盈。", isBuiltIn: true),
        HajimiUITheme(id: "theme-36-ibm-amber", code: "#36", name: "琥珀大型机 · IBM 3270 Amber Monolith", englishName: "1980s Mainframe Plasma Amber", category: "赛博复古与未来终端", layoutStyle: "L10 极客命令流 ⌘K", appearanceMode: "dark", cardCornerRadius: 2, workspaceHex: "#0C0700", sidebarHex: "#140C00", panelHex: "#1F1200", elevatedPanelHex: "#2B1A00", accentHex: "#F59E0B", uploadAccentHex: "#FDE047", indigoAccentHex: "#D97706", borderAlpha: 0.35, featureSummary: "复古气体等离子琥珀色 (#F59E0B) 荧光屏", description: "致敬大型机黄金时代的温暖琥珀单色显示器，零蓝光刺激。", isBuiltIn: true),
        HajimiUITheme(id: "theme-37-synthwave-1984", code: "#37", name: "落日合成波 · Synthwave Outrun 1984", englishName: "Miami Sunset & Neon Laser Grid", category: "赛博复古与未来终端", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "dark", cardCornerRadius: 12, workspaceHex: "#120428", sidebarHex: "#1B063B", panelHex: "#260952", elevatedPanelHex: "#340D6E", accentHex: "#00F5D4", uploadAccentHex: "#FF2A85", indigoAccentHex: "#F472B6", borderAlpha: 0.32, featureSummary: "80年代复古未来主义霓虹粉青撞色", description: "伴随 Hysteria2 / TUIC 的高速数据洪流，尽显复古霓虹张力。", isBuiltIn: true),
        HajimiUITheme(id: "theme-38-nerv-tactical", code: "#38", name: "特务机关 · Evangelion NERV Tactical", englishName: "MAGI Supercomputer Honeycomb HUD", category: "赛博复古与未来终端", layoutStyle: "L5 科研示波多窗矩阵", appearanceMode: "dark", cardCornerRadius: 0, workspaceHex: "#0A0705", sidebarHex: "#140D08", panelHex: "#1C110A", elevatedPanelHex: "#29180E", accentHex: "#FF5500", uploadAccentHex: "#22C55E", indigoAccentHex: "#F97316", borderAlpha: 0.45, featureSummary: "MAGI 超算风：黑底警报橙 + 翠绿安全指示", description: "将 DNS 防泄漏保护与增强模式 VIF 塑造成特务机关指挥中心大屏。", isBuiltIn: true),
        HajimiUITheme(id: "theme-39-submarine-sonar", code: "#39", name: "深海声呐 · Submarine Tactical Sonar", englishName: "Acoustic Radar & Deep Trench Cyan", category: "赛博复古与未来终端", layoutStyle: "L4 中心能量环+悬浮舱", appearanceMode: "dark", cardCornerRadius: 14, workspaceHex: "#030D14", sidebarHex: "#061621", panelHex: "#092030", elevatedPanelHex: "#0E2D42", accentHex: "#06B6D4", uploadAccentHex: "#10B981", indigoAccentHex: "#22D3EE", featureSummary: "深海海沟幽蓝与声呐青绿脉冲", description: "深海声呐罗盘色调，沉稳酷炫。", isBuiltIn: true),
        HajimiUITheme(id: "theme-40-spacex-dragon", code: "#40", name: "星舰航电 · SpaceX Dragon Avionics", englishName: "Crew Dragon Flight Deck Touchscreen", category: "赛博复古与未来终端", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "dark", cardCornerRadius: 6, workspaceHex: "#0B0E14", sidebarHex: "#11161F", panelHex: "#171E2B", elevatedPanelHex: "#1F293A", accentHex: "#38BDF8", uploadAccentHex: "#22C55E", indigoAccentHex: "#60A5FA", featureSummary: "载人龙飞船触控舱高对比航电蓝", description: "借鉴现代航天器座舱 UI 规范，关键状态清晰可读。", isBuiltIn: true),

        // 七、艺术流派与工业设计系列 (#41 - #46)
        HajimiUITheme(id: "theme-41-braun-rams", code: "#41", name: "博朗百灵 · Dieter Rams Braun T1000", englishName: "Less But Better Industrial Functionalism", category: "艺术流派与工业设计", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "light", cardCornerRadius: 8, workspaceHex: "#ECEAE4", sidebarHex: "#E2DFD7", panelHex: "#F7F6F2", elevatedPanelHex: "#FFFFFF", accentHex: "#EA580C", uploadAccentHex: "#16A34A", indigoAccentHex: "#D97706", textPrimaryHex: "#1C1917", textSecondaryHex: "#57534E", featureSummary: "迪特·拉姆斯工业美学：暖灰铝机身 + 博朗橙按键", description: "向 Braun T1000 收音机致敬，克制的暖灰米白盘面配亮橙主控键。", isBuiltIn: true),
        HajimiUITheme(id: "theme-42-teenage-eng", code: "#42", name: "少年工程 · Teenage Engineering Field", englishName: "OP-1 Field Modular Synthesizer UI", category: "艺术流派与工业设计", layoutStyle: "L7 瑞士网格/粗野分栏", appearanceMode: "light", cardCornerRadius: 4, workspaceHex: "#D6D7D2", sidebarHex: "#C8C9C3", panelHex: "#E8E9E4", elevatedPanelHex: "#F4F5F0", accentHex: "#FF4F00", uploadAccentHex: "#0066FF", indigoAccentHex: "#2563EB", textPrimaryHex: "#18181B", textSecondaryHex: "#52525B", featureSummary: "OP-1 Field 合成器工业灰底配高饱和橙蓝功能键", description: "把每个代理模块与 DNS 引擎当作一台精密的硬件合成器模块。", isBuiltIn: true),
        HajimiUITheme(id: "theme-43-swiss-grid", code: "#43", name: "瑞士国际网格 · Swiss Typographic Grid", englishName: "Josef Müller-Brockmann International Style", category: "艺术流派与工业设计", layoutStyle: "L7 瑞士网格/粗野分栏", appearanceMode: "light", cardCornerRadius: 0, workspaceHex: "#F5F3EF", sidebarHex: "#EBE8E1", panelHex: "#F5F3EF", elevatedPanelHex: "#FFFFFF", accentHex: "#E11D48", uploadAccentHex: "#111111", indigoAccentHex: "#BE123C", textPrimaryHex: "#111111", textSecondaryHex: "#555555", borderAlpha: 0.45, featureSummary: "苏黎世平面设计学派：直角正交网格与瑞士红", description: "依靠纯粹的对比、留白比例与正交网格线构筑博物馆级排版美感。", isBuiltIn: true),
        HajimiUITheme(id: "theme-44-neo-brutalism", code: "#44", name: "新粗野波普 · Neo-Brutalism Studio", englishName: "Hard Shadow & Bold Pop Color Blocks", category: "艺术流派与工业设计", layoutStyle: "L7 瑞士网格/粗野分栏", appearanceMode: "light", cardCornerRadius: 8, workspaceHex: "#FEF08A", sidebarHex: "#FDE047", panelHex: "#FFFFFF", elevatedPanelHex: "#E0F2FE", accentHex: "#EC4899", uploadAccentHex: "#3B82F6", indigoAccentHex: "#8B5CF6", textPrimaryHex: "#000000", textSecondaryHex: "#374151", borderAlpha: 0.65, featureSummary: "高饱和明黄/电光粉/天蓝波普撞色", description: "充满先锋潮牌与设计社区活力的 Neo-Brutalism 风格。", isBuiltIn: true),
        HajimiUITheme(id: "theme-45-soft-neumorphism", code: "#45", name: "温润新拟态 · Soft Neumorphism Tactile", englishName: "Extruded Ceramic & Soft Dual Shadows", category: "艺术流派与工业设计", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "light", cardCornerRadius: 20, workspaceHex: "#E0E5EC", sidebarHex: "#E0E5EC", panelHex: "#E6EBF2", elevatedPanelHex: "#EDF2F9", accentHex: "#0D9488", uploadAccentHex: "#4F46E5", indigoAccentHex: "#6366F1", textPrimaryHex: "#2D3748", textSecondaryHex: "#718096", featureSummary: "温润哑光陶瓷灰与青碧强调色", description: "触感温润柔和，如同从整块哑光陶瓷上自然浮起。", isBuiltIn: true),
        HajimiUITheme(id: "theme-46-nothing-dot", code: "#46", name: "透明点阵 · Nothing OS Dot-Matrix", englishName: "Transparent PCB & Red Dot Typography", category: "艺术流派与工业设计", layoutStyle: "L6 状态栏灵动岛+弹窗", appearanceMode: "dark", cardCornerRadius: 18, workspaceHex: "#0A0A0C", sidebarHex: "#111114", panelHex: "#17171C", elevatedPanelHex: "#222228", accentHex: "#EF4444", uploadAccentHex: "#38BDF8", indigoAccentHex: "#F87171", featureSummary: "Nothing 透明工业风：深灰电路底 + 标志性点阵红", description: "前卫极简的黑白红点阵工业语言。", isBuiltIn: true),

        // 八、东方美学与自然意境系列 (#47 - #50)
        HajimiUITheme(id: "theme-47-song-celadon", code: "#47", name: "宋代汝窑 · Song Dynasty Celadon", englishName: "Rain-Cleared Sky Blue Porcelain", category: "东方美学与自然意境", layoutStyle: "L2 顶栏胶囊+双联屏", appearanceMode: "light", cardCornerRadius: 16, workspaceHex: "#E4EFE9", sidebarHex: "#D7E6DE", panelHex: "#F3F8F5", elevatedPanelHex: "#FFFFFF", accentHex: "#2C6E58", uploadAccentHex: "#B45309", indigoAccentHex: "#0F766E", textPrimaryHex: "#1C3B32", textSecondaryHex: "#52796F", featureSummary: "“雨过天青云破处”汝窑天青釉色", description: "汲取宋代极简美学与汝窑天青色泽，温润如玉。", isBuiltIn: true),
        HajimiUITheme(id: "theme-48-ink-vermilion", code: "#48", name: "水墨丹青 · Ink Wash & Vermilion Seal", englishName: "Xuan Paper & Chinese Cinnabar Stamp", category: "东方美学与自然意境", layoutStyle: "L1 经典左栏+Bento", appearanceMode: "light", cardCornerRadius: 6, workspaceHex: "#F7F4ED", sidebarHex: "#EEE9DF", panelHex: "#FCFAF5", elevatedPanelHex: "#FFFFFF", accentHex: "#B91C1C", uploadAccentHex: "#1F2937", indigoAccentHex: "#991B1B", textPrimaryHex: "#1C1917", textSecondaryHex: "#57534E", featureSummary: "宣纸米白肌理 + 焦墨与朱砂印泥红", description: "以传统书画的焦墨、淡墨与朱砂印章红构建信息层级。", isBuiltIn: true),
        HajimiUITheme(id: "theme-49-kyoto-matcha", code: "#49", name: "京都竹林 · Kyoto Matcha & Hinoki", englishName: "Arashiyama Bamboo & Cypress Wood", category: "东方美学与自然意境", layoutStyle: "L3 窄轨图标+三栏工程台", appearanceMode: "dark", cardCornerRadius: 12, workspaceHex: "#0D1712", sidebarHex: "#13221A", panelHex: "#1A2E24", elevatedPanelHex: "#233D30", accentHex: "#34D399", uploadAccentHex: "#FBBF24", indigoAccentHex: "#10B981", featureSummary: "岚山深竹暗绿与桧木金暖色调", description: "深邃静谧的森林竹海绿意，极具自然呼吸感。", isBuiltIn: true),
        HajimiUITheme(id: "theme-50-nordic-aurora", code: "#50", name: "极夜北极光 · Nordic Aurora Borealis", englishName: "Icelandic Polar Night & Bioluminescence", category: "东方美学与自然意境", layoutStyle: "L9 visionOS空间景深窗", appearanceMode: "dark", cardCornerRadius: 22, workspaceHex: "#060D18", sidebarHex: "#0B1626", panelHex: "#102036", elevatedPanelHex: "#172D4A", accentHex: "#2DD4BF", uploadAccentHex: "#A855F7", indigoAccentHex: "#38BDF8", featureSummary: "冰岛极夜深蓝天幕 + 极光青绿与紫罗兰", description: "将北极光流体配色融入空间毛玻璃视窗。", isBuiltIn: true)
    ]
}
