import AppKit
import Foundation
import Network
import HajimiCore
import HajimiDiagnosticsUI
import HajimiMacOSObjC
import HajimiNativeCore
import HajimiRuntime
import HajimiUIComponents
import UniformTypeIdentifiers

extension MainWindowController {
    @objc func showNetworkDiagnostics() {
        if diagnosticsPanel == nil {
            NetworkPerformanceDiagnostics.shared.reset()
            NetworkPerformanceDiagnostics.shared.setCollecting(true)
            ProbeScheduler.shared.resetStatistics()
            ProbeScheduler.shared.setCollectingStatistics(true)
            let capabilities = NetworkDiagnosticsAppAdapter.capabilities(contextProvider: { [weak self] in
                self?.networkDiagnosticsContext ?? .unavailable
            }, startDiagnostics: { [weak self] update in
                guard let self else {
                    return AppNetworkRuntime.unavailable(onUpdate: update)
                }
                return self.networkRuntime.startDiagnostics(configuration: self.networkDiagnosticsConfiguration,
                    onUpdate: update)
            })
            let panel = NetworkDiagnosticsPanelController(capabilities: capabilities)
            panel.onVisibilityChanged = { visible in
                NetworkPerformanceDiagnostics.shared.setCollecting(visible)
                ProbeScheduler.shared.setCollectingStatistics(visible)
            }
            panel.onClose = { [weak self, weak panel] in
                NetworkPerformanceDiagnostics.shared.setCollecting(false)
                NetworkPerformanceDiagnostics.shared.reset()
                ProbeScheduler.shared.setCollectingStatistics(false)
                ProbeScheduler.shared.resetStatistics()
                guard let self, self.diagnosticsPanel === panel else { return }
                self.diagnosticsPanel = nil
            }
            diagnosticsPanel = panel
        } else {
            NetworkPerformanceDiagnostics.shared.setCollecting(true)
            ProbeScheduler.shared.setCollectingStatistics(true)
        }
        diagnosticsPanel?.showWindow(nil)
        diagnosticsPanel?.window?.makeKeyAndOrderFront(nil)
    }

    var networkDiagnosticsContext: NetworkDiagnosticsRuntimeContext {
        networkRuntime.context(configuration: networkDiagnosticsConfiguration)
    }

    var networkDiagnosticsConfiguration: NetworkDiagnosticsConfiguration {
        NetworkDiagnosticsConfiguration(mode: selectedModeForExtension.displayName, selectedPolicy: selectedPolicy,
            groupSelections: groupSelections, profileRevision: profileRevision, systemProxy: isSystemProxyActive)
    }

    func refreshSettings() {
        refreshSubscriptionSettings()
        refreshLocalProxySettingsForExtension()
        refreshDNSSettingsFields()
        helperStatusLabel.stringValue = "正在检查…"
        helperStatusLabel.textColor = .secondaryLabelColor
        helperInstallButton.isEnabled = false
        helperUninstallButton.isEnabled = false
        helperClient.installationStatus { [weak self] status in
            guard let self else { return }
            self.helperInstallationStatus = status
            self.helperStatusLabel.stringValue = status.displayText
            switch status {
            case .notInstalled:
                self.helperStatusLabel.textColor = .secondaryLabelColor
                self.helperInstallButton.title = "安装 Helper"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = false
            case .needsUpdate:
                self.helperStatusLabel.textColor = .systemOrange
                self.helperInstallButton.title = "更新 Helper"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = true
            case .installed:
                self.helperStatusLabel.textColor = .systemGreen
                self.helperInstallButton.title = "重新安装"
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = true
            }
        }
    }

    func refreshDNSSettingsFields() {
        // Navigation can happen while a DNS Save is preparing remote rules.
        // Do not replace its draft with the old profile until that request
        // finishes; only an actual user edit should change the displayed text.
        guard dnsSaveRequestID == nil else { return }
        let encrypted = profile.effectiveEncryptedDNSServers
        let traditional = profile.traditionalDNSServers
        let resolverSummary: String
        if !encrypted.isEmpty {
            let encryptedSummary = profile.configuredEncryptedDNSServers.isEmpty
                ? "默认加密 DNS" : "加密 DNS \(encrypted.count) 个"
            resolverSummary = encryptedSummary + " · 传统 DNS \(traditional.count) 个（仅引导 / 测试）"
        } else {
            resolverSummary = traditional.isEmpty ? "系统 DNS（兼容模式）" : "传统 DNS \(traditional.count) 个（兼容模式）"
        }
        let modeTitle: String
        switch profile.dnsSelectionMode {
        case .encryptedOnly: modeTitle = "仅用加密"
        case .balanced: modeTitle = "稳定均衡"
        case .mixedSpeed: modeTitle = "速度优先"
        }
        dnsSummaryLabel.stringValue = modeTitle + " · "
            + (profile.dnsPrewarmEnabled ? "后台预热 · " : "预热关闭 · ")
            + (profile.dnsLeakProtectionEnabled ? "保护开启 · " : "⚠︎ 保护关闭 · ") + resolverSummary
        if profile.dnsSelectionMode == .mixedSpeed {
            dnsSummaryLabel.stringValue += " · 普通 DNS \(profile.dnsProxyFallbackServers.count) 个（代理内日常择优）"
        } else if profile.dnsSelectionMode == .balanced && !profile.effectiveEncryptedDNSServers.isEmpty {
            dnsSummaryLabel.stringValue += profile.dnsProxyFallbackEnabled ? " · 代理内普通后备开启" : " · 普通后备关闭"
        }
        dnsSummaryLabel.toolTip = dnsSummaryLabel.stringValue
        dnsSummaryLabel.textColor = profile.dnsLeakProtectionEnabled && profile.dnsSelectionMode != .mixedSpeed
            ? .secondaryLabelColor : .systemOrange
        cancelDNSConnectivityTest()
        dnsForm.load(DNSSettingsDraft(profile: profile))
        dnsSettingsStatus.stringValue = ""
    }

    @objc func installHelperFromSettings() {
        helperInstallButton.isEnabled = false
        helperUninstallButton.isEnabled = false
        helperStatusLabel.stringValue = "正在请求管理员授权并安装…"
        helperStatusLabel.textColor = .systemBlue
        helperClient.installOrUpdate { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.helperStatusLabel.stringValue = "Helper 安装完成"
                self.helperStatusLabel.textColor = .systemGreen
                self.refreshSettings()
            case .failure(let error):
                self.helperInstallButton.isEnabled = true
                self.helperUninstallButton.isEnabled = self.helperInstallationStatus != .notInstalled
                self.helperStatusLabel.stringValue = "安装失败"
                self.helperStatusLabel.textColor = .systemRed
                self.showError(title: "无法安装 Helper", error: error)
            }
        }
    }

    @objc func openDNSSettings() {
        refreshDNSSettingsFields()
        settingsOverviewView.isHidden = true
        themeSettingsView.isHidden = true
        dnsSettingsView.isHidden = false
    }

    @objc func closeDNSSettings() {
        cancelDNSConnectivityTest()
        dnsSettingsView.isHidden = true
        settingsOverviewView.isHidden = false
        refreshDNSSettingsFields()
    }

    @objc func dnsProtectionChanged() {
        let enabled = dnsForm.protectionButton.state == .on
        dnsSettingsStatus.stringValue = enabled
            ? "保存后启用保护；增强模式将接管系统 DNS"
            : "⚠︎ 保存后关闭保护，可能使用系统或明文 DNS"
        dnsSettingsStatus.textColor = enabled ? .secondaryLabelColor : .systemOrange
    }

    @objc func dnsProxyFallbackChanged() {
        let enabled = dnsForm.proxyFallbackButton.state == .on
        dnsSettingsStatus.stringValue = enabled
            ? "保存后仅经合格加密代理回退；节点可见域名，出口仍明文"
            : "保存后关闭普通 DNS 后备；独立批准列表保留"
        dnsSettingsStatus.textColor = enabled ? .systemOrange : .secondaryLabelColor
    }

    @objc func saveDNSSettings() {
        cancelDNSConnectivityTest()
        do {
            let submittedDraft = dnsForm.draft
            try validateDNSSettings(submittedDraft)
            let text = try submittedDraft.applying(to: profileTextView.string)
            let requestID = UUID()
            dnsSaveRequestID = requestID
            dnsSettingsStatus.stringValue = "正在后台准备 DNS 规则集…"
            dnsSettingsStatus.textColor = .systemBlue
            // Pressing Save commits this snapshot even if the user navigates
            // away. Later edits in this panel remain an unsaved draft instead
            // of being erased by the old asynchronous result.
            applyProfileTextInBackground(text, prefix: "DNS 已保存并应用",
                                         completion: { [weak self] result in
                guard let self, self.dnsSaveRequestID == requestID else { return }
                self.dnsSaveRequestID = nil
                switch result {
                case .success:
                    let draftUnchanged = self.dnsForm.draft == submittedDraft
                    if self.dnsSettingsView.isHidden || draftUnchanged {
                        self.refreshDNSSettingsFields()
                    }
                    self.dnsSettingsStatus.stringValue = draftUnchanged || self.dnsSettingsView.isHidden
                        ? "✓ DNS 已保存并应用"
                        : "✓ 先前设置已保存；当前输入还有未保存的修改"
                    self.dnsSettingsStatus.textColor = .systemGreen
                    self.dnsSettingsStatus.toolTip = nil
                case .failure(let error):
                    self.dnsSettingsStatus.stringValue = "✕ \(error.localizedDescription)"
                    self.dnsSettingsStatus.textColor = .systemRed
                    self.dnsSettingsStatus.toolTip = error.localizedDescription
                    if self.dnsSettingsView.isHidden {
                        self.showError(title: "DNS 保存失败", error: error)
                    }
                }
            })
        } catch {
            dnsSettingsStatus.stringValue = "✕ \(error.localizedDescription)"
            dnsSettingsStatus.textColor = .systemRed
            dnsSettingsStatus.toolTip = error.localizedDescription
        }
    }

    func validateDNSSettings(_ draft: DNSSettingsDraft) throws {
        let traditional = draft.traditionalServers
        guard traditional.count <= 8, draft.encryptedServers.count <= 8 else {
            throw makeProfileApplyErrorForExtension("每类 DNS 最多配置 8 个服务器")
        }
        if let invalid = traditional.first(where: { TraditionalDNSServer($0) == nil }) {
            throw makeProfileApplyErrorForExtension("传统 DNS 地址无效：\(invalid)。请填写 IP 或 IP:端口，例如 223.5.5.5、[2606:4700:4700::1111]:53；DoH / DoT 请填入加密 DNS 栏。")
        }
        for raw in draft.encryptedServers {
            if raw.lowercased().hasPrefix("https://"),
               let endpoint = DoHEndpoint(raw, allowUnresolvedHost: true) {
                if endpoint.needsBootstrap && traditional.isEmpty {
                    throw makeProfileApplyErrorForExtension("DoH 域名 \(endpoint.host) 需要传统 DNS 引导，或在 URL 后附 #IP 指定引导地址")
                }
            } else if raw.lowercased().hasPrefix("tls://"), DoTEndpoint(raw) != nil {
                continue
            } else {
                throw makeProfileApplyErrorForExtension("加密 DNS 地址无效：\(raw)。DoH 格式为 https://域名/dns-query；DoT 格式为 tls://域名#IP。传统 DNS IP 请填入下栏。")
            }
        }
    }

    func cancelDNSConnectivityTest() {
        dnsConnectivityRequestID = nil
        dnsConnectivityResolver?.cancel()
        dnsConnectivityResolver = nil
        dnsForm.connectivityButton.isEnabled = true
    }

    @objc func testTraditionalDNSConnectivity() {
        cancelDNSConnectivityTest()
        let draft = dnsForm.draft
        let servers = draft.traditionalServers
        guard !servers.isEmpty, servers.count <= 8,
              servers.allSatisfy({ TraditionalDNSServer($0) != nil }) else {
            dnsSettingsStatus.stringValue = "✕ 请在传统 DNS 栏填写 1–8 个有效 IP 地址后测试"
            dnsSettingsStatus.textColor = .systemRed
            return
        }
        let requestID = UUID()
        let started = Date.timeIntervalSinceReferenceDate
        let resolver = TraditionalDNSBootstrapResolver(servers: servers, allowedDoHHosts: [])
        dnsConnectivityRequestID = requestID
        dnsConnectivityResolver = resolver
        dnsForm.connectivityButton.isEnabled = false
        dnsSettingsStatus.stringValue = "正在用传统 DNS 查询固定连通性测试域名…"
        dnsSettingsStatus.textColor = .systemBlue
        dnsSettingsStatus.toolTip = nil
        resolver.testConnectivity(queue: .main) { [weak self] result in
            guard let self, self.dnsConnectivityRequestID == requestID else { return }
            self.cancelDNSConnectivityTest()
            let changed = self.dnsForm.draft.traditionalText != draft.traditionalText
            switch result {
            case .success:
                let elapsed = Int((Date.timeIntervalSinceReferenceDate - started) * 1_000)
                self.dnsSettingsStatus.stringValue = "✓ 传统 DNS 可达（\(elapsed) ms）；未测试加密 DNS"
                    + (changed ? "；当前输入已有修改" : "")
                self.dnsSettingsStatus.textColor = .systemGreen
                self.dnsSettingsStatus.toolTip = "固定测试域名：captive.apple.com。本测试不保存配置，不代表 HTTPS 或代理连通性。"
            case .failure(let error):
                self.dnsSettingsStatus.stringValue = "✕ 传统 DNS 测试失败：\(error.localizedDescription)"
                self.dnsSettingsStatus.textColor = .systemRed
                self.dnsSettingsStatus.toolTip = error.localizedDescription
            }
        }
    }
}
