# 哈基米 (Hajimi) for macOS — 50款UI主题配置包与导入说明

本配置包包含专为 **哈基米 (Hajimi) for macOS** 打造的 **8 大美学流派 × 10 种宏观布局推荐 = 50 款 UI 主题配置文件 (`.hajimitheme.json`)**。

---

## 一、如何在哈基米客户端中使用与导入主题

1. **打开设置页面**：
   - 启动 **哈基米** 客户端，点击左侧边栏底部 **「设置 (Settings)」**。
   - 在设置总览页即可看到新增的 **「UI 主题与外观」** 卡片，支持直接下拉切换全部 50 款内置主题，或点击 **「UI 主题设置…」** 进入完整主题工作台。

2. **方式 A：通过本地文件导入（支持单主题文件或合集包）**：
   - 在「设置 → UI 主题与外观」卡片或「UI 主题设置」子页面中，点击 **「导入文件…」** / **「本地文件导入…」**。
   - 选择本压缩包内的任意单个主题文件（如 `single-themes/08-theme-08-ginger-tabby.hajimitheme.json`），或直接选择全套合集文件 `hajimi-all-50-themes-pack.hajimitheme.json` 即可一键导入并立即应用。

3. **方式 B：通过远程 URL 导入（支持 HTTP / HTTPS 链接）**：
   - 将任意 `.hajimitheme.json` 单主题文件、分流派主题包（`category-packs/*.json`）或全套 50 款合集包托管至 GitHub Raw、Gist、Cloudflare R2 或任意静态 HTTP 服务。
   - 在客户端点击 **「URL 导入…」** / **「URL 远程导入…」**，填入 URL 地址（例如 `https://raw.githubusercontent.com/.../hajimi-all-50-themes-pack.hajimitheme.json`），勾选“导入后立即应用该主题”，点击 **「下载并导入」** 即可。
   - 通过 URL 导入的主题会自动记录远程 `sourceURL`，后续可点击 **「更新当前 URL 主题」** 一键同步最新配色。

---

## 二、目录结构说明

- `hajimi-all-50-themes-pack.hajimitheme.json`：包含全部 50 款主题的单文件全集包（支持一次性通过文件或 URL 导入全部 50 款主题）。
- `single-themes/`：50 款独立主题配置文件（`01` 至 `50`，每款一个 `.hajimitheme.json` 文件）。
- `category-packs/`：按 8 大美学流派分类的主题包：
  1. `01-macos-native-evolution.hajimitheme.json`（macOS 原生进化系列 · 7款）
  2. `02-hajimi-cat-kawaii.hajimitheme.json`（哈基米橘猫萌宠系列 · 7款）
  3. `03-proxy-legend-homage.hajimitheme.json`（网络极客与名作致敬系列 · 7款）
  4. `04-academic-telemetry-lab.hajimitheme.json`（科研算法与遥测实验室系列 · 6款）
  5. `05-modern-saas-craft.hajimitheme.json`（现代先锋软件美学系列 · 7款）
  6. `06-cyber-retro-terminal.hajimitheme.json`（赛博复古与未来终端系列 · 6款）
  7. `07-industrial-art-movements.hajimitheme.json`（艺术流派与工业设计系列 · 6款）
  8. `08-eastern-zen-aesthetics.hajimitheme.json`（东方美学与自然意境系列 · 4款）

---

## 三、自定义主题 JSON 字段规范

您可以直接复制任意 `.hajimitheme.json` 修改以下字段制作专属主题：

```json
{
  "id": "custom-my-theme",
  "code": "#51",
  "name": "我的专属哈基米主题",
  "englishName": "My Custom Hajimi Theme",
  "category": "自定义与外部导入",
  "layoutStyle": "L1 经典左栏+Bento",
  "appearanceMode": "dark",
  "cardCornerRadius": 16.0,
  "innerCornerRadius": 11.0,
  "workspaceHex": "#0F1214",
  "sidebarHex": "#14181B",
  "panelHex": "#1A1F22",
  "elevatedPanelHex": "#202629",
  "mutedPanelHex": "#14181B",
  "accentHex": "#2ED19C",
  "accentTextHex": "#34E8B8",
  "uploadAccentHex": "#59B0FA",
  "indigoAccentHex": "#8A94FA",
  "textPrimaryHex": "#ECFDF5",
  "textSecondaryHex": "#8DA399",
  "borderAlpha": 0.14,
  "highlightAlpha": 0.08,
  "featureSummary": "自定义配色亮点说明",
  "description": "支持通过本地文件或远程 URL 导入"
}
```
