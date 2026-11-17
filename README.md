# 哈基米 (Hajimi)

面向 macOS 13+（支持 `arm64` 与 `x86_64` 通用架构）的原生网络代理与增强模式（TUN）客户端。项目采用 **Swift + Objective-C/C++ + C++17 + C11** 高内聚模块化分层架构，**100% 依赖行业标准协议栈与现代密码学库**（[OpenSSL 3.5 LTS](https://openssl-library.org/source/)、`ngtcp2`、`nghttp3`、`libssh2`、Apple `Network.framework` / `Security.framework` / `CryptoKit` / `Compression`），不拉起任何外部代理内核子进程。

## 核心特性

### 1. 完全依赖标准协议栈的全网络前沿引擎

所有协议、密码学、传输层与 DNS 管线均严格建立在 IETF RFC / NIST FIPS 标准协议栈之上，拒绝非标准 TCP/TLS 分片篡改或手写密码学原语：

| 类别 | 支持协议 / 前沿特性 | 底层标准协议栈与规范 |
| :--- | :--- | :--- |
| **后量子与现代 TLS 1.3** | 后量子混合密钥协商 `X25519MLKEM768` (`0x11EC`)、TLS 证书压缩 (`CompressedCertificate` Brotli/Zlib)、ECH 配置解析、TLS 1.2/1.3 强制下限、XTLS REALITY | [RFC 10024](https://www.rfc-editor.org/info/rfc10024/)、[NIST FIPS 203](https://nhimg.org/ml-kem-fips-203-guide) ([OpenSSL 3.5 LTS](https://openssl-library.org/source/) `EVP_PKEY` `ML-KEM-768`)、[RFC 8879](https://www.rfc-editor.org/info/rfc8879/) (`Compression.framework`)、[RFC 9849](https://port0.io/blog/ndr-under-tls-1-3-and-ech)、[RFC 8996](https://grokipedia.com/page/Downgrade_attack) |
| **QUIC v1/v2 与 HTTP/3** | Hysteria v1/v2、TUIC v5、TrustTunnel (HTTP/3 & MASQUE)、QUIC v2 兼容协商、QUIC Bit Greasing、内核级 `DONTFRAG` DPLPMTUD | [RFC 9369](https://www.rfc-editor.org/info/rfc9369/) (QUIC v2)、[RFC 9368 / RFC 9287 / RFC 9221](https://www.rfc-editor.org/subjects/quic/) ([ngtcp2 1.18.0](https://nghttp2.org/ngtcp2/types.html) & [OSTIF 审计版 nghttp3 1.12.0](https://ostif.org/nghttp3-ngtcp2-audits-complete/))、[RFC 9298](https://www.rfc-editor.org/info/rfc9298/) (`connect-udp`)、[RFC 9484](https://www.rfc-editor.org/info/rfc9484/) (`connect-ip`) |
| **经典与多路复用代理协议** | Shadowsocks (Classic / AEAD / SIP022 2022)、SSR、VMess AEAD、VLESS (含标准 XTLS-Vision)、Trojan、Snell v4–v6、AnyTLS、WireGuard、Sudoku、Mieru、SSHv2 | [OpenSSL 3.5 LTS](https://openssl-library.org/source/) `EVP_CIPHER` / `EVP_MAC` / `EVP_KDF("ARGON2ID")` / `EVP_blake2s256` / `BLAKE2SMAC`、BLAKE3、`libssh2`（抗 [Terrapin 降级防护](https://grokipedia.com/page/Downgrade_attack)） |
| **入站、全传输载体与优先级** | HTTP CONNECT、SOCKS5 (`UDP ASSOCIATE`)、TUN (`utun` + Fake-IP)、HTTP/2 (双向流控 + Extended `CONNECT` + 扩展优先级)、WebSocket、XHTTP、mKCP、Mux.Cool | [RFC 9113](https://visualrfc.com/rfc/9113/chapter-3/) HTTP/2、[RFC 9218](https://ietfminutes.org/minutes/ietf126/anrw.html) HTTP 扩展优先级 (`Priority: u=0, i`)、RFC 6455 WebSocket、RFC 1928/1929 SOCKS5、RFC 8200 IPv6 扩展头 |
| **前沿加密 DNS、负缓存与诊断** | DoH、DoT、DoQ、ODoH 异源隔离、DDR 自发现、SVCB/HTTPS `ech` 与 `dohpath` 缓存、权威 `SOA` 负缓存、`Serve-Stale` 兜底、DE-R 诊断上报、Happy Eyeballs v3 编排 | [RFC 2308](https://www.rfc-editor.org/info/rfc2308/)、[RFC 8767](https://www.rfc-editor.org/subjects/dns/)、[RFC 9460](https://www.rfc-editor.org/info/rfc9460/)、[RFC 9461](https://www.rfc-editor.org/info/rfc9461/)、[RFC 9462](https://www.rfc-editor.org/info/rfc9462/)、[RFC 9520](https://www.rfc-editor.org/info/rfc9520/)、[RFC 9567](https://www.rfc-editor.org/info/rfc9567/) (`REPORT-CHANNEL`)、[Happy Eyeballs v3](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/) |

### 2. 纵深安全架构

* **供应链哈希锁定与 LTS 安全基线**：本地静态构建默认采用 [OpenSSL 3.5.9 LTS](https://safeguard.sh/resources/blog/openssl-3-4-3-6-end-of-life-october-november-2026)（官方支持至 2030-04，包含最新 QUIC/TLS 安全补丁），全套构建脚本强制 `--proto '=https' --tlsv1.2` 与官方 SHA-256 清单核验，失配即拒绝解压编译。
* **特权守护进程零信任鉴权（Fail-Closed）**：`HajimiHelper`（`HelperSocketServer.swift`）强制执行 `getpeereid`、`LOCAL_PEERPID`、优先拦截 `/tmp`/`/var/tmp`/`/Volumes` 等不可信路径，并通过 `Security.framework` 执行 `kSecCSStrictValidate` 严格动态代码签名验证。
* **本地控制接口防重绑定与防 CSRF**：`ExternalController` 默认仅绑定回环地址，实施 `Host` 白名单校验及变更接口 `Origin` / `Sec-Fetch-Site` / `Content-Type` 防跨站请求伪造校验，仅接受常量时间比对的 `X-Key` 请求头（禁用 URL `?x-key=` 明文传参）。
* **协议边界、DNS 防投毒与反降级加固**：
  * **TLS / SSH 反降级**：Apple `Network.framework` 强制 TLS 1.2 下限（`h3`/`doq` 强制 TLS 1.3，遵循 [RFC 8996](https://grokipedia.com/page/Downgrade_attack)）；SSHv2 优先协商 `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com` 与 `curve25519-sha256`；TLS 证书解压严格校验 `uncompressed_length + 1` 防御 [RFC 8879](https://www.rfc-editor.org/info/rfc8879/) 膨胀炸弹。
  * **DNS 负缓存祖先核验与 DE-R 环路阻断**：[RFC 2308](https://www.rfc-editor.org/info/rfc2308/) 负缓存强制校验权威区 `SOA` 为查询域名的合法祖先（阻断跨域 `SOA` 负缓存投毒）；[RFC 9567](https://www.rfc-editor.org/info/rfc9567/) §8.1 强制拦截位于 `QNAME` 子树内的自指上报代理域名；线速计算 256 桶香农熵识别高熵长标签 DNS 隧道/DGA 异常。
  * **SOCKS5 / HTTP/2 边界校验与凭据零残留**：SOCKS5 校验 RFC 1929 `<= 255` 字节上限并拦截私网/CGNAT/`::ffff:0:0/96` 反射；所有 KDF 中间态、ML-KEM 私钥、SSH 私钥/口令及 SOCKS5/HTTP 认证缓冲区在使用后立即调用 `OPENSSL_cleanse` 擦除。

### 3. 全协议全传输性能优化与模块化架构

* **超大单体文件全面解耦分拆**：`MainWindowController`、`ProxyEngine`、`NativeTunnel`、`HelperDaemon`、`TLS13`、`WireGuard`、`Sudoku`、`Mieru` 八大核心子系统均按职责边界拆分为高内聚独立文件（全仓 C++17 单文件均控制在 `<= 1,715` 行），大幅提升增量编译并发度与代码可读性。
* **流/数据报 32 KiB 批量写合并与单遍融合掩码**：`OrderedWriter`（`BufferedStream` / VLESS / Trojan / HTTP / SOCKS5 / Sudoku / Mieru TCP）与 `PreparedStreamDatagram`（流式承载 UDP）支持最高 `32 KiB` 连续小包零拷贝/单次合并写入，显著降低 TLS 1.3 记录封装与系统调用次数；WebSocket `hajimi_ws_encode_frame` 采用 32 字节展开 SWAR 单遍融合拷贝掩码，降低 50% 内存读写带宽。
* **全链路 $O(1)$ 游标收缩与零拷贝缓存老化**：`HTTP2`、`GRPCFraming`、`XHTTP`（`HTTP1ResponseParser`）、`EncryptedDNS`（`DoHHTTPResponseParser`）、`Vision` 与 `PreparedStreamDatagram` 全面采用 $O(1)$ 游标/切片推进消除 $O(N^2)$ `memmove`；`DNSQueryCache` 采用写时复制（CoW）原地字节改写完成 TTL 递减与事务 ID 重写，配合 [RFC 9218](https://ietfminutes.org/minutes/ietf126/anrw.html) `Priority: u=0, i` 降低首跳解析尾延迟。

## 目录结构

```text
.
├── Package.swift                 # SwiftPM 工程定义（20 个原生模块目标）
├── Makefile                      # 原生依赖编译、应用打包签名与全套回归测试入口
├── README.md                     # 项目说明文档
├── 项目架构与维护文档.md           # 架构设计、模块分拆拓扑、安全基线与日常维护手册
├── PROTOCOL_STACK_AUDIT.md       # 标准协议栈合规与三轮前沿升级审计矩阵
├── Sources/
│   ├── HajimiDataPlaneC/         # C11 零拷贝 IPv4/IPv6（含 RFC 8200 扩展头）/TCP/UDP 解析与校验和
│   ├── HajimiFlowCXX/            # C++17 有界字节队列、TCP 乱序重叠合并重组、SACK、RTO 与 BDP 估算
│   ├── HajimiProtocolCXX/        # C++17 线缆编解码、单遍 SWAR WS 掩码、DNS 线速熵/SOA/DE-R 分析与 UCB1 评分
│   ├── HajimiRoutingCXX/         # C++17 零分配 ASCII 域名后缀树与预编译并发路由匹配引擎
│   ├── HajimiProtocolsCXX/       # C++17 模块化全协议栈（WireGuardCore/SudokuCodec/MieruCore/QUIC v2/ML-KEM-768/SSHv2）
│   ├── HajimiCXXProtocolBridge/  # Objective-C++ C++ 协议栈桥接与 32 KiB 流式 UDP 批量写引擎
│   ├── HajimiProxyRuntime/       # Objective-C++ TLS 1.2/1.3 基线、低时延服务类与物理网卡缓存运行时
│   ├── HajimiMacOSObjC/          # Objective-C 流量环形缓冲、状态栏组件与 NetworkExtension 控制器
│   ├── HajimiDNS/                # Swift DNS 检验、RFC 2308 负缓存、Serve-Stale、DNSWireAnalyzer 与 Happy Eyeballs v3
│   ├── HajimiRouting/            # Swift 路由规则模型与进程名（PROCESS-NAME）匹配器
│   ├── HajimiRuntime/            # Swift 运行时会话状态机、重载协调与启动意图模型
│   ├── HajimiRuntimeTestSupport/ # Swift 运行时生命周期离线测试支撑
│   ├── HajimiCore/               # Swift 代理引擎（含 ProxyEngineDNSTransports）、加密 DNS、TLS 1.3 模块化栈与传输载体
│   ├── HajimiNativeCore/         # Swift 模块化用户态 TUN 引擎（NativeTunnel / UDPAndICMP / SelfTest）
│   ├── HajimiIPC/                # Swift App <-> root Helper Unix Socket 协议与 SCM_RIGHTS FD 传递
│   ├── HajimiHelper/             # 模块化 root 守护进程（HelperDaemon / SystemDNSRedirect / HelperSocketServer）
│   ├── HajimiUIComponents/       # 原生 AppKit 主题引擎与复用视觉控件库
│   ├── HajimiDiagnosticsUI/      # 网络诊断与遥测中心 AppKit 仪表盘模块
│   ├── HajimiDiagnosticsUITestSupport/ # 诊断面板离线自检夹具（HAJIMI_MINIMAL_RELEASE=1 时自动剥离）
│   └── HajimiApp/                # 模块化 macOS 主应用（MainWindowController 及状态栏/DNS诊断/规则配置等 7 个扩展模块）
├── SmokeTests/                   # C/C++/ObjC++/Swift/Python 离线冒烟、协议互操作与压力测试套件
├── scripts/                      # 原生依赖（OpenSSL 3.5.9 / ngtcp2 / nghttp3 / libssh2）校验构建与回归提取脚本
├── Resources/                    # Info.plist、Entitlements、图标资源与第三方开源许可证声明
└── Vendor/HajimiQUIC/            # ngtcp2 + nghttp3 + OpenSSL 3.5+ 集成说明
```

## 环境要求与构建指南

### 依赖要求

* **操作系统**：macOS 13.0 (Ventura) 及以上（Apple Silicon `arm64` 或 Intel `x86_64`）
* **编译工具链**：Xcode 15+ / Command Line Tools（Swift 5.9+、Clang C11/C++17）、CMake、Make、Python 3
* **OpenSSL 3.5+ LTS**：可通过 Homebrew 安装 `openssl@3`（`3.5.9+`），若本机未安装或缺少 QUIC TLS API，`scripts/build_native_core.sh` 将自动拉取经 SHA-256 校验的 [OpenSSL 3.5.9 LTS](https://openssl-library.org/source/) 并在 `.build/Vendor/OpenSSL` 内完成本地静态编译

### 快速构建与运行

```bash
# 1. 校验并静态编译原生密码学与传输依赖（OpenSSL 3.5.9 / ngtcp2 1.18.0 / nghttp3 1.12.0 / libssh2）
make native-core

# 2. 编译 Release 二进制并打包签名生成 dist/哈基米.app（可通过 HAJIMI_MINIMAL_RELEASE=1 剥离内置测试夹具）
make app

# 3. 直接构建并启动应用
make run
```

构建双架构通用发行包（Universal Binary）：

```bash
make ARCHS="arm64 x86_64" archive
```

## 验证与测试

所有自动化测试均在本地内存或回环接口上闭环执行，不修改宿主机路由表、系统代理或 DNS 设置：

```bash
# 运行 C11/C++17 数据面、流重组、编解码（含 DNS 线速熵/SOA/DE-R 分析）与预编译路由测试
make test-native
make test-compiled-rules

# 运行 C++17 全协议栈（含 ML-KEM-768、OrderedWriter 批量写、WireGuard、Sudoku、Mieru、TrustTunnel、SSH 等）测试
make test-cpp

# 运行 QUIC v1/v2（Hysteria v1/v2 & TUIC v5）互操作测试（支持 HAJIMI_SANITIZE=1 开启 ASan/UBSan）
make test-quic

# 运行完整验证门禁（原生协议、DNS 负缓存/Serve-Stale/DDR/ECH/DE-R、增强模式生命周期及打包校验）
make verify
```

## 配置兼容与前沿节点参数

* **配置与订阅格式**：原生兼容 Surge `.conf`、Clash YAML、Base64 订阅及 `ss://`、`ssr://`、`vmess://`、`vless://`、`trojan://`、`snell://`、`hy2://`、`tuic://`、`anytls://`、`wireguard://`、`sudoku://`、`mieru://`、`trusttunnel://`、`ssh://` 分享链接导入导出。
* **前沿标准可选参数**：
  * `pqc = auto | true | false`（QUIC 协议族与 REALITY TLS 1.3）：默认自动协商 [RFC 10024](https://www.rfc-editor.org/info/rfc10024/) `X25519MLKEM768` 后量子混合密钥交换，兼容回退经典 `X25519`。
  * `quic-version = auto | 1 | 2`（Hysteria / Hysteria2 / TUIC / TrustTunnel QUIC）：`auto` 默认通过 [RFC 9368](https://www.rfc-editor.org/subjects/quic/) 无缝协商升级至 [RFC 9369](https://www.rfc-editor.org/info/rfc9369/) QUIC v2 (`0x6b3343cf`)，设为 `2` 则直接以 QUIC v2 发起握手。
* **外部控制接口**：支持在 `[General]` 中配置 `http-api = 127.0.0.1:6171` 与 `http-api-key = <secret>`，通过 `X-Key` 请求头调用标准 JSON 控制接口。

## 许可证说明

第三方开源组件（OpenSSL Apache-2.0、ngtcp2 MIT、nghttp3 MIT、libssh2 BSD-3-Clause）许可证声明详见 `Resources/ThirdPartyNotices.txt`。
