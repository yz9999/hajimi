# Hajimi 协议栈商业化标准合规性审查报告 (Protocol Stack Audit Report)

- **审查范围**：`Sources/HajimiProtocolsCXX/`、`Sources/HajimiProtocolCXX/`、`Sources/HajimiCXXProtocolBridge/` 及 Swift 传输承载层全量出站协议栈
- **审查基准**：各协议官方规范与主流商业开源实现（`Xray-core`、`sing-box`、`mihomo/Clash.Meta`、`AdGuardTeam/TrustTunnel`、`WireGuard Whitepaper / RFC 6479`、`Surge Snell v4`、`enfein/mieru v3`、`SUDOKU-ASCII/sudoku`、`apernet/hysteria v1/v2`、`EAIoT/tuic v5`、`anytls/anytls-go`、`RFC 4251-4254 SSH`、`RFC 1928 SOCKS5`）
- **生成时间**：2026-11-07（初版审查基于 `Build 67`，全量修复落地于 `Build 68`）

---

## 0. 修复落地进展总览 (Remediation Status — Build 68)

| 优先级 | 协议 / 模块 | 修复状态 | 关键修复内容摘要 |
| :--- | :--- | :--- | :--- |
| **P0.1** | **Snell v4** | ✅ **已修复** | 在 [Snell.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp) 中将 `CompatMode::Standard`（RFC 9106 Argon2id 32→16B + 标准 7 字节 `{4,0,0,pad_hi,pad_lo,len_hi,len_lo}` 帧头 + `swapPadding`）设为所有 Snell v4+ 节点的**唯一首次默认模式**，消除了连接真实 Surge `snell-server v4` 时前两次 TCP 必败回退的延迟与告警，并移除了生产代码中的 `"fixture.invalid"` 硬编码。 |
| **P0.2** | **VLESS + XTLS Vision UDP** | ✅ **已修复** | 在 [Validation.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Validation.cpp) 与 [VlessTrojanProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp) 中原生实现了 C++ **XUDP (`command = 3` Mux over Vision)** 帧编解码（`encodeXudpFrame` / `tryExtractXudpPacket`，兼容 New/Keep/Keep+Address 状态帧），使 `flow=xtls-rprx-vision` 节点完整支持 QUIC/DNS/游戏 UDP 转发。 |
| **P0.3** | **TrustTunnel (HTTP/3 QUIC)** | ✅ **已修复** | 在 [TrustTunnelProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp) 中实现了基于 `quic::Connection` (`ngtcp2`) + `nghttp3_qpack_encoder`/`nghttp3_qpack_decoder` 的真实 **HTTP/3 (`h3`) QUIC `CONNECT` Stream**（[`HTTP3ConnectStream`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp)），彻底淘汰了 `quic=true` 时在 TCP+TLS 上伪造 `"h3"` ALPN 发送 HTTP/1.1 的做法。 |
| **P0.4** | **ShadowsocksR (SSR)** | ✅ **已修复** | 在 [Crypto.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Crypto.cpp)、[Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp) 与 [NativeOutbound.swift](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiCore/NativeOutbound.swift) 中完整补齐了 SSR 流密码（`aes-128/192/256-cfb`、`aes-128/192/256-ctr`、`rc4`、`rc4-md5`、`chacha20`、`chacha20-ietf`、`none`）、混淆插件（`plain`、`http_simple`、`http_post`、`tls1.2_ticket_auth`、`tls1.2_ticket_fastauth`）与协议插件（`origin`、`verify_sha1`/`ota`、`auth_sha1_v4`、`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a` 及其 `_compatible` 变体）。 |
| **P1.5** | **WireGuard** | ✅ **已修复** | 在 [WireGuardProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp) 中移除 `unansweredTxPackets_ > 8` 非标重握手触发器，改为遵循 WireGuard 白皮书 §6.1 的标准定时器（`KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15s` 无响应重握手、`REKEY_AFTER_TIME = 120s`、`REJECT_AFTER_TIME = 180s`、`REKEY_AFTER_MESSAGES = 2^60`）；新增 `Type = 3` Cookie Reply (`XChaCha20-Poly1305`) 与 `mac2` 生成、RFC 6479 64-bit 防重放滑动窗口、`PersistentKeepalive` / 被动保活定时器、以及隧道内 `AAAA` IPv6 DNS 解析。 |
| **P1.6** | **QUIC 协议族连接池复用** | ✅ **已修复** | 在 [QUICTransport.hpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.hpp)、[QUICTransport.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp) 与 [QUICProtocols.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICProtocols.cpp) 中实现 `quic::SharedStream` 与 `PooledQUICSession` 多路复用连接池（按 `(TransportFactory, Node)` 共享已通过 Hysteria2 `/auth` 或 TUIC `authenticate` 的底层 QUIC 连接），并修复 `QUICTransport.cpp` 仅在 `errno == EMSGSIZE` 时触发 MTU 下调。 |
| **P2.7** | **VMess 多加密算法支持** | ✅ **已修复** | 在 [VMess.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp) 与 [Validation.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Validation.cpp) 中支持 `aes-128-gcm` (`security=3`)、`chacha20-poly1305` (`security=4`，含双 MD5 32B Body Key 派生)、`none` (`security=5`) 与 `zero` (`security=6`)。 |
| **P2.8** | **Mieru UDP 标准 Nonce** | ✅ **已修复** | 在 [MieruProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp) 中移除了 `MieruUDPStream::onPacket` 内针对历史非标服务端的 `beNonce` / `leNonce` 异常捕获重试分支，严格对齐 `enfein/mieru v3` 规范。 |

---

## 1. 原始审查总览与严重等级矩阵 (Original Executive Summary)

| 序号 | 协议 / 模块 | 源码位置 | 严重等级 | 合规状态 | 核心非标问题摘要 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **TrustTunnel** | [TrustTunnelProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp#L39-L273) | **P0 (严重非标)** | ❌ 私有定制协议 | 1. `quic=true` 时仅将 ALPN 设为 `"h3"`，底层仍走 **TCP+TLS** 发送 HTTP/1.1 文本请求，完全无法连接真实 QUIC/HTTP3 服务端；<br>2. TCP 仅发 HTTP/1.1 `CONNECT`（官方为 HTTP/2 `h2` 多路复用）；<br>3. UDP 使用私有 `_trusttunnel_udp_:443` 伪目标 + 自定义流分帧，仅适配测试脚本 `hajimi_extra_servers.py`，与 AdGuard 官方实现不兼容。 |
| **2** | **Snell v4** | [Snell.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L67-L395) | **P0 (严重非标)** | ⚠️ 默认优先非标变体 | 1. Snell v4 默认使用非 RFC 标准 Argon2id 变体（`Compat16Pool7`，专为适配测试脚本 Python 实现而写）；<br>2. 在前两次握手尝试（`Compat16Pool7` / `Compat16RFC`）中，v4 节点却发送 **Snell v3 的 2 字节长度头** 而非 v4 标准的 7 字节 `{4,0,0,pad_hi,pad_lo,len_hi,len_lo}` 头；<br>3. 连接真实 Surge `snell-server v4` 时，前 2 次 TCP 连接必因解密失败被服务端 RST，需触发 3 次 TCP 重连回退才能回落到 `CompatMode::Standard`；<br>4. 生产代码中残留 `"fixture.invalid"` 与 `"node.scope.invalid"` 测试域名判断。 |
| **3** | **ShadowsocksR (SSR)** | [Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L138-L141) | **P0 (严重缺失)** | ❌ 仅支持裸 CFB | 强制要求 `cipher = aes-*-cfb` 且 `protocol = origin` 且 `obfs = plain`，未实现任何标准 SSR 协议插件（`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a/b`）与混淆插件（`tls1.2_ticket_auth`、`http_simple`）。真实商业机场 SSR 节点会直接报错拦截。 |
| **4** | **VLESS + XTLS Vision** | [VlessTrojanProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp#L223-L226) | **P1 (高危缺陷)** | ⚠️ Vision 下 UDP 断流 | 当节点配置 `flow=xtls-rprx-vision`（当前最主流的 VLESS+Reality 商业配置）时，所有 UDP 流量直接抛出异常 `"VLESS Vision UDP requires an XUDP carrier"`，未实现 XUDP (`command=3`) 也未回退为标准 VLESS UDP (`command=2`)，导致 QUIC/DNS/游戏 UDP 在 Vision 节点下完全不可用。 |
| **5** | **WireGuard** | [WireGuardProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L365-L1620) | **P1 (高危非标)** | ⚠️ 多处违反协议规范 | 1. **非标重握手触发器**：连续发送 >8 个上行 IP 包未收到下行包即强制重握手（[`sendIPPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L958-L961)），导致并发建连或大文件上传时频繁重置会话密钥；<br>2. **缺失 Cookie Reply (`Type=3`) 与 `mac2`**：服务端高负载开启 DoS 保护时无法完成握手；<br>3. **缺失防重放滑动窗口 (Anti-Replay Window)** 与标准定时器（`REKEY_AFTER_TIME=120s`、`PersistentKeepalive`）；<br>4. **隧道内 DNS 仅支持 IPv4 `A` 记录**，且未配置 IPv6 时硬编码私网地址 `fd00:6861:6a69:66::2`；<br>5. 残留 `"fixture.invalid"` 测试主机名硬编码。 |
| **6** | **QUIC / Hysteria2 / TUIC v5 / Hysteria1** | [QUICProtocols.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICProtocols.cpp#L391-L439)<br>[QUICTransport.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L606-L1242) | **P1 (架构非标)** | ⚠️ 无连接复用 / 缺 Brutal | 1. **无 QUIC 连接池与流多路复用**：每条代理 TCP 流或 Datagram 会话都新建独立 UDP Socket、独立 OS 线程（`std::thread`）、独立 TLS 1.3 + QUIC 握手和 `/auth` 认证，违背 QUIC 单连接多路复用设计，高并发下握手延迟高且易触发服务端限流；<br>2. **缺失 Hysteria 标志性 Brutal 拥塞控制**（仅支持 `ngtcp2` 内置 BBR/Cubic/Reno）；<br>3. 禁用 `ngtcp2` 标准 PMTUD，改用自定义连续 3 次 `send()` 失败缩减 MTU 且直接丢弃待发包。 |
| **7** | **VMess** | [VMess.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp#L168-L185) | **P2 (中度非标)** | ⚠️ 忽略加密配置 | 1. 忽略节点配置的 `cipher` / `security` 参数（如 `chacha20-poly1305`、`none`/`zero`），在 [`VMessStream`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp#L175) 中硬编码 `security = 3` (`AES-128-GCM`)；<br>2. 未实现 `RequestOptionChunkMasking (0x04)` 长度混淆与 `GlobalPadding (0x08)`。 |
| **8** | **Mieru (v3)** | [MieruProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L59-L1783) | **P2 (架构与细节)** | ⚠️ 无多路复用 / 启发式解密 | 1. 虽解析了 `multiplexing` 配置项（`MULTIPLEXING_LOW/MIDDLE/HIGH`），但实际未实现 Mieru 标准的单底层连接多 Session 复用，每条流均独占一条底层 TCP/UDP 连接；<br>2. 仅实现了下行低熵模式（`protoType 10/11`）解码，未实现上行低熵编码发送；<br>3. UDP 载荷解密（[`onPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L1286-L1298)）保留了对旧非标服务端 `beNonce`/`leNonce` 的二次/三次异常捕获回退。 |
| **9** | **Sudoku** | [SudokuProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1016-L1695) | **P2 (启发式兼容)** | ⚠️ 含非标服务端兼容逻辑 | 1. 未实现 `kKIPTypeStartMux (0x11)` 单连接多路复用；<br>2. 包含 `tryFlipDownlinkAndRedecode()` 与 `padMarker_` 动态学习逻辑（[`SudokuProtocol.cpp`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1031-L1063)），用于在配置与服务端不匹配或服务端使用非标 6-bit 打包标记时启发式翻转重试。 |
| **10** | **Shadowsocks (SS)** | [Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L118-L177) | **P2 (生态兼容)** | ⚠️ 缺少 SIP003 插件与部分算法 | 1. 明确拒绝所有 `plugin` / `obfs` 参数（[`Shadowsocks.cpp`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L120-L124)），不支持商业机场广泛使用的 `simple-obfs` (`obfs=http/tls`)、`v2ray-plugin`、`shadow-tls`；<br>2. 缺少 legacy 流加密算法（`rc4-md5`、`chacha20-ietf`、`salsa20`）及 `2022-blake3-chacha20-poly1305`。 |
| **11** | **AnyTLS / SSH / SOCKS5 / HTTP / Trojan** | [AnyTLS.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/AnyTLS.cpp)<br>[SSH.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SSH.cpp)<br>[Socks5Protocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Socks5Protocol.cpp) | **P3 (基本合规)** | ✅ 符合核心规范 | 线格式符合标准规范，仅有少量可演进项（如 SSH 未支持 `aes128-gcm` / HostKey 指纹校验；AnyTLS UoT 仅支持 v2 单目标流而不支持 v1 多目标复用）。 |

---

## 2. 逐协议深度审查与代码证据 (Detailed Protocol Audit)

---

### 2.1 TrustTunnel — 严重非标（私有定制协议 & 假 QUIC 模式）

- **源码文件**：[TrustTunnelProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp#L39-L273)
- **严重等级**：**P0 (Blocker)**

#### 问题详情

1. **`quic=true` 模式实为“伪 QUIC”（TCP+TLS 上强行设置 `ALPN = h3` 并发送 HTTP/1.1 报文）**
   - **代码位置**：[`connectTrustTunnel`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp#L227-L234)
     ```cpp
     auto tls = tlsOptions(node, true);
     if (tls.alpn.empty()) {
         tls.alpn.push_back(node.flag("quic", false) ? "h3" : "http/1.1");
     }
     factory->tcp(node, tls, [node, target, auth = std::move(auth), completion = std::move(completion)]
                  (std::shared_ptr<Stream> raw, Error err) mutable {
     ```
   - **原因分析**：当用户或订阅配置 `quic=true` 时，代码将 TLS ALPN 设为 `"h3"`，但紧接着调用的却是 `factory->tcp(node, tls, ...)`（基于 TCP 的 TLS 连接），随后在 TCP 流上直接发送明文 `CONNECT host:port HTTP/1.1\r\n...`。
   - **实际影响**：真正的 HTTP/3 (QUIC) TrustTunnel 服务端监听在 **UDP** 端口且使用 QUIC 帧与 QPACK 头部压缩；在 TCP+TLS 上协商 `"h3"` ALPN 并发 HTTP/1.1 文本会直接被任何标准服务端拒绝。

2. **TCP 隧道未实现 HTTP/2 (`h2`) 多路复用，UDP 隧道采用私有 `_trusttunnel_udp_:443` 帧格式**
   - **代码位置**：[`StreamPacketDatagram`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp#L39-L198)、[`connectTrustTunnel`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp#L254-L273)
     ```cpp
     std::string authority = target.udp
         ? std::string("_trusttunnel_udp_:443")
         : formatHostHeaderAuthority(target.host) + ":" + std::to_string(target.port);
     ```
   - **原因分析**：AdGuard 官方开源的 [AdGuardTeam/TrustTunnel](https://github.com/AdGuardTeam/TrustTunnel) 基于 **HTTP/2 (`h2`)** 和 **HTTP/3 (`h3`)** 标准扩展 CONNECT 机制构建。而当前实现：
     - 强制使用 `HTTP/1.1`（每条流独占一个 TCP 连接）；
     - UDP 转发通过向虚构域名 `_trusttunnel_udp_:443` 发起 `HTTP/1.1 CONNECT`，再在字节流内封装自定义的 `[ATYP][ADDR][PORT][LEN_BE16][PAYLOAD]` 帧。该格式完全是为了配合仓库内测试脚本 `deploy_hajimi_test_nodes.sh` 中的 `hajimi_extra_servers.py` 而编写的私有协议。

#### 修复建议
- TCP+TLS 路径接入 `nghttp2`（或项目内 HTTP/2 帧引擎），默认协商 `ALPN = h2` 并使用标准 HTTP/2 `CONNECT` Stream；
- `quic=true` 路径必须走 `QUICTransport` (UDP + `ngtcp2` + HTTP/3 `CONNECT` / Capsule Datagram)，严禁在 TCP 上伪造 `"h3"` ALPN；
- 对照 `AdGuardTeam/TrustTunnel` 官方客户端线格式重构 UDP 隧道封装。

---

### 2.2 Snell v4 — 严重非标（默认优先使用测试脚本专用 Argon2id 变体与 v3 帧头）

- **源码文件**：[Snell.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L54-L701)
- **严重等级**：**P0 (Blocker)**

#### 问题详情

1. **默认兼容模式 (`Compat16Pool7`) 使用非 RFC 9106 的 Argon2id 索引算法**
   - **代码位置**：[`endpointCompatMode`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L67-L83)、[`deriveSnellArgon2idFallback`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L240-L307)、[`deriveKeyWithMode`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L340-L355)
     ```cpp
     // Snell.cpp:74
     return version >= 4 ? CompatMode::Compat16Pool7 : CompatMode::Standard;

     // Snell.cpp:285-290
     const uint32_t pool = pool7Variant
         ? (q - sl + idx - (idx == 0 ? 1u : 0u))
         : (q - sl + idx - 1u);
     ```
   - **原因分析**：`pool7Variant = true` 违反了 RFC 9106 §3.4 的标准参考块索引计算公式（当 `pass > 0 && slice == 0 && idx > 0` 时未减 1），且输出 `tagLen = 16`（标准 Snell v4 使用 `tagLen = 32` 取前 16 字节作为 AES-128-GCM 密钥）。这个变体纯粹是为了兼容此前自研 Python 测试服务端中写错的 Argon2id 函数。

2. **Snell v4 前两次握手尝试发送的是 Snell v3 的 2 字节长度头，导致连接真实 Surge Snell v4 服务端时前两次 TCP 必败**
   - **代码位置**：[`Encoder::frame`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L372-L394)、[`tryFallbackCompat`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L653-L701)
     ```cpp
     if (version_ < 4 || mode_ != CompatMode::Standard) {
         Buffer length; snellPut16(length, payload.size());
         auto lengthChunk = crypto::seal(cipher_, key_, snellNonce(nonce_++), length);
         ...
     ```
   - **原因分析**：当用户配置 `version = 4` 时：
     - 第 1 次 TCP 连接使用 `Compat16Pool7`（错误密钥 + v3 2 字节头）→ 真实 `snell-server v4` 解密失败并断开连接；
     - [`tryFallbackCompat`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L662-L664) 捕获失败后发起第 2 次 TCP 连接，使用 `Compat16RFC`（错误 `tagLen=16` + v3 2 字节头）→ 再次被真实服务端断开；
     - 第 3 次 TCP 连接才切换到 `CompatMode::Standard`（标准 32->16B Argon2id 密钥 + 7 字节 v4 头部 `{4,0,0,pad_hi,pad_lo,len_hi,len_lo}` + `swapPadding`）。
   - **实际影响**：连接任何正版 Surge `snell-server v4` 节点时，首次建连延迟增加 2 个完整 TCP+握手 RTT，且服务端日志会刷出两条 AEAD 解密错误告警（极易触发 fail2ban 封禁客户端 IP）。

3. **生产代码硬编码测试域名判断**
   - **代码位置**：[Snell.cpp:68](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L68)、[Snell.cpp:85](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L85)、[Snell.cpp:654](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L654)、[Snell.cpp:901](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp#L901)
     ```cpp
     if (node.host == "fixture.invalid") return CompatMode::Standard;
     ```

#### 修复建议
- 将 `CompatMode::Standard` 设为所有 Snell v4 节点的**唯一默认模式**；
- 彻底删除 `Compat16Pool7`、`Compat16RFC`、`pool7Variant` 及 `"fixture.invalid"` / `"node.scope.invalid"` 硬编码判断。

---

### 2.3 ShadowsocksR (SSR) & Shadowsocks (SS) — 协议插件与混淆生态缺失

- **源码文件**：[Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L118-L177)
- **严重等级**：SSR 为 **P0**，SS 插件生态为 **P2**

#### 问题详情

1. **SSR 仅允许 `aes-*-cfb` + `protocol=origin` + `obfs=plain`**
   - **代码位置**：[`Config::Config`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L138-L141)
     ```cpp
     if (lower(node.type)=="ssr" || lower(node.type)=="shadowsocksr") {
         if (!cfb || lower(node.option("protocol","origin"))!="origin" || lower(node.option("obfs","plain"))!="plain")
             throw std::runtime_error("SSR supports AES-CFB with origin/plain only");
     }
     ```
   - **实际影响**：`protocol=origin` + `obfs=plain` 实际上就是退化版的原版 Shadowsocks 流加密。真实世界中的 SSR 节点几乎 100% 启用了 `auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a` 等协议插件以及 `tls1.2_ticket_auth`、`http_simple` 等混淆插件，导入后全部会在校验阶段直接报错。

2. **Shadowsocks 拒绝所有 SIP003 `plugin` / `obfs`**
   - **代码位置**：[`Config::Config`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp#L120-L124)
     ```cpp
     for (auto key : {"plugin","plugin-opts","obfs","obfs-host","obfs-uri"})
         if (!node.option(key).empty())
             if (!(lower(node.type)=="ssr" || lower(node.type)=="shadowsocksr") || std::string(key)!="obfs")
                 throw std::runtime_error("Unsupported Shadowsocks plugin option");
     ```
   - **实际影响**：商业机场中大量 SS 节点附带 `obfs=http` / `obfs=tls` (`simple-obfs`) 或 `v2ray-plugin` (`mode=websocket`)，目前会被直接拒绝。

#### 修复建议
- 为 SS 实现内置的 `simple-obfs`（`http` 与 `tls` ClientHello 封装）和 `v2ray-plugin`（复用 WebSocket 传输层）；
- 为 SSR 补齐 `auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a` 与 `http_simple`、`tls1.2_ticket_auth`，支持 `rc4-md5` / `chacha20-ietf`。

---

### 2.4 VLESS + XTLS Vision — 开启 Vision 流控时 UDP 完全不可用

- **源码文件**：[VlessTrojanProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp#L216-L246)、[Vision.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Vision.cpp#L1-L144)
- **严重等级**：**P1 (High)**

#### 问题详情

- **代码位置**：[`PlainFramedStream::PlainFramedStream`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp#L223-L226)
  ```cpp
  auto flow = node.option("flow");
  if (!flow.empty()) {
      if (target_.udp)
          throw std::runtime_error("VLESS Vision UDP requires an XUDP carrier");
      if (lower(flow) != "xtls-rprx-vision")
          throw std::runtime_error("Unsupported VLESS flow");
      ...
  ```
- **原因分析**：在 `Xray-core`、`sing-box` 和 `mihomo` 标准实现中，当 VLESS 节点配置了 `flow=xtls-rprx-vision` 时：
  1. 标准做法是通过 VLESS `command = 3` (Mux / XUDP) 在 Vision 流内承载 UDP 数据包；
  2. 或者对独立 UDP 流（`command = 2`）不写入 Vision Addon（因为 XTLS Vision 仅作用于 TCP TLS-in-TLS 流），直接发送 `command = 2` 的 2 字节长度前缀 UDP 帧。
- **实际影响**：目前 Hajimi 遇到 `flow=xtls-rprx-vision` 且 `target.udp == true` 时直接抛出异常，导致所有 VLESS+Reality+Vision 节点的 UDP（包括 QUIC/HTTP3、WebRTC、游戏语音、UDP DNS）全部失败。

#### 修复建议
- 短期立即可行修复：当 `target_.udp == true` 时，忽略 `flow=xtls-rprx-vision`（向服务端发送空的 Addon 长度 `0x00` 与 `command = 2`），并在 `connectVlessTrojan` 中对 `target.udp` 不包裹 `VisionStream`（`Xray-core` 服务端原生支持在同一用户的 `xtls-rprx-vision` 节点上接收 `command = 2` 无 flow 的 UDP 请求）；
- 长期完整修复：实现标准 XUDP (`command = 3` + GlobalID) 封装。

---

### 2.5 WireGuard — 非标重握手触发器、缺少 Cookie Reply / 防重放窗口及 IPv6 缺陷

- **源码文件**：[WireGuardProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L350-L1650)
- **严重等级**：**P1 (High)**

#### 问题详情

1. **非标重握手触发器：连续发 8 个上行包未收到回包即强制发起 Noise 重握手**
   - **代码位置**：[`SharedWGTunnel::sendIPPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L958-L961)
     ```cpp
     if (++unansweredTxPackets_ > 8) {
         unansweredTxPackets_ = 0;
         triggerRehandshake = true;
     }
     ```
   - **原因分析**：在 WireGuard 官方白皮书 §6.1–6.2 中，触发重握手的条件是基于**时间**（`KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15s` 未收到对端任何包，或会话达到 `REKEY_AFTER_TIME = 120s`）或**包序号上限**（`REKEY_AFTER_MESSAGES = 2^60`）。
   - **实际影响**：当客户端打开网页同时发起 >8 个并发 TCP `SYN` 或 DNS 查询，或者上传大文件连续发出 9 个 MTU 分片而服务端 ACK 尚未到达时，`unansweredTxPackets_ > 8` 立即触发 `sendHandshakeInitiation(true)` 重置会话密钥，导致正在传输的上下文发生握手风暴与乱序丢包。

2. **未实现 `Type = 3` (Cookie Reply) 处理与 `mac2` 计算**
   - **代码位置**：[`buildHandshakeInitiation`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L446-L450)、[`onCarrierPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L1116)
   - **原因分析**：`msg[132..148]` (`mac2`) 始终填 0，`onCarrierPacket` 仅处理 `pkt[0] == 2` (Handshake Response) 和 `pkt[0] == 4` (Transport Data)，直接丢弃 `pkt[0] == 3` (Cookie Reply)。当服务端处于高并发状态返回 Cookie Reply 时，客户端无法完成握手。

3. **未实现 Transport Data 防重放滑动窗口 (Anti-Replay Sliding Window)**
   - **代码位置**：[`decryptTransportPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L515-L547)
   - **原因分析**：解密后未校验 `counter` 是否重放或落后于滑动窗口（RFC 6479）。

4. **缺失标准保活与密钥生命周期定时器 (`PersistentKeepalive`、`REKEY_AFTER_TIME = 120s`、`REJECT_AFTER_TIME = 180s`)**
   - **代码位置**：[`parseWGConfig`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L350-L410) 未解析 `persistent-keepalive`，隧道空闲时不会自动发送空载荷保活包（Type 4, 0-byte payload），NAT 映射过期后下行流量会中断。

5. **隧道内 DNS 仅支持 IPv4 `A` 记录，且未配置 IPv6 时硬编码伪造 ULA 源地址**
   - **代码位置**：[`parseWGConfig`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L369)、[`resolveHostIPv4`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L776-L837)、[`WireGuardUDPDatagram::send`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L1294)、[`WireGuardTCPStream::beginTargetConnect`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L1612)
     ```cpp
     std::string v6Str = stripCidr(node.option("ipv6", node.option("self-ip-v6")));
     cfg.hasSelfIPv6 = !v6Str.empty();
     if (v6Str.empty()) v6Str = "fd00:6861:6a69:66::2";
     ```
   - **原因分析**：
     - 若用户节点仅配置了 IPv4 隧道内地址（未配 `self-ip-v6`），当目标地址是 IPv6 字面量时，代码未检查 `cfg_.hasSelfIPv6`，直接用硬编码的 `"fd00:6861:6a69:66::2"` 作为源 IP 构造 IPv6 包发往服务端，必然被标准 WireGuard 服务端因 `AllowedIPs` 不匹配而丢弃；
     - 隧道内域名解析 [`resolveHostIPv4`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L776) 仅发送 IPv4 `A` 记录查询，不支持 `AAAA` 记录与 IPv6 DNS 服务器。

6. **生产代码残留 `"fixture.invalid"` 测试域名判断**
   - **代码位置**：[WireGuardProtocol.cpp:866](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L866)、[WireGuardProtocol.cpp:877](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L877)、[WireGuardProtocol.cpp:1212](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp#L1212)。

#### 修复建议
- 将 `unansweredTxPackets_ > 8` 替换为基于时间戳的 `lastRxTime` 超时检查（如距离上次收到对端报文超过 15 秒且期间有上行发送才触发重握手）；
- 补齐 `Type = 3` Cookie Reply 解密（XChaCha20-Poly1305）与 `mac2` 计算；
- 在发起 IPv6 目标连接前检查 `cfg_.hasSelfIPv6`，并支持 `AAAA` 隧道内解析；移除 `"fixture.invalid"` 硬编码。

---

### 2.6 QUIC 协议族 (Hysteria2 / TUIC v5 / Hysteria1) — 无单连接多路复用 & 缺少 Brutal 拥塞控制

- **源码文件**：[QUICProtocols.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICProtocols.cpp#L391-L439)、[QUICTransport.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L606-L1242)
- **严重等级**：**P1 (High - 架构与性能)**

#### 问题详情

1. **每条代理 TCP 流均新建独立 QUIC 连接与独立 OS 线程 (`std::thread`)，未实现 QUIC 多路复用**
   - **代码位置**：[`connectQUICProtocol`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICProtocols.cpp#L391-L439)、[`Connection::start`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L1146)、[`connectQuicStream`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L1221-L1242)
     ```cpp
     // QUICProtocols.cpp:414
     quic::connectQuicStream(config, [node, target, completion](std::shared_ptr<quic::Session> session, ...
     // QUICTransport.cpp:1146
     worker_ = std::thread([self] { self->run(); });
     ```
   - **原因分析**：QUIC 协议（Hysteria2 / TUIC v5）的核心优势在于：**同一个节点共享一条底层 QUIC `Connection`**，认证一次后，所有并发 TCP 请求仅需在已有 QUIC 连接上打开新的双向流（`ngtcp2_conn_open_bidi_stream`，0-RTT 开销）。
   - **实际影响**：当前实现每发起一个 TCP 请求（例如浏览器加载一个网页产生 30 个并发连接），就会创建 30 个 UDP Socket、启动 30 个 `std::thread` 线程、执行 30 次完整的 TLS 1.3 + QUIC 握手和 30 次 Hysteria2 HTTP/3 `/auth`（或 TUIC `authenticate`）认证！这不仅造成严重的 CPU/内存/线程开销和首包延迟，还会触发商业服务端对单 IP 高频新建 QUIC 会话的速率限制。

2. **缺少 Hysteria1 / Hysteria2 的 Brutal 拥塞控制算法**
   - **代码位置**：[`Connection::initQuic`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L607-L609)
     ```cpp
     auto cc = lower(cfg_.cc);
     ngtcp2_cc_algo algo = cc == "cubic" ? NGTCP2_CC_ALGO_CUBIC : cc == "reno" ? NGTCP2_CC_ALGO_RENO : NGTCP2_CC_ALGO_BBR;
     ```
   - **原因分析**：仅支持 `ngtcp2` 自带的 BBR/Cubic/Reno，虽然在 Hysteria2 `/auth` 请求头中发送了 `Hysteria-CC-RX` 带宽协商字段，但客户端本地发送并未实现恒定速率的 Brutal 拥塞控制。

3. **禁用 `ngtcp2` 标准 PMTUD，使用非标的连续 3 次 `send()` 失败缩减 MTU 策略**
   - **代码位置**：[`QUICTransport.cpp:606`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L606)、[`QUICTransport.cpp:944-973`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp#L944-L973)
   - **原因分析**：设置了 `settings.no_pmtud = 1`，并在 `::send()` 返回错误时丢弃 `pendingWire`（等待 QUIC 超时重传）并手动将 `maxTxPayload_` 降至 1200。

#### 修复建议
- 参考 `AnyTLS.cpp` 中的 `ClientPool` 架构，在 `QUICProtocols.cpp` 中按 `(Node, TransportFactory)` 维护共享的 `quic::Session` 连接池，复用已通过 `/auth` 认证的 QUIC 连接打开新双向流（`openStream`），仅在连接断开或迁移时重建；
- 将 `QUICTransport` 的每连接独立 `std::thread` 改造为基于 `dispatch_source_t` 事件驱动。

---

### 2.7 VMess — 硬编码 `AES-128-GCM` 忽略用户加密配置

- **源码文件**：[VMess.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp#L168-L185)
- **严重等级**：**P2 (Medium)**

#### 问题详情

- **代码位置**：[`VMessStream::VMessStream`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp#L175)
  ```cpp
  command.insert(command.end(),{verification_,1,uint8_t((padding<<4)|3),0,uint8_t(muxTarget(target)?3:target.udp?2:1)});
  ```
- **原因分析**：
  1. 第 3 字节低 4 位固定写死为 `3`（即 `Security = AES-128-GCM`），完全忽略了节点参数中的 `cipher` / `security`（如 `chacha20-poly1305` = `4`、`none` / `zero` = `5`）；
  2. 第 2 字节 `Option` 固定写死为 `1`（仅 `RequestOptionChunkStream`），未启用现代 V2Ray/Xray 默认的 `RequestOptionChunkMasking (0x04)`（使用 Shake128 对每个数据块长度做 XOR 掩码）。
- **实际影响**：虽然绝大多数标准 V2Ray/Xray 服务端允许客户端自选 AEAD 算法与 Option，但如果服务端强制要求 `security: "none"` 或特定加密方式，或者中间网络依赖 `ChunkMasking` 隐藏固定长度特征，硬编码 `AES-128-GCM` + 无 Masking 会降低兼容性与抗特征能力。

#### 修复建议
- 解析 `node.option("cipher", node.option("security", "auto"))`，支持 `aes-128-gcm (3)`、`chacha20-poly1305 (4)`（含双 16B Key 派生扩展）与 `none/zero (5)`；
- 支持 `RequestOptionChunkMasking (0x04)` Shake128 长度掩码。

---

### 2.8 Mieru (v3) — 缺少单连接多 Session 复用与上行低熵编码

- **源码文件**：[MieruProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L59-L1783)
- **严重等级**：**P2 (Medium)**

#### 问题详情

1. **配置了 `multiplexing` 参数但未实际执行连接池复用**
   - **代码位置**：[`parseMieruConfig`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L59-L66)、[`connectMieru`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L1672-L1776)
   - **原因分析**：虽然解析了 `MULTIPLEXING_OFF / LOW / MIDDLE / HIGH`，但在 [`connectMieru`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L1704-L1775) 中，每次调用都会新建一条底层 TCP Stream 或 UDP Datagram Socket，并在其上仅运行单个 `sessionID`。官方 `enfein/mieru` 客户端在 `MULTIPLEXING_LOW/MIDDLE/HIGH` 下会在单条底层 TCP/UDP 隧道上复用多个 `sessionID`。
   - **实际影响**：与官方 `mita` 服务端完全兼容（`mita` 原生支持单连接单 Session），但在高并发短连接场景下，新建底层连接的开销高于多路复用模式。

2. **UDP 载荷解密中保留了历史非标 Nonce 回退分支**
   - **代码位置**：[`MieruUDPStream::onPacket`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp#L1286-L1298)
     ```cpp
     try {
         plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, nonce, cipherPayload);
     } catch (...) {
         Buffer beNonce = nonce;
         incrementNonceBE(beNonce);
         try {
             plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, beNonce, cipherPayload);
         } catch (...) {
             Buffer leNonce = nonce;
             incrementNonceLE(leNonce);
             plainPayload = crypto::open(crypto::AEAD::XChaCha20Poly1305, rxKey_, leNonce, cipherPayload);
         }
     }
     ```
   - **原因分析**：标准 `mita` v3 服务端在 UDP 模式下对 Metadata 与 Payload 使用同一个包头 `nonce`（即第一个 `try` 分支 100% 命中）。`catch` 中的 `beNonce` 与 `leNonce` 是为历史非标测试脚本服务端留下的兜底逻辑。虽然不影响正常包的性能，但当收到损坏的 UDP 报文时会多执行两次无意义的 AEAD 解密尝试。

---

### 2.9 Sudoku — 未实现 KIP Mux (`0x11`) 与包含启发式下行翻转兼容逻辑

- **源码文件**：[SudokuProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1016-L1695)
- **严重等级**：**P2 (Medium)**

#### 问题详情

1. **定义了 `kKIPTypeStartMux (0x11)` 但未实现单连接多路复用**
   - **代码位置**：[`SudokuProtocol.cpp:1019`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1019)
   - **原因分析**：`[[maybe_unused]] constexpr uint8_t kKIPTypeStartMux = 0x11;`，当前每条 TCP 连接使用 `kKIPTypeOpenTCP (0x10)` 独立建连，UDP 使用 `kKIPTypeStartUoT (0x12)`。与官方 `SUDOKU-ASCII/sudoku` 服务端完全兼容，但未利用 `StartMux` 复用底层握手。

2. **启发式下行模式翻转 (`tryFlipDownlinkAndRedecode`) 与 `padMarker_` 学习缓存**
   - **代码位置**：[`SudokuProtocol.cpp:1031-1063`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1031-L1063)、[`SudokuProtocol.cpp:1441-1511`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SudokuProtocol.cpp#L1441-L1511)
   - **原因分析**：当用户客户端配置的 `enable-pure-downlink` 与服务端实际配置相反，或非标服务端在 6-bit 打包下行模式中使用了非 `paddingPool[0]` 的字节作为尾填充标记时，客户端通过捕获握手阶段的解码异常自动翻转 `enablePureDownlink` 并学习 `padMarker_`。对标准服务端无负面影响，但属于非标容错启发式代码。

---

### 2.10 AnyTLS / SSH / SOCKS5 / HTTP / Trojan — 合规性评估

1. **AnyTLS ([AnyTLS.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/AnyTLS.cpp#L1-L827))**
   - **合规状态**：✅ 高度符合 `anytls/anytls-go` 官方规范（SHA256(password) + Padding Scheme + Session Multiplexing + `v2.udp-over-tcp.arpa` UoT）。
   - **次要差异**：在 [`Session::parsePaddingScheme`](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/AnyTLS.cpp#L244-L280) 中未处理 `check-interval` 等扩展定时器指令，且仅实现了 UoT v2（每目标地址独立 Stream），未实现 UoT v1（单 Stream 多目标地址）。

2. **SSH ([SSH.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SSH.cpp#L1-L975))**
   - **合规状态**：✅ 符合 RFC 4251–4254 及 OpenSSH `chacha20-poly1305@openssh.com` 规范，实现了连接池复用与 `direct-tcpip` 通道流控。
   - **次要差异**：
     - 仅实现了 `chacha20-poly1305@openssh.com` 与 `aes128-ctr` / `aes256-ctr`，未实现 `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`；
     - 未支持服务端 Host Key 指纹校验（`host-key` 参数）；
     - 加密私钥（Encrypted OpenSSH Private Key with passphrase）未支持解密。

3. **SOCKS5 / HTTP Proxy / Trojan ([Socks5Protocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Socks5Protocol.cpp)、[SocksDatagram.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/SocksDatagram.cpp)、[HttpProxyProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/HttpProxyProtocol.cpp)、[VlessTrojanProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp))**
   - **合规状态**：✅ 均严格符合 RFC 1928 / RFC 1929 / RFC 9110 / Trojan 官方规范。
   - **次要差异**：`SocksDatagram.cpp` 在收到 SOCKS5 `UDP ASSOCIATE` 返回 `BND.ADDR = 0.0.0.0` 或 `::` 时已正确替换为代理节点 IP，但未监听控制 TCP 连接的被动断开通知。

---

## 3. 商业化整改优先级路线图 (Remediation Roadmap)

### 第一阶段（P0 立即整改 — 消除非标私有实现与错误默认行为）
1. **Snell v4 ([Snell.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Snell.cpp))**：
   - 将默认模式改为 `CompatMode::Standard`（标准 RFC 9106 Argon2id 32->16B + 标准 7 字节 v4 帧头），移除 `Compat16Pool7` / `Compat16RFC` 及其导致的 3 次 TCP 重连回退，清理 `"fixture.invalid"` 硬编码。
2. **VLESS Vision UDP ([VlessTrojanProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VlessTrojanProtocol.cpp))**：
   - 修复 `flow=xtls-rprx-vision` 下 `target.udp == true` 直接抛异常的问题，允许 UDP 流量使用标准 VLESS `command = 2` 或 XUDP `command = 3` 正常转发。
3. **TrustTunnel ([TrustTunnelProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/TrustTunnelProtocol.cpp))**：
   - 移除 `quic=true` 在 TCP 上伪造 `"h3"` ALPN 的逻辑，接入真实 HTTP/2 (`h2`) 与 QUIC HTTP/3 (`h3`) 传输层，对齐 `AdGuardTeam/TrustTunnel` 官方规范。
4. **ShadowsocksR ([Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp))**：
   - 补齐标准 SSR 协议插件（`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a`）与混淆插件（`tls1.2_ticket_auth`、`http_simple`）。

### 第二阶段（P1 核心稳定性与性能升级）
1. **WireGuard ([WireGuardProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/WireGuardProtocol.cpp))**：
   - 移除 `unansweredTxPackets_ > 8` 的非标重握手触发器，改为符合白皮书的 15s 超时重握手与 120s 周期重协商；
   - 增加 `Type = 3` Cookie Reply 与 `mac2` 支持、RFC 6479 防重放窗口、`PersistentKeepalive` 定时器以及隧道内 IPv6 `AAAA` DNS 解析。
2. **QUIC 协议族 ([QUICProtocols.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICProtocols.cpp) & [QUICTransport.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/QUICTransport.cpp))**：
   - 实现 Hysteria2 / TUIC v5 单 QUIC 连接多路复用连接池（`SessionPool`），消除每条 TCP 流新建 QUIC 连接与 `std::thread` 的开销；
   - 补齐 Hysteria2 Brutal 拥塞控制算法。

### 第三阶段（P2 生态完善）
1. **VMess ([VMess.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/VMess.cpp))**：支持 `chacha20-poly1305` 与 `none/zero` 加密配置，支持 `RequestOptionChunkMasking (0x04)`。
2. **Shadowsocks ([Shadowsocks.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/Shadowsocks.cpp))**：内置 `simple-obfs` (`http` / `tls`) 与 `2022-blake3-chacha20-poly1305` 支持。
3. **Mieru ([MieruProtocol.cpp](file:///Users/weiwei/Downloads/hajimi-main/Sources/HajimiProtocolsCXX/MieruProtocol.cpp))**：移除 UDP 载荷解密的 `beNonce`/`leNonce` 历史兜底分支，按 `multiplexing` 级别支持单底层连接多 Session 复用。

