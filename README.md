# 哈基米 (Hajimi) for macOS

## 项目简介

**哈基米 (Hajimi)** 是一款面向 **macOS 13+**（支持 Intel `x86_64` 与 Apple Silicon `arm64` 双架构）的原生高性能网络代理、协议栈、加密 DNS 与规则分流客户端。

本项目由AI编写，自行优化、修改和完善，仅供学习交流使用。

- **原生 C11 / C++17 / C++20 协议与数据平面**：核心代理协议栈、零拷贝切片 AEAD/TLS 加解密、QUIC/HTTP3 传输、紧凑双生基数树（CIDR）与逆向标签后缀 Trie 路由匹配、以及用户态 TCP/UDP/ICMP 报文处理均采用 C11 / C++17 / Objective-C++ / Swift 6.0 原生编写，无外部 Go/Rust 运行时依赖。
- **全场景流量接管**：支持本地 HTTP / HTTPS / SOCKS5 混合或独立端口代理监听、macOS 系统代理与增强模式（特权 Helper 驱动的 `utun` 虚拟网卡 + Fake-IP `198.18.0.0/15` + 用户态 L3/L4 协议栈）。
- **学术级防泄漏加密 DNS 架构**：内置 DoH（DNS over HTTPS）、DoT（DNS over TLS）、DoQ（DNS over QUIC, [RFC 9250](https://www.rfc-editor.org/info/rfc9250/)）与 ODoH（Oblivious DoH, [RFC 9230](https://www.rfc-editor.org/info/rfc9230/)）自适应解析器，融合 [RFC 8467](https://www.rfc-editor.org/info/rfc8467/) 抗边信道流量指纹填充、[RFC 7871](https://www.rfc-editor.org/info/rfc7871/) ECS 客户端子网隐私净化、[RFC 8767](https://www.rfc-editor.org/info/rfc8767/) Serve-Stale 容灾缓存以及 UCB1 多臂老虎机 + 新息自适应卡尔曼-韦尔福德（Kalman-Welford）尾延迟感知对冲调度。
- **多格式配置与订阅兼容**：原生支持 [Surge 配置规范](https://manual.nssurge.com/)（`.conf`）、Clash / Mihomo YAML 订阅与 Base64 节点分享链接导入。

---

## 目录

1. [支持的出站代理协议详解（19 种协议实体）](#1-支持的出站代理协议详解19-种协议实体)
2. [支持的传输层、多路复用与伪装载体详解（13 类载体）](#2-支持的传输层多路复用与伪装载体详解13-类载体)
3. [支持的加密 DNS 与服务发现协议详解](#3-支持的加密-dns-与服务发现协议详解)
4. [本地入站代理与虚拟网卡（TUN）数据平面](#4-本地入站代理与虚拟网卡tun数据平面)
5. [跨学科科研级底层、传输、网速与安全优化](#5-跨学科科研级底层传输网速与安全优化)
6. [源码模块拓扑与目录结构](#6-源码模块拓扑与目录结构)
7. [构建、测试与打包指南](#7-构建测试与打包指南)
8. [致谢：开源协议作者、科研学者与 IETF 标准](#8-致谢开源协议作者科研学者与-ietf-标准)

---

## 1. 支持的出站代理协议详解（19 种协议实体）

哈基米通过 `HajimiProtocolsCXX`、`HajimiProtocolCXX` 与 `HajimiCore` 完整支持 **19 种出站协议类型**（含 `direct` / `reject` 策略原语与 17 种加密/隧道代理协议）：

| 协议分类 | 协议名称 (`type`) | 标准/规范依据 | 加密算法 / 认证机制 | TCP 流转发 | UDP 转发模式 | 核心特性与支持参数 |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **现代零特征协议** | **VLESS** (`vless`) | [XTLS VLESS v0](https://xtls.github.io/development/protocols/vless.html) | UUID (16B) + TLS 1.3 / [REALITY](https://github.com/XTLS/REALITY) / [XTLS-Vision](https://xtls.github.io/development/protocols/vless.html) | ✓ | ✓ (XUDP / UoT / Frame) | 支持 `flow=xtls-rprx-vision`（TLS-in-TLS 零拷贝直通）、首包 Header+ClientHello 0-RTT 合并发送、TLS/WS/gRPC/H2/XHTTP/mKCP、`mux=true` (`v1.mux.cool`) |
| **现代零特征协议** | **VMess** (`vmess`) | [Project V VMess AEAD](https://www.v2fly.org/developer/protocols/vmess.html) | UUID + KDF (`HMAC-SHA256`) + AuthID (`AES-128-ECB`) + Body (`AES-128-GCM` / `ChaCha20-Poly1305` / `zero`) | ✓ | ✓ (AEAD Frame / XUDP) | 强制现代 VMess AEAD 头部认证（拒绝 Legacy MD5 重放风险），支持 0-RTT 首包合并、16 KiB 零拷贝切片加密（`sealSlice`）与认证 EOF 帧 |
| **现代零特征协议** | **Trojan** (`trojan`) | [Trojan Protocol](https://trojan-gfw.github.io/trojan/protocol) | `SHA-224` 十六进制口令摘要 (56B) + TLS 1.3 / REALITY | ✓ | ✓ (Trojan UDP Frame) | 支持首包 56B SHA-224 头部与上行载荷合并发送、支持 TLS / REALITY / WebSocket / gRPC / HTTP2 / XHTTP 载体 |
| **现代零特征协议** | **AnyTLS** (`anytls`) | [AnyTLS Specification](https://github.com/anytls/anytls-go) | `SHA-256(password)` + 动态填充策略协商 + 多路复用连接池 | ✓ | ✓ (UoT v2) | 支持 TLS 逻辑流会话复用（Idle Session Pool）、可配置动态分段填充方案（`padding-scheme`）消除 TLS-in-TLS 指纹、SYN/SYNACK 握手确认与心跳保活 |
| **QUIC 原生协议** | **Hysteria 2** (`hysteria2` / `hy2`) | [Hysteria v2 Protocol](https://v2.hysteria.network/docs/developers/Protocol/) | HTTP/3 伪装认证 (`/auth` POST) + QUIC ([RFC 9000](https://www.rfc-editor.org/info/rfc9000/)) + Salamander 混淆 | ✓ (`0x401` Bidirectional Stream) | ✓ (QUIC Datagram + 分片重组) | 基于 `ngtcp2` + `nghttp3`，支持 Salamander `BLAKE2b-256` 逐包 XOR 混淆、Brutal/BBR 速率通告（`up` / `down`）、端口跳跃（`mport` / `ports`）与流级随机 Padding |
| **QUIC 原生协议** | **Hysteria v1** (`hysteria` / `hy1`) | [Hysteria v1 Protocol](https://v1.hysteria.network/) | ALPN `hysteria` + QUIC 控制流认证 + 速率协商 | ✓ (QUIC Stream) | ✓ (QUIC Datagram / Stream 回退) | 支持 `auth` / `auth-str`、`up` / `down` 带宽声明、`obfs` (XPlus) 混淆、Session ID 多路 UDP 会话与 TCP 流式回退 |
| **QUIC 原生协议** | **TUIC v5** (`tuic` / `tuic5`) | [TUIC v5 Specification](https://github.com/EAimTY/tuic) | UUID + TLS 1.3 Exporter ([RFC 8446 §7.5](https://www.rfc-editor.org/info/rfc8446/)) 32B 令牌 | ✓ (`Connect` Stream) | ✓ (`native` Datagram / `quic` Uni-Stream) | 基于 `ngtcp2` 支持 0-RTT 并行 `Authenticate` + `Connect` 帧发送、UDP Association 关联表、分片重组与心跳保活 |
| **抗审查与混淆协议** | **Mieru (見える) v3** (`mieru`) | [Mieru Protocol v3](https://github.com/enfein/mieru) | `PBKDF2-HMAC-SHA256`（2 分钟时间桶动态密钥）+ `XChaCha20-Poly1305` | ✓ (`MieruTCPStream`) | ✓ (`MieruUDPStream` 可靠重传) | 支持 TCP 与 UDP 双底层传输、48B 加密元数据块、随机前后缀填充、低熵比特扩展模式（Low-Entropy Mode，BMI2 `_pext_u64` / CLZ 硬件加速）与 UDP 选择性重传状态机 |
| **抗审查与混淆协议** | **Sudoku (数独协议)** (`sudoku`) | [Sudoku Protocol](https://github.com/SUDOKU-ASCII/sudoku) | `SHA-256` 确定性 Fisher-Yates 洗牌 4×4 数独网格 + `HKDF-SHA256` + AEAD | ✓ | ✓ (UoT Frame) | 支持 4×4 数独 $O(1)$ 谜题编码混淆（标准 ASCII 低熵模式与 `entropier` `custom-table`/`custom-tables` X-V 双射布局）、KIP 控制协议与 UoT |
| **抗审查与混淆协议** | **TrustTunnel** (`trusttunnel`) | [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) / [RFC 8441](https://www.rfc-editor.org/info/rfc8441/) / [RFC 9298](https://www.rfc-editor.org/info/rfc9298/) | HTTP Basic (`Proxy-Authorization`) + TLS 1.3 (`h2` / `h3` / `http/1.1`) | ✓ (`CONNECT` / HPACK Stream) | ✓ ([RFC 9297](https://www.rfc-editor.org/info/rfc9297/) Capsule / `_udp` Tunnel) | 伪装标准 HTTPS (HTTP/1.1、HTTP/2 TLS) 与 HTTP/3 QUIC 的全流量 VPN 隧道，原生实现 HTTP/2 帧状态机与 IETF MASQUE Datagram/Capsule 编解码 |
| **经典与通用 AEAD 协议** | **Shadowsocks (SS)** (`ss` / `shadowsocks`) | [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html) | `HKDF-SHA1` (`"ss-subkey"`) + `AES-128/192/256-GCM`、`ChaCha20-IETF-Poly1305`、`XChaCha20-IETF-Poly1305`（兼容 `AES-CFB`/`CTR`） | ✓ | ✓ (Per-packet Salt AEAD) | 内置双域 LRU Salt 防重放缓存（拦截反射与重放攻击），支持 `obfs=http/tls`、`v2ray-plugin`、`shadow-tls` 插件参数與零拷贝切片加密 |
| **经典与通用 AEAD 协议** | **Shadowsocks 2022** (`ss` / `shadowsocks`) | [SIP022 Shadowsocks 2022](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md) | `BLAKE3` 密钥派生 (`"shadowsocks 2022 session subkey"`) + `2022-blake3-aes-128/256-gcm` / `2022-blake3-chacha20-poly1305` | ✓ | ✓ (`AES-ECB` 独立包头 + AEAD) | 支持可扩展多级身份链头（Multi-User EIH，`iPSK1:iPSK2:uPSK`）、64 秒时间戳窗口校验与 64-bit 滑动窗口防重放 |
| **经典与通用 AEAD 协议** | **ShadowsocksR** (`ssr`) | [SSR Protocol Specification](https://github.com/shadowsocksrr/shadowsocks-rss) | 协议插件 (`origin`, `auth_aes128_md5/sha1`, `auth_chain_a/b`) + 混淆 (`plain`, `http_simple/post`, `tls1.2_ticket_auth`) | ✓ | ✓ | 完整支持 SSR 协议层（`protocol` / `protocol-param`）与混淆层（`obfs` / `obfs-param`）状态机 |
| **经典与通用 AEAD 协议** | **Snell (v4–v6)** (`snell`) | [Surge Snell Specification](https://manual.nssurge.com/policies/snell.html) | [RFC 9106 Argon2id](https://www.rfc-editor.org/info/rfc9106/) (`m=8KiB, t=3, p=1`) + `AES-128-GCM` / `ChaCha20-Poly1305` | ✓ | ✓ (Snell v4–v6 UDP Relay) | 支持 v4–v6 会话复用（`reuse=true`）与 UDP 转发（已移除不安全的旧版 v1–v3），自动协商 `Standard` (32B Key) 与 `Compat16` (16B Key) 服务端变体并缓存零回退直连 |
| **L3 / SSH 隧道协议** | **WireGuard** (`wireguard`) | [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf) | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`（`X25519` + `ChaCha20-Poly1305` + [RFC 7693 BLAKE2s](https://www.rfc-editor.org/info/rfc7693/)） | ✓ (用户态 L3/L4 TCP 状态机) | ✓ (用户态 IPv4/UDP 封装) | 纯用户态实现完整 Noise 握手、单调递增 TAI64N 防重放时间戳、64-bit SWAR 校验和、Cloudflare WARP 3 字节 `reserved` 字段与单隧道多流复用（`SharedWGTunnel`） |
| **L3 / SSH 隧道协议** | **SSH** (`ssh`) | [RFC 4251](https://www.rfc-editor.org/info/rfc4251/) / [RFC 4254](https://www.rfc-editor.org/info/rfc4254/) (`direct-tcpip`) | 口令认证 / PEM 私钥 (`Ed25519`, `RSA-SHA2-256/512`, `ECDSA`) + 主机公钥指纹钉扎 | ✓ (`SSH_MSG_CHANNEL_DATA`) | ✓ (TCP/DoH 回退) | 基于非阻塞 `libssh2` 状态机，支持密码、私钥、主机公钥白名单校验、私钥文件权限/FIFO 符号链接安全审计与半关闭 (`SSH_MSG_CHANNEL_EOF`) |
| **标准代理协议** | **SOCKS5 / SOCKS5-TLS** (`socks5` / `socks5-tls`) | [RFC 1928](https://www.rfc-editor.org/info/rfc1928/) / [RFC 1929](https://www.rfc-editor.org/info/rfc1929/) | 无认证 (`0x00`) / 用户名密码 (`0x02`) + 可选 TLS 1.3 | ✓ (`CONNECT 0x01`) | ✓ (`UDP ASSOCIATE 0x03`) | 标准 SOCKS5（含 `UDP ASSOCIATE`）与 TLS 加密 SOCKS5，严格校验服务端返回地址类型并绑定 UDP 关联控制流生命周期 |
| **标准代理协议** | **HTTP / HTTPS** (`http` / `https`) | [RFC 9110](https://www.rfc-editor.org/info/rfc9110/) / [RFC 9112](https://www.rfc-editor.org/info/rfc9112/) | HTTP Basic (`Proxy-Authorization`) + 可选 TLS 1.3 | ✓ (`CONNECT` / Absolute-URI Rewrite) | — | 对普通 HTTP 流量自动执行规范化绝对 URI 改写并剥离敏感代理头，对 HTTPS/任意端口执行 `CONNECT` 隧道握手并保留预读残留字节 |
| **内置基础策略** | **Direct / Reject** (`direct` / `reject` / `reject-tinygif` / `reject-drop`) | 内置路由动作原语 | — | ✓ | ✓ | 支持直连（Happy Eyeballs 双栈并发竞速）、立即拒绝、静默丢包与 1×1 透明 GIF 响应合成 |

---

## 2. 支持的传输层、多路复用与伪装载体详解（13 类载体）

哈基米的传输层采用可组合装饰器管线（Composable Carrier Pipeline）设计，支持将上层代理协议灵活挂载于以下 13 类底层传输与多路复用载体之上：

| 传输载体 / 特性 | 配置标识 | 标准 / 协议规范 | 核心实现机制与优化细节 |
| :--- | :--- | :--- | :--- |
| **TCP + Happy Eyeballs v2** | `network=tcp` (默认) | [RFC 8305](https://www.rfc-editor.org/info/rfc8305/) | IPv6/IPv4 交错地址排序与 250ms 阶梯式并发建连竞速，开启 `TCP_NODELAY`、自适应套接字缓冲区与 `TCP_NOTSENT_LOWAT` 低水位控制 |
| **TLS 1.3 / TLS 1.2** | `tls=true`, `sni=...`, `alpn=...` | [RFC 8446](https://www.rfc-editor.org/info/rfc8446/) | 支持自定义 SNI、ALPN 协商列表、SHA-256 服务端证书指纹钉扎（`server-cert-fingerprint-sha256`）与客户端 uTLS 指纹模拟（`client-fingerprint`） |
| **XTLS-REALITY** | `security=reality`, `reality-public-key`, `reality-short-id` | [XTLS REALITY](https://github.com/XTLS/REALITY) | 客户端在 TLS 1.3 `ClientHello` 中嵌入 `X25519` ECDH 派生与 `AES-GCM` 认证 `SessionId` / `ShortId`，消除服务端 TLS 指纹特征并抵御主动探测 |
| **XTLS-rprx-Vision** | `flow=xtls-rprx-vision` | [XTLS Vision](https://xtls.github.io/development/protocols/vless.html) | 自动识别内层 TLS 1.3 握手边界（兼容 Middlebox ChangeCipherSpec），对握手包实施长填充（900–1400B）并在 `ApplicationData` 阶段切换至零拷贝 `Direct` 直通模式 |
| **WebSocket (WS / WSS)** | `network=ws`, `ws-path`, `ws-headers` | [RFC 6455](https://www.rfc-editor.org/info/rfc6455/) | 支持 64-bit 8 字节步进向量化 XOR 掩码（`hajimi_ws_xor_mask`）、HTTP Upgrade 握手余量字节零丢失继承与 `max-early-data` (0-RTT Early Data) 头注入 |
| **HTTP/2 (H2)** | `network=h2` / `http`, `http-path`, `http-host` | [RFC 9113](https://www.rfc-editor.org/info/rfc9113/) | 基于 ALPN `h2` 的多路复用双向流载体，内置 HPACK 头部编解码与动态流控窗口维护 |
| **gRPC (Gun)** | `network=grpc`, `grpc-service-name` | [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md) | 编码 `:path = /<serviceName>/Tun`、`content-type = application/grpc` 及 5 字节 Length-Prefixed Message 帧头（1B 压缩标志 + 4B 大端长度 + Protobuf `0x0a` 变长字段） |
| **XHTTP / SplitHTTP** | `network=xhttp` / `splithttp`, `mode=...` | [Xray XHTTP](https://github.com/XTLS/Xray-core) | 支持将上行（POST 分块流）与下行（GET 事件流）分离或复用于 HTTP/1.1、HTTP/2、HTTP/3 通道，穿透 CDN 与受限中间件 |
| **mKCP (KCP over UDP)** | `network=kcp` / `mkcp`, `seed=...`, `header-type=...` | [KCP ARQ Protocol](https://github.com/skywind3000/kcp) / [Xray mKCP](https://xtls.github.io/config/transport.html#kcpobject) | 完整实现 KCP 滑窗重传、快速重传、无延迟 ACK、FNV-1a 32-bit 校验（`hajimi_mkcp_fnv1a`）、SimpleAuthenticator 64-bit 滚动 XOR 与 AES-128-GCM 混淆及伪装头（`srtp` / `utp` / `wechat-video` / `dtls` / `wireguard`） |
| **QUIC / HTTP/3 传输层** | `HajimiQUIC` (`ngtcp2` + `nghttp3`) | [RFC 9000](https://www.rfc-editor.org/info/rfc9000/) / [RFC 9114](https://www.rfc-editor.org/info/rfc9114/) | 集成 `ngtcp2` + `nghttp3` + `quictls`，支持 QUIC 双向/单向流、[RFC 9221](https://www.rfc-editor.org/info/rfc9221/) 不可靠数据报扩展（Datagram Frame）、0-RTT 恢复与连接迁移 |
| **Mux.Cool 多路复用** | `mux=true` | [Project V Mux.Cool v1](https://www.v2fly.org/developer/protocols/muxcool.html) | 在单条 VLESS / VMess / Trojan / Shadowsocks 连接上复用多个子会话（目标 `v1.mux.cool:9527`），由 `hajimi_mux_encode_frame` 提供零分配帧编码 |
| **XUDP 与 UDP-over-TCP (UoT)** | 自动协商 | Xray XUDP / Sing-box UoT v1 & v2 | 支持带 8 字节 `GlobalID`（BLAKE3 源地址哈希）的 XUDP 多目标复用帧（`hajimi_xudp_encode_frame`）以及 Sing-box `sp.v2.udp-over-tcp.arpa` UoT v2 协议 |
| **链式代理 (Proxy Chaining)** | `underlying-proxy=...` / `dialer-proxy=...` | Surge / Clash Meta 链式跳板规范 | 支持任意出站协议通过另一代理节点或策略组建立底层 TCP/UDP 传输通道，内置有向图环路检测（Cycle Detection）防止自环死锁 |

---

## 3. 支持的加密 DNS 与服务发现协议详解

| 协议 / 标准 | 语法示例 | 核心作用与技术实现 |
| :--- | :--- | :--- |
| **DoH (DNS over HTTPS, [RFC 8484](https://www.rfc-editor.org/info/rfc8484/))** | `https://1.1.1.1/dns-query`, `h3://...` | 基于 HTTPS (HTTP/2 & HTTP/3) 的加密域名解析，支持代理隧道承载、证书 SAN 严格校验与连接池热复用 |
| **DoT (DNS over TLS, [RFC 7858](https://www.rfc-editor.org/info/rfc7858/))** | `tls://8.8.8.8:853` | 基于 TLS 853 端口的 2 字节长度前缀流式加密 DNS 解析，支持 SPKI 固定与会话恢复 |
| **DoQ (DNS over QUIC, [RFC 9250](https://www.rfc-editor.org/info/rfc9250/))** | `quic://dns.adguard-dns.com:853` | 2 字节长度前缀 QUIC 独立流传输（ALPN `doq`），严格执行 [RFC 9250 §4.2.1](https://www.rfc-editor.org/info/rfc9250/) 线格式 Message ID 置 `0x0000`，消除 TCP 队头阻塞（HoL Blocking）与握手延迟 |
| **ODoH (Oblivious DoH, [RFC 9230](https://www.rfc-editor.org/info/rfc9230/))** | `odoh://...` (Relay + Target) | 异源 Oblivious Proxy 与 Oblivious Target 物理分离，结合 [RFC 9180 HPKE](https://www.rfc-editor.org/info/rfc9180/) 从密码学上解耦客户端真实 IP 与查询域名 |
| **SVCB / HTTPS ([RFC 9460](https://www.rfc-editor.org/info/rfc9460/)) & DDR ([RFC 9462](https://www.rfc-editor.org/info/rfc9462/))** | Type `64` (`SVCB`), Type `65` (`HTTPS`) | 单次查询获取目标 HTTP/3 (`h3`)、TLS ECH 公钥参数及 `_dns.resolver.arpa` 指定加密解析器自动发现（DDR） |
| **EDNS(0) 块长度填充 ([RFC 7830](https://www.rfc-editor.org/info/rfc7830/) / [RFC 8467](https://www.rfc-editor.org/info/rfc8467/))** | 自动启用（加密上游） | C++ 原生 `hajimi_dns_apply_edns_padding` 自动注入或扩展 Option Code 12，将查询报文对齐至 **128 字节倍数**、响应对齐至 **468 字节倍数**，抵御包长边信道指纹分析 |
| **ECS 客户端子网脱敏 ([RFC 7871](https://www.rfc-editor.org/info/rfc7871/))** | 自动启用（代理/加密上游） | C++ 原生 `hajimi_dns_sanitize_ecs` 支持剥离 Option Code 8、匿名置 `/0` 或隐私截断（IPv4 $\le /24$、IPv6 $\le /56$），防止客户端子网泄露 |
| **Fake-IP 零延迟映射 ([RFC 3089](https://www.rfc-editor.org/info/rfc3089/))** | `198.18.0.0/15` 地址池 | C++ 零分配解析器 `hajimi_fakeip_parse_question` 与 `hajimi_fakeip_build_reply`，结合 FNV-1a 哈希与 SQLite WAL 持久化映射表，消除代理连接前的远程 DNS 往返延迟 |

---

## 4. 本地入站代理与虚拟网卡（TUN）数据平面

1. **统一端口 / 独立端口 HTTP & SOCKS5 入站服务器（`LocalProxyServer` / `HajimiProtocolCXX`）**：
   - 支持在单一端口上通过首字节自动嗅探区分 **SOCKS5**（`0x05`）与 **HTTP/1.0、HTTP/1.1**（`CONNECT` 及普通方法），也可分别绑定独立监听端口；
   - 支持本地入站恒定时间身份认证（`hajimi_constant_time_memcmp`，防御时序侧信道攻击）；
   - 内置 TLS ClientHello SNI 嗅探与 HTTP Host 嗅探，支持基于域名的二次重路由。
2. **特权 Helper 与 `utun` 虚拟网卡透明接管（`HajimiHelper` / `HajimiNativeCore` / `HajimiDataPlaneC`）**：
   - 通过 `SMJobBless` / XPC 安全通信管理 macOS `utun` 接口、路由表与系统 DNS；
   - 用户态 TCP/IP 协议栈支持 128-bit SWAR 并行校验和、[RFC 7323](https://www.rfc-editor.org/info/rfc7323/) TCP 窗口缩放、[RFC 2018](https://www.rfc-editor.org/info/rfc2018/) 选择性确认（SACK）以及全局 32 MiB 原子配额保护的零拷贝顺次借用与乱序重组器。

---

## 5. 跨学科科研级底层、传输、网速与安全优化

本项目在工程实现中深度融合了计算机网络、应用数学、统计物理、排队论与现代密码学的研究成果：

1. **排队论与拥塞控制（Kleinrock BDP + BBRv3 + Nichols-Jacobson CoDel）**：
   - 采用 Kathleen Nichols 三槽滑动窗口最大带宽滤波器跟踪瓶颈链路交付率 $\widehat{\text{BtlBw}}$ 与最小传播时延 $\widehat{\text{RTprop}}$，动态计算 Kleinrock 最优工作点窗口 $W = g \cdot \widehat{\text{BtlBw}} \cdot \widehat{\text{RTprop}}$；
   - 融合 [BBRv3 (draft-ietf-ccwg-bbr-04)](https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-04) 的 2% 丢包阈值 `inflight_hi` / `inflight_lo`（$\beta = 0.70$）包络约束，以及 [RFC 8289 CoDel](https://www.rfc-editor.org/info/rfc8289/) 驻留队列膨胀检测（当持续 3 轮以上 $r_t > 1.25 \cdot \widehat{\text{RTprop}} + 5\text{ ms}$ 时自动切入 Drain 排空增益调制），兼顾满速吞吐与超低排队延迟。
2. **多臂老虎机与非平稳卡尔曼滤波选路（UCB1 + Innovation-Adaptive Kalman-Welford + Cornish-Fisher + Beta-Binomial）**：
   - **Smart 策略组与自适应 DNS 选路**采用 **新息自适应卡尔曼-韦尔福德递推（Innovation-Adaptive Kalman-Welford Filter）** 在线跟踪指数加权均值 $\hat{\mu}$ 与方差 $\hat{\sigma}^2$：当归一化新息 $z_k = |r_k - \hat{\mu}_{k-1}| / \sigma_{\text{floor}} > 3.0$ 时自动提升卡尔曼增益 $\alpha_k \in [0.25, 0.45]$，以 ~2 倍速度响应网络路由突变；
   - 结合 **Cornish-Fisher 90%/95% 分位尾部延迟估计**、**经验贝叶斯 Beta-Binomial 共轭后验可靠度** $\hat{p} = \frac{S + \alpha_0}{S + F + \alpha_0 + \beta_0}$（带指数遗忘半衰期 $\tau = 300\text{ s}$）、**Mathis-Semke-Mahdavi 宏观吞吐丢包惩罚**（$\propto \hat{p}^{-2}$）以及 **Auer-Cesa-Bianchi UCB1 置信上界探索奖励**，自动规避高抖动/微丢包节点。
3. **数论双射混淆与零移动一致性哈希（Stafford Mix13 + Google Jump Consistent Hash）**：
   - 负载均衡策略组（`load-balance`）采用 David Stafford **SplitMix64 Mix13** $\text{GF}(2^{64})$ 双射雪崩混合器与 Lamping & Veach **Jump Consistent Hash**，在零额外空间开销下保证节点池增删时的最小会话迁移率 $\frac{1}{N}$。
4. **寄存器内并行计算（SWAR）与硬件位指令加速**：
   - **Alan Mycroft 64-bit SWAR 可打印 ASCII 扫描器**：在 `ProtocolCodec.cpp` 中单周期并行校验 8 字节 HTTP 头部字符，解析速率达 **1.80M req/s**；
   - **64-bit / 128-bit SWAR 互联网校验和**：在 `hajimi_dataplane.c` 与 `WireGuardProtocol.cpp` 中以 64B/16B 展开循环并行折叠校验和；
   - **BMI2 `_pext_u64` / CLZ 硬件位聚集**：加速 Mieru 低熵模式（Low-Entropy Mode）比特提取。
5. **零拷贝流管线与密码学前向安全（Zero-Copy Slice AEAD & Memory Hygiene）**：
   - `OrderedWriter::flush()` 实现 $O(1)$ `std::move` 零拷贝写派发；`crypto::sealSlice` / `openSlice` 消除 VMess、Shadowsocks、Mieru、WireGuard 与 Vision 的分片临时缓冲区拷贝，单核 `XChaCha20-Poly1305` 吞吐量达 **2.54 GiB/s**，`Reader` 内存流吞吐量达 **124.3 GiB/s**；
   - 对 WireGuard `Noise_IKpsk2` 临时私钥、会话密钥、`HChaCha20` 派生子密钥及 Snell `Argon2id` 8 KiB 内存矩阵实施严格的 `OPENSSL_cleanse` 即时清零，保障进程内存前向安全（PFS）。

---

## 6. 源码模块拓扑与目录结构

```text
├── Package.swift                        # SwiftPM 包定义（macOS 13.0+，19 个 Target 模块）
├── Makefile                             # 全流程构建、通用二进制合并、冒烟测试、DMG 打包与签名公证脚本
├── 项目架构与维护文档.md                   # 完整架构演进、根因取证与科研级优化维护档案（Sections 1–32）
├── Sources/
│   ├── HajimiDataPlaneC/                # C11 高吞吐 TUN 数据平面（128-bit SWAR 校验和、MSS 钳制、WS 掩码）
│   ├── HajimiFlowCXX/                   # C++17 32MiB 有界队列、TCP 乱序重组、RACK-TLP、BBRv3+CoDel BDP 估计器
│   ├── HajimiRoutingCXX/                # C++17 紧凑双生基数树 (IPv4/IPv6 CIDR) 与逆向标签域名后缀树
│   ├── HajimiProtocolCXX/               # C++17 零分配协议编解码器、DoQ/EDNS0/MASQUE 编解码与自适应选路算子
│   ├── HajimiProtocolsCXX/              # C++17 全协议异步流/数据报运行时（VLESS/VMess/Trojan/SS/Snell/Mieru/WG/QUIC 等）
│   ├── HajimiCXXProtocolBridge/         # Objective-C++ 桥接层（连接 Network.framework / OpenSSL 与 C++ 协议栈）
│   ├── HajimiProxyRuntime/              # Objective-C++ 底层网络流与 TLS/REALITY 运行时
│   ├── HajimiCore/                      # Swift 核心模型、配置解析器、策略组健康监控、mKCP 与 NativeMux
│   ├── HajimiDNS/                       # Swift 加密 DNS 引擎（DoH/DoT/DoQ/ODoH/DDR/SVCB/ECS/Padding/UCB1）
│   ├── HajimiRouting/                   # Swift 路由规则编译器与 GeoIP/GeoSite/RuleSet 引擎
│   ├── HajimiNativeCore/                # Swift 本地代理服务器、TUN 协议栈控制器与连接诊断引擎
│   ├── HajimiRuntime/                   # Swift 运行时协调器、系统代理管理与 XPC 客户端
│   ├── HajimiHelper/                    # macOS 特权 Helper 守护进程（utun 接口、路由表与 DNS 配置）
│   ├── HajimiIPC/                       # 主程序与 Helper 之间的 XPC 通信协议定义
│   ├── HajimiMacOSObjC/                 # macOS 系统级 Objective-C 桥接组件
│   ├── HajimiUIComponents/              # SwiftUI 共享原生视觉组件
│   ├── HajimiDiagnosticsUI/             # 实时流量图表、连接瀑布流与建连诊断工作台 UI
│   └── HajimiApp/                       # macOS 主应用入口、菜单栏控制器、策略看板与配置编辑器
├── SmokeTests/                          # C++17 / Swift 独立冒烟与性能基准测试套件
├── Tests/                               # XCTest 单元与集成测试套件
├── NetworkExtension/                    # NEPacketTunnelProvider 系统扩展集成脚手架与说明文档
└── Vendor/HajimiQUIC/                   # 预编译 Universal2 静态库说明（OpenSSL 3.6 + ngtcp2 + nghttp3 + libssh2）
```

---

## 7. 构建、测试与打包指南

- **环境要求**：macOS 13.0 (Ventura) 或更高版本，Xcode 16+ / Swift 6.0+ 工具链。
- **常用命令**：
  ```bash
  make build                     # 构建当前架构 Release 二进制
  make test                      # 运行全套 C/C++ 协议、路由、流控、加密 DNS 与 Swift 冒烟自检
  make reader-performance-check  # 运行 C++ 零拷贝 Reader 性能基准
  make protocol-codec-check      # 运行 C++ 协议编解码与算子自检（121,342 项检查）
  make dmg                       # 构建 arm64 + x86_64 通用二进制并打包 macOS .app 与 .dmg 镜像
  ```

---

## 8. 致谢：开源协议作者、科研学者与 IETF 标准

本项目在 C++ 原生协议栈实现、加密 DNS 重构、数据平面加速与自适应调度算法研发过程中，深度参考并受益于以下优秀的开源协议规范、网络与安全顶会（ACM SIGCOMM、ACM IMC、NDSS、USENIX Security、PETS、WWW、PAM）学术论文及 IETF RFC 标准，特此向相关开源作者与科研学者致以诚挚感谢：

### 1. 代理协议规范与开源项目作者

- **Xray-core (VLESS / XTLS-Vision / REALITY / XHTTP / mKCP)** — 感谢 [@XTLS](https://github.com/XTLS) 与 RPRX 团队
  - 开源仓库：[https://github.com/XTLS/Xray-core](https://github.com/XTLS/Xray-core)
  - REALITY 协议：[https://github.com/XTLS/REALITY](https://github.com/XTLS/REALITY)
- **V2Ray / v2fly-core (VMess / Mux.Cool)** — 感谢 [@v2fly](https://github.com/v2fly) 社区与 Project V 作者
  - 开源仓库：[https://github.com/v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- **Hysteria (Hysteria v1 / v2)** — 感谢 [@apernet](https://github.com/apernet) (Aperture Internet Laboratory)
  - 开源仓库：[https://github.com/apernet/hysteria](https://github.com/apernet/hysteria)
- **TUIC (TUIC v5)** — 感谢 [@EAimTY](https://github.com/EAimTY) 与 [@tuic-protocol](https://github.com/tuic-protocol)
  - 开源仓库：[https://github.com/tuic-protocol/tuic](https://github.com/tuic-protocol/tuic) · [https://github.com/EAimTY/tuic](https://github.com/EAimTY/tuic)
- **AnyTLS (AnyTLS / sing-anytls)** — 感谢 [@anytls](https://github.com/anytls) 作者
  - 开源仓库：[https://github.com/anytls/anytls-go](https://github.com/anytls/anytls-go) · [https://github.com/anytls/sing-anytls](https://github.com/anytls/sing-anytls)
- **Mieru / 見える (Mieru v3)** — 感谢 [@enfein](https://github.com/enfein)
  - 开源仓库：[https://github.com/enfein/mieru](https://github.com/enfein/mieru)
- **Sudoku Protocol (数独协议)** — 感谢 [@SUDOKU-ASCII](https://github.com/SUDOKU-ASCII)
  - 开源仓库：[https://github.com/SUDOKU-ASCII/sudoku](https://github.com/SUDOKU-ASCII/sudoku)
- **TrustTunnel** — 感谢 [@TrustTunnel](https://github.com/TrustTunnel) (AdGuard VPN 开源团队)
  - 开源仓库：[https://github.com/TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) · [https://github.com/TrustTunnel/TrustTunnelClient](https://github.com/TrustTunnel/TrustTunnelClient)
- **Shadowsocks & Shadowsocks-2022 (SIP022)** — 感谢 [@clowwindy](https://github.com/clowwindy)、[@shadowsocks](https://github.com/shadowsocks) 社区与 SIP022 规范作者
  - 开源仓库：[https://github.com/shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) · [https://github.com/shadowsocks/shadowsocks-org](https://github.com/shadowsocks/shadowsocks-org)
- **Trojan** — 感谢 [@trojan-gfw](https://github.com/trojan-gfw)
  - 开源仓库：[https://github.com/trojan-gfw/trojan](https://github.com/trojan-gfw/trojan)
- **Snell** — 感谢 [@surge-networks](https://github.com/surge-networks)
  - 开源仓库：[https://github.com/surge-networks/snell](https://github.com/surge-networks/snell)
- **WireGuard** — 感谢 **Jason A. Donenfeld** ([@zx2c4](https://github.com/zx2c4))
  - 协议白皮书：[https://www.wireguard.com/papers/wireguard.pdf](https://www.wireguard.com/papers/wireguard.pdf)
- **KCP (A Fast and Reliable ARQ Protocol)** — 感谢 [@skywind3000](https://github.com/skywind3000) (韦易笑)
  - 开源仓库：[https://github.com/skywind3000/kcp](https://github.com/skywind3000/kcp)
- **Mihomo (Clash.Meta) 订阅格式参考** — 感谢 [@MetaCubeX](https://github.com/MetaCubeX)
  - 开源仓库：[https://github.com/MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)

### 2. 前沿学术论文与 IETF RFC 标准致谢

- **DNS over Dedicated QUIC Connections (DoQ) 性能与韧性研究**
  - **学术论文**：*One to Rule Them All? A First Look at DNS over QUIC* — 感谢作者 **Mike Kosek, Trinh Viet Doan, Malte Granderath, Vaibhav Bajpai** (*ACM IMC 2022*)
    - 论文链接：[https://arxiv.org/abs/2305.00790](https://arxiv.org/abs/2305.00790)
  - **学术论文**：*Evaluating DNS Resiliency with Truncation, Fragmentation, DoQ and DoH3* — 感谢作者 **Vaibhav Bajpai** 等 (*PAM 2026*)
    - 论文链接：[https://vaibhavbajpai.com/documents/papers/proceedings/2026-pam-doq-doh3.pdf](https://vaibhavbajpai.com/documents/papers/proceedings/2026-pam-doq-doh3.pdf)
  - **IETF 标准**：*RFC 9250: DNS over Dedicated QUIC Connections* (**Christian Huitema, Sara Dickinson, Allison Mankin**) — [https://www.rfc-editor.org/info/rfc9250/](https://www.rfc-editor.org/info/rfc9250/)
- **Oblivious DNS (ODoH / ODoQ) 无感知隐私解耦架构**
  - **学术论文**：*Oblivious DNS over HTTPS (ODoH): A Practical Privacy Enhancement to DNS* — 感谢作者 **Sudheesh Singanamalla, Suphanat Chunhapanya, Marek Vavruša, Tanya Verma, Peter Wu, Marwan Fayed, Kurtis Heimerl, Nick Sullivan, Christopher Wood** (*PoPETS / PETS 2021*)
    - 论文链接：[https://petsymposium.org/2021/files/papers/issue4/popets-2021-0085.pdf](https://petsymposium.org/2021/files/papers/issue4/popets-2021-0085.pdf)
  - **学术论文**：*Oblivious DNS-over-QUIC (ODoQ)* (*2025*)
    - 论文链接：[https://arxiv.org/abs/2509.11123](https://arxiv.org/abs/2509.11123)
  - **IETF 标准**：*RFC 9230: Oblivious DNS over HTTPS* (**Eric Kinnear, Patrick McManus, Tommy Pauly, Tanya Verma, Christopher A. Wood**) — [https://www.rfc-editor.org/info/rfc9230/](https://www.rfc-editor.org/info/rfc9230/)
- **抗加密 DNS 边信道流量指纹分析与 EDNS(0) 块填充策略**
  - **学术论文**：*Encrypted DNS -> Privacy? A Traffic Analysis Perspective* — 感谢作者 **Sandra Siby, Marc Juarez, Claudia Diaz, Narseo Vallina-Rodriguez, Carmela Troncoso** (*NDSS 2020*)
    - 论文链接：[https://arxiv.org/abs/1906.09682](https://arxiv.org/abs/1906.09682)
  - **学术论文**：*Padding Ain't Enough: Assessing the Privacy Guarantees of Encrypted DNS* — 感谢作者 **Jonas Bushart, Christian Rossow** (*USENIX FOCI 2020*)
    - 论文链接：[https://www.usenix.org/conference/foci20/presentation/bushart](https://www.usenix.org/conference/foci20/presentation/bushart)
  - **IETF 标准**：*RFC 7830: The EDNS(0) Padding Option* & *RFC 8467: Padding Policies for Extension Mechanisms for DNS (EDNS(0))* (**Alexander Mayrhofer**) — [https://www.rfc-editor.org/info/rfc7830/](https://www.rfc-editor.org/info/rfc7830/) · [https://www.rfc-editor.org/info/rfc8467/](https://www.rfc-editor.org/info/rfc8467/)
- **UCB1 多臂老虎机自适应调度、加密 DNS 性能测量与 Happy Eyeballs 竞速**
  - **学术论文**：*Finite-time Analysis of the Multiarmed Bandit Problem (UCB1)* — 感谢作者 **Peter Auer, Nicolò Cesa-Bianchi, Paul Fischer** (*Machine Learning, 2002*)
    - 论文链接：[https://homes.di.unimi.it/~cesabian/Pubblicazioni/ml-02.pdf](https://homes.di.unimi.it/~cesabian/Pubblicazioni/ml-02.pdf)
  - **学术论文**：*Comparing the Effects of DNS, DoT, and DoH on Web Performance* — 感谢作者 **Austin Hounsel, Kevin Borgolte, Paul Schmitt, Jordan Holland, Nick Feamster** (*WWW 2020*)
    - 论文链接：[https://arxiv.org/abs/1907.08089](https://arxiv.org/abs/1907.08089)
  - **IETF 标准**：*RFC 8305: Happy Eyeballs Version 2* (**David Schinazi, Tommy Pauly**) & *Happy Eyeballs Version 3 Draft* — [https://www.rfc-editor.org/info/rfc8305/](https://www.rfc-editor.org/info/rfc8305/) · [https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-03.html](https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-03.html)
- **指定解析器自动发现 (DDR)、SVCB/HTTPS 服务绑定与 EDE 扩展错误诊断**
  - **学术论文**：*Discovering the Discovery of Designated Resolvers (DDR)* — 感谢作者 **Yevheniya Nosyk, Maciej Korczyński, Andrzej Duda** (*PETS 2025 / RIPE Labs*)
    - 论文链接：[https://labs.ripe.net/author/yevheniya-nosyk/discovering-the-discovery-of-designated-resolvers/](https://labs.ripe.net/author/yevheniya-nosyk/discovering-the-discovery-of-designated-resolvers/)
  - **学术论文**：*Extended DNS Errors: Unlocking the Full Potential of DNS Troubleshooting* — 感谢作者 **Yevheniya Nosyk** 等 (*ACM IMC 2023 / RIPE Labs*)
    - 论文链接：[https://labs.ripe.net/author/yevheniya-nosyk/extended-dns-errors-unlocking-the-full-potential-of-dns-troubleshooting/](https://labs.ripe.net/author/yevheniya-nosyk/extended-dns-errors-unlocking-the-full-potential-of-dns-troubleshooting/)
  - **IETF 标准**：*RFC 9460 (SVCB/HTTPS)* · *RFC 9462 (DDR)* · *RFC 8914 (Extended DNS Errors)* — [https://www.rfc-editor.org/info/rfc9460/](https://www.rfc-editor.org/info/rfc9460/) · [https://www.rfc-editor.org/info/rfc9462/](https://www.rfc-editor.org/info/rfc9462/) · [https://www.rfc-editor.org/info/rfc8914/](https://www.rfc-editor.org/info/rfc8914/)
- **ECS 客户端子网隐私保护、Serve-Stale 容灾缓存与 Optimistic DNS**
  - **学术研究**：*Privacy and DNS Client Subnet* — 感谢作者 **Geoff Huston** (*APNIC Research, 2024*)
    - 研究链接：[https://blog.apnic.net/2024/07/23/privacy-and-dns-client-subnet/](https://blog.apnic.net/2024/07/23/privacy-and-dns-client-subnet/)
  - **IETF 标准与草案**：*RFC 7871 (Client Subnet in DNS Queries)* · *RFC 8767 (Serving Stale Data to Improve DNS Resiliency)* · *RFC 9520 (Negative Caching of DNS Resolution Failures)* · *Optimistic DNS Draft* — [https://www.rfc-editor.org/info/rfc7871/](https://www.rfc-editor.org/info/rfc7871/) · [https://www.rfc-editor.org/info/rfc8767/](https://www.rfc-editor.org/info/rfc8767/) · [https://www.rfc-editor.org/info/rfc9520/](https://www.rfc-editor.org/info/rfc9520/) · [https://www.ietf.org/archive/id/draft-gakiwate-dnsop-optimistic-dns-00.html](https://www.ietf.org/archive/id/draft-gakiwate-dnsop-optimistic-dns-00.html)
- **排队论拥塞控制 (BBRv3 / CoDel / RACK-TLP)、一致性哈希与统计滤波研究**
  - **拥塞控制与驻留延迟控制**：感谢 **Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh, Van Jacobson, Kathleen Nichols, Leonard Kleinrock** 等学者提出的 *BBRv3* ([draft-ietf-ccwg-bbr-04](https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-04))、*CoDel (Controlled Delay)* ([RFC 8289](https://www.rfc-editor.org/info/rfc8289/)) 与 *RACK-TLP* ([RFC 8985](https://www.rfc-editor.org/info/rfc8985/))
  - **宏观 TCP 吞吐量模型与在线方差递推**：感谢 **Matthew Mathis, Jeffrey Semke, Jamshid Mahdavi** (*ACM SIGCOMM CCR, 1997*) 与 **B. P. Welford / D. H. D. West** (*Communications of the ACM, 1979*)
  - **零移动一致性哈希**：*A Fast, Minimal Memory, Consistent Hash Algorithm (Jump Consistent Hash)* — 感谢作者 **John Lamping, Eric Veach** ([https://arxiv.org/abs/1406.2294](https://arxiv.org/abs/1406.2294))

### 3. 底层密码学与 QUIC / SSH 开源库

- **OpenSSL (TLS 1.3 & QUIC Crypto 原语)** — [https://github.com/openssl/openssl](https://github.com/openssl/openssl)
- **ngtcp2 (IETF QUIC 协议栈)** — [https://github.com/ngtcp2/ngtcp2](https://github.com/ngtcp2/ngtcp2)
- **nghttp3 (HTTP/3 & QPACK 协议栈)** — [https://github.com/ngtcp2/nghttp3](https://github.com/ngtcp2/nghttp3)
- **libssh2 (SSH2 客户端协议库)** — [https://github.com/libssh2/libssh2](https://github.com/libssh2/libssh2)
- **BLAKE3 (密码学哈希算法)** — [https://github.com/BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
