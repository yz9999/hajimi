# 哈基米 (Hajimi) for macOS

## 项目简介

**哈基米 (Hajimi)** 是一款面向 **macOS 13+**（支持 Intel `x86_64` 与 Apple Silicon `arm64`）的原生网络代理与规则分流客户端。

本项目由AI编写，自行优化、修改和完善，仅供学习交流使用。

- **原生 C/C++17 协议与数据平面**：核心代理协议栈、AEAD/TLS 加解密、QUIC 传输、零拷贝域名后缀 Trie / CIDR 路由匹配以及用户态 TCP/UDP 报文处理均采用 C11 / C++17 / Objective-C++ / Swift 原生编写，无外部 Go 运行时依赖。
- **全场景流量接管**：支持本地 HTTP / SOCKS5 代理监听、macOS 系统代理与增强模式（`utun` 虚拟网卡 + Fake-IP）。
- **学术级防泄漏加密 DNS 架构**：内置 DoH（DNS over HTTPS）、DoT（DNS over TLS）、DoQ（DNS over QUIC）与 ODoH（Oblivious DoH）自适应解析器，融合 RFC 8467 抗边信道流量指纹填充、RFC 7871 ECS 客户端子网隐私净化、RFC 8767 Serve-Stale 容灾缓存以及 UCB1 多臂老虎机 + Happy Eyeballs 尾延迟感知对冲调度。
- **多格式配置与订阅兼容**：原生支持 Surge 风格 `.conf` 配置、Clash YAML 订阅与 Base64 节点分享链接导入。

## 支持的协议

### 1. 出站代理协议

| 类别 | 协议名称 | TCP | UDP | 核心特性与传输支持 |
| --- | --- | :---: | :---: | --- |
| **现代代理协议** | **VLESS** | ✓ | ✓ | 支持 `XTLS-Vision` (`xtls-rprx-vision`)、REALITY、TLS、WS、gRPC、XHTTP、mKCP、XUDP |
| | **VMess** | ✓ | ✓ | 支持 AEAD 认证加密（AES-128-GCM / ChaCha20-Poly1305）、0-RTT 首包合并、TLS、WS、gRPC、XHTTP、mKCP |
| | **Trojan** | ✓ | ✓ | 标准 TLS 承载、WebSocket / gRPC 传输与 UDP 转发 |
| | **AnyTLS** | ✓ | ✓ | TLS 逻辑流会话复用、动态 Padding 混淆消除 TLS-in-TLS 指纹、UoT v2 (UDP over TCP) |
| **QUIC 代理协议** | **Hysteria v2 / v1** | ✓ | ✓ | 基于 `ngtcp2` 原生 QUIC + HTTP/3、Salamander / XPlus 混淆与原生 UDP Datagram |
| | **TUIC v5** | ✓ | ✓ | 基于 `ngtcp2` 0-RTT QUIC 多路复用、TLS Exporter 认证、Native Datagram / QUIC Stream UDP |
| **抗审查与混淆协议** | **Mieru (見える) v3** | ✓ | ✓ | PBKDF2 时间桶密钥派生 + XChaCha20-Poly1305 加密，支持 TCP 与 UDP 双底层传输 |
| | **Sudoku (数独协议)** | ✓ | ✓ | 4×4 数独 O(1) 谜题编码混淆（ASCII / Entropy 模式）、KIP 控制协议与 UoT |
| | **TrustTunnel** | ✓ | ✓ | 伪装标准 HTTPS (HTTP/1.1 TLS) 与 HTTP/3 QUIC 的全流量 VPN 隧道协议 |
| **经典与通用协议** | **Shadowsocks (SS)** | ✓ | ✓ | 支持 AEAD（AES-128/256-GCM、ChaCha20-IETF-Poly1305） |
| | **Shadowsocks 2022** | ✓ | ✓ | 支持 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305` 与 EIH |
| | **ShadowsocksR (SSR)** | ✓ | ✓ | 兼容经典流密码与 `origin` / `plain` 协议混淆 |
| | **Snell (v1–v4)** | ✓ | ✓ | 轻量级加密代理协议（支持 v1–v4 会话与 UDP 转发） |
| | **HTTP / HTTPS** | ✓ | — | 标准 HTTP CONNECT 隧道与 Basic 鉴权 |
| | **SOCKS5 / SOCKS5-TLS** | ✓ | ✓ | 标准 SOCKS5（含 `UDP ASSOCIATE`）与 TLS 加密 SOCKS5 |
| | **SSH** | ✓ | — | 基于 `libssh2` 的 SSH 隧道转发，支持密码、私钥与 Host-Key 指纹校验 |

### 2. 加密 DNS 与隐私保护协议

| 协议 / 标准 | 核心作用 |
| --- | --- |
| **DoH (DNS over HTTPS)** | 基于 HTTPS 的加密域名解析，支持代理隧道承载、证书 SAN 严格校验与连接池热复用 |
| **DoT (DNS over TLS)** | 基于 TLS 853 端口的流式加密 DNS 解析 |
| **DoQ (DNS over QUIC, RFC 9250)** | 2 字节长度前缀 QUIC 独立流传输，消除 TCP 队头阻塞（HoL Blocking）与握手延迟 |
| **ODoH (Oblivious DoH, RFC 9230)** | 异源 Oblivious Proxy 与 Oblivious Target 物理分离，从密码学上解耦客户端真实 IP 与查询域名 |
| **SVCB / HTTPS (RFC 9460) & DDR (RFC 9462)** | 单次查询获取目标 HTTP/3 (`h3`)、TLS ECH 公钥参数及 `_dns.resolver.arpa` 指定加密解析器自动发现 |

## 致谢：开源协议作者、科研学者与 IETF 标准

本项目在 C++ 原生协议栈实现、加密 DNS 重构与自适应调度算法研发过程中，深度参考并受益于以下优秀的开源协议规范、网络与安全顶会（ACM IMC、NDSS、USENIX Security、PETS、WWW、PAM）学术论文及 IETF RFC 标准，特此向相关开源作者与科研学者致以诚挚感谢：

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

### 3. 底层密码学与 QUIC / SSH 开源库

- **OpenSSL (TLS 1.3 & QUIC Crypto 原语)** — [https://github.com/openssl/openssl](https://github.com/openssl/openssl)
- **ngtcp2 (IETF QUIC 协议栈)** — [https://github.com/ngtcp2/ngtcp2](https://github.com/ngtcp2/ngtcp2)
- **nghttp3 (HTTP/3 & QPACK 协议栈)** — [https://github.com/ngtcp2/nghttp3](https://github.com/ngtcp2/nghttp3)
- **libssh2 (SSH2 客户端协议库)** — [https://github.com/libssh2/libssh2](https://github.com/libssh2/libssh2)
- **BLAKE3 (密码学哈希算法)** — [https://github.com/BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
