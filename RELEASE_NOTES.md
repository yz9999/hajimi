# 哈基米 (Hajimi) 版本更新说明

## v0.1.0-Build73

### 核心问题修复（QUIC / Hysteria / Hysteria2 / TUIC / Snell）
- **修复 QUIC 协议族（`hy1` / `hy2` / `tuic`）TLS 1.3 握手兼容性问题**：
  - 将默认 TLS 密钥交换组恢复为标准单包 `Initial` 经典曲线组 `X25519:P-256:P-384`，解决 OpenSSL 3.5+ 默认仅携带 `X25519MLKEM768` 导致未开启后量子混合组的 `quic-go` / `sing-quic` / `aioquic` 服务端握手失败及双包 `Initial` 分片被丢弃的问题；显式配置 `pqc=true` 时采用 `*X25519MLKEM768:*X25519:P-256:P-384` 同时携带混合与经典双 `key_share`。
  - 默认采用 RFC 9000 `QUIC v1` 稳定协商，将 `grease-quic-bit` 与出站 `IP_TOS` / `IPV6_TCLASS` ECN 标记改为显式按需启用（保留入站 `recvmsg` ECN 拥塞反馈），并禁用握手完成前的 Brutal 速率限流。
- **修复 QUIC 连接池（`PooledQUICSession`）复用自死锁与生命周期问题**：
  - 修复 `PooledQUICSession::ensureAuthenticated()` 在连接已就绪（`ready_ == true`）时持有非递归互斥锁同步触发回调导致串行传输队列永久死锁、后续并发流/UDP 请求卡在 `transportStarted` 的问题。
  - 严格对齐 RFC 9114 §6.2.1，确保 `Hysteria2` 在同一事件轮次内按序先建立 HTTP/3 控制流与 QPACK 单向流（`0x00` / `0x02` / `0x03`）再发起 `/auth` 双向认证流（0 额外 RTT）。
  - 优化连接池弱引用持有、认证失败自动剔除、仅对陈旧复用连接触发单次重拨，以及进程退出时先于 `OPENSSL_cleanup` 安全停止 QUIC 后台线程。
- **恢复并强化 Snell v4–v6 多模式帧兼容自动回退与首包重放**：
  - 在零分配 AEAD 路径上完整支持 `Standard`（23B 随机填充）、`StandardZeroPad`（23B 零填充）、`Compat16Std32`（Mihomo/Clash 18B 帧头 + 32B Argon2id 派生截断）、`Compat16RFC`（18B 帧头 + 16B 派生）与 `Compat16Pool7` 五种服务端实现自动探测回退。
  - 支持延迟握手场景下首包回复前的并发载荷（如 DoH `TLS ClientHello`）无损合并重拨重放，并按节点维度缓存已验证模式，后续连接直接 `1-RTT` 零重试连通。

### 标准协议栈与传输性能优化（承接 Build 71–72 更新）
- **QUIC / Hysteria2 / TUIC 传输层**：Mac 原生 `kqueue` 微秒级定时器与发送节奏控制、自适应 16 MB 流/连接接收窗口、RFC 8899 DPLPMTUD 路径 MTU 探测、TLS Session Ticket 会话恢复、Hysteria2 TCP 请求头与首包 0-RTT 合并发送。
- **用户态数据平面（`utun`）与 TCP/HTTP2/WebSocket 载体**：用户态 TCP 栈补齐 RFC 8985 RACK-TLP 尾丢包探测、SACK 乱序重组与 IPv4/IPv6 MSS 钳制；HTTP/2 升级 16 MB BDP 动态流控窗口与编译期 Huffman DFA 解码；WebSocket 升级 `os_unfair_lock` 低开销帧掩码管线。
- **加密与多协议内核**：AEAD（AES-GCM / ChaCha20-Poly1305）零分配栈上 `EVP_CIPHER_CTX` 加密解密；WireGuard 升级 RFC 6479 2048 位防重放滑动窗口与零拷贝会话发送；VMess / Shadowsocks / Trojan / VLESS Vision 头部合并与热路径零拷贝优化。
