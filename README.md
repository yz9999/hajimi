# 哈基米 (Hajimi) for macOS

哈基米是 macOS 13+ 的本地代理应用。HTTP/HTTPS、SOCKS5/SOCKS5-TLS、Shadowsocks（含 2022）、VMess、VLESS、Trojan、AnyTLS、Hysteria v1/v2、TUIC v5 的实际协议内核统一使用 C++17，包括认证、加解密、流/会话与 UDP 封装；不再链接 Go 协议库或 Go 运行时。Swift 负责界面、配置、路由与应用调度，Objective-C/Objective-C++ 负责系统网络 I/O 与桥接，C 负责 IP 报文处理。
## 当前架构与边界

| 部分 | 实际实现 |
|---|---|
| 界面、配置、监听与路由调度 | Swift + AppKit；Objective-C Dashboard 统计绘制 |
| 平台 TCP/TLS/UDP I/O | Objective-C++，Network.framework C API，默认验证 TLS |
| HTTP(S)、SOCKS5(-TLS)、SS/SS2022、VMess、VLESS/Vision、Trojan | C++17 实际握手、认证、加解密、TCP/UDP 封装与有界会话 |
| 双向转发、背压、半关闭、超时与流量统计合并 | Objective-C++；每方向最多一个在途读或写，默认 64 KiB 分块 |
| IP/TCP/UDP 报文解析、校验和、封包 | C，无托管 GC |
| TCP 上传队列、乱序重组、序号运算、重传计时 | C++17；队列/乱序副本共享 32 MiB 原生载荷预算，惰性分配 |
| HTTP 请求解析/重写、SOCKS5 数据报解析、VLESS/Trojan 请求头 | 无堆分配的 C++17 编解码器，经 C ABI 接入实际路径 |
| ASCII 域名精确/后缀/关键词匹配 | C++17，无堆分配；不适用时回退 Swift |
| AnyTLS | C++17：TLS 上的逻辑流、会话复用、padding/SYNACK/heartbeat 与 UoT v2 |
| Hysteria v1/v2、TUIC v5 | C++17：ngtcp2 QUIC reactor、HTTP/3/QPACK、TLS exporter、流/数据报、重组与 obfs |
| 可选 WS/gRPC/XHTTP/mKCP、Mux/XUDP、REALITY TLS 载体 | 保留 Swift 实现，通过只传递不透明字节的桥接供 C++ 协议内核使用 |
| 增强模式 | 独立 root Helper 建立 utun 与路由，再把设备描述符交给 App |
| Network Extension | Objective-C 管理器与 Provider 适配层；尚缺完整独立 Packet Engine 和 Apple 授权签名，不能接管真实流量 |

实际出口统一进入 `Sources/HajimiProtocolsCXX`，而非仅把请求头编解码器改为 C++。OpenSSL 提供 C 加密原语，ngtcp2/nghttp3/libssh2 为本地静态 C 依赖；Objective-C++ 桥接负责配置解码、对象生命周期与平台 I/O，不实现代理协议。旧 Swift 协议/QUIC 实验代码及 Go 参考目录保留作历史参考，不承担这些协议的实际出口；可选载体和部分 utun 调度仍为 Swift，因此不应把整个应用描述为“全部 C++”。

当前 QUIC 每个 TCP/UDP 会话使用独立连接，尚未跨请求复用，也不复刻 Brutal 带宽控制。端口跳跃、0-RTT、ECH、BBR profile、证书指纹 pinning 与 QUIC 代理链明确拒绝；详见 [QUIC 实现边界](Vendor/HajimiQUIC/README.md)。

32 MiB 预算只覆盖 C++ 队列容量与乱序载荷副本（含扩容时旧/新缓冲的瞬时峰值），不包括 Swift 下载/重传缓冲、协议库、系统网络栈、分配器元数据或进程 RSS。No GC 不等于零分配，也不能单凭语言选择推断低延迟、吞吐或内存优势。性能烟雾测试输出回环吞吐、32 KiB echo RTT 的 p50/p99 与进程 RSS 样本，不能替代真实节点基准或最低性能保证。

Network Extension 编译与签名边界见 [集成说明](NetworkExtension/INTEGRATION.md)。设置中的“检查接入条件”仅读取本应用签名与内嵌 Provider 信息，不保存 VPN 配置或修改网络；没有完整 Packet Engine 的 Provider 会在安装网络设置前明确失败。当前可用增强模式仍为 Helper + utun。

## 出站协议

| 协议 | TCP | UDP | 已知范围 |
|---|:---:|:---:|---|
| HTTP / HTTPS | ✓ | — | 上游 CONNECT / HTTP 转发，Basic 认证；HTTPS 校验证书 |
| SOCKS5 / SOCKS5-TLS | ✓ | ✓ / — | 本地 SOCKS 入口可通过明文 SOCKS5 UDP ASSOCIATE；SOCKS5-TLS 不降级为明文 UDP |
| Shadowsocks AEAD | ✓ | ✓ | AES-GCM、ChaCha20-Poly1305；不含 plugin/obfs |
| Shadowsocks 2022 | ✓ | ✓* | AES/ChaCha20，AES 支持 EIH |
| VMess | ✓ | ✓ | 仅 AEAD，alter-id=0 |
| VLESS | ✓ | ✓ | encryption=none；Vision 要求 TCP + REALITY |
| Trojan | ✓ | ✓ | 默认 TLS |
| AnyTLS | ✓ | ✓ | C++ 会话复用；UDP 为 UoT v2 |
| Hysteria v1 / v2 | ✓ | ✓ | C++/ngtcp2；XPlus / Salamander；不支持端口跳跃 |
| TUIC v5 | ✓ | ✓ | C++/ngtcp2；UDP 支持 native DATAGRAM 与 quic 单向流 |

* Shadowsocks 2022 的 UDP 必须显式设置 udp=true。HTTP(S)、SOCKS5(-TLS) 上游没有 TUN UDP 出站；选中 SOCKS5-TLS 时也不会退回明文 UDP 握手。本地 SOCKS5 入口与上游出站是不同功能。

额外保留 C++ SSR（AES-CFB、origin/plain）、Snell v1–v4 与 SSH 出站。Snell v5/obfs 尚未实现，明确拒绝；SSH 必须配置 host-key pin 或明确设置 skip-cert-verify=true，后者会失去服务端身份保护。未配置 pin 不再默认接受任意 SSH 服务端。

DNS/53 默认沿用参考实现的直连兼容行为，可能产生明文 DNS；建议显式配置 DoH/DoT。显式 `REJECT` 优先于 DNS 兼容、fake-IP、DoH/DoT：TCP、原生 UDP 和本地 SOCKS5 UDP 都不会把拒绝结果改成直连或解析应答。若当前策略选中 HTTPS 或 SOCKS5-TLS，哈基米会阻止 UDP/53 明文直连：增强模式可使用配置的 DoH/DoT 或 fake-IP 合成应答，否则拒绝该数据报；本地 SOCKS5 UDP 入口同样拒绝。TCP DNS 可以通过相应的 TLS 上游传输。

控制接口重载会撤销并关闭已接收的连接，每代连接使用独立的密钥快照；默认最多 64 个控制客户端，包含旧代已取消但仍待清理的连接，整个请求/应答有 15 秒绝对期限。已经通过入口检查的后端操作仍可能完成，重载不是事务回滚。HTTP/SOCKS 代理入口默认最多 512 个连接，HTTP 握手有 15 秒绝对期限，慢速发送不会续期。QUIC 收包 mailbox 最多 512 报文/2 MiB，并合并回调、分批处理；只有解析出的回环地址跳过物理网卡绑定。

本地 SOCKS UDP 单独限制资源：每个 association 最多 32 个客户端端点、256 个 DIRECT 流及各 32 个策略 relay，进程共享最多 1,024 个逻辑资源名额，原生 relay 的目标也计入该名额。无效首包、失败和取消会回收资源，空闲期限为 120 秒、每 30 秒检查；不同客户端的流和回包彼此隔离。DIRECT/回包发送为单在途、每队列最多 64 包/256 KiB，共享最多 8,192 包/8 MiB（含在途发送），资源满时拒绝新增，发送队列超限时关闭受影响的流；C++ 会话还有各自独立的 512 包/2 MiB 发送限制。这些预算不等于全进程内存或操作系统 socket 数量的精确上限。

classic Shadowsocks AEAD 叠加进程共享的有界 salt 重放缓存，TCP/UDP、算法和密钥域隔离，缓存不保留明文密码/PSK。TCP 保留最新 32,768 项、最长 10 分钟，UDP 保留最新 65,536 项、最长 5 分钟，并继续保留会话内防重放；容量/时间窗口之外或进程重启之后不提供永久重放保证。SS2022 的时间戳和请求回显验证保持独立。SSH 的 UI 配置验证不读私钥文件，实际异步拨号前拒绝非普通文件并限制读取大小。

Helper 的重载/停止在串行变更内部校验已认证的本地 UID/PID 与会话 owner，只有已认证 root、daemon 自身清理或 orphan 恢复可跨 owner。系统代理恢复会在管理员授权后逐组件重新核对现场，避免覆盖授权弹窗期间的外部更改；`networksetup` 的分离读取/写入仍不是跨程序原子 CAS，执行期间应避免多个网络工具并发修改。

VMess/VLESS/Trojan 继承参考实现的 TCP、WebSocket、gRPC、XHTTP 和 mKCP 传输，具体兼容性取决于节点选项；不支持的组合会报错。协议列表是代码路径范围，不代表每种远端服务配置均完成联网互通测试。默认验证 TLS 身份；只有显式设置 skip-cert-verify=true 才跳过验证，这样会失去防中间人保护。

## 构建

需要 macOS 13+、Swift 5.9+ Command Line Tools、CMake，以及 OpenSSL 3.5+ 的头文件和静态库；本机验证使用 OpenSSL 3.6.2。无需 Go。首次构建将 checksum-pinned 的 ngtcp2/nghttp3/libssh2 源码构建到 `.build/Vendor`，不全局安装依赖。OpenSSL 默认从 `/usr/local/opt/openssl@3` 或 `/opt/homebrew/opt/openssl@3` 读取；其它位置设置 HAJIMI_OPENSSL_ROOT。

~~~bash
make verify
open dist/哈基米.app

# universal 还需提供包含两种架构的 OpenSSL 静态库：
make ARCHS="x86_64 arm64" native-core
make ARCHS="x86_64 arm64" verify
~~~

原生模块可独立验证；Network Extension 目前仅做编译验证（输出未签名且不可启用的开发扩展）：

~~~bash
make test-native
make test-quic
make test-chains
make network-extension
~~~

make verify 会运行 C++ 协议/加密与跨会话重放、读缓冲/终端错误、独立回环 QUIC 互通与有界收包、HTTP/SOCKS 两跳代理链与失效链拒绝、DNS 拒绝/控制器重载/入口上限与超时、配置、Objective-C++ 桥接/转发/取消/半关闭、Objective-C 权限预检、Helper、UDP 策略切换与性能烟雾测试，构建并校验签名，并检查最终二进制不含旧 Go runtime/bridge 符号；不会安装 Helper、修改系统代理或启用增强模式。QUIC/SSH 互通测试工具只在 `.build` 本地 Python venv 中安装，不随应用分发。可另外执行：

~~~bash
python3 SmokeTests/live_proxies.py --binary .build/x86_64-apple-macosx/release/Hajimi
~~~

该可选测试在本机临时启动 HTTP 来源和 TLS 代理，验证 HTTPS / SOCKS5-TLS 的真实握手和证书拒绝；不访问公网，也不需要 root。

## 使用

首次启动只运行本地代理监听，不会自动修改系统代理或装入 root Helper。默认监听 HTTP 127.0.0.1:7262 与 SOCKS5 127.0.0.1:7263：

~~~bash
curl --noproxy "" -x http://127.0.0.1:7262 https://example.com
curl --noproxy "" --socks5-hostname 127.0.0.1:7263 https://example.com
~~~

用户配置存放在 ~/Library/Application Support/Hajimi/profile.conf。示例：

~~~ini
[General]
http-listen = 127.0.0.1:7262
socks5-listen = 127.0.0.1:7263

[Proxy]
SecureHTTP = https, proxy.example.com, 443, username=user, password=secret
SecureSOCKS = socks5-tls, proxy.example.com, 443, username=user, password=secret
SS2022 = ss, proxy.example.com, 8388, 2022-blake3-aes-128-gcm, BASE64_PSK, udp=true
VLESS = vless, proxy.example.com, 443, uuid, tls=true, servername=proxy.example.com
Trojan = trojan, proxy.example.com, 443, password, sni=proxy.example.com
HY2 = hysteria2, proxy.example.com, 443, password, sni=proxy.example.com

[Proxy Group]
Proxy = select, SecureHTTP, SecureSOCKS, SS2022, VLESS, Trojan, HY2, DIRECT

[Rule]
DOMAIN-SUFFIX,example.com,Proxy
FINAL,DIRECT
~~~

配置支持 Surge 风格规则和策略组，以及 Clash YAML / 分享链接订阅；不实现 Surge 的 MITM、Rewrite、Script 或 WireGuard 出站。界面中可手动启用系统代理或增强模式，前者影响整台 Mac 的代理设置，后者需要管理员授权，均应先保存当前网络状态。Helper 安装标识为 app.hajimi.helper，使用专用隧道地址；检测到已有第三方 utun 路由会拒绝接管。为避免破坏其它网络软件，Helper 不再盲目清除未证明属于本会话的路由或 DNS；若 Helper 异常崩溃后遗留设置，需由用户确认并手动恢复。

## 源码与分发注意

本项目从用户指定的 Lurge 工作目录复制而来；旧 LurgeQUICBridge/Go 目录仅作历史参考，不再参与构建。原参考目录包含未提交改动，项目不附其顶层授权文件。许可证和参考来源见 Resources/ThirdPartyNotices.txt；改写语言不自动消除派生源码的许可义务。公开分发前必须核实参考源码使用权、第三方许可证、相应源码提供义务，以及 Developer ID / Apple 授权签名要求；当前验证为本地开发构建。

本项目由OpenAI的6.0sol模型编写，感谢模型提供者：𝔁𝓲 𝓬𝓱𝓮𝓷 https://t.me/PastKing ｜ Dakota Riley https://t.me/jayshouxx
