#!/usr/bin/env bash
# ==============================================================================
# 哈基米 (Hajimi) 全协议 + 全传输层 30 节点 VPS 一键部署脚本 (v3.0 全内置零外部断链版)
# ==============================================================================
# 适用系统: Ubuntu 20.04/22.04/24.04, Debian 11/12 (x86_64 / arm64, root 权限)
#
# 本脚本一键搭建哈基米支持的全部 18 种出站协议 + 全传输层组合（共 30 个测试节点）：
#   [Sing-box 核心托管 (20 节点)]
#   - 20001 (TCP+UDP): SS-AES128GCM        (Shadowsocks AEAD aes-128-gcm)
#   - 20002 (TCP+UDP): SS2022-BLAKE3       (Shadowsocks 2022 2022-blake3-aes-128-gcm)
#   - 20021 (TCP+UDP): SS-ChaCha20         (Shadowsocks AEAD chacha20-ietf-poly1305)
#   - 20022 (TCP+UDP): SS2022-ChaCha20     (Shadowsocks 2022 2022-blake3-chacha20-poly1305)
#   - 20004 (TCP)    : VMess-AEAD          (VMess TCP + UDP-over-TCP)
#   - 20005 (TCP)    : VMess-WS-TLS        (VMess + WebSocket + TLS + UDP)
#   - 20023 (TCP)    : VMess-gRPC-TLS      (VMess + gRPC + TLS + UDP)
#   - 20006 (TCP)    : VLESS-Vision-REALITY(VLESS + XTLS-Vision + REALITY + XUDP)
#   - 20007 (TCP)    : VLESS-WS-TLS        (VLESS + WebSocket + TLS + XUDP)
#   - 20024 (TCP)    : VLESS-gRPC-TLS      (VLESS + gRPC + TLS + XUDP)
#   - 20008 (TCP)    : Trojan-TLS          (Trojan + TLS + UDP)
#   - 20025 (TCP)    : Trojan-WS-TLS       (Trojan + WebSocket + TLS + UDP)
#   - 20026 (TCP)    : Trojan-gRPC-TLS     (Trojan + gRPC + TLS + UDP)
#   - 20009 (UDP)    : Hysteria-v1         (Hysteria v1 QUIC alpn=hysteria,h3 + UDP)
#   - 20010 (UDP)    : Hysteria2-QUIC      (Hysteria2 QUIC HTTP/3 + UDP)
#   - 20027 (UDP)    : Hysteria2-Salamander(Hysteria2 QUIC + Salamander 混淆 + UDP)
#   - 20013 (UDP)    : TUIC-v5             (TUIC v5 QUIC + UDP native)
#   - 20014 (TCP)    : AnyTLS-Node         (AnyTLS TLS 1.3 Padding + UoT UDP)
#   - 20030 (TCP+UDP): SOCKS5-Auth         (SOCKS5 账号密码认证 + UDP Associate)
#   - 20016 (TCP)    : HTTPS-Connect       (HTTPS TLS CONNECT 隧道代理)
#   - 20028 (TCP)    : HTTP-Plain          (HTTP 明文 CONNECT 代理)
#
#   [Mieru 官方 mita 服务端 (2 节点)]
#   - 20011 (TCP)    : Mieru-TCP           (Mieru v3 Stream AEAD TCP)
#   - 20017 (UDP)    : Mieru-UDP           (Mieru v3 Packet AEAD UDP + UoT)
#
#   [hajimi-extra 内置全协议服务端 (6 节点，100% 自包含，无任何外部二进制下载依赖)]
#   - 20003 (TCP)    : Snell-v4            (Snell v4 Argon2id + AES-128-GCM + UoT UDP)
#   - 20012 (TCP)    : Sudoku-UoT          (Sudoku v0.5.2 ASCII Pure Downlink + KIP + UoT UDP)
#   - 20029 (TCP)    : Sudoku-Entropy      (Sudoku v0.5.2 Custom xvxvppvv + 6-bit Packed Downlink + UoT)
#   - 20018 (TCP)    : TrustTunnel         (TrustTunnel HTTPS CONNECT + _trusttunnel_udp_:443)
#   - 20019 (TCP)    : SOCKS5-TLS          (SOCKS5 over TLS + UDP Associate)
#   - 20020 (TCP+UDP): SSR-Origin          (ShadowsocksR aes-128-cfb origin/plain TCP + UDP)
#
#   [系统级 SSH 与 WireGuard (2 节点)]
#   - 22    (TCP)    : SSH-Tunnel          (SSH 专用受限转发账户 password + Ed25519 私钥)
#   - 51820 (UDP)    : WireGuard-Node      (WireGuard 内核态 VPN 隧道)
#
# 用法:
#   chmod +x deploy_hajimi_test_nodes.sh
#   sudo ./deploy_hajimi_test_nodes.sh
#   sudo ./deploy_hajimi_test_nodes.sh --serve 20080   # 开启临时 HTTP 订阅下载服务
#   sudo ./deploy_hajimi_test_nodes.sh --status        # 查看所有服务状态与端口监听自检
#   sudo ./deploy_hajimi_test_nodes.sh --uninstall     # 一键卸载并清理所有测试服务
# ==============================================================================

set -euo pipefail

WORK_DIR="/opt/hajimi-test"
CERT_DIR="${WORK_DIR}/certs"
BIN_DIR="${WORK_DIR}/bin"
CONF_DIR="${WORK_DIR}/conf"
OUT_DIR="${WORK_DIR}/client-outputs"
STATE_ENV="${WORK_DIR}/credentials.env"

SINGBOX_VERSION="1.12.0"
MIERU_VERSION="3.15.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_err "请使用 root 权限运行本脚本 (例如: sudo $0)"
        exit 1
    fi
}

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "${machine}" in
        x86_64|amd64)
            ARCH_DEB="amd64"
            ARCH_SB="amd64"
            ;;
        aarch64|arm64)
            ARCH_DEB="arm64"
            ARCH_SB="arm64"
            ;;
        *)
            log_err "不支持的 CPU 架构: ${machine} (仅支持 x86_64 / arm64)"
            exit 1
            ;;
    esac
}

detect_public_ip() {
    PUBLIC_IP="${HAJIMI_PUBLIC_IP:-}"
    if [[ -z "${PUBLIC_IP}" ]]; then
        PUBLIC_IP="$(curl -4fsSL --max-time 6 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [[ -z "${PUBLIC_IP}" ]]; then
        PUBLIC_IP="$(curl -4fsSL --max-time 6 https://ifconfig.me 2>/dev/null || true)"
    fi
    if [[ -z "${PUBLIC_IP}" ]]; then
        PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || true)"
    fi
    PUBLIC_IPV6="${HAJIMI_PUBLIC_IPV6:-}"
    if [[ -z "${PUBLIC_IPV6}" ]]; then
        PUBLIC_IPV6="$(curl -6fsSL --max-time 5 https://api64.ipify.org 2>/dev/null | grep ':' || true)"
    fi
    if [[ -z "${PUBLIC_IPV6}" ]]; then
        PUBLIC_IPV6="$(curl -6fsSL --max-time 5 https://ifconfig.me 2>/dev/null | grep ':' || true)"
    fi
    if [[ -z "${PUBLIC_IPV6}" ]]; then
        PUBLIC_IPV6="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | grep -v '^fe80' | head -n1 || true)"
    fi
    if [[ -z "${PUBLIC_IP}" && -n "${PUBLIC_IPV6}" ]]; then
        PUBLIC_IP="${PUBLIC_IPV6}"
    fi
    if [[ -z "${PUBLIC_IP}" ]]; then
        log_err "无法自动检测 VPS 公网 IP 地址，请通过 HAJIMI_PUBLIC_IP=x.x.x.x sudo $0 指定"
        exit 1
    fi
    DEFAULT_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
    if [[ -z "${DEFAULT_IFACE}" ]]; then
        DEFAULT_IFACE="$(ip -6 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
    fi
    if [[ -z "${DEFAULT_IFACE}" ]]; then
        DEFAULT_IFACE="eth0"
    fi
    if [[ -n "${PUBLIC_IPV6}" ]]; then
        log_ok "检测到公网双栈 IP: IPv4=${PUBLIC_IP}, IPv6=${PUBLIC_IPV6} (主网卡: ${DEFAULT_IFACE})"
    else
        log_ok "检测到公网 IP: ${PUBLIC_IP} (主网卡: ${DEFAULT_IFACE})"
    fi
}

uninstall_all() {
    require_root
    log_info "正在停止并卸载所有 Hajimi 测试节点服务..."
    for svc in hajimi-singbox hajimi-extra hajimi-sub-http mita wg-quick@wg0; do
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/hajimi-singbox.service \
          /etc/systemd/system/hajimi-extra.service \
          /etc/systemd/system/hajimi-sub-http.service
    systemctl daemon-reload
    rm -f /etc/wireguard/wg0.conf
    if id "hajimi_tunnel" &>/dev/null; then
        userdel -r hajimi_tunnel 2>/dev/null || true
    fi
    rm -f /etc/ssh/sshd_config.d/99-hajimi-test.conf
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    rm -rf "${WORK_DIR}"
    log_ok "所有 Hajimi 测试服务及目录 (${WORK_DIR}) 已清理完毕。"
    exit 0
}

show_status() {
    echo "=================================================================="
    echo "                Hajimi VPS 测试服务运行状态                        "
    echo "=================================================================="
    for svc in hajimi-singbox hajimi-extra mita wg-quick@wg0 ssh; do
        if systemctl is-active --quiet "${svc}" 2>/dev/null; then
            echo -e "  ● ${svc}: ${GREEN}running (运行中)${NC}"
        else
            echo -e "  ○ ${svc}: ${RED}inactive (未运行)${NC}"
        fi
    done
    echo "------------------------------------------------------------------"
    echo "监听端口概览 (20001 - 20030, 51820, 22):"
    ss -tulnp | grep -E ':(200[0-3][0-9]|51820|22)\b' || true
    echo "=================================================================="
}

install_base_packages() {
    log_info "正在安装系统依赖与内核转发组件..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -qq
    apt-get install -y -qq curl wget tar unzip openssl jq qrencode \
        wireguard wireguard-tools iptables iproute2 ca-certificates \
        python3 python3-cryptography openssh-server

    cat >/etc/sysctl.d/99-hajimi-proxy.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1 || true
    log_ok "系统基础依赖与 BBR/IP 转发已就绪"
}

prepare_directories_and_certs() {
    mkdir -p "${CERT_DIR}" "${BIN_DIR}" "${CONF_DIR}" "${OUT_DIR}"
    chmod 700 "${WORK_DIR}" "${CERT_DIR}" "${CONF_DIR}" "${OUT_DIR}"

    if [[ ! -f "${CERT_DIR}/server.crt" || ! -f "${CERT_DIR}/server.key" ]]; then
        local san_ext="IP:${PUBLIC_IP},DNS:www.bing.com,DNS:example.com"
        if [[ -n "${PUBLIC_IPV6:-}" && "${PUBLIC_IPV6}" != "${PUBLIC_IP}" ]]; then
            san_ext="IP:${PUBLIC_IP},IP:${PUBLIC_IPV6},DNS:www.bing.com,DNS:example.com"
        fi
        log_info "正在生成自签名 TLS 证书 (SAN: ${san_ext})..."
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -days 3650 -nodes \
            -keyout "${CERT_DIR}/server.key" \
            -out "${CERT_DIR}/server.crt" \
            -subj "/CN=${PUBLIC_IP}" \
            -addext "subjectAltName=${san_ext}" \
            >/dev/null 2>&1
        chmod 600 "${CERT_DIR}/server.key"
        chmod 644 "${CERT_DIR}/server.crt"
    fi
    CERT_SHA256="$(openssl x509 -in "${CERT_DIR}/server.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
    log_ok "TLS 证书就绪 (SHA256: ${CERT_SHA256})"
}

install_singbox() {
    if [[ -x "${BIN_DIR}/sing-box" ]]; then
        log_ok "sing-box 已安装: $(${BIN_DIR}/sing-box version | head -n1)"
        return
    fi
    log_info "正在下载 sing-box v${SINGBOX_VERSION} (${ARCH_SB})..."
    local tarball="sing-box-${SINGBOX_VERSION}-linux-${ARCH_SB}.tar.gz"
    local url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${tarball}"
    curl -fsSL --retry 3 -o "/tmp/${tarball}" "${url}"
    tar -xzf "/tmp/${tarball}" -C /tmp
    install -m 755 "/tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH_SB}/sing-box" "${BIN_DIR}/sing-box"
    rm -rf "/tmp/${tarball}" "/tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH_SB}"
    log_ok "sing-box 安装完成: $(${BIN_DIR}/sing-box version | head -n1)"
}

install_mieru_mita() {
    if command -v mita >/dev/null 2>&1; then
        log_ok "Mieru 服务端 (mita) 已安装: $(mita version 2>/dev/null || echo 'installed')"
        return
    fi
    log_info "正在下载 Mieru 服务端 (mita v${MIERU_VERSION} ${ARCH_DEB})..."
    local deb="mita_${MIERU_VERSION}_${ARCH_DEB}.deb"
    local url="https://github.com/enfein/mieru/releases/download/v${MIERU_VERSION}/${deb}"
    if curl -fsSL --retry 3 -o "/tmp/${deb}" "${url}"; then
        dpkg -i "/tmp/${deb}" >/dev/null 2>&1 || apt-get install -f -y -qq
        rm -f "/tmp/${deb}"
        log_ok "mita 安装完成"
    else
        log_warn "mita v${MIERU_VERSION} 下载失败，尝试从 GitHub 最新 Release 获取..."
        local latest_url
        latest_url="$(curl -fsSL https://api.github.com/repos/enfein/mieru/releases/latest | jq -r ".assets[] | select(.name | test(\"mita_.*_${ARCH_DEB}\\\\.deb$\")) | .browser_download_url" | head -n1 || true)"
        if [[ -n "${latest_url}" ]]; then
            curl -fsSL --retry 3 -o "/tmp/mita_latest.deb" "${latest_url}"
            dpkg -i "/tmp/mita_latest.deb" >/dev/null 2>&1 || apt-get install -f -y -qq
            rm -f "/tmp/mita_latest.deb"
            log_ok "mita 最新版安装完成"
        else
            log_warn "无法自动下载 mita，将跳过 Mieru 服务启动"
        fi
    fi
}

generate_or_load_credentials() {
    if [[ -f "${STATE_ENV}" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_ENV}"
        log_ok "已加载现有节点密钥配置 (${STATE_ENV})"
    fi

    COMMON_PASS="${COMMON_PASS:-$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)}"
    COMMON_USER="${COMMON_USER:-hajimi}"
    SSH_TUNNEL_USER="${SSH_TUNNEL_USER:-hajimi_tunnel}"
    UUID_V4="${UUID_V4:-$(cat /proc/sys/kernel/random/uuid)}"
    SS2022_AES128_KEY="${SS2022_AES128_KEY:-$(openssl rand -base64 16)}"
    SS2022_CHACHA_KEY="${SS2022_CHACHA_KEY:-$(openssl rand -base64 32)}"
    SNELL_PSK="${SNELL_PSK:-$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 28)}"
    HY2_OBFS_PASS="${HY2_OBFS_PASS:-$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)}"

    if [[ -z "${REALITY_PRIV_KEY:-}" || -z "${REALITY_PUB_KEY:-}" ]]; then
        local kp
        kp="$("${BIN_DIR}/sing-box" generate reality-keypair)"
        REALITY_PRIV_KEY="$(echo "${kp}" | awk '/PrivateKey/{print $2}')"
        REALITY_PUB_KEY="$(echo "${kp}" | awk '/PublicKey/{print $2}')"
    fi
    REALITY_SHORT_ID="${REALITY_SHORT_ID:-$(openssl rand -hex 8)}"
    REALITY_SNI="${REALITY_SNI:-www.apple.com}"

    if [[ -z "${SUDOKU_CLIENT_KEY:-}" ]]; then
        SUDOKU_CLIENT_KEY="$(python3 -c 'import secrets; L = (1 << 252) + 27742317777372353535851937790883648493; r = secrets.randbelow(L - 1) + 1; k = secrets.randbelow(L - 1) + 1; print((r.to_bytes(32, "little") + k.to_bytes(32, "little")).hex())')"
    fi
    SUDOKU_MASTER_PUB="${SUDOKU_MASTER_PUB:-}"

    if [[ -z "${WG_SERVER_PRIV:-}" || -z "${WG_CLIENT_PRIV:-}" ]]; then
        WG_SERVER_PRIV="$(wg genkey)"
        WG_SERVER_PUB="$(echo "${WG_SERVER_PRIV}" | wg pubkey)"
        WG_CLIENT_PRIV="$(wg genkey)"
        WG_CLIENT_PUB="$(echo "${WG_CLIENT_PRIV}" | wg pubkey)"
        WG_PSK="$(wg genpsk)"
    fi

    cat >"${STATE_ENV}" <<EOF
COMMON_PASS="${COMMON_PASS}"
COMMON_USER="${COMMON_USER}"
SSH_TUNNEL_USER="${SSH_TUNNEL_USER}"
UUID_V4="${UUID_V4}"
SS2022_AES128_KEY="${SS2022_AES128_KEY}"
SS2022_CHACHA_KEY="${SS2022_CHACHA_KEY}"
SNELL_PSK="${SNELL_PSK}"
HY2_OBFS_PASS="${HY2_OBFS_PASS}"
REALITY_PRIV_KEY="${REALITY_PRIV_KEY}"
REALITY_PUB_KEY="${REALITY_PUB_KEY}"
REALITY_SHORT_ID="${REALITY_SHORT_ID}"
REALITY_SNI="${REALITY_SNI}"
SUDOKU_CLIENT_KEY="${SUDOKU_CLIENT_KEY}"
SUDOKU_MASTER_PUB="${SUDOKU_MASTER_PUB}"
WG_SERVER_PRIV="${WG_SERVER_PRIV}"
WG_SERVER_PUB="${WG_SERVER_PUB}"
WG_CLIENT_PRIV="${WG_CLIENT_PRIV}"
WG_CLIENT_PUB="${WG_CLIENT_PUB}"
WG_PSK="${WG_PSK}"
EOF
    chmod 600 "${STATE_ENV}"
}

configure_singbox_service() {
    log_info "正在生成 sing-box 多协议全传输层配置 (20 个入站节点)..."
    cat >"${CONF_DIR}/sing-box.json" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-aes128gcm-in",
      "listen": "::",
      "listen_port": 20001,
      "method": "aes-128-gcm",
      "password": "${COMMON_PASS}"
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-blake3-in",
      "listen": "::",
      "listen_port": 20002,
      "method": "2022-blake3-aes-128-gcm",
      "password": "${SS2022_AES128_KEY}"
    },
    {
      "type": "shadowsocks",
      "tag": "ss-chacha20-in",
      "listen": "::",
      "listen_port": 20021,
      "method": "chacha20-ietf-poly1305",
      "password": "${COMMON_PASS}"
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-chacha20-in",
      "listen": "::",
      "listen_port": 20022,
      "method": "2022-blake3-chacha20-poly1305",
      "password": "${SS2022_CHACHA_KEY}"
    },
    {
      "type": "vmess",
      "tag": "vmess-tcp-in",
      "listen": "::",
      "listen_port": 20004,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}",
          "alterId": 0
        }
      ]
    },
    {
      "type": "vmess",
      "tag": "vmess-ws-tls-in",
      "listen": "::",
      "listen_port": 20005,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}",
          "alterId": 0
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["http/1.1"]
      },
      "transport": {
        "type": "ws",
        "path": "/vmess-ws"
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-grpc-tls-in",
      "listen": "::",
      "listen_port": 20023,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}",
          "alterId": 0
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h2"]
      },
      "transport": {
        "type": "grpc",
        "service_name": "vmess-grpc"
      }
    },
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": 20006,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_SNI}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIV_KEY}",
          "short_id": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "vless-ws-tls-in",
      "listen": "::",
      "listen_port": 20007,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["http/1.1"]
      },
      "transport": {
        "type": "ws",
        "path": "/vless-ws"
      }
    },
    {
      "type": "vless",
      "tag": "vless-grpc-tls-in",
      "listen": "::",
      "listen_port": 20024,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h2"]
      },
      "transport": {
        "type": "grpc",
        "service_name": "vless-grpc"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-tls-in",
      "listen": "::",
      "listen_port": 20008,
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["http/1.1", "h2"]
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-ws-tls-in",
      "listen": "::",
      "listen_port": 20025,
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["http/1.1"]
      },
      "transport": {
        "type": "ws",
        "path": "/trojan-ws"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-grpc-tls-in",
      "listen": "::",
      "listen_port": 20026,
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h2"]
      },
      "transport": {
        "type": "grpc",
        "service_name": "trojan-grpc"
      }
    },
    {
      "type": "hysteria",
      "tag": "hysteria1-in",
      "listen": "::",
      "listen_port": 20009,
      "up_mbps": 100,
      "down_mbps": 100,
      "users": [
        {
          "name": "hajimi",
          "auth_str": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["hysteria", "h3"]
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": 20010,
      "up_mbps": 100,
      "down_mbps": 100,
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h3"]
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-salamander-in",
      "listen": "::",
      "listen_port": 20027,
      "up_mbps": 100,
      "down_mbps": 100,
      "obfs": {
        "type": "salamander",
        "password": "${HY2_OBFS_PASS}"
      },
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h3"]
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-v5-in",
      "listen": "::",
      "listen_port": 20013,
      "users": [
        {
          "name": "hajimi",
          "uuid": "${UUID_V4}",
          "password": "${COMMON_PASS}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["h3"]
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": 20014,
      "users": [
        {
          "name": "hajimi",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key"
      }
    },
    {
      "type": "mixed",
      "tag": "socks5-auth-in",
      "listen": "::",
      "listen_port": 20030,
      "users": [
        {
          "username": "${COMMON_USER}",
          "password": "${COMMON_PASS}"
        }
      ]
    },
    {
      "type": "http",
      "tag": "https-connect-in",
      "listen": "::",
      "listen_port": 20016,
      "users": [
        {
          "username": "${COMMON_USER}",
          "password": "${COMMON_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/server.crt",
        "key_path": "${CERT_DIR}/server.key",
        "alpn": ["http/1.1"]
      }
    },
    {
      "type": "http",
      "tag": "http-plain-in",
      "listen": "::",
      "listen_port": 20028,
      "users": [
        {
          "username": "${COMMON_USER}",
          "password": "${COMMON_PASS}"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
EOF

    cat >/etc/systemd/system/hajimi-singbox.service <<EOF
[Unit]
Description=Hajimi Multi-Protocol Test Server (sing-box)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/sing-box run -c ${CONF_DIR}/sing-box.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now hajimi-singbox.service
    log_ok "hajimi-singbox.service 已启动 (监听端口: 20001,20002,20004..20010,20013..20016,20021..20028)"
}

configure_mieru_service() {
    if ! command -v mita >/dev/null 2>&1; then
        log_warn "未检测到 mita，跳过 Mieru TCP/UDP 服务配置"
        return
    fi
    log_info "正在配置 Mieru 服务端 (TCP:20011, UDP:20017)..."
    mkdir -p /etc/mita
    cat >/etc/mita/server.json <<EOF
{
  "portBindings": [
    {
      "port": 20011,
      "protocol": "TCP"
    },
    {
      "port": 20017,
      "protocol": "UDP"
    }
  ],
  "users": [
    {
      "name": "${COMMON_USER}",
      "password": "${COMMON_PASS}"
    }
  ],
  "loggingLevel": "INFO",
  "mtu": 1400
}
EOF
    systemctl enable --now mita 2>/dev/null || true
    mita apply config /etc/mita/server.json 2>/dev/null || true
    mita start 2>/dev/null || systemctl restart mita 2>/dev/null || true
    log_ok "Mieru (mita) 已启动 (TCP: 20011, UDP: 20017)"
}

configure_extra_protocol_servers() {
    log_info "正在配置内置全自包含协议服务端 (Snell v4:20003, Sudoku-UoT:20012, Sudoku-Entropy:20029, TrustTunnel:20018, SOCKS5-TLS:20019, SSR-Origin:20020)..."
    cat >"${WORK_DIR}/extra-config.json" <<EOF
{
  "bind_host": "::",
  "cert": "${CERT_DIR}/server.crt",
  "key": "${CERT_DIR}/server.key",
  "public_ip": "${PUBLIC_IP}",
  "public_ipv6": "${PUBLIC_IPV6:-}",
  "snell_port": 20003,
  "snell_psk": "${SNELL_PSK}",
  "tt_port": 20018,
  "tt_user": "${COMMON_USER}",
  "tt_pass": "${COMMON_PASS}",
  "s5tls_port": 20019,
  "s5_user": "${COMMON_USER}",
  "s5_pass": "${COMMON_PASS}",
  "ssr_port": 20020,
  "ssr_pass": "${COMMON_PASS}",
  "sudoku_profiles": [
    {
      "port": 20012,
      "key": "${SUDOKU_CLIENT_KEY}",
      "aead_method": "chacha20-poly1305",
      "table_type": "prefer_ascii",
      "custom_table": "",
      "enable_pure_downlink": true,
      "padding_min": 2,
      "padding_max": 7
    },
    {
      "port": 20029,
      "key": "${SUDOKU_CLIENT_KEY}",
      "aead_method": "aes-128-gcm",
      "table_type": "up_ascii_down_entropy",
      "custom_table": "xvxvppvv",
      "enable_pure_downlink": false,
      "padding_min": 2,
      "padding_max": 7
    }
  ]
}
EOF
    chmod 600 "${WORK_DIR}/extra-config.json"

    cat >"${BIN_DIR}/hajimi_extra_servers.py" <<'PYEOF'
#!/usr/bin/env python3
"""
Hajimi Extra Protocol Test Servers (100% Self-Contained):
1. Snell v4 TCP + UoT UDP Server (Port 20003)
2. Sudoku v0.5.2 Obfuscated KIP + RecordConn + TCP/UoT Server (Port 20012 & Port 20029)
3. TrustTunnel HTTPS CONNECT + UDP-over-Stream Server (Port 20018)
4. SOCKS5-TLS Server with TCP CONNECT + UDP ASSOCIATE (Port 20019)
5. ShadowsocksR (SSR) aes-128-cfb origin/plain TCP + UDP Server (Port 20020)
"""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

# ============================================================================
# Common SOCKS5 Address Helpers
# ============================================================================

def parse_socks_addr(buf: bytes, offset: int = 0):
    if offset >= len(buf):
        raise ValueError("Truncated SOCKS address")
    atyp = buf[offset]
    offset += 1
    if atyp == 1:
        if offset + 6 > len(buf):
            raise ValueError("Truncated IPv4 address")
        host = socket.inet_ntop(socket.AF_INET, buf[offset:offset + 4])
        port = struct.unpack(">H", buf[offset + 4:offset + 6])[0]
        return host, port, offset + 6
    elif atyp == 3:
        if offset + 1 > len(buf):
            raise ValueError("Truncated domain length")
        dlen = buf[offset]
        offset += 1
        if offset + dlen + 2 > len(buf):
            raise ValueError("Truncated domain address")
        host = buf[offset:offset + dlen].decode("utf-8", errors="replace")
        port = struct.unpack(">H", buf[offset + dlen:offset + dlen + 2])[0]
        return host, port, offset + dlen + 2
    elif atyp == 4:
        if offset + 18 > len(buf):
            raise ValueError("Truncated IPv6 address")
        host = socket.inet_ntop(socket.AF_INET6, buf[offset:offset + 16])
        port = struct.unpack(">H", buf[offset + 16:offset + 18])[0]
        return host, port, offset + 18
    else:
        raise ValueError(f"Unsupported ATYP {atyp}")

def normalize_ip_literal(host: str) -> str:
    h = host.strip("[]")
    if "%" in h:
        h = h.split("%", 1)[0]
    if h.lower().startswith("::ffff:"):
        candidate = h[7:]
        try:
            socket.inet_pton(socket.AF_INET, candidate)
            return candidate
        except OSError:
            pass
    return h

def encode_socks_addr(host: str, port: int) -> bytes:
    h = normalize_ip_literal(host)
    try:
        ip4 = socket.inet_pton(socket.AF_INET, h)
        return b"\x01" + ip4 + struct.pack(">H", port)
    except OSError:
        pass
    try:
        ip6 = socket.inet_pton(socket.AF_INET6, h)
        return b"\x04" + ip6 + struct.pack(">H", port)
    except OSError:
        pass
    hb = h.encode("utf-8")
    return b"\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port)

def encode_snell_udp_addr(host: str, port: int) -> bytes:
    h = normalize_ip_literal(host)
    try:
        ip4 = socket.inet_pton(socket.AF_INET, h)
        return b"\x04" + ip4 + struct.pack(">H", port)
    except OSError:
        pass
    ip6 = socket.inet_pton(socket.AF_INET6, h)
    return b"\x06" + ip6 + struct.pack(">H", port)

async def pipe_HalfClose(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(32768)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def resolve_udp_destination(host: str, port: int):
    h = normalize_ip_literal(host)
    try:
        socket.inet_pton(socket.AF_INET6, h)
        return socket.AF_INET6, (h, port, 0, 0)
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET, h)
        return socket.AF_INET, (h, port)
    except OSError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(h, port, type=socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"Cannot resolve UDP target {host}:{port}")
    for family, socktype, proto, canonname, sockaddr in infos:
        if family == socket.AF_INET:
            return family, sockaddr
    family, socktype, proto, canonname, sockaddr = infos[0]
    return family, sockaddr

class DualStackUDPRelay:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock4.setblocking(False)
        self.sock6 = None
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.setblocking(False)
            self.sock6 = s6
        except OSError:
            pass

    async def sendto(self, dst_host: str, dst_port: int, payload: bytes):
        family, sockaddr = await resolve_udp_destination(dst_host, dst_port)
        if family == socket.AF_INET6 and self.sock6 is not None:
            await self.loop.sock_sendto(self.sock6, payload, sockaddr)
        else:
            await self.loop.sock_sendto(self.sock4, payload, sockaddr)

    def start_rx_tasks(self, on_packet_coro):
        tasks = []
        async def _rx_loop(sock):
            try:
                while True:
                    data, addr = await self.loop.sock_recvfrom(sock, 65535)
                    await on_packet_coro(data, addr[0], addr[1])
            except Exception:
                pass
        tasks.append(asyncio.create_task(_rx_loop(self.sock4)))
        if self.sock6 is not None:
            tasks.append(asyncio.create_task(_rx_loop(self.sock6)))
        return tasks

    def close(self, tasks=None):
        tasks = tasks or []
        for t in tasks:
            t.cancel()
        try:
            self.sock4.close()
        except Exception:
            pass
        if self.sock6 is not None:
            try:
                self.sock6.close()
            except Exception:
                pass

# ============================================================================
# 1. Snell v4 Server (Argon2id + AES-128-GCM + UoT UDP)
# ============================================================================

def derive_snell_v4_key_pure_python(psk: bytes, salt: bytes, tag_len: int = 32) -> bytes:
    """
    Pure-Python Argon2id (v=0x13, y=2, p=1, m=8 KiB, t=3, tagLen=tag_len)[:16]
    matching Snell.cpp deriveKey / deriveKeyCompat16 byte-for-byte.
    """
    def blake2b_long(data: bytes, out_len: int) -> bytes:
        le_len = struct.pack("<I", out_len)
        if out_len <= 64:
            return hashlib.blake2b(le_len + data, digest_size=out_len).digest()
        out = bytearray()
        v = hashlib.blake2b(le_len + data, digest_size=64).digest()
        out.extend(v[:32])
        while len(out) < out_len:
            rem = out_len - len(out)
            if rem <= 64:
                v = hashlib.blake2b(v, digest_size=rem).digest()
                out.extend(v)
                break
            v = hashlib.blake2b(v, digest_size=64).digest()
            out.extend(v[:32])
        return bytes(out[:out_len])

    def rotr64(x: int, n: int) -> int:
        return ((x >> n) | ((x << (64 - n)) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF

    def f_blaMka(x: int, y: int) -> int:
        m = (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF)
        return (x + y + 2 * m) & 0xFFFFFFFFFFFFFFFF

    def g_round(v, a, b, c, d):
        v[a] = f_blaMka(v[a], v[b])
        v[d] = rotr64(v[d] ^ v[a], 32)
        v[c] = f_blaMka(v[c], v[d])
        v[b] = rotr64(v[b] ^ v[c], 24)
        v[a] = f_blaMka(v[a], v[b])
        v[d] = rotr64(v[d] ^ v[a], 16)
        v[c] = f_blaMka(v[c], v[d])
        v[b] = rotr64(v[b] ^ v[c], 63)

    def permute_p(v, idx):
        g_round(v, idx[0], idx[4], idx[8],  idx[12])
        g_round(v, idx[1], idx[5], idx[9],  idx[13])
        g_round(v, idx[2], idx[6], idx[10], idx[14])
        g_round(v, idx[3], idx[7], idx[11], idx[15])
        g_round(v, idx[0], idx[5], idx[10], idx[15])
        g_round(v, idx[1], idx[6], idx[11], idx[12])
        g_round(v, idx[2], idx[7], idx[8],  idx[13])
        g_round(v, idx[3], idx[4], idx[9],  idx[14])

    def fill_block(prev_blk, ref_blk, next_blk, with_xor: bool):
        r = [prev_blk[i] ^ ref_blk[i] for i in range(128)]
        z = list(r)
        for i in range(8):
            permute_p(z, [16 * i + j for j in range(16)])
        for i in range(8):
            cols = []
            for j in range(8):
                cols.append(2 * i + 16 * j)
                cols.append(2 * i + 16 * j + 1)
            permute_p(z, cols)
        for i in range(128):
            val = z[i] ^ r[i]
            if with_xor:
                next_blk[i] ^= val
            else:
                next_blk[i] = val

    h0_in = struct.pack("<IIIIII", 1, tag_len, 8, 3, 0x13, 2)
    h0_in += struct.pack("<I", len(psk)) + psk
    h0_in += struct.pack("<I", len(salt)) + salt
    h0_in += struct.pack("<II", 0, 0)
    h0 = hashlib.blake2b(h0_in, digest_size=64).digest()

    mem = [[0] * 128 for _ in range(8)]
    for b in range(2):
        raw = blake2b_long(h0 + struct.pack("<II", b, 0), 1024)
        mem[b] = list(struct.unpack("<128Q", raw))

    for p_pass in range(3):
        for s_slice in range(4):
            use_index_indep = (p_pass == 0 and s_slice < 2)
            pseudo = [0] * 128
            if use_index_indep:
                zin = [0] * 128
                zin[0] = p_pass
                zin[1] = 0
                zin[2] = s_slice
                zin[3] = 8
                zin[4] = 3
                zin[5] = 2
                zin[6] = 1
                tmp = [0] * 128
                zero = [0] * 128
                fill_block(zero, zin, tmp, False)
                fill_block(zero, tmp, pseudo, False)
            start = 2 if (p_pass == 0 and s_slice == 0) else 0
            for idx in range(start, 2):
                col = s_slice * 2 + idx
                prev = (col + 7) % 8
                j12 = pseudo[idx] if use_index_indep else mem[prev][0]
                j1 = j12 & 0xFFFFFFFF
                if p_pass == 0:
                    pool = s_slice * 2 + idx - 1
                else:
                    pool = 8 - 2 + idx - (1 if idx == 0 else 0)
                x = (j1 * j1) >> 32
                y = (pool * x) >> 32
                rel = pool - 1 - y
                ref_start = 0 if p_pass == 0 else ((s_slice + 1) % 4) * 2
                ref_idx = (ref_start + rel) % 8
                fill_block(mem[prev], mem[ref_idx], mem[col], p_pass != 0)

    final_raw = struct.pack("<128Q", *mem[7])
    return blake2b_long(final_raw, tag_len)[:16]

def derive_snell_v4_key(psk: bytes, salt: bytes, tag_len: int = 32) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        kdf = Argon2id(salt=salt, length=tag_len, iterations=3, lanes=1, memory_cost=8)
        return kdf.derive(psk)[:16]
    except Exception:
        return derive_snell_v4_key_pure_python(psk, salt, tag_len)

def snell_swap_padding(data: bytes) -> bytes:
    out = bytearray(data)
    limit = len(out) & ~1
    for i in range(0, limit, 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return bytes(out)

def snell_advance_nonce(nonce: bytearray):
    for i in range(len(nonce)):
        nonce[i] = (nonce[i] + 1) & 0xFF
        if nonce[i] != 0:
            return

class SnellStream:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, psk: str):
        self.reader = reader
        self.writer = writer
        self.psk = psk.encode("utf-8")
        self.rx_key = None
        self.rx_nonce = bytearray(12)
        self.tx_key = None
        self.tx_nonce = bytearray(12)
        self.compat16 = None  # Auto-detected on first record: False = standard v4 (tag32+23B hdr), True = compat16 (tag16+18B hdr)
        self.plain_buf = bytearray()

    async def read_packet(self) -> bytes:
        if self.rx_key is None:
            salt = await self.reader.readexactly(16)
            first18 = await self.reader.readexactly(18)
            key32 = derive_snell_v4_key(self.psk, salt, 32)
            key16_pool7 = derive_snell_v4_key_pure_python(self.psk, salt, 16)
            key16_rfc = derive_snell_v4_key(self.psk, salt, 16)
            matched_k16 = None
            matched_pool7 = False
            plain_len_bytes = None
            for cand_key, is_pool7 in ((key16_pool7, True), (key16_rfc, False)):
                try:
                    plain_len_bytes = AESGCM(cand_key).decrypt(bytes(self.rx_nonce), first18, None)
                    matched_k16 = cand_key
                    matched_pool7 = is_pool7
                    break
                except Exception:
                    pass
            if matched_k16 is not None:
                self.rx_key = matched_k16
                self.compat16 = True
                self.use_pool7 = matched_pool7
                snell_advance_nonce(self.rx_nonce)
                chunk_len = struct.unpack(">H", plain_len_bytes)[0]
                if chunk_len == 0:
                    return b""
                enc_payload = await self.reader.readexactly(chunk_len + 16)
                payload = AESGCM(self.rx_key).decrypt(bytes(self.rx_nonce), enc_payload, None)
                snell_advance_nonce(self.rx_nonce)
                return payload
            else:
                rem5 = await self.reader.readexactly(5)
                enc_hdr23 = first18 + rem5
                hdr = AESGCM(key32).decrypt(bytes(self.rx_nonce), enc_hdr23, None)
                if len(hdr) != 7 or hdr[0] not in (4, 5, 6):
                    raise ValueError("Invalid Snell v4-v6 extended header")
                self.rx_key = key32
                self.compat16 = False
                self.use_pool7 = False
                snell_advance_nonce(self.rx_nonce)
                pad_len, chunk_len = struct.unpack(">HH", hdr[3:7])
                if pad_len > 0:
                    enc_pad = await self.reader.readexactly(pad_len + 16)
                    dec_pad = AESGCM(self.rx_key).decrypt(bytes(self.rx_nonce), enc_pad, None)
                    snell_advance_nonce(self.rx_nonce)
                    _ = snell_swap_padding(dec_pad)
                if chunk_len == 0:
                    return b""
                enc_payload = await self.reader.readexactly(chunk_len + 16)
                payload = AESGCM(self.rx_key).decrypt(bytes(self.rx_nonce), enc_payload, None)
                snell_advance_nonce(self.rx_nonce)
                return payload

        aesgcm = AESGCM(self.rx_key)
        if self.compat16:
            enc_len = await self.reader.readexactly(18)
            plain_len_bytes = aesgcm.decrypt(bytes(self.rx_nonce), enc_len, None)
            snell_advance_nonce(self.rx_nonce)
            chunk_len = struct.unpack(">H", plain_len_bytes)[0]
            if chunk_len == 0:
                return b""
            enc_payload = await self.reader.readexactly(chunk_len + 16)
            payload = aesgcm.decrypt(bytes(self.rx_nonce), enc_payload, None)
            snell_advance_nonce(self.rx_nonce)
            return payload
        else:
            enc_hdr = await self.reader.readexactly(23)
            hdr = aesgcm.decrypt(bytes(self.rx_nonce), enc_hdr, None)
            if len(hdr) != 7 or hdr[0] != 4:
                raise ValueError("Invalid Snell v4 extended header")
            snell_advance_nonce(self.rx_nonce)
            pad_len, chunk_len = struct.unpack(">HH", hdr[3:7])
            if pad_len > 0:
                enc_pad = await self.reader.readexactly(pad_len + 16)
                dec_pad = aesgcm.decrypt(bytes(self.rx_nonce), enc_pad, None)
                snell_advance_nonce(self.rx_nonce)
                _ = snell_swap_padding(dec_pad)
            if chunk_len == 0:
                return b""
            enc_payload = await self.reader.readexactly(chunk_len + 16)
            payload = aesgcm.decrypt(bytes(self.rx_nonce), enc_payload, None)
            snell_advance_nonce(self.rx_nonce)
            return payload

    async def read_exact_plain(self, n: int) -> bytes:
        while len(self.plain_buf) < n:
            pkt = await self.read_packet()
            if not pkt:
                raise EOFError("Snell stream EOF")
            self.plain_buf.extend(pkt)
        out = bytes(self.plain_buf[:n])
        del self.plain_buf[:n]
        return out

    async def write_packet(self, data: bytes):
        out = bytearray()
        use_compat16 = bool(self.compat16)
        if self.tx_key is None:
            salt = os.urandom(16)
            if use_compat16 and getattr(self, "use_pool7", False):
                self.tx_key = derive_snell_v4_key_pure_python(self.psk, salt, 16)
            else:
                self.tx_key = derive_snell_v4_key(self.psk, salt, 16 if use_compat16 else 32)
            out.extend(salt)
        aesgcm = AESGCM(self.tx_key)
        offset = 0
        if not data:
            if use_compat16:
                enc_len = aesgcm.encrypt(bytes(self.tx_nonce), b"\x00\x00", None)
                snell_advance_nonce(self.tx_nonce)
                out.extend(enc_len)
            else:
                hdr_plain = b"\x04\x00\x00\x00\x00\x00\x00"
                enc_hdr = aesgcm.encrypt(bytes(self.tx_nonce), hdr_plain, None)
                snell_advance_nonce(self.tx_nonce)
                out.extend(enc_hdr)
        while offset < len(data):
            chunk = data[offset:offset + 16384]
            offset += len(chunk)
            if use_compat16:
                enc_len = aesgcm.encrypt(bytes(self.tx_nonce), struct.pack(">H", len(chunk)), None)
                snell_advance_nonce(self.tx_nonce)
                enc_body = aesgcm.encrypt(bytes(self.tx_nonce), chunk, None)
                snell_advance_nonce(self.tx_nonce)
                out.extend(enc_len)
                out.extend(enc_body)
            else:
                hdr_plain = b"\x04\x00\x00\x00\x00" + struct.pack(">H", len(chunk))
                enc_hdr = aesgcm.encrypt(bytes(self.tx_nonce), hdr_plain, None)
                snell_advance_nonce(self.tx_nonce)
                enc_body = aesgcm.encrypt(bytes(self.tx_nonce), chunk, None)
                snell_advance_nonce(self.tx_nonce)
                out.extend(enc_hdr)
                out.extend(enc_body)
        self.writer.write(bytes(out))
        await self.writer.drain()

async def handle_snell(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, psk: str):
    ss = SnellStream(reader, writer, psk)
    try:
        hdr = await ss.read_exact_plain(3)
        if hdr[0] != 1:
            return
        cmd = hdr[1]
        cid_len = hdr[2]
        if cid_len > 0:
            await ss.read_exact_plain(cid_len)
        if cmd == 0:  # PING
            await ss.write_packet(b"\x01")
            return
        elif cmd in (1, 5):  # CONNECT / CONNECT v2
            hlen = (await ss.read_exact_plain(1))[0]
            host_Port = await ss.read_exact_plain(hlen + 2)
            host = host_Port[:hlen].decode("utf-8", errors="replace")
            port = struct.unpack(">H", host_Port[hlen:hlen + 2])[0]
            rem_r, rem_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
            await ss.write_packet(b"\x00")
            if ss.plain_buf:
                rem_w.write(bytes(ss.plain_buf))
                ss.plain_buf.clear()
                await rem_w.drain()

            async def c2s():
                try:
                    while True:
                        pkt = await ss.read_packet()
                        if not pkt:
                            break
                        rem_w.write(pkt)
                        await rem_w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        rem_w.close()
                    except Exception:
                        pass

            async def s2c():
                try:
                    while True:
                        chunk = await rem_r.read(16384)
                        if not chunk:
                            await ss.write_packet(b"")
                            break
                        await ss.write_packet(chunk)
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            await asyncio.gather(c2s(), s2c())
        elif cmd == 6:  # UDP (Snell v3/v4 UoT)
            await ss.write_packet(b"\x00")
            loop = asyncio.get_running_loop()
            relay = DualStackUDPRelay(loop)

            async def on_snell_udp(data: bytes, src_ip: str, src_port: int):
                reply = encode_snell_udp_addr(src_ip, src_port) + data
                await ss.write_packet(reply)

            rx_tasks = relay.start_rx_tasks(on_snell_udp)
            try:
                while True:
                    pkt = await ss.read_packet()
                    if not pkt or len(pkt) < 4:
                        break
                    ucmd = pkt[0]
                    if ucmd != 1:
                        continue
                    hlen = pkt[1]
                    if hlen > 0:
                        if len(pkt) < 2 + hlen + 2:
                            continue
                        dst_host = pkt[2:2 + hlen].decode("utf-8", errors="replace")
                        dst_port = struct.unpack(">H", pkt[2 + hlen:4 + hlen])[0]
                        payload = pkt[4 + hlen:]
                    else:
                        iver = pkt[2]
                        if iver == 4:
                            if len(pkt) < 9:
                                continue
                            dst_host = socket.inet_ntop(socket.AF_INET, pkt[3:7])
                            dst_port = struct.unpack(">H", pkt[7:9])[0]
                            payload = pkt[9:]
                        elif iver == 6:
                            if len(pkt) < 21:
                                continue
                            dst_host = socket.inet_ntop(socket.AF_INET6, pkt[3:19])
                            dst_port = struct.unpack(">H", pkt[19:21])[0]
                            payload = pkt[21:]
                        else:
                            continue
                    await relay.sendto(dst_host, dst_port, payload)
            finally:
                relay.close(rx_tasks)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ============================================================================
# 2. Sudoku v0.5.2 Server (O(1) 4x4 Puzzle + 6-bit PackedConn + RecordConn + KIP)
# ============================================================================

_GO_RNG_COOKED = [
    -4181792142133755926, -4576982950128230565, 1395769623340756751, 5333664234075297259,
    -6347679516498800754, 9033628115061424579, 7143218595135194537, 4812947590706362721,
    7937252194349799378, 5307299880338848416, 8209348851763925077, -7107630437535961764,
    4593015457530856296, 8140875735541888011, -5903942795589686782, -603556388664454774,
    -7496297993371156308, 113108499721038619, 4569519971459345583, -4160538177779461077,
    -6835753265595711384, -6507240692498089696, 6559392774825876886, 7650093201692370310,
    7684323884043752161, -8965504200858744418, -2629915517445760644, 271327514973697897,
    -6433985589514657524, 1065192797246149621, 3344507881999356393, -4763574095074709175,
    7465081662728599889, 1014950805555097187, -4773931307508785033, -5742262670416273165,
    2418672789110888383, 5796562887576294778, 4484266064449540171, 3738982361971787048,
    -4699774852342421385, 10530508058128498, -589538253572429690, -6598062107225984180,
    8660405965245884302, 10162832508971942, -2682657355892958417, 7031802312784620857,
    6240911277345944669, 831864355460801054, -1218937899312622917, 2116287251661052151,
    2202309800992166967, 9161020366945053561, 4069299552407763864, 4936383537992622449,
    457351505131524928, -8881176990926596454, -6375600354038175299, -7155351920868399290,
    4368649989588021065, 887231587095185257, -3659780529968199312, -2407146836602825512,
    5616972787034086048, -751562733459939242, 1686575021641186857, -5177887698780513806,
    -4979215821652996885, -1375154703071198421, 5632136521049761902, -8390088894796940536,
    -193645528485698615, -5979788902190688516, -4907000935050298721, -285522056888777828,
    -2776431630044341707, 1679342092332374735, 6050638460742422078, -2229851317345194226,
    -1582494184340482199, 5881353426285907985, 812786550756860885, 4541845584483343330,
    -6497901820577766722, 4980675660146853729, -4012602956251539747, -329088717864244987,
    -2896929232104691526, 1495812843684243920, -2153620458055647789, 7370257291860230865,
    -2466442761497833547, 4706794511633873654, -1398851569026877145, 8549875090542453214,
    -9189721207376179652, -7894453601103453165, 7297902601803624459, 1011190183918857495,
    -6985347000036920864, 5147159997473910359, -8326859945294252826, 2659470849286379941,
    6097729358393448602, -7491646050550022124, -5117116194870963097, -896216826133240300,
    -745860416168701406, 5803876044675762232, -787954255994554146, -3234519180203704564,
    -4507534739750823898, -1657200065590290694, 505808562678895611, -4153273856159712438,
    -8381261370078904295, 572156825025677802, 1791881013492340891, 3393267094866038768,
    -5444650186382539299, 2352769483186201278, -7930912453007408350, -325464993179687389,
    -3441562999710612272, -6489413242825283295, 5092019688680754699, -227247482082248967,
    4234737173186232084, 5027558287275472836, 4635198586344772304, -536033143587636457,
    5907508150730407386, -8438615781380831356, 972392927514829904, -3801314342046600696,
    -4064951393885491917, -174840358296132583, 2407211146698877100, -1640089820333676239,
    3940796514530962282, -5882197405809569433, 3095313889586102949, -1818050141166537098,
    5832080132947175283, 7890064875145919662, 8184139210799583195, -8073512175445549678,
    -7758774793014564506, -4581724029666783935, 3516491885471466898, -8267083515063118116,
    6657089965014657519, 5220884358887979358, 1796677326474620641, 5340761970648932916,
    1147977171614181568, 5066037465548252321, 2574765911837859848, 1085848279845204775,
    -5873264506986385449, 6116438694366558490, 2107701075971293812, -7420077970933506541,
    2469478054175558874, -1855128755834809824, -5431463669011098282, -9038325065738319171,
    -6966276280341336160, 7217693971077460129, -8314322083775271549, 7196649268545224266,
    -3585711691453906209, -5267827091426810625, 8057528650917418961, -5084103596553648165,
    -2601445448341207749, -7850010900052094367, 6527366231383600011, 3507654575162700890,
    9202058512774729859, 1954818376891585542, -2582991129724600103, 8299563319178235687,
    -5321504681635821435, 7046310742295574065, -2376176645520785576, -7650733936335907755,
    8850422670118399721, 3631909142291992901, 5158881091950831288, -6340413719511654215,
    4763258931815816403, 6280052734341785344, -4979582628649810958, 2043464728020827976,
    -2678071570832690343, 4562580375758598164, 5495451168795427352, -7485059175264624713,
    553004618757816492, 6895160632757959823, -989748114590090637, 7139506338801360852,
    -672480814466784139, 5535668688139305547, 2430933853350256242, -3821430778991574732,
    -1063731997747047009, -3065878205254005442, 7632066283658143750, 6308328381617103346,
    3681878764086140361, 3289686137190109749, 6587997200611086848, 244714774258135476,
    -5143583659437639708, 8090302575944624335, 2945117363431356361, -8359047641006034763,
    3009039260312620700, -793344576772241777, 401084700045993341, -1968749590416080887,
    4707864159563588614, -3583123505891281857, -3240864324164777915, -5908273794572565703,
    -3719524458082857382, -5281400669679581926, 8118566580304798074, 3839261274019871296,
    7062410411742090847, -8481991033874568140, 6027994129690250817, -6725542042704711878,
    -2971981702428546974, -7854441788951256975, 8809096399316380241, 6492004350391900708,
    2462145737463489636, -8818543617934476634, -5070345602623085213, -8961586321599299868,
    -3758656652254704451, -8630661632476012791, 6764129236657751224, -709716318315418359,
    -3403028373052861600, -8838073512170985897, -3999237033416576341, -2920240395515973663,
    -2073249475545404416, 368107899140673753, -6108185202296464250, -6307735683270494757,
    4782583894627718279, 6718292300699989587, 8387085186914375220, 3387513132024756289,
    4654329375432538231, -292704475491394206, -3848998599978456535, 7623042350483453954,
    7725442901813263321, 9186225467561587250, -5132344747257272453, -6865740430362196008,
    2530936820058611833, 1636551876240043639, -3658707362519810009, 1452244145334316253,
    -7161729655835084979, -7943791770359481772, 9108481583171221009, -3200093350120725999,
    5007630032676973346, 2153168792952589781, 6720334534964750538, -3181825545719981703,
    3433922409283786309, 2285479922797300912, 3110614940896576130, -2856812446131932915,
    -3804580617188639299, 7163298419643543757, 4891138053923696990, 580618510277907015,
    1684034065251686769, 4429514767357295841, -8893025458299325803, -8103734041042601133,
    7177515271653460134, 4589042248470800257, -1530083407795771245, 143607045258444228,
    246994305896273627, -8356954712051676521, 6473547110565816071, 3092379936208876896,
    2058427839513754051, -4089587328327907870, 8785882556301281247, -3074039370013608197,
    -637529855400303673, 6137678347805511274, -7152924852417805802, 5708223427705576541,
    -3223714144396531304, 4358391411789012426, 325123008708389849, 6837621693887290924,
    4843721905315627004, -3212720814705499393, -3825019837890901156, 4602025990114250980,
    1044646352569048800, 9106614159853161675, -8394115921626182539, -4304087667751778808,
    2681532557646850893, 3681559472488511871, -3915372517896561773, -2889241648411946534,
    -6564663803938238204, -8060058171802589521, 581945337509520675, 3648778920718647903,
    -4799698790548231394, -7602572252857820065, 220828013409515943, -1072987336855386047,
    4287360518296753003, -4633371852008891965, 5513660857261085186, -225854293646_200_1533,
    -8744380348503999773, 8746140185685648781, 228500091334420247, 1356187007457302238,
    3019253992034194581, 3152601605678500003, -8793219284148773595, 5559581553696971176,
    4916432985369275664, -8559797105120221417, -5802598197927043732, 2868348622579915573,
    -7224052902810357288, -5894682518218493085, 2587672709781371173, -7706116723325376475,
    3092343956317362483, -5561119517847711700, 972445599196498113, -1558506600978816441,
    1708913533482282562, -2305554874185907314, -6005743014309462908, -6653329009633068701,
    -483583197311151195, 2488075924621352812, -4529369641467339140, -4663743555056261452,
    2997203966153298104, 1282559373026354493, 240113143146674385, 8665713329246516443,
    628141331766346752, -4651421219668005332, -7750560848702540400, 7596648026010355826,
    -3132152619100351065, 7834161864828164065, 7103445518877254909, 4390861237357459201,
    -4780718172614204074, -319889632007444440, 622261699494173647, -3186110786557562560,
    -8718967088789066690, -1948156510637662747, -8212195255998774408, -7028621931231314745,
    2623071828615234808, -4066058308780939700, -5484966924888173764, -6683604512778046238,
    -6756087640505506466, 5256026990536851868, 7841086888628396109, 6640857538655893162,
    -8021284697816458310, -7109857044414059830, -1689021141511844405, -4298087301956291063,
    -4077748265377282003, -998231156719803476, 2719520354384050532, 9132346697815513771,
    4332154495710163773, -2085582442760428892, 6994721091344268833, -2556143461985726874,
    -8567931991128098309, 59934747298466858, -3098398008776739403, -265597256199410390,
    2332206071942466437, -7522315324568406181, 3154897383618636503, -7585605855467168281,
    -6762850759087199275, 197309393502684135, -8579694182469508493, 2543179307861934850,
    4350769010207485119, -4468719947444108136, -7207776534213261296, -1224312577878317200,
    4287946071480840813, 8362686366770308971, 6486469209321732151, -5605644191012979782,
    -1669018511020473564, 4450022655153542367, -7618176296641240059, -3896357471549267421,
    -4596796223304447488, -6531150016257070659, -8982326463137525940, -4125325062227681798,
    -1306489741394045544, -8338554946557245229, 5329160409530630596, 7790979528857726136,
    4955070238059373407, -4304834761432101506, -6215295852904371179, 3007769226071157901,
    -6753025801236972788, 8928702772696731736, 7856187920214445904, -4748497451462800923,
    7900176660600710914, -7082800908938549136, -6797926979589575837, -6737316883512927978,
    4186670094382025798, 1883939007446035042, -414705992779907823, 3734134241178479257,
    4065968871360089196, 6953124200385847784, -7917685222115876751, -7585632937840318161,
    -5567246375906782599, -5256612402221608788, 3106378204088556331, -2894472214076325998,
    4565385105440252958, 1979884289539493806, -6891578849933910383, 3783206694208922581,
    8464961209802336085, 2843963751609577687, 3030678195484896323, -4429654462759003204,
    4459239494808162889, 402587895800087237, 8057891408711167515, 4541888170938985079,
    1042662272908816815, -3666068979732206850, 2647678726283249984, 2144477441549833761,
    -3417019821499388721, -2105601033380872185, 5916597177708541638, -8760774321402454447,
    8833658097025758785, 5970273481425315300, 563813119381731307, -6455022486202078793,
    1598828206250873866, -4016978389451217698, -2988328551145513985, -6071154634840136312,
    8469693267274066490, 125672920241807416, -3912292412830714870, -2559617104544284221,
    -486523741806024092, -4735332261862713930, 5923302823487327109, -9082480245771672572,
    -1808429243461201518, 7990420780896957397, 4317817392807076702, 3625184369705367340,
    -6482649271566653105, -3480272027152017464, -3225473396345736649, -368878695502291645,
    -3981164001421868007, -8522033136963788610, 7609280429197514109, 3020985755112334161,
    -2572049329799262942, 2635195723621160615, 5144520864246028816, -8188285521126945980,
    1567242097116389047, 8172389260191636581, -2885551685425483535, -7060359469858316883,
    -6480181133964513127, -7317004403633452381, 6011544915663598137, 5932255307352610768,
    2241128460406315459, -8327867140638080220, 3094483003111372717, 4583857460292963101,
    9079887171656594975, -384082854924064405, -3460631649611717935, 4225072055348026230,
    -7385151438465742745, 3801620336801580414, -399845416774701952, -7446754431269675473,
    7899055018877642622, 5421679761463003041, 5521102963086275121, -4975092593295409910,
    8735487530905098534, -7462844945281082830, -2080886987197029914, -1000715163927557685,
    -4253840471931071485, -5828896094657903328, 6424174453260338141, 359248545074932887,
    -5949720754023045210, -2426265837057637212, 3030918217665093212, -9077771202237461772,
    -3186796180789149575, 740416251634527158, -2142944401404840226, 6951781370868335478,
    399922722363687927, -8928469722407522623, -1378421100515597285, -8343051178220066766,
    -3030716356046100229, -8811767350470065420, 9026808440365124461, 6440783557497587732,
    4615674634722404292, 539897290441580544, 2096238225866883852, 8751955639408182687,
    -7316147128802486205, 7381039757301768559, 6157238513393239656, -1473377804940618233,
    8629571604380892756, 5280433031239081479, 7101611890139813254, 2479018537985767835,
    7169176924412769570, -1281305539061572506, -7865612307799218120, 2278447439451174845,
    3625338785743880657, 6477479539006708521, 8976185375579272206, -3712000482142939688,
    1326024180520890843, 7537449876596048829, 5464680203499696154, 3189671183162196045,
    6346751753565857109, -8982212049534145501, -6127578587196093755, -245039190118465649,
    -6320577374581628592, 7208698530190629697, 7276901792339343736, -7490986807540332668,
    4133292154170828382, 2918308698224194548, -7703910638917631350, -3929437324238184044,
    -4300543082831323144, -6344160503358350167, 5896236396443472108, -758328221503023383,
    -1894351639983151068, -307900319840287220, -6278469401177312761, -2171292963361310674,
    8382142935188824023, 9103922860780351547, 4152330101494654406,
]

class GoRng:
    RNG_LEN = 607
    RNG_TAP = 273
    RNG_MASK = (1 << 63) - 1
    INT32_MAX = (1 << 31) - 1

    def __init__(self, seed: int):
        self.tap = 0
        self.feed = self.RNG_LEN - self.RNG_TAP
        self.vec = [0] * self.RNG_LEN
        if seed < 0:
            rem = -((-seed) % self.INT32_MAX)
        else:
            rem = seed % self.INT32_MAX
        if rem < 0:
            rem += self.INT32_MAX
        if rem == 0:
            rem = 89482311
        x = rem
        for i in range(-20, self.RNG_LEN):
            x = self._seedrand(x)
            if i >= 0:
                u = (x << 40) & 0xFFFFFFFFFFFFFFFF
                x = self._seedrand(x)
                u ^= (x << 20) & 0xFFFFFFFFFFFFFFFF
                x = self._seedrand(x)
                u ^= x & 0xFFFFFFFFFFFFFFFF
                u ^= (_GO_RNG_COOKED[i] & 0xFFFFFFFFFFFFFFFF)
                self.vec[i] = u

    @staticmethod
    def _seedrand(x: int) -> int:
        hi = x // 44488
        lo = x % 44488
        x = 48271 * lo - 3399 * hi
        if x < 0:
            x += (1 << 31) - 1
        return x

    def uint64_val(self) -> int:
        self.tap -= 1
        if self.tap < 0:
            self.tap += self.RNG_LEN
        self.feed -= 1
        if self.feed < 0:
            self.feed += self.RNG_LEN
        x = (self.vec[self.feed] + self.vec[self.tap]) & 0xFFFFFFFFFFFFFFFF
        self.vec[self.feed] = x
        return x

    def uint32_val(self) -> int:
        return ((self.uint64_val() & self.RNG_MASK) >> 31) & 0xFFFFFFFF

    def int31n(self, n: int) -> int:
        un = n & 0xFFFFFFFF
        v = self.uint32_val()
        prod = v * un
        low = prod & 0xFFFFFFFF
        if low < un:
            thresh = ((1 << 32) - un) % un
            while low < thresh:
                v = self.uint32_val()
                prod = v * un
                low = prod & 0xFFFFFFFF
        return (prod >> 32) & 0x7FFFFFFF

_ALL_SUDOKU_GRIDS = None

def get_all_sudoku_grids():
    global _ALL_SUDOKU_GRIDS
    if _ALL_SUDOKU_GRIDS is not None:
        return _ALL_SUDOKU_GRIDS
    res = []
    g = [0] * 16
    def dfs(idx: int):
        if idx == 16:
            res.append(tuple(g))
            return
        r, c = idx // 4, idx % 4
        br, bc = (r // 2) * 2, (c // 2) * 2
        for num in range(1, 5):
            ok = True
            for i in range(4):
                if g[r * 4 + i] == num or g[i * 4 + c] == num:
                    ok = False
                    break
            if ok:
                for i in range(2):
                    for j in range(2):
                        if g[(br + i) * 4 + (bc + j)] == num:
                            ok = False
                            break
            if ok:
                g[idx] = num
                dfs(idx + 1)
                g[idx] = 0
    dfs(0)
    _ALL_SUDOKU_GRIDS = res
    return res

class SudokuLayout:
    def __init__(self, prefer_ascii: bool, custom_pattern: str = ""):
        self.is_ascii = prefer_ascii
        self.is_custom = False
        self.x_mask = 0
        self.x_bits = [0, 0]
        self.p_bits = [0, 0]
        self.v_bits = [0, 0, 0, 0]
        self.group_to_byte = [0] * 64
        self.byte_to_group = [0xFF] * 256
        self.padding_pool = []

        if prefer_ascii:
            self._populate()
            self.padding_pool = [0x20 + i for i in range(32)]
        elif custom_pattern and len(custom_pattern) == 8:
            self.is_ascii = False
            self.is_custom = True
            xi = pi = vi = 0
            for i, ch in enumerate(custom_pattern):
                bit = 7 - i
                if ch == "x":
                    self.x_bits[xi] = bit
                    xi += 1
                elif ch == "p":
                    self.p_bits[pi] = bit
                    pi += 1
                elif ch == "v":
                    self.v_bits[vi] = bit
                    vi += 1
            self.x_mask = (1 << self.x_bits[0]) | (1 << self.x_bits[1])
            self._populate()
            seen = set()
            for drop in range(2):
                for val in range(4):
                    for pos in range(16):
                        if bin(pos).count("1") >= 2:
                            b = self.group_to_byte[(val << 4) | pos] & (~(1 << self.x_bits[drop]) & 0xFF)
                            if b not in seen:
                                seen.add(b)
                                self.padding_pool.append(b)
        else:
            self.is_ascii = False
            self._populate()
            for i in range(8):
                self.padding_pool.append(0x80 + i)
                self.padding_pool.append(0x10 + i)

    def _compute_group_byte(self, group: int) -> int:
        val = (group >> 4) & 0x03
        pos = group & 0x0F
        if self.is_ascii:
            b = 0x40 | (val << 4) | pos
            return 0x0A if b == 0x7F else b
        if self.is_custom:
            out = self.x_mask
            if val & 0x02:
                out |= 1 << self.p_bits[0]
            if val & 0x01:
                out |= 1 << self.p_bits[1]
            if pos & 0x08:
                out |= 1 << self.v_bits[0]
            if pos & 0x04:
                out |= 1 << self.v_bits[1]
            if pos & 0x02:
                out |= 1 << self.v_bits[2]
            if pos & 0x01:
                out |= 1 << self.v_bits[3]
            return out
        return (val << 5) | pos

    def _populate(self):
        for g in range(64):
            b = self._compute_group_byte(g)
            self.group_to_byte[g] = b
            self.byte_to_group[b] = g

    def encode_hint(self, val: int, pos: int) -> int:
        return self.group_to_byte[((val & 0x03) << 4) | (pos & 0x0F)]

class SudokuTable:
    def __init__(self, master_key: str, prefer_ascii: bool, custom_pattern: str = ""):
        self.layout = SudokuLayout(prefer_ascii, custom_pattern)
        digest = hashlib.sha256(master_key.encode("utf-8")).digest()
        seed = struct.unpack(">q", digest[:8])[0]
        rng = GoRng(seed)
        shuffled = list(get_all_sudoku_grids())
        for i in range(len(shuffled) - 1, 0, -1):
            j = rng.int31n(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

        self.hint_sets = [0] * 64
        for b, g in enumerate(shuffled):
            bit = 1 << b
            for pos in range(16):
                val = g[pos] - 1
                self.hint_sets[(val << 4) | pos] |= bit

        mask_256 = (1 << 256) - 1
        high_32 = ((1 << 288) - 1) ^ mask_256
        self.encode_table = [[] for _ in range(256)]
        for b in range(256):
            g = shuffled[b]
            for p0 in range(13):
                s0 = self.hint_sets[((g[p0] - 1) << 4) | p0]
                for p1 in range(p0 + 1, 14):
                    s01 = s0 & self.hint_sets[((g[p1] - 1) << 4) | p1]
                    if not s01:
                        continue
                    for p2 in range(p1 + 1, 15):
                        s012 = s01 & self.hint_sets[((g[p2] - 1) << 4) | p2]
                        if not s012:
                            continue
                        for p3 in range(p2 + 1, 16):
                            s0123 = s012 & self.hint_sets[((g[p3] - 1) << 4) | p3]
                            if (s0123 & high_32) != 0:
                                continue
                            low = s0123 & mask_256
                            if low and (low & (low - 1)) == 0:
                                self.encode_table[b].append((
                                    self.layout.encode_hint(g[p0] - 1, p0),
                                    self.layout.encode_hint(g[p1] - 1, p1),
                                    self.layout.encode_hint(g[p2] - 1, p2),
                                    self.layout.encode_hint(g[p3] - 1, p3),
                                ))

    def solve_4_hints(self, h0: int, h1: int, h2: int, h3: int) -> int:
        g0 = self.layout.byte_to_group[h0]
        g1 = self.layout.byte_to_group[h1]
        g2 = self.layout.byte_to_group[h2]
        g3 = self.layout.byte_to_group[h3]
        if g0 >= 64 or g1 >= 64 or g2 >= 64 or g3 >= 64:
            raise ValueError("Invalid Sudoku hint byte")
        inter = self.hint_sets[g0] & self.hint_sets[g1] & self.hint_sets[g2] & self.hint_sets[g3]
        if inter <= 0 or inter >= (1 << 256) or (inter & (inter - 1)) != 0:
            raise ValueError("Ambiguous or invalid Sudoku 4-hint group")
        return inter.bit_length() - 1

    def encode_pure_bytes(self, data: bytes, pad_min: int = 2, pad_max: int = 7) -> bytes:
        out = bytearray()
        pool = self.layout.padding_pool
        for b in data:
            puzzles = self.encode_table[b]
            clues = list(random.choice(puzzles))
            random.shuffle(clues)
            for c in clues:
                if pad_max > 0 and pool and random.randint(0, 99) < random.randint(pad_min, pad_max):
                    out.append(random.choice(pool))
                out.append(c)
        if pad_max > 0 and pool and random.randint(0, 99) < random.randint(pad_min, pad_max):
            out.append(random.choice(pool))
        return bytes(out)

    def encode_packed_6bit(self, data: bytes, pad_min: int = 2, pad_max: int = 7) -> bytes:
        out = bytearray()
        pool = self.layout.padding_pool
        pad_marker = pool[0] if pool else 0x80
        other_pads = pool[1:] if len(pool) > 1 else []
        acc = 0
        bits = 0
        for b in data:
            acc = (acc << 8) | b
            bits += 8
            while bits >= 6:
                bits -= 6
                if pad_max > 0 and other_pads and random.randint(0, 99) < random.randint(pad_min, pad_max):
                    out.append(random.choice(other_pads))
                grp = (acc >> bits) & 0x3F
                out.append(self.layout.group_to_byte[grp])
        if bits > 0:
            grp = (acc << (6 - bits)) & 0x3F
            out.append(self.layout.group_to_byte[grp])
            out.append(pad_marker)
        return bytes(out)

_SUDOKU_TABLE_CACHE = {}

def get_sudoku_table(master_key: str, prefer_ascii: bool, custom_pattern: str = "") -> SudokuTable:
    k = (master_key, prefer_ascii, custom_pattern if not prefer_ascii else "")
    if k not in _SUDOKU_TABLE_CACHE:
        _SUDOKU_TABLE_CACHE[k] = SudokuTable(master_key, prefer_ascii, custom_pattern if not prefer_ascii else "")
    return _SUDOKU_TABLE_CACHE[k]

def sudoku_recover_master_public_key(key_hex: str):
    trimmed = key_hex.strip()
    try:
        raw = bytes.fromhex(trimmed)
    except ValueError:
        raw = b""
    if len(raw) not in (32, 64):
        kb = trimmed.encode("utf-8")
        return trimmed, hashlib.sha256(kb).digest()[:8]
    user_hash8 = hashlib.sha256(raw).digest()[:8]
    L = (1 << 252) + 27742317777372353535851937790883648493
    if len(raw) == 64:
        r = int.from_bytes(raw[:32], "little")
        k = int.from_bytes(raw[32:], "little")
        if r >= L or k >= L:
            return trimmed.lower(), user_hash8
        x = (r + k) % L
    else:
        x = int.from_bytes(raw, "little")
        if x >= L or x == 0:
            return trimmed.lower(), user_hash8
    if x == 0:
        return trimmed.lower(), user_hash8

    p = (1 << 255) - 19
    d = (-121665 * pow(121666, p - 2, p)) % p
    d2 = (2 * d) % p
    Bx = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    By = 0x6666666666666666666666666666666666666666666666666666666666666658

    def ed_add(P, Q):
        X1, Y1, Z1, T1 = P
        X2, Y2, Z2, T2 = Q
        A = ((Y1 - X1) * (Y2 - X2)) % p
        B = ((Y1 + X1) * (Y2 + X2)) % p
        C = (d2 * T1 * T2) % p
        D = (2 * Z1 * Z2) % p
        E = (B - A) % p
        F = (D - C) % p
        G = (D + C) % p
        H = (B + A) % p
        return ((E * F) % p, (G * H) % p, (F * G) % p, (E * H) % p)

    res = (0, 1, 1, 0)
    base = (Bx, By, 1, (Bx * By) % p)
    val = x
    while val > 0:
        if val & 1:
            res = ed_add(res, base)
        base = ed_add(base, base)
        val >>= 1

    zi = pow(res[2], p - 2, p)
    aff_x = (res[0] * zi) % p
    aff_y = (res[1] * zi) % p
    pub = bytearray(aff_y.to_bytes(32, "little"))
    if aff_x & 1:
        pub[31] |= 0x80
    return bytes(pub).hex(), user_hash8

def hkdf_expand_sha256(prk: bytes, info: bytes, out_len: int) -> bytes:
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < out_len:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:out_len])

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hkdf_expand_sha256(prk, info, out_len)

def derive_sudoku_epoch_key(base_key32: bytes, aead_method: str, epoch: int) -> bytes:
    msg = f"sudoku-record:{aead_method}".encode("utf-8") + struct.pack(">I", epoch)
    mac = hmac.new(base_key32, msg, hashlib.sha256).digest()
    return mac[:16] if aead_method == "aes-128-gcm" else mac[:32]

class SudokuServerSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 master_pub_key: str, aead_method: str, up_table: SudokuTable, down_table: SudokuTable,
                 pure_downlink: bool, pad_min: int = 2, pad_max: int = 7):
        self.reader = reader
        self.writer = writer
        self.master_pub_key = master_pub_key
        self.aead_method = aead_method
        self.up_table = up_table
        self.down_table = down_table
        self.pure_downlink = pure_downlink
        self.pad_min = pad_min
        self.pad_max = pad_max

        sum_key = hashlib.sha256(master_pub_key.encode("utf-8")).digest()
        self.rx_base = hkdf_expand_sha256(sum_key, b"sudoku-psk-c2s", 32)
        self.tx_base = hkdf_expand_sha256(sum_key, b"sudoku-psk-s2c", 32)
        self.send_epoch = 1
        self.send_seq = 1
        self.http_mask_stripped = False
        self.raw_buf = bytearray()
        self.hint_buf = []
        self.decoded_buf = bytearray()
        self.plain_buf = bytearray()

    def rekey_session(self, shared32: bytes, client_nonce16: bytes):
        salt = hashlib.sha256(self.master_pub_key.encode("utf-8")).digest()
        ikm = shared32 + client_nonce16
        self.rx_base = hkdf_sha256(ikm, salt, b"sudoku-session-c2s", 32)
        self.tx_base = hkdf_sha256(ikm, salt, b"sudoku-session-s2c", 32)
        self.send_epoch = 2
        self.send_seq = 1

    async def _ensure_decoded(self, needed: int):
        while len(self.decoded_buf) < needed:
            chunk = await self.reader.read(16384)
            if not chunk:
                raise EOFError("Sudoku client closed connection")
            if not self.http_mask_stripped:
                self.raw_buf.extend(chunk)
                if len(self.raw_buf) >= 4 and not bytes(self.raw_buf[:4]).upper().startswith((b"POST", b"GET ", b"PUT ", b"HEAD")):
                    self.http_mask_stripped = True
                    to_feed = bytes(self.raw_buf)
                    self.raw_buf.clear()
                else:
                    idx = self.raw_buf.find(b"\r\n\r\n")
                    if idx != -1:
                        self.http_mask_stripped = True
                        to_feed = bytes(self.raw_buf[idx + 4:])
                        self.raw_buf.clear()
                        # Send HTTP 200 OK mask response immediately
                        self.writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\n\r\n")
                        await self.writer.drain()
                    else:
                        continue
            else:
                to_feed = chunk

            for b in to_feed:
                if self.up_table.layout.byte_to_group[b] >= 64:
                    continue
                self.hint_buf.append(b)
                if len(self.hint_buf) == 4:
                    val = self.up_table.solve_4_hints(
                        self.hint_buf[0], self.hint_buf[1], self.hint_buf[2], self.hint_buf[3]
                    )
                    self.decoded_buf.append(val)
                    self.hint_buf.clear()

    async def read_record(self) -> bytes:
        await self._ensure_decoded(2)
        body_len = struct.unpack(">H", self.decoded_buf[:2])[0]
        await self._ensure_decoded(2 + body_len)
        body = bytes(self.decoded_buf[2:2 + body_len])
        del self.decoded_buf[:2 + body_len]
        if self.aead_method == "none":
            return body
        hdr = body[:12]
        cipher = body[12:]
        epoch = struct.unpack(">I", hdr[:4])[0]
        key = derive_sudoku_epoch_key(self.rx_base, self.aead_method, epoch)
        if self.aead_method == "aes-128-gcm":
            return AESGCM(key).decrypt(hdr, cipher, hdr)
        return ChaCha20Poly1305(key).decrypt(hdr, cipher, hdr)

    async def ensure_plain(self, needed: int):
        while len(self.plain_buf) < needed:
            rec = await self.read_record()
            self.plain_buf.extend(rec)

    async def read_plain_exact(self, n: int) -> bytes:
        await self.ensure_plain(n)
        out = bytes(self.plain_buf[:n])
        del self.plain_buf[:n]
        return out

    async def read_plain_some(self, max_len: int = 16384) -> bytes:
        if not self.plain_buf:
            rec = await self.read_record()
            self.plain_buf.extend(rec)
        out = bytes(self.plain_buf[:max_len])
        del self.plain_buf[:len(out)]
        return out

    async def read_kip_message(self):
        while True:
            hdr = await self.read_plain_exact(6)
            if hdr[:3] != b"kip":
                raise ValueError(f"Invalid KIP magic: {hdr[:3]!r}")
            msg_type = hdr[3]
            pay_len = struct.unpack(">H", hdr[4:6])[0]
            payload = await self.read_plain_exact(pay_len)
            if msg_type == 0x14:  # KeepAlive
                continue
            return msg_type, payload

    def _seal_record(self, plain: bytes) -> bytes:
        if self.aead_method == "none":
            return struct.pack(">H", len(plain)) + plain
        epoch = self.send_epoch
        seq = self.send_seq
        self.send_seq += 1
        hdr = struct.pack(">IQ", epoch, seq)
        key = derive_sudoku_epoch_key(self.tx_base, self.aead_method, epoch)
        if self.aead_method == "aes-128-gcm":
            cipher = AESGCM(key).encrypt(hdr, plain, hdr)
        else:
            cipher = ChaCha20Poly1305(key).encrypt(hdr, plain, hdr)
        body = hdr + cipher
        return struct.pack(">H", len(body)) + body

    async def write_plain(self, data: bytes):
        out = bytearray()
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 16384]
            offset += len(chunk)
            rec = self._seal_record(chunk)
            if self.pure_downlink:
                out.extend(self.down_table.encode_pure_bytes(rec, self.pad_min, self.pad_max))
            else:
                out.extend(self.down_table.encode_packed_6bit(rec, self.pad_min, self.pad_max))
        self.writer.write(bytes(out))
        await self.writer.drain()

async def handle_sudoku(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, profile: dict):
    master_pub, _ = sudoku_recover_master_public_key(profile["key"])
    t_type = profile.get("table_type", "prefer_ascii")
    custom_tbl = profile.get("custom_table", "")
    up_ascii = t_type in ("prefer_ascii", "up_ascii_down_entropy")
    down_ascii = t_type in ("prefer_ascii", "up_entropy_down_ascii")
    up_table = get_sudoku_table(master_pub, up_ascii, "" if up_ascii else custom_tbl)
    down_table = get_sudoku_table(master_pub, down_ascii, "" if down_ascii else custom_tbl)
    sess = SudokuServerSession(
        reader, writer, master_pub,
        aead_method=profile.get("aead_method", "chacha20-poly1305"),
        up_table=up_table, down_table=down_table,
        pure_downlink=profile.get("enable_pure_downlink", True),
        pad_min=profile.get("padding_min", 2),
        pad_max=profile.get("padding_max", 7),
    )
    try:
        msg_type, ch_payload = await asyncio.wait_for(sess.read_kip_message(), timeout=10.0)
        if msg_type != 0x01 or len(ch_payload) < 64:
            return
        client_nonce16 = ch_payload[16:32]
        client_pub32 = ch_payload[32:64]

        srv_priv = X25519PrivateKey.generate()
        srv_pub32 = srv_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        shared32 = srv_priv.exchange(X25519PublicKey.from_public_bytes(client_pub32))

        sh_payload = client_nonce16 + srv_pub32 + struct.pack(">I", 0x1F)
        sh_kip = b"kip\x02" + struct.pack(">H", len(sh_payload)) + sh_payload
        await sess.write_plain(sh_kip)

        sess.rekey_session(shared32, client_nonce16)

        cmd_type, cmd_payload = await asyncio.wait_for(sess.read_kip_message(), timeout=10.0)
        if cmd_type == 0x10:  # OpenTCP
            dst_host, dst_port, _ = parse_socks_addr(cmd_payload, 0)
            rem_r, rem_w = await asyncio.wait_for(asyncio.open_connection(dst_host, dst_port), timeout=10.0)
            if sess.plain_buf:
                rem_w.write(bytes(sess.plain_buf))
                sess.plain_buf.clear()
                await rem_w.drain()

            async def c2s():
                try:
                    while True:
                        data = await sess.read_plain_some(16384)
                        if not data:
                            break
                        rem_w.write(data)
                        await rem_w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        rem_w.close()
                    except Exception:
                        pass

            async def s2c():
                try:
                    while True:
                        data = await rem_r.read(16384)
                        if not data:
                            break
                        await sess.write_plain(data)
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            await asyncio.gather(c2s(), s2c())
        elif cmd_type == 0x12:  # StartUoT
            loop = asyncio.get_running_loop()
            relay = DualStackUDPRelay(loop)

            async def on_sudoku_udp(data: bytes, src_ip: str, src_port: int):
                saddr = encode_socks_addr(src_ip, src_port)
                pkt = struct.pack(">HH", len(saddr), len(data)) + saddr + data
                await sess.write_plain(pkt)

            rx_tasks = relay.start_rx_tasks(on_sudoku_udp)
            try:
                while True:
                    hdr = await sess.read_plain_exact(4)
                    addr_len, pay_len = struct.unpack(">HH", hdr)
                    body = await sess.read_plain_exact(addr_len + pay_len)
                    dst_host, dst_port, _ = parse_socks_addr(body[:addr_len], 0)
                    payload = body[addr_len:]
                    await relay.sendto(dst_host, dst_port, payload)
            finally:
                relay.close(rx_tasks)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ============================================================================
# 3. TrustTunnel HTTPS CONNECT & UDP-over-Stream Server
# ============================================================================

async def handle_trusttunnel(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             expected_user: str, expected_pass: str):
    try:
        raw_hdr = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        lines = raw_hdr.decode("latin1").split("\r\n")
        if not lines or not lines[0].upper().startswith("CONNECT "):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        authority = lines[0].split(" ")[1]
        expected_b64 = base64.b64encode(f"{expected_user}:{expected_pass}".encode()).decode()
        authed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                val = line.split(":", 1)[1].strip()
                if val == f"Basic {expected_b64}":
                    authed = True
                    break
        if not authed:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            await writer.drain()
            return

        if authority.startswith("_trusttunnel_udp_"):
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            loop = asyncio.get_running_loop()
            relay = DualStackUDPRelay(loop)

            async def on_tt_udp(data: bytes, src_ip: str, src_port: int):
                saddr = encode_socks_addr(src_ip, src_port)
                pkt = struct.pack(">HH", len(saddr), len(data)) + saddr + data
                writer.write(pkt)
                await writer.drain()

            rx_tasks = relay.start_rx_tasks(on_tt_udp)
            try:
                while True:
                    hdr = await reader.readexactly(4)
                    addr_len, pay_len = struct.unpack(">HH", hdr)
                    body = await reader.readexactly(addr_len + pay_len)
                    dst_host, dst_port, _ = parse_socks_addr(body[:addr_len], 0)
                    payload = body[addr_len:]
                    await relay.sendto(dst_host, dst_port, payload)
            finally:
                relay.close(rx_tasks)
        else:
            if authority.startswith("["):
                idx = authority.rfind("]:")
                host = authority[1:idx]
                port = int(authority[idx + 2:])
            else:
                host, port_s = authority.rsplit(":", 1)
                port = int(port_s)
            rem_r, rem_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(pipe_HalfClose(reader, rem_w), pipe_HalfClose(rem_r, writer))
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ============================================================================
# 4. SOCKS5-TLS Server (TCP CONNECT + UDP ASSOCIATE)
# ============================================================================

class Socks5UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        self.client_addr = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 4:
            return
        if self.client_addr is None or addr == self.client_addr:
            if data[0] != 0 or data[1] != 0 or data[2] != 0:
                return
            self.client_addr = addr
            try:
                dst_host, dst_port, off = parse_socks_addr(data, 3)
                payload = data[off:]
                asyncio.create_task(self._forward_to_target(dst_host, dst_port, payload))
            except Exception:
                pass
        else:
            saddr = encode_socks_addr(addr[0], addr[1])
            self.transport.sendto(b"\x00\x00\x00" + saddr + data, self.client_addr)

    async def _forward_to_target(self, dst_host: str, dst_port: int, payload: bytes):
        try:
            _, sockaddr = await resolve_udp_destination(dst_host, dst_port)
            self.transport.sendto(payload, sockaddr)
        except Exception:
            pass

async def handle_socks5_tls(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            expected_user: str, expected_pass: str, public_ip: str, public_ipv6: str = ""):
    try:
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        if hdr[0] != 5:
            return
        methods = await reader.readexactly(hdr[1])
        if 2 in methods:
            writer.write(b"\x05\x02")
            await writer.drain()
            ver = (await reader.readexactly(1))[0]
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")
            plen = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(plen)).decode("utf-8", errors="replace")
            if ver != 1 or user != expected_user or pw != expected_pass:
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        elif 0 in methods:
            writer.write(b"\x05\x00")
            await writer.drain()
        else:
            writer.write(b"\x05\xff")
            await writer.drain()
            return

        req = await reader.readexactly(4)
        cmd, atyp = req[1], req[3]
        if atyp == 1:
            raw_addr = await reader.readexactly(6)
            host, port, _ = parse_socks_addr(b"\x01" + raw_addr, 0)
        elif atyp == 3:
            dlen = (await reader.readexactly(1))[0]
            raw_addr = await reader.readexactly(dlen + 2)
            host, port, _ = parse_socks_addr(b"\x03" + bytes([dlen]) + raw_addr, 0)
        elif atyp == 4:
            raw_addr = await reader.readexactly(18)
            host, port, _ = parse_socks_addr(b"\x04" + raw_addr, 0)
        else:
            return

        if cmd == 1:  # CONNECT
            rem_r, rem_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await asyncio.gather(pipe_HalfClose(reader, rem_w), pipe_HalfClose(rem_r, writer))
        elif cmd == 3:  # UDP ASSOCIATE
            loop = asyncio.get_running_loop()
            sockname = writer.get_extra_info("sockname")
            local_ip = normalize_ip_literal(sockname[0]) if sockname else ""
            is_v6_ctrl = (":" in local_ip)
            bind_udp_addr = ("::", 0) if is_v6_ctrl else ("0.0.0.0", 0)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: Socks5UDPProtocol(loop), local_addr=bind_udp_addr
            )
            udp_port = transport.get_extra_info("sockname")[1]
            adv_ip = (public_ipv6 or local_ip or public_ip) if is_v6_ctrl else public_ip
            bnd = encode_socks_addr(adv_ip, udp_port)
            writer.write(b"\x05\x00\x00" + bnd)
            await writer.drain()
            try:
                while await reader.read(1024):
                    pass
            finally:
                transport.close()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

# ============================================================================
# 5. ShadowsocksR (SSR) origin + plain + aes-128-cfb (TCP & UDP)
# ============================================================================

def evp_bytes_to_key(password: bytes, key_len: int) -> bytes:
    m = []
    d = b""
    while len(b"".join(m)) < key_len:
        d = hashlib.md5(d + password).digest()
        m.append(d)
    return b"".join(m)[:key_len]

async def handle_ssr_origin(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, password: str):
    key = evp_bytes_to_key(password.encode("utf-8"), 16)
    try:
        iv_in = await asyncio.wait_for(reader.readexactly(16), timeout=10.0)
        dec = Cipher(algorithms.AES(key), modes.CFB(iv_in)).decryptor()
        first = dec.update(await reader.readexactly(1))
        atyp = first[0]
        if atyp == 1:
            rest = dec.update(await reader.readexactly(6))
            host, port, _ = parse_socks_addr(first + rest, 0)
        elif atyp == 3:
            dlen_b = dec.update(await reader.readexactly(1))
            rest = dec.update(await reader.readexactly(dlen_b[0] + 2))
            host, port, _ = parse_socks_addr(first + dlen_b + rest, 0)
        elif atyp == 4:
            rest = dec.update(await reader.readexactly(18))
            host, port, _ = parse_socks_addr(first + rest, 0)
        else:
            return

        rem_r, rem_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
        iv_out = os.urandom(16)
        enc = Cipher(algorithms.AES(key), modes.CFB(iv_out)).encryptor()
        sent_iv = False

        async def c2s():
            try:
                while True:
                    chunk = await reader.read(32768)
                    if not chunk:
                        break
                    rem_w.write(dec.update(chunk))
                    await rem_w.drain()
            except Exception:
                pass
            finally:
                try:
                    rem_w.close()
                except Exception:
                    pass

        async def s2c():
            nonlocal sent_iv
            try:
                while True:
                    chunk = await rem_r.read(32768)
                    if not chunk:
                        break
                    out = enc.update(chunk)
                    if not sent_iv:
                        sent_iv = True
                        out = iv_out + out
                    writer.write(out)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(c2s(), s2c())
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

class SSRUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, password: str):
        self.key = evp_bytes_to_key(password.encode("utf-8"), 16)
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, client_addr):
        if len(data) <= 16:
            return
        try:
            iv = data[:16]
            dec = Cipher(algorithms.AES(self.key), modes.CFB(iv)).decryptor()
            plain = dec.update(data[16:]) + dec.finalize()
            dst_host, dst_port, off = parse_socks_addr(plain, 0)
            payload = plain[off:]
            asyncio.create_task(self._relay_udp(dst_host, dst_port, payload, client_addr))
        except Exception:
            pass

    async def _relay_udp(self, dst_host: str, dst_port: int, payload: bytes, client_addr):
        loop = asyncio.get_running_loop()
        sock = None
        try:
            family, sockaddr = await resolve_udp_destination(dst_host, dst_port)
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)
            await loop.sock_sendto(sock, payload, sockaddr)
            reply, raddr = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout=8.0)
            saddr = encode_socks_addr(raddr[0], raddr[1])
            iv_out = os.urandom(16)
            enc = Cipher(algorithms.AES(self.key), modes.CFB(iv_out)).encryptor()
            wire = iv_out + enc.update(saddr + reply) + enc.finalize()
            self.transport.sendto(wire, client_addr)
        except Exception:
            pass
        finally:
            if sock is not None:
                sock.close()

# ============================================================================
# Main Daemon Entrypoint
# ============================================================================

async def start_dual_stack_tcp_server(client_cb, bind_host: str, port: int, ssl_ctx=None):
    if bind_host in ("::", ""):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::", port))
            sock.listen(512)
            sock.setblocking(False)
            return await asyncio.start_server(client_cb, sock=sock, ssl=ssl_ctx)
        except OSError:
            return await asyncio.start_server(client_cb, host="0.0.0.0", port=port, ssl=ssl_ctx)
    return await asyncio.start_server(client_cb, host=bind_host, port=port, ssl=ssl_ctx)

async def start_dual_stack_udp_endpoint(protocol_factory, bind_host: str, port: int):
    loop = asyncio.get_running_loop()
    if bind_host in ("::", ""):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::", port))
            sock.setblocking(False)
            return await loop.create_datagram_endpoint(protocol_factory, sock=sock)
        except OSError:
            return await loop.create_datagram_endpoint(protocol_factory, local_addr=("0.0.0.0", port))
    return await loop.create_datagram_endpoint(protocol_factory, local_addr=(bind_host, port))

async def main():
    with open("/opt/hajimi-test/extra-config.json", "r", encoding="utf-8") as f:
        cfg = json.load(f)

    bind_host = cfg.get("bind_host", "::")
    public_ipv6 = cfg.get("public_ipv6", "")

    tls_tt = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_tt.load_cert_chain(cfg["cert"], cfg["key"])
    tls_tt.set_alpn_protocols(["http/1.1", "h2"])

    tls_s5 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_s5.load_cert_chain(cfg["cert"], cfg["key"])

    # Pre-warm Sudoku tables before accepting connections
    for s_prof in cfg.get("sudoku_profiles", []):
        mpub, _ = sudoku_recover_master_public_key(s_prof["key"])
        t_type = s_prof.get("table_type", "prefer_ascii")
        ctbl = s_prof.get("custom_table", "")
        get_sudoku_table(mpub, t_type in ("prefer_ascii", "up_ascii_down_entropy"), ctbl)
        get_sudoku_table(mpub, t_type in ("prefer_ascii", "up_entropy_down_ascii"), ctbl)

    s_snell = await start_dual_stack_tcp_server(
        lambda r, w: handle_snell(r, w, cfg["snell_psk"]),
        bind_host, cfg["snell_port"]
    )
    s_tt = await start_dual_stack_tcp_server(
        lambda r, w: handle_trusttunnel(r, w, cfg["tt_user"], cfg["tt_pass"]),
        bind_host, cfg["tt_port"], ssl_ctx=tls_tt
    )
    s_s5tls = await start_dual_stack_tcp_server(
        lambda r, w: handle_socks5_tls(r, w, cfg["s5_user"], cfg["s5_pass"], cfg["public_ip"], public_ipv6),
        bind_host, cfg["s5tls_port"], ssl_ctx=tls_s5
    )
    s_ssr = await start_dual_stack_tcp_server(
        lambda r, w: handle_ssr_origin(r, w, cfg["ssr_pass"]),
        bind_host, cfg["ssr_port"]
    )

    await start_dual_stack_udp_endpoint(
        lambda: SSRUDPProtocol(cfg["ssr_pass"]),
        bind_host, cfg["ssr_port"]
    )

    sudoku_servers = []
    for s_prof in cfg.get("sudoku_profiles", []):
        srv = await start_dual_stack_tcp_server(
            lambda r, w, p=s_prof: handle_sudoku(r, w, p),
            bind_host, s_prof["port"]
        )
        sudoku_servers.append(srv)

    all_servers = [s_snell, s_tt, s_s5tls, s_ssr] + sudoku_servers
    for srv in all_servers:
        await srv.start_serving()

    print("hajimi-extra servers started successfully on all ports", flush=True)
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())

PYEOF

    chmod 755 "${BIN_DIR}/hajimi_extra_servers.py"

    cat >/etc/systemd/system/hajimi-extra.service <<EOF
[Unit]
Description=Hajimi Extra Protocol Servers (Snell v4 / Sudoku v0.5.2 / TrustTunnel / SOCKS5-TLS / SSR-Origin)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${BIN_DIR}/hajimi_extra_servers.py
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now hajimi-extra.service
    systemctl restart hajimi-extra.service
    log_ok "hajimi-extra.service 已启动 (Snell v4:20003, Sudoku-UoT:20012, Sudoku-Entropy:20029, TrustTunnel:20018, SOCKS5-TLS:20019, SSR:20020)"
}

configure_wireguard_service() {
    log_info "正在配置 WireGuard 服务端 (UDP: 51820)..."
    mkdir -p /etc/wireguard
    cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 100.64.0.1/24, fd00:6861:6a69:66::1/64
ListenPort = 51820
PrivateKey = ${WG_SERVER_PRIV}
MTU = 1420
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 100.64.0.0/24 -o ${DEFAULT_IFACE} -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; ip6tables -A FORWARD -o wg0 -j ACCEPT 2>/dev/null || true; ip6tables -t nat -A POSTROUTING -s fd00:6861:6a69:66::/64 -o ${DEFAULT_IFACE} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 100.64.0.0/24 -o ${DEFAULT_IFACE} -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; ip6tables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true; ip6tables -t nat -D POSTROUTING -s fd00:6861:6a69:66::/64 -o ${DEFAULT_IFACE} -j MASQUERADE 2>/dev/null || true

[Peer]
PublicKey = ${WG_CLIENT_PUB}
PresharedKey = ${WG_PSK}
AllowedIPs = 100.64.0.2/32, fd00:6861:6a69:66::2/128
EOF
    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable --now wg-quick@wg0 2>/dev/null || wg-quick up wg0 2>/dev/null || log_warn "WireGuard 启动失败 (若 VPS 为 OpenVZ/LXC 容器需宿主机开启 tun/wireguard 模块)"
    log_ok "WireGuard 配置完成 (UDP: 51820)"
}

configure_ssh_test_account() {
    log_info "正在配置 SSH 专用隧道测试账号 (${SSH_TUNNEL_USER}, 支持密码与 Ed25519 私钥)..."
    if ! id "${SSH_TUNNEL_USER}" &>/dev/null; then
        useradd -m -s /bin/sh ${SSH_TUNNEL_USER}
    else
        usermod -s /bin/sh ${SSH_TUNNEL_USER} 2>/dev/null || true
    fi
    echo "${SSH_TUNNEL_USER}:${COMMON_PASS}" | chpasswd

    local ssh_dir="/home/${SSH_TUNNEL_USER}/.ssh"
    mkdir -p "${ssh_dir}"
    if [[ ! -f "${WORK_DIR}/ssh_client_ed25519" ]]; then
        ssh-keygen -t ed25519 -N "" -C "hajimi-ssh-test" -f "${WORK_DIR}/ssh_client_ed25519" >/dev/null 2>&1
    fi
    cat "${WORK_DIR}/ssh_client_ed25519.pub" > "${ssh_dir}/authorized_keys"
    chown -R ${SSH_TUNNEL_USER}:${SSH_TUNNEL_USER} "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    chmod 600 "${ssh_dir}/authorized_keys"

    mkdir -p /etc/ssh/sshd_config.d
    rm -f /etc/ssh/sshd_config.d/99-hajimi-test.conf
    # OpenSSH uses first-match-wins across Include /etc/ssh/sshd_config.d/*.conf.
    # Place 00-hajimi-test.conf before 50-cloud-init.conf / 60-cloudimg-settings.conf.
    cat >/etc/ssh/sshd_config.d/00-hajimi-test.conf <<EOF
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
AllowTcpForwarding yes

Match User ${SSH_TUNNEL_USER}
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    PubkeyAuthentication yes
    AllowTcpForwarding yes
    MaxSessions 64
    PermitOpen any
    PermitTTY no
    X11Forwarding no
EOF
    for cf in /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/60-cloudimg-settings.conf; do
        if [[ -f "${cf}" ]]; then
            sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/g' "${cf}" 2>/dev/null || true
        fi
    done
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

    SSH_HOST_PUBKEY="$(awk '{print $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || head -n1 /etc/ssh/ssh_host_*.pub | awk '{print $1 " " $2}')"
    log_ok "SSH 测试账号配置完成 (User: ${SSH_TUNNEL_USER}, Port: 22)"
}

open_firewall_ports() {
    log_info "正在放行防火墙端口 (TCP/UDP 20001-20029, UDP 51820, TCP 22)..."
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 20001:20030/tcp >/dev/null 2>&1 || true
        ufw allow 20001:20030/udp >/dev/null 2>&1 || true
        ufw allow 51820/udp >/dev/null 2>&1 || true
        ufw allow 22/tcp >/dev/null 2>&1 || true
    fi
    iptables -I INPUT -p tcp --dport 20001:20030 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 20001:20030 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
    ip6tables -I INPUT -p tcp --dport 20001:20030 -j ACCEPT 2>/dev/null || true
    ip6tables -I INPUT -p udp --dport 20001:20030 -j ACCEPT 2>/dev/null || true
    ip6tables -I INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
    log_ok "IPv4 / IPv6 双栈防火墙端口已放行"
}

generate_client_configs() {
    local has_ipv6=0
    if [[ -n "${PUBLIC_IPV6:-}" && "${PUBLIC_IPV6}" != "${PUBLIC_IP}" ]]; then
        has_ipv6=1
        log_info "正在生成哈基米客户端单文件合并订阅配置 (含 30 个 IPv4 节点 + 30 个 IPv6 节点，共 60 节点)..."
    else
        log_info "正在生成哈基米客户端全套订阅配置文件 (共 30 个全协议全传输层节点)..."
    fi

    # 清理旧版分离的 IPv6 独立文件（现已合并至同一文件）
    rm -f "${OUT_DIR}/hajimi-all-nodes-ipv6.conf" "${OUT_DIR}/hajimi-clash-meta-ipv6.yaml"

    local v4_all_list="SS-AES128GCM, SS2022-BLAKE3, SS-ChaCha20, SS2022-ChaCha20, Snell-v4, VMess-AEAD, VMess-WS-TLS, VMess-gRPC-TLS, VLESS-Vision-REALITY, VLESS-WS-TLS, VLESS-gRPC-TLS, Trojan-TLS, Trojan-WS-TLS, Trojan-gRPC-TLS, Hysteria-v1, Hysteria2-QUIC, Hysteria2-Salamander, Mieru-TCP, Mieru-UDP, Sudoku-UoT, Sudoku-Entropy, TUIC-v5, AnyTLS-Node, SOCKS5-Auth, SOCKS5-TLS, HTTPS-Connect, HTTP-Plain, TrustTunnel, SSR-Origin, SSH-Tunnel, WireGuard-Node"
    local v4_auto_list="SS-AES128GCM, SS2022-BLAKE3, SS-ChaCha20, SS2022-ChaCha20, Snell-v4, VMess-AEAD, VMess-WS-TLS, VMess-gRPC-TLS, VLESS-Vision-REALITY, VLESS-WS-TLS, VLESS-gRPC-TLS, Trojan-TLS, Trojan-WS-TLS, Trojan-gRPC-TLS, Hysteria-v1, Hysteria2-QUIC, Hysteria2-Salamander, Mieru-TCP, Mieru-UDP, Sudoku-UoT, Sudoku-Entropy, TUIC-v5, AnyTLS-Node, SOCKS5-Auth, SOCKS5-TLS, HTTPS-Connect, TrustTunnel, SSR-Origin"
    local v6_all_list="SS-AES128GCM-IPv6, SS2022-BLAKE3-IPv6, SS-ChaCha20-IPv6, SS2022-ChaCha20-IPv6, Snell-v4-IPv6, VMess-AEAD-IPv6, VMess-WS-TLS-IPv6, VMess-gRPC-TLS-IPv6, VLESS-Vision-REALITY-IPv6, VLESS-WS-TLS-IPv6, VLESS-gRPC-TLS-IPv6, Trojan-TLS-IPv6, Trojan-WS-TLS-IPv6, Trojan-gRPC-TLS-IPv6, Hysteria-v1-IPv6, Hysteria2-QUIC-IPv6, Hysteria2-Salamander-IPv6, Mieru-TCP-IPv6, Mieru-UDP-IPv6, Sudoku-UoT-IPv6, Sudoku-Entropy-IPv6, TUIC-v5-IPv6, AnyTLS-Node-IPv6, SOCKS5-Auth-IPv6, SOCKS5-TLS-IPv6, HTTPS-Connect-IPv6, HTTP-Plain-IPv6, TrustTunnel-IPv6, SSR-Origin-IPv6, SSH-Tunnel-IPv6, WireGuard-Node-IPv6"
    local v6_auto_list="SS-AES128GCM-IPv6, SS2022-BLAKE3-IPv6, SS-ChaCha20-IPv6, SS2022-ChaCha20-IPv6, Snell-v4-IPv6, VMess-AEAD-IPv6, VMess-WS-TLS-IPv6, VMess-gRPC-TLS-IPv6, VLESS-Vision-REALITY-IPv6, VLESS-WS-TLS-IPv6, VLESS-gRPC-TLS-IPv6, Trojan-TLS-IPv6, Trojan-WS-TLS-IPv6, Trojan-gRPC-TLS-IPv6, Hysteria-v1-IPv6, Hysteria2-QUIC-IPv6, Hysteria2-Salamander-IPv6, Mieru-TCP-IPv6, Mieru-UDP-IPv6, Sudoku-UoT-IPv6, Sudoku-Entropy-IPv6, TUIC-v5-IPv6, AnyTLS-Node-IPv6, SOCKS5-Auth-IPv6, SOCKS5-TLS-IPv6, HTTPS-Connect-IPv6, TrustTunnel-IPv6, SSR-Origin-IPv6"

    # 1. Surge / Hajimi 原生 .conf 配置文件 (IPv4 + IPv6 合并单文件)
    cat >"${OUT_DIR}/hajimi-all-nodes.conf" <<EOF
# ============================================================================
# 哈基米 (Hajimi) 全协议全传输层 IPv4 + IPv6 合并测试配置 (Surge .conf 原生格式)
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 服务器 IPv4: ${PUBLIC_IP}
# 服务器 IPv6: ${PUBLIC_IPV6:-未检测到}
# ============================================================================

[General]
loglevel = notify
ipv6 = true
dns-server = 223.5.5.5, 119.29.29.29, 2400:3200::1, 2402:4e00::
encrypted-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
skip-proxy = 127.0.0.1, ::1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fc00::/7, fe80::/10, localhost, *.local
http-listen = 127.0.0.1:6152
socks5-listen = 127.0.0.1:6153

[Proxy]
# ==================== IPv4 节点区 (30 节点) ====================
# 1-4. Shadowsocks (AEAD & SS2022)
SS-AES128GCM = ss, ${PUBLIC_IP}, 20001, encrypt-method=aes-128-gcm, password=${COMMON_PASS}, udp-relay=true
SS2022-BLAKE3 = ss, ${PUBLIC_IP}, 20002, encrypt-method=2022-blake3-aes-128-gcm, password="${SS2022_AES128_KEY}", udp-relay=true
SS-ChaCha20 = ss, ${PUBLIC_IP}, 20021, encrypt-method=chacha20-ietf-poly1305, password=${COMMON_PASS}, udp-relay=true
SS2022-ChaCha20 = ss, ${PUBLIC_IP}, 20022, encrypt-method=2022-blake3-chacha20-poly1305, password="${SS2022_CHACHA_KEY}", udp-relay=true

# 5. Snell v4 (TCP + UoT UDP)
Snell-v4 = snell, ${PUBLIC_IP}, 20003, psk=${SNELL_PSK}, version=4, reuse=true, udp-relay=true

# 6-8. VMess (TCP / WS-TLS / gRPC-TLS)
VMess-AEAD = vmess, ${PUBLIC_IP}, 20004, username=${UUID_V4}, vmess-aead=true, encrypt-method=aes-128-gcm, udp-relay=true
VMess-WS-TLS = vmess, ${PUBLIC_IP}, 20005, username=${UUID_V4}, vmess-aead=true, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, ws=true, ws-path=/vmess-ws, udp-relay=true
VMess-gRPC-TLS = vmess, ${PUBLIC_IP}, 20023, username=${UUID_V4}, vmess-aead=true, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, network=grpc, grpc-service-name=vmess-grpc, udp-relay=true

# 9-11. VLESS (Vision-REALITY / WS-TLS / gRPC-TLS)
VLESS-Vision-REALITY = vless, ${PUBLIC_IP}, 20006, username=${UUID_V4}, flow=xtls-rprx-vision, tls=true, sni=${REALITY_SNI}, reality-public-key=${REALITY_PUB_KEY}, reality-short-id=${REALITY_SHORT_ID}, client-fingerprint=chrome, udp-relay=true
VLESS-WS-TLS = vless, ${PUBLIC_IP}, 20007, username=${UUID_V4}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, ws=true, ws-path=/vless-ws, udp-relay=true
VLESS-gRPC-TLS = vless, ${PUBLIC_IP}, 20024, username=${UUID_V4}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, network=grpc, grpc-service-name=vless-grpc, udp-relay=true

# 12-14. Trojan (TLS / WS-TLS / gRPC-TLS)
Trojan-TLS = trojan, ${PUBLIC_IP}, 20008, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true
Trojan-WS-TLS = trojan, ${PUBLIC_IP}, 20025, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, ws=true, ws-path=/trojan-ws, udp-relay=true
Trojan-gRPC-TLS = trojan, ${PUBLIC_IP}, 20026, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, network=grpc, grpc-service-name=trojan-grpc, udp-relay=true

# 15-18. QUIC 系列 (Hysteria v1 / Hysteria2 / Hysteria2-Salamander / TUIC v5)
Hysteria-v1 = hysteria, ${PUBLIC_IP}, 20009, auth-str=${COMMON_PASS}, up=100, down=100, alpn=hysteria, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true
Hysteria2-QUIC = hysteria2, ${PUBLIC_IP}, 20010, password=${COMMON_PASS}, up=100, down=100, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true
Hysteria2-Salamander = hysteria2, ${PUBLIC_IP}, 20027, password=${COMMON_PASS}, obfs=salamander, obfs-password=${HY2_OBFS_PASS}, up=100, down=100, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true
TUIC-v5 = tuic, ${PUBLIC_IP}, 20013, uuid=${UUID_V4}, password=${COMMON_PASS}, alpn=h3, congestion-controller=bbr, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true

# 19-20. Mieru v3 (TCP & UDP)
Mieru-TCP = mieru, ${PUBLIC_IP}, 20011, username=${COMMON_USER}, password=${COMMON_PASS}, transport=TCP, multiplexing=MULTIPLEXING_LOW, udp-relay=true
Mieru-UDP = mieru, ${PUBLIC_IP}, 20017, username=${COMMON_USER}, password=${COMMON_PASS}, transport=UDP, multiplexing=MULTIPLEXING_LOW, mtu=1400, udp-relay=true

# 21-22. Sudoku v0.5.2 (ASCII Pure Downlink & Custom xvxvppvv 6-bit Packed Downlink)
Sudoku-UoT = sudoku, ${PUBLIC_IP}, 20012, key=${SUDOKU_CLIENT_KEY}, aead-method=chacha20-poly1305, table-type=prefer_ascii, padding-min=2, padding-max=7, enable-pure-downlink=true, http-mask=true, http-mask-mode=legacy, udp-relay=true
Sudoku-Entropy = sudoku, ${PUBLIC_IP}, 20029, key=${SUDOKU_CLIENT_KEY}, aead-method=aes-128-gcm, table-type=up_ascii_down_entropy, custom-table=xvxvppvv, padding-min=2, padding-max=7, enable-pure-downlink=false, http-mask=true, http-mask-mode=legacy, udp-relay=true

# 23. AnyTLS
AnyTLS-Node = anytls, ${PUBLIC_IP}, 20014, password=${COMMON_PASS}, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true

# 24-28. SOCKS5 / SOCKS5-TLS / HTTPS / HTTP / TrustTunnel
SOCKS5-Auth = socks5, ${PUBLIC_IP}, 20030, username=${COMMON_USER}, password=${COMMON_PASS}, udp-relay=true
SOCKS5-TLS = socks5-tls, ${PUBLIC_IP}, 20019, username=${COMMON_USER}, password=${COMMON_PASS}, sni=${PUBLIC_IP}, skip-cert-verify=true
HTTPS-Connect = https, ${PUBLIC_IP}, 20016, username=${COMMON_USER}, password=${COMMON_PASS}, sni=${PUBLIC_IP}, skip-cert-verify=true
HTTP-Plain = http, ${PUBLIC_IP}, 20028, username=${COMMON_USER}, password=${COMMON_PASS}
TrustTunnel = trusttunnel, ${PUBLIC_IP}, 20018, username=${COMMON_USER}, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IP}, skip-cert-verify=true, udp-relay=true

# 29. ShadowsocksR (SSR)
SSR-Origin = ssr, ${PUBLIC_IP}, 20020, encrypt-method=aes-128-cfb, password=${COMMON_PASS}, protocol=origin, obfs=plain, udp-relay=true

# 30-31. SSH & WireGuard
SSH-Tunnel = ssh, ${PUBLIC_IP}, 22, username=${SSH_TUNNEL_USER}, password=${COMMON_PASS}, host-key="${SSH_HOST_PUBKEY}", host-key-algorithms=ssh-ed25519
WireGuard-Node = wireguard, section-name=WGTest
EOF

    if [[ "${has_ipv6}" -eq 1 ]]; then
        cat >>"${OUT_DIR}/hajimi-all-nodes.conf" <<EOF

# ==================== IPv6 节点区 (30 节点) ====================
SS-AES128GCM-IPv6 = ss, ${PUBLIC_IPV6}, 20001, encrypt-method=aes-128-gcm, password=${COMMON_PASS}, udp-relay=true
SS2022-BLAKE3-IPv6 = ss, ${PUBLIC_IPV6}, 20002, encrypt-method=2022-blake3-aes-128-gcm, password="${SS2022_AES128_KEY}", udp-relay=true
SS-ChaCha20-IPv6 = ss, ${PUBLIC_IPV6}, 20021, encrypt-method=chacha20-ietf-poly1305, password=${COMMON_PASS}, udp-relay=true
SS2022-ChaCha20-IPv6 = ss, ${PUBLIC_IPV6}, 20022, encrypt-method=2022-blake3-chacha20-poly1305, password="${SS2022_CHACHA_KEY}", udp-relay=true
Snell-v4-IPv6 = snell, ${PUBLIC_IPV6}, 20003, psk=${SNELL_PSK}, version=4, reuse=true, udp-relay=true
VMess-AEAD-IPv6 = vmess, ${PUBLIC_IPV6}, 20004, username=${UUID_V4}, vmess-aead=true, encrypt-method=aes-128-gcm, udp-relay=true
VMess-WS-TLS-IPv6 = vmess, ${PUBLIC_IPV6}, 20005, username=${UUID_V4}, vmess-aead=true, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, ws=true, ws-path=/vmess-ws, udp-relay=true
VMess-gRPC-TLS-IPv6 = vmess, ${PUBLIC_IPV6}, 20023, username=${UUID_V4}, vmess-aead=true, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, network=grpc, grpc-service-name=vmess-grpc, udp-relay=true
VLESS-Vision-REALITY-IPv6 = vless, ${PUBLIC_IPV6}, 20006, username=${UUID_V4}, flow=xtls-rprx-vision, tls=true, sni=${REALITY_SNI}, reality-public-key=${REALITY_PUB_KEY}, reality-short-id=${REALITY_SHORT_ID}, client-fingerprint=chrome, udp-relay=true
VLESS-WS-TLS-IPv6 = vless, ${PUBLIC_IPV6}, 20007, username=${UUID_V4}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, ws=true, ws-path=/vless-ws, udp-relay=true
VLESS-gRPC-TLS-IPv6 = vless, ${PUBLIC_IPV6}, 20024, username=${UUID_V4}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, network=grpc, grpc-service-name=vless-grpc, udp-relay=true
Trojan-TLS-IPv6 = trojan, ${PUBLIC_IPV6}, 20008, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
Trojan-WS-TLS-IPv6 = trojan, ${PUBLIC_IPV6}, 20025, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, ws=true, ws-path=/trojan-ws, udp-relay=true
Trojan-gRPC-TLS-IPv6 = trojan, ${PUBLIC_IPV6}, 20026, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, network=grpc, grpc-service-name=trojan-grpc, udp-relay=true
Hysteria-v1-IPv6 = hysteria, ${PUBLIC_IPV6}, 20009, auth-str=${COMMON_PASS}, up=100, down=100, alpn=hysteria, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
Hysteria2-QUIC-IPv6 = hysteria2, ${PUBLIC_IPV6}, 20010, password=${COMMON_PASS}, up=100, down=100, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
Hysteria2-Salamander-IPv6 = hysteria2, ${PUBLIC_IPV6}, 20027, password=${COMMON_PASS}, obfs=salamander, obfs-password=${HY2_OBFS_PASS}, up=100, down=100, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
TUIC-v5-IPv6 = tuic, ${PUBLIC_IPV6}, 20013, uuid=${UUID_V4}, password=${COMMON_PASS}, alpn=h3, congestion-controller=bbr, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
Mieru-TCP-IPv6 = mieru, ${PUBLIC_IPV6}, 20011, username=${COMMON_USER}, password=${COMMON_PASS}, transport=TCP, multiplexing=MULTIPLEXING_LOW, udp-relay=true
Mieru-UDP-IPv6 = mieru, ${PUBLIC_IPV6}, 20017, username=${COMMON_USER}, password=${COMMON_PASS}, transport=UDP, multiplexing=MULTIPLEXING_LOW, mtu=1400, udp-relay=true
Sudoku-UoT-IPv6 = sudoku, ${PUBLIC_IPV6}, 20012, key=${SUDOKU_CLIENT_KEY}, aead-method=chacha20-poly1305, table-type=prefer_ascii, padding-min=2, padding-max=7, enable-pure-downlink=true, http-mask=true, http-mask-mode=legacy, udp-relay=true
Sudoku-Entropy-IPv6 = sudoku, ${PUBLIC_IPV6}, 20029, key=${SUDOKU_CLIENT_KEY}, aead-method=aes-128-gcm, table-type=up_ascii_down_entropy, custom-table=xvxvppvv, padding-min=2, padding-max=7, enable-pure-downlink=false, http-mask=true, http-mask-mode=legacy, udp-relay=true
AnyTLS-Node-IPv6 = anytls, ${PUBLIC_IPV6}, 20014, password=${COMMON_PASS}, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
SOCKS5-Auth-IPv6 = socks5, ${PUBLIC_IPV6}, 20030, username=${COMMON_USER}, password=${COMMON_PASS}, udp-relay=true
SOCKS5-TLS-IPv6 = socks5-tls, ${PUBLIC_IPV6}, 20019, username=${COMMON_USER}, password=${COMMON_PASS}, sni=${PUBLIC_IPV6}, skip-cert-verify=true
HTTPS-Connect-IPv6 = https, ${PUBLIC_IPV6}, 20016, username=${COMMON_USER}, password=${COMMON_PASS}, sni=${PUBLIC_IPV6}, skip-cert-verify=true
HTTP-Plain-IPv6 = http, ${PUBLIC_IPV6}, 20028, username=${COMMON_USER}, password=${COMMON_PASS}
TrustTunnel-IPv6 = trusttunnel, ${PUBLIC_IPV6}, 20018, username=${COMMON_USER}, password=${COMMON_PASS}, tls=true, sni=${PUBLIC_IPV6}, skip-cert-verify=true, udp-relay=true
SSR-Origin-IPv6 = ssr, ${PUBLIC_IPV6}, 20020, encrypt-method=aes-128-cfb, password=${COMMON_PASS}, protocol=origin, obfs=plain, udp-relay=true
SSH-Tunnel-IPv6 = ssh, ${PUBLIC_IPV6}, 22, username=${SSH_TUNNEL_USER}, password=${COMMON_PASS}, host-key="${SSH_HOST_PUBKEY}", host-key-algorithms=ssh-ed25519
WireGuard-Node-IPv6 = wireguard, section-name=WGTestIPv6
EOF
    fi

    cat >>"${OUT_DIR}/hajimi-all-nodes.conf" <<EOF

[WireGuard WGTest]
private-key = ${WG_CLIENT_PRIV}
self-ip = 100.64.0.2
self-ip-v6 = fd00:6861:6a69:66::2
dns-server = 223.5.5.5, 2400:3200::1
mtu = 1420
peer = (public-key = ${WG_SERVER_PUB}, allowed-ips = "0.0.0.0/0, ::/0", endpoint = ${PUBLIC_IP}:51820, pre-shared-key = ${WG_PSK}, keepalive = 25)
EOF

    if [[ "${has_ipv6}" -eq 1 ]]; then
        cat >>"${OUT_DIR}/hajimi-all-nodes.conf" <<EOF

[WireGuard WGTestIPv6]
private-key = ${WG_CLIENT_PRIV}
self-ip = 100.64.0.2
self-ip-v6 = fd00:6861:6a69:66::2
dns-server = 2400:3200::1, 223.5.5.5
mtu = 1420
peer = (public-key = ${WG_SERVER_PUB}, allowed-ips = "0.0.0.0/0, ::/0", endpoint = [${PUBLIC_IPV6}]:51820, pre-shared-key = ${WG_PSK}, keepalive = 25)

[Proxy Group]
Proxy = select, Auto-All, Auto-IPv4, Auto-IPv6, ${v4_all_list}, ${v6_all_list}, DIRECT
Auto-All = url-test, ${v4_auto_list}, ${v6_auto_list}, url=http://www.gstatic.com/generate_204, interval=300
Auto-IPv4 = url-test, ${v4_auto_list}, url=http://www.gstatic.com/generate_204, interval=300
Auto-IPv6 = url-test, ${v6_auto_list}, url=http://www.gstatic.com/generate_204, interval=300

[Rule]
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
EOF
    else
        cat >>"${OUT_DIR}/hajimi-all-nodes.conf" <<EOF

[Proxy Group]
Proxy = select, Auto-All, ${v4_all_list}, DIRECT
Auto-All = url-test, ${v4_auto_list}, url=http://www.gstatic.com/generate_204, interval=300

[Rule]
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
EOF
    fi

    # 2. Clash Meta (Mihomo) YAML 订阅配置文件 (IPv4 + IPv6 合并单文件)
    cat >"${OUT_DIR}/hajimi-clash-meta.yaml" <<EOF
# ============================================================================
# 哈基米 (Hajimi) 全协议全传输层 IPv4 + IPv6 合并测试配置 (Clash Meta / Mihomo YAML 格式)
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 服务器 IPv4: ${PUBLIC_IP}
# 服务器 IPv6: ${PUBLIC_IPV6:-未检测到}
# ============================================================================
mixed-port: 7890
allow-lan: false
ipv6: true
mode: rule
log-level: info

proxies:
  # ==================== IPv4 节点区 ====================
  - name: "SS-AES128GCM"
    type: ss
    server: ${PUBLIC_IP}
    port: 20001
    cipher: aes-128-gcm
    password: "${COMMON_PASS}"
    udp: true

  - name: "SS2022-BLAKE3"
    type: ss
    server: ${PUBLIC_IP}
    port: 20002
    cipher: 2022-blake3-aes-128-gcm
    password: "${SS2022_AES128_KEY}"
    udp: true

  - name: "SS-ChaCha20"
    type: ss
    server: ${PUBLIC_IP}
    port: 20021
    cipher: chacha20-ietf-poly1305
    password: "${COMMON_PASS}"
    udp: true

  - name: "SS2022-ChaCha20"
    type: ss
    server: ${PUBLIC_IP}
    port: 20022
    cipher: 2022-blake3-chacha20-poly1305
    password: "${SS2022_CHACHA_KEY}"
    udp: true

  - name: "Snell-v4"
    type: snell
    server: ${PUBLIC_IP}
    port: 20003
    psk: "${SNELL_PSK}"
    version: 4
    udp: true

  - name: "VMess-AEAD"
    type: vmess
    server: ${PUBLIC_IP}
    port: 20004
    uuid: ${UUID_V4}
    alterId: 0
    cipher: aes-128-gcm
    udp: true

  - name: "VMess-WS-TLS"
    type: vmess
    server: ${PUBLIC_IP}
    port: 20005
    uuid: ${UUID_V4}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: true
    servername: ${PUBLIC_IP}
    network: ws
    ws-opts:
      path: /vmess-ws

  - name: "VMess-gRPC-TLS"
    type: vmess
    server: ${PUBLIC_IP}
    port: 20023
    uuid: ${UUID_V4}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: true
    servername: ${PUBLIC_IP}
    network: grpc
    grpc-opts:
      grpc-service-name: vmess-grpc

  - name: "VLESS-Vision-REALITY"
    type: vless
    server: ${PUBLIC_IP}
    port: 20006
    uuid: ${UUID_V4}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${REALITY_SNI}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${REALITY_PUB_KEY}
      short-id: "${REALITY_SHORT_ID}"

  - name: "VLESS-WS-TLS"
    type: vless
    server: ${PUBLIC_IP}
    port: 20007
    uuid: ${UUID_V4}
    tls: true
    udp: true
    skip-cert-verify: true
    servername: ${PUBLIC_IP}
    network: ws
    ws-opts:
      path: /vless-ws

  - name: "VLESS-gRPC-TLS"
    type: vless
    server: ${PUBLIC_IP}
    port: 20024
    uuid: ${UUID_V4}
    tls: true
    udp: true
    skip-cert-verify: true
    servername: ${PUBLIC_IP}
    network: grpc
    grpc-opts:
      grpc-service-name: vless-grpc

  - name: "Trojan-TLS"
    type: trojan
    server: ${PUBLIC_IP}
    port: 20008
    password: "${COMMON_PASS}"
    udp: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true

  - name: "Trojan-WS-TLS"
    type: trojan
    server: ${PUBLIC_IP}
    port: 20025
    password: "${COMMON_PASS}"
    udp: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /trojan-ws

  - name: "Trojan-gRPC-TLS"
    type: trojan
    server: ${PUBLIC_IP}
    port: 20026
    password: "${COMMON_PASS}"
    udp: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: trojan-grpc

  - name: "Hysteria-v1"
    type: hysteria
    server: ${PUBLIC_IP}
    port: 20009
    auth-str: "${COMMON_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    alpn:
      - hysteria
      - h3

  - name: "Hysteria2-QUIC"
    type: hysteria2
    server: ${PUBLIC_IP}
    port: 20010
    password: "${COMMON_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: ${PUBLIC_IP}
    skip-cert-verify: true

  - name: "Hysteria2-Salamander"
    type: hysteria2
    server: ${PUBLIC_IP}
    port: 20027
    password: "${COMMON_PASS}"
    obfs: salamander
    obfs-password: "${HY2_OBFS_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: ${PUBLIC_IP}
    skip-cert-verify: true

  - name: "Mieru-TCP"
    type: mieru
    server: ${PUBLIC_IP}
    port: 20011
    transport: TCP
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    multiplexing: MULTIPLEXING_LOW
    udp: true

  - name: "Mieru-UDP"
    type: mieru
    server: ${PUBLIC_IP}
    port: 20017
    transport: UDP
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    multiplexing: MULTIPLEXING_LOW
    mtu: 1400
    udp: true

  - name: "Sudoku-UoT"
    type: sudoku
    server: ${PUBLIC_IP}
    port: 20012
    key: "${SUDOKU_CLIENT_KEY}"
    aead-method: chacha20-poly1305
    table-type: prefer_ascii
    padding-min: 2
    padding-max: 7
    enable-pure-downlink: true
    http-mask: true
    http-mask-mode: legacy
    udp: true

  - name: "Sudoku-Entropy"
    type: sudoku
    server: ${PUBLIC_IP}
    port: 20029
    key: "${SUDOKU_CLIENT_KEY}"
    aead-method: aes-128-gcm
    table-type: up_ascii_down_entropy
    custom-table: xvxvppvv
    padding-min: 2
    padding-max: 7
    enable-pure-downlink: false
    http-mask: true
    http-mask-mode: legacy
    udp: true

  - name: "TUIC-v5"
    type: tuic
    server: ${PUBLIC_IP}
    port: 20013
    uuid: ${UUID_V4}
    password: "${COMMON_PASS}"
    congestion-controller: bbr
    udp-relay-mode: native
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    alpn:
      - h3

  - name: "AnyTLS-Node"
    type: anytls
    server: ${PUBLIC_IP}
    port: 20014
    password: "${COMMON_PASS}"
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    udp: true

  - name: "SOCKS5-Auth"
    type: socks5
    server: ${PUBLIC_IP}
    port: 20030
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    udp: true

  - name: "SOCKS5-TLS"
    type: socks5
    server: ${PUBLIC_IP}
    port: 20019
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true

  - name: "HTTPS-Connect"
    type: http
    server: ${PUBLIC_IP}
    port: 20016
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true

  - name: "HTTP-Plain"
    type: http
    server: ${PUBLIC_IP}
    port: 20028
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"

  - name: "TrustTunnel"
    type: trusttunnel
    server: ${PUBLIC_IP}
    port: 20018
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: ${PUBLIC_IP}
    skip-cert-verify: true
    udp: true

  - name: "SSR-Origin"
    type: ssr
    server: ${PUBLIC_IP}
    port: 20020
    cipher: aes-128-cfb
    password: "${COMMON_PASS}"
    protocol: origin
    obfs: plain
    udp: true

  - name: "SSH-Tunnel"
    type: ssh
    server: ${PUBLIC_IP}
    port: 22
    username: ${SSH_TUNNEL_USER}
    password: "${COMMON_PASS}"
    host-key:
      - "${SSH_HOST_PUBKEY}"

  - name: "WireGuard-Node"
    type: wireguard
    server: ${PUBLIC_IP}
    port: 51820
    ip: 100.64.0.2
    ipv6: fd00:6861:6a69:66::2
    private-key: "${WG_CLIENT_PRIV}"
    public-key: "${WG_SERVER_PUB}"
    pre-shared-key: "${WG_PSK}"
    mtu: 1420
    udp: true
EOF

    if [[ "${has_ipv6}" -eq 1 ]]; then
        cat >>"${OUT_DIR}/hajimi-clash-meta.yaml" <<EOF

  # ==================== IPv6 节点区 ====================
  - name: "SS-AES128GCM-IPv6"
    type: ss
    server: "${PUBLIC_IPV6}"
    port: 20001
    cipher: aes-128-gcm
    password: "${COMMON_PASS}"
    udp: true

  - name: "SS2022-BLAKE3-IPv6"
    type: ss
    server: "${PUBLIC_IPV6}"
    port: 20002
    cipher: 2022-blake3-aes-128-gcm
    password: "${SS2022_AES128_KEY}"
    udp: true

  - name: "SS-ChaCha20-IPv6"
    type: ss
    server: "${PUBLIC_IPV6}"
    port: 20021
    cipher: chacha20-ietf-poly1305
    password: "${COMMON_PASS}"
    udp: true

  - name: "SS2022-ChaCha20-IPv6"
    type: ss
    server: "${PUBLIC_IPV6}"
    port: 20022
    cipher: 2022-blake3-chacha20-poly1305
    password: "${SS2022_CHACHA_KEY}"
    udp: true

  - name: "Snell-v4-IPv6"
    type: snell
    server: "${PUBLIC_IPV6}"
    port: 20003
    psk: "${SNELL_PSK}"
    version: 4
    udp: true

  - name: "VMess-AEAD-IPv6"
    type: vmess
    server: "${PUBLIC_IPV6}"
    port: 20004
    uuid: ${UUID_V4}
    alterId: 0
    cipher: aes-128-gcm
    udp: true

  - name: "VMess-WS-TLS-IPv6"
    type: vmess
    server: "${PUBLIC_IPV6}"
    port: 20005
    uuid: ${UUID_V4}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: true
    servername: "${PUBLIC_IPV6}"
    network: ws
    ws-opts:
      path: /vmess-ws

  - name: "VMess-gRPC-TLS-IPv6"
    type: vmess
    server: "${PUBLIC_IPV6}"
    port: 20023
    uuid: ${UUID_V4}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    skip-cert-verify: true
    servername: "${PUBLIC_IPV6}"
    network: grpc
    grpc-opts:
      grpc-service-name: vmess-grpc

  - name: "VLESS-Vision-REALITY-IPv6"
    type: vless
    server: "${PUBLIC_IPV6}"
    port: 20006
    uuid: ${UUID_V4}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${REALITY_SNI}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${REALITY_PUB_KEY}
      short-id: "${REALITY_SHORT_ID}"

  - name: "VLESS-WS-TLS-IPv6"
    type: vless
    server: "${PUBLIC_IPV6}"
    port: 20007
    uuid: ${UUID_V4}
    tls: true
    udp: true
    skip-cert-verify: true
    servername: "${PUBLIC_IPV6}"
    network: ws
    ws-opts:
      path: /vless-ws

  - name: "VLESS-gRPC-TLS-IPv6"
    type: vless
    server: "${PUBLIC_IPV6}"
    port: 20024
    uuid: ${UUID_V4}
    tls: true
    udp: true
    skip-cert-verify: true
    servername: "${PUBLIC_IPV6}"
    network: grpc
    grpc-opts:
      grpc-service-name: vless-grpc

  - name: "Trojan-TLS-IPv6"
    type: trojan
    server: "${PUBLIC_IPV6}"
    port: 20008
    password: "${COMMON_PASS}"
    udp: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true

  - name: "Trojan-WS-TLS-IPv6"
    type: trojan
    server: "${PUBLIC_IPV6}"
    port: 20025
    password: "${COMMON_PASS}"
    udp: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /trojan-ws

  - name: "Trojan-gRPC-TLS-IPv6"
    type: trojan
    server: "${PUBLIC_IPV6}"
    port: 20026
    password: "${COMMON_PASS}"
    udp: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: trojan-grpc

  - name: "Hysteria-v1-IPv6"
    type: hysteria
    server: "${PUBLIC_IPV6}"
    port: 20009
    auth-str: "${COMMON_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    alpn:
      - hysteria
      - h3

  - name: "Hysteria2-QUIC-IPv6"
    type: hysteria2
    server: "${PUBLIC_IPV6}"
    port: 20010
    password: "${COMMON_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true

  - name: "Hysteria2-Salamander-IPv6"
    type: hysteria2
    server: "${PUBLIC_IPV6}"
    port: 20027
    password: "${COMMON_PASS}"
    obfs: salamander
    obfs-password: "${HY2_OBFS_PASS}"
    up: "100 Mbps"
    down: "100 Mbps"
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true

  - name: "Mieru-TCP-IPv6"
    type: mieru
    server: "${PUBLIC_IPV6}"
    port: 20011
    transport: TCP
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    multiplexing: MULTIPLEXING_LOW
    udp: true

  - name: "Mieru-UDP-IPv6"
    type: mieru
    server: "${PUBLIC_IPV6}"
    port: 20017
    transport: UDP
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    multiplexing: MULTIPLEXING_LOW
    mtu: 1400
    udp: true

  - name: "Sudoku-UoT-IPv6"
    type: sudoku
    server: "${PUBLIC_IPV6}"
    port: 20012
    key: "${SUDOKU_CLIENT_KEY}"
    aead-method: chacha20-poly1305
    table-type: prefer_ascii
    padding-min: 2
    padding-max: 7
    enable-pure-downlink: true
    http-mask: true
    http-mask-mode: legacy
    udp: true

  - name: "Sudoku-Entropy-IPv6"
    type: sudoku
    server: "${PUBLIC_IPV6}"
    port: 20029
    key: "${SUDOKU_CLIENT_KEY}"
    aead-method: aes-128-gcm
    table-type: up_ascii_down_entropy
    custom-table: xvxvppvv
    padding-min: 2
    padding-max: 7
    enable-pure-downlink: false
    http-mask: true
    http-mask-mode: legacy
    udp: true

  - name: "TUIC-v5-IPv6"
    type: tuic
    server: "${PUBLIC_IPV6}"
    port: 20013
    uuid: ${UUID_V4}
    password: "${COMMON_PASS}"
    congestion-controller: bbr
    udp-relay-mode: native
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    alpn:
      - h3

  - name: "AnyTLS-Node-IPv6"
    type: anytls
    server: "${PUBLIC_IPV6}"
    port: 20014
    password: "${COMMON_PASS}"
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    udp: true

  - name: "SOCKS5-Auth-IPv6"
    type: socks5
    server: "${PUBLIC_IPV6}"
    port: 20030
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    udp: true

  - name: "SOCKS5-TLS-IPv6"
    type: socks5
    server: "${PUBLIC_IPV6}"
    port: 20019
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true

  - name: "HTTPS-Connect-IPv6"
    type: http
    server: "${PUBLIC_IPV6}"
    port: 20016
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true

  - name: "HTTP-Plain-IPv6"
    type: http
    server: "${PUBLIC_IPV6}"
    port: 20028
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"

  - name: "TrustTunnel-IPv6"
    type: trusttunnel
    server: "${PUBLIC_IPV6}"
    port: 20018
    username: "${COMMON_USER}"
    password: "${COMMON_PASS}"
    tls: true
    sni: "${PUBLIC_IPV6}"
    skip-cert-verify: true
    udp: true

  - name: "SSR-Origin-IPv6"
    type: ssr
    server: "${PUBLIC_IPV6}"
    port: 20020
    cipher: aes-128-cfb
    password: "${COMMON_PASS}"
    protocol: origin
    obfs: plain
    udp: true

  - name: "SSH-Tunnel-IPv6"
    type: ssh
    server: "${PUBLIC_IPV6}"
    port: 22
    username: ${SSH_TUNNEL_USER}
    password: "${COMMON_PASS}"
    host-key:
      - "${SSH_HOST_PUBKEY}"

  - name: "WireGuard-Node-IPv6"
    type: wireguard
    server: "${PUBLIC_IPV6}"
    port: 51820
    ip: 100.64.0.2
    ipv6: fd00:6861:6a69:66::2
    private-key: "${WG_CLIENT_PRIV}"
    public-key: "${WG_SERVER_PUB}"
    pre-shared-key: "${WG_PSK}"
    mtu: 1420
    udp: true

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "Auto-All"
      - "Auto-IPv4"
      - "Auto-IPv6"
      - "SS-AES128GCM"
      - "SS2022-BLAKE3"
      - "SS-ChaCha20"
      - "SS2022-ChaCha20"
      - "Snell-v4"
      - "VMess-AEAD"
      - "VMess-WS-TLS"
      - "VMess-gRPC-TLS"
      - "VLESS-Vision-REALITY"
      - "VLESS-WS-TLS"
      - "VLESS-gRPC-TLS"
      - "Trojan-TLS"
      - "Trojan-WS-TLS"
      - "Trojan-gRPC-TLS"
      - "Hysteria-v1"
      - "Hysteria2-QUIC"
      - "Hysteria2-Salamander"
      - "Mieru-TCP"
      - "Mieru-UDP"
      - "Sudoku-UoT"
      - "Sudoku-Entropy"
      - "TUIC-v5"
      - "AnyTLS-Node"
      - "SOCKS5-Auth"
      - "SOCKS5-TLS"
      - "HTTPS-Connect"
      - "HTTP-Plain"
      - "TrustTunnel"
      - "SSR-Origin"
      - "SSH-Tunnel"
      - "WireGuard-Node"
      - "SS-AES128GCM-IPv6"
      - "SS2022-BLAKE3-IPv6"
      - "SS-ChaCha20-IPv6"
      - "SS2022-ChaCha20-IPv6"
      - "Snell-v4-IPv6"
      - "VMess-AEAD-IPv6"
      - "VMess-WS-TLS-IPv6"
      - "VMess-gRPC-TLS-IPv6"
      - "VLESS-Vision-REALITY-IPv6"
      - "VLESS-WS-TLS-IPv6"
      - "VLESS-gRPC-TLS-IPv6"
      - "Trojan-TLS-IPv6"
      - "Trojan-WS-TLS-IPv6"
      - "Trojan-gRPC-TLS-IPv6"
      - "Hysteria-v1-IPv6"
      - "Hysteria2-QUIC-IPv6"
      - "Hysteria2-Salamander-IPv6"
      - "Mieru-TCP-IPv6"
      - "Mieru-UDP-IPv6"
      - "Sudoku-UoT-IPv6"
      - "Sudoku-Entropy-IPv6"
      - "TUIC-v5-IPv6"
      - "AnyTLS-Node-IPv6"
      - "SOCKS5-Auth-IPv6"
      - "SOCKS5-TLS-IPv6"
      - "HTTPS-Connect-IPv6"
      - "HTTP-Plain-IPv6"
      - "TrustTunnel-IPv6"
      - "SSR-Origin-IPv6"
      - "SSH-Tunnel-IPv6"
      - "WireGuard-Node-IPv6"
      - DIRECT

  - name: "Auto-All"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - "SS-AES128GCM"
      - "SS2022-BLAKE3"
      - "SS-ChaCha20"
      - "SS2022-ChaCha20"
      - "Snell-v4"
      - "VMess-AEAD"
      - "VMess-WS-TLS"
      - "VMess-gRPC-TLS"
      - "VLESS-Vision-REALITY"
      - "VLESS-WS-TLS"
      - "VLESS-gRPC-TLS"
      - "Trojan-TLS"
      - "Trojan-WS-TLS"
      - "Trojan-gRPC-TLS"
      - "Hysteria-v1"
      - "Hysteria2-QUIC"
      - "Hysteria2-Salamander"
      - "Mieru-TCP"
      - "Mieru-UDP"
      - "Sudoku-UoT"
      - "Sudoku-Entropy"
      - "TUIC-v5"
      - "AnyTLS-Node"
      - "SOCKS5-Auth"
      - "SOCKS5-TLS"
      - "HTTPS-Connect"
      - "TrustTunnel"
      - "SSR-Origin"
      - "SS-AES128GCM-IPv6"
      - "SS2022-BLAKE3-IPv6"
      - "SS-ChaCha20-IPv6"
      - "SS2022-ChaCha20-IPv6"
      - "Snell-v4-IPv6"
      - "VMess-AEAD-IPv6"
      - "VMess-WS-TLS-IPv6"
      - "VMess-gRPC-TLS-IPv6"
      - "VLESS-Vision-REALITY-IPv6"
      - "VLESS-WS-TLS-IPv6"
      - "VLESS-gRPC-TLS-IPv6"
      - "Trojan-TLS-IPv6"
      - "Trojan-WS-TLS-IPv6"
      - "Trojan-gRPC-TLS-IPv6"
      - "Hysteria-v1-IPv6"
      - "Hysteria2-QUIC-IPv6"
      - "Hysteria2-Salamander-IPv6"
      - "Mieru-TCP-IPv6"
      - "Mieru-UDP-IPv6"
      - "Sudoku-UoT-IPv6"
      - "Sudoku-Entropy-IPv6"
      - "TUIC-v5-IPv6"
      - "AnyTLS-Node-IPv6"
      - "SOCKS5-Auth-IPv6"
      - "SOCKS5-TLS-IPv6"
      - "HTTPS-Connect-IPv6"
      - "TrustTunnel-IPv6"
      - "SSR-Origin-IPv6"

  - name: "Auto-IPv4"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - "SS-AES128GCM"
      - "SS2022-BLAKE3"
      - "SS-ChaCha20"
      - "SS2022-ChaCha20"
      - "Snell-v4"
      - "VMess-AEAD"
      - "VMess-WS-TLS"
      - "VMess-gRPC-TLS"
      - "VLESS-Vision-REALITY"
      - "VLESS-WS-TLS"
      - "VLESS-gRPC-TLS"
      - "Trojan-TLS"
      - "Trojan-WS-TLS"
      - "Trojan-gRPC-TLS"
      - "Hysteria-v1"
      - "Hysteria2-QUIC"
      - "Hysteria2-Salamander"
      - "Mieru-TCP"
      - "Mieru-UDP"
      - "Sudoku-UoT"
      - "Sudoku-Entropy"
      - "TUIC-v5"
      - "AnyTLS-Node"
      - "SOCKS5-Auth"
      - "SOCKS5-TLS"
      - "HTTPS-Connect"
      - "TrustTunnel"
      - "SSR-Origin"

  - name: "Auto-IPv6"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - "SS-AES128GCM-IPv6"
      - "SS2022-BLAKE3-IPv6"
      - "SS-ChaCha20-IPv6"
      - "SS2022-ChaCha20-IPv6"
      - "Snell-v4-IPv6"
      - "VMess-AEAD-IPv6"
      - "VMess-WS-TLS-IPv6"
      - "VMess-gRPC-TLS-IPv6"
      - "VLESS-Vision-REALITY-IPv6"
      - "VLESS-WS-TLS-IPv6"
      - "VLESS-gRPC-TLS-IPv6"
      - "Trojan-TLS-IPv6"
      - "Trojan-WS-TLS-IPv6"
      - "Trojan-gRPC-TLS-IPv6"
      - "Hysteria-v1-IPv6"
      - "Hysteria2-QUIC-IPv6"
      - "Hysteria2-Salamander-IPv6"
      - "Mieru-TCP-IPv6"
      - "Mieru-UDP-IPv6"
      - "Sudoku-UoT-IPv6"
      - "Sudoku-Entropy-IPv6"
      - "TUIC-v5-IPv6"
      - "AnyTLS-Node-IPv6"
      - "SOCKS5-Auth-IPv6"
      - "SOCKS5-TLS-IPv6"
      - "HTTPS-Connect-IPv6"
      - "TrustTunnel-IPv6"
      - "SSR-Origin-IPv6"

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
    else
        cat >>"${OUT_DIR}/hajimi-clash-meta.yaml" <<EOF

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "SS-AES128GCM"
      - "SS2022-BLAKE3"
      - "SS-ChaCha20"
      - "SS2022-ChaCha20"
      - "Snell-v4"
      - "VMess-AEAD"
      - "VMess-WS-TLS"
      - "VMess-gRPC-TLS"
      - "VLESS-Vision-REALITY"
      - "VLESS-WS-TLS"
      - "VLESS-gRPC-TLS"
      - "Trojan-TLS"
      - "Trojan-WS-TLS"
      - "Trojan-gRPC-TLS"
      - "Hysteria-v1"
      - "Hysteria2-QUIC"
      - "Hysteria2-Salamander"
      - "Mieru-TCP"
      - "Mieru-UDP"
      - "Sudoku-UoT"
      - "Sudoku-Entropy"
      - "TUIC-v5"
      - "AnyTLS-Node"
      - "SOCKS5-Auth"
      - "SOCKS5-TLS"
      - "HTTPS-Connect"
      - "HTTP-Plain"
      - "TrustTunnel"
      - "SSR-Origin"
      - "SSH-Tunnel"
      - "WireGuard-Node"
      - DIRECT

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
    fi

    # 3. 分享链接列表 (IPv4 + IPv6 合并单文件)
    local ss1_b64
    ss1_b64="$(echo -n "aes-128-gcm:${COMMON_PASS}" | base64 -w0)"
    local ss2_b64
    ss2_b64="$(echo -n "2022-blake3-aes-128-gcm:${SS2022_AES128_KEY}" | base64 -w0)"
    local vmess_tcp_json
    vmess_tcp_json="$(jq -nc --arg add "${PUBLIC_IP}" --arg id "${UUID_V4}"         '{v:"2",ps:"VMess-AEAD",add:$add,port:"20004",id:$id,aid:"0",scy:"aes-128-gcm",net:"tcp",type:"none",tls:""}' | base64 -w0)"
    local vmess_ws_json
    vmess_ws_json="$(jq -nc --arg add "${PUBLIC_IP}" --arg id "${UUID_V4}"         '{v:"2",ps:"VMess-WS-TLS",add:$add,port:"20005",id:$id,aid:"0",scy:"auto",net:"ws",path:"/vmess-ws",tls:"tls",sni:$add}' | base64 -w0)"

    cat >"${OUT_DIR}/hajimi-share-links.txt" <<EOF
ss://${ss1_b64}@${PUBLIC_IP}:20001#SS-AES128GCM
ss://${ss2_b64}@${PUBLIC_IP}:20002#SS2022-BLAKE3
vmess://${vmess_tcp_json}
vmess://${vmess_ws_json}
vless://${UUID_V4}@${PUBLIC_IP}:20006?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#VLESS-Vision-REALITY
vless://${UUID_V4}@${PUBLIC_IP}:20007?encryption=none&security=tls&sni=${PUBLIC_IP}&allowInsecure=1&type=ws&path=%2Fvl-ws#VLESS-WS-TLS
trojan://${COMMON_PASS}@${PUBLIC_IP}:20008?security=tls&sni=${PUBLIC_IP}&allowInsecure=1#Trojan-TLS
hysteria://${PUBLIC_IP}:20009?auth=${COMMON_PASS}&upmbps=100&downmbps=100&insecure=1&peer=${PUBLIC_IP}&alpn=hysteria#Hysteria-v1
hysteria2://${COMMON_PASS}@${PUBLIC_IP}:20010?insecure=1&sni=${PUBLIC_IP}#Hysteria2-QUIC
tuic://${UUID_V4}:${COMMON_PASS}@${PUBLIC_IP}:20013?congestion_control=bbr&alpn=h3&allow_insecure=1&sni=${PUBLIC_IP}#TUIC-v5
anytls://${COMMON_PASS}@${PUBLIC_IP}:20014?sni=${PUBLIC_IP}&insecure=1#AnyTLS-Node
socks5://${COMMON_USER}:${COMMON_PASS}@${PUBLIC_IP}:20030#SOCKS5-Auth
EOF

    if [[ "${has_ipv6}" -eq 1 ]]; then
        local vmess_tcp_v6_json
        vmess_tcp_v6_json="$(jq -nc --arg add "${PUBLIC_IPV6}" --arg id "${UUID_V4}"             '{v:"2",ps:"VMess-AEAD-IPv6",add:$add,port:"20004",id:$id,aid:"0",scy:"aes-128-gcm",net:"tcp",type:"none",tls:""}' | base64 -w0)"
        local vmess_ws_v6_json
        vmess_ws_v6_json="$(jq -nc --arg add "${PUBLIC_IPV6}" --arg id "${UUID_V4}"             '{v:"2",ps:"VMess-WS-TLS-IPv6",add:$add,port:"20005",id:$id,aid:"0",scy:"auto",net:"ws",path:"/vmess-ws",tls:"tls",sni:$add}' | base64 -w0)"
        cat >>"${OUT_DIR}/hajimi-share-links.txt" <<EOF
ss://${ss1_b64}@[${PUBLIC_IPV6}]:20001#SS-AES128GCM-IPv6
ss://${ss2_b64}@[${PUBLIC_IPV6}]:20002#SS2022-BLAKE3-IPv6
vmess://${vmess_tcp_v6_json}
vmess://${vmess_ws_v6_json}
vless://${UUID_V4}@[${PUBLIC_IPV6}]:20006?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#VLESS-Vision-REALITY-IPv6
vless://${UUID_V4}@[${PUBLIC_IPV6}]:20007?encryption=none&security=tls&sni=${PUBLIC_IPV6}&allowInsecure=1&type=ws&path=%2Fvl-ws#VLESS-WS-TLS-IPv6
trojan://${COMMON_PASS}@[${PUBLIC_IPV6}]:20008?security=tls&sni=${PUBLIC_IPV6}&allowInsecure=1#Trojan-TLS-IPv6
hysteria://[${PUBLIC_IPV6}]:20009?auth=${COMMON_PASS}&upmbps=100&downmbps=100&insecure=1&peer=${PUBLIC_IPV6}&alpn=hysteria#Hysteria-v1-IPv6
hysteria2://${COMMON_PASS}@[${PUBLIC_IPV6}]:20010?insecure=1&sni=${PUBLIC_IPV6}#Hysteria2-QUIC-IPv6
tuic://${UUID_V4}:${COMMON_PASS}@[${PUBLIC_IPV6}]:20013?congestion_control=bbr&alpn=h3&allow_insecure=1&sni=${PUBLIC_IPV6}#TUIC-v5-IPv6
anytls://${COMMON_PASS}@[${PUBLIC_IPV6}]:20014?sni=${PUBLIC_IPV6}&insecure=1#AnyTLS-Node-IPv6
socks5://${COMMON_USER}:${COMMON_PASS}@[${PUBLIC_IPV6}]:20030#SOCKS5-Auth-IPv6
EOF
    fi

    base64 -w0 "${OUT_DIR}/hajimi-share-links.txt" > "${OUT_DIR}/hajimi-share-links-base64.txt"
    chmod 644 "${OUT_DIR}/"*
    log_ok "客户端配置文件 (IPv4 + IPv6 已合并为单文件) 已全部生成至 ${OUT_DIR}/"
}

verify_services_and_ports() {
    log_info "正在执行服务端进程与监听端口自检..."
    sleep 2
    for svc in hajimi-singbox hajimi-extra; do
        if systemctl is-active --quiet "${svc}"; then
            log_ok "服务 ${svc} 运行正常"
        else
            log_err "服务 ${svc} 未正常运行，日志如下："
            journalctl -u "${svc}" -n 30 --no-pager || true
        fi
    done
    local missing=0
    for p in 20001 20002 20003 20004 20005 20006 20007 20008 20012 20014 20030 20016 20018 20019 20020 20021 20022 20023 20024 20025 20026 20028 20029; do
        if ! ss -tln | grep -q ":${p}\b"; then
            log_warn "TCP 端口 ${p} 未检测到监听!"
            missing=$((missing + 1))
        fi
    done
    for p in 20001 20002 20009 20010 20013 20020 20021 20022 20027; do
        if ! ss -uln | grep -q ":${p}\b"; then
            log_warn "UDP 端口 ${p} 未检测到监听!"
            missing=$((missing + 1))
        fi
    done
    if [[ "${missing}" -eq 0 ]]; then
        log_ok "全部核心 TCP/UDP 节点端口监听自检 100% 通过！"
    fi
}

enable_http_subscription_server() {
    local sub_port="${1:-20080}"
    local sub_token
    sub_token="$(openssl rand -hex 8)"
    cat >/etc/systemd/system/hajimi-sub-http.service <<EOF
[Unit]
Description=Hajimi Temporary Subscription HTTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${OUT_DIR}
ExecStart=/usr/bin/python3 -m http.server ${sub_port} --bind ::
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    iptables -I INPUT -p tcp --dport "${sub_port}" -j ACCEPT 2>/dev/null || true
    ip6tables -I INPUT -p tcp --dport "${sub_port}" -j ACCEPT 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable --now hajimi-sub-http.service
    echo ""
    log_ok "已开启订阅 HTTP 下载服务 (端口: ${sub_port})"
    echo -e "  - Surge / 哈基米 .conf 订阅链接 (含IPv4+IPv6): ${GREEN}http://${PUBLIC_IP}:${sub_port}/hajimi-all-nodes.conf${NC}"
    echo -e "  - Clash Meta YAML 订阅链接    (含IPv4+IPv6): ${GREEN}http://${PUBLIC_IP}:${sub_port}/hajimi-clash-meta.yaml${NC}"
    echo -e "  - 分享链接列表订阅            (含IPv4+IPv6): ${GREEN}http://${PUBLIC_IP}:${sub_port}/hajimi-share-links.txt${NC}"
    if [[ -n "${PUBLIC_IPV6:-}" && "${PUBLIC_IPV6}" != "${PUBLIC_IP}" ]]; then
        echo -e "  - Surge / 哈基米 .conf (IPv6直连下载)      : ${GREEN}http://[${PUBLIC_IPV6}]:${sub_port}/hajimi-all-nodes.conf${NC}"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}==============================================================================${NC}"
    echo -e "${GREEN}      🎉 哈基米 (Hajimi) 全协议 30 节点测试环境一键部署完成！                 ${NC}"
    echo -e "${GREEN}==============================================================================${NC}"
    echo -e "服务器公网 IPv4: ${CYAN}${PUBLIC_IP}${NC}"
    echo -e "服务器公网 IPv6: ${CYAN}${PUBLIC_IPV6:-未检测到}${NC}"
    echo -e "通用用户名     : ${CYAN}${COMMON_USER}${NC}"
    echo -e "通用密码/PSK   : ${CYAN}${COMMON_PASS}${NC}"
    echo -e "通用 UUID      : ${CYAN}${UUID_V4}${NC}"
    echo -e "------------------------------------------------------------------------------"
    echo -e "可以直接导入哈基米 App 的配置文件路径 (IPv4 与 IPv6 节点已合并至同一文件):"
    echo -e "  1) Surge 原生全协议配置 (IPv4+IPv6 合并单文件): ${YELLOW}${OUT_DIR}/hajimi-all-nodes.conf${NC}"
    echo -e "  2) Clash Meta YAML 配置 (IPv4+IPv6 合并单文件): ${YELLOW}${OUT_DIR}/hajimi-clash-meta.yaml${NC}"
    echo -e "  3) 通用分享链接列表     (IPv4+IPv6 合并单文件): ${YELLOW}${OUT_DIR}/hajimi-share-links.txt${NC}"
    echo -e "  4) SSH 私钥文件 (如需测试私钥登录): ${YELLOW}${WORK_DIR}/ssh_client_ed25519${NC}"
    echo -e "------------------------------------------------------------------------------"
    echo -e "端口与协议对应表 (30 节点):"
    echo -e "  [20001 TCP/UDP] SS-AES128GCM         [20002 TCP/UDP] SS2022-BLAKE3"
    echo -e "  [20021 TCP/UDP] SS-ChaCha20          [20022 TCP/UDP] SS2022-ChaCha20"
    echo -e "  [20003 TCP]     Snell-v4 (含UoT)     [20004 TCP]     VMess-AEAD"
    echo -e "  [20005 TCP]     VMess-WS-TLS         [20023 TCP]     VMess-gRPC-TLS"
    echo -e "  [20006 TCP]     VLESS-Vision-REALITY [20007 TCP]     VLESS-WS-TLS"
    echo -e "  [20024 TCP]     VLESS-gRPC-TLS       [20008 TCP]     Trojan-TLS"
    echo -e "  [20025 TCP]     Trojan-WS-TLS        [20026 TCP]     Trojan-gRPC-TLS"
    echo -e "  [20009 UDP]     Hysteria-v1          [20010 UDP]     Hysteria2-QUIC"
    echo -e "  [20027 UDP]     Hysteria2-Salamander [20013 UDP]     TUIC-v5"
    echo -e "  [20011 TCP]     Mieru-TCP            [20017 UDP]     Mieru-UDP"
    echo -e "  [20012 TCP]     Sudoku-UoT (ASCII)   [20029 TCP]     Sudoku-Entropy (6-bit)"
    echo -e "  [20014 TCP]     AnyTLS-Node          [20030 TCP/UDP] SOCKS5-Auth"
    echo -e "  [20016 TCP]     HTTPS-Connect        [20028 TCP]     HTTP-Plain"
    echo -e "  [20018 TCP]     TrustTunnel (含UDP)  [20019 TCP]     SOCKS5-TLS"
    echo -e "  [20020 TCP/UDP] SSR-Origin           [22 TCP]        SSH-Tunnel"
    echo -e "  [51820 UDP]     WireGuard-Node"
    echo -e "${GREEN}==============================================================================${NC}"
}

main() {
    case "${1:-}" in
        --uninstall)
            uninstall_all
            ;;
        --status)
            show_status
            exit 0
            ;;
    esac

    require_root
    detect_arch
    detect_public_ip
    install_base_packages
    prepare_directories_and_certs
    install_singbox
    install_mieru_mita
    generate_or_load_credentials
    configure_singbox_service
    configure_mieru_service
    configure_extra_protocol_servers
    configure_wireguard_service
    configure_ssh_test_account
    open_firewall_ports
    generate_client_configs
    verify_services_and_ports
    print_summary

    if [[ "${1:-}" == "--serve" ]]; then
        enable_http_subscription_server "${2:-20080}"
    fi
}

main "$@"
