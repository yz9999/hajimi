#pragma once
#include "Runtime.hpp"

namespace hajimi {

// TrustTunnel protocol (HTTP/1.1 TLS & HTTP/3 QUIC VPN tunnel with TCP & stream-backed UDP)
Error validateTrustTunnel(const Node &node, bool udp);
void connectTrustTunnel(const Node &node, const Target &target,
                        std::shared_ptr<TransportFactory> factory, StreamCallback completion);
void makeTrustTunnelDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                             DatagramCallback completion);
bool trustTunnelProtocolSelfTest();

} // namespace hajimi
