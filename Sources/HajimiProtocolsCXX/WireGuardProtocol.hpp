#pragma once
#include "Runtime.hpp"

namespace hajimi {

Error validateWireGuard(const Node &node, bool udp);
void connectWireGuard(const Node &node, const Target &target,
                      std::shared_ptr<TransportFactory> factory,
                      StreamCallback completion);
void makeWireGuardDatagram(const Node &node,
                           std::shared_ptr<TransportFactory> factory,
                           DatagramCallback completion);
void resetWireGuardClient(const std::shared_ptr<TransportFactory> &factory);
bool wireGuardProtocolSelfTest();

} // namespace hajimi
