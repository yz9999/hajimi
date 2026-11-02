#pragma once
#include "Runtime.hpp"

namespace hajimi {

// Mieru protocol (PBKDF2 2-minute time-bucket key derivation + XChaCha20-Poly1305 + TCP/UDP underlays)
Error validateMieru(const Node &node, bool udp);
void connectMieru(const Node &node, const Target &target,
                  std::shared_ptr<TransportFactory> factory, StreamCallback completion);
void makeMieruDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                       DatagramCallback completion);
bool mieruProtocolSelfTest();

} // namespace hajimi
