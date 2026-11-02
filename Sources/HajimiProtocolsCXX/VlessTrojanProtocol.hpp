#pragma once
#include "Runtime.hpp"

namespace hajimi {

// Standalone VLESS (with XTLS Vision) & Trojan Outbound Protocol Module
void connectVlessTrojanProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    StreamCallback completion,
    std::shared_ptr<TransportFactory> factory = nullptr);

} // namespace hajimi
