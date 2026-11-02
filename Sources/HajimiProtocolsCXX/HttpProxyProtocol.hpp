#pragma once
#include "Runtime.hpp"

namespace hajimi {

// Standalone HTTP / HTTPS CONNECT Outbound Protocol Module
void connectHttpProxyProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion);

} // namespace hajimi
