#pragma once
#include "Runtime.hpp"
#include "ProtocolStream.hpp"

namespace hajimi {

// Standalone SOCKS5 / SOCKS5-TLS Outbound Protocol Module
void readSocksAddressFromReader(
    std::shared_ptr<Reader> reader,
    uint8_t type,
    std::function<void(Buffer, Error)> completion);

void connectSocks5Protocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion);

} // namespace hajimi
