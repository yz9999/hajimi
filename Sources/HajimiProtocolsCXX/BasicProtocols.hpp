#pragma once
#include "Runtime.hpp"

namespace hajimi {
void connectBasicProtocol(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeBasicDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
Error validateBasicProtocol(const Node &, bool udp);
Buffer uuidBytes(const std::string &);
Buffer vmessKDF(const Buffer &,const std::vector<Buffer> &);
void connectVMessProtocol(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void connectSocksAssociation(const Node &, std::shared_ptr<TransportFactory>, std::function<void(std::shared_ptr<Stream>,Target,Error)>,
    std::function<void(std::shared_ptr<Stream>)> transportReady={});
void makeSocksDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
} // namespace hajimi
