#pragma once
#include "Runtime.hpp"

namespace hajimi {
using SocksAcceptCallback = std::function<void(Target, uint8_t command, Buffer initial, Error)>;
// The listener is responsible for enforcing its loopback binding. This engine
// selects only RFC 1928 no-auth (0); it does not implement a public listener's
// access/authentication policy. On success the stream remains open and the
// caller owns CONNECT/UDP ASSOCIATE routing and the eventual success reply.
// The callback and raw I/O/timer callbacks execute on factory's serial queue.
void acceptSOCKS5(std::shared_ptr<Stream> source, std::shared_ptr<TransportFactory> factory,
                  SocksAcceptCallback completion);
// IPv4/IPv6/domain BND.ADDR encoding. Empty host means the IPv4 wildcard.
// Throws a static, credential-free error for an invalid address/reply code.
Buffer socksReply(uint8_t reply, const Target &bound);
} // namespace hajimi
