#pragma once
#include "Runtime.hpp"

namespace hajimi {
Error validateSSH(const Node &, bool udp);
void resetSSHClients();
void resetSSHClient(const std::shared_ptr<TransportFactory> &factory);
bool sshSessionPoolSelfTest();
namespace ssh {
bool hostKeyMatches(const Node &, const Buffer &wireKey);
}
} // namespace hajimi
