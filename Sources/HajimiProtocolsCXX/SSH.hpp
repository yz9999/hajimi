#pragma once
#include "Runtime.hpp"

namespace hajimi {
Error validateSSH(const Node &, bool udp);
void resetSSHClients();
bool sshSessionPoolSelfTest();
namespace ssh {
bool hostKeyMatches(const Node &, const Buffer &wireKey);
}
} // namespace hajimi
