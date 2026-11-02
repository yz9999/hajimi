#pragma once
#include "Runtime.hpp"

namespace hajimi {
Error validateSSH(const Node &, bool udp);
namespace ssh {
bool hostKeyMatches(const Node &, const Buffer &wireKey);
}
} // namespace hajimi
