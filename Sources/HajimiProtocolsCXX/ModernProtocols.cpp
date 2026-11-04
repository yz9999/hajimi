// Aggregated entry point for modular modern outbound protocols (Sudoku, Mieru, TrustTunnel, WireGuard).
// Each protocol is implemented in its own isolated compilation unit:
//   - SudokuProtocol.cpp
//   - MieruProtocol.cpp
//   - TrustTunnelProtocol.cpp
//   - WireGuardProtocol.cpp
#include "ModernProtocols.hpp"

namespace hajimi {

bool modernProtocolsSelfTest() {
    return sudokuProtocolSelfTest() &&
           mieruProtocolSelfTest() &&
           trustTunnelProtocolSelfTest() &&
           wireGuardProtocolSelfTest();
}

} // namespace hajimi
