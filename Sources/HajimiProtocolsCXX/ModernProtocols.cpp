// Aggregated entry point for modular modern outbound protocols (Sudoku, Mieru, TrustTunnel).
// Each protocol is implemented in its own isolated compilation unit:
//   - SudokuProtocol.cpp
//   - MieruProtocol.cpp
//   - TrustTunnelProtocol.cpp
#include "ModernProtocols.hpp"

namespace hajimi {

bool modernProtocolsSelfTest() {
    return sudokuProtocolSelfTest() &&
           mieruProtocolSelfTest() &&
           trustTunnelProtocolSelfTest();
}

} // namespace hajimi
