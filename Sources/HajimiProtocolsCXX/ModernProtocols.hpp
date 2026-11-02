#pragma once
#include "SudokuProtocol.hpp"
#include "MieruProtocol.hpp"
#include "TrustTunnelProtocol.hpp"

namespace hajimi {

// Aggregated self-test entry point for Sudoku, Mieru, and TrustTunnel
bool modernProtocolsSelfTest();

} // namespace hajimi
