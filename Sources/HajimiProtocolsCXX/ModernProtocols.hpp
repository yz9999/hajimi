#pragma once
#include "SudokuProtocol.hpp"
#include "MieruProtocol.hpp"
#include "TrustTunnelProtocol.hpp"
#include "WireGuardProtocol.hpp"

namespace hajimi {

// Aggregated self-test entry point for Sudoku, Mieru, TrustTunnel, and WireGuard
bool modernProtocolsSelfTest();

} // namespace hajimi
