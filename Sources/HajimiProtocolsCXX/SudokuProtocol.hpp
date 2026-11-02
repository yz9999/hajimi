#pragma once
#include "Runtime.hpp"

namespace hajimi {

// Sudoku protocol (4x4 grid O(1) hint-table obfuscation + RecordConn AEAD + KIP + UoT)
Error validateSudoku(const Node &node, bool udp);
void connectSudoku(const Node &node, const Target &target,
                   std::shared_ptr<TransportFactory> factory, StreamCallback completion);
void makeSudokuDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                        DatagramCallback completion);
bool sudokuProtocolSelfTest();

} // namespace hajimi
