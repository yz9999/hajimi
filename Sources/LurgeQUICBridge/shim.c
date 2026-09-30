#include "LurgeQUICBridge.h"

// Bump when the statically linked Go archive changes so SwiftPM relinks both
// the GUI and Helper even though the archive lives behind an unsafe -L flag.
int lurge_quic_bridge_anchor = 3;
