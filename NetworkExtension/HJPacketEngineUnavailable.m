// A link-time unavailable sentinel, NOT a packet engine. The provider refuses
// startup when this NULL API is returned, before changing network settings.
// A real, force-loaded engine archive supplies a strong definition instead.
#define HJ_PACKET_ENGINE_IMPLEMENTATION 1
#include "HJPacketEngineBridge.h"

__attribute__((weak))
const hj_packet_engine_api_v1 *hajimi_packet_engine_get_api_v1(void) {
    return NULL;
}
