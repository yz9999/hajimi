#ifndef LURGE_QUIC_BRIDGE_H
#define LURGE_QUIC_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t LurgeQUICClientCreate(char *configJSON, char **errorOut);
void LurgeQUICClientClose(uintptr_t handle);
uintptr_t LurgeQUICTCPConnect(uintptr_t handle, char *host, uint16_t port, char **errorOut);
long long LurgeQUICStreamRead(uintptr_t handle, void *buffer, int capacity, char **errorOut);
long long LurgeQUICStreamWrite(uintptr_t handle, void *buffer, int length, char **errorOut);
void LurgeQUICStreamClose(uintptr_t handle);
uintptr_t LurgeQUICUDPCreate(uintptr_t handle, char **errorOut);
int LurgeQUICUDPSend(uintptr_t handle, char *host, uint16_t port,
                     void *buffer, int length, char **errorOut);
long long LurgeQUICUDPReceive(uintptr_t handle, void *buffer, int capacity,
                             char *hostBuffer, int hostCapacity, uint16_t *portOut,
                             char **errorOut);
void LurgeQUICUDPClose(uintptr_t handle);
void LurgeQUICFreeCString(char *value);

#ifdef __cplusplus
}
#endif

#endif
