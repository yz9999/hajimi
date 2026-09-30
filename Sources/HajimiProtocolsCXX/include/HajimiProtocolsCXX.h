#ifndef HAJIMI_PROTOCOLS_CXX_H
#define HAJIMI_PROTOCOLS_CXX_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* The app uses the Objective-C bridge for OS I/O. This symbol executes the
 * pure-C++ protocol/crypto checks without connecting or changing networks. */
int hajimi_cpp_protocol_self_test(void);
/* Returns needed/written bytes, or zero for invalid/oversized inputs. If
 * capacity is smaller than the result, no output bytes are written. */
size_t hajimi_cpp_http_basic_authorization(const uint8_t *username,size_t username_length,
    const uint8_t *password,size_t password_length,uint8_t *output,size_t capacity);
size_t hajimi_cpp_socks5_reply(uint8_t reply,const uint8_t *host,size_t host_length,
    uint16_t port,uint8_t *output,size_t capacity);
#ifdef __cplusplus
}
#endif
#endif
