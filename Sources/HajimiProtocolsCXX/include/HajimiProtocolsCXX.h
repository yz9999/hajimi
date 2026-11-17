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

/* NIST FIPS 203 ML-KEM-768 via OpenSSL 3.5+ EVP_PKEY standard provider API
 * (for RFC 10024 X25519MLKEM768 hybrid TLS 1.3 key exchange).
 * Sizes: public_key = 1184 bytes, private_key = 2400 bytes,
 *        ciphertext = 1088 bytes, shared_secret = 32 bytes.
 * Returns 1 on success, 0 if OpenSSL < 3.5 or inputs are invalid. */
int hajimi_cpp_mlkem768_available(void);
int hajimi_cpp_mlkem768_keygen(uint8_t *public_key,size_t public_capacity,
    uint8_t *private_key,size_t private_capacity);
int hajimi_cpp_mlkem768_decaps(const uint8_t *private_key,size_t private_length,
    const uint8_t *ciphertext,size_t ciphertext_length,
    uint8_t *shared_secret,size_t secret_capacity);
#ifdef __cplusplus
}
#endif
#endif
