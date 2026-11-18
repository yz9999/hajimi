#pragma once
#include "Runtime.hpp"
#include <memory>
#include <string>

namespace hajimi::crypto {
// Failures throw std::runtime_error with static, credential-free messages.
enum class AEAD { AES128GCM, AES192GCM, AES256GCM, ChaCha20Poly1305, XChaCha20Poly1305 };
Buffer randomBytes(size_t count);
Buffer digest(const std::string &name, const Buffer &input);
Buffer digestSlice(const std::string &name, const uint8_t *input, size_t inputLen);
Buffer hmac(const std::string &name, const Buffer &key, const Buffer &input);
Buffer hmacSlice(const std::string &name, const uint8_t *key, size_t keyLen,
                 const uint8_t *input, size_t inputLen);
Buffer hkdf(const std::string &digestName, const Buffer &key, const Buffer &salt,
            const Buffer &info, size_t count);
Buffer hkdfSHA1(const Buffer &key, const Buffer &salt, const Buffer &info, size_t count);
Buffer passwordToKeyMD5(const std::string &password, size_t count);
Buffer aesECBBlock(const Buffer &block, const Buffer &key, bool encrypt = true);
Buffer seal(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &plain,
            const Buffer &associatedData = {});
Buffer open(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &sealed,
            const Buffer &associatedData = {});
Buffer sealSlice(AEAD method, const Buffer &key, const Buffer &nonce,
                 const uint8_t *plain, size_t plainLen,
                 const Buffer &associatedData = {});
Buffer openSlice(AEAD method, const Buffer &key, const Buffer &nonce,
                 const uint8_t *sealed, size_t sealedLen,
                 const Buffer &associatedData = {});
bool sealInto(AEAD method, const uint8_t *key, size_t keyLen,
              const uint8_t *nonce, size_t nonceLen,
              const uint8_t *plain, size_t plainLen,
              uint8_t *dstCipherAndTag,
              const uint8_t *aad = nullptr, size_t aadLen = 0);
bool openInto(AEAD method, const uint8_t *key, size_t keyLen,
              const uint8_t *nonce, size_t nonceLen,
              const uint8_t *cipherAndTag, size_t cipherAndTagLen,
              uint8_t *dstPlain,
              const uint8_t *aad = nullptr, size_t aadLen = 0);
Buffer blake3(const Buffer &input, size_t count = 32);
Buffer blake3Keyed(const Buffer &key, const Buffer &input, size_t count = 32);
Buffer blake3DeriveKey(const std::string &context, const Buffer &material, size_t count = 32);
std::string base64Encode(const Buffer &input);
Buffer base64Decode(const std::string &input, bool urlSafe = false);
bool constantTimeEqual(const Buffer &a, const Buffer &b);

// NIST FIPS 203 ML-KEM-768 via OpenSSL 3.5+ EVP_PKEY provider API (RFC 10024).
inline constexpr size_t kMLKEM768PublicKeyBytes = 1184;
inline constexpr size_t kMLKEM768PrivateKeyBytes = 2400;
inline constexpr size_t kMLKEM768CiphertextBytes = 1088;
inline constexpr size_t kMLKEM768SharedSecretBytes = 32;
bool mlkem768Available() noexcept;
bool mlkem768Keygen(uint8_t *publicKey, size_t publicCap,
                    uint8_t *privateKey, size_t privateCap) noexcept;
bool mlkem768Encaps(const uint8_t *publicKey, size_t publicLen,
                    uint8_t *ciphertext, size_t ciphertextCap,
                    uint8_t *sharedSecret, size_t secretCap) noexcept;
bool mlkem768Decaps(const uint8_t *privateKey, size_t privateLen,
                    const uint8_t *ciphertext, size_t ciphertextLen,
                    uint8_t *sharedSecret, size_t secretCap) noexcept;

// Stateful, non-padding cipher: AES-{128,192,256}-CFB/CTR and ChaCha20.
class CipherStream {
public:
    CipherStream(const std::string &name, const Buffer &key, const Buffer &iv, bool encrypt);
    ~CipherStream();
    CipherStream(CipherStream &&) noexcept;
    CipherStream &operator=(CipherStream &&) noexcept;
    CipherStream(const CipherStream &) = delete;
    CipherStream &operator=(const CipherStream &) = delete;
    Buffer update(const Buffer &input);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace hajimi::crypto
