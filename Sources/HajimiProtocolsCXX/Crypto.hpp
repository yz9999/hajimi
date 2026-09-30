#pragma once
#include "Runtime.hpp"
#include <memory>
#include <string>

namespace hajimi::crypto {
// Failures throw std::runtime_error with static, credential-free messages.
enum class AEAD { AES128GCM, AES192GCM, AES256GCM, ChaCha20Poly1305, XChaCha20Poly1305 };
Buffer randomBytes(size_t count);
Buffer digest(const std::string &name, const Buffer &input);
Buffer hmac(const std::string &name, const Buffer &key, const Buffer &input);
Buffer hkdf(const std::string &digestName, const Buffer &key, const Buffer &salt,
            const Buffer &info, size_t count);
Buffer hkdfSHA1(const Buffer &key, const Buffer &salt, const Buffer &info, size_t count);
Buffer passwordToKeyMD5(const std::string &password, size_t count);
Buffer aesECBBlock(const Buffer &block, const Buffer &key, bool encrypt = true);
Buffer seal(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &plain,
            const Buffer &associatedData = {});
Buffer open(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &sealed,
            const Buffer &associatedData = {});
Buffer blake3(const Buffer &input, size_t count = 32);
Buffer blake3Keyed(const Buffer &key, const Buffer &input, size_t count = 32);
Buffer blake3DeriveKey(const std::string &context, const Buffer &material, size_t count = 32);
std::string base64Encode(const Buffer &input);
Buffer base64Decode(const std::string &input, bool urlSafe = false);
bool constantTimeEqual(const Buffer &a, const Buffer &b);

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
