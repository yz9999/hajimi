#include "Crypto.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <stdexcept>

namespace hajimi::crypto {
namespace {
void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}
int length(size_t value) {
    require(value <= INT_MAX, "Crypto input exceeds implementation limit");
    return static_cast<int>(value);
}
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
EVP_CIPHER_CTX *reusableCipherContext() {
    thread_local CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    require(ctx != nullptr, "Cipher context allocation failed");
    EVP_CIPHER_CTX_reset(ctx.get());
    return ctx.get();
}
const EVP_MD *mdForName(const std::string &name) {
    if (name == "SHA256" || name == "sha256") return EVP_sha256();
    if (name == "SHA1" || name == "sha1") return EVP_sha1();
    if (name == "MD5" || name == "md5") return EVP_md5();
    if (name == "SHA224" || name == "SHA-224" || name == "sha224") return EVP_sha224();
    if (name == "SHA384" || name == "SHA-384" || name == "sha384") return EVP_sha384();
    if (name == "SHA512" || name == "SHA-512" || name == "sha512") return EVP_sha512();
    return EVP_get_digestbyname(name.c_str());
}
uint32_t load32(const uint8_t *p) noexcept {
#if defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
#else
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
#endif
}
void store32(uint32_t value, uint8_t *p) noexcept {
#if defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    std::memcpy(p, &value, sizeof(value));
#else
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(value >> (i * 8));
#endif
}
uint32_t rotl(uint32_t value, unsigned count) noexcept { return value << count | value >> (32 - count); }
void quarter(std::array<uint32_t, 16> &s, unsigned a, unsigned b, unsigned c, unsigned d) noexcept {
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}
void hChaCha20Into(const Buffer &key, const Buffer &nonce, std::array<uint8_t, 32> &out) {
    require(key.size() == 32 && nonce.size() >= 16, "HChaCha20 key or nonce length invalid");
    struct HChaChaCache {
        bool valid = false;
        std::array<uint8_t, 32> key{};
        std::array<uint8_t, 16> nonce16{};
        std::array<uint8_t, 32> derived{};
        ~HChaChaCache() {
            OPENSSL_cleanse(key.data(), key.size());
            OPENSSL_cleanse(nonce16.data(), nonce16.size());
            OPENSSL_cleanse(derived.data(), derived.size());
        }
    };
    thread_local HChaChaCache cache;
    if (cache.valid &&
        std::memcmp(cache.nonce16.data(), nonce.data(), 16) == 0 &&
        CRYPTO_memcmp(cache.key.data(), key.data(), 32) == 0) {
        out = cache.derived;
        return;
    }
    std::array<uint32_t,16> state{0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for (unsigned i = 0; i < 8; ++i) state[i+4] = load32(key.data() + i*4);
    for (unsigned i = 0; i < 4; ++i) state[i+12] = load32(nonce.data() + i*4);
    for (unsigned i = 0; i < 10; ++i) {
        quarter(state,0,4,8,12); quarter(state,1,5,9,13);
        quarter(state,2,6,10,14); quarter(state,3,7,11,15);
        quarter(state,0,5,10,15); quarter(state,1,6,11,12);
        quarter(state,2,7,8,13); quarter(state,3,4,9,14);
    }
    for (unsigned i = 0; i < 4; ++i) {
        store32(state[i], out.data()+i*4);
        store32(state[i+12], out.data()+(i+4)*4);
    }
    OPENSSL_cleanse(state.data(), sizeof(state));
    std::memcpy(cache.key.data(), key.data(), 32);
    std::memcpy(cache.nonce16.data(), nonce.data(), 16);
    cache.derived = out;
    cache.valid = true;
}
const EVP_CIPHER *cipherFor(AEAD method) {
    switch (method) {
    case AEAD::AES128GCM: return EVP_aes_128_gcm();
    case AEAD::AES192GCM: return EVP_aes_192_gcm();
    case AEAD::AES256GCM: return EVP_aes_256_gcm();
    case AEAD::ChaCha20Poly1305:
    case AEAD::XChaCha20Poly1305: return EVP_chacha20_poly1305();
    }
    throw std::runtime_error("Unknown AEAD method");
}
unsigned cipherSlotFor(AEAD method) noexcept {
    switch (method) {
    case AEAD::AES128GCM: return 0;
    case AEAD::AES192GCM: return 1;
    case AEAD::AES256GCM: return 2;
    case AEAD::ChaCha20Poly1305:
    case AEAD::XChaCha20Poly1305: return 3;
    }
    return 0;
}
EVP_CIPHER_CTX *reusableAEADContext(AEAD method, const EVP_CIPHER *algorithm, bool encrypt,
                                    const uint8_t *keyPtr, const uint8_t *noncePtr) {
    struct Slot {
        CipherContext ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
        bool bound = false;
    };
    thread_local Slot slots[4][2];
    Slot &slot = slots[cipherSlotFor(method)][encrypt ? 1 : 0];
    require(slot.ctx != nullptr, "AEAD cipher context allocation failed");
    EVP_CIPHER_CTX *raw = slot.ctx.get();
    if (slot.bound) {
        if (EVP_CipherInit_ex(raw, nullptr, nullptr, keyPtr, noncePtr, encrypt ? 1 : 0) == 1) {
            return raw;
        }
        EVP_CIPHER_CTX_reset(raw);
        slot.bound = false;
    }
    require(EVP_CipherInit_ex(raw, algorithm, nullptr, keyPtr, noncePtr, encrypt ? 1 : 0) == 1,
            "AEAD initialization failed");
    slot.bound = true;
    return raw;
}
}

Buffer randomBytes(size_t count) {
    Buffer result(count);
    require(RAND_bytes(result.data(), length(count)) == 1, "Secure random generator failed");
    return result;
}
Buffer digestSlice(const std::string &name, const uint8_t *input, size_t inputLen) {
    const EVP_MD *algorithm = mdForName(name);
    require(algorithm != nullptr, "Unknown hash algorithm");
    Buffer output(EVP_MD_get_size(algorithm)); unsigned written = 0;
    static const uint8_t emptyByte = 0;
    require(EVP_Digest(inputLen ? input : &emptyByte, inputLen, output.data(), &written, algorithm, nullptr) == 1,
            "Hash calculation failed");
    output.resize(written); return output;
}
Buffer digest(const std::string &name, const Buffer &input) {
    return digestSlice(name, input.data(), input.size());
}
EVP_MAC_CTX *reusableHMACContextFor(const std::string &name, const uint8_t *keyPtr, size_t keyLen) {
    static EVP_MAC *const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    require(mac != nullptr, "HMAC algorithm unavailable");
    using MacCtx = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;
    struct BoundMacSlot {
        MacCtx ctx{EVP_MAC_CTX_new(mac), EVP_MAC_CTX_free};
        bool digestBound = false;
    };
    int slotIdx = -1;
    const char *canonical = name.c_str();
    if (name == "SHA256" || name == "sha256") { slotIdx = 0; canonical = "SHA256"; }
    else if (name == "SHA1" || name == "sha1") { slotIdx = 1; canonical = "SHA1"; }
    else if (name == "MD5" || name == "md5") { slotIdx = 2; canonical = "MD5"; }
    else if (name == "SHA384" || name == "sha384") { slotIdx = 3; canonical = "SHA384"; }
    else if (name == "SHA512" || name == "sha512") { slotIdx = 4; canonical = "SHA512"; }

    if (slotIdx >= 0) {
        thread_local BoundMacSlot slots[5];
        BoundMacSlot &slot = slots[slotIdx];
        require(slot.ctx != nullptr, "HMAC context allocation failed");
        EVP_MAC_CTX *raw = slot.ctx.get();
        if (slot.digestBound) {
            if (EVP_MAC_init(raw, keyPtr, keyLen, nullptr) == 1) {
                return raw;
            }
            slot.digestBound = false;
        }
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(canonical), 0),
            OSSL_PARAM_construct_end()
        };
        require(EVP_MAC_init(raw, keyPtr, keyLen, params) == 1, "HMAC initialization failed");
        slot.digestBound = true;
        return raw;
    }

    thread_local MacCtx fallbackCtx(EVP_MAC_CTX_new(mac), EVP_MAC_CTX_free);
    require(fallbackCtx != nullptr, "HMAC context allocation failed");
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(name.c_str()), 0),
        OSSL_PARAM_construct_end()
    };
    require(EVP_MAC_init(fallbackCtx.get(), keyPtr, keyLen, params) == 1, "HMAC initialization failed");
    return fallbackCtx.get();
}
Buffer hmacSlice(const std::string &name, const uint8_t *key, size_t keyLen,
                 const uint8_t *input, size_t inputLen) {
    static const uint8_t emptyKey = 0;
    EVP_MAC_CTX *ctx = reusableHMACContextFor(name, (keyLen == 0 || !key) ? &emptyKey : key, keyLen);
    require(EVP_MAC_update(ctx, inputLen ? input : &emptyKey, inputLen) == 1, "HMAC update failed");
    Buffer output(EVP_MAC_CTX_get_mac_size(ctx));
    size_t written = 0;
    require(EVP_MAC_final(ctx, output.data(), &written, output.size()) == 1, "HMAC finalization failed");
    output.resize(written);
    return output;
}
Buffer hmac(const std::string &name, const Buffer &key, const Buffer &input) {
    return hmacSlice(name, key.data(), key.size(), input.data(), input.size());
}
Buffer hkdf(const std::string &name, const Buffer &key, const Buffer &salt, const Buffer &info, size_t count) {
    static const uint8_t emptyKey = 0;
    EVP_MAC_CTX *ctx = reusableHMACContextFor(name, salt.empty() ? &emptyKey : salt.data(), salt.size());
    require(EVP_MAC_update(ctx, key.data(), key.size()) == 1, "HKDF extract initialization failed");
    std::array<uint8_t, EVP_MAX_MD_SIZE> prk{};
    size_t prkLen = 0;
    require(EVP_MAC_final(ctx, prk.data(), &prkLen, prk.size()) == 1 && prkLen > 0, "HKDF extract finalization failed");
    require(count <= 255 * prkLen, "HKDF output exceeds specification limit");
    Buffer output;
    output.reserve(count);
    std::array<uint8_t, EVP_MAX_MD_SIZE> prev{};
    size_t prevLen = 0;
    for (unsigned block = 1; output.size() < count; ++block) {
        const uint8_t counter = uint8_t(block);
        require(EVP_MAC_init(ctx, prk.data(), prkLen, nullptr) == 1,
                "HKDF expand init failed");
        if (prevLen > 0) {
            require(EVP_MAC_update(ctx, prev.data(), prevLen) == 1, "HKDF expand update prev failed");
        }
        if (!info.empty()) {
            require(EVP_MAC_update(ctx, info.data(), info.size()) == 1, "HKDF expand update info failed");
        }
        require(EVP_MAC_update(ctx, &counter, 1) == 1 &&
                EVP_MAC_final(ctx, prev.data(), &prevLen, prev.size()) == 1,
                "HKDF expand finalization failed");
        size_t take = std::min(prevLen, count - output.size());
        output.insert(output.end(), prev.data(), prev.data() + take);
    }
    OPENSSL_cleanse(prk.data(), prk.size());
    OPENSSL_cleanse(prev.data(), prev.size());
    return output;
}
Buffer hkdfSHA1(const Buffer &key, const Buffer &salt, const Buffer &info, size_t count) {
    return hkdf("SHA1",key,salt,info,count);
}
Buffer passwordToKeyMD5(const std::string &password, size_t count) {
    require(count <= 64,"Legacy password key length invalid");
    Buffer result, previous, bytes(password.begin(),password.end());
    while (result.size() < count) {
        Buffer input = previous; input.insert(input.end(),bytes.begin(),bytes.end());
        previous = digest("MD5",input);
        result.insert(result.end(),previous.begin(),previous.end());
    }
    result.resize(count); return result;
}

Buffer aesECBBlock(const Buffer &block, const Buffer &key, bool encrypt) {
    require(block.size() == 16,"AES block length invalid");
    const EVP_CIPHER *algorithm = key.size() == 16 ? EVP_aes_128_ecb() :
        key.size() == 24 ? EVP_aes_192_ecb() : key.size() == 32 ? EVP_aes_256_ecb() : nullptr;
    require(algorithm != nullptr,"AES key length invalid");
    EVP_CIPHER_CTX *ctx = reusableCipherContext();
    require(EVP_CipherInit_ex(ctx,algorithm,nullptr,key.data(),nullptr,encrypt?1:0) == 1 &&
            EVP_CIPHER_CTX_set_padding(ctx,0) == 1,"AES initialization failed");
    Buffer output(32); int written=0, final=0;
    require(EVP_CipherUpdate(ctx,output.data(),&written,block.data(),16) == 1 &&
            EVP_CipherFinal_ex(ctx,output.data()+written,&final) == 1 && written+final == 16,
            "AES block processing failed");
    output.resize(16); return output;
}

namespace {
Buffer aeadSlice(bool encrypt, AEAD method, const Buffer &key, const Buffer &nonce,
                 const uint8_t *inputPtr, size_t inputLen, const Buffer &aad) {
    const EVP_CIPHER *algorithm = cipherFor(method);
    require(key.size() == size_t(EVP_CIPHER_get_key_length(algorithm)),"AEAD key length invalid");
    require(nonce.size() == (method == AEAD::XChaCha20Poly1305 ? 24u : 12u),"AEAD nonce length invalid");
    require(encrypt || inputLen >= 16,"AEAD ciphertext is truncated");
    std::array<uint8_t, 32> derivedKey{};
    std::array<uint8_t, 12> derivedNonce{};
    struct SubkeyGuard {
        std::array<uint8_t, 32> &k;
        bool active;
        ~SubkeyGuard() { if (active) OPENSSL_cleanse(k.data(), k.size()); }
    } guard{derivedKey, method == AEAD::XChaCha20Poly1305};
    const uint8_t *keyPtr = key.data();
    const uint8_t *noncePtr = nonce.data();
    if (method == AEAD::XChaCha20Poly1305) {
        hChaCha20Into(key, nonce, derivedKey);
        std::copy(nonce.begin() + 16, nonce.end(), derivedNonce.begin() + 4);
        keyPtr = derivedKey.data();
        noncePtr = derivedNonce.data();
    }
    EVP_CIPHER_CTX *ctx = reusableAEADContext(method, algorithm, encrypt, keyPtr, noncePtr);
    int written=0, final=0;
    if (!aad.empty()) {
        require(EVP_CipherUpdate(ctx,nullptr,&written,aad.data(),length(aad.size())) == 1,
                "AEAD associated data processing failed");
        written = 0;
    }
    size_t dataLength = encrypt ? inputLen : inputLen-16;
    Buffer output(dataLength + 16);
    if (dataLength > 0) {
        require(EVP_CipherUpdate(ctx,output.data(),&written,inputPtr,length(dataLength)) == 1,
                "AEAD processing failed");
    }
    if (!encrypt) require(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,16,
                                const_cast<uint8_t *>(inputPtr+dataLength)) == 1,"AEAD tag setup failed");
    if (EVP_CipherFinal_ex(ctx,output.data()+written,&final) != 1) {
        OPENSSL_cleanse(output.data(),output.size());
        throw std::runtime_error("AEAD authentication failed");
    }
    require(size_t(written+final) == dataLength,"AEAD output length invalid");
    if (encrypt) {
        require(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,output.data()+dataLength) == 1,
                "AEAD tag retrieval failed");
    } else {
        output.resize(dataLength);
    }
    return output;
}
}
Buffer seal(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &plain, const Buffer &aad) {
    return aeadSlice(true,method,key,nonce,plain.data(),plain.size(),aad);
}
Buffer open(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &sealed, const Buffer &aad) {
    return aeadSlice(false,method,key,nonce,sealed.data(),sealed.size(),aad);
}
Buffer sealSlice(AEAD method, const Buffer &key, const Buffer &nonce,
                 const uint8_t *plain, size_t plainLen, const Buffer &aad) {
    return aeadSlice(true,method,key,nonce,plain,plainLen,aad);
}
Buffer openSlice(AEAD method, const Buffer &key, const Buffer &nonce,
                 const uint8_t *sealed, size_t sealedLen, const Buffer &aad) {
    return aeadSlice(false,method,key,nonce,sealed,sealedLen,aad);
}

std::string base64Encode(const Buffer &input) {
    require(input.size() <= size_t(INT_MAX)/4*3,"Base64 input exceeds implementation limit");
    std::string output(4*((input.size()+2)/3)+1,'\0');
    int count=EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&output[0]),input.data(),length(input.size()));
    require(count >= 0,"Base64 encoding failed"); output.resize(count); return output;
}
Buffer base64Decode(const std::string &input, bool urlSafe) {
    if (input.empty()) return {};
    require(input.size() <= size_t(INT_MAX),"Base64 input exceeds implementation limit");
    std::string value = input;
    if (urlSafe) { std::replace(value.begin(),value.end(),'-','+'); std::replace(value.begin(),value.end(),'_','/'); }
    size_t padding = value.find('=');
    if (padding == std::string::npos) padding = value.size();
    require(value.size()-padding <= 2,"Base64 padding invalid");
    for (size_t i=0;i<value.size();++i) {
        char c = value[i];
        bool alphabet=(c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/';
        require(i<padding ? alphabet : c=='=',"Base64 encoding invalid");
    }
    require(padding%4 != 1,"Base64 length invalid");
    if (padding != value.size()) require(value.size()%4 == 0,"Base64 padding invalid");
    while (value.size()%4) value.push_back('=');
    Buffer result(value.size()/4*3);
    int written=EVP_DecodeBlock(result.data(),reinterpret_cast<const uint8_t *>(value.data()),length(value.size()));
    require(written >= 0,"Base64 decoding failed");
    size_t trailing = value.size()-padding;
    require(size_t(written) >= trailing,"Base64 padding invalid");
    result.resize(size_t(written)-trailing);
    // Reject nonzero unused bits, instead of silently accepting malformed PSKs.
    std::string canonical=base64Encode(result);
    require(canonical.substr(0,padding) == value.substr(0,padding),"Base64 unused bits invalid");
    return result;
}
bool constantTimeEqual(const Buffer &a, const Buffer &b) {
    return a.size() == b.size() && (a.empty() || CRYPTO_memcmp(a.data(),b.data(),a.size()) == 0);
}

struct CipherStream::Impl {
    enum class Mode { EVP, RC4, ChaCha20Legacy, Passthrough };
    Mode mode = Mode::EVP;
    CipherContext context{EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free};
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> algorithm{nullptr,EVP_CIPHER_free};
    std::array<uint8_t, 256> rc4S{};
    uint8_t rc4I = 0;
    uint8_t rc4J = 0;
    std::array<uint8_t, 32> chachaKey{};
    std::array<uint8_t, 8> chachaNonce{};
    uint64_t chachaCounter = 0;
    std::array<uint8_t, 64> chachaBlock{};
    size_t chachaOffset = 64;
};
CipherStream::CipherStream(const std::string &name,const Buffer &key,const Buffer &iv,bool encrypt)
    : impl_(std::make_unique<Impl>()) {
    if (name == "NONE" || name == "none" || name == "table") {
        impl_->mode = Impl::Mode::Passthrough;
        return;
    }
    if (name == "RC4" || name == "rc4" || name == "RC4-MD5" || name == "rc4-md5") {
        impl_->mode = Impl::Mode::RC4;
        Buffer actualKey = key;
        if (name == "RC4-MD5" || name == "rc4-md5") {
            require(!key.empty() && !iv.empty(), "RC4-MD5 key or IV empty");
            Buffer material = key;
            material.insert(material.end(), iv.begin(), iv.end());
            actualKey = digest("MD5", material);
        }
        require(!actualKey.empty(), "RC4 key empty");
        for (size_t i = 0; i < 256; ++i) impl_->rc4S[i] = static_cast<uint8_t>(i);
        uint8_t j = 0;
        for (size_t i = 0; i < 256; ++i) {
            j = static_cast<uint8_t>(j + impl_->rc4S[i] + actualKey[i % actualKey.size()]);
            std::swap(impl_->rc4S[i], impl_->rc4S[j]);
        }
        return;
    }
    if (name == "CHACHA20" || name == "chacha20") {
        require(key.size() == 32 && iv.size() == 8, "ChaCha20 key or IV length invalid");
        impl_->mode = Impl::Mode::ChaCha20Legacy;
        std::memcpy(impl_->chachaKey.data(), key.data(), 32);
        std::memcpy(impl_->chachaNonce.data(), iv.data(), 8);
        return;
    }
    if (name == "CHACHA20-IETF" || name == "chacha20-ietf") {
        require(key.size() == 32 && iv.size() == 12, "ChaCha20-IETF key or IV length invalid");
        Buffer osslIv(16, 0);
        std::memcpy(osslIv.data() + 4, iv.data(), 12);
        impl_->algorithm.reset(EVP_CIPHER_fetch(nullptr, "ChaCha20", nullptr));
        require(impl_->context != nullptr && impl_->algorithm != nullptr, "ChaCha20-IETF unavailable");
        require(EVP_CipherInit_ex(impl_->context.get(), impl_->algorithm.get(), nullptr, key.data(), osslIv.data(), encrypt ? 1 : 0) == 1 &&
                EVP_CIPHER_CTX_set_padding(impl_->context.get(), 0) == 1, "ChaCha20-IETF initialization failed");
        return;
    }
    impl_->algorithm.reset(EVP_CIPHER_fetch(nullptr,name.c_str(),nullptr));
    require(impl_->context != nullptr && impl_->algorithm != nullptr,"Stream cipher unavailable");
    require(key.size() == size_t(EVP_CIPHER_get_key_length(impl_->algorithm.get())) &&
            iv.size() == size_t(EVP_CIPHER_get_iv_length(impl_->algorithm.get())),"Stream cipher key or IV length invalid");
    require(EVP_CipherInit_ex(impl_->context.get(),impl_->algorithm.get(),nullptr,key.data(),iv.data(),encrypt?1:0) == 1 &&
            EVP_CIPHER_CTX_set_padding(impl_->context.get(),0) == 1,"Stream cipher initialization failed");
}
CipherStream::~CipherStream() = default;
CipherStream::CipherStream(CipherStream &&) noexcept = default;
CipherStream &CipherStream::operator=(CipherStream &&) noexcept = default;
Buffer CipherStream::update(const Buffer &input) {
    require(impl_ != nullptr,"Stream cipher has been moved");
    if (input.empty()) return {};
    if (impl_->mode == Impl::Mode::Passthrough) {
        return input;
    }
    if (impl_->mode == Impl::Mode::RC4) {
        Buffer output(input.size());
        for (size_t k = 0; k < input.size(); ++k) {
            impl_->rc4I = static_cast<uint8_t>(impl_->rc4I + 1);
            impl_->rc4J = static_cast<uint8_t>(impl_->rc4J + impl_->rc4S[impl_->rc4I]);
            std::swap(impl_->rc4S[impl_->rc4I], impl_->rc4S[impl_->rc4J]);
            uint8_t t = static_cast<uint8_t>(impl_->rc4S[impl_->rc4I] + impl_->rc4S[impl_->rc4J]);
            output[k] = input[k] ^ impl_->rc4S[t];
        }
        return output;
    }
    if (impl_->mode == Impl::Mode::ChaCha20Legacy) {
        Buffer output(input.size());
        for (size_t idx = 0; idx < input.size(); ++idx) {
            if (impl_->chachaOffset >= 64) {
                std::array<uint32_t, 16> state{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
                for (unsigned i = 0; i < 8; ++i) state[i + 4] = load32(impl_->chachaKey.data() + i * 4);
                state[12] = static_cast<uint32_t>(impl_->chachaCounter & 0xffffffffu);
                state[13] = static_cast<uint32_t>((impl_->chachaCounter >> 32) & 0xffffffffu);
                state[14] = load32(impl_->chachaNonce.data());
                state[15] = load32(impl_->chachaNonce.data() + 4);
                auto working = state;
                for (unsigned i = 0; i < 10; ++i) {
                    quarter(working, 0, 4, 8, 12); quarter(working, 1, 5, 9, 13);
                    quarter(working, 2, 6, 10, 14); quarter(working, 3, 7, 11, 15);
                    quarter(working, 0, 5, 10, 15); quarter(working, 1, 6, 11, 12);
                    quarter(working, 2, 7, 8, 13); quarter(working, 3, 4, 9, 14);
                }
                for (unsigned i = 0; i < 16; ++i) {
                    store32(working[i] + state[i], impl_->chachaBlock.data() + i * 4);
                }
                ++impl_->chachaCounter;
                impl_->chachaOffset = 0;
            }
            output[idx] = input[idx] ^ impl_->chachaBlock[impl_->chachaOffset++];
        }
        return output;
    }
    Buffer output(input.size()+EVP_MAX_BLOCK_LENGTH); int written=0;
    require(EVP_CipherUpdate(impl_->context.get(),output.data(),&written,input.data(),length(input.size())) == 1,
            "Stream cipher processing failed");
    output.resize(written); return output;
}
} // namespace hajimi::crypto
