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
uint32_t load32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
void store32(uint32_t value, uint8_t *p) {
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(value >> (i * 8));
}
uint32_t rotl(uint32_t value, unsigned count) { return value << count | value >> (32 - count); }
void quarter(std::array<uint32_t, 16> &s, unsigned a, unsigned b, unsigned c, unsigned d) {
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}
Buffer hChaCha20(const Buffer &key, const Buffer &nonce) {
    require(key.size() == 32 && nonce.size() >= 16, "HChaCha20 key or nonce length invalid");
    std::array<uint32_t,16> state{0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for (unsigned i = 0; i < 8; ++i) state[i+4] = load32(key.data() + i*4);
    for (unsigned i = 0; i < 4; ++i) state[i+12] = load32(nonce.data() + i*4);
    for (unsigned i = 0; i < 10; ++i) {
        quarter(state,0,4,8,12); quarter(state,1,5,9,13);
        quarter(state,2,6,10,14); quarter(state,3,7,11,15);
        quarter(state,0,5,10,15); quarter(state,1,6,11,12);
        quarter(state,2,7,8,13); quarter(state,3,4,9,14);
    }
    Buffer result(32);
    for (unsigned i = 0; i < 4; ++i) {
        store32(state[i], result.data()+i*4);
        store32(state[i+12], result.data()+(i+4)*4);
    }
    OPENSSL_cleanse(state.data(), sizeof(state));
    return result;
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
}

Buffer randomBytes(size_t count) {
    Buffer result(count);
    require(RAND_bytes(result.data(), length(count)) == 1, "Secure random generator failed");
    return result;
}
Buffer digest(const std::string &name, const Buffer &input) {
    const EVP_MD *algorithm = EVP_get_digestbyname(name.c_str());
    require(algorithm != nullptr, "Unknown hash algorithm");
    Buffer output(EVP_MD_get_size(algorithm)); unsigned written = 0;
    require(EVP_Digest(input.data(), input.size(), output.data(), &written, algorithm, nullptr) == 1,
            "Hash calculation failed");
    output.resize(written); return output;
}
Buffer hmac(const std::string &name, const Buffer &key, const Buffer &input) {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr,"HMAC",nullptr),EVP_MAC_free);
    require(mac != nullptr, "HMAC algorithm unavailable");
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac.get()),EVP_MAC_CTX_free);
    require(ctx != nullptr, "HMAC context allocation failed");
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,const_cast<char *>(name.c_str()),0),
        OSSL_PARAM_construct_end()
    };
    static const uint8_t emptyKey = 0;
    require(EVP_MAC_init(ctx.get(),key.empty()?&emptyKey:key.data(),key.size(),params) == 1,
            "HMAC initialization failed");
    require(EVP_MAC_update(ctx.get(),input.data(),input.size()) == 1,"HMAC update failed");
    Buffer output(EVP_MAC_CTX_get_mac_size(ctx.get())); size_t written = 0;
    require(EVP_MAC_final(ctx.get(),output.data(),&written,output.size()) == 1,"HMAC finalization failed");
    output.resize(written); return output;
}
Buffer hkdf(const std::string &name, const Buffer &key, const Buffer &salt, const Buffer &info, size_t count) {
    Buffer prk = hmac(name,salt,key), output, previous;
    require(count <= 255 * prk.size(),"HKDF output exceeds specification limit");
    output.reserve(count);
    for (unsigned block = 1; output.size() < count; ++block) {
        Buffer material = previous;
        material.insert(material.end(),info.begin(),info.end()); material.push_back(uint8_t(block));
        previous = hmac(name,prk,material);
        size_t take = std::min(previous.size(), count-output.size());
        output.insert(output.end(),previous.begin(),previous.begin()+take);
    }
    OPENSSL_cleanse(prk.data(),prk.size()); return output;
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
    CipherContext ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    require(ctx != nullptr,"Cipher context allocation failed");
    require(EVP_CipherInit_ex(ctx.get(),algorithm,nullptr,key.data(),nullptr,encrypt?1:0) == 1 &&
            EVP_CIPHER_CTX_set_padding(ctx.get(),0) == 1,"AES initialization failed");
    Buffer output(32); int written=0, final=0;
    require(EVP_CipherUpdate(ctx.get(),output.data(),&written,block.data(),16) == 1 &&
            EVP_CipherFinal_ex(ctx.get(),output.data()+written,&final) == 1 && written+final == 16,
            "AES block processing failed");
    output.resize(16); return output;
}

namespace {
Buffer aead(bool encrypt, AEAD method, const Buffer &key, const Buffer &nonce,
            const Buffer &input, const Buffer &aad) {
    const EVP_CIPHER *algorithm = cipherFor(method);
    require(key.size() == size_t(EVP_CIPHER_get_key_length(algorithm)),"AEAD key length invalid");
    require(nonce.size() == (method == AEAD::XChaCha20Poly1305 ? 24u : 12u),"AEAD nonce length invalid");
    require(encrypt || input.size() >= 16,"AEAD ciphertext is truncated");
    Buffer actualKey = key, actualNonce = nonce;
    if (method == AEAD::XChaCha20Poly1305) {
        actualKey = hChaCha20(key,nonce); actualNonce.assign(12,0);
        std::copy(nonce.begin()+16,nonce.end(),actualNonce.begin()+4);
    }
    CipherContext ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    require(ctx != nullptr,"AEAD context allocation failed");
    require(EVP_CipherInit_ex(ctx.get(),algorithm,nullptr,nullptr,nullptr,encrypt?1:0) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_AEAD_SET_IVLEN,length(actualNonce.size()),nullptr) == 1 &&
            EVP_CipherInit_ex(ctx.get(),nullptr,nullptr,actualKey.data(),actualNonce.data(),encrypt?1:0) == 1,
            "AEAD initialization failed");
    OPENSSL_cleanse(actualKey.data(),actualKey.size());
    int written=0, final=0;
    if (!aad.empty()) require(EVP_CipherUpdate(ctx.get(),nullptr,&written,aad.data(),length(aad.size())) == 1,
                              "AEAD associated data processing failed");
    size_t dataLength = encrypt ? input.size() : input.size()-16;
    Buffer output(dataLength+16);
    require(EVP_CipherUpdate(ctx.get(),output.data(),&written,input.data(),length(dataLength)) == 1,
            "AEAD processing failed");
    if (!encrypt) require(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_AEAD_SET_TAG,16,
                                const_cast<uint8_t *>(input.data()+dataLength)) == 1,"AEAD tag setup failed");
    if (EVP_CipherFinal_ex(ctx.get(),output.data()+written,&final) != 1) {
        OPENSSL_cleanse(output.data(),output.size());
        throw std::runtime_error("AEAD authentication failed");
    }
    require(size_t(written+final) == dataLength,"AEAD output length invalid");
    if (encrypt) require(EVP_CIPHER_CTX_ctrl(ctx.get(),EVP_CTRL_AEAD_GET_TAG,16,output.data()+dataLength) == 1,
                         "AEAD tag retrieval failed");
    else output.resize(dataLength);
    return output;
}
}
Buffer seal(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &plain, const Buffer &aad) {
    return aead(true,method,key,nonce,plain,aad);
}
Buffer open(AEAD method, const Buffer &key, const Buffer &nonce, const Buffer &sealed, const Buffer &aad) {
    return aead(false,method,key,nonce,sealed,aad);
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
    CipherContext context{EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free};
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> algorithm{nullptr,EVP_CIPHER_free};
};
CipherStream::CipherStream(const std::string &name,const Buffer &key,const Buffer &iv,bool encrypt)
    : impl_(std::make_unique<Impl>()) {
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
    Buffer output(input.size()+EVP_MAX_BLOCK_LENGTH); int written=0;
    require(EVP_CipherUpdate(impl_->context.get(),output.data(),&written,input.data(),length(input.size())) == 1,
            "Stream cipher processing failed");
    output.resize(written); return output;
}
} // namespace hajimi::crypto
