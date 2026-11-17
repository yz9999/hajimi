#include "include/HajimiProtocolsCXX.h"
#include "BasicProtocols.hpp"
#include "ProtocolStream.hpp"
#include "Crypto.hpp"
#include "ServerProtocols.hpp"
#include "ModernProtocols.hpp"
#include "SSH.hpp"
#include <array>
#include <openssl/crypto.h>
#include <cstring>
#include <stdexcept>
#include <vector>

using namespace hajimi;
static Buffer hex(const std::string &value){
    Buffer result;for(size_t offset=0;offset<value.size();offset+=2)result.push_back(uint8_t(std::stoul(value.substr(offset,2),nullptr,16)));return result;
}
static bool orderedWriterCoalesceSelfTest(){
    struct DeferredCarrier final : Stream {
        std::vector<Buffer> writes;
        std::vector<WriteCallback> pending;
        bool finCalled = false;
        void write(Buffer data, WriteCallback completion) override {
            writes.push_back(std::move(data));
            pending.push_back(std::move(completion));
        }
        void read(size_t, ReadCallback cb) override { cb({}, true, {}); }
        void close() override {}
        void shutdownWrite(WriteCallback completion) override {
            finCalled = true;
            pending.push_back(std::move(completion));
        }
        bool supportsHalfClose() const override { return true; }
        void step() {
            if (pending.empty()) return;
            auto cb = std::move(pending.front());
            pending.erase(pending.begin());
            cb({});
        }
    };
    auto carrier = std::make_shared<DeferredCarrier>();
    auto writer = std::make_shared<OrderedWriter>(carrier, maximumQueuedBytes, 128, 32768);
    std::vector<int> order;
    // First write starts active carrier write immediately; next 3 queue behind it and coalesce into 1 write!
    writer->write({1, 2}, [&](Error e) { if (e.empty()) order.push_back(1); });
    writer->write({3, 4, 5}, [&](Error e) { if (e.empty()) order.push_back(2); });
    writer->write({6}, [&](Error e) { if (e.empty()) order.push_back(3); });
    writer->write({7, 8, 9}, [&](Error e) { if (e.empty()) order.push_back(4); });
    writer->finish([&](Error e) { if (e.empty()) order.push_back(5); });
    if (carrier->writes.size() != 1 || carrier->writes[0] != Buffer{1, 2}) return false;
    carrier->step(); // completes {1, 2} and flushes coalesced {3, 4, 5, 6, 7, 8, 9}
    if (carrier->writes.size() != 2 || carrier->writes[1] != Buffer{3, 4, 5, 6, 7, 8, 9}) return false;
    carrier->step(); // completes coalesced batch and flushes FIN
    if (!carrier->finCalled) return false;
    carrier->step(); // completes FIN
    return order == std::vector<int>{1, 2, 3, 4, 5};
}
extern "C" int hajimi_cpp_protocol_self_test(void){
    try{
        auto key=hex("000102030405060708090a0b0c0d0e0f"),plain=hex("00112233445566778899aabbccddeeff");
        if(crypto::aesECBBlock(plain,key)!=hex("69c4e0d86a7b0430d8cdb78070b4c55a"))return 1;
        if(crypto::blake3({})!=hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"))return 2;
        Buffer zeroKey(16),nonce(12);
        if(crypto::seal(crypto::AEAD::AES128GCM,zeroKey,nonce,{})!=hex("58e2fccefa7e3061367f1d57a4e7455a"))return 3;
        if(crypto::hkdf("SHA256",Buffer(22,0x0b),hex("000102030405060708090a0b0c"),hex("f0f1f2f3f4f5f6f7f8f9"),42)!=hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))return 4;
        if(uuidBytes("00010203-0405-0607-0809-0a0b0c0d0e0f")!=key)return 5;
        auto utf8=[](const std::string &value){return Buffer(value.begin(),value.end());};
        if(vmessKDF(utf8("Demo Key for KDF Value Test"),{utf8("Demo Path for KDF Value Test"),utf8("Demo Path for KDF Value Test2"),utf8("Demo Path for KDF Value Test3")})!=hex("53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"))return 8;
        for(auto host:{"127.0.0.1","2001:db8::1","example.com"}){
            Target target{host,443,true,false};auto encoded=socksAddress(target);size_t consumed=0;auto parsed=parseSocksAddress(encoded,consumed);
            if(parsed.host!=target.host || parsed.port!=443 || consumed!=encoded.size())return 6;
        }
        auto username=hex("75736572"),password=hex("70617373");uint8_t output[32];
        auto length=hajimi_cpp_http_basic_authorization(username.data(),username.size(),password.data(),password.size(),output,sizeof(output));
        if(std::string(reinterpret_cast<char *>(output),length)!="Basic dXNlcjpwYXNz")return 7;
        if(!modernProtocolsSelfTest())return 9;
        for (const auto &sshHost : {"198.51.100.10", "2001:db8::10"}) {
            Node sshNode;
            sshNode.type = "ssh";
            sshNode.host = sshHost;
            sshNode.port = 22;
            sshNode.parameters["username"] = "ssh-user";
            sshNode.parameters["password"] = "example-secret";
            sshNode.parameters["host-key"] = "[ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti]";
            sshNode.parameters["host-key-algorithms"] = "[ssh-ed25519]";
            if (!validateProtocol(sshNode, false).empty()) return 10;
        }
        for (const auto &ssrHost : {"198.51.100.10", "2001:db8::10"}) {
            Node ssrNode;
            ssrNode.type = "ssr";
            ssrNode.host = ssrHost;
            ssrNode.port = 8388;
            ssrNode.parameters["cipher"] = "aes-128-cfb";
            ssrNode.parameters["password"] = "example-secret";
            ssrNode.parameters["protocol"] = "origin";
            ssrNode.parameters["obfs"] = "plain";
            if (!validateProtocol(ssrNode, false).empty() || !validateProtocol(ssrNode, true).empty()) return 11;
        }
        if (!sshSessionPoolSelfTest()) return 12;
        if (hajimi_cpp_mlkem768_available()) {
            std::array<uint8_t, crypto::kMLKEM768PublicKeyBytes> pk{};
            std::array<uint8_t, crypto::kMLKEM768PrivateKeyBytes> sk{};
            std::array<uint8_t, crypto::kMLKEM768CiphertextBytes> ct{};
            std::array<uint8_t, crypto::kMLKEM768SharedSecretBytes> ssEnc{}, ssDec{};
            if (!hajimi_cpp_mlkem768_keygen(pk.data(), pk.size(), sk.data(), sk.size())) return 13;
            if (!crypto::mlkem768Encaps(pk.data(), pk.size(), ct.data(), ct.size(), ssEnc.data(), ssEnc.size())) return 14;
            if (!hajimi_cpp_mlkem768_decaps(sk.data(), sk.size(), ct.data(), ct.size(), ssDec.data(), ssDec.size())) return 15;
            if (CRYPTO_memcmp(ssEnc.data(), ssDec.data(), ssEnc.size()) != 0) return 16;
            ct[0] ^= 0xff; // NIST FIPS 203 implicit rejection must yield an independent secret
            std::array<uint8_t, crypto::kMLKEM768SharedSecretBytes> ssTampered{};
            if (hajimi_cpp_mlkem768_decaps(sk.data(), sk.size(), ct.data(), ct.size(), ssTampered.data(), ssTampered.size()) &&
                CRYPTO_memcmp(ssEnc.data(), ssTampered.data(), ssEnc.size()) == 0) return 17;
            OPENSSL_cleanse(sk.data(), sk.size());
            OPENSSL_cleanse(ssEnc.data(), ssEnc.size());
            OPENSSL_cleanse(ssDec.data(), ssDec.size());
            OPENSSL_cleanse(ssTampered.data(), ssTampered.size());
        } else {
            uint8_t dummy[32]{};
            if (hajimi_cpp_mlkem768_keygen(dummy, sizeof(dummy), dummy, sizeof(dummy)) != 0) return 18;
        }
        if (!orderedWriterCoalesceSelfTest()) return 19;
        return 0;
    }catch(const std::exception &){return 99;}
}
extern "C" size_t hajimi_cpp_http_basic_authorization(const uint8_t *username,size_t usernameLength,const uint8_t *password,size_t passwordLength,uint8_t *output,size_t capacity){
    if((!username && usernameLength) || (!password && passwordLength) || usernameLength>4096 || passwordLength>4096)return 0;
    try{
        Buffer input;if(usernameLength)input.insert(input.end(),username,username+usernameLength);input.push_back(':');
        if(passwordLength)input.insert(input.end(),password,password+passwordLength);
        auto value=std::string("Basic ")+crypto::base64Encode(input);
        OPENSSL_cleanse(input.data(), input.size());
        if(output && capacity>=value.size())std::memcpy(output,value.data(),value.size());
        size_t outLen = value.size();
        OPENSSL_cleanse(value.data(), value.size());
        return outLen;
    }catch(const std::exception &){return 0;}
}
extern "C" size_t hajimi_cpp_socks5_reply(uint8_t reply,const uint8_t *host,size_t hostLength,uint16_t port,uint8_t *output,size_t capacity){
    if((!host && hostLength) || hostLength>255)return 0;
    try{Target target;target.port=port;if(hostLength)target.host.assign(reinterpret_cast<const char *>(host),hostLength);
        auto value=socksReply(reply,target);if(output && capacity>=value.size())std::memcpy(output,value.data(),value.size());
        return value.size();
    }catch(const std::exception &){return 0;}
}
extern "C" int hajimi_cpp_mlkem768_available(void){
    return crypto::mlkem768Available() ? 1 : 0;
}
extern "C" int hajimi_cpp_mlkem768_keygen(uint8_t *publicKey,size_t publicCapacity,uint8_t *privateKey,size_t privateCapacity){
    return crypto::mlkem768Keygen(publicKey, publicCapacity, privateKey, privateCapacity) ? 1 : 0;
}
extern "C" int hajimi_cpp_mlkem768_decaps(const uint8_t *privateKey,size_t privateLength,const uint8_t *ciphertext,size_t ciphertextLength,uint8_t *sharedSecret,size_t secretCapacity){
    return crypto::mlkem768Decaps(privateKey, privateLength, ciphertext, ciphertextLength, sharedSecret, secretCapacity) ? 1 : 0;
}
