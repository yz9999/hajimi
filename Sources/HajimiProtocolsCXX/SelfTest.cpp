#include "include/HajimiProtocolsCXX.h"
#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ServerProtocols.hpp"
#include <cstring>
#include <stdexcept>

using namespace hajimi;
static Buffer hex(const std::string &value){
    Buffer result;for(size_t offset=0;offset<value.size();offset+=2)result.push_back(uint8_t(std::stoul(value.substr(offset,2),nullptr,16)));return result;
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
        return 0;
    }catch(const std::exception &){return 99;}
}
extern "C" size_t hajimi_cpp_http_basic_authorization(const uint8_t *username,size_t usernameLength,const uint8_t *password,size_t passwordLength,uint8_t *output,size_t capacity){
    if((!username && usernameLength) || (!password && passwordLength) || usernameLength>4096 || passwordLength>4096)return 0;
    try{
        Buffer input;if(usernameLength)input.insert(input.end(),username,username+usernameLength);input.push_back(':');
        if(passwordLength)input.insert(input.end(),password,password+passwordLength);
        auto value=std::string("Basic ")+crypto::base64Encode(input);
        if(output && capacity>=value.size())std::memcpy(output,value.data(),value.size());return value.size();
    }catch(const std::exception &){return 0;}
}
extern "C" size_t hajimi_cpp_socks5_reply(uint8_t reply,const uint8_t *host,size_t hostLength,uint16_t port,uint8_t *output,size_t capacity){
    if((!host && hostLength) || hostLength>255)return 0;
    try{Target target;target.port=port;if(hostLength)target.host.assign(reinterpret_cast<const char *>(host),hostLength);
        auto value=socksReply(reply,target);if(output && capacity>=value.size())std::memcpy(output,value.data(),value.size());return value.size();
    }catch(const std::exception &){return 0;}
}
