#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include <algorithm>
#include <array>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace hajimi {
using Hash=std::function<Buffer(const Buffer &)>;
static Buffer genericHMAC(const Buffer &key,const Buffer &message,const Hash &hash) {
    Buffer normalized=key.size()>64?hash(key):key; normalized.resize(64);
    Buffer inner(64),outer(64);
    inner.reserve(64 + message.size());
    outer.reserve(96);
    for(size_t i=0;i<64;++i){inner[i]=normalized[i]^0x36;outer[i]=normalized[i]^0x5c;}
    inner.insert(inner.end(),message.begin(),message.end()); auto result=hash(inner);
    outer.insert(outer.end(),result.begin(),result.end()); return hash(outer);
}
Buffer vmessKDF(const Buffer &key,const std::vector<Buffer> &path) {
    static const Buffer kVmessKdfSalt = bytes("VMess AEAD KDF");
    Hash creator=[](const Buffer &message){return crypto::hmac("SHA256",kVmessKdfSalt,message);};
    for(auto &salt:path){auto parent=creator;creator=[salt,parent](const Buffer &message){return genericHMAC(salt,message,parent);};}
    return creator(key);
}
static uint32_t fnv1a(const Buffer &data) { uint32_t hash=2166136261U;for(auto byte:data)hash=(hash^byte)*16777619U;return hash; }
static uint32_t crc32(const Buffer &data) noexcept {
    static constexpr std::array<uint32_t, 256> kTable = []() constexpr {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t v = i;
            for (int n = 0; n < 8; ++n) v = (v >> 1) ^ ((v & 1) ? 0xedb88320U : 0);
            t[i] = v;
        }
        return t;
    }();
    uint32_t value=0xffffffffU;
    for(auto byte:data) value = (value >> 8) ^ kTable[(value ^ byte) & 0xffU];
    return ~value;
}
static Buffer bodyNonce(uint32_t counter,const Buffer &iv) {
    if(counter>65535 || iv.size()<12)throw std::runtime_error("VMess nonce sequence exhausted");
    Buffer nonce;nonce.reserve(12);append16(nonce,uint16_t(counter));nonce.insert(nonce.end(),iv.begin()+2,iv.begin()+12);return nonce;
}
static Buffer vmessChaChaPolyKey(const Buffer &key16) {
    Buffer first = crypto::digest("MD5", key16);
    Buffer second = crypto::digest("MD5", first);
    first.insert(first.end(), second.begin(), second.end());
    return first;
}
static const std::pair<Buffer, Buffer> &cachedVmessCommandAndAuthKey(const Buffer &uuid16) {
    std::string keyStr(reinterpret_cast<const char *>(uuid16.data()), uuid16.size());
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, std::pair<Buffer, Buffer>> cache;
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(keyStr);
        if (it != cache.end()) return it->second;
        if (cache.size() > 64) cache.clear();
    }
    Buffer material = uuid16;
    static const Buffer kSuffix = bytes("c48619fe-8f02-49e0-b9e9-edf763e17e21");
    material.insert(material.end(), kSuffix.begin(), kSuffix.end());
    Buffer cmdKey = crypto::digest("MD5", material);
    Buffer authKey = prefix(vmessKDF(cmdKey, {bytes("AES Auth ID Encryption")}), 16);
    std::lock_guard<std::mutex> lock(cacheMutex);
    return cache.emplace(std::move(keyStr), std::make_pair(std::move(cmdKey), std::move(authKey))).first->second;
}
static Buffer sealHeader(const Buffer &command,const Buffer &commandKey,const Buffer &authKey) {
    Buffer auth;auth.reserve(16);append64(auth,unixSeconds());auto random=crypto::randomBytes(4);auth.insert(auth.end(),random.begin(),random.end());append32(auth,crc32(auth));
    auto authID=crypto::aesECBBlock(auth,authKey),connectionNonce=crypto::randomBytes(8);
    auto lengthKey=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Key_Length"),authID,connectionNonce}),16);
    auto lengthIV=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Nonce_Length"),authID,connectionNonce}),12);
    Buffer length;append16(length,uint16_t(command.size()));
    auto encryptedLength=crypto::seal(crypto::AEAD::AES128GCM,lengthKey,lengthIV,length,authID);
    auto payloadKey=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Key"),authID,connectionNonce}),16);
    auto payloadIV=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Nonce"),authID,connectionNonce}),12);
    auto payload=crypto::seal(crypto::AEAD::AES128GCM,payloadKey,payloadIV,command,authID);
    Buffer output;output.reserve(authID.size()+encryptedLength.size()+connectionNonce.size()+payload.size());
    output.insert(output.end(),authID.begin(),authID.end());
    output.insert(output.end(),encryptedLength.begin(),encryptedLength.end());
    output.insert(output.end(),connectionNonce.begin(),connectionNonce.end());
    output.insert(output.end(),payload.begin(),payload.end());
    return output;
}
class VMessStream final:public Stream,public std::enable_shared_from_this<VMessStream> {
    std::shared_ptr<Stream> source_;std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Reader> reader_;std::shared_ptr<OrderedWriter> writer_;
    Buffer requestIV_,requestKey_,responseIV_,responseKey_,bodyTxKey_,bodyRxKey_,request_;
    proto_common::CursorBuffer buffer_;
    uint8_t verification_,securityType_=3;uint32_t writeCounter_=0,readCounter_=0;
    crypto::AEAD bodyAead_=crypto::AEAD::AES128GCM;
    bool udp_,bodyEncrypted_=true,chunkStream_=true,coalesceHeader_=false,headerSent_=false,ready_=false,closed_=false,eof_=false,writeEnded_=false;
    ReadCallback pending_;size_t maximum_=0;
    void flushPendingHeaderIfIdle(){
        if(closed_ || headerSent_)return;
        headerSent_=true;
        Buffer header=std::move(request_);request_.clear();
        if(header.empty())return;
        auto self=shared_from_this();
        writer_->write(std::move(header),[self](Error error){
            if(!error.empty() && !self->closed_)self->failRead(error);
        });
    }
    void finishRead(Buffer data,bool eof,Error error){auto callback=std::move(pending_);pending_=nullptr;if(callback)callback(std::move(data),eof,std::move(error));}
    void failRead(Error error){
        if(error=="EOF"){eof_=true;finishRead({},true,{});return;}
        auto callback=std::move(pending_);pending_=nullptr;close();if(callback)callback({},true,std::move(error));
    }
    void deliver(Buffer data){
        if(udp_ && data.size()>maximum_){failRead("VMess datagram receive buffer too small");return;}
        if(data.size()>maximum_){
            buffer_.append(data.data()+maximum_,data.size()-maximum_);
            data.resize(maximum_);
        }
        finishRead(std::move(data),false,{});
    }
    void responseHeader(){
        auto self=shared_from_this();
        reader_->exactly(18,[self](Buffer length,Error error){
            if(!error.empty()){self->failRead(error=="EOF"?"Missing VMess response authentication":error);return;}
            try{
                auto key=prefix(vmessKDF(self->responseKey_,{bytes("AEAD Resp Header Len Key")}),16);
                auto iv=prefix(vmessKDF(self->responseIV_,{bytes("AEAD Resp Header Len IV")}),12);
                auto plain=crypto::open(crypto::AEAD::AES128GCM,key,iv,length);
                if(plain.size()!=2)throw std::runtime_error("Invalid VMess response header length");
                size_t count=read16(plain);if(count<4 || count>4096)throw std::runtime_error("VMess response header limit exceeded");
                self->reader_->exactly(count+16,[self](Buffer payload,Error error){
                    if(!error.empty()){self->failRead(error=="EOF"?"Truncated VMess response header":error);return;}
                    try{
                        auto key=prefix(vmessKDF(self->responseKey_,{bytes("AEAD Resp Header Key")}),16);
                        auto iv=prefix(vmessKDF(self->responseIV_,{bytes("AEAD Resp Header IV")}),12);
                        auto plain=crypto::open(crypto::AEAD::AES128GCM,key,iv,payload);
                        if(plain.size()<4 || plain[0]!=self->verification_ || plain[2]!=0 || plain[3]!=0)throw std::runtime_error("VMess response authentication failed");
                        self->ready_=true;self->nextRead();
                    }catch(const std::exception &e){self->failRead(e.what());}
                });
            }catch(const std::exception &e){self->failRead(e.what());}
        });
    }
    void nextRead(){
        if(!pending_)return;
        if(!buffer_.empty()){finishRead(buffer_.consume(maximum_),false,{});return;}
        if(eof_){finishRead({},true,{});return;}
        if(!ready_){responseHeader();return;}
        auto self=shared_from_this();
        if(!chunkStream_){
            reader_->some(maximum_,[self](Buffer data,bool eof,Error error){
                if(!error.empty()){self->failRead(error);return;}
                if(eof && data.empty()){self->eof_=true;self->finishRead({},true,{});return;}
                if(eof)self->eof_=true;
                self->deliver(std::move(data));
            });
            return;
        }
        reader_->exactly(2,[self](Buffer length,Error error){
            if(!error.empty()){self->failRead(error);return;}
            size_t count=read16(length);
            if(!self->bodyEncrypted_){
                if(count==0){self->eof_=true;self->finishRead({},true,{});return;}
                if(!self->udp_ && count>17*1024){self->failRead("Invalid VMess body frame length");return;}
                self->reader_->exactly(count,[self](Buffer plain,Error error){
                    if(!error.empty()){self->failRead(error=="EOF"?"Truncated VMess body frame":error);return;}
                    self->deliver(std::move(plain));
                });
                return;
            }
            if(count<16 || (!self->udp_ && count>17*1024)){self->failRead("Invalid VMess body frame length");return;}
            self->reader_->exactly(count,[self](Buffer sealed,Error error){
                if(!error.empty()){self->failRead(error=="EOF"?"Truncated VMess body frame":error);return;}
                try{
                    auto nonce=bodyNonce(self->readCounter_,self->responseIV_);
                    auto data=crypto::open(self->bodyAead_,self->bodyRxKey_,nonce,sealed);++self->readCounter_;
                    if(data.empty()){self->eof_=true;self->finishRead({},true,{});}else self->deliver(std::move(data));
                }catch(const std::exception &e){self->failRead(e.what());}
            });
        });
    }
public:
    VMessStream(const Node &node,const Target &target,std::shared_ptr<Stream> source,std::shared_ptr<TransportFactory> factory=nullptr)
        :source_(std::move(source)),factory_(std::move(factory)),reader_(std::make_shared<Reader>(source_)),writer_(std::make_shared<OrderedWriter>(source_)),
         udp_(target.udp),coalesceHeader_(!target.udp && factory_ && static_cast<bool>(factory_->after)) {
        std::string rawUuid = node.option("uuid", node.option("username"));
        if (rawUuid.find('=') != std::string::npos && !node.option("username").empty()) {
            rawUuid = node.option("username");
        }
        auto uuid=uuidBytes(rawUuid);
        auto cipher=node.option("cipher",node.option("encrypt-method",node.option("encryption","auto")));
        std::transform(cipher.begin(),cipher.end(),cipher.begin(),[](unsigned char c){return char(std::tolower(c));});
        if(cipher.rfind("encrypt-method=",0)==0) cipher=cipher.substr(15);
        if(cipher=="chacha20-poly1305" || cipher=="chacha20-ietf-poly1305"){
            securityType_=4;
            bodyAead_=crypto::AEAD::ChaCha20Poly1305;
            bodyEncrypted_=true;
            chunkStream_=true;
        }else if(cipher=="none"){
            securityType_=5;
            bodyEncrypted_=false;
            chunkStream_=true;
        }else if(cipher=="zero"){
            securityType_=target.udp?5:6;
            bodyEncrypted_=false;
            chunkStream_=target.udp;
        }else{
            securityType_=3;
            bodyAead_=crypto::AEAD::AES128GCM;
            bodyEncrypted_=true;
            chunkStream_=true;
        }
        auto randomMaterial=crypto::randomBytes(34);
        requestIV_.assign(randomMaterial.begin(),randomMaterial.begin()+16);
        requestKey_.assign(randomMaterial.begin()+16,randomMaterial.begin()+32);
        verification_=randomMaterial[32];
        uint8_t padding=randomMaterial[33]&15;
        responseKey_=prefix(crypto::digest("SHA256",requestKey_),16);responseIV_=prefix(crypto::digest("SHA256",requestIV_),16);
        if(securityType_==4){
            bodyTxKey_=vmessChaChaPolyKey(requestKey_);
            bodyRxKey_=vmessChaChaPolyKey(responseKey_);
        }else{
            bodyTxKey_=requestKey_;
            bodyRxKey_=responseKey_;
        }
        uint8_t optionFlags=chunkStream_?1:0;
        Buffer command;command.reserve(64+padding);
        command.push_back(1);
        command.insert(command.end(),requestIV_.begin(),requestIV_.end());command.insert(command.end(),requestKey_.begin(),requestKey_.end());
        command.insert(command.end(),{verification_,optionFlags,uint8_t((padding<<4)|securityType_),0,uint8_t(muxTarget(target)?3:target.udp?2:1)});
        if(!muxTarget(target)){
            append16(command,target.port);auto address=socksAddress(target);address.resize(address.size()-2);
            if(address[0]==3)address[0]=2;else if(address[0]==4)address[0]=3;
            command.insert(command.end(),address.begin(),address.end());
        }
        if(padding>0){auto random=crypto::randomBytes(padding);command.insert(command.end(),random.begin(),random.end());}
        append32(command,fnv1a(command));
        const auto &keys=cachedVmessCommandAndAuthKey(uuid);
        request_=sealHeader(command,keys.first,keys.second);
    }
    void start(StreamCallback completion){
        auto self=shared_from_this();
        if(coalesceHeader_){
            std::weak_ptr<VMessStream> weak=self;
            factory_->after(0.1,[weak]{if(auto strong=weak.lock())strong->flushPendingHeaderIfIdle();});
            completion(self,{});
            return;
        }
        headerSent_=true;
        writer_->write(std::move(request_),[self,completion=std::move(completion)](Error error)mutable{
            if(!error.empty()){self->close();completion(nullptr,error);}else completion(self,{});
        });
    }
    void write(Buffer data,WriteCallback completion)override{
        if(closed_ || writeEnded_){completion("Stream write side closed");return;}
        if(data.empty()){completion({});return;}
        if(udp_ && data.size()>65507){completion("VMess UDP payload exceeds wire limit");return;}
        const size_t chunkSize=udp_?65507:16368,chunks=(data.size()+chunkSize-1)/chunkSize;
        const size_t perChunkOverhead=chunkStream_?(bodyEncrypted_?18:2):0;
        const size_t headerBytes=headerSent_?0:request_.size();
        if(data.size()>maximumQueuedBytes || (perChunkOverhead>0 && chunks>(maximumQueuedBytes-data.size())/perChunkOverhead) || !writer_->canAccept(headerBytes+data.size()+chunks*perChunkOverhead)){
            completion("VMess write queue limit exceeded");return;
        }
        if(bodyEncrypted_ && writeCounter_+chunks>65536){close();completion("VMess nonce sequence exhausted");return;}
        try{
            Buffer output;output.reserve(headerBytes+data.size()+chunks*perChunkOverhead);
            if(!headerSent_){
                headerSent_=true;
                output.insert(output.end(),request_.begin(),request_.end());
                request_.clear();
            }
            if(!chunkStream_){
                output.insert(output.end(),data.begin(),data.end());
            }else if(!bodyEncrypted_){
                for(size_t offset=0;offset<data.size();){
                    size_t count=std::min(chunkSize,data.size()-offset);
                    append16(output,uint16_t(count));
                    output.insert(output.end(),data.data()+offset,data.data()+offset+count);
                    offset+=count;
                }
            }else{
                for(size_t offset=0;offset<data.size();){
                    size_t count=std::min(chunkSize,data.size()-offset);
                    Buffer sealed=crypto::sealSlice(bodyAead_,bodyTxKey_,bodyNonce(writeCounter_,requestIV_),data.data()+offset,count);
                    append16(output,uint16_t(sealed.size()));output.insert(output.end(),sealed.begin(),sealed.end());++writeCounter_;offset+=count;
                }
            }
            writer_->write(std::move(output),std::move(completion));
        }catch(const std::exception &e){close();completion(e.what());}
    }
    void read(size_t maximum,ReadCallback completion)override{
        if(closed_){completion({},true,"Stream closed");return;}
        if(pending_){completion({},false,"Concurrent stream read");return;}
        if(!maximum || maximum>maximumReadBytes){completion({},false,"Invalid maximum read size");return;}
        maximum_=maximum;pending_=std::move(completion);nextRead();
    }
    void close()override{if(closed_)return;closed_=true;request_.clear();writer_->close();reader_->close();buffer_.clear();finishRead({},true,"Stream closed");}
    // VMess AEAD carries an authenticated zero-length EOF marker before FIN.
    void shutdownWrite(WriteCallback completion)override{
        if(closed_ || writeEnded_){completion("Stream write side closed");return;}
        if(!supportsHalfClose()){completion("VMess carrier does not support half-close");return;}
        const size_t headerBytes=headerSent_?0:request_.size();
        const size_t eofBytes=chunkStream_?(bodyEncrypted_?18:2):0;
        if(!writer_->canAccept(headerBytes+eofBytes)){completion("VMess write queue limit exceeded");return;}
        writeEnded_=true;
        try{
            Buffer frame;frame.reserve(headerBytes+eofBytes);
            if(!headerSent_){
                headerSent_=true;
                frame.insert(frame.end(),request_.begin(),request_.end());
                request_.clear();
            }
            if(chunkStream_){
                if(bodyEncrypted_){
                    auto sealed=crypto::seal(bodyAead_,bodyTxKey_,bodyNonce(writeCounter_,requestIV_),{});++writeCounter_;
                    append16(frame,uint16_t(sealed.size()));frame.insert(frame.end(),sealed.begin(),sealed.end());
                }else{
                    append16(frame,0);
                }
            }
            auto self=shared_from_this();
            if(frame.empty()){
                writer_->finish(std::move(completion));
            }else{
                writer_->write(std::move(frame),[self,completion=std::move(completion)](Error error)mutable{if(!error.empty())completion(error);else self->writer_->finish(std::move(completion));});
            }
        }catch(const std::exception &e){close();completion(e.what());}
    }
    bool supportsHalfClose()const override{return !udp_ && source_->supportsHalfClose();}
};
void connectVMessProtocol(const Node &node,const Target &target,std::shared_ptr<TransportFactory> factory,StreamCallback completion){
    factory->tcp(node,tlsOptions(node),[node,target,factory,completion=std::move(completion)](std::shared_ptr<Stream> source,Error error)mutable{
        if(!error.empty() || !source){completion(nullptr,error.empty()?"Transport did not return a stream":error);return;}
        try{auto stream=std::make_shared<VMessStream>(node,target,source,factory);stream->start(std::move(completion));}
        catch(const std::exception &e){source->close();completion(nullptr,e.what());}
    });
}
} // namespace hajimi
