#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include <algorithm>
#include <functional>
#include <stdexcept>

namespace hajimi {
using Hash=std::function<Buffer(const Buffer &)>;
static Buffer genericHMAC(const Buffer &key,const Buffer &message,const Hash &hash) {
    Buffer normalized=key.size()>64?hash(key):key; normalized.resize(64);
    Buffer inner(64),outer(64);
    for(size_t i=0;i<64;++i){inner[i]=normalized[i]^0x36;outer[i]=normalized[i]^0x5c;}
    inner.insert(inner.end(),message.begin(),message.end()); auto result=hash(inner);
    outer.insert(outer.end(),result.begin(),result.end()); return hash(outer);
}
Buffer vmessKDF(const Buffer &key,const std::vector<Buffer> &path) {
    Hash creator=[](const Buffer &message){return crypto::hmac("SHA256",bytes("VMess AEAD KDF"),message);};
    for(auto &salt:path){auto parent=creator;creator=[salt,parent](const Buffer &message){return genericHMAC(salt,message,parent);};}
    return creator(key);
}
static uint32_t fnv1a(const Buffer &data) { uint32_t hash=2166136261U;for(auto byte:data)hash=(hash^byte)*16777619U;return hash; }
static uint32_t crc32(const Buffer &data) {
    uint32_t value=0xffffffffU;
    for(auto byte:data){value^=byte;for(int n=0;n<8;++n)value=(value>>1)^((value&1)?0xedb88320U:0);}
    return ~value;
}
static Buffer bodyNonce(uint32_t counter,const Buffer &iv) {
    if(counter>65535 || iv.size()<12)throw std::runtime_error("VMess nonce sequence exhausted");
    Buffer nonce;append16(nonce,uint16_t(counter));nonce.insert(nonce.end(),iv.begin()+2,iv.begin()+12);return nonce;
}
static Buffer sealHeader(const Buffer &command,const Buffer &commandKey) {
    Buffer auth;append64(auth,unixSeconds());auto random=crypto::randomBytes(4);auth.insert(auth.end(),random.begin(),random.end());append32(auth,crc32(auth));
    auto authKey=prefix(vmessKDF(commandKey,{bytes("AES Auth ID Encryption")}),16);
    auto authID=crypto::aesECBBlock(auth,authKey),connectionNonce=crypto::randomBytes(8);
    auto lengthKey=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Key_Length"),authID,connectionNonce}),16);
    auto lengthIV=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Nonce_Length"),authID,connectionNonce}),12);
    Buffer length;append16(length,uint16_t(command.size()));
    auto encryptedLength=crypto::seal(crypto::AEAD::AES128GCM,lengthKey,lengthIV,length,authID);
    auto payloadKey=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Key"),authID,connectionNonce}),16);
    auto payloadIV=prefix(vmessKDF(commandKey,{bytes("VMess Header AEAD Nonce"),authID,connectionNonce}),12);
    auto payload=crypto::seal(crypto::AEAD::AES128GCM,payloadKey,payloadIV,command,authID);
    Buffer output=authID;output.insert(output.end(),encryptedLength.begin(),encryptedLength.end());
    output.insert(output.end(),connectionNonce.begin(),connectionNonce.end());output.insert(output.end(),payload.begin(),payload.end());return output;
}
class VMessStream final:public Stream,public std::enable_shared_from_this<VMessStream> {
    std::shared_ptr<Stream> source_;std::shared_ptr<Reader> reader_;std::shared_ptr<OrderedWriter> writer_;
    Buffer requestIV_,requestKey_,responseIV_,responseKey_,request_,buffer_;
    uint8_t verification_;uint32_t writeCounter_=0,readCounter_=0;bool udp_,ready_=false,closed_=false,eof_=false,writeEnded_=false;
    ReadCallback pending_;size_t maximum_=0;
    void finishRead(Buffer data,bool eof,Error error){auto callback=std::move(pending_);pending_=nullptr;if(callback)callback(std::move(data),eof,std::move(error));}
    void failRead(Error error){
        if(error=="EOF"){eof_=true;finishRead({},true,{});return;}
        auto callback=std::move(pending_);pending_=nullptr;close();if(callback)callback({},true,std::move(error));
    }
    void deliver(Buffer data){
        if(udp_ && data.size()>maximum_){failRead("VMess datagram receive buffer too small");return;}
        if(data.size()>maximum_){buffer_.assign(data.begin()+maximum_,data.end());data.resize(maximum_);}
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
        if(!buffer_.empty()){auto data=std::move(buffer_);buffer_.clear();deliver(std::move(data));return;}
        if(eof_){finishRead({},true,{});return;}
        if(!ready_){responseHeader();return;}
        auto self=shared_from_this();
        reader_->exactly(2,[self](Buffer length,Error error){
            if(!error.empty()){self->failRead(error);return;}
            size_t count=read16(length);
            if(count<16 || (!self->udp_ && count>17*1024)){self->failRead("Invalid VMess body frame length");return;}
            self->reader_->exactly(count,[self](Buffer sealed,Error error){
                if(!error.empty()){self->failRead(error=="EOF"?"Truncated VMess body frame":error);return;}
                try{
                    auto nonce=bodyNonce(self->readCounter_,self->responseIV_);
                    auto data=crypto::open(crypto::AEAD::AES128GCM,self->responseKey_,nonce,sealed);++self->readCounter_;
                    if(data.empty()){self->eof_=true;self->finishRead({},true,{});}else self->deliver(std::move(data));
                }catch(const std::exception &e){self->failRead(e.what());}
            });
        });
    }
public:
    VMessStream(const Node &node,const Target &target,std::shared_ptr<Stream> source)
        :source_(std::move(source)),reader_(std::make_shared<Reader>(source_)),writer_(std::make_shared<OrderedWriter>(source_)),udp_(target.udp) {
        auto uuid=uuidBytes(node.option("uuid",node.option("username")));
        requestIV_=crypto::randomBytes(16);requestKey_=crypto::randomBytes(16);verification_=crypto::randomBytes(1)[0];
        responseKey_=prefix(crypto::digest("SHA256",requestKey_),16);responseIV_=prefix(crypto::digest("SHA256",requestIV_),16);
        uint8_t padding=crypto::randomBytes(1)[0]&15;
        Buffer command{1};command.insert(command.end(),requestIV_.begin(),requestIV_.end());command.insert(command.end(),requestKey_.begin(),requestKey_.end());
        command.insert(command.end(),{verification_,1,uint8_t((padding<<4)|3),0,uint8_t(muxTarget(target)?3:target.udp?2:1)});
        if(!muxTarget(target)){
            append16(command,target.port);auto address=socksAddress(target);address.resize(address.size()-2);
            if(address[0]==3)address[0]=2;else if(address[0]==4)address[0]=3;
            command.insert(command.end(),address.begin(),address.end());
        }
        auto random=crypto::randomBytes(padding);command.insert(command.end(),random.begin(),random.end());append32(command,fnv1a(command));
        auto suffix=bytes("c48619fe-8f02-49e0-b9e9-edf763e17e21");uuid.insert(uuid.end(),suffix.begin(),suffix.end());
        request_=sealHeader(command,crypto::digest("MD5",uuid));
    }
    void start(StreamCallback completion){auto self=shared_from_this();writer_->write(std::move(request_),[self,completion=std::move(completion)](Error error)mutable{
        if(!error.empty()){self->close();completion(nullptr,error);}else completion(self,{});
    });}
    void write(Buffer data,WriteCallback completion)override{
        if(closed_ || writeEnded_){completion("Stream write side closed");return;}
        if(data.empty()){completion({});return;}
        if(udp_ && data.size()>65507){completion("VMess UDP payload exceeds wire limit");return;}
        const size_t chunkSize=udp_?65507:16368,chunks=(data.size()+chunkSize-1)/chunkSize;
        if(data.size()>maximumQueuedBytes || chunks>(maximumQueuedBytes-data.size())/18 || !writer_->canAccept(data.size()+chunks*18)){
            completion("VMess write queue limit exceeded");return;
        }
        if(writeCounter_+chunks>65536){close();completion("VMess nonce sequence exhausted");return;}
        try{
            Buffer output;output.reserve(data.size()+chunks*18);
            for(size_t offset=0;offset<data.size();){
                size_t count=std::min(chunkSize,data.size()-offset);Buffer plain(data.begin()+offset,data.begin()+offset+count);
                auto sealed=crypto::seal(crypto::AEAD::AES128GCM,requestKey_,bodyNonce(writeCounter_,requestIV_),plain);
                append16(output,uint16_t(sealed.size()));output.insert(output.end(),sealed.begin(),sealed.end());++writeCounter_;offset+=count;
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
    void close()override{if(closed_)return;closed_=true;writer_->close();reader_->close();buffer_.clear();finishRead({},true,"Stream closed");}
    // VMess AEAD carries an authenticated zero-length EOF marker before FIN.
    void shutdownWrite(WriteCallback completion)override{
        if(closed_ || writeEnded_){completion("Stream write side closed");return;}
        if(!supportsHalfClose()){completion("VMess carrier does not support half-close");return;}
        if(!writer_->canAccept(18)){completion("VMess write queue limit exceeded");return;}
        writeEnded_=true;
        try{
            auto sealed=crypto::seal(crypto::AEAD::AES128GCM,requestKey_,bodyNonce(writeCounter_,requestIV_),{});++writeCounter_;
            Buffer frame;append16(frame,uint16_t(sealed.size()));frame.insert(frame.end(),sealed.begin(),sealed.end());auto self=shared_from_this();
            writer_->write(std::move(frame),[self,completion=std::move(completion)](Error error)mutable{if(!error.empty())completion(error);else self->writer_->finish(std::move(completion));});
        }catch(const std::exception &e){close();completion(e.what());}
    }
    bool supportsHalfClose()const override{return !udp_ && source_->supportsHalfClose();}
};
void connectVMessProtocol(const Node &node,const Target &target,std::shared_ptr<TransportFactory> factory,StreamCallback completion){
    factory->tcp(node,tlsOptions(node),[node,target,completion=std::move(completion)](std::shared_ptr<Stream> source,Error error)mutable{
        if(!error.empty() || !source){completion(nullptr,error.empty()?"Transport did not return a stream":error);return;}
        try{auto stream=std::make_shared<VMessStream>(node,target,source);stream->start(std::move(completion));}
        catch(const std::exception &e){source->close();completion(nullptr,e.what());}
    });
}
} // namespace hajimi
