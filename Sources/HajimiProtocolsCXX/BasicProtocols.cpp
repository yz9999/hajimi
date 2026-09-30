#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include "Vision.hpp"
#include <algorithm>
#include <cctype>
#include <deque>
#include <stdexcept>

namespace hajimi {
Buffer uuidBytes(const std::string &text) {
    if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-')
        throw std::runtime_error("Invalid protocol UUID");
    Buffer result; int high = -1;
    for (size_t i=0; i<text.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        char ch = char(std::tolower(static_cast<unsigned char>(text[i])));
        int value = ch >= '0' && ch <= '9' ? ch-'0' : ch >= 'a' && ch <= 'f' ? ch-'a'+10 : -1;
        if (value < 0) throw std::runtime_error("Invalid protocol UUID");
        if (high < 0) high = value; else { result.push_back(uint8_t(high*16+value)); high = -1; }
    }
    if (result.size() != 16) throw std::runtime_error("Invalid protocol UUID");
    return result;
}
static std::string authority(const Target &target) {
    if (target.host.empty() || target.host.find_first_of("\r\n\t ") != std::string::npos || target.host.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid HTTP CONNECT target");
    std::string host = target.host;
    if (host.find(':') != std::string::npos && host.front() != '[') host = "["+host+"]";
    return host+":"+std::to_string(target.port);
}
static void readAddress(std::shared_ptr<Reader> reader, uint8_t type, std::function<void(Buffer,Error)> completion) {
    if (type == 1 || type == 4) {
        reader->exactly(type == 1 ? 6 : 18, [type, completion=std::move(completion)](Buffer tail, Error error) mutable {
            if (!error.empty()) { completion({}, error); return; }
            tail.insert(tail.begin(), type); completion(std::move(tail), {});
        });
    } else if (type == 3) {
        reader->exactly(1, [reader, completion=std::move(completion)](Buffer length, Error error) mutable {
            if (!error.empty() || !length[0]) { completion({}, error.empty() ? "Invalid domain address" : error); return; }
            uint8_t count = length[0];
            reader->exactly(size_t(count)+2, [count, completion=std::move(completion)](Buffer tail, Error error) mutable {
                if (!error.empty()) { completion({}, error); return; }
                tail.insert(tail.begin(), {3,count}); completion(std::move(tail), {});
            });
        });
    } else completion({}, "Unsupported SOCKS address type");
}
class SocksHandshake : public std::enable_shared_from_this<SocksHandshake> {
    Node node_; Target target_; std::shared_ptr<Stream> source_; std::shared_ptr<Reader> reader_; StreamCallback completion_;
    uint8_t command_=1; std::function<void(Target)> bound_;
    std::shared_ptr<TransportFactory> factory_;
    void fail(Error error) { source_->close(); auto callback=std::exchange(completion_,{}); if (callback) callback(nullptr, std::move(error)); }
    void request() {
        Buffer data{5,command_,0}; auto address=socksAddress(target_); data.insert(data.end(),address.begin(),address.end());
        auto self=shared_from_this();
        source_->write(std::move(data), [self](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(4,[self](Buffer header,Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (header[0]!=5 || header[1]!=0 || header[2]!=0) { self->fail("SOCKS5 CONNECT rejected"); return; }
                readAddress(self->reader_,header[3],[self](Buffer address,Error error) {
                    if (!error.empty()) { self->fail(error); return; }
                    try { size_t consumed=0;auto target=parseSocksAddress(address,consumed);if(self->bound_)self->bound_(target); }
                    catch(const std::exception &e){self->fail(e.what());return;}
                    auto callback=std::exchange(self->completion_,{});
                    if (callback) callback(std::make_shared<BufferedStream>(self->source_,self->reader_),{});
                });
            });
        });
    }
    void authenticate() {
        auto username=node_.option("username"), password=node_.option("password");
        Buffer request{1,uint8_t(username.size())}; request.insert(request.end(),username.begin(),username.end());
        request.push_back(uint8_t(password.size())); request.insert(request.end(),password.begin(),password.end());
        auto self=shared_from_this();
        source_->write(std::move(request),[self](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(2,[self](Buffer response,Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (response[0]!=1 || response[1]!=0) { self->fail("SOCKS5 authentication rejected"); return; }
                self->request();
            });
        });
    }
public:
    SocksHandshake(Node node,Target target,std::shared_ptr<Stream> stream,StreamCallback completion,uint8_t command=1,std::function<void(Target)> bound={},std::shared_ptr<TransportFactory> factory=nullptr)
        :node_(std::move(node)),target_(std::move(target)),source_(std::move(stream)),reader_(std::make_shared<Reader>(source_)),completion_(std::move(completion)),command_(command),bound_(std::move(bound)),factory_(std::move(factory)) {}
    void start() {
        const uint8_t method=node_.parameters.count("username") ? 2 : 0;
        auto self=shared_from_this();
        if(factory_ && factory_->after){std::weak_ptr<SocksHandshake> weak=self;factory_->after(15,[weak]{if(auto self=weak.lock())if(self->completion_)self->fail("SOCKS5 handshake timed out");});}
        source_->write({5,1,method},[self,method](Error error) {
            if (!error.empty()) { self->fail(error); return; }
            self->reader_->exactly(2,[self,method](Buffer response,Error error) {
                if (!error.empty()) { self->fail(error); return; }
                if (response[0]!=5 || response[1]!=method) { self->fail("SOCKS5 authentication method mismatch"); return; }
                if (method==2) self->authenticate(); else self->request();
            });
        });
    }
};
static void httpHandshake(const Node &node,const Target &target,std::shared_ptr<Stream> source,std::shared_ptr<TransportFactory> factory,StreamCallback completion) {
    if (target.plainHTTP) { completion(std::make_shared<BufferedStream>(source,std::make_shared<Reader>(source)),{}); return; }
    auto destination=authority(target);
    std::string request="CONNECT "+destination+" HTTP/1.1\r\nHost: "+destination+"\r\nProxy-Connection: Keep-Alive\r\n";
    if (node.parameters.count("username")) request+="Proxy-Authorization: Basic "+crypto::base64Encode(bytes(node.option("username")+":"+node.option("password")))+"\r\n";
    request+="\r\n";
    auto reader=std::make_shared<Reader>(source);
    auto callback=std::make_shared<StreamCallback>(std::move(completion));
    auto finish=[callback](std::shared_ptr<Stream> stream,Error error){auto complete=std::exchange(*callback,{});if(complete)complete(std::move(stream),std::move(error));};
    if(factory->after){std::weak_ptr<StreamCallback> weak=callback;std::weak_ptr<Stream> transport=source;
        factory->after(15,[weak,transport]{if(auto callback=weak.lock())if(*callback){if(auto source=transport.lock())source->close();auto complete=std::exchange(*callback,{});complete(nullptr,"HTTP CONNECT handshake timed out");}});}
    source->write(bytes(request),[source,reader,callback,finish](Error error) mutable {
        if (!error.empty()) { source->close(); finish(nullptr,error); return; }
        reader->until({'\r','\n','\r','\n'},65536,[source,reader,callback,finish](Buffer header,Error error) mutable {
            if(!*callback)return;
            if (!error.empty()) { source->close(); finish(nullptr,error); return; }
            auto end=std::find(header.begin(),header.end(),'\r'); std::string line(header.begin(),end);
            auto space=line.find(' ');
            bool version=line.compare(0,9,"HTTP/1.1 ")==0 || line.compare(0,9,"HTTP/1.0 ")==0;
            bool status=space!=std::string::npos && line.size()>=space+4 && line[space+1]=='2'
                && std::isdigit(static_cast<unsigned char>(line[space+2])) && std::isdigit(static_cast<unsigned char>(line[space+3]))
                && (line.size()==space+4 || line[space+4]==' ');
            if (!version || !status) { source->close(); finish(nullptr,"HTTP CONNECT rejected"); return; }
            finish(std::make_shared<BufferedStream>(source,reader),{});
        });
    });
}

class PlainFramedStream : public Stream, public std::enable_shared_from_this<PlainFramedStream> {
    enum class Kind { VLESS, Trojan };
    Kind kind_; Target target_; std::shared_ptr<Stream> source_; std::shared_ptr<Reader> reader_; std::shared_ptr<OrderedWriter> writer_;
    Buffer request_, buffered_; std::unique_ptr<VisionCodec> vision_;
    bool responseReady_, closed_=false, eof_=false; ReadCallback pendingRead_;
    size_t requested_=0;
    void finishRead(Buffer data,bool eof,Error error) {
        auto callback=std::move(pendingRead_); pendingRead_=nullptr;
        if (callback) callback(std::move(data),eof,std::move(error));
    }
    void failedRead(Error error) {
        if(error=="EOF"){eof_=true;finishRead({},true,{});return;}
        auto callback=std::move(pendingRead_);pendingRead_=nullptr;close();if(callback)callback({},true,std::move(error));
    }
    void deliver(Buffer data,bool eof=false) {
        if (!target_.udp && data.size()>requested_) {
            buffered_.assign(data.begin()+requested_,data.end()); data.resize(requested_); eof_=eof;
            finishRead(std::move(data),false,{});
        } else if (target_.udp && data.size()>requested_) finishRead({},false,"Datagram receive buffer too small");
        else finishRead(std::move(data),eof,{});
    }
    void nextRead() {
        if (!pendingRead_) return;
        if (!buffered_.empty()) {
            auto data=std::move(buffered_); buffered_.clear(); deliver(std::move(data),eof_); return;
        }
        if (eof_) { finishRead({},true,{}); return; }
        auto self=shared_from_this();
        if (!responseReady_) {
            reader_->exactly(2,[self](Buffer header,Error error) {
                if (!error.empty()) { self->failedRead(error=="EOF"?"Missing VLESS response header":error); return; }
                if (header[0]!=0) { self->failedRead("Invalid VLESS response version"); return; }
                self->reader_->exactly(header[1],[self](Buffer,Error error) {
                    if (!error.empty()) { self->failedRead(error=="EOF"?"Truncated VLESS response addons":error); return; }
                    self->responseReady_=true; self->nextRead();
                });
            }); return;
        }
        if (vision_) {
            reader_->some(65536,[self](Buffer data,bool eof,Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                try {
                    bool direct=false; auto decoded=self->vision_->decode(data,direct);
                    if (direct) self->source_->enableVisionDirectRead();
                    if (eof && self->vision_->truncated()) { self->failedRead("Truncated Vision frame"); return; }
                    if (!decoded.empty() || eof) self->deliver(std::move(decoded),eof); else self->nextRead();
                } catch (const std::exception &e) { self->failedRead(e.what()); }
            }); return;
        }
        if (!target_.udp) { reader_->some(requested_,[self](Buffer data,bool eof,Error error) { self->finishRead(std::move(data),eof,std::move(error)); }); return; }
        if (kind_==Kind::VLESS) {
            reader_->exactly(2,[self](Buffer length,Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                self->reader_->exactly(read16(length),[self](Buffer data,Error error) {
                    if (!error.empty()) self->failedRead(error=="EOF"?"Truncated VLESS UDP payload":error); else self->deliver(std::move(data));
                });
            });
        } else {
            reader_->exactly(1,[self](Buffer type,Error error) {
                if (!error.empty()) { self->failedRead(error); return; }
                readAddress(self->reader_,type[0],[self](Buffer address,Error error) {
                    if (!error.empty()) { self->failedRead(error=="EOF"?"Truncated Trojan UDP address":error); return; }
                    try { size_t consumed=0; parseSocksAddress(address,consumed); }
                    catch (const std::exception &e) { self->failedRead(e.what()); return; }
                    self->reader_->exactly(4,[self](Buffer header,Error error) {
                        if (!error.empty()) { self->failedRead(error=="EOF"?"Truncated Trojan UDP header":error); return; }
                        if (header[2]!='\r' || header[3]!='\n') { self->failedRead("Invalid Trojan UDP frame"); return; }
                        self->reader_->exactly(read16(header),[self](Buffer data,Error error) {
                            if (!error.empty()) self->failedRead(error=="EOF"?"Truncated Trojan UDP payload":error); else self->deliver(std::move(data));
                        });
                    });
                });
            });
        }
    }
public:
    PlainFramedStream(const Node &node,Target target,std::shared_ptr<Stream> source)
        :kind_(node.type=="vless"?Kind::VLESS:Kind::Trojan),target_(std::move(target)),source_(std::move(source)),reader_(std::make_shared<Reader>(source_)),writer_(std::make_shared<OrderedWriter>(source_)),responseReady_(kind_==Kind::Trojan) {
        if (kind_==Kind::VLESS) {
            auto uuid=uuidBytes(node.option("uuid",node.option("username")));
            request_.push_back(0); request_.insert(request_.end(),uuid.begin(),uuid.end());
            auto flow=node.option("flow");
            if (!flow.empty()) {
                if (target_.udp || !source_->supportsVisionDirect()) throw std::runtime_error("VLESS Vision needs a direct-capable REALITY TCP carrier");
                std::string canonical="xtls-rprx-vision"; Buffer addons{0x0a,uint8_t(canonical.size())}; addons.insert(addons.end(),canonical.begin(),canonical.end());
                request_.push_back(uint8_t(addons.size())); request_.insert(request_.end(),addons.begin(),addons.end());
                vision_=std::make_unique<VisionCodec>(uuid,!muxTarget(target_));
            } else request_.push_back(0);
            request_.push_back(muxTarget(target_)?3:target_.udp?2:1);
            if (!muxTarget(target_)) {
                append16(request_,target_.port);
                auto address=socksAddress(target_); address.resize(address.size()-2);
                if (address[0]==3) address[0]=2; else if (address[0]==4) address[0]=3;
                request_.insert(request_.end(),address.begin(),address.end());
            }
            if (vision_) { auto padding=vision_->initialPadding(); request_.insert(request_.end(),padding.begin(),padding.end()); }
        } else {
            auto hash=crypto::digest("SHA224",bytes(node.option("password"))); static constexpr char hex[]="0123456789abcdef";
            for (auto b:hash) { request_.push_back(hex[b>>4]); request_.push_back(hex[b&15]); }
            request_.insert(request_.end(),{'\r','\n',uint8_t(target_.udp?3:1)});
            auto address=socksAddress(target_); request_.insert(request_.end(),address.begin(),address.end()); request_.insert(request_.end(),{'\r','\n'});
        }
    }
    void start(StreamCallback completion) {
        auto self=shared_from_this();
        writer_->write(std::move(request_),[self,completion=std::move(completion)](Error error) mutable {
            if (!error.empty()) { self->close(); completion(nullptr,error); } else completion(self,{});
        });
    }
    void write(Buffer data,WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        size_t wireBound=data.size();
        if(vision_)wireBound+=std::max<size_t>(1,(data.size()+8170)/8171)*1420+16;
        else if(target_.udp)wireBound+=kind_==Kind::Trojan?socksAddress(target_).size()+4:2;
        if (!writer_->canAccept(wireBound) || (target_.udp && data.size()>65535)) { completion("Protocol write queue limit exceeded"); return; }
        try {
            bool direct=false;
            if (vision_) data=vision_->encode(data,direct);
            else if (target_.udp) {
                Buffer frame;
                if (kind_==Kind::Trojan) frame=socksAddress(target_);
                append16(frame,uint16_t(data.size())); if (kind_==Kind::Trojan) frame.insert(frame.end(),{'\r','\n'});
                frame.insert(frame.end(),data.begin(),data.end()); data=std::move(frame);
            }
            auto self=shared_from_this();
            writer_->write(std::move(data),[self,direct,completion=std::move(completion)](Error error) mutable {
                if (direct && error.empty()) self->source_->enableVisionDirectWrite(); completion(std::move(error));
            });
        } catch (const std::exception &e) { close(); completion(e.what()); }
    }
    void read(size_t maximum,ReadCallback completion) override {
        if (closed_) { completion({},true,"Stream closed"); return; }
        if (pendingRead_) { completion({},false,"Concurrent stream read"); return; }
        if (!maximum || maximum>maximumReadBytes) { completion({},false,"Invalid maximum read size"); return; }
        requested_=maximum; pendingRead_=std::move(completion); nextRead();
    }
    void close() override {
        if (closed_) return;
        closed_=true; writer_->close(); reader_->close(); buffered_.clear(); finishRead({},true,"Stream closed");
    }
    void shutdownWrite(WriteCallback completion) override {
        if(!supportsHalfClose()){completion("Protocol does not support half-close");return;}
        writer_->finish(std::move(completion));
    }
    bool supportsHalfClose() const override { return !target_.udp && source_->supportsHalfClose(); }
};

void connectBasicProtocol(const Node &node,const Target &target,std::shared_ptr<TransportFactory> factory,StreamCallback completion) {
    if (node.type=="vmess") { connectVMessProtocol(node,target,std::move(factory),std::move(completion)); return; }
    bool tlsDefault=node.type=="https" || node.type=="socks5-tls" || node.type=="trojan";
    auto tls=tlsOptions(node,tlsDefault);
    if ((node.type=="http" || node.type=="https") && tls.enabled && tls.alpn.empty()) tls.alpn={"http/1.1"};
    factory->tcp(node,tls,[node,target,factory,completion=std::move(completion)](std::shared_ptr<Stream> source,Error error) mutable {
        if (!error.empty() || !source) { completion(nullptr,error.empty()?"Transport did not return a stream":error); return; }
        try {
            if (node.type=="direct") completion(source,{});
            else if (node.type=="http" || node.type=="https") httpHandshake(node,target,source,factory,std::move(completion));
            else if (node.type=="socks5" || node.type=="socks5-tls") std::make_shared<SocksHandshake>(node,target,source,std::move(completion),1,std::function<void(Target)>{},factory)->start();
            else if (node.type=="vless" || node.type=="trojan") std::make_shared<PlainFramedStream>(node,target,source)->start(std::move(completion));
            else { source->close(); completion(nullptr,"Unsupported C++ protocol"); }
        } catch (const std::exception &e) { source->close(); if (completion) completion(nullptr,e.what()); }
    });
}

class StreamDatagrams final : public Datagram,public std::enable_shared_from_this<StreamDatagrams> {
    struct Pending { Buffer data; WriteCallback completion; };
    struct Flow { Target target; std::shared_ptr<Stream> stream; std::deque<Pending> pending; bool connecting=false,sending=false; uint64_t activity=0; };
    Node node_; std::shared_ptr<TransportFactory> factory_; std::unordered_map<std::string,std::shared_ptr<Flow>> flows_;
    PacketCallback receive_; WriteCallback failure_; size_t queued_=0,requests_=0; bool closed_=false,started_=false;
    void failFlow(const std::string &key,std::shared_ptr<Flow> flow,Error error) {
        auto found=flows_.find(key); if (found==flows_.end() || found->second!=flow) return;
        flows_.erase(found); if (flow->stream) flow->stream->close();
        auto pending=std::move(flow->pending); flow->pending.clear();
        for (auto &entry:pending) { queued_-=entry.data.size(); --requests_; entry.completion(error); }
        if (!closed_ && failure_ && error!="EOF") failure_(error);
    }
    void flush(const std::string &key,std::shared_ptr<Flow> flow) {
        if (closed_ || !flow->stream || flow->sending || flow->pending.empty()) return;
        flow->sending=true; auto self=shared_from_this();
        flow->stream->write(flow->pending.front().data,[self,key,flow](Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key)!=flow) return;
            flow->sending=false;
            if (!error.empty()) { self->failFlow(key,flow,error); return; }
            auto entry=std::move(flow->pending.front()); flow->pending.pop_front(); self->queued_-=entry.data.size(); --self->requests_;
            flow->activity=unixSeconds(); entry.completion({}); self->flush(key,flow);
        });
    }
    void read(const std::string &key,std::shared_ptr<Flow> flow) {
        if (closed_ || !started_ || !flow->stream) return;
        auto self=shared_from_this();
        flow->stream->read(65535,[self,key,flow](Buffer data,bool eof,Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key)!=flow) return;
            if (!error.empty()) { self->failFlow(key,flow,error); return; }
            if ((!data.empty() || !eof) && self->receive_) { flow->activity=unixSeconds(); self->receive_(flow->target,std::move(data)); }
            if (eof) self->failFlow(key,flow,"EOF"); else self->factory_->post([self,key,flow]{self->read(key,flow);});
        });
    }
    void reap() {
        if (closed_) return;
        auto now=unixSeconds(); std::vector<std::pair<std::string,std::shared_ptr<Flow>>> stale;
        for (auto &entry:flows_) if (!entry.second->connecting && entry.second->pending.empty() && now-entry.second->activity>=120) stale.push_back(entry);
        for (auto &entry:stale) failFlow(entry.first,entry.second,"EOF");
        if (factory_->after) { std::weak_ptr<StreamDatagrams> weak=shared_from_this(); factory_->after(30,[weak]{if(auto self=weak.lock())self->reap();}); }
    }
public:
    StreamDatagrams(Node node,std::shared_ptr<TransportFactory> factory):node_(std::move(node)),factory_(std::move(factory)) {}
    void send(Target target,Buffer data,WriteCallback completion) override {
        if (closed_) { completion("Datagram session closed"); return; }
        if (data.size()>65535 || data.size()>maximumQueuedBytes-queued_ || requests_>=512) { completion("Datagram queue limit exceeded"); return; }
        target.udp=true; std::string key=target.host+":"+std::to_string(target.port); std::shared_ptr<Flow> flow;
        if (auto found=flows_.find(key);found!=flows_.end()) flow=found->second;
        else {
            if (flows_.size()>=128) { completion("Datagram flow limit exceeded"); return; }
            flow=std::make_shared<Flow>(); flow->target=target; flow->activity=unixSeconds(); flows_[key]=flow;
        }
        queued_+=data.size(); ++requests_; flow->pending.push_back({std::move(data),std::move(completion)});
        if (flow->stream) { flush(key,flow); return; }
        if (flow->connecting) return;
        flow->connecting=true; auto self=shared_from_this();
        connectProtocol(node_,target,factory_,[self,key,flow](std::shared_ptr<Stream> stream,Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key)!=flow) { if(stream)stream->close(); return; }
            flow->connecting=false;
            if (!error.empty() || !stream) { self->failFlow(key,flow,error.empty()?"UDP stream connect failed":error); return; }
            flow->stream=std::move(stream); self->flush(key,flow); self->read(key,flow);
        });
    }
    void start(PacketCallback receive,WriteCallback failure) override {
        if (started_) { failure("Datagram receiver already started"); return; }
        if (closed_) { failure("Datagram session closed"); return; }
        receive_=std::move(receive); failure_=std::move(failure); started_=true;
        for (auto &entry:flows_) if(entry.second->stream)read(entry.first,entry.second);
        reap();
    }
    void close() override {
        if (closed_) return; closed_=true; auto flows=std::move(flows_); flows_.clear();
        for (auto &entry:flows) {
            auto flow=entry.second; if(flow->stream)flow->stream->close();
            for(auto &pending:flow->pending)pending.completion("Datagram session closed");
        }
        queued_=requests_=0; receive_=nullptr; failure_=nullptr;
    }
};
void makeBasicDatagram(const Node &node,std::shared_ptr<TransportFactory> factory,DatagramCallback completion) {
    if(node.type=="socks5" || node.type=="socks5-tls"){makeSocksDatagram(node,std::move(factory),std::move(completion));return;}
    completion(std::make_shared<StreamDatagrams>(node,std::move(factory)),{});
}
void connectSocksAssociation(const Node &node,std::shared_ptr<TransportFactory> factory,std::function<void(std::shared_ptr<Stream>,Target,Error)> completion,std::function<void(std::shared_ptr<Stream>)> transportReady){
    factory->tcp(node,tlsOptions(node,node.type=="socks5-tls"),[node,factory,completion=std::move(completion),transportReady=std::move(transportReady)](std::shared_ptr<Stream> stream,Error error)mutable{
        if(!error.empty() || !stream){completion(nullptr,{},error.empty()?"SOCKS5 control connection failed":error);return;}
        if(transportReady)transportReady(stream);
        auto bound=std::make_shared<Target>();
        auto handshake=std::make_shared<SocksHandshake>(node,Target{"0.0.0.0",0,false,false},stream,
            [bound,completion=std::move(completion)](std::shared_ptr<Stream> stream,Error error)mutable{completion(std::move(stream),*bound,std::move(error));},3,
            [bound](Target target){*bound=std::move(target);},factory);
        handshake->start();
    });
}
} // namespace hajimi
