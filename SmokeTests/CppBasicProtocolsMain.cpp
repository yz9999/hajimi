#include "Runtime.hpp"
#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include "Vision.hpp"
#include <algorithm>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace hajimi { Buffer vmessKDF(const Buffer &,const std::vector<Buffer> &); }
using namespace hajimi;
namespace {
unsigned checks=0;
void expect(bool value,const char *what) {++checks;if(!value)throw std::runtime_error(what);}
Buffer b(const std::string &s) {return {s.begin(),s.end()};}
void append(Buffer &a,const Buffer &z) {a.insert(a.end(),z.begin(),z.end());}
Buffer part(const Buffer &in,size_t offset,size_t count) {
    if(offset>in.size()||count>in.size()-offset)throw std::runtime_error("Peer fixture truncated");
    return {in.begin()+offset,in.begin()+offset+count};
}
Buffer hex(const std::string &s) {Buffer out;for(size_t i=0;i<s.size();i+=2)out.push_back(uint8_t(std::stoul(s.substr(i,2),nullptr,16)));return out;}
Buffer sequence(size_t n) {Buffer out(n);for(size_t i=0;i<n;++i)out[i]=uint8_t(i%251);return out;}
uint64_t u64(const Buffer &a,size_t i) {uint64_t n=0;for(size_t j=0;j<8;++j)n=n<<8|a.at(i+j);return n;}
uint32_t u32(const Buffer &a,size_t i) {uint32_t n=0;for(size_t j=0;j<4;++j)n=n<<8|a.at(i+j);return n;}
struct Loop {
    std::deque<std::function<void()>> tasks;
    void post(std::function<void()> task){tasks.push_back(std::move(task));}
    void run(){size_t budget=200000;while(!tasks.empty()){if(!budget--)throw std::runtime_error("Fake loop did not quiesce");
        auto task=std::move(tasks.front());tasks.pop_front();task();}}
};
class RawStream final:public Stream {
public:
    Loop &loop;Buffer input;size_t offset=0,fragment=13,readMaximum=0;ReadCallback reading;
    std::vector<Buffer> writes;std::deque<WriteCallback> held;std::function<void(const Buffer &)> peer;
    bool eof=false,closed=false,hold=false,fin=false,directRead=false,directWrite=false,directCapable=false;
    Error receiveError;
    explicit RawStream(Loop &l):loop(l){}
    void satisfy(){if(!reading || (offset==input.size()&&!eof&&!closed&&receiveError.empty()))return;
        auto done=std::move(reading);reading={};size_t count=std::min({fragment,readMaximum,input.size()-offset});
        Buffer data=part(input,offset,count);offset+=count;bool end=eof&&offset==input.size();
        Error error=closed?"Raw closed":offset==input.size()?receiveError:Error{};
        loop.post([done,data=std::move(data),end,error]()mutable{done(std::move(data),end,error);});}
    void feed(Buffer data,bool end=false){append(input,data);eof=end;satisfy();}
    void read(size_t n,ReadCallback done)override{expect(!reading,"Concurrent raw read");reading=std::move(done);readMaximum=n;satisfy();}
    void write(Buffer data,WriteCallback done)override{writes.push_back(std::move(data));if(peer)peer(writes.back());
        if(hold)held.push_back(std::move(done));else loop.post([done]{done({});});}
    void completeOne(){expect(!held.empty(),"No held write");auto done=std::move(held.front());held.pop_front();loop.post([done]{done({});});}
    void close()override{closed=true;satisfy();while(!held.empty()){auto done=std::move(held.front());held.pop_front();loop.post([done]{done("Raw closed");});}}
    bool supportsHalfClose()const override{return true;}
    void shutdownWrite(WriteCallback done)override{fin=true;loop.post([done]{done({});});}
    bool supportsVisionDirect()const override{return directCapable;}
    void enableVisionDirectRead()override{directRead=true;}
    void enableVisionDirectWrite()override{directWrite=true;}
};
class RawDatagram final:public Datagram {
public:
    Loop &loop;PacketCallback receive;WriteCallback failure;std::vector<Buffer> writes;std::vector<Target> targets;bool closed=false;
    explicit RawDatagram(Loop &l):loop(l){}
    void send(Target target,Buffer data,WriteCallback done)override{targets.push_back(std::move(target));writes.push_back(std::move(data));loop.post([done]{done({});});}
    void start(PacketCallback r,WriteCallback f)override{receive=std::move(r);failure=std::move(f);}
    void feed(Buffer data){auto callback=receive;loop.post([callback,data=std::move(data)]()mutable{if(callback)callback({},std::move(data));});}
    void close()override{closed=true;receive={};failure={};}
};
struct Harness {
    Loop loop;std::shared_ptr<RawStream> raw=std::make_shared<RawStream>(loop);
    std::shared_ptr<RawDatagram> udp=std::make_shared<RawDatagram>(loop);
    std::shared_ptr<TransportFactory> io=std::make_shared<TransportFactory>();TLSOptions tls;Node udpNode;
    Harness(){io->post=[this](std::function<void()> task){loop.post(std::move(task));};
        io->tcp=[this](const Node &,const TLSOptions &options,StreamCallback done){tls=options;auto source=raw;loop.post([source,done]{done(source,{});});};
        io->udp=[this](const Node &node,DatagramCallback done){udpNode=node;auto source=udp;loop.post([source,done]{done(source,{});});};}
    std::shared_ptr<Stream> connect(const Node &node,const Target &target){std::shared_ptr<Stream> out;Error error;
        connectBasicProtocol(node,target,io,[&](std::shared_ptr<Stream> result,Error e){out=std::move(result);error=e;});loop.run();
        expect(out && error.empty(),"Basic protocol connect failed");return out;}
};
Node node(std::string type){Node n;n.type=std::move(type);n.host="proxy.example";n.port=443;
    n.parameters["uuid"]="00112233-4455-6677-8899-aabbccddeeff";n.parameters["password"]="secret";return n;}
Buffer readOnce(Harness &h,std::shared_ptr<Stream> stream,size_t maximum=65535,bool *end=nullptr){Buffer out;Error error;bool called=false,eof=false;
    stream->read(maximum,[&](Buffer data,bool e,Error err){out=std::move(data);eof=e;error=std::move(err);called=true;});h.loop.run();
    expect(called && error.empty(),"Expected read stalled/failed");if(end)*end=eof;return out;}
void httpTests(){
    for(const auto &type:{"http","https"}){
        Harness h;h.raw->fragment=65536;Node n=node(type);n.parameters["username"]="user";
        h.raw->peer=[&](const Buffer &request){std::string text(request.begin(),request.end());
            expect(text.find("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n")==0,"HTTP CONNECT authority");
            expect(text.find("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n")!=std::string::npos,"HTTP proxy Basic authentication");
            h.raw->feed(b("HTTP/1.1 200 Connection Established\r\nX-Test: value\r\n\r\nLEFTOVER"));};
        auto stream=h.connect(n,{"2001:db8::1",443,false,false});
        expect(h.tls.enabled==(std::string(type)=="https"),"HTTP TLS default");
        if(h.tls.enabled)expect(h.tls.alpn==std::vector<std::string>{"http/1.1"},"HTTPS CONNECT ALPN");
        expect(readOnce(h,stream)==b("LEFTOVER"),"HTTP CONNECT lost leftover bytes");
        bool fin=false;stream->shutdownWrite([&](Error e){expect(e.empty(),"HTTP half-close");fin=true;});h.loop.run();
        expect(fin && h.raw->fin,"HTTP half-close not forwarded");stream->close();h.loop.run();
    }
    for(const auto &response:{"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n","HTTP/1.10 200 OK\r\n\r\n",
                             "HTTP/1.1 2000 Bad\r\n\r\n","HTTP/1.1 20a Bad\r\n\r\n"}){
        Harness h;h.raw->peer=[&](const Buffer &){h.raw->feed(b(response));};bool called=false;
        connectBasicProtocol(node("http"),{"example.com",80,false,false},h.io,[&](std::shared_ptr<Stream> s,Error e){
            expect(!s && !e.empty(),"Invalid HTTP CONNECT response accepted");called=true;});h.loop.run();
        expect(called && h.raw->closed,"Rejected HTTP CONNECT was not closed");
    }
    Harness h;auto direct=h.connect(node("http"),{"example.com",80,false,true});
    expect(h.raw->writes.empty(),"Plain HTTP unexpectedly sent CONNECT");direct->close();
}
void socksPeer(Harness &h,const Node &n,bool rejectMethod=false,bool rejectAuth=false,Target bound={"bound.example",1080,false,false}){
    h.raw->peer=[&h,n,rejectMethod,rejectAuth,bound](const Buffer &request){size_t index=h.raw->writes.size();
        bool auth=n.parameters.count("username");
        if(index==1){expect(request==Buffer({5,1,uint8_t(auth?2:0)}),"SOCKS offered an unexpected auth method");
            h.raw->feed({5,uint8_t(rejectMethod?(auth?0:2):(auth?2:0))});}
        else if(auth && index==2){Buffer expected{1,4};append(expected,b("user"));expected.push_back(6);append(expected,b("secret"));
            expect(request==expected,"SOCKS username/password framing");h.raw->feed({1,uint8_t(rejectAuth?1:0)});}
        else{expect(request.size()>=4 && request[0]==5 && request[2]==0,"SOCKS request header");
            Buffer reply{5,0,0};append(reply,socksAddress(bound));append(reply,b("TAIL"));h.raw->feed(std::move(reply));}
    };
}
void socksTests(){
    for(bool auth:{false,true}){Harness h;h.raw->fragment=65536;Node n=node("socks5-tls");if(auth)n.parameters["username"]="user";
        socksPeer(h,n);Target target{"example.com",443,false,false};auto stream=h.connect(n,target);
        expect(h.tls.enabled,"SOCKS5-TLS did not enable TLS");
        Buffer command{5,1,0};append(command,socksAddress(target));expect(h.raw->writes.back()==command,"SOCKS CONNECT destination");
        expect(readOnce(h,stream)==b("TAIL"),"SOCKS bound-domain reply lost bytes");stream->close();h.loop.run();}
    for(unsigned scenario=0;scenario<3;++scenario){Harness h;Node n=node("socks5");if(scenario!=1)n.parameters["username"]="user";
        socksPeer(h,n,scenario<2,scenario==2);bool called=false;
        connectBasicProtocol(n,{"example.com",80,false,false},h.io,[&](std::shared_ptr<Stream> s,Error e){expect(!s&&!e.empty(),"SOCKS auth downgrade/failure accepted");called=true;});
        h.loop.run();expect(called&&h.raw->closed,"Rejected SOCKS handshake not closed");}
}
void readerTests(){
    {Harness h;auto reader=std::make_shared<Reader>(h.raw,8);bool got=false;
        reader->exactly(9,[&](Buffer,Error e){expect(!e.empty(),"Reader admitted over-cap read");got=true;});expect(got,"Reader over-cap callback missing");}
    for(bool partial:{false,true}){Harness h;auto reader=std::make_shared<Reader>(h.raw);h.raw->feed(partial?Buffer{1}:Buffer{},true);bool called=false;
        reader->exactly(2,[&](Buffer,Error e){expect(e==(partial?"Truncated stream":"EOF"),"Reader EOF/truncation distinction");called=true;});h.loop.run();expect(called,"Reader EOF callback lost");}
    {Harness h;auto reader=std::make_shared<Reader>(h.raw);bool first=false,busy=false;
        reader->exactly(2,[&](Buffer data,Error e){expect(data==Buffer({1,2})&&e.empty(),"First Reader read broken by concurrent read");first=true;});
        reader->exactly(1,[&](Buffer,Error e){expect(!e.empty(),"Concurrent Reader read accepted");busy=true;});h.raw->feed({1,2});h.loop.run();expect(first&&busy,"Reader callbacks lost");}
    {Harness h;h.raw->fragment=65536;auto reader=std::make_shared<Reader>(h.raw);h.raw->feed(b("head\r\n\r\ntail"));bool parsed=false;
        reader->until({'\r','\n','\r','\n'},32,[&](Buffer data,Error e){expect(data==b("head\r\n\r\n")&&e.empty(),"Reader delimiter parse");parsed=true;});h.loop.run();
        expect(parsed && reader->take()==b("tail"),"Reader take did not preserve leftovers");}
    {Harness h;h.raw->fragment=65536;auto reader=std::make_shared<Reader>(h.raw,8);h.raw->feed(b("123456789"));bool rejected=false;
        reader->until({'\r','\n'},8,[&](Buffer,Error e){expect(!e.empty(),"Reader delimiter cap exceeded");rejected=true;});h.loop.run();expect(rejected,"Reader header limit stalled");}
    {Harness h;auto reader=std::make_shared<Reader>(h.raw);unsigned calls=0;
        reader->exactly(2,[&](Buffer,Error e){expect(!e.empty(),"Canceled Reader read succeeded");++calls;});reader->close();h.loop.run();expect(calls==1,"Reader close callback not exactly once");}
    {struct Oversize final:Stream{bool closed=false;void write(Buffer,WriteCallback done)override{done({});}
        void read(size_t maximum,ReadCallback done)override{done(Buffer(maximum+1),false,{});}void close()override{closed=true;}};
        auto raw=std::make_shared<Oversize>();auto reader=std::make_shared<Reader>(raw,8);bool rejected=false;
        reader->exactly(1,[&](Buffer,Error e){expect(!e.empty(),"Reader accepted oversized transport callback");rejected=true;});expect(rejected&&raw->closed,"Reader source-cap violation not closed");}
    // A terminal error may share its callback with the final valid bytes.
    // Never mark those bytes as clean EOF before the error has been observed.
    for(bool atEOF:{false,true})for(size_t maximum:{size_t(2),size_t(64)}){
        Harness h;h.raw->fragment=65536;h.raw->receiveError="Synthetic transport reset";
        h.raw->feed(b("last-data"),atEOF);auto reader=std::make_shared<Reader>(h.raw);Buffer received;
        while(received.size()<9){bool called=false;
            reader->some(maximum,[&](Buffer data,bool eof,Error e){expect(!data.empty()&&!eof&&e.empty(),"Reader hid terminal error behind clean EOF");append(received,data);called=true;});
            h.loop.run();expect(called,"Reader error-with-data callback stalled");}
        expect(received==b("last-data"),"Reader discarded legal bytes preceding terminal error");
        bool failed=false;reader->some(maximum,[&](Buffer data,bool eof,Error e){expect(data.empty()&&eof&&e==h.raw->receiveError,"Reader lost pending terminal error");failed=true;});
        h.loop.run();expect(failed,"Reader terminal error not delivered after buffer drain");reader->close();h.loop.run();
    }
    {Harness h;h.raw->fragment=65536;h.raw->receiveError="Synthetic TLS truncation";
        h.raw->feed(b("head\r\n\r\ntail"),true);auto reader=std::make_shared<Reader>(h.raw);bool parsed=false;
        reader->until({'\r','\n','\r','\n'},32,[&](Buffer data,Error e){expect(data==b("head\r\n\r\n")&&e.empty(),"Reader lost complete header accompanying error");parsed=true;});h.loop.run();expect(parsed,"Reader complete header stalled");
        auto stream=std::make_shared<BufferedStream>(h.raw,reader);bool delivered=false,failed=false;
        stream->read(64,[&](Buffer data,bool eof,Error e){expect(data==b("tail")&&!eof&&e.empty(),"BufferedStream advertised clean EOF before error");delivered=true;});h.loop.run();
        stream->read(64,[&](Buffer data,bool eof,Error e){expect(data.empty()&&eof&&e==h.raw->receiveError,"BufferedStream swallowed terminal error");failed=true;});h.loop.run();expect(delivered&&failed,"BufferedStream error regression callbacks missing");stream->close();h.loop.run();}
    {Harness h;h.raw->fragment=65536;h.raw->receiveError="Synthetic reset after exact read";
        h.raw->feed(b("abcdef"),true);auto reader=std::make_shared<Reader>(h.raw);bool exact=false;
        reader->exactly(3,[&](Buffer data,Error e){expect(data==b("abc")&&e.empty(),"Reader rejected legal exact bytes preceding error");exact=true;});h.loop.run();
        expect(exact&&reader->take()==b("def"),"Reader take included consumed prefix or lost error-adjacent bytes");bool failed=false;
        reader->some(8,[&](Buffer data,bool eof,Error e){expect(data.empty()&&eof&&e==h.raw->receiveError,"Reader take lost terminal error state");failed=true;});h.loop.run();expect(failed,"Reader take/error callback missing");reader->close();h.loop.run();}
    // Small-field reads must not erase/move the remaining 64 KiB per field.
    {Harness h;h.raw->fragment=65536;auto input=sequence(65536);h.raw->feed(input,true);auto reader=std::make_shared<Reader>(h.raw,65536);
        for(size_t offset=0;offset<input.size();offset+=2){bool called=false;
            reader->exactly(2,[&,offset](Buffer data,Error e){expect(e.empty()&&data==part(input,offset,2),"Reader offset small-field consumption changed bytes");called=true;});h.loop.run();expect(called,"Reader small-field callback missing");}
        expect(reader->take().empty(),"Reader take returned consumed bytes");bool ended=false;
        reader->some(8,[&](Buffer data,bool eof,Error e){expect(data.empty()&&eof&&e.empty(),"Reader offset drain lost clean EOF");ended=true;});h.loop.run();expect(ended,"Reader drain EOF callback missing");}
    // Repeated small-limit appends force compaction without exceeding the
    // logical receive cap; a consumed prefix must not count against the cap.
    {Harness h;h.raw->fragment=37;auto input=sequence(8192);h.raw->feed(input,true);auto reader=std::make_shared<Reader>(h.raw,128);
        size_t offset=0,step=0;while(offset<input.size()){size_t count=std::min<size_t>(1+(step++%47),input.size()-offset);bool called=false;
            reader->exactly(count,[&,offset,count](Buffer data,Error e){expect(e.empty()&&data==part(input,offset,count),"Reader forced compaction changed bytes");called=true;});h.loop.run();expect(called&&h.raw->readMaximum<=128,"Reader offset inflated receive limit");offset+=count;}
        expect(reader->take().empty(),"Reader compaction left dead prefix in take");}
    {Harness h;h.raw->fragment=11;Buffer input(100,'x'),header(35,'a');append(header,b("\r\n\r\n"));append(input,header);append(input,b("tail123"));h.raw->feed(input,true);
        auto reader=std::make_shared<Reader>(h.raw,128);bool skipped=false,parsed=false;
        reader->exactly(100,[&](Buffer data,Error e){expect(data==Buffer(100,'x')&&e.empty(),"Reader delimiter prefix skip");skipped=true;});h.loop.run();
        reader->until({'\r','\n','\r','\n'},64,[&](Buffer data,Error e){expect(data==header&&e.empty(),"Reader incremental delimiter scan lost compaction/overlap");parsed=true;});h.loop.run();expect(skipped&&parsed,"Reader compacted delimiter callbacks missing");
        Buffer tail;bool ended=false;while(!ended){bool called=false;reader->some(16,[&](Buffer data,bool eof,Error e){expect(e.empty(),"Reader delimiter tail failed");append(tail,data);ended=eof;called=true;});h.loop.run();expect(called,"Reader delimiter tail stalled");}
        expect(tail==b("tail123"),"Reader delimiter scan consumed post-header tail");}
    {Harness h;h.raw->fragment=65536;h.raw->feed(b("junkhead\r\n\r\n"),true);auto reader=std::make_shared<Reader>(h.raw,16);bool parsed=false;
        reader->exactly(4,[](Buffer data,Error e){expect(data==b("junk")&&e.empty(),"Reader header-limit prefix skip");});h.loop.run();
        reader->until({'\r','\n','\r','\n'},8,[&](Buffer data,Error e){expect(data==b("head\r\n\r\n")&&e.empty(),"Reader counted dead prefix against header limit");parsed=true;});h.loop.run();expect(parsed,"Reader offset header-limit callback missing");}
    {Harness h;h.raw->fragment=1;Buffer header(12000,'a');append(header,b("\r\n\r\n"));h.raw->feed(header,true);auto reader=std::make_shared<Reader>(h.raw);bool parsed=false;
        reader->until({'\r','\n','\r','\n'},16384,[&](Buffer data,Error e){expect(data==header&&e.empty(),"Reader byte-fragment delimiter scan changed header");parsed=true;});h.loop.run();expect(parsed,"Reader incremental header scan stalled");}
}
void vlessTests(){
    const Buffer uuid=hex("00112233445566778899aabbccddeeff");
    for(bool udp:{false,true}){Harness h;h.raw->fragment=2;Target target{"example.com",443,udp,false};auto stream=h.connect(node("vless"),target);
        Buffer expected{0};append(expected,uuid);expected.insert(expected.end(),{0,uint8_t(udp?2:1),1,0xbb,2,11});append(expected,b("example.com"));
        expect(h.raw->writes[0]==expected,"VLESS request header address/command/UUID");
        Buffer response{0,3,0xa1,0xa2,0xa3};
        if(udp){append16(response,3);append(response,b("abc"));append16(response,4);append(response,b("defg"));}
        else append(response,b("abcdefg"));h.raw->feed(std::move(response));
        if(udp){expect(readOnce(h,stream)==b("abc"),"VLESS first datagram boundary");expect(readOnce(h,stream)==b("defg"),"VLESS second datagram boundary");}
        else{Buffer all;while(all.size()<7)append(all,readOnce(h,stream,3));expect(all==b("abcdefg"),"VLESS skipped addons/payload");}
        bool wrote=false;stream->write(b("uplink"),[&](Error e){expect(e.empty(),"VLESS write");wrote=true;});h.loop.run();
        Buffer wire=udp?Buffer{0,6}:Buffer{};append(wire,b("uplink"));expect(wrote&&h.raw->writes.back()==wire,"VLESS UDP/TCP uplink framing");
        bool finished=false;stream->shutdownWrite([&](Error e){expect(e.empty()!=udp,"VLESS half-close mode");finished=true;});h.loop.run();
        expect(finished && h.raw->fin!=udp,"VLESS UDP permitted FIN");stream->close();h.loop.run();}
    for(unsigned scenario=0;scenario<2;++scenario){Harness h;auto stream=h.connect(node("vless"),{"example.com",443,false,false});
        h.raw->feed(scenario==0?Buffer{1,0}:Buffer{0,5,1,2},true);bool failed=false;
        stream->read(64,[&](Buffer,bool eof,Error e){expect(eof&&!e.empty(),"Malformed VLESS response accepted");failed=true;});h.loop.run();
        expect(failed&&h.raw->closed,"VLESS protocol failure not terminal");}
}
Buffer trojanPacket(const Target &target,const Buffer &payload){Buffer out=socksAddress(target);append16(out,uint16_t(payload.size()));
    out.insert(out.end(),{'\r','\n'});append(out,payload);return out;}
void trojanTests(){
    for(bool udp:{false,true}){Harness h;Target target{"initial.example",443,udp,false};auto stream=h.connect(node("trojan"),target);
        Buffer expected=b("95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12");expected.insert(expected.end(),{'\r','\n',uint8_t(udp?3:1)});
        append(expected,socksAddress(target));expected.insert(expected.end(),{'\r','\n'});
        expect(h.tls.enabled && h.raw->writes[0]==expected,"Trojan SHA224 command header/TLS");
        if(udp){Buffer response=trojanPacket({"reply.example",53,true,false},b("first"));
            append(response,trojanPacket({"2001:db8::123",443,true,false},b("second")));append(response,trojanPacket({"1.2.3.4",53,true,false},{}));
            h.raw->feed(std::move(response));expect(readOnce(h,stream)==b("first"),"Trojan domain UDP frame");
            expect(readOnce(h,stream)==b("second"),"Trojan varying-address IPv6 frame");expect(readOnce(h,stream).empty(),"Trojan empty UDP packet");}
        else{h.raw->feed(b("reply"));expect(readOnce(h,stream)==b("reply"),"Trojan TCP unframed payload");}
        stream->write(b("up"),[](Error e){expect(e.empty(),"Trojan send");});h.loop.run();
        expect(h.raw->writes.back()==(udp?trojanPacket(target,b("up")):b("up")),"Trojan UDP uplink packet");
        bool done=false;stream->shutdownWrite([&](Error e){expect(e.empty()!=udp,"Trojan half-close mode");done=true;});h.loop.run();
        expect(done&&h.raw->fin!=udp,"Trojan UDP FIN permitted");stream->close();h.loop.run();}
    Harness h;auto stream=h.connect(node("trojan"),{"initial.example",443,true,false});Buffer response=trojanPacket({"reply.example",53,true,false},b("bad"));
    size_t consumed=0;parseSocksAddress(response,consumed);response[consumed+2]='x';h.raw->feed(std::move(response));bool failed=false;
    stream->read(64,[&](Buffer,bool eof,Error e){expect(eof&&!e.empty(),"Trojan invalid frame separator accepted");failed=true;});h.loop.run();
    expect(failed&&h.raw->closed,"Trojan malformed frame not terminal");
}
Buffer visionFrame(const Buffer &uuid,uint8_t command,const Buffer &content,size_t padding,bool first=true){Buffer out=first?uuid:Buffer{};
    out.push_back(command);append16(out,uint16_t(content.size()));append16(out,uint16_t(padding));append(out,content);out.resize(out.size()+padding);return out;}
void visionTests(){
    Buffer uuid=hex("00112233445566778899aabbccddeeff");VisionCodec codec(uuid,true);Buffer combined=visionFrame(uuid,0,b("first"),3);
    append(combined,visionFrame(uuid,1,b("last"),2,false));append(combined,b("raw"));Buffer decoded;
    for(auto byte:combined){bool direct=false;append(decoded,codec.decode({byte},direct));expect(!direct,"Vision command1 requested direct mode");}
    expect(decoded==b("firstlastraw")&&!codec.truncated(),"Vision fragmented decode/end-padding boundary");
    bool bad=false;try{VisionCodec mismatch(uuid,true);bool direct=false;mismatch.decode(Buffer(16,0xff),direct);}catch(const std::exception &){bad=true;}
    expect(bad,"Vision UUID mismatch accepted");
    bad=false;try{VisionCodec wrong(uuid,true);bool direct=false;wrong.decode(visionFrame(uuid,3,{},0),direct);}catch(const std::exception &){bad=true;}
    expect(bad,"Vision invalid command accepted");
    VisionCodec directCodec(uuid,true);bool direct=false;Buffer packet=visionFrame(uuid,2,b("tls"),3);append(packet,b("tail"));
    expect(directCodec.decode(packet,direct)==b("tlstail")&&direct,"Vision direct handoff lost coalesced tail");
    expect(directCodec.decode(b("more"),direct)==b("more")&&!direct,"Vision direct stream was re-framed");
    VisionCodec truncated(uuid,true);truncated.decode(part(visionFrame(uuid,0,b("abc"),0),0,18),direct);
    expect(truncated.truncated(),"Vision truncation not detected");
    VisionCodec encoder(uuid,true);Buffer initial=encoder.initialPadding();
    expect(part(initial,0,16)==uuid&&initial[16]==0&&read16(initial,17)==0&&read16(initial,19)>=900,"Vision initial UUID/padding");
    Buffer clientHello{0x16,3,3,0,1,1};encoder.encode(clientHello,direct);
    Buffer hello(55,0);hello[0]=0x16;hello[1]=3;hello[2]=3;hello[4]=50;hello[5]=2;hello[8]=46;hello[9]=3;hello[10]=3;
    hello[44]=0x13;hello[45]=1;hello[48]=6;hello[50]=0x2b;hello[52]=2;hello[53]=3;hello[54]=4;
    encoder.decode(visionFrame(uuid,0,hello,0),direct);Buffer record{0x17,3,3,0,4,1,2,3,4};Buffer outbound=encoder.encode(record,direct);
    expect(direct&&outbound[0]==2,"Vision TLS1.3 direct switch not at record boundary");
    expect(encoder.encode(b("unwrapped"),direct)==b("unwrapped")&&!direct,"Vision direct writes still padded");
}
// Independent recursive implementation, pinned to the upstream v2fly vector:
// github.com/v2fly/v2ray-core/blob/master/proxy/vmess/aead/kdf_test.go
Buffer peerNestedHash(const Buffer &message,const std::vector<Buffer> &path,size_t depth){
    if(!depth)return crypto::hmac("SHA256",b("VMess AEAD KDF"),message);
    Buffer key=path[depth-1];if(key.size()>64)key=peerNestedHash(key,path,depth-1);key.resize(64,0);
    Buffer inner(64),outer(64);for(size_t i=0;i<64;++i){inner[i]=key[i]^0x36;outer[i]=key[i]^0x5c;}
    append(inner,message);append(outer,peerNestedHash(inner,path,depth-1));return peerNestedHash(outer,path,depth-1);
}
Buffer peerKDF(const Buffer &key,const std::vector<Buffer> &path){return peerNestedHash(key,path,path.size());}
Buffer cut(Buffer data,size_t count){data.resize(count);return data;}
uint32_t peerCRC(const Buffer &data){uint32_t table[256];for(uint32_t i=0;i<256;++i){uint32_t n=i;
    for(unsigned bit=0;bit<8;++bit)n=n&1?(n>>1)^0xedb88320U:n>>1;table[i]=n;}
    uint32_t n=~uint32_t(0);for(auto byte:data)n=table[(n^byte)&255]^(n>>8);return ~n;}
uint32_t peerFNV(const Buffer &data){uint32_t n=0x811c9dc5U;for(auto byte:data){n^=byte;n*=0x01000193U;}return n;}
Buffer peerNonce(uint16_t counter,const Buffer &iv){Buffer out;append16(out,counter);append(out,part(iv,2,10));return out;}
struct VMessPeer {
    Buffer key,iv,responseKey,responseIV;uint8_t verification=0;uint32_t sendCounter=0,receiveCounter=0;
    explicit VMessPeer(const Buffer &wire,const Target &target){
        Buffer uuid=hex("00112233445566778899aabbccddeeff");append(uuid,b("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
        Buffer commandKey=crypto::digest("MD5",uuid),authID=part(wire,0,16),connection=part(wire,34,8);
        Buffer authKey=cut(peerKDF(commandKey,{b("AES Auth ID Encryption")}),16);
        Buffer auth=crypto::aesECBBlock(authID,authKey,false);uint64_t timestamp=u64(auth,0),now=unixSeconds();
        expect((timestamp>now?timestamp-now:now-timestamp)<=30,"VMess AuthID timestamp");
        expect(u32(auth,12)==peerCRC(part(auth,0,12)),"VMess AuthID CRC32");
        Buffer lengthKey=cut(peerKDF(commandKey,{b("VMess Header AEAD Key_Length"),authID,connection}),16);
        Buffer lengthIV=cut(peerKDF(commandKey,{b("VMess Header AEAD Nonce_Length"),authID,connection}),12);
        Buffer length=crypto::open(crypto::AEAD::AES128GCM,lengthKey,lengthIV,part(wire,16,18),authID);
        Buffer payloadKey=cut(peerKDF(commandKey,{b("VMess Header AEAD Key"),authID,connection}),16);
        Buffer payloadIV=cut(peerKDF(commandKey,{b("VMess Header AEAD Nonce"),authID,connection}),12);
        Buffer command=crypto::open(crypto::AEAD::AES128GCM,payloadKey,payloadIV,part(wire,42,read16(length)+16),authID);
        expect(wire.size()==42+read16(length)+16 && command[0]==1,"VMess command payload length/version");
        expect(u32(command,command.size()-4)==peerFNV(part(command,0,command.size()-4)),"VMess FNV command checksum");
        expect(command[34]==1 && (command[35]&15)==3 && command[36]==0,"VMess body encryption/options");
        size_t padding=command[35]>>4;
        if(muxTarget(target)){expect(command[37]==3&&command.size()==38+padding+4,"VMess mux header included address/port");}
        else{expect(command[37]==(target.udp?2:1)&&read16(command,38)==target.port,"VMess request command/port");
            expect(command[40]==2 && command[41]==target.host.size() && part(command,42,target.host.size())==b(target.host),"VMess request domain");
            expect(command.size()==42+target.host.size()+padding+4,"VMess padding nibble/layout");}
        iv=part(command,1,16);key=part(command,17,16);verification=command[33];
        responseKey=cut(crypto::digest("SHA256",key),16);responseIV=cut(crypto::digest("SHA256",iv),16);
    }
    Buffer responseHeader(bool wrongVerification=false){Buffer plain{uint8_t(verification^(wrongVerification?1:0)),0,0,0},length;append16(length,uint16_t(plain.size()));
        Buffer lk=cut(peerKDF(responseKey,{b("AEAD Resp Header Len Key")}),16),li=cut(peerKDF(responseIV,{b("AEAD Resp Header Len IV")}),12);
        Buffer pk=cut(peerKDF(responseKey,{b("AEAD Resp Header Key")}),16),pi=cut(peerKDF(responseIV,{b("AEAD Resp Header IV")}),12);
        Buffer wire=crypto::seal(crypto::AEAD::AES128GCM,lk,li,length);append(wire,crypto::seal(crypto::AEAD::AES128GCM,pk,pi,plain));return wire;}
    Buffer responseFrame(const Buffer &plain){Buffer cipher=crypto::seal(crypto::AEAD::AES128GCM,responseKey,peerNonce(uint16_t(sendCounter++),responseIV),plain);
        Buffer out;append16(out,uint16_t(cipher.size()));append(out,cipher);return out;}
    std::vector<Buffer> requestFrames(const Buffer &wire){size_t offset=0;std::vector<Buffer> frames;
        while(offset<wire.size()){size_t count=read16(wire,offset);offset+=2;
            frames.push_back(crypto::open(crypto::AEAD::AES128GCM,key,peerNonce(uint16_t(receiveCounter++),iv),part(wire,offset,count)));offset+=count;}
        return frames;}
};
void vmessTests(){
    std::vector<Buffer> path{b("Demo Path for KDF Value Test"),b("Demo Path for KDF Value Test2"),b("Demo Path for KDF Value Test3")};
    Buffer expected=hex("53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892");
    expect(vmessKDF(b("Demo Key for KDF Value Test"),path)==expected,"VMess KDF upstream vector");
    expect(peerKDF(b("Demo Key for KDF Value Test"),path)==expected,"Independent peer KDF upstream vector");
    expect(peerCRC(b("123456789"))==0xcbf43926U && peerFNV(b("foobar"))==0xbf9cf968U,"Peer CRC/FNV standard vectors");
    {Harness h;Target target{"v1.mux.cool",9527,false,false};auto stream=h.connect(node("vmess"),target);VMessPeer peer(h.raw->writes[0],target);stream->close();h.loop.run();}
    {Harness h;auto stream=h.connect(node("vless"),{"v1.mux.cool",9527,false,false});Buffer expected{0};append(expected,hex("00112233445566778899aabbccddeeff"));
        expected.insert(expected.end(),{0,3});expect(h.raw->writes[0]==expected,"VLESS mux header included destination address");stream->close();h.loop.run();}
    for(bool udp:{false,true}){Harness h;Target target{"example.com",443,udp,false};auto stream=h.connect(node("vmess"),target);VMessPeer peer(h.raw->writes[0],target);
        Buffer uplink=sequence(udp?60000:70000);bool sent=false;stream->write(uplink,[&](Error e){expect(e.empty(),"VMess send");sent=true;});h.loop.run();
        auto packets=peer.requestFrames(h.raw->writes[1]);Buffer got;for(auto &packet:packets)append(got,packet);
        expect(sent&&got==uplink&&(udp?packets.size()==1:packets.size()==5),"VMess outbound TCP chunks/UDP packet boundary");
        Buffer wire=peer.responseHeader(),downlink=sequence(udp?60000:17000);
        if(udp)append(wire,peer.responseFrame(downlink));else{append(wire,peer.responseFrame(part(downlink,0,16368)));append(wire,peer.responseFrame(part(downlink,16368,632)));}
        append(wire,peer.responseFrame({}));h.raw->feed(std::move(wire));Buffer received;bool end=false;
        if(udp){expect(readOnce(h,stream)==downlink,"VMess UDP response split/coalesced");expect(readOnce(h,stream,65535,&end).empty()&&end,"VMess EOF marker");}
        else{for(size_t i=0;i<100&&!end;++i)append(received,readOnce(h,stream,257,&end));expect(end&&received==downlink,"VMess inbound framed data/EOF");}
        bool finished=false;stream->shutdownWrite([&](Error e){expect(e.empty()!=udp,"VMess half-close mode");finished=true;});h.loop.run();
        expect(finished&&h.raw->fin!=udp,"VMess half-close not forwarded");
        if(!udp){auto frames=peer.requestFrames(h.raw->writes.back());expect(frames.size()==1&&frames[0].empty(),"VMess FIN lacks authenticated EOF marker");}
        stream->close();h.loop.run();}
}
void vmessFailureTests(){
    for(unsigned scenario=0;scenario<5;++scenario){Harness h;Target target{"example.com",443,false,false};auto stream=h.connect(node("vmess"),target);
        VMessPeer peer(h.raw->writes[0],target);Buffer response=peer.responseHeader(scenario==0);
        if(scenario==1)response.back()^=1;
        else if(scenario==2)response.resize(18);
        else if(scenario>=3){Buffer body=peer.responseFrame(b("ab"));if(scenario==3)body.resize(2);else body.back()^=1;append(response,body);}
        h.raw->feed(std::move(response),true);bool failed=false;
        stream->read(65535,[&](Buffer data,bool eof,Error e){expect(data.empty()&&eof&&!e.empty(),"Unauthenticated/truncated VMess response accepted");failed=true;});h.loop.run();
        expect(failed&&h.raw->closed,"VMess auth/framing failure not terminal");}
    for(const auto &type:{"vless","trojan"}){Harness h;Target target{"example.com",443,true,false};auto stream=h.connect(node(type),target);Buffer response;
        if(std::string(type)=="vless"){response={0,0,0,3};}
        else{response=socksAddress(target);append16(response,3);response.insert(response.end(),{'\r','\n'});}
        h.raw->feed(std::move(response),true);bool failed=false;
        stream->read(64,[&](Buffer,bool eof,Error e){expect(eof&&!e.empty(),"Length-prefixed datagram EOF accepted as clean");failed=true;});h.loop.run();
        expect(failed&&h.raw->closed,"Incomplete UDP stream packet not terminal");}
}
void vmessQueueAndFIN(){
    Harness h;Target target{"example.com",443,false,false};auto stream=h.connect(node("vmess"),target);VMessPeer peer(h.raw->writes[0],target);
    h.raw->hold=true;unsigned completed=0;bool rejected=false;
    for(unsigned i=0;i<128;++i)stream->write({uint8_t(i)},[&](Error e){expect(e.empty(),"Accepted queued VMess write failed");++completed;});
    stream->write({0xee},[&](Error e){expect(!e.empty(),"VMess operation-cap overflow accepted");rejected=true;});
    expect(rejected&&!completed&&h.raw->held.size()==1,"VMess queue not serialized/bounded");
    while(!h.raw->held.empty()){h.raw->completeOne();h.loop.run();}
    expect(completed==128 && h.raw->writes.size()==129,"VMess accepted write completion count");
    for(size_t i=1;i<h.raw->writes.size();++i){auto frames=peer.requestFrames(h.raw->writes[i]);expect(frames.size()==1&&frames[0]==Buffer{uint8_t(i-1)},"VMess queued nonce sequence changed");}
    stream->write({0xfa},[](Error e){expect(e.empty(),"Write after rejected VMess queue failed");});h.raw->completeOne();h.loop.run();
    auto frames=peer.requestFrames(h.raw->writes.back());expect(frames.size()==1&&frames[0]==Buffer{0xfa},"Rejected write consumed VMess nonce");
    bool finished=false,lateRejected=false;stream->shutdownWrite([&](Error e){expect(e.empty(),"VMess FIN failed");finished=true;});
    stream->write({0xfb},[&](Error e){expect(!e.empty(),"VMess data accepted after EOF queued");lateRejected=true;});
    expect(lateRejected&&!finished,"VMess FIN did not immediately end writes");h.raw->completeOne();h.loop.run();
    expect(finished&&h.raw->fin,"VMess FIN completion missing");frames=peer.requestFrames(h.raw->writes.back());expect(frames.size()==1&&frames[0].empty(),"VMess queued FIN is not authenticated EOF");
    stream->close();h.loop.run();
    Harness c;auto plain=c.connect(node("vless"),target);c.raw->hold=true;unsigned canceled=0,readCanceled=0;bool overflow=false;
    plain->write(Buffer(maximumQueuedBytes/2,1),[&](Error e){expect(!e.empty(),"Canceled active plain write succeeded");++canceled;});
    plain->write(Buffer(maximumQueuedBytes/2,2),[&](Error e){expect(!e.empty(),"Canceled queued plain write succeeded");++canceled;});
    plain->write({3},[&](Error e){expect(!e.empty(),"Plain stream byte-cap overflow accepted");overflow=true;});
    plain->read(32,[&](Buffer,bool eof,Error e){expect(eof&&!e.empty(),"Pending plain read not canceled");++readCanceled;});
    plain->close();c.loop.run();expect(overflow&&canceled==2&&readCanceled==1,"Close callbacks not exactly once");
}
void socksDatagramTests(){
    Harness h;Node n=node("socks5");Target relay{"relay.example",12345,true,false};
    h.raw->peer=[&](const Buffer &request){if(h.raw->writes.size()==1){expect(request==Buffer({5,1,0}),"SOCKS UDP method");h.raw->feed({5,0});}
        else{Buffer expected{5,3,0};append(expected,socksAddress({"0.0.0.0",0,false,false}));expect(request==expected,"SOCKS UDP ASSOCIATE request");
            Buffer response{5,0,0};append(response,socksAddress(relay));h.raw->feed(std::move(response));}};
    std::shared_ptr<Datagram> session;makeSocksDatagram(n,h.io,[&](std::shared_ptr<Datagram> result,Error e){expect(e.empty(),"SOCKS UDP session");session=std::move(result);});
    unsigned received=0,failures=0,sent=0;Target target{"dns.example",53,true,false};
    session->start([&](Target t,Buffer data){expect(t.host==target.host&&t.port==53&&data==b("answer"),"SOCKS UDP reply framing");++received;},[&](Error){++failures;});
    session->send(target,b("query"),[&](Error e){expect(e.empty(),"SOCKS UDP send");++sent;});h.loop.run();
    expect(sent==1&&h.udpNode.host==relay.host&&h.udpNode.port==relay.port,"SOCKS UDP relay domain ignored");
    Buffer packet{0,0,0};append(packet,socksAddress(target));append(packet,b("query"));expect(h.udp->writes[0]==packet,"SOCKS UDP client header");
    packet={0,0,0};append(packet,socksAddress(target));append(packet,b("answer"));h.udp->feed(packet);h.loop.run();expect(received==1,"SOCKS UDP valid response dropped");
    packet[2]=1;h.udp->feed(packet);h.loop.run();expect(received==1&&!failures,"SOCKS UDP fragments accepted/fatal");
    h.udp->feed({0,0,0,0xff});h.loop.run();expect(received==1&&!failures,"Malformed SOCKS UDP killed session");
    h.raw->feed({},true);h.loop.run();expect(failures==1&&h.udp->closed&&h.raw->closed,"SOCKS control EOF did not close association");
    session->close();h.loop.run();expect(failures==1,"SOCKS association close repeated failure");
    Harness pending;std::shared_ptr<Datagram> blocked;unsigned canceled=0;bool overflow=false;
    pending.raw->peer=[&](const Buffer &){if(pending.raw->writes.size()==1)pending.raw->feed({5,0});};
    makeSocksDatagram(n,pending.io,[&](std::shared_ptr<Datagram> result,Error e){expect(e.empty(),"Pending SOCKS UDP session");blocked=std::move(result);});
    for(unsigned i=0;i<512;++i)blocked->send(target,{uint8_t(i)},[&](Error e){expect(!e.empty(),"Canceled association write succeeded");++canceled;});
    blocked->send(target,{1},[&](Error e){expect(!e.empty(),"SOCKS datagram operation-cap overflow admitted");overflow=true;});
    pending.loop.run();expect(pending.raw->writes.size()==2&&pending.raw->reading&&overflow,"SOCKS pending association fixture/queue limit");
    blocked->close();pending.loop.run();expect(canceled==512&&pending.raw->closed&&!pending.raw->reading,"Pending UDP association did not cancel raw control/read");
}
}
int main(){
    const char *phase="Reader";
    try{readerTests();phase="HTTP";httpTests();phase="SOCKS";socksTests();phase="VLESS";vlessTests();phase="Trojan";trojanTests();
        phase="Vision";visionTests();phase="VMess";vmessTests();phase="VMess rejection";vmessFailureTests();
        phase="queue/FIN/cancel";vmessQueueAndFIN();phase="SOCKS UDP";socksDatagramTests();
        std::cout<<"C++ basic protocols smoke passed: "<<checks<<" checks\n";return 0;
    }catch(const std::exception &e){std::cerr<<"C++ basic protocols smoke failed ["<<phase<<"]: "<<e.what()<<"\n";return 1;}
}
