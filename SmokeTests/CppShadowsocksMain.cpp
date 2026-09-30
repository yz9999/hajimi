#include "Crypto.hpp"
#include "Runtime.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace hajimi;
namespace {
std::atomic<unsigned> checks{0};
void expect(bool condition,const char *message) {
    ++checks;if (!condition) throw std::runtime_error(message);
}
void append(Buffer &out,const Buffer &in) {out.insert(out.end(),in.begin(),in.end());}
Buffer part(const Buffer &in,size_t offset,size_t count) {
    if (offset>in.size() || count>in.size()-offset) throw std::runtime_error("Test fixture truncated");
    return {in.begin()+offset,in.begin()+offset+count};
}
Buffer bytes(const std::string &s) {return {s.begin(),s.end()};}
Buffer hex(const std::string &s) {
    Buffer out;for (size_t i=0;i<s.size();i+=2) out.push_back(uint8_t(std::stoul(s.substr(i,2),nullptr,16)));return out;
}
Buffer sequence(size_t count,uint8_t start=0) {
    Buffer out(count);for (size_t i=0;i<count;++i) out[i]=uint8_t(start+i);return out;
}
void put16(Buffer &out,size_t n) {out.push_back(uint8_t(n>>8));out.push_back(uint8_t(n));}
void put64(Buffer &out,uint64_t n) {for (int i=7;i>=0;--i) out.push_back(uint8_t(n>>(i*8)));}
size_t u16(const Buffer &in,size_t i) {return size_t(in.at(i))<<8|in.at(i+1);}
uint64_t u64(const Buffer &in,size_t i) {
    uint64_t n=0;for (size_t j=0;j<8;++j) n=n<<8|in.at(i+j);return n;
}
template<class Function> void rejects(Function function,const char *message) {
    bool threw=false;try {function();} catch (const std::exception &) {threw=true;}expect(threw,message);
}
struct Scheduler {
    std::deque<std::function<void()>> tasks;
    void post(std::function<void()> task) {tasks.push_back(std::move(task));}
    void run() {
        size_t budget=100000;
        while (!tasks.empty()) {
            if (!budget--) throw std::runtime_error("Test scheduler did not quiesce");
            auto task=std::move(tasks.front());tasks.pop_front();task();
        }
    }
};
class FakeStream final:public Stream {
public:
    Scheduler &scheduler;std::vector<Buffer> writes;std::deque<WriteCallback> held;
    Buffer incoming;size_t offset=0,fragment=7,pendingMaximum=0;
    ReadCallback pending;bool holdWrites=false,eof=false,closed=false,halfClosed=false;
    explicit FakeStream(Scheduler &s):scheduler(s) {}
    void write(Buffer data,WriteCallback completion) override {
        writes.push_back(std::move(data));
        if (holdWrites) held.push_back(std::move(completion));else scheduler.post([completion]{completion({});});
    }
    void read(size_t maximum,ReadCallback completion) override {
        expect(!pending,"Fake transport received concurrent read");pendingMaximum=maximum;pending=std::move(completion);satisfy();
    }
    void satisfy() {
        if (!pending || (offset==incoming.size()&&!eof&&!closed)) return;
        auto completion=std::move(pending);pending={};
        size_t count=std::min({pendingMaximum,fragment,incoming.size()-offset});
        Buffer data=part(incoming,offset,count);offset+=count;
        bool end=eof&&offset==incoming.size();Error error=closed?"Transport closed":"";
        scheduler.post([completion,data=std::move(data),end,error]() mutable {completion(std::move(data),end,error);});
    }
    void feed(Buffer data,bool end=false) {append(incoming,data);eof=end;satisfy();}
    void close() override {
        closed=true;satisfy();
        while (!held.empty()) {auto completion=std::move(held.front());held.pop_front();scheduler.post([completion]{completion("Transport closed");});}
    }
    bool supportsHalfClose() const override {return true;}
    void shutdownWrite(WriteCallback completion) override {halfClosed=true;scheduler.post([completion]{completion({});});}
};
class FakeDatagram final:public Datagram {
public:
    Scheduler &scheduler;std::vector<Buffer> packets;PacketCallback receiver;WriteCallback failure;
    bool closed=false;
    explicit FakeDatagram(Scheduler &s):scheduler(s) {}
    void send(Target,Buffer data,WriteCallback completion) override {
        packets.push_back(std::move(data));scheduler.post([completion]{completion({});});
    }
    void start(PacketCallback receive,WriteCallback fail) override {receiver=std::move(receive);failure=std::move(fail);}
    void close() override {closed=true;receiver={};failure={};}
    void feed(Buffer packet) {
        auto callback=receiver;scheduler.post([callback,packet=std::move(packet)]() mutable {if(callback)callback({},std::move(packet));});
    }
};
std::shared_ptr<TransportFactory> factory(Scheduler &scheduler,std::shared_ptr<FakeStream> stream={},std::shared_ptr<FakeDatagram> udp={}) {
    auto result=std::make_shared<TransportFactory>();
    result->post=[&scheduler](std::function<void()> task){scheduler.post(std::move(task));};
    result->tcp=[&scheduler,stream](const Node &,const TLSOptions &,StreamCallback done){scheduler.post([stream,done]{done(stream,{});});};
    result->udp=[&scheduler,udp](const Node &,DatagramCallback done){scheduler.post([udp,done]{done(udp,{});});};
    return result;
}
void cryptoVectors() {
    expect(crypto::digest("SHA256",bytes("abc"))==hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),"SHA256 vector");
    expect(crypto::digest("MD5",bytes("abc"))==hex("900150983cd24fb0d6963f7d28e17f72"),"MD5 vector");
    expect(crypto::hmac("SHA256",Buffer(20,0x0b),bytes("Hi There"))==hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),"HMAC vector");
    expect(crypto::hkdf("SHA256",Buffer(22,0x0b),sequence(13),sequence(10,0xf0),42)==
           hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),"RFC5869 HKDF vector");
    Buffer block=hex("00112233445566778899aabbccddeeff");
    expect(crypto::aesECBBlock(block,sequence(16))==hex("69c4e0d86a7b0430d8cdb78070b4c55a"),"AES128 FIPS vector");
    expect(crypto::aesECBBlock(block,sequence(32))==hex("8ea2b7ca516745bfeafc49904b496089"),"AES256 FIPS vector");
    Buffer key(16,0),nonce(12,0),plain(16,0);
    expect(crypto::seal(crypto::AEAD::AES128GCM,key,nonce,plain)==
           hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),"NIST AESGCM vector");
    for (auto method:{crypto::AEAD::AES128GCM,crypto::AEAD::AES192GCM,crypto::AEAD::AES256GCM,
                      crypto::AEAD::ChaCha20Poly1305,crypto::AEAD::XChaCha20Poly1305}) {
        size_t count=method==crypto::AEAD::AES128GCM?16:method==crypto::AEAD::AES192GCM?24:32;
        Buffer k=sequence(count),n=sequence(method==crypto::AEAD::XChaCha20Poly1305?24:12);
        Buffer sealed=crypto::seal(method,k,n,bytes("payload"),bytes("associated"));
        expect(crypto::open(method,k,n,sealed,bytes("associated"))==bytes("payload"),"AEAD roundtrip");
        sealed.back()^=1;rejects([&]{crypto::open(method,k,n,sealed,bytes("associated"));},"AEAD tampering accepted");
    }
    expect(crypto::base64Decode("AQIDBA")==sequence(4,1),"Unpadded base64");
    expect(crypto::base64Decode(crypto::base64Encode(sequence(32)))==sequence(32),"Base64 roundtrip");
    rejects([]{crypto::base64Decode("AAAA:");},"Malformed base64 accepted");
    rejects([]{crypto::base64Decode("AR==");},"Nonzero unused base64 bits accepted");
    const std::string context="BLAKE3 2019-12-27 16:29:52 test vectors context";
    Buffer friendKey=bytes("whats the Elvish word for friend");
    expect(crypto::blake3({})==hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),"BLAKE3 empty");
    expect(crypto::blake3Keyed(friendKey,{})==hex("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),"BLAKE3 keyed");
    expect(crypto::blake3DeriveKey(context,{})==hex("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),"BLAKE3 derive");
    struct Vector{size_t size;const char *hash,*derive;};
    for (const Vector &v:std::vector<Vector>{
        {1025,"d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444","effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
        {3072,"b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2","050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"},
        {8192,"aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63","ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"}}) {
        Buffer input(v.size);for(size_t i=0;i<input.size();++i)input[i]=uint8_t(i%251);
        expect(crypto::blake3(input)==hex(v.hash),"BLAKE3 tree hash vector");
        expect(crypto::blake3DeriveKey(context,input)==hex(v.derive),"BLAKE3 tree derive vector");
    }
    Buffer psk=sequence(32,0x64),material=psk;append(material,Buffer(32,0xaa));
    Buffer derived=crypto::blake3DeriveKey("shadowsocks 2022 session subkey",material);
    expect(derived==hex("471dc6fd0dc74138d6865e559927db33f7e0fe603f3bb2d982da59fc0162c85b"),"SIP022 TCP session key vector");
    material=psk;append(material,sequence(8,1));
    expect(crypto::blake3DeriveKey("shadowsocks 2022 session subkey",material)==
           hex("150557261c48edaafa98fc2992ee8ecd606c52a867798a6bf7f7ecbe94e06aa9"),"SIP022 UDP session key vector");
    material=sequence(32);append(material,Buffer(32,0xaa));
    Buffer identityKey=crypto::blake3DeriveKey("shadowsocks 2022 identity subkey",material);
    expect(crypto::aesECBBlock(crypto::blake3(psk,16),identityKey)==hex("ee76f0b2b44e0cb0dab66a3ee2f612c9"),"SIP023 TCP EIH vector");
    Buffer identity=crypto::blake3(psk,16),separate=sequence(8,1);append(separate,Buffer(8,0));
    for(size_t i=0;i<16;++i)identity[i]^=separate[i];
    expect(crypto::aesECBBlock(identity,sequence(32))==hex("e4069992ecde45339addce9a8299d109"),"SIP023 UDP EIH vector");
}

struct Spec {
    Node node;crypto::AEAD method;size_t size,nonceSize=12;bool modern=false,cfb=false;
    std::vector<Buffer> keys;
    Spec(std::string name,size_t keyLength,crypto::AEAD algorithm,bool multikey=false):method(algorithm),size(keyLength) {
        node.type="ss";node.host="127.0.0.1";node.port=12345;node.parameters["cipher"]=name;
        modern=name.rfind("2022-",0)==0;cfb=name.find("cfb")!=std::string::npos;
        if (name=="xchacha20-ietf-poly1305")nonceSize=24;
        if (modern) {if(multikey)keys.push_back(sequence(size));keys.push_back(sequence(size,0x64));
            for(const auto &key:keys) {if(!node.parameters["password"].empty())node.parameters["password"]+=':';
                node.parameters["password"]+=crypto::base64Encode(key);}}
        else {node.parameters["password"]="test password";keys.push_back(crypto::passwordToKeyMD5("test password",size));}
    }
    Buffer subkey(const Buffer &salt) const {
        if(modern){Buffer m=keys.back();append(m,salt);return crypto::blake3DeriveKey("shadowsocks 2022 session subkey",m,size);}
        return crypto::hkdfSHA1(keys.back(),salt,bytes("ss-subkey"),size);
    }
};
struct Counter {
    crypto::AEAD method;Buffer key,nonce;
    explicit Counter(const Spec &spec,const Buffer &salt):method(spec.method),key(spec.subkey(salt)),nonce(spec.nonceSize,0) {}
    void increment(){for(auto &b:nonce)if(++b)return;}
    Buffer seal(const Buffer &data){Buffer out=crypto::seal(method,key,nonce,data);increment();return out;}
    Buffer open(const Buffer &data){Buffer out=crypto::open(method,key,nonce,data);increment();return out;}
    Buffer frame(const Buffer &data){Buffer n;put16(n,data.size());Buffer out=seal(n);append(out,seal(data));return out;}
};
void datagramKnownAnswers() {
    Spec spec("2022-blake3-aes-256-gcm",32,crypto::AEAD::AES256GCM);
    spec.keys={sequence(32)};
    Buffer session=sequence(8,1),header=session;put64(header,0);
    Buffer body{0};put64(body,1700000000);put16(body,0);append(body,socksAddress({"example.com",443,true,false}));
    append(body,bytes("lurge-sip022-known-answer"));
    Buffer wire=crypto::aesECBBlock(header,spec.keys[0]);
    append(wire,crypto::seal(spec.method,spec.subkey(session),part(header,4,12),body));
    expect(wire==hex("65627bd127f455618ff9d0f081df2db4"
                    "7e41c363d48a26c057fcafd4eb348dd067cf7fcb35c0e4744094af381f896528"
                    "d5722b043577b66754447146f69467334c2412b32e1e1e6ca4f843462ff8f9a5449b3b"),"SIP022 AES datagram external vector");
    Buffer merged=hex("000102030405060708090a0b0c0d0e0f10111213141516"
                      "17bfe02c5bb5f4aa86334426cecb52a8eb4a4728a5fdb34e1a7f0b2da529b8e34e"
                      "4606b6e74a027105b8e5c23ce1423c0f70018e2c35139e3474f2e30dbdd56999d7"
                      "5298d66cb40feb432848ec3a0b7ad53c728b559ec9d7ce8167e9df21fd0a2af839");
    Buffer opened=crypto::open(crypto::AEAD::XChaCha20Poly1305,sequence(32),part(merged,0,24),part(merged,24,merged.size()-24));
    expect(opened[16]==1 && u64(opened,17)==1700000000,"SIP022 XChaCha external header vector");
    expect(part(opened,25,8)==sequence(8,0x11),"SIP022 XChaCha echoed session vector");
    size_t cursor=35+u16(opened,33),consumed=0;
    Target target=parseSocksAddress(part(opened,cursor,opened.size()-cursor),consumed);cursor+=consumed;
    expect(target.host=="example.com" && target.port==443,"SIP022 XChaCha external address vector");
    expect(part(opened,cursor,opened.size()-cursor)==bytes("lurge-sip022-merged-known-answer"),"SIP022 XChaCha external payload vector");
}
void tcpInterop(const Spec &spec) {
    Scheduler scheduler;auto raw=std::make_shared<FakeStream>(scheduler);
    std::shared_ptr<Stream> stream;Error error;
    Target target{"2001:db8::1",443,false,false};
    connectShadowsocks(spec.node,target,factory(scheduler,raw),[&](std::shared_ptr<Stream> result,Error e){stream=std::move(result);error=e;});
    scheduler.run();expect(stream && error.empty(),"Shadowsocks TCP connect failed");expect(raw->writes.size()==1,"Initial prologue split into writes");
    Buffer request=raw->writes[0],salt=part(request,0,spec.cfb?16:spec.size),address;
    std::unique_ptr<Counter> client;
    std::unique_ptr<crypto::CipherStream> cfb;
    if(spec.cfb) {
        cfb=std::make_unique<crypto::CipherStream>(spec.node.option("cipher"),spec.keys.back(),salt,false);
        address=cfb->update(part(request,16,request.size()-16));
    } else {
        client=std::make_unique<Counter>(spec,salt);size_t offset=spec.size;
        if(spec.modern) {
            for(size_t i=0;i+1<spec.keys.size();++i) {
                Buffer material=spec.keys[i];append(material,salt);
                Buffer key=crypto::blake3DeriveKey("shadowsocks 2022 identity subkey",material,spec.size);
                expect(crypto::aesECBBlock(part(request,offset,16),key,false)==crypto::blake3(spec.keys[i+1],16),"TCP EIH identifies wrong key");offset+=16;
            }
            Buffer fixed=client->open(part(request,offset,27));offset+=27;
            uint64_t stamp=u64(fixed,1),now=unixSeconds();
            expect(fixed[0]==0 && (stamp>now?stamp-now:now-stamp)<=1,"SIP022 request fixed header");
            address=client->open(part(request,offset,u16(fixed,9)+16));offset+=u16(fixed,9)+16;
            expect(offset==request.size(),"SIP022 prologue has trailing data");
        } else {
            Buffer length=client->open(part(request,offset,18));offset+=18;
            address=client->open(part(request,offset,u16(length,0)+16));
        }
    }
    size_t consumed=0;Target actual=parseSocksAddress(address,consumed);
    expect(actual.host==target.host && actual.port==target.port,"TCP request destination changed");
    if(spec.modern) {
        size_t padding=u16(address,consumed);
        expect(padding>0 && padding<=900 && address.size()==consumed+2+padding,"SIP022 initial empty request not padded");
    } else expect(consumed==address.size(),"Classic TCP prologue trailing bytes");
    Buffer payload(70000);for(size_t i=0;i<payload.size();++i)payload[i]=uint8_t(i%251);
    bool sent=false;stream->write(payload,[&](Error e){expect(e.empty(),"TCP send failed");sent=true;});scheduler.run();
    expect(sent && raw->writes.size()==2,"TCP write not completed");
    Buffer decoded;
    if(spec.cfb) decoded=cfb->update(raw->writes[1]);
    else {
        Buffer wire=raw->writes[1];size_t offset=0;
        while(offset<wire.size()) {
            Buffer length=client->open(part(wire,offset,18));offset+=18;size_t count=u16(length,0);
            expect(count<=(spec.modern?65535:16383),"TCP outbound exceeded chunk cap");
            append(decoded,client->open(part(wire,offset,count+16)));offset+=count+16;
        }
    }
    expect(decoded==payload,"TCP bulk payload changed");
    Buffer responseSalt(spec.cfb?16:spec.size,0xbb),reply=responseSalt;
    Buffer greeting=bytes("server greeting"),tail=sequence(1024);Buffer expected=greeting;append(expected,tail);
    if(spec.cfb) {
        crypto::CipherStream server(spec.node.option("cipher"),spec.keys.back(),responseSalt,true);append(reply,server.update(expected));
    } else {
        Counter server(spec,responseSalt);
        if(spec.modern) {Buffer fixed{1};put64(fixed,unixSeconds());append(fixed,salt);put16(fixed,greeting.size());
            append(reply,server.seal(fixed));append(reply,server.seal(greeting));}
        else append(reply,server.frame(greeting));
        append(reply,server.frame(tail));
    }
    raw->feed(std::move(reply),true);Buffer got;bool eof=false;
    for(unsigned i=0;i<500 && !eof;++i) {
        bool called=false;
        stream->read(257,[&](Buffer data,bool end,Error e){expect(e.empty(),"TCP reply rejected");append(got,data);eof=end;called=true;});
        scheduler.run();expect(called,"TCP read stalled");
    }
    expect(eof && got==expected,"Fragmented TCP inbound payload/EOF changed");
    bool half=false;stream->shutdownWrite([&](Error e){expect(e.empty(),"Half-close rejected");half=true;});scheduler.run();
    expect(half && raw->halfClosed,"TCP half-close not forwarded");
    stream->write(bytes("late"),[&](Error e){expect(!e.empty(),"Write after half-close accepted");});scheduler.run();
    stream->close();scheduler.run();expect(raw->closed,"TCP close not forwarded");
}
Buffer inspectClientDatagram(const Spec &spec,const Buffer &wire,const Target &expected,const Buffer &payload,uint64_t identifier) {
    Buffer body,session;size_t cursor=0;
    if(spec.cfb) {
        crypto::CipherStream cipher(spec.node.option("cipher"),spec.keys.back(),part(wire,0,16),false);
        body=cipher.update(part(wire,16,wire.size()-16));
    } else if(!spec.modern) {
        Buffer salt=part(wire,0,spec.size);
        body=crypto::open(spec.method,spec.subkey(salt),Buffer(spec.nonceSize,0),part(wire,spec.size,wire.size()-spec.size));
    } else if(spec.method==crypto::AEAD::ChaCha20Poly1305) {
        body=crypto::open(crypto::AEAD::XChaCha20Poly1305,spec.keys.back(),part(wire,0,24),part(wire,24,wire.size()-24));
        session=part(body,0,8);expect(u64(body,8)==identifier,"ChaCha UDP packet counter");cursor=16;
    } else {
        Buffer separate=crypto::aesECBBlock(part(wire,0,16),spec.keys.front(),false);session=part(separate,0,8);
        expect(u64(separate,8)==identifier,"AES UDP packet counter");size_t offset=16;
        for(size_t i=0;i+1<spec.keys.size();++i) {
            Buffer hash=crypto::aesECBBlock(part(wire,offset,16),spec.keys[i],false);offset+=16;
            for(size_t j=0;j<16;++j)hash[j]^=separate[j];
            expect(hash==crypto::blake3(spec.keys[i+1],16),"UDP EIH identifies wrong key");
        }
        body=crypto::open(spec.method,spec.subkey(session),part(separate,4,12),part(wire,offset,wire.size()-offset));
    }
    if(spec.modern) {
        expect(body.at(cursor)==0,"SIP022 UDP client packet type");uint64_t stamp=u64(body,cursor+1),now=unixSeconds();
        expect((stamp>now?stamp-now:now-stamp)<=1,"SIP022 UDP client timestamp");
        size_t padding=u16(body,cursor+9);cursor+=11;
        if(expected.port==53 && payload.size()<900)expect(padding>0 && padding<=900-payload.size(),"SIP022 DNS padding missing");
        else expect(padding==0,"SIP022 padded non-DNS packet");cursor+=padding;
    }
    size_t used=0;Target target=parseSocksAddress(part(body,cursor,body.size()-cursor),used);cursor+=used;
    expect(target.host==expected.host && target.port==expected.port,"UDP client target changed");
    expect(part(body,cursor,body.size()-cursor)==payload,"UDP client payload changed");return session;
}
Buffer serverDatagram(const Spec &spec,const Buffer &client,uint64_t id,const Target &target,const Buffer &payload,
                      uint64_t timestamp=unixSeconds(),Buffer serverSession=Buffer(8,0xa5)) {
    if(spec.cfb) {
        Buffer iv(16,uint8_t(id)),body=socksAddress(target);append(body,payload);
        crypto::CipherStream cipher(spec.node.option("cipher"),spec.keys.back(),iv,true);append(iv,cipher.update(body));return iv;
    }
    if(!spec.modern) {
        Buffer salt(spec.size,uint8_t(id)),body=socksAddress(target);append(body,payload);Buffer wire=salt;
        append(wire,crypto::seal(spec.method,spec.subkey(salt),Buffer(spec.nonceSize,0),body));return wire;
    }
    bool merged=spec.method==crypto::AEAD::ChaCha20Poly1305;Buffer header=serverSession;put64(header,id);Buffer body;
    if(merged)body=header;
    body.push_back(1);put64(body,timestamp);append(body,client);put16(body,0);append(body,socksAddress(target));append(body,payload);
    if(merged) {Buffer nonce=sequence(24,uint8_t(id)),wire=nonce;
        append(wire,crypto::seal(crypto::AEAD::XChaCha20Poly1305,spec.keys.back(),nonce,body));return wire;}
    Buffer wire=crypto::aesECBBlock(header,spec.keys.back());
    append(wire,crypto::seal(spec.method,spec.subkey(serverSession),part(header,4,12),body));return wire;
}
void udpInterop(const Spec &spec) {
    Scheduler scheduler;auto raw=std::make_shared<FakeDatagram>(scheduler);std::shared_ptr<Datagram> datagram;
    makeShadowsocksDatagram(spec.node,factory(scheduler,{},raw),[&](std::shared_ptr<Datagram> result,Error error){
        expect(error.empty(),"Shadowsocks UDP connect failed");datagram=std::move(result);});scheduler.run();
    expect(bool(datagram),"Missing UDP session");unsigned receives=0,failures=0;
    Target dns{"1.2.3.4",53,true,false},other{"2001:db8::2",443,true,false};Buffer last;
    datagram->start([&](Target target,Buffer data){expect(target.host==dns.host && target.port==dns.port,"UDP server target changed");
        last=std::move(data);++receives;},[&](Error){++failures;});scheduler.run();
    unsigned sends=0;
    datagram->send(dns,bytes("query"),[&](Error error){expect(error.empty(),"UDP send failed");++sends;});
    datagram->send(other,bytes("second"),[&](Error error){expect(error.empty(),"Second UDP send failed");++sends;});scheduler.run();
    expect(sends==2 && raw->packets.size()==2,"UDP send queue stalled");
    Buffer client=inspectClientDatagram(spec,raw->packets[0],dns,bytes("query"),0);
    Buffer client2=inspectClientDatagram(spec,raw->packets[1],other,bytes("second"),1);
    expect(client==client2,"UDP changed client session between packets");
    if(!spec.modern && !spec.cfb) {
        raw->feed(raw->packets[0]);scheduler.run();expect(receives==0,"Classic UDP request reflected as server response");
    }
    Buffer reply=serverDatagram(spec,client,9,dns,bytes("answer"));raw->feed(reply);scheduler.run();
    expect(receives==1 && last==bytes("answer"),"UDP valid answer dropped");
    if(!spec.cfb) {
        raw->feed(reply);scheduler.run();expect(receives==1,"UDP replay delivered");
        Buffer corrupt=reply;corrupt.back()^=1;raw->feed(corrupt);scheduler.run();expect(receives==1 && !failures,"UDP tamper killed session");
    }
    if(spec.modern) {
        raw->feed(serverDatagram(spec,client,10,dns,bytes("SID collision"),unixSeconds(),client));scheduler.run();
        expect(receives==1,"Server reused client session ID");
        raw->feed(serverDatagram(spec,Buffer(8,0xee),10,dns,bytes("foreign")));scheduler.run();
        expect(receives==1 && !failures,"UDP foreign client session accepted");
        raw->feed(serverDatagram(spec,client,10,dns,bytes("stale"),unixSeconds()-31));scheduler.run();
        expect(receives==1 && !failures,"UDP stale timestamp accepted");
        raw->feed(serverDatagram(spec,client,8,dns,bytes("reordered")));scheduler.run();
        expect(receives==2 && last==bytes("reordered"),"UDP out-of-order fresh packet dropped");
        raw->feed(serverDatagram(spec,client,8,dns,bytes("reordered")));scheduler.run();expect(receives==2,"UDP reordered replay delivered");
        raw->feed(serverDatagram(spec,client,8201,dns,bytes("window shift")));scheduler.run();
        expect(receives==3,"UDP replay window did not shift");raw->feed(reply);scheduler.run();expect(receives==3,"UDP expired packet delivered");
        raw->feed(serverDatagram(spec,client,0,dns,bytes("new server"),unixSeconds(),Buffer(8,0xa6)));scheduler.run();
        expect(receives==4 && last==bytes("new server"),"UDP server rekey dropped");
        raw->feed(serverDatagram(spec,client,8200,dns,bytes("near reordered")));scheduler.run();expect(receives==5,"Shifted replay window lost nearby packet");
        raw->feed(serverDatagram(spec,client,65,dns,bytes("word boundary")));scheduler.run();expect(receives==6,"Shifted replay window lost word boundary");
        raw->feed(serverDatagram(spec,client,65,dns,bytes("word boundary")));scheduler.run();expect(receives==6,"Word boundary replay accepted");
    }
    datagram->send(dns,Buffer(65507),[&](Error error){expect(!error.empty(),"Oversized framed UDP payload accepted");});scheduler.run();
    expect(!raw->closed && !failures,"Invalid UDP payload killed session");
    datagram->close();scheduler.run();expect(raw->closed,"UDP close not forwarded");
}
void tcpRejectionAndCancellation() {
    for(unsigned scenario=0;scenario<4;++scenario) {
        Spec spec("2022-blake3-aes-128-gcm",16,crypto::AEAD::AES128GCM);
        Scheduler scheduler;auto raw=std::make_shared<FakeStream>(scheduler);std::shared_ptr<Stream> stream;
        connectShadowsocks(spec.node,{"example.com",443,false,false},factory(scheduler,raw),[&](std::shared_ptr<Stream> result,Error error){
            expect(error.empty(),"Negative fixture connect failed");stream=std::move(result);});scheduler.run();
        bool failed=false;
        stream->read(128,[&](Buffer data,bool eof,Error error){expect(data.empty() && eof && !error.empty(),"Invalid SIP022 TCP reply accepted");failed=true;});
        stream->read(128,[&](Buffer,bool,Error error){expect(!error.empty(),"Concurrent protocol read accepted");});scheduler.run();
        Buffer salt=part(raw->writes[0],0,spec.size),responseSalt(spec.size,0xcc),wire=responseSalt;
        Counter server(spec,responseSalt);Buffer fixed{1};
        put64(fixed,scenario==1?uint64_t(-1):unixSeconds());
        append(fixed,scenario==0?Buffer(spec.size,0xff):salt);put16(fixed,3);
        append(wire,server.seal(fixed));append(wire,server.seal(bytes("abc")));
        if(scenario==2)wire.back()^=1;
        if(scenario==3)wire.resize(wire.size()-3);
        raw->feed(std::move(wire),true);scheduler.run();expect(failed && raw->closed,"Invalid TCP reply did not terminate");
    }
    for(unsigned scenario=0;scenario<3;++scenario) {
        Spec spec("aes-128-gcm",16,crypto::AEAD::AES128GCM);
        Scheduler scheduler;auto raw=std::make_shared<FakeStream>(scheduler);std::shared_ptr<Stream> stream;
        connectShadowsocks(spec.node,{"example.com",443,false,false},factory(scheduler,raw),[&](std::shared_ptr<Stream> s,Error e){
            expect(e.empty(),"Classic negative fixture connect");stream=std::move(s);});scheduler.run();
        bool rejected=false;
        stream->read(128,[&](Buffer,bool eof,Error e){expect(eof && !e.empty(),"Invalid classic TCP reply accepted");rejected=true;});scheduler.run();
        Buffer salt=scenario==0?part(raw->writes[0],0,16):Buffer(16,0xaa),wire=salt;Counter server(spec,salt);
        Buffer length;put16(length,scenario==1?0x4000:3);append(wire,server.seal(length));append(wire,server.seal(bytes("abc")));
        if(scenario==2)wire.back()^=1;
        raw->feed(std::move(wire),true);scheduler.run();expect(rejected && raw->closed,"Classic tamper/reflection/chunk limit not enforced");
    }
    Spec spec("aes-256-gcm",32,crypto::AEAD::AES256GCM);
    Scheduler scheduler;auto raw=std::make_shared<FakeStream>(scheduler);std::shared_ptr<Stream> stream;
    connectShadowsocks(spec.node,{"example.com",443,false,false},factory(scheduler,raw),[&](std::shared_ptr<Stream> result,Error error){
        expect(error.empty(),"Queue fixture connect failed");stream=std::move(result);});scheduler.run();
    unsigned completed=0;bool overflow=false,readCanceled=false;raw->holdWrites=true;
    stream->write(Buffer(maximumQueuedBytes/2,1),[&](Error error){expect(!error.empty(),"Canceled in-flight write succeeded");++completed;});
    stream->write(Buffer(maximumQueuedBytes/2,2),[&](Error error){expect(!error.empty(),"Canceled queued write succeeded");++completed;});
    stream->write(Buffer(1,3),[&](Error error){expect(!error.empty(),"Bounded TCP queue overflow accepted");overflow=true;});
    stream->read(512,[&](Buffer,bool eof,Error error){expect(eof && !error.empty(),"Pending read cancellation lost");readCanceled=true;});
    scheduler.run();expect(overflow && !completed && raw->writes.size()==2,"TCP queue was not serialized/bounded");
    stream->close();scheduler.run();expect(completed==2 && readCanceled,"Close did not complete all callbacks exactly once");
    stream->write(bytes("closed"),[&](Error error){expect(!error.empty(),"Closed TCP stream accepted write");});scheduler.run();
}
Spec replaySpec(std::string password="shared replay regression",std::string cipher="aes-128-gcm",
                size_t size=16,crypto::AEAD method=crypto::AEAD::AES128GCM) {
    Spec spec(std::move(cipher),size,method);spec.node.parameters["password"]=std::move(password);
    spec.keys={crypto::passwordToKeyMD5(spec.node.option("password"),size)};return spec;
}
Buffer tcpReply(const Spec &spec,const Buffer &salt,const Buffer &payload,const Buffer &requestSalt={}) {
    Buffer wire=salt;Counter server(spec,salt);
    if(spec.modern){Buffer fixed{1};put64(fixed,unixSeconds());append(fixed,requestSalt);put16(fixed,payload.size());
        append(wire,server.seal(fixed));append(wire,server.seal(payload));}
    else append(wire,server.frame(payload));
    return wire;
}
Buffer classicUDPReply(const Spec &spec,const Buffer &salt,const Buffer &body) {
    Buffer wire=salt;append(wire,crypto::seal(spec.method,spec.subkey(salt),Buffer(spec.nonceSize,0),body));return wire;
}
struct TCPReplayFixture {
    Scheduler scheduler;std::shared_ptr<FakeStream> raw=std::make_shared<FakeStream>(scheduler);
    std::shared_ptr<Stream> stream;Buffer received;Error error;bool called=false,eof=false;
    explicit TCPReplayFixture(const Spec &spec,Target target={"example.com",443,false,false}) {
        connectShadowsocks(spec.node,target,factory(scheduler,raw),[this](std::shared_ptr<Stream> result,Error e){
            expect(result&&e.empty(),"Replay TCP fixture connect failed");stream=std::move(result);});scheduler.run();
    }
    void read(Buffer reply) {
        raw->feed(std::move(reply),true);
        stream->read(65535,[this](Buffer data,bool end,Error e){received=std::move(data);eof=end;error=std::move(e);called=true;});
        scheduler.run();expect(called,"Replay TCP fixture read stalled");
    }
    void close(){stream->close();scheduler.run();}
};
struct UDPReplayFixture {
    Scheduler scheduler;std::shared_ptr<FakeDatagram> raw=std::make_shared<FakeDatagram>(scheduler);
    std::shared_ptr<Datagram> session;unsigned receives=0,failures=0;Buffer received;
    explicit UDPReplayFixture(const Spec &spec) {
        makeShadowsocksDatagram(spec.node,factory(scheduler,{},raw),[this](std::shared_ptr<Datagram> result,Error e){
            expect(result&&e.empty(),"Replay UDP fixture connect failed");session=std::move(result);});scheduler.run();
        session->start([this](Target,Buffer data){++receives;received=std::move(data);},[this](Error){++failures;});scheduler.run();
    }
    void feed(Buffer packet){raw->feed(std::move(packet));scheduler.run();}
    void close(){session->close();scheduler.run();}
};
void classicSharedReplayTests() {
    auto spec=replaySpec();Buffer salt=sequence(16,0x51),payload=bytes("recorded response"),wire=tcpReply(spec,salt,payload);
    {TCPReplayFixture first(spec,{"old.example",80,false,false});first.read(wire);
        expect(first.received==payload&&first.error.empty(),"First classic TCP response dropped");first.close();}
    {TCPReplayFixture second(spec,{"new.example",443,false,false});second.read(wire);
        expect(second.received.empty()&&second.eof&&!second.error.empty()&&second.raw->closed,"Classic TCP ciphertext replay crossed connections");second.close();}
    {TCPReplayFixture normal(spec);normal.read(tcpReply(spec,sequence(16,0x52),payload));
        expect(normal.received==payload&&normal.error.empty(),"Shared TCP replay cache rejected fresh salt");normal.close();}
    {TCPReplayFixture original(spec),reflected(spec);reflected.read(original.raw->writes[0]);
        expect(reflected.received.empty()&&!reflected.error.empty()&&reflected.raw->closed,"Classic request reflection crossed TCP connections");original.close();reflected.close();}
    Target dns{"1.2.3.4",53,true,false};Buffer body=socksAddress(dns);append(body,payload);
    auto packet=classicUDPReply(spec,sequence(16,0x61),body);
    {UDPReplayFixture first(spec);first.feed(packet);first.feed(packet);
        expect(first.receives==1&&first.received==payload&&!first.failures,"Classic UDP same-session replay or valid packet handling changed");first.close();}
    {UDPReplayFixture second(spec);second.feed(packet);
        expect(!second.receives&&!second.failures,"Classic UDP replay crossed sessions");second.feed(classicUDPReply(spec,sequence(16,0x62),body));
        expect(second.receives==1&&second.received==payload&&!second.failures,"Replay drop killed subsequent fresh UDP traffic");second.close();}
    {UDPReplayFixture original(spec),reflected(spec);bool sent=false;
        original.session->send(dns,bytes("query"),[&](Error e){expect(e.empty(),"Replay request UDP send failed");sent=true;});original.scheduler.run();
        expect(sent&&original.raw->packets.size()==1,"Replay request UDP fixture did not send");reflected.feed(original.raw->packets[0]);
        expect(!reflected.receives&&!reflected.failures,"Classic UDP request reflection crossed sessions");original.close();reflected.close();}
}
void classicReplayDomainTests() {
    Buffer salt=sequence(16,0x71),payload=bytes("domain response");
    for(const auto &password:{"replay key A","replay key B"}){
        auto spec=replaySpec(password);TCPReplayFixture tcp(spec);tcp.read(tcpReply(spec,salt,payload));
        expect(tcp.received==payload&&tcp.error.empty(),"TCP replay cache mixed distinct password/key domains");tcp.close();
        Target target{"1.2.3.4",443,true,false};Buffer body=socksAddress(target);append(body,payload);
        UDPReplayFixture udp(spec);udp.feed(classicUDPReply(spec,salt,body));
        expect(udp.receives==1&&udp.received==payload&&!udp.failures,"UDP replay cache mixed distinct keys or TCP/UDP protocol domains");udp.close();
    }
    Buffer wideSalt=sequence(32,0x72);
    for(const auto &spec:std::vector<Spec>{replaySpec("replay cipher domain","aes-256-gcm",32,crypto::AEAD::AES256GCM),
                                         replaySpec("replay cipher domain","chacha20-ietf-poly1305",32,crypto::AEAD::ChaCha20Poly1305)}){
        TCPReplayFixture tcp(spec);tcp.read(tcpReply(spec,wideSalt,payload));
        expect(tcp.received==payload&&tcp.error.empty(),"TCP replay cache mixed cipher domains sharing derived key");tcp.close();
        Buffer body=socksAddress({"1.2.3.4",443,true,false});append(body,payload);UDPReplayFixture udp(spec);udp.feed(classicUDPReply(spec,wideSalt,body));
        expect(udp.receives==1&&!udp.failures,"UDP replay cache mixed cipher domains sharing derived key");udp.close();
    }
    {auto canonical=replaySpec("replay cipher aliases","chacha20-ietf-poly1305",32,crypto::AEAD::ChaCha20Poly1305),alias=canonical;
        alias.node.parameters["cipher"]="chacha20-poly1305";auto wire=tcpReply(canonical,wideSalt,payload);
        TCPReplayFixture first(canonical);first.read(wire);expect(first.received==payload&&first.error.empty(),"Canonical cipher response failed");first.close();
        TCPReplayFixture second(alias);second.read(wire);expect(second.received.empty()&&!second.error.empty(),"Cipher alias bypassed shared replay domain");second.close();}
    // Modern request echo/session binding is not a classic-salt cache domain.
    {Spec modern("2022-blake3-aes-128-gcm",16,crypto::AEAD::AES128GCM);Buffer modernSalt(16,0xee);
        for(unsigned i=0;i<2;++i){TCPReplayFixture tcp(modern);auto requestSalt=part(tcp.raw->writes[0],0,16);
            tcp.read(tcpReply(modern,modernSalt,payload,requestSalt));expect(tcp.received==payload&&tcp.error.empty(),"Classic global cache contaminated SS2022 request-echo handling");tcp.close();}}
}
void classicReplayPoisoningTests() {
    auto spec=replaySpec("replay poison regression");Buffer payload=bytes("valid after invalid");
    for(unsigned scenario=0;scenario<5;++scenario){Buffer salt=sequence(16,uint8_t(0x81+scenario)),good=tcpReply(spec,salt,payload),bad=good;
        if(scenario==0)bad[spec.size+17]^=1; // Unauthenticated length.
        else if(scenario==1)bad.back()^=1; // Unauthenticated first body.
        else if(scenario==2)bad.resize(spec.size+17); // Truncated first length.
        else if(scenario==3)bad.pop_back(); // Truncated first body.
        else{Counter server(spec,salt);Buffer length;put16(length,0x4000);bad=salt;append(bad,server.seal(length));append(bad,server.seal(payload));}
        {TCPReplayFixture rejected(spec);rejected.read(bad);expect(rejected.received.empty()&&!rejected.error.empty()&&rejected.raw->closed,"Malformed TCP response accepted");rejected.close();}
        {TCPReplayFixture valid(spec);valid.read(good);expect(valid.received==payload&&valid.error.empty(),"Unauthenticated/truncated TCP input poisoned shared salt cache");valid.close();}
    }
    Buffer goodBody=socksAddress({"1.2.3.4",53,true,false});append(goodBody,payload);
    for(unsigned scenario=0;scenario<5;++scenario){Buffer salt=sequence(16,uint8_t(0x91+scenario)),good=classicUDPReply(spec,salt,goodBody),bad=good;
        if(scenario==0)bad.back()^=1;
        else if(scenario==1)bad.pop_back();
        else if(scenario==2)bad=classicUDPReply(spec,salt,Buffer{0x7f});
        else if(scenario==3)bad=classicUDPReply(spec,salt,Buffer{3,0,0,53});
        else bad=classicUDPReply(spec,salt,socksAddress({"1.2.3.4",0,true,false}));
        UDPReplayFixture udp(spec);udp.feed(bad);expect(!udp.receives&&!udp.failures,"Malformed UDP packet delivered or killed session");
        udp.feed(good);expect(udp.receives==1&&udp.received==payload&&!udp.failures,"Invalid UDP packet poisoned shared replay cache");udp.close();
    }
}
void classicReplayConcurrencyTests() {
    constexpr size_t workers=8;auto spec=replaySpec("replay concurrency regression");Buffer payload=bytes("concurrent response");
    for(bool distinct:{false,true}){
        std::atomic<size_t> ready{0};std::atomic<bool> go{false};std::array<Buffer,workers> received;
        std::array<Error,workers> failures;std::array<std::exception_ptr,workers> exceptions{};std::vector<std::thread> threads;
        for(size_t i=0;i<workers;++i)threads.emplace_back([&,i]{ready.fetch_add(1);while(!go.load())std::this_thread::yield();
            try{TCPReplayFixture tcp(spec);auto salt=sequence(16,distinct?uint8_t(0xa1+i):uint8_t(0xb1));tcp.read(tcpReply(spec,salt,payload));
                received[i]=tcp.received;failures[i]=tcp.error;tcp.close();}catch(...){exceptions[i]=std::current_exception();}});
        while(ready.load()!=workers)std::this_thread::yield();go=true;for(auto &thread:threads)thread.join();
        unsigned accepts=0;for(size_t i=0;i<workers;++i){if(exceptions[i])std::rethrow_exception(exceptions[i]);
            if(failures[i].empty()){expect(received[i]==payload,"Concurrent valid TCP reply changed bytes");++accepts;}
            else expect(received[i].empty(),"Concurrent replay leaked plaintext before salt commit");}
        expect(accepts==(distinct?workers:1),"Shared TCP replay cache check/commit not atomic or rejected fresh concurrent salts");
    }
    Buffer body=socksAddress({"1.2.3.4",53,true,false});append(body,payload);
    for(bool distinct:{false,true}){
        std::atomic<size_t> ready{0};std::atomic<bool> go{false};std::array<unsigned,workers> delivered{},failures{};
        std::array<std::exception_ptr,workers> exceptions{};std::vector<std::thread> threads;
        for(size_t i=0;i<workers;++i)threads.emplace_back([&,i]{ready.fetch_add(1);while(!go.load())std::this_thread::yield();
            try{UDPReplayFixture udp(spec);auto salt=sequence(16,distinct?uint8_t(0xc1+i):uint8_t(0xd1));udp.feed(classicUDPReply(spec,salt,body));
                delivered[i]=udp.receives;failures[i]=udp.failures;udp.close();}catch(...){exceptions[i]=std::current_exception();}});
        while(ready.load()!=workers)std::this_thread::yield();go=true;for(auto &thread:threads)thread.join();
        unsigned accepts=0;for(size_t i=0;i<workers;++i){if(exceptions[i])std::rethrow_exception(exceptions[i]);
            expect(!failures[i]&&delivered[i]<=1,"Concurrent UDP replay killed session or duplicated delivery");accepts+=delivered[i];}
        expect(accepts==(distinct?workers:1),"Shared UDP replay cache check/commit not atomic or rejected fresh concurrent salts");
    }
}
void validation() {
    Spec spec("2022-blake3-aes-128-gcm",16,crypto::AEAD::AES128GCM,true);
    expect(validateShadowsocks(spec.node,false).empty(),"Valid multikey PSK rejected");
    auto invalid=spec.node;invalid.parameters["password"]="hunter2";
    expect(!validateShadowsocks(invalid,false).empty(),"2022 passphrase accepted");
    invalid=spec.node;invalid.parameters["password"]=crypto::base64Encode(sequence(32));
    expect(!validateShadowsocks(invalid,true).empty(),"2022 wrong-length PSK accepted");
    invalid=spec.node;invalid.parameters["password"]+=':';
    expect(!validateShadowsocks(invalid,true).empty(),"Empty multikey segment accepted");
    invalid=spec.node;invalid.parameters["plugin"]="v2ray-plugin";
    expect(!validateShadowsocks(invalid,false).empty(),"Unsupported SIP003 plugin accepted");
    invalid=spec.node;invalid.parameters["obfs"]="tls";
    expect(!validateShadowsocks(invalid,false).empty(),"Unsupported obfuscation plugin accepted");
    invalid=spec.node;invalid.parameters["network"]="ws";
    expect(!validateShadowsocks(invalid,false).empty(),"Unsupported Shadowsocks carrier accepted");
    Spec chacha("2022-blake3-chacha20-poly1305",32,crypto::AEAD::ChaCha20Poly1305,true);
    expect(!validateShadowsocks(chacha.node,false).empty(),"ChaCha2022 EIH accepted");
    Spec cfb("aes-256-cfb",32,crypto::AEAD::AES256GCM);cfb.node.type="ssr";
    expect(validateShadowsocks(cfb.node,true).empty(),"SSR origin/plain AESCFB rejected");
    cfb.node.parameters["protocol"]="auth_chain_a";
    expect(!validateShadowsocks(cfb.node,true).empty(),"Unsupported SSR protocol accepted");
}
}
int main() {
    try {
        cryptoVectors();datagramKnownAnswers();validation();
        for(const Spec &spec:std::vector<Spec>{
            {"aes-128-gcm",16,crypto::AEAD::AES128GCM},
            {"aes-192-gcm",24,crypto::AEAD::AES192GCM},
            {"aes-256-gcm",32,crypto::AEAD::AES256GCM},
            {"chacha20-ietf-poly1305",32,crypto::AEAD::ChaCha20Poly1305},
            {"xchacha20-ietf-poly1305",32,crypto::AEAD::XChaCha20Poly1305},
            {"2022-blake3-aes-128-gcm",16,crypto::AEAD::AES128GCM},
            {"2022-blake3-aes-256-gcm",32,crypto::AEAD::AES256GCM},
            {"2022-blake3-chacha20-poly1305",32,crypto::AEAD::ChaCha20Poly1305},
            {"2022-blake3-aes-128-gcm",16,crypto::AEAD::AES128GCM,true},
            {"2022-blake3-aes-256-gcm",32,crypto::AEAD::AES256GCM,true},
            {"aes-128-cfb",16,crypto::AEAD::AES128GCM},
            {"aes-192-cfb",24,crypto::AEAD::AES192GCM},
            {"aes-256-cfb",32,crypto::AEAD::AES256GCM}}) {tcpInterop(spec);udpInterop(spec);}
        Spec ssr("aes-256-cfb",32,crypto::AEAD::AES256GCM);ssr.node.type="ssr";
        ssr.node.parameters["protocol"]="origin";ssr.node.parameters["obfs"]="plain";
        tcpInterop(ssr);udpInterop(ssr);
        tcpRejectionAndCancellation();classicSharedReplayTests();classicReplayDomainTests();classicReplayPoisoningTests();classicReplayConcurrencyTests();
        std::cout<<"C++ Shadowsocks/crypto smoke passed: "<<checks.load()<<" checks\n";return 0;
    } catch(const std::exception &error) {std::cerr<<"C++ Shadowsocks smoke failed: "<<error.what()<<"\n";return 1;}
}
