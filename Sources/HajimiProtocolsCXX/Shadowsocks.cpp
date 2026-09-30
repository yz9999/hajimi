#include "Runtime.hpp"
#include "Crypto.hpp"
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <deque>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace hajimi {
namespace {
using crypto::AEAD;
void append(Buffer &out,const Buffer &data) { out.insert(out.end(),data.begin(),data.end()); }
Buffer slice(const Buffer &data,size_t offset,size_t count) {
    if (offset>data.size() || count>data.size()-offset) throw std::runtime_error("Shadowsocks packet truncated");
    return Buffer(data.begin()+offset,data.begin()+offset+count);
}
void put16(Buffer &out,size_t value) { out.push_back(uint8_t(value>>8)); out.push_back(uint8_t(value)); }
void put64(Buffer &out,uint64_t value) { for (int i=7;i>=0;--i) out.push_back(uint8_t(value>>(i*8))); }
uint64_t get64(const Buffer &in,size_t offset) {
    if (offset>in.size() || in.size()-offset<8) throw std::runtime_error("Shadowsocks integer truncated");
    uint64_t value=0; for (unsigned i=0;i<8;++i) value=value<<8 | in[offset+i]; return value;
}
size_t get16(const Buffer &in,size_t offset) {
    if (offset>in.size() || in.size()-offset<2) throw std::runtime_error("Shadowsocks length truncated");
    return size_t(in[offset])<<8 | in[offset+1];
}
bool fresh(uint64_t timestamp,uint64_t now) { return (timestamp>now ? timestamp-now : now-timestamp)<=30; }
std::string lower(std::string value) {
    std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return char(std::tolower(c));});
    return value;
}
using ReplayDomain = std::array<uint8_t,32>;
struct ClassicReplayToken {
    ReplayDomain domain{};
    std::array<uint8_t,32> salt{};
    uint8_t saltSize=0;
    bool operator==(const ClassicReplayToken &other) const {
        return saltSize==other.saltSize && domain==other.domain && salt==other.salt;
    }
};
struct ClassicReplayHash {
    size_t operator()(const ClassicReplayToken &token) const noexcept {
        size_t value=1469598103934665603ULL;
        for (auto byte:token.domain) value=(value^byte)*1099511628211ULL;
        for (auto byte:token.salt) value=(value^byte)*1099511628211ULL;
        return (value^token.saltSize)*1099511628211ULL;
    }
};
// Classic AEAD has no timestamp or request echo, so an infinite replay window
// would require unbounded memory. These process-wide exact caches retain the
// newest 32,768 TCP salts for <=10 minutes and 65,536 UDP salts for <=5 minutes.
// Capacity evicts the oldest record rather than blocking sustained legitimate
// UDP traffic; protection lasts only while a record is retained. TCP and UDP
// are separate protocol domains, so UDP volume cannot evict TCP protection.
// Expiration is lazy on access; storage remains count-bounded even when idle.
// The key domain is a SHA-256 fingerprint of cipher parameters and the derived
// key, never a retained password or PSK. Untrusted input is committed only after
// authentication AND framing validation; check+insert is atomic across strands.
class ClassicReplayCache {
    using Clock = std::chrono::steady_clock;
    struct Entry { ClassicReplayToken token; Clock::time_point added; };
    std::mutex mutex_;
    std::unordered_set<ClassicReplayToken,ClassicReplayHash> tokens_;
    std::deque<Entry> order_;
    size_t capacity_;
    Clock::duration lifetime_;
    void removeOldest() {
        tokens_.erase(order_.front().token); order_.pop_front();
    }
    void expire(Clock::time_point now) {
        while (!order_.empty() && now-order_.front().added>=lifetime_) removeOldest();
    }
public:
    ClassicReplayCache(size_t capacity,Clock::duration lifetime):capacity_(capacity),lifetime_(lifetime) {}
    bool contains(const ClassicReplayToken &token) {
        std::lock_guard<std::mutex> guard(mutex_); expire(Clock::now());
        return tokens_.count(token)!=0;
    }
    bool commit(const ClassicReplayToken &token) {
        std::lock_guard<std::mutex> guard(mutex_);
        auto now=Clock::now(); expire(now);
        if (tokens_.count(token)) return false;
        while (tokens_.size()>=capacity_) removeOldest();
        order_.push_back({token,now});
        try { tokens_.insert(token); }
        catch (...) { order_.pop_back(); throw; }
        return true;
    }
};
ClassicReplayCache &classicReplayCache(bool udp) {
    // Network/dispatch cancellation is asynchronous, including during exit.
    // Function-static destructors cannot safely race late callbacks or other
    // globals' destructors. Intentionally retain exactly these two bounded
    // registries for the process lifetime; C++11 static initialization remains
    // thread-safe, and the OS reclaims their storage on process termination.
    static auto *const tcp=new ClassicReplayCache(32768,std::chrono::minutes(10));
    static auto *const datagrams=new ClassicReplayCache(65536,std::chrono::minutes(5));
    return *(udp?datagrams:tcp);
}
struct Config {
    AEAD method=AEAD::AES256GCM;
    bool modern=false, cfb=false;
    size_t keyLength=32,nonceLength=12;
    std::string cfbName;
    std::vector<Buffer> keys;
    ReplayDomain replayDomain{};
    const Buffer &key() const { return keys.back(); }
    explicit Config(const Node &node) {
        auto network=lower(node.option("network",node.option("transport","tcp")));
        if (!network.empty() && network!="tcp") throw std::runtime_error("Shadowsocks requires the TCP carrier");
        auto plugin=lower(node.option("plugin"));
        if (!plugin.empty() && plugin!="none") throw std::runtime_error("Shadowsocks SIP003 plugins are not supported");
        auto obfs=lower(node.option("obfs",node.option("obfs-mode")));
        if (!obfs.empty() && obfs!="none" && obfs!="plain")
            throw std::runtime_error("Shadowsocks obfuscation plugin is not supported");
        std::string name=lower(node.option("cipher",node.option("encrypt-method")));
        modern=name.rfind("2022-blake3-",0)==0;
        if (name=="aes-128-gcm" || name=="2022-blake3-aes-128-gcm") {method=AEAD::AES128GCM;keyLength=16;}
        else if (name=="aes-192-gcm") {method=AEAD::AES192GCM;keyLength=24;}
        else if (name=="aes-256-gcm" || name=="2022-blake3-aes-256-gcm") method=AEAD::AES256GCM;
        else if (name=="chacha20-ietf-poly1305" || name=="chacha20-poly1305" ||
                 name=="2022-blake3-chacha20-poly1305") method=AEAD::ChaCha20Poly1305;
        else if (name=="xchacha20-ietf-poly1305") {method=AEAD::XChaCha20Poly1305;nonceLength=24;}
        else if (name=="aes-128-cfb" || name=="aes-192-cfb" || name=="aes-256-cfb") {
            cfb=true; cfbName=name; keyLength=name=="aes-128-cfb"?16:name=="aes-192-cfb"?24:32;
        } else throw std::runtime_error("Shadowsocks cipher unsupported");
        if (lower(node.type)=="ssr" || lower(node.type)=="shadowsocksr") {
            if (!cfb || lower(node.option("protocol","origin"))!="origin" || lower(node.option("obfs","plain"))!="plain")
                throw std::runtime_error("SSR supports AES-CFB with origin/plain only");
        }
        std::string password=node.option("password");
        if (password.empty()) throw std::runtime_error("Shadowsocks password missing");
        if (!modern) {
            keys.push_back(crypto::passwordToKeyMD5(password,keyLength));
            if (!cfb) {
                const std::string label="Hajimi classic Shadowsocks replay v1";
                Buffer material(label.begin(),label.end());
                material.insert(material.end(),{uint8_t(method),uint8_t(keyLength),uint8_t(nonceLength)});
                append(material,key()); auto domain=crypto::digest("SHA256",material);
                OPENSSL_cleanse(material.data(),material.size());
                std::copy(domain.begin(),domain.end(),replayDomain.begin());
            }
            return;
        }
        auto begin=password.find_first_not_of(" \t\r\n"), end=password.find_last_not_of(" \t\r\n");
        if (begin==std::string::npos) throw std::runtime_error("Shadowsocks2022 PSK missing");
        password=password.substr(begin,end-begin+1);
        size_t start=0;
        do {
            size_t colon=password.find(':',start);
            std::string segment=password.substr(start,colon==std::string::npos?colon:colon-start);
            if (segment.empty()) throw std::runtime_error("Shadowsocks2022 PSK chain contains empty segment");
            Buffer key=crypto::base64Decode(segment);
            if (key.size()!=keyLength) throw std::runtime_error("Shadowsocks2022 PSK length invalid");
            keys.push_back(std::move(key));
            if (keys.size()>16) throw std::runtime_error("Shadowsocks2022 PSK chain exceeds safety limit");
            if (colon==std::string::npos) break;
            start=colon+1;
        } while (true);
        if (method==AEAD::ChaCha20Poly1305 && keys.size()!=1)
            throw std::runtime_error("Shadowsocks2022 ChaCha20 does not support identity headers");
    }
    Buffer subkey(const Buffer &salt) const {
        if (modern) {Buffer material=key();append(material,salt);
            return crypto::blake3DeriveKey("shadowsocks 2022 session subkey",material,keyLength);}
        const std::string context="ss-subkey";
        return crypto::hkdfSHA1(key(),salt,Buffer(context.begin(),context.end()),keyLength);
    }
    Buffer tcpIdentity(const Buffer &salt) const {
        Buffer out;
        for (size_t i=0;i+1<keys.size();++i) {
            Buffer material=keys[i]; append(material,salt);
            Buffer derived=crypto::blake3DeriveKey("shadowsocks 2022 identity subkey",material,keyLength);
            append(out,crypto::aesECBBlock(crypto::blake3(keys[i+1],16),derived));
        }
        return out;
    }
    Buffer udpIdentity(const Buffer &header) const {
        Buffer out;
        for (size_t i=0;i+1<keys.size();++i) {
            Buffer hash=crypto::blake3(keys[i+1],16);
            for (size_t j=0;j<16;++j) hash[j]^=header[j];
            append(out,crypto::aesECBBlock(hash,keys[i]));
        }
        return out;
    }
};
ClassicReplayToken classicToken(const Config &config,const Buffer &salt) {
    if (salt.size()!=config.keyLength || salt.size()>32)
        throw std::runtime_error("Shadowsocks replay salt length invalid");
    ClassicReplayToken token; token.domain=config.replayDomain; token.saltSize=uint8_t(salt.size());
    std::copy(salt.begin(),salt.end(),token.salt.begin()); return token;
}
Buffer freshClassicSalt(const Config &config,bool udp) {
    for (unsigned attempt=0;attempt<8;++attempt) {
        Buffer salt=crypto::randomBytes(config.keyLength);
        if (classicReplayCache(udp).commit(classicToken(config,salt))) return salt;
    }
    throw std::runtime_error("Shadowsocks could not allocate a fresh salt");
}
struct Cipher {
    AEAD method; Buffer key,nonce; bool exhausted=false;
    Cipher(const Config &config,const Buffer &salt):method(config.method),key(config.subkey(salt)),nonce(config.nonceLength,0) {}
    void advance() {
        for (auto &byte:nonce) if (++byte!=0) return;
        exhausted=true;
    }
    Buffer crypt(const Buffer &data,bool encrypt) {
        if (exhausted) throw std::runtime_error("Shadowsocks nonce exhausted");
        Buffer out=encrypt?crypto::seal(method,key,nonce,data):crypto::open(method,key,nonce,data);
        advance(); return out;
    }
};

// A C++ strand also makes synchronous test transports safe: callbacks enqueue
// work instead of recursively re-entering a partially updated protocol state.
class Strand : public std::enable_shared_from_this<Strand> {
    std::mutex lock_; std::deque<std::function<void()>> tasks_; bool scheduled_=false;
    std::shared_ptr<TransportFactory> factory_;
public:
    explicit Strand(std::shared_ptr<TransportFactory> factory):factory_(std::move(factory)) {}
    void post(std::function<void()> task) {
        bool schedule=false;
        {std::lock_guard<std::mutex> guard(lock_);tasks_.push_back(std::move(task));
            if (!scheduled_) {scheduled_=true;schedule=true;}}
        if (!schedule) return;
        auto self=shared_from_this();
        auto run=[self] {
            for (;;) {
                std::function<void()> next;
                {std::lock_guard<std::mutex> guard(self->lock_);
                    if (self->tasks_.empty()) {self->scheduled_=false;return;}
                    next=std::move(self->tasks_.front());self->tasks_.pop_front();}
                next();
            }
        };
        if (factory_ && factory_->post) factory_->post(std::move(run)); else run();
    }
};
struct Admission {
    std::atomic<size_t> bytes{0},operations{0};
    bool reserve(size_t count) {
        if (count>maximumQueuedBytes) return false;
        size_t prior=bytes.load();
        do { if (prior>maximumQueuedBytes-count) return false; }
        while (!bytes.compare_exchange_weak(prior,prior+count));
        if (operations.fetch_add(1)>=1024) {operations.fetch_sub(1);bytes.fetch_sub(count);return false;}
        return true;
    }
    void release(size_t count) {bytes.fetch_sub(count);operations.fetch_sub(1);}
};
class SSStream final : public Stream, public std::enable_shared_from_this<SSStream> {
    struct Write {
        Buffer data; WriteCallback callback; bool halfClose=false,finished=false;
        size_t cost=0;
    };
    Config config_; Target target_; std::shared_ptr<Stream> raw_; std::shared_ptr<Reader> reader_;
    std::shared_ptr<Strand> strand_; Admission admission_;
    Buffer requestSalt_,responseSalt_,received_; size_t receiveOffset_=0;
    std::unique_ptr<Cipher> sendCipher_,receiveCipher_;
    std::unique_ptr<crypto::CipherStream> sendCFB_,receiveCFB_;
    std::deque<std::shared_ptr<Write>> writes_;
    std::atomic<bool> readAdmitted_{false}; ReadCallback readCallback_;
    size_t readMaximum_=0; unsigned emptyChunks_=0;
    bool closed_=false,sending_=false,writeEnded_=false,receiveHeader_=false,readEOF_=false,classicResponseCommitted_=false;
    Error terminal_;
    void finishWrite(const std::shared_ptr<Write> &write,Error error) {
        if (write->finished) return;
        write->finished=true;admission_.release(write->cost);
        auto callback=std::exchange(write->callback,{});callback(std::move(error));
    }
    void finishRead(Buffer data,bool eof,Error error) {
        if (!readCallback_) return;
        auto callback=std::move(readCallback_);readCallback_={};readAdmitted_.store(false);
        callback(std::move(data),eof,std::move(error));
    }
    void fail(Error error) {
        if (closed_) return;
        closed_=true;terminal_=error.empty()?"Shadowsocks stream closed":error;reader_->close();
        auto pending=std::move(writes_);sending_=false;
        for (auto &write:pending) finishWrite(write,terminal_);
        finishRead({},true,terminal_);
    }
    Buffer frame(const Buffer &plain) {
        Buffer length;put16(length,plain.size());
        Buffer out=sendCipher_->crypt(length,true);append(out,sendCipher_->crypt(plain,true));return out;
    }
    Buffer encode(const Buffer &data) {
        if (config_.cfb) return sendCFB_->update(data);
        Buffer out; size_t limit=config_.modern?65535:16383;
        for (size_t offset=0;offset<data.size();) {
            size_t take=std::min(limit,data.size()-offset);
            append(out,frame(slice(data,offset,take)));offset+=take;
        }
        return out;
    }
    void pumpWrites() {
        if (closed_ || sending_ || writes_.empty()) return;
        auto write=writes_.front();sending_=true;
        auto self=shared_from_this();
        auto done=[self,write](Error error) {
            self->strand_->post([self,write,error=std::move(error)]() mutable {
                if (write->finished) return;
                if (!error.empty()) {self->fail(std::move(error));return;}
                self->sending_=false;self->writes_.pop_front();self->finishWrite(write,{});self->pumpWrites();
            });
        };
        try {
            if (write->halfClose) raw_->shutdownWrite(std::move(done));
            else if (write->data.empty()) done({});
            else raw_->write(encode(write->data),std::move(done));
        } catch (const std::exception &e) {fail(e.what());}
    }
    void enqueue(Buffer data,WriteCallback completion,bool halfClose) {
        size_t cost=data.size();
        if (!admission_.reserve(cost)) {completion("Shadowsocks write queue full");return;}
        auto self=shared_from_this();
        strand_->post([self,data=std::move(data),completion=std::move(completion),cost,halfClose]() mutable {
            auto write=std::make_shared<Write>();write->data=std::move(data);write->callback=std::move(completion);
            write->cost=cost;write->halfClose=halfClose;
            if (self->closed_ || self->writeEnded_) {
                self->finishWrite(write,self->closed_?self->terminal_:"Shadowsocks write side closed");return;
            }
            if (halfClose) self->writeEnded_=true;
            self->writes_.push_back(write);self->pumpWrites();
        });
    }
    void exact(size_t count,bool allowEOF,std::function<void(Buffer)> consume) {
        auto self=shared_from_this();
        reader_->exactly(count,[self,allowEOF,consume=std::move(consume)](Buffer data,Error error) mutable {
            self->strand_->post([self,allowEOF,consume=std::move(consume),data=std::move(data),error=std::move(error)]() mutable {
                if (self->closed_) return;
                if (!error.empty()) {
                    if (allowEOF && error=="EOF") {self->readEOF_=true;self->finishRead({},true,{});}
                    else self->fail(error=="EOF"?"Shadowsocks response truncated":std::move(error));
                    return;
                }
                try {consume(std::move(data));} catch (const std::exception &e) {self->fail(e.what());}
            });
        });
    }
    void body(size_t count) {
        auto self=shared_from_this();
        exact(count+16,false,[self](Buffer data) {
            Buffer plain=self->receiveCipher_->crypt(data,false);
            if (!self->config_.modern && !self->config_.cfb && !self->classicResponseCommitted_) {
                // No bytes reach a caller until the first complete body is
                // authenticated and this salt wins the cross-connection race.
                if (!classicReplayCache(false).commit(classicToken(self->config_,self->responseSalt_)))
                    throw std::runtime_error("Shadowsocks response salt replayed");
                self->classicResponseCommitted_=true; self->responseSalt_.clear();
            }
            self->received_=std::move(plain);self->receiveOffset_=0;
            if (self->received_.empty()) {
                if (++self->emptyChunks_>32) throw std::runtime_error("Shadowsocks sent excessive empty chunks");
            } else self->emptyChunks_=0;
            self->readNext();
        });
    }
    void readCFB() {
        auto self=shared_from_this();
        reader_->some(readMaximum_,[self](Buffer data,bool eof,Error error) mutable {
            self->strand_->post([self,data=std::move(data),eof,error=std::move(error)]() mutable {
                if (self->closed_) return;
                if (!error.empty()) {self->fail(std::move(error));return;}
                try {
                    Buffer plain=self->receiveCFB_->update(data);self->readEOF_=eof;
                    if (plain.empty() && !eof) {self->readCFB();return;}
                    self->finishRead(std::move(plain),eof,{});
                } catch (const std::exception &e) {self->fail(e.what());}
            });
        });
    }
    void readNext() {
        if (closed_ || !readCallback_) return;
        if (receiveOffset_<received_.size()) {
            size_t take=std::min(readMaximum_,received_.size()-receiveOffset_);
            Buffer out=slice(received_,receiveOffset_,take);receiveOffset_+=take;
            if (receiveOffset_==received_.size()) {received_.clear();receiveOffset_=0;}
            finishRead(std::move(out),false,{});return;
        }
        if (readEOF_) {finishRead({},true,{});return;}
        auto self=shared_from_this();
        if ((!config_.cfb && !receiveCipher_) || (config_.cfb && !receiveCFB_)) {
            exact(config_.cfb?16:config_.keyLength,true,[self](Buffer salt) {
                if (self->config_.cfb)
                    self->receiveCFB_=std::make_unique<crypto::CipherStream>(self->config_.cfbName,self->config_.key(),salt,false);
                else {
                    if (crypto::constantTimeEqual(salt,self->requestSalt_))
                        throw std::runtime_error("Shadowsocks response reused request salt");
                    if (!self->config_.modern) {
                        if (classicReplayCache(false).contains(classicToken(self->config_,salt)))
                            throw std::runtime_error("Shadowsocks response salt replayed");
                        self->responseSalt_=salt;
                    }
                    self->receiveCipher_=std::make_unique<Cipher>(self->config_,salt);
                }
                self->readNext();
            });return;
        }
        if (config_.cfb) {readCFB();return;}
        if (config_.modern && !receiveHeader_) {
            exact(11+config_.keyLength+16,false,[self](Buffer data) {
                Buffer header=self->receiveCipher_->crypt(data,false);
                if (header.size()!=11+self->config_.keyLength || header[0]!=1)
                    throw std::runtime_error("Shadowsocks2022 response header invalid");
                if (!fresh(get64(header,1),unixSeconds()))
                    throw std::runtime_error("Shadowsocks2022 response timestamp outside 30-second window");
                if (!crypto::constantTimeEqual(slice(header,9,self->config_.keyLength),self->requestSalt_))
                    throw std::runtime_error("Shadowsocks2022 response request salt mismatch");
                self->receiveHeader_=true;self->body(get16(header,9+self->config_.keyLength));
            });return;
        }
        exact(18,true,[self](Buffer data) {
            Buffer length=self->receiveCipher_->crypt(data,false);
            if (length.size()!=2) throw std::runtime_error("Shadowsocks length chunk invalid");
            size_t count=get16(length,0);
            if (count>(self->config_.modern?65535:16383)) throw std::runtime_error("Shadowsocks chunk exceeds limit");
            self->body(count);
        });
    }
public:
    SSStream(Config config,Target target,std::shared_ptr<Stream> raw,std::shared_ptr<TransportFactory> factory)
        :config_(std::move(config)),target_(std::move(target)),raw_(std::move(raw)),reader_(std::make_shared<Reader>(raw_)),
         strand_(std::make_shared<Strand>(std::move(factory))) {
        requestSalt_=!config_.modern && !config_.cfb?freshClassicSalt(config_,false):
            crypto::randomBytes(config_.cfb?16:config_.keyLength);
        if (config_.cfb) sendCFB_=std::make_unique<crypto::CipherStream>(config_.cfbName,config_.key(),requestSalt_,true);
        else sendCipher_=std::make_unique<Cipher>(config_,requestSalt_);
    }
    void start(StreamCallback completion) {
        auto self=shared_from_this();
        auto callback=std::make_shared<StreamCallback>(std::move(completion));
        auto finish=[callback](std::shared_ptr<Stream> stream,Error error) {
            if (!*callback) return;
            auto handler=std::move(*callback);*callback={};handler(std::move(stream),std::move(error));
        };
        strand_->post([self,finish]() mutable {
            try {
                Buffer address=socksAddress(self->target_);
                if (address.empty()) throw std::runtime_error("Shadowsocks target invalid");
                Buffer output=self->requestSalt_;
                if (self->config_.cfb) append(output,self->sendCFB_->update(address));
                else if (!self->config_.modern) append(output,self->frame(address));
                else {
                    Buffer random=crypto::randomBytes(2);size_t padding=1+get16(random,0)%900;
                    put16(address,padding);append(address,crypto::randomBytes(padding));
                    Buffer fixed{0};put64(fixed,unixSeconds());put16(fixed,address.size());
                    append(output,self->config_.tcpIdentity(self->requestSalt_));
                    append(output,self->sendCipher_->crypt(fixed,true));append(output,self->sendCipher_->crypt(address,true));
                }
                self->raw_->write(std::move(output),[self,finish](Error error) mutable {
                    self->strand_->post([self,finish,error=std::move(error)]() mutable {
                        if (!error.empty()) {self->fail(error);finish(nullptr,std::move(error));}
                        else if (self->closed_) finish(nullptr,self->terminal_);
                        else finish(self,{});
                    });
                });
            } catch (const std::exception &e) {self->fail(e.what());finish(nullptr,e.what());}
        });
    }
    void write(Buffer data,WriteCallback completion) override {enqueue(std::move(data),std::move(completion),false);}
    void read(size_t maximum,ReadCallback completion) override {
        if (!maximum) {completion({},false,"Shadowsocks read size must be positive");return;}
        bool expected=false;
        if (!readAdmitted_.compare_exchange_strong(expected,true)) {
            completion({},false,"Shadowsocks read already pending");return;
        }
        auto self=shared_from_this();
        strand_->post([self,maximum,completion=std::move(completion)]() mutable {
            self->readCallback_=std::move(completion);self->readMaximum_=std::min(maximum,maximumReadBytes);
            if (self->closed_) self->finishRead({},true,self->terminal_);else self->readNext();
        });
    }
    void close() override {auto self=shared_from_this();strand_->post([self]{self->fail("Shadowsocks stream closed");});}
    bool supportsHalfClose() const override {return raw_->supportsHalfClose();}
    void shutdownWrite(WriteCallback completion) override {
        if (!supportsHalfClose()) {completion("Shadowsocks transport does not support half-close");return;}
        enqueue({},std::move(completion),true);
    }
};

struct ReplayWindow {
    static constexpr size_t bitCount=8192,wordCount=bitCount/64;
    std::array<uint64_t,wordCount> bits{};uint64_t highest=0;bool initialized=false;
    bool accept(uint64_t packet) {
        if (!initialized) {initialized=true;highest=packet;bits[0]=1;return true;}
        if (packet>highest) {
            uint64_t delta=packet-highest;
            if (delta>=bitCount) bits.fill(0);
            else {
                size_t words=size_t(delta/64);unsigned shift=unsigned(delta%64);
                for (size_t i=wordCount;i-->0;) {
                    uint64_t value=i>=words?bits[i-words]<<shift:0;
                    if (shift && i>words) value|=bits[i-words-1]>>(64-shift);
                    bits[i]=value;
                }
            }
            highest=packet;bits[0]|=1;return true;
        }
        uint64_t delta=highest-packet;
        if (delta>=bitCount) return false;
        size_t word=size_t(delta/64);uint64_t mask=uint64_t(1)<<(delta%64);
        if (bits[word]&mask) return false;
        bits[word]|=mask;return true;
    }
};
class SSDatagram final : public Datagram,public std::enable_shared_from_this<SSDatagram> {
    struct Write {Target target;Buffer data;WriteCallback callback;size_t cost=0;bool finished=false;};
    struct ServerSession {ReplayWindow replay;Buffer subkey;uint64_t lastSeen=0;};
    Config config_;Target remote_;std::shared_ptr<Datagram> raw_;std::shared_ptr<Strand> strand_;Admission admission_;
    Buffer clientSession_;uint64_t packetCounter_=0;bool counterExhausted_=false;
    std::unordered_map<std::string,ServerSession> serverSessions_;
    // Keep the existing per-session count window too: expiry/eviction in the
    // shared cache must not weaken protection for an already-open UDP session.
    std::set<Buffer> classicSalts_;std::deque<Buffer> classicSaltOrder_;
    std::deque<std::shared_ptr<Write>> writes_;PacketCallback receive_;WriteCallback failure_;
    bool closed_=false,started_=false,sending_=false;Error terminal_;
    void finish(const std::shared_ptr<Write> &write,Error error) {
        if (write->finished) return;
        write->finished=true;admission_.release(write->cost);
        auto callback=std::exchange(write->callback,{});callback(std::move(error));
    }
    void fail(Error error) {
        if (closed_) return;
        closed_=true;terminal_=error.empty()?"Shadowsocks UDP closed":error;raw_->close();
        auto writes=std::move(writes_);sending_=false;
        for (auto &write:writes) finish(write,terminal_);
        auto callback=std::exchange(failure_,{});receive_={};if (callback) callback(terminal_);
    }
    Buffer encode(const Target &target,const Buffer &data) {
        if (target.host.empty() || !target.port) throw std::runtime_error("Shadowsocks UDP target invalid");
        Buffer address=socksAddress(target);
        if (address.empty()) throw std::runtime_error("Shadowsocks UDP target invalid");
        if (config_.cfb) {
            append(address,data);
            if (address.size()+16>65507) throw std::runtime_error("Shadowsocks UDP payload too large");
            Buffer iv=crypto::randomBytes(16);crypto::CipherStream cipher(config_.cfbName,config_.key(),iv,true);
            Buffer out=iv;append(out,cipher.update(address));return out;
        }
        if (!config_.modern) {
            append(address,data);
            if (address.size()+config_.keyLength+16>65507) throw std::runtime_error("Shadowsocks UDP payload too large");
            Buffer salt=freshClassicSalt(config_,true),out=salt;
            append(out,crypto::seal(config_.method,config_.subkey(salt),Buffer(config_.nonceLength,0),address));
            rememberClassicSalt(salt);
            return out;
        }
        if (counterExhausted_) throw std::runtime_error("Shadowsocks2022 UDP packet counter exhausted");
        bool merged=config_.method==AEAD::ChaCha20Poly1305;
        Buffer header=clientSession_;put64(header,packetCounter_);
        Buffer body;
        if (merged) body=header;
        body.push_back(0);put64(body,unixSeconds());
        size_t padding=target.port==53 && data.size()<900 ? 1+get16(crypto::randomBytes(2),0)%(900-data.size()):0;
        put16(body,padding);append(body,crypto::randomBytes(padding));append(body,address);append(body,data);
        size_t prefix=merged?24:16+16*(config_.keys.size()-1);
        if (body.size()+prefix+16>65507) throw std::runtime_error("Shadowsocks2022 UDP payload too large");
        Buffer out;
        if (merged) {
            Buffer nonce=crypto::randomBytes(24);out=nonce;
            append(out,crypto::seal(AEAD::XChaCha20Poly1305,config_.key(),nonce,body));
        } else {
            out=crypto::aesECBBlock(header,config_.keys.front());append(out,config_.udpIdentity(header));
            append(out,crypto::seal(config_.method,config_.subkey(clientSession_),slice(header,4,12),body));
        }
        if (packetCounter_==std::numeric_limits<uint64_t>::max()) counterExhausted_=true;else ++packetCounter_;
        return out;
    }
    void rememberClassicSalt(const Buffer &salt) {
        classicSalts_.insert(salt);classicSaltOrder_.push_back(salt);
        if (classicSaltOrder_.size()>8192) {classicSalts_.erase(classicSaltOrder_.front());classicSaltOrder_.pop_front();}
    }
    void decode(const Buffer &packet) {
        if (packet.size()>65535) return;
        Buffer body,salt,session;uint64_t identifier=0;size_t cursor=0;
        if (config_.cfb) {
            if (packet.size()<=16) return;
            crypto::CipherStream cipher(config_.cfbName,config_.key(),slice(packet,0,16),false);
            body=cipher.update(slice(packet,16,packet.size()-16));
        } else if (!config_.modern) {
            if (packet.size()<config_.keyLength+16) return;
            salt=slice(packet,0,config_.keyLength);
            if (classicSalts_.count(salt) || classicReplayCache(true).contains(classicToken(config_,salt))) return;
            body=crypto::open(config_.method,config_.subkey(salt),Buffer(config_.nonceLength,0),
                              slice(packet,config_.keyLength,packet.size()-config_.keyLength));
        } else if (config_.method==AEAD::ChaCha20Poly1305) {
            if (packet.size()<24+16+35) return;
            body=crypto::open(AEAD::XChaCha20Poly1305,config_.key(),slice(packet,0,24),slice(packet,24,packet.size()-24));
            session=slice(body,0,8);identifier=get64(body,8);cursor=16;
        } else {
            if (packet.size()<16+16+19) return;
            Buffer header=crypto::aesECBBlock(slice(packet,0,16),config_.key(),false);
            session=slice(header,0,8);identifier=get64(header,8);
            std::string name(session.begin(),session.end());auto found=serverSessions_.find(name);
            Buffer key=found==serverSessions_.end()?config_.subkey(session):found->second.subkey;
            body=crypto::open(config_.method,key,slice(header,4,12),slice(packet,16,packet.size()-16));
        }
        uint64_t now=unixSeconds();
        if (config_.modern) {
            if (crypto::constantTimeEqual(session,clientSession_)) return;
            if (cursor>body.size() || body.size()-cursor<19 || body[cursor]!=1) return;
            if (!fresh(get64(body,cursor+1),now)) return;
            if (!crypto::constantTimeEqual(slice(body,cursor+9,8),clientSession_)) return;
            size_t padding=get16(body,cursor+17);cursor+=19;
            if (padding>body.size()-cursor) return;
            cursor+=padding;
        }
        Buffer remaining=slice(body,cursor,body.size()-cursor);size_t consumed=0;
        Target target=parseSocksAddress(remaining,consumed);
        if (!consumed || consumed>remaining.size() || target.host.empty() || !target.port) return;
        target.udp=true;
        if (config_.modern) {
            // Cache eviction never re-admits a still-fresh server session.
            // Expiration exceeds the 30-second timestamp acceptance window.
            for (auto it=serverSessions_.begin();it!=serverSessions_.end();) {
                if (now>it->second.lastSeen && now-it->second.lastSeen>60) it=serverSessions_.erase(it);else ++it;
            }
            std::string name(session.begin(),session.end());auto found=serverSessions_.find(name);
            if (found==serverSessions_.end()) {
                if (serverSessions_.size()>=64) return;
                ServerSession state;state.subkey=config_.subkey(session);state.lastSeen=now;
                found=serverSessions_.emplace(name,std::move(state)).first;
            }
            if (!found->second.replay.accept(identifier)) return;
            found->second.lastSeen=now;
        } else if (!config_.cfb) {
            if (!classicReplayCache(true).commit(classicToken(config_,salt))) return;
            rememberClassicSalt(salt);
        }
        if (receive_) receive_(std::move(target),slice(remaining,consumed,remaining.size()-consumed));
    }
    void pumpWrites() {
        if (closed_ || sending_ || writes_.empty()) return;
        auto write=writes_.front();Buffer packet;
        try {packet=encode(write->target,write->data);}
        catch (const std::exception &e) {writes_.pop_front();finish(write,e.what());pumpWrites();return;}
        sending_=true;auto self=shared_from_this();
        raw_->send(remote_,std::move(packet),[self,write](Error error) mutable {
            self->strand_->post([self,write,error=std::move(error)]() mutable {
                if (write->finished) return;
                if (!error.empty()) {self->fail(std::move(error));return;}
                self->sending_=false;self->writes_.pop_front();self->finish(write,{});self->pumpWrites();
            });
        });
    }
public:
    SSDatagram(Config config,Target remote,std::shared_ptr<Datagram> raw,std::shared_ptr<TransportFactory> factory)
        :config_(std::move(config)),remote_(std::move(remote)),raw_(std::move(raw)),
         strand_(std::make_shared<Strand>(std::move(factory))),clientSession_(crypto::randomBytes(8)) {}
    void send(Target target,Buffer data,WriteCallback completion) override {
        size_t cost=data.size();
        if (cost>65507) {completion("Shadowsocks UDP payload too large");return;}
        if (!admission_.reserve(cost)) {completion("Shadowsocks UDP queue full");return;}
        auto self=shared_from_this();
        strand_->post([self,target=std::move(target),data=std::move(data),completion=std::move(completion),cost]() mutable {
            auto write=std::make_shared<Write>();write->target=std::move(target);write->data=std::move(data);
            write->callback=std::move(completion);write->cost=cost;
            if (self->closed_) {self->finish(write,self->terminal_);return;}
            self->writes_.push_back(write);self->pumpWrites();
        });
    }
    void start(PacketCallback receive,WriteCallback failure) override {
        auto self=shared_from_this();
        strand_->post([self,receive=std::move(receive),failure=std::move(failure)]() mutable {
            if (self->closed_) {failure(self->terminal_);return;}
            if (self->started_) {failure("Shadowsocks UDP receiver already started");return;}
            self->started_=true;self->receive_=std::move(receive);self->failure_=std::move(failure);
            self->raw_->start([self](Target,Buffer packet) mutable {
                self->strand_->post([self,packet=std::move(packet)] {
                    if (self->closed_) return;
                    try {self->decode(packet);} catch (const std::exception &) {
                        // Authentication/framing failures are packet drops, not
                        // fatal: an unauthenticated datagram cannot kill a flow.
                    }
                });
            },[self](Error error) mutable {
                self->strand_->post([self,error=std::move(error)]() mutable {self->fail(std::move(error));});
            });
        });
    }
    void close() override {
        auto self=shared_from_this();strand_->post([self]{self->fail("Shadowsocks UDP closed");});
    }
};
} // namespace

Error validateShadowsocks(const Node &node,bool) {
    try {
        if (node.host.empty() || !node.port) return "Shadowsocks server address invalid";
        Config config(node);return {};
    } catch (const std::exception &e) {return e.what();}
}
void connectShadowsocks(const Node &node,const Target &target,std::shared_ptr<TransportFactory> factory,StreamCallback completion) {
    auto callback=std::make_shared<StreamCallback>(std::move(completion));
    auto finish=[callback](std::shared_ptr<Stream> stream,Error error) {
        if (!*callback) return;
        auto handler=std::move(*callback);*callback={};handler(std::move(stream),std::move(error));
    };
    try {
        if (!factory || !factory->tcp) throw std::runtime_error("Shadowsocks TCP transport unavailable");
        if (target.udp) throw std::runtime_error("Shadowsocks UDP requires datagram transport");
        if (target.host.empty() || !target.port) throw std::runtime_error("Shadowsocks TCP target invalid");
        if (node.host.empty() || !node.port) throw std::runtime_error("Shadowsocks server address invalid");
        Config config(node);
        factory->tcp(node,tlsOptions(node,false),[config=std::move(config),target,factory,finish](std::shared_ptr<Stream> raw,Error error) mutable {
            if (!error.empty() || !raw) {finish(nullptr,error.empty()?"Shadowsocks TCP transport unavailable":std::move(error));return;}
            try {auto stream=std::make_shared<SSStream>(std::move(config),target,raw,factory);stream->start(finish);}
            catch (const std::exception &e) {raw->close();finish(nullptr,e.what());}
        });
    } catch (const std::exception &e) {finish(nullptr,e.what());}
}
void makeShadowsocksDatagram(const Node &node,std::shared_ptr<TransportFactory> factory,DatagramCallback completion) {
    auto callback=std::make_shared<DatagramCallback>(std::move(completion));
    auto finish=[callback](std::shared_ptr<Datagram> datagram,Error error) {
        if (!*callback) return;
        auto handler=std::move(*callback);*callback={};handler(std::move(datagram),std::move(error));
    };
    try {
        if (!factory || !factory->udp) throw std::runtime_error("Shadowsocks UDP transport unavailable");
        if (node.host.empty() || !node.port) throw std::runtime_error("Shadowsocks server address invalid");
        Config config(node);Target remote{node.host,node.port,true,false};
        factory->udp(node,[config=std::move(config),remote,factory,finish](std::shared_ptr<Datagram> raw,Error error) mutable {
            if (!error.empty() || !raw) {finish(nullptr,error.empty()?"Shadowsocks UDP transport unavailable":std::move(error));return;}
            try {finish(std::make_shared<SSDatagram>(std::move(config),remote,raw,factory),{});}
            catch (const std::exception &e) {raw->close();finish(nullptr,e.what());}
        });
    } catch (const std::exception &e) {finish(nullptr,e.what());}
}
} // namespace hajimi
