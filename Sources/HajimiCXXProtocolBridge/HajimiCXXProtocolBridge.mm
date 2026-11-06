#import "HajimiCXXProtocolBridge.h"
#import <Network/Network.h>
#include "Runtime.hpp"
#include "ProtocolStream.hpp"
#include "AnyTLS.hpp"
#include "MieruProtocol.hpp"
#include "WireGuardProtocol.hpp"
#include "ServerProtocols.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

NSErrorDomain const HJCppProtocolErrorDomain=@"app.hajimi.cpp-protocol";
namespace {
using namespace hajimi;
class PlatformErrorMetadata final : public ErrorMetadata {
    NSError *__strong error_;
public:
    explicit PlatformErrorMetadata(NSError *error) : error_(error) {}
    NSError *native() const { return error_; }
};
NSError *cancelledError() {
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:ECANCELED userInfo:@{NSLocalizedDescriptionKey:@"Stream cancelled"}];
}
NSError *nativeError(const Error &error, bool cancelled = false) {
    if(error.empty())return nil;
    if(cancelled)return cancelledError();
    if(auto platform=std::dynamic_pointer_cast<const PlatformErrorMetadata>(error.metadata()))return platform->native();
    if(error=="Protocol client cancelled" || error=="Native UDP connection cancelled")return cancelledError();
    NSString *message=[[NSString alloc]initWithBytes:error.data() length:error.size() encoding:NSUTF8StringEncoding];
    if(error.find("timed out") != std::string::npos ||
       error.find("timeout") != std::string::npos ||
       error=="Mieru UDP retransmission limit exceeded"){
        return [NSError errorWithDomain:NSPOSIXErrorDomain code:ETIMEDOUT userInfo:@{NSLocalizedDescriptionKey:message?:@"Connection timed out"}];
    }
    if(error=="Mieru SOCKS5 target connect rejected"){
        return [NSError errorWithDomain:NSPOSIXErrorDomain code:ECONNREFUSED userInfo:@{NSLocalizedDescriptionKey:message?:@"Connection refused"}];
    }
    if(error=="EOF" ||
       error=="Stream closed" ||
       error=="Datagram session closed" ||
       error=="Mieru UDP session closed" ||
       error=="Mieru UDP openSessionResponse rejected" ||
       error=="Mieru SOCKS5 reply invalid" ||
       error=="Mieru UDP socket error" ||
       error=="Mieru UDP target connection closed by server" ||
       error=="Mieru UDP dial failed" ||
       error=="UDP transport send failed" ||
       error=="UDP transport receive failed" ||
       error=="Native UDP connection failed" ||
       error=="UDP transport closed" ||
       error=="Chained UDP transport closed" ||
       error=="WireGuard remote peer reset TCP connection" ||
       error=="WireGuard UDP carrier failed" ||
       error=="AnyTLS session closed" ||
       error=="AnyTLS UoT carrier closed" ||
       error=="Sudoku UoT carrier closed" ||
       error=="UDP carrier closed" ||
       error=="QUIC peer closed connection" ||
       error=="QUIC UDP receive failed" ||
       error=="QUIC UDP send failed" ||
       error=="Snell peer closed during handshake"){
        return [NSError errorWithDomain:NSPOSIXErrorDomain code:ECONNRESET userInfo:@{NSLocalizedDescriptionKey:message?:@"Connection reset by peer"}];
    }
    return [NSError errorWithDomain:HJCppProtocolErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey:message?:@"Native protocol failure"}];
}
Error cppError(NSError *error) {
    if(!error)return {};
    const char *description=error.localizedDescription.UTF8String;
    return Error(description&&*description?description:"Platform transport failed",std::make_shared<PlatformErrorMetadata>(error));
}
std::string cppString(NSString *value){
    if(!value)return {};NSData *encoded=[value dataUsingEncoding:NSUTF8StringEncoding];
    if(!encoded)throw std::runtime_error("Invalid Unicode text");if(!encoded.length)return {};
    return std::string(static_cast<const char *>(encoded.bytes),encoded.length);
}
Buffer buffer(NSData *data) {
    if(!data.length)return {};
    auto begin=static_cast<const uint8_t *>(data.bytes);return Buffer(begin,begin+data.length);
}
// Copy dispatch regions directly into the vector's single allocation. Mapping
// fragmented dispatch_data first can allocate/coalesce a second full buffer;
// the C++ stream still owns its bytes after the platform callback returns.
Buffer dispatchBuffer(dispatch_data_t content) {
    const size_t length=content?dispatch_data_get_size(content):0;
    if(!length)return {};
    Buffer result;result.reserve(length);auto output=&result;
    const bool copied=dispatch_data_apply(content,^bool(dispatch_data_t,size_t offset,const void *bytes,size_t size){
        if(offset!=output->size() || offset>length || size>length-offset || (size&&!bytes))return false;
        if(size){auto first=static_cast<const uint8_t *>(bytes);output->insert(output->end(),first,first+size);}
        return true;
    });
    if(!copied || result.size()!=length)throw std::runtime_error("Invalid fragmented platform buffer");
    return result;
}
NSData *data(Buffer value) {
    if(value.empty())return [NSData data];
    auto owned=new Buffer(std::move(value));
    return [[NSData alloc]initWithBytesNoCopy:owned->data() length:owned->size() deallocator:^(void *,NSUInteger){delete owned;}];
}
NSData *mapped(dispatch_data_t content) {
    if(!content)return [NSData data];
    const void *bytes=nullptr;size_t count=0;auto mapping=dispatch_data_create_map(content,&bytes,&count);
    if(!mapping)return nil;
    return [[NSData alloc]initWithBytesNoCopy:const_cast<void *>(bytes) length:count deallocator:^(void *,NSUInteger){(void)mapping;}];
}
bool loopback(const std::string &host) {
    if(host=="localhost" || host=="::1" || host=="[::1]")return true;
    in_addr address{};return inet_pton(AF_INET,host.c_str(),&address)==1 && (ntohl(address.s_addr)>>24)==127;
}
bool isLoopbackSockaddr(const sockaddr *address, socklen_t size) {
    if (!address || size < sizeof(sockaddr)) return false;
    if (address->sa_family == AF_INET && size >= sizeof(sockaddr_in)) {
        auto value = reinterpret_cast<const sockaddr_in *>(address);
        return (ntohl(value->sin_addr.s_addr) >> 24) == 127;
    }
    if (address->sa_family == AF_INET6 && size >= sizeof(sockaddr_in6)) {
        const auto &value = reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(&value)) return true;
        return IN6_IS_ADDR_V4MAPPED(&value) && value.s6_addr[12] == 127;
    }
    return false;
}
bool addressLiteral(const std::string &host) {
    std::string clean = host;
    if (clean.size() >= 2 && clean.front() == '[' && clean.back() == ']')
        clean = clean.substr(1, clean.size() - 2);
    if (clean.find(':') != std::string::npos) {
        auto scope = clean.find('%');
        if (scope != std::string::npos) clean.resize(scope);
    }
    in_addr ipv4{}; in6_addr ipv6{};
    return inet_pton(AF_INET,clean.c_str(),&ipv4)==1 || inet_pton(AF_INET6,clean.c_str(),&ipv6)==1;
}
Node decode(NSData *configuration) {
    if(configuration.length>1024*1024)throw std::runtime_error("Protocol configuration is too large");
    NSError *error=nil;id parsed=[NSJSONSerialization JSONObjectWithData:configuration options:0 error:&error];
    if(![parsed isKindOfClass:NSDictionary.class])throw std::runtime_error("Invalid protocol configuration JSON");
    NSDictionary *object=parsed;Node node;
    for(NSString *key in @[@"type",@"host",@"name",@"connectHost"]){id value=object[key];if(value && ![value isKindOfClass:NSString.class])throw std::runtime_error("Invalid protocol configuration field");}
    node.type=cppString([object[@"type"] lowercaseString]);node.host=cppString(object[@"host"]);node.name=cppString(object[@"name"]);
    node.connectHost=cppString(object[@"connectHost"]);
    if(!node.connectHost.empty() && !addressLiteral(node.connectHost))throw std::runtime_error("Proxy connectHost must be a numeric address");
    id port=object[@"port"];if(![port isKindOfClass:NSNumber.class] || [port doubleValue]!=[port unsignedIntValue] || [port unsignedIntValue]>65535)throw std::runtime_error("Invalid proxy port");
    node.port=uint16_t([port unsignedIntValue]);
    id parameters=object[@"parameters"];
    if(parameters && ![parameters isKindOfClass:NSDictionary.class])throw std::runtime_error("Invalid protocol parameters");
    for(id key in parameters){id value=parameters[key];if(![key isKindOfClass:NSString.class] || ![value isKindOfClass:NSString.class])throw std::runtime_error("Protocol parameters must be strings");
        auto name=cppString(key);if(name.find('\0')!=std::string::npos)throw std::runtime_error("Invalid protocol option name");node.parameters[name]=cppString(value);
    }
    return node;
}
void post(dispatch_queue_t queue,std::function<void()> work){
    // A block's copied std::function also copies any captured payload vectors.
    // Transfer one task owner instead, retaining asynchronous FIFO delivery.
    auto task=new std::function<void()>(std::move(work));
    dispatch_async_f(queue,task,[](void *context){
        @autoreleasepool{
            std::unique_ptr<std::function<void()>> pending(static_cast<std::function<void()> *>(context));
            (*pending)();
        }
    });
}
class PlatformStream final:public Stream,public std::enable_shared_from_this<PlatformStream>{
    id<HJByteStream> native_;dispatch_queue_t queue_;bool closed_=false,ownsCancellation_;
public:
    PlatformStream(id<HJByteStream> native,dispatch_queue_t queue,bool ownsCancellation=true):native_(native),queue_(queue),ownsCancellation_(ownsCancellation){}
    ~PlatformStream(){if(ownsCancellation_)[native_ cancel];}
    void write(Buffer value,WriteCallback completion)override{
        if(closed_){completion("Stream closed");return;}
        NSData *payload=data(std::move(value));auto self=shared_from_this();
        const auto dispatchBytes=dispatch_data_create(payload.bytes,payload.length,nullptr,^{(void)payload;});
        [native_ sendContent:dispatchBytes isComplete:NO completion:^(NSError *error){auto failure=cppError(error);post(self->queue_,[self,completion,failure]{completion(failure);});}];
    }
    void read(size_t maximum,ReadCallback completion)override{
        if(closed_){completion({},true,"Stream closed");return;}
        auto self=shared_from_this();
        [native_ receiveWithMaximum:maximum completion:^(dispatch_data_t content,BOOL eof,NSError *error){
            Buffer value;auto failure=cppError(error);bool ended=eof;
            try{value=dispatchBuffer(content);}catch(const std::exception &exception){
                if(failure.empty())failure=exception.what();ended=true;
            }
            post(self->queue_,[self,completion,value=std::move(value),ended,failure]()mutable{completion(std::move(value),ended,failure);});
        }];
    }
    void close()override{if(closed_)return;closed_=true;[native_ cancel];}
    bool supportsHalfClose()const override{return native_.supportsHalfClose;}
    void shutdownWrite(WriteCallback completion)override{
        if(closed_){completion("Stream closed");return;}auto self=shared_from_this();
        [native_ sendContent:nil isComplete:YES completion:^(NSError *error){auto failure=cppError(error);post(self->queue_,[self,completion,failure]{completion(failure);});}];
    }
    bool supportsVisionDirect()const override{return [native_ conformsToProtocol:@protocol(HJCppVisionCarrier)];}
    void enableVisionDirectWrite()override{if(supportsVisionDirect())[(id<HJCppVisionCarrier>)native_ enableVisionDirectWrite];}
    void enableVisionDirectRead()override{if(supportsVisionDirect())[(id<HJCppVisionCarrier>)native_ enableVisionDirectRead];}
};

struct BridgeInterfaceCache {
    std::mutex lock;
    std::unordered_map<std::string, std::pair<unsigned int, nw_interface_t>> entries;
};
BridgeInterfaceCache &sharedBridgeInterfaceCache() {
    static BridgeInterfaceCache *cache = new BridgeInterfaceCache();
    return *cache;
}
void flushCachedBridgeInterfaces() {
    auto &cache = sharedBridgeInterfaceCache();
    std::lock_guard<std::mutex> guard(cache.lock);
    for (auto it = cache.entries.begin(); it != cache.entries.end(); ) {
        unsigned int currentIdx = if_nametoindex(it->first.c_str());
        if (!currentIdx || currentIdx != it->second.first) {
            it = cache.entries.erase(it);
        } else {
            ++it;
        }
    }
}

void closeOwnedSocket(const std::shared_ptr<std::atomic<int>> &owner) noexcept {
    if (!owner) return;
    int fd = owner->exchange(-1);
    if (fd >= 0) ::close(fd);
}

// High-performance non-blocking POSIX UDP datagram transport with 4 MB kernel
// socket buffers, synchronous zero-copy ::send (guaranteeing closeSessionRequest
// delivery before socket teardown), and batched DISPATCH_SOURCE_TYPE_READ receive.
class PreparedStreamDatagram final:public Datagram,public std::enable_shared_from_this<PreparedStreamDatagram>{
    struct PendingWrite {
        Buffer framed;
        WriteCallback completion;
    };
    id<HJByteStream> native_;
    dispatch_queue_t queue_;
    Target peer_;
    Buffer rxBuffer_;
    size_t rxOffset_ = 0;
    std::deque<PendingWrite> writeQueue_;
    size_t queuedWriteBytes_ = 0;
    bool closed_ = false, started_ = false, sending_ = false;
    PacketCallback receive_;
    WriteCallback failure_;
    void flushWrites() {
        if (closed_ || !native_ || sending_ || writeQueue_.empty()) return;
        sending_ = true;
        auto self = shared_from_this();
        NSData *payload = data(std::move(writeQueue_.front().framed));
        const size_t sentBytes = payload.length;
        const auto dispatchBytes = dispatch_data_create(payload.bytes, payload.length, nullptr, ^{ (void)payload; });
        [native_ sendContent:dispatchBytes isComplete:NO completion:^(NSError *error) {
            auto failure = cppError(error);
            post(self->queue_, [self, sentBytes, failure] {
                if (self->closed_) return;
                self->sending_ = false;
                if (self->writeQueue_.empty()) return;
                auto current = std::move(self->writeQueue_.front());
                self->writeQueue_.pop_front();
                self->queuedWriteBytes_ = self->queuedWriteBytes_ >= sentBytes ? self->queuedWriteBytes_ - sentBytes : 0;
                if (!failure.empty()) {
                    auto remaining = std::move(self->writeQueue_);
                    self->writeQueue_.clear();
                    self->queuedWriteBytes_ = 0;
                    if (current.completion) current.completion(failure);
                    for (auto &item : remaining) {
                        if (item.completion) item.completion(failure);
                    }
                    return;
                }
                if (current.completion) current.completion({});
                self->flushWrites();
            });
        }];
    }
    void pumpRead() {
        if (closed_ || !started_ || !native_) return;
        auto self = shared_from_this();
        [native_ receiveWithMaximum:65536 completion:^(dispatch_data_t content, BOOL eof, NSError *error) {
            Buffer value;
            auto failure = cppError(error);
            bool ended = eof;
            try { value = dispatchBuffer(content); }
            catch (const std::exception &ex) {
                if (failure.empty()) failure = ex.what();
                ended = true;
            }
            post(self->queue_, [self, value = std::move(value), ended, failure]() mutable {
                if (self->closed_) return;
                if (!value.empty()) {
                    if (self->rxOffset_ == self->rxBuffer_.size()) {
                        self->rxBuffer_.clear();
                        self->rxOffset_ = 0;
                    } else if (self->rxOffset_ >= 65536 && self->rxOffset_ * 2 >= self->rxBuffer_.size()) {
                        self->rxBuffer_.erase(self->rxBuffer_.begin(), self->rxBuffer_.begin() + self->rxOffset_);
                        self->rxOffset_ = 0;
                    }
                    self->rxBuffer_.insert(self->rxBuffer_.end(), value.begin(), value.end());
                    while (self->rxBuffer_.size() - self->rxOffset_ >= 2) {
                        const uint8_t *p = self->rxBuffer_.data() + self->rxOffset_;
                        uint16_t frameLen = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
                        if (self->rxBuffer_.size() - self->rxOffset_ < 2 + size_t(frameLen)) break;
                        Buffer packet(p + 2, p + 2 + frameLen);
                        self->rxOffset_ += 2 + size_t(frameLen);
                        if (self->receive_ && !self->closed_) {
                            self->receive_(self->peer_, std::move(packet));
                        }
                    }
                    if (self->rxOffset_ == self->rxBuffer_.size()) {
                        self->rxBuffer_.clear();
                        self->rxOffset_ = 0;
                    }
                }
                if (!failure.empty() || ended) {
                    auto cb = std::move(self->failure_);
                    self->close();
                    if (cb) cb(failure.empty() ? Error("Chained UDP transport closed") : failure);
                    return;
                }
                self->pumpRead();
            });
        }];
    }
public:
    PreparedStreamDatagram(id<HJByteStream> native, dispatch_queue_t queue, Target peer)
        : native_(native), queue_(queue), peer_(std::move(peer)) {}
    ~PreparedStreamDatagram() override { close(); }
    void send(Target, Buffer value, WriteCallback completion) override {
        if (value.size() > 65535) {
            if (completion) completion("UDP packet exceeds wire limit");
            return;
        }
        auto self = shared_from_this();
        post(queue_, [self, value = std::move(value), completion = std::move(completion)]() mutable {
            if (self->closed_ || !self->native_) {
                if (completion) completion("UDP transport closed");
                return;
            }
            const size_t framedSize = 2 + value.size();
            if (self->writeQueue_.size() >= 256 || framedSize > maximumQueuedBytes - self->queuedWriteBytes_) {
                if (completion) completion("Chained UDP write queue limit exceeded");
                return;
            }
            Buffer framed;
            framed.reserve(framedSize);
            framed.push_back(uint8_t((value.size() >> 8) & 0xff));
            framed.push_back(uint8_t(value.size() & 0xff));
            framed.insert(framed.end(), value.begin(), value.end());
            self->queuedWriteBytes_ += framedSize;
            self->writeQueue_.push_back({std::move(framed), std::move(completion)});
            self->flushWrites();
        });
    }
    void start(PacketCallback receive, WriteCallback failure) override {
        if (closed_ || !native_) {
            if (failure) failure("UDP transport closed");
            return;
        }
        if (started_) {
            if (failure) failure("UDP receiver already started");
            return;
        }
        started_ = true;
        receive_ = std::move(receive);
        failure_ = std::move(failure);
        pumpRead();
    }
    void close() override {
        if (closed_) return;
        closed_ = true;
        receive_ = nullptr;
        failure_ = nullptr;
        rxBuffer_.clear();
        rxOffset_ = 0;
        auto pending = std::move(writeQueue_);
        writeQueue_.clear();
        queuedWriteBytes_ = 0;
        sending_ = false;
        [native_ cancel];
        for (auto &item : pending) {
            if (item.completion) item.completion("UDP transport closed");
        }
    }
};

class PlatformDatagram final:public Datagram,public std::enable_shared_from_this<PlatformDatagram>{
    std::shared_ptr<std::atomic<int>> fdOwner_;
    dispatch_queue_t queue_;
    dispatch_source_t readSource_ = nil;
    Target peer_;
    bool closed_ = false, started_ = false;
    PacketCallback receive_;
    WriteCallback failure_;
public:
    PlatformDatagram(int fd, dispatch_queue_t queue, Target peer)
        : fdOwner_(std::make_shared<std::atomic<int>>(fd)), queue_(queue), peer_(std::move(peer)) {}
    ~PlatformDatagram() override {
        if (readSource_) {
            dispatch_source_cancel(readSource_);
            readSource_ = nil;
        } else {
            closeOwnedSocket(fdOwner_);
        }
    }
    void send(Target, Buffer value, WriteCallback completion) override {
        int fd = fdOwner_ ? fdOwner_->load() : -1;
        if (closed_ || fd < 0) {
            if (completion) completion("UDP transport closed");
            return;
        }
        if (value.size() > 65507) {
            if (completion) completion("UDP packet exceeds wire limit");
            return;
        }
        static const uint8_t emptyByte = 0;
        const void *bufPtr = value.empty() ? static_cast<const void *>(&emptyByte) : static_cast<const void *>(value.data());
        ssize_t sent = ::send(fd, bufPtr, value.size(), 0);
        if (sent < 0 && errno == EINTR) {
            sent = ::send(fd, bufPtr, value.size(), 0);
        }
        // Never block context->queue with ::usleep on transient EAGAIN/ENOBUFS;
        // upper-layer MieruUDPStream / QUIC / WireGuard timers handle retransmission asynchronously.
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == ECONNREFUSED)) {
            if (completion) completion({});
            return;
        }
        if (sent < 0) {
            if (completion) completion("UDP transport send failed");
            return;
        }
        if (completion) completion({});
    }
    void start(PacketCallback receive, WriteCallback failure) override {
        int fd = fdOwner_ ? fdOwner_->load() : -1;
        if (closed_ || fd < 0) {
            if (failure) failure("UDP transport closed");
            return;
        }
        if (started_) {
            if (failure) failure("UDP receiver already started");
            return;
        }
        started_ = true;
        receive_ = std::move(receive);
        failure_ = std::move(failure);
        readSource_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, static_cast<uintptr_t>(fd), 0, queue_);
        if (!readSource_) {
            auto cb = std::move(failure_);
            close();
            if (cb) cb("Unable to create UDP dispatch read source");
            return;
        }
        auto owner = fdOwner_;
        dispatch_source_set_cancel_handler(readSource_, ^{
            closeOwnedSocket(owner);
        });
        std::weak_ptr<PlatformDatagram> weak = shared_from_this();
        dispatch_source_set_event_handler(readSource_, ^{
            @autoreleasepool {
                auto self = weak.lock();
                if (!self || self->closed_) return;
                uint8_t scratch[65536];
                for (int i = 0; i < 128; ++i) {
                    if (self->closed_) return;
                    int currentFd = self->fdOwner_ ? self->fdOwner_->load() : -1;
                    if (currentFd < 0) return;
                    ssize_t n = ::recv(currentFd, scratch, sizeof(scratch), 0);
                    if (n < 0) {
                        if (errno == EINTR || errno == ECONNREFUSED) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        auto cb = std::move(self->failure_);
                        self->close();
                        if (cb) cb("UDP transport receive failed");
                        return;
                    }
                    if (self->receive_) {
                        Buffer payload(scratch, scratch + static_cast<size_t>(n));
                        self->receive_(self->peer_, std::move(payload));
                    }
                }
            }
        });
        dispatch_resume(readSource_);
    }
    void abortWithReason(const Error &reason) {
        if (closed_) return;
        auto cb = std::move(failure_);
        close();
        if (cb) cb(reason);
    }
    void close() override {
        if (closed_) return;
        closed_ = true;
        receive_ = nullptr;
        failure_ = nullptr;
        if (readSource_) {
            dispatch_source_cancel(readSource_);
            readSource_ = nil;
        } else {
            closeOwnedSocket(fdOwner_);
        }
    }
};

std::shared_ptr<PlatformDatagram> dialPOSIXDatagram(const Node &node, dispatch_queue_t queue, Error &outError) {
    if (node.host.empty() || !node.port) {
        outError = "Invalid UDP endpoint";
        return nullptr;
    }
    const std::string dialHost = node.dialHost();
    if (!addressLiteral(dialHost)) {
        outError = "Proxy server needs encrypted DNS bootstrapping before UDP dial";
        return nullptr;
    }
    addrinfo hints{}, *addresses = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    const std::string portStr = std::to_string(node.port);
    int resolved = ::getaddrinfo(dialHost.c_str(), portStr.c_str(), &hints, &addresses);
    if (resolved != 0 || !addresses) {
        if (addresses) ::freeaddrinfo(addresses);
        outError = "Invalid numeric UDP endpoint";
        return nullptr;
    }
    unsigned int ifIdx = 0;
    if (!node.interfaceName.empty() && !loopback(dialHost)) {
        ifIdx = if_nametoindex(node.interfaceName.c_str());
        if (!ifIdx) {
            ::freeaddrinfo(addresses);
            outError = "Required outbound interface does not exist";
            return nullptr;
        }
    }
    int connectedFd = -1;
    for (auto *addr = addresses; addr != nullptr; addr = addr->ai_next) {
        int fd = ::socket(addr->ai_family, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        int flags = ::fcntl(fd, F_GETFL, 0);
        (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
#if defined(__APPLE__)
        int one = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
        if (ifIdx && !isLoopbackSockaddr(addr->ai_addr, addr->ai_addrlen)) {
#if defined(__APPLE__)
            int level = addr->ai_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
            int option = addr->ai_family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
            if (::setsockopt(fd, level, option, &ifIdx, sizeof(ifIdx)) != 0) {
                ::close(fd);
                continue;
            }
#endif
        }
        // Right-size per-socket UDP buffers (1 MB RCV / 512 KB SND) so 30-60 concurrent
        // per-stream Mieru-UDP sockets cannot exhaust macOS XNU kernel mbuf clusters (ENOBUFS).
        for (int bufSize : {1024 * 1024, 512 * 1024, 256 * 1024}) {
            if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize)) == 0) break;
        }
        for (int bufSize : {512 * 1024, 256 * 1024}) {
            if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize)) == 0) break;
        }
        if (::connect(fd, addr->ai_addr, addr->ai_addrlen) != 0) {
            ::close(fd);
            continue;
        }
        connectedFd = fd;
        break;
    }
    ::freeaddrinfo(addresses);
    if (connectedFd < 0) {
        outError = "Native UDP connection failed";
        return nullptr;
    }
    Target peer{node.host, node.port, true, false};
    return std::make_shared<PlatformDatagram>(connectedFd, queue, std::move(peer));
}

struct Context:std::enable_shared_from_this<Context>{
    Node node;dispatch_queue_t queue,output;HJCppTransportDialer dialer;HJCppPhysicalTransportDialer physicalDialer;
    HJCppScopedPhysicalTransportDialer scopedPhysicalDialer=nil;
    HJCppScopedPreparedTransportDialer scopedPreparedDialer=nil;
    std::shared_ptr<TransportFactory> factory;bool closed=false;uint64_t nextOperation=0;
    std::atomic<bool> cancellationSignal{false};uint64_t nextAttempt=0;
    std::unordered_map<uint64_t,std::function<void()>> pending;
    std::unordered_map<uint64_t,std::function<void()>> attempts;
    std::vector<std::weak_ptr<Stream>> streams;std::vector<std::weak_ptr<Datagram>> datagrams;
    std::mutex scopeMutex;
    std::unordered_map<std::string,std::shared_ptr<std::atomic<bool>>> scopeFlags;
    std::unordered_map<std::string,std::vector<std::weak_ptr<PlatformDatagram>>> scopeSetupDatagrams;
    std::unordered_map<std::string,std::vector<uint64_t>> scopeOperations;
    Context(Node value,dispatch_queue_t target,HJCppTransportDialer transport,HJCppPhysicalTransportDialer physical):
        node(std::move(value)),output(target),dialer([transport copy]),physicalDialer([physical copy]){
        queue=dispatch_queue_create_with_target("app.hajimi.cpp-protocol.strand",DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,target);
    }
    template<class T>void prune(std::vector<std::weak_ptr<T>> &values){if(values.size()>16){values.erase(std::remove_if(values.begin(),values.end(),[](auto &value){return value.expired();}),values.end());if(values.capacity()>128 && values.size()<32)values.shrink_to_fit();}}
    std::shared_ptr<std::atomic<bool>> flagForScope(const std::string &scopeKey) {
        if (scopeKey.empty()) return nullptr;
        std::lock_guard<std::mutex> lock(scopeMutex);
        if (scopeFlags.size() > 256) {
            for (auto it = scopeFlags.begin(); it != scopeFlags.end(); ) {
                if (!it->second || (it->second.use_count() <= 1 && !it->second->load())) {
                    it = scopeFlags.erase(it);
                } else {
                    ++it;
                }
            }
            if (scopeFlags.size() > 1024) {
                for (auto it = scopeFlags.begin(); it != scopeFlags.end(); ) {
                    if (it->second.use_count() <= 1) it = scopeFlags.erase(it);
                    else ++it;
                }
            }
        }
        auto &flag = scopeFlags[scopeKey];
        if (!flag) flag = std::make_shared<std::atomic<bool>>(false);
        return flag;
    }
    bool isScopeCancelled(const std::string &scopeKey) {
        if (scopeKey.empty()) return false;
        std::lock_guard<std::mutex> lock(scopeMutex);
        auto it = scopeFlags.find(scopeKey);
        return it != scopeFlags.end() && it->second && it->second->load();
    }
    void detachScopeSetup(const std::string &scopeKey) {
        if (scopeKey.empty()) return;
        scopeSetupDatagrams.erase(scopeKey);
        scopeOperations.erase(scopeKey);
        // MUST unconditionally erase scopeKey from scopeFlags once setup completes:
        // HJCppByteStream._factory and MieruUDPStream.factory_ both retain the scoped
        // TransportFactory (so scopeFlag.use_count() is >= 2 on success). Leaving
        // scopeKey in scopeFlags caused post-setup cleanup calls to cancelScope(scopeKey)
        // to store(true) into the live stream's scopeFlag and kill Mieru-UDP at 40ms!
        std::lock_guard<std::mutex> lock(scopeMutex);
        scopeFlags.erase(scopeKey);
    }
    void cancelScope(const std::string &scopeKey) {
        if (scopeKey.empty()) return;
        {
            std::lock_guard<std::mutex> lock(scopeMutex);
            auto &flag = scopeFlags[scopeKey];
            if (!flag) flag = std::make_shared<std::atomic<bool>>(true);
            else flag->store(true);
        }
        auto self = shared_from_this();
        post(queue, [self, scopeKey]() {
            auto it = self->scopeSetupDatagrams.find(scopeKey);
            if (it != self->scopeSetupDatagrams.end()) {
                auto list = std::move(it->second);
                self->scopeSetupDatagrams.erase(it);
                for (auto &weak : list) {
                    if (auto dgram = weak.lock()) {
                        dgram->abortWithReason("Native UDP connection cancelled");
                    }
                }
            }
            auto opIt = self->scopeOperations.find(scopeKey);
            if (opIt != self->scopeOperations.end()) {
                auto ops = std::move(opIt->second);
                self->scopeOperations.erase(opIt);
                for (uint64_t op : ops) {
                    auto pendingIt = self->pending.find(op);
                    if (pendingIt != self->pending.end()) {
                        auto cancelFn = std::move(pendingIt->second);
                        self->pending.erase(pendingIt);
                        cancelFn();
                    }
                }
            }
        });
    }
    void cancel(){
        if(closed)return;closed=true;cancellationSignal=true;
        resetAnyTLSClient(factory);
        resetWireGuardClient(factory);
        scopeSetupDatagrams.clear();
        scopeOperations.clear();
        {
            std::lock_guard<std::mutex> lock(scopeMutex);
            for (auto &kv : scopeFlags) {
                if (kv.second) kv.second->store(true);
            }
            scopeFlags.clear();
        }
        auto waiters=std::move(pending);pending.clear();for(auto &entry:waiters)entry.second();
        auto oldAttempts=std::move(attempts);attempts.clear();for(auto &entry:oldAttempts)entry.second();
        auto oldStreams=std::move(streams);streams.clear();for(auto &weak:oldStreams)if(auto stream=weak.lock())stream->close();
        auto oldDatagrams=std::move(datagrams);datagrams.clear();for(auto &weak:oldDatagrams)if(auto value=weak.lock())value->close();dialer=nil;physicalDialer=nil;scopedPhysicalDialer=nil;scopedPreparedDialer=nil;
    }
    bool usesSharedFactory()const{
        return node.type=="anytls" || node.type=="wireguard" || node.type=="hysteria" || node.type=="hysteria2" || node.type=="tuic";
    }
    std::shared_ptr<TransportFactory> factoryForScope(NSUUID *scope);
    void dialTCP(const Node &,const TLSOptions &,NSUUID *scope,StreamCallback);
    void dialUDP(const Node &,const std::string &scopeKey,DatagramCallback);
    void initialize();
};
std::shared_ptr<TransportFactory> Context::factoryForScope(NSUUID *scope){
    if(usesSharedFactory())return factory;
    if(!scope && !scopedPhysicalDialer && !scopedPreparedDialer)return factory;
    // The scope is immutable and retained by the operation's factory, not a
    // transient Context field. Lazy datagram dials may run after construction
    // and other logical operations have finished on the same client strand.
    auto scoped=std::make_shared<TransportFactory>(*factory);
    std::weak_ptr<Context> weak=shared_from_this();NSUUID *identity=[scope copy];
    std::string scopeKey = identity ? cppString(identity.UUIDString) : std::string{};
    auto scopeFlag = flagForScope(scopeKey);
    if (scopeFlag) {
        scoped->cancelled = [weak, scopeFlag]() {
            auto context = weak.lock();
            return !context || context->cancellationSignal.load() || scopeFlag->load();
        };
    }
    if (scopedPhysicalDialer || scopedPreparedDialer) {
        scoped->tcp=[weak,identity](const Node &node,const TLSOptions &tls,StreamCallback completion){
            auto context=weak.lock();if(!context){completion(nullptr,"Protocol client cancelled");return;}
            context->dialTCP(node,tls,identity,std::move(completion));
        };
    }
    if (!scopeKey.empty() || scopedPreparedDialer) {
        scoped->udp=[weak,scopeKey](const Node &node,DatagramCallback completion){
            auto context=weak.lock();if(!context){completion(nullptr,"Protocol client cancelled");return;}
            context->dialUDP(node,scopeKey,std::move(completion));
        };
    }
    return scoped;
}
void Context::dialTCP(const Node &node,const TLSOptions &tls,NSUUID *scope,StreamCallback completion){
    if(closed){completion(nullptr,"Protocol client cancelled");return;}
    // Legacy unscoped hooks retain their API. A scope-aware independent dial
    // must never silently fall back to all of the cached client's owners.
    // External prepared carriers retain precedence and their existing rules.
    if(!dialer && (scopedPhysicalDialer || scopedPreparedDialer) && !usesSharedFactory() && !scope){
        completion(nullptr,"Independent physical transport requires a connection scope");return;
    }
    auto context=shared_from_this();auto attempt=++nextAttempt;
    auto ready=^(id<HJByteStream> stream,NSError *error){
        auto failure=cppError(error);post(context->queue,[context,stream,completion,failure,attempt]{
            context->attempts.erase(attempt);
            if(context->closed){[stream cancel];completion(nullptr,"Protocol client cancelled");return;}
            if(!failure.empty() || !stream){[stream cancel];completion(nullptr,failure.empty()?"Native transport did not return a stream":failure);return;}
            auto value=std::make_shared<PlatformStream>(stream,context->queue);context->prune(context->streams);context->streams.push_back(value);completion(value,{});
        });
    };
    if(dialer){dialer(ready);return;}
    if(scopedPreparedDialer){
        dispatch_block_t cancel=scopedPreparedDialer(scope,ready);
        attempts[attempt]=[cancel]{if(cancel)cancel();};return;
    }
    NSMutableArray<NSString *> *alpn=[NSMutableArray array];for(auto &value:tls.alpn)[alpn addObject:[NSString stringWithUTF8String:value.c_str()]];
    if(!addressLiteral(node.dialHost())){ready(nil,nativeError("Proxy server needs encrypted DNS bootstrapping before TCP dial"));return;}
    if(scopedPhysicalDialer || physicalDialer){
        NSString *interface=node.interfaceName.empty()?nil:[NSString stringWithUTF8String:node.interfaceName.c_str()];
        auto host=[NSString stringWithUTF8String:node.dialHost().c_str()];auto serverName=[NSString stringWithUTF8String:tls.serverName.c_str()];
        dispatch_block_t cancel=scopedPhysicalDialer
            ?scopedPhysicalDialer(host,node.port,tls.enabled,serverName,tls.skipVerify,alpn,interface,scope,ready)
            :physicalDialer(host,node.port,tls.enabled,serverName,tls.skipVerify,alpn,interface,ready);
        attempts[attempt]=[cancel]{if(cancel)cancel();};return;
    }
    NSString *interface=node.interfaceName.empty() || loopback(node.dialHost())?nil:[NSString stringWithUTF8String:node.interfaceName.c_str()];
    auto cancel=[HJNetworkStream beginConnectToHost:[NSString stringWithUTF8String:node.dialHost().c_str()] port:node.port tls:tls.enabled
        serverName:[NSString stringWithUTF8String:tls.serverName.c_str()] skipCertificateVerification:tls.skipVerify
        alpn:alpn interfaceName:interface queue:context->queue timeout:12 completion:ready];
    attempts[attempt]=[cancel]{cancel();};
}
void Context::dialUDP(const Node &node,const std::string &scopeKey,DatagramCallback completion){
    if(closed){completion(nullptr,"Protocol client cancelled");return;}
    // IMPORTANT: Never hold scopeMutex while invoking completion(), because
    // completion() -> done() -> detachScopeSetup() acquires scopeMutex on the
    // same thread and would self-deadlock context->queue and DoHResolver.queue!
    if (isScopeCancelled(scopeKey)) {
        completion(nullptr, "Native UDP connection cancelled");
        return;
    }
    if ((dialer || scopedPreparedDialer) && !node.option("underlying-proxy", node.option("dialer-proxy")).empty()) {
        auto context = shared_from_this();
        auto attempt = ++nextAttempt;
        Target peerTarget{node.dialHost(), node.port, true, false};
        auto ready = ^(id<HJByteStream> stream, NSError *error) {
            auto failure = cppError(error);
            post(context->queue, [context, stream, completion, failure, attempt, peerTarget]() mutable {
                context->attempts.erase(attempt);
                if (context->closed) { [stream cancel]; completion(nullptr, "Protocol client cancelled"); return; }
                if (!failure.empty() || !stream) {
                    [stream cancel];
                    completion(nullptr, failure.empty() ? "Chained UDP transport did not return a stream" : failure);
                    return;
                }
                auto value = std::make_shared<PreparedStreamDatagram>(stream, context->queue, std::move(peerTarget));
                context->prune(context->datagrams);
                context->datagrams.push_back(value);
                completion(std::move(value), {});
            });
        };
        if (dialer) { dialer(ready); return; }
        NSUUID *scopeUUID = (!usesSharedFactory() && !scopeKey.empty())
            ? [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:scopeKey.c_str()]]
            : nil;
        dispatch_block_t cancel = scopedPreparedDialer(scopeUUID, ready);
        attempts[attempt] = [cancel] { if (cancel) cancel(); };
        return;
    }
    Error err;
    auto value=dialPOSIXDatagram(node,queue,err);
    if(!err.empty() || !value){
        completion(nullptr,err.empty()?Error("Native UDP connection failed"):err);
        return;
    }
    prune(datagrams);
    datagrams.push_back(value);
    if(!scopeKey.empty()){
        scopeSetupDatagrams[scopeKey].push_back(value);
    }
    completion(std::move(value),{});
}
void Context::initialize(){
    factory=std::make_shared<TransportFactory>();std::weak_ptr<Context> weak=shared_from_this();auto strand=queue;
    factory->cancelled=[weak]{auto context=weak.lock();return !context || context->cancellationSignal.load();};
    factory->post=[strand](std::function<void()> work){post(strand,std::move(work));};
    factory->after=[strand](double seconds,std::function<void()> work){
        if(!std::isfinite(seconds) || seconds<0)seconds=0;seconds=std::min(seconds,86400.0);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,int64_t(seconds*NSEC_PER_SEC)),strand,^{@autoreleasepool{work();}});
    };
    factory->tcp=[weak](const Node &node,const TLSOptions &tls,StreamCallback completion){
        auto context=weak.lock();if(!context){completion(nullptr,"Protocol client cancelled");return;}
        context->dialTCP(node,tls,nil,std::move(completion));
    };
    factory->udp=[weak](const Node &node,DatagramCallback completion){
        auto context=weak.lock();if(!context || context->closed){completion(nullptr,"Protocol client cancelled");return;}
        context->dialUDP(node,{},std::move(completion));
    };
}
} // namespace

@interface HJCppByteStream () {
    std::shared_ptr<Stream> _stream;
    std::shared_ptr<Context> _context;
    std::shared_ptr<TransportFactory> _factory;
    dispatch_queue_t _output;
    std::atomic<bool> _cancelled;
    std::atomic<size_t> _queuedBytes,_queuedRequests;
    BOOL _halfClose;
}
- (instancetype)initWithStream:(std::shared_ptr<Stream>)stream context:(std::shared_ptr<Context>)context factory:(std::shared_ptr<TransportFactory>)factory output:(dispatch_queue_t)output;
@end
@interface HJCppDatagramSession () {
    std::shared_ptr<Datagram> _datagram;
    std::shared_ptr<Context> _context;
    std::shared_ptr<TransportFactory> _factory;
    dispatch_queue_t _output;
    std::atomic<bool> _cancelled;
    std::atomic<size_t> _queuedBytes,_queuedRequests;
}
- (instancetype)initWithDatagram:(std::shared_ptr<Datagram>)datagram context:(std::shared_ptr<Context>)context factory:(std::shared_ptr<TransportFactory>)factory output:(dispatch_queue_t)output;
@end
@interface HJCppProtocolClient () { std::shared_ptr<Context> _context; }
@end

namespace {
bool reserve(std::atomic<size_t> &bytes,std::atomic<size_t> &requests,size_t size){
    auto count=requests.fetch_add(1);
    if(count>=128){requests.fetch_sub(1);return false;}
    auto current=bytes.load();
    for(;;){if(size>maximumQueuedBytes || current>maximumQueuedBytes-size){requests.fetch_sub(1);return false;}
        if(bytes.compare_exchange_weak(current,current+size))return true;}
}
void deliver(dispatch_queue_t queue,HJStreamWriteCompletion completion,Error error,bool cancelled=false){
    NSError *failure=nativeError(error,cancelled);dispatch_async(queue,^{completion(failure);});
}
}

@implementation HJCppByteStream
- (instancetype)initWithStream:(std::shared_ptr<Stream>)stream context:(std::shared_ptr<Context>)context factory:(std::shared_ptr<TransportFactory>)factory output:(dispatch_queue_t)output{
    if((self=[super init])){_stream=std::move(stream);_context=std::move(context);_factory=std::move(factory);_output=output;_cancelled=false;_queuedBytes=0;_queuedRequests=0;_halfClose=_stream->supportsHalfClose();}return self;
}
- (BOOL)supportsHalfClose{return _halfClose;}
- (void)sendData:(NSData *)payload completion:(HJStreamWriteCompletion)completion{
    if(_cancelled.load()){deliver(_output,completion,"Stream closed",true);return;}
    if(!reserve(_queuedBytes,_queuedRequests,payload.length)){deliver(_output,completion,"C++ stream write queue limit exceeded");return;}
    NSData *snapshot=[payload copy];auto context=_context;auto stream=_stream;auto output=_output;size_t size=snapshot.length;
    post(context->queue,[self,context,stream,output,snapshot,size,completion]{
        if(self->_cancelled.load() || context->closed){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(output,completion,"Stream closed",true);return;}
        auto done=[self,context,output,size,completion](Error error){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(output,completion,std::move(error),self->_cancelled.load() || context->closed);};
        try{stream->write(buffer(snapshot),done);}catch(const std::exception &e){done(e.what());}
    });
}
- (void)sendContent:(dispatch_data_t)content isComplete:(BOOL)complete completion:(HJStreamWriteCompletion)completion{
    if(complete && content && dispatch_data_get_size(content)){
        [self sendData:mapped(content) completion:^(NSError *error){if(error)completion(error);else [self sendContent:nil isComplete:YES completion:completion];}];return;
    }
    if(!complete){[self sendData:mapped(content) completion:completion];return;}
    auto context=_context;auto stream=_stream;auto output=_output;
    post(context->queue,[self,context,stream,output,completion]{
        if(self->_cancelled.load() || context->closed){deliver(output,completion,"Stream closed",true);return;}
        try{stream->shutdownWrite([self,context,output,completion](Error error){deliver(output,completion,std::move(error),self->_cancelled.load() || context->closed);});}
        catch(const std::exception &e){deliver(output,completion,e.what(),self->_cancelled.load() || context->closed);}
    });
}
- (void)receiveDataWithMaximum:(NSUInteger)maximum completion:(HJDataReadCompletion)completion{
    auto context=_context;auto stream=_stream;auto output=_output;
    if(!maximum || maximum>maximumReadBytes){dispatch_async(output,^{completion(nil,NO,nativeError("Invalid maximum read size"));});return;}
    post(context->queue,[self,context,stream,output,maximum,completion]{
        if(self->_cancelled.load() || context->closed){dispatch_async(output,^{completion(nil,YES,cancelledError());});return;}
        auto done=[self,context,output,completion](Buffer value,bool eof,Error error){NSData *payload=data(std::move(value));NSError *failure=nativeError(error,self->_cancelled.load() || context->closed);dispatch_async(output,^{completion(payload,eof,failure);});};
        try{stream->read(maximum,done);}catch(const std::exception &e){done({},true,e.what());}
    });
}
- (void)receiveWithMaximum:(NSUInteger)maximum completion:(HJStreamReadCompletion)completion{
    [self receiveDataWithMaximum:maximum completion:^(NSData *payload,BOOL eof,NSError *error){
        dispatch_data_t content=nil;if(payload.length)content=dispatch_data_create(payload.bytes,payload.length,nullptr,^{(void)payload;});completion(content,eof,error);
    }];
}
- (void)cancel{if(_cancelled.exchange(true))return;auto context=_context;auto stream=_stream;post(context->queue,[context,stream]{stream->close();});}
- (void)dealloc{auto context=_context;auto stream=_stream;if(context && stream)post(context->queue,[context,stream]{stream->close();});}
@end

@implementation HJCppDatagramSession
- (instancetype)initWithDatagram:(std::shared_ptr<Datagram>)datagram context:(std::shared_ptr<Context>)context factory:(std::shared_ptr<TransportFactory>)factory output:(dispatch_queue_t)output{
    if((self=[super init])){_datagram=std::move(datagram);_context=std::move(context);_factory=std::move(factory);_output=output;_cancelled=false;_queuedBytes=0;_queuedRequests=0;}return self;
}
- (void)sendPayload:(NSData *)payload host:(NSString *)host port:(uint16_t)port completion:(HJStreamWriteCompletion)completion{
    auto context=_context;auto datagram=_datagram;auto output=_output;
    if(_cancelled.load()){deliver(output,completion,"Datagram session closed",true);return;}
    if(!reserve(_queuedBytes,_queuedRequests,payload.length)){deliver(output,completion,"Datagram write queue limit exceeded");return;}
    NSData *snapshot=[payload copy];NSString *destination=[host copy];size_t size=snapshot.length;
    post(context->queue,[self,context,datagram,output,snapshot,destination,port,size,completion]{
        auto done=[self,context,output,size,completion](Error error){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(output,completion,std::move(error),self->_cancelled.load() || context->closed);};
        if(self->_cancelled.load() || context->closed){done("Datagram session closed");return;}
        try{Target target{cppString(destination),port,true,false};datagram->send(std::move(target),buffer(snapshot),done);}
        catch(const std::exception &e){done(e.what());}
    });
}
- (void)cancel{if(_cancelled.exchange(true))return;auto context=_context;auto datagram=_datagram;post(context->queue,[context,datagram]{datagram->close();});}
- (void)dealloc{auto context=_context;auto datagram=_datagram;if(context && datagram)post(context->queue,[context,datagram]{datagram->close();});}
@end

@implementation HJCppProtocolClient
+ (NSError *)validationErrorForConfiguration:(NSData *)configuration udp:(BOOL)udp{
    try{return nativeError(validateProtocol(decode(configuration),udp));}catch(const std::exception &e){return nativeError(e.what());}
}
- (instancetype)initWithConfiguration:(NSData *)configuration interfaceName:(NSString *)interfaceName queue:(dispatch_queue_t)queue preparedTransportDialer:(HJCppTransportDialer)dialer error:(NSError **)error{
    try{
        auto node=decode(configuration);auto failure=validateProtocol(node,false);if(!failure.empty()){if(error)*error=nativeError(failure);return nil;}
        node.interfaceName=cppString(interfaceName);
        auto network=node.option("network",node.option("transport","tcp"));
        std::transform(network.begin(),network.end(),network.begin(),[](unsigned char c){return char(std::tolower(c));});
        bool quic=node.type=="hysteria" || node.type=="hysteria2" || node.type=="tuic";
        bool selfManaged=node.type=="mieru" || node.type=="sudoku" || node.type=="trusttunnel" || node.type=="snell" || node.type=="anytls" || node.type=="ssh" || node.type=="wireguard";
        bool needsCarrier=!quic && !selfManaged && network!="tcp" && !network.empty();
        bool reality=node.parameters.count("reality-public-key") || node.option("security")=="reality";
        if((needsCarrier || reality) && !dialer){if(error)*error=nativeError("This configuration requires a prepared carrier adapter");return nil;}
        if((self=[super init])){_context=std::make_shared<Context>(std::move(node),queue,dialer,nil);_context->initialize();}return self;
    }catch(const std::exception &e){if(error)*error=nativeError(e.what());return nil;}
}
- (instancetype)initWithConfiguration:(NSData *)configuration interfaceName:(NSString *)interfaceName queue:(dispatch_queue_t)queue preparedTransportDialer:(HJCppTransportDialer)dialer physicalTransportDialer:(HJCppPhysicalTransportDialer)physical error:(NSError **)error{
    self=[self initWithConfiguration:configuration interfaceName:interfaceName queue:queue preparedTransportDialer:dialer error:error];
    if(self)_context->physicalDialer=[physical copy];
    return self;
}
- (instancetype)initWithConfiguration:(NSData *)configuration interfaceName:(NSString *)interfaceName queue:(dispatch_queue_t)queue preparedTransportDialer:(HJCppTransportDialer)dialer scopedPhysicalTransportDialer:(HJCppScopedPhysicalTransportDialer)physical error:(NSError **)error{
    self=[self initWithConfiguration:configuration interfaceName:interfaceName queue:queue preparedTransportDialer:dialer error:error];
    if(self)_context->scopedPhysicalDialer=[physical copy];
    return self;
}
- (instancetype)initWithConfiguration:(NSData *)configuration interfaceName:(NSString *)interfaceName queue:(dispatch_queue_t)queue preparedTransportDialer:(HJCppTransportDialer)dialer scopedPreparedTransportDialer:(HJCppScopedPreparedTransportDialer)prepared scopedPhysicalTransportDialer:(HJCppScopedPhysicalTransportDialer)physical error:(NSError **)error{
    // The designated initializer validates carrier-dependent configurations.
    // Its compatibility shim is never invoked: the scoped hook below replaces
    // it before publication, while an explicitly supplied legacy hook wins.
    HJCppTransportDialer compatible=dialer;
    if(!compatible && prepared)compatible=^(void (^done)(id<HJByteStream>,NSError *)){prepared(nil,done);};
    self=[self initWithConfiguration:configuration interfaceName:interfaceName queue:queue preparedTransportDialer:compatible error:error];
    if(self){_context->dialer=[dialer copy];_context->scopedPreparedDialer=[prepared copy];_context->scopedPhysicalDialer=[physical copy];}
    return self;
}
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP completion:(void (^)(HJCppByteStream *,NSError *))completion{
    [self connectToHost:host port:port udp:udp plainHTTP:plainHTTP callbackQueue:_context->output completion:completion];
}
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP callbackQueue:(dispatch_queue_t)output completion:(void (^)(HJCppByteStream *,NSError *))completion{
    [self connectToHost:host port:port udp:udp plainHTTP:plainHTTP callbackQueue:output connectionScope:nil completion:completion];
}
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP callbackQueue:(dispatch_queue_t)output connectionScope:(NSUUID *)scope completion:(void (^)(HJCppByteStream *,NSError *))completion{
    auto context=_context;NSString *destination=[host copy];NSUUID *identity=[scope copy];
    std::string scopeKey = identity ? cppString(identity.UUIDString) : std::string{};
    post(context->queue,[context,output,destination,port,udp,plainHTTP,identity,scopeKey,completion]{
        if(context->closed || context->isScopeCancelled(scopeKey)){context->detachScopeSetup(scopeKey);dispatch_async(output,^{completion(nil,nativeError("Protocol client cancelled"));});return;}
        uint64_t operation=++context->nextOperation;
        context->pending[operation]=[output,completion]{dispatch_async(output,^{completion(nil,nativeError("Protocol client cancelled"));});};
        if(!scopeKey.empty()){context->scopeOperations[scopeKey].push_back(operation);}
        auto factory=context->factoryForScope(identity);
        auto done=[context,output,operation,factory,scopeKey,completion](std::shared_ptr<Stream> stream,Error error){
            context->detachScopeSetup(scopeKey);
            auto found=context->pending.find(operation);if(found==context->pending.end()){if(stream)stream->close();return;}context->pending.erase(found);
            HJCppByteStream *wrapped=nil;if(stream){context->prune(context->streams);context->streams.push_back(stream);wrapped=[[HJCppByteStream alloc]initWithStream:stream context:context factory:factory output:output];}
            NSError *failure=nativeError(error);dispatch_async(output,^{completion(wrapped,failure);});
        };
        std::weak_ptr<Context> weakCtx=context;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,int64_t(12*NSEC_PER_SEC)),context->queue,^{
            if(auto strong=weakCtx.lock()){
                if(strong->pending.find(operation)!=strong->pending.end()){
                    done(nullptr,"Protocol connection setup timed out");
                }
            }
        });
        try{Target target{cppString(destination),port,bool(udp),bool(plainHTTP)};connectProtocol(context->node,target,factory,done);}
        catch(const std::exception &e){done(nullptr,e.what());}
    });
}
- (void)createDatagramSessionWithReceive:(HJCppPacketHandler)receive failure:(HJStreamWriteCompletion)failure completion:(void (^)(HJCppDatagramSession *,NSError *))completion{
    [self createDatagramSessionWithCallbackQueue:_context->output receive:receive failure:failure completion:completion];
}
- (void)createDatagramSessionWithCallbackQueue:(dispatch_queue_t)output receive:(HJCppPacketHandler)receive failure:(HJStreamWriteCompletion)failure completion:(void (^)(HJCppDatagramSession *,NSError *))completion{
    [self createDatagramSessionWithCallbackQueue:output connectionScope:nil receive:receive failure:failure completion:completion];
}
- (void)createDatagramSessionWithCallbackQueue:(dispatch_queue_t)output connectionScope:(NSUUID *)scope receive:(HJCppPacketHandler)receive failure:(HJStreamWriteCompletion)failure completion:(void (^)(HJCppDatagramSession *,NSError *))completion{
    auto context=_context;NSUUID *identity=[scope copy];
    std::string scopeKey = identity ? cppString(identity.UUIDString) : std::string{};
    post(context->queue,[context,output,identity,scopeKey,receive,failure,completion]{
        if(context->closed || context->isScopeCancelled(scopeKey)){context->detachScopeSetup(scopeKey);dispatch_async(output,^{completion(nil,nativeError("Protocol client cancelled"));});return;}
        uint64_t operation=++context->nextOperation;
        context->pending[operation]=[output,completion]{dispatch_async(output,^{completion(nil,nativeError("Protocol client cancelled"));});};
        if(!scopeKey.empty()){context->scopeOperations[scopeKey].push_back(operation);}
        auto factory=context->factoryForScope(identity);
        auto done=[context,output,operation,factory,scopeKey,receive,failure,completion](std::shared_ptr<Datagram> datagram,Error error){
            context->detachScopeSetup(scopeKey);
            auto found=context->pending.find(operation);if(found==context->pending.end()){if(datagram)datagram->close();return;}context->pending.erase(found);
            if(!error.empty() || !datagram){NSError *value=nativeError(error.empty()?"Protocol did not create a datagram session":error);dispatch_async(output,^{completion(nil,value);});return;}
            context->prune(context->datagrams);context->datagrams.push_back(datagram);
            auto wrapped=[[HJCppDatagramSession alloc]initWithDatagram:datagram context:context factory:factory output:output];
            std::weak_ptr<Context> weak=context;
            datagram->start([weak,output,receive](Target target,Buffer value){if(auto context=weak.lock()){
                NSString *host=[[NSString alloc]initWithBytes:target.host.data() length:target.host.size() encoding:NSUTF8StringEncoding];
                if(!host)return;auto port=target.port;NSData *payload=data(std::move(value));
                dispatch_async(output,^{receive(host,port,payload);});
            }},[weak,output,failure](Error error){if(weak.lock())deliver(output,failure,std::move(error));});
            dispatch_async(output,^{completion(wrapped,nil);});
        };
        try{makeProtocolDatagram(context->node,factory,done);}catch(const std::exception &e){done(nullptr,e.what());}
    });
}
- (void)cancelConnectionScope:(NSUUID *)connectionScope{
    auto context=_context;
    if(!context || !connectionScope)return;
    std::string scopeKey=cppString(connectionScope.UUIDString);
    context->cancelScope(scopeKey);
}
- (void)cancel{auto context=_context;if(context)post(context->queue,[context]{context->cancel();});}
- (void)dealloc{auto context=_context;if(context)post(context->queue,[context]{context->cancel();});}
@end

@implementation HJCppServerProtocols
+ (void)acceptSOCKS5FromStream:(id<HJByteStream>)native queue:(dispatch_queue_t)output completion:(void (^)(NSString *,uint16_t,uint8_t,NSData *,NSError *))completion{
    auto strand=dispatch_queue_create_with_target("app.hajimi.cpp-socks-server",DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,output);
    post(strand,[strand,output,native,completion]{
        auto factory=std::make_shared<TransportFactory>();
        factory->post=[strand](std::function<void()> work){post(strand,std::move(work));};
        factory->after=[strand](double delay,std::function<void()> work){dispatch_after(dispatch_time(DISPATCH_TIME_NOW,int64_t(delay*NSEC_PER_SEC)),strand,^{work();});};
        auto source=std::make_shared<PlatformStream>(native,strand,false);
        auto done=[output,completion](Target target,uint8_t command,Buffer initial,Error error){
            NSString *host=[[NSString alloc]initWithBytes:target.host.data() length:target.host.size() encoding:NSUTF8StringEncoding];
            NSData *payload=data(std::move(initial));auto port=target.port;NSError *failure=nativeError(error);
            dispatch_async(output,^{completion(host,port,command,payload,failure);});
        };
        try{acceptSOCKS5(source,factory,done);}catch(const std::exception &e){source->close();done({},0,{},e.what());}
    });
}
@end

void HJFlushCachedBridgeInterfaces(void) {
    flushCachedBridgeInterfaces();
    hajimi::resetAnyTLSClients();
    hajimi::resetWireGuardClient(nullptr);
}
