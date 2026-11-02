#import <HajimiCXXProtocolBridge.h>
#include "Crypto.hpp"
#include "AnyTLS.hpp"
#include "Runtime.hpp"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <functional>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

typedef void (^HJFragmentedBridgeReadHandler)(NSUInteger, HJStreamReadCompletion);
typedef void (^HJFragmentedBridgeWriteHandler)(dispatch_data_t, BOOL, HJStreamWriteCompletion);

// HJCallbackStream exposes NSData to its receive handler. This carrier keeps
// the dispatch_data regions intact across the real PlatformStream boundary.
@interface HJFragmentedMemoryStream : NSObject <HJByteStream>
@property(nonatomic,copy) HJFragmentedBridgeReadHandler readHandler;
@property(nonatomic,copy) HJFragmentedBridgeWriteHandler writeHandler;
@end
@implementation HJFragmentedMemoryStream {
    std::atomic<bool> _cancelled;
}
- (instancetype)init { if((self=[super init]))_cancelled.store(false);return self; }
- (BOOL)supportsHalfClose { return YES; }
- (void)receiveWithMaximum:(NSUInteger)maximum completion:(HJStreamReadCompletion)completion {
    if(_cancelled.load()){completion(nil,YES,[NSError errorWithDomain:@"fragmented-memory" code:1 userInfo:nil]);return;}
    self.readHandler(maximum,completion);
}
- (void)sendContent:(dispatch_data_t)content isComplete:(BOOL)complete completion:(HJStreamWriteCompletion)completion {
    if(_cancelled.load()){completion([NSError errorWithDomain:@"fragmented-memory" code:1 userInfo:nil]);return;}
    self.writeHandler(content,complete,completion);
}
- (void)cancel { _cancelled.store(true); }
@end

using namespace hajimi;
namespace {
std::atomic<unsigned> checks{0};
void expect(bool value,const char *message){++checks;if(!value)throw std::runtime_error(message);}
Buffer bytes(const std::string &s){return {s.begin(),s.end()};}
Buffer part(const Buffer &in,size_t offset,size_t count){if(offset>in.size()||count>in.size()-offset)throw std::runtime_error("Reference peer packet truncated");
    return {in.begin()+offset,in.begin()+offset+count};}
void append(Buffer &out,const Buffer &in){out.insert(out.end(),in.begin(),in.end());}
void put16(Buffer &out,size_t n){out.push_back(uint8_t(n>>8));out.push_back(uint8_t(n));}
void put64(Buffer &out,uint64_t n){for(int i=7;i>=0;--i)out.push_back(uint8_t(n>>(i*8)));}
size_t get16(const Buffer &in,size_t offset){return size_t(in.at(offset))<<8|in.at(offset+1);}
Buffer buffer(NSData *data){if(!data.length)return {};const auto p=static_cast<const uint8_t *>(data.bytes);return {p,p+data.length};}
NSData *data(const Buffer &value){return [NSData dataWithBytes:value.data() length:value.size()];}
void wait(dispatch_semaphore_t signal,const char *message){
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(20);
    // Security.framework's default trust evaluation can dispatch to main.
    // AppKit already pumps this loop; a standalone CLI must do so explicitly.
    while(dispatch_semaphore_wait(signal,DISPATCH_TIME_NOW)!=0){
        if(std::chrono::steady_clock::now()>deadline){expect(false,message);return;}
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.01,true);
    }
    ++checks;
}
struct Socket {
    int fd=-1;
    explicit Socket(int descriptor=-1):fd(descriptor){}
    ~Socket(){if(fd>=0)::close(fd);}
    Socket(Socket &&other)noexcept:fd(other.fd){other.fd=-1;}
    Socket(const Socket &)=delete;Socket &operator=(const Socket &)=delete;
};
void configure(int fd){int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));timeval timeout{6,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));}
Socket listenSocket(int type,uint16_t &port){Socket socket(::socket(AF_INET,type,0));if(socket.fd<0)throw std::runtime_error("Create loopback socket failed");
    configure(socket.fd);sockaddr_in address{};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(socket.fd,reinterpret_cast<sockaddr *>(&address),sizeof(address)))throw std::runtime_error("Bind loopback socket failed");
    socklen_t length=sizeof(address);if(getsockname(socket.fd,reinterpret_cast<sockaddr *>(&address),&length))throw std::runtime_error("Loopback port unavailable");
    port=ntohs(address.sin_port);if(type==SOCK_STREAM&&listen(socket.fd,4))throw std::runtime_error("Listen failed");return socket;}
void sendAll(int fd,const Buffer &payload){size_t sent=0;while(sent<payload.size()){ssize_t count=send(fd,payload.data()+sent,payload.size()-sent,0);
    if(count<=0)throw std::runtime_error("Peer TCP send failed");sent+=size_t(count);}}
Buffer receiveExactly(int fd,size_t wanted){Buffer out(wanted);size_t offset=0;while(offset<wanted){ssize_t n=recv(fd,out.data()+offset,wanted-offset,0);
    if(n<=0)throw std::runtime_error("Peer TCP stream truncated");offset+=size_t(n);}return out;}
class TCPPeer {
public:
    uint16_t port=0;
private:
    Socket listener_;std::thread worker_;std::exception_ptr failure_;
public:
    explicit TCPPeer(std::function<void(int)> peer):listener_(listenSocket(SOCK_STREAM,port)){worker_=std::thread([this,peer]{try{
        Socket accepted(accept(listener_.fd,nullptr,nullptr));if(accepted.fd<0)throw std::runtime_error("Peer accept failed");configure(accepted.fd);peer(accepted.fd);
    }catch(...){failure_=std::current_exception();}});}
    void join(){if(worker_.joinable())worker_.join();if(failure_)std::rethrow_exception(failure_);}
    ~TCPPeer(){if(worker_.joinable()){shutdown(listener_.fd,SHUT_RDWR);worker_.join();}}
};
NSData *configuration(NSString *type,uint16_t port,NSDictionary *parameters=@{}){return [NSJSONSerialization dataWithJSONObject:
    @{ @"type":type,@"host":@"127.0.0.1",@"port":@(port),@"name":@"loopback-test",@"parameters":parameters } options:0 error:nil];}
HJCppProtocolClient *client(NSData *config,dispatch_queue_t queue,HJCppTransportDialer prepared=nil){NSError *error=nil;
    HJCppProtocolClient *value=[[HJCppProtocolClient alloc]initWithConfiguration:config interfaceName:nil queue:queue preparedTransportDialer:prepared error:&error];
    expect(value&& !error,"C++ bridge client creation failed");return value;}
HJCppByteStream *connect(HJCppProtocolClient *value,NSError **outError=nullptr){dispatch_semaphore_t signal=dispatch_semaphore_create(0);
    __block HJCppByteStream *stream=nil;__block NSError *error=nil;
    [value connectToHost:@"destination.example" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *result,NSError *failure){stream=result;error=failure;dispatch_semaphore_signal(signal);}];
    wait(signal,"Bridge connect timed out");if(outError)*outError=error;else expect(stream&&!error,"Bridge TCP protocol connect failed");return stream;}
Buffer read(HJCppByteStream *stream,NSUInteger maximum=65536,bool *outEOF=nullptr){dispatch_semaphore_t signal=dispatch_semaphore_create(0);
    __block NSData *payload=nil;__block NSError *error=nil;__block BOOL eof=NO;
    [stream receiveDataWithMaximum:maximum completion:^(NSData *result,BOOL ended,NSError *failure){payload=result;eof=ended;error=failure;dispatch_semaphore_signal(signal);}];
    wait(signal,"Bridge read timed out");expect(!error,"Bridge read failed");if(outEOF)*outEOF=eof;return buffer(payload);}
void write(HJCppByteStream *stream,const Buffer &payload){dispatch_semaphore_t signal=dispatch_semaphore_create(0);__block NSError *error=nil;
    [stream sendData:data(payload) completion:^(NSError *failure){error=failure;dispatch_semaphore_signal(signal);}];wait(signal,"Bridge write timed out");expect(!error,"Bridge write failed");}
NSError *bridgeTransportFailure(NSString *description,NSInteger code=-9806){
    NSError *socket=[NSError errorWithDomain:NSPOSIXErrorDomain code:ECONNRESET userInfo:nil];
    NSError *network=[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorNetworkConnectionLost userInfo:@{NSUnderlyingErrorKey:socket}];
    return [NSError errorWithDomain:NSOSStatusErrorDomain code:code
        userInfo:@{NSLocalizedDescriptionKey:description,NSUnderlyingErrorKey:network}];
}
void expectBridgeTransportFailure(NSError *actual,NSError *original){
    expect(actual==original,"Bridge replaced the original platform NSError");
    expect([actual.domain isEqualToString:original.domain]&&actual.code==original.code,"Bridge lost platform error domain/code");
    NSError *network=actual.userInfo[NSUnderlyingErrorKey],*socket=network.userInfo[NSUnderlyingErrorKey];
    expect([network.domain isEqualToString:NSURLErrorDomain]&&network.code==NSURLErrorNetworkConnectionLost
        &&[socket.domain isEqualToString:NSPOSIXErrorDomain]&&socket.code==ECONNRESET,"Bridge lost the underlying NSError chain");
}
dispatch_data_t bridgeMemoryBytes(const Buffer &value){
    NSData *payload=data(value);return dispatch_data_create(payload.bytes,payload.length,nullptr,^{(void)payload;});
}
void bridgeErrorValues(){
    struct Metadata final:ErrorMetadata{std::shared_ptr<std::atomic<unsigned>> releases;
        explicit Metadata(std::shared_ptr<std::atomic<unsigned>> value):releases(std::move(value)){}
        ~Metadata()override{++*releases;}};
    auto releases=std::make_shared<std::atomic<unsigned>>(0);std::weak_ptr<const ErrorMetadata> weak;
    {
        auto metadata=std::make_shared<Metadata>(releases);weak=metadata;
        Error original("EOF",metadata);metadata.reset();
        expect(!original.empty()&&original!="EOF"&&Error("EOF")=="EOF","Typed description became the protocol EOF sentinel");
        Error copied=original,moved=std::move(copied);
        expect(moved==original&&moved.metadata()==original.metadata(),"Error copy/move lost native identity");
        Error rewritten=std::string("context: ")+original;
        expect(!rewritten.metadata()&&rewritten=="context: EOF","Error concatenation retained unrelated native metadata");
        rewritten=original;rewritten+=" (rewritten)";
        expect(!rewritten.metadata()&&rewritten.find("rewritten")!=std::string::npos,"Error append retained stale native metadata");
        rewritten=original;rewritten="new failure";
        expect(!rewritten.metadata()&&rewritten=="new failure","Error replacement retained stale native metadata");
        rewritten=original;rewritten.clear();
        expect(rewritten.empty()&&!rewritten.metadata()&&Error("",original.metadata()).empty(),"Empty error stopped meaning success");
        moved.clear();expect(!weak.expired(),"A remaining Error copy lost metadata ownership");
    }
    expect(weak.expired()&&releases->load()==1,"Error metadata was leaked or destroyed more than once");
}
void bridgeErrorRoundTrip(dispatch_queue_t queue){
    bridgeErrorValues();
    NSDictionary *identity=@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff",@"password":@"memory-test"};
    for(NSString *type in @[@"http",@"vless",@"vmess",@"anytls"]){
        NSError *original=bridgeTransportFailure(@"Peer closed without notification");
        auto value=client(configuration(type,1,identity),queue,^(void (^done)(id<HJByteStream>,NSError *)){
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool{done(nil,original);}});
        });
        NSError *failure=nil;auto stream=connect(value,&failure);
        expect(!stream,"Platform dial failure published a protocol stream");expectBridgeTransportFailure(failure,original);[value cancel];
    }
    for(bool writeFailure:{false,true}){
        NSError *original=bridgeTransportFailure(writeFailure?@"Handshake write reset":@"Handshake read reset");
        HJFragmentedMemoryStream *carrier=[HJFragmentedMemoryStream new];
        carrier.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion done){done(writeFailure?original:nil);};
        carrier.readHandler=^(NSUInteger,HJStreamReadCompletion done){done(nil,YES,original);};
        auto value=client(configuration(@"http",1),queue,^(void (^done)(id<HJByteStream>,NSError *)){done(carrier,nil);});
        NSError *failure=nil;auto stream=connect(value,&failure);
        expect(!stream,"Failed HTTP handshake published a stream");expectBridgeTransportFailure(failure,original);[value cancel];
    }
    for(unsigned operation=0;operation<3;++operation){
        NSError *original=bridgeTransportFailure(operation==0?@"Download reset":operation==1?@"Upload reset":@"FIN reset");
        auto reads=std::make_shared<std::atomic<unsigned>>(0),writes=std::make_shared<std::atomic<unsigned>>(0);
        HJFragmentedMemoryStream *carrier=[HJFragmentedMemoryStream new];
        carrier.readHandler=^(NSUInteger,HJStreamReadCompletion done){
            if(reads->fetch_add(1)==0)done(bridgeMemoryBytes(bytes("HTTP/1.1 200 Connected\r\n\r\n")),NO,nil);
            else done(nil,YES,original);
        };
        carrier.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion done){done(writes->fetch_add(1)==0?nil:original);};
        auto value=client(configuration(@"http",1),queue,^(void (^done)(id<HJByteStream>,NSError *)){done(carrier,nil);});
        auto stream=connect(value);auto completed=dispatch_semaphore_create(0);__block NSError *failure=nil;
        if(operation==0)[stream receiveDataWithMaximum:8 completion:^(NSData *,BOOL,NSError *error){failure=error;dispatch_semaphore_signal(completed);}];
        else if(operation==1)[stream sendData:data(bytes("query")) completion:^(NSError *error){failure=error;dispatch_semaphore_signal(completed);}];
        else [stream sendContent:nil isComplete:YES completion:^(NSError *error){failure=error;dispatch_semaphore_signal(completed);}];
        wait(completed,"Established stream error callback missing");expectBridgeTransportFailure(failure,original);
        if(operation==0){
            [stream receiveDataWithMaximum:8 completion:^(NSData *,BOOL,NSError *error){failure=error;dispatch_semaphore_signal(completed);}];
            wait(completed,"Retained stream terminal error callback missing");expectBridgeTransportFailure(failure,original);
        }
        [stream cancel];[value cancel];
    }
    // C++ treats an untyped EOF as framing context. A platform NSError using
    // that same description must still arrive with its original native type.
    for(NSString *type in @[@"vless",@"vmess"]){
        NSError *sentinel=bridgeTransportFailure(@"EOF");
        HJFragmentedMemoryStream *carrier=[HJFragmentedMemoryStream new];
        carrier.readHandler=^(NSUInteger,HJStreamReadCompletion done){done(nil,YES,sentinel);};
        carrier.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion done){done(nil);};
        auto value=client(configuration(type,1,identity),queue,^(void (^done)(id<HJByteStream>,NSError *)){done(carrier,nil);});
        auto stream=connect(value);auto completed=dispatch_semaphore_create(0);__block NSError *failure=nil;
        [stream receiveDataWithMaximum:8 completion:^(NSData *,BOOL,NSError *error){failure=error;dispatch_semaphore_signal(completed);}];
        wait(completed,"Typed EOF description callback missing");expectBridgeTransportFailure(failure,sentinel);[stream cancel];[value cancel];
    }

    HJFragmentedMemoryStream *denied=[HJFragmentedMemoryStream new];
    denied.readHandler=^(NSUInteger,HJStreamReadCompletion done){done(bridgeMemoryBytes(bytes("HTTP/1.1 403 Forbidden\r\n\r\n")),NO,nil);};
    denied.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion done){done(nil);};
    auto rejected=client(configuration(@"http",1),queue,^(void (^done)(id<HJByteStream>,NSError *)){done(denied,nil);});
    NSError *failure=nil;auto stream=connect(rejected,&failure);
    expect(!stream&&[failure.domain isEqualToString:HJCppProtocolErrorDomain]&&failure.code==1
        &&[failure.localizedDescription isEqualToString:@"HTTP CONNECT rejected"],"Pure C++ error changed its public domain/code/message");
    [rejected cancel];
}
void bridgeErrorARCLifetime(dispatch_queue_t queue){
    auto started=dispatch_semaphore_create(0),blocked=dispatch_semaphore_create(0),unblock=dispatch_semaphore_create(0);
    auto produced=dispatch_semaphore_create(0),completed=dispatch_semaphore_create(0);
    __block void (^heldReady)(id<HJByteStream>,NSError *)=nil;
    __block __weak NSError *original=nil;__block NSError *result=nil;
    auto value=client(configuration(@"http",1),queue,^(void (^done)(id<HJByteStream>,NSError *)){
        heldReady=[done copy];dispatch_semaphore_signal(started);
    });
    [value connectToHost:@"lifetime.invalid" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *,NSError *error){
        result=error;dispatch_semaphore_signal(completed);
    }];
    wait(started,"Native error lifetime fixture did not start its dial");
    auto unblockOnExit=std::shared_ptr<void>(nullptr,[unblock](void *){dispatch_semaphore_signal(unblock);});
    dispatch_async(queue,^{dispatch_semaphore_signal(blocked);dispatch_semaphore_wait(unblock,DISPATCH_TIME_FOREVER);});
    wait(blocked,"Native error lifetime queue gate did not start");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        @autoreleasepool{
            // The producer's only strong reference dies before the C++ queue
            // runs. In particular an empty localized description is still a
            // failed NSError, not the protocol API's successful empty Error.
            NSError *failure=bridgeTransportFailure(@"");original=failure;heldReady(nil,failure);
        }
        dispatch_semaphore_signal(produced);
    });
    wait(produced,"Foreign native error producer did not finish");
    expect(original!=nil,"C++ bridge did not retain NSError beyond its producer's autorelease pool");
    dispatch_semaphore_signal(unblock);wait(completed,"Retained native error did not reach its Swift-facing callback");
    expectBridgeTransportFailure(result,original);[value cancel];heldReady=nil;
}
void bridgeErrorScopes(dispatch_queue_t queue){
    typedef void (^Ready)(id<HJByteStream>,NSError *);
    __block Ready firstReady=nil,secondReady=nil;
    NSUUID *first=NSUUID.UUID,*second=NSUUID.UUID;auto dialed=dispatch_semaphore_create(0),completed=dispatch_semaphore_create(0);
    NSError *firstError=bridgeTransportFailure(@"Same display text",-9806),*secondError=bridgeTransportFailure(@"Same display text",-9813);
    HJCppScopedPhysicalTransportDialer dialer=^dispatch_block_t(NSString *,uint16_t,BOOL,NSString *,BOOL,NSArray<NSString *> *,NSString *,NSUUID *scope,Ready done){
        if([scope isEqual:first])firstReady=[done copy];else if([scope isEqual:second])secondReady=[done copy];
        dispatch_semaphore_signal(dialed);return ^{};
    };
    NSError *creation=nil;auto value=[[HJCppProtocolClient alloc]initWithConfiguration:configuration(@"http",1)
        interfaceName:nil queue:queue preparedTransportDialer:nil scopedPhysicalTransportDialer:dialer error:&creation];
    expect(value&&!creation,"Scoped native error fixture could not create its client");
    __block NSError *firstResult=nil,*secondResult=nil;auto callbacks=std::make_shared<std::atomic<unsigned>>(0);
    [value connectToHost:@"first.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:queue connectionScope:first
        completion:^(HJCppByteStream *,NSError *error){firstResult=error;++*callbacks;dispatch_semaphore_signal(completed);}];
    [value connectToHost:@"second.invalid" port:443 udp:NO plainHTTP:NO callbackQueue:queue connectionScope:second
        completion:^(HJCppByteStream *,NSError *error){secondResult=error;++*callbacks;dispatch_semaphore_signal(completed);}];
    wait(dialed,"First scoped dial missing");wait(dialed,"Second scoped dial missing");expect(firstReady&&secondReady,"Scope lost its physical completion");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{secondReady(nil,secondError);firstReady(nil,firstError);});
    wait(completed,"First scoped error callback missing");wait(completed,"Second scoped error callback missing");
    expectBridgeTransportFailure(firstResult,firstError);expectBridgeTransportFailure(secondResult,secondError);
    expect(callbacks->load()==2,"Concurrent native failures duplicated or lost a callback");[value cancel];firstReady=nil;secondReady=nil;
}
void bridgeAnyTLSErrorFanout(dispatch_queue_t queue,bool writeFailure,bool payloadFailure){
    NSError *original=bridgeTransportFailure(@"AnyTLS carrier reset");
    auto reading=dispatch_semaphore_create(0),writing=dispatch_semaphore_create(0),completed=dispatch_semaphore_create(0);
    __block HJStreamReadCompletion heldRead=nil;__block HJStreamWriteCompletion heldWrite=nil;
    auto blockWrites=std::make_shared<std::atomic<bool>>(false);
    HJFragmentedMemoryStream *carrier=[HJFragmentedMemoryStream new];
    carrier.readHandler=^(NSUInteger,HJStreamReadCompletion done){heldRead=[done copy];dispatch_semaphore_signal(reading);};
    carrier.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion done){
        if(blockWrites->load()){heldWrite=[done copy];dispatch_semaphore_signal(writing);}else done(nil);
    };
    auto value=client(configuration(@"anytls",1,@{@"password":@"memory-test"}),queue,^(void (^done)(id<HJByteStream>,NSError *)){done(carrier,nil);});
    auto stream=connect(value);wait(reading,"AnyTLS carrier did not start its frame read");
    if(payloadFailure){
        HJStreamReadCompletion header=[heldRead copy];heldRead=nil;
        header(bridgeMemoryBytes(Buffer{anytls::PSH,0,0,0,1,0,3}),NO,nil);
        wait(reading,"AnyTLS carrier did not start its frame payload read");
    }
    __block NSError *readError=nil,*writeError=nil;auto callbacks=std::make_shared<std::atomic<unsigned>>(0);
    [stream receiveDataWithMaximum:8 completion:^(NSData *,BOOL,NSError *error){readError=error;++*callbacks;dispatch_semaphore_signal(completed);}];
    blockWrites->store(true);
    [stream sendData:data(bytes("pending")) completion:^(NSError *error){writeError=error;++*callbacks;dispatch_semaphore_signal(completed);}];
    wait(writing,"AnyTLS carrier did not retain its pending write");
    if(writeFailure)heldWrite(original);else heldRead(nil,YES,original);
    wait(completed,"AnyTLS terminal read/write callback missing");wait(completed,"AnyTLS terminal fanout lost a callback");
    expectBridgeTransportFailure(readError,original);expectBridgeTransportFailure(writeError,original);
    expect(callbacks->load()==2,"AnyTLS native failure did not resolve its admitted operations once");
    if(!writeFailure)heldWrite(nil);
    [stream cancel];[value cancel];heldRead=nil;heldWrite=nil;
}
struct FragmentedRegions {
    std::atomic<unsigned> allocated{0},released{0};
    dispatch_semaphore_t releaseSignal=dispatch_semaphore_create(0);
};
dispatch_data_t fragmentedBytes(const Buffer &payload,const std::shared_ptr<FragmentedRegions> &regions){
    dispatch_data_t result=dispatch_data_empty;size_t offset=0;
    for(size_t wanted:{size_t(1),size_t(3),size_t(17),size_t(1031),payload.size()}){
        const size_t count=std::min(wanted,payload.size()-offset);if(!count)continue;
        auto owned=new Buffer(payload.begin()+offset,payload.begin()+offset+count);++regions->allocated;
        auto state=regions;
        dispatch_data_t region=dispatch_data_create(owned->data(),owned->size(),dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^{
            delete owned;++state->released;dispatch_semaphore_signal(state->releaseSignal);
        });
        // dispatch may canonicalize away these empty concatenation nodes.
        result=dispatch_data_create_concat(result,dispatch_data_empty);
        result=dispatch_data_create_concat(result,region);
        result=dispatch_data_create_concat(result,dispatch_data_empty);offset+=count;
    }
    return result;
}
void fragmentedBridge(dispatch_queue_t queue){
    const Buffer greeting{0x00,0x7f,0x80,0xff,0x01,0xfe,0x00};
    Buffer payload(32768);for(size_t index=0;index<payload.size();++index)payload[index]=uint8_t(index*131+17);
    auto valid=std::make_shared<std::atomic<bool>>(true);
    auto reads=std::make_shared<std::atomic<unsigned>>(0);
    auto firstRegions=std::make_shared<FragmentedRegions>(),lastRegions=std::make_shared<FragmentedRegions>();
    __block HJStreamReadCompletion heldRead=nil;
    dispatch_semaphore_t pending=dispatch_semaphore_create(0),done=dispatch_semaphore_create(0);
    HJFragmentedMemoryStream *carrier=[HJFragmentedMemoryStream new];
    carrier.readHandler=^(NSUInteger maximum,HJStreamReadCompletion completion){
        if(reads->fetch_add(1)==0){Buffer response=bytes("HTTP/1.1 200 Connected\r\n\r\n");append(response,greeting);
            if(response.size()>maximum)valid->store(false);
            completion(fragmentedBytes(response,firstRegions),NO,nil);
        }else{if(maximum<payload.size())valid->store(false);heldRead=[completion copy];dispatch_semaphore_signal(pending);}
    };
    carrier.writeHandler=^(dispatch_data_t content,BOOL,HJStreamWriteCompletion completion){
        __block std::string header;
        dispatch_data_apply(content,^bool(dispatch_data_t,size_t,const void *bytes,size_t length){header.append(static_cast<const char *>(bytes),length);return true;});
        if(header.find("CONNECT destination.example:443 HTTP/1.1\r\n")!=0)valid->store(false);completion(nil);
    };
    auto value=client(configuration(@"http",1),queue,^(void (^completion)(id<HJByteStream>,NSError *)){completion(carrier,nil);});
    auto stream=connect(value);Buffer received;
    while(received.size()<greeting.size()){bool eof=false;auto chunk=read(stream,3,&eof);expect(!eof&&!chunk.empty(),"Fragmented CONNECT tail ended early");append(received,chunk);}
    expect(received==greeting,"Fragmented CONNECT header/tail lost binary bytes");
    auto callbacks=std::make_shared<std::atomic<unsigned>>(0);
    __block NSData *delivered=nil;__block BOOL ended=NO;__block NSError *failure=nil;
    [stream receiveDataWithMaximum:65536 completion:^(NSData *content,BOOL eof,NSError *error){
        delivered=content;ended=eof;failure=error;++*callbacks;dispatch_semaphore_signal(done);
    }];
    wait(pending,"Fragmented carrier did not retain its payload read callback");
    dispatch_semaphore_t blocked=dispatch_semaphore_create(0),unblock=dispatch_semaphore_create(0);
    // Hold the transport target while invoking the retained native callback on
    // this foreign queue. Its posted consumer cannot run until the regions die.
    dispatch_async(queue,^{dispatch_semaphore_signal(blocked);dispatch_semaphore_wait(unblock,DISPATCH_TIME_FOREVER);});
    auto unblockOnExit=std::shared_ptr<void>(nullptr,[unblock](void *){dispatch_semaphore_signal(unblock);});
    wait(blocked,"Fragmented ownership gate did not start");
    HJStreamReadCompletion complete=[heldRead copy];heldRead=nil;
    @autoreleasepool{
        dispatch_data_t content=fragmentedBytes(payload,lastRegions);__block unsigned actualRegions=0;
        dispatch_data_apply(content,^bool(dispatch_data_t,size_t,const void *,size_t length){if(length)++actualRegions;return true;});
        expect(actualRegions>1,"Fragmented carrier fixture unexpectedly became contiguous");complete(content,YES,nil);
    }
    for(unsigned index=0;index<lastRegions->allocated.load();++index)wait(lastRegions->releaseSignal,"Fragmented source region survived its callback");
    expect(lastRegions->released.load()==lastRegions->allocated.load()&&callbacks->load()==0,
        "Fragmented bridge retained the native source or consumed it before the ownership gate");
    dispatch_semaphore_signal(unblock);wait(done,"Fragmented payload callback missing");
    expect(valid->load()&&!failure&&ended&&callbacks->load()==1&&buffer(delivered)==payload,
        "Fragmented retained callback lost payload/EOF or delivered more than once");
    [stream cancel];[value cancel];

    // A clean empty final read may be represented by nil or dispatch_data_empty.
    for(bool nilContent:{false,true}){
        auto count=std::make_shared<std::atomic<unsigned>>(0);HJFragmentedMemoryStream *empty=[HJFragmentedMemoryStream new];
        empty.readHandler=^(NSUInteger,HJStreamReadCompletion completion){
            if(count->fetch_add(1)==0){auto header=bytes("HTTP/1.1 200 Connected\r\n\r\n");completion(fragmentedBytes(header,firstRegions),NO,nil);}
            else completion(nilContent?nil:dispatch_data_empty,YES,nil);
        };
        empty.writeHandler=^(dispatch_data_t,BOOL,HJStreamWriteCompletion completion){completion(nil);};
        auto emptyClient=client(configuration(@"http",1),queue,^(void (^completion)(id<HJByteStream>,NSError *)){completion(empty,nil);});
        auto emptyStream=connect(emptyClient);bool eof=false;
        expect(read(emptyStream,65536,&eof).empty()&&eof&&count->load()==2,"Empty fragmented carrier did not preserve EOF");
        [emptyStream cancel];[emptyClient cancel];
    }
}
Buffer connectHeader(int fd){Buffer out;while(out.size()<65536){append(out,receiveExactly(fd,1));if(out.size()>=4&&part(out,out.size()-4,4)==bytes("\r\n\r\n"))return out;}
    throw std::runtime_error("HTTP peer header limit exceeded");}
void tcpBridge(dispatch_queue_t queue){
    TCPPeer peer([](int fd){Buffer header=connectHeader(fd);std::string text(header.begin(),header.end());
        expect(text.find("CONNECT destination.example:443 HTTP/1.1\r\n")==0,"Real HTTP CONNECT destination");
        expect(text.find("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n")!=std::string::npos,"Real proxy authentication");
        sendAll(fd,bytes("HTTP/1.1 200 Connected\r\n\r\nGREETING"));Buffer received=receiveExactly(fd,32*4),expected;
        for(unsigned i=0;i<32;++i){expected.push_back(0);expected.push_back(0);expected.push_back(0);expected.push_back(uint8_t(i));}
        expect(received==expected,"Bridge FIFO/NSMutableData snapshot corrupted");uint8_t byte=0;expect(recv(fd,&byte,1,0)==0,"Bridge FIN did not half-close native TCP");
        sendAll(fd,bytes("AFTER-FIN"));});
    HJCppProtocolClient *value=client(configuration(@"http",peer.port,@{@"username":@"user",@"password":@"secret"}),queue);
    HJCppByteStream *stream=connect(value);Buffer greeting;while(greeting.size()<8)append(greeting,read(stream,3));expect(greeting==bytes("GREETING"),"Bridge HTTP leftover bytes lost");
    dispatch_group_t group=dispatch_group_create();auto failed=std::make_shared<std::atomic<bool>>(false);auto callbacks=std::make_shared<std::atomic<unsigned>>(0);
    for(unsigned i=0;i<32;++i){uint8_t record[4]{0,0,0,uint8_t(i)};NSMutableData *mutableData=[NSMutableData dataWithBytes:record length:4];dispatch_group_enter(group);
        [stream sendData:mutableData completion:^(NSError *error){if(error)failed->store(true);++*callbacks;dispatch_group_leave(group);}];std::memset(mutableData.mutableBytes,0xff,4);}
    expect(dispatch_group_wait(group,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC))==0,"Bridge FIFO writes timed out");expect(!failed->load()&&callbacks->load()==32,"Bridge write callbacks not exactly once");
    dispatch_semaphore_t finished=dispatch_semaphore_create(0);__block NSError *finError=nil;
    [stream sendContent:nil isComplete:YES completion:^(NSError *error){finError=error;dispatch_semaphore_signal(finished);}];wait(finished,"Bridge FIN timed out");expect(!finError,"Bridge FIN failed");
    Buffer tail;bool eof=false;for(unsigned i=0;i<20&&!eof;++i)append(tail,read(stream,3,&eof));expect(eof&&tail==bytes("AFTER-FIN"),"Bridge half-close killed downlink");
    [stream cancel];[value cancel];peer.join();
}
void pinnedDNSBridge(dispatch_queue_t queue){
    NSData *unresolved=[NSJSONSerialization dataWithJSONObject:
        @{ @"type":@"http",@"host":@"never-resolve.invalid",@"port":@1,@"name":@"unresolved",@"parameters":@{} } options:0 error:nil];
    HJCppProtocolClient *blocked=client(unresolved,queue);NSError *error=nil;
    HJCppByteStream *stream=connect(blocked,&error);
    expect(!stream&&error&&[error.localizedDescription containsString:@"encrypted DNS"],"Unpinned hostname reached the system DNS transport");
    [blocked cancel];
    NSData *invalidPin=[NSJSONSerialization dataWithJSONObject:
        @{ @"type":@"http",@"host":@"never-resolve.invalid",@"connectHost":@"another.invalid",@"port":@1,@"name":@"bad-pin",@"parameters":@{} } options:0 error:nil];
    NSError *pinError=nil;auto invalid=[[HJCppProtocolClient alloc]initWithConfiguration:invalidPin interfaceName:nil queue:queue preparedTransportDialer:nil error:&pinError];
    expect(!invalid&&pinError,"Hostname bootstrap masquerading as a numeric pin was accepted");
    TCPPeer peer([](int fd){auto header=connectHeader(fd);expect(std::string(header.begin(),header.end()).find("CONNECT destination.example:443 HTTP/1.1\r\n")==0,
        "Pinned first-hop address replaced the application destination");sendAll(fd,bytes("HTTP/1.1 200 Connected\r\n\r\nPINNED"));});
    NSData *pinned=[NSJSONSerialization dataWithJSONObject:
        @{ @"type":@"http",@"host":@"proxy.example.invalid",@"connectHost":@"127.0.0.1",@"port":@(peer.port),@"name":@"safe-pin",@"parameters":@{} } options:0 error:nil];
    auto safe=client(pinned,queue);auto connected=connect(safe);Buffer answer;
    while(answer.size()<6)append(answer,read(connected));expect(answer==bytes("PINNED"),"Numeric bootstrap did not connect to the pinned proxy IP");
    [connected cancel];[safe cancel];peer.join();
    Node named;named.type="https";named.host="proxy.example.invalid";named.connectHost="127.0.0.1";
    expect(tlsOptions(named,true).serverName==named.host,"Numeric proxy address replaced the original TLS certificate identity");
    named.parameters["sni"]="";
    expect(tlsOptions(named,true).serverName==named.host,"Empty SNI lost the original hostname after numeric pinning");
}
void preparedCancellation(dispatch_queue_t queue){
    __block HJDataReadCompletion heldRead=nil;__block HJStreamWriteCompletion heldWrite=nil;__block NSUInteger sendCount=0;
    auto cancelCalls=std::make_shared<std::atomic<unsigned>>(0);
    dispatch_semaphore_t nativeCanceled=dispatch_semaphore_create(0);
    HJCallbackStream *carrier=[[HJCallbackStream alloc]initWithQueue:queue supportsHalfClose:YES receiveHandler:^(NSUInteger,HJDataReadCompletion complete){heldRead=[complete copy];}
        sendHandler:^(NSData *,BOOL,HJStreamWriteCompletion complete){if(sendCount++==0)complete(nil);else heldWrite=[complete copy];}
        cancelHandler:^{++*cancelCalls;dispatch_semaphore_signal(nativeCanceled);}];
    HJCppTransportDialer dialer=^(void (^complete)(id<HJByteStream>,NSError *)){complete(carrier,nil);};
    HJCppProtocolClient *value=client(configuration(@"vless",1,@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff"}),queue,dialer);
    HJCppByteStream *stream=connect(value);auto completed=std::make_shared<std::atomic<unsigned>>(0),readCompleted=std::make_shared<std::atomic<unsigned>>(0);
    auto valid=std::make_shared<std::atomic<bool>>(true);dispatch_group_t group=dispatch_group_create();NSData *payload=data(Buffer(16384,0x41));
    for(unsigned i=0;i<128;++i){dispatch_group_enter(group);[stream sendData:payload completion:^(NSError *error){if(!error)valid->store(false);++*completed;dispatch_group_leave(group);}];}
    dispatch_semaphore_t overflow=dispatch_semaphore_create(0);__block NSError *overflowError=nil;
    [stream sendData:[NSData dataWithBytes:"x" length:1] completion:^(NSError *error){overflowError=error;dispatch_semaphore_signal(overflow);}];
    wait(overflow,"Bridge queue cap callback timed out");expect(overflowError!=nil,"Bridge byte/request admission cap ignored");
    dispatch_semaphore_t readDone=dispatch_semaphore_create(0);[stream receiveDataWithMaximum:64 completion:^(NSData *,BOOL eof,NSError *error){
        if(!eof||!error)valid->store(false);++*readCompleted;dispatch_semaphore_signal(readDone);}];
    dispatch_sync(queue,^{});[stream cancel];[value cancel];wait(readDone,"Bridge canceled read callback missing");
    expect(dispatch_group_wait(group,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC))==0,"Bridge canceled write callbacks missing");
    wait(nativeCanceled,"Prepared carrier cancel handler missing");
    dispatch_sync(queue,^{if(heldRead){heldRead([NSData data],YES,nil);heldRead([NSData data],YES,nil);}if(heldWrite){heldWrite(nil);heldWrite(nil);}});
    dispatch_sync(queue,^{});expect(valid->load()&&completed->load()==128&&readCompleted->load()==1&&cancelCalls->load()==1,"Bridge cancellation/late-completion contract violated");
    __block void (^lateReady)(id<HJByteStream>,NSError *)=nil;HJCppProtocolClient *pending=client(configuration(@"vless",1,@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff"}),queue,
        ^(void (^complete)(id<HJByteStream>,NSError *)){lateReady=[complete copy];});
    auto connected=std::make_shared<std::atomic<unsigned>>(0);dispatch_semaphore_t canceled=dispatch_semaphore_create(0);
    [pending connectToHost:@"destination.example" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *result,NSError *error){if(result||!error)valid->store(false);++*connected;dispatch_semaphore_signal(canceled);}];
    [pending cancel];wait(canceled,"Bridge pending connect cancel missing");dispatch_sync(queue,^{if(lateReady)lateReady(carrier,nil);});dispatch_sync(queue,^{});
    expect(valid->load()&&connected->load()==1,"Late dial completion repeated canceled connect");
}
void physicalDialerMemory(dispatch_queue_t queue){
    for(bool skipVerify:{false,true}){
        auto calls=std::make_shared<std::atomic<unsigned>>(0),closes=std::make_shared<std::atomic<unsigned>>(0);
        auto valid=std::make_shared<std::atomic<bool>>(true);
        __block dispatch_block_t readyCancel=nil;
        HJCppPhysicalTransportDialer physical=^dispatch_block_t(NSString *host,uint16_t port,BOOL tls,NSString *serverName,
            BOOL skip,NSArray<NSString *> *alpn,NSString *interface,void (^complete)(id<HJByteStream>,NSError *)){
            ++*calls;
            if(![host isEqualToString:@"203.0.113.41"]||port!=443||!tls||skip!=skipVerify
                ||![serverName isEqualToString:@"identity.example.invalid"]||![alpn isEqualToArray:@[@"http/1.1"]]
                ||![interface isEqualToString:@"en-memory-fixture"])valid->store(false);
            HJCallbackStream *carrier=[[HJCallbackStream alloc]initWithQueue:queue supportsHalfClose:YES
                receiveHandler:^(NSUInteger,HJDataReadCompletion done){done(data(bytes("HTTP/1.1 200 Connected\r\n\r\nMETA")),NO,nil);}
                sendHandler:^(NSData *payload,BOOL,HJStreamWriteCompletion done){
                    auto wire=buffer(payload);std::string text(wire.begin(),wire.end());
                    if(text.find("CONNECT destination.example:443 HTTP/1.1\r\n")!=0)valid->store(false);done(nil);}
                cancelHandler:^{++*closes;}];
            complete(carrier,nil);
            // This is the native beginConnect contract: after readiness its
            // pending cancellation handle does not close the accepted carrier.
            readyCancel=^{};
            return readyCancel;
        };
        NSData *config=[NSJSONSerialization dataWithJSONObject:@{@"type":@"https",@"name":@"physical-memory",
            @"host":@"original.node.invalid",@"connectHost":@"203.0.113.41",@"port":@443,
            @"parameters":@{@"sni":@"identity.example.invalid",@"skip-cert-verify":skipVerify?@"true":@"false",@"alpn":@"http/1.1"}}
            options:0 error:nil];
        NSError *error=nil;
        auto value=[[HJCppProtocolClient alloc]initWithConfiguration:config interfaceName:@"en-memory-fixture" queue:queue
            preparedTransportDialer:nil physicalTransportDialer:physical error:&error];
        expect(value&&!error,"Physical dialer additive initializer failed");
        for(unsigned index=0;index<2;++index){auto stream=connect(value);readyCancel();
            expect(read(stream,4)==bytes("META"),"After-ready physical cancel changed the accepted transport");[stream cancel];}
        [value cancel];dispatch_sync(queue,^{});
        expect(valid->load()&&calls->load()==2,"Physical hook lost TLS/SNI/ALPN/interface or stable-client fresh dial");
    }
    auto hookCalls=std::make_shared<std::atomic<unsigned>>(0),cancels=std::make_shared<std::atomic<unsigned>>(0);
    auto callbacks=std::make_shared<std::atomic<unsigned>>(0),lateCloses=std::make_shared<std::atomic<unsigned>>(0);
    auto valid=std::make_shared<std::atomic<bool>>(true);
    dispatch_semaphore_t started=dispatch_semaphore_create(0),done=dispatch_semaphore_create(0),lateClosed=dispatch_semaphore_create(0);
    __block void (^lateReady)(id<HJByteStream>,NSError *)=nil;
    HJCppPhysicalTransportDialer pending=^dispatch_block_t(NSString *,uint16_t,BOOL,NSString *,BOOL,NSArray<NSString *> *,NSString *,
        void (^complete)(id<HJByteStream>,NSError *)){
        ++*hookCalls;lateReady=[complete copy];dispatch_semaphore_signal(started);
        return ^{++*cancels;complete(nil,[NSError errorWithDomain:@"memory-cancel" code:1 userInfo:nil]);};
    };
    NSError *creationError=nil;
    auto value=[[HJCppProtocolClient alloc]initWithConfiguration:configuration(@"vless",1,@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff"})
        interfaceName:nil queue:queue preparedTransportDialer:nil physicalTransportDialer:pending error:&creationError];
    expect(value&&!creationError,"Pending physical client creation failed");
    [value connectToHost:@"destination.example" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *stream,NSError *error){
        if(stream||!error)valid->store(false);++*callbacks;dispatch_semaphore_signal(done);}];
    wait(started,"Physical fixture did not start");[value cancel];[value cancel];wait(done,"Physical cancellation callback missing");
    HJCallbackStream *late=[[HJCallbackStream alloc]initWithQueue:queue supportsHalfClose:YES
        receiveHandler:^(NSUInteger,HJDataReadCompletion complete){complete(nil,YES,nil);}
        sendHandler:^(NSData *,BOOL,HJStreamWriteCompletion complete){valid->store(false);complete(nil);}
        cancelHandler:^{++*lateCloses;dispatch_semaphore_signal(lateClosed);}];
    lateReady(late,nil);wait(lateClosed,"Late physical result was not closed");dispatch_sync(queue,^{});
    expect(valid->load()&&hookCalls->load()==1&&cancels->load()==1&&callbacks->load()==1&&lateCloses->load()==1,
           "Physical attempt cancellation/late-result ownership failed");

    // Old prepared carriers have precedence and keep their old semantics.
    HJCallbackStream *prepared=[[HJCallbackStream alloc]initWithQueue:queue supportsHalfClose:YES
        receiveHandler:^(NSUInteger,HJDataReadCompletion complete){complete(nil,YES,nil);}
        sendHandler:^(NSData *,BOOL,HJStreamWriteCompletion complete){complete(nil);}cancelHandler:^{}];
    auto before=hookCalls->load();
    auto chained=[[HJCppProtocolClient alloc]initWithConfiguration:configuration(@"vless",1,@{@"uuid":@"00112233-4455-6677-8899-aabbccddeeff"})
        interfaceName:nil queue:queue preparedTransportDialer:^(void (^complete)(id<HJByteStream>,NSError *)){complete(prepared,nil);}
        physicalTransportDialer:pending error:&creationError];
    expect(chained&&!creationError,"Prepared-plus-physical initializer failed");
    auto stream=connect(chained);[stream cancel];[chained cancel];
    expect(hookCalls->load()==before,"Physical hook replaced the prepared/chained carrier");
    NSData *unresolved=[NSJSONSerialization dataWithJSONObject:@{@"type":@"http",@"host":@"never-resolve.invalid",@"port":@1,@"parameters":@{}} options:0 error:nil];
    auto blocked=[[HJCppProtocolClient alloc]initWithConfiguration:unresolved interfaceName:nil queue:queue
        preparedTransportDialer:nil physicalTransportDialer:pending error:&creationError];
    NSError *failure=nil;stream=connect(blocked,&failure);
    expect(!stream&&failure&&hookCalls->load()==before,"A nonliteral hostname reached the physical hook/system resolver");[blocked cancel];
}
int64_t monotonicNanos(){return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
void pendingTLSCancellation(dispatch_queue_t queue,bool cppClient){
    dispatch_semaphore_t started=dispatch_semaphore_create(0),peerClosed=dispatch_semaphore_create(0),done=dispatch_semaphore_create(0);
    auto peerCloseTime=std::make_shared<std::atomic<int64_t>>(0),callbackTime=std::make_shared<std::atomic<int64_t>>(0);
    auto callbacks=std::make_shared<std::atomic<unsigned>>(0);auto valid=std::make_shared<std::atomic<bool>>(true);
    // No TLS response is sent. Reading ClientHello proves the native pending
    // transport exists; EOF/reset proves cancel closes it, not just its callback.
    TCPPeer peer([started,peerClosed,peerCloseTime](int fd){
        uint8_t input[4096];ssize_t first=recv(fd,input,sizeof(input),0);expect(first>0,"TLS blackhole never received native ClientHello");
        dispatch_semaphore_signal(started);
        for(;;){ssize_t n=recv(fd,input,sizeof(input),0);if(n>0)continue;
            expect(n==0||(n<0&&errno==ECONNRESET),"Pending TLS attempt stayed open until socket timeout");
            peerCloseTime->store(monotonicNanos());dispatch_semaphore_signal(peerClosed);return;}
    });
    HJCppProtocolClient *value=nil;dispatch_block_t cancel=nil;
    if(cppClient){value=client(configuration(@"https",peer.port,@{@"sni":@"localhost",@"skip-cert-verify":@"true"}),queue);
        [value connectToHost:@"destination.example" port:443 udp:NO plainHTTP:NO completion:^(HJCppByteStream *result,NSError *error){
            if(result||!error)valid->store(false);callbackTime->store(monotonicNanos());++*callbacks;dispatch_semaphore_signal(done);}];
    }else cancel=[HJNetworkStream beginConnectToHost:@"127.0.0.1" port:peer.port tls:YES serverName:@"localhost" skipCertificateVerification:YES
        alpn:@[@"http/1.1"] interfaceName:nil queue:queue timeout:12 completion:^(HJNetworkStream *result,NSError *error){
            if(result||!error||error.code!=HJProxyRuntimeErrorCancelled)valid->store(false);callbackTime->store(monotonicNanos());++*callbacks;dispatch_semaphore_signal(done);}];
    wait(started,"Pending TLS cancellation fixture never started");expect(callbacks->load()==0,"TLS blackhole became ready without peer handshake");
    int64_t requested=monotonicNanos();if(cppClient)[value cancel];else{cancel();cancel();}
    wait(done,"Pending TLS cancel completion missing");wait(peerClosed,"Pending TLS cancellation failed to close actual peer socket");peer.join();
    expect(valid->load()&&callbacks->load()==1,"Pending TLS cancel completed incorrectly/more than once");
    expect(callbackTime->load()-requested>=0&&callbackTime->load()-requested<=500000000,"Pending TLS callback cancellation exceeded 500ms");
    expect(peerCloseTime->load()-requested>=0&&peerCloseTime->load()-requested<=500000000,"Pending TLS peer FD remained open beyond 500ms");
    if(cppClient)[value cancel];else cancel();dispatch_sync(queue,^{});CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.025,true);
    expect(callbacks->load()==1,"Late native TLS event repeated cancel completion");
    std::cout<<(cppClient?"C++ client":"Native beginConnect")<<" pending TLS cancel: callback "
        <<(callbackTime->load()-requested)/1000000.0<<"ms, peer EOF "<<(peerCloseTime->load()-requested)/1000000.0<<"ms\n";
}
void readyCancelClosure(dispatch_queue_t queue){
    TCPPeer peer([](int fd){expect(receiveExactly(fd,4)==bytes("PING"),"After-ready cancellation closed native stream");sendAll(fd,bytes("PONG"));});
    dispatch_semaphore_t connected=dispatch_semaphore_create(0),written=dispatch_semaphore_create(0);
    __block HJNetworkStream *stream=nil;__block NSError *failure=nil;auto callbacks=std::make_shared<std::atomic<unsigned>>(0);
    dispatch_block_t cancel=[HJNetworkStream beginConnectToHost:@"127.0.0.1" port:peer.port tls:NO serverName:nil skipCertificateVerification:NO alpn:@[]
        interfaceName:nil queue:queue timeout:12 completion:^(HJNetworkStream *result,NSError *error){stream=result;failure=error;++*callbacks;dispatch_semaphore_signal(connected);}];
    wait(connected,"Native ready stream fixture timed out");expect(stream&&!failure,"Native TCP did not become ready");cancel();cancel();
    [stream sendData:data(bytes("PING")) completion:^(NSError *error){failure=error;dispatch_semaphore_signal(written);}];wait(written,"After-ready cancel killed write");expect(!failure,"Ready stream write failed after cancel closure");
    Buffer reply;for(unsigned i=0;i<10&&reply.size()<4;++i){dispatch_semaphore_t received=dispatch_semaphore_create(0);__block NSData *payload=nil;
        [stream receiveDataWithMaximum:4 completion:^(NSData *result,BOOL,NSError *error){payload=result;failure=error;dispatch_semaphore_signal(received);}];
        wait(received,"After-ready cancel killed read");expect(!failure,"Ready stream read failed after cancel closure");append(reply,buffer(payload));}
    expect(reply==bytes("PONG")&&callbacks->load()==1,"After-ready cancel changed stream/connect callback");peer.join();[stream cancel];
}
std::shared_ptr<SSL_CTX> tlsContext(){
    std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> generator(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr),EVP_PKEY_CTX_free);
    EVP_PKEY *rawKey=nullptr;expect(generator&&EVP_PKEY_keygen_init(generator.get())==1&&EVP_PKEY_CTX_set_rsa_keygen_bits(generator.get(),2048)==1&&EVP_PKEY_keygen(generator.get(),&rawKey)==1,"Test TLS key generation failed");
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(rawKey,EVP_PKEY_free);
    std::unique_ptr<X509,decltype(&X509_free)> certificate(X509_new(),X509_free);expect(bool(certificate),"Test certificate allocation failed");
    X509_set_version(certificate.get(),2);ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()),1);
    X509_gmtime_adj(X509_getm_notBefore(certificate.get()),-60);X509_gmtime_adj(X509_getm_notAfter(certificate.get()),3600);
    X509_set_pubkey(certificate.get(),key.get());X509_NAME *name=X509_get_subject_name(certificate.get());
    X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char *>("localhost"),-1,-1,0);X509_set_issuer_name(certificate.get(),name);
    X509V3_CTX extensionContext;X509V3_set_ctx(&extensionContext,certificate.get(),certificate.get(),nullptr,nullptr,0);
    X509_EXTENSION *san=X509V3_EXT_conf_nid(nullptr,&extensionContext,NID_subject_alt_name,const_cast<char *>("DNS:localhost,IP:127.0.0.1"));
    expect(san&&X509_add_ext(certificate.get(),san,-1)==1,"Test certificate SAN failed");X509_EXTENSION_free(san);
    expect(X509_sign(certificate.get(),key.get(),EVP_sha256())>0,"Test certificate signature failed");
    std::shared_ptr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()),SSL_CTX_free);expect(bool(context),"TLS context allocation failed");
    expect(SSL_CTX_set_min_proto_version(context.get(),TLS1_2_VERSION)==1&&SSL_CTX_use_certificate(context.get(),certificate.get())==1&&
        SSL_CTX_use_PrivateKey(context.get(),key.get())==1&&SSL_CTX_check_private_key(context.get())==1,"TLS context setup failed");return context;
}
void tlsBridge(dispatch_queue_t queue){auto context=tlsContext();
    for(bool skipVerify:{false,true}){std::cerr<<"Bridge TLS: "<<(skipVerify?"explicit test bypass":"strict trust")<<"\n";
        TCPPeer peer([context,skipVerify](int fd){std::unique_ptr<SSL,decltype(&SSL_free)> tls(SSL_new(context.get()),SSL_free);
        expect(tls&&SSL_set_fd(tls.get(),fd)==1,"TLS peer setup failed");int accepted=SSL_accept(tls.get());if(!skipVerify&&accepted!=1)return;
        expect(accepted==1,"Native TLS transport handshake failed");Buffer header;uint8_t byte=0;
        while(header.size()<65536){if(SSL_read(tls.get(),&byte,1)!=1){if(!skipVerify)return;throw std::runtime_error("TLS HTTP peer header missing");}header.push_back(byte);
            if(header.size()>=4&&part(header,header.size()-4,4)==bytes("\r\n\r\n"))break;}
        expect(std::string(header.begin(),header.end()).find("CONNECT destination.example:443 HTTP/1.1\r\n")==0,"TLS proxy request not C++ HTTP CONNECT");
        Buffer response=bytes("HTTP/1.1 200 TLS Connected\r\n\r\nTLS-OK");expect(SSL_write(tls.get(),response.data(),int(response.size()))==int(response.size()),"TLS peer response failed");
        uint8_t input[4]{};size_t count=0;while(count<4){int n=SSL_read(tls.get(),input+count,int(4-count));if(n<=0)throw std::runtime_error("TLS bridge payload missing");count+=size_t(n);}
        expect(Buffer(input,input+4)==bytes("PING"),"TLS bridge payload corrupted");SSL_shutdown(tls.get());});
        NSDictionary *parameters=skipVerify?@{@"sni":@"localhost",@"skip-cert-verify":@"true"}:@{@"sni":@"localhost"};
        HJCppProtocolClient *value=client(configuration(@"https",peer.port,parameters),queue);NSError *error=nil;HJCppByteStream *stream=connect(value,&error);
        if(!skipVerify){if(error)std::cerr<<"Strict TLS rejection: "<<error.localizedDescription.UTF8String<<"\n";
            expect(!stream&&error,"Native TLS failed to validate untrusted certificate");}
        else{expect(stream&&!error,"Explicit test TLS skip-verify did not connect");Buffer reply;while(reply.size()<6)append(reply,read(stream,3));
            expect(reply==bytes("TLS-OK"),"TLS CONNECT leftover lost");write(stream,bytes("PING"));}
        peer.join();[stream cancel];[value cancel];}
}
class UDPPeer {
public:
    uint16_t port=0;
private:
    Socket socket_;std::thread worker_;std::exception_ptr failure_;
public:
    explicit UDPPeer(std::function<void(int)> peer):socket_(listenSocket(SOCK_DGRAM,port)){worker_=std::thread([this,peer]{try{peer(socket_.fd);}catch(...){failure_=std::current_exception();}});}
    void join(){if(worker_.joinable())worker_.join();if(failure_)std::rethrow_exception(failure_);}
    ~UDPPeer(){if(worker_.joinable()){shutdown(socket_.fd,SHUT_RDWR);worker_.join();}}
};
Buffer ssSubkey(const Buffer &psk,const Buffer &salt){Buffer material=psk;append(material,salt);return crypto::blake3DeriveKey("shadowsocks 2022 session subkey",material,16);}
void udpBridge(dispatch_queue_t queue){Buffer psk;for(uint8_t i=1;i<=16;++i)psk.push_back(i);
    UDPPeer peer([psk](int fd){Buffer wire(65535);sockaddr_storage address{};socklen_t addressLength=sizeof(address);
        ssize_t count=recvfrom(fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr *>(&address),&addressLength);expect(count>32,"Bridge UDP query absent");wire.resize(size_t(count));
        Buffer separate=crypto::aesECBBlock(part(wire,0,16),psk,false),clientSession=part(separate,0,8);
        Buffer body=crypto::open(crypto::AEAD::AES128GCM,ssSubkey(psk,clientSession),part(separate,4,12),part(wire,16,wire.size()-16));
        expect(body[0]==0,"Bridge SS2022 UDP wrong packet type");size_t cursor=11+get16(body,9),consumed=0;
        Target target=parseSocksAddress(part(body,cursor,body.size()-cursor),consumed);cursor+=consumed;
        expect(target.host=="dns.example"&&target.port==53&&part(body,cursor,body.size()-cursor)==bytes("query"),"Bridge UDP target/payload corrupted");
        Buffer serverSession(8,0xa5);
        auto response=[&](uint64_t id,const Buffer &payload){Buffer header=serverSession;put64(header,id);Buffer plain{1};put64(plain,unixSeconds());append(plain,clientSession);put16(plain,0);
            append(plain,socksAddress(target));append(plain,payload);Buffer out=crypto::aesECBBlock(header,psk);
            append(out,crypto::seal(crypto::AEAD::AES128GCM,ssSubkey(psk,serverSession),part(header,4,12),plain));return out;};
        Buffer first=response(0,bytes("first")),second=response(1,bytes("second"));
        for(const auto &packet:{first,first,second})expect(sendto(fd,packet.data(),packet.size(),0,reinterpret_cast<sockaddr *>(&address),addressLength)==ssize_t(packet.size()),"UDP reference peer response failed");
    });
    NSString *password=[NSString stringWithUTF8String:crypto::base64Encode(psk).c_str()];HJCppProtocolClient *value=client(configuration(@"ss",peer.port,
        @{@"cipher":@"2022-blake3-aes-128-gcm",@"password":password}),queue);
    __block HJCppDatagramSession *session=nil;__block NSError *creationError=nil;dispatch_semaphore_t ready=dispatch_semaphore_create(0),second=dispatch_semaphore_create(0);
    auto receives=std::make_shared<std::atomic<unsigned>>(0);auto valid=std::make_shared<std::atomic<bool>>(true);
    [value createDatagramSessionWithReceive:^(NSString *host,uint16_t port,NSData *payload){++*receives;if(![host isEqualToString:@"dns.example"]||port!=53)valid->store(false);
        Buffer received=buffer(payload);if(received!=bytes("first")&&received!=bytes("second"))valid->store(false);if(received==bytes("second"))dispatch_semaphore_signal(second);
    } failure:^(NSError *){valid->store(false);} completion:^(HJCppDatagramSession *result,NSError *error){session=result;creationError=error;dispatch_semaphore_signal(ready);}];
    wait(ready,"Bridge UDP session create timed out");expect(session&&!creationError,"Bridge UDP session create failed");
    dispatch_semaphore_t sent=dispatch_semaphore_create(0);__block NSError *sendError=nil;
    [session sendPayload:data(bytes("query")) host:@"dns.example" port:53 completion:^(NSError *error){sendError=error;dispatch_semaphore_signal(sent);}];
    wait(sent,"Bridge UDP query send timed out");expect(!sendError,"Bridge UDP query send failed");wait(second,"Bridge UDP replies timed out");
    expect(valid->load()&&receives->load()==2,"Bridge UDP dropped/corrupted packet or replay delivered");[session cancel];[value cancel];peer.join();
}
}
int main(int argc,char **argv){@autoreleasepool{const char *phase="real TCP";try{
    dispatch_queue_t queue=dispatch_queue_create("app.hajimi.cpp-bridge-smoke",DISPATCH_QUEUE_SERIAL);
    std::string selected=argc>1?argv[1]:"all";
    expect(selected=="all"||selected=="tcp"||selected=="cancel"||selected=="pending"||selected=="tls"||selected=="udp"||selected=="dns"||selected=="physical"||selected=="fragmented"||selected=="errors","Unknown bridge smoke selector");
    phase="memory-only native error preservation";if(selected=="all"||selected=="errors"){
        bridgeErrorRoundTrip(queue);bridgeErrorARCLifetime(queue);bridgeErrorScopes(queue);
        bridgeAnyTLSErrorFanout(queue,false,false);bridgeAnyTLSErrorFanout(queue,false,true);bridgeAnyTLSErrorFanout(queue,true,false);
    }
    if(selected=="all"||selected=="tcp")tcpBridge(queue);
    phase="memory-only fragmented receive";if(selected=="all"||selected=="fragmented")fragmentedBridge(queue);
    phase="pinned DNS";if(selected=="all"||selected=="dns")pinnedDNSBridge(queue);
    phase="prepared carrier cancellation";if(selected=="all"||selected=="cancel")preparedCancellation(queue);
    phase="memory-only physical dialer";if(selected=="all"||selected=="physical"){
        physicalDialerMemory(queue);if(selected=="physical")preparedCancellation(queue);}
    phase="pending native transport cancellation";if(selected=="all"||selected=="pending"){
        pendingTLSCancellation(queue,true);pendingTLSCancellation(queue,false);readyCancelClosure(queue);}
    phase="real TLS";if(selected=="all"||selected=="tls")tlsBridge(queue);
    phase="real UDP";if(selected=="all"||selected=="udp")udpBridge(queue);
    std::cout<<"C++ Objective-C bridge smoke passed: "<<checks.load()<<" checks\n";return 0;
}catch(const std::exception &error){std::cerr<<"C++ bridge smoke failed ["<<phase<<"]: "<<error.what()<<"\n";return 1;}}}
