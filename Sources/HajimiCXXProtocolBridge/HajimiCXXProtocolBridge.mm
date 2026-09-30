#import "HajimiCXXProtocolBridge.h"
#import <Network/Network.h>
#include "Runtime.hpp"
#include "AnyTLS.hpp"
#include "ServerProtocols.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cmath>
#include <deque>
#include <limits>
#include <net/if.h>
#include <stdexcept>
#include <utility>

NSErrorDomain const HJCppProtocolErrorDomain=@"app.hajimi.cpp-protocol";
namespace {
using namespace hajimi;
NSError *nativeError(const Error &error) {
    if(error.empty())return nil;
    NSString *message=[[NSString alloc]initWithBytes:error.data() length:error.size() encoding:NSUTF8StringEncoding];
    return [NSError errorWithDomain:HJCppProtocolErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey:message?:@"Native protocol failure"}];
}
Error cppError(NSError *error) {return error ? Error(error.localizedDescription.UTF8String?:"Platform transport failed") : Error{};}
std::string cppString(NSString *value){
    if(!value)return {};NSData *encoded=[value dataUsingEncoding:NSUTF8StringEncoding];
    if(!encoded)throw std::runtime_error("Invalid Unicode text");if(!encoded.length)return {};
    return std::string(static_cast<const char *>(encoded.bytes),encoded.length);
}
Buffer buffer(NSData *data) {
    if(!data.length)return {};
    auto begin=static_cast<const uint8_t *>(data.bytes);return Buffer(begin,begin+data.length);
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
Node decode(NSData *configuration) {
    if(configuration.length>1024*1024)throw std::runtime_error("Protocol configuration is too large");
    NSError *error=nil;id parsed=[NSJSONSerialization JSONObjectWithData:configuration options:0 error:&error];
    if(![parsed isKindOfClass:NSDictionary.class])throw std::runtime_error("Invalid protocol configuration JSON");
    NSDictionary *object=parsed;Node node;
    for(NSString *key in @[@"type",@"host",@"name"]){id value=object[key];if(value && ![value isKindOfClass:NSString.class])throw std::runtime_error("Invalid protocol configuration field");}
    node.type=cppString([object[@"type"] lowercaseString]);node.host=cppString(object[@"host"]);node.name=cppString(object[@"name"]);
    id port=object[@"port"];if(![port isKindOfClass:NSNumber.class] || [port doubleValue]!=[port unsignedIntValue] || [port unsignedIntValue]>65535)throw std::runtime_error("Invalid proxy port");
    node.port=uint16_t([port unsignedIntValue]);
    id parameters=object[@"parameters"];
    if(parameters && ![parameters isKindOfClass:NSDictionary.class])throw std::runtime_error("Invalid protocol parameters");
    for(id key in parameters){id value=parameters[key];if(![key isKindOfClass:NSString.class] || ![value isKindOfClass:NSString.class])throw std::runtime_error("Protocol parameters must be strings");
        auto name=cppString(key);if(name.find('\0')!=std::string::npos)throw std::runtime_error("Invalid protocol option name");node.parameters[name]=cppString(value);
    }
    return node;
}
void post(dispatch_queue_t queue,std::function<void()> work){dispatch_async(queue,^{@autoreleasepool{work();}});}
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
            NSData *payload=mapped(content);auto value=buffer(payload);auto failure=cppError(error);
            post(self->queue_,[self,completion,value=std::move(value),eof,failure]()mutable{completion(std::move(value),eof,failure);});
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

class PlatformDatagram final:public Datagram,public std::enable_shared_from_this<PlatformDatagram>{
    nw_connection_t connection_;dispatch_queue_t queue_;Target peer_;bool closed_=false,started_=false;
    PacketCallback receive_;WriteCallback failure_;
    void read(){
        if(closed_ || !started_)return;auto self=shared_from_this();
        nw_connection_receive_message(connection_,^(dispatch_data_t content,nw_content_context_t,bool,nw_error_t error){
            auto payload=buffer(mapped(content));Error failure=error?"UDP transport receive failed":Error{};
            post(self->queue_,[self,payload=std::move(payload),failure]()mutable{
                if(self->closed_)return;
                if(!failure.empty()){
                    auto callback=std::move(self->failure_);self->close();if(callback)callback(failure);return;
                }
                if(self->receive_)self->receive_(self->peer_,std::move(payload));self->read();
            });
        });
    }
public:
    PlatformDatagram(nw_connection_t connection,dispatch_queue_t queue,Target peer):connection_(connection),queue_(queue),peer_(std::move(peer)){}
    ~PlatformDatagram(){nw_connection_cancel(connection_);}
    void send(Target,Buffer value,WriteCallback completion)override{
        if(closed_){completion("UDP transport closed");return;}
        if(value.size()>65507){completion("UDP packet exceeds wire limit");return;}
        NSData *payload=data(std::move(value));auto self=shared_from_this();
        auto dispatchBytes=dispatch_data_create(payload.bytes,payload.length,nullptr,^{(void)payload;});
        nw_connection_send(connection_,dispatchBytes,NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,true,^(nw_error_t error){
            Error failure=error?"UDP transport send failed":Error{};post(self->queue_,[self,completion,failure]{completion(failure);});
        });
    }
    void start(PacketCallback receive,WriteCallback failure)override{
        if(closed_){failure("UDP transport closed");return;}if(started_){failure("UDP receiver already started");return;}
        started_=true;receive_=std::move(receive);failure_=std::move(failure);read();
    }
    void close()override{if(closed_)return;closed_=true;receive_=nullptr;failure_=nullptr;nw_connection_cancel(connection_);}
};

class UDPAttempt:public std::enable_shared_from_this<UDPAttempt>{
    Node node_;dispatch_queue_t queue_;DatagramCallback completion_;
    nw_parameters_t parameters_;nw_connection_t connection_;nw_path_monitor_t monitor_;dispatch_source_t timer_;
    std::shared_ptr<UDPAttempt> keepAlive_;bool finished_=false;
    void finish(std::shared_ptr<Datagram> value,Error error){
        if(finished_)return;finished_=true;
        if(timer_){dispatch_source_cancel(timer_);timer_=nil;}
        if(monitor_){nw_path_monitor_cancel(monitor_);monitor_=nil;}
        if(connection_){nw_connection_set_state_changed_handler(connection_,nil);if(!value)nw_connection_cancel(connection_);}
        auto callback=std::move(completion_);auto retained=std::move(keepAlive_);callback(std::move(value),std::move(error));
    }
    void dial(){
        if(finished_ || connection_)return;
        auto endpoint=nw_endpoint_create_host(node_.host.c_str(),std::to_string(node_.port).c_str());
        connection_=nw_connection_create(endpoint,parameters_);if(!connection_){finish(nullptr,"Unable to create native UDP connection");return;}
        std::weak_ptr<UDPAttempt> weak=shared_from_this();nw_connection_set_queue(connection_,queue_);
        nw_connection_set_state_changed_handler(connection_,^(nw_connection_state_t state,nw_error_t){
            if(auto self=weak.lock()){
                if(state==nw_connection_state_ready){Target peer{self->node_.host,self->node_.port,true,false};self->finish(std::make_shared<PlatformDatagram>(self->connection_,self->queue_,std::move(peer)),{});}
                else if(state==nw_connection_state_failed || state==nw_connection_state_cancelled)self->finish(nullptr,"Native UDP connection failed");
            }
        });
        nw_connection_start(connection_);
    }
public:
    UDPAttempt(Node node,dispatch_queue_t queue,DatagramCallback callback):node_(std::move(node)),queue_(queue),completion_(std::move(callback)){}
    void cancel(){finish(nullptr,"Native UDP connection cancelled");}
    void start(){
        keepAlive_=shared_from_this();
        if(node_.host.empty() || !node_.port){finish(nullptr,"Invalid UDP endpoint");return;}
        parameters_=nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,NW_PARAMETERS_DEFAULT_CONFIGURATION);
        if(!parameters_){finish(nullptr,"Unable to create native UDP parameters");return;}
        std::weak_ptr<UDPAttempt> weak=shared_from_this();
        timer_=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,queue_);
        dispatch_source_set_timer(timer_,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),DISPATCH_TIME_FOREVER,0);
        dispatch_source_set_event_handler(timer_,^{if(auto self=weak.lock())self->finish(nullptr,"Native UDP connection timed out");});dispatch_resume(timer_);
        if(node_.interfaceName.empty() || loopback(node_.host)){dial();return;}
        if(!if_nametoindex(node_.interfaceName.c_str())){finish(nullptr,"Required outbound interface does not exist");return;}
        monitor_=nw_path_monitor_create();nw_path_monitor_set_queue(monitor_,queue_);
        nw_path_monitor_set_update_handler(monitor_,^(nw_path_t path){
            if(auto self=weak.lock()){
                if(self->finished_ || self->connection_)return;
                __block nw_interface_t selected=nil;
                nw_path_enumerate_interfaces(path,^bool(nw_interface_t interface){
                    auto name=nw_interface_get_name(interface);if(name && self->node_.interfaceName==name){selected=interface;return false;}return true;
                });
                if(!selected)return;
                nw_parameters_require_interface(self->parameters_,selected);self->dial();
            }
        });nw_path_monitor_start(monitor_);
    }
};

struct Context:std::enable_shared_from_this<Context>{
    Node node;dispatch_queue_t queue,output;HJCppTransportDialer dialer;
    std::shared_ptr<TransportFactory> factory;bool closed=false;uint64_t nextOperation=0;
    std::atomic<bool> cancellationSignal{false};uint64_t nextAttempt=0;
    std::unordered_map<uint64_t,std::function<void()>> pending;
    std::unordered_map<uint64_t,std::function<void()>> attempts;
    std::vector<std::weak_ptr<Stream>> streams;std::vector<std::weak_ptr<Datagram>> datagrams;
    Context(Node value,dispatch_queue_t target,HJCppTransportDialer transport):node(std::move(value)),output(target),dialer([transport copy]){
        queue=dispatch_queue_create_with_target("app.hajimi.cpp-protocol.strand",DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,target);
    }
    template<class T>void prune(std::vector<std::weak_ptr<T>> &values){if(values.size()>64)values.erase(std::remove_if(values.begin(),values.end(),[](auto &value){return value.expired();}),values.end());}
    void cancel(){
        if(closed)return;closed=true;cancellationSignal=true;
        resetAnyTLSClient(factory);
        auto waiters=std::move(pending);pending.clear();for(auto &entry:waiters)entry.second();
        auto oldAttempts=std::move(attempts);attempts.clear();for(auto &entry:oldAttempts)entry.second();
        auto oldStreams=std::move(streams);streams.clear();for(auto &weak:oldStreams)if(auto stream=weak.lock())stream->close();
        auto oldDatagrams=std::move(datagrams);datagrams.clear();for(auto &weak:oldDatagrams)if(auto value=weak.lock())value->close();dialer=nil;
    }
    void initialize();
};
void Context::initialize(){
    factory=std::make_shared<TransportFactory>();std::weak_ptr<Context> weak=shared_from_this();auto strand=queue;
    factory->cancelled=[weak]{auto context=weak.lock();return !context || context->cancellationSignal.load();};
    factory->post=[strand](std::function<void()> work){post(strand,std::move(work));};
    factory->after=[strand](double seconds,std::function<void()> work){
        if(!std::isfinite(seconds) || seconds<0)seconds=0;seconds=std::min(seconds,86400.0);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,int64_t(seconds*NSEC_PER_SEC)),strand,^{@autoreleasepool{work();}});
    };
    factory->tcp=[weak](const Node &node,const TLSOptions &tls,StreamCallback completion){
        auto context=weak.lock();if(!context || context->closed){completion(nullptr,"Protocol client cancelled");return;}
        auto attempt=++context->nextAttempt;
        auto ready=^(id<HJByteStream> stream,NSError *error){
            auto failure=cppError(error);post(context->queue,[context,stream,completion,failure,attempt]{
                context->attempts.erase(attempt);
                if(context->closed){[stream cancel];completion(nullptr,"Protocol client cancelled");return;}
                if(!failure.empty() || !stream){[stream cancel];completion(nullptr,failure.empty()?"Native transport did not return a stream":failure);return;}
                auto value=std::make_shared<PlatformStream>(stream,context->queue);context->prune(context->streams);context->streams.push_back(value);completion(value,{});
            });
        };
        if(context->dialer){context->dialer(ready);return;}
        NSMutableArray<NSString *> *alpn=[NSMutableArray array];for(auto &value:tls.alpn)[alpn addObject:[NSString stringWithUTF8String:value.c_str()]];
        NSString *interface=node.interfaceName.empty() || loopback(node.host)?nil:[NSString stringWithUTF8String:node.interfaceName.c_str()];
        auto cancel=[HJNetworkStream beginConnectToHost:[NSString stringWithUTF8String:node.host.c_str()] port:node.port tls:tls.enabled
            serverName:[NSString stringWithUTF8String:tls.serverName.c_str()] skipCertificateVerification:tls.skipVerify
            alpn:alpn interfaceName:interface queue:context->queue timeout:12 completion:ready];
        context->attempts[attempt]=[cancel]{cancel();};
    };
    factory->udp=[weak](const Node &node,DatagramCallback completion){
        auto context=weak.lock();if(!context || context->closed){completion(nullptr,"Protocol client cancelled");return;}
        auto attempt=++context->nextAttempt;
        auto callback=[context,attempt,completion=std::move(completion)](std::shared_ptr<Datagram> value,Error error)mutable{
            context->attempts.erase(attempt);
            if(context->closed){if(value)value->close();completion(nullptr,"Protocol client cancelled");return;}
            if(value){context->prune(context->datagrams);context->datagrams.push_back(value);}completion(std::move(value),std::move(error));
        };
        auto dial=std::make_shared<UDPAttempt>(node,context->queue,std::move(callback));
        std::weak_ptr<UDPAttempt> pending=dial;context->attempts[attempt]=[pending]{if(auto dial=pending.lock())dial->cancel();};dial->start();
    };
}
} // namespace

@interface HJCppByteStream () {
    std::shared_ptr<Stream> _stream;
    std::shared_ptr<Context> _context;
    std::atomic<bool> _cancelled;
    std::atomic<size_t> _queuedBytes,_queuedRequests;
    BOOL _halfClose;
}
- (instancetype)initWithStream:(std::shared_ptr<Stream>)stream context:(std::shared_ptr<Context>)context;
@end
@interface HJCppDatagramSession () {
    std::shared_ptr<Datagram> _datagram;
    std::shared_ptr<Context> _context;
    std::atomic<bool> _cancelled;
    std::atomic<size_t> _queuedBytes,_queuedRequests;
}
- (instancetype)initWithDatagram:(std::shared_ptr<Datagram>)datagram context:(std::shared_ptr<Context>)context;
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
void deliver(dispatch_queue_t queue,HJStreamWriteCompletion completion,Error error){
    NSError *failure=nativeError(error);dispatch_async(queue,^{completion(failure);});
}
}

@implementation HJCppByteStream
- (instancetype)initWithStream:(std::shared_ptr<Stream>)stream context:(std::shared_ptr<Context>)context{
    if((self=[super init])){_stream=std::move(stream);_context=std::move(context);_cancelled=false;_queuedBytes=0;_queuedRequests=0;_halfClose=_stream->supportsHalfClose();}return self;
}
- (BOOL)supportsHalfClose{return _halfClose;}
- (void)sendData:(NSData *)payload completion:(HJStreamWriteCompletion)completion{
    if(_cancelled.load()){deliver(_context->output,completion,"Stream closed");return;}
    if(!reserve(_queuedBytes,_queuedRequests,payload.length)){deliver(_context->output,completion,"C++ stream write queue limit exceeded");return;}
    NSData *snapshot=[payload copy];auto context=_context;auto stream=_stream;size_t size=snapshot.length;
    post(context->queue,[self,context,stream,snapshot,size,completion]{
        if(self->_cancelled.load() || context->closed){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(context->output,completion,"Stream closed");return;}
        auto done=[self,context,size,completion](Error error){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(context->output,completion,std::move(error));};
        try{stream->write(buffer(snapshot),done);}catch(const std::exception &e){done(e.what());}
    });
}
- (void)sendContent:(dispatch_data_t)content isComplete:(BOOL)complete completion:(HJStreamWriteCompletion)completion{
    if(complete && content && dispatch_data_get_size(content)){
        [self sendData:mapped(content) completion:^(NSError *error){if(error)completion(error);else [self sendContent:nil isComplete:YES completion:completion];}];return;
    }
    if(!complete){[self sendData:mapped(content) completion:completion];return;}
    auto context=_context;auto stream=_stream;
    post(context->queue,[self,context,stream,completion]{
        if(self->_cancelled.load() || context->closed){deliver(context->output,completion,"Stream closed");return;}
        try{stream->shutdownWrite([context,completion](Error error){deliver(context->output,completion,std::move(error));});}
        catch(const std::exception &e){deliver(context->output,completion,e.what());}
    });
}
- (void)receiveDataWithMaximum:(NSUInteger)maximum completion:(HJDataReadCompletion)completion{
    auto context=_context;auto stream=_stream;
    if(!maximum || maximum>maximumReadBytes){dispatch_async(context->output,^{completion(nil,NO,nativeError("Invalid maximum read size"));});return;}
    post(context->queue,[self,context,stream,maximum,completion]{
        if(self->_cancelled.load() || context->closed){dispatch_async(context->output,^{completion(nil,YES,nativeError("Stream closed"));});return;}
        auto done=[context,completion](Buffer value,bool eof,Error error){NSData *payload=data(std::move(value));NSError *failure=nativeError(error);dispatch_async(context->output,^{completion(payload,eof,failure);});};
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
- (instancetype)initWithDatagram:(std::shared_ptr<Datagram>)datagram context:(std::shared_ptr<Context>)context{
    if((self=[super init])){_datagram=std::move(datagram);_context=std::move(context);_cancelled=false;_queuedBytes=0;_queuedRequests=0;}return self;
}
- (void)sendPayload:(NSData *)payload host:(NSString *)host port:(uint16_t)port completion:(HJStreamWriteCompletion)completion{
    auto context=_context;auto datagram=_datagram;
    if(_cancelled.load()){deliver(context->output,completion,"Datagram session closed");return;}
    if(!reserve(_queuedBytes,_queuedRequests,payload.length)){deliver(context->output,completion,"Datagram write queue limit exceeded");return;}
    NSData *snapshot=[payload copy];NSString *destination=[host copy];size_t size=snapshot.length;
    post(context->queue,[self,context,datagram,snapshot,destination,port,size,completion]{
        auto done=[self,context,size,completion](Error error){self->_queuedBytes.fetch_sub(size);self->_queuedRequests.fetch_sub(1);deliver(context->output,completion,std::move(error));};
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
        bool quic=node.type=="hysteria" || node.type=="hysteria2" || node.type=="tuic";
        bool needsCarrier=!quic && network!="tcp" && !network.empty();
        bool reality=node.parameters.count("reality-public-key") || node.option("security")=="reality";
        if((needsCarrier || reality) && !dialer){if(error)*error=nativeError("This configuration requires a prepared carrier adapter");return nil;}
        if((self=[super init])){_context=std::make_shared<Context>(std::move(node),queue,dialer);_context->initialize();}return self;
    }catch(const std::exception &e){if(error)*error=nativeError(e.what());return nil;}
}
- (void)connectToHost:(NSString *)host port:(uint16_t)port udp:(BOOL)udp plainHTTP:(BOOL)plainHTTP completion:(void (^)(HJCppByteStream *,NSError *))completion{
    auto context=_context;NSString *destination=[host copy];
    post(context->queue,[context,destination,port,udp,plainHTTP,completion]{
        if(context->closed){dispatch_async(context->output,^{completion(nil,nativeError("Protocol client cancelled"));});return;}
        uint64_t operation=++context->nextOperation;
        context->pending[operation]=[context,completion]{dispatch_async(context->output,^{completion(nil,nativeError("Protocol client cancelled"));});};
        auto done=[context,operation,completion](std::shared_ptr<Stream> stream,Error error){
            auto found=context->pending.find(operation);if(found==context->pending.end()){if(stream)stream->close();return;}context->pending.erase(found);
            HJCppByteStream *wrapped=nil;if(stream){context->prune(context->streams);context->streams.push_back(stream);wrapped=[[HJCppByteStream alloc]initWithStream:stream context:context];}
            NSError *failure=nativeError(error);dispatch_async(context->output,^{completion(wrapped,failure);});
        };
        try{Target target{cppString(destination),port,bool(udp),bool(plainHTTP)};connectProtocol(context->node,target,context->factory,done);}
        catch(const std::exception &e){done(nullptr,e.what());}
    });
}
- (void)createDatagramSessionWithReceive:(HJCppPacketHandler)receive failure:(HJStreamWriteCompletion)failure completion:(void (^)(HJCppDatagramSession *,NSError *))completion{
    auto context=_context;
    post(context->queue,[context,receive,failure,completion]{
        if(context->closed){dispatch_async(context->output,^{completion(nil,nativeError("Protocol client cancelled"));});return;}
        uint64_t operation=++context->nextOperation;
        context->pending[operation]=[context,completion]{dispatch_async(context->output,^{completion(nil,nativeError("Protocol client cancelled"));});};
        auto done=[context,operation,receive,failure,completion](std::shared_ptr<Datagram> datagram,Error error){
            auto found=context->pending.find(operation);if(found==context->pending.end()){if(datagram)datagram->close();return;}context->pending.erase(found);
            if(!error.empty() || !datagram){NSError *value=nativeError(error.empty()?"Protocol did not create a datagram session":error);dispatch_async(context->output,^{completion(nil,value);});return;}
            context->prune(context->datagrams);context->datagrams.push_back(datagram);
            auto wrapped=[[HJCppDatagramSession alloc]initWithDatagram:datagram context:context];
            std::weak_ptr<Context> weak=context;
            datagram->start([weak,receive](Target target,Buffer value){if(auto context=weak.lock()){
                NSString *host=[[NSString alloc]initWithBytes:target.host.data() length:target.host.size() encoding:NSUTF8StringEncoding];
                if(!host)return;auto port=target.port;NSData *payload=data(std::move(value));
                dispatch_async(context->output,^{receive(host,port,payload);});
            }},[weak,failure](Error error){if(auto context=weak.lock())deliver(context->output,failure,std::move(error));});
            dispatch_async(context->output,^{completion(wrapped,nil);});
        };
        try{makeProtocolDatagram(context->node,context->factory,done);}catch(const std::exception &e){done(nullptr,e.what());}
    });
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
