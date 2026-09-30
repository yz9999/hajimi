#include "BasicProtocols.hpp"
#include <deque>
#include <stdexcept>

namespace hajimi {
class SocksDatagrams final:public Datagram,public std::enable_shared_from_this<SocksDatagrams>{
    struct Pending{Buffer wire;WriteCallback completion;};
    Node node_;std::shared_ptr<TransportFactory> factory_;std::shared_ptr<Stream> control_;std::shared_ptr<Datagram> raw_;
    std::deque<Pending> queue_;size_t bytes_=0;bool connecting_=false,closed_=false,started_=false,sending_=false,receiving_=false;
    PacketCallback receive_;WriteCallback failure_;Target relay_;
    void fail(Error error){
        if(closed_)return;closed_=true;if(control_)control_->close();if(raw_)raw_->close();
        auto queue=std::move(queue_);queue_.clear();bytes_=0;
        for(auto &entry:queue)entry.completion(error);
        if(failure_)failure_(error);receive_=nullptr;failure_=nullptr;
    }
    void monitorControl(){
        if(closed_ || !control_)return;auto self=shared_from_this();
        control_->read(1,[self](Buffer data,bool eof,Error error){
            if(self->closed_)return;
            if(!error.empty() || eof || !data.empty()){self->fail(error.empty()?"SOCKS5 UDP association closed":error);return;}
            self->factory_->post([self]{self->monitorControl();});
        });
    }
    void flush(){
        if(closed_ || !raw_ || sending_ || queue_.empty())return;
        sending_=true;auto self=shared_from_this();
        raw_->send(relay_,queue_.front().wire,[self](Error error){
            if(self->closed_)return;self->sending_=false;
            if(!error.empty()){self->fail(error);return;}
            auto entry=std::move(self->queue_.front());self->queue_.pop_front();self->bytes_-=entry.wire.size();
            entry.completion({});self->flush();
        });
    }
    void beginReceive(){
        if(closed_ || !started_ || !raw_ || receiving_)return;
        receiving_=true;std::weak_ptr<SocksDatagrams> weak=shared_from_this();
        raw_->start([weak](Target,Buffer wire){
            if(auto self=weak.lock()){
                if(self->closed_ || wire.size()<4 || wire[0] || wire[1] || wire[2])return; // RFC1928 FRAG unsupported: drop, never concatenate.
                try{Buffer body(wire.begin()+3,wire.end());size_t consumed=0;auto target=parseSocksAddress(body,consumed);
                    Buffer payload(body.begin()+consumed,body.end());if(self->receive_)self->receive_(std::move(target),std::move(payload));}
                catch(const std::exception &){} // Malformed unauthenticated UDP is discarded.
            }
        },[weak](Error error){if(auto self=weak.lock())self->fail(std::move(error));});
    }
    void connect(){
        if(closed_ || connecting_ || raw_)return;
        if(!factory_->udp){fail("Missing native UDP transport");return;}
        connecting_=true;auto self=shared_from_this();
        connectSocksAssociation(node_,factory_,[self](std::shared_ptr<Stream> control,Target bound,Error error){
            if(self->closed_){if(control)control->close();return;}
            if(!error.empty() || !control){self->fail(error.empty()?"SOCKS5 UDP association failed":error);return;}
            if(!bound.port){control->close();self->fail("SOCKS5 server returned an invalid UDP relay");return;}
            if(bound.host=="0.0.0.0" || bound.host=="::")bound.host=self->node_.host;
            self->control_=std::move(control);self->relay_=bound;self->monitorControl();
            Node relay=self->node_;relay.type="direct";relay.host=bound.host;relay.port=bound.port;
            self->factory_->udp(relay,[self](std::shared_ptr<Datagram> raw,Error error){
                self->connecting_=false;
                if(self->closed_){if(raw)raw->close();return;}
                if(!error.empty() || !raw){self->fail(error.empty()?"SOCKS5 UDP transport failed":error);return;}
                self->raw_=std::move(raw);self->beginReceive();self->flush();
            });
        },[self](std::shared_ptr<Stream> control){if(self->closed_)control->close();else self->control_=std::move(control);});
    }
public:
    SocksDatagrams(Node node,std::shared_ptr<TransportFactory> factory):node_(std::move(node)),factory_(std::move(factory)){}
    void send(Target target,Buffer data,WriteCallback completion)override{
        if(closed_){completion("Datagram session closed");return;}
        try{auto address=socksAddress(target);size_t length=3+address.size()+data.size();
            if(length>65507 || length>maximumQueuedBytes-bytes_ || queue_.size()>=512){completion("SOCKS5 UDP queue or packet limit exceeded");return;}
            Buffer wire{0,0,0};wire.insert(wire.end(),address.begin(),address.end());wire.insert(wire.end(),data.begin(),data.end());
            bytes_+=wire.size();queue_.push_back({std::move(wire),std::move(completion)});connect();flush();
        }catch(const std::exception &e){completion(e.what());}
    }
    void start(PacketCallback receive,WriteCallback failure)override{
        if(closed_){failure("Datagram session closed");return;}if(started_){failure("Datagram receiver already started");return;}
        started_=true;receive_=std::move(receive);failure_=std::move(failure);connect();beginReceive();
    }
    void close()override{
        if(closed_)return;failure_=nullptr;fail("Datagram session closed");
    }
};
void makeSocksDatagram(const Node &node,std::shared_ptr<TransportFactory> factory,DatagramCallback completion){
    completion(std::make_shared<SocksDatagrams>(node,std::move(factory)),{});
}
} // namespace hajimi
