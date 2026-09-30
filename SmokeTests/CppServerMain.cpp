#include "ServerProtocols.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include <utility>

using namespace hajimi;
namespace {
struct Loop {
    std::deque<std::function<void()>> jobs;
    struct Timer { double deadline; std::function<void()> callback; };
    std::vector<Timer> timers; double now = 0;
    void post(std::function<void()> callback) { jobs.push_back(std::move(callback)); }
    void drain() {
        size_t count = 0;
        while (!jobs.empty()) {
            if (++count > 100000) throw std::runtime_error("SOCKS test loop did not quiesce");
            auto callback = std::move(jobs.front()); jobs.pop_front(); callback();
        }
    }
    void advance(double time) {
        now += time;
        std::vector<std::function<void()>> due;
        for (auto &timer : timers) if (timer.callback && timer.deadline <= now)
            due.push_back(std::exchange(timer.callback, {}));
        for (auto &callback : due) callback(); drain();
    }
};
class Peer final : public Stream, public std::enable_shared_from_this<Peer> {
    Loop &loop_; ReadCallback read_; size_t maximum_ = 0;
public:
    explicit Peer(Loop &loop) : loop_(loop) {}
    std::deque<Buffer> input; Buffer output; std::deque<WriteCallback> writes;
    bool eof = false, closed = false, holdWrites = false, failWrite = false;
    Error readError; unsigned closes = 0, readCalls = 0;
    void write(Buffer data, WriteCallback callback) override {
        auto self = shared_from_this();
        loop_.post([self, data = std::move(data), callback]() mutable {
            if (self->closed || self->failWrite) { callback("Transport write failed"); return; }
            self->output.insert(self->output.end(), data.begin(), data.end());
            if (self->holdWrites) self->writes.push_back(callback); else callback({});
        });
    }
    void read(size_t maximum, ReadCallback callback) override {
        assert(!read_ && maximum > 0); ++readCalls; maximum_ = maximum;
        read_ = std::move(callback); deliver();
    }
    void close() override {
        if (closed) return; closed = true; ++closes; deliver();
        while (!writes.empty()) {
            auto callback = std::move(writes.front()); writes.pop_front();
            loop_.post([callback] { callback("Cancelled"); });
        }
    }
    void deliver() {
        if (!read_ || (input.empty() && !eof && !closed && readError.empty())) return;
        Buffer output;
        if (!input.empty()) {
            auto &chunk = input.front(); size_t size = std::min(maximum_, chunk.size());
            output.assign(chunk.begin(), chunk.begin() + size); chunk.erase(chunk.begin(), chunk.begin() + size);
            if (chunk.empty()) input.pop_front();
        }
        bool end = (eof && input.empty()) || closed;
        auto callback = std::exchange(read_, {}); auto error = closed ? Error{"Cancelled"} : std::exchange(readError, {});
        loop_.post([callback, output = std::move(output), end, error]() mutable { callback(std::move(output), end, error); });
    }
};
struct Result { unsigned calls = 0; Target target; uint8_t command = 0; Buffer initial; Error error; };
struct Fixture {
    Loop loop; std::shared_ptr<Peer> peer = std::make_shared<Peer>(loop);
    std::shared_ptr<TransportFactory> factory = std::make_shared<TransportFactory>(); Result result;
    Fixture() {
        factory->post = [this](std::function<void()> callback) { loop.post(std::move(callback)); };
        factory->after = [this](double delay, std::function<void()> callback) {
            loop.timers.push_back({loop.now + delay, std::move(callback)});
        };
    }
    ~Fixture() { peer->close(); loop.drain(); }
    void start() {
        acceptSOCKS5(peer, factory, [this](Target target, uint8_t command, Buffer initial, Error error) {
            ++result.calls; result.target = std::move(target); result.command = command;
            result.initial = std::move(initial); result.error = std::move(error);
        }); loop.drain();
    }
};
void append(Buffer &out, const Buffer &in) { out.insert(out.end(), in.begin(), in.end()); }
Buffer wire(const Buffer &request, const Buffer &initial = {}) {
    Buffer out{5, 3, 2, 0, 1}; append(out, request); append(out, initial); return out;
}
const Buffer ipv4{5, 1, 0, 1, 192, 0, 2, 7, 0, 80};
const Buffer ipv6{5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0xbb};
const Buffer domain{5, 1, 0, 3, 12, 'e','x','a','m','p','l','e','.','t','e','s','t', 1, 0xbb};
void accepted(Fixture &fixture, const std::string &host, uint16_t port, uint8_t command, Buffer initial) {
    assert(fixture.result.calls == 1 && fixture.result.error.empty() && fixture.result.command == command);
    assert(fixture.result.target.host == host && fixture.result.target.port == port);
    assert(fixture.result.target.udp == (command == 3) && fixture.result.initial == initial);
    assert(!fixture.peer->closed && fixture.peer->output == Buffer({5, 0}));
    fixture.loop.advance(30); assert(fixture.result.calls == 1 && !fixture.peer->closed);
}
void rejected(Buffer request, uint8_t reply) {
    Fixture fixture; fixture.peer->input.push_back(wire(request)); fixture.start();
    assert(fixture.result.calls == 1 && !fixture.result.error.empty() && fixture.result.command == 0);
    Buffer expected{5, 0}; append(expected, socksReply(reply, {}));
    assert(fixture.peer->output == expected && fixture.peer->closes == 1);
    fixture.loop.advance(30); assert(fixture.result.calls == 1 && fixture.peer->closes == 1);
}
} // namespace

int main() {
    const Buffer payload{'r','e','a','d','-','a','h','e','a','d',0,255};
    for (auto item : std::vector<std::pair<Buffer, Target>>{{ipv4,{"192.0.2.7",80}},
            {ipv6,{"2001:db8::1",443}}, {domain,{"example.test",443}}}) {
        auto bytes = wire(item.first, payload);
        for (size_t cut = 1; cut < bytes.size() - payload.size(); ++cut) {
            Fixture fixture; fixture.peer->input.push_back(Buffer(bytes.begin(), bytes.begin() + cut));
            fixture.peer->input.push_back(Buffer(bytes.begin() + cut, bytes.end())); fixture.start();
            accepted(fixture, item.second.host, item.second.port, 1, payload);
        }
        Fixture fixture;
        for (auto byte : bytes) fixture.peer->input.push_back({byte});
        fixture.start(); accepted(fixture, item.second.host, item.second.port, 1, {});
        Buffer remaining; for (auto &chunk : fixture.peer->input) append(remaining, chunk);
        assert(remaining == payload);
    }
    { Fixture fixture; fixture.peer->input.push_back(wire(ipv4, payload)); fixture.peer->eof = true;
      fixture.start(); accepted(fixture, "192.0.2.7", 80, 1, payload); }
    for (auto address : {Buffer{5,3,0,1,0,0,0,0,0,0}, Buffer{5,3,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}) {
        Fixture fixture; fixture.peer->input.push_back(wire(address, payload)); fixture.start();
        accepted(fixture, address[3] == 1 ? "0.0.0.0" : "::", 0, 3, payload);
    }
    { Buffer maximum{5,1,0,3,255}; maximum.insert(maximum.end(),255,'a'); append(maximum,{0,1});
      Fixture fixture; fixture.peer->input.push_back(wire(maximum)); fixture.start(); accepted(fixture,std::string(255,'a'),1,1,{}); }
    { Buffer greeting{5,255}; greeting.insert(greeting.end(),254,2); greeting.push_back(0);
      append(greeting,domain); append(greeting,payload); Fixture fixture; fixture.peer->input.push_back(greeting);
      fixture.start(); accepted(fixture,"example.test",443,1,payload); }
    for (auto greeting : {Buffer{4,1,0}, Buffer{5,0}, Buffer{5,2,1,2}, Buffer{5,1,255}}) {
        Fixture fixture; fixture.peer->input.push_back(greeting); fixture.start();
        assert(fixture.result.calls == 1 && !fixture.result.error.empty() && fixture.peer->output == Buffer({5,255}));
    }
    for (auto command : {0,2,4,255}) { auto request = ipv4; request[1] = command; rejected(request,7); }
    { auto request=ipv4; request[0]=4; rejected(request,1); }
    { auto request=ipv4; request[2]=1; rejected(request,1); }
    { auto request=ipv4; request[3]=2; rejected(request,8); }
    { auto request=ipv4; request[8]=request[9]=0; rejected(request,1); }
    rejected({5,1,0,3,0},8);
    for (auto byte : {uint8_t(0),uint8_t('/'),uint8_t(255)}) { auto request=domain; request[5]=byte; rejected(request,8); }
    auto bytes=wire(domain);
    for(size_t length=0;length<bytes.size();++length) {
        Fixture fixture; if(length)fixture.peer->input.push_back(Buffer(bytes.begin(),bytes.begin()+length));
        fixture.peer->eof=true; fixture.start(); assert(fixture.result.calls==1 && !fixture.result.error.empty() && fixture.peer->closed);
    }
    { Fixture fixture; fixture.start(); fixture.loop.advance(19.99); assert(fixture.result.calls==0);
      fixture.loop.advance(0.01); assert(fixture.result.calls==1 && fixture.result.error=="SOCKS5 handshake timed out");
      fixture.loop.advance(40); assert(fixture.result.calls==1 && fixture.peer->closes==1); }
    for (auto prefix : {Buffer{5,1,0}, Buffer{5,1,2}, Buffer{5,1,0,5,1,0}}) {
        Fixture fixture; fixture.peer->input.push_back(prefix); fixture.peer->holdWrites = prefix.size()==3;
        fixture.start(); fixture.loop.advance(20); assert(fixture.result.calls==1 && !fixture.result.error.empty());
        assert(fixture.peer->closes==1); fixture.loop.advance(30); assert(fixture.result.calls==1);
    }
    { Fixture fixture; fixture.peer->input.push_back({5,1,0}); fixture.peer->failWrite=true; fixture.start();
      assert(fixture.result.calls==1 && !fixture.result.error.empty() && fixture.peer->closed); }
    { Fixture fixture; fixture.peer->readError="Transport read failed"; fixture.start();
      assert(fixture.result.calls==1 && fixture.result.error=="Transport read failed" && fixture.peer->closed); }
    { Fixture fixture; fixture.start(); fixture.peer->close(); fixture.loop.drain(); fixture.loop.advance(30);
      assert(fixture.result.calls==1 && !fixture.result.error.empty() && fixture.peer->closes==1); }
    { Fixture fixture; fixture.peer->input.push_back({5,1,0}); fixture.peer->holdWrites=true; fixture.start();
      fixture.peer->close(); fixture.loop.drain(); fixture.loop.advance(30);
      assert(fixture.result.calls==1 && !fixture.result.error.empty() && fixture.peer->closes==1); }
    assert(socksReply(0,{}) == Buffer({5,0,0,1,0,0,0,0,0,0}));
    assert(socksReply(7,{"127.0.0.1",1080}) == Buffer({5,7,0,1,127,0,0,1,4,56}));
    auto reply=socksReply(0,{"[2001:db8::1]",443}); assert(reply.size()==22 && reply[3]==4 && reply[20]==1 && reply[21]==0xbb);
    reply=socksReply(8,{"example.test",53}); assert(reply.size()==19 && reply[3]==3 && reply[4]==12 && reply.back()==53);
    for(auto bound:{Target{"bad/host",1},Target{std::string("host\0bad",8),1}}) {
        bool failed=false;try{(void)socksReply(0,bound);}catch(const std::invalid_argument&){failed=true;}assert(failed);
    }
    bool failed=false;try{(void)socksReply(9,{});}catch(const std::invalid_argument&){failed=true;}assert(failed);
    std::puts("C++ SOCKS5 server split-field/commands/replies/read-ahead/EOF/timeout/cancel checks passed");
}
