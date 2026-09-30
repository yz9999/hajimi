#include "../Sources/HajimiProtocolsCXX/Runtime.hpp"
#include <condition_variable>
#include <deque>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <cstdlib>
#include <atomic>
#include <set>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace hajimi;
namespace {
class Queue {
    struct State {
        std::mutex lock; std::condition_variable wake; bool stopped = false;
        std::deque<std::function<void()>> tasks;
    };
    std::shared_ptr<State> state_ = std::make_shared<State>(); std::thread worker_;
public:
    Queue() : worker_([state = state_] {
        for (;;) {
            std::function<void()> task;
            { std::unique_lock<std::mutex> lock(state->lock); state->wake.wait(lock, [state] { return state->stopped || !state->tasks.empty(); });
              if (state->tasks.empty() && state->stopped) return; task = std::move(state->tasks.front()); state->tasks.pop_front(); }
            task();
        }
    }) {}
    ~Queue() {
        { std::lock_guard<std::mutex> lock(state_->lock); state_->stopped = true; } state_->wake.notify_one();
        if (worker_.get_id() == std::this_thread::get_id()) worker_.detach(); else worker_.join();
    }
    void post(std::function<void()> task) { { std::lock_guard<std::mutex> lock(state_->lock); state_->tasks.push_back(std::move(task)); } state_->wake.notify_one(); }
};
template<class T> T wait(std::future<T> &future, const std::string &phase) {
    if (std::getenv("HAJIMI_QUIC_TEST_TRACE")) std::cerr << "QUIC stage: " << phase << '\n';
    if (future.wait_for(std::chrono::seconds(18)) != std::future_status::ready)
        throw std::runtime_error("QUIC test timed out at " + phase);
    try { return future.get(); }
    catch (const std::exception &error) { throw std::runtime_error("QUIC " + phase + ": " + error.what()); }
}
std::shared_ptr<Stream> tcp(const Node &node, std::shared_ptr<TransportFactory> factory) {
    auto promise = std::make_shared<std::promise<std::shared_ptr<Stream>>>(); auto result = promise->get_future();
    factory->post([node, factory, promise] { connectQUICProtocol(node, {"example.com", 443}, factory,
        [promise](std::shared_ptr<Stream> stream, Error error) {
            if (!error.empty()) promise->set_exception(std::make_exception_ptr(std::runtime_error(error)));
            else promise->set_value(stream);
        }); });
    return wait(result, "TCP TLS/auth/connect");
}
void write(std::shared_ptr<Stream> stream, Buffer bytes, std::shared_ptr<TransportFactory> factory, bool shutdown = false) {
    auto promise = std::make_shared<std::promise<Error>>(); auto result = promise->get_future();
    factory->post([stream, bytes = std::move(bytes), promise, shutdown]() mutable {
        auto done = [promise](Error error) { promise->set_value(error); };
        if (shutdown) stream->shutdownWrite(done); else stream->write(std::move(bytes), done);
    });
    auto error = wait(result, shutdown ? "TCP half-close" : "TCP payload write");
    if (!error.empty()) throw std::runtime_error(error);
}
Buffer read(std::shared_ptr<Stream> stream, std::shared_ptr<TransportFactory> factory, bool &eof, size_t received = 0) {
    auto promise = std::make_shared<std::promise<std::pair<Buffer, bool>>>(); auto result = promise->get_future();
    factory->post([stream, promise] { stream->read(65536, [promise](Buffer data, bool end, Error error) {
        if (!error.empty()) promise->set_exception(std::make_exception_ptr(std::runtime_error(error)));
        else promise->set_value({std::move(data), end});
    }); });
    auto value = wait(result, "TCP read/FIN after " + std::to_string(received) + " bytes"); eof = value.second; return value.first;
}
void checkUDP(const Node &node, std::shared_ptr<TransportFactory> factory) {
    auto promise = std::make_shared<std::promise<std::shared_ptr<Datagram>>>(); auto result = promise->get_future();
    factory->post([node, factory, promise] { makeQUICDatagram(node, factory,
        [promise](std::shared_ptr<Datagram> session, Error error) {
            if (!error.empty()) promise->set_exception(std::make_exception_ptr(std::runtime_error(error)));
            else promise->set_value(session);
        }); });
    auto session = wait(result, "UDP TLS/auth/association");
    struct Inbox { std::shared_ptr<std::promise<Buffer>> promise; bool finished = false; };
    auto inbox = std::make_shared<Inbox>();
    size_t count = node.option("udp-relay-mode") == "quic" ? 96 : 3;
    for (size_t iteration = 0; iteration < count; ++iteration) {
        auto received = std::make_shared<std::promise<Buffer>>(); auto future = received->get_future();
        Buffer payload(iteration == 1 ? 0 : iteration == 2 ? 65507 : 3500);
        for (size_t i = 0; i < payload.size(); ++i) payload[i] = (i * 79 + 33 + iteration) & 255;
        factory->post([session, received, inbox, payload, iteration] {
            inbox->promise = received; inbox->finished = false;
            if (iteration == 0) session->start([inbox](Target target, Buffer data) {
            if (inbox->finished) return; inbox->finished = true;
            if (target.host != "example.com" || target.port != 5353)
                inbox->promise->set_exception(std::make_exception_ptr(std::runtime_error("UDP target changed")));
            else inbox->promise->set_value(std::move(data));
        }, [inbox](Error error) {
            if (inbox->finished) return; inbox->finished = true;
            inbox->promise->set_exception(std::make_exception_ptr(std::runtime_error(error)));
        });
        session->send({"example.com", 5353, true}, payload, [received, inbox](Error error) {
            if (error.empty() || inbox->finished) return; inbox->finished = true;
            received->set_exception(std::make_exception_ptr(std::runtime_error(error)));
        });
        });
        if (wait(future, "UDP receive/reassembly iteration " + std::to_string(iteration) +
                 " (" + std::to_string(payload.size()) + " bytes)") != payload)
            throw std::runtime_error("Fragmented UDP payload mismatch");
    }
    factory->post([session] { session->close(); });
}

struct Blackhole {
    int descriptor = -1; uint16_t port = 0;
    Blackhole() {
        descriptor = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (descriptor < 0) throw std::runtime_error("Could not create QUIC blackhole socket");
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t size = sizeof(local);
        if (::bind(descriptor, reinterpret_cast<sockaddr *>(&local), size) ||
            ::getsockname(descriptor, reinterpret_cast<sockaddr *>(&local), &size)) {
            ::close(descriptor); descriptor = -1;
            throw std::runtime_error("Could not bind QUIC blackhole socket");
        }
        port = ntohs(local.sin_port);
    }
    ~Blackhole() { if (descriptor >= 0) ::close(descriptor); }
    void started() {
        // A bound, receiving UDP sink is important: an unused port can send
        // ICMP and fail the test before it ever exercises cancellation.
        std::set<uint16_t> sources;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (sources.size() < 2 && std::chrono::steady_clock::now() < deadline) {
            pollfd poller{descriptor, POLLIN, 0};
            if (::poll(&poller, 1, 25) <= 0) continue;
            uint8_t packet[2048]; sockaddr_in source{}; socklen_t size = sizeof(source);
            if (::recvfrom(descriptor, packet, sizeof(packet), 0,
                           reinterpret_cast<sockaddr *>(&source), &size) > 0)
                sources.insert(source.sin_port);
        }
        if (sources.size() != 2) throw std::runtime_error("TCP/UDP QUIC reactors did not both send an Initial");
    }
};
struct CancelCompletion {
    std::atomic<size_t> calls{0}; std::promise<Error> promise;
    void finish(bool returnedResource, Error error) {
        if (returnedResource) error = "Cancelled QUIC dial returned a live transport";
        if (calls.fetch_add(1) == 0) promise.set_value(std::move(error));
    }
};
struct CallbackGate {
    std::mutex mutex; std::condition_variable wake; bool holding = true;
    std::deque<std::function<void()>> callbacks;
};
void checkCancellation(Node node, const std::shared_ptr<Queue> &queue,
                       bool queuedReady, bool alreadyCancelled = false) {
    auto signal = std::make_shared<std::atomic<bool>>(alreadyCancelled);
    auto factory = std::make_shared<TransportFactory>(); std::weak_ptr<TransportFactory> lifetime = factory;
    factory->cancelled = [signal] { return signal->load(std::memory_order_acquire); };
    auto gate = std::make_shared<CallbackGate>();
    if (queuedReady) factory->post = [queue, gate](std::function<void()> callback) {
        {
            std::lock_guard<std::mutex> lock(gate->mutex);
            if (gate->holding) { gate->callbacks.push_back(std::move(callback)); gate->wake.notify_one(); return; }
        }
        queue->post(std::move(callback));
    };
    else factory->post = [queue](std::function<void()> callback) { queue->post(std::move(callback)); };
    std::unique_ptr<Blackhole> blackhole;
    if (!queuedReady) { blackhole = std::make_unique<Blackhole>(); node.port = blackhole->port; }
    auto tcp = std::make_shared<CancelCompletion>(), udp = std::make_shared<CancelCompletion>();
    auto tcpResult = tcp->promise.get_future(), udpResult = udp->promise.get_future();
    // Start directly on the strand. In the ready-race case only callbacks
    // posted by the two TLS reactors are held, not these setup operations.
    queue->post([factory, node, tcp, udp] {
        connectQUICProtocol(node, {"example.com", 443}, factory,
            [tcp](std::shared_ptr<Stream> stream, Error error) {
                bool returned = bool(stream); if (stream) stream->close(); tcp->finish(returned, std::move(error));
            });
        makeQUICDatagram(node, factory, [udp](std::shared_ptr<Datagram> session, Error error) {
            bool returned = bool(session); if (session) session->close(); udp->finish(returned, std::move(error));
        });
    });
    if (queuedReady) {
        std::unique_lock<std::mutex> lock(gate->mutex);
        if (!gate->wake.wait_for(lock, std::chrono::seconds(2), [gate] { return gate->callbacks.size() >= 2; }))
            throw std::runtime_error("Two QUIC TLS-ready callbacks were not queued");
    } else if (!alreadyCancelled) blackhole->started();
    auto start = std::chrono::steady_clock::now(), deadline = start + std::chrono::milliseconds(500);
    signal->store(true, std::memory_order_release);
    if (queuedReady) {
        std::deque<std::function<void()>> callbacks;
        { std::lock_guard<std::mutex> lock(gate->mutex); gate->holding = false; callbacks.swap(gate->callbacks); }
        for (auto &callback : callbacks) queue->post(std::move(callback));
    }
    factory.reset();
    if (tcpResult.wait_until(deadline) != std::future_status::ready ||
        udpResult.wait_until(deadline) != std::future_status::ready)
        throw std::runtime_error("Cancelled TCP/UDP QUIC dials did not complete within 500 ms");
    auto tcpError = tcpResult.get(), udpError = udpResult.get();
    if (tcpError.find("cancel") == std::string::npos || udpError.find("cancel") == std::string::npos)
        throw std::runtime_error("Cancelled QUIC dial did not return a cancellation error: " + tcpError + "; " + udpError);
    // Each reactor/Connection::Impl strongly owns this factory. Expiry proves
    // their destruction (including TLS/socket/pipe cleanup), not just a
    // promptly delivered error while a ten-second reactor keeps running.
    while (!lifetime.expired() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (!lifetime.expired()) throw std::runtime_error("Cancelled QUIC reactor/socket ownership did not converge within 500 ms");
    auto barrier = std::make_shared<std::promise<void>>(); auto drained = barrier->get_future();
    queue->post([barrier] { barrier->set_value(); });
    if (drained.wait_until(deadline) != std::future_status::ready || tcp->calls != 1 || udp->calls != 1)
        throw std::runtime_error("Cancelled QUIC TCP/UDP callbacks were not exactly once");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    std::cout << node.type << (queuedReady ? " queued-TLS-ready" : alreadyCancelled ? " pre-start" : " blackhole")
              << " TCP/UDP cancellation + exactly-once + reactor/socket release passed (" << elapsed << " ms)\n";
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 4) throw std::runtime_error("usage: quic-check protocol port CA.pem [obfs|quic|reject|bad-auth]");
        auto queue = std::make_shared<Queue>(); auto factory = std::make_shared<TransportFactory>();
        factory->post = [queue](std::function<void()> task) { queue->post(std::move(task)); };
        Node node; node.type = argv[1]; node.host = "127.0.0.1"; node.port = std::stoi(argv[2]);
        node.interfaceName = "lo0";
        node.parameters = {{"sni", "localhost"}, {"ca", argv[3]}, {"password", "interop-password"},
            {"auth-str", "interop-password"}, {"uuid", "00000000-0000-4000-8000-000000000001"}, {"up", "10"}, {"down", "100"}};
        std::string mode = argc > 4 ? argv[4] : "";
        if (mode == "obfs") {
            node.parameters["obfs"] = node.type == "hysteria2" ? "salamander" : "interop-obfs";
            if (node.type == "hysteria2") node.parameters["obfs-password"] = "interop-obfs";
        } else if (mode == "quic") node.parameters["udp-relay-mode"] = "quic";
        else if (mode == "reject") node.parameters["sni"] = "wrong.invalid";
        else if (mode == "system-reject") node.parameters.erase("ca");
        else if (mode == "skip") {
            node.parameters.erase("ca"); node.parameters["sni"] = "wrong.invalid";
            node.parameters["skip-cert-verify"] = "true";
        }
        else if (mode == "bad-auth") node.parameters["password"] = node.parameters["auth-str"] = "wrong-password";
        if (!validateQUICProtocol(node, false).empty()) throw std::runtime_error(validateQUICProtocol(node, false));
        if (mode == "cancel" || mode == "cancel-ready") {
            if (mode == "cancel") {
                checkCancellation(node, queue, false); checkCancellation(node, queue, false, true);
            } else checkCancellation(node, queue, true);
            return 0;
        }
        if (mode == "reject" || mode == "system-reject" || mode == "bad-auth") {
            bool rejected = false; try {
                auto stream = tcp(node, factory);
                if (mode == "bad-auth" && node.type == "tuic") { bool eof = false; (void)read(stream, factory, eof); }
                factory->post([stream] { stream->close(); });
            }
            catch (...) { rejected = true; }
            if (!rejected) throw std::runtime_error("Invalid TLS/auth was accepted");
            std::cout << node.type << " " << mode << " correctly rejected\n"; return 0;
        }
        auto stream = tcp(node, factory); Buffer payload(20000);
        for (size_t i = 0; i < payload.size(); ++i) payload[i] = (i * 13 + 7) & 255;
        write(stream, payload, factory); write(stream, {}, factory, true);
        Buffer expected{'s','e','r','v','e','r','-','p','r','e','f','i','x'}; expected.insert(expected.end(), payload.begin(), payload.end());
        Buffer output; bool eof = false;
        while (!eof) { auto part = read(stream, factory, eof, output.size()); output.insert(output.end(), part.begin(), part.end()); }
        if (output != expected) throw std::runtime_error("TCP payload/prefix/half-close mismatch");
        factory->post([stream] { stream->close(); }); stream.reset();
        checkUDP(node, factory);
        std::cout << node.type << " " << mode << " TLS/auth + TCP/half-close + UDP/fragments passed\n";
        return 0;
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
