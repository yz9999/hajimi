// Compile this isolated test with the production transport implementation so
// admission/lifecycle checks exercise real dispatch paths, not a queue model.
#define HAJIMI_QUIC_BOUNDARY_TESTS 1
#include "../Sources/HajimiProtocolsCXX/QUICTransport.cpp"
#include <ifaddrs.h>
#include <iostream>
#include <stdexcept>

namespace hajimi::quic {
struct BoundaryChecks {
    static size_t run() {
        size_t checks = 0;
        auto expect = [&](bool value, const char *message) {
            ++checks; if (!value) throw std::runtime_error(message);
        };
        auto ipv4 = [&](const char *host, bool loopback) {
            sockaddr_in address{}; address.sin_family = AF_INET;
            expect(inet_pton(AF_INET, host, &address.sin_addr) == 1, "IPv4 fixture address parse failed");
            expect(isLoopbackAddress(reinterpret_cast<sockaddr *>(&address), sizeof(address)) == loopback,
                   "IPv4 loopback classification changed");
            expect(!isLoopbackAddress(reinterpret_cast<sockaddr *>(&address), sizeof(address) - 1),
                   "Truncated IPv4 address was accepted");
        };
        auto ipv6 = [&](const char *host, bool loopback) {
            sockaddr_in6 address{}; address.sin6_family = AF_INET6;
            expect(inet_pton(AF_INET6, host, &address.sin6_addr) == 1, "IPv6 fixture address parse failed");
            expect(isLoopbackAddress(reinterpret_cast<sockaddr *>(&address), sizeof(address)) == loopback,
                   "IPv6 loopback classification changed");
            expect(!isLoopbackAddress(reinterpret_cast<sockaddr *>(&address), sizeof(address) - 1),
                   "Truncated IPv6 address was accepted");
        };
        ipv4("127.0.0.1", true); ipv4("127.12.34.56", true);
        ipv4("0.0.0.0", false); ipv4("192.0.2.1", false);
        ipv6("::1", true); ipv6("::ffff:127.0.0.1", true);
        ipv6("::ffff:192.0.2.1", false); ipv6("2001:db8::1", false); ipv6("::", false);
        expect(!isLoopbackAddress(nullptr, 0), "Null address was accepted");

        struct State {
            std::deque<std::function<void()>> work;
            std::atomic<bool> cancelled{false};
            size_t delivered = 0;
        };
        auto state = std::make_shared<State>(); auto factory = std::make_shared<TransportFactory>();
        factory->post = [state](std::function<void()> callback) { state->work.push_back(std::move(callback)); };
        factory->cancelled = [state] { return state->cancelled.load(); };
        Node node; node.type = "tuic"; node.host = "127.0.0.1"; node.port = 54321;
        auto connection = std::shared_ptr<Connection>(new Connection(node, factory));
        connection->impl_->owner = connection;
        connection->impl_->packetReceive = [state](Buffer) { ++state->delivered; };
        auto drain = [&] {
            size_t batches = 0;
            while (!state->work.empty()) {
                expect(++batches <= 16, "Datagram draining did not yield/converge in bounded batches");
                auto callback = std::move(state->work.front()); state->work.pop_front(); callback();
                expect(state->work.size() <= 1, "More than one receive-drain callback was queued");
            }
        };
        for (size_t i = 0; i < 10000; ++i) connection->impl_->receiveDatagram(nullptr, 0);
        expect(connection->impl_->received->packets.size() == 512, "Empty DATAGRAM admission was not capped by count");
        expect(connection->impl_->received->bytes == 0, "Empty DATAGRAM consumed payload bytes");
        expect(state->work.size() == 1, "Empty DATAGRAM flood created per-packet callbacks");
        auto first = std::move(state->work.front()); state->work.pop_front(); first();
        expect(state->delivered == 64 && state->work.size() == 1, "A drain did not stop at the 64-packet batch limit");
        drain();
        expect(state->delivered == 512 && connection->impl_->received->packets.empty(), "Admitted empty DATAGRAMs were lost");
        expect(!connection->impl_->received->scheduled, "Empty mailbox kept its dispatch reservation");
        uint8_t byte = 0x42;
        for (size_t i = 0; i < 10000; ++i) connection->impl_->receiveDatagram(&byte, 1);
        expect(connection->impl_->received->packets.size() == 512 && connection->impl_->received->bytes == 512,
               "Tiny DATAGRAM admission exceeded packet/byte limits");
        drain(); expect(state->delivered == 1024, "Tiny DATAGRAM drain mismatch");
        Buffer block(65536, 0x73);
        for (size_t i = 0; i < 100; ++i) connection->impl_->receiveDatagram(block.data(), block.size());
        expect(connection->impl_->received->bytes == maximumQueuedBytes &&
               connection->impl_->received->packets.size() == 32, "DATAGRAM payload byte budget was not enforced");
        drain(); expect(connection->impl_->received->bytes == 0, "Draining leaked receive byte reservations");
        connection->impl_->receiveDatagram(&byte, 1);
        auto beforeClose = state->delivered;
        auto mailbox = connection->impl_->received;
        connection->close();
        expect(mailbox->packets.empty() && mailbox->bytes == 0 && mailbox->closed,
               "Close did not synchronously free receive payloads");
        connection->impl_->receiveDatagram(&byte, 1);
        expect(mailbox->packets.empty(), "Closed connection admitted a DATAGRAM");
        std::weak_ptr<Connection> lifetime = connection;
        connection.reset();
        expect(lifetime.expired(), "Stalled receive callbacks retained the closed Connection");
        drain(); expect(state->delivered == beforeClose, "Queued callback delivered a DATAGRAM after close");

        auto cancelled = std::shared_ptr<Connection>(new Connection(node, factory));
        cancelled->impl_->owner = cancelled;
        cancelled->impl_->packetReceive = [state](Buffer) { ++state->delivered; };
        cancelled->impl_->receiveDatagram(&byte, 1); state->cancelled = true;
        drain();
        expect(cancelled->impl_->received->closed && cancelled->impl_->received->bytes == 0 &&
               state->delivered == beforeClose, "Factory cancellation did not discard queued receive work");
        cancelled.reset(); state->cancelled = false;

        // Socket connect() does not transmit UDP. Read the actual bound-if
        // options to verify the production setup path, without altering routes.
        std::string physical;
        ifaddrs *interfaces = nullptr;
        if (!getifaddrs(&interfaces)) {
            for (auto value = interfaces; value; value = value->ifa_next) {
                if (!value->ifa_addr || (value->ifa_flags & IFF_LOOPBACK) || !(value->ifa_flags & IFF_UP)) continue;
                if (value->ifa_addr->sa_family == AF_INET && value->ifa_name && if_nametoindex(value->ifa_name)) {
                    physical = value->ifa_name; break;
                }
            }
            freeifaddrs(interfaces);
        }
        if (!physical.empty()) {
            for (const auto *host : {"127.0.0.1", "127.12.34.56", "::1", "::ffff:127.0.0.1", "localhost"}) {
                Node configured = node; configured.host = host; configured.interfaceName = physical;
                auto socketOwner = std::shared_ptr<Connection>(new Connection(configured, factory));
                expect(socketOwner->impl_->setupSocket().empty(), "Loopback socket failed while physical interface was configured");
                expect(isLoopbackAddress(reinterpret_cast<sockaddr *>(&socketOwner->impl_->remote),
                                         socketOwner->impl_->remoteLength), "Resolved localhost was not loopback");
#if defined(__APPLE__)
                unsigned bound = 999; socklen_t size = sizeof(bound);
                bool v6 = socketOwner->impl_->remote.ss_family == AF_INET6;
                expect(!getsockopt(socketOwner->impl_->socket, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
                                   v6 ? IPV6_BOUND_IF : IP_BOUND_IF, &bound, &size) && bound == 0,
                       "Loopback socket remained bound to the physical interface");
#endif
            }
            Node configured = node; configured.host = "192.0.2.1"; configured.interfaceName = physical;
            auto socketOwner = std::shared_ptr<Connection>(new Connection(configured, factory));
            auto error = socketOwner->impl_->setupSocket();
#if defined(__APPLE__)
            if (error.empty()) {
                unsigned bound = 0; socklen_t size = sizeof(bound);
                expect(!getsockopt(socketOwner->impl_->socket, IPPROTO_IP, IP_BOUND_IF, &bound, &size) &&
                       bound == if_nametoindex(physical.c_str()), "Non-loopback socket bypassed physical interface binding");
            } else expect(socketOwner->impl_->socket < 0, "Remote bind failure left an unbound fallback socket");
#else
            expect(error.empty() || socketOwner->impl_->socket < 0, "Remote bind failure left an unbound fallback socket");
#endif
        } else std::cout << "No active non-loopback interface: runtime physical-interface check skipped\n";
        Node invalid = node; invalid.interfaceName = "hajimi-no-such-interface";
        auto badInterface = std::shared_ptr<Connection>(new Connection(invalid, factory));
        expect(badInterface->impl_->setupSocket() == "QUIC interface does not exist" && badInterface->impl_->socket < 0,
               "Invalid physical interface silently fell back to an unbound socket");
        return checks;
    }
};
} // namespace hajimi::quic

int main() {
    try {
        auto checks = hajimi::quic::BoundaryChecks::run();
        std::cout << "C++ QUIC boundaries: " << checks << " mailbox/lifecycle/address/bind checks passed\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
