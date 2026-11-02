#include "SSH.hpp"
#include "Crypto.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <poll.h>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

using namespace hajimi;
namespace {
class SocketStream;
struct Loop {
    using Clock = std::chrono::steady_clock;
    struct Timer { Clock::time_point due; std::function<void()> work; };
    std::queue<std::function<void()>> work;
    std::vector<Timer> timers;
    std::vector<std::weak_ptr<SocketStream>> sockets;
    void post(std::function<void()> next) { work.push(std::move(next)); }
    void after(double seconds, std::function<void()> next) { timers.push_back({Clock::now() + std::chrono::milliseconds(int(seconds * 1000)), std::move(next)}); }
    void drain() {
        size_t count = 0;
        while (!work.empty()) { assert(++count < 1000000); auto next = std::move(work.front()); work.pop(); next(); }
    }
    void until(const std::function<bool()> &done, double seconds = 15);
};
class SocketStream final : public Stream, public std::enable_shared_from_this<SocketStream> {
public:
    SocketStream(Loop &loop, int descriptor) : loop_(loop), descriptor_(descriptor) {}
    ~SocketStream() override { close(); }
    size_t sentBytes = 0;
    int descriptor() const { return descriptor_; }
    short events() const { return short((pendingRead_ ? POLLIN : 0) | (pendingWrite_ ? POLLOUT : 0)); }
    void write(Buffer data, WriteCallback completion) override {
        assert(!pendingWrite_); if (descriptor_ < 0) { completion("Test carrier closed"); return; }
        output_ = std::move(data); offset_ = 0; pendingWrite_ = std::move(completion);
    }
    void read(size_t maximum, ReadCallback completion) override {
        assert(!pendingRead_); if (descriptor_ < 0) { completion({}, true, "Test carrier closed"); return; }
        maximum_ = maximum; pendingRead_ = std::move(completion);
    }
    void close() override {
        if (descriptor_ >= 0) { ::close(descriptor_); descriptor_ = -1; }
        if (auto callback = std::exchange(pendingWrite_, {})) loop_.post([callback = std::move(callback)] { callback("Test carrier closed"); });
        if (auto callback = std::exchange(pendingRead_, {})) loop_.post([callback = std::move(callback)] { callback({}, true, "Test carrier closed"); });
    }
    void tick(short events) {
        if (descriptor_ < 0) return;
        if (pendingWrite_ && (events & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t count = ::send(descriptor_, output_.data() + offset_, output_.size() - offset_, 0);
            if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                std::fprintf(stderr, "SSH fixture TCP send failed: errno=%d, queued=%zu, sent=%zu\n", errno, output_.size() - offset_, sentBytes);
                close(); return;
            }
            if (count > 0) { offset_ += size_t(count); sentBytes += size_t(count); }
            if (offset_ == output_.size()) {
                output_.clear(); offset_ = 0; auto callback = std::exchange(pendingWrite_, {});
                loop_.post([callback = std::move(callback)] { callback({}); });
            }
        }
        if (pendingRead_ && (events & (POLLIN | POLLERR | POLLHUP))) {
            Buffer data(maximum_); ssize_t count = ::recv(descriptor_, data.data(), data.size(), 0);
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (count < 0) { close(); return; }
            data.resize(size_t(count)); auto callback = std::exchange(pendingRead_, {});
            loop_.post([callback = std::move(callback), data = std::move(data), count]() mutable { callback(std::move(data), !count, {}); });
        }
    }
private:
    Loop &loop_;
    int descriptor_;
    Buffer output_;
    size_t offset_ = 0, maximum_ = 0;
    WriteCallback pendingWrite_;
    ReadCallback pendingRead_;
};
void Loop::until(const std::function<bool()> &done, double seconds) {
    auto deadline = Clock::now() + std::chrono::milliseconds(int(seconds * 1000));
    while (!done()) {
        drain(); if (done()) break;
        assert(Clock::now() < deadline);
        auto now = Clock::now();
        for (auto &timer : timers) if (timer.work && timer.due <= now) { post(std::exchange(timer.work, {})); }
        std::vector<pollfd> descriptors; std::vector<std::shared_ptr<SocketStream>> sources;
        for (const auto &weak : sockets) if (auto source = weak.lock(); source && source->descriptor() >= 0 && source->events()) {
            descriptors.push_back({source->descriptor(), source->events(), 0}); sources.push_back(std::move(source));
        }
        int code = ::poll(descriptors.data(), descriptors.size(), 10); assert(code >= 0 || errno == EINTR);
        for (size_t i = 0; i < descriptors.size(); ++i) if (descriptors[i].revents) sources[i]->tick(descriptors[i].revents);
    }
    drain();
}
std::shared_ptr<TransportFactory> makeFactory(Loop &loop) {
    auto factory = std::make_shared<TransportFactory>();
    factory->post = [&loop](std::function<void()> work) { loop.post(std::move(work)); };
    factory->after = [&loop](double seconds, std::function<void()> work) { loop.after(seconds, std::move(work)); };
    factory->tcp = [&loop](const Node &node, const TLSOptions &tls, StreamCallback completion) {
        assert(node.host == "127.0.0.1" && !tls.enabled);
        int descriptor = ::socket(AF_INET, SOCK_STREAM, 0); assert(descriptor >= 0);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(node.port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(descriptor, reinterpret_cast<sockaddr *>(&address), sizeof(address))) { ::close(descriptor); completion({}, "Fixture TCP connect failed"); return; }
        int flags = fcntl(descriptor, F_GETFL, 0); assert(flags >= 0 && !fcntl(descriptor, F_SETFL, flags | O_NONBLOCK));
#ifdef SO_NOSIGPIPE
        int enabled = 1; assert(!setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)));
#endif
        auto stream = std::make_shared<SocketStream>(loop, descriptor); loop.sockets.push_back(stream);
        loop.post([stream, completion = std::move(completion)] { completion(stream, {}); });
    };
    return factory;
}
Buffer bytes(const std::string &text) { return Buffer(text.begin(), text.end()); }
class BlackholeStream final : public Stream {
public:
    explicit BlackholeStream(Loop &loop) : loop_(loop) {}
    void write(Buffer, WriteCallback completion) override { loop_.post([completion = std::move(completion)] { completion({}); }); }
    void read(size_t, ReadCallback completion) override { assert(!pending_); pending_ = std::move(completion); }
    void close() override {
        if (auto completion = std::exchange(pending_, {})) loop_.post([completion = std::move(completion)] { completion({}, true, {}); });
    }
private:
    Loop &loop_;
    ReadCallback pending_;
};
} // namespace

int main(int argc, char **argv) {
    if (argc != 7) { std::fputs("Run through SmokeTests/cpp_ssh_interop.py for the local SSH fixture.\n", stderr); return 2; }
    unsigned port = unsigned(std::stoul(argv[1])); assert(port && port <= 65535);
    Node node; node.type = "ssh"; node.host = "127.0.0.1"; node.port = uint16_t(port);
    node.parameters["username"] = "fixture-user"; node.parameters["password"] = "fixture-password"; node.parameters["host-key"] = argv[2];
    assert(validateSSH(node, false).empty() && !validateSSH(node, true).empty());
    Node insecure = node; insecure.parameters.erase("host-key"); assert(!validateSSH(insecure, false).empty());
    insecure.parameters["skip-cert-verify"] = "true"; assert(validateSSH(insecure, false).empty());
    Node partial = insecure; partial.parameters.erase("skip-cert-verify"); partial.parameters["skip-common-name-verify"] = "true";
    assert(!validateSSH(partial, false).empty());
    Node unsupported = node; unsupported.parameters["host-key-algorithms"] = "not-a-real-ssh-key-algorithm"; assert(!validateSSH(unsupported, false).empty());
    Node missingKey = node; missingKey.parameters["private-key"] = "fixture-file-that-does-not-exist";
    assert(validateSSH(missingKey, false).empty()); // Support checks are pure configuration validation.
    std::istringstream keyText(argv[3]); std::string keyType, encoded; keyText >> keyType >> encoded;
    auto wireKey = crypto::base64Decode(encoded); assert(ssh::hostKeyMatches(node, wireKey));
    Node authorized = node; authorized.parameters["host-key"] = argv[3]; assert(ssh::hostKeyMatches(authorized, wireKey));
    Node wrongPin = node; wrongPin.parameters["host-key"] = "SHA256:" + crypto::base64Encode(Buffer(32, 0));
    wrongPin.parameters["skip-cert-verify"] = "true"; assert(!ssh::hostKeyMatches(wrongPin, wireKey));

    Loop loop; auto factory = makeFactory(loop); Target target{"target.test", 443, false, false};
    {
        char temporary[] = "/tmp/hajimi-ssh-boundary.XXXXXX";
        auto directory = ::mkdtemp(temporary); assert(directory);
        struct Cleanup {
            std::string path;
            ~Cleanup() {
                for (const char *name : {"fifo", "fifo-link", "empty", "oversize", "invalid"})
                    ::unlink((path + "/" + name).c_str());
                ::rmdir(path.c_str());
            }
        } cleanup{directory};
        auto file = [&](const std::string &name, size_t size) {
            int descriptor = ::open((cleanup.path + "/" + name).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            assert(descriptor >= 0);
            assert(!::ftruncate(descriptor, off_t(size))); assert(!::close(descriptor));
        };
        file("empty", 0); file("oversize", 256 * 1024 + 1); file("invalid", 100);
        assert(!::mkfifo((cleanup.path + "/fifo").c_str(), 0600));
        assert(!::symlink((cleanup.path + "/fifo").c_str(), (cleanup.path + "/fifo-link").c_str()));
        auto probe = std::make_shared<TransportFactory>(); unsigned dials = 0;
        probe->post = factory->post; probe->after = factory->after;
        probe->tcp = [&](const Node &, const TLSOptions &, StreamCallback done) {
            ++dials; done({}, "Unexpected dial before private-key validation");
        };
        auto failBeforeDial = [&](const std::string &path, const std::string &expected) {
            Node selected = node; selected.parameters["private-key"] = path;
            assert(validateSSH(selected, false).empty());
            auto started = std::chrono::steady_clock::now();
            unsigned callbacks = 0; Error result;
            connectSSH(selected, target, probe, [&](std::shared_ptr<Stream> stream, Error error) {
                assert(!stream); ++callbacks; result = std::move(error);
            });
            loop.drain();
            assert(callbacks == 1 && dials == 0 && result.find(expected) != std::string::npos);
            assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500));
        };
        auto started = std::chrono::steady_clock::now();
        Node fifo = node; fifo.parameters["private-key"] = cleanup.path + "/fifo";
        for (unsigned i = 0; i < 1000; ++i) assert(validateSSH(fifo, false).empty());
        assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500));
        failBeforeDial(cleanup.path + "/missing", "Cannot read");
        failBeforeDial(cleanup.path + "/fifo", "regular file");
        failBeforeDial(cleanup.path + "/fifo-link", "regular file");
        failBeforeDial(cleanup.path, "regular file");
        failBeforeDial(cleanup.path + "/empty", "empty");
        failBeforeDial(cleanup.path + "/oversize", "bound");
        failBeforeDial(cleanup.path + "/invalid", "not PEM");
        Node bounded = node; bounded.parameters["private-key"] = std::string(256 * 1024 + 1, 'x');
        assert(!validateSSH(bounded, false).empty());
        bounded.parameters["private-key"] = std::string("key\0path", 8);
        assert(!validateSSH(bounded, false).empty());
    }
    unsigned rounds = 0;
    auto roundTrip = [&](Node selected) {
        std::shared_ptr<Stream> stream; bool done = false;
        connectSSH(selected, target, factory, [&](std::shared_ptr<Stream> connected, Error error) {
            if (!error.empty()) std::fprintf(stderr, "SSH fixture positive path failed: %s\n", error.c_str());
            assert(error.empty() && connected); stream = std::move(connected); done = true;
        });
        loop.until([&] { return done; }); assert(stream->supportsHalfClose());
        Buffer payload(350001); for (size_t i = 0; i < payload.size(); ++i) payload[i] = uint8_t(i + rounds);
        Buffer received; unsigned writes = 0; bool eof = false, halfClosed = false, overflow = false, duplicateRead = false;
        stream->write(Buffer(payload.begin(), payload.begin() + 190000), [&](Error error) { assert(error.empty()); ++writes; });
        stream->write(Buffer(payload.begin() + 190000, payload.end()), [&](Error error) { assert(error.empty()); ++writes; });
        stream->write(Buffer(maximumQueuedBytes + 1, 0), [&](Error error) { overflow = !error.empty(); });
        stream->shutdownWrite([&](Error error) { assert(error.empty()); halfClosed = true; });
        std::function<void()> more;
        more = [&] {
            stream->read(1023, [&](Buffer data, bool end, Error error) {
                if (!error.empty()) std::fprintf(stderr, "SSH fixture read failed: round=%u, received=%zu/%zu, error=%s\n",
                                                 rounds + 1, received.size(), payload.size(), error.c_str());
                assert(error.empty()); received.insert(received.end(), data.begin(), data.end()); eof = end; if (!eof) more();
            });
        };
        more(); stream->read(1, [&](Buffer, bool, Error error) { duplicateRead = !error.empty(); });
        loop.until([&] { return eof && halfClosed && writes == 2 && overflow && duplicateRead; });
        assert(received == payload); more = {};
        bool lateWrite = false; stream->write(bytes("after EOF"), [&](Error error) { lateWrite = !error.empty(); });
        loop.drain(); assert(lateWrite);
        std::weak_ptr<Stream> weak = stream; stream->close(); stream.reset(); loop.drain(); assert(weak.expired()); ++rounds;
    };
    roundTrip(node); roundTrip(authorized);
    Node privateKey = node; privateKey.parameters.erase("password"); privateKey.parameters["private-key"] = argv[4];
    privateKey.parameters["host-key-algorithms"] = "rsa-sha2-512|rsa-sha2-256"; roundTrip(privateKey);
    std::ifstream pem(argv[4], std::ios::binary); std::string inlineKey((std::istreambuf_iterator<char>(pem)), {});
    std::string escaped; for (char ch : inlineKey) escaped += ch == '\n' ? "\\n" : std::string(1, ch);
    privateKey.parameters["private-key"] = escaped; roundTrip(privateKey);
    privateKey.parameters["private-key"] = argv[5]; privateKey.parameters["private-key-passphrase"] = "fixture-passphrase"; roundTrip(privateKey);
    privateKey.parameters["private-key"] = argv[6]; privateKey.parameters.erase("private-key-passphrase"); roundTrip(privateKey);

    // Cancel while native wire packets are already draining, not only after EOF.
    std::shared_ptr<Stream> canceled; bool cancellationConnected = false;
    connectSSH(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) {
        assert(error.empty()); canceled = std::move(stream); cancellationConnected = true;
    }); loop.until([&] { return cancellationConnected; });
    auto raw = loop.sockets.back().lock(); assert(raw); size_t baseline = raw->sentBytes;
    unsigned canceledWrites = 0, canceledReads = 0;
    canceled->write(Buffer(1024 * 1024, 0x71), [&](Error error) { assert(!error.empty()); ++canceledWrites; });
    loop.until([&] { return raw->sentBytes > baseline; }); assert(canceledWrites == 0);
    canceled->read(1024, [&](Buffer, bool eof, Error error) { assert(eof && !error.empty()); ++canceledReads; });
    std::weak_ptr<Stream> canceledWeak = canceled; canceled->close(); canceled.reset(); loop.drain();
    assert(canceledWeak.expired() && canceledWrites == 1 && canceledReads == 1);

    auto failure = [&](Node selected, Target destination, const std::string &expected) {
        unsigned callbacks = 0; Error result;
        connectSSH(selected, destination, factory, [&](std::shared_ptr<Stream> stream, Error error) {
            assert(!stream && !error.empty()); ++callbacks; result = std::move(error);
        }); loop.until([&] { return callbacks != 0; }); assert(callbacks == 1 && result.find(expected) != std::string::npos);
        assert(result.find("fixture-password") == std::string::npos && result.find("fixture-passphrase") == std::string::npos);
    };
    failure(wrongPin, target, "host-key pin mismatch");
    Node wrongPassword = node; wrongPassword.parameters["password"] = "wrong-fixture-password";
    failure(wrongPassword, target, "authentication failed");
    failure(node, Target{"reject.test", 443, false, false}, "direct-tcpip request failed");
    Node wrongPassphrase = privateKey; wrongPassphrase.parameters["private-key"] = argv[5];
    wrongPassphrase.parameters["private-key-passphrase"] = "wrong-fixture-passphrase";
    failure(wrongPassphrase, target, "private-key authentication failed");

    auto blackhole = std::make_shared<BlackholeStream>(loop); auto blackFactory = std::make_shared<TransportFactory>();
    blackFactory->post = factory->post; blackFactory->after = factory->after;
    blackFactory->tcp = [&loop, blackhole](const Node &, const TLSOptions &, StreamCallback completion) {
        loop.post([blackhole, completion = std::move(completion)] { completion(blackhole, {}); });
    };
    unsigned timeoutCallbacks = 0;
    connectSSH(node, target, blackFactory, [&](std::shared_ptr<Stream> stream, Error error) {
        assert(!stream && error.find("timed out") != std::string::npos); ++timeoutCallbacks;
    }); loop.drain(); assert(!timeoutCallbacks && loop.timers.back().work);
    auto timeout = std::exchange(loop.timers.back().work, {}); timeout(); loop.drain(); assert(timeoutCallbacks == 1);
    timeout(); loop.drain(); assert(timeoutCallbacks == 1);
    std::puts("C++ SSH: pinned identities, password/RSA/PEM/OpenSSH/Ed25519 auth, TCP data, half-close, and negative paths passed");
}
