#if defined(__APPLE__) && !defined(__APPLE_USE_RFC_3542)
#define __APPLE_USE_RFC_3542 1
#endif
#include "QUICTransport.hpp"
#include "ProtocolCommon.hpp"
#include "Crypto.hpp"
#include <ngtcp2/ngtcp2.h>
#include <cmath>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#ifndef NGTCP2_PROTO_VER_V2
#define NGTCP2_PROTO_VER_V2 0x6b3343cfU
#endif
#include <openssl/x509v3.h>
#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/event.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <deque>
#include <fstream>
#include <list>
#include <mutex>
#include <thread>
#include <algorithm>
#include <cstring>
#include <utility>
#if defined(HAJIMI_QUIC_DIAGNOSTICS)
#include <cstdio>
#include <cstdlib>
#endif

namespace hajimi::quic {
namespace {
ngtcp2_tstamp now() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
// BLAKE2b with a 32-byte digest (not a truncation of BLAKE2b-512).
Buffer blake2b256(const Buffer &input);
bool computeObfsKey(bool salamander, const std::string &password,
                    const uint8_t *salt, size_t saltLen, uint8_t outKey[32]);

struct QuicSessionCache {
    static constexpr size_t kMaxEntries = 64;
    struct Entry {
        SSL_SESSION *session = nullptr;
        std::list<std::string>::iterator lruIt;
    };
    std::mutex mutex;
    std::list<std::string> lru;
    std::unordered_map<std::string, Entry> entries;
};

QuicSessionCache &sharedQuicSessionCache() {
    static auto *cache = new QuicSessionCache();
    return *cache;
}

bool isSessionFresh(const SSL_SESSION *session) {
    if (!session || !SSL_SESSION_is_resumable(session)) return false;
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
    time_t created = SSL_SESSION_get_time_ex(session);
#else
    time_t created = static_cast<time_t>(SSL_SESSION_get_time(session));
#endif
    long timeout = SSL_SESSION_get_timeout(session);
    time_t current = std::time(nullptr);
    if (created <= 0 || timeout <= 0 || current < created) return false;
    return (current - created) < static_cast<time_t>(timeout);
}

SSL_SESSION *getCachedQuicSession(const std::string &key) {
    if (key.empty()) return nullptr;
    auto &cache = sharedQuicSessionCache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto it = cache.entries.find(key);
    if (it == cache.entries.end()) return nullptr;
    if (!isSessionFresh(it->second.session)) {
        SSL_SESSION_free(it->second.session);
        cache.lru.erase(it->second.lruIt);
        cache.entries.erase(it);
        return nullptr;
    }
    cache.lru.splice(cache.lru.begin(), cache.lru, it->second.lruIt);
    if (SSL_SESSION_up_ref(it->second.session) != 1) return nullptr;
    return it->second.session;
}

bool storeCachedQuicSession(const std::string &key, SSL_SESSION *session) {
    if (key.empty() || !isSessionFresh(session)) return false;
    auto &cache = sharedQuicSessionCache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto existing = cache.entries.find(key);
    if (existing != cache.entries.end()) {
        if (existing->second.session != session) {
            SSL_SESSION_free(existing->second.session);
            existing->second.session = session;
        } else {
            return false;
        }
        cache.lru.splice(cache.lru.begin(), cache.lru, existing->second.lruIt);
        return true;
    }
    while (cache.entries.size() >= QuicSessionCache::kMaxEntries && !cache.lru.empty()) {
        const std::string &oldest = cache.lru.back();
        auto oldIt = cache.entries.find(oldest);
        if (oldIt != cache.entries.end()) {
            SSL_SESSION_free(oldIt->second.session);
            cache.entries.erase(oldIt);
        }
        cache.lru.pop_back();
    }
    cache.lru.push_front(key);
    cache.entries.emplace(key, QuicSessionCache::Entry{session, cache.lru.begin()});
    return true;
}

void evictCachedQuicSession(const std::string &key) {
    if (key.empty()) return;
    auto &cache = sharedQuicSessionCache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto it = cache.entries.find(key);
    if (it == cache.entries.end()) return;
    SSL_SESSION_free(it->second.session);
    cache.lru.erase(it->second.lruIt);
    cache.entries.erase(it);
}

std::string computeCaHash(const std::string &caPath) {
    if (caPath.empty()) return {};
    Buffer material(caPath.begin(), caPath.end());
    material.push_back(0);
    std::ifstream in(caPath, std::ios::binary);
    if (in) {
        char chunk[4096];
        size_t total = 0;
        while (in && total < 262144) {
            in.read(chunk, static_cast<std::streamsize>(std::min<size_t>(sizeof(chunk), 262144 - total)));
            auto got = static_cast<size_t>(in.gcount());
            if (!got) break;
            material.insert(material.end(), reinterpret_cast<const uint8_t *>(chunk),
                            reinterpret_cast<const uint8_t *>(chunk) + got);
            total += got;
        }
    }
    return crypto::base64Encode(crypto::digest("SHA256", material));
}
uint64_t parseQuicBandwidthBytesPerSec(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c); }), value.end());
    if (value.empty()) return 0;
    char *end = nullptr;
    double number = std::strtod(value.c_str(), &end);
    if (end == value.c_str() || !std::isfinite(number) || number <= 0) return 0;
    std::string unit(end);
    double multiplier = 125000.0; // Bare value: Mbps
    if (!unit.empty()) {
        multiplier = 1.0;
        auto power = std::string("KMGT").find(static_cast<char>(std::toupper(unit[0])));
        if (power != std::string::npos) {
            multiplier = std::pow(1024.0, power + 1);
            unit.erase(0, 1);
        }
        if (unit.empty() || (unit[0] != 'b' && unit[0] != 'B')) return 0;
        if (unit[0] == 'b') multiplier /= 8.0;
        unit.erase(0, 1);
        if (!unit.empty() && unit != "ps" && unit != "/s") return 0;
    }
    double bytes = number * multiplier;
    return (bytes < static_cast<double>(UINT64_MAX) && bytes >= 1.0) ? static_cast<uint64_t>(bytes) : 0;
}
bool isLoopbackAddress(const sockaddr *address, socklen_t size) {
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
void traceStream(const Node &node, const char *event, int64_t id, size_t bytes, bool fin, bool pending) {
#if defined(HAJIMI_QUIC_DIAGNOSTICS)
    if (std::getenv("HAJIMI_QUIC_TEST_TRACE"))
        std::fprintf(stderr, "%s native %s stream=%lld bytes=%zu fin=%d read=%d\n",
                     node.type.c_str(), event, static_cast<long long>(id), bytes, fin, pending);
#else
    (void)node; (void)event; (void)id; (void)bytes; (void)fin; (void)pending;
#endif
}
}

struct Connection::Impl {
    struct Write {
        Buffer bytes; uint64_t offset = 0; size_t sent = 0;
        WriteCallback completion;
    };
    struct State {
        std::deque<Write> writes; proto_common::CursorBuffer input; uint64_t end = 0;
        size_t readMaximum = 0; ReadCallback read;
        bool eof = false, fin = false, finSent = false, closed = false;
        bool finished = false, eofDelivered = false;
        Error error; WriteCallback shutdown;
    };
    struct Channel final : Stream {
        std::weak_ptr<Connection> connection; int64_t id;
        Channel(std::shared_ptr<Connection> value, int64_t streamID)
            : connection(value), id(streamID) {}
        ~Channel() override = default;
        void write(Buffer, WriteCallback) override;
        void read(size_t, ReadCallback) override;
        void close() override;
        void shutdownWrite(WriteCallback) override;
        bool supportsHalfClose() const override { return true; }
    };
    // The application strand can be slower than the UDP reactor. Bound both
    // payload bytes and objects before copying/dispatching, including empty
    // DATAGRAMs, and merge reception into one scheduled batch at a time.
    struct ReceiveMailbox {
        static constexpr size_t maximumPackets = 512, maximumBatch = 64;
        std::mutex mutex;
        std::deque<Buffer> packets;
        size_t bytes = 0;
        bool scheduled = false, closed = false;
        void close() {
            std::lock_guard<std::mutex> lock(mutex);
            closed = true; scheduled = false; packets.clear(); bytes = 0;
        }
    };
    Node node; std::shared_ptr<TransportFactory> factory;
    std::weak_ptr<Connection> owner; std::thread worker;
    std::mutex mutex; std::deque<std::function<void()>> jobs;
    std::atomic<bool> stopping{false}; std::atomic<bool> wakePending{false};
    std::atomic<size_t> datagramSize{0};
    std::atomic<size_t> stagedWrites{0}, stagedPackets{0}; bool jobsClosed = false;
    std::shared_ptr<ReceiveMailbox> received = std::make_shared<ReceiveMailbox>();
    int socket = -1, wake[2]{-1, -1};
#if defined(__APPLE__)
    int kq_ = -1;
    int registeredSocket_ = -1;
    bool writeFilterEnabled_ = false;
#endif
    int lastSocketEcn_ = -1;
    uint8_t pendingWireEcn_ = 0;
    uint8_t obfsSaltSize_ = 0;
    bool salamanderObfs_ = false;
    std::string obfsPassword_;
    std::string sessionCacheKey_;
    bool usedCachedSession_ = false;
    std::shared_ptr<Datagram> chainedDatagram;
    std::deque<Buffer> chainedInbound;
    uint16_t activePort = 0;
    sockaddr_storage local{}, remote{}; socklen_t localLength = 0, remoteLength = 0;
    uint16_t selectTargetPort() const {
        auto raw = node.option("ports", node.option("port-range"));
        if (raw.empty()) return node.port;
        std::vector<std::pair<uint16_t, uint16_t>> ranges;
        size_t pos = 0;
        while (pos <= raw.size()) {
            auto comma = raw.find(',', pos);
            if (comma == std::string::npos) comma = raw.size();
            auto token = raw.substr(pos, comma - pos);
            pos = comma + 1;
            auto dash = token.find('-');
            try {
                if (dash == std::string::npos) {
                    int p = std::stoi(token);
                    if (p >= 1 && p <= 65535) ranges.push_back({uint16_t(p), uint16_t(p)});
                } else {
                    int a = std::stoi(token.substr(0, dash));
                    int b = std::stoi(token.substr(dash + 1));
                    if (a >= 1 && b >= a && b <= 65535) ranges.push_back({uint16_t(a), uint16_t(b)});
                }
            } catch (...) {}
        }
        if (ranges.empty()) return node.port;
        uint8_t r[4]{};
        (void)RAND_bytes(r, sizeof(r));
        const auto &picked = ranges[r[0] % ranges.size()];
        uint16_t span = uint16_t(picked.second - picked.first + 1);
        uint16_t offset = span > 1 ? uint16_t(((uint16_t(r[1]) << 8) | r[2]) % span) : 0;
        return uint16_t(picked.first + offset);
    }
    ngtcp2_conn *conn = nullptr; SSL_CTX *tlsContext = nullptr; SSL *tls = nullptr;
    ngtcp2_crypto_ossl_ctx *cryptoContext = nullptr; ngtcp2_crypto_conn_ref reference{};
    std::unordered_map<int64_t, State> streams;
    struct Packet { Buffer bytes; WriteCallback completion; };
    std::deque<Packet> packets; Buffer pendingWire;
    size_t writeBytes = 0, readBytes = 0, packetBytes = 0;
    Ready ready; std::function<void(Buffer)> packetReceive; WriteCallback packetFailure;
    std::function<void(std::shared_ptr<Stream>)> peerStreams;
    Error terminal; bool handshake = false, applicationReady = false;
    std::string verifyName;
    ngtcp2_tstamp deadline = 0;
    enum class DPLPMTUDState : uint8_t { Base = 0, Searching = 1, SearchComplete = 2, BlackholeRecovery = 3 };
    DPLPMTUDState pmtudState_ = DPLPMTUDState::Searching;
    size_t maxTxPayload_ = 1350;
    size_t pmtudProbesSucceeded_ = 0;
    size_t consecutiveSendLosses_ = 0;
    uint64_t brutalUpBps_ = 0;
    uint64_t brutalTokens_ = 0;
    ngtcp2_tstamp brutalLastRefill_ = 0;
    bool hasObfuscation() const { return obfsSaltSize_ != 0; }
    size_t obfsOverhead() const { return obfsSaltSize_; }
    void notifyWake() {
        if (!wakePending.exchange(true, std::memory_order_acq_rel) && wake[1] >= 0) {
            uint8_t value = 1;
            (void)::write(wake[1], &value, 1);
        }
    }
    bool migrateSocketOnPathChange() {
        int oldSocket = socket;
        socket = -1;
        if (!setupSocket().empty() || socket < 0) {
            socket = oldSocket;
            return false;
        }
        if (oldSocket >= 0) ::close(oldSocket);
#if defined(__APPLE__)
        registeredSocket_ = -1;
        writeFilterEnabled_ = false;
#endif
        if (conn) {
            ngtcp2_addr localAddr{reinterpret_cast<sockaddr *>(&local), localLength};
            ngtcp2_conn_set_local_addr(conn, &localAddr);
        }
        return true;
    }

    Impl(Node value, std::shared_ptr<TransportFactory> io)
        : node(std::move(value)), factory(std::move(io)) {
        if (node.type == "hysteria2" && node.option("obfs") == "salamander") {
            obfsPassword_ = node.option("obfs-password");
            if (!obfsPassword_.empty()) {
                salamanderObfs_ = true;
                obfsSaltSize_ = 8;
            }
        } else if (node.type == "hysteria") {
            obfsPassword_ = node.option("obfs");
            if (!obfsPassword_.empty()) {
                salamanderObfs_ = false;
                obfsSaltSize_ = 16;
            }
        }
    }
    ~Impl();
    bool cancellationRequested() const {
        return factory && factory->cancelled && factory->cancelled();
    }
    bool cancelled() const { return stopping.load() || cancellationRequested(); }
    void dispatch(std::function<void()> callback) {
        if (factory && factory->post) factory->post(std::move(callback));
        else callback();
    }
    void post(std::function<void()> callback);
    void receiveDatagram(const uint8_t *, size_t);
    void dispatchDatagrams(std::function<void(Buffer)>);
    void drainDatagrams(const std::function<void(Buffer)> &);
    static bool reserve(std::atomic<size_t> &bytes, size_t count) {
        size_t previous = bytes.load();
        do { if (count > maximumQueuedBytes - previous) return false; }
        while (!bytes.compare_exchange_weak(previous, previous + count));
        return true;
    }
    void fail(Error);
    void run();
    Error setupSocket(); Error setupTLS(); Error setupQUIC();
    Error readPackets(); Error writePackets();
    Buffer obfuscate(const uint8_t *, size_t, bool);
    void satisfy(int64_t);
    void collect(int64_t id) {
        if (stopping) return; // fail() walks the stream map to cancel callbacks.
        auto found = streams.find(id); if (found == streams.end()) return;
        auto &state = found->second;
        if (state.finished && state.writes.empty() && state.input.empty() && !state.read &&
            (state.closed || (id & 3) == 2 || ((id & 3) == 3 && state.eofDelivered))) streams.erase(found);
    }
    void addStream(bool, StreamCallback);
    void queueWrite(int64_t, Buffer, WriteCallback);
    void queueRead(int64_t, size_t, ReadCallback);
    void finishWrite(int64_t, WriteCallback);
    void closeStream(int64_t);
    static int receive(ngtcp2_conn *, uint32_t, int64_t, uint64_t,
                       const uint8_t *, size_t, void *, void *);
    static int acknowledge(ngtcp2_conn *, int64_t, uint64_t, uint64_t, void *, void *);
    static int streamClosed(ngtcp2_conn *, uint32_t, int64_t, uint64_t, void *, void *);
    static int streamReset(ngtcp2_conn *, int64_t, uint64_t, uint64_t, void *, void *);
    static int handshakeDone(ngtcp2_conn *, void *);
    static int newSessionCallback(SSL *, SSL_SESSION *);
#if defined(__APPLE__)
    static int certificateTrust(X509_STORE_CTX *, void *);
#endif
};

Connection::Impl::~Impl() {
    stopping = true;
    received->close();
    if (worker.joinable()) {
        if (worker.get_id() == std::this_thread::get_id()) worker.detach();
        else worker.join();
    }
    if (tls) { SSL_set_app_data(tls, nullptr); SSL_free(tls); }
    if (cryptoContext) ngtcp2_crypto_ossl_ctx_del(cryptoContext);
    if (conn) ngtcp2_conn_del(conn);
    if (tlsContext) SSL_CTX_free(tlsContext);
    if (chainedDatagram) { chainedDatagram->close(); chainedDatagram.reset(); }
#if defined(__APPLE__)
    if (kq_ >= 0) ::close(kq_);
#endif
    if (socket >= 0) ::close(socket);
    for (auto fd : wake) if (fd >= 0) ::close(fd);
}

void Connection::Impl::receiveDatagram(const uint8_t *data, size_t size) {
    if (cancelled() || !packetReceive) return;
    {
        std::lock_guard<std::mutex> lock(received->mutex);
        if (received->closed || received->packets.size() >= ReceiveMailbox::maximumPackets ||
            size > maximumQueuedBytes - received->bytes) return; // UDP drops under pressure.
        Buffer bytes;
        if (size) bytes.assign(data, data + size);
        received->packets.push_back(std::move(bytes)); received->bytes += size;
        if (received->scheduled) return;
        received->scheduled = true;
    }
    dispatchDatagrams(packetReceive);
}

void Connection::Impl::dispatchDatagrams(std::function<void(Buffer)> callback) {
    auto weak = owner; auto mailbox = received;
    // A stalled application queue must not keep a cancelled reactor, its TLS
    // context or socket alive. close() frees queued payloads synchronously.
    dispatch([weak, mailbox, callback = std::move(callback)] {
        auto connection = weak.lock();
        if (!connection || connection->isClosed()) { mailbox->close(); return; }
        connection->impl_->drainDatagrams(callback);
    });
}

void Connection::Impl::drainDatagrams(const std::function<void(Buffer)> &callback) {
    for (size_t count = 0; count < ReceiveMailbox::maximumBatch; ++count) {
        if (cancelled()) { received->close(); return; }
        Buffer bytes;
        {
            std::lock_guard<std::mutex> lock(received->mutex);
            if (received->closed) return;
            if (received->packets.empty()) { received->scheduled = false; return; }
            bytes = std::move(received->packets.front()); received->packets.pop_front();
            received->bytes -= bytes.size();
        }
        callback(std::move(bytes));
    }
    {
        std::lock_guard<std::mutex> lock(received->mutex);
        if (received->closed) return;
        if (received->packets.empty()) { received->scheduled = false; return; }
    }
    dispatchDatagrams(callback); // Yield to other work between bounded batches.
}

void Connection::Impl::post(std::function<void()> callback) {
    bool finished = false;
    { std::lock_guard<std::mutex> lock(mutex); finished = jobsClosed;
      if (!finished) jobs.push_back(std::move(callback)); }
    if (finished) { dispatch(std::move(callback)); return; }
    notifyWake();
}

Error Connection::Impl::setupSocket() {
    if (cancelled()) return "QUIC connection cancelled";
    lastSocketEcn_ = -1;
    activePort = selectTargetPort();
    if (!node.option("underlying-proxy", node.option("dialer-proxy")).empty() && factory && factory->udp) {
        sockaddr_in loc4{}, rem4{};
        loc4.sin_family = AF_INET; loc4.sin_port = htons(10000); loc4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rem4.sin_family = AF_INET; rem4.sin_port = htons(activePort ? activePort : 443); rem4.sin_addr.s_addr = htonl(0x7f000002);
        localLength = sizeof(loc4); remoteLength = sizeof(rem4);
        std::memcpy(&local, &loc4, localLength); std::memcpy(&remote, &rem4, remoteLength);
        struct ChainedUDPWaitState {
            std::mutex lock;
            std::condition_variable cv;
            bool done = false;
            bool abandoned = false;
            std::shared_ptr<Datagram> dgram;
            Error dialErr;
        };
        auto waitState = std::make_shared<ChainedUDPWaitState>();
        auto startUDP = [factory = this->factory, node = this->node, waitState]() {
            factory->udp(node, [waitState](std::shared_ptr<Datagram> d, Error e) {
                bool shouldClose = false;
                {
                    std::lock_guard<std::mutex> g(waitState->lock);
                    if (waitState->abandoned) {
                        shouldClose = true;
                    } else {
                        waitState->dgram = std::move(d);
                        waitState->dialErr = std::move(e);
                        waitState->done = true;
                    }
                }
                if (shouldClose && d) d->close();
                waitState->cv.notify_one();
            });
        };
        if (factory->post) factory->post(startUDP);
        else startUDP();
        std::shared_ptr<Datagram> dgram;
        Error dialErr;
        bool completed = false;
        {
            std::unique_lock<std::mutex> u(waitState->lock);
            waitState->cv.wait_for(u, std::chrono::seconds(10), [&] { return waitState->done || cancelled(); });
            if (!waitState->done || cancelled()) {
                waitState->abandoned = true;
                dgram = std::move(waitState->dgram);
            } else {
                completed = true;
                dgram = std::move(waitState->dgram);
                dialErr = std::move(waitState->dialErr);
            }
        }
        if (cancelled()) { if (dgram) dgram->close(); return "QUIC connection cancelled"; }
        if (!completed || !dialErr.empty() || !dgram) {
            if (dgram) dgram->close();
            return dialErr.empty() ? Error("QUIC underlying-proxy UDP relay unavailable") : dialErr;
        }
        chainedDatagram = dgram;
        std::weak_ptr<Connection> weakOwner = owner;
        chainedDatagram->start(
            [weakOwner](Target, Buffer pkt) {
                auto connOwner = weakOwner.lock();
                if (!connOwner || connOwner->isClosed()) return;
                auto *impl = connOwner->impl_.get();
                {
                    std::lock_guard<std::mutex> g(impl->mutex);
                    if (impl->chainedInbound.size() < 512) impl->chainedInbound.push_back(std::move(pkt));
                }
                impl->notifyWake();
            },
            [weakOwner](Error e) {
                auto connOwner = weakOwner.lock();
                if (!connOwner) return;
                connOwner->impl_->post([weakOwner, e] {
                    if (auto c = weakOwner.lock()) c->impl_->fail(e.empty() ? "QUIC underlying UDP relay closed" : e);
                });
            }
        );
        return {};
    }
    addrinfo hints{}, *addresses = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    // AI_NUMERICHOST is essential: this call only converts a pinned address,
    // never performs an implicit system/plaintext DNS bootstrap for QUIC.
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    int resolved = getaddrinfo(node.dialHost().c_str(), std::to_string(activePort ? activePort : node.port).c_str(), &hints, &addresses);
    if (cancelled()) {
        if (addresses) freeaddrinfo(addresses);
        return "QUIC connection cancelled";
    }
    if (resolved) return "QUIC server needs a numeric encrypted-DNS bootstrap address";
    unsigned index = node.interfaceName.empty() ? 0 : if_nametoindex(node.interfaceName.c_str());
    if (!node.interfaceName.empty() && !index) {
        freeaddrinfo(addresses); return "QUIC interface does not exist";
    }
    for (auto address = addresses; address; address = address->ai_next) {
        if (cancelled()) { freeaddrinfo(addresses); return "QUIC connection cancelled"; }
        int candidate = ::socket(address->ai_family, SOCK_DGRAM, 0);
        if (candidate < 0) continue;
        int flags = fcntl(candidate, F_GETFL, 0);
        fcntl(candidate, F_SETFL, flags | O_NONBLOCK);
        fcntl(candidate, F_SETFD, FD_CLOEXEC);
        // Decide per resolved address, not by hostname: localhost may resolve
        // to either family, and a mixed answer must never unbind a remote peer.
        if (index && !isLoopbackAddress(address->ai_addr, address->ai_addrlen)) {
#if defined(__APPLE__)
            int level = address->ai_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
            int option = address->ai_family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
            if (setsockopt(candidate, level, option, &index, sizeof(index))) {
                ::close(candidate); continue;
            }
#else
            if (setsockopt(candidate, SOL_SOCKET, SO_BINDTODEVICE,
                           node.interfaceName.c_str(), node.interfaceName.size() + 1)) {
                ::close(candidate); continue;
            }
#endif
        }
        for (int bufSize : {4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024}) {
            if (setsockopt(candidate, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize)) == 0) break;
        }
        for (int bufSize : {4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024}) {
            if (setsockopt(candidate, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize)) == 0) break;
        }
        // RFC 9000 §14: QUIC packets MUST NOT be fragmented at the IP layer;
        // enabling Don't-Fragment lets oversized probes surface EMSGSIZE to DPLPMTUD.
#if defined(__APPLE__)
        if (address->ai_family == AF_INET) {
            int df = 1;
            (void)setsockopt(candidate, IPPROTO_IP, IP_DONTFRAG, &df, sizeof(df));
        } else if (address->ai_family == AF_INET6) {
            int df = 1;
            (void)setsockopt(candidate, IPPROTO_IPV6, IPV6_DONTFRAG, &df, sizeof(df));
        }
#elif defined(__linux__)
        if (address->ai_family == AF_INET) {
            int df = IP_PMTUDISC_DO;
            (void)setsockopt(candidate, IPPROTO_IP, IP_MTU_DISCOVER, &df, sizeof(df));
        } else if (address->ai_family == AF_INET6) {
            int df = IPV6_PMTUDISC_DO;
            (void)setsockopt(candidate, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &df, sizeof(df));
        }
#endif
        if (obfsOverhead() == 0) {
            int ecnRecv = 1;
            if (address->ai_family == AF_INET) {
#if defined(IP_RECVTOS)
                (void)setsockopt(candidate, IPPROTO_IP, IP_RECVTOS, &ecnRecv, sizeof(ecnRecv));
#endif
            } else if (address->ai_family == AF_INET6) {
#if defined(IPV6_RECVTCLASS)
                (void)setsockopt(candidate, IPPROTO_IPV6, IPV6_RECVTCLASS, &ecnRecv, sizeof(ecnRecv));
#endif
            }
        }
        if (::connect(candidate, address->ai_addr, address->ai_addrlen)) {
            ::close(candidate); continue;
        }
        if (cancelled()) {
            ::close(candidate); freeaddrinfo(addresses); return "QUIC connection cancelled";
        }
        remoteLength = address->ai_addrlen;
        std::memcpy(&remote, address->ai_addr, remoteLength); socket = candidate; break;
    }
    freeaddrinfo(addresses);
    if (cancelled()) return "QUIC connection cancelled";
    if (socket < 0) return "QUIC UDP socket connect/bind failed";
    localLength = sizeof(local);
    if (getsockname(socket, reinterpret_cast<sockaddr *>(&local), &localLength))
        return "QUIC local socket address unavailable";
    return {};
}

Error Connection::Impl::setupTLS() {
    if (cancelled()) return "QUIC connection cancelled";
    static std::once_flag initialized;
    std::call_once(initialized, [] { ngtcp2_crypto_ossl_init(); });
    tlsContext = SSL_CTX_new(TLS_client_method());
    if (!tlsContext || !SSL_CTX_set_min_proto_version(tlsContext, TLS1_3_VERSION))
        return "QUIC TLS context creation failed";
    // RFC 10024 / NIST FIPS 203: Post-quantum hybrid X25519MLKEM768 is opt-in for QUIC (`pqc=true`),
    // because a 1216-byte hybrid key_share fragments QUIC Initial ClientHello across multiple UDP
    // datagrams and breaks QUIC peers (e.g. aioquic / older quic-go) that lack HelloRetryRequest.
    // When opted in, `*` prefixes instruct OpenSSL 3.5+ to send BOTH hybrid and X25519 key shares.
    auto pqOption = proto_common::lowerAscii(node.option("pqc", node.option("pq", "off")));
    bool enablePQC = (pqOption == "true" || pqOption == "1" || pqOption == "on");
    ERR_set_mark();
    if (!enablePQC || SSL_CTX_set1_groups_list(tlsContext, "*X25519MLKEM768:*X25519:P-256:P-384") != 1) {
        ERR_pop_to_mark();
        (void)SSL_CTX_set1_groups_list(tlsContext, "X25519:P-256:P-384");
    } else {
        ERR_clear_last_mark();
    }
    auto options = tlsOptions(node, true);
    SSL_CTX_set_verify(tlsContext, options.skipVerify ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_session_cache_mode(tlsContext, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(tlsContext, newSessionCallback);
    verifyName = options.serverName.empty() ? node.host : options.serverName;
    std::string caPath;
    if (!options.skipVerify) {
        caPath = node.option("ca");
        if (caPath.empty()) {
#if defined(__APPLE__)
            // Static OpenSSL cannot assume Homebrew's cert.pem exists on the
            // recipient's Mac. Use the system trust store + hostname policy.
            SSL_CTX_set_cert_verify_callback(tlsContext, certificateTrust, this);
#else
            if (!SSL_CTX_set_default_verify_paths(tlsContext)) return "QUIC trust store unavailable";
#endif
        } else if (!SSL_CTX_load_verify_locations(tlsContext, caPath.c_str(), nullptr))
            return "QUIC CA file could not be loaded";
    }
    if (cancelled()) return "QUIC connection cancelled";
    tls = SSL_new(tlsContext);
    if (!tls || ngtcp2_crypto_ossl_ctx_new(&cryptoContext, tls) ||
        ngtcp2_crypto_ossl_configure_client_session(tls)) return "QUIC TLS initialization failed";
    reference.user_data = this;
    reference.get_conn = [](ngtcp2_crypto_conn_ref *ref) {
        return static_cast<Impl *>(ref->user_data)->conn;
    };
    SSL_set_app_data(tls, &reference); SSL_set_connect_state(tls);
    std::string name = options.serverName.empty() ? node.host : options.serverName;
    if (name.size() >= 2 && name.front() == '[' && name.back() == ']')
        name = name.substr(1, name.size() - 2);
    if (name.find(':') != std::string::npos) {
        auto scope = name.find('%');
        if (scope != std::string::npos) name.resize(scope);
    }
    uint8_t numeric[16];
    bool isIP = inet_pton(AF_INET, name.c_str(), numeric) == 1 ||
                inet_pton(AF_INET6, name.c_str(), numeric) == 1;
    const bool disableSni = node.flag("disable-sni");
    if (!isIP && !disableSni && !SSL_set_tlsext_host_name(tls, name.c_str()))
        return "QUIC SNI configuration failed";
    if (!options.skipVerify) {
        auto params = SSL_get0_param(tls);
        if (isIP) {
            if (!X509_VERIFY_PARAM_set1_ip_asc(params, name.c_str())) return "QUIC IP verification setup failed";
        } else if (!SSL_set1_host(tls, name.c_str())) return "QUIC hostname verification setup failed";
    }
    if (options.alpn.empty()) {
        if (node.type == "hysteria") {
            options.alpn.push_back("hysteria");
            options.alpn.push_back("h3");
        } else {
            options.alpn.push_back("h3");
        }
    }
    Buffer alpn;
    for (const auto &value : options.alpn) {
        if (value.empty() || value.size() > 255) return "QUIC ALPN value is invalid";
        alpn.push_back(static_cast<uint8_t>(value.size()));
        alpn.insert(alpn.end(), value.begin(), value.end());
    }
    if (SSL_set_alpn_protos(tls, alpn.data(), static_cast<unsigned>(alpn.size())))
        return "QUIC ALPN configuration failed";
    {
        uint16_t effPort = activePort ? activePort : node.port;
        std::string caHash = options.skipVerify ? std::string{} : computeCaHash(caPath);
        sessionCacheKey_.clear();
        sessionCacheKey_.reserve(128 + caHash.size() + alpn.size() * 2);
        sessionCacheKey_ += node.dialHost();
        sessionCacheKey_.push_back('|');
        sessionCacheKey_ += std::to_string(effPort);
        sessionCacheKey_.push_back('|');
        sessionCacheKey_ += verifyName;
        sessionCacheKey_.push_back('|');
        sessionCacheKey_ += disableSni ? "nosni|" : "sni|";
        sessionCacheKey_ += crypto::base64Encode(alpn);
        sessionCacheKey_.push_back('|');
        sessionCacheKey_ += options.skipVerify ? "1|" : "0|";
        sessionCacheKey_ += caHash;
        if (SSL_SESSION *cached = getCachedQuicSession(sessionCacheKey_)) {
            if (SSL_set_session(tls, cached) == 1) {
                usedCachedSession_ = true;
            }
            SSL_SESSION_free(cached);
        }
    }
    return cancelled() ? "QUIC connection cancelled" : Error{};
}

int Connection::Impl::newSessionCallback(SSL *ssl, SSL_SESSION *session) {
    if (!ssl || !session) return 0;
    auto *ref = static_cast<ngtcp2_crypto_conn_ref *>(SSL_get_app_data(ssl));
    if (!ref || !ref->user_data) return 0;
    auto *self = static_cast<Impl *>(ref->user_data);
    if (self->cancelled() || self->sessionCacheKey_.empty()) return 0;
    if (SSL_get_verify_mode(ssl) != SSL_VERIFY_NONE && SSL_get_verify_result(ssl) != X509_V_OK) return 0;
    return storeCachedQuicSession(self->sessionCacheKey_, session) ? 1 : 0;
}

#if defined(__APPLE__)
int Connection::Impl::certificateTrust(X509_STORE_CTX *store, void *user) {
    auto self = static_cast<Impl *>(user);
    if (self->cancelled()) {
        self->terminal = "QUIC connection cancelled";
        X509_STORE_CTX_set_error(store, X509_V_ERR_CERT_REJECTED); return 0;
    }
    struct Release {
        CFTypeRef object = nullptr;
        ~Release() { if (object) CFRelease(object); }
    };
    auto certificates = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    Release certificatesLife{certificates};
    auto hostname = CFStringCreateWithBytes(kCFAllocatorDefault,
        reinterpret_cast<const UInt8 *>(self->verifyName.data()), self->verifyName.size(),
        kCFStringEncodingUTF8, false);
    Release hostnameLife{hostname};
    if (!certificates || !hostname) { X509_STORE_CTX_set_error(store, X509_V_ERR_OUT_OF_MEM); return 0; }
    auto appendCertificate = [certificates](X509 *certificate) {
        int size = i2d_X509(certificate, nullptr);
        if (size <= 0 || size > 1024 * 1024) return false;
        Buffer der(static_cast<size_t>(size)); auto destination = der.data();
        if (i2d_X509(certificate, &destination) != size) return false;
        auto bytes = CFDataCreate(kCFAllocatorDefault, der.data(), der.size()); Release bytesLife{bytes};
        if (!bytes) return false;
        auto value = SecCertificateCreateWithData(kCFAllocatorDefault, bytes); Release valueLife{value};
        if (!value) return false;
        CFArrayAppendValue(certificates, value); return true;
    };
    bool valid = false;
    try {
        auto leaf = X509_STORE_CTX_get0_cert(store); auto chain = X509_STORE_CTX_get0_untrusted(store);
        int count = chain ? sk_X509_num(chain) : 0;
        if (leaf && count <= 16 && appendCertificate(leaf)) {
            bool complete = true;
            for (int index = 0; index < count; ++index) {
                auto certificate = sk_X509_value(chain, index);
                if (X509_cmp(leaf, certificate) != 0 && !appendCertificate(certificate)) { complete = false; break; }
            }
            auto policy = SecPolicyCreateSSL(true, hostname); Release policyLife{policy};
            SecTrustRef trust = nullptr;
            if (complete && policy && SecTrustCreateWithCertificates(certificates, policy, &trust) == errSecSuccess) {
                Release trustLife{trust}; CFErrorRef error = nullptr;
                SecTrustSetNetworkFetchAllowed(trust, false);
                valid = SecTrustEvaluateWithError(trust, &error);
                if (error) CFRelease(error);
            }
        }
    } catch (...) { valid = false; }
    if (self->cancelled()) { self->terminal = "QUIC connection cancelled"; valid = false; }
    X509_STORE_CTX_set_error(store, valid ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
    return valid ? 1 : 0;
}
#endif

Error Connection::Impl::setupQUIC() {
    if (cancelled()) return "QUIC connection cancelled";
    ngtcp2_path path{{reinterpret_cast<sockaddr *>(&local), localLength},
                     {reinterpret_cast<sockaddr *>(&remote), remoteLength}, nullptr};
    ngtcp2_callbacks callbacks{};
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb; callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb; callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.handshake_completed = handshakeDone;
    callbacks.recv_stream_data = receive; callbacks.acked_stream_data_offset = acknowledge;
    callbacks.stream_close = streamClosed; callbacks.stream_reset = streamReset;
    callbacks.rand = [](uint8_t *output, size_t size, const ngtcp2_rand_ctx *) {
        if (RAND_bytes(output, static_cast<int>(size)) != 1) std::abort();
    };
    callbacks.get_new_connection_id = [](ngtcp2_conn *, ngtcp2_cid *cid,
                                         uint8_t *token, size_t size, void *) {
        cid->datalen = size;
        return RAND_bytes(cid->data, static_cast<int>(size)) == 1 &&
               RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) == 1
               ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    };
    callbacks.recv_datagram = [](ngtcp2_conn *, uint32_t, const uint8_t *data,
                                 size_t size, void *user) {
        static_cast<Impl *>(user)->receiveDatagram(data, size);
        return 0;
    };
    ngtcp2_cid destination{}, source{};
    destination.datalen = NGTCP2_MIN_INITIAL_DCIDLEN; source.datalen = 8;
    if (RAND_bytes(destination.data, static_cast<int>(destination.datalen)) != 1 ||
        RAND_bytes(source.data, static_cast<int>(source.datalen)) != 1) return "QUIC secure RNG failed";
    ngtcp2_settings settings; ngtcp2_settings_default(&settings);
    settings.initial_ts = now(); settings.handshake_timeout = 10 * NGTCP2_SECONDS;
    maxTxPayload_ = 1350 - obfsOverhead();
    settings.max_tx_udp_payload_size = maxTxPayload_; settings.no_pmtud = 1;
    settings.max_stream_window = 16 * 1024 * 1024;
    settings.max_window = 64 * 1024 * 1024;
    settings.ack_thresh = 4;
    auto congestion = proto_common::lowerAscii(node.option("congestion-controller", node.option("congestion", "bbr")));
    settings.cc_algo = congestion == "cubic" ? NGTCP2_CC_ALGO_CUBIC :
                       congestion == "reno" ? NGTCP2_CC_ALGO_RENO : NGTCP2_CC_ALGO_BBR;
    if (node.type == "hysteria2" || node.type == "hysteria") {
        brutalUpBps_ = parseQuicBandwidthBytesPerSec(node.option("up", node.option("up-speed", node.option("upload-bandwidth"))));
        if (brutalUpBps_ > 0) {
            brutalUpBps_ = std::max<uint64_t>(brutalUpBps_, 65536);
            brutalTokens_ = std::max<uint64_t>(65536, brutalUpBps_ / 20);
            brutalLastRefill_ = settings.initial_ts;
        }
    }
    ngtcp2_transport_params params; ngtcp2_transport_params_default(&params);
    params.initial_max_data = 16 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 2 * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 2 * 1024 * 1024;
    params.initial_max_stream_data_uni = 512 * 1024;
    params.initial_max_streams_bidi = 64; params.initial_max_streams_uni = 64;
    params.max_idle_timeout = 60 * NGTCP2_SECONDS;
    params.max_datagram_frame_size = 1200;
    if (node.flag("grease-quic-bit", false)) {
        params.grease_quic_bit = 1;
    }
    // Default to RFC 9000 QUIC v1 for universal interoperability with sing-quic / quic-go / quinn;
    // opt into RFC 9369 QUIC v2 / RFC 9368 compatible version negotiation via `quic-version=2|v2|auto`.
    static const uint32_t kPreferredQuicVersions[] = {NGTCP2_PROTO_VER_V2, NGTCP2_PROTO_VER_V1};
    auto quicVerOpt = proto_common::lowerAscii(node.option("quic-version", "1"));
    uint32_t clientQuicVersion = (quicVerOpt == "2" || quicVerOpt == "v2")
        ? NGTCP2_PROTO_VER_V2 : NGTCP2_PROTO_VER_V1;
    if (quicVerOpt == "2" || quicVerOpt == "v2" || quicVerOpt == "auto") {
        settings.preferred_versions = kPreferredQuicVersions;
        settings.preferred_versionslen = 2;
    }
    int code = ngtcp2_conn_client_new(&conn, &destination, &source, &path,
        clientQuicVersion, &callbacks, &settings, &params, nullptr, this);
    if (code) return "QUIC connection creation failed";
    ngtcp2_conn_set_tls_native_handle(conn, cryptoContext);
    ngtcp2_conn_set_keep_alive_timeout(conn, 10 * NGTCP2_SECONDS);
    return cancelled() ? "QUIC connection cancelled" : Error{};
}

int Connection::Impl::handshakeDone(ngtcp2_conn *conn, void *user) {
    auto self = static_cast<Impl *>(user);
    if (self->cancelled()) {
        self->terminal = "QUIC connection cancelled"; return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    const unsigned char *alpn = nullptr; unsigned size = 0;
    SSL_get0_alpn_selected(self->tls, &alpn, &size);
    if (!size) { self->terminal = "QUIC server did not negotiate ALPN"; return NGTCP2_ERR_CALLBACK_FAILURE; }
    if (self->node.type == "hysteria2" && std::string(reinterpret_cast<const char *>(alpn), size) != "h3") {
        self->terminal = "Hysteria2 server negotiated incompatible ALPN"; return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (SSL_get_verify_mode(self->tls) != SSL_VERIFY_NONE &&
        SSL_get_verify_result(self->tls) != X509_V_OK) {
        self->terminal = "QUIC TLS certificate verification failed"; return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    auto remote = ngtcp2_conn_get_remote_transport_params(conn);
    size_t safeMaxDatagram = self->maxTxPayload_ > 200 ? self->maxTxPayload_ - 200 : 1000;
    self->datagramSize = remote ? std::min<size_t>(safeMaxDatagram, remote->max_datagram_frame_size > 3
        ? remote->max_datagram_frame_size - 3 : 0) : 0;
    self->handshake = true;
    if (self->ready) {
        auto callback = std::exchange(self->ready, {}); auto owner = self->owner.lock();
        self->dispatch([callback, owner] {
            if (!owner || owner->isClosed()) {
                if (owner) owner->close();
                callback(nullptr, "QUIC connection cancelled"); return;
            }
            callback(owner, {});
        });
    }
    return 0;
}

int Connection::Impl::receive(ngtcp2_conn *conn, uint32_t flags, int64_t id,
                             uint64_t, const uint8_t *data, size_t count,
                             void *user, void *) {
    auto self = static_cast<Impl *>(user);
    traceStream(self->node, "receive", id, count, flags & NGTCP2_STREAM_DATA_FLAG_FIN, false);
    if (self->cancelled()) {
        self->terminal = "QUIC connection cancelled"; return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    auto found = self->streams.find(id);
    if (found == self->streams.end()) {
        if (!self->peerStreams) {
            ngtcp2_conn_extend_max_stream_offset(conn, id, count);
            ngtcp2_conn_extend_max_offset(conn, count);
            return 0;
        }
        if (self->streams.size() >= 64) return NGTCP2_ERR_CALLBACK_FAILURE;
        found = self->streams.emplace(id, State{}).first;
        auto callback = self->peerStreams;
        auto owner = self->owner.lock();
        auto channel = std::make_shared<Channel>(owner, id);
        self->dispatch([callback, channel, owner] {
            if (!owner || owner->isClosed()) { channel->close(); return; }
            callback(channel);
        });
    }
    auto &state = found->second;
    if (state.closed) return 0;
    static constexpr size_t kMaxStreamWindow = 16 * 1024 * 1024;
    static constexpr size_t kMaxConnWindow = 64 * 1024 * 1024;
    if (state.input.size() > kMaxStreamWindow ||
        count > kMaxStreamWindow - state.input.size() ||
        self->readBytes > kMaxConnWindow ||
        count > kMaxConnWindow - self->readBytes) return NGTCP2_ERR_CALLBACK_FAILURE;
    state.input.append(data, count); self->readBytes += count;
    state.eof = state.eof || (flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    self->satisfy(id);
    return 0;
}

int Connection::Impl::acknowledge(ngtcp2_conn *, int64_t id, uint64_t offset,
                                 uint64_t count, void *user, void *) {
    auto self = static_cast<Impl *>(user); auto found = self->streams.find(id);
    if (found == self->streams.end()) return 0;
    auto &queue = found->second.writes;
    while (!queue.empty() && queue.front().offset + queue.front().bytes.size() <= offset + count) {
        self->writeBytes -= queue.front().bytes.size(); self->stagedWrites -= queue.front().bytes.size(); queue.pop_front();
    }
    return 0;
}

int Connection::Impl::streamClosed(ngtcp2_conn *conn, uint32_t flags, int64_t id,
                                  uint64_t code, void *user, void *) {
    auto self = static_cast<Impl *>(user); auto found = self->streams.find(id);
    traceStream(self->node, "close", id, static_cast<size_t>(code), false,
                found != self->streams.end() && bool(found->second.read));
    if (found == self->streams.end()) return 0;
    auto &state = found->second; state.eof = true; state.finished = true;
    if ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) && code)
        state.error = "QUIC peer reset stream";
    for (auto &write : state.writes) {
        self->writeBytes -= write.bytes.size(); self->stagedWrites -= write.bytes.size();
        if (write.completion) {
            auto callback = std::exchange(write.completion, {}); auto error = state.error;
            self->dispatch([callback, error] { callback(error.empty() ? "QUIC stream closed before write" : error); });
        }
    }
    state.writes.clear(); self->satisfy(id); self->collect(id);
    if ((id & 3) == 3) ngtcp2_conn_extend_max_streams_uni(conn, 1);
    else if ((id & 3) == 1) ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    return 0;
}

int Connection::Impl::streamReset(ngtcp2_conn *, int64_t id, uint64_t,
                                 uint64_t, void *user, void *) {
    auto self = static_cast<Impl *>(user); auto found = self->streams.find(id);
    if (found != self->streams.end()) {
        found->second.error = "QUIC peer reset stream"; found->second.eof = true;
        self->satisfy(id);
    }
    return 0;
}

void Connection::Impl::satisfy(int64_t id) {
    auto found = streams.find(id); if (found == streams.end()) return;
    auto &state = found->second;
    if (!state.read || (state.input.empty() && !state.eof && state.error.empty())) return;
    size_t count = std::min(state.readMaximum, state.input.size());
    Buffer output = state.input.consume(count);
    readBytes -= count;
    if (count) {
        ngtcp2_conn_extend_max_stream_offset(conn, id, count);
        ngtcp2_conn_extend_max_offset(conn, count);
    }
    bool eof = state.eof && state.input.empty(); state.eofDelivered = state.eofDelivered || eof;
    traceStream(node, "deliver", id, count, eof, true);
    auto error = state.error;
    auto callback = std::move(state.read); state.read = {};
    dispatch([callback, output = std::move(output), eof, error]() mutable {
        callback(std::move(output), eof, error);
    });
    collect(id);
}

void Connection::Impl::addStream(bool uni, StreamCallback completion) {
    if (cancelled() || !handshake || streams.size() >= 64) {
        dispatch([completion] { completion(nullptr, "QUIC connection is closed or stream limit reached"); }); return;
    }
    int64_t id = -1;
    int code = uni ? ngtcp2_conn_open_uni_stream(conn, &id, nullptr) :
                     ngtcp2_conn_open_bidi_stream(conn, &id, nullptr);
    if (code) {
        dispatch([completion] { completion(nullptr, "QUIC peer stream limit reached"); }); return;
    }
    streams.emplace(id, State{});
    auto connection = owner.lock();
    auto channel = std::make_shared<Channel>(connection, id);
    dispatch([completion, channel, connection] {
        if (!connection || connection->isClosed()) {
            channel->close(); completion(nullptr, "QUIC connection cancelled"); return;
        }
        completion(channel, {});
    });
}

void Connection::Impl::queueWrite(int64_t id, Buffer data, WriteCallback completion) {
    auto found = streams.find(id);
    Error error;
    if (cancelled() || found == streams.end() || found->second.closed || found->second.fin)
        error = "QUIC stream is closed for writing";
    else if (data.size() > maximumQueuedBytes - writeBytes) error = "QUIC write queue limit exceeded";
    if (!error.empty() || data.empty()) {
        stagedWrites -= data.size();
        dispatch([completion, error] { if (completion) completion(error); }); return;
    }
    auto &state = found->second;
    Write write; write.offset = state.end; state.end += data.size(); writeBytes += data.size();
    write.bytes = std::move(data); write.completion = std::move(completion);
    state.writes.push_back(std::move(write));
}

void Connection::Impl::queueRead(int64_t id, size_t maximum, ReadCallback completion) {
    auto found = streams.find(id);
    traceStream(node, "read", id, maximum, found != streams.end() && found->second.eof,
                found != streams.end() && bool(found->second.read));
    if (cancelled() || found == streams.end() || found->second.closed) {
        dispatch([completion] { completion({}, true, "QUIC stream is closed"); }); return;
    }
    auto &state = found->second;
    if (state.read || !maximum || maximum > maximumReadBytes) {
        dispatch([completion] { completion({}, false, "Invalid or overlapping QUIC read"); }); return;
    }
    state.readMaximum = maximum; state.read = std::move(completion); satisfy(id);
}

void Connection::Impl::finishWrite(int64_t id, WriteCallback completion) {
    auto found = streams.find(id);
    if (cancelled() || found == streams.end() || found->second.closed || found->second.fin) {
        dispatch([completion] { completion("QUIC write side is already closed"); }); return;
    }
    found->second.fin = true; found->second.shutdown = std::move(completion);
}

void Connection::Impl::closeStream(int64_t id) {
    auto found = streams.find(id); if (found == streams.end() || found->second.closed) return;
    auto &state = found->second; state.closed = true; state.eof = true;
    state.error = "QUIC stream cancelled";
    readBytes -= state.input.size(); state.input.clear(); satisfy(id);
    if (conn && !cancelled()) ngtcp2_conn_shutdown_stream(conn, 0, id, 0);
    // Retransmission buffers are retained until stream_close or conn_del.
}

void Connection::Impl::Channel::write(Buffer data, WriteCallback callback) {
    auto value = connection.lock(); if (!value) { callback("QUIC connection is closed"); return; }
    auto self = value->impl_.get(); auto streamID = id;
    if (!Impl::reserve(self->stagedWrites, data.size())) {
        self->dispatch([callback] { callback("QUIC write queue limit exceeded"); }); return;
    }
    self->post([value, self, streamID, data = std::move(data), callback]() mutable {
        self->queueWrite(streamID, std::move(data), callback);
    });
}
void Connection::Impl::Channel::read(size_t maximum, ReadCallback callback) {
    auto value = connection.lock(); if (!value) { callback({}, true, "QUIC connection is closed"); return; }
    auto self = value->impl_.get(); auto streamID = id;
    self->post([value, self, streamID, maximum, callback] { self->queueRead(streamID, maximum, callback); });
}
void Connection::Impl::Channel::shutdownWrite(WriteCallback callback) {
    auto value = connection.lock(); if (!value) { callback("QUIC connection is closed"); return; }
    auto self = value->impl_.get(); auto streamID = id;
    self->post([value, self, streamID, callback] { self->finishWrite(streamID, callback); });
}
void Connection::Impl::Channel::close() {
    auto value = connection.lock(); if (!value) return;
    auto self = value->impl_.get(); auto streamID = id;
    self->post([value, self, streamID] { self->closeStream(streamID); });
}

Buffer Connection::Impl::obfuscate(const uint8_t *data, size_t size, bool outbound) {
    if (!hasObfuscation()) return Buffer(data, data + size);
    const size_t saltSize = obfsSaltSize_;
    if (!outbound && size <= saltSize) return {};
    uint8_t salt[16]{};
    if (outbound) {
        if (RAND_bytes(salt, static_cast<int>(saltSize)) != 1)
            throw std::runtime_error("QUIC obfuscation RNG failed");
    } else {
        std::memcpy(salt, data, saltSize);
    }
    uint8_t key[32]{};
    if (!computeObfsKey(salamanderObfs_, obfsPassword_, salt, saltSize, key)) {
        OPENSSL_cleanse(salt, sizeof(salt));
        OPENSSL_cleanse(key, sizeof(key));
        throw std::runtime_error("QUIC obfuscation key derivation failed");
    }
    const size_t inOffset = outbound ? 0 : saltSize;
    const size_t payloadLen = size - inOffset;
    const size_t outOffset = outbound ? saltSize : 0;
    Buffer result(outOffset + payloadLen);
    if (outbound) std::memcpy(result.data(), salt, saltSize);
    const uint8_t *src = data + inOffset;
    uint8_t *dst = result.data() + outOffset;
    size_t i = 0;
    for (; i + 8 <= payloadLen; i += 8) {
        uint64_t dw = 0, kw = 0;
        std::memcpy(&dw, src + i, 8);
        std::memcpy(&kw, key + (i & 24), 8);
        dw ^= kw;
        std::memcpy(dst + i, &dw, 8);
    }
    for (; i < payloadLen; ++i) {
        dst[i] = src[i] ^ key[i & 31];
    }
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(key, sizeof(key));
    return result;
}

Error Connection::Impl::readPackets() {
    if (chainedDatagram) {
        for (size_t iteration = 0; iteration < 64; ++iteration) {
            if (cancelled()) return "QUIC connection cancelled";
            Buffer raw;
            {
                std::lock_guard<std::mutex> g(mutex);
                if (chainedInbound.empty()) break;
                raw = std::move(chainedInbound.front());
                chainedInbound.pop_front();
            }
            const uint8_t *pktPtr = raw.data();
            size_t pktLen = raw.size();
            Buffer decoded;
            if (hasObfuscation()) {
                decoded = obfuscate(raw.data(), raw.size(), false);
                if (decoded.empty()) continue;
                pktPtr = decoded.data();
                pktLen = decoded.size();
            } else if (pktLen == 0) {
                continue;
            }
            ngtcp2_path path{{reinterpret_cast<sockaddr *>(&local), localLength},
                             {reinterpret_cast<sockaddr *>(&remote), remoteLength}, nullptr};
            ngtcp2_pkt_info info{};
            int code = ngtcp2_conn_read_pkt(conn, &path, &info, pktPtr, pktLen, now());
            if (code == NGTCP2_ERR_DISCARD_PKT) continue;
            if (code) {
                if (!terminal.empty()) return terminal;
                if (SSL_get_verify_result(tls) != X509_V_OK) return "QUIC TLS certificate verification failed";
                return code == NGTCP2_ERR_DRAINING ? "QUIC peer closed connection" : "QUIC packet/TLS processing failed";
            }
        }
        return {};
    }
    uint8_t input[65536];
    for (size_t iteration = 0; iteration < 64; ++iteration) {
        if (cancelled()) return "QUIC connection cancelled";
        iovec iov{input, sizeof(input)};
        alignas(cmsghdr) uint8_t control[64]{};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        if (!hasObfuscation()) {
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);
        }
        auto length = ::recvmsg(socket, &msg, 0);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return {};
            if (errno == EINTR || errno == ECONNREFUSED) continue;
            return "QUIC UDP receive failed";
        }
        if (length == 0 || (msg.msg_flags & MSG_TRUNC)) continue;
        if (cancelled()) return "QUIC connection cancelled";
        ngtcp2_pkt_info info{};
        if (!hasObfuscation() && !(msg.msg_flags & MSG_CTRUNC)) {
            for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                size_t dataLen = cmsg->cmsg_len >= CMSG_LEN(0) ? static_cast<size_t>(cmsg->cmsg_len - CMSG_LEN(0)) : 0;
                if ((cmsg->cmsg_level == IPPROTO_IP && (cmsg->cmsg_type == IP_TOS
#if defined(IP_RECVTOS)
                    || cmsg->cmsg_type == IP_RECVTOS
#endif
                    )) || (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) {
                    if (dataLen >= sizeof(int)) {
                        int tos = 0;
                        std::memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
                        info.ecn = static_cast<uint8_t>(tos) & NGTCP2_ECN_MASK;
                    } else if (dataLen >= 1) {
                        info.ecn = (*reinterpret_cast<const uint8_t *>(CMSG_DATA(cmsg))) & NGTCP2_ECN_MASK;
                    }
                }
            }
        }
        const uint8_t *pktPtr = input;
        size_t pktLen = static_cast<size_t>(length);
        Buffer decoded;
        if (hasObfuscation()) {
            decoded = obfuscate(input, pktLen, false);
            if (decoded.empty()) continue;
            pktPtr = decoded.data();
            pktLen = decoded.size();
        }
        ngtcp2_path path{{reinterpret_cast<sockaddr *>(&local), localLength},
                         {reinterpret_cast<sockaddr *>(&remote), remoteLength}, nullptr};
        int code = ngtcp2_conn_read_pkt(conn, &path, &info, pktPtr, pktLen, now());
        if (code == NGTCP2_ERR_DISCARD_PKT) continue;
        if (code) {
            if (!terminal.empty()) return terminal;
            if (SSL_get_verify_result(tls) != X509_V_OK) return "QUIC TLS certificate verification failed";
            return code == NGTCP2_ERR_DRAINING ? "QUIC peer closed connection" : "QUIC packet/TLS processing failed";
        }
    }
    return {};
}

Error Connection::Impl::writePackets() {
    if (cancelled()) return "QUIC connection cancelled";
    const bool enableOutboundEcn = !hasObfuscation() && node.flag("ecn", false);
    auto applySocketEcn = [&](uint8_t pktEcn) {
        if (enableOutboundEcn && socket >= 0) {
            int desiredEcn = static_cast<int>(pktEcn & NGTCP2_ECN_MASK);
            if (desiredEcn != lastSocketEcn_) {
                int level = remote.ss_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
                int opt = remote.ss_family == AF_INET6 ? IPV6_TCLASS : IP_TOS;
                if (setsockopt(socket, level, opt, &desiredEcn, sizeof(desiredEcn)) == 0) {
                    lastSocketEcn_ = desiredEcn;
                }
            }
        }
    };
    auto transmitSocketBuffer = [&](const uint8_t *wireData, size_t wireSize, uint8_t pktEcn) -> int {
        if (cancelled()) return -1;
        if (!wireSize) return 1;
        applySocketEcn(pktEcn);
        auto length = ::send(socket, wireData, wireSize, 0);
        if (length == static_cast<ssize_t>(wireSize)) {
            consecutiveSendLosses_ = 0;
            if (wireSize >= 1280 && pmtudState_ == DPLPMTUDState::Searching) {
                if (++pmtudProbesSucceeded_ >= 3) pmtudState_ = DPLPMTUDState::SearchComplete;
            } else if (pmtudState_ == DPLPMTUDState::BlackholeRecovery && ++pmtudProbesSucceeded_ >= 16) {
                // RFC 8899 §5.2: probe upward again after sustained recovery at base PMTU
                size_t ceiling = 1350 - obfsOverhead();
                if (maxTxPayload_ < ceiling) {
                    maxTxPayload_ = std::min<size_t>(ceiling, maxTxPayload_ + 80);
                    pmtudState_ = DPLPMTUDState::Searching;
                    pmtudProbesSucceeded_ = 0;
                }
            }
            return 1;
        }
        if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS || errno == ECONNREFUSED)) return 0;
        if (length < 0 && errno == EMSGSIZE && maxTxPayload_ > 1200) {
            maxTxPayload_ = maxTxPayload_ > 1280 ? 1280 : 1200;
            pmtudState_ = DPLPMTUDState::BlackholeRecovery;
            pmtudProbesSucceeded_ = 0;
            size_t currentLimit = datagramSize.load();
            if (currentLimit > maxTxPayload_ - 200) datagramSize.store(maxTxPayload_ - 200);
            return 1;
        }
        if (length < 0 && (errno == EADDRNOTAVAIL || errno == ENETDOWN || errno == ENETUNREACH || errno == EHOSTUNREACH || errno == ENOTCONN)
            && migrateSocketOnPathChange()) {
            applySocketEcn(pktEcn);
            auto retried = ::send(socket, wireData, wireSize, 0);
            if (retried == static_cast<ssize_t>(wireSize)) return 1;
            if (retried < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS || errno == ECONNREFUSED)) return 0;
        }
        return -1;
    };
    if (!pendingWire.empty()) {
        if (chainedDatagram) {
            Target dst{node.dialHost(), activePort ? activePort : node.port, true, false};
            Buffer pkt = std::move(pendingWire);
            pendingWire.clear();
            chainedDatagram->send(std::move(dst), std::move(pkt), [](Error) {});
        } else {
            int sent = transmitSocketBuffer(pendingWire.data(), pendingWire.size(), pendingWireEcn_);
            if (sent == 1) pendingWire.clear();
            else return sent == 0 ? Error{} : cancelled() ? "QUIC connection cancelled" : "QUIC UDP send failed";
        }
    }
    std::vector<int64_t> ids;
    ids.reserve(streams.size());
    for (auto &entry : streams) if (!entry.second.closed) ids.push_back(entry.first);
    std::sort(ids.begin(), ids.end(), [](int64_t a, int64_t b) {
        bool aUni = (a & 2) != 0;
        bool bUni = (b & 2) != 0;
        if (aUni != bUni) return aUni > bUni;
        return a < b;
    });
    size_t cursor = 0;
    ngtcp2_tstamp timestamp = now();
    const bool useBrutalPacing = handshake && brutalUpBps_ > 0;
    if (useBrutalPacing) {
        if (timestamp > brutalLastRefill_) {
            uint64_t elapsedNs = timestamp - brutalLastRefill_;
            uint64_t addBytes = static_cast<uint64_t>((static_cast<double>(brutalUpBps_) * static_cast<double>(elapsedNs)) / 1e9);
            uint64_t burstCap = std::max<uint64_t>(65536, brutalUpBps_ / 10);
            brutalTokens_ = std::min<uint64_t>(burstCap, brutalTokens_ + addBytes);
            brutalLastRefill_ = timestamp;
        }
    }
    const size_t sendQuantum = !useBrutalPacing
        ? std::max<size_t>(maxTxPayload_, ngtcp2_conn_get_send_quantum(conn))
        : SIZE_MAX;
    size_t burstSentBytes = 0;
    auto streamHasPendingWork = [](const State &st) {
        if (st.fin && !st.finSent) return true;
        for (const auto &chunk : st.writes) {
            if (chunk.sent < chunk.bytes.size()) return true;
        }
        return false;
    };
    for (size_t iteration = 0; iteration < 256; ++iteration) {
        if (useBrutalPacing && brutalTokens_ < maxTxPayload_ && iteration > 0) break;
        if (!useBrutalPacing && burstSentBytes >= sendQuantum && iteration > 0) break;
        if (cancelled()) return "QUIC connection cancelled";
        ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info info{}; uint8_t output[1350]; ngtcp2_ssize written = 0;
        size_t wireBudget = std::min<size_t>(sizeof(output), maxTxPayload_);
        if (!packets.empty() && handshake) {
            auto &packet = packets.front(); ngtcp2_vec vector{packet.bytes.data(), packet.bytes.size()}; int accepted = 0;
            written = ngtcp2_conn_writev_datagram(conn, &path.path, &info, output,
                wireBudget, &accepted, 0, 0, &vector, 1, timestamp);
            if (accepted || written == NGTCP2_ERR_INVALID_ARGUMENT || written == NGTCP2_ERR_INVALID_STATE) {
                auto callback = std::move(packet.completion); packetBytes -= packet.bytes.size();
                stagedPackets -= packet.bytes.size(); packets.pop_front();
                auto error = accepted ? Error{} : "QUIC peer does not support this datagram size";
                dispatch([callback, error] { if (callback) callback(error); });
                if (!accepted) continue;
            }
        } else {
            size_t scannedInRound = 0;
            for (size_t inner = 0; inner < 32; ++inner) {
                int64_t id = -1;
                State *state = nullptr;
                ngtcp2_vec vectors[16];
                size_t vecCount = 0;
                size_t totalAvailInStream = 0;
                size_t gatheredBytes = 0;
                if (inner < 31) {
                    while (scannedInRound < ids.size()) {
                        auto candidate = ids[cursor++ % ids.size()];
                        ++scannedInRound;
                        auto foundIt = streams.find(candidate);
                        if (foundIt == streams.end() || foundIt->second.closed) continue;
                        auto &value = foundIt->second;
                        vecCount = 0;
                        totalAvailInStream = 0;
                        gatheredBytes = 0;
                        for (auto &chunk : value.writes) {
                            if (chunk.sent >= chunk.bytes.size()) continue;
                            size_t rem = chunk.bytes.size() - chunk.sent;
                            totalAvailInStream += rem;
                            if (vecCount < 16) {
                                vectors[vecCount++] = {chunk.bytes.data() + chunk.sent, rem};
                                gatheredBytes += rem;
                            }
                        }
                        if (vecCount > 0 || (value.fin && !value.finSent)) {
                            id = candidate;
                            state = &value;
                            break;
                        }
                    }
                }
                if (id == -1) {
                    written = ngtcp2_conn_writev_stream(
                        conn, &path.path, &info, output, wireBudget,
                        nullptr, 0, -1, nullptr, 0, timestamp);
                    break;
                }
                const bool fin = state->fin && !state->finSent && (totalAvailInStream == gatheredBytes);
                bool moreDataRemains = (totalAvailInStream > gatheredBytes);
                if (!moreDataRemains && ids.size() > 1) {
                    for (int64_t otherId : ids) {
                        if (otherId == id) continue;
                        auto otherIt = streams.find(otherId);
                        if (otherIt != streams.end() && !otherIt->second.closed && streamHasPendingWork(otherIt->second)) {
                            moreDataRemains = true;
                            break;
                        }
                    }
                }
                uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
                if (moreDataRemains && inner + 1 < 31) flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
                ngtcp2_ssize consumed = -1;
                written = ngtcp2_conn_writev_stream(
                    conn, &path.path, &info, output, wireBudget,
                    &consumed, flags, id,
                    vecCount ? vectors : nullptr, vecCount, timestamp);
                if (consumed >= 0 && state) {
                    size_t remConsumed = static_cast<size_t>(consumed);
                    for (auto &chunk : state->writes) {
                        if (remConsumed == 0) break;
                        if (chunk.sent >= chunk.bytes.size()) continue;
                        size_t avail = chunk.bytes.size() - chunk.sent;
                        size_t take = std::min(avail, remConsumed);
                        chunk.sent += take;
                        remConsumed -= take;
                        if (chunk.sent == chunk.bytes.size() && chunk.completion) {
                            auto callback = std::exchange(chunk.completion, {});
                            dispatch([callback] { callback({}); });
                        }
                    }
                    if (fin && static_cast<size_t>(consumed) == gatheredBytes) {
                        traceStream(node, "send-fin", id, static_cast<size_t>(consumed), true, false);
                        state->finSent = true;
                        auto callback = std::exchange(state->shutdown, {});
                        if (callback) dispatch([callback] { callback({}); });
                    }
                }
                if (written == NGTCP2_ERR_WRITE_MORE) {
                    if (consumed > 0 || (fin && gatheredBytes == 0)) scannedInRound = 0;
                    continue;
                }
                if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED || written == NGTCP2_ERR_STREAM_NOT_FOUND) {
                    continue;
                }
                if (written == NGTCP2_ERR_STREAM_SHUT_WR) {
                    if (state) closeStream(id);
                    continue;
                }
                break;
            }
        }
        if (written < 0) return "QUIC packet write failed";
        if (!written) break;
        const size_t ulen = static_cast<size_t>(written);
        burstSentBytes += ulen;
        if (useBrutalPacing) {
            brutalTokens_ = (brutalTokens_ > ulen) ? (brutalTokens_ - ulen) : 0;
        }
        if (chainedDatagram) {
            Target dst{node.dialHost(), activePort ? activePort : node.port, true, false};
            Buffer pkt = hasObfuscation() ? obfuscate(output, ulen, true) : Buffer(output, output + ulen);
            chainedDatagram->send(std::move(dst), std::move(pkt), [](Error) {});
        } else if (hasObfuscation()) {
            Buffer obfsPkt = obfuscate(output, ulen, true);
            int sent = transmitSocketBuffer(obfsPkt.data(), obfsPkt.size(), 0);
            if (sent < 0) return cancelled() ? "QUIC connection cancelled" : "QUIC UDP send failed";
            if (!sent) { pendingWire = std::move(obfsPkt); pendingWireEcn_ = 0; break; }
        } else {
            int sent = transmitSocketBuffer(output, ulen, info.ecn);
            if (sent < 0) return cancelled() ? "QUIC connection cancelled" : "QUIC UDP send failed";
            if (!sent) { pendingWire.assign(output, output + ulen); pendingWireEcn_ = info.ecn; break; }
        }
    }
    ngtcp2_conn_update_pkt_tx_time(conn, timestamp);
    return {};
}

void Connection::Impl::fail(Error error) {
    if (usedCachedSession_ && !handshake && !cancellationRequested() && !sessionCacheKey_.empty()) {
        evictCachedQuicSession(sessionCacheKey_);
        usedCachedSession_ = false;
    }
    if (terminal.empty()) terminal = std::move(error);
    stopping = true;
    received->close();
    if (ready) {
        auto callback = std::exchange(ready, {}); auto message = terminal;
        dispatch([callback, message] { callback(nullptr, message); });
    }
    for (auto &entry : streams) {
        auto &state = entry.second; state.eof = true; state.error = terminal;
        satisfy(entry.first);
        for (auto &write : state.writes) if (write.completion) {
            auto callback = std::exchange(write.completion, {}); auto message = terminal;
            dispatch([callback, message] { callback(message); });
        }
        if (state.shutdown) {
            auto callback = std::exchange(state.shutdown, {}); auto message = terminal;
            dispatch([callback, message] { callback(message); });
        }
    }
    while (!packets.empty()) {
        auto callback = std::move(packets.front().completion); stagedPackets -= packets.front().bytes.size(); packets.pop_front();
        if (callback) { auto message = terminal; dispatch([callback, message] { callback(message); }); }
    }
    if (packetFailure) {
        auto callback = std::exchange(packetFailure, {}); auto message = terminal;
        dispatch([callback, message] { callback(message); });
    }
    packetReceive = {}; peerStreams = {};
}

void Connection::Impl::run() {
    deadline = now() + 12 * NGTCP2_SECONDS;
    try {
        Error error = setupSocket();
        if (error.empty()) error = cancelled() ? "QUIC connection cancelled" : setupTLS();
        if (error.empty()) error = cancelled() ? "QUIC connection cancelled" : setupQUIC();
        if (error.empty() && cancelled()) error = "QUIC connection cancelled";
#if defined(__APPLE__)
        if (error.empty()) {
            kq_ = ::kqueue();
            if (kq_ >= 0) {
                (void)fcntl(kq_, F_SETFD, FD_CLOEXEC);
                struct kevent wakeEv{};
                EV_SET(&wakeEv, static_cast<uintptr_t>(wake[0]), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
                (void)::kevent(kq_, &wakeEv, 1, nullptr, 0, nullptr);
            }
        }
#endif
        if (!error.empty()) fail(error);
        while (!stopping) {
            if (cancelled()) { fail("QUIC connection cancelled"); break; }
            std::deque<std::function<void()>> tasks;
            { std::lock_guard<std::mutex> lock(mutex); tasks.swap(jobs); }
            for (auto &task : tasks) {
                if (cancellationRequested()) fail("QUIC connection cancelled");
                task(); // Closing still executes jobs so every callback resolves.
            }
            if (stopping) break;
            if (cancelled()) { fail("QUIC connection cancelled"); break; }
            if (!applicationReady && now() >= deadline) { fail("QUIC protocol handshake timed out"); break; }
            if (now() >= ngtcp2_conn_get_expiry(conn)) {
                if (ngtcp2_conn_handle_expiry(conn, now())) { fail("QUIC idle/handshake timeout"); break; }
            }
            error = writePackets(); if (!error.empty()) { fail(error); break; }
            auto expiry = ngtcp2_conn_get_expiry(conn);
            auto current = now();
            static constexpr uint64_t kMaxWaitNs = 100ULL * NGTCP2_MILLISECONDS;
            uint64_t waitNs = expiry > current ? (expiry - current) : 0;
            if (!pendingWire.empty() && waitNs == 0) waitNs = NGTCP2_MILLISECONDS;
            if (waitNs > kMaxWaitNs) waitNs = kMaxWaitNs;
            if (chainedDatagram) {
                std::lock_guard<std::mutex> g(mutex);
                if (!chainedInbound.empty()) waitNs = 0;
            }
            bool wakeReadable = false;
            bool socketReadable = false;
#if defined(__APPLE__)
            if (kq_ >= 0) {
                struct kevent changes[2];
                int nchanges = 0;
                if (socket >= 0 && socket != registeredSocket_) {
                    EV_SET(&changes[nchanges++], static_cast<uintptr_t>(socket), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
                    registeredSocket_ = socket;
                    writeFilterEnabled_ = false;
                }
                const bool wantWrite = (socket >= 0 && !pendingWire.empty());
                if (socket >= 0 && wantWrite != writeFilterEnabled_) {
                    EV_SET(&changes[nchanges++], static_cast<uintptr_t>(socket), EVFILT_WRITE,
                           wantWrite ? (EV_ADD | EV_ENABLE) : (EV_ADD | EV_DISABLE), 0, 0, nullptr);
                    writeFilterEnabled_ = wantWrite;
                }
                struct timespec ts{
                    static_cast<time_t>(waitNs / NGTCP2_SECONDS),
                    static_cast<long>(waitNs % NGTCP2_SECONDS)
                };
                struct kevent events[4];
                int nev = ::kevent(kq_, nchanges ? changes : nullptr, nchanges, events, 4, &ts);
                if (nev < 0 && errno != EINTR) { fail("QUIC event polling failed"); break; }
                for (int i = 0; i < nev; ++i) {
                    if (events[i].ident == static_cast<uintptr_t>(wake[0])) {
                        wakeReadable = true;
                    } else if (socket >= 0 && events[i].ident == static_cast<uintptr_t>(socket)) {
                        if (events[i].filter == EVFILT_READ || (events[i].flags & EV_ERROR)) {
                            socketReadable = true;
                        }
                    }
                }
            } else
#endif
            {
                uint64_t waitMs = waitNs > 0 ? (waitNs + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS : 0;
                pollfd descriptors[2]{
                    {socket, static_cast<short>(socket >= 0 ? (POLLIN | (pendingWire.empty() ? 0 : POLLOUT)) : 0), 0},
                    {wake[0], POLLIN, 0}
                };
                int result = ::poll(descriptors, 2, static_cast<int>(std::min<uint64_t>(waitMs, 100)));
                if (result < 0 && errno != EINTR) { fail("QUIC event polling failed"); break; }
                wakeReadable = (descriptors[1].revents & POLLIN) != 0;
                socketReadable = socket >= 0 && (descriptors[0].revents & (POLLIN | POLLERR)) != 0;
            }
            if (cancelled()) { fail("QUIC connection cancelled"); break; }
            if (wakeReadable) {
                uint8_t values[256];
                while (::read(wake[0], values, sizeof(values)) > 0) {}
                wakePending.store(false, std::memory_order_seq_cst);
            }
            if (chainedDatagram || socketReadable) {
                error = readPackets(); if (!error.empty()) { fail(error); break; }
            }
        }
    } catch (...) { fail("QUIC runtime/cryptography failure"); }
    fail(terminal.empty() ? "QUIC connection cancelled" : terminal);
    std::deque<std::function<void()>> remaining;
    { std::lock_guard<std::mutex> lock(mutex); remaining.swap(jobs); }
    for (auto &task : remaining) task();
    if (conn && socket >= 0 && !cancellationRequested()) {
        // A factory cancellation does not need another network packet. A
        // normal stream close still sends CONNECTION_CLOSE when possible.
        try {
            ngtcp2_ccerr close; ngtcp2_ccerr_default(&close);
            ngtcp2_ccerr_set_application_error(&close, node.type == "hysteria2" ? 0x100 : 0, nullptr, 0);
            ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path);
            ngtcp2_pkt_info info{}; uint8_t output[1350];
            auto length = ngtcp2_conn_write_connection_close(conn, &path.path, &info,
                output, sizeof(output), &close, now());
            if (length > 0 && !cancellationRequested()) {
                if (hasObfuscation()) {
                    auto bytes = obfuscate(output, static_cast<size_t>(length), true);
                    (void)::send(socket, bytes.data(), bytes.size(), 0);
                } else {
                    (void)::send(socket, output, static_cast<size_t>(length), 0);
                }
            }
        } catch (...) { /* Transport cleanup must not depend on close-frame crypto. */ }
    }
    // Do not wait for application wrappers or queued callbacks to release
    // their Connection references before returning the physical UDP socket.
#if defined(__APPLE__)
    if (kq_ >= 0) { ::close(kq_); kq_ = -1; }
#endif
    if (socket >= 0) { ::close(socket); socket = -1; }
    std::deque<std::function<void()>> finalJobs;
    { std::lock_guard<std::mutex> lock(mutex); jobsClosed = true; finalJobs.swap(jobs); }
    for (auto &job : finalJobs) dispatch(std::move(job));
}

Connection::Connection(Node value, std::shared_ptr<TransportFactory> factory)
    : impl_(std::make_unique<Impl>(std::move(value), std::move(factory))) {}
Connection::~Connection() { close(); }

void Connection::connect(Node value, std::shared_ptr<TransportFactory> factory, Ready ready) {
    auto connection = std::shared_ptr<Connection>(new Connection(std::move(value), std::move(factory)));
    connection->impl_->owner = connection; connection->impl_->ready = std::move(ready);
    if (connection->impl_->cancelled()) { connection->impl_->fail("QUIC connection cancelled"); return; }
    if (::pipe(connection->impl_->wake)) {
        auto callback = std::exchange(connection->impl_->ready, {}); callback(nullptr, "QUIC wake pipe creation failed"); return;
    }
    for (auto descriptor : connection->impl_->wake) {
        fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK);
        fcntl(descriptor, F_SETFD, FD_CLOEXEC);
    }
    // The worker owns the connection until cancellation or a terminal error.
    connection->impl_->worker = std::thread([connection] { connection->impl_->run(); });
}
void Connection::open(bool uni, StreamCallback callback) {
    auto self = shared_from_this(); impl_->post([self, uni, callback] { self->impl_->addStream(uni, callback); });
}
void Connection::authenticated() {
    auto self = shared_from_this(); impl_->post([self] {
        if (!self->isClosed()) self->impl_->applicationReady = true;
    });
}
void Connection::close() {
    if (!impl_) return;
    impl_->stopping = true;
    impl_->received->close();
    impl_->notifyWake();
}
size_t Connection::datagramLimit() const { return impl_->datagramSize.load(); }
bool Connection::isClosed() const { return impl_->cancelled(); }

void Connection::exportKey(Buffer label, Buffer context, std::function<void(Buffer, Error)> callback) {
    auto self = shared_from_this();
    impl_->post([self, label = std::move(label), context = std::move(context), callback] {
        Buffer output(32); auto impl = self->impl_.get();
        bool success = !impl->cancelled() && impl->handshake &&
            SSL_export_keying_material(impl->tls, output.data(), output.size(),
                reinterpret_cast<const char *>(label.data()), label.size(),
                context.data(), context.size(), 1) == 1;
        impl->dispatch([self, callback, output = std::move(output), success]() mutable {
            if (self->isClosed()) { callback({}, "QUIC connection cancelled"); return; }
            callback(success ? std::move(output) : Buffer{}, success ? Error{} : "QUIC TLS exporter failed");
        });
    });
}
void Connection::receiveDatagrams(std::function<void(Buffer)> receive, WriteCallback failure) {
    auto self = shared_from_this(); impl_->post([self, receive, failure] {
        if (self->isClosed()) {
            self->impl_->dispatch([failure] { failure("QUIC connection is closed"); }); return;
        }
        self->impl_->packetReceive = receive; self->impl_->packetFailure = failure;
    });
}
void Connection::receivePeerStreams(std::function<void(std::shared_ptr<Stream>)> callback) {
    auto self = shared_from_this(); impl_->post([self, callback] {
        if (!self->isClosed()) self->impl_->peerStreams = callback;
    });
}
void Connection::sendDatagrams(std::vector<Buffer> packets, WriteCallback callback) {
    size_t size = 0;
    for (auto &packet : packets) {
        if (packet.size() > datagramLimit() || packet.size() > maximumQueuedBytes - size) {
            impl_->dispatch([callback] { callback("QUIC datagram exceeds negotiated maximum"); }); return;
        }
        size += packet.size();
    }
    if (packets.empty() || packets.size() > 1024 || !Impl::reserve(impl_->stagedPackets, size)) {
        impl_->dispatch([callback] { callback("QUIC datagram queue limit exceeded"); }); return;
    }
    auto self = shared_from_this(); impl_->post([self, size, packets = std::move(packets), callback]() mutable {
        auto impl = self->impl_.get();
        if (impl->cancelled() || size > maximumQueuedBytes - impl->packetBytes || packets.empty()) {
            impl->stagedPackets -= size;
            impl->dispatch([callback] { callback("QUIC datagram queue is closed/full"); }); return;
        }
        auto remaining = std::make_shared<size_t>(packets.size());
        auto failed = std::make_shared<bool>(false);
        for (auto &packet : packets) {
            impl->packetBytes += packet.size();
            impl->packets.push_back({std::move(packet), [remaining, failed, callback](Error error) {
                if (!error.empty() && !*failed) { *failed = true; callback(error); }
                if (--*remaining == 0 && !*failed) callback({});
            }});
        }
    });
}

OwnedStream::OwnedStream(std::shared_ptr<Connection> connection, std::shared_ptr<Stream> stream,
                         std::shared_ptr<Reader> reader)
    : connection_(std::move(connection)), stream_(std::move(stream)), reader_(std::move(reader)) {}
OwnedStream::~OwnedStream() { close(); }
void OwnedStream::write(Buffer value, WriteCallback callback) {
    if (!stream_) { callback("QUIC stream is closed"); return; }
    stream_->write(std::move(value), std::move(callback));
}
void OwnedStream::read(size_t count, ReadCallback callback) {
    if (!stream_) { callback({}, true, "QUIC stream is closed"); return; }
    if (reader_) reader_->some(count, std::move(callback));
    else stream_->read(count, std::move(callback));
}
void OwnedStream::shutdownWrite(WriteCallback callback) {
    if (!stream_) { callback("QUIC stream is closed"); return; }
    stream_->shutdownWrite(std::move(callback));
}
void OwnedStream::close() {
    if (stream_) { stream_->close(); stream_.reset(); }
    if (reader_) { reader_->close(); reader_.reset(); }
    if (connection_) { connection_->close(); connection_.reset(); }
}

SharedStream::SharedStream(std::shared_ptr<Connection> connection, std::shared_ptr<Stream> stream,
                           std::shared_ptr<Reader> reader)
    : connection_(std::move(connection)), stream_(std::move(stream)), reader_(std::move(reader)) {}
SharedStream::~SharedStream() { close(); }
void SharedStream::write(Buffer value, WriteCallback callback) {
    if (!stream_) { callback("QUIC stream is closed"); return; }
    stream_->write(std::move(value), std::move(callback));
}
void SharedStream::read(size_t count, ReadCallback callback) {
    if (!stream_) { callback({}, true, "QUIC stream is closed"); return; }
    if (reader_) reader_->some(count, std::move(callback));
    else stream_->read(count, std::move(callback));
}
void SharedStream::shutdownWrite(WriteCallback callback) {
    if (!stream_) { callback("QUIC stream is closed"); return; }
    stream_->shutdownWrite(std::move(callback));
}
void SharedStream::close() {
    if (stream_) { stream_->close(); stream_.reset(); }
    if (reader_) { reader_->close(); reader_.reset(); }
    connection_.reset();
}

namespace {
const EVP_MD *cachedBlake2bMd() {
    static const EVP_MD *md = []() -> const EVP_MD * {
        EVP_MD *fetched = EVP_MD_fetch(nullptr, "BLAKE2B-512", nullptr);
        if (!fetched) std::abort();
        // Verify BLAKE2b-256("") == 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        static constexpr uint8_t kExpectedEmpty[32]{
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
            0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
            0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
            0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8
        };
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) std::abort();
        size_t outLen = 32;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &outLen),
            OSSL_PARAM_construct_end()
        };
        uint8_t digest[32]{};
        unsigned int written = 0;
        bool ok = EVP_DigestInit_ex2(ctx, fetched, params) == 1 &&
                  EVP_DigestUpdate(ctx, "", 0) == 1 &&
                  EVP_DigestFinal_ex(ctx, digest, &written) == 1 &&
                  written == 32 &&
                  std::memcmp(digest, kExpectedEmpty, 32) == 0;
        EVP_MD_CTX_free(ctx);
        if (!ok) std::abort();
        return fetched;
    }();
    return md;
}

Buffer blake2b256(const Buffer &input) {
    Buffer output(32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX allocation failed");
    size_t outLen = 32;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &outLen),
        OSSL_PARAM_construct_end()
    };
    unsigned int written = 0;
    bool ok = EVP_DigestInit_ex2(ctx, cachedBlake2bMd(), params) == 1 &&
              EVP_DigestUpdate(ctx, input.empty() ? "" : reinterpret_cast<const char *>(input.data()), input.size()) == 1 &&
              EVP_DigestFinal_ex(ctx, output.data(), &written) == 1 &&
              written == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("BLAKE2b-256 digest failed");
    return output;
}

bool computeObfsKey(bool salamander, const std::string &password,
                    const uint8_t *salt, size_t saltLen, uint8_t outKey[32]) {
    if (salamander && password.empty() && saltLen == 0) {
        auto empty = blake2b256({});
        std::memcpy(outKey, empty.data(), 32);
        return true;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    unsigned int written = 0;
    if (salamander) {
        size_t outLen = 32;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &outLen),
            OSSL_PARAM_construct_end()
        };
        ok = EVP_DigestInit_ex2(ctx, cachedBlake2bMd(), params) == 1 &&
             EVP_DigestUpdate(ctx, password.data(), password.size()) == 1 &&
             EVP_DigestUpdate(ctx, salt, saltLen) == 1 &&
             EVP_DigestFinal_ex(ctx, outKey, &written) == 1 &&
             written == 32;
    } else {
        ok = EVP_DigestInit_ex2(ctx, EVP_sha256(), nullptr) == 1 &&
             EVP_DigestUpdate(ctx, password.data(), password.size()) == 1 &&
             EVP_DigestUpdate(ctx, salt, saltLen) == 1 &&
             EVP_DigestFinal_ex(ctx, outKey, &written) == 1 &&
             written == 32;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}
} // namespace
} // namespace hajimi::quic
