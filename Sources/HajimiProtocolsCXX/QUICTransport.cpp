#include "QUICTransport.hpp"
#include "Crypto.hpp"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
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
#include <deque>
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
        std::deque<Write> writes; Buffer input; uint64_t end = 0;
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
    std::atomic<bool> stopping{false}; std::atomic<size_t> datagramSize{0};
    std::atomic<size_t> stagedWrites{0}, stagedPackets{0}; bool jobsClosed = false;
    std::shared_ptr<ReceiveMailbox> received = std::make_shared<ReceiveMailbox>();
    int socket = -1, wake[2]{-1, -1};
    sockaddr_storage local{}, remote{}; socklen_t localLength = 0, remoteLength = 0;
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

    Impl(Node value, std::shared_ptr<TransportFactory> io)
        : node(std::move(value)), factory(std::move(io)) {}
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
    if (wake[1] >= 0) { uint8_t value = 1; (void)::write(wake[1], &value, 1); }
}

Error Connection::Impl::setupSocket() {
    if (cancelled()) return "QUIC connection cancelled";
    addrinfo hints{}, *addresses = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    int resolved = getaddrinfo(node.host.c_str(), std::to_string(node.port).c_str(), &hints, &addresses);
    // getaddrinfo is not interruptible. Do not create a socket or enter TLS
    // when cancellation happened while the resolver was blocking.
    if (cancelled()) {
        if (addresses) freeaddrinfo(addresses);
        return "QUIC connection cancelled";
    }
    if (resolved) return "QUIC server DNS resolution failed";
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
    auto options = tlsOptions(node, true);
    SSL_CTX_set_verify(tlsContext, options.skipVerify ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, nullptr);
    verifyName = options.serverName.empty() ? node.host : options.serverName;
    if (!options.skipVerify) {
        auto ca = node.option("ca");
        if (ca.empty()) {
#if defined(__APPLE__)
            // Static OpenSSL cannot assume Homebrew's cert.pem exists on the
            // recipient's Mac. Use the system trust store + hostname policy.
            SSL_CTX_set_cert_verify_callback(tlsContext, certificateTrust, this);
#else
            if (!SSL_CTX_set_default_verify_paths(tlsContext)) return "QUIC trust store unavailable";
#endif
        } else if (!SSL_CTX_load_verify_locations(tlsContext, ca.c_str(), nullptr))
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
    uint8_t numeric[16];
    bool isIP = inet_pton(AF_INET, name.c_str(), numeric) == 1 ||
                inet_pton(AF_INET6, name.c_str(), numeric) == 1;
    if (!isIP && !node.flag("disable-sni") && !SSL_set_tlsext_host_name(tls, name.c_str()))
        return "QUIC SNI configuration failed";
    if (!options.skipVerify) {
        auto params = SSL_get0_param(tls);
        if (isIP) {
            if (!X509_VERIFY_PARAM_set1_ip_asc(params, name.c_str())) return "QUIC IP verification setup failed";
        } else if (!SSL_set1_host(tls, name.c_str())) return "QUIC hostname verification setup failed";
    }
    if (options.alpn.empty()) options.alpn.push_back(node.type == "hysteria" ? "hysteria" : "h3");
    Buffer alpn;
    for (const auto &value : options.alpn) {
        if (value.empty() || value.size() > 255) return "QUIC ALPN value is invalid";
        alpn.push_back(static_cast<uint8_t>(value.size()));
        alpn.insert(alpn.end(), value.begin(), value.end());
    }
    if (SSL_set_alpn_protos(tls, alpn.data(), static_cast<unsigned>(alpn.size())))
        return "QUIC ALPN configuration failed";
    return cancelled() ? "QUIC connection cancelled" : Error{};
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
    settings.max_tx_udp_payload_size = 1350; settings.no_pmtud = 1;
    auto congestion = node.option("congestion-controller", node.option("congestion", "bbr"));
    settings.cc_algo = congestion == "cubic" ? NGTCP2_CC_ALGO_CUBIC :
                       congestion == "reno" ? NGTCP2_CC_ALGO_RENO : NGTCP2_CC_ALGO_BBR;
    ngtcp2_transport_params params; ngtcp2_transport_params_default(&params);
    params.initial_max_data = 4 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = maximumQueuedBytes;
    params.initial_max_stream_data_bidi_remote = maximumQueuedBytes;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_streams_bidi = 16; params.initial_max_streams_uni = 16;
    params.max_idle_timeout = 60 * NGTCP2_SECONDS;
    params.max_datagram_frame_size = 1200;
    int code = ngtcp2_conn_client_new(&conn, &destination, &source, &path,
        NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);
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
    self->datagramSize = remote ? std::min<size_t>(1150, remote->max_datagram_frame_size > 3
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
    if (count > maximumQueuedBytes - state.input.size() ||
        self->readBytes + count > 4 * 1024 * 1024) return NGTCP2_ERR_CALLBACK_FAILURE;
    state.input.insert(state.input.end(), data, data + count); self->readBytes += count;
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
    Buffer output(state.input.begin(), state.input.begin() + count);
    state.input.erase(state.input.begin(), state.input.begin() + count); readBytes -= count;
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
    bool salamander = node.type == "hysteria2" && node.option("obfs") == "salamander";
    std::string password = salamander ? node.option("obfs-password") :
                           node.type == "hysteria" ? node.option("obfs") : "";
    if (password.empty()) return Buffer(data, data + size);
    size_t saltSize = salamander ? 8 : 16;
    if (!outbound && size <= saltSize) return {};
    Buffer salt = outbound ? crypto::randomBytes(saltSize) : Buffer(data, data + saltSize);
    Buffer material(password.begin(), password.end()); material.insert(material.end(), salt.begin(), salt.end());
    Buffer key = salamander ? blake2b256(material) : crypto::digest("SHA256", material);
    Buffer result = outbound ? salt : Buffer{};
    size_t offset = outbound ? 0 : saltSize;
    result.reserve(result.size() + size - offset);
    for (size_t index = offset; index < size; ++index)
        result.push_back(data[index] ^ key[(index - offset) % key.size()]);
    return result;
}

Error Connection::Impl::readPackets() {
    uint8_t input[65536];
    for (size_t iteration = 0; iteration < 64; ++iteration) {
        if (cancelled()) return "QUIC connection cancelled";
        auto length = ::recv(socket, input, sizeof(input), 0);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return {};
            if (errno == EINTR) continue;
            return "QUIC UDP receive failed";
        }
        auto data = obfuscate(input, static_cast<size_t>(length), false);
        if (data.empty()) continue;
        if (cancelled()) return "QUIC connection cancelled";
        ngtcp2_path path{{reinterpret_cast<sockaddr *>(&local), localLength},
                         {reinterpret_cast<sockaddr *>(&remote), remoteLength}, nullptr};
        ngtcp2_pkt_info info{};
        int code = ngtcp2_conn_read_pkt(conn, &path, &info, data.data(), data.size(), now());
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
    auto sendWire = [&]() -> int {
        if (cancelled()) return -1;
        if (pendingWire.empty()) return 1;
        auto length = ::send(socket, pendingWire.data(), pendingWire.size(), 0);
        if (length == static_cast<ssize_t>(pendingWire.size())) { pendingWire.clear(); return 1; }
        if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        return -1;
    };
    int sent = sendWire();
    if (sent <= 0) return sent == 0 ? Error{} : cancelled() ? "QUIC connection cancelled" : "QUIC UDP send failed";
    std::vector<int64_t> ids;
    for (auto &entry : streams) if (!entry.second.closed) ids.push_back(entry.first);
    size_t cursor = 0; ngtcp2_tstamp timestamp = now();
    for (size_t iteration = 0; iteration < 64; ++iteration) {
        if (cancelled()) return "QUIC connection cancelled";
        ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info info{}; uint8_t output[1350]; ngtcp2_ssize written = 0;
        if (!packets.empty() && handshake) {
            auto &packet = packets.front(); ngtcp2_vec vector{packet.bytes.data(), packet.bytes.size()}; int accepted = 0;
            written = ngtcp2_conn_writev_datagram(conn, &path.path, &info, output,
                sizeof(output), &accepted, 0, 0, &vector, 1, timestamp);
            if (accepted || written == NGTCP2_ERR_INVALID_ARGUMENT || written == NGTCP2_ERR_INVALID_STATE) {
                auto callback = std::move(packet.completion); packetBytes -= packet.bytes.size();
                stagedPackets -= packet.bytes.size(); packets.pop_front();
                auto error = accepted ? Error{} : "QUIC peer does not support this datagram size";
                dispatch([callback, error] { if (callback) callback(error); });
                if (!accepted) continue;
            }
        } else {
            int64_t id = -1; State *state = nullptr; Write *write = nullptr;
            for (size_t attempt = 0; attempt < ids.size(); ++attempt) {
                auto candidate = ids[cursor++ % ids.size()]; auto &value = streams.at(candidate);
                for (auto &chunk : value.writes) if (chunk.sent < chunk.bytes.size()) { write = &chunk; break; }
                if (write || (value.fin && !value.finSent)) { id = candidate; state = &value; break; }
            }
            ngtcp2_vec vector{}; size_t count = 0;
            if (write) { vector = {write->bytes.data() + write->sent, write->bytes.size() - write->sent}; count = 1; }
            bool fin = state && state->fin && (!write || write->offset + write->bytes.size() == state->end);
            ngtcp2_ssize consumed = -1;
            written = ngtcp2_conn_writev_stream(conn, &path.path, &info, output, sizeof(output),
                &consumed, fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0, id, &vector, count, timestamp);
            if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED) continue;
            if (written == NGTCP2_ERR_STREAM_SHUT_WR) { if (state) closeStream(id); continue; }
            if (consumed >= 0 && write) {
                write->sent += static_cast<size_t>(consumed);
                if (write->sent == write->bytes.size() && write->completion) {
                    auto callback = std::exchange(write->completion, {}); dispatch([callback] { callback({}); });
                }
            }
            if (consumed >= 0 && fin && (!write || write->sent == write->bytes.size())) {
                traceStream(node, "send-fin", id, static_cast<size_t>(consumed), true, false);
                state->finSent = true; auto callback = std::exchange(state->shutdown, {});
                if (callback) dispatch([callback] { callback({}); });
            }
        }
        if (written < 0) return "QUIC packet write failed";
        if (!written) break;
        pendingWire = obfuscate(output, static_cast<size_t>(written), true);
        sent = sendWire();
        if (sent < 0) return cancelled() ? "QUIC connection cancelled" : "QUIC UDP send failed";
        if (!sent) break;
    }
    ngtcp2_conn_update_pkt_tx_time(conn, timestamp);
    return {};
}

void Connection::Impl::fail(Error error) {
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
            auto wait = expiry > now() ? (expiry - now()) / NGTCP2_MILLISECONDS : 0;
            pollfd descriptors[2]{{socket, static_cast<short>(POLLIN | (pendingWire.empty() ? 0 : POLLOUT)), 0},
                                  {wake[0], POLLIN, 0}};
            int result = ::poll(descriptors, 2, static_cast<int>(std::min<uint64_t>(wait + 1, 100)));
            if (result < 0 && errno != EINTR) { fail("QUIC event polling failed"); break; }
            if (cancelled()) { fail("QUIC connection cancelled"); break; }
            if (descriptors[1].revents & POLLIN) { uint8_t values[256]; while (::read(wake[0], values, sizeof(values)) > 0) {} }
            if (descriptors[0].revents & (POLLIN | POLLERR)) {
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
            if (length > 0) {
                auto bytes = obfuscate(output, static_cast<size_t>(length), true);
                if (!cancellationRequested()) (void)::send(socket, bytes.data(), bytes.size(), 0);
            }
        } catch (...) { /* Transport cleanup must not depend on close-frame crypto. */ }
    }
    // Do not wait for application wrappers or queued callbacks to release
    // their Connection references before returning the physical UDP socket.
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
    if (!impl_) return; impl_->stopping = true;
    impl_->received->close();
    if (impl_->wake[1] >= 0) { uint8_t value = 1; (void)::write(impl_->wake[1], &value, 1); }
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

namespace {
Buffer blake2b256(const Buffer &input) {
    static constexpr uint64_t iv[8]{0x6a09e667f3bcc908,0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,
        0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179};
    static constexpr uint8_t permutation[12][16]{
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}};
    uint64_t hash[8]; std::copy(std::begin(iv), std::end(iv), hash); hash[0] ^= 0x01010020;
    size_t offset = 0;
    do {
        uint8_t block[128]{}; size_t count = std::min<size_t>(128, input.size() - offset);
        if (count) std::memcpy(block, input.data() + offset, count);
        offset += count; bool final = offset == input.size(); uint64_t message[16]{}, v[16];
        for (size_t word = 0; word < 16; ++word)
            for (size_t byte = 0; byte < 8; ++byte) message[word] |= uint64_t(block[word * 8 + byte]) << (byte * 8);
        std::copy(hash, hash + 8, v); std::copy(std::begin(iv), std::end(iv), v + 8);
        v[12] ^= offset; if (final) v[14] = ~v[14];
        auto rotate = [](uint64_t x, unsigned r) { return (x >> r) | (x << (64 - r)); };
        auto mix = [&](int a,int b,int c,int d,uint64_t x,uint64_t y) {
            v[a] += v[b] + x; v[d] = rotate(v[d] ^ v[a],32); v[c] += v[d]; v[b] = rotate(v[b] ^ v[c],24);
            v[a] += v[b] + y; v[d] = rotate(v[d] ^ v[a],16); v[c] += v[d]; v[b] = rotate(v[b] ^ v[c],63);
        };
        for (auto &p : permutation) {
            mix(0,4,8,12,message[p[0]],message[p[1]]); mix(1,5,9,13,message[p[2]],message[p[3]]);
            mix(2,6,10,14,message[p[4]],message[p[5]]); mix(3,7,11,15,message[p[6]],message[p[7]]);
            mix(0,5,10,15,message[p[8]],message[p[9]]); mix(1,6,11,12,message[p[10]],message[p[11]]);
            mix(2,7,8,13,message[p[12]],message[p[13]]); mix(3,4,9,14,message[p[14]],message[p[15]]);
        }
        for (size_t word = 0; word < 8; ++word) hash[word] ^= v[word] ^ v[word + 8];
        if (final) break;
    } while (true);
    Buffer output(32);
    for (size_t index = 0; index < output.size(); ++index) output[index] = hash[index / 8] >> ((index % 8) * 8);
    return output;
}
} // namespace
} // namespace hajimi::quic
