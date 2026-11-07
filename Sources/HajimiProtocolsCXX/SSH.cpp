// SSH transport/authentication is supplied by the locally built, pinned C
// libssh2 library. This C++ adapter owns async I/O, host identity validation,
// SSHSessionPool multiplexing (up to 64 concurrent direct-tcpip channels per
// authenticated LIBSSH2_SESSION), bounded buffering, cancellation, and half-close.
#include "SSH.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include <libssh2.h>
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <utility>

namespace hajimi {
namespace {
constexpr size_t maximumSSHKeyBytes = 256 * 1024;
constexpr size_t maxChannelsPerSSHSession = 64;

std::string trim(std::string text) {
    for (int iter = 0; iter < 3; ++iter) {
        size_t start = text.find_first_not_of(" \r\n\t"), end = text.find_last_not_of(" \r\n\t");
        if (start == std::string::npos) return {};
        text = text.substr(start, end - start + 1);
        if (text.size() >= 2 &&
            ((text.front() == '"' && text.back() == '"') ||
             (text.front() == '\'' && text.back() == '\'') ||
             (text.front() == '[' && text.back() == ']'))) {
            text = text.substr(1, text.size() - 2);
        } else {
            break;
        }
    }
    size_t start = text.find_first_not_of(" \r\n\t"), end = text.find_last_not_of(" \r\n\t");
    return start == std::string::npos ? std::string{} : text.substr(start, end - start + 1);
}

std::vector<std::string> list(std::string value, bool commas) {
    for (auto &ch : value) if (ch == '|' || ch == ';' || ch == '\n' || (commas && ch == ',')) ch = '\n';
    std::istringstream input(value); std::string item; std::vector<std::string> result;
    while (std::getline(input, item)) {
        item = trim(std::move(item)); if (item.empty()) continue;
        if (result.size() >= 64) throw std::runtime_error("SSH option list exceeds its bound");
        result.push_back(std::move(item));
    }
    return result;
}

struct HostPin { bool fingerprint; Buffer value; std::string keyType; };

uint32_t sshWord(const uint8_t *bytes) {
    return uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 | uint32_t(bytes[3]);
}

std::vector<HostPin> pins(const Node &node) {
    auto raw = node.option("host-key");
    if (raw.size() > 64 * 1024) throw std::runtime_error("SSH host-key option exceeds its bound");
    std::vector<HostPin> result;
    for (const auto &pin : list(raw, false)) {
        if (pin.compare(0, 7, "SHA256:") == 0) {
            Buffer value;
            try { value = crypto::base64Decode(pin.substr(7)); }
            catch (const std::exception &) { throw std::runtime_error("Invalid SSH SHA256 host-key pin"); }
            if (value.size() != 32) throw std::runtime_error("SSH SHA256 host-key pin must contain 32 bytes");
            result.push_back({true, std::move(value), {}}); continue;
        }
        std::istringstream input(pin); std::string type, encoded; input >> type >> encoded;
        if (type.empty() || encoded.empty()) throw std::runtime_error("SSH host-key must be SHA256 pin or authorized-key text");
        Buffer value;
        try { value = crypto::base64Decode(encoded); }
        catch (const std::exception &) { throw std::runtime_error("Invalid SSH authorized host-key encoding"); }
        if (value.size() < 8 || value.size() > 16384 || sshWord(value.data()) > value.size() - 4 ||
            std::string(value.begin() + 4, value.begin() + 4 + sshWord(value.data())) != type)
            throw std::runtime_error("Invalid SSH authorized host-key wire type");
        result.push_back({false, std::move(value), type});
    }
    return result;
}

void initializeSSH() {
    static std::once_flag once; static int status = -1;
    std::call_once(once, [] { status = libssh2_init(0); });
    if (status) throw std::runtime_error("Cannot initialize native SSH crypto");
}

std::string hostAlgorithms(const Node &node) {
    auto algorithms = list(node.option("host-key-algorithms"), true);
    bool explicitAlgs = !algorithms.empty();
    if (!explicitAlgs) {
        auto configuredPins = pins(node);
        for (const auto &pin : configuredPins) {
            if (pin.fingerprint || pin.keyType.empty()) continue;
            if (pin.keyType == "ssh-rsa") {
                algorithms.push_back("rsa-sha2-512");
                algorithms.push_back("rsa-sha2-256");
                algorithms.push_back("ssh-rsa");
            } else {
                algorithms.push_back(pin.keyType);
            }
        }
    }
    if (algorithms.empty()) return {};
    initializeSSH();
    std::unique_ptr<LIBSSH2_SESSION, decltype(&libssh2_session_free)> session(libssh2_session_init(), libssh2_session_free);
    if (!session) throw std::runtime_error("Cannot create SSH algorithm validation context");
    const char **supported = nullptr;
    int count = libssh2_session_supported_algs(session.get(), LIBSSH2_METHOD_HOSTKEY, &supported);
    if (count < 0) throw std::runtime_error("Cannot inspect native SSH host-key algorithms");
    std::set<std::string> available;
    for (int i = 0; i < count; ++i) available.insert(supported[i]);
    libssh2_free(session.get(), supported);
    std::string result;
    std::set<std::string> seen;
    for (const auto &algorithm : algorithms) {
        if (!available.count(algorithm)) {
            if (explicitAlgs) throw std::runtime_error("Requested SSH host-key algorithm is unavailable in native libssh2");
            continue;
        }
        if (!seen.insert(algorithm).second) continue;
        if (!result.empty()) result += ',';
        result += algorithm;
    }
    return result;
}

void validatePrivateKeyOption(const std::string &value) {
    if (value.size() > maximumSSHKeyBytes || value.find('\0') != std::string::npos)
        throw std::runtime_error("SSH private-key option exceeds its bound or contains NUL");
}

std::string loadPrivateKey(std::string value) {
    if (value.empty()) return {};
    validatePrivateKeyOption(value);
    if (value.find("PRIVATE KEY") == std::string::npos) {
        struct stat status{};
        if (::stat(value.c_str(), &status)) throw std::runtime_error("Cannot read configured SSH private-key file");
        if (!S_ISREG(status.st_mode)) throw std::runtime_error("SSH private-key file must be a regular file");
        struct Descriptor {
            int value;
            ~Descriptor() { if (value >= 0) ::close(value); }
        } input{::open(value.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
        if (input.value < 0 || ::fstat(input.value, &status))
            throw std::runtime_error("Cannot read configured SSH private-key file");
        if (!S_ISREG(status.st_mode)) throw std::runtime_error("SSH private-key file must be a regular file");
        if (status.st_size <= 0 || uint64_t(status.st_size) > maximumSSHKeyBytes)
            throw std::runtime_error("SSH private-key file exceeds its bound or is empty");
        std::string loaded; loaded.reserve(size_t(status.st_size));
        char block[16 * 1024];
        while (loaded.size() <= maximumSSHKeyBytes) {
            auto maximum = std::min(sizeof(block), maximumSSHKeyBytes + 1 - loaded.size());
            auto count = ::read(input.value, block, maximum);
            if (count < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("Cannot read configured SSH private-key file");
            }
            if (!count) break;
            loaded.append(block, size_t(count));
        }
        if (loaded.empty() || loaded.size() > maximumSSHKeyBytes) throw std::runtime_error("SSH private-key file exceeds its bound or is empty");
        value = std::move(loaded);
    } else {
        size_t offset = 0;
        while ((offset = value.find("\\n", offset)) != std::string::npos) { value.replace(offset, 2, "\n"); ++offset; }
    }
    if (value.find("PRIVATE KEY") == std::string::npos || value.find('\0') != std::string::npos)
        throw std::runtime_error("Configured SSH private-key is not PEM or OpenSSH key text");
    return value;
}

void sshPut32(Buffer &bytes, uint32_t value) {
    bytes.insert(bytes.end(), {uint8_t(value >> 24), uint8_t(value >> 16), uint8_t(value >> 8), uint8_t(value)});
}

Buffer directRequest(const Target &target) {
    Buffer data; sshPut32(data, uint32_t(target.host.size())); data.insert(data.end(), target.host.begin(), target.host.end());
    sshPut32(data, target.port); sshPut32(data, 9); data.insert(data.end(), {'1','2','7','.','0','.','0','.','1'}); sshPut32(data, 0);
    return data;
}
} // namespace

namespace ssh {
bool hostKeyMatches(const Node &node, const Buffer &wireKey) {
    auto configured = pins(node);
    if (configured.empty()) return node.flag("skip-cert-verify");
    auto digest = crypto::digest("SHA256", wireKey);
    for (const auto &pin : configured) if (crypto::constantTimeEqual(pin.value, pin.fingerprint ? digest : wireKey)) return true;
    return false;
}
} // namespace ssh

namespace {
class SSHChannelStream;

/// Multiplexed SSH-2 connection session owning a single LIBSSH2_SESSION and TCP
/// carrier, capable of opening up to maxChannelsPerSSHSession (64) concurrent
/// direct-tcpip channels without repeating TCP/KEX/Auth handshakes.
class SSHConnectionSession final : public std::enable_shared_from_this<SSHConnectionSession> {
public:
    SSHConnectionSession(Node node, std::string privateKey, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), privateKey_(std::move(privateKey)), factory_(std::move(factory)) {}
    ~SSHConnectionSession() {
        closed_ = true;
        if (carrier_) carrier_->close();
        releaseNative();
    }

    bool canReserveChannel() const {
        return !closed_ && !carrierEOF_ && !wireOverflow_ && reservedSlots_ < maxChannelsPerSSHSession;
    }

    void reserveChannelSlot() { ++reservedSlots_; }

    void attachChannel(const std::shared_ptr<SSHChannelStream> &channel);
    void onChannelClosed();
    void requestPump();
    void post(std::function<void()> work) { factory_->post(std::move(work)); }
    void forceClose(Error reason) { failSession(std::move(reason)); }
    bool ownedBy(const std::shared_ptr<TransportFactory> &factory) const { return !factory || factory_ == factory; }
    void reset() {
        if (factory_ && factory_->post) {
            auto self = shared_from_this();
            factory_->post([self] { self->failSession("SSH session pool reset"); });
        } else {
            failSession("SSH session pool reset");
        }
    }

    LIBSSH2_SESSION *nativeSession() const { return session_; }
    size_t outgoingBytes() const { return outgoingBytes_; }
    bool isReady() const { return !closed_ && stage_ == Stage::Ready; }
    bool isClosed() const { return closed_; }
    const Error &terminalError() const { return terminal_; }
    void markNeedInbound() { needInbound_ = true; }
    bool hasPendingWireOutput() const { return rawWriting_ || !outgoing_.empty(); }

private:
    enum class Stage { Idle, Transport, Handshake, HostKey, PublicKey, Password, KeyboardInteractive, Ready };
    Node node_;
    std::string privateKey_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Stream> carrier_;
    LIBSSH2_SESSION *session_ = nullptr;
    int descriptor_ = -1;
    Stage stage_ = Stage::Idle;
    std::string username_, password_, passphrase_;
    std::deque<Buffer> incoming_, outgoing_;
    size_t incomingBytes_ = 0, incomingOffset_ = 0, outgoingBytes_ = 0;
    std::vector<std::weak_ptr<SSHChannelStream>> channels_;
    size_t reservedSlots_ = 0;
    bool closed_ = false, pumpQueued_ = false, rawReading_ = false, rawWriting_ = false, needInbound_ = false;
    bool carrierEOF_ = false, wireOverflow_ = false, hostKeyVerified_ = false;
    Error terminal_;

    void startTransport();
    void initializeNative();
    void releaseNative();
    void pump();
    bool stepSessionSetup();
    void flushWire();
    void receiveWire();
    void failSession(Error);

    static LIBSSH2_SEND_FUNC(sendCallback);
    static LIBSSH2_RECV_FUNC(receiveCallback);
    static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(keyboardInteractiveCallback);
};

class SSHChannelStream final : public Stream, public std::enable_shared_from_this<SSHChannelStream> {
public:
    SSHChannelStream(std::shared_ptr<SSHConnectionSession> session, Target target,
                     std::shared_ptr<TransportFactory> factory, StreamCallback completion)
        : session_(std::move(session)), target_(std::move(target)),
          factory_(std::move(factory)), completion_(std::move(completion)),
          channelRequest_(directRequest(target_)) {}

    ~SSHChannelStream() override {
        closeChannelInternal("SSH stream closed", true);
    }

    void start() {
        auto self = shared_from_this();
        selfKeepAlive_ = self;
        double budget = ProtocolTimeouts::clampSetupBudget(factory_->remainingDeadlineSeconds);
        factory_->after(budget, [weak = std::weak_ptr<SSHChannelStream>(self)] {
            if (auto pending = weak.lock(); pending && pending->completion_) {
                pending->failChannel("SSH handshake timed out", true);
            }
        });
        if (factory_->cancelled && factory_->cancelled()) {
            failChannel("SSH connection cancelled", false);
            return;
        }
        session_->attachChannel(self);
    }

    void write(Buffer data, WriteCallback completion) override {
        auto self = shared_from_this();
        session_->post([self, data = std::move(data), completion = std::move(completion)]() mutable {
            self->enqueue(std::move(data), false, std::move(completion));
        });
    }

    void shutdownWrite(WriteCallback completion) override {
        auto self = shared_from_this();
        session_->post([self, completion = std::move(completion)]() mutable {
            self->enqueue({}, true, std::move(completion));
        });
    }

    void read(size_t maximum, ReadCallback completion) override {
        auto self = shared_from_this();
        session_->post([self, maximum, completion = std::move(completion)]() mutable {
            if (self->closed_) { completion({}, true, self->terminal_); return; }
            if (!self->ready_) { completion({}, false, "SSH session is not ready"); return; }
            if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid SSH read bound"); return; }
            if (self->pendingRead_) { completion({}, false, "An SSH channel read is already pending"); return; }
            self->readBuffer_.resize(maximum);
            self->pendingRead_ = std::move(completion);
            self->session_->requestPump();
        });
    }

    void close() override {
        auto self = shared_from_this();
        session_->post([self] { self->failChannel("SSH stream closed", false); });
    }

    bool supportsHalfClose() const override { return true; }

    bool isClosed() const { return closed_; }

    bool stepChannel() {
        if (closed_ || !session_ || !session_->isReady()) return false;
        auto *ssh = session_->nativeSession();
        if (!ssh) return false;

        if (!ready_) {
            if (factory_->cancelled && factory_->cancelled()) {
                failChannel("SSH connection cancelled", false);
                return false;
            }
            channel_ = libssh2_channel_open_ex(ssh, "direct-tcpip", 12, 256 * 1024, 32768,
                                               reinterpret_cast<const char *>(channelRequest_.data()),
                                               unsigned(channelRequest_.size()));
            if (!channel_) {
                int code = libssh2_session_last_errno(ssh);
                if (code == LIBSSH2_ERROR_EAGAIN) {
                    session_->markNeedInbound();
                    return false;
                }
                failChannel("SSH direct-tcpip request failed (native code " + std::to_string(code) + ")", false);
                return false;
            }
            ready_ = true;
            channelRequest_.clear();
            auto keep = std::move(selfKeepAlive_);
            if (auto cb = std::exchange(completion_, {})) cb(shared_from_this(), {});
            return true;
        }

        bool progress = stepWrite();
        if (!closed_) progress = stepRead() || progress;
        return progress;
    }

    void onSessionFailed(const Error &error) {
        failChannel(error, false);
    }

private:
    struct PendingWrite { Buffer data; size_t offset = 0; bool end = false, endSent = false; WriteCallback completion; };
    std::shared_ptr<SSHChannelStream> selfKeepAlive_;
    std::shared_ptr<SSHConnectionSession> session_;
    Target target_;
    std::shared_ptr<TransportFactory> factory_;
    StreamCallback completion_;
    Buffer channelRequest_, readBuffer_;
    LIBSSH2_CHANNEL *channel_ = nullptr;
    std::deque<PendingWrite> writes_;
    size_t queuedApplication_ = 0;
    ReadCallback pendingRead_;
    bool ready_ = false, closed_ = false, readEOF_ = false, writeClosing_ = false, slotReleased_ = false;
    Error terminal_;

    void enqueue(Buffer data, bool end, WriteCallback completion) {
        if (closed_ || !ready_ || writeClosing_) {
            completion(terminal_.empty() ? "SSH write side closed" : terminal_);
            return;
        }
        if (data.size() > maximumQueuedBytes - queuedApplication_ || writes_.size() >= 256) {
            completion("SSH application write queue exceeds its bound");
            return;
        }
        if (data.empty() && !end) { completion({}); return; }
        if (end) writeClosing_ = true;
        queuedApplication_ += data.size();
        writes_.push_back({std::move(data), 0, end, false, std::move(completion)});
        session_->requestPump();
    }

    bool stepWrite() {
        if (writes_.empty() || !channel_) return false;
        auto &pending = writes_.front();
        if ((!pending.end && pending.offset == pending.data.size()) || pending.endSent) {
            if (session_->hasPendingWireOutput()) return false;
            queuedApplication_ -= pending.data.size();
            auto callback = std::exchange(pending.completion, {});
            writes_.pop_front();
            callback({});
            return true;
        }
        if (session_->outgoingBytes() >= 64 * 1024) return false;
        if (pending.end) {
            int code = libssh2_channel_send_eof(channel_);
            if (code == LIBSSH2_ERROR_EAGAIN) { session_->markNeedInbound(); return false; }
            if (code) { failChannel("SSH write half-close failed (native code " + std::to_string(code) + ")", false); return false; }
            pending.endSent = true;
            return true;
        }
        size_t count = std::min<size_t>(32768, pending.data.size() - pending.offset);
        ssize_t code = libssh2_channel_write_ex(channel_, 0, reinterpret_cast<const char *>(pending.data.data() + pending.offset), count);
        if (code == LIBSSH2_ERROR_EAGAIN || !code) { session_->markNeedInbound(); return false; }
        if (code < 0) { failChannel("SSH channel write failed (native code " + std::to_string(code) + ")", false); return false; }
        if (size_t(code) > count) { failChannel("SSH library returned an invalid write length", false); return false; }
        pending.offset += size_t(code);
        return true;
    }

    bool stepRead() {
        if (!pendingRead_ || !channel_) return false;
        if (readEOF_) {
            auto callback = std::exchange(pendingRead_, {});
            readBuffer_.clear();
            callback({}, true, {});
            return true;
        }
        ssize_t code = libssh2_channel_read_ex(channel_, 0, reinterpret_cast<char *>(readBuffer_.data()), readBuffer_.size());
        if (code == LIBSSH2_ERROR_EAGAIN) return false;
        if (code < 0) { failChannel("SSH channel read failed (native code " + std::to_string(code) + ")", false); return false; }
        readEOF_ = libssh2_channel_eof(channel_) != 0;
        if (!code && !readEOF_) { session_->markNeedInbound(); return false; }
        if (size_t(code) > readBuffer_.size()) { failChannel("SSH library returned an invalid read length", false); return false; }
        readBuffer_.resize(size_t(code));
        auto data = std::move(readBuffer_);
        readBuffer_.clear();
        auto callback = std::exchange(pendingRead_, {});
        callback(std::move(data), readEOF_, {});
        return true;
    }

    void closeChannelInternal(Error error, bool fromDestructor) {
        (void)fromDestructor;
        if (closed_) return;
        closed_ = true;
        auto keep = std::move(selfKeepAlive_);
        terminal_ = std::move(error);
        if (channel_ && session_ && session_->nativeSession()) {
            libssh2_channel_close(channel_);
            libssh2_channel_free(channel_);
            channel_ = nullptr;
        }
        if (session_ && !slotReleased_) {
            slotReleased_ = true;
            session_->onChannelClosed();
        }
        auto completion = std::exchange(completion_, {});
        auto read = std::exchange(pendingRead_, {});
        auto writes = std::move(writes_);
        writes_.clear();
        readBuffer_.clear();
        channelRequest_.clear();
        queuedApplication_ = 0;
        if (completion) completion({}, terminal_);
        for (auto &pending : writes) if (auto callback = std::exchange(pending.completion, {})) callback(terminal_);
        if (read) read({}, true, terminal_);
    }

    void failChannel(Error error, bool abortSessionIfHandshake) {
        bool wasHandshaking = !ready_;
        auto sessionRef = session_;
        closeChannelInternal(error, false);
        if (abortSessionIfHandshake && wasHandshaking && sessionRef) {
            sessionRef->forceClose(std::move(error));
        }
    }
};

void SSHConnectionSession::attachChannel(const std::shared_ptr<SSHChannelStream> &channel) {
    if (closed_) {
        if (reservedSlots_ > 0) --reservedSlots_;
        channel->onSessionFailed(terminal_.empty() ? "SSH session closed" : terminal_);
        return;
    }
    channels_.push_back(channel);
    if (stage_ == Stage::Idle) {
        startTransport();
    } else {
        requestPump();
    }
}

void SSHConnectionSession::onChannelClosed() {
    if (reservedSlots_ > 0) --reservedSlots_;
    channels_.erase(std::remove_if(channels_.begin(), channels_.end(),
                                   [](const std::weak_ptr<SSHChannelStream> &w) {
                                       auto s = w.lock();
                                       return !s || s->isClosed();
                                   }),
                    channels_.end());
    if (reservedSlots_ == 0 && channels_.empty()) {
        // Close idle session when no active or pending channels remain so
        // carrier sockets are promptly reclaimed after a burst completes.
        failSession("SSH session idle closed");
        return;
    }
    requestPump();
}

void SSHConnectionSession::startTransport() {
    stage_ = Stage::Transport;
    auto self = shared_from_this();
    factory_->tcp(node_, {}, [self](std::shared_ptr<Stream> raw, Error error) {
        self->post([self, raw = std::move(raw), error = std::move(error)]() mutable {
            if (self->closed_) { if (raw) raw->close(); return; }
            if (!error.empty() || !raw) {
                self->failSession(error.empty() ? "SSH TCP transport failed" : std::move(error));
                return;
            }
            self->carrier_ = std::move(raw);
            try { self->initializeNative(); }
            catch (const std::exception &failure) { self->failSession(failure.what()); return; }
            self->stage_ = Stage::Handshake;
            self->requestPump();
        });
    });
}

void SSHConnectionSession::initializeNative() {
    initializeSSH();
    username_ = node_.option("username", node_.option("user"));
    password_ = node_.option("password");
    passphrase_ = node_.option("private-key-passphrase");
    descriptor_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor_ < 0) throw std::runtime_error("Cannot allocate SSH callback socket descriptor");
    session_ = libssh2_session_init_ex(nullptr, nullptr, nullptr, this);
    if (!session_) throw std::runtime_error("Cannot allocate native SSH session");
    libssh2_session_set_blocking(session_, 0);
    libssh2_session_callback_set2(session_, LIBSSH2_CALLBACK_SEND, reinterpret_cast<libssh2_cb_generic *>(&sendCallback));
    libssh2_session_callback_set2(session_, LIBSSH2_CALLBACK_RECV, reinterpret_cast<libssh2_cb_generic *>(&receiveCallback));
    if (libssh2_session_banner_set(session_, "SSH-2.0-Hajimi_native_1")) throw std::runtime_error("Cannot set SSH client identification");
    auto algorithms = hostAlgorithms(node_);
    if (!algorithms.empty() && libssh2_session_method_pref(session_, LIBSSH2_METHOD_HOSTKEY, algorithms.c_str()))
        throw std::runtime_error("Cannot configure SSH host-key algorithms");
}

void SSHConnectionSession::releaseNative() {
    if (session_) {
        int code;
        unsigned attempts = 0;
        do { code = libssh2_session_free(session_); } while (code == LIBSSH2_ERROR_EAGAIN && ++attempts < 8);
        session_ = nullptr;
    }
    if (descriptor_ >= 0) { ::close(descriptor_); descriptor_ = -1; }
}

LIBSSH2_SEND_FUNC(SSHConnectionSession::sendCallback) {
    (void)socket; (void)flags;
    auto self = static_cast<SSHConnectionSession *>(*abstract);
    if (self->closed_) return -EPIPE;
    if (!length) return 0;
    if (length > maximumQueuedBytes - self->outgoingBytes_ || self->outgoing_.size() >= 256) {
        self->wireOverflow_ = true; return -EPIPE;
    }
    const auto begin = static_cast<const uint8_t *>(buffer);
    try { self->outgoing_.emplace_back(begin, begin + length); }
    catch (const std::exception &) { self->wireOverflow_ = true; return -ENOMEM; }
    self->outgoingBytes_ += length;
    return ssize_t(length);
}

LIBSSH2_RECV_FUNC(SSHConnectionSession::receiveCallback) {
    (void)socket; (void)flags;
    auto self = static_cast<SSHConnectionSession *>(*abstract);
    if (self->closed_) return 0;
    if (self->incoming_.empty()) { self->needInbound_ = true; return self->carrierEOF_ ? 0 : -EAGAIN; }
    size_t count = std::min(length, self->incoming_.front().size() - self->incomingOffset_);
    std::memcpy(buffer, self->incoming_.front().data() + self->incomingOffset_, count);
    self->incomingOffset_ += count; self->incomingBytes_ -= count;
    if (self->incomingOffset_ == self->incoming_.front().size()) { self->incoming_.pop_front(); self->incomingOffset_ = 0; }
    return ssize_t(count);
}

LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(SSHConnectionSession::keyboardInteractiveCallback) {
    (void)name; (void)name_len; (void)instruction; (void)instruction_len; (void)prompts;
    auto self = static_cast<SSHConnectionSession *>(*abstract);
    if (!self || self->closed_ || num_prompts <= 0 || num_prompts > 16) return;
    for (int i = 0; i < num_prompts; ++i) {
        size_t len = self->password_.size();
        char *copy = static_cast<char *>(std::malloc(len + 1));
        if (!copy) return;
        if (len > 0) std::memcpy(copy, self->password_.data(), len);
        copy[len] = '\0';
        responses[i].text = copy;
        responses[i].length = static_cast<unsigned int>(len);
    }
}

void SSHConnectionSession::requestPump() {
    if (closed_ || pumpQueued_) return;
    pumpQueued_ = true;
    auto self = shared_from_this();
    post([self] { self->pumpQueued_ = false; self->pump(); });
}

bool SSHConnectionSession::stepSessionSetup() {
    int code = 0;
    switch (stage_) {
        case Stage::Idle:
        case Stage::Transport:
            return false;
        case Stage::Handshake:
            code = libssh2_session_handshake(session_, descriptor_);
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) { failSession("SSH key exchange failed (native code " + std::to_string(code) + ")"); return false; }
            stage_ = Stage::HostKey;
            return true;
        case Stage::HostKey: {
            size_t size = 0; int type = 0;
            const char *key = libssh2_session_hostkey(session_, &size, &type); (void)type;
            if (!key || !size || size > 16384) { failSession("SSH peer supplied an invalid host key"); return false; }
            bool matches = false;
            try { matches = ssh::hostKeyMatches(node_, Buffer(key, key + size)); }
            catch (const std::exception &failure) { failSession(failure.what()); return false; }
            if (!matches) { failSession("SSH host-key pin mismatch"); return false; }
            hostKeyVerified_ = true;
            stage_ = privateKey_.empty() ? Stage::Password : Stage::PublicKey;
            return true;
        }
        case Stage::PublicKey:
            code = libssh2_userauth_publickey_frommemory(session_, username_.data(), username_.size(), nullptr, 0,
                                                         privateKey_.data(), privateKey_.size(), passphrase_.c_str());
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) {
                if (!password_.empty()) { stage_ = Stage::Password; return true; }
                failSession("SSH private-key authentication failed (native code " + std::to_string(code) + ")");
                return false;
            }
            stage_ = Stage::Ready;
            password_.clear(); privateKey_.clear(); passphrase_.clear();
            return true;
        case Stage::Password:
            code = libssh2_userauth_password_ex(session_, username_.data(), unsigned(username_.size()), password_.data(),
                                                unsigned(password_.size()), nullptr);
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) {
                if (!password_.empty()) { stage_ = Stage::KeyboardInteractive; return true; }
                failSession("SSH password authentication failed (native code " + std::to_string(code) + ")");
                return false;
            }
            stage_ = Stage::Ready;
            password_.clear(); privateKey_.clear(); passphrase_.clear();
            return true;
        case Stage::KeyboardInteractive:
            code = libssh2_userauth_keyboard_interactive_ex(session_, username_.data(), unsigned(username_.size()),
                                                            &keyboardInteractiveCallback);
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) {
                failSession("SSH password authentication failed (native code " + std::to_string(code) + ")");
                return false;
            }
            stage_ = Stage::Ready;
            password_.clear(); privateKey_.clear(); passphrase_.clear();
            return true;
        case Stage::Ready:
            return false;
    }
    return false;
}

void SSHConnectionSession::pump() {
    if (closed_ || !session_) return;
    needInbound_ = false;
    unsigned steps = 0;
    for (; steps < 64 && !closed_; ++steps) {
        bool progress = false;
        if (stage_ != Stage::Ready) {
            progress = stepSessionSetup();
        } else {
            for (size_t i = 0; i < channels_.size() && !closed_; ++i) {
                if (auto ch = channels_[i].lock(); ch && !ch->isClosed()) {
                    progress = ch->stepChannel() || progress;
                }
            }
        }
        if (wireOverflow_ && !closed_) { failSession("SSH native wire queue exceeds its bound"); break; }
        if (!progress) break;
    }
    if (closed_) return;
    if (session_ && (libssh2_session_block_directions(session_) & LIBSSH2_SESSION_BLOCK_INBOUND) != 0) {
        needInbound_ = true;
    }
    flushWire();
    receiveWire();
    if (steps == 64) requestPump();
}

void SSHConnectionSession::flushWire() {
    if (closed_ || rawWriting_ || outgoing_.empty()) return;
    rawWriting_ = true;
    Buffer data = std::move(outgoing_.front());
    outgoing_.pop_front();
    while (!outgoing_.empty() && data.size() + outgoing_.front().size() <= 65536) {
        data.insert(data.end(), outgoing_.front().begin(), outgoing_.front().end());
        outgoing_.pop_front();
    }
    size_t count = data.size();
    auto self = shared_from_this();
    carrier_->write(std::move(data), [self, count](Error error) {
        self->post([self, count, error = std::move(error)]() mutable {
            if (self->closed_) return;
            self->rawWriting_ = false;
            self->outgoingBytes_ -= count;
            if (!error.empty()) { self->failSession("SSH TCP carrier write failed"); return; }
            self->requestPump();
        });
    });
}

void SSHConnectionSession::receiveWire() {
    if (closed_ || rawReading_ || !needInbound_ || carrierEOF_) return;
    if (incomingBytes_ >= maximumQueuedBytes) { failSession("SSH incoming wire queue exceeds its bound"); return; }
    rawReading_ = true;
    size_t maximum = std::min<size_t>(65536, maximumQueuedBytes - incomingBytes_);
    auto self = shared_from_this();
    carrier_->read(maximum, [self, maximum](Buffer data, bool eof, Error error) {
        self->post([self, maximum, data = std::move(data), eof, error = std::move(error)]() mutable {
            if (self->closed_) return;
            self->rawReading_ = false;
            if (!error.empty()) { self->failSession("SSH TCP carrier read failed"); return; }
            if (data.size() > maximum || data.size() > maximumQueuedBytes - self->incomingBytes_) {
                self->failSession("SSH carrier returned oversized input");
                return;
            }
            if (data.empty() && !eof) { self->failSession("SSH carrier read made no progress"); return; }
            self->incomingBytes_ += data.size();
            if (!data.empty()) self->incoming_.push_back(std::move(data));
            self->carrierEOF_ = eof;
            self->requestPump();
        });
    });
}

void SSHConnectionSession::failSession(Error error) {
    if (closed_) return;
    closed_ = true;
    terminal_ = std::move(error);
    auto activeChannels = std::move(channels_);
    channels_.clear();
    reservedSlots_ = 0;
    for (auto &weak : activeChannels) {
        if (auto ch = weak.lock()) ch->onSessionFailed(terminal_);
    }
    if (carrier_) { carrier_->close(); carrier_.reset(); }
    releaseNative();
    incoming_.clear(); outgoing_.clear();
    incomingBytes_ = incomingOffset_ = outgoingBytes_ = 0;
    privateKey_.clear(); password_.clear(); passphrase_.clear(); node_.parameters.clear();
}

class SSHSessionPool {
    std::mutex mutex_;
    std::map<std::string, std::vector<std::weak_ptr<SSHConnectionSession>>> pool_;

    static std::string makeKey(const Node &node, const std::string &privateKey, const TransportFactory *factory) {
        std::string authMaterial = node.option("username", node.option("user")) + "|" +
            node.option("password") + "|" + privateKey + "|" + node.option("private-key-passphrase") + "|" +
            node.option("host-key") + "|" + node.option("host-key-algorithms") + "|" +
            (node.flag("skip-cert-verify") ? "1" : "0");
        auto digest = crypto::digest("SHA256", Buffer(authMaterial.begin(), authMaterial.end()));
        return std::to_string(reinterpret_cast<uintptr_t>(factory)) + "|" +
               node.dialHost() + ":" + std::to_string(node.port) + "|" + crypto::base64Encode(digest);
    }

public:
    std::shared_ptr<SSHConnectionSession> acquire(const Node &node, std::string privateKey,
                                                  const std::shared_ptr<TransportFactory> &factory) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = makeKey(node, privateKey, factory.get());
        auto &bucket = pool_[key];
        for (auto it = bucket.begin(); it != bucket.end();) {
            auto session = it->lock();
            if (!session || session->isClosed()) {
                it = bucket.erase(it);
                continue;
            }
            if (session->canReserveChannel()) {
                session->reserveChannelSlot();
                return session;
            }
            ++it;
        }
        auto created = std::make_shared<SSHConnectionSession>(node, std::move(privateKey), factory);
        created->reserveChannelSlot();
        bucket.push_back(created);
        return created;
    }

    void resetForFactory(const std::shared_ptr<TransportFactory> &factory) {
        std::vector<std::shared_ptr<SSHConnectionSession>> active;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto poolIt = pool_.begin(); poolIt != pool_.end();) {
                auto &bucket = poolIt->second;
                for (auto it = bucket.begin(); it != bucket.end();) {
                    auto session = it->lock();
                    if (!session || session->isClosed()) {
                        it = bucket.erase(it);
                    } else if (session->ownedBy(factory)) {
                        active.push_back(std::move(session));
                        it = bucket.erase(it);
                    } else {
                        ++it;
                    }
                }
                if (bucket.empty()) poolIt = pool_.erase(poolIt);
                else ++poolIt;
            }
        }
        for (auto &s : active) s->reset();
    }

    void resetAll() {
        resetForFactory(nullptr);
    }
};

SSHSessionPool &globalSSHSessionPool() {
    static auto *const pool = new SSHSessionPool();
    return *pool;
}
} // namespace

void resetSSHClients() {
    globalSSHSessionPool().resetAll();
}

void resetSSHClient(const std::shared_ptr<TransportFactory> &factory) {
    globalSSHSessionPool().resetForFactory(factory);
}

Error validateSSH(const Node &node, bool udp) {
    if (udp) return "SSH direct-tcpip does not provide UDP relay";
    auto username = node.option("username", node.option("user"));
    if (username.empty()) return "SSH requires username";
    if (username.size() > 255 || username.find('\0') != std::string::npos) return "SSH username exceeds its bound or contains NUL";
    if (node.option("password").empty() && node.option("private-key").empty()) return "SSH requires password or private-key";
    if (node.option("password").size() > 65536 || node.option("private-key-passphrase").size() > 65536 ||
        node.option("private-key-passphrase").find('\0') != std::string::npos) return "SSH password or passphrase exceeds its bound";
    if (node.flag("tls")) return "SSH does not use an outer TLS transport";
    if (!node.option("security").empty() && node.option("security") != "none") return "SSH outer security transports are not implemented";
    if (node.option("network", "tcp") != "tcp") return "SSH requires TCP transport";
    if (node.flag("skip-common-name-verify") && !node.flag("skip-cert-verify")) return "SSH identity bypass requires explicit skip-cert-verify";
    for (const auto &key : {"certificate", "agent", "agent-path", "alpn", "client-fingerprint", "fingerprint", "ca-str", "ca"})
        if (!node.option(key).empty()) return "SSH option is not implemented: " + std::string(key);
    if (node.option("host-key-algorithms").size() > 4096) return "SSH host-key-algorithms exceeds its bound";
    try {
        if (pins(node).empty() && !node.flag("skip-cert-verify")) return "SSH requires host-key pin or explicit skip-cert-verify=true";
        (void)hostAlgorithms(node); validatePrivateKeyOption(node.option("private-key"));
    } catch (const std::exception &error) { return error.what(); }
    return {};
}

void connectSSH(const Node &node, const Target &target, std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    if (auto error = validateSSH(node, false); !error.empty()) { completion({}, std::move(error)); return; }
    if (!factory || !factory->tcp || !factory->post || !factory->after) { completion({}, "SSH platform transport is unavailable"); return; }
    if (target.host.empty() || target.host.size() > 255 || !target.port || target.host.find('\0') != std::string::npos) {
        completion({}, "Invalid SSH direct-tcpip destination"); return;
    }
    if (factory->cancelled && factory->cancelled()) {
        completion({}, "SSH connection cancelled");
        return;
    }
    factory->post([node, target, factory, completion = std::move(completion)]() mutable {
        if (factory->cancelled && factory->cancelled()) {
            completion({}, "SSH connection cancelled");
            return;
        }
        std::string loadedKey;
        try {
            loadedKey = loadPrivateKey(node.option("private-key"));
        } catch (const std::exception &error) {
            completion({}, error.what());
            return;
        }
        if (factory->cancelled && factory->cancelled()) {
            completion({}, "SSH connection cancelled");
            return;
        }
        auto session = globalSSHSessionPool().acquire(node, std::move(loadedKey), factory);
        std::make_shared<SSHChannelStream>( std::move(session), target, factory, std::move(completion) )->start();
    });
}

bool sshSessionPoolSelfTest() {
    try {
        Node node;
        node.type = "ssh";
        node.host = "192.0.2.10";
        node.port = 22;
        node.parameters["username"] = "pool-user";
        node.parameters["password"] = "pool-pass";
        node.parameters["host-key"] = "[ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaAzGBPULXLmLDph0UFoOO0D3s87CoIWQgIqNFwGuvy]";
        node.parameters["host-key-algorithms"] = "[ssh-ed25519]";
        if (!validateSSH(node, false).empty()) return false;

        Node missingPin = node;
        missingPin.parameters.erase("host-key");
        if (validateSSH(missingPin, false).empty()) return false;

        // Verify SSHSessionPool multiplexes 100 concurrent channels across <= 2 SSH sessions (64 channels/session cap).
        auto factory = std::make_shared<TransportFactory>();
        size_t tcpDials = 0;
        std::vector<std::shared_ptr<SSHConnectionSession>> heldSessions;
        for (int i = 0; i < 100; ++i) {
            auto s = globalSSHSessionPool().acquire(node, {}, factory);
            if (std::find(heldSessions.begin(), heldSessions.end(), s) == heldSessions.end()) {
                heldSessions.push_back(s);
                ++tcpDials;
            }
        }
        bool ok = (tcpDials == 2 && heldSessions.size() == 2);
        heldSessions.clear();
        globalSSHSessionPool().resetAll();
        if (!ok) return false;

        // Verify SSHChannelStream stays alive across async transport dial (regression test for premature destructor).
        auto asyncFactory = std::make_shared<TransportFactory>();
        asyncFactory->post = [](std::function<void()> fn) { if (fn) fn(); };
        asyncFactory->after = [](double, std::function<void()>) {};
        StreamCallback savedTcpCb;
        asyncFactory->tcp = [&savedTcpCb](const Node &, const TLSOptions &, StreamCallback cb) {
            savedTcpCb = std::move(cb);
        };
        bool prematureClose = false;
        Error receivedError;
        connectSSH(node, Target{"example.com", 443, false}, asyncFactory, [&](std::shared_ptr<Stream>, Error err) {
            prematureClose = true;
            receivedError = std::move(err);
        });
        // While TCP dial is still pending, completion must NOT have fired with "SSH stream closed".
        if (prematureClose || !savedTcpCb) {
            globalSSHSessionPool().resetAll();
            return false;
        }
        savedTcpCb({}, "simulated dial failure");
        globalSSHSessionPool().resetAll();
        return prematureClose && receivedError.find("SSH stream closed") == std::string::npos;
    } catch (const std::exception &) {
        return false;
    }
}

} // namespace hajimi
