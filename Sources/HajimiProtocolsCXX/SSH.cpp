// SSH transport/authentication is supplied by the locally built, pinned C
// libssh2 library. This C++ adapter owns async I/O, host identity validation,
// bounded buffering, direct-tcpip framing, cancellation, and half-close.
#include "SSH.hpp"
#include "Crypto.hpp"
#include <libssh2.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace hajimi {
namespace {
constexpr size_t maximumSSHKeyBytes = 256 * 1024;
std::string trim(std::string text) {
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
struct HostPin { bool fingerprint; Buffer value; };
uint32_t sshWord(const uint8_t *bytes) {
    return uint32_t(bytes[0]) << 24 | uint32_t(bytes[1]) << 16 | uint32_t(bytes[2]) << 8 | bytes[3];
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
            result.push_back({true, std::move(value)}); continue;
        }
        std::istringstream input(pin); std::string type, encoded; input >> type >> encoded;
        if (type.empty() || encoded.empty()) throw std::runtime_error("SSH host-key must be SHA256 pin or authorized-key text");
        Buffer value;
        try { value = crypto::base64Decode(encoded); }
        catch (const std::exception &) { throw std::runtime_error("Invalid SSH authorized host-key encoding"); }
        if (value.size() < 8 || value.size() > 16384 || sshWord(value.data()) > value.size() - 4 ||
            std::string(value.begin() + 4, value.begin() + 4 + sshWord(value.data())) != type)
            throw std::runtime_error("Invalid SSH authorized host-key wire type");
        result.push_back({false, std::move(value)});
    }
    return result;
}
void initializeSSH() {
    static std::once_flag once; static int status = -1;
    std::call_once(once, [] { status = libssh2_init(0); });
    if (status) throw std::runtime_error("Cannot initialize native SSH crypto");
}
std::string hostAlgorithms(const Node &node) {
    auto algorithms = list(node.option("host-key-algorithms"), true); if (algorithms.empty()) return {};
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
    for (const auto &algorithm : algorithms) {
        if (!available.count(algorithm)) throw std::runtime_error("Requested SSH host-key algorithm is unavailable in native libssh2");
        if (!result.empty()) result += ','; result += algorithm;
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
        // UI support checks never reach this path. Precheck the file kind, then
        // validate the opened descriptor as well to close the replacement race.
        // O_NONBLOCK prevents a swapped FIFO from blocking before fstat().
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
class SSHStream final : public Stream, public std::enable_shared_from_this<SSHStream> {
public:
    SSHStream(Node node, Target target, std::shared_ptr<TransportFactory> factory, StreamCallback completion)
        : node_(std::move(node)), target_(std::move(target)), factory_(std::move(factory)), completion_(std::move(completion)) {}
    ~SSHStream() override { closed_ = true; if (carrier_) carrier_->close(); releaseNative(); }
    void start();
    void write(Buffer, WriteCallback) override;
    void read(size_t, ReadCallback) override;
    void close() override;
    void shutdownWrite(WriteCallback) override;
    bool supportsHalfClose() const override { return true; }
private:
    enum class Stage { Transport, Handshake, HostKey, PublicKey, Password, Channel, Ready };
    struct PendingWrite { Buffer data; size_t offset = 0; bool end = false, endSent = false; WriteCallback completion; };
    Node node_;
    Target target_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Stream> carrier_;
    StreamCallback completion_;
    LIBSSH2_SESSION *session_ = nullptr;
    LIBSSH2_CHANNEL *channel_ = nullptr;
    int descriptor_ = -1;
    Stage stage_ = Stage::Transport;
    std::string username_, password_, privateKey_, passphrase_;
    Buffer channelRequest_, readBuffer_;
    std::deque<Buffer> incoming_, outgoing_;
    size_t incomingBytes_ = 0, incomingOffset_ = 0, outgoingBytes_ = 0, queuedApplication_ = 0;
    std::deque<PendingWrite> writes_;
    ReadCallback pendingRead_;
    bool closed_ = false, pumpQueued_ = false, rawReading_ = false, rawWriting_ = false, needInbound_ = false;
    bool carrierEOF_ = false, readEOF_ = false, writeClosing_ = false, wireOverflow_ = false;
    Error terminal_;
    void post(std::function<void()> work) { factory_->post(std::move(work)); }
    void initializeNative();
    void releaseNative();
    void requestPump();
    void pump();
    bool stepSetup();
    bool stepWrite();
    bool stepRead();
    void flushWire();
    void receiveWire();
    void fail(Error);
    void enqueue(Buffer, bool, WriteCallback);
    static LIBSSH2_SEND_FUNC(sendCallback);
    static LIBSSH2_RECV_FUNC(receiveCallback);
};
void SSHStream::start() {
    auto self = shared_from_this();
    factory_->after(12, [weak = std::weak_ptr<SSHStream>(self)] {
        if (auto pending = weak.lock(); pending && pending->completion_) pending->fail("SSH handshake timed out");
    });
    // Disk I/O belongs to the asynchronous dial strand, never validateSSH()
    // (which is also used for UI rendering). Reject unusable files before any
    // TCP dial and avoid opening a remote connection just to discover a typo.
    if (factory_->cancelled && factory_->cancelled()) { fail("SSH connection cancelled"); return; }
    try { privateKey_ = loadPrivateKey(node_.option("private-key")); }
    catch (const std::exception &error) { fail(error.what()); return; }
    if (factory_->cancelled && factory_->cancelled()) { fail("SSH connection cancelled"); return; }
    factory_->tcp(node_, {}, [self](std::shared_ptr<Stream> raw, Error error) {
        self->post([self, raw = std::move(raw), error = std::move(error)]() mutable {
            if (self->closed_) { if (raw) raw->close(); return; }
            if (!error.empty() || !raw) { self->fail(error.empty() ? "SSH TCP transport failed" : std::move(error)); return; }
            self->carrier_ = std::move(raw);
            try { self->initializeNative(); }
            catch (const std::exception &failure) { self->fail(failure.what()); return; }
            self->stage_ = Stage::Handshake; self->requestPump();
        });
    });
}
void SSHStream::initializeNative() {
    initializeSSH(); username_ = node_.option("username", node_.option("user")); password_ = node_.option("password");
    passphrase_ = node_.option("private-key-passphrase");
    channelRequest_ = directRequest(target_);
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
void SSHStream::releaseNative() {
    if (session_) {
        // SEND never returns EAGAIN: outer pumping applies backpressure before
        // packet construction, so abort cannot strand a partial outgoing packet.
        // Closed callbacks return hard errors, allowing libssh2 to free channels
        // without waiting for the now-closed peer's close acknowledgement.
        int code;
        unsigned attempts = 0;
        do { code = libssh2_session_free(session_); } while (code == LIBSSH2_ERROR_EAGAIN && ++attempts < 8);
        session_ = nullptr; channel_ = nullptr;
    }
    if (descriptor_ >= 0) { ::close(descriptor_); descriptor_ = -1; }
}
LIBSSH2_SEND_FUNC(SSHStream::sendCallback) {
    (void)socket; (void)flags;
    auto self = static_cast<SSHStream *>(*abstract);
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
LIBSSH2_RECV_FUNC(SSHStream::receiveCallback) {
    (void)socket; (void)flags;
    auto self = static_cast<SSHStream *>(*abstract);
    if (self->closed_) return 0;
    if (self->incoming_.empty()) { self->needInbound_ = true; return self->carrierEOF_ ? 0 : -EAGAIN; }
    size_t count = std::min(length, self->incoming_.front().size() - self->incomingOffset_);
    std::memcpy(buffer, self->incoming_.front().data() + self->incomingOffset_, count);
    self->incomingOffset_ += count; self->incomingBytes_ -= count;
    if (self->incomingOffset_ == self->incoming_.front().size()) { self->incoming_.pop_front(); self->incomingOffset_ = 0; }
    return ssize_t(count);
}
void SSHStream::requestPump() {
    if (closed_ || pumpQueued_) return;
    pumpQueued_ = true;
    auto self = shared_from_this(); post([self] { self->pumpQueued_ = false; self->pump(); });
}
bool SSHStream::stepSetup() {
    int code = 0;
    switch (stage_) {
        case Stage::Transport: return false;
        case Stage::Handshake:
            code = libssh2_session_handshake(session_, descriptor_);
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) { fail("SSH key exchange failed (native code " + std::to_string(code) + ")"); return false; }
            stage_ = Stage::HostKey; return true;
        case Stage::HostKey: {
            size_t size = 0; int type = 0; const char *key = libssh2_session_hostkey(session_, &size, &type); (void)type;
            if (!key || !size || size > 16384) { fail("SSH peer supplied an invalid host key"); return false; }
            bool matches;
            try { matches = ssh::hostKeyMatches(node_, Buffer(key, key + size)); }
            catch (const std::exception &failure) { fail(failure.what()); return false; }
            if (!matches) { fail("SSH host-key pin mismatch"); return false; }
            stage_ = privateKey_.empty() ? Stage::Password : Stage::PublicKey; return true;
        }
        case Stage::PublicKey:
            code = libssh2_userauth_publickey_frommemory(session_, username_.data(), username_.size(), nullptr, 0,
                                                       privateKey_.data(), privateKey_.size(), passphrase_.c_str());
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) {
                if (!password_.empty()) { stage_ = Stage::Password; return true; }
                fail("SSH private-key authentication failed (native code " + std::to_string(code) + ")"); return false;
            }
            stage_ = Stage::Channel; return true;
        case Stage::Password:
            code = libssh2_userauth_password_ex(session_, username_.data(), unsigned(username_.size()), password_.data(),
                                              unsigned(password_.size()), nullptr);
            if (code == LIBSSH2_ERROR_EAGAIN) return false;
            if (code) { fail("SSH password authentication failed (native code " + std::to_string(code) + ")"); return false; }
            stage_ = Stage::Channel; return true;
        case Stage::Channel:
            channel_ = libssh2_channel_open_ex(session_, "direct-tcpip", 12, 256 * 1024, 32768,
                                              reinterpret_cast<const char *>(channelRequest_.data()), unsigned(channelRequest_.size()));
            if (!channel_) {
                code = libssh2_session_last_errno(session_); if (code == LIBSSH2_ERROR_EAGAIN) return false;
                fail("SSH direct-tcpip request failed (native code " + std::to_string(code) + ")"); return false;
            }
            stage_ = Stage::Ready;
            password_.clear(); privateKey_.clear(); passphrase_.clear(); node_.parameters.clear(); channelRequest_.clear();
            if (auto callback = std::exchange(completion_, {})) callback(shared_from_this(), {});
            return true;
        case Stage::Ready: return false;
    }
    return false;
}
bool SSHStream::stepWrite() {
    if (writes_.empty()) return false;
    auto &pending = writes_.front();
    if ((!pending.end && pending.offset == pending.data.size()) || pending.endSent) {
        if (rawWriting_ || !outgoing_.empty()) return false;
        queuedApplication_ -= pending.data.size(); auto callback = std::exchange(pending.completion, {}); writes_.pop_front(); callback({}); return true;
    }
    // Keep only a few native channel packets awaiting platform send completion.
    if (outgoingBytes_ >= 64 * 1024) return false;
    if (pending.end) {
        int code = libssh2_channel_send_eof(channel_);
        if (code == LIBSSH2_ERROR_EAGAIN) return false;
        if (code) { fail("SSH write half-close failed (native code " + std::to_string(code) + ")"); return false; }
        pending.endSent = true; return true;
    }
    size_t count = std::min<size_t>(16384, pending.data.size() - pending.offset);
    ssize_t code = libssh2_channel_write_ex(channel_, 0, reinterpret_cast<const char *>(pending.data.data() + pending.offset), count);
    if (code == LIBSSH2_ERROR_EAGAIN || !code) return false;
    if (code < 0) { fail("SSH channel write failed (native code " + std::to_string(code) + ")"); return false; }
    if (size_t(code) > count) { fail("SSH library returned an invalid write length"); return false; }
    pending.offset += size_t(code); return true;
}
bool SSHStream::stepRead() {
    if (!pendingRead_) return false;
    if (readEOF_) { auto callback = std::exchange(pendingRead_, {}); readBuffer_.clear(); callback({}, true, {}); return true; }
    ssize_t code = libssh2_channel_read_ex(channel_, 0, reinterpret_cast<char *>(readBuffer_.data()), readBuffer_.size());
    if (code == LIBSSH2_ERROR_EAGAIN) return false;
    if (code < 0) { fail("SSH channel read failed (native code " + std::to_string(code) + ")"); return false; }
    readEOF_ = libssh2_channel_eof(channel_) != 0;
    if (!code && !readEOF_) { needInbound_ = true; return false; }
    if (size_t(code) > readBuffer_.size()) { fail("SSH library returned an invalid read length"); return false; }
    readBuffer_.resize(size_t(code)); auto data = std::move(readBuffer_); readBuffer_.clear();
    auto callback = std::exchange(pendingRead_, {}); callback(std::move(data), readEOF_, {}); return true;
}
void SSHStream::pump() {
    if (closed_ || !session_) return;
    needInbound_ = false;
    unsigned steps = 0;
    for (; steps < 32 && !closed_; ++steps) {
        bool progress;
        if (stage_ != Stage::Ready) progress = stepSetup();
        else { progress = stepWrite(); if (!closed_) progress = stepRead() || progress; }
        if (wireOverflow_ && !closed_) { fail("SSH native wire queue exceeds its bound"); break; }
        if (!progress) break;
    }
    if (closed_) return;
    flushWire(); receiveWire();
    if (steps == 32) requestPump();
}
void SSHStream::flushWire() {
    if (closed_ || rawWriting_ || outgoing_.empty()) return;
    rawWriting_ = true; auto data = std::move(outgoing_.front()); outgoing_.pop_front(); size_t count = data.size();
    auto self = shared_from_this();
    carrier_->write(std::move(data), [self, count](Error error) {
        self->post([self, count, error = std::move(error)]() mutable {
            if (self->closed_) return;
            self->rawWriting_ = false; self->outgoingBytes_ -= count;
            if (!error.empty()) { self->fail("SSH TCP carrier write failed"); return; }
            self->requestPump();
        });
    });
}
void SSHStream::receiveWire() {
    if (closed_ || rawReading_ || !needInbound_ || carrierEOF_) return;
    if (incomingBytes_ >= maximumQueuedBytes) { fail("SSH incoming wire queue exceeds its bound"); return; }
    rawReading_ = true; size_t maximum = std::min<size_t>(65536, maximumQueuedBytes - incomingBytes_);
    auto self = shared_from_this();
    carrier_->read(maximum, [self, maximum](Buffer data, bool eof, Error error) {
        self->post([self, maximum, data = std::move(data), eof, error = std::move(error)]() mutable {
            if (self->closed_) return;
            self->rawReading_ = false;
            if (!error.empty()) { self->fail("SSH TCP carrier read failed"); return; }
            if (data.size() > maximum || data.size() > maximumQueuedBytes - self->incomingBytes_) { self->fail("SSH carrier returned oversized input"); return; }
            if (data.empty() && !eof) { self->fail("SSH carrier read made no progress"); return; }
            self->incomingBytes_ += data.size();
            if (!data.empty()) self->incoming_.push_back(std::move(data));
            self->carrierEOF_ = eof; self->requestPump();
        });
    });
}
void SSHStream::enqueue(Buffer data, bool end, WriteCallback completion) {
    if (closed_ || stage_ != Stage::Ready || writeClosing_) { completion(terminal_.empty() ? "SSH write side closed" : terminal_); return; }
    if (data.size() > maximumQueuedBytes - queuedApplication_ || writes_.size() >= 256) { completion("SSH application write queue exceeds its bound"); return; }
    if (data.empty() && !end) { completion({}); return; }
    if (end) writeClosing_ = true;
    queuedApplication_ += data.size(); writes_.push_back({std::move(data), 0, end, false, std::move(completion)}); requestPump();
}
void SSHStream::write(Buffer data, WriteCallback completion) {
    auto self = shared_from_this();
    post([self, data = std::move(data), completion = std::move(completion)]() mutable { self->enqueue(std::move(data), false, std::move(completion)); });
}
void SSHStream::shutdownWrite(WriteCallback completion) {
    auto self = shared_from_this(); post([self, completion = std::move(completion)]() mutable { self->enqueue({}, true, std::move(completion)); });
}
void SSHStream::read(size_t maximum, ReadCallback completion) {
    auto self = shared_from_this();
    post([self, maximum, completion = std::move(completion)]() mutable {
        if (self->closed_) { completion({}, true, self->terminal_); return; }
        if (self->stage_ != Stage::Ready) { completion({}, false, "SSH session is not ready"); return; }
        if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid SSH read bound"); return; }
        if (self->pendingRead_) { completion({}, false, "An SSH channel read is already pending"); return; }
        self->readBuffer_.resize(maximum); self->pendingRead_ = std::move(completion); self->requestPump();
    });
}
void SSHStream::fail(Error error) {
    if (closed_) return;
    closed_ = true; terminal_ = std::move(error);
    if (carrier_) carrier_->close(); releaseNative();
    auto completion = std::exchange(completion_, {});
    auto read = std::exchange(pendingRead_, {}); auto writes = std::move(writes_); writes_.clear();
    incoming_.clear(); outgoing_.clear(); readBuffer_.clear(); incomingBytes_ = outgoingBytes_ = queuedApplication_ = 0;
    privateKey_.clear(); password_.clear(); passphrase_.clear(); node_.parameters.clear();
    if (completion) completion({}, terminal_);
    for (auto &pending : writes) if (auto callback = std::exchange(pending.completion, {})) callback(terminal_);
    if (read) read({}, true, terminal_);
}
void SSHStream::close() {
    auto self = shared_from_this(); post([self] { self->fail("SSH stream closed"); });
}
} // namespace

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
    for (const auto &key : {"dialer-proxy", "underlying-proxy", "certificate", "agent", "agent-path", "alpn", "client-fingerprint", "fingerprint", "ca-str", "ca"})
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
    factory->post([node, target, factory, completion = std::move(completion)]() mutable {
        std::make_shared<SSHStream>(node, target, factory, std::move(completion))->start();
    });
}
} // namespace hajimi
