#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <cctype>

namespace hajimi {
using Buffer = std::vector<uint8_t>;
using Error = std::string; // Empty means success; never carries credentials.
using WriteCallback = std::function<void(Error)>;
using ReadCallback = std::function<void(Buffer, bool, Error)>;
struct Target {
    std::string host;
    uint16_t port = 0;
    bool udp = false;
    bool plainHTTP = false;
};
struct Node {
    std::string type, name, host, interfaceName;
    uint16_t port = 0;
    std::unordered_map<std::string, std::string> parameters;
    std::string option(const std::string &key, const std::string &fallback = "") const {
        auto found = parameters.find(key);
        return found == parameters.end() ? fallback : found->second;
    }
    bool flag(const std::string &key, bool fallback = false) const {
        auto value = option(key);
        if (value.empty()) return fallback;
        std::string normalized;
        for (auto ch : value) if (!std::isspace(static_cast<unsigned char>(ch))) normalized.push_back(char(std::tolower(static_cast<unsigned char>(ch))));
        value = std::move(normalized);
        return value == "1" || value == "true" || value == "yes" || value == "on";
    }
};
class Stream {
public:
    // Internal protocol API: invoke through the serialized factory strand and
    // a bounded admission boundary. The exported Objective-C++ bridge reserves
    // bytes/requests before dispatch, not after a caller can flood post().
    virtual ~Stream() = default;
    virtual void write(Buffer data, WriteCallback completion) = 0;
    virtual void read(size_t maximum, ReadCallback completion) = 0;
    virtual void close() = 0;
    virtual void shutdownWrite(WriteCallback completion) { completion("Protocol does not support write half-close"); }
    virtual bool supportsHalfClose() const { return false; }
    // Optional raw-carrier handoff for XTLS Vision. The C++ VLESS engine,
    // not the platform bridge, decides when a validated frame switches mode.
    virtual bool supportsVisionDirect() const { return false; }
    virtual void enableVisionDirectWrite() {}
    virtual void enableVisionDirectRead() {}
};
using StreamCallback = std::function<void(std::shared_ptr<Stream>, Error)>;
using PacketCallback = std::function<void(Target, Buffer)>;
class Datagram {
public:
    virtual ~Datagram() = default;
    virtual void send(Target target, Buffer data, WriteCallback completion) = 0;
    virtual void start(PacketCallback receive, WriteCallback failure) = 0;
    virtual void close() = 0;
};
using DatagramCallback = std::function<void(std::shared_ptr<Datagram>, Error)>;
struct TLSOptions {
    bool enabled = false, skipVerify = false;
    std::string serverName;
    std::vector<std::string> alpn;
};
/// Platform I/O only. Protocol framing, authentication, crypto and sessions
/// must stay in .cpp code, not in the Swift/Objective-C adapters.
struct TransportFactory {
    std::function<void(const Node &, const TLSOptions &, StreamCallback)> tcp;
    std::function<void(const Node &, DatagramCallback)> udp;
    std::function<void(std::function<void()>)> post;
    std::function<void(double, std::function<void()>)> after;
    // Cross-thread, fail-closed runtime shutdown signal (empty means false).
    // post/after still deliver cleanup work after this signal becomes true.
    std::function<bool()> cancelled;
};
constexpr size_t maximumQueuedBytes = 2 * 1024 * 1024;
constexpr size_t maximumReadBytes = 512 * 1024;

void connectProtocol(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeProtocolDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
Error validateProtocol(const Node &, bool udp);
Error validateShadowsocks(const Node &, bool udp);

void connectShadowsocks(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeShadowsocksDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
void connectAnyTLS(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeAnyTLSDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
void connectQUICProtocol(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeQUICDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
Error validateQUICProtocol(const Node &, bool udp);
void connectSnell(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);
void makeSnellDatagram(const Node &, std::shared_ptr<TransportFactory>, DatagramCallback);
void connectSSH(const Node &, const Target &, std::shared_ptr<TransportFactory>, StreamCallback);

/// Bounded buffered stream parser, shared by handshake and frame engines.
/// Its implementation preserves pending bytes and serializes raw reads.
class Reader : public std::enable_shared_from_this<Reader> {
public:
    explicit Reader(std::shared_ptr<Stream> source, size_t limit = maximumQueuedBytes);
    void exactly(size_t count, std::function<void(Buffer, Error)>);
    void until(Buffer marker, size_t limit, std::function<void(Buffer, Error)>);
    void some(size_t maximum, ReadCallback);
    Buffer take();
    void close();
private:
    std::shared_ptr<Stream> source_;
    Buffer buffer_;
    size_t limit_, readOffset_ = 0;
    bool eof_ = false, reading_ = false, closed_ = false;
    Error terminal_;
    size_t buffered() const;
    void compact(bool force = false);
    Buffer consume(size_t count);
    void untilFrom(Buffer marker, size_t limit, size_t scanned, std::function<void(Buffer, Error)>);
    void more(std::function<void(Error)>);
};
Buffer socksAddress(const Target &);
Target parseSocksAddress(const Buffer &, size_t &consumed);
uint64_t unixSeconds();
TLSOptions tlsOptions(const Node &, bool defaultTLS = false);
} // namespace hajimi
