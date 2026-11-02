#pragma once
#include "Runtime.hpp"

namespace hajimi::quic {
// Every ngtcp2 call is confined to the connection's C++ reactor. Application
// callbacks are delivered to TransportFactory::post, never from TLS callbacks.
class Connection : public std::enable_shared_from_this<Connection> {
public:
    using Ready = std::function<void(std::shared_ptr<Connection>, Error)>;
    static void connect(Node, std::shared_ptr<TransportFactory>, Ready);
    ~Connection();
    void open(bool unidirectional, StreamCallback);
    void sendDatagrams(std::vector<Buffer>, WriteCallback);
    void receiveDatagrams(std::function<void(Buffer)>, WriteCallback);
    void receivePeerStreams(std::function<void(std::shared_ptr<Stream>)>);
    void exportKey(Buffer label, Buffer context, std::function<void(Buffer, Error)>);
    void authenticated();
    void close();
    bool isClosed() const;
    size_t datagramLimit() const;
private:
#if defined(HAJIMI_QUIC_BOUNDARY_TESTS)
    friend struct BoundaryChecks;
#endif
    struct Impl;
    explicit Connection(Node, std::shared_ptr<TransportFactory>);
    std::unique_ptr<Impl> impl_;
};

// An application stream owns its QUIC connection, whereas control/auth
// streams only close their individual stream.
class OwnedStream final : public Stream {
public:
    OwnedStream(std::shared_ptr<Connection>, std::shared_ptr<Stream>,
                std::shared_ptr<Reader> = {});
    ~OwnedStream() override;
    void write(Buffer, WriteCallback) override;
    void read(size_t, ReadCallback) override;
    void shutdownWrite(WriteCallback) override;
    bool supportsHalfClose() const override { return true; }
    void close() override;
private:
    std::shared_ptr<Connection> connection_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
};
} // namespace hajimi::quic
