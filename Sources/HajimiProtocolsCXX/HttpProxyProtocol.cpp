#include "HttpProxyProtocol.hpp"
#include "Crypto.hpp"
#include "ProtocolStream.hpp"
#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace hajimi {

namespace {

std::string authority(const Target &target) {
    if (target.host.empty() || target.host.find_first_of("\r\n\t ") != std::string::npos || target.host.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid HTTP CONNECT target");
    std::string host = target.host;
    if (host.find(':') != std::string::npos && host.front() != '[') host = "[" + host + "]";
    return host + ":" + std::to_string(target.port);
}

} // namespace

void connectHttpProxyProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<Stream> source,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion) {
    if (target.plainHTTP) {
        completion(std::make_shared<BufferedStream>(source, std::make_shared<Reader>(source)), {});
        return;
    }
    auto destination = authority(target);
    std::string request;
    request.reserve(128 + destination.size() * 2);
    request += "CONNECT ";
    request += destination;
    request += " HTTP/1.1\r\nHost: ";
    request += destination;
    request += "\r\nProxy-Connection: Keep-Alive\r\n";
    if (!node.option("username").empty()) {
        request += "Proxy-Authorization: Basic ";
        request += crypto::base64Encode(bytes(node.option("username") + ":" + node.option("password")));
        request += "\r\n";
    }
    request += "\r\n";

    auto reader = std::make_shared<Reader>(source);
    auto callback = std::make_shared<StreamCallback>(std::move(completion));
    auto finish = [callback](std::shared_ptr<Stream> stream, Error error) {
        auto complete = std::exchange(*callback, {});
        if (complete) complete(std::move(stream), std::move(error));
    };
    if (factory && factory->after) {
        std::weak_ptr<StreamCallback> weak = callback;
        std::weak_ptr<Stream> transport = source;
        factory->after(15, [weak, transport] {
            if (auto cb = weak.lock()) {
                if (*cb) {
                    if (auto s = transport.lock()) s->close();
                    auto complete = std::exchange(*cb, {});
                    complete(nullptr, "HTTP CONNECT handshake timed out");
                }
            }
        });
    }
    source->write(bytes(request), [source, reader, callback, finish](Error error) mutable {
        if (!error.empty()) {
            source->close();
            finish(nullptr, error);
            return;
        }
        reader->until({'\r', '\n', '\r', '\n'}, 65536, [source, reader, callback, finish](Buffer header, Error error) mutable {
            if (!*callback) return;
            if (!error.empty()) {
                source->close();
                finish(nullptr, error);
                return;
            }
            auto end = std::find(header.begin(), header.end(), '\r');
            std::string line(header.begin(), end);
            auto space = line.find(' ');
            bool version = line.compare(0, 9, "HTTP/1.1 ") == 0 || line.compare(0, 9, "HTTP/1.0 ") == 0;
            bool status = space != std::string::npos && line.size() >= space + 4 && line[space + 1] == '2'
                && std::isdigit(static_cast<unsigned char>(line[space + 2]))
                && std::isdigit(static_cast<unsigned char>(line[space + 3]))
                && (line.size() == space + 4 || line[space + 4] == ' ');
            if (!version || !status) {
                source->close();
                finish(nullptr, "HTTP CONNECT rejected");
                return;
            }
            finish(std::make_shared<BufferedStream>(source, reader), {});
        });
    });
}

} // namespace hajimi
