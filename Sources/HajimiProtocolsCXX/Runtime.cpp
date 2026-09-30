#include "Runtime.hpp"
#include "BasicProtocols.hpp"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <stdexcept>

namespace hajimi {
Reader::Reader(std::shared_ptr<Stream> source, size_t limit)
    : source_(std::move(source)), limit_(std::min(limit, maximumQueuedBytes)) {
    if (!source_ || !limit_) throw std::invalid_argument("Invalid buffered stream");
}
size_t Reader::buffered() const { return buffer_.size() - readOffset_; }
void Reader::compact(bool force) {
    if (!readOffset_) return;
    if (readOffset_ == buffer_.size()) {
        buffer_.clear(); readOffset_ = 0;
    } else if (force || (readOffset_ >= 65536 && readOffset_ >= buffer_.size() / 2)) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + readOffset_); readOffset_ = 0;
    }
}
Buffer Reader::consume(size_t count) {
    auto first = buffer_.begin() + readOffset_;
    Buffer result(first, first + count);
    readOffset_ += count; compact();
    return result;
}
void Reader::more(std::function<void(Error)> completion) {
    if (closed_) { completion("Stream closed"); return; }
    if (reading_) { completion("Concurrent stream read"); return; }
    if (!terminal_.empty()) { completion(terminal_); return; }
    if (eof_) { completion("EOF"); return; }
    if (buffered() >= limit_) { completion("Stream buffer limit exceeded"); return; }
    reading_ = true;
    auto self = shared_from_this();
    const size_t requested = std::min<size_t>(65536, limit_ - buffered());
    source_->read(requested, [self, requested, completion = std::move(completion)](Buffer data, bool eof, Error error) mutable {
        self->reading_ = false;
        if (self->closed_) { completion("Stream closed"); return; }
        if (data.size() > requested || data.size() > self->limit_ - self->buffered()) {
            self->terminal_ = "Transport read exceeded buffer limit";
            self->source_->close(); completion(self->terminal_); return;
        }
        // Dead headroom must not consume the logical receive budget, nor let
        // the physical vector grow beyond the configured limit. Compact only
        // when an actual append needs room (or consume() reaches its threshold).
        if (data.size() > self->limit_ - self->buffer_.size()) self->compact(true);
        size_t required = self->buffer_.size() + data.size();
        if (required > self->buffer_.capacity())
            self->buffer_.reserve(std::min(self->limit_, std::max(required, self->buffer_.capacity() * 2)));
        self->buffer_.insert(self->buffer_.end(), data.begin(), data.end());
        self->eof_ = eof;
        if (!error.empty()) self->terminal_ = std::move(error);
        else if (data.empty() && !eof) self->terminal_ = "Transport returned an empty read";
        completion(self->terminal_);
    });
}
void Reader::exactly(size_t count, std::function<void(Buffer, Error)> completion) {
    if (closed_) { completion({}, "Stream closed"); return; }
    if (reading_) { completion({}, "Concurrent stream read"); return; }
    if (count > limit_) { completion({}, "Stream read limit exceeded"); return; }
    if (buffered() >= count) {
        completion(consume(count), {}); return;
    }
    if (!terminal_.empty()) { completion({}, terminal_); return; }
    if (eof_) { completion({}, buffered() ? "Truncated stream" : "EOF"); return; }
    auto self = shared_from_this();
    more([self, count, completion = std::move(completion)](Error) mutable {
        self->exactly(count, std::move(completion));
    });
}
void Reader::until(Buffer marker, size_t limit, std::function<void(Buffer, Error)> completion) {
    untilFrom(std::move(marker), limit, 0, std::move(completion));
}
void Reader::untilFrom(Buffer marker, size_t limit, size_t scanned, std::function<void(Buffer, Error)> completion) {
    if (closed_) { completion({}, "Stream closed"); return; }
    if (reading_) { completion({}, "Concurrent stream read"); return; }
    if (marker.empty() || !limit || limit > limit_) { completion({}, "Invalid stream delimiter limit"); return; }
    auto first = buffer_.begin() + readOffset_;
    auto found = std::search(first + std::min(scanned, buffered()), buffer_.end(), marker.begin(), marker.end());
    if (found != buffer_.end()) {
        size_t length = size_t(found - first) + marker.size();
        if (length > limit) { completion({}, "Stream header limit exceeded"); return; }
        completion(consume(length), {}); return;
    }
    if (buffered() >= limit) { completion({}, "Stream header limit exceeded"); return; }
    if (!terminal_.empty()) { completion({}, terminal_); return; }
    if (eof_) { completion({}, buffered() ? "Truncated stream" : "EOF"); return; }
    // Only the old suffix can begin a delimiter spanning the next raw read.
    // This is relative to unread bytes, so forced compaction preserves it.
    size_t next = buffered() >= marker.size() ? buffered() - marker.size() + 1 : 0;
    auto self = shared_from_this();
    more([self, marker = std::move(marker), limit, next, completion = std::move(completion)](Error) mutable {
        self->untilFrom(std::move(marker), limit, next, std::move(completion));
    });
}
void Reader::some(size_t maximum, ReadCallback completion) {
    if (closed_) { completion({}, true, "Stream closed"); return; }
    if (reading_) { completion({}, false, "Concurrent stream read"); return; }
    if (!maximum || maximum > maximumReadBytes) { completion({}, false, "Invalid maximum read size"); return; }
    if (buffered()) {
        Buffer result = consume(std::min(maximum, buffered()));
        // Deliver valid buffered bytes first, but never advertise a clean EOF
        // before the pending transport error has been delivered on the next
        // read. Consumers otherwise stop at EOF and silently lose the error.
        completion(std::move(result), eof_ && !buffered() && terminal_.empty(), {}); return;
    }
    if (!terminal_.empty()) { completion({}, true, terminal_); return; }
    if (eof_) { completion({}, true, {}); return; }
    auto self = shared_from_this();
    more([self, maximum, completion = std::move(completion)](Error) mutable {
        self->some(maximum, std::move(completion));
    });
}
Buffer Reader::take() { compact(true); Buffer result; result.swap(buffer_); readOffset_ = 0; return result; }
void Reader::close() {
    if (closed_) return;
    closed_ = true; Buffer().swap(buffer_); readOffset_ = 0; source_->close();
}

Buffer socksAddress(const Target &target) {
    Buffer output;
    std::string host = target.host;
    if (host.size() > 1 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size()-2);
    if(host.find(':')!=std::string::npos){auto scope=host.find('%');if(scope!=std::string::npos)host.resize(scope);}
    in_addr v4{}; in6_addr v6{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        output.push_back(1); auto bytes = reinterpret_cast<uint8_t *>(&v4); output.insert(output.end(), bytes, bytes+4);
    } else if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        output.push_back(4); auto bytes = reinterpret_cast<uint8_t *>(&v6); output.insert(output.end(), bytes, bytes+16);
    } else {
        hajimi_address checked{};
        auto valid=hajimi_address_from_host(reinterpret_cast<const uint8_t *>(host.data()),host.size(),target.port,&checked);
        if (host.empty() || host.size() > 255 || valid.status!=HAJIMI_CODEC_OK)
            throw std::runtime_error("Invalid destination domain");
        output.push_back(3); output.push_back(uint8_t(host.size())); output.insert(output.end(), host.begin(), host.end());
    }
    output.push_back(uint8_t(target.port >> 8)); output.push_back(uint8_t(target.port));
    return output;
}
Target parseSocksAddress(const Buffer &data, size_t &consumed) {
    consumed = 0;
    if (data.empty()) throw std::runtime_error("Truncated SOCKS address");
    Target target; size_t end = 0; char text[INET6_ADDRSTRLEN]{};
    switch (data[0]) {
    case 1:
        if (data.size() < 7) throw std::runtime_error("Truncated IPv4 address");
        if (!inet_ntop(AF_INET, data.data()+1, text, sizeof(text))) throw std::runtime_error("Invalid IPv4 address");
        target.host = text; end = 5; break;
    case 4:
        if (data.size() < 19) throw std::runtime_error("Truncated IPv6 address");
        if (!inet_ntop(AF_INET6, data.data()+1, text, sizeof(text))) throw std::runtime_error("Invalid IPv6 address");
        target.host = text; end = 17; break;
    case 3:
        if (data.size() < 2 || !data[1] || data.size() < size_t(data[1])+4) throw std::runtime_error("Truncated domain address");
        end = 2 + data[1]; target.host.assign(data.begin()+2, data.begin()+end);
        {hajimi_address checked{};auto valid=hajimi_address_from_host(reinterpret_cast<const uint8_t *>(target.host.data()),target.host.size(),0,&checked);
        if(valid.status!=HAJIMI_CODEC_OK)throw std::runtime_error("Invalid domain address");}
        break;
    default: throw std::runtime_error("Unsupported address type");
    }
    target.port = uint16_t(data[end]) << 8 | data[end+1]; target.udp = true; consumed = end+2;
    return target;
}
uint64_t unixSeconds() {
    return uint64_t(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
TLSOptions tlsOptions(const Node &node, bool defaultTLS) {
    TLSOptions options;
    auto security=node.option("security");std::transform(security.begin(),security.end(),security.begin(),[](unsigned char ch){return char(std::tolower(ch));});
    options.enabled = node.flag("tls", defaultTLS || security=="tls");
    options.skipVerify = node.flag("skip-cert-verify") || node.flag("skip-common-name-verify");
    options.serverName = node.option("sni", node.option("servername", node.option("ws-host",node.host)));
    auto value = node.option("alpn"); std::string item;
    auto append = [&] { if (!item.empty()) options.alpn.push_back(item); item.clear(); };
    for (char ch : value) {
        if (ch == ',' || ch == '|') append();
        else if (!std::isspace(static_cast<unsigned char>(ch)) && ch != '[' && ch != ']' && ch != '\'' && ch != '"') item.push_back(ch);
    }
    append();
    return options;
}
void connectProtocol(const Node &node, const Target &target, std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    auto error = validateProtocol(node, target.udp);
    if (!error.empty()) { completion(nullptr, error); return; }
    if(target.host.empty() || !target.port){completion(nullptr,"Missing or invalid destination");return;}
    try{(void)socksAddress(target);}catch(const std::exception &e){completion(nullptr,e.what());return;}
    if(target.udp && (node.type=="socks5" || node.type=="socks5-tls")){completion(nullptr,"SOCKS5 UDP requires a datagram association");return;}
    if (!factory || !factory->tcp || !factory->post) { completion(nullptr, "Missing native transport factory"); return; }
    if (node.type == "ss" || node.type == "ssr") connectShadowsocks(node, target, std::move(factory), std::move(completion));
    else if (node.type == "anytls") connectAnyTLS(node, target, std::move(factory), std::move(completion));
    else if (node.type == "hysteria" || node.type == "hysteria2" || node.type == "tuic") connectQUICProtocol(node, target, std::move(factory), std::move(completion));
    else if (node.type == "snell") connectSnell(node, target, std::move(factory), std::move(completion));
    else if (node.type == "ssh") connectSSH(node, target, std::move(factory), std::move(completion));
    else connectBasicProtocol(node, target, std::move(factory), std::move(completion));
}
void makeProtocolDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    auto error = validateProtocol(node, true);
    if (!error.empty()) { completion(nullptr, error); return; }
    if (!factory || !factory->tcp || !factory->post) { completion(nullptr, "Missing native transport factory"); return; }
    if (node.type == "ss" || node.type == "ssr") makeShadowsocksDatagram(node, std::move(factory), std::move(completion));
    else if (node.type == "anytls") makeAnyTLSDatagram(node, std::move(factory), std::move(completion));
    else if (node.type == "hysteria" || node.type == "hysteria2" || node.type == "tuic") makeQUICDatagram(node, std::move(factory), std::move(completion));
    else if (node.type == "snell") makeSnellDatagram(node, std::move(factory), std::move(completion));
    else makeBasicDatagram(node, std::move(factory), std::move(completion));
}
} // namespace hajimi
