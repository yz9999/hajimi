// A bounded test-only VMess AEAD peer. The recursive KDF implementation is
// copied from the independently pinned peer in CppBasicProtocolsMain.cpp.
// It admits only 127.0.0.1 and one CLI-approved loopback TLS origin port.
#include "Crypto.hpp"
#include "Runtime.hpp"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace hajimi;
namespace {
std::atomic<unsigned> active{0};
std::mutex errors;
Buffer bytes(const std::string &value) { return {value.begin(), value.end()}; }
void append(Buffer &to, const Buffer &value) { to.insert(to.end(), value.begin(), value.end()); }
void put16(Buffer &out, uint16_t value) { out.push_back(uint8_t(value >> 8)); out.push_back(uint8_t(value)); }
uint16_t get16(const Buffer &in, size_t offset) { return uint16_t(in.at(offset)) << 8 | in.at(offset + 1); }
uint32_t get32(const Buffer &in, size_t offset) {
    uint32_t value = 0; for (unsigned i = 0; i < 4; ++i) value = value << 8 | in.at(offset + i); return value;
}
uint64_t get64(const Buffer &in, size_t offset) {
    uint64_t value = 0; for (unsigned i = 0; i < 8; ++i) value = value << 8 | in.at(offset + i); return value;
}
Buffer part(const Buffer &in, size_t offset, size_t count) {
    if (offset > in.size() || count > in.size() - offset) throw std::runtime_error("VMess peer metadata limit");
    return {in.begin() + offset, in.begin() + offset + count};
}
Buffer cut(Buffer value, size_t count) { value.resize(std::min(value.size(), count)); return value; }
void require(bool condition, const char *message) { if (!condition) throw std::runtime_error(message); }
Buffer peerNestedHash(const Buffer &message, const std::vector<Buffer> &path, size_t depth) {
    if (!depth) return crypto::hmac("SHA256", bytes("VMess AEAD KDF"), message);
    Buffer key = path[depth - 1];
    if (key.size() > 64) key = peerNestedHash(key, path, depth - 1);
    key.resize(64, 0); Buffer inner(64), outer(64);
    for (size_t i = 0; i < 64; ++i) { inner[i] = key[i] ^ 0x36; outer[i] = key[i] ^ 0x5c; }
    append(inner, message); append(outer, peerNestedHash(inner, path, depth - 1));
    return peerNestedHash(outer, path, depth - 1);
}
Buffer peerKDF(const Buffer &key, const std::vector<Buffer> &path) { return peerNestedHash(key, path, path.size()); }
uint32_t peerCRC(const Buffer &data) {
    uint32_t value = 0xffffffffU;
    for (auto byte : data) { value ^= byte; for (unsigned i = 0; i < 8; ++i) value = (value >> 1) ^ ((value & 1) ? 0xedb88320U : 0); }
    return ~value;
}
uint32_t peerFNV(const Buffer &data) { uint32_t value = 0x811c9dc5U; for (auto byte : data) { value ^= byte; value *= 0x01000193U; } return value; }
Buffer nonce(uint32_t counter, const Buffer &iv) {
    require(counter < 65536, "VMess peer nonce exhaustion"); Buffer out; put16(out, uint16_t(counter)); append(out, part(iv, 2, 10)); return out;
}
struct Socket {
    int fd;
    explicit Socket(int fd = -1) : fd(fd) {}
    Socket(const Socket &) = delete;
    ~Socket() { if (fd >= 0) close(fd); }
};
void configure(int fd) {
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    timeval deadline{10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
}
bool readExact(int fd, size_t count, Buffer &out) {
    out.resize(count); size_t offset = 0;
    while (offset < count) {
        auto received = recv(fd, out.data() + offset, count - offset, 0);
        if (received <= 0) return false; offset += size_t(received);
    }
    return true;
}
bool sendAll(int fd, const Buffer &data) {
    size_t offset = 0;
    while (offset < data.size()) {
        auto sent = send(fd, data.data() + offset, data.size() - offset, 0);
        if (sent <= 0) return false; offset += size_t(sent);
    }
    return true;
}
struct Peer {
    Buffer key, iv, responseKey, responseIV;
    uint8_t verification = 0;
    uint32_t sendCounter = 0, receiveCounter = 0;
    bool readHeader(int fd, uint16_t port) {
        Buffer first;
        if (!readExact(fd, 42, first)) return false;
        Buffer uuid{0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        append(uuid, bytes("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
        Buffer commandKey = crypto::digest("MD5", uuid), authID = part(first, 0, 16), connection = part(first, 34, 8);
        Buffer authKey = cut(peerKDF(commandKey, {bytes("AES Auth ID Encryption")}), 16);
        Buffer auth = crypto::aesECBBlock(authID, authKey, false);
        auto stamp = get64(auth, 0), now = uint64_t(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        require((stamp > now ? stamp - now : now - stamp) <= 30 && get32(auth, 12) == peerCRC(part(auth, 0, 12)), "VMess peer AuthID rejected");
        Buffer lengthKey = cut(peerKDF(commandKey, {bytes("VMess Header AEAD Key_Length"), authID, connection}), 16);
        Buffer lengthIV = cut(peerKDF(commandKey, {bytes("VMess Header AEAD Nonce_Length"), authID, connection}), 12);
        Buffer length = crypto::open(crypto::AEAD::AES128GCM, lengthKey, lengthIV, part(first, 16, 18), authID);
        require(length.size() == 2 && get16(length, 0) >= 49 && get16(length, 0) <= 512, "VMess peer command length rejected");
        Buffer sealed;
        if (!readExact(fd, get16(length, 0) + 16, sealed)) return false;
        Buffer payloadKey = cut(peerKDF(commandKey, {bytes("VMess Header AEAD Key"), authID, connection}), 16);
        Buffer payloadIV = cut(peerKDF(commandKey, {bytes("VMess Header AEAD Nonce"), authID, connection}), 12);
        Buffer command = crypto::open(crypto::AEAD::AES128GCM, payloadKey, payloadIV, sealed, authID);
        size_t padding = command.at(35) >> 4;
        require(command.size() == 49 + padding && command[0] == 1 && command[34] == 1
                && (command[35] & 15) == 3 && command[36] == 0 && command[37] == 1
                && get16(command, 38) == port && command[40] == 1
                && part(command, 41, 4) == Buffer({127, 0, 0, 1})
                && get32(command, command.size() - 4) == peerFNV(part(command, 0, command.size() - 4)),
                "VMess peer destination escaped its single literal-loopback origin");
        iv = part(command, 1, 16); key = part(command, 17, 16); verification = command[33];
        responseKey = cut(crypto::digest("SHA256", key), 16); responseIV = cut(crypto::digest("SHA256", iv), 16);
        return true;
    }
    Buffer header() {
        Buffer plain{verification, 0, 0, 0}, length; put16(length, uint16_t(plain.size()));
        Buffer lk = cut(peerKDF(responseKey, {bytes("AEAD Resp Header Len Key")}), 16);
        Buffer li = cut(peerKDF(responseIV, {bytes("AEAD Resp Header Len IV")}), 12);
        Buffer pk = cut(peerKDF(responseKey, {bytes("AEAD Resp Header Key")}), 16);
        Buffer pi = cut(peerKDF(responseIV, {bytes("AEAD Resp Header IV")}), 12);
        Buffer wire = crypto::seal(crypto::AEAD::AES128GCM, lk, li, length);
        append(wire, crypto::seal(crypto::AEAD::AES128GCM, pk, pi, plain)); return wire;
    }
    Buffer frame(const Buffer &plain) {
        Buffer encrypted = crypto::seal(crypto::AEAD::AES128GCM, responseKey, nonce(sendCounter++, responseIV), plain);
        Buffer out; put16(out, uint16_t(encrypted.size())); append(out, encrypted); return out;
    }
    Buffer decode(const Buffer &wire) { return crypto::open(crypto::AEAD::AES128GCM, key, nonce(receiveCounter++, iv), wire); }
};
void report(const std::exception &error) { std::lock_guard<std::mutex> lock(errors); std::cerr << error.what() << '\n'; }
void serve(int descriptor, uint16_t port) {
    struct Admission { ~Admission() { --active; } } admission;
    Socket client(descriptor); configure(client.fd);
    try {
        Peer peer;
        if (!peer.readHeader(client.fd, port)) return;
        Socket origin(socket(AF_INET, SOCK_STREAM, 0)); require(origin.fd >= 0, "VMess peer origin socket unavailable"); configure(origin.fd);
        sockaddr_in address{}; address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
        require(connect(origin.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "VMess peer loopback origin connection failed");
        if (!sendAll(client.fd, peer.header())) return;
        std::thread upload([&] {
            try {
                Buffer length, wire;
                while (readExact(client.fd, 2, length)) {
                    size_t count = get16(length, 0); require(count >= 16 && count <= 17 * 1024, "VMess peer body frame limit");
                    if (!readExact(client.fd, count, wire)) break;
                    Buffer plain = peer.decode(wire);
                    if (plain.empty() || !sendAll(origin.fd, plain)) break;
                }
            } catch (const std::exception &error) { report(error); }
            shutdown(origin.fd, SHUT_WR);
        });
        try {
            Buffer plain(8192);
            while (true) {
                auto count = recv(origin.fd, plain.data(), plain.size(), 0);
                if (count <= 0) break;
                Buffer data(plain.begin(), plain.begin() + count);
                if (!sendAll(client.fd, peer.frame(data))) break;
            }
            sendAll(client.fd, peer.frame({}));
        } catch (const std::exception &error) { report(error); }
        shutdown(client.fd, SHUT_RDWR); shutdown(origin.fd, SHUT_RDWR);
        upload.join();
    } catch (const std::exception &error) { report(error); }
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 3 || std::strcmp(argv[1], "--origin-port")) return 2;
    char *end = nullptr; long origin = std::strtol(argv[2], &end, 10);
    if (!end || *end || origin <= 0 || origin > 65535) return 2;
    try {
        Socket listener(socket(AF_INET, SOCK_STREAM, 0)); require(listener.fd >= 0, "VMess peer listener unavailable"); configure(listener.fd);
        sockaddr_in address{}; address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        require(bind(listener.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "VMess peer loopback bind failed");
        socklen_t length = sizeof(address);
        require(getsockname(listener.fd, reinterpret_cast<sockaddr *>(&address), &length) == 0
                && address.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && listen(listener.fd, 256) == 0,
                "VMess peer loopback listener guard failed");
        std::cout << "VMESS_LOOPBACK_PORT " << ntohs(address.sin_port) << std::endl;
        while (true) {
            sockaddr_in source{}; length = sizeof(source);
            int descriptor = accept(listener.fd, reinterpret_cast<sockaddr *>(&source), &length);
            if (descriptor < 0) continue;
            if (source.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || active.load() >= 128) { close(descriptor); continue; }
            ++active; std::thread(serve, descriptor, uint16_t(origin)).detach();
        }
    } catch (const std::exception &error) { report(error); return 1; }
}
