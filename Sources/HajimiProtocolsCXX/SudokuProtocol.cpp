// Sudoku Outbound Protocol (Stream, Multiplexer, UoT Datagram & SelfTest)
#include "SudokuProtocol.hpp"
#include "SudokuCodec.hpp"
#include "ProtocolCommon.hpp"
#include <openssl/evp.h>
#include <array>
#include <mutex>
#include <unordered_map>

namespace hajimi {
namespace {
using namespace proto_common;
using namespace sudoku_detail;

// Sudoku obfuscated + RecordConn + KIP stream
class SudokuStream final : public Stream, public std::enable_shared_from_this<SudokuStream> {
public:
    SudokuStream(std::shared_ptr<Stream> raw, SudokuConfig cfg, std::string masterPubKey,
                 Buffer userHash8, std::shared_ptr<const SudokuTable> upTable,
                 std::shared_ptr<const SudokuTable> downTable,
                 std::string endpointTag = {})
        : raw_(std::move(raw)), writer_(std::make_shared<OrderedWriter>(raw_, maximumQueuedBytes, 128, 32768)), cfg_(std::move(cfg)), masterPubKey_(std::move(masterPubKey)),
          userHash8_(std::move(userHash8)), upTable_(std::move(upTable)), downTable_(std::move(downTable)) {
        (void)endpointTag;
        if (downTable_ && !downTable_->layout.paddingPool.empty()) {
            padMarker_ = downTable_->layout.paddingPool[0];
        }
        httpMaskResponseDone_ = cfg_.disableHttpMask;
        deriveSudokuPSKDirectionalBases(masterPubKey_, txBaseKey_, rxBaseKey_);
        sendEpoch_ = randomNonZeroUint32();
        sendSeq_ = randomNonZeroUint64();
        cachedTxEpoch_ = 0;
        cachedRxEpoch_ = 0;
    }

    void startHandshake(const Target &target, StreamCallback rawReady,
                        std::shared_ptr<TransportFactory> factory = nullptr) {
        auto readyFlag = std::make_shared<bool>(false);
        StreamCallback ready = [rawReady = std::move(rawReady), readyFlag](std::shared_ptr<Stream> s, Error e) mutable {
            if (*readyFlag) {
                if (s) s->close();
                return;
            }
            *readyFlag = true;
            if (rawReady) rawReady(std::move(s), std::move(e));
        };
        if (factory && factory->after) {
            auto self = shared_from_this();
            factory->after(10.0, [self, ready]() mutable {
                if (!self->handshakeDone_ && !self->closed_) {
                    self->close();
                    ready(nullptr, "Sudoku handshake timed out");
                }
            });
        }
        try {
            generateX25519KeyPair(clientPriv32_, clientPub32_);
            clientNonce16_ = crypto::randomBytes(16);

            Buffer wirePreface;
            if (!cfg_.disableHttpMask) {
                std::string path = cfg_.pathRoot.empty() ? "/stream" : ("/" + cfg_.pathRoot + "/stream");
                std::string host = formatHostHeaderAuthority(cfg_.httpMaskHost.empty() ? std::string("example.com") : cfg_.httpMaskHost);
                std::string httpReq = "POST " + path + " HTTP/1.1\r\n"
                    "Host: " + host + "\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Connection: close\r\n"
                    "X-Sudoku-Tunnel: legacy\r\n\r\n";
                wirePreface.insert(wirePreface.end(), httpReq.begin(), httpReq.end());
            }

            Buffer chPayload;
            appendBE64(chPayload, uint64_t(unixSeconds()));
            chPayload.insert(chPayload.end(), userHash8_.begin(), userHash8_.end());
            chPayload.insert(chPayload.end(), clientNonce16_.begin(), clientNonce16_.end());
            chPayload.insert(chPayload.end(), clientPub32_.begin(), clientPub32_.end());
            appendBE32(chPayload, kKIPFeatureAll);

            Buffer kipHello = buildKIPMessage(kKIPTypeClientHello, chPayload);
            Buffer recHello = sealRecord(kipHello);
            Buffer obfsHello = sudokuEncodeBytes(recHello, *upTable_, cfg_.paddingMin, cfg_.paddingMax);
            wirePreface.insert(wirePreface.end(), obfsHello.begin(), obfsHello.end());

            auto self = shared_from_this();
            writer_->write(std::move(wirePreface), [self, target, ready = std::move(ready)](Error writeErr) mutable {
                if (!writeErr.empty()) {
                    self->close();
                    ready(nullptr, writeErr);
                    return;
                }
                self->readKIPMessage([self, target, ready = std::move(ready)](uint8_t msgType, Buffer payload, Error err) mutable {
                    if (!err.empty()) {
                        self->close();
                        ready(nullptr, err);
                        return;
                    }
                    if (msgType != kKIPTypeServerHello || payload.size() < 52) {
                        self->close();
                        ready(nullptr, "Invalid Sudoku KIP ServerHello");
                        return;
                    }
                    try {
                        self->handshakeDone_ = true;
                        Buffer serverPub(payload.begin() + 16, payload.begin() + 48);
                        Buffer shared = computeX25519Shared(self->clientPriv32_, serverPub);
                        Buffer sessC2S, sessS2C;
                        deriveSudokuSessionDirectionalBases(self->masterPubKey_, shared, self->clientNonce16_, sessC2S, sessS2C);
                        self->rekey(std::move(sessC2S), std::move(sessS2C));

                        Buffer postCmd;
                        if (target.udp) {
                            postCmd = buildKIPMessage(kKIPTypeStartUoT, {});
                        } else {
                            postCmd = buildKIPMessage(kKIPTypeOpenTCP, socksAddress(target));
                        }
                        Buffer recCmd = self->sealRecord(postCmd);
                        Buffer obfsCmd = sudokuEncodeBytes(recCmd, *self->upTable_, self->cfg_.paddingMin, self->cfg_.paddingMax);
                        self->writer_->write(std::move(obfsCmd), [self, ready = std::move(ready)](Error cmdErr) mutable {
                            if (!cmdErr.empty()) {
                                self->close();
                                ready(nullptr, cmdErr);
                                return;
                            }
                            ready(self, {});
                        });
                    } catch (const std::exception &e) {
                        self->close();
                        ready(nullptr, e.what());
                    }
                });
            });
        } catch (const std::exception &e) {
            close();
            ready(nullptr, e.what());
        }
    }

    void startMuxHandshake(StreamCallback rawReady, std::shared_ptr<TransportFactory> factory = nullptr) {
        auto readyFlag = std::make_shared<bool>(false);
        StreamCallback ready = [rawReady = std::move(rawReady), readyFlag](std::shared_ptr<Stream> s, Error e) mutable {
            if (*readyFlag) {
                if (s) s->close();
                return;
            }
            *readyFlag = true;
            if (rawReady) rawReady(std::move(s), std::move(e));
        };
        if (factory && factory->after) {
            auto self = shared_from_this();
            factory->after(10.0, [self, ready]() mutable {
                if (!self->handshakeDone_ && !self->closed_) {
                    self->close();
                    ready(nullptr, "Sudoku mux handshake timed out");
                }
            });
        }
        try {
            generateX25519KeyPair(clientPriv32_, clientPub32_);
            clientNonce16_ = crypto::randomBytes(16);

            Buffer wirePreface;
            if (!cfg_.disableHttpMask) {
                std::string path = cfg_.pathRoot.empty() ? "/stream" : ("/" + cfg_.pathRoot + "/stream");
                std::string host = formatHostHeaderAuthority(cfg_.httpMaskHost.empty() ? std::string("example.com") : cfg_.httpMaskHost);
                std::string httpReq = "POST " + path + " HTTP/1.1\r\n"
                    "Host: " + host + "\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Connection: close\r\n"
                    "X-Sudoku-Tunnel: legacy\r\n\r\n";
                wirePreface.insert(wirePreface.end(), httpReq.begin(), httpReq.end());
            }

            Buffer chPayload;
            appendBE64(chPayload, uint64_t(unixSeconds()));
            chPayload.insert(chPayload.end(), userHash8_.begin(), userHash8_.end());
            chPayload.insert(chPayload.end(), clientNonce16_.begin(), clientNonce16_.end());
            chPayload.insert(chPayload.end(), clientPub32_.begin(), clientPub32_.end());
            appendBE32(chPayload, kKIPFeatureAll);

            Buffer kipHello = buildKIPMessage(kKIPTypeClientHello, chPayload);
            Buffer recHello = sealRecord(kipHello);
            Buffer obfsHello = sudokuEncodeBytes(recHello, *upTable_, cfg_.paddingMin, cfg_.paddingMax);
            wirePreface.insert(wirePreface.end(), obfsHello.begin(), obfsHello.end());

            auto self = shared_from_this();
            writer_->write(std::move(wirePreface), [self, ready = std::move(ready)](Error writeErr) mutable {
                if (!writeErr.empty()) {
                    self->close();
                    ready(nullptr, writeErr);
                    return;
                }
                self->readKIPMessage([self, ready = std::move(ready)](uint8_t msgType, Buffer payload, Error err) mutable {
                    if (!err.empty()) {
                        self->close();
                        ready(nullptr, err);
                        return;
                    }
                    if (msgType != kKIPTypeServerHello || payload.size() < 52) {
                        self->close();
                        ready(nullptr, "Invalid Sudoku KIP ServerHello");
                        return;
                    }
                    try {
                        self->handshakeDone_ = true;
                        Buffer serverPub(payload.begin() + 16, payload.begin() + 48);
                        Buffer shared = computeX25519Shared(self->clientPriv32_, serverPub);
                        Buffer sessC2S, sessS2C;
                        deriveSudokuSessionDirectionalBases(self->masterPubKey_, shared, self->clientNonce16_, sessC2S, sessS2C);
                        self->rekey(std::move(sessC2S), std::move(sessS2C));

                        Buffer postCmd = buildKIPMessage(kKIPTypeStartMux, {});
                        Buffer recCmd = self->sealRecord(postCmd);
                        Buffer obfsCmd = sudokuEncodeBytes(recCmd, *self->upTable_, self->cfg_.paddingMin, self->cfg_.paddingMax);
                        self->writer_->write(std::move(obfsCmd), [self, ready = std::move(ready)](Error cmdErr) mutable {
                            if (!cmdErr.empty()) {
                                self->close();
                                ready(nullptr, cmdErr);
                                return;
                            }
                            ready(self, {});
                        });
                    } catch (const std::exception &e) {
                        self->close();
                        ready(nullptr, e.what());
                    }
                });
            });
        } catch (const std::exception &e) {
            close();
            ready(nullptr, e.what());
        }
    }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Stream closed"); return; }
        if (data.empty()) { completion({}); return; }
        try {
            Buffer wire;
            wire.reserve(data.size() * 5 + 128);
            size_t offset = 0;
            while (offset < data.size()) {
                size_t chunkLen = std::min<size_t>(16384, data.size() - offset);
                Buffer rec;
                if (offset == 0 && chunkLen == data.size()) {
                    rec = sealRecord(data);
                } else {
                    Buffer plain(data.begin() + offset, data.begin() + offset + chunkLen);
                    rec = sealRecord(plain);
                }
                offset += chunkLen;
                sudokuAppendEncodedBytes(wire, rec, *upTable_, cfg_.paddingMin, cfg_.paddingMax);
            }
            writer_->write(std::move(wire), std::move(completion));
        } catch (const std::exception &e) {
            completion(e.what());
        }
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) { completion({}, true, "Stream closed"); return; }
        if (!pendingPlain_.empty()) {
            if (pendingPlain_.size() < maximum && handshakeDone_) {
                try {
                    while (decodedBuf_.size() >= 2 && pendingPlain_.size() < maximum) {
                        uint16_t nextLen = readBE16(decodedBuf_.data());
                        if (decodedBuf_.size() < 2 + size_t(nextLen)) break;
                        Buffer nextBody = decodedBuf_.sliceAndAdvance(2, size_t(nextLen));
                        size_t nextConsumed = 2 + size_t(nextLen);
                        if (recordScanOffset_ >= nextConsumed) {
                            recordScanOffset_ -= nextConsumed;
                        } else {
                            recordScanOffset_ = 0;
                        }
                        if (nextRecordBoundary_ > nextConsumed) {
                            nextRecordBoundary_ -= nextConsumed;
                        } else {
                            nextRecordBoundary_ = 0;
                            if (decodedBuf_.size() >= recordScanOffset_ + 2) {
                                nextRecordBoundary_ = recordScanOffset_ + 2 + size_t(readBE16(decodedBuf_.data() + recordScanOffset_));
                            }
                        }
                        Buffer extraPlain = openRecordBody(nextBody);
                        if (!extraPlain.empty()) {
                            pendingPlain_.append(extraPlain.data(), extraPlain.size());
                        }
                    }
                } catch (const std::exception &e) {
                    completion({}, true, e.what());
                    return;
                }
            }
            completion(pendingPlain_.consume(maximum), false, {});
            return;
        }
        auto self = shared_from_this();
        readNextRecord([self, maximum, completion = std::move(completion)](Buffer plain, bool eof, Error err) mutable {
            if (!err.empty() || eof) {
                completion({}, true, err);
                return;
            }
            if (plain.empty()) {
                self->read(maximum, std::move(completion));
                return;
            }
            size_t n = std::min(maximum, plain.size());
            Buffer out(plain.begin(), plain.begin() + n);
            if (n < plain.size()) {
                self->pendingPlain_.append(plain.data() + n, plain.size() - n);
            }
            completion(std::move(out), false, {});
        });
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        if (writer_) writer_->close();
        raw_->close();
    }

private:
    void rekey(Buffer newTxBase, Buffer newRxBase) {
        txBaseKey_ = std::move(newTxBase);
        rxBaseKey_ = std::move(newRxBase);
        sendEpoch_ = randomNonZeroUint32();
        sendSeq_ = randomNonZeroUint64();
        recvInitialized_ = false;
        cachedTxEpoch_ = 0;
        cachedRxEpoch_ = 0;
    }

    Buffer sealRecord(const Buffer &plain) {
        if (cfg_.aeadMethod == "none") {
            Buffer out;
            appendBE16(out, uint16_t(plain.size()));
            out.insert(out.end(), plain.begin(), plain.end());
            return out;
        }
        uint32_t epoch = sendEpoch_;
        uint64_t seq = sendSeq_++;
        if (cachedTxEpoch_ != epoch || cachedTxKey_.empty()) {
            cachedTxKey_ = deriveSudokuEpochKey(txBaseKey_, cfg_.aeadMethod, epoch);
            cachedTxEpoch_ = epoch;
        }
        uint8_t header[12];
        header[0] = uint8_t((epoch >> 24) & 0xff);
        header[1] = uint8_t((epoch >> 16) & 0xff);
        header[2] = uint8_t((epoch >> 8) & 0xff);
        header[3] = uint8_t(epoch & 0xff);
        for (int i = 7; i >= 0; --i) {
            header[4 + (7 - i)] = uint8_t((seq >> (i * 8)) & 0xff);
        }

        auto method = (cfg_.aeadMethod == "aes-128-gcm") ? crypto::AEAD::AES128GCM : crypto::AEAD::ChaCha20Poly1305;
        uint16_t bodyLen = uint16_t(12 + plain.size() + 16);
        Buffer frame(2 + size_t(bodyLen));
        frame[0] = uint8_t(bodyLen >> 8);
        frame[1] = uint8_t(bodyLen & 0xff);
        std::memcpy(frame.data() + 2, header, 12);
        if (!crypto::sealInto(method, cachedTxKey_.data(), cachedTxKey_.size(),
                              header, 12, plain.data(), plain.size(),
                              frame.data() + 14, header, 12)) {
            throw std::runtime_error("Sudoku AEAD seal failed");
        }
        return frame;
    }

    Buffer openRecordBody(const Buffer &body) {
        if (cfg_.aeadMethod == "none") return body;
        if (body.size() < 12 + 16) throw std::runtime_error("Sudoku record body too short");
        uint32_t pktEpoch = readBE32(body.data());
        uint64_t pktSeq = readBE64(body.data() + 4);
        if (!recvInitialized_) {
            if (pktEpoch == 0) throw std::runtime_error("Sudoku invalid zero epoch");
            recvEpoch_ = pktEpoch;
            recvSeq_ = pktSeq + 1;
            recvInitialized_ = true;
        } else {
            if (pktEpoch == recvEpoch_) {
                if (pktSeq != recvSeq_) throw std::runtime_error("Sudoku record sequence out of order");
                recvSeq_++;
            } else if (pktEpoch > recvEpoch_) {
                recvEpoch_ = pktEpoch;
                recvSeq_ = pktSeq + 1;
            } else {
                throw std::runtime_error("Sudoku record epoch rollback rejected");
            }
        }
        if (cachedRxEpoch_ != pktEpoch || cachedRxKey_.empty()) {
            cachedRxKey_ = deriveSudokuEpochKey(rxBaseKey_, cfg_.aeadMethod, pktEpoch);
            cachedRxEpoch_ = pktEpoch;
        }
        Buffer header(body.begin(), body.begin() + 12);
        Buffer cipher(body.begin() + 12, body.end());
        auto method = (cfg_.aeadMethod == "aes-128-gcm") ? crypto::AEAD::AES128GCM : crypto::AEAD::ChaCha20Poly1305;
        return crypto::open(method, cachedRxKey_, header, cipher, header);
    }

    void feedObfsBytes(const Buffer &wire) {
        if (cfg_.enablePureDownlink) {
            for (uint8_t b : wire) {
                if (!downTable_->layout.isHint(b)) continue;
                hintBuf_[hintCount_++] = b;
                if (hintCount_ == 4) {
                    uint8_t decoded = 0;
                    if (!downTable_->solve4Hints(hintBuf_, decoded)) {
                        throw std::runtime_error("Sudoku downlink puzzle decode failed");
                    }
                    decodedBuf_.push_back(decoded);
                    hintCount_ = 0;
                }
            }
        } else {
            for (uint8_t b : wire) {
                uint8_t grp = 0;
                if (!downTable_->layout.decodeGroup(b, grp)) {
                    // Per SUDOKU-ASCII/sudoku pkg/obfs/sudoku/packed.go:
                    // PackedConn uses layout.PaddingPool[0] as padMarker; seeing padMarker
                    // resets residual 6-bit accumulator (rBuf = 0, rBits = 0).
                    if (b == padMarker_) {
                        bitAcc_ = 0;
                        bitCount_ = 0;
                    }
                    continue;
                }
                bitAcc_ = (bitAcc_ << 6) | uint32_t(grp & 0x3f);
                bitCount_ += 6;
                if (bitCount_ >= 8) {
                    bitCount_ -= 8;
                    decodedBuf_.push_back(uint8_t((bitAcc_ >> bitCount_) & 0xff));
                    if (nextRecordBoundary_ == 0 && decodedBuf_.size() >= recordScanOffset_ + 2) {
                        uint16_t rlen = readBE16(decodedBuf_.data() + recordScanOffset_);
                        if (handshakeDone_ || (rlen >= 28 && rlen <= 2048)) {
                            nextRecordBoundary_ = recordScanOffset_ + 2 + size_t(rlen);
                        }
                    }
                    if (nextRecordBoundary_ > 0 && decodedBuf_.size() == nextRecordBoundary_) {
                        if (bitCount_ > 0) {
                            bitAcc_ = 0;
                            bitCount_ = 0;
                        }
                        recordScanOffset_ = nextRecordBoundary_;
                        nextRecordBoundary_ = 0;
                    }
                }
            }
        }
    }

    bool stripHttpMaskIfNeeded(Buffer &chunk) {
        if (httpMaskResponseDone_) return true;
        httpMaskBuf_.insert(httpMaskBuf_.end(), chunk.begin(), chunk.end());
        chunk.clear();
        static const char kHttpPrefix[] = "HTTP/";
        size_t checkLen = std::min<size_t>(httpMaskBuf_.size(), 5);
        bool matchesPrefix = true;
        for (size_t i = 0; i < checkLen; ++i) {
            char c = char(httpMaskBuf_[i]);
            if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
            if (c != kHttpPrefix[i]) {
                matchesPrefix = false;
                break;
            }
        }
        if (!matchesPrefix) {
            httpMaskResponseDone_ = true;
            chunk = std::move(httpMaskBuf_);
            httpMaskBuf_.clear();
            return true;
        }
        if (httpMaskBuf_.size() < 5) {
            return false;
        }
        for (size_t i = 0; i + 3 < httpMaskBuf_.size(); ++i) {
            if (httpMaskBuf_[i] == '\r' && httpMaskBuf_[i + 1] == '\n' &&
                httpMaskBuf_[i + 2] == '\r' && httpMaskBuf_[i + 3] == '\n') {
                httpMaskResponseDone_ = true;
                chunk.assign(httpMaskBuf_.begin() + ptrdiff_t(i + 4), httpMaskBuf_.end());
                httpMaskBuf_.clear();
                return true;
            }
        }
        for (size_t i = 0; i + 1 < httpMaskBuf_.size(); ++i) {
            if (httpMaskBuf_[i] == '\n' && httpMaskBuf_[i + 1] == '\n') {
                httpMaskResponseDone_ = true;
                chunk.assign(httpMaskBuf_.begin() + ptrdiff_t(i + 2), httpMaskBuf_.end());
                httpMaskBuf_.clear();
                return true;
            }
        }
        if (httpMaskBuf_.size() > 8192) {
            httpMaskResponseDone_ = true;
            chunk = std::move(httpMaskBuf_);
            httpMaskBuf_.clear();
            return true;
        }
        return false;
    }

    void ensureDecodedBytes(size_t needed, std::function<void(Error)> completion) {
        if (closed_) { completion("Stream closed"); return; }
        if (decodedBuf_.size() >= needed) {
            completion({});
            return;
        }
        auto self = shared_from_this();
        raw_->read(262144, [self, needed, completion = std::move(completion)](Buffer chunk, bool eof, Error err) mutable {
            if (!err.empty()) { completion(err); return; }
            if (!chunk.empty()) {
                if (!self->stripHttpMaskIfNeeded(chunk)) {
                    if (eof) {
                        completion("EOF");
                        return;
                    }
                    self->ensureDecodedBytes(needed, std::move(completion));
                    return;
                }
            }
            if (!chunk.empty()) {
                try {
                    self->feedObfsBytes(chunk);
                } catch (const std::exception &e) {
                    completion(e.what());
                    return;
                }
            }
            if (self->decodedBuf_.size() >= needed) {
                completion({});
                return;
            }
            if (eof) {
                completion("EOF");
                return;
            }
            self->ensureDecodedBytes(needed, std::move(completion));
        });
    }

    void readNextRecord(ReadCallback completion) {
        auto self = shared_from_this();
        ensureDecodedBytes(2, [self, completion = std::move(completion)](Error err) mutable {
            if (!err.empty()) {
                if (err == "EOF") completion({}, true, {});
                else completion({}, true, err);
                return;
            }
            uint16_t bodyLen = readBE16(self->decodedBuf_.data());
            self->ensureDecodedBytes(2 + size_t(bodyLen), [self, bodyLen, completion = std::move(completion)](Error berr) mutable {
                if (!berr.empty()) {
                    completion({}, true, berr);
                    return;
                }
                Buffer body = self->decodedBuf_.sliceAndAdvance(2, size_t(bodyLen));
                size_t consumedRec = 2 + size_t(bodyLen);
                if (self->recordScanOffset_ >= consumedRec) {
                    self->recordScanOffset_ -= consumedRec;
                } else {
                    self->recordScanOffset_ = 0;
                }
                if (self->nextRecordBoundary_ > consumedRec) {
                    self->nextRecordBoundary_ -= consumedRec;
                } else {
                    self->nextRecordBoundary_ = 0;
                    if (self->decodedBuf_.size() >= self->recordScanOffset_ + 2) {
                        self->nextRecordBoundary_ = self->recordScanOffset_ + 2 + size_t(readBE16(self->decodedBuf_.data() + self->recordScanOffset_));
                    }
                }
                try {
                    Buffer plain = self->openRecordBody(body);
                    while (self->handshakeDone_ && self->decodedBuf_.size() >= 2) {
                        uint16_t nextLen = readBE16(self->decodedBuf_.data());
                        if (self->decodedBuf_.size() < 2 + size_t(nextLen)) break;
                        Buffer nextBody = self->decodedBuf_.sliceAndAdvance(2, size_t(nextLen));
                        size_t nextConsumed = 2 + size_t(nextLen);
                        if (self->recordScanOffset_ >= nextConsumed) {
                            self->recordScanOffset_ -= nextConsumed;
                        } else {
                            self->recordScanOffset_ = 0;
                        }
                        if (self->nextRecordBoundary_ > nextConsumed) {
                            self->nextRecordBoundary_ -= nextConsumed;
                        } else {
                            self->nextRecordBoundary_ = 0;
                            if (self->decodedBuf_.size() >= self->recordScanOffset_ + 2) {
                                self->nextRecordBoundary_ = self->recordScanOffset_ + 2 + size_t(readBE16(self->decodedBuf_.data() + self->recordScanOffset_));
                            }
                        }
                        Buffer extraPlain = self->openRecordBody(nextBody);
                        if (!extraPlain.empty()) {
                            plain.insert(plain.end(), extraPlain.begin(), extraPlain.end());
                        }
                    }
                    completion(std::move(plain), false, {});
                } catch (const std::exception &e) {
                    self->close();
                    completion({}, true, e.what());
                }
            });
        });
    }

    void ensurePlainBytes(size_t needed, std::function<void(Error)> completion) {
        if (closed_) { completion("Stream closed"); return; }
        if (pendingPlain_.size() >= needed) {
            completion({});
            return;
        }
        auto self = shared_from_this();
        readNextRecord([self, needed, completion = std::move(completion)](Buffer plain, bool eof, Error err) mutable {
            if (!err.empty()) { completion(err); return; }
            if (!plain.empty()) {
                self->pendingPlain_.append(plain);
            }
            if (self->pendingPlain_.size() >= needed) {
                completion({});
                return;
            }
            if (eof) {
                completion("EOF");
                return;
            }
            self->ensurePlainBytes(needed, std::move(completion));
        });
    }

    void readKIPMessage(std::function<void(uint8_t, Buffer, Error)> completion) {
        auto self = shared_from_this();
        ensurePlainBytes(6, [self, completion = std::move(completion)](Error err) mutable {
            if (!err.empty()) { completion(0, {}, err); return; }
            if (self->pendingPlain_[0] != 'k' || self->pendingPlain_[1] != 'i' || self->pendingPlain_[2] != 'p') {
                completion(0, {}, "Invalid KIP magic");
                return;
            }
            uint8_t msgType = self->pendingPlain_[3];
            uint16_t payLen = readBE16(self->pendingPlain_.data() + 4);
            self->ensurePlainBytes(6 + size_t(payLen), [self, msgType, payLen, completion = std::move(completion)](Error perr) mutable {
                if (!perr.empty()) { completion(0, {}, perr); return; }
                Buffer payload = self->pendingPlain_.sliceAndAdvance(6, size_t(payLen));
                if (msgType == kKIPTypeKeepAlive) {
                    self->readKIPMessage(std::move(completion));
                    return;
                }
                completion(msgType, std::move(payload), {});
            });
        });
    }

    std::shared_ptr<Stream> raw_;
    std::shared_ptr<OrderedWriter> writer_;
    SudokuConfig cfg_;
    std::string masterPubKey_;
    Buffer userHash8_;
    std::shared_ptr<const SudokuTable> upTable_;
    std::shared_ptr<const SudokuTable> downTable_;

    Buffer clientPriv32_, clientPub32_, clientNonce16_;
    Buffer txBaseKey_, rxBaseKey_;
    Buffer cachedTxKey_, cachedRxKey_;
    uint32_t cachedTxEpoch_ = 0;
    uint32_t cachedRxEpoch_ = 0;
    uint32_t sendEpoch_ = 1;
    uint64_t sendSeq_ = 1;
    uint32_t recvEpoch_ = 0;
    uint64_t recvSeq_ = 0;
    bool recvInitialized_ = false;

    uint8_t hintBuf_[4]{};
    int hintCount_ = 0;
    uint32_t bitAcc_ = 0;
    int bitCount_ = 0;
    size_t recordScanOffset_ = 0;
    size_t nextRecordBoundary_ = 0;
    uint8_t padMarker_ = 0;
    Buffer httpMaskBuf_;
    bool httpMaskResponseDone_ = true;
    CursorBuffer decodedBuf_;
    CursorBuffer pendingPlain_;
    bool handshakeDone_ = false;
    bool closed_ = false;
};

// Sudoku KIP StartMux (0x11) Multiplexed Session & SubStream
class SudokuMuxSession final : public std::enable_shared_from_this<SudokuMuxSession> {
public:
    explicit SudokuMuxSession(std::shared_ptr<SudokuStream> carrier)
        : carrier_(std::move(carrier)), reader_(std::make_shared<Reader>(carrier_)),
          writer_(std::make_shared<OrderedWriter>(carrier_, maximumQueuedBytes, 128, proto_stream::kMaxCoalescedWriteBytes)) {}

    bool isClosed() const noexcept { return closed_; }

    void startReadLoop() {
        pumpRead();
    }

    void openSubStream(const Target &target, StreamCallback completion);

    void writeMuxFrame(uint8_t frameType, uint32_t streamID, const uint8_t *payload, size_t len, WriteCallback completion) {
        if (closed_) {
            if (completion) completion(terminal_.empty() ? Error("Sudoku mux session closed") : terminal_);
            return;
        }
        Buffer frame;
        frame.reserve(7 + len);
        frame.push_back(frameType);
        appendBE32(frame, streamID);
        appendBE16(frame, uint16_t(len));
        if (len > 0) frame.insert(frame.end(), payload, payload + len);
        writer_->write(std::move(frame), std::move(completion));
    }

    void unregisterStream(uint32_t streamID) {
        streams_.erase(streamID);
    }

    void closeAll(Error err) {
        if (closed_) return;
        closed_ = true;
        terminal_ = err.empty() ? Error("Sudoku mux session closed") : err;
        writer_->close();
        reader_->close();
        if (carrier_) carrier_->close();
        auto active = std::move(streams_);
        streams_.clear();
        for (auto &kv : active) {
            if (auto sub = kv.second.lock()) {
                sub->onRemoteReset(terminal_);
            }
        }
    }

    class SubStream final : public Stream, public std::enable_shared_from_this<SubStream> {
    public:
        SubStream(std::shared_ptr<SudokuMuxSession> session, uint32_t streamID)
            : session_(std::move(session)), streamID_(streamID) {}
        ~SubStream() override { close(); }

        void write(Buffer data, WriteCallback completion) override {
            if (closed_) { completion(terminal_.empty() ? Error("Sudoku mux stream closed") : terminal_); return; }
            if (data.empty()) { completion({}); return; }
            auto sess = session_.lock();
            if (!sess || sess->isClosed()) { completion("Sudoku mux session closed"); return; }
            size_t offset = 0;
            while (offset < data.size()) {
                size_t chunk = std::min<size_t>(32768, data.size() - offset);
                bool isLast = (offset + chunk == data.size());
                sess->writeMuxFrame(kSudokuMuxFrameData, streamID_, data.data() + offset, chunk,
                                    isLast ? std::move(completion) : WriteCallback([](Error) {}));
                offset += chunk;
            }
        }

        void read(size_t maximum, ReadCallback completion) override {
            if (!buffered_.empty()) {
                Buffer out = buffered_.consume(maximum);
                bool done = buffered_.empty() && remoteClosed_;
                completion(std::move(out), done, {});
                return;
            }
            if (remoteClosed_) {
                completion({}, true, terminal_);
                return;
            }
            if (closed_) {
                completion({}, true, terminal_.empty() ? Error("Sudoku mux stream closed") : terminal_);
                return;
            }
            pendingMax_ = maximum;
            pendingRead_ = std::move(completion);
        }

        void close() override {
            if (closed_) return;
            closed_ = true;
            if (auto sess = session_.lock()) {
                sess->unregisterStream(streamID_);
                if (!remoteClosed_ && !sess->isClosed()) {
                    sess->writeMuxFrame(kSudokuMuxFrameClose, streamID_, nullptr, 0, [](Error) {});
                }
            }
            if (auto cb = std::exchange(pendingRead_, {})) {
                cb({}, true, terminal_.empty() ? Error("Sudoku mux stream closed") : terminal_);
            }
        }

        void onRemoteData(const Buffer &payload) {
            if (closed_ || payload.empty()) return;
            buffered_.append(payload.data(), payload.size());
            if (pendingRead_) {
                auto cb = std::exchange(pendingRead_, {});
                Buffer out = buffered_.consume(pendingMax_);
                bool done = buffered_.empty() && remoteClosed_;
                cb(std::move(out), done, {});
            }
        }

        void onRemoteClose() {
            remoteClosed_ = true;
            if (pendingRead_ && buffered_.empty()) {
                auto cb = std::exchange(pendingRead_, {});
                cb({}, true, {});
            }
        }

        void onRemoteReset(const Error &err) {
            remoteClosed_ = true;
            terminal_ = err.empty() ? Error("Sudoku mux stream reset by peer") : err;
            if (pendingRead_) {
                auto cb = std::exchange(pendingRead_, {});
                cb({}, true, terminal_);
            }
        }

    private:
        std::weak_ptr<SudokuMuxSession> session_;
        uint32_t streamID_ = 0;
        CursorBuffer buffered_;
        ReadCallback pendingRead_;
        size_t pendingMax_ = 0;
        Error terminal_;
        bool remoteClosed_ = false;
        bool closed_ = false;
    };

private:
    void pumpRead() {
        if (closed_) return;
        auto self = shared_from_this();
        reader_->exactly(7, [self](Buffer hdr, Error err) {
            if (self->closed_) return;
            if (!err.empty()) {
                self->closeAll(err == "EOF" ? Error{} : err);
                return;
            }
            uint8_t fType = hdr[0];
            uint32_t sid = readBE32(hdr.data() + 1);
            uint16_t payLen = readBE16(hdr.data() + 5);
            if (payLen == 0) {
                self->dispatchFrame(fType, sid, {});
                self->pumpRead();
                return;
            }
            self->reader_->exactly(payLen, [self, fType, sid](Buffer payload, Error perr) {
                if (self->closed_) return;
                if (!perr.empty()) {
                    self->closeAll(perr);
                    return;
                }
                self->dispatchFrame(fType, sid, payload);
                self->pumpRead();
            });
        });
    }

    void dispatchFrame(uint8_t fType, uint32_t sid, const Buffer &payload) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        auto sub = it->second.lock();
        if (!sub) {
            streams_.erase(it);
            return;
        }
        if (fType == kSudokuMuxFrameData) {
            sub->onRemoteData(payload);
        } else if (fType == kSudokuMuxFrameClose) {
            streams_.erase(it);
            sub->onRemoteClose();
        } else if (fType == kSudokuMuxFrameReset) {
            streams_.erase(it);
            std::string msg(payload.begin(), payload.end());
            sub->onRemoteReset(msg.empty() ? Error("Sudoku mux stream reset") : Error(msg));
        }
    }

    std::shared_ptr<SudokuStream> carrier_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
    std::unordered_map<uint32_t, std::weak_ptr<SubStream>> streams_;
    uint32_t nextStreamID_ = 1;
    Error terminal_;
    bool closed_ = false;
};

void SudokuMuxSession::openSubStream(const Target &target, StreamCallback completion) {
    if (closed_) {
        completion(nullptr, terminal_.empty() ? Error("Sudoku mux session closed") : terminal_);
        return;
    }
    Buffer addr;
    try {
        addr = socksAddress(target);
    } catch (const std::exception &e) {
        completion(nullptr, e.what());
        return;
    }
    uint32_t sid = nextStreamID_++;
    if (sid == 0) sid = nextStreamID_++;
    auto sub = std::make_shared<SubStream>(shared_from_this(), sid);
    streams_[sid] = sub;
    writeMuxFrame(kSudokuMuxFrameOpen, sid, addr.data(), addr.size(), [self = shared_from_this(), sid, sub, completion = std::move(completion)](Error err) mutable {
        if (!err.empty()) {
            self->unregisterStream(sid);
            completion(nullptr, err);
            return;
        }
        completion(sub, {});
    });
}

struct PooledSudokuMuxEntry {
    std::mutex mtx;
    std::shared_ptr<TransportFactory> factory;
    std::shared_ptr<SudokuMuxSession> session;
    std::vector<std::function<void(std::shared_ptr<SudokuMuxSession>, Error)>> waiters;
    bool connecting = false;
    void closeEntry() {
        std::shared_ptr<SudokuMuxSession> oldSession;
        std::vector<std::function<void(std::shared_ptr<SudokuMuxSession>, Error)>> pending;
        {
            std::lock_guard<std::mutex> lock(mtx);
            connecting = false;
            oldSession = std::move(session);
            pending = std::move(waiters);
            waiters.clear();
        }
        if (oldSession) oldSession->closeAll("Sudoku mux client reset");
        for (auto &w : pending) w(nullptr, "Sudoku mux client reset");
    }
};

std::mutex &sudokuMuxPoolMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, std::shared_ptr<PooledSudokuMuxEntry>> &sudokuMuxPool() {
    static std::unordered_map<std::string, std::shared_ptr<PooledSudokuMuxEntry>> pool;
    return pool;
}

// Sudoku UoT (UDP-over-TCP) Datagram: frame format [uint16 addrLen (BE)][uint16 payloadLen (BE)][socksAddress][payload]
class SudokuUoTDatagram final : public Datagram, public std::enable_shared_from_this<SudokuUoTDatagram> {
public:
    SudokuUoTDatagram(Node node, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), factory_(std::move(factory)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram closed"); return; }
        if (data.size() > 65535 || target.host.empty() || !target.port) {
            completion("Invalid Sudoku UoT target or payload size");
            return;
        }
        Buffer packet;
        try {
            Buffer addr = socksAddress(target);
            appendBE16(packet, uint16_t(addr.size()));
            appendBE16(packet, uint16_t(data.size()));
            packet.insert(packet.end(), addr.begin(), addr.end());
            packet.insert(packet.end(), data.begin(), data.end());
        } catch (const std::exception &e) {
            completion(e.what());
            return;
        }

        auto self = shared_from_this();
        sendPacketWithRetry(target, std::move(packet), std::move(completion), true);
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        receive_ = std::move(receive);
        failure_ = std::move(failure);
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        resetActiveStream();
    }

private:
    void resetActiveStream() {
        auto r = std::move(reader_);
        auto s = std::move(stream_);
        streamUsed_ = false;
        if (r) r->close();
        else if (s) s->close();
    }

    void sendPacketWithRetry(Target target, Buffer packet, WriteCallback completion, bool allowRetry) {
        auto self = shared_from_this();
        ensureStream(target, [self, target, packet = std::move(packet), completion = std::move(completion), allowRetry](Error err) mutable {
            if (!err.empty() || !self->stream_) {
                completion(err.empty() ? Error("Sudoku UoT stream unavailable") : err);
                return;
            }
            auto active = self->stream_;
            const bool wasUsed = self->streamUsed_;
            self->streamUsed_ = true;
            active->write(packet, [self, target, packet, completion = std::move(completion), active, wasUsed, allowRetry](Error writeErr) mutable {
                if (!writeErr.empty() && !self->closed_ && wasUsed && allowRetry) {
                    if (self->stream_ == active) self->resetActiveStream();
                    self->sendPacketWithRetry(std::move(target), std::move(packet), std::move(completion), false);
                    return;
                }
                completion(std::move(writeErr));
            });
        });
    }

    void ensureStream(const Target &initialTarget, WriteCallback ready) {
        if (stream_) { ready({}); return; }
        pendingReady_.push_back(std::move(ready));
        if (connecting_) return;
        connecting_ = true;

        Target udpTarget = initialTarget;
        udpTarget.udp = true;
        auto self = shared_from_this();
        connectSudoku(node_, udpTarget, factory_, [self](std::shared_ptr<Stream> stream, Error err) {
            self->connecting_ = false;
            auto callbacks = std::move(self->pendingReady_);
            self->pendingReady_.clear();
            if (self->closed_ || !err.empty() || !stream) {
                Error finalErr = !err.empty() ? err : Error("Sudoku UoT carrier closed");
                for (auto &cb : callbacks) cb(finalErr);
                return;
            }
            self->stream_ = std::move(stream);
            self->reader_ = std::make_shared<Reader>(self->stream_);
            self->streamUsed_ = false;
            for (auto &cb : callbacks) cb({});
            self->readLoop();
        });
    }

    void readLoop() {
        if (closed_ || !reader_) return;
        auto self = shared_from_this();
        auto activeReader = reader_;
        activeReader->exactly(4, [self, activeReader](Buffer hdr, Error err) {
            if (self->closed_ || self->reader_ != activeReader) return;
            if (!err.empty()) {
                const bool wasUsed = self->streamUsed_;
                self->resetActiveStream();
                if (self->failure_ && err != "EOF" && !wasUsed) self->failure_(err);
                return;
            }
            uint16_t addrLen = readBE16(hdr.data());
            uint16_t payLen = readBE16(hdr.data() + 2);
            activeReader->exactly(size_t(addrLen) + size_t(payLen), [self, activeReader, addrLen, payLen](Buffer body, Error berr) {
                if (self->closed_ || self->reader_ != activeReader) return;
                if (!berr.empty()) {
                    self->resetActiveStream();
                    if (self->failure_) self->failure_(berr);
                    return;
                }
                try {
                    Buffer addrBuf(body.begin(), body.begin() + addrLen);
                    size_t consumed = 0;
                    Target source = parseSocksAddress(addrBuf, consumed);
                    Buffer payload(body.begin() + addrLen, body.begin() + addrLen + payLen);
                    if (self->receive_) self->receive_(source, std::move(payload));
                    self->readLoop();
                } catch (const std::exception &e) {
                    if (self->failure_) self->failure_(e.what());
                }
            });
        });
    }

    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::shared_ptr<Stream> stream_;
    std::shared_ptr<Reader> reader_;
    std::vector<WriteCallback> pendingReady_;
    PacketCallback receive_;
    WriteCallback failure_;
    bool streamUsed_ = false;
    bool connecting_ = false;
    bool closed_ = false;
};

} // namespace

void resetSudokuClients() {
    std::vector<std::shared_ptr<PooledSudokuMuxEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(sudokuMuxPoolMutex());
        for (auto &kv : sudokuMuxPool()) {
            if (kv.second) entries.push_back(kv.second);
        }
        sudokuMuxPool().clear();
    }
    for (auto &e : entries) e->closeEntry();
}

void resetSudokuClient(const std::shared_ptr<TransportFactory> &factory) {
    if (!factory) {
        resetSudokuClients();
        return;
    }
    std::vector<std::shared_ptr<PooledSudokuMuxEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(sudokuMuxPoolMutex());
        for (auto it = sudokuMuxPool().begin(); it != sudokuMuxPool().end();) {
            if (!it->second || it->second->factory == factory) {
                if (it->second) entries.push_back(it->second);
                it = sudokuMuxPool().erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto &e : entries) e->closeEntry();
}

Error validateSudoku(const Node &node, bool) {
    SudokuConfig cfg;
    return parseSudokuConfig(node, cfg);
}

void connectSudoku(const Node &node, const Target &target,
                   std::shared_ptr<TransportFactory> factory, StreamCallback completion) {
    SudokuConfig cfg;
    auto err = parseSudokuConfig(node, cfg);
    if (!err.empty()) { completion(nullptr, err); return; }

    std::string endpointTag = formatHostHeaderAuthority(node.dialHost()) + ":" + std::to_string(node.port);
    const bool useMux = !target.udp && (cfg.multiplex == "on" || cfg.multiplex == "true" || cfg.multiplex == "auto");
    if (useMux) {
        std::string poolKey = std::to_string(reinterpret_cast<uintptr_t>(factory.get())) + "|" +
            endpointTag + "|" + node.interfaceName + "|" + cfg.key + "|" + cfg.tableType + "|" + cfg.customTable;
        std::shared_ptr<PooledSudokuMuxEntry> entry;
        std::vector<std::shared_ptr<PooledSudokuMuxEntry>> evicted;
        {
            std::lock_guard<std::mutex> lock(sudokuMuxPoolMutex());
            if (sudokuMuxPool().size() >= 64 && !sudokuMuxPool().count(poolKey)) {
                for (auto &kv : sudokuMuxPool()) {
                    if (kv.second) evicted.push_back(kv.second);
                }
                sudokuMuxPool().clear();
            }
            auto &slot = sudokuMuxPool()[poolKey];
            if (!slot) {
                slot = std::make_shared<PooledSudokuMuxEntry>();
                slot->factory = factory;
            }
            entry = slot;
        }
        for (auto &old : evicted) old->closeEntry();

        std::shared_ptr<SudokuMuxSession> readySession;
        bool startDial = false;
        {
            std::lock_guard<std::mutex> entryLock(entry->mtx);
            if (entry->session && !entry->session->isClosed()) {
                readySession = entry->session;
            } else {
                entry->session.reset();
                entry->waiters.push_back([target, completion = std::move(completion)](std::shared_ptr<SudokuMuxSession> sess, Error muxErr) mutable {
                    if (!muxErr.empty() || !sess) {
                        completion(nullptr, muxErr.empty() ? Error("Sudoku mux session unavailable") : muxErr);
                        return;
                    }
                    sess->openSubStream(target, std::move(completion));
                });
                if (!entry->connecting) {
                    entry->connecting = true;
                    startDial = true;
                }
            }
        }
        if (readySession) {
            readySession->openSubStream(target, std::move(completion));
            return;
        }
        if (!startDial) return;

        auto tls = tlsOptions(node, !cfg.disableHttpMask && cfg.httpMaskTls);
        factory->tcp(node, tls, [factory, cfg = std::move(cfg), endpointTag = std::move(endpointTag), entry]
                     (std::shared_ptr<Stream> raw, Error dialErr) mutable {
            if (!dialErr.empty() || !raw) {
                std::vector<std::function<void(std::shared_ptr<SudokuMuxSession>, Error)>> pending;
                {
                    std::lock_guard<std::mutex> entryLock(entry->mtx);
                    entry->connecting = false;
                    pending = std::move(entry->waiters);
                    entry->waiters.clear();
                }
                Error finalErr = dialErr.empty() ? Error("Sudoku TCP dial failed") : dialErr;
                for (auto &w : pending) w(nullptr, finalErr);
                return;
            }
            try {
                std::string masterPubKey;
                Buffer userHash8;
                sudokuRecoverMasterPublicKey(cfg.key, masterPubKey, userHash8);
                const bool upAscii = (cfg.tableType == "prefer_ascii" || cfg.tableType == "up_ascii_down_entropy");
                const bool downAscii = (cfg.tableType == "prefer_ascii" || cfg.tableType == "up_entropy_down_ascii");
                auto upTable = getSudokuTable(masterPubKey, upAscii, upAscii ? "" : cfg.customTable);
                auto downTable = (upAscii == downAscii)
                    ? upTable
                    : getSudokuTable(masterPubKey, downAscii, downAscii ? "" : cfg.customTable);
                auto sudokuStream = std::make_shared<SudokuStream>(
                    raw, std::move(cfg), std::move(masterPubKey), std::move(userHash8),
                    std::move(upTable), std::move(downTable), std::move(endpointTag));
                sudokuStream->startMuxHandshake([entry](std::shared_ptr<Stream> readyCarrier, Error hsErr) {
                    std::vector<std::function<void(std::shared_ptr<SudokuMuxSession>, Error)>> pending;
                    if (!hsErr.empty() || !readyCarrier) {
                        {
                            std::lock_guard<std::mutex> entryLock(entry->mtx);
                            entry->connecting = false;
                            pending = std::move(entry->waiters);
                            entry->waiters.clear();
                        }
                        Error finalErr = hsErr.empty() ? Error("Sudoku mux handshake failed") : hsErr;
                        for (auto &w : pending) w(nullptr, finalErr);
                        return;
                    }
                    auto muxSess = std::make_shared<SudokuMuxSession>(std::static_pointer_cast<SudokuStream>(readyCarrier));
                    muxSess->startReadLoop();
                    {
                        std::lock_guard<std::mutex> entryLock(entry->mtx);
                        entry->connecting = false;
                        entry->session = muxSess;
                        pending = std::move(entry->waiters);
                        entry->waiters.clear();
                    }
                    for (auto &w : pending) w(muxSess, {});
                }, factory);
            } catch (const std::exception &e) {
                raw->close();
                std::vector<std::function<void(std::shared_ptr<SudokuMuxSession>, Error)>> pending;
                {
                    std::lock_guard<std::mutex> entryLock(entry->mtx);
                    entry->connecting = false;
                    pending = std::move(entry->waiters);
                    entry->waiters.clear();
                }
                for (auto &w : pending) w(nullptr, e.what());
            }
        });
        return;
    }

    auto tls = tlsOptions(node, !cfg.disableHttpMask && cfg.httpMaskTls);
    factory->tcp(node, tls, [factory, cfg = std::move(cfg), endpointTag = std::move(endpointTag), target, completion = std::move(completion)]
                 (std::shared_ptr<Stream> raw, Error dialErr) mutable {
        if (!dialErr.empty() || !raw) {
            completion(nullptr, dialErr.empty() ? Error("Sudoku TCP dial failed") : dialErr);
            return;
        }
        try {
            std::string masterPubKey;
            Buffer userHash8;
            sudokuRecoverMasterPublicKey(cfg.key, masterPubKey, userHash8);

            const bool upAscii = (cfg.tableType == "prefer_ascii" || cfg.tableType == "up_ascii_down_entropy");
            const bool downAscii = (cfg.tableType == "prefer_ascii" || cfg.tableType == "up_entropy_down_ascii");

            auto upTable = getSudokuTable(masterPubKey, upAscii, upAscii ? "" : cfg.customTable);
            auto downTable = (upAscii == downAscii)
                ? upTable
                : getSudokuTable(masterPubKey, downAscii, downAscii ? "" : cfg.customTable);

            auto sudokuStream = std::make_shared<SudokuStream>(
                raw, std::move(cfg), std::move(masterPubKey), std::move(userHash8),
                std::move(upTable), std::move(downTable), std::move(endpointTag));
            sudokuStream->startHandshake(target, std::move(completion), factory);
        } catch (const std::exception &e) {
            raw->close();
            completion(nullptr, e.what());
        }
    });
}

void makeSudokuDatagram(const Node &node, std::shared_ptr<TransportFactory> factory,
                        DatagramCallback completion) {
    auto err = validateSudoku(node, true);
    if (!err.empty()) { completion(nullptr, err); return; }
    completion(std::make_shared<SudokuUoTDatagram>(node, std::move(factory)), {});
}

bool sudokuProtocolSelfTest() {
    try {
        std::string masterPub;
        Buffer userHash;
        if (!sudokuRecoverMasterPublicKey(
                "b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140a"
                "ac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e",
                masterPub, userHash) ||
            masterPub != "6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b" ||
            userHash.size() != 8) {
            return false;
        }
        std::string userPub = masterPub;
        Buffer userHash2 = userHash;

        Buffer sample(256);
        for (int i = 0; i < 256; ++i) sample[size_t(i)] = uint8_t(i);
        for (bool ascii : {true, false}) {
            Buffer enc = sudokuEncodeTable(sample, ascii);
            Buffer dec = sudokuDecodeTable(enc, ascii);
            if (dec != sample) return false;
        }
        Buffer encCustom = sudokuEncodeTable(sample, false, "xvxvppvv");
        Buffer decCustom = sudokuDecodeTable(encCustom, false, "xvxvppvv");
        if (decCustom != sample) return false;

        {
            auto upTbl = getSudokuTable(userPub, true, "");
            auto downTbl = getSudokuTable(userPub, false, "xvxvppvv");
            for (int trial = 0; trial < 20; ++trial) {
                Buffer obfsUp = sudokuEncodeBytes(sample, *upTbl, 10, 23);
                Buffer decodedUp;
                uint8_t h[4]; int hc = 0;
                for (uint8_t w : obfsUp) {
                    if (!upTbl->layout.isHint(w)) continue;
                    h[hc++] = w;
                    if (hc == 4) {
                        uint8_t b = 0;
                        if (!upTbl->solve4Hints(h, b)) return false;
                        decodedUp.push_back(b);
                        hc = 0;
                    }
                }
                if (hc != 0 || decodedUp != sample) return false;

                Buffer obfsDown = sudokuEncodeBytes(sample, *downTbl, 10, 23);
                Buffer decodedDown;
                for (uint8_t w : obfsDown) {
                    if (!downTbl->layout.isHint(w)) continue;
                    h[hc++] = w;
                    if (hc == 4) {
                        uint8_t b = 0;
                        if (!downTbl->solve4Hints(h, b)) return false;
                        decodedDown.push_back(b);
                        hc = 0;
                    }
                }
                if (hc != 0 || decodedDown != sample) return false;
            }
        }

        Node sudokuNode;
        sudokuNode.type = "sudoku"; sudokuNode.host = "127.0.0.1"; sudokuNode.port = 8443;
        sudokuNode.parameters["key"] = "sudoku-secret-key";
        sudokuNode.parameters["custom-table"] = "xpxpvovv";
        if (validateSudoku(sudokuNode, false).empty()) return false;
        sudokuNode.parameters["custom-table"] = "xvxvppvv";
        if (!validateSudoku(sudokuNode, false).empty()) return false;

        {
            struct LoopStream : public Stream {
                Buffer rx;
                Buffer tx;
                ReadCallback pending;
                size_t pendingMax = 0;
                bool closed = false;
                void write(Buffer d, WriteCallback cb) override {
                    tx.insert(tx.end(), d.begin(), d.end());
                    cb({});
                }
                void read(size_t m, ReadCallback cb) override {
                    if (!rx.empty()) {
                        size_t n = std::min(m, rx.size());
                        Buffer out(rx.begin(), rx.begin() + n);
                        rx.erase(rx.begin(), rx.begin() + n);
                        cb(std::move(out), false, {});
                        return;
                    }
                    pendingMax = m;
                    pending = std::move(cb);
                }
                void close() override { closed = true; }
                void feedRx(const Buffer &d) {
                    rx.insert(rx.end(), d.begin(), d.end());
                    if (pending && !rx.empty()) {
                        auto cb = std::move(pending);
                        pending = {};
                        size_t n = std::min(pendingMax, rx.size());
                        Buffer out(rx.begin(), rx.begin() + n);
                        rx.erase(rx.begin(), rx.begin() + n);
                        cb(std::move(out), false, {});
                    }
                }
            };

            auto upTbl = getSudokuTable(userPub, true, "");
            auto downTbl = getSudokuTable(userPub, false, "xvxvppvv");
            const uint8_t testPadMarker = downTbl->layout.paddingPool[0];
            auto packDownlink6Bit = [&](const Buffer &rec) -> Buffer {
                Buffer wire;
                uint32_t acc = 0;
                int bits = 0;
                size_t step = 0;
                for (uint8_t b : rec) {
                    acc = (acc << 8) | b;
                    bits += 8;
                    while (bits >= 6) {
                        bits -= 6;
                        if ((++step % 5) == 0 && downTbl->layout.paddingPool.size() > 1) {
                            wire.push_back(downTbl->layout.paddingPool[1 + (step % (downTbl->layout.paddingPool.size() - 1))]);
                        }
                        wire.push_back(downTbl->layout.encodeHint(((acc >> (bits + 4)) & 3), ((acc >> bits) & 0x0f)));
                    }
                }
                if (bits > 0) {
                    wire.push_back(downTbl->layout.encodeHint((((acc << (6 - bits)) >> 4) & 3), ((acc << (6 - bits)) & 0x0f)));
                    wire.push_back(testPadMarker);
                }
                if (downTbl->layout.paddingPool.size() > 1) {
                    wire.push_back(downTbl->layout.paddingPool[1]);
                }
                return wire;
            };

            auto raw = std::make_shared<LoopStream>();
            SudokuConfig cfg;
            cfg.key = "b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140aac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e";
            cfg.aeadMethod = "chacha20-poly1305";
            cfg.tableType = "up_ascii_down_entropy";
            cfg.customTable = "xvxvppvv";
            cfg.enablePureDownlink = false;
            cfg.disableHttpMask = false;

            auto stream = std::make_shared<SudokuStream>(raw, cfg, userPub, userHash2, upTbl, downTbl, "127.0.0.1:8443");
            std::shared_ptr<Stream> readyStream;
            Error readyErr;
            stream->startHandshake(Target{"example.com", 443, false, false}, [&](std::shared_ptr<Stream> s, Error e) {
                readyStream = s;
                readyErr = e;
            });

            // Strip client HTTP POST preface before decoding client obfs bytes
            size_t txStart = 0;
            for (size_t i = 0; i + 3 < raw->tx.size(); ++i) {
                if (raw->tx[i] == '\r' && raw->tx[i + 1] == '\n' &&
                    raw->tx[i + 2] == '\r' && raw->tx[i + 3] == '\n') {
                    txStart = i + 4;
                    break;
                }
            }
            if (txStart == 0) return false;

            Buffer clientRec;
            uint8_t h[4]; int hc = 0;
            for (size_t idx = txStart; idx < raw->tx.size(); ++idx) {
                uint8_t w = raw->tx[idx];
                if (!upTbl->layout.isHint(w)) continue;
                h[hc++] = w;
                if (hc == 4) {
                    uint8_t b = 0;
                    if (!upTbl->solve4Hints(h, b)) return false;
                    clientRec.push_back(b);
                    hc = 0;
                }
            }
            if (clientRec.size() < 2 + 12 + 16) return false;
            Buffer pskC2S, pskS2C;
            deriveSudokuPSKDirectionalBases(userPub, pskC2S, pskS2C);
            uint32_t cEpoch = readBE32(clientRec.data() + 2);
            Buffer cKey = deriveSudokuEpochKey(pskC2S, "chacha20-poly1305", cEpoch);
            Buffer cHdr(clientRec.begin() + 2, clientRec.begin() + 14);
            Buffer cCipher(clientRec.begin() + 14, clientRec.end());
            Buffer cKip = crypto::open(crypto::AEAD::ChaCha20Poly1305, cKey, cHdr, cCipher, cHdr);
            if (cKip.size() < 6 + 64 || cKip[3] != kKIPTypeClientHello) return false;
            Buffer clientNonce16(cKip.begin() + 6 + 16, cKip.begin() + 6 + 32);
            Buffer clientPub32(cKip.begin() + 6 + 32, cKip.begin() + 6 + 64);

            Buffer srvPriv32, srvPub32;
            generateX25519KeyPair(srvPriv32, srvPub32);
            Buffer shPayload;
            shPayload.insert(shPayload.end(), clientNonce16.begin(), clientNonce16.end());
            shPayload.insert(shPayload.end(), srvPub32.begin(), srvPub32.end());
            appendBE32(shPayload, kKIPFeatureAll);
            Buffer shKip = buildKIPMessage(kKIPTypeServerHello, shPayload);

            Buffer sKey = deriveSudokuEpochKey(pskS2C, "chacha20-poly1305", 1);
            Buffer sHdr;
            appendBE32(sHdr, 1);
            appendBE64(sHdr, 1);
            Buffer sCipher = crypto::seal(crypto::AEAD::ChaCha20Poly1305, sKey, sHdr, shKip, sHdr);
            Buffer sRec;
            appendBE16(sRec, uint16_t(sHdr.size() + sCipher.size()));
            sRec.insert(sRec.end(), sHdr.begin(), sHdr.end());
            sRec.insert(sRec.end(), sCipher.begin(), sCipher.end());

            raw->tx.clear();
            std::string httpRespHdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n";
            Buffer wireResp(httpRespHdr.begin(), httpRespHdr.end());
            Buffer packedSh = packDownlink6Bit(sRec);
            wireResp.insert(wireResp.end(), packedSh.begin(), packedSh.end());
            raw->feedRx(wireResp);
            if (!readyErr.empty() || !readyStream) return false;

            Buffer sharedSecret = computeX25519Shared(srvPriv32, clientPub32);
            Buffer sessC2S, sessS2C;
            deriveSudokuSessionDirectionalBases(userPub, sharedSecret, clientNonce16, sessC2S, sessS2C);
            Buffer sessKey = deriveSudokuEpochKey(sessS2C, "chacha20-poly1305", 2);

            for (uint64_t seq = 1; seq <= 2; ++seq) {
                Buffer appPlain(seq == 1 ? 60 : 73, uint8_t(0x30 + seq));
                Buffer appHdr;
                appendBE32(appHdr, 2);
                appendBE64(appHdr, seq);
                Buffer appCipher = crypto::seal(crypto::AEAD::ChaCha20Poly1305, sessKey, appHdr, appPlain, appHdr);
                Buffer appRec;
                appendBE16(appRec, uint16_t(appHdr.size() + appCipher.size()));
                appRec.insert(appRec.end(), appHdr.begin(), appHdr.end());
                appRec.insert(appRec.end(), appCipher.begin(), appCipher.end());

                raw->feedRx(packDownlink6Bit(appRec));
                Buffer gotPlain;
                Error readErr;
                readyStream->read(1024, [&](Buffer d, bool, Error e) {
                    gotPlain = std::move(d);
                    readErr = e;
                });
                if (!readErr.empty() || gotPlain != appPlain) return false;
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hajimi
