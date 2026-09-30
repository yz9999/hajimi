package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	snellMaxFrame = 0x3fff
	snellSaltSize = 16
)

type snellClient struct {
	config bridgeConfig
}

func createSnell(config bridgeConfig) (bridgeClient, error) {
	if config.PSK == "" {
		return nil, errors.New("missing Snell psk")
	}
	if config.Version == 0 {
		config.Version = 4
	}
	if config.Version == 5 {
		config.Version = 4
	}
	if config.Version < 1 || config.Version > 4 {
		return nil, fmt.Errorf("unsupported Snell version %d", config.Version)
	}
	return &snellClient{config: config}, nil
}

func (c *snellClient) open() (*snellReplyConn, error) {
	ctx, cancel := contextWithTimeout()
	defer cancel()
	server := net.JoinHostPort(c.config.Host, strconv.Itoa(int(c.config.Port)))
	raw, err := dialBoundTCP(ctx, server, c.config.InterfaceName)
	if err != nil {
		return nil, err
	}
	var encrypted snellFrameConn
	if c.config.Version >= 4 {
		encrypted = newSnellV4Conn(raw, []byte(c.config.PSK))
	} else {
		encrypted = newSnellAEADConn(raw, []byte(c.config.PSK), c.config.Version)
	}
	return &snellReplyConn{snellFrameConn: encrypted}, nil
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 12*time.Second)
}

func (c *snellClient) DialTCP(address string) (io.ReadWriteCloser, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid Snell target host")
	}
	conn, err := c.open()
	if err != nil {
		return nil, err
	}
	command := byte(1)
	if c.config.Version == 2 {
		command = 5
	}
	header := []byte{1, command, 0, byte(len(host))}
	header = append(header, host...)
	header = binary.BigEndian.AppendUint16(header, uint16(port))
	if _, err = conn.Write(header); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *snellClient) DialUDP() (bridgeUDP, error) {
	if c.config.Version < 3 {
		return nil, errors.New("Snell v1/v2 do not support UDP")
	}
	conn, err := c.open()
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write([]byte{1, 6, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	if c.config.Version >= 4 {
		if err = conn.readReply(); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return &snellUDP{conn: conn}, nil
}

func (c *snellClient) Close() error { return nil }

type snellFrameConn interface {
	net.Conn
	WritePacketFrame([]byte) (int, error)
}

type snellReplyConn struct {
	snellFrameConn
	replyMutex sync.Mutex
	replied    bool
}

func (c *snellReplyConn) readReply() error {
	c.replyMutex.Lock()
	defer c.replyMutex.Unlock()
	if c.replied {
		return nil
	}
	var command [1]byte
	if _, err := io.ReadFull(c.snellFrameConn, command[:]); err != nil {
		return err
	}
	if command[0] == 0 {
		c.replied = true
		return nil
	}
	if command[0] != 2 {
		return fmt.Errorf("unsupported Snell reply command %d", command[0])
	}
	var detail [2]byte
	if _, err := io.ReadFull(c.snellFrameConn, detail[:]); err != nil {
		return err
	}
	message := make([]byte, int(detail[1]))
	if _, err := io.ReadFull(c.snellFrameConn, message); err != nil {
		return err
	}
	return fmt.Errorf("Snell server error %d: %s", detail[0], string(message))
}

func (c *snellReplyConn) Read(value []byte) (int, error) {
	if err := c.readReply(); err != nil {
		return 0, err
	}
	return c.snellFrameConn.Read(value)
}

type snellUDP struct {
	conn       *snellReplyConn
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

func (u *snellUDP) Send(payload []byte, address string) error {
	u.writeMutex.Lock()
	defer u.writeMutex.Unlock()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return err
	}
	packet := []byte{1}
	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("invalid Snell UDP domain")
		}
		packet = append(packet, byte(len(host)))
		packet = append(packet, host...)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		packet = append(packet, 0, 4)
		packet = append(packet, ipv4...)
	} else {
		packet = append(packet, 0, 6)
		packet = append(packet, ip.To16()...)
	}
	packet = binary.BigEndian.AppendUint16(packet, uint16(port))
	packet = append(packet, payload...)
	if len(packet) > snellMaxFrame {
		return errors.New("Snell UDP packet too large")
	}
	_, err = u.conn.WritePacketFrame(packet)
	return err
}

func (u *snellUDP) Receive() ([]byte, string, error) {
	u.readMutex.Lock()
	defer u.readMutex.Unlock()
	buffer := make([]byte, snellMaxFrame)
	n, err := u.conn.Read(buffer)
	if err != nil {
		return nil, "", err
	}
	buffer = buffer[:n]
	if len(buffer) < 1 {
		return nil, "", errors.New("empty Snell UDP response")
	}
	var host string
	var offset int
	switch buffer[0] {
	case 4:
		if len(buffer) < 7 {
			return nil, "", errors.New("invalid Snell UDP IPv4 response")
		}
		host, offset = net.IP(buffer[1:5]).String(), 5
	case 6:
		if len(buffer) < 19 {
			return nil, "", errors.New("invalid Snell UDP IPv6 response")
		}
		host, offset = net.IP(buffer[1:17]).String(), 17
	default:
		return nil, "", errors.New("invalid Snell UDP response address")
	}
	port := binary.BigEndian.Uint16(buffer[offset : offset+2])
	return append([]byte(nil), buffer[offset+2:]...), net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (u *snellUDP) Close() error { return u.conn.Close() }

// Snell v1-v3 use the Shadowsocks AEAD record layout with an Argon2id key.
type snellAEADConn struct {
	net.Conn
	psk        []byte
	version    int
	reader     *snellAEADReader
	writer     *snellAEADWriter
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

func newSnellAEADConn(conn net.Conn, psk []byte, version int) *snellAEADConn {
	return &snellAEADConn{Conn: conn, psk: psk, version: version}
}

func snellAEAD(psk, salt []byte, version int) (cipher.AEAD, error) {
	key := argon2.IDKey(psk, salt, 3, 8, 1, 32)
	if version == 1 {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *snellAEADConn) Read(value []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.reader == nil {
		salt := make([]byte, snellSaltSize)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		aead, err := snellAEAD(c.psk, salt, c.version)
		if err != nil {
			return 0, err
		}
		c.reader = &snellAEADReader{source: c.Conn, aead: aead}
	}
	return c.reader.Read(value)
}

func (c *snellAEADConn) Write(value []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	return c.writer.Write(value)
}

func (c *snellAEADConn) WritePacketFrame(value []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	if err := c.writer.writeFrame(value); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (c *snellAEADConn) ensureWriter() error {
	if c.writer != nil {
		return nil
	}
	salt := make([]byte, snellSaltSize)
	if _, err := cryptorand.Read(salt); err != nil {
		return err
	}
	aead, err := snellAEAD(c.psk, salt, c.version)
	if err != nil {
		return err
	}
	if err = writeFull(c.Conn, salt); err != nil {
		return err
	}
	c.writer = &snellAEADWriter{target: c.Conn, aead: aead}
	return nil
}

type snellAEADWriter struct {
	target io.Writer
	aead   cipher.AEAD
	nonce  [12]byte
}

func (w *snellAEADWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, w.writeFrame(nil)
	}
	written := 0
	for written < len(value) {
		end := written + snellMaxFrame
		if end > len(value) {
			end = len(value)
		}
		if err := w.writeFrame(value[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *snellAEADWriter) writeFrame(payload []byte) error {
	if len(payload) > snellMaxFrame {
		return errors.New("Snell frame too large")
	}
	length := []byte{byte(len(payload) >> 8), byte(len(payload))}
	frame := w.aead.Seal(nil, w.nonce[:w.aead.NonceSize()], length, nil)
	incrementLittleEndian(w.nonce[:w.aead.NonceSize()])
	frame = w.aead.Seal(frame, w.nonce[:w.aead.NonceSize()], payload, nil)
	incrementLittleEndian(w.nonce[:w.aead.NonceSize()])
	return writeFull(w.target, frame)
}

type snellAEADReader struct {
	source io.Reader
	aead   cipher.AEAD
	nonce  [12]byte
	buffer []byte
}

func (r *snellAEADReader) Read(value []byte) (int, error) {
	if len(r.buffer) == 0 {
		header := make([]byte, 2+r.aead.Overhead())
		if _, err := io.ReadFull(r.source, header); err != nil {
			return 0, err
		}
		plain, err := r.aead.Open(nil, r.nonce[:r.aead.NonceSize()], header, nil)
		incrementLittleEndian(r.nonce[:r.aead.NonceSize()])
		if err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(plain)) & snellMaxFrame
		if length == 0 {
			return 0, io.EOF
		}
		ciphertext := make([]byte, length+r.aead.Overhead())
		if _, err = io.ReadFull(r.source, ciphertext); err != nil {
			return 0, err
		}
		r.buffer, err = r.aead.Open(nil, r.nonce[:r.aead.NonceSize()], ciphertext, nil)
		incrementLittleEndian(r.nonce[:r.aead.NonceSize()])
		if err != nil {
			return 0, err
		}
	}
	n := copy(value, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}

// Snell v4 uses independent encrypted frame headers and randomized first
// packet padding.  v5 servers remain wire-compatible with this v4 client.
type snellV4Conn struct {
	net.Conn
	psk        []byte
	reader     *snellV4Reader
	writer     *snellV4Writer
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

func newSnellV4Conn(conn net.Conn, psk []byte) *snellV4Conn {
	return &snellV4Conn{Conn: conn, psk: psk}
}

func snellV4AEAD(psk, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(psk, salt, 3, 8, 1, 32)
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *snellV4Conn) Read(value []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.reader == nil {
		salt := make([]byte, snellSaltSize)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		aead, err := snellV4AEAD(c.psk, salt)
		if err != nil {
			return 0, err
		}
		c.reader = &snellV4Reader{source: c.Conn, aead: aead}
	}
	return c.reader.Read(value)
}

func (c *snellV4Conn) Write(value []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	return c.writer.Write(value)
}

func (c *snellV4Conn) WritePacketFrame(value []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.ensureWriter(); err != nil {
		return 0, err
	}
	if err := c.writer.writeFrame(value, c.writer.nextPadding(len(value))); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (c *snellV4Conn) ensureWriter() error {
	if c.writer != nil {
		return nil
	}
	salt := make([]byte, snellSaltSize)
	if _, err := cryptorand.Read(salt); err != nil {
		return err
	}
	aead, err := snellV4AEAD(c.psk, salt)
	if err != nil {
		return err
	}
	delta, err := cryptorand.Int(cryptorand.Reader, big.NewInt(256))
	if err != nil {
		return err
	}
	c.writer = &snellV4Writer{target: c.Conn, aead: aead, salt: salt,
		initialPadding: 256 + int(delta.Int64())}
	return nil
}

type snellV4Writer struct {
	target         io.Writer
	aead           cipher.AEAD
	nonce          [12]byte
	salt           []byte
	saltSent       bool
	initialPadding int
}

func (w *snellV4Writer) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, w.writeFrame(nil, 0)
	}
	written := 0
	for written < len(value) {
		limit := snellMaxFrame
		if !w.saltSent {
			limit = 1460 - 55 - w.initialPadding
		}
		if limit < 1 {
			limit = 1
		}
		end := written + limit
		if end > len(value) {
			end = len(value)
		}
		if err := w.writeFrame(value[written:end], w.nextPadding(end-written)); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *snellV4Writer) nextPadding(payloadLength int) int {
	if w.saltSent || payloadLength == 0 {
		return 0
	}
	return w.initialPadding
}

func (w *snellV4Writer) writeFrame(payload []byte, paddingLength int) error {
	if len(payload) > snellMaxFrame || paddingLength > snellMaxFrame {
		return errors.New("Snell v4 frame too large")
	}
	header := make([]byte, 7)
	header[0] = 4
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLength))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	frame := make([]byte, 0, snellSaltSize+len(header)+32+paddingLength+len(payload))
	if !w.saltSent {
		frame = append(frame, w.salt...)
	}
	frame = w.aead.Seal(frame, w.nonce[:], header, nil)
	incrementLittleEndian(w.nonce[:])
	var payloadCipher []byte
	if len(payload) > 0 {
		payloadCipher = w.aead.Seal(nil, w.nonce[:], payload, nil)
		incrementLittleEndian(w.nonce[:])
	}
	if paddingLength > 0 {
		padding := make([]byte, paddingLength)
		if _, err := cryptorand.Read(padding); err != nil {
			return err
		}
		swapSnellPadding(padding, payloadCipher)
		frame = append(frame, padding...)
	}
	frame = append(frame, payloadCipher...)
	w.saltSent = true
	return writeFull(w.target, frame)
}

type snellV4Reader struct {
	source io.Reader
	aead   cipher.AEAD
	nonce  [12]byte
	buffer []byte
}

func (r *snellV4Reader) Read(value []byte) (int, error) {
	if len(r.buffer) == 0 {
		headerCipher := make([]byte, 7+r.aead.Overhead())
		if _, err := io.ReadFull(r.source, headerCipher); err != nil {
			return 0, err
		}
		header, err := r.aead.Open(nil, r.nonce[:], headerCipher, nil)
		incrementLittleEndian(r.nonce[:])
		if err != nil {
			return 0, err
		}
		if len(header) != 7 || header[0] != 4 {
			return 0, errors.New("invalid Snell v4 frame")
		}
		paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
		payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
		if payloadLength == 0 {
			return 0, io.EOF
		}
		if payloadLength > snellMaxFrame || paddingLength > snellMaxFrame {
			return 0, errors.New("Snell v4 frame too large")
		}
		frame := make([]byte, paddingLength+payloadLength+r.aead.Overhead())
		if _, err = io.ReadFull(r.source, frame); err != nil {
			return 0, err
		}
		if paddingLength > 0 {
			swapSnellPadding(frame[:paddingLength], frame[paddingLength:])
		}
		r.buffer, err = r.aead.Open(nil, r.nonce[:], frame[paddingLength:], nil)
		incrementLittleEndian(r.nonce[:])
		if err != nil {
			return 0, err
		}
	}
	n := copy(value, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}

func swapSnellPadding(padding, payload []byte) {
	limit := len(padding)
	if len(payload) < limit {
		limit = len(payload)
	}
	for index := 0; index < limit; index += 2 {
		padding[index], payload[index] = payload[index], padding[index]
	}
}

func incrementLittleEndian(value []byte) {
	for index := range value {
		value[index]++
		if value[index] != 0 {
			return
		}
	}
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		value = value[count:]
	}
	return nil
}
