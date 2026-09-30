package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/apernet/quic-go"
)

type hysteria1Client struct {
	conn       *quic.Conn
	packetConn net.PacketConn
	control    *quic.Stream
	cancel     context.CancelFunc
	nextPacket atomic.Uint32
	mutex      sync.RWMutex
	udp        map[uint32]*hysteria1UDP
}

type hysteria1UDP struct {
	client    *hysteria1Client
	id        uint32
	hold      *quic.Stream
	receive   chan hysteria1ReceivedPacket
	closeOnce sync.Once
	mutex     sync.Mutex
	fragments map[uint16]*hysteria1Fragments
}

type hysteria1ReceivedPacket struct {
	data    []byte
	address string
}
type hysteria1Fragments struct {
	parts    [][]byte
	address  string
	received int
}

func newHysteria1Client(config bridgeConfig) (bridgeClient, error) {
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))))
	if err != nil {
		return nil, err
	}
	base, err := listenBoundUDP(remote, config.InterfaceName)
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn = base
	if config.Obfs != "" {
		packetConn = newXPlusPacketConn(base, []byte(config.Obfs))
	}
	alpn := "hysteria"
	if len(config.ALPN) > 0 {
		alpn = config.ALPN[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	conn, err := quic.Dial(ctx, packetConn, remote, &tls.Config{
		NextProtos: []string{alpn}, ServerName: config.SNI,
		InsecureSkipVerify: config.SkipVerify, MinVersion: tls.VersionTLS13,
	}, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 60 * time.Second,
		KeepAlivePeriod: 20 * time.Second, EnableDatagrams: true,
		MaxDatagramFrameSize: 1200, InitialStreamReceiveWindow: 16 << 20,
		MaxStreamReceiveWindow: 16 << 20, InitialConnectionReceiveWindow: 40 << 20,
		MaxConnectionReceiveWindow: 40 << 20,
	})
	cancel()
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	control, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	hello := make([]byte, 19+len(config.Auth))
	hello[0] = 3
	binary.BigEndian.PutUint64(hello[1:9], config.Up)
	binary.BigEndian.PutUint64(hello[9:17], config.Down)
	if len(config.Auth) > 65535 {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, errors.New("Hysteria auth too long")
	}
	binary.BigEndian.PutUint16(hello[17:19], uint16(len(config.Auth)))
	copy(hello[19:], config.Auth)
	if _, err = control.Write(hello); err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	response := make([]byte, 19)
	if _, err = io.ReadFull(control, response); err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	messageLength := int(binary.BigEndian.Uint16(response[17:19]))
	message := make([]byte, messageLength)
	if _, err = io.ReadFull(control, message); err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	if response[0] == 0 {
		conn.CloseWithError(2, "auth error")
		packetConn.Close()
		return nil, fmt.Errorf("Hysteria authentication failed: %s", message)
	}
	background, backgroundCancel := context.WithCancel(context.Background())
	client := &hysteria1Client{conn: conn, packetConn: packetConn, control: control,
		cancel: backgroundCancel, udp: make(map[uint32]*hysteria1UDP)}
	client.nextPacket.Store(uint32(time.Now().UnixNano()))
	go client.receiveDatagrams(background)
	return client, nil
}

func (c *hysteria1Client) DialTCP(address string) (io.ReadWriteCloser, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	stream, sessionID, err := c.openRequest(false, host, uint16(port))
	_ = sessionID
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (c *hysteria1Client) DialUDP() (bridgeUDP, error) {
	stream, sessionID, err := c.openRequest(true, "", 0)
	if err != nil {
		return nil, err
	}
	value := &hysteria1UDP{client: c, id: sessionID, hold: stream,
		receive:   make(chan hysteria1ReceivedPacket, 1024),
		fragments: make(map[uint16]*hysteria1Fragments)}
	c.mutex.Lock()
	if _, exists := c.udp[sessionID]; exists {
		c.mutex.Unlock()
		stream.Close()
		return nil, errors.New("duplicate Hysteria UDP session")
	}
	c.udp[sessionID] = value
	c.mutex.Unlock()
	return value, nil
}

func (c *hysteria1Client) openRequest(udp bool, host string, port uint16) (*quic.Stream, uint32, error) {
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, 0, err
	}
	if len(host) > 65535 {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, errors.New("target host too long")
	}
	request := make([]byte, 5+len(host))
	if udp {
		request[0] = 1
	}
	binary.BigEndian.PutUint16(request[1:3], uint16(len(host)))
	copy(request[3:3+len(host)], host)
	binary.BigEndian.PutUint16(request[3+len(host):], port)
	if _, err = stream.Write(request); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, err
	}
	response := make([]byte, 7)
	if _, err = io.ReadFull(stream, response); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, err
	}
	messageLength := int(binary.BigEndian.Uint16(response[5:7]))
	message := make([]byte, messageLength)
	if _, err = io.ReadFull(stream, message); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, err
	}
	if response[0] == 0 {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, 0, fmt.Errorf("Hysteria connection rejected: %s", message)
	}
	return stream, binary.BigEndian.Uint32(response[1:5]), nil
}

func (c *hysteria1Client) Close() error {
	c.cancel()
	_ = c.control.Close()
	c.mutex.Lock()
	values := make([]*hysteria1UDP, 0, len(c.udp))
	for _, value := range c.udp {
		values = append(values, value)
	}
	c.udp = make(map[uint32]*hysteria1UDP)
	c.mutex.Unlock()
	for _, value := range values {
		value.closeLocal()
	}
	err := c.conn.CloseWithError(0, "")
	_ = c.packetConn.Close()
	return err
}

func (c *hysteria1Client) receiveDatagrams(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(data) < 14 {
			continue
		}
		sessionID := binary.BigEndian.Uint32(data[0:4])
		hostLength := int(binary.BigEndian.Uint16(data[4:6]))
		offset := 6 + hostLength
		if hostLength == 0 || offset+8 > len(data) {
			continue
		}
		host := string(data[6:offset])
		port := binary.BigEndian.Uint16(data[offset : offset+2])
		packetID := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		fragmentID, fragmentTotal := data[offset+4], data[offset+5]
		length := int(binary.BigEndian.Uint16(data[offset+6 : offset+8]))
		offset += 8
		if fragmentTotal == 0 || fragmentID >= fragmentTotal || len(data) != offset+length {
			continue
		}
		c.mutex.RLock()
		value := c.udp[sessionID]
		c.mutex.RUnlock()
		if value != nil {
			value.feed(packetID, fragmentTotal, fragmentID,
				net.JoinHostPort(host, strconv.Itoa(int(port))), append([]byte(nil), data[offset:]...))
		}
	}
}

func (u *hysteria1UDP) Send(data []byte, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return err
	}
	if len(host) == 0 || len(host) > 65535 {
		return errors.New("invalid Hysteria UDP host")
	}
	headerSize := 14 + len(host)
	capacity := 1200 - headerSize
	if capacity <= 0 {
		return errors.New("Hysteria UDP address too large")
	}
	count := (len(data) + capacity - 1) / capacity
	if count == 0 {
		count = 1
	}
	if count > 255 {
		return errors.New("Hysteria UDP packet too large")
	}
	packetID := uint16(0)
	if count > 1 {
		packetID = uint16(u.client.nextPacket.Add(1))
		if packetID == 0 {
			packetID = uint16(u.client.nextPacket.Add(1))
		}
	}
	for index := 0; index < count; index++ {
		start, end := index*capacity, (index+1)*capacity
		if start > len(data) {
			start = len(data)
		}
		if end > len(data) {
			end = len(data)
		}
		part := data[start:end]
		message := make([]byte, headerSize, headerSize+len(part))
		binary.BigEndian.PutUint32(message[0:4], u.id)
		binary.BigEndian.PutUint16(message[4:6], uint16(len(host)))
		copy(message[6:6+len(host)], host)
		offset := 6 + len(host)
		binary.BigEndian.PutUint16(message[offset:offset+2], uint16(port))
		binary.BigEndian.PutUint16(message[offset+2:offset+4], packetID)
		message[offset+4], message[offset+5] = uint8(index), uint8(count)
		binary.BigEndian.PutUint16(message[offset+6:offset+8], uint16(len(part)))
		message = append(message, part...)
		if err := u.client.conn.SendDatagram(message); err != nil {
			return err
		}
	}
	return nil
}

func (u *hysteria1UDP) Receive() ([]byte, string, error) {
	value, ok := <-u.receive
	if !ok {
		return nil, "", io.EOF
	}
	return value.data, value.address, nil
}

func (u *hysteria1UDP) Close() error {
	u.closeOnce.Do(func() {
		u.client.mutex.Lock()
		delete(u.client.udp, u.id)
		u.client.mutex.Unlock()
		_ = u.hold.Close()
		u.closeLocal()
	})
	return nil
}

func (u *hysteria1UDP) closeLocal() {
	defer func() { _ = recover() }()
	close(u.receive)
}

func (u *hysteria1UDP) feed(packetID uint16, total, index uint8, address string, data []byte) {
	if total == 1 {
		select {
		case u.receive <- hysteria1ReceivedPacket{data: data, address: address}:
		default:
		}
		return
	}
	u.mutex.Lock()
	value := u.fragments[packetID]
	if value == nil || len(value.parts) != int(total) {
		value = &hysteria1Fragments{parts: make([][]byte, int(total)), address: address}
		u.fragments[packetID] = value
	}
	if value.parts[index] == nil {
		value.parts[index] = data
		value.received++
	}
	if value.received == int(total) {
		var result []byte
		for _, part := range value.parts {
			result = append(result, part...)
		}
		delete(u.fragments, packetID)
		target := value.address
		u.mutex.Unlock()
		select {
		case u.receive <- hysteria1ReceivedPacket{data: result, address: target}:
		default:
		}
		return
	}
	if len(u.fragments) > 64 {
		u.fragments = make(map[uint16]*hysteria1Fragments)
	}
	u.mutex.Unlock()
}

type xPlusPacketConn struct {
	conn        *net.UDPConn
	key         []byte
	random      *rand.Rand
	mutex       sync.Mutex
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
	readBuffer  []byte
	writeBuffer []byte
}

func newXPlusPacketConn(conn *net.UDPConn, key []byte) net.PacketConn {
	return &xPlusPacketConn{conn: conn, key: append([]byte(nil), key...),
		random:     rand.New(rand.NewSource(time.Now().UnixNano())),
		readBuffer: make([]byte, 4096), writeBuffer: make([]byte, 4096)}
}

func (c *xPlusPacketConn) ReadFrom(output []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.conn.ReadFrom(c.readBuffer)
		if n <= 16 {
			c.readMutex.Unlock()
			if err != nil {
				return 0, addr, err
			}
			continue
		}
		length := n - 16
		if len(output) < length {
			c.readMutex.Unlock()
			return 0, addr, io.ErrShortBuffer
		}
		input := make([]byte, len(c.key)+16)
		copy(input, c.key)
		copy(input[len(c.key):], c.readBuffer[:16])
		hash := sha256.Sum256(input)
		for i, value := range c.readBuffer[16:n] {
			output[i] = value ^ hash[i%sha256.Size]
		}
		c.readMutex.Unlock()
		return length, addr, err
	}
}

func (c *xPlusPacketConn) WriteTo(input []byte, addr net.Addr) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if len(input)+16 > len(c.writeBuffer) {
		return 0, errors.New("obfuscated QUIC packet too large")
	}
	c.mutex.Lock()
	_, _ = c.random.Read(c.writeBuffer[:16])
	c.mutex.Unlock()
	keyInput := make([]byte, len(c.key)+16)
	copy(keyInput, c.key)
	copy(keyInput[len(c.key):], c.writeBuffer[:16])
	hash := sha256.Sum256(keyInput)
	for i, value := range input {
		c.writeBuffer[i+16] = value ^ hash[i%sha256.Size]
	}
	_, err := c.conn.WriteTo(c.writeBuffer[:len(input)+16], addr)
	if err != nil {
		return 0, err
	}
	return len(input), nil
}

func (c *xPlusPacketConn) Close() error                          { return c.conn.Close() }
func (c *xPlusPacketConn) LocalAddr() net.Addr                   { return c.conn.LocalAddr() }
func (c *xPlusPacketConn) SetDeadline(t time.Time) error         { return c.conn.SetDeadline(t) }
func (c *xPlusPacketConn) SetReadDeadline(t time.Time) error     { return c.conn.SetReadDeadline(t) }
func (c *xPlusPacketConn) SetWriteDeadline(t time.Time) error    { return c.conn.SetWriteDeadline(t) }
func (c *xPlusPacketConn) SetReadBuffer(size int) error          { return c.conn.SetReadBuffer(size) }
func (c *xPlusPacketConn) SetWriteBuffer(size int) error         { return c.conn.SetWriteBuffer(size) }
func (c *xPlusPacketConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }
