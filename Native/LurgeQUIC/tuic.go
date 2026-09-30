package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/google/uuid"
)

type tuicClient struct {
	conn       *quic.Conn
	packetConn net.PacketConn
	cancel     context.CancelFunc
	nextAssoc  atomic.Uint32
	nextPacket atomic.Uint32
	mutex      sync.RWMutex
	udp        map[uint16]*tuicUDP
}

type tuicUDP struct {
	client    *tuicClient
	id        uint16
	receive   chan tuicReceivedPacket
	closeOnce sync.Once
	mutex     sync.Mutex
	fragments map[uint16]*tuicFragments
}

type tuicReceivedPacket struct {
	data    []byte
	address string
}
type tuicFragments struct {
	parts    [][]byte
	address  string
	received int
}

func createTUIC(config bridgeConfig) (bridgeClient, error) {
	userID, err := uuid.Parse(config.UUID)
	if err != nil {
		return nil, fmt.Errorf("invalid TUIC UUID: %w", err)
	}
	if config.Password == "" {
		return nil, errors.New("missing TUIC password")
	}
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))))
	if err != nil {
		return nil, err
	}
	packetConn, err := listenBoundUDP(remote, config.InterfaceName)
	if err != nil {
		return nil, err
	}
	alpn := config.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	tlsConfig := &tls.Config{ServerName: config.SNI, InsecureSkipVerify: config.SkipVerify,
		NextProtos: alpn, MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	conn, err := quic.Dial(ctx, packetConn, remote, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 60 * time.Second,
		KeepAlivePeriod: 10 * time.Second, EnableDatagrams: true,
		MaxDatagramFrameSize: 1200, InitialStreamReceiveWindow: 8 << 20,
		MaxStreamReceiveWindow: 16 << 20, InitialConnectionReceiveWindow: 16 << 20,
		MaxConnectionReceiveWindow: 64 << 20,
	})
	cancel()
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	state := conn.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(string(userID[:]), []byte(config.Password), 32)
	if err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	auth, err := conn.OpenUniStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	command := make([]byte, 0, 50)
	command = append(command, 0x05, 0x00)
	command = append(command, userID[:]...)
	command = append(command, token...)
	if _, err = auth.Write(command); err == nil {
		err = auth.Close()
	}
	if err != nil {
		conn.CloseWithError(0, "")
		packetConn.Close()
		return nil, err
	}
	background, backgroundCancel := context.WithCancel(context.Background())
	client := &tuicClient{conn: conn, packetConn: packetConn, cancel: backgroundCancel,
		udp: make(map[uint16]*tuicUDP)}
	client.nextAssoc.Store(uint32(time.Now().UnixNano()))
	client.nextPacket.Store(uint32(time.Now().UnixNano() >> 16))
	go client.receiveDatagrams(background)
	go client.heartbeat(background)
	return client, nil
}

func (c *tuicClient) DialTCP(address string) (io.ReadWriteCloser, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	header, err := encodeTUICAddress(host, uint16(port))
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	command := append([]byte{0x05, 0x01}, header...)
	if _, err = stream.Write(command); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	return stream, nil
}

func (c *tuicClient) DialUDP() (bridgeUDP, error) {
	for attempts := 0; attempts < 65535; attempts++ {
		id := uint16(c.nextAssoc.Add(1))
		if id == 0 {
			continue
		}
		c.mutex.Lock()
		if _, exists := c.udp[id]; !exists {
			value := &tuicUDP{client: c, id: id, receive: make(chan tuicReceivedPacket, 1024),
				fragments: make(map[uint16]*tuicFragments)}
			c.udp[id] = value
			c.mutex.Unlock()
			return value, nil
		}
		c.mutex.Unlock()
	}
	return nil, errors.New("TUIC association IDs exhausted")
}

func (c *tuicClient) Close() error {
	c.cancel()
	c.mutex.Lock()
	values := make([]*tuicUDP, 0, len(c.udp))
	for _, value := range c.udp {
		values = append(values, value)
	}
	c.udp = make(map[uint16]*tuicUDP)
	c.mutex.Unlock()
	for _, value := range values {
		value.closeLocal()
	}
	err := c.conn.CloseWithError(0, "")
	_ = c.packetConn.Close()
	return err
}

func (c *tuicClient) receiveDatagrams(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		c.handlePacket(data)
	}
}

func (c *tuicClient) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.conn.SendDatagram([]byte{0x05, 0x04})
		}
	}
}

func (c *tuicClient) handlePacket(data []byte) {
	if len(data) < 11 || data[0] != 0x05 || data[1] != 0x02 {
		return
	}
	assocID := binary.BigEndian.Uint16(data[2:4])
	packetID := binary.BigEndian.Uint16(data[4:6])
	fragmentTotal, fragmentID := data[6], data[7]
	size := int(binary.BigEndian.Uint16(data[8:10]))
	host, port, offset, hasAddress, ok := decodeTUICAddress(data, 10)
	if !ok || fragmentTotal == 0 || fragmentID >= fragmentTotal || len(data) != offset+size {
		return
	}
	c.mutex.RLock()
	value := c.udp[assocID]
	c.mutex.RUnlock()
	if value == nil {
		return
	}
	value.feed(packetID, fragmentTotal, fragmentID, host, port, hasAddress,
		append([]byte(nil), data[offset:]...))
}

func (u *tuicUDP) Send(data []byte, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return err
	}
	encodedAddress, err := encodeTUICAddress(host, uint16(portValue))
	if err != nil {
		return err
	}
	firstCapacity := 1200 - 10 - len(encodedAddress)
	laterCapacity := 1200 - 11
	if firstCapacity <= 0 {
		return errors.New("TUIC address too large")
	}
	parts := make([][]byte, 0, 2)
	if len(data) == 0 {
		parts = append(parts, nil)
	}
	for offset := 0; offset < len(data); {
		capacity := laterCapacity
		if len(parts) == 0 {
			capacity = firstCapacity
		}
		end := offset + capacity
		if end > len(data) {
			end = len(data)
		}
		parts = append(parts, data[offset:end])
		offset = end
	}
	if len(parts) > 255 {
		return errors.New("TUIC UDP packet too large")
	}
	packetID := uint16(u.client.nextPacket.Add(1))
	if packetID == 0 {
		packetID = uint16(u.client.nextPacket.Add(1))
	}
	for index, part := range parts {
		command := make([]byte, 10, 10+len(encodedAddress)+len(part))
		command[0], command[1] = 0x05, 0x02
		binary.BigEndian.PutUint16(command[2:4], u.id)
		binary.BigEndian.PutUint16(command[4:6], packetID)
		command[6], command[7] = uint8(len(parts)), uint8(index)
		binary.BigEndian.PutUint16(command[8:10], uint16(len(part)))
		if index == 0 {
			command = append(command, encodedAddress...)
		} else {
			command = append(command, 0xff)
		}
		command = append(command, part...)
		if err := u.client.conn.SendDatagram(command); err != nil {
			return err
		}
	}
	return nil
}

func (u *tuicUDP) Receive() ([]byte, string, error) {
	value, ok := <-u.receive
	if !ok {
		return nil, "", io.EOF
	}
	return value.data, value.address, nil
}

func (u *tuicUDP) Close() error {
	u.closeOnce.Do(func() {
		u.client.mutex.Lock()
		delete(u.client.udp, u.id)
		u.client.mutex.Unlock()
		u.closeLocal()
		if stream, err := u.client.conn.OpenUniStream(); err == nil {
			command := []byte{0x05, 0x03, byte(u.id >> 8), byte(u.id)}
			_, _ = stream.Write(command)
			_ = stream.Close()
		}
	})
	return nil
}

func (u *tuicUDP) closeLocal() {
	defer func() { _ = recover() }()
	close(u.receive)
}

func (u *tuicUDP) feed(packetID uint16, total, index uint8, host string, port uint16,
	hasAddress bool, data []byte) {
	if total == 1 {
		if !hasAddress {
			return
		}
		select {
		case u.receive <- tuicReceivedPacket{data: data, address: net.JoinHostPort(host, strconv.Itoa(int(port)))}:
		default:
		}
		return
	}
	u.mutex.Lock()
	value := u.fragments[packetID]
	if value == nil || len(value.parts) != int(total) {
		value = &tuicFragments{parts: make([][]byte, int(total))}
		u.fragments[packetID] = value
	}
	if value.parts[index] == nil {
		value.parts[index] = data
		value.received++
	}
	if index == 0 && hasAddress {
		value.address = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if value.received == int(total) && value.address != "" {
		var result []byte
		for _, part := range value.parts {
			result = append(result, part...)
		}
		delete(u.fragments, packetID)
		address := value.address
		u.mutex.Unlock()
		select {
		case u.receive <- tuicReceivedPacket{data: result, address: address}:
		default:
		}
		return
	}
	if len(u.fragments) > 64 {
		u.fragments = make(map[uint16]*tuicFragments)
	}
	u.mutex.Unlock()
}

func encodeTUICAddress(host string, port uint16) ([]byte, error) {
	host = stripIPv6Brackets(host)
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			result := append([]byte{0x01}, ipv4...)
			return binary.BigEndian.AppendUint16(result, port), nil
		}
		ipv6 := ip.To16()
		result := append([]byte{0x02}, ipv6...)
		return binary.BigEndian.AppendUint16(result, port), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid TUIC domain")
	}
	result := []byte{0x00, byte(len(host))}
	result = append(result, host...)
	return binary.BigEndian.AppendUint16(result, port), nil
}

func decodeTUICAddress(data []byte, offset int) (string, uint16, int, bool, bool) {
	if offset >= len(data) {
		return "", 0, offset, false, false
	}
	switch data[offset] {
	case 0xff:
		return "", 0, offset + 1, false, true
	case 0x00:
		if offset+2 > len(data) {
			return "", 0, offset, false, false
		}
		length := int(data[offset+1])
		end := offset + 2 + length
		if length == 0 || end+2 > len(data) {
			return "", 0, offset, false, false
		}
		return string(data[offset+2 : end]), binary.BigEndian.Uint16(data[end : end+2]), end + 2, true, true
	case 0x01:
		if offset+7 > len(data) {
			return "", 0, offset, false, false
		}
		return net.IP(data[offset+1 : offset+5]).String(), binary.BigEndian.Uint16(data[offset+5 : offset+7]), offset + 7, true, true
	case 0x02:
		if offset+19 > len(data) {
			return "", 0, offset, false, false
		}
		return net.IP(data[offset+1 : offset+17]).String(), binary.BigEndian.Uint16(data[offset+17 : offset+19]), offset + 19, true, true
	default:
		return "", 0, offset, false, false
	}
}

func stripIPv6Brackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}
