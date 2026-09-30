package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

// anyTLSClient embeds the upstream protocol implementation into Lurge's
// static archive.  It is a library object in the App/Helper process, never a
// spawned proxy executable or loopback compatibility listener.
type anyTLSClient struct {
	client *anytls.Client
	cancel context.CancelFunc
}

func createAnyTLS(config bridgeConfig) (bridgeClient, error) {
	if config.Password == "" {
		return nil, errors.New("missing AnyTLS password")
	}
	server := net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port)))
	ctx, cancel := context.WithCancel(context.Background())
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password: config.Password,
		Logger:   logger.NOP(),
		DialOut: func(dialContext context.Context) (net.Conn, error) {
			attempt, attemptCancel := context.WithTimeout(dialContext, 12*time.Second)
			defer attemptCancel()
			raw, err := dialBoundTCP(attempt, server, config.InterfaceName)
			if err != nil {
				return nil, err
			}
			tlsConfig := &tls.Config{
				ServerName: config.SNI, InsecureSkipVerify: config.SkipVerify,
				NextProtos: config.ALPN, MinVersion: tls.VersionTLS12,
			}
			if tlsConfig.ServerName == "" {
				tlsConfig.ServerName = config.Host
			}
			secure := tls.Client(raw, tlsConfig)
			if err = secure.HandshakeContext(attempt); err != nil {
				raw.Close()
				return nil, err
			}
			return secure, nil
		},
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return &anyTLSClient{client: client, cancel: cancel}, nil
}

func (c *anyTLSClient) DialTCP(address string) (io.ReadWriteCloser, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return c.client.CreateProxy(ctx, M.ParseSocksaddrHostPort(host, uint16(port)))
}

func (c *anyTLSClient) DialUDP() (bridgeUDP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	stream, err := c.client.CreateProxy(ctx, uot.RequestDestination(uot.Version))
	if err != nil {
		return nil, err
	}
	request := uot.Request{IsConnect: false,
		Destination: M.ParseSocksaddrHostPort("0.0.0.0", 0)}
	if err = uot.WriteRequest(stream, request); err != nil {
		stream.Close()
		return nil, err
	}
	return &anyTLSUDP{conn: uot.NewConn(stream, request)}, nil
}

func (c *anyTLSClient) Close() error {
	c.cancel()
	return c.client.Close()
}

type anyTLSUDP struct {
	conn       *uot.Conn
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

func (u *anyTLSUDP) Send(data []byte, address string) error {
	u.writeMutex.Lock()
	defer u.writeMutex.Unlock()
	destination := M.ParseSocksaddr(address)
	if !destination.IsValid() {
		return errors.New("invalid AnyTLS UDP destination")
	}
	packet := buf.NewPacket()
	defer packet.Release()
	_, _ = packet.Write(data)
	return u.conn.WritePacket(packet, destination)
}

func (u *anyTLSUDP) Receive() ([]byte, string, error) {
	u.readMutex.Lock()
	defer u.readMutex.Unlock()
	packet := buf.NewSize(65_535)
	defer packet.Release()
	destination, err := u.conn.ReadPacket(packet)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), packet.Bytes()...), destination.String(), nil
}

func (u *anyTLSUDP) Close() error { return u.conn.Close() }
