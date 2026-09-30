package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	hy2 "github.com/apernet/hysteria/core/v2/client"
	newobfs "github.com/apernet/hysteria/extras/v2/obfs"
)

type bridgeConfig struct {
	Type                 string   `json:"type"`
	Host                 string   `json:"host"`
	Port                 uint16   `json:"port"`
	SNI                  string   `json:"sni"`
	ALPN                 []string `json:"alpn"`
	SkipVerify           bool     `json:"skip_verify"`
	Auth                 string   `json:"auth"`
	UUID                 string   `json:"uuid"`
	Password             string   `json:"password"`
	Username             string   `json:"username"`
	PrivateKey           string   `json:"private_key"`
	PrivateKeyPassphrase string   `json:"private_key_passphrase"`
	HostKeys             []string `json:"host_keys"`
	HostKeyAlgorithms    []string `json:"host_key_algorithms"`
	PSK                  string   `json:"psk"`
	Version              int      `json:"version"`
	Obfs                 string   `json:"obfs"`
	ObfsPassword         string   `json:"obfs_password"`
	Congestion           string   `json:"congestion"`
	BBRProfile           string   `json:"bbr_profile"`
	Up                   uint64   `json:"up"`
	Down                 uint64   `json:"down"`
	InterfaceName        string   `json:"interface_name"`
}

type bridgeClient interface {
	DialTCP(string) (io.ReadWriteCloser, error)
	DialUDP() (bridgeUDP, error)
	Close() error
}

type bridgeUDP interface {
	Send([]byte, string) error
	Receive() ([]byte, string, error)
	Close() error
}

type hy2Client struct{ client hy2.Client }
type hy2UDP struct{ conn hy2.HyUDPConn }

func (c *hy2Client) DialTCP(addr string) (io.ReadWriteCloser, error) { return c.client.TCP(addr) }
func (c *hy2Client) DialUDP() (bridgeUDP, error) {
	value, err := c.client.UDP()
	if err != nil {
		return nil, err
	}
	return &hy2UDP{conn: value}, nil
}
func (c *hy2Client) Close() error                     { return c.client.Close() }
func (u *hy2UDP) Send(data []byte, addr string) error { return u.conn.Send(data, addr) }
func (u *hy2UDP) Receive() ([]byte, string, error)    { return u.conn.Receive() }
func (u *hy2UDP) Close() error                        { return u.conn.Close() }

type handleTable struct {
	sync.RWMutex
	next  atomic.Uint64
	items map[uint64]any
}

var handles = handleTable{items: make(map[uint64]any)}

func addHandle(value any) uint64 {
	id := handles.next.Add(1)
	handles.Lock()
	handles.items[id] = value
	handles.Unlock()
	return id
}

func getHandle(id uint64) any {
	handles.RLock()
	value := handles.items[id]
	handles.RUnlock()
	return value
}

func takeHandle(id uint64) any {
	handles.Lock()
	value := handles.items[id]
	delete(handles.items, id)
	handles.Unlock()
	return value
}

func setError(target **C.char, err error) {
	if target == nil {
		return
	}
	if err == nil {
		*target = nil
	} else {
		*target = C.CString(err.Error())
	}
}

func createClient(config bridgeConfig) (bridgeClient, error) {
	if config.Host == "" || config.Port == 0 {
		return nil, errors.New("missing native protocol server")
	}
	switch config.Type {
	case "hysteria":
		return createHY1(config)
	case "hysteria2":
		return createHY2(config)
	case "tuic":
		return createTUIC(config)
	case "anytls":
		return createAnyTLS(config)
	case "snell":
		return createSnell(config)
	case "ssh":
		return createSSH(config)
	default:
		return nil, fmt.Errorf("unsupported native protocol %q", config.Type)
	}
}

func dialBoundTCP(ctx context.Context, address, interfaceName string) (net.Conn, error) {
	dialer := net.Dialer{}
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, err
		}
		dialer.Control = func(network, address string, raw syscall.RawConn) error {
			var controlErr error
			err := raw.Control(func(fd uintptr) {
				if network == "tcp6" {
					controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 125, iface.Index)
				} else {
					controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, iface.Index)
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		}
	}
	return dialer.DialContext(ctx, "tcp", address)
}

func createHY1(config bridgeConfig) (bridgeClient, error) {
	return newHysteria1Client(config)
}

type hy2ConnFactory struct {
	interfaceName string
	obfsPassword  string
}

func (f *hy2ConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		resolved, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return nil, err
		}
		udpAddr = resolved
	}
	conn, err := listenBoundUDP(udpAddr, f.interfaceName)
	if err != nil {
		return nil, err
	}
	if f.obfsPassword == "" {
		return conn, nil
	}
	return newobfs.WrapPacketConnSalamander(conn, []byte(f.obfsPassword))
}

func createHY2(config bridgeConfig) (bridgeClient, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))))
	if err != nil {
		return nil, err
	}
	congestion := config.Congestion
	if congestion == "" {
		congestion = "bbr"
	}
	client, _, err := hy2.NewClient(&hy2.Config{
		ConnFactory: &hy2ConnFactory{interfaceName: config.InterfaceName, obfsPassword: config.ObfsPassword},
		ServerAddr:  addr, Auth: config.Auth,
		TLSConfig:        hy2.TLSConfig{ServerName: config.SNI, InsecureSkipVerify: config.SkipVerify},
		CongestionConfig: hy2.CongestionConfig{Type: congestion, BBRProfile: config.BBRProfile},
		BandwidthConfig:  hy2.BandwidthConfig{MaxTx: config.Up, MaxRx: config.Down},
	})
	if err != nil {
		return nil, err
	}
	return &hy2Client{client: client}, nil
}

func listenBoundUDP(remote *net.UDPAddr, interfaceName string) (*net.UDPConn, error) {
	network := "udp4"
	address := "0.0.0.0:0"
	if remote.IP != nil && remote.IP.To4() == nil {
		network, address = "udp6", "[::]:0"
	}
	listenConfig := net.ListenConfig{}
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, err
		}
		listenConfig.Control = func(network, address string, raw syscall.RawConn) error {
			var controlErr error
			err := raw.Control(func(fd uintptr) {
				if remote.IP != nil && remote.IP.To4() == nil {
					controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 125, iface.Index)
				} else {
					controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, iface.Index)
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		}
	}
	packet, err := listenConfig.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	conn, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, errors.New("unexpected UDP socket type")
	}
	return conn, nil
}

//export LurgeQUICClientCreate
func LurgeQUICClientCreate(configJSON *C.char, errorOut **C.char) C.uintptr_t {
	if configJSON == nil {
		setError(errorOut, errors.New("missing QUIC config"))
		return 0
	}
	var config bridgeConfig
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &config); err != nil {
		setError(errorOut, err)
		return 0
	}
	client, err := createClient(config)
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	setError(errorOut, nil)
	return C.uintptr_t(addHandle(client))
}

//export LurgeQUICClientClose
func LurgeQUICClientClose(handle C.uintptr_t) {
	if value, ok := takeHandle(uint64(handle)).(bridgeClient); ok {
		_ = value.Close()
	}
}

//export LurgeQUICTCPConnect
func LurgeQUICTCPConnect(handle C.uintptr_t, host *C.char, port C.uint16_t,
	errorOut **C.char) C.uintptr_t {
	client, ok := getHandle(uint64(handle)).(bridgeClient)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC client handle"))
		return 0
	}
	if host == nil {
		setError(errorOut, errors.New("missing target host"))
		return 0
	}
	stream, err := client.DialTCP(net.JoinHostPort(C.GoString(host), strconv.Itoa(int(port))))
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	setError(errorOut, nil)
	return C.uintptr_t(addHandle(stream))
}

//export LurgeQUICStreamRead
func LurgeQUICStreamRead(handle C.uintptr_t, buffer unsafe.Pointer, capacity C.int,
	errorOut **C.char) C.longlong {
	stream, ok := getHandle(uint64(handle)).(io.ReadWriteCloser)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC stream handle"))
		return -1
	}
	if buffer == nil || capacity <= 0 {
		setError(errorOut, errors.New("invalid read buffer"))
		return -1
	}
	value := make([]byte, int(capacity))
	n, err := stream.Read(value)
	if n > 0 {
		C.memcpy(buffer, unsafe.Pointer(&value[0]), C.size_t(n))
	}
	if err != nil && !errors.Is(err, io.EOF) {
		setError(errorOut, err)
		return -1
	}
	setError(errorOut, nil)
	return C.longlong(n)
}

//export LurgeQUICStreamWrite
func LurgeQUICStreamWrite(handle C.uintptr_t, buffer unsafe.Pointer, length C.int,
	errorOut **C.char) C.longlong {
	stream, ok := getHandle(uint64(handle)).(io.ReadWriteCloser)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC stream handle"))
		return -1
	}
	if length < 0 || (length > 0 && buffer == nil) {
		setError(errorOut, errors.New("invalid write buffer"))
		return -1
	}
	value := C.GoBytes(buffer, length)
	n, err := stream.Write(value)
	if err != nil {
		setError(errorOut, err)
		return -1
	}
	setError(errorOut, nil)
	return C.longlong(n)
}

//export LurgeQUICStreamClose
func LurgeQUICStreamClose(handle C.uintptr_t) {
	if value, ok := takeHandle(uint64(handle)).(io.ReadWriteCloser); ok {
		_ = value.Close()
	}
}

//export LurgeQUICUDPCreate
func LurgeQUICUDPCreate(handle C.uintptr_t, errorOut **C.char) C.uintptr_t {
	client, ok := getHandle(uint64(handle)).(bridgeClient)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC client handle"))
		return 0
	}
	value, err := client.DialUDP()
	if err != nil {
		setError(errorOut, err)
		return 0
	}
	setError(errorOut, nil)
	return C.uintptr_t(addHandle(value))
}

//export LurgeQUICUDPSend
func LurgeQUICUDPSend(handle C.uintptr_t, host *C.char, port C.uint16_t,
	buffer unsafe.Pointer, length C.int, errorOut **C.char) C.int {
	value, ok := getHandle(uint64(handle)).(bridgeUDP)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC UDP handle"))
		return -1
	}
	if host == nil || length < 0 || (length > 0 && buffer == nil) {
		setError(errorOut, errors.New("invalid UDP send arguments"))
		return -1
	}
	err := value.Send(C.GoBytes(buffer, length), net.JoinHostPort(C.GoString(host), strconv.Itoa(int(port))))
	if err != nil {
		setError(errorOut, err)
		return -1
	}
	setError(errorOut, nil)
	return 0
}

//export LurgeQUICUDPReceive
func LurgeQUICUDPReceive(handle C.uintptr_t, buffer unsafe.Pointer, capacity C.int,
	hostBuffer *C.char, hostCapacity C.int, portOut *C.uint16_t, errorOut **C.char) C.longlong {
	value, ok := getHandle(uint64(handle)).(bridgeUDP)
	if !ok {
		setError(errorOut, errors.New("invalid QUIC UDP handle"))
		return -1
	}
	data, address, err := value.Receive()
	if err != nil {
		setError(errorOut, err)
		return -1
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		setError(errorOut, err)
		return -1
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		setError(errorOut, err)
		return -1
	}
	if len(data) > int(capacity) || len(host)+1 > int(hostCapacity) || buffer == nil || hostBuffer == nil || portOut == nil {
		setError(errorOut, errors.New("UDP receive buffer too small"))
		return -1
	}
	if len(data) > 0 {
		C.memcpy(buffer, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}
	hostBytes := append([]byte(host), 0)
	C.memcpy(unsafe.Pointer(hostBuffer), unsafe.Pointer(&hostBytes[0]), C.size_t(len(hostBytes)))
	*portOut = C.uint16_t(port)
	setError(errorOut, nil)
	return C.longlong(len(data))
}

//export LurgeQUICUDPClose
func LurgeQUICUDPClose(handle C.uintptr_t) {
	if value, ok := takeHandle(uint64(handle)).(bridgeUDP); ok {
		_ = value.Close()
	}
}

//export LurgeQUICFreeCString
func LurgeQUICFreeCString(value *C.char) { C.free(unsafe.Pointer(value)) }

func main() {}
