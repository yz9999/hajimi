package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshBridgeClient struct {
	server        string
	interfaceName string
	config        *ssh.ClientConfig
	mutex         sync.Mutex
	client        *ssh.Client
}

func createSSH(config bridgeConfig) (bridgeClient, error) {
	if config.Username == "" {
		return nil, errors.New("missing SSH username")
	}
	auth := make([]ssh.AuthMethod, 0, 2)
	if config.PrivateKey != "" {
		keyData := []byte(strings.ReplaceAll(config.PrivateKey, `\n`, "\n"))
		if !bytes.Contains(keyData, []byte("PRIVATE KEY")) {
			loaded, err := os.ReadFile(config.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("read SSH private key: %w", err)
			}
			keyData = loaded
		}
		var signer ssh.Signer
		var err error
		if config.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(config.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if config.Password != "" {
		auth = append(auth, ssh.Password(config.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("SSH requires password or private-key")
	}

	hostKeyCallback, err := sshHostKeyCallback(config.HostKeys)
	if err != nil {
		return nil, err
	}
	clientConfig := &ssh.ClientConfig{
		User: config.Username, Auth: auth, HostKeyCallback: hostKeyCallback,
		Timeout: 12 * time.Second, ClientVersion: "SSH-2.0-OpenSSH_9.7",
	}
	if len(config.HostKeyAlgorithms) > 0 {
		clientConfig.HostKeyAlgorithms = config.HostKeyAlgorithms
	}
	return &sshBridgeClient{
		server:        net.JoinHostPort(config.Host, fmt.Sprint(config.Port)),
		interfaceName: config.InterfaceName, config: clientConfig,
	}, nil
}

func sshHostKeyCallback(values []string) (ssh.HostKeyCallback, error) {
	if len(values) == 0 {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	keys := make([]ssh.PublicKey, 0, len(values))
	fingerprints := make(map[string]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "SHA256:") {
			fingerprints[value] = struct{}{}
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(value))
		if err != nil {
			return nil, fmt.Errorf("parse SSH host-key: %w", err)
		}
		keys = append(keys, key)
	}
	return func(_ string, _ net.Addr, actual ssh.PublicKey) error {
		if _, ok := fingerprints[ssh.FingerprintSHA256(actual)]; ok {
			return nil
		}
		for _, key := range keys {
			if bytes.Equal(key.Marshal(), actual.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("SSH host key mismatch: %s", ssh.FingerprintSHA256(actual))
	}, nil
}

func (c *sshBridgeClient) connect() (*ssh.Client, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	raw, err := dialBoundTCP(ctx, c.server, c.interfaceName)
	if err != nil {
		return nil, err
	}
	connection, channels, requests, err := ssh.NewClientConn(raw, c.server, c.config)
	if err != nil {
		raw.Close()
		return nil, err
	}
	client := ssh.NewClient(connection, channels, requests)
	c.client = client
	go func() {
		_ = client.Wait()
		c.mutex.Lock()
		if c.client == client {
			c.client = nil
		}
		c.mutex.Unlock()
	}()
	return client, nil
}

func (c *sshBridgeClient) DialTCP(address string) (io.ReadWriteCloser, error) {
	client, err := c.connect()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return client.DialContext(ctx, "tcp", address)
}

func (c *sshBridgeClient) DialUDP() (bridgeUDP, error) {
	return nil, errors.New("SSH native outbound does not provide UDP relay")
}

func (c *sshBridgeClient) Close() error {
	c.mutex.Lock()
	client := c.client
	c.client = nil
	c.mutex.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}
