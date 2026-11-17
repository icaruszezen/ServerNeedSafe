package sshmanager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	defaultDialTimeout = 12 * time.Second
	maxJumpHops        = 5
)

// DialTCPFunc abstracts raw TCP transport creation (e.g. blind WebSocket TCP relay in WASM/client mode,
// or direct OS TCP socket in native tests).
type DialTCPFunc func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error)

// HostKeyUntrustedError is returned when connecting to a host whose SSH host key
// is either unknown (under strict ask_new policy) or has changed (MITM protection).
type HostKeyUntrustedError struct {
	Reason               string `json:"reason"` // "unknown" or "mismatch"
	Address              string `json:"address"`
	ServerName           string `json:"server_name"`
	KeyType              string `json:"key_type"`
	PresentedFingerprint string `json:"presented_fingerprint"`
	PresentedPublicKey   string `json:"presented_public_key"`
	ExpectedFingerprint  string `json:"expected_fingerprint,omitempty"`
}

func (e *HostKeyUntrustedError) Error() string {
	if e.Reason == "mismatch" {
		return fmt.Sprintf("警告：服务器 [%s] (%s) 的 SSH 主机密钥指纹发生变化（原指纹 %s，当前 %s），已拦截连接以防范中间人攻击",
			e.ServerName, e.Address, e.ExpectedFingerprint, e.PresentedFingerprint)
	}
	return fmt.Sprintf("首次连接服务器 [%s] (%s)，请核验并信任其 SSH 主机指纹：%s (%s)",
		e.ServerName, e.Address, e.PresentedFingerprint, e.KeyType)
}

// ManagedSSHClient wraps an ssh.Client along with any underlying Jump Host ssh.Clients
// so closing the client cleanly tears down the entire tunnel chain.
type ManagedSSHClient struct {
	*ssh.Client
	Server      *vault.ServerConfig
	Fingerprint string
	closers     []func() error
	closeOnce   sync.Once
}

func (m *ManagedSSHClient) Close() error {
	var firstErr error
	m.closeOnce.Do(func() {
		if m.Client != nil {
			if err := m.Client.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		for i := len(m.closers) - 1; i >= 0; i-- {
			if err := m.closers[i](); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

// Manager coordinates end-to-end client-side SSH dialing, interactive PTY sessions, SFTP operations, and probes.
type Manager struct {
	store          *vault.Store
	dialTCP        DialTCPFunc
	mu             sync.Mutex
	activeSessions map[string]*TerminalSession
}

func NewManager(store *vault.Store) *Manager {
	m := &Manager{
		store:          store,
		activeSessions: make(map[string]*TerminalSession),
	}
	// Automatically terminate all active SSH terminals if the client vault is locked!
	store.RegisterOnLock(func() {
		m.CloseAllSessions()
	})
	return m
}

// SetDialTCPFunc configures a custom raw TCP transport (such as the zero-knowledge WebSocket TCP relay).
func (m *Manager) SetDialTCPFunc(fn DialTCPFunc) {
	m.mu.Lock()
	m.dialTCP = fn
	m.mu.Unlock()
}

func (m *Manager) openRawTCP(addr string, timeout time.Duration) (net.Conn, error) {
	m.mu.Lock()
	fn := m.dialTCP
	m.mu.Unlock()

	if fn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return fn(ctx, addr, timeout)
	}
	return net.DialTimeout("tcp", addr, timeout)
}

// DialOptions customizes dial behavior (e.g. trusting a presented host key fingerprint).
type DialOptions struct {
	TrustFingerprint string // If non-empty and matches presented fingerprint, pins it in KnownHosts
	ClientIP         string
	Timeout          time.Duration
}

// Dial connects to the target server (through any configured JumpHost chain) and verifies host keys end-to-end.
func (m *Manager) Dial(serverID string, opts DialOptions) (*ManagedSSHClient, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultDialTimeout
	}
	visited := make(map[string]bool)
	return m.dialChain(serverID, opts, visited, 0)
}

func (m *Manager) dialChain(serverID string, opts DialOptions, visited map[string]bool, depth int) (*ManagedSSHClient, error) {
	if depth > maxJumpHops {
		return nil, errors.New("SSH 跳板机链路层级超过上限 (最多 5 层)")
	}
	if visited[serverID] {
		return nil, errors.New("检测到循环的 SSH 跳板机配置链路")
	}
	visited[serverID] = true

	srv, err := m.store.GetServerSecret(serverID)
	if err != nil {
		return nil, err
	}

	authMethods, err := m.buildAuthMethods(srv)
	if err != nil {
		return nil, err
	}

	settings, err := m.store.GetSettings()
	if err != nil {
		return nil, err
	}

	targetAddr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	var capturedFingerprint string
	var hostKeyErr error

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		pubB64 := base64.StdEncoding.EncodeToString(key.Marshal())
		capturedFingerprint = fp

		existing, err := m.store.GetKnownHost(targetAddr)
		if err != nil {
			hostKeyErr = err
			return err
		}

		// Explicit user approval for this exact fingerprint
		if opts.TrustFingerprint != "" && opts.TrustFingerprint == fp {
			err := m.store.TrustKnownHost(vault.KnownHost{
				Address:      targetAddr,
				ServerName:   srv.Name,
				KeyType:      key.Type(),
				Fingerprint:  fp,
				PublicKeyB64: pubB64,
			}, opts.ClientIP)
			if err != nil {
				hostKeyErr = err
				return err
			}
			return nil
		}

		if existing != nil {
			if existing.Fingerprint != fp || existing.PublicKeyB64 != pubB64 {
				hkErr := &HostKeyUntrustedError{
					Reason:               "mismatch",
					Address:              targetAddr,
					ServerName:           srv.Name,
					KeyType:              key.Type(),
					PresentedFingerprint: fp,
					PresentedPublicKey:   pubB64,
					ExpectedFingerprint:  existing.Fingerprint,
				}
				hostKeyErr = hkErr
				return hkErr
			}
			m.store.TouchKnownHostVerified(targetAddr)
			return nil
		}

		// Unknown host key
		if settings.HostKeyPolicy == vault.HostKeyTOFU {
			if err := m.store.TrustKnownHost(vault.KnownHost{
				Address:      targetAddr,
				ServerName:   srv.Name,
				KeyType:      key.Type(),
				Fingerprint:  fp,
				PublicKeyB64: pubB64,
			}, opts.ClientIP); err != nil {
				hostKeyErr = err
				return err
			}
			return nil
		}

		hkErr := &HostKeyUntrustedError{
			Reason:               "unknown",
			Address:              targetAddr,
			ServerName:           srv.Name,
			KeyType:              key.Type(),
			PresentedFingerprint: fp,
			PresentedPublicKey:   pubB64,
		}
		hostKeyErr = hkErr
		return hkErr
	}

	sshCfg := &ssh.ClientConfig{
		User:            srv.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         opts.Timeout,
	}

	// Direct TCP (or blind WS-TCP relay) dial if no JumpServerID configured
	if strings.TrimSpace(srv.JumpServerID) == "" {
		rawConn, err := m.openRawTCP(targetAddr, opts.Timeout)
		if err != nil {
			return nil, fmt.Errorf("无法连接到主机 %s: %w", targetAddr, err)
		}
		_ = rawConn.SetDeadline(time.Now().Add(opts.Timeout))
		c, chans, reqs, err := ssh.NewClientConn(rawConn, targetAddr, sshCfg)
		if err != nil {
			_ = rawConn.Close()
			if hostKeyErr != nil {
				return nil, hostKeyErr
			}
			return nil, fmt.Errorf("SSH 握手或认证失败 (%s): %w", targetAddr, err)
		}
		_ = rawConn.SetDeadline(time.Time{})
		return &ManagedSSHClient{
			Client:      ssh.NewClient(c, chans, reqs),
			Server:      srv,
			Fingerprint: capturedFingerprint,
		}, nil
	}

	// Dial via Bastion / Jump Host chain (SSH direct-tcpip inside E2EE tunnel!)
	jumpOpts := opts
	jumpOpts.TrustFingerprint = ""
	jumpClient, err := m.dialChain(srv.JumpServerID, jumpOpts, visited, depth+1)
	if err != nil {
		return nil, fmt.Errorf("连接跳板机失败: %w", err)
	}

	tunneledConn, err := jumpClient.Dial("tcp", targetAddr)
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("通过跳板机转发至 %s 失败: %w", targetAddr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(tunneledConn, targetAddr, sshCfg)
	if err != nil {
		_ = tunneledConn.Close()
		_ = jumpClient.Close()
		if hostKeyErr != nil {
			return nil, hostKeyErr
		}
		return nil, fmt.Errorf("通过跳板机进行 SSH 认证失败 (%s): %w", targetAddr, err)
	}

	return &ManagedSSHClient{
		Client:      ssh.NewClient(c, chans, reqs),
		Server:      srv,
		Fingerprint: capturedFingerprint,
		closers:     []func() error{jumpClient.Close},
	}, nil
}

func (m *Manager) buildAuthMethods(srv *vault.ServerConfig) ([]ssh.AuthMethod, error) {
	switch srv.AuthType {
	case vault.AuthPassword:
		if srv.Password == "" {
			return nil, errors.New("该服务器未配置 SSH 登录密码")
		}
		return passwordAuthMethods(srv.Password), nil

	case vault.AuthPrivateKey:
		if strings.TrimSpace(srv.PrivateKey) == "" {
			return nil, errors.New("该服务器未配置 SSH 私钥")
		}
		signer, err := parsePrivateKeySigner(srv.PrivateKey, srv.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case vault.AuthCredential:
		if srv.CredentialID == "" {
			return nil, errors.New("该服务器未绑定凭据库密钥")
		}
		cred, err := m.store.GetCredentialSecret(srv.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("读取关联加密凭据失败: %w", err)
		}
		if cred.Kind == vault.AuthPassword {
			if cred.Password == "" {
				return nil, errors.New("关联凭据未设置密码")
			}
			return passwordAuthMethods(cred.Password), nil
		}
		signer, err := parsePrivateKeySigner(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	default:
		return nil, fmt.Errorf("未知的 SSH 认证方式: %s", srv.AuthType)
	}
}

func passwordAuthMethods(secret string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(secret),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = secret
			}
			return answers, nil
		}),
	}
}

func parsePrivateKeySigner(pemStr, passphrase string) (ssh.Signer, error) {
	pemBytes := []byte(strings.TrimSpace(pemStr))
	defer vault.ZeroBytes(pemBytes)
	if passphrase != "" {
		passBytes := []byte(passphrase)
		defer vault.ZeroBytes(passBytes)
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, passBytes)
		if err != nil {
			return nil, fmt.Errorf("解析加密 SSH 私钥失败（请检查私钥格式或私钥口令）: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var passMissing *ssh.PassphraseMissingError
		if errors.As(err, &passMissing) {
			return nil, errors.New("该 SSH 私钥受口令保护，请提供私钥口令 (Passphrase)")
		}
		return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
	}
	return signer, nil
}
