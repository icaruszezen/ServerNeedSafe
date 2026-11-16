package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxAuditEntries = 500

var (
	ErrNotFound     = errors.New("目标记录不存在")
	ErrInvalidInput = errors.New("输入参数不合法")
)

// Store manages the in-memory lifecycle and atomic encrypted disk persistence of vault.sns.
type Store struct {
	mu           sync.RWMutex
	filePath     string
	dek          []byte
	header       *EnvelopeHeader
	state        *VaultState
	unlockedAt   time.Time
	lastActivity time.Time
	onLockHooks  []func()

	// Allow overriding KDF cost in fast unit tests if needed while keeping production defaults strict
	kdfTime      uint32
	kdfMemoryKiB uint32
	kdfThreads   uint8
}

// NewStore creates a Store pointing to vaultFilePath (e.g. /data/vault.sns).
func NewStore(vaultFilePath string) (*Store, error) {
	dir := filepath.Dir(vaultFilePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	return &Store{
		filePath:     vaultFilePath,
		kdfTime:      defaultKDFTime,
		kdfMemoryKiB: defaultKDFMemoryKiB,
		kdfThreads:   defaultKDFThreads,
	}, nil
}

// RegisterOnLock registers a callback invoked whenever the vault transitions to locked state.
func (s *Store) RegisterOnLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onLockHooks = append(s.onLockHooks, fn)
}

func (s *Store) fileExistsLocked() bool {
	info, err := os.Stat(s.filePath)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// Status returns the current lifecycle status of the vault.
func (s *Store) Status() VaultStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.fileExistsLocked() {
		return StatusUninitialized
	}
	if len(s.dek) == 0 || s.state == nil {
		return StatusLocked
	}
	return StatusUnlocked
}

// FilePath returns the encrypted vault file path.
func (s *Store) FilePath() string {
	return s.filePath
}

// Setup initializes a brand-new encrypted vault protected by password.
func (s *Store) Setup(password, clientIP string) error {
	if len([]rune(password)) < 8 {
		return ErrWeakPassword
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fileExistsLocked() {
		return ErrVaultAlreadyInit
	}

	salt, err := randomBytes(kdfSaltSize)
	if err != nil {
		return err
	}
	dek, err := randomBytes(dekSize)
	if err != nil {
		return err
	}

	hdr := &EnvelopeHeader{
		KDFAlgo:      "argon2id",
		KDFTime:      s.kdfTime,
		KDFMemoryKiB: s.kdfMemoryKiB,
		KDFThreads:   s.kdfThreads,
		KDFSalt:      salt,
	}
	kek, err := deriveKEK(password, hdr)
	if err != nil {
		zeroBytes(dek)
		return err
	}
	err = wrapDEK(kek, dek, hdr)
	zeroBytes(kek)
	if err != nil {
		zeroBytes(dek)
		return err
	}

	initialState := DefaultVaultState()
	appendAuditLocked(initialState, "vault.setup", "vault.sns", "初始化管理员密码与零知识加密保险库", clientIP, true)

	if err := s.persistStateLocked(dek, hdr, initialState); err != nil {
		zeroBytes(dek)
		return err
	}

	s.dek = dek
	s.state = initialState
	now := time.Now().UTC()
	s.unlockedAt = now
	s.lastActivity = now
	return nil
}

// UnlockOrVerify cryptographically verifies the Admin Password against the encrypted vault.
// If locked, it decrypts and loads the vault into memory.
// If already unlocked in memory, it still verifies the password against the wrapped DEK on disk.
func (s *Store) UnlockOrVerify(password, clientIP string) error {
	if password == "" {
		return ErrInvalidPassword
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.fileExistsLocked() {
		return ErrVaultNotInit
	}

	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("read vault file: %w", err)
	}

	// Case 1: Already unlocked in memory — verify password cryptographically against header wrapped DEK
	if len(s.dek) == dekSize && s.state != nil {
		_, hdr, _, err := parseVaultContainer(raw)
		if err != nil {
			return err
		}
		candidateDEK, err := unwrapDEK(password, hdr)
		if err != nil {
			appendAuditLocked(s.state, "vault.verify_failed", "session", "管理员密码验证失败", clientIP, false)
			_ = s.saveLocked()
			return ErrInvalidPassword
		}
		matched := constantTimeEqual(candidateDEK, s.dek)
		zeroBytes(candidateDEK)
		if !matched {
			appendAuditLocked(s.state, "vault.verify_failed", "session", "管理员密码密钥校验不匹配", clientIP, false)
			_ = s.saveLocked()
			return ErrInvalidPassword
		}
		s.lastActivity = time.Now().UTC()
		appendAuditLocked(s.state, "vault.session_auth", "session", "通过管理员密码验证建立新会话", clientIP, true)
		_ = s.saveLocked()
		return nil
	}

	// Case 2: Currently locked — full container authentication + decryption
	dek, hdr, state, err := openVaultContainer(raw, password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	s.dek = dek
	s.header = hdr
	s.state = state
	s.unlockedAt = now
	s.lastActivity = now

	appendAuditLocked(s.state, "vault.unlock", "vault.sns", "管理员密码验证通过，解密加载保险库", clientIP, true)
	return s.saveLocked()
}

// Lock wipes the in-memory DEK and decrypted sensitive buffers, returning the vault to locked state.
func (s *Store) Lock(reason, clientIP string) {
	s.mu.Lock()
	if len(s.dek) > 0 && s.state != nil {
		if reason != "" {
			appendAuditLocked(s.state, "vault.lock", "vault.sns", reason, clientIP, true)
			_ = s.saveLocked()
		}
		scrubStateSecrets(s.state)
		zeroBytes(s.dek)
	}
	s.dek = nil
	s.state = nil
	s.header = nil
	hooks := slices.Clone(s.onLockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
}

func scrubStateSecrets(st *VaultState) {
	if st == nil {
		return
	}
	for i := range st.Servers {
		st.Servers[i].Password = ""
		st.Servers[i].PrivateKey = ""
		st.Servers[i].Passphrase = ""
	}
	for i := range st.Credentials {
		st.Credentials[i].Password = ""
		st.Credentials[i].PrivateKey = ""
		st.Credentials[i].Passphrase = ""
	}
}

// TouchActivity refreshes the idle auto-lock timer.
func (s *Store) TouchActivity() {
	s.mu.Lock()
	if s.state != nil {
		s.lastActivity = time.Now().UTC()
	}
	s.mu.Unlock()
}

// CheckAutoLock locks the vault if AutoLockMinutes > 0 and inactivity exceeds threshold.
func (s *Store) CheckAutoLock() bool {
	s.mu.RLock()
	if len(s.dek) == 0 || s.state == nil {
		s.mu.RUnlock()
		return false
	}
	mins := s.state.Settings.AutoLockMinutes
	last := s.lastActivity
	s.mu.RUnlock()

	if mins <= 0 {
		return false
	}
	if time.Since(last) >= time.Duration(mins)*time.Minute {
		s.Lock(fmt.Sprintf("超过 %d 分钟无操作自动锁定保险库", mins), "system")
		return true
	}
	return false
}

// ChangePassword verifies oldPassword, rotates both the Argon2id salt and master DEK,
// and atomically re-encrypts the entire vault file.
func (s *Store) ChangePassword(oldPassword, newPassword, clientIP string) error {
	if len([]rune(newPassword)) < 8 {
		return ErrWeakPassword
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dek) == 0 || s.state == nil || s.header == nil {
		return ErrVaultLocked
	}

	// Cryptographically verify oldPassword against current wrapped DEK
	verifiedDEK, err := unwrapDEK(oldPassword, s.header)
	if err != nil {
		appendAuditLocked(s.state, "vault.password_change_failed", "vault.sns", "修改管理员密码失败：原密码错误", clientIP, false)
		_ = s.saveLocked()
		return ErrInvalidPassword
	}
	matched := constantTimeEqual(verifiedDEK, s.dek)
	zeroBytes(verifiedDEK)
	if !matched {
		return ErrInvalidPassword
	}

	newSalt, err := randomBytes(kdfSaltSize)
	if err != nil {
		return err
	}
	newDEK, err := randomBytes(dekSize)
	if err != nil {
		return err
	}

	newHdr := &EnvelopeHeader{
		KDFAlgo:      "argon2id",
		KDFTime:      s.kdfTime,
		KDFMemoryKiB: s.kdfMemoryKiB,
		KDFThreads:   s.kdfThreads,
		KDFSalt:      newSalt,
	}
	newKEK, err := deriveKEK(newPassword, newHdr)
	if err != nil {
		zeroBytes(newDEK)
		return err
	}
	err = wrapDEK(newKEK, newDEK, newHdr)
	zeroBytes(newKEK)
	if err != nil {
		zeroBytes(newDEK)
		return err
	}

	appendAuditLocked(s.state, "vault.password_changed", "vault.sns", "管理员密码已更新并完成主密钥轮换重加密", clientIP, true)

	if err := s.persistStateLocked(newDEK, newHdr, s.state); err != nil {
		zeroBytes(newDEK)
		return err
	}

	zeroBytes(s.dek)
	s.dek = newDEK
	s.lastActivity = time.Now().UTC()
	return nil
}

// ExportEncryptedBytes reads the raw encrypted vault.sns container for backup download.
func (s *Store) ExportEncryptedBytes(clientIP string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dek) == 0 || s.state == nil {
		return nil, ErrVaultLocked
	}
	appendAuditLocked(s.state, "vault.export", "vault.sns", "导出加密数据包备份", clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return os.ReadFile(s.filePath)
}

// ImportEncryptedVault validates an uploaded .sns backup file using its Admin Password,
// atomically writes it to disk, and loads the decrypted state into memory.
func (s *Store) ImportEncryptedVault(raw []byte, password, clientIP string) error {
	dek, hdr, state, err := openVaultContainer(raw, password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	appendAuditLocked(state, "vault.import", "vault.sns", "导入并验证加密备份数据包", clientIP, true)
	if err := s.persistStateLocked(dek, hdr, state); err != nil {
		zeroBytes(dek)
		return err
	}

	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	s.dek = dek
	s.state = state
	now := time.Now().UTC()
	s.unlockedAt = now
	s.lastActivity = now
	return nil
}

// EncryptionInfo returns non-sensitive cryptographic metadata about the active vault.
func (s *Store) EncryptionInfo() (*EncryptionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hdr *EnvelopeHeader
	var size int64
	if info, err := os.Stat(s.filePath); err == nil {
		size = info.Size()
	}
	if s.header != nil {
		hdr = s.header
	} else if s.fileExistsLocked() {
		raw, err := os.ReadFile(s.filePath)
		if err == nil {
			_, parsed, _, parseErr := parseVaultContainer(raw)
			if parseErr == nil {
				hdr = parsed
			}
		}
	}
	if hdr == nil {
		return &EncryptionInfo{
			FormatVersion: int(vaultFormatVersion),
			KDFAlgo:       "argon2id",
			KDFTime:       s.kdfTime,
			KDFMemoryKiB:  s.kdfMemoryKiB,
			KDFThreads:    s.kdfThreads,
			WrapAlgo:      "aes-256-gcm",
			CipherAlgo:    "xchacha20-poly1305",
		}, nil
	}
	return &EncryptionInfo{
		FormatVersion:  int(vaultFormatVersion),
		KDFAlgo:        hdr.KDFAlgo,
		KDFTime:        hdr.KDFTime,
		KDFMemoryKiB:   hdr.KDFMemoryKiB,
		KDFThreads:     hdr.KDFThreads,
		WrapAlgo:       hdr.WrapAlgo,
		CipherAlgo:     hdr.CipherAlgo,
		VaultSizeBytes: size,
	}, nil
}

func (s *Store) saveLocked() error {
	if len(s.dek) == 0 || s.header == nil || s.state == nil {
		return ErrVaultLocked
	}
	return s.persistStateLocked(s.dek, s.header, s.state)
}

func (s *Store) persistStateLocked(dek []byte, baseHdr *EnvelopeHeader, state *VaultState) error {
	state.UpdatedAt = time.Now().UTC()
	containerBytes, updatedHdr, err := sealVaultContainer(dek, baseHdr, state)
	if err != nil {
		return err
	}

	tmpPath := s.filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp vault file: %w", err)
	}
	if _, err := f.Write(containerBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp vault file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp vault file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename vault file: %w", err)
	}
	s.header = updatedHdr
	return nil
}

func appendAuditLocked(state *VaultState, action, target, detail, clientIP string, success bool) {
	entry := AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  clientIP,
		Success:   success,
	}
	state.AuditLogs = append([]AuditEntry{entry}, state.AuditLogs...)
	if len(state.AuditLogs) > maxAuditEntries {
		state.AuditLogs = state.AuditLogs[:maxAuditEntries]
	}
}

// RecordAudit logs an event inside the encrypted vault.
func (s *Store) RecordAudit(action, target, detail, clientIP string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dek) == 0 || s.state == nil {
		return
	}
	appendAuditLocked(s.state, action, target, detail, clientIP, success)
	_ = s.saveLocked()
}

// --- Servers CRUD ---

func (s *Store) ListServers() ([]ServerView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	out := make([]ServerView, len(s.state.Servers))
	for i, srv := range s.state.Servers {
		out[i] = srv.ToView()
	}
	return out, nil
}

// GetServerSecret returns a deep copy of ServerConfig including decrypted credentials for internal SSH dialing.
func (s *Store) GetServerSecret(id string) (*ServerConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, srv := range s.state.Servers {
		if srv.ID == id {
			cp := srv
			cp.Tags = slices.Clone(srv.Tags)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// ServerMutationInput represents create/update request fields for an SSH server.
type ServerMutationInput struct {
	Name          string   `json:"name"`
	Group         string   `json:"group"`
	Tags          []string `json:"tags"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Username      string   `json:"username"`
	AuthType      AuthType `json:"auth_type"`
	Password      *string  `json:"password,omitempty"`    // nil = keep existing on update
	PrivateKey    *string  `json:"private_key,omitempty"` // nil = keep existing on update
	Passphrase    *string  `json:"passphrase,omitempty"`  // nil = keep existing on update
	CredentialID  string   `json:"credential_id"`
	JumpServerID  string   `json:"jump_server_id"`
	DefaultPath   string   `json:"default_path"`
	Notes         string   `json:"notes"`
	Pinned        bool     `json:"pinned"`
	KeepAliveSec  int      `json:"keep_alive_sec"`
}

func sanitizeServerInput(in *ServerMutationInput) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	in.Group = strings.TrimSpace(in.Group)
	if in.Group == "" {
		in.Group = "默认分组"
	}
	if in.Port <= 0 || in.Port > 65535 {
		in.Port = 22
	}
	if in.KeepAliveSec <= 0 {
		in.KeepAliveSec = 30
	}
	if in.Name == "" || in.Host == "" || in.Username == "" {
		return fmt.Errorf("%w: 服务器名称、主机地址与用户名不能为空", ErrInvalidInput)
	}
	switch in.AuthType {
	case AuthPassword, AuthPrivateKey, AuthCredential:
	default:
		return fmt.Errorf("%w: 不支持的认证类型 %s", ErrInvalidInput, in.AuthType)
	}
	cleanTags := make([]string, 0, len(in.Tags))
	for _, t := range in.Tags {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" && !slices.Contains(cleanTags, trimmed) {
			cleanTags = append(cleanTags, trimmed)
		}
	}
	in.Tags = cleanTags
	return nil
}

func (s *Store) CreateServer(in ServerMutationInput, clientIP string) (*ServerView, error) {
	if err := sanitizeServerInput(&in); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	now := time.Now().UTC()
	srv := ServerConfig{
		ID:           uuid.NewString(),
		Name:         in.Name,
		Group:        in.Group,
		Tags:         in.Tags,
		Host:         in.Host,
		Port:         in.Port,
		Username:     in.Username,
		AuthType:     in.AuthType,
		CredentialID: in.CredentialID,
		JumpServerID: in.JumpServerID,
		DefaultPath:  strings.TrimSpace(in.DefaultPath),
		Notes:        strings.TrimSpace(in.Notes),
		Pinned:       in.Pinned,
		KeepAliveSec: in.KeepAliveSec,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if in.Password != nil {
		srv.Password = *in.Password
	}
	if in.PrivateKey != nil {
		srv.PrivateKey = *in.PrivateKey
	}
	if in.Passphrase != nil {
		srv.Passphrase = *in.Passphrase
	}

	if !slices.Contains(s.state.Groups, srv.Group) {
		s.state.Groups = append(s.state.Groups, srv.Group)
	}

	s.state.Servers = append(s.state.Servers, srv)
	appendAuditLocked(s.state, "server.create", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "新增服务器资产配置", clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	view := srv.ToView()
	return &view, nil
}

func (s *Store) UpdateServer(id string, in ServerMutationInput, clientIP string) (*ServerView, error) {
	if err := sanitizeServerInput(&in); err != nil {
		return nil, err
	}
	if in.JumpServerID == id {
		return nil, fmt.Errorf("%w: 跳板机不能指向服务器自身", ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	idx := -1
	for i := range s.state.Servers {
		if s.state.Servers[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotFound
	}

	srv := s.state.Servers[idx]
	srv.Name = in.Name
	srv.Group = in.Group
	srv.Tags = in.Tags
	srv.Host = in.Host
	srv.Port = in.Port
	srv.Username = in.Username
	srv.AuthType = in.AuthType
	srv.CredentialID = in.CredentialID
	srv.JumpServerID = in.JumpServerID
	srv.DefaultPath = strings.TrimSpace(in.DefaultPath)
	srv.Notes = strings.TrimSpace(in.Notes)
	srv.Pinned = in.Pinned
	srv.KeepAliveSec = in.KeepAliveSec
	srv.UpdatedAt = time.Now().UTC()

	if in.Password != nil {
		srv.Password = *in.Password
	}
	if in.PrivateKey != nil {
		srv.PrivateKey = *in.PrivateKey
	}
	if in.Passphrase != nil {
		srv.Passphrase = *in.Passphrase
	}

	if !slices.Contains(s.state.Groups, srv.Group) {
		s.state.Groups = append(s.state.Groups, srv.Group)
	}

	s.state.Servers[idx] = srv
	appendAuditLocked(s.state, "server.update", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "更新服务器连接配置", clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	view := srv.ToView()
	return &view, nil
}

func (s *Store) DeleteServer(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	for i, srv := range s.state.Servers {
		if srv.ID == id {
			s.state.Servers = slices.Delete(s.state.Servers, i, i+1)
			// Clear jump references pointing to deleted server
			for j := range s.state.Servers {
				if s.state.Servers[j].JumpServerID == id {
					s.state.Servers[j].JumpServerID = ""
				}
			}
			appendAuditLocked(s.state, "server.delete", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "删除服务器配置", clientIP, true)
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) UpdateServerRuntimeMeta(id string, latencyMs int64, osInfo string, connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	for i := range s.state.Servers {
		if s.state.Servers[i].ID == id {
			if latencyMs > 0 {
				s.state.Servers[i].LastLatencyMs = latencyMs
			}
			if osInfo != "" {
				s.state.Servers[i].LastOSInfo = osInfo
			}
			if connected {
				now := time.Now().UTC()
				s.state.Servers[i].LastConnectedAt = &now
			}
			_ = s.saveLocked()
			return
		}
	}
}

// --- Groups Management ---

func (s *Store) ListGroups() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.Groups), nil
}

func (s *Store) AddGroup(name string) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	if !slices.Contains(s.state.Groups, name) {
		s.state.Groups = append(s.state.Groups, name)
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return slices.Clone(s.state.Groups), nil
}

func (s *Store) DeleteGroup(name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	s.state.Groups = slices.DeleteFunc(s.state.Groups, func(g string) bool { return g == name })
	for i := range s.state.Servers {
		if s.state.Servers[i].Group == name {
			s.state.Servers[i].Group = "默认分组"
		}
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return slices.Clone(s.state.Groups), nil
}

// --- Credentials / Keychain CRUD ---

type CredentialMutationInput struct {
	Name         string   `json:"name"`
	Kind         AuthType `json:"kind"`
	UsernameHint string   `json:"username_hint"`
	Password     *string  `json:"password,omitempty"`
	PrivateKey   *string  `json:"private_key,omitempty"`
	Passphrase   *string  `json:"passphrase,omitempty"`
	PublicKey    string   `json:"public_key"`
	Fingerprint  string   `json:"fingerprint"`
	KeyAlgorithm string   `json:"key_algorithm"`
	Notes        string   `json:"notes"`
}

func (s *Store) ListCredentials() ([]CredentialView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	out := make([]CredentialView, len(s.state.Credentials))
	for i, c := range s.state.Credentials {
		out[i] = c.ToView()
	}
	return out, nil
}

func (s *Store) GetCredentialSecret(id string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, c := range s.state.Credentials {
		if c.ID == id {
			cp := c
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) CreateCredential(in CredentialMutationInput, clientIP string) (*CredentialView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || (in.Kind != AuthPassword && in.Kind != AuthPrivateKey) {
		return nil, fmt.Errorf("%w: 凭据名称与类型不合法", ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	now := time.Now().UTC()
	cred := Credential{
		ID:           uuid.NewString(),
		Name:         in.Name,
		Kind:         in.Kind,
		UsernameHint: strings.TrimSpace(in.UsernameHint),
		PublicKey:    strings.TrimSpace(in.PublicKey),
		Fingerprint:  strings.TrimSpace(in.Fingerprint),
		KeyAlgorithm: strings.TrimSpace(in.KeyAlgorithm),
		Notes:        strings.TrimSpace(in.Notes),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if in.Password != nil {
		cred.Password = *in.Password
	}
	if in.PrivateKey != nil {
		cred.PrivateKey = *in.PrivateKey
	}
	if in.Passphrase != nil {
		cred.Passphrase = *in.Passphrase
	}

	s.state.Credentials = append(s.state.Credentials, cred)
	appendAuditLocked(s.state, "credential.create", cred.Name, fmt.Sprintf("新增加密凭据 (%s)", cred.Kind), clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	v := cred.ToView()
	return &v, nil
}

func (s *Store) UpdateCredential(id string, in CredentialMutationInput, clientIP string) (*CredentialView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || (in.Kind != AuthPassword && in.Kind != AuthPrivateKey) {
		return nil, ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	for i := range s.state.Credentials {
		if s.state.Credentials[i].ID == id {
			cred := s.state.Credentials[i]
			cred.Name = in.Name
			cred.Kind = in.Kind
			cred.UsernameHint = strings.TrimSpace(in.UsernameHint)
			cred.Notes = strings.TrimSpace(in.Notes)
			if in.PublicKey != "" {
				cred.PublicKey = strings.TrimSpace(in.PublicKey)
			}
			if in.Fingerprint != "" {
				cred.Fingerprint = strings.TrimSpace(in.Fingerprint)
			}
			if in.KeyAlgorithm != "" {
				cred.KeyAlgorithm = strings.TrimSpace(in.KeyAlgorithm)
			}
			if in.Password != nil {
				cred.Password = *in.Password
			}
			if in.PrivateKey != nil {
				cred.PrivateKey = *in.PrivateKey
			}
			if in.Passphrase != nil {
				cred.Passphrase = *in.Passphrase
			}
			cred.UpdatedAt = time.Now().UTC()
			s.state.Credentials[i] = cred
			appendAuditLocked(s.state, "credential.update", cred.Name, "更新加密凭据", clientIP, true)
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
			v := cred.ToView()
			return &v, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) DeleteCredential(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	for i, c := range s.state.Credentials {
		if c.ID == id {
			// Check if any server still depends on this credential
			for _, srv := range s.state.Servers {
				if srv.AuthType == AuthCredential && srv.CredentialID == id {
					return fmt.Errorf("%w: 服务器 [%s] 正在使用该凭据，请先解除绑定", ErrInvalidInput, srv.Name)
				}
			}
			s.state.Credentials = slices.Delete(s.state.Credentials, i, i+1)
			appendAuditLocked(s.state, "credential.delete", c.Name, "删除加密凭据", clientIP, true)
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

// --- Snippets CRUD ---

func (s *Store) ListSnippets() ([]Snippet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.Snippets), nil
}

func (s *Store) UpsertSnippet(in Snippet, clientIP string) (*Snippet, error) {
	in.Title = strings.TrimSpace(in.Title)
	in.Command = strings.TrimSpace(in.Command)
	in.Category = strings.TrimSpace(in.Category)
	if in.Category == "" {
		in.Category = "通用指令"
	}
	if in.Title == "" || in.Command == "" {
		return nil, fmt.Errorf("%w: 指令标题与命令内容不能为空", ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	now := time.Now().UTC()
	if in.ID != "" {
		for i := range s.state.Snippets {
			if s.state.Snippets[i].ID == in.ID {
				in.CreatedAt = s.state.Snippets[i].CreatedAt
				in.UpdatedAt = now
				s.state.Snippets[i] = in
				appendAuditLocked(s.state, "snippet.update", in.Title, "更新快捷指令", clientIP, true)
				if err := s.saveLocked(); err != nil {
					return nil, err
				}
				return &in, nil
			}
		}
	}

	in.ID = uuid.NewString()
	in.CreatedAt = now
	in.UpdatedAt = now
	s.state.Snippets = append(s.state.Snippets, in)
	appendAuditLocked(s.state, "snippet.create", in.Title, "新增快捷指令", clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return &in, nil
}

func (s *Store) DeleteSnippet(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	for i, sn := range s.state.Snippets {
		if sn.ID == id {
			s.state.Snippets = slices.Delete(s.state.Snippets, i, i+1)
			appendAuditLocked(s.state, "snippet.delete", sn.Title, "删除快捷指令", clientIP, true)
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

// --- KnownHosts (SSH Host Key Pinning / TOFU) ---

func (s *Store) ListKnownHosts() ([]KnownHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.KnownHosts), nil
}

func (s *Store) GetKnownHost(address string) (*KnownHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, kh := range s.state.KnownHosts {
		if kh.Address == address {
			cp := kh
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *Store) TrustKnownHost(kh KnownHost, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	now := time.Now().UTC()
	kh.LastVerifiedAt = now
	for i := range s.state.KnownHosts {
		if s.state.KnownHosts[i].Address == kh.Address {
			kh.FirstSeenAt = s.state.KnownHosts[i].FirstSeenAt
			s.state.KnownHosts[i] = kh
			appendAuditLocked(s.state, "hostkey.update", kh.Address, fmt.Sprintf("更新信任的 SSH 主机指纹 (%s)", kh.Fingerprint), clientIP, true)
			return s.saveLocked()
		}
	}
	kh.FirstSeenAt = now
	s.state.KnownHosts = append(s.state.KnownHosts, kh)
	appendAuditLocked(s.state, "hostkey.trust", kh.Address, fmt.Sprintf("首次信任并固定 SSH 主机指纹 (%s)", kh.Fingerprint), clientIP, true)
	return s.saveLocked()
}

func (s *Store) TouchKnownHostVerified(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	for i := range s.state.KnownHosts {
		if s.state.KnownHosts[i].Address == address {
			s.state.KnownHosts[i].LastVerifiedAt = time.Now().UTC()
			_ = s.saveLocked()
			return
		}
	}
}

func (s *Store) DeleteKnownHost(address, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	for i, kh := range s.state.KnownHosts {
		if kh.Address == address {
			s.state.KnownHosts = slices.Delete(s.state.KnownHosts, i, i+1)
			appendAuditLocked(s.state, "hostkey.delete", address, "移除已保存的 SSH 主机指纹记录", clientIP, true)
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

// --- Settings & Audit Logs ---

func (s *Store) GetSettings() (*AppSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	cp := s.state.Settings
	return &cp, nil
}

func (s *Store) UpdateSettings(in AppSettings, clientIP string) (*AppSettings, error) {
	if in.AutoLockMinutes < 0 || in.AutoLockMinutes > 1440 {
		in.AutoLockMinutes = 30
	}
	if in.TerminalFontSize < 10 || in.TerminalFontSize > 28 {
		in.TerminalFontSize = 14
	}
	if in.TerminalScrollback < 500 || in.TerminalScrollback > 50000 {
		in.TerminalScrollback = 5000
	}
	if in.HostKeyPolicy != HostKeyAskNew && in.HostKeyPolicy != HostKeyTOFU {
		in.HostKeyPolicy = HostKeyTOFU
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	s.state.Settings = in
	appendAuditLocked(s.state, "settings.update", "app", "更新安全策略与终端偏好设置", clientIP, true)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	cp := s.state.Settings
	return &cp, nil
}

func (s *Store) ListAuditLogs(limit int) ([]AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	if limit <= 0 || limit > len(s.state.AuditLogs) {
		limit = len(s.state.AuditLogs)
	}
	return slices.Clone(s.state.AuditLogs[:limit]), nil
}
