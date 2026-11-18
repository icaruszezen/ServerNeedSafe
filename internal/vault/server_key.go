package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	localKeyFileName = ".vault.key"
	localSealAAD     = "SNS-LOCAL-SEAL-v1:"
	// minEnvMasterKeyLen is the documented minimum length of SNS_MASTER_KEY. The env secret is only
	// expanded with HKDF (no password stretching), so it MUST already be a high-entropy random value.
	minEnvMasterKeyLen = 32

	// SealModeEnv means .vault.key is wrapped under a key derived from SNS_MASTER_KEY (secret kept outside /data).
	SealModeEnv = "env"
	// SealModeFile means the random wrapping key is stored inside .vault.key itself (protected only by 0600
	// file permissions): anyone who can read the data directory can decrypt vault.sns.
	SealModeFile = "file"
)

var (
	// ErrWeakMasterKey is returned when SNS_MASTER_KEY is set but shorter than the documented minimum.
	ErrWeakMasterKey = fmt.Errorf("SNS_MASTER_KEY 长度不足 %d 字节，拒绝使用低熵外部主密钥封装 .vault.key", minEnvMasterKeyLen)
	// ErrSealDowngrade is returned when an SNS_MASTER_KEY-protected .vault.key would be silently rewritten
	// as a plaintext-key file seal because the env variable is missing (e.g. a misconfigured restart).
	ErrSealDowngrade = errors.New("现有 .vault.key 受 SNS_MASTER_KEY 外部主密钥保护，但当前进程未配置该环境变量；已拒绝降级为明文文件密钥封装（如确需关闭外部主密钥，请手动删除 .vault.key 后重新登录）")
)

type localKeySealFile struct {
	Version           int    `json:"version"`
	VaultID           string `json:"vault_id"`
	EnvProtected      bool   `json:"env_protected,omitempty"`
	MasterKeyB64      string `json:"master_key_b64,omitempty"`
	NonceB64          string `json:"nonce_b64"`
	WrappedSecretsB64 string `json:"wrapped_secrets_b64"`
	UpdatedAt         string `json:"updated_at"`
}

// ServerKeyManager manages the local 0600 server-side seal key (.vault.key or SNS_MASTER_KEY env)
// so sns-server and desktop mode can auto-mount vault.sns in <1ms across restarts and run
// 7x24 SSH monitoring and scheduled AI patrol without manual unsealing, while keeping vault.sns
// and exported .sns backups strictly encrypted with the admin password.
//
// SECURITY NOTE: without SNS_MASTER_KEY the wrapping key is stored inside .vault.key next to vault.sns,
// so a leak of the whole data directory (or a host root compromise) is equivalent to a leak of the
// vault DEK. Exported .sns backups never contain .vault.key and stay password-protected.
type ServerKeyManager struct {
	mu      sync.Mutex
	keyPath string
}

// NewServerKeyManager creates a ServerKeyManager rooted in dataDir (alongside vault.sns).
func NewServerKeyManager(dataDir string) *ServerKeyManager {
	return &ServerKeyManager{
		keyPath: filepath.Join(dataDir, localKeyFileName),
	}
}

// KeyPath returns the path to the local .vault.key seal file.
func (m *ServerKeyManager) KeyPath() string {
	return m.keyPath
}

// HasLocalKey reports whether a local auto-unlock seal file exists on disk.
func (m *ServerKeyManager) HasLocalKey() bool {
	info, err := os.Stat(m.keyPath)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func (m *ServerKeyManager) readSeal() (*localKeySealFile, error) {
	m.mu.Lock()
	raw, err := os.ReadFile(m.keyPath)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	var seal localKeySealFile
	if err := json.Unmarshal(raw, &seal); err != nil {
		return nil, err
	}
	return &seal, nil
}

// SealMode reports how the current .vault.key is protected: SealModeEnv, SealModeFile, or "" if absent/unreadable.
func (m *ServerKeyManager) SealMode() string {
	seal, err := m.readSeal()
	if err != nil {
		return ""
	}
	if seal.EnvProtected {
		return SealModeEnv
	}
	return SealModeFile
}

// SealVaultID returns the VaultID the current .vault.key was issued for ("" if absent/unreadable).
func (m *ServerKeyManager) SealVaultID() string {
	seal, err := m.readSeal()
	if err != nil {
		return ""
	}
	return seal.VaultID
}

// Remove best-effort overwrites and deletes .vault.key (used when the seal no longer matches the mounted
// vault, e.g. after a remote password rotation re-keyed the DEK), so a stale wrapped DEK does not linger on disk.
func (m *ServerKeyManager) Remove() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, err := os.Stat(m.keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() && info.Size() > 0 {
		if f, oErr := os.OpenFile(m.keyPath, os.O_WRONLY, 0o600); oErr == nil {
			_, _ = f.Write(make([]byte, info.Size()))
			_ = f.Sync()
			_ = f.Close()
		}
	}
	if err := os.Remove(m.keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func resolveEnvMasterKey() ([]byte, bool, error) {
	rawEnv := strings.TrimSpace(os.Getenv("SNS_MASTER_KEY"))
	if rawEnv == "" {
		return nil, false, nil
	}
	if len(rawEnv) < minEnvMasterKeyLen {
		return nil, true, ErrWeakMasterKey
	}
	key, err := hkdfDerive32([]byte(rawEnv), []byte("ServerNeedSafe-MasterKey-Salt-v1"), "SNS-LOCAL-MASTER-KEY-v1")
	if err != nil {
		return nil, true, err
	}
	return key, true, nil
}

// TryAutoUnlock attempts to unwrap DEK + AuthPrivateKey from .vault.key and unlock store in <1ms.
// If vault.sns exists from a legacy v2 deployment without .vault.key, migrationPending is returned as true
// so the first admin password login automatically upgrades and persists .vault.key.
// A non-nil err (with migrationPending=true) explains why an EXISTING seal could not be used
// (stale VaultID, missing/weak SNS_MASTER_KEY, tampering); callers should log it.
func (m *ServerKeyManager) TryAutoUnlock(store *ClientVault, bs *BlindStore) (autoUnlocked bool, migrationPending bool, err error) {
	if store == nil || bs == nil || !bs.IsInitialized() {
		return false, false, nil
	}

	rawBlob, vaultID, _, rErr := bs.ReadBlob()
	if rErr != nil {
		return false, false, rErr
	}

	m.mu.Lock()
	sealBytes, sErr := os.ReadFile(m.keyPath)
	m.mu.Unlock()
	if sErr != nil {
		if errors.Is(sErr, os.ErrNotExist) {
			return false, true, nil
		}
		return false, true, fmt.Errorf("读取 .vault.key 失败: %w", sErr)
	}
	defer zeroBytes(sealBytes)

	var seal localKeySealFile
	if err := json.Unmarshal(sealBytes, &seal); err != nil {
		return false, true, fmt.Errorf(".vault.key 格式损坏: %w", err)
	}
	if seal.VaultID == "" || seal.VaultID != vaultID {
		return false, true, errors.New(".vault.key 与当前 vault.sns 的 VaultID 不匹配（已过期的自动挂载密钥）")
	}

	var masterKey []byte
	if seal.EnvProtected {
		envKey, hasEnv, kErr := resolveEnvMasterKey()
		if kErr != nil {
			return false, true, kErr
		}
		if !hasEnv {
			return false, true, errors.New(".vault.key 受 SNS_MASTER_KEY 保护，但当前进程未配置该环境变量")
		}
		masterKey = envKey
	} else {
		mk, dErr := base64.StdEncoding.DecodeString(seal.MasterKeyB64)
		if dErr != nil || len(mk) != dekSize {
			return false, true, errors.New(".vault.key 文件主密钥字段损坏")
		}
		masterKey = mk
	}
	defer zeroBytes(masterKey)

	nonce, nErr := base64.StdEncoding.DecodeString(seal.NonceB64)
	wrapped, wErr := base64.StdEncoding.DecodeString(seal.WrappedSecretsB64)
	if nErr != nil || wErr != nil {
		return false, true, errors.New(".vault.key 封装字段编码损坏")
	}

	block, cErr := aes.NewCipher(masterKey)
	if cErr != nil {
		return false, true, cErr
	}
	gcm, gErr := cipher.NewGCM(block)
	if gErr != nil || len(nonce) != gcm.NonceSize() {
		return false, true, errors.New(".vault.key 封装 nonce 无效")
	}

	plain, oErr := gcm.Open(nil, nonce, wrapped, []byte(localSealAAD+vaultID))
	if oErr != nil {
		return false, true, errors.New(".vault.key 认证解封失败（外部主密钥不匹配或文件遭到篡改）")
	}
	defer zeroBytes(plain)

	if len(plain) != dekSize+ed25519.PrivateKeySize {
		return false, true, errors.New(".vault.key 解封载荷长度异常")
	}
	dek := slices.Clone(plain[:dekSize])
	authPriv := ed25519.PrivateKey(slices.Clone(plain[dekSize:]))

	if uErr := store.UnlockWithLocalKey(rawBlob, dek, authPriv); uErr != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return false, true, fmt.Errorf(".vault.key 中的密钥无法挂载当前 vault.sns（密码/DEK 已轮换）: %w", uErr)
	}
	zeroBytes(dek)
	zeroBytes(authPriv)
	return true, false, nil
}

// SaveFromStore wraps the active store's DEK and Ed25519 key under the local master key
// and atomically persists .vault.key with strict 0600 permissions.
func (m *ServerKeyManager) SaveFromStore(store *ClientVault) error {
	if store == nil {
		return ErrVaultLocked
	}

	store.mu.RLock()
	if len(store.dek) != dekSize || len(store.authPriv) != ed25519.PrivateKeySize || store.header == nil {
		store.mu.RUnlock()
		return ErrVaultLocked
	}
	vaultID := store.header.VaultID
	secretPayload := make([]byte, 0, dekSize+ed25519.PrivateKeySize)
	secretPayload = append(secretPayload, store.dek...)
	secretPayload = append(secretPayload, store.authPriv...)
	store.mu.RUnlock()
	defer zeroBytes(secretPayload)

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.keyPath), 0o700); err != nil {
		return fmt.Errorf("mkdir key dir: %w", err)
	}

	envKey, hasEnv, err := resolveEnvMasterKey()
	if err != nil {
		return err
	}

	var masterKey []byte
	var masterKeyB64 string
	if hasEnv {
		masterKey = envKey
	} else {
		// Reuse existing random master key if present, else generate a fresh 256-bit key
		if prevRaw, rErr := os.ReadFile(m.keyPath); rErr == nil {
			var prev localKeySealFile
			uErr := json.Unmarshal(prevRaw, &prev)
			zeroBytes(prevRaw)
			if uErr == nil && prev.EnvProtected {
				// The operator previously moved the wrapping secret OUT of the data directory via
				// SNS_MASTER_KEY. Re-writing the seal with a plaintext file key here would silently
				// re-expose the DEK to anyone who can read /data (e.g. after a misconfigured restart).
				return ErrSealDowngrade
			}
			if uErr == nil {
				if prevMK, dErr := base64.StdEncoding.DecodeString(prev.MasterKeyB64); dErr == nil && len(prevMK) == dekSize {
					masterKey = prevMK
				}
			}
		}
		if len(masterKey) != dekSize {
			mk, gErr := randomBytes(dekSize)
			if gErr != nil {
				return gErr
			}
			masterKey = mk
		}
		masterKeyB64 = base64.StdEncoding.EncodeToString(masterKey)
	}
	defer zeroBytes(masterKey)

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return err
	}
	wrapped := gcm.Seal(nil, nonce, secretPayload, []byte(localSealAAD+vaultID))

	seal := localKeySealFile{
		Version:           1,
		VaultID:           vaultID,
		EnvProtected:      hasEnv,
		MasterKeyB64:      masterKeyB64,
		NonceB64:          base64.StdEncoding.EncodeToString(nonce),
		WrappedSecretsB64: base64.StdEncoding.EncodeToString(wrapped),
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}
	encoded, err := json.MarshalIndent(&seal, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	defer zeroBytes(encoded)

	tmpPath := m.keyPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp key file: %w", err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, m.keyPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if dir, dErr := os.Open(filepath.Dir(m.keyPath)); dErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// UnlockWithLocalKey decrypts and mounts a SNSVAULT v2 container directly using the server's
// unwrapped DEK and Ed25519 private key in <1ms (zero Argon2id derivation on service restart).
func (s *ClientVault) UnlockWithLocalKey(raw []byte, dek []byte, authPriv ed25519.PrivateKey) error {
	if len(dek) != dekSize || len(authPriv) != ed25519.PrivateKeySize {
		return ErrCorruptedVault
	}
	ver, _, parsedHdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return err
	}
	if err := ValidateV2HeaderStructural(ver, parsedHdr); err != nil {
		return err
	}
	authPub := authPriv.Public().(ed25519.PublicKey)
	hdr, state, err := OpenVaultWithKnownDEK(raw, dek, parsedHdr.VaultID, authPub)
	if err != nil {
		return err
	}
	ensureMonitorInitialized(state)
	EnsureStateDefaults(state)

	s.mu.Lock()
	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	if len(s.authPriv) > 0 {
		zeroBytes(s.authPriv)
	}
	now := time.Now().UTC()
	s.dek = slices.Clone(dek)
	s.authPriv = slices.Clone(authPriv)
	s.header = hdr
	s.state = state
	s.lastBlob = slices.Clone(raw)
	s.kdfTime = hdr.KDFTime
	s.kdfMemoryKiB = hdr.KDFMemoryKiB
	s.kdfThreads = hdr.KDFThreads
	s.anchor = &VaultAnchor{
		VaultID:          hdr.VaultID,
		MinRevision:      hdr.Revision,
		AuthPubKeySHA256: sha256Hex(hdr.AuthPublicKey),
	}
	s.unlockedAt = now
	s.lastActivity = now
	hooks := slices.Clone(s.onUnlockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
	return nil
}

// UpdateKDFParams verifies the current admin password and re-wraps the vault container using
// the selected Argon2id memory/time/parallelism profile without losing any stored assets.
func (s *ClientVault) UpdateKDFParams(password string, kdfTime uint32, kdfMemoryKiB uint32, kdfThreads uint8, clientIP string) (*EncryptionInfo, error) {
	if password == "" {
		return nil, ErrInvalidPassword
	}
	if kdfMemoryKiB < MinAllowedKDFMemoryKiB || kdfMemoryKiB > 512*1024 || kdfTime < 1 || kdfTime > 16 || kdfThreads < 1 || kdfThreads > 16 {
		return nil, fmt.Errorf("%w: KDF 参数超出安全范围（内存需在 16 MiB ~ 512 MiB 之间）", ErrInvalidInput)
	}

	s.mu.Lock()
	if len(s.dek) == 0 || s.state == nil || s.header == nil {
		s.mu.Unlock()
		return nil, ErrVaultLocked
	}

	verifiedDEK, verifiedPriv, err := unwrapDEKV2(password, s.header, s.minMemoryKiB)
	if err != nil {
		s.mu.Unlock()
		return nil, ErrInvalidPassword
	}
	matched := constantTimeEqual(verifiedDEK, s.dek)
	zeroBytes(verifiedDEK)
	zeroBytes(verifiedPriv)
	if !matched {
		s.mu.Unlock()
		return nil, ErrInvalidPassword
	}

	newSalt, err := randomBytes(kdfSaltSize)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	newDEK, err := randomBytes(dekSize)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	newKEK, newAuthPriv, newAuthPub, err := DeriveVaultKeys(password, newSalt, kdfTime, kdfMemoryKiB, kdfThreads, s.minMemoryKiB)
	if err != nil {
		zeroBytes(newDEK)
		s.mu.Unlock()
		return nil, err
	}

	prevRev := s.header.Revision
	newHdr := &EnvelopeHeader{
		VaultID:       s.header.VaultID,
		Revision:      prevRev + 1,
		KDFAlgo:       "argon2id",
		KDFTime:       kdfTime,
		KDFMemoryKiB:  kdfMemoryKiB,
		KDFThreads:    kdfThreads,
		KDFSalt:       newSalt,
		AuthAlgo:      "ed25519",
		AuthPublicKey: newAuthPub,
	}
	err = wrapDEKV2(newKEK, newDEK, newHdr)
	zeroBytes(newKEK)
	if err != nil {
		zeroBytes(newDEK)
		zeroBytes(newAuthPriv)
		s.mu.Unlock()
		return nil, err
	}

	working := cloneVaultState(s.state)
	working.UpdatedAt = time.Now().UTC()
	appendAuditLocked(
		working,
		"vault.kdf_updated",
		"vault.sns",
		fmt.Sprintf("调整 Argon2id 密钥派生档位为 %d MiB / %d 轮 / %d 并行度", kdfMemoryKiB/1024, kdfTime, kdfThreads),
		clientIP,
		true,
	)

	rawBlob, sealedHdr, err := SealVaultContainer(newDEK, newHdr, working)
	if err != nil {
		zeroBytes(newDEK)
		zeroBytes(newAuthPriv)
		s.mu.Unlock()
		return nil, err
	}

	oldSig, newSig := SignPasswordRotate(
		s.authPriv,
		newAuthPriv,
		sealedHdr.VaultID,
		prevRev,
		sealedHdr.Revision,
		s.header.AuthPublicKey,
		sealedHdr.AuthPublicKey,
		rawBlob,
	)

	if err := s.backend.RotatePassword(rawBlob, prevRev, oldSig, newSig); err != nil {
		zeroBytes(newDEK)
		zeroBytes(newAuthPriv)
		s.mu.Unlock()
		return nil, err
	}

	zeroBytes(s.dek)
	zeroBytes(s.authPriv)
	s.dek = newDEK
	s.authPriv = newAuthPriv
	s.header = sealedHdr
	s.state = working
	s.lastBlob = rawBlob
	s.kdfTime = kdfTime
	s.kdfMemoryKiB = kdfMemoryKiB
	s.kdfThreads = kdfThreads
	if s.anchor != nil {
		s.anchor.MinRevision = sealedHdr.Revision
		s.anchor.AuthPubKeySHA256 = sha256Hex(sealedHdr.AuthPublicKey)
	}
	s.lastActivity = time.Now().UTC()
	s.mu.Unlock()

	return s.EncryptionInfo()
}

// RecordAuditAsync appends an audit entry asynchronously so interactive login responses
// are never blocked on vault re-encryption and fsync.
func (s *ClientVault) RecordAuditAsync(action, target, detail, clientIP string, success bool) {
	go s.RecordAudit(action, target, detail, clientIP, success)
}
