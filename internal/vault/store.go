package vault

import (
	"crypto/ed25519"
	"errors"
	"fmt"
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

// CiphertextBackend abstracts transport of opaque SNSVAULT v2 ciphertext blobs and Ed25519 signatures.
// Implementations (e.g. HTTP client to remote sns-server or local BlindStore adapter) NEVER see
// passwords, DEKs, or plaintext VaultState.
type CiphertextBackend interface {
	IsInitialized() (bool, error)
	PublicParams() (*PublicKDFParams, error)
	Initialize(raw []byte, sig []byte) error
	Read() (raw []byte, err error)
	Put(raw []byte, expectedPrevRev uint64, sig []byte) error
	RotatePassword(raw []byte, expectedPrevRev uint64, oldSig, newSig []byte) error
	Import(raw []byte, newSig, overwriteSig []byte) error
}

type localBlindAdapter struct {
	bs *BlindStore
}

// NewBlindStoreBackend wraps a BlindStore as a CiphertextBackend (used in tests and direct local wiring).
func NewBlindStoreBackend(bs *BlindStore) CiphertextBackend {
	return &localBlindAdapter{bs: bs}
}

func (a *localBlindAdapter) IsInitialized() (bool, error) {
	return a.bs.IsInitialized(), nil
}

func (a *localBlindAdapter) PublicParams() (*PublicKDFParams, error) {
	return a.bs.PublicChallengeParams()
}

func (a *localBlindAdapter) Initialize(raw []byte, sig []byte) error {
	_, _, err := a.bs.InitializeBlob(raw, sig)
	return err
}

func (a *localBlindAdapter) Read() ([]byte, error) {
	raw, _, _, err := a.bs.ReadBlob()
	return raw, err
}

func (a *localBlindAdapter) Put(raw []byte, expectedPrevRev uint64, sig []byte) error {
	_, err := a.bs.PutBlob(raw, expectedPrevRev, sig)
	return err
}

func (a *localBlindAdapter) RotatePassword(raw []byte, expectedPrevRev uint64, oldSig, newSig []byte) error {
	_, _, err := a.bs.RotatePasswordBlob(raw, expectedPrevRev, oldSig, newSig)
	return err
}

func (a *localBlindAdapter) Import(raw []byte, newSig, overwriteSig []byte) error {
	_, _, err := a.bs.ImportBlob(raw, newSig, overwriteSig)
	return err
}

// VaultAnchor tracks the pinned VaultID, AuthPublicKey SHA-256, and monotonic Revision
// on the client to detect server-side rollback, deletion, or vault substitution attacks.
type VaultAnchor struct {
	VaultID          string `json:"vault_id"`
	MinRevision      uint64 `json:"min_revision"`
	AuthPubKeySHA256 string `json:"auth_pubkey_sha256"`
}

// ClientVault manages the client-side decrypted VaultState strictly in volatile client memory
// and persists ONLY authenticated XChaCha20-Poly1305 ciphertext blobs to CiphertextBackend.
type ClientVault struct {
	mu            sync.RWMutex
	backend       CiphertextBackend
	dek           []byte
	authPriv      ed25519.PrivateKey
	header        *EnvelopeHeader
	state         *VaultState
	lastBlob      []byte
	anchor        *VaultAnchor
	unlockedAt    time.Time
	lastActivity  time.Time
	onLockHooks   []func()
	onUnlockHooks []func()

	kdfTime      uint32
	kdfMemoryKiB uint32
	kdfThreads   uint8
	minMemoryKiB uint32
}

// Store is an alias for ClientVault for clean compatibility with sshmanager.
type Store = ClientVault

// NewClientVault creates a client-side E2EE vault engine backed by a zero-knowledge CiphertextBackend.
func NewClientVault(backend CiphertextBackend) *ClientVault {
	return &ClientVault{
		backend:      backend,
		kdfTime:      DefaultKDFTime,
		kdfMemoryKiB: DefaultKDFMemoryKiB,
		kdfThreads:   DefaultKDFThreads,
		minMemoryKiB: MinAllowedKDFMemoryKiB,
	}
}

// NewStore creates a BlindStore + ClientVault pair pointing to vaultFilePath (convenience constructor for tests).
func NewStore(vaultFilePath string) (*ClientVault, error) {
	bs, err := NewBlindStore(vaultFilePath)
	if err != nil {
		return nil, err
	}
	return NewClientVault(NewBlindStoreBackend(bs)), nil
}

// SetKDFParams customizes Argon2id parameters (e.g. 16 MiB in fast unit tests; production defaults to 64 MiB).
func (s *ClientVault) SetKDFParams(timeCost, memoryKiB uint32, threads uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if timeCost >= 1 {
		s.kdfTime = timeCost
	}
	if memoryKiB >= MinAllowedKDFMemoryKiB {
		s.kdfMemoryKiB = memoryKiB
	}
	if threads >= 1 {
		s.kdfThreads = threads
	}
}

// SetAnchor configures the client's anti-rollback anchor loaded from trusted client storage.
func (s *ClientVault) SetAnchor(anchor *VaultAnchor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if anchor != nil && anchor.VaultID != "" {
		cp := *anchor
		s.anchor = &cp
	} else {
		s.anchor = nil
	}
}

// GetAnchor returns a copy of the latest client anti-rollback anchor.
func (s *ClientVault) GetAnchor() *VaultAnchor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.anchor == nil {
		return nil
	}
	cp := *s.anchor
	return &cp
}

func (s *ClientVault) verifyAndAdvanceAnchorLocked(hdr *EnvelopeHeader) error {
	pubFP := sha256Hex(hdr.AuthPublicKey)
	if s.anchor != nil {
		if s.anchor.VaultID != "" && hdr.VaultID != s.anchor.VaultID {
			return fmt.Errorf("%w: 保险库 ID 不匹配（预期 %s，服务端返回 %s）", ErrRollbackDetected, s.anchor.VaultID, hdr.VaultID)
		}
		if hdr.Revision < s.anchor.MinRevision {
			return fmt.Errorf("%w: 版本号发生回退（本地已锚定 #%d，服务端返回 #%d）", ErrRollbackDetected, s.anchor.MinRevision, hdr.Revision)
		}
	}
	s.anchor = &VaultAnchor{
		VaultID:          hdr.VaultID,
		MinRevision:      hdr.Revision,
		AuthPubKeySHA256: pubFP,
	}
	return nil
}

// RegisterOnLock registers a callback invoked whenever the client vault transitions to locked state.
func (s *ClientVault) RegisterOnLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onLockHooks = append(s.onLockHooks, fn)
}

// RegisterOnUnlock registers a callback invoked whenever the client vault transitions to unlocked state.
func (s *ClientVault) RegisterOnUnlock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onUnlockHooks = append(s.onUnlockHooks, fn)
}

// Status returns the current lifecycle status of the client vault.
func (s *ClientVault) Status() VaultStatus {
	s.mu.RLock()
	unlocked := len(s.dek) == dekSize && s.state != nil
	backend := s.backend
	s.mu.RUnlock()

	if unlocked {
		return StatusUnlocked
	}
	if backend != nil {
		init, err := backend.IsInitialized()
		if err == nil && !init {
			return StatusUninitialized
		}
	}
	return StatusLocked
}

// AuthPrivateKeyCopy returns a temporary copy of the client's Ed25519 authentication private key if unlocked.
func (s *ClientVault) AuthPrivateKeyCopy() ed25519.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.authPriv) == 0 {
		return nil
	}
	return slices.Clone(s.authPriv)
}

// Setup initializes a brand-new client-encrypted SNSVAULT v2 container and pushes ONLY ciphertext + signature to backend.
func (s *ClientVault) Setup(password, clientIP string) error {
	if len([]rune(password)) < 8 {
		return ErrWeakPassword
	}

	s.mu.Lock()

	if init, err := s.backend.IsInitialized(); err != nil {
		s.mu.Unlock()
		return err
	} else if init {
		s.mu.Unlock()
		return ErrVaultAlreadyInit
	}

	// If an anchor already existed locally, warn about server wipe attack unless anchor was cleared explicitly!
	if s.anchor != nil && s.anchor.VaultID != "" {
		vid := s.anchor.VaultID
		s.mu.Unlock()
		return fmt.Errorf("%w: 本地记录该服务端曾初始化保险库 (%s)，但服务端当前为空，疑似遭到重置删除", ErrRollbackDetected, vid)
	}

	salt, err := randomBytes(kdfSaltSize)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	dek, err := randomBytes(dekSize)
	if err != nil {
		s.mu.Unlock()
		return err
	}

	kek, authPriv, authPub, err := DeriveVaultKeys(password, salt, s.kdfTime, s.kdfMemoryKiB, s.kdfThreads, s.minMemoryKiB)
	if err != nil {
		zeroBytes(dek)
		s.mu.Unlock()
		return err
	}

	hdr := &EnvelopeHeader{
		VaultID:       uuid.NewString(),
		Revision:      1,
		KDFAlgo:       "argon2id",
		KDFTime:       s.kdfTime,
		KDFMemoryKiB:  s.kdfMemoryKiB,
		KDFThreads:    s.kdfThreads,
		KDFSalt:       salt,
		AuthAlgo:      "ed25519",
		AuthPublicKey: authPub,
	}
	err = wrapDEKV2(kek, dek, hdr)
	zeroBytes(kek)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}

	initialState := DefaultVaultState()
	appendAuditLocked(initialState, "vault.setup", "vault.sns", "客户端本地初始化零知识全量加密保险库 (SNSVAULT v2)", clientIP, true)

	rawBlob, sealedHdr, err := SealVaultContainer(dek, hdr, initialState)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}
	sig := SignSetup(authPriv, sealedHdr.VaultID, sealedHdr.Revision, rawBlob)

	if err := s.backend.Initialize(rawBlob, sig); err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}

	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	if len(s.authPriv) > 0 {
		zeroBytes(s.authPriv)
	}
	s.dek = dek
	s.authPriv = authPriv
	s.header = sealedHdr
	s.state = initialState
	s.lastBlob = rawBlob
	_ = s.verifyAndAdvanceAnchorLocked(sealedHdr)
	now := time.Now().UTC()
	s.unlockedAt = now
	s.lastActivity = now
	hooks := slices.Clone(s.onUnlockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
	return nil
}

// UnlockOrVerify fetches the encrypted container from backend, verifies anti-rollback constraints,
// derives keys locally via Argon2id, and decrypts VaultState strictly in client memory.
func (s *ClientVault) UnlockOrVerify(password, clientIP string) error {
	if password == "" {
		return ErrInvalidPassword
	}

	raw, err := s.backend.Read()
	if err != nil {
		return err
	}
	return s.UnlockFromRawBlob(raw, password, clientIP, true)
}

// UnlockFromRawBlob authenticates and decrypts a pre-fetched SNSVAULT v2 container in client memory.
func (s *ClientVault) UnlockFromRawBlob(raw []byte, password, clientIP string, recordAudit bool) error {
	if password == "" {
		return ErrInvalidPassword
	}

	dek, authPriv, hdr, state, ver, err := OpenVaultContainer(raw, password, s.minMemoryKiB)
	if err != nil {
		return err
	}
	if ver != vaultFormatVersion {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return ErrCorruptedVault
	}
	ensureMonitorInitialized(state)

	s.mu.Lock()

	if err := s.verifyAndAdvanceAnchorLocked(hdr); err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}

	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	if len(s.authPriv) > 0 {
		zeroBytes(s.authPriv)
	}

	now := time.Now().UTC()
	s.dek = dek
	s.authPriv = authPriv
	s.header = hdr
	s.state = state
	s.lastBlob = slices.Clone(raw)
	s.unlockedAt = now
	s.lastActivity = now

	if recordAudit {
		_ = s.mutateLocked(func(st *VaultState) error {
			appendAuditLocked(st, "vault.unlock", "client-memory", "客户端零知识验证通过，本地内存解密保险库", clientIP, true)
			return nil
		})
	}
	hooks := slices.Clone(s.onUnlockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
	return nil
}

// MinMemoryKiB returns the enforced Argon2id KDF memory floor.
func (s *ClientVault) MinMemoryKiB() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.minMemoryKiB == 0 {
		return MinAllowedKDFMemoryKiB
	}
	return s.minMemoryKiB
}

// LastSealedBlob returns a copy of the latest sealed SNSVAULT v2 ciphertext container if unlocked.
func (s *ClientVault) LastSealedBlob() ([]byte, *EnvelopeHeader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.dek) == 0 || s.header == nil || len(s.lastBlob) == 0 {
		return nil, nil, ErrVaultLocked
	}
	hdrCp := *s.header
	return slices.Clone(s.lastBlob), &hdrCp, nil
}

// UnlockWithPreDerivedKeys completes unlock using KEK + AuthKeyPair derived during the zero-knowledge login step.
func (s *ClientVault) UnlockWithPreDerivedKeys(
	raw []byte,
	kek []byte,
	authPriv ed25519.PrivateKey,
	authPub ed25519.PublicKey,
	expectedKDF *PublicKDFParams,
	clientIP string,
	recordAudit bool,
) error {
	dek, hdr, state, err := OpenVaultContainerPreDerived(raw, kek, authPub, expectedKDF)
	if err != nil {
		return err
	}
	ensureMonitorInitialized(state)

	s.mu.Lock()

	if err := s.verifyAndAdvanceAnchorLocked(hdr); err != nil {
		zeroBytes(dek)
		s.mu.Unlock()
		return err
	}
	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	if len(s.authPriv) > 0 {
		zeroBytes(s.authPriv)
	}

	now := time.Now().UTC()
	s.dek = dek
	s.authPriv = slices.Clone(authPriv)
	s.header = hdr
	s.state = state
	s.lastBlob = slices.Clone(raw)
	s.unlockedAt = now
	s.lastActivity = now

	if recordAudit {
		_ = s.mutateLocked(func(st *VaultState) error {
			appendAuditLocked(st, "vault.unlock", "client-memory", "客户端零知识验证通过，本地内存解密保险库", clientIP, true)
			return nil
		})
	}
	hooks := slices.Clone(s.onUnlockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
	return nil
}

// Lock wipes the client's in-memory DEK, Ed25519 private key, and decrypted state buffers.
func (s *ClientVault) Lock(reason, clientIP string) {
	s.mu.Lock()
	if len(s.dek) > 0 && s.state != nil {
		if reason != "" {
			_ = s.mutateLocked(func(st *VaultState) error {
				appendAuditLocked(st, "vault.lock", "client-memory", reason, clientIP, true)
				return nil
			})
		}
		scrubStateSecrets(s.state)
		zeroBytes(s.dek)
		zeroBytes(s.authPriv)
	}
	s.dek = nil
	s.authPriv = nil
	s.state = nil
	s.header = nil
	s.lastBlob = nil
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
		st.Servers[i].Name = ""
		st.Servers[i].Host = ""
		st.Servers[i].Username = ""
		st.Servers[i].Password = ""
		st.Servers[i].PrivateKey = ""
		st.Servers[i].Passphrase = ""
		st.Servers[i].Notes = ""
	}
	for i := range st.Credentials {
		st.Credentials[i].Name = ""
		st.Credentials[i].Password = ""
		st.Credentials[i].PrivateKey = ""
		st.Credentials[i].Passphrase = ""
		st.Credentials[i].Notes = ""
	}
	scrubMonitorData(st)
}

func cloneVaultState(st *VaultState) *VaultState {
	cp := *st
	cp.Groups = slices.Clone(st.Groups)
	cp.Servers = make([]ServerConfig, len(st.Servers))
	for i, srv := range st.Servers {
		srvCp := srv
		srvCp.Tags = slices.Clone(srv.Tags)
		srvCp.WatchedServices = slices.Clone(srv.WatchedServices)
		srvCp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		if srv.LastConnectedAt != nil {
			t := *srv.LastConnectedAt
			srvCp.LastConnectedAt = &t
		}
		cp.Servers[i] = srvCp
	}
	cp.Credentials = slices.Clone(st.Credentials)
	cp.Snippets = slices.Clone(st.Snippets)
	cp.KnownHosts = slices.Clone(st.KnownHosts)
	cp.AuditLogs = slices.Clone(st.AuditLogs)
	cp.Monitor = cloneMonitorVaultData(st.Monitor)
	return &cp
}

func (s *ClientVault) mutateLocked(mutFn func(st *VaultState) error) error {
	if len(s.dek) != dekSize || len(s.authPriv) != ed25519.PrivateKeySize || s.header == nil || s.state == nil {
		return ErrVaultLocked
	}

	attempt := func() error {
		working := cloneVaultState(s.state)
		if err := mutFn(working); err != nil {
			return err
		}
		working.UpdatedAt = time.Now().UTC()

		prevRev := s.header.Revision
		nextBase := *s.header
		nextBase.Revision = prevRev + 1

		rawBlob, sealedHdr, err := SealVaultContainer(s.dek, &nextBase, working)
		if err != nil {
			return err
		}
		sig := SignVaultPut(s.authPriv, sealedHdr.VaultID, prevRev, sealedHdr.Revision, rawBlob)
		if err := s.backend.Put(rawBlob, prevRev, sig); err != nil {
			return err
		}
		s.header = sealedHdr
		s.state = working
		s.lastBlob = rawBlob
		_ = s.verifyAndAdvanceAnchorLocked(sealedHdr)
		return nil
	}

	err := attempt()
	if errors.Is(err, ErrRevisionConflict) {
		// Pull latest authenticated ciphertext blob, verify no rollback, decrypt with known DEK, and retry once
		latestRaw, rErr := s.backend.Read()
		if rErr != nil {
			return err
		}
		latestHdr, latestState, oErr := OpenVaultWithKnownDEK(latestRaw, s.dek, s.header.VaultID, s.header.AuthPublicKey)
		if oErr != nil {
			return oErr
		}
		if latestHdr.Revision <= s.header.Revision {
			return ErrRollbackDetected
		}
		s.header = latestHdr
		s.state = latestState
		s.lastBlob = latestRaw
		_ = s.verifyAndAdvanceAnchorLocked(latestHdr)
		return attempt()
	}
	return err
}

// TouchActivity refreshes the client idle auto-lock timer.
func (s *ClientVault) TouchActivity() {
	s.mu.Lock()
	if s.state != nil {
		s.lastActivity = time.Now().UTC()
	}
	s.mu.Unlock()
}

// CheckAutoLock locks the client vault if AutoLockMinutes > 0 and inactivity exceeds threshold
// (unless UnattendedWhileUnlocked monitoring is actively running with configured servers).
func (s *ClientVault) CheckAutoLock() bool {
	s.mu.RLock()
	if len(s.dek) == 0 || s.state == nil {
		s.mu.RUnlock()
		return false
	}
	mins := s.state.Settings.AutoLockMinutes
	last := s.lastActivity
	mon := s.state.Monitor
	unattended := mon != nil && mon.Settings.Enabled && mon.Settings.UnattendedWhileUnlocked && len(s.state.Servers) > 0
	s.mu.RUnlock()

	if mins <= 0 || unattended {
		return false
	}
	if time.Since(last) >= time.Duration(mins)*time.Minute {
		s.Lock(fmt.Sprintf("超过 %d 分钟无操作自动擦除本地密钥并锁定保险库", mins), "client")
		return true
	}
	return false
}

// ChangePassword verifies oldPassword locally, rotates Argon2id salt, master DEK, AND Ed25519 AuthKeyPair,
// and atomically pushes the dual-signed re-encrypted container without exposing either password to the server.
func (s *ClientVault) ChangePassword(oldPassword, newPassword, clientIP string) error {
	if len([]rune(newPassword)) < 8 {
		return ErrWeakPassword
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dek) == 0 || s.state == nil || s.header == nil {
		return ErrVaultLocked
	}

	verifiedDEK, verifiedPriv, err := unwrapDEKV2(oldPassword, s.header, s.minMemoryKiB)
	if err != nil {
		_ = s.mutateLocked(func(st *VaultState) error {
			appendAuditLocked(st, "vault.password_change_failed", "vault.sns", "修改管理员密码失败：原密码本地校验未通过", clientIP, false)
			return nil
		})
		return ErrInvalidPassword
	}
	matched := constantTimeEqual(verifiedDEK, s.dek)
	zeroBytes(verifiedDEK)
	zeroBytes(verifiedPriv)
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

	newKEK, newAuthPriv, newAuthPub, err := DeriveVaultKeys(newPassword, newSalt, s.kdfTime, s.kdfMemoryKiB, s.kdfThreads, s.minMemoryKiB)
	if err != nil {
		zeroBytes(newDEK)
		return err
	}

	prevRev := s.header.Revision
	newHdr := &EnvelopeHeader{
		VaultID:       s.header.VaultID,
		Revision:      prevRev + 1,
		KDFAlgo:       "argon2id",
		KDFTime:       s.kdfTime,
		KDFMemoryKiB:  s.kdfMemoryKiB,
		KDFThreads:    s.kdfThreads,
		KDFSalt:       newSalt,
		AuthAlgo:      "ed25519",
		AuthPublicKey: newAuthPub,
	}
	err = wrapDEKV2(newKEK, newDEK, newHdr)
	zeroBytes(newKEK)
	if err != nil {
		zeroBytes(newDEK)
		zeroBytes(newAuthPriv)
		return err
	}

	working := cloneVaultState(s.state)
	working.UpdatedAt = time.Now().UTC()
	appendAuditLocked(working, "vault.password_changed", "vault.sns", "客户端完成管理员密码、DEK 与零知识签名密钥全量轮换重加密", clientIP, true)

	rawBlob, sealedHdr, err := SealVaultContainer(newDEK, newHdr, working)
	if err != nil {
		zeroBytes(newDEK)
		zeroBytes(newAuthPriv)
		return err
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
		return err
	}

	zeroBytes(s.dek)
	zeroBytes(s.authPriv)
	s.dek = newDEK
	s.authPriv = newAuthPriv
	s.header = sealedHdr
	s.state = working
	s.lastBlob = rawBlob
	if s.anchor != nil {
		s.anchor.MinRevision = sealedHdr.Revision
		s.anchor.AuthPubKeySHA256 = sha256Hex(sealedHdr.AuthPublicKey)
	}
	s.lastActivity = time.Now().UTC()
	return nil
}

// ExportEncryptedBytes records an audit entry and returns the latest sealed SNSVAULT v2 ciphertext bytes.
func (s *ClientVault) ExportEncryptedBytes(clientIP string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dek) == 0 || s.state == nil {
		return nil, ErrVaultLocked
	}
	if err := s.mutateLocked(func(st *VaultState) error {
		appendAuditLocked(st, "vault.export", "vault.sns", "客户端导出全量加密备份数据包 (.sns)", clientIP, true)
		return nil
	}); err != nil {
		return nil, err
	}
	return slices.Clone(s.lastBlob), nil
}

// ImportEncryptedVault decrypts and authenticates an uploaded .sns backup file (v1 or v2) locally on the client,
// re-seals it as an authenticated v2 container, and atomically pushes ciphertext to the backend.
// If overwriting an already-initialized vault with a different password, currentAdminPassword can be provided
// when the client vault is not already unlocked.
func (s *ClientVault) ImportEncryptedVault(raw []byte, backupPassword, currentAdminPassword, clientIP string) error {
	dek, authPriv, hdr, state, ver, err := OpenVaultContainer(raw, backupPassword, 8192)
	if err != nil {
		return err
	}
	ensureMonitorInitialized(state)

	s.mu.Lock()

	// Upgrade v1 backup or advance revision on v2 backup so ciphertext nonce is fresh
	var targetHdr EnvelopeHeader
	if ver == vaultFormatVersionV1 || len(authPriv) == 0 {
		salt, sErr := randomBytes(kdfSaltSize)
		if sErr != nil {
			zeroBytes(dek)
			s.mu.Unlock()
			return sErr
		}
		kek, derivedPriv, derivedPub, kErr := DeriveVaultKeys(backupPassword, salt, s.kdfTime, s.kdfMemoryKiB, s.kdfThreads, s.minMemoryKiB)
		if kErr != nil {
			zeroBytes(dek)
			s.mu.Unlock()
			return kErr
		}
		targetHdr = EnvelopeHeader{
			VaultID:       uuid.NewString(),
			Revision:      1,
			KDFAlgo:       "argon2id",
			KDFTime:       s.kdfTime,
			KDFMemoryKiB:  s.kdfMemoryKiB,
			KDFThreads:    s.kdfThreads,
			KDFSalt:       salt,
			AuthAlgo:      "ed25519",
			AuthPublicKey: derivedPub,
		}
		wErr := wrapDEKV2(kek, dek, &targetHdr)
		zeroBytes(kek)
		if wErr != nil {
			zeroBytes(dek)
			zeroBytes(derivedPriv)
			s.mu.Unlock()
			return wErr
		}
		authPriv = derivedPriv
	} else {
		targetHdr = *hdr
		targetHdr.Revision = hdr.Revision + 1
	}

	state.UpdatedAt = time.Now().UTC()
	appendAuditLocked(state, "vault.import", "vault.sns", "客户端本地校验并恢复加密备份数据包", clientIP, true)

	sealedBlob, sealedHdr, err := SealVaultContainer(dek, &targetHdr, state)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}

	newSig := SignVaultImport(authPriv, sealedHdr.VaultID, sealedHdr.Revision, sealedBlob)
	var overwriteSig []byte

	if init, initErr := s.backend.IsInitialized(); initErr == nil && init {
		params, pErr := s.backend.PublicParams()
		if pErr != nil {
			zeroBytes(dek)
			zeroBytes(authPriv)
			s.mu.Unlock()
			return pErr
		}
		if len(s.authPriv) == ed25519.PrivateKeySize && s.header != nil && s.header.VaultID == params.VaultID {
			overwriteSig = SignVaultImportOverwrite(s.authPriv, params.VaultID, sealedHdr.VaultID, sealedBlob)
		} else {
			pwToTry := currentAdminPassword
			if pwToTry == "" {
				pwToTry = backupPassword
			}
			kekTmp, curPriv, _, dErr := DeriveVaultKeys(pwToTry, params.KDFSalt, params.KDFTime, params.KDFMemoryKiB, params.KDFThreads, s.minMemoryKiB)
			if dErr != nil {
				zeroBytes(dek)
				zeroBytes(authPriv)
				s.mu.Unlock()
				return dErr
			}
			zeroBytes(kekTmp)
			overwriteSig = SignVaultImportOverwrite(curPriv, params.VaultID, sealedHdr.VaultID, sealedBlob)
			zeroBytes(curPriv)
		}
	}

	if err := s.backend.Import(sealedBlob, newSig, overwriteSig); err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		s.mu.Unlock()
		return err
	}

	if len(s.dek) > 0 {
		zeroBytes(s.dek)
	}
	if len(s.authPriv) > 0 {
		zeroBytes(s.authPriv)
	}
	s.dek = dek
	s.authPriv = authPriv
	s.header = sealedHdr
	s.state = state
	s.lastBlob = sealedBlob
	s.anchor = &VaultAnchor{
		VaultID:          sealedHdr.VaultID,
		MinRevision:      sealedHdr.Revision,
		AuthPubKeySHA256: sha256Hex(sealedHdr.AuthPublicKey),
	}
	now := time.Now().UTC()
	s.unlockedAt = now
	s.lastActivity = now
	hooks := slices.Clone(s.onUnlockHooks)
	s.mu.Unlock()

	for _, fn := range hooks {
		fn()
	}
	return nil
}

// EncryptionInfo returns cryptographic metadata from the active client vault.
func (s *ClientVault) EncryptionInfo() (*EncryptionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.header == nil {
		return &EncryptionInfo{
			FormatVersion: int(vaultFormatVersion),
			KDFAlgo:       "argon2id",
			KDFTime:       s.kdfTime,
			KDFMemoryKiB:  s.kdfMemoryKiB,
			KDFThreads:    s.kdfThreads,
			WrapAlgo:      "aes-256-gcm",
			CipherAlgo:    "xchacha20-poly1305",
			AuthAlgo:      "ed25519",
			ZeroKnowledge: true,
		}, nil
	}
	return &EncryptionInfo{
		FormatVersion:    int(vaultFormatVersion),
		VaultID:          s.header.VaultID,
		Revision:         s.header.Revision,
		KDFAlgo:          s.header.KDFAlgo,
		KDFTime:          s.header.KDFTime,
		KDFMemoryKiB:     s.header.KDFMemoryKiB,
		KDFThreads:       s.header.KDFThreads,
		WrapAlgo:         s.header.WrapAlgo,
		CipherAlgo:       s.header.CipherAlgo,
		AuthAlgo:         s.header.AuthAlgo,
		AuthPubKeySHA256: sha256Hex(s.header.AuthPublicKey),
		VaultSizeBytes:   int64(len(s.lastBlob)),
		ZeroKnowledge:    true,
	}, nil
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

// RecordAudit logs an event inside the client-encrypted vault.
func (s *ClientVault) RecordAudit(action, target, detail, clientIP string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dek) == 0 || s.state == nil {
		return
	}
	_ = s.mutateLocked(func(st *VaultState) error {
		appendAuditLocked(st, action, target, detail, clientIP, success)
		return nil
	})
}

// --- Servers CRUD ---

func (s *ClientVault) ListServers() ([]ServerView, error) {
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

// GetServerSecret returns a deep copy of ServerConfig including decrypted credentials for client-side SSH dialing.
func (s *ClientVault) GetServerSecret(id string) (*ServerConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	for _, srv := range s.state.Servers {
		if srv.ID == id {
			cp := srv
			cp.Tags = slices.Clone(srv.Tags)
			cp.WatchedServices = slices.Clone(srv.WatchedServices)
			cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// ServerMutationInput represents create/update request fields for an SSH server.
type ServerMutationInput struct {
	Name              string   `json:"name"`
	Group             string   `json:"group"`
	Tags              []string `json:"tags"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Username          string   `json:"username"`
	AuthType          AuthType `json:"auth_type"`
	Password          *string  `json:"password,omitempty"`    // nil = keep existing on update
	PrivateKey        *string  `json:"private_key,omitempty"` // nil = keep existing on update
	Passphrase        *string  `json:"passphrase,omitempty"`  // nil = keep existing on update
	CredentialID      string   `json:"credential_id"`
	JumpServerID      string   `json:"jump_server_id"`
	DefaultPath       string   `json:"default_path"`
	Notes             string   `json:"notes"`
	Pinned            bool     `json:"pinned"`
	KeepAliveSec      int      `json:"keep_alive_sec"`
	MonitorEnabled    *bool    `json:"monitor_enabled,omitempty"`
	CustomIntervalSec *int     `json:"custom_interval_sec,omitempty"`
	WatchedServices   []string `json:"watched_services,omitempty"`
	WatchedPorts      []int    `json:"watched_ports,omitempty"`
}

func sanitizeServiceNames(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		clean := strings.TrimSpace(item)
		if clean == "" || len(clean) > 64 {
			continue
		}
		valid := true
		for _, ch := range clean {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '@') {
				valid = false
				break
			}
		}
		if valid && !slices.Contains(out, clean) {
			out = append(out, clean)
		}
	}
	return out
}

func sanitizePortList(raw []int) []int {
	out := make([]int, 0, len(raw))
	for _, p := range raw {
		if p > 0 && p <= 65535 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
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
	if in.CustomIntervalSec != nil {
		v := *in.CustomIntervalSec
		if v < 0 {
			v = 0
		} else if v > 0 && v < 10 {
			v = 10
		} else if v > 86400 {
			v = 86400
		}
		*in.CustomIntervalSec = v
	}
	if in.WatchedServices != nil {
		in.WatchedServices = sanitizeServiceNames(in.WatchedServices)
	}
	if in.WatchedPorts != nil {
		in.WatchedPorts = sanitizePortList(in.WatchedPorts)
	}
	return nil
}

func (s *ClientVault) CreateServer(in ServerMutationInput, clientIP string) (*ServerView, error) {
	if err := sanitizeServerInput(&in); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	newID := uuid.NewString()
	var view ServerView
	err := s.mutateLocked(func(st *VaultState) error {
		now := time.Now().UTC()
		srv := ServerConfig{
			ID:              newID,
			Name:            in.Name,
			Group:           in.Group,
			Tags:            slices.Clone(in.Tags),
			Host:            in.Host,
			Port:            in.Port,
			Username:        in.Username,
			AuthType:        in.AuthType,
			CredentialID:    in.CredentialID,
			JumpServerID:    in.JumpServerID,
			DefaultPath:     strings.TrimSpace(in.DefaultPath),
			Notes:           strings.TrimSpace(in.Notes),
			Pinned:          in.Pinned,
			KeepAliveSec:    in.KeepAliveSec,
			WatchedServices: slices.Clone(in.WatchedServices),
			WatchedPorts:    slices.Clone(in.WatchedPorts),
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if in.MonitorEnabled != nil {
			srv.MonitorDisabled = !(*in.MonitorEnabled)
		}
		if in.CustomIntervalSec != nil {
			srv.CustomIntervalSec = *in.CustomIntervalSec
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
		if !slices.Contains(st.Groups, srv.Group) {
			st.Groups = append(st.Groups, srv.Group)
		}
		st.Servers = append(st.Servers, srv)
		appendAuditLocked(st, "server.create", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "新增服务器资产配置", clientIP, true)
		view = srv.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &view, nil
}

func (s *ClientVault) UpdateServer(id string, in ServerMutationInput, clientIP string) (*ServerView, error) {
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

	var view ServerView
	err := s.mutateLocked(func(st *VaultState) error {
		idx := -1
		for i := range st.Servers {
			if st.Servers[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return ErrNotFound
		}

		srv := st.Servers[idx]
		srv.Name = in.Name
		srv.Group = in.Group
		srv.Tags = slices.Clone(in.Tags)
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
		if in.MonitorEnabled != nil {
			srv.MonitorDisabled = !(*in.MonitorEnabled)
		}
		if in.CustomIntervalSec != nil {
			srv.CustomIntervalSec = *in.CustomIntervalSec
		}
		if in.WatchedServices != nil {
			srv.WatchedServices = slices.Clone(in.WatchedServices)
		}
		if in.WatchedPorts != nil {
			srv.WatchedPorts = slices.Clone(in.WatchedPorts)
		}
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
		if !slices.Contains(st.Groups, srv.Group) {
			st.Groups = append(st.Groups, srv.Group)
		}
		st.Servers[idx] = srv
		appendAuditLocked(st, "server.update", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "更新服务器连接配置", clientIP, true)
		view = srv.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &view, nil
}

func (s *ClientVault) DeleteServer(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, srv := range st.Servers {
			if srv.ID == id {
				st.Servers = slices.Delete(st.Servers, i, i+1)
				for j := range st.Servers {
					if st.Servers[j].JumpServerID == id {
						st.Servers[j].JumpServerID = ""
					}
				}
				// Purge monitoring state associated with deleted server
				if st.Monitor != nil {
					delete(st.Monitor.LatestSnapshots, id)
					delete(st.Monitor.HistoryByServer, id)
					delete(st.Monitor.PortBaselines, id)
					prefix := id + "|"
					for k := range st.Monitor.BreachStreaks {
						if strings.HasPrefix(k, prefix) {
							delete(st.Monitor.BreachStreaks, k)
						}
					}
					st.Monitor.Alerts = slices.DeleteFunc(st.Monitor.Alerts, func(a MonitorAlert) bool {
						return a.ServerID == id
					})
				}
				appendAuditLocked(st, "server.delete", fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port), "删除服务器配置", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *ClientVault) UpdateServerRuntimeMeta(id string, latencyMs int64, osInfo string, connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	_ = s.mutateLocked(func(st *VaultState) error {
		for i := range st.Servers {
			if st.Servers[i].ID == id {
				if latencyMs > 0 {
					st.Servers[i].LastLatencyMs = latencyMs
				}
				if osInfo != "" {
					st.Servers[i].LastOSInfo = osInfo
				}
				if connected {
					now := time.Now().UTC()
					st.Servers[i].LastConnectedAt = &now
				}
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- Groups Management ---

func (s *ClientVault) ListGroups() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.Groups), nil
}

func (s *ClientVault) AddGroup(name string) ([]string, error) {
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
		if err := s.mutateLocked(func(st *VaultState) error {
			if !slices.Contains(st.Groups, name) {
				st.Groups = append(st.Groups, name)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return slices.Clone(s.state.Groups), nil
}

func (s *ClientVault) DeleteGroup(name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	if err := s.mutateLocked(func(st *VaultState) error {
		st.Groups = slices.DeleteFunc(st.Groups, func(g string) bool { return g == name })
		for i := range st.Servers {
			if st.Servers[i].Group == name {
				st.Servers[i].Group = "默认分组"
			}
		}
		return nil
	}); err != nil {
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

func (s *ClientVault) ListCredentials() ([]CredentialView, error) {
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

func (s *ClientVault) GetCredentialSecret(id string) (*Credential, error) {
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

func (s *ClientVault) CreateCredential(in CredentialMutationInput, clientIP string) (*CredentialView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || (in.Kind != AuthPassword && in.Kind != AuthPrivateKey) {
		return nil, fmt.Errorf("%w: 凭据名称与类型不合法", ErrInvalidInput)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	newID := uuid.NewString()
	var v CredentialView
	err := s.mutateLocked(func(st *VaultState) error {
		now := time.Now().UTC()
		cred := Credential{
			ID:           newID,
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
		st.Credentials = append(st.Credentials, cred)
		appendAuditLocked(st, "credential.create", cred.Name, fmt.Sprintf("新增加密凭据 (%s)", cred.Kind), clientIP, true)
		v = cred.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *ClientVault) UpdateCredential(id string, in CredentialMutationInput, clientIP string) (*CredentialView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || (in.Kind != AuthPassword && in.Kind != AuthPrivateKey) {
		return nil, ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}

	var v CredentialView
	err := s.mutateLocked(func(st *VaultState) error {
		for i := range st.Credentials {
			if st.Credentials[i].ID == id {
				cred := st.Credentials[i]
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
				st.Credentials[i] = cred
				appendAuditLocked(st, "credential.update", cred.Name, "更新加密凭据", clientIP, true)
				v = cred.ToView()
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *ClientVault) DeleteCredential(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, c := range st.Credentials {
			if c.ID == id {
				for _, srv := range st.Servers {
					if srv.AuthType == AuthCredential && srv.CredentialID == id {
						return fmt.Errorf("%w: 服务器 [%s] 正在使用该凭据，请先解除绑定", ErrInvalidInput, srv.Name)
					}
				}
				st.Credentials = slices.Delete(st.Credentials, i, i+1)
				appendAuditLocked(st, "credential.delete", c.Name, "删除加密凭据", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- Snippets CRUD ---

func (s *ClientVault) ListSnippets() ([]Snippet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.Snippets), nil
}

func (s *ClientVault) UpsertSnippet(in Snippet, clientIP string) (*Snippet, error) {
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

	newID := in.ID
	if newID == "" {
		newID = uuid.NewString()
	}
	var out Snippet
	err := s.mutateLocked(func(st *VaultState) error {
		now := time.Now().UTC()
		if in.ID != "" {
			for i := range st.Snippets {
				if st.Snippets[i].ID == in.ID {
					updated := in
					updated.CreatedAt = st.Snippets[i].CreatedAt
					updated.UpdatedAt = now
					st.Snippets[i] = updated
					appendAuditLocked(st, "snippet.update", updated.Title, "更新快捷指令", clientIP, true)
					out = updated
					return nil
				}
			}
		}
		created := in
		created.ID = newID
		created.CreatedAt = now
		created.UpdatedAt = now
		st.Snippets = append(st.Snippets, created)
		appendAuditLocked(st, "snippet.create", created.Title, "新增快捷指令", clientIP, true)
		out = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *ClientVault) DeleteSnippet(id, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, sn := range st.Snippets {
			if sn.ID == id {
				st.Snippets = slices.Delete(st.Snippets, i, i+1)
				appendAuditLocked(st, "snippet.delete", sn.Title, "删除快捷指令", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- KnownHosts (SSH Host Key Pinning / TOFU) ---

func (s *ClientVault) ListKnownHosts() ([]KnownHost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.state.KnownHosts), nil
}

func (s *ClientVault) GetKnownHost(address string) (*KnownHost, error) {
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

func (s *ClientVault) TrustKnownHost(kh KnownHost, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		now := time.Now().UTC()
		khCp := kh
		khCp.LastVerifiedAt = now
		for i := range st.KnownHosts {
			if st.KnownHosts[i].Address == khCp.Address {
				khCp.FirstSeenAt = st.KnownHosts[i].FirstSeenAt
				st.KnownHosts[i] = khCp
				appendAuditLocked(st, "hostkey.update", khCp.Address, fmt.Sprintf("更新信任的 SSH 主机指纹 (%s)", khCp.Fingerprint), clientIP, true)
				return nil
			}
		}
		khCp.FirstSeenAt = now
		st.KnownHosts = append(st.KnownHosts, khCp)
		appendAuditLocked(st, "hostkey.trust", khCp.Address, fmt.Sprintf("首次信任并固定 SSH 主机指纹 (%s)", khCp.Fingerprint), clientIP, true)
		return nil
	})
}

func (s *ClientVault) TouchKnownHostVerified(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return
	}
	_ = s.mutateLocked(func(st *VaultState) error {
		for i := range st.KnownHosts {
			if st.KnownHosts[i].Address == address {
				st.KnownHosts[i].LastVerifiedAt = time.Now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *ClientVault) DeleteKnownHost(address, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return ErrVaultLocked
	}
	return s.mutateLocked(func(st *VaultState) error {
		for i, kh := range st.KnownHosts {
			if kh.Address == address {
				st.KnownHosts = slices.Delete(st.KnownHosts, i, i+1)
				appendAuditLocked(st, "hostkey.delete", address, "移除已保存的 SSH 主机指纹记录", clientIP, true)
				return nil
			}
		}
		return ErrNotFound
	})
}

// --- Settings & Audit Logs ---

func (s *ClientVault) GetSettings() (*AppSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	cp := s.state.Settings
	return &cp, nil
}

func (s *ClientVault) UpdateSettings(in AppSettings, clientIP string) (*AppSettings, error) {
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
	in.RemoteSyncURL = strings.TrimSpace(in.RemoteSyncURL)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrVaultLocked
	}
	if err := s.mutateLocked(func(st *VaultState) error {
		st.Settings = in
		appendAuditLocked(st, "settings.update", "app", "更新安全策略与终端偏好设置", clientIP, true)
		return nil
	}); err != nil {
		return nil, err
	}
	cp := s.state.Settings
	return &cp, nil
}

func (s *ClientVault) ListAuditLogs(limit int) ([]AuditEntry, error) {
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
