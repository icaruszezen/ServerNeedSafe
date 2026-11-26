package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	maxAuditEntries        = 500
	defaultFlushDebounce   = 2 * time.Second
	secretsFileName        = "secrets.enc"
	monitorRuntimeFileName = "monitor_runtime.json"
	aiopsRuntimeFileName   = "aiops_runtime.json"
	auditRuntimeFileName   = "audit_logs.json"
	legacyVaultFileName    = "vault.sns"
)

var (
	ErrNotFound     = errors.New("目标记录不存在")
	ErrInvalidInput = errors.New("输入参数不合法")
)

// Store manages split-storage persistence for ServerNeedSafe:
//   - Sensitive credentials & configuration live in secrets.enc (XChaCha20-Poly1305 encrypted under
//     an auto-managed local master.key or SNS_MASTER_KEY env var, decoupled from the Web admin password).
//   - High-frequency operational data (monitor snapshots/history/alerts, AI sessions/memories/runbooks/patrol,
//     audit logs, server latency/online timestamps) lives in separate plain JSON files with independent
//     locking and debounced atomic flushing, so 7x24 background tasks never lock or rewrite secrets.enc.
type Store struct {
	dataDir     string
	secretsPath string
	monitorPath string
	aiopsPath   string
	auditPath   string
	legacyPath  string

	masterKey     []byte
	masterKeyMode string // "file" or "env"
	masterKeyPath string

	secMu                  sync.RWMutex
	secrets                *SecretsState
	secretsFileSize        int64
	legacyMigrationPending bool
	onReadyHooks           []func()

	rtMu            sync.RWMutex
	monitorRT       *MonitorRuntimeState
	aiopsRT         *AIOpsRuntimeState
	auditRT         *AuditRuntimeState
	dirtyMonitor    bool
	dirtyAIOps      bool
	dirtyAudit      bool
	monitorFileSize int64
	aiopsFileSize   int64
	auditFileSize   int64

	flushMu       sync.Mutex
	flushDebounce time.Duration
	flushWakeCh   chan struct{}
	stopCh        chan struct{}
	flusherDone   chan struct{}
	closeOnce     sync.Once
}

// NewStore opens or creates the split-storage data directory and immediately loads secrets.enc
// (or auto-migrates a legacy v2.x vault.sns + .vault.key) so 7x24 background engines start without locking.
// Passing either a directory path ("/data") or a legacy file path ("/data/vault.sns") is supported.
func NewStore(dataDirOrFile string) (*Store, error) {
	dataDir := strings.TrimSpace(dataDirOrFile)
	if dataDir == "" {
		dataDir = "./data"
	}
	lower := strings.ToLower(dataDir)
	if strings.HasSuffix(lower, ".sns") || strings.HasSuffix(lower, ".enc") {
		dataDir = filepath.Dir(dataDir)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	masterKey, keyMode, keyPath, err := loadOrCreateMasterKey(dataDir)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	s := &Store{
		dataDir:       dataDir,
		secretsPath:   filepath.Join(dataDir, secretsFileName),
		monitorPath:   filepath.Join(dataDir, monitorRuntimeFileName),
		aiopsPath:     filepath.Join(dataDir, aiopsRuntimeFileName),
		auditPath:     filepath.Join(dataDir, auditRuntimeFileName),
		legacyPath:    filepath.Join(dataDir, legacyVaultFileName),
		masterKey:     masterKey,
		masterKeyMode: keyMode,
		masterKeyPath: keyPath,
		monitorRT:     DefaultMonitorRuntimeState(),
		aiopsRT:       DefaultAIOpsRuntimeState(now),
		auditRT:       DefaultAuditRuntimeState(),
		flushDebounce: defaultFlushDebounce,
		flushWakeCh:   make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		flusherDone:   make(chan struct{}),
	}

	if err := s.loadInitialState(); err != nil {
		zeroBytes(s.masterKey)
		return nil, err
	}

	go s.flushLoop()
	return s, nil
}

func (s *Store) loadInitialState() error {
	// 1. Primary v3 path: secrets.enc exists
	if info, err := os.Stat(s.secretsPath); err == nil && !info.IsDir() && info.Size() > 0 {
		raw, err := os.ReadFile(s.secretsPath)
		if err != nil {
			return fmt.Errorf("read secrets.enc: %w", err)
		}
		sec, decErr := OpenSecretsBytes(s.masterKey, raw)
		if decErr != nil && s.masterKeyMode == MasterKeyModeEnv {
			// Operator may have switched from file master.key to SNS_MASTER_KEY: transparently re-seal once.
			if fileKey, fkErr := tryReadFileMasterKey(s.dataDir); fkErr == nil {
				if sec2, decErr2 := OpenSecretsBytes(fileKey, raw); decErr2 == nil {
					sec = sec2
					decErr = nil
					ensureSecretsDefaults(sec)
					if sealed, sErr := SealSecretsBytes(s.masterKey, sec); sErr == nil {
						if wErr := atomicWriteFile(s.secretsPath, sealed, 0o600, true); wErr == nil {
							raw = sealed
							log.Printf("[ServerNeedSafe] 已使用 SNS_MASTER_KEY 自动重新封装敏感资产库 %s", s.secretsPath)
						}
					}
				}
				zeroBytes(fileKey)
			}
		}
		if decErr != nil {
			return fmt.Errorf("decrypt secrets.enc: %w (请检查 master.key 或 SNS_MASTER_KEY 是否匹配)", decErr)
		}
		ensureSecretsDefaults(sec)
		s.secrets = sec
		s.secretsFileSize = int64(len(raw))
		s.loadRuntimeFilesBestEffort()
		return nil
	}

	// 2. Legacy v2.x upgrade path: vault.sns exists without secrets.enc
	if info, err := os.Stat(s.legacyPath); err == nil && !info.IsDir() && info.Size() > 0 {
		legacyRaw, err := os.ReadFile(s.legacyPath)
		if err != nil {
			return fmt.Errorf("read legacy vault.sns: %w", err)
		}
		hdr, legacyState, mErr := tryOpenLegacyVaultWithLocalKey(s.dataDir, legacyRaw)
		if mErr == nil && legacyState != nil {
			if err := s.migrateFromLegacyState(hdr, legacyState, ""); err != nil {
				return fmt.Errorf("auto-migrate legacy vault.sns: %w", err)
			}
			log.Printf("[ServerNeedSafe] 已自动将旧版 vault.sns + .vault.key 无感迁移至分层存储架构（secrets.enc + 独立运行态文件）")
			return nil
		}
		// Legacy vault.sns exists without a usable .vault.key: wait for one-time legacy password login.
		s.legacyMigrationPending = true
		log.Printf("[ServerNeedSafe] 检测到旧版 vault.sns（无可用 .vault.key），请通过 Web 登录输入一次原管理员密码完成永久自动升级")
		return nil
	}

	// 3. Fresh uninitialized install
	return nil
}

func (s *Store) loadRuntimeFilesBestEffort() {
	if raw, err := os.ReadFile(s.monitorPath); err == nil && len(raw) > 0 {
		var m MonitorRuntimeState
		if json.Unmarshal(raw, &m) == nil {
			ensureMonitorRuntimeDefaults(&m)
			s.monitorRT = &m
			s.monitorFileSize = int64(len(raw))
		} else {
			log.Printf("[ServerNeedSafe] 警告: monitor_runtime.json 解析失败，已重置为空运行态")
		}
	}
	if raw, err := os.ReadFile(s.aiopsPath); err == nil && len(raw) > 0 {
		var a AIOpsRuntimeState
		if json.Unmarshal(raw, &a) == nil {
			ensureAIOpsRuntimeDefaults(&a)
			s.aiopsRT = &a
			s.aiopsFileSize = int64(len(raw))
		} else {
			log.Printf("[ServerNeedSafe] 警告: aiops_runtime.json 解析失败，已重置为空运行态")
		}
	}
	if raw, err := os.ReadFile(s.auditPath); err == nil && len(raw) > 0 {
		var au AuditRuntimeState
		if json.Unmarshal(raw, &au) == nil {
			if au.AuditLogs == nil {
				au.AuditLogs = []AuditEntry{}
			}
			s.auditRT = &au
			s.auditFileSize = int64(len(raw))
		}
	}
}

// migrateFromLegacyState converts a decrypted legacy v1/v2 VaultState into v3 split storage and archives legacy files.
// Caller must either be in loadInitialState (single-threaded) or hold secMu.Lock().
func (s *Store) migrateFromLegacyState(hdr *LegacyEnvelopeHeader, st *VaultState, plaintextPassword string) error {
	ensureMonitorInitialized(st)
	EnsureStateDefaults(st)

	vaultID := st.VaultID
	if vaultID == "" && hdr != nil {
		vaultID = hdr.VaultID
	}
	if vaultID == "" {
		vaultID = uuid.NewString()
	}

	sec := &SecretsState{
		SchemaVersion:   3,
		VaultID:         vaultID,
		Revision:        max(uint64(1), st.Revision),
		AuthVersion:     1,
		CreatedAt:       st.CreatedAt,
		UpdatedAt:       time.Now().UTC(),
		Groups:          slices.Clone(st.Groups),
		Servers:         cloneServersWithoutRuntime(st.Servers),
		Credentials:     slices.Clone(st.Credentials),
		Snippets:        slices.Clone(st.Snippets),
		KnownHosts:      slices.Clone(st.KnownHosts),
		Settings:        st.Settings,
		MonitorSettings: st.Monitor.Settings,
		MonitorRules:    slices.Clone(st.Monitor.Rules),
		AISettings:      cloneAISettings(st.AISettings),
	}
	if plaintextPassword != "" {
		pwHash, err := HashAdminPassword(plaintextPassword)
		if err != nil {
			return err
		}
		sec.AdminPasswordHash = pwHash
	} else if hdr != nil && len(hdr.AuthPublicKey) > 0 && len(hdr.KDFSalt) >= 16 {
		sec.LegacyAuth = &LegacyPasswordVerifier{
			KDFTime:       hdr.KDFTime,
			KDFMemoryKiB:  hdr.KDFMemoryKiB,
			KDFThreads:    hdr.KDFThreads,
			KDFSalt:       slices.Clone(hdr.KDFSalt),
			AuthPublicKey: slices.Clone(hdr.AuthPublicKey),
		}
	}
	ensureSecretsDefaults(sec)

	monRT := DefaultMonitorRuntimeState()
	if st.Monitor != nil {
		monRT.LatestSnapshots = st.Monitor.LatestSnapshots
		monRT.HistoryByServer = st.Monitor.HistoryByServer
		monRT.Alerts = st.Monitor.Alerts
		monRT.BreachStreaks = st.Monitor.BreachStreaks
		monRT.PortBaselines = st.Monitor.PortBaselines
	}
	for _, srv := range st.Servers {
		if srv.LastConnectedAt != nil || srv.LastLatencyMs > 0 || srv.LastOSInfo != "" {
			monRT.ServerRuntime[srv.ID] = ServerRuntimeMeta{
				LastConnectedAt: srv.LastConnectedAt,
				LastLatencyMs:   srv.LastLatencyMs,
				LastOSInfo:      srv.LastOSInfo,
			}
		}
	}
	ensureMonitorRuntimeDefaults(monRT)

	aiRT := &AIOpsRuntimeState{
		HostMemories:    st.HostMemories,
		AIMemories:      st.AIMemories,
		Runbooks:        st.Runbooks,
		AISessions:      st.AISessions,
		PatrolBaselines: st.PatrolBaselines,
		PatrolRecords:   st.PatrolRecords,
	}
	ensureAIOpsRuntimeDefaults(aiRT)

	auditRT := &AuditRuntimeState{
		AuditLogs: slices.Clone(st.AuditLogs),
	}
	if auditRT.AuditLogs == nil {
		auditRT.AuditLogs = []AuditEntry{}
	}

	sealed, err := SealSecretsBytes(s.masterKey, sec)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.secretsPath, sealed, 0o600, true); err != nil {
		return err
	}

	s.secrets = sec
	s.secretsFileSize = int64(len(sealed))
	s.legacyMigrationPending = false

	s.rtMu.Lock()
	s.monitorRT = monRT
	s.aiopsRT = aiRT
	s.auditRT = auditRT
	s.dirtyMonitor = true
	s.dirtyAIOps = true
	s.dirtyAudit = true
	s.rtMu.Unlock()

	if err := s.FlushNow(); err != nil {
		return err
	}

	// Archive legacy vault.sns and remove obsolete .vault.key
	backupPath := s.legacyPath + ".migrated.bak"
	_ = os.Rename(s.legacyPath, backupPath)
	removeFileBestEffort(filepath.Join(s.dataDir, legacyKeyFileName))
	return nil
}

// SetFlushDebounce customizes the runtime JSON debounce interval (useful in fast unit tests).
func (s *Store) SetFlushDebounce(d time.Duration) {
	if d <= 0 {
		d = 50 * time.Millisecond
	}
	s.flushMu.Lock()
	s.flushDebounce = d
	s.flushMu.Unlock()
}

func (s *Store) triggerFlush() {
	select {
	case s.flushWakeCh <- struct{}{}:
	default:
	}
}

func (s *Store) flushLoop() {
	defer close(s.flusherDone)
	var timer *time.Timer
	var timerCh <-chan time.Time

	for {
		select {
		case <-s.stopCh:
			if timer != nil {
				timer.Stop()
			}
			_ = s.FlushNow()
			return
		case <-s.flushWakeCh:
			if timer == nil {
				s.flushMu.Lock()
				d := s.flushDebounce
				s.flushMu.Unlock()
				timer = time.NewTimer(d)
				timerCh = timer.C
			}
		case <-timerCh:
			timer = nil
			timerCh = nil
			_ = s.FlushNow()
		}
	}
}

// FlushNow synchronously persists any dirty non-secret runtime JSON files using atomic renames.
// It never touches secrets.enc and holds rtMu only briefly to serialize JSON.
func (s *Store) FlushNow() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	var monBytes, aiBytes, auditBytes []byte
	var err error

	s.rtMu.Lock()
	doMon := s.dirtyMonitor
	doAI := s.dirtyAIOps
	doAudit := s.dirtyAudit
	if doMon {
		monBytes, err = json.Marshal(s.monitorRT)
		if err != nil {
			s.rtMu.Unlock()
			return err
		}
		s.dirtyMonitor = false
	}
	if doAI {
		aiBytes, err = json.Marshal(s.aiopsRT)
		if err != nil {
			if doMon {
				s.dirtyMonitor = true
			}
			s.rtMu.Unlock()
			return err
		}
		s.dirtyAIOps = false
	}
	if doAudit {
		auditBytes, err = json.Marshal(s.auditRT)
		if err != nil {
			if doMon {
				s.dirtyMonitor = true
			}
			if doAI {
				s.dirtyAIOps = true
			}
			s.rtMu.Unlock()
			return err
		}
		s.dirtyAudit = false
	}
	s.rtMu.Unlock()

	var firstErr error
	if doMon {
		if wErr := atomicWriteFile(s.monitorPath, monBytes, 0o600, false); wErr != nil {
			s.rtMu.Lock()
			s.dirtyMonitor = true
			s.rtMu.Unlock()
			firstErr = wErr
		} else {
			s.rtMu.Lock()
			s.monitorFileSize = int64(len(monBytes))
			s.rtMu.Unlock()
		}
	}
	if doAI {
		if wErr := atomicWriteFile(s.aiopsPath, aiBytes, 0o600, false); wErr != nil {
			s.rtMu.Lock()
			s.dirtyAIOps = true
			s.rtMu.Unlock()
			if firstErr == nil {
				firstErr = wErr
			}
		} else {
			s.rtMu.Lock()
			s.aiopsFileSize = int64(len(aiBytes))
			s.rtMu.Unlock()
		}
	}
	if doAudit {
		if wErr := atomicWriteFile(s.auditPath, auditBytes, 0o600, false); wErr != nil {
			s.rtMu.Lock()
			s.dirtyAudit = true
			s.rtMu.Unlock()
			if firstErr == nil {
				firstErr = wErr
			}
		} else {
			s.rtMu.Lock()
			s.auditFileSize = int64(len(auditBytes))
			s.rtMu.Unlock()
		}
	}
	return firstErr
}

// Close flushes all pending runtime JSON updates synchronously and stops the background flusher.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		<-s.flusherDone
	})
}

// DataDir returns the root directory containing secrets.enc, master.key, and runtime JSON files.
func (s *Store) DataDir() string {
	return s.dataDir
}

// SecretsPath returns the full path to the encrypted secrets.enc file.
func (s *Store) SecretsPath() string {
	return s.secretsPath
}

// MasterKeyPath returns the path to master.key (empty when using SNS_MASTER_KEY env mode).
func (s *Store) MasterKeyPath() string {
	return s.masterKeyPath
}

// MasterKeyMode returns "env" when SNS_MASTER_KEY is active, or "file" when using master.key.
func (s *Store) MasterKeyMode() string {
	return s.masterKeyMode
}

// RegisterOnReady registers a callback fired when the store transitions from uninitialized/legacy-pending to ready.
func (s *Store) RegisterOnReady(fn func()) {
	s.secMu.Lock()
	s.onReadyHooks = append(s.onReadyHooks, fn)
	s.secMu.Unlock()
}

// RegisterOnUnlock is an alias for RegisterOnReady for clean wiring with background engines.
func (s *Store) RegisterOnUnlock(fn func()) {
	s.RegisterOnReady(fn)
}

func (s *Store) fireReadyHooks(hooks []func()) {
	for _, fn := range hooks {
		fn()
	}
}

// Status reports whether the store is ready (StatusUnlocked), awaiting legacy v2.0 password migration (StatusLocked),
// or fresh (StatusUninitialized).
func (s *Store) Status() VaultStatus {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets != nil {
		return StatusUnlocked
	}
	if s.legacyMigrationPending {
		return StatusLocked
	}
	return StatusUninitialized
}

// IsInitialized returns true when either secrets.enc is mounted or a legacy vault.sns awaits one-time migration.
func (s *Store) IsInitialized() bool {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	return s.secrets != nil || s.legacyMigrationPending
}

// IsReady returns true when secrets.enc is mounted and 7x24 background jobs can read credentials and run.
func (s *Store) IsReady() bool {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	return s.secrets != nil
}

// IsLegacyMigrationPending returns true only when an old vault.sns without .vault.key awaits one-time password migration.
func (s *Store) IsLegacyMigrationPending() bool {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	return s.secrets == nil && s.legacyMigrationPending
}

// AuthVersion returns the monotonic session generation (incremented on password change / full restore).
func (s *Store) AuthVersion() uint64 {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return 0
	}
	return s.secrets.AuthVersion
}

// Setup initializes the admin login password hash and creates secrets.enc + runtime JSON files.
func (s *Store) Setup(password, clientIP string) error {
	pwHash, err := HashAdminPassword(password)
	if err != nil {
		return err
	}

	s.secMu.Lock()
	if s.secrets != nil || s.legacyMigrationPending {
		s.secMu.Unlock()
		return ErrVaultAlreadyInit
	}

	sec := DefaultSecretsState(uuid.NewString())
	sec.AdminPasswordHash = pwHash
	ensureSecretsDefaults(sec)

	sealed, err := SealSecretsBytes(s.masterKey, sec)
	if err != nil {
		s.secMu.Unlock()
		return err
	}
	if err := atomicWriteFile(s.secretsPath, sealed, 0o600, true); err != nil {
		s.secMu.Unlock()
		return err
	}

	s.secrets = sec
	s.secretsFileSize = int64(len(sealed))
	hooks := slices.Clone(s.onReadyHooks)
	s.secMu.Unlock()

	now := time.Now().UTC()
	s.rtMu.Lock()
	s.monitorRT = DefaultMonitorRuntimeState()
	s.aiopsRT = DefaultAIOpsRuntimeState(now)
	s.auditRT = DefaultAuditRuntimeState()
	s.appendAuditRuntimeLocked("vault.setup", "secrets.enc", "初始化管理员密码与分层加密存储（敏感凭据独立加密 + 后台运行态拆分）", clientIP, true)
	s.dirtyMonitor = true
	s.dirtyAIOps = true
	s.dirtyAudit = true
	s.rtMu.Unlock()

	_ = s.FlushNow()
	s.fireReadyHooks(hooks)
	return nil
}

// VerifyPassword verifies the admin login password. If the store was auto-migrated from a legacy v2.x vault
// before the admin logged in, a successful login transparently upgrades LegacyAuth to AdminPasswordHash.
func (s *Store) VerifyPassword(password string) error {
	if password == "" {
		return ErrInvalidPassword
	}
	s.secMu.RLock()
	if s.secrets == nil {
		pending := s.legacyMigrationPending
		s.secMu.RUnlock()
		if pending {
			return ErrVaultLocked
		}
		return ErrVaultNotInit
	}
	pwHash := s.secrets.AdminPasswordHash
	var legacyCopy *LegacyPasswordVerifier
	if s.secrets.LegacyAuth != nil {
		cp := *s.secrets.LegacyAuth
		cp.KDFSalt = slices.Clone(s.secrets.LegacyAuth.KDFSalt)
		cp.AuthPublicKey = slices.Clone(s.secrets.LegacyAuth.AuthPublicKey)
		legacyCopy = &cp
	}
	s.secMu.RUnlock()

	if pwHash != "" {
		if !VerifyAdminPassword(password, pwHash) {
			return ErrInvalidPassword
		}
		return nil
	}
	if legacyCopy != nil {
		if !VerifyLegacyAuth(password, legacyCopy) {
			return ErrInvalidPassword
		}
		// Transparently upgrade legacy password verifier to fast lightweight Argon2id hash.
		if newHash, err := HashAdminPassword(password); err == nil {
			s.secMu.Lock()
			if s.secrets != nil && s.secrets.AdminPasswordHash == "" {
				_ = s.mutateSecretsLocked(func(sec *SecretsState) error {
					sec.AdminPasswordHash = newHash
					sec.LegacyAuth = nil
					return nil
				})
			}
			s.secMu.Unlock()
		}
		return nil
	}
	return ErrInvalidPassword
}

// LoginWithPassword verifies the admin password, transparently completing a one-time legacy v2.0 migration
// if vault.sns existed without .vault.key.
func (s *Store) LoginWithPassword(password, clientIP string) error {
	if password == "" {
		return ErrInvalidPassword
	}
	if s.IsLegacyMigrationPending() {
		return s.MigrateLegacyVaultWithPassword(password, clientIP)
	}
	return s.VerifyPassword(password)
}

// MigrateLegacyVaultWithPassword decrypts a legacy vault.sns (without .vault.key) once using its password
// and permanently migrates it to v3 split storage so it never locks again.
func (s *Store) MigrateLegacyVaultWithPassword(password, clientIP string) error {
	if password == "" {
		return ErrInvalidPassword
	}
	legacyRaw, err := os.ReadFile(s.legacyPath)
	if err != nil {
		return fmt.Errorf("读取旧版 vault.sns 失败: %w", err)
	}
	hdr, legacyState, _, err := OpenLegacyVaultContainer(legacyRaw, password)
	if err != nil {
		return err
	}

	s.secMu.Lock()
	if s.secrets != nil {
		s.secMu.Unlock()
		return nil
	}
	if err := s.migrateFromLegacyState(hdr, legacyState, password); err != nil {
		s.secMu.Unlock()
		return err
	}
	hooks := slices.Clone(s.onReadyHooks)
	s.secMu.Unlock()

	s.RecordAudit("vault.migrate", "secrets.enc", "完成旧版 vault.sns 一次性密码迁移至分层免锁存储架构", clientIP, true)
	s.fireReadyHooks(hooks)
	return nil
}

// ChangePassword updates ONLY the admin login password hash and increments AuthVersion.
// It does NOT change the master encryption key and NEVER interrupts background monitoring or AI patrol.
func (s *Store) ChangePassword(oldPassword, newPassword, clientIP string) error {
	if len([]rune(newPassword)) < 8 {
		return ErrWeakPassword
	}
	if err := s.VerifyPassword(oldPassword); err != nil {
		s.RecordAudit("auth.password_change_failed", "admin", "修改管理员密码失败：原密码校验未通过", clientIP, false)
		return ErrInvalidPassword
	}

	newHash, err := HashAdminPassword(newPassword)
	if err != nil {
		return err
	}

	s.secMu.Lock()
	if s.secrets == nil {
		s.secMu.Unlock()
		return ErrVaultNotInit
	}
	err = s.mutateSecretsLocked(func(sec *SecretsState) error {
		sec.AdminPasswordHash = newHash
		sec.LegacyAuth = nil
		sec.AuthVersion++
		return nil
	})
	s.secMu.Unlock()
	if err != nil {
		return err
	}

	s.RecordAudit("auth.password_changed", "admin", "管理员登录密码已更新，其他设备 Web 会话已注销（后台监控与巡检保持运行）", clientIP, true)
	return nil
}

// EncryptionInfo returns read-only encryption metadata.
func (s *Store) EncryptionInfo() (*EncryptionInfo, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return &EncryptionInfo{
			FormatVersion:    3,
			CipherAlgo:       "xchacha20-poly1305",
			PasswordHashAlgo: "argon2id-16m",
			MasterKeyMode:    s.masterKeyMode,
		}, nil
	}
	return &EncryptionInfo{
		FormatVersion:    3,
		VaultID:          s.secrets.VaultID,
		Revision:         s.secrets.Revision,
		CipherAlgo:       "xchacha20-poly1305",
		PasswordHashAlgo: "argon2id-16m",
		MasterKeyMode:    s.masterKeyMode,
		VaultSizeBytes:   s.secretsFileSize,
	}, nil
}

// StorageInfo returns on-disk split storage footprint metrics for the Security Center UI.
func (s *Store) StorageInfo() StorageFilesInfo {
	s.secMu.RLock()
	secSize := s.secretsFileSize
	s.secMu.RUnlock()

	s.rtMu.RLock()
	monSize := s.monitorFileSize
	aiSize := s.aiopsFileSize
	audSize := s.auditFileSize
	s.rtMu.RUnlock()

	return StorageFilesInfo{
		DataDir:           s.dataDir,
		SecretsPath:       s.secretsPath,
		SecretsSizeBytes:  secSize,
		MasterKeyMode:     s.masterKeyMode,
		MasterKeyPath:     s.masterKeyPath,
		MonitorSizeBytes:  monSize,
		AIOpsSizeBytes:    aiSize,
		AuditSizeBytes:    audSize,
		RuntimeTotalBytes: monSize + aiSize + audSize,
	}
}

// --- Portable Backup Export/Import & Simplified Cross-Instance Sync ---

// BuildBackupBundle constructs a portable BackupBundle / SyncSnapshot.
// Core configuration (including encrypted secrets) and AI knowledge (HostMemories, AIMemories, Runbooks)
// are always included; operational history (monitor telemetry, alerts, AI chats, patrol records, audit logs)
// is included when includeRuntime is true.
func (s *Store) BuildBackupBundle(includeRuntime bool) (*BackupBundle, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultNotInit
	}
	sec := cloneSecretsState(s.secrets)
	s.secMu.RUnlock()

	s.rtMu.RLock()
	aiKnow := AIKnowledgeSnapshot{
		HostMemories: cloneHostMemories(s.aiopsRT.HostMemories),
		AIMemories:   cloneAIMemories(s.aiopsRT.AIMemories),
		Runbooks:     cloneRunbooks(s.aiopsRT.Runbooks),
	}
	var rtSnap *RuntimeDataSnapshot
	if includeRuntime {
		rtSnap = &RuntimeDataSnapshot{
			Monitor:           cloneMonitorRuntimeState(s.monitorRT),
			AISessions:        cloneAISessions(s.aiopsRT.AISessions),
			PatrolBaselines:   clonePatrolBaselines(s.aiopsRT.PatrolBaselines),
			PatrolRecords:     clonePatrolRecords(s.aiopsRT.PatrolRecords),
			ExternalApprovals: cloneExternalApprovals(s.aiopsRT.ExternalApprovals),
			AuditLogs:         slices.Clone(s.auditRT.AuditLogs),
		}
	}
	s.rtMu.RUnlock()

	return &BackupBundle{
		SchemaVersion:  3,
		IncludeRuntime: includeRuntime,
		ExportedAt:     time.Now().UTC(),
		Config: CoreConfigSnapshot{
			VaultID:         sec.VaultID,
			Revision:        sec.Revision,
			Groups:          sec.Groups,
			Servers:         sec.Servers,
			Credentials:     sec.Credentials,
			Snippets:        sec.Snippets,
			KnownHosts:      sec.KnownHosts,
			Settings:        sec.Settings,
			MonitorSettings: sec.MonitorSettings,
			MonitorRules:    sec.MonitorRules,
			AISettings:      sec.AISettings,
		},
		AIKnowledge: aiKnow,
		Runtime:     rtSnap,
	}, nil
}

// ExportBackupBytes builds and encrypts a portable password-protected .sns v3 backup container.
func (s *Store) ExportBackupBytes(backupPassword string, includeRuntime bool, clientIP string) ([]byte, error) {
	if len([]rune(backupPassword)) < 8 {
		return nil, ErrWeakPassword
	}
	bundle, err := s.BuildBackupBundle(includeRuntime)
	if err != nil {
		return nil, err
	}
	raw, err := SealBackupContainer(backupPassword, bundle)
	if err != nil {
		return nil, err
	}
	scopeLabel := "核心配置与 AI 记忆"
	if includeRuntime {
		scopeLabel = "全量配置、AI 记忆与监控/巡检运行数据"
	}
	s.RecordAudit("vault.export", "backup.sns", fmt.Sprintf("导出加密备份包 (.sns · %s, %.1f KB)", scopeLabel, float64(len(raw))/1024.0), clientIP, true)
	return raw, nil
}

// ApplySyncSnapshot applies a BackupBundle / SyncSnapshot onto this Store.
//   - On an uninitialized store, initAdminPassword sets the initial Web admin login password.
//   - On an already-initialized store, the existing admin login password is preserved.
//   - When includeRuntime is false, existing 7x24 monitor history, alerts, AI sessions, patrol records, and audit logs are preserved.
func (s *Store) ApplySyncSnapshot(bundle *BackupBundle, includeRuntime bool, initAdminPassword string, clientIP string, auditAction string) error {
	if bundle == nil {
		return ErrCorruptedVault
	}

	s.secMu.Lock()
	wasReady := s.secrets != nil
	var nextSec *SecretsState
	if wasReady {
		nextSec = cloneSecretsState(s.secrets)
		nextSec.Revision++
	} else {
		pwHash, err := HashAdminPassword(initAdminPassword)
		if err != nil {
			s.secMu.Unlock()
			return err
		}
		vid := strings.TrimSpace(bundle.Config.VaultID)
		if vid == "" {
			vid = uuid.NewString()
		}
		nextSec = DefaultSecretsState(vid)
		nextSec.AdminPasswordHash = pwHash
		if bundle.Config.Revision > 0 {
			nextSec.Revision = bundle.Config.Revision + 1
		}
	}

	nextSec.UpdatedAt = time.Now().UTC()
	nextSec.Groups = slices.Clone(bundle.Config.Groups)
	nextSec.Servers = cloneServersWithoutRuntime(bundle.Config.Servers)
	nextSec.Credentials = slices.Clone(bundle.Config.Credentials)
	nextSec.Snippets = slices.Clone(bundle.Config.Snippets)
	nextSec.KnownHosts = slices.Clone(bundle.Config.KnownHosts)
	nextSec.Settings = bundle.Config.Settings
	nextSec.MonitorSettings = bundle.Config.MonitorSettings
	nextSec.MonitorRules = slices.Clone(bundle.Config.MonitorRules)
	nextSec.AISettings = cloneAISettings(bundle.Config.AISettings)
	ensureSecretsDefaults(nextSec)

	sealed, err := SealSecretsBytes(s.masterKey, nextSec)
	if err != nil {
		s.secMu.Unlock()
		return err
	}
	if err := atomicWriteFile(s.secretsPath, sealed, 0o600, true); err != nil {
		s.secMu.Unlock()
		return err
	}

	s.secrets = nextSec
	s.secretsFileSize = int64(len(sealed))
	s.legacyMigrationPending = false
	hooks := slices.Clone(s.onReadyHooks)
	s.secMu.Unlock()

	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.monitorRT = DefaultMonitorRuntimeState()
	}
	if s.aiopsRT == nil {
		s.aiopsRT = DefaultAIOpsRuntimeState(time.Now().UTC())
	}
	if s.auditRT == nil {
		s.auditRT = DefaultAuditRuntimeState()
	}

	// Always synchronize AI SRE knowledge (host profiles, long-term memories, runbooks).
	s.aiopsRT.HostMemories = cloneHostMemories(bundle.AIKnowledge.HostMemories)
	s.aiopsRT.AIMemories = cloneAIMemories(bundle.AIKnowledge.AIMemories)
	if bundle.AIKnowledge.Runbooks != nil {
		s.aiopsRT.Runbooks = cloneRunbooks(bundle.AIKnowledge.Runbooks)
	}
	s.dirtyAIOps = true

	if includeRuntime && bundle.Runtime != nil {
		if bundle.Runtime.Monitor != nil {
			s.monitorRT = cloneMonitorRuntimeState(bundle.Runtime.Monitor)
			ensureMonitorRuntimeDefaults(s.monitorRT)
			s.dirtyMonitor = true
		}
		if bundle.Runtime.AISessions != nil {
			s.aiopsRT.AISessions = cloneAISessions(bundle.Runtime.AISessions)
		}
		if bundle.Runtime.PatrolBaselines != nil {
			s.aiopsRT.PatrolBaselines = clonePatrolBaselines(bundle.Runtime.PatrolBaselines)
		}
		if bundle.Runtime.PatrolRecords != nil {
			s.aiopsRT.PatrolRecords = clonePatrolRecords(bundle.Runtime.PatrolRecords)
		}
		if bundle.Runtime.ExternalApprovals != nil {
			s.aiopsRT.ExternalApprovals = cloneExternalApprovals(bundle.Runtime.ExternalApprovals)
		}
		if bundle.Runtime.AuditLogs != nil {
			s.auditRT.AuditLogs = slices.Clone(bundle.Runtime.AuditLogs)
			if len(s.auditRT.AuditLogs) > maxAuditEntries {
				s.auditRT.AuditLogs = s.auditRT.AuditLogs[:maxAuditEntries]
			}
		}
	}
	ensureAIOpsRuntimeDefaults(s.aiopsRT)

	if auditAction == "" {
		auditAction = "vault.import"
	}
	scopeDesc := "核心配置与 AI 记忆（保留本地监控/巡检运行数据）"
	if includeRuntime && bundle.Runtime != nil {
		scopeDesc = "全量配置、AI 记忆与监控/巡检运行数据"
	}
	s.appendAuditRuntimeLocked(auditAction, "secrets.enc", fmt.Sprintf("导入/同步完成 (%s)", scopeDesc), clientIP, true)
	s.dirtyAudit = true
	s.rtMu.Unlock()

	if err := s.FlushNow(); err != nil {
		return err
	}
	// If migrating over a pending legacy vault.sns, archive it so next restart uses secrets.enc cleanly.
	if _, err := os.Stat(s.legacyPath); err == nil {
		_ = os.Rename(s.legacyPath, s.legacyPath+".migrated.bak")
		removeFileBestEffort(filepath.Join(s.dataDir, legacyKeyFileName))
	}
	if !wasReady {
		s.fireReadyHooks(hooks)
	}
	return nil
}

// ImportBackupBytes decrypts a v1, v2, or v3 .sns backup file and restores it onto this Store.
func (s *Store) ImportBackupBytes(raw []byte, backupPassword string, includeRuntime bool, clientIP string) error {
	bundle, _, err := OpenBackupContainer(raw, backupPassword)
	if err != nil {
		return err
	}
	return s.ApplySyncSnapshot(bundle, includeRuntime, backupPassword, clientIP, "vault.import")
}

// --- Internal Secrets Mutation & State Normalization Helpers ---

func (s *Store) mutateSecretsLocked(mutFn func(sec *SecretsState) error) error {
	if s.secrets == nil {
		if s.legacyMigrationPending {
			return ErrVaultLocked
		}
		return ErrVaultNotInit
	}
	working := cloneSecretsState(s.secrets)
	if err := mutFn(working); err != nil {
		return err
	}
	working.UpdatedAt = time.Now().UTC()
	working.Revision++
	ensureSecretsDefaults(working)

	sealed, err := SealSecretsBytes(s.masterKey, working)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.secretsPath, sealed, 0o600, true); err != nil {
		return err
	}
	s.secrets = working
	s.secretsFileSize = int64(len(sealed))
	return nil
}

func (s *Store) mutateSecrets(mutFn func(sec *SecretsState) error) error {
	s.secMu.Lock()
	defer s.secMu.Unlock()
	return s.mutateSecretsLocked(mutFn)
}

func ensureSecretsDefaults(sec *SecretsState) {
	if sec == nil {
		return
	}
	now := time.Now().UTC()
	if sec.SchemaVersion < 3 {
		sec.SchemaVersion = 3
	}
	if sec.VaultID == "" {
		sec.VaultID = uuid.NewString()
	}
	if sec.Revision == 0 {
		sec.Revision = 1
	}
	if sec.AuthVersion == 0 {
		sec.AuthVersion = 1
	}
	if sec.Groups == nil {
		sec.Groups = []string{}
	}
	if sec.Servers == nil {
		sec.Servers = []ServerConfig{}
	}
	if sec.Credentials == nil {
		sec.Credentials = []Credential{}
	}
	if sec.Snippets == nil {
		sec.Snippets = []Snippet{}
	}
	if sec.KnownHosts == nil {
		sec.KnownHosts = []KnownHost{}
	}
	if sec.Settings.TerminalFontSize < 10 || sec.Settings.TerminalFontSize > 28 {
		sec.Settings.TerminalFontSize = 14
	}
	if sec.Settings.TerminalScrollback < 500 || sec.Settings.TerminalScrollback > 50000 {
		sec.Settings.TerminalScrollback = 5000
	}
	if sec.Settings.HostKeyPolicy != HostKeyAskNew && sec.Settings.HostKeyPolicy != HostKeyTOFU {
		sec.Settings.HostKeyPolicy = HostKeyTOFU
	}
	if sec.MonitorSettings.IntervalSec == 0 && sec.MonitorSettings.RetentionPoints == 0 {
		sec.MonitorSettings = DefaultMonitorSettings()
	} else {
		sec.MonitorSettings = sanitizeMonitorSettings(sec.MonitorSettings)
	}
	sec.MonitorRules = mergeMonitorAlertRules(sec.MonitorRules)

	if sec.AISettings.DefaultMode == "" {
		sec.AISettings.DefaultMode = AIModeStandard
	}
	if sec.AISettings.Providers == nil {
		sec.AISettings.Providers = []AIProviderConfig{}
	}
	if sec.AISettings.Patrol.IntervalMinutes <= 0 {
		def := DefaultPatrolConfig()
		sec.AISettings.Patrol.IntervalMinutes = def.IntervalMinutes
		sec.AISettings.Patrol.CPUWarnPercent = def.CPUWarnPercent
		sec.AISettings.Patrol.MemWarnPercent = def.MemWarnPercent
		sec.AISettings.Patrol.DiskWarnPercent = def.DiskWarnPercent
		sec.AISettings.Patrol.SSHFailWarnCount = def.SSHFailWarnCount
		sec.AISettings.Patrol.CheckListeningPorts = def.CheckListeningPorts
		sec.AISettings.Patrol.CheckPrivilegedUsers = def.CheckPrivilegedUsers
		sec.AISettings.Patrol.AnalysisMode = def.AnalysisMode
		sec.AISettings.Patrol.ExternalFallbackMinutes = def.ExternalFallbackMinutes
		sec.AISettings.Patrol.NotifyPendingApprovals = def.NotifyPendingApprovals
	}
	sec.AISettings.Patrol.AnalysisMode = NormalizePatrolAnalysisMode(sec.AISettings.Patrol.AnalysisMode)
	if sec.AISettings.Patrol.ExternalFallbackMinutes <= 0 {
		sec.AISettings.Patrol.ExternalFallbackMinutes = 15
	}
	if sec.AISettings.Patrol.ServerIDs == nil {
		sec.AISettings.Patrol.ServerIDs = []string{}
	}
	if sec.AISettings.Patrol.Webhooks == nil {
		sec.AISettings.Patrol.Webhooks = []WebhookChannel{}
	}
	if sec.AISettings.MCP.DesktopLoopbackPort < 1024 || sec.AISettings.MCP.DesktopLoopbackPort > 65535 {
		sec.AISettings.MCP.DesktopLoopbackPort = DefaultMCPConfig().DesktopLoopbackPort
	}
	if sec.AISettings.MCP.Tokens == nil {
		sec.AISettings.MCP.Tokens = []MCPToken{}
	}
	if !sec.AISettings.AgentsMD.Initialized && sec.AISettings.AgentsMD.Revision == 0 && sec.AISettings.AgentsMD.Content == "" {
		sec.AISettings.AgentsMD = DefaultAgentsMDConfig(now)
	}
	if !sec.AISettings.MemoryConfig.Initialized && sec.AISettings.MemoryConfig.AgentsMDMaxChars == 0 {
		sec.AISettings.MemoryConfig = DefaultAIMemoryConfig()
	} else {
		sec.AISettings.MemoryConfig = SanitizeAIMemoryConfig(sec.AISettings.MemoryConfig)
	}
}

func ensureMonitorRuntimeDefaults(m *MonitorRuntimeState) {
	if m == nil {
		return
	}
	if m.LatestSnapshots == nil {
		m.LatestSnapshots = make(map[string]*ServerMonitorSnapshot)
	}
	if m.HistoryByServer == nil {
		m.HistoryByServer = make(map[string][]MonitorSamplePoint)
	}
	if m.Alerts == nil {
		m.Alerts = []MonitorAlert{}
	}
	if m.BreachStreaks == nil {
		m.BreachStreaks = make(map[string]int)
	}
	if m.PortBaselines == nil {
		m.PortBaselines = make(map[string][]string)
	}
	if m.ServerRuntime == nil {
		m.ServerRuntime = make(map[string]ServerRuntimeMeta)
	}
	if m.KnownHostLastVerified == nil {
		m.KnownHostLastVerified = make(map[string]time.Time)
	}
}

func ensureAIOpsRuntimeDefaults(a *AIOpsRuntimeState) {
	if a == nil {
		return
	}
	if a.HostMemories == nil {
		a.HostMemories = []HostMemory{}
	}
	if a.AIMemories == nil {
		a.AIMemories = []AIMemoryEntry{}
	}
	if a.Runbooks == nil {
		a.Runbooks = DefaultStarterRunbooks(time.Now().UTC())
	}
	if a.AISessions == nil {
		a.AISessions = []AIChatSession{}
	}
	if a.PatrolBaselines == nil {
		a.PatrolBaselines = []ServerBaselineSnapshot{}
	}
	if a.PatrolRecords == nil {
		a.PatrolRecords = []PatrolRecord{}
	}
	if a.ExternalApprovals == nil {
		a.ExternalApprovals = []ExternalApproval{}
	}
	if a.MCPTokenUsage == nil {
		a.MCPTokenUsage = make(map[string]MCPTokenRuntimeUsage)
	}
}

func cloneServersWithoutRuntime(servers []ServerConfig) []ServerConfig {
	out := make([]ServerConfig, len(servers))
	for i, srv := range servers {
		cp := srv
		cp.Tags = slices.Clone(srv.Tags)
		cp.WatchedServices = slices.Clone(srv.WatchedServices)
		cp.WatchedPorts = slices.Clone(srv.WatchedPorts)
		cp.LastConnectedAt = nil
		cp.LastLatencyMs = 0
		cp.LastOSInfo = ""
		out[i] = cp
	}
	return out
}

func cloneAISettings(src AISettings) AISettings {
	dst := src
	dst.Providers = slices.Clone(src.Providers)
	dst.Patrol.ServerIDs = slices.Clone(src.Patrol.ServerIDs)
	dst.Patrol.Webhooks = slices.Clone(src.Patrol.Webhooks)
	dst.MCP.Tokens = cloneMCPTokens(src.MCP.Tokens)
	return dst
}

func cloneSecretsState(src *SecretsState) *SecretsState {
	if src == nil {
		return nil
	}
	cp := *src
	if src.LegacyAuth != nil {
		la := *src.LegacyAuth
		la.KDFSalt = slices.Clone(src.LegacyAuth.KDFSalt)
		la.AuthPublicKey = slices.Clone(src.LegacyAuth.AuthPublicKey)
		cp.LegacyAuth = &la
	}
	cp.Groups = slices.Clone(src.Groups)
	cp.Servers = cloneServersWithoutRuntime(src.Servers)
	cp.Credentials = slices.Clone(src.Credentials)
	cp.Snippets = slices.Clone(src.Snippets)
	cp.KnownHosts = slices.Clone(src.KnownHosts)
	cp.MonitorRules = slices.Clone(src.MonitorRules)
	cp.AISettings = cloneAISettings(src.AISettings)
	return &cp
}

func cloneMonitorRuntimeState(in *MonitorRuntimeState) *MonitorRuntimeState {
	if in == nil {
		return DefaultMonitorRuntimeState()
	}
	cp := &MonitorRuntimeState{
		LatestSnapshots:       make(map[string]*ServerMonitorSnapshot, len(in.LatestSnapshots)),
		HistoryByServer:       make(map[string][]MonitorSamplePoint, len(in.HistoryByServer)),
		Alerts:                make([]MonitorAlert, len(in.Alerts)),
		BreachStreaks:         make(map[string]int, len(in.BreachStreaks)),
		PortBaselines:         make(map[string][]string, len(in.PortBaselines)),
		ServerRuntime:         make(map[string]ServerRuntimeMeta, len(in.ServerRuntime)),
		KnownHostLastVerified: make(map[string]time.Time, len(in.KnownHostLastVerified)),
	}
	for k, v := range in.LatestSnapshots {
		cp.LatestSnapshots[k] = cloneSnapshot(v)
	}
	for k, v := range in.HistoryByServer {
		cp.HistoryByServer[k] = slices.Clone(v)
	}
	for i, al := range in.Alerts {
		alCp := al
		if al.AcknowledgedAt != nil {
			t := *al.AcknowledgedAt
			alCp.AcknowledgedAt = &t
		}
		if al.ResolvedAt != nil {
			t := *al.ResolvedAt
			alCp.ResolvedAt = &t
		}
		cp.Alerts[i] = alCp
	}
	for k, v := range in.BreachStreaks {
		cp.BreachStreaks[k] = v
	}
	for k, v := range in.PortBaselines {
		cp.PortBaselines[k] = slices.Clone(v)
	}
	for k, v := range in.ServerRuntime {
		meta := v
		if v.LastConnectedAt != nil {
			t := *v.LastConnectedAt
			meta.LastConnectedAt = &t
		}
		cp.ServerRuntime[k] = meta
	}
	for k, v := range in.KnownHostLastVerified {
		cp.KnownHostLastVerified[k] = v
	}
	return cp
}

func cloneHostMemories(in []HostMemory) []HostMemory {
	out := make([]HostMemory, len(in))
	for i, m := range in {
		cp := m
		cp.KeyServices = slices.Clone(m.KeyServices)
		cp.DeployPaths = slices.Clone(m.DeployPaths)
		if m.MonitorSyncedAt != nil {
			t := *m.MonitorSyncedAt
			cp.MonitorSyncedAt = &t
		}
		out[i] = cp
	}
	return out
}

func cloneAIMemories(in []AIMemoryEntry) []AIMemoryEntry {
	out := make([]AIMemoryEntry, len(in))
	for i, m := range in {
		out[i] = cloneMemoryEntry(m)
	}
	return out
}

func cloneRunbooks(in []AIRunbook) []AIRunbook {
	out := make([]AIRunbook, len(in))
	for i, rb := range in {
		cp := rb
		cp.Tags = slices.Clone(rb.Tags)
		cp.DiagnosticSteps = slices.Clone(rb.DiagnosticSteps)
		cp.FixCommands = slices.Clone(rb.FixCommands)
		out[i] = cp
	}
	return out
}

func cloneAISessions(in []AIChatSession) []AIChatSession {
	out := make([]AIChatSession, len(in))
	for i, cs := range in {
		out[i] = cloneSession(cs)
	}
	return out
}

func clonePatrolBaselines(in []ServerBaselineSnapshot) []ServerBaselineSnapshot {
	out := make([]ServerBaselineSnapshot, len(in))
	for i, b := range in {
		cp := b
		cp.ListeningPorts = slices.Clone(b.ListeningPorts)
		cp.UIDZeroUsers = slices.Clone(b.UIDZeroUsers)
		out[i] = cp
	}
	return out
}

func clonePatrolRecords(in []PatrolRecord) []PatrolRecord {
	out := make([]PatrolRecord, len(in))
	for i, r := range in {
		out[i] = cloneSinglePatrolRecord(r)
	}
	return out
}

// --- Audit Logging (non-secret runtime file, never touches secrets.enc) ---

func (s *Store) appendAuditRuntimeLocked(action, target, detail, clientIP string, success bool) {
	if s.auditRT == nil {
		s.auditRT = DefaultAuditRuntimeState()
	}
	entry := AuditEntry{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  clientIP,
		Success:   success,
	}
	s.auditRT.AuditLogs = append([]AuditEntry{entry}, s.auditRT.AuditLogs...)
	if len(s.auditRT.AuditLogs) > maxAuditEntries {
		s.auditRT.AuditLogs = s.auditRT.AuditLogs[:maxAuditEntries]
	}
	s.dirtyAudit = true
}

// RecordAudit logs an event into the non-secret runtime audit buffer and triggers debounced disk flush.
func (s *Store) RecordAudit(action, target, detail, clientIP string, success bool) {
	if !s.IsReady() {
		return
	}
	s.rtMu.Lock()
	s.appendAuditRuntimeLocked(action, target, detail, clientIP, success)
	s.rtMu.Unlock()
	s.triggerFlush()
}

// RecordAuditAsync logs an audit event without blocking callers.
func (s *Store) RecordAuditAsync(action, target, detail, clientIP string, success bool) {
	s.RecordAudit(action, target, detail, clientIP, success)
}

func (s *Store) ListAuditLogs(limit int) ([]AuditEntry, error) {
	if !s.IsReady() {
		return nil, ErrVaultLocked
	}
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	if s.auditRT == nil {
		return []AuditEntry{}, nil
	}
	if limit <= 0 || limit > len(s.auditRT.AuditLogs) {
		limit = len(s.auditRT.AuditLogs)
	}
	return slices.Clone(s.auditRT.AuditLogs[:limit]), nil
}

// --- Servers CRUD ---

func applyServerRuntimeMeta(view *ServerView, meta ServerRuntimeMeta) {
	if meta.LastConnectedAt != nil {
		t := *meta.LastConnectedAt
		view.LastConnectedAt = &t
	}
	if meta.LastLatencyMs > 0 {
		view.LastLatencyMs = meta.LastLatencyMs
	}
	if meta.LastOSInfo != "" {
		view.LastOSInfo = meta.LastOSInfo
	}
}

func (s *Store) ListServers() ([]ServerView, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	out := make([]ServerView, len(s.secrets.Servers))
	for i, srv := range s.secrets.Servers {
		out[i] = srv.ToView()
	}
	s.secMu.RUnlock()

	s.rtMu.RLock()
	if s.monitorRT != nil && len(s.monitorRT.ServerRuntime) > 0 {
		for i := range out {
			if meta, ok := s.monitorRT.ServerRuntime[out[i].ID]; ok {
				applyServerRuntimeMeta(&out[i], meta)
			}
		}
	}
	s.rtMu.RUnlock()
	return out, nil
}

// GetServerSecret returns a deep copy of ServerConfig including decrypted credentials for SSH dialing.
func (s *Store) GetServerSecret(id string) (*ServerConfig, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	for _, srv := range s.secrets.Servers {
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
	Password          *string  `json:"password,omitempty"`
	PrivateKey        *string  `json:"private_key,omitempty"`
	Passphrase        *string  `json:"passphrase,omitempty"`
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

func (s *Store) CreateServer(in ServerMutationInput, clientIP string) (*ServerView, error) {
	if err := sanitizeServerInput(&in); err != nil {
		return nil, err
	}

	newID := uuid.NewString()
	var view ServerView
	err := s.mutateSecrets(func(sec *SecretsState) error {
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
		if !slices.Contains(sec.Groups, srv.Group) {
			sec.Groups = append(sec.Groups, srv.Group)
		}
		sec.Servers = append(sec.Servers, srv)
		view = srv.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("server.create", fmt.Sprintf("%s (%s:%d)", view.Name, view.Host, view.Port), "新增服务器资产配置", clientIP, true)
	return &view, nil
}

func (s *Store) UpdateServer(id string, in ServerMutationInput, clientIP string) (*ServerView, error) {
	if err := sanitizeServerInput(&in); err != nil {
		return nil, err
	}
	if in.JumpServerID == id {
		return nil, fmt.Errorf("%w: 跳板机不能指向服务器自身", ErrInvalidInput)
	}

	var view ServerView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		idx := -1
		for i := range sec.Servers {
			if sec.Servers[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return ErrNotFound
		}

		srv := sec.Servers[idx]
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
		if !slices.Contains(sec.Groups, srv.Group) {
			sec.Groups = append(sec.Groups, srv.Group)
		}
		sec.Servers[idx] = srv
		view = srv.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.rtMu.RLock()
	if s.monitorRT != nil {
		if meta, ok := s.monitorRT.ServerRuntime[id]; ok {
			applyServerRuntimeMeta(&view, meta)
		}
	}
	s.rtMu.RUnlock()

	s.RecordAudit("server.update", fmt.Sprintf("%s (%s:%d)", view.Name, view.Host, view.Port), "更新服务器连接配置", clientIP, true)
	return &view, nil
}

func (s *Store) DeleteServer(id, clientIP string) error {
	var deletedTarget string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, srv := range sec.Servers {
			if srv.ID == id {
				deletedTarget = fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port)
				sec.Servers = slices.Delete(sec.Servers, i, i+1)
				for j := range sec.Servers {
					if sec.Servers[j].JumpServerID == id {
						sec.Servers[j].JumpServerID = ""
					}
				}
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}

	// Purge runtime monitoring metadata associated with the deleted server.
	s.rtMu.Lock()
	if s.monitorRT != nil {
		delete(s.monitorRT.LatestSnapshots, id)
		delete(s.monitorRT.HistoryByServer, id)
		delete(s.monitorRT.PortBaselines, id)
		delete(s.monitorRT.ServerRuntime, id)
		prefix := id + "|"
		for k := range s.monitorRT.BreachStreaks {
			if strings.HasPrefix(k, prefix) {
				delete(s.monitorRT.BreachStreaks, k)
			}
		}
		s.monitorRT.Alerts = slices.DeleteFunc(s.monitorRT.Alerts, func(a MonitorAlert) bool {
			return a.ServerID == id
		})
		s.dirtyMonitor = true
	}
	s.appendAuditRuntimeLocked("server.delete", deletedTarget, "删除服务器配置", clientIP, true)
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

// UpdateServerRuntimeMeta updates per-server latency / OS / last-connected timestamps strictly in
// runtime state (monitor_runtime.json), NEVER rewriting secrets.enc.
func (s *Store) UpdateServerRuntimeMeta(id string, latencyMs int64, osInfo string, connected bool) {
	if !s.IsReady() || id == "" {
		return
	}
	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.monitorRT = DefaultMonitorRuntimeState()
	}
	meta := s.monitorRT.ServerRuntime[id]
	if latencyMs > 0 {
		meta.LastLatencyMs = latencyMs
	}
	if osInfo != "" {
		meta.LastOSInfo = osInfo
	}
	if connected {
		now := time.Now().UTC()
		meta.LastConnectedAt = &now
	}
	s.monitorRT.ServerRuntime[id] = meta
	s.dirtyMonitor = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

// --- Groups Management ---

func (s *Store) ListGroups() ([]string, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.secrets.Groups), nil
}

func (s *Store) AddGroup(name string) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidInput
	}
	var out []string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		if !slices.Contains(sec.Groups, name) {
			sec.Groups = append(sec.Groups, name)
		}
		out = slices.Clone(sec.Groups)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DeleteGroup(name string) ([]string, error) {
	var out []string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		sec.Groups = slices.DeleteFunc(sec.Groups, func(g string) bool { return g == name })
		for i := range sec.Servers {
			if sec.Servers[i].Group == name {
				sec.Servers[i].Group = "默认分组"
			}
		}
		out = slices.Clone(sec.Groups)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	out := make([]CredentialView, len(s.secrets.Credentials))
	for i, c := range s.secrets.Credentials {
		out[i] = c.ToView()
	}
	return out, nil
}

func (s *Store) GetCredentialSecret(id string) (*Credential, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	for _, c := range s.secrets.Credentials {
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

	newID := uuid.NewString()
	var v CredentialView
	err := s.mutateSecrets(func(sec *SecretsState) error {
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
		sec.Credentials = append(sec.Credentials, cred)
		v = cred.ToView()
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("credential.create", v.Name, fmt.Sprintf("新增加密凭据 (%s)", v.Kind), clientIP, true)
	return &v, nil
}

func (s *Store) UpdateCredential(id string, in CredentialMutationInput, clientIP string) (*CredentialView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || (in.Kind != AuthPassword && in.Kind != AuthPrivateKey) {
		return nil, ErrInvalidInput
	}

	var v CredentialView
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i := range sec.Credentials {
			if sec.Credentials[i].ID == id {
				cred := sec.Credentials[i]
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
				sec.Credentials[i] = cred
				v = cred.ToView()
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit("credential.update", v.Name, "更新加密凭据", clientIP, true)
	return &v, nil
}

func (s *Store) DeleteCredential(id, clientIP string) error {
	var deletedName string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, c := range sec.Credentials {
			if c.ID == id {
				for _, srv := range sec.Servers {
					if srv.AuthType == AuthCredential && srv.CredentialID == id {
						return fmt.Errorf("%w: 服务器 [%s] 正在使用该凭据，请先解除绑定", ErrInvalidInput, srv.Name)
					}
				}
				deletedName = c.Name
				sec.Credentials = slices.Delete(sec.Credentials, i, i+1)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}
	s.RecordAudit("credential.delete", deletedName, "删除加密凭据", clientIP, true)
	return nil
}

// --- Snippets CRUD ---

func (s *Store) ListSnippets() ([]Snippet, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	return slices.Clone(s.secrets.Snippets), nil
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

	newID := in.ID
	if newID == "" {
		newID = uuid.NewString()
	}
	var out Snippet
	action := "snippet.create"
	detail := "新增快捷指令"
	err := s.mutateSecrets(func(sec *SecretsState) error {
		now := time.Now().UTC()
		if in.ID != "" {
			for i := range sec.Snippets {
				if sec.Snippets[i].ID == in.ID {
					updated := in
					updated.CreatedAt = sec.Snippets[i].CreatedAt
					updated.UpdatedAt = now
					sec.Snippets[i] = updated
					out = updated
					action = "snippet.update"
					detail = "更新快捷指令"
					return nil
				}
			}
		}
		created := in
		created.ID = newID
		created.CreatedAt = now
		created.UpdatedAt = now
		sec.Snippets = append(sec.Snippets, created)
		out = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.RecordAudit(action, out.Title, detail, clientIP, true)
	return &out, nil
}

func (s *Store) DeleteSnippet(id, clientIP string) error {
	var title string
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, sn := range sec.Snippets {
			if sn.ID == id {
				title = sn.Title
				sec.Snippets = slices.Delete(sec.Snippets, i, i+1)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}
	s.RecordAudit("snippet.delete", title, "删除快捷指令", clientIP, true)
	return nil
}

// --- KnownHosts (SSH Host Key Pinning / TOFU) ---

func (s *Store) ListKnownHosts() ([]KnownHost, error) {
	s.secMu.RLock()
	if s.secrets == nil {
		s.secMu.RUnlock()
		return nil, ErrVaultLocked
	}
	out := slices.Clone(s.secrets.KnownHosts)
	s.secMu.RUnlock()

	s.rtMu.RLock()
	if s.monitorRT != nil && len(s.monitorRT.KnownHostLastVerified) > 0 {
		for i := range out {
			if t, ok := s.monitorRT.KnownHostLastVerified[out[i].Address]; ok && t.After(out[i].LastVerifiedAt) {
				out[i].LastVerifiedAt = t
			}
		}
	}
	s.rtMu.RUnlock()
	return out, nil
}

func (s *Store) GetKnownHost(address string) (*KnownHost, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	for _, kh := range s.secrets.KnownHosts {
		if kh.Address == address {
			cp := kh
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *Store) TrustKnownHost(kh KnownHost, clientIP string) error {
	action := "hostkey.trust"
	detail := fmt.Sprintf("首次信任并固定 SSH 主机指纹 (%s)", kh.Fingerprint)
	err := s.mutateSecrets(func(sec *SecretsState) error {
		now := time.Now().UTC()
		khCp := kh
		khCp.LastVerifiedAt = now
		for i := range sec.KnownHosts {
			if sec.KnownHosts[i].Address == khCp.Address {
				khCp.FirstSeenAt = sec.KnownHosts[i].FirstSeenAt
				sec.KnownHosts[i] = khCp
				action = "hostkey.update"
				detail = fmt.Sprintf("更新信任的 SSH 主机指纹 (%s)", khCp.Fingerprint)
				return nil
			}
		}
		khCp.FirstSeenAt = now
		sec.KnownHosts = append(sec.KnownHosts, khCp)
		return nil
	})
	if err != nil {
		return err
	}
	s.RecordAudit(action, kh.Address, detail, clientIP, true)
	return nil
}

// TouchKnownHostVerified updates only the runtime last-verified timestamp without touching secrets.enc.
func (s *Store) TouchKnownHostVerified(address string) {
	if !s.IsReady() || address == "" {
		return
	}
	s.rtMu.Lock()
	if s.monitorRT == nil {
		s.monitorRT = DefaultMonitorRuntimeState()
	}
	s.monitorRT.KnownHostLastVerified[address] = time.Now().UTC()
	s.dirtyMonitor = true
	s.rtMu.Unlock()
	s.triggerFlush()
}

func (s *Store) DeleteKnownHost(address, clientIP string) error {
	err := s.mutateSecrets(func(sec *SecretsState) error {
		for i, kh := range sec.KnownHosts {
			if kh.Address == address {
				sec.KnownHosts = slices.Delete(sec.KnownHosts, i, i+1)
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}
	s.rtMu.Lock()
	if s.monitorRT != nil {
		delete(s.monitorRT.KnownHostLastVerified, address)
		s.dirtyMonitor = true
	}
	s.appendAuditRuntimeLocked("hostkey.delete", address, "移除已保存的 SSH 主机指纹记录", clientIP, true)
	s.rtMu.Unlock()
	s.triggerFlush()
	return nil
}

// --- Settings ---

func (s *Store) GetSettings() (*AppSettings, error) {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil {
		return nil, ErrVaultLocked
	}
	cp := s.secrets.Settings
	var upd UpdateSettings
	if cp.Update != nil {
		upd = NormalizeUpdateSettings(*cp.Update)
	} else {
		upd = DefaultUpdateSettings()
	}
	cp.Update = &upd
	return &cp, nil
}

func (s *Store) UpdateSettings(in AppSettings, clientIP string) (*AppSettings, error) {
	if in.AutoLockMinutes < 0 || in.AutoLockMinutes > 1440 {
		in.AutoLockMinutes = 0
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

	var out AppSettings
	err := s.mutateSecrets(func(sec *SecretsState) error {
		if in.Update == nil {
			// Preserve existing update preferences when general settings form omits `update`.
			in.Update = sec.Settings.Update
		} else {
			norm := NormalizeUpdateSettings(*in.Update)
			norm.CustomMirrorURL = strings.TrimSpace(norm.CustomMirrorURL)
			norm.SkippedVersion = strings.TrimSpace(norm.SkippedVersion)
			in.Update = &norm
		}
		sec.Settings = in
		out = sec.Settings
		return nil
	})
	if err != nil {
		return nil, err
	}
	var upd UpdateSettings
	if out.Update != nil {
		upd = NormalizeUpdateSettings(*out.Update)
	} else {
		upd = DefaultUpdateSettings()
	}
	out.Update = &upd
	s.RecordAudit("settings.update", "app", "更新安全策略与终端偏好设置", clientIP, true)
	return &out, nil
}

// GetUpdateSettings returns normalized release-check & auto-update preferences.
func (s *Store) GetUpdateSettings() UpdateSettings {
	s.secMu.RLock()
	defer s.secMu.RUnlock()
	if s.secrets == nil || s.secrets.Settings.Update == nil {
		return DefaultUpdateSettings()
	}
	return NormalizeUpdateSettings(*s.secrets.Settings.Update)
}

// UpdateUpdateSettings persists release-check & auto-update preferences inside secrets.enc.
func (s *Store) UpdateUpdateSettings(in UpdateSettings, clientIP string) (UpdateSettings, error) {
	norm := NormalizeUpdateSettings(in)
	norm.CustomMirrorURL = strings.TrimSpace(norm.CustomMirrorURL)
	norm.SkippedVersion = strings.TrimSpace(norm.SkippedVersion)

	var out UpdateSettings
	err := s.mutateSecrets(func(sec *SecretsState) error {
		cp := norm
		sec.Settings.Update = &cp
		out = cp
		return nil
	})
	if err != nil {
		return UpdateSettings{}, err
	}
	s.RecordAudit("update.config", "system", fmt.Sprintf("更新版本检测与国内加速策略 (mode=%s, interval=%dh, prerelease=%v)", out.MirrorMode, out.CheckIntervalHours, out.IncludePrerelease), clientIP, true)
	return out, nil
}
