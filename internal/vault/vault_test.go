package vault

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func strPtr(s string) *string { return &s }

// buildLegacyV2ContainerForTest synthesizes a real legacy v2.1 SNSVAULT container and optional .vault.key
// so we can verify unattended migration and legacy .sns backup import end-to-end.
func buildLegacyV2ContainerForTest(t *testing.T, password string, state *VaultState) (rawBlob []byte, dek []byte, authPriv ed25519.PrivateKey, vaultID string) {
	t.Helper()
	salt, _ := randomBytes(kdfSaltSize)
	dek, _ = randomBytes(dekSize)
	master := argon2.IDKey([]byte(password), salt, 2, 16*1024, 2, dekSize)
	kek, _ := hkdfDerive32(master, salt, "SNSVAULT-v2-KEK")
	authSeed, _ := hkdfDerive32(master, salt, "SNSVAULT-v2-AUTH-ED25519")
	authPriv = ed25519.NewKeyFromSeed(authSeed)
	authPub := authPriv.Public().(ed25519.PublicKey)

	vaultID = uuid.NewString()
	state.VaultID = vaultID
	state.Revision = 3
	state.SchemaVersion = 2

	hdr := LegacyEnvelopeHeader{
		VaultID:       vaultID,
		Revision:      3,
		KDFAlgo:       "argon2id",
		KDFTime:       2,
		KDFMemoryKiB:  16 * 1024,
		KDFThreads:    2,
		KDFSalt:       salt,
		AuthAlgo:      "ed25519",
		AuthPublicKey: slices.Clone(authPub),
		WrapAlgo:      "aes-256-gcm",
		CipherAlgo:    "xchacha20-poly1305",
	}
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	wrapNonce, _ := randomBytes(gcm.NonceSize())
	hdr.WrappedDEKNonce = wrapNonce
	hdr.WrappedDEK = gcm.Seal(nil, wrapNonce, dek, legacyDekWrapAADV2(&hdr))

	aead, _ := chacha20poly1305.NewX(dek)
	pNonce, _ := randomBytes(aead.NonceSize())
	hdr.PayloadNonce = pNonce

	hdrBytes, _ := json.Marshal(&hdr)
	prefix := make([]byte, 8+2+4+len(hdrBytes))
	copy(prefix[0:8], vaultMagic)
	binary.BigEndian.PutUint16(prefix[8:10], vaultFormatVersionV2)
	binary.BigEndian.PutUint32(prefix[10:14], uint32(len(hdrBytes)))
	copy(prefix[14:], hdrBytes)

	rawJSON, _ := json.Marshal(state)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	_, _ = zw.Write(rawJSON)
	_ = zw.Close()
	comp := gz.Bytes()
	frame := make([]byte, 4+len(comp)+128)
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(comp)))
	copy(frame[4:4+len(comp)], comp)

	ct := aead.Seal(nil, pNonce, frame, prefix)
	out := make([]byte, len(prefix)+len(ct))
	copy(out, prefix)
	copy(out[len(prefix):], ct)
	return out, dek, authPriv, vaultID
}

func writeLegacyLocalKeyFile(t *testing.T, dir, vaultID string, dek []byte, authPriv ed25519.PrivateKey) {
	t.Helper()
	mk, _ := randomBytes(dekSize)
	block, _ := aes.NewCipher(mk)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := randomBytes(gcm.NonceSize())
	payload := append(slices.Clone(dek), authPriv...)
	wrapped := gcm.Seal(nil, nonce, payload, []byte(legacySealAAD+vaultID))

	seal := legacyLocalKeySealFile{
		Version:           1,
		VaultID:           vaultID,
		MasterKeyB64:      base64.StdEncoding.EncodeToString(mk),
		NonceB64:          base64.StdEncoding.EncodeToString(nonce),
		WrappedSecretsB64: base64.StdEncoding.EncodeToString(wrapped),
	}
	encoded, _ := json.MarshalIndent(&seal, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, legacyKeyFileName), encoded, 0o600); err != nil {
		t.Fatalf("write legacy .vault.key: %v", err)
	}
}

func TestSplitStorageEncryptionDecoupledMonitoringAndNoRewriteOnTelemetry(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.SetFlushDebounce(30 * time.Millisecond)

	if store.IsInitialized() || store.Status() != StatusUninitialized {
		t.Fatalf("expected fresh uninitialized store")
	}

	adminPass := "AdminPass#2026!Decoupled"
	if err := store.Setup(adminPass, "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !store.IsReady() || store.Status() != StatusUnlocked {
		t.Fatalf("expected ready store after setup")
	}

	// Verify 0600 master.key & secrets.enc created
	mkInfo, err := os.Stat(filepath.Join(dir, masterKeyFileName))
	if err != nil || mkInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 master.key, got stat=%v err=%v", mkInfo, err)
	}

	// Create server with secret password & AI provider with secret API key
	srv, err := store.CreateServer(ServerMutationInput{
		Name:     "prod-core-01",
		Group:    "生产环境",
		Host:     "10.0.0.10",
		Port:     22,
		Username: "opsadmin",
		AuthType: AuthPassword,
		Password: strPtr("SuperSecretSSHPass!9988"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	_, _, err = store.UpsertAIProvider(AIProviderMutationInput{
		Name:      "DeepSeek",
		Protocol:  AIProtocolOpenAI,
		BaseURL:   "https://api.deepseek.com/v1",
		APIKey:    strPtr("sk-ultra-secret-deepseek-998877"),
		Model:     "deepseek-chat",
		SetActive: true,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider: %v", err)
	}

	// Verify secrets.enc has ZERO plaintext leakage of SSH password, AI API key, or admin password!
	rawSecretsBefore, err := os.ReadFile(store.SecretsPath())
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	for _, needle := range []string{
		adminPass,
		"SuperSecretSSHPass!9988",
		"sk-ultra-secret-deepseek-998877",
		"prod-core-01",
	} {
		if bytes.Contains(rawSecretsBefore, []byte(needle)) {
			t.Fatalf("SECURITY FAILURE: secrets.enc leaked plaintext %q", needle)
		}
	}

	// Record high-frequency monitor snapshots, server runtime meta, patrol records, and audit logs ->
	// MUST NOT rewrite secrets.enc at all!
	_, _, _, err = store.RecordMonitorSnapshots([]*ServerMonitorSnapshot{
		{
			ServerID:    srv.ID,
			Reachable:   true,
			LatencyMs:   18,
			OS:          "Ubuntu 24.04 LTS",
			CPUPercent:  32.5,
			MemPercent:  48.0,
			DiskPercent: 55.0,
		},
	})
	if err != nil {
		t.Fatalf("RecordMonitorSnapshots: %v", err)
	}
	store.UpdateServerRuntimeMeta(srv.ID, 15, "Ubuntu 24.04 LTS", true)
	store.RecordAudit("test.event", "runtime", "audit stays in runtime json", "127.0.0.1", true)
	if err := store.AppendPatrolRecord(PatrolRecord{
		ID:           "patrol-1",
		Status:       "healthy",
		TotalServers: 1,
		HealthyCount: 1,
	}); err != nil {
		t.Fatalf("AppendPatrolRecord: %v", err)
	}

	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}

	rawSecretsAfter, err := os.ReadFile(store.SecretsPath())
	if err != nil {
		t.Fatalf("read secrets.enc after telemetry: %v", err)
	}
	if !bytes.Equal(rawSecretsBefore, rawSecretsAfter) {
		t.Fatalf("EXPECTED secrets.enc NOT to be rewritten during monitor/patrol/runtime/audit writes!")
	}

	// Verify runtime JSON files were persisted independently and contain zero secrets
	for _, rtFile := range []string{monitorRuntimeFileName, aiopsRuntimeFileName, auditRuntimeFileName} {
		rawRT, err := os.ReadFile(filepath.Join(dir, rtFile))
		if err != nil || len(rawRT) == 0 {
			t.Fatalf("expected runtime file %s to exist, err=%v", rtFile, err)
		}
		for _, secret := range []string{"SuperSecretSSHPass!9988", "sk-ultra-secret-deepseek-998877", adminPass} {
			if bytes.Contains(rawRT, []byte(secret)) {
				t.Fatalf("SECURITY FAILURE: runtime file %s leaked secret %q!", rtFile, secret)
			}
		}
	}

	// Change admin password -> increments AuthVersion, keeps masterKey & all secrets & runtime intact!
	newPass := "NewAdminPass#2026!Rotated"
	prevVer := store.AuthVersion()
	if err := store.ChangePassword(adminPass, newPass, "127.0.0.1"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if store.AuthVersion() != prevVer+1 {
		t.Fatalf("expected AuthVersion to increment")
	}
	if err := store.VerifyPassword(adminPass); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("old password should fail after change")
	}
	if err := store.VerifyPassword(newPass); err != nil {
		t.Fatalf("new password should succeed: %v", err)
	}
	store.Close()

	// Re-open Store (simulating container/process restart) -> immediately ready with zero password unlock!
	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reopen NewStore: %v", err)
	}
	defer reopened.Close()

	if !reopened.IsReady() || reopened.Status() != StatusUnlocked {
		t.Fatalf("expected reopened store to be immediately ready without manual unlock")
	}
	servers, err := reopened.ListServers()
	if err != nil || len(servers) != 1 || servers[0].LastLatencyMs != 15 || servers[0].LastOSInfo != "Ubuntu 24.04 LTS" {
		t.Fatalf("expected merged server runtime metadata after restart, got %+v err=%v", servers, err)
	}
	overview, err := reopened.GetMonitorOverview()
	if err != nil || overview.KPI.OnlineServers != 1 || overview.KPI.TotalSamples != 1 {
		t.Fatalf("expected persisted monitor history after restart, got %+v err=%v", overview, err)
	}
	patrols, _, err := reopened.ListPatrolRecords(10, false)
	if err != nil || len(patrols) != 1 {
		t.Fatalf("expected persisted patrol record after restart, got %+v err=%v", patrols, err)
	}

	// Tampering with secrets.enc must be rejected by XChaCha20-Poly1305 AEAD!
	tampered := slices.Clone(rawSecretsAfter)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := OpenSecretsBytes(reopened.masterKey, tampered); !errors.Is(err, ErrCorruptedVault) {
		t.Fatalf("expected AEAD tamper rejection, got %v", err)
	}
}

func TestLegacyV2AutoMigrationAndLegacyManualMigration(t *testing.T) {
	legacyPass := "LegacyAdminPass#2025!"
	legacyState := DefaultVaultState()
	legacyState.Servers = []ServerConfig{
		{
			ID:       "srv-legacy-1",
			Name:     "legacy-db-node",
			Group:    "核心数据库",
			Host:     "10.1.2.3",
			Port:     22,
			Username: "root",
			AuthType: AuthPassword,
			Password: "LegacySSHSecret!42",
		},
	}
	legacyState.Monitor.LatestSnapshots["srv-legacy-1"] = &ServerMonitorSnapshot{
		ServerID:   "srv-legacy-1",
		ServerName: "legacy-db-node",
		Reachable:  true,
		CPUPercent: 44.2,
	}

	rawBlob, dek, authPriv, vaultID := buildLegacyV2ContainerForTest(t, legacyPass, legacyState)

	// Case A: Legacy vault.sns + .vault.key -> unattended automatic migration on boot!
	dirA := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, legacyVaultFileName), rawBlob, 0o600); err != nil {
		t.Fatalf("write legacy vault.sns: %v", err)
	}
	writeLegacyLocalKeyFile(t, dirA, vaultID, dek, authPriv)

	storeA, err := NewStore(dirA)
	if err != nil {
		t.Fatalf("NewStore auto-migration: %v", err)
	}
	defer storeA.Close()

	if !storeA.IsReady() || storeA.IsLegacyMigrationPending() {
		t.Fatalf("expected immediate unattended migration to ready state")
	}
	secSrv, err := storeA.GetServerSecret("srv-legacy-1")
	if err != nil || secSrv.Password != "LegacySSHSecret!42" {
		t.Fatalf("migrated server secret mismatch: %+v err=%v", secSrv, err)
	}
	// Existing admin password MUST still work and transparently upgrade to lightweight Argon2id hash!
	if err := storeA.VerifyPassword("WrongPassword"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("wrong password should fail after auto-migration")
	}
	if err := storeA.VerifyPassword(legacyPass); err != nil {
		t.Fatalf("legacy password must keep working after auto-migration: %v", err)
	}
	// Verify legacy files archived/removed
	if _, err := os.Stat(filepath.Join(dirA, legacyVaultFileName+".migrated.bak")); err != nil {
		t.Fatalf("expected vault.sns.migrated.bak archive")
	}
	if _, err := os.Stat(filepath.Join(dirA, legacyKeyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected obsolete .vault.key removed")
	}

	// Case B: Legacy vault.sns WITHOUT .vault.key -> one-time password login migrates permanently!
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirB, legacyVaultFileName), rawBlob, 0o600); err != nil {
		t.Fatalf("write legacy vault.sns B: %v", err)
	}
	storeB, err := NewStore(dirB)
	if err != nil {
		t.Fatalf("NewStore pending migration: %v", err)
	}
	defer storeB.Close()
	if storeB.IsReady() || !storeB.IsLegacyMigrationPending() {
		t.Fatalf("expected legacyMigrationPending=true without .vault.key")
	}
	if err := storeB.LoginWithPassword("WrongPass", "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected invalid password on wrong legacy pass, got %v", err)
	}
	if err := storeB.LoginWithPassword(legacyPass, "127.0.0.1"); err != nil {
		t.Fatalf("LoginWithPassword legacy migration failed: %v", err)
	}
	if !storeB.IsReady() || storeB.IsLegacyMigrationPending() {
		t.Fatalf("expected storeB ready after one-time legacy password migration")
	}
	secSrvB, err := storeB.GetServerSecret("srv-legacy-1")
	if err != nil || secSrvB.Password != "LegacySSHSecret!42" {
		t.Fatalf("migrated server B mismatch: %+v err=%v", secSrvB, err)
	}
}

func TestBackupExportImportV3AndLegacyV2Compatibility(t *testing.T) {
	dir1 := t.TempDir()
	s1, err := NewStore(dir1)
	if err != nil {
		t.Fatalf("NewStore s1: %v", err)
	}
	defer s1.Close()

	if err := s1.Setup("SourceAdmin#2026!", "127.0.0.1"); err != nil {
		t.Fatalf("Setup s1: %v", err)
	}
	srv, err := s1.CreateServer(ServerMutationInput{
		Name:     "backup-node-01",
		Group:    "生产环境",
		Host:     "10.50.0.1",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: strPtr("BackupNodeSSH#2026"),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	_, _, _, _ = s1.RecordMonitorSnapshots([]*ServerMonitorSnapshot{
		{ServerID: srv.ID, Reachable: true, CPUPercent: 61.5, MemPercent: 52.0},
	})
	_, _ = s1.UpsertAIMemory(AIMemoryEntry{
		Scope:   "global",
		Title:   "备份测试记忆",
		Content: "所有核心服务均采用 systemd 管理",
	}, false, "127.0.0.1")

	// 1. Export v3 backup with custom passphrase (config + AI knowledge only, no runtime)
	backupPass := "PortableBackupPass#99!"
	configOnlyBytes, err := s1.ExportBackupBytes(backupPass, false, "127.0.0.1")
	if err != nil {
		t.Fatalf("ExportBackupBytes(config): %v", err)
	}
	if bytes.Contains(configOnlyBytes, []byte("BackupNodeSSH#2026")) {
		t.Fatalf("backup leaked plaintext SSH password")
	}

	// 2. Export v3 full backup (including runtime monitor history)
	fullBytes, err := s1.ExportBackupBytes(backupPass, true, "127.0.0.1")
	if err != nil {
		t.Fatalf("ExportBackupBytes(full): %v", err)
	}

	// 3. Restore config-only backup onto a fresh server -> has server + AI memory, zero monitor samples
	dir2 := t.TempDir()
	s2, err := NewStore(dir2)
	if err != nil {
		t.Fatalf("NewStore s2: %v", err)
	}
	defer s2.Close()

	if err := s2.ImportBackupBytes(configOnlyBytes, "WrongBackupPass", true, "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword on wrong backup passphrase, got %v", err)
	}
	if err := s2.ImportBackupBytes(configOnlyBytes, backupPass, true, "127.0.0.1"); err != nil {
		t.Fatalf("ImportBackupBytes(configOnly): %v", err)
	}
	s2Srv, err := s2.GetServerSecret(srv.ID)
	if err != nil || s2Srv.Password != "BackupNodeSSH#2026" {
		t.Fatalf("restored server secret mismatch: %+v err=%v", s2Srv, err)
	}
	mems, _ := s2.ListAIMemories()
	if len(mems) != 1 || mems[0].Title != "备份测试记忆" {
		t.Fatalf("expected AI knowledge restored, got %+v", mems)
	}
	ov2, _ := s2.GetMonitorOverview()
	if ov2.KPI.TotalSamples != 0 {
		t.Fatalf("expected 0 monitor samples in config-only restore, got %d", ov2.KPI.TotalSamples)
	}

	// 4. Restore full backup onto s2 -> preserves s2's admin login password AND restores monitor sample!
	if err := s2.ImportBackupBytes(fullBytes, backupPass, true, "127.0.0.1"); err != nil {
		t.Fatalf("ImportBackupBytes(full): %v", err)
	}
	ov2Full, _ := s2.GetMonitorOverview()
	if ov2Full.KPI.TotalSamples != 1 {
		t.Fatalf("expected 1 monitor sample after full restore, got %d", ov2Full.KPI.TotalSamples)
	}

	// 5. Legacy v2 .sns backup import compatibility
	legacyState := DefaultVaultState()
	legacyState.Servers = []ServerConfig{
		{ID: "leg-srv", Name: "legacy-backup-node", Group: "默认分组", Host: "10.9.9.9", Port: 22, Username: "root", AuthType: AuthPassword, Password: "LegacyBackupPassword!"},
	}
	legRaw, _, _, _ := buildLegacyV2ContainerForTest(t, "LegacyBakPass#2025", legacyState)
	dir3 := t.TempDir()
	s3, _ := NewStore(dir3)
	defer s3.Close()
	if err := s3.ImportBackupBytes(legRaw, "LegacyBakPass#2025", true, "127.0.0.1"); err != nil {
		t.Fatalf("import legacy v2 backup failed: %v", err)
	}
	gotLeg, err := s3.GetServerSecret("leg-srv")
	if err != nil || gotLeg.Password != "LegacyBackupPassword!" {
		t.Fatalf("legacy backup server mismatch: %+v err=%v", gotLeg, err)
	}
}

func TestEnvMasterKeyOverrideAndTransparentRekey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SNS_MASTER_KEY", "")

	// 1. Start in file-key mode (master.key)
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore(file): %v", err)
	}
	if s1.MasterKeyMode() != MasterKeyModeFile {
		t.Fatalf("expected file mode, got %s", s1.MasterKeyMode())
	}
	if err := s1.Setup("EnvRekeyAdmin#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	_, _ = s1.CreateServer(ServerMutationInput{
		Name: "env-node", Group: "默认分组", Host: "10.0.0.2", Port: 22, Username: "root", AuthType: AuthPassword, Password: strPtr("EnvNodePass!"),
	}, "127.0.0.1")
	s1.Close()

	// 2. Restart with SNS_MASTER_KEY set -> seamlessly re-seals secrets.enc under env key!
	t.Setenv("SNS_MASTER_KEY", "custom-env-master-secret-2026-high-entropy")
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore(env rekey): %v", err)
	}
	defer s2.Close()
	if s2.MasterKeyMode() != MasterKeyModeEnv {
		t.Fatalf("expected env mode, got %s", s2.MasterKeyMode())
	}
	srvs, err := s2.ListServers()
	if err != nil || len(srvs) != 1 || srvs[0].Name != "env-node" {
		t.Fatalf("expected server preserved after env key migration, got %+v err=%v", srvs, err)
	}
}
