package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func strPtr(s string) *string { return &s }

func newFastTestClient(t *testing.T, bs *BlindStore) *ClientVault {
	t.Helper()
	cv := NewClientVault(NewBlindStoreBackend(bs))
	cv.SetKDFParams(1, 16*1024, 2)
	return cv
}

func TestVaultZeroKnowledgeEncryptionAndTamperResistance(t *testing.T) {
	tmpDir := t.TempDir()
	vaultFile := filepath.Join(tmpDir, "vault.sns")

	bs, err := NewBlindStore(vaultFile)
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	store := newFastTestClient(t, bs)

	if store.Status() != StatusUninitialized {
		t.Fatalf("expected uninitialized, got %s", store.Status())
	}

	if err := store.Setup("short", "127.0.0.1"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}

	masterPass := "AdminMaster#2026!Safe"
	if err := store.Setup(masterPass, "127.0.0.1"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if store.Status() != StatusUnlocked {
		t.Fatalf("expected unlocked after setup, got %s", store.Status())
	}

	// Add sensitive SSH server, credential, snippet, known host
	fakePEM := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----"
	cred, err := store.CreateCredential(CredentialMutationInput{
		Name:         "CoreProdDeployKey",
		Kind:         AuthPrivateKey,
		UsernameHint: "secops_admin",
		PrivateKey:   strPtr(fakePEM),
		Passphrase:   strPtr("KeyPass#7788"),
		Notes:        "Internal Bastion Key",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	srv, err := store.CreateServer(ServerMutationInput{
		Name:         "prod-core-postgres",
		Group:        "核心机密集群",
		Tags:         []string{"database", "tier-0"},
		Host:         "10.240.88.19",
		Port:         22022,
		Username:     "secops_admin",
		AuthType:     AuthPassword,
		Password:     strPtr("SuperSecretSSHPass!99"),
		CredentialID: cred.ID,
		Notes:        "Primary financial database server",
		Pinned:       true,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	_, err = store.UpsertSnippet(Snippet{
		Title:    "Check Kernel Exploit Surface",
		Category: "SecAudit",
		Command:  "sysctl kernel.unprivileged_bpf_disabled",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertSnippet: %v", err)
	}

	if err := store.TrustKnownHost(KnownHost{
		Address:      "10.240.88.19:22022",
		ServerName:   "prod-core-postgres",
		KeyType:      "ssh-ed25519",
		Fingerprint:  "SHA256:UniqueFingerprintSecretXYZ123",
		PublicKeyB64: "AAAAC3NzaC1lZDI1NTE5AAAAI...",
	}, "127.0.0.1"); err != nil {
		t.Fatalf("TrustKnownHost: %v", err)
	}

	// Simulate Server Root Breach #1: inspect raw bytes on server disk!
	rawDiskBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("ReadFile vault.sns: %v", err)
	}
	forbiddenPlaintexts := []string{
		"prod-core-postgres",
		"核心机密集群",
		"10.240.88.19",
		"22022",
		"secops_admin",
		"SuperSecretSSHPass!99",
		"OPENSSH PRIVATE KEY",
		"KeyPass#7788",
		"CoreProdDeployKey",
		"Primary financial database",
		"unprivileged_bpf_disabled",
		"UniqueFingerprintSecretXYZ123",
		"生产环境",
		"vault.setup",
		masterPass,
	}
	for _, needle := range forbiddenPlaintexts {
		if bytes.Contains(rawDiskBytes, []byte(needle)) {
			t.Fatalf("SECURITY FAILURE: leaked plaintext %q inside raw vault.sns!", needle)
		}
	}

	// Simulate Server Root Breach #2: inspect BlindStore struct fields in server RAM!
	bsDump := fmt.Sprintf("%s %+v", bs.filePath, bs.header)
	for _, needle := range forbiddenPlaintexts {
		if bytes.Contains([]byte(bsDump), []byte(needle)) {
			t.Fatalf("SECURITY FAILURE: BlindStore in server RAM leaked %q!", needle)
		}
	}
	bsType := reflect.TypeFor[BlindStore]()
	for i := 0; i < bsType.NumField(); i++ {
		fName := bsType.Field(i).Name
		if fName == "dek" || fName == "state" || fName == "authPriv" {
			t.Fatalf("SECURITY FAILURE: BlindStore must never possess field %q", fName)
		}
	}

	// Verify PublicChallengeParams exposes ZERO offline oracle (no AuthPublicKey, no WrappedDEK)
	pubParams, err := bs.PublicChallengeParams()
	if err != nil {
		t.Fatalf("PublicChallengeParams: %v", err)
	}
	pubJSON, _ := json.Marshal(pubParams)
	if bytes.Contains(pubJSON, []byte("auth_public_key")) || bytes.Contains(pubJSON, []byte("wrapped_dek")) {
		t.Fatalf("SECURITY FAILURE: PublicChallengeParams leaked offline oracle fields: %s", string(pubJSON))
	}

	// Verify Zero-Knowledge Ed25519 Challenge-Response Auth on BlindStore
	_, authPrivDerived, _, err := DeriveVaultKeys(masterPass, pubParams.KDFSalt, pubParams.KDFTime, pubParams.KDFMemoryKiB, pubParams.KDFThreads, MinAllowedKDFMemoryKiB)
	if err != nil {
		t.Fatalf("DeriveVaultKeys: %v", err)
	}
	chalSig := SignAuthChallenge(authPrivDerived, "chal-1", "deadbeef0102", pubParams.VaultID)
	if _, err := bs.VerifyClientChallenge("chal-1", "deadbeef0102", chalSig); err != nil {
		t.Fatalf("VerifyClientChallenge failed for valid proof: %v", err)
	}
	if _, err := bs.VerifyClientChallenge("chal-1", "wrongnonce", chalSig); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword on replayed/mismatched nonce, got %v", err)
	}

	// Verify UnlockOrVerify rejects wrong password even while unlocked
	if err := store.UnlockOrVerify("WrongAdminPass!123", "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword while unlocked, got %v", err)
	}
	if err := store.UnlockOrVerify(masterPass, "127.0.0.1"); err != nil {
		t.Fatalf("expected valid password verification while unlocked, got %v", err)
	}

	// Lock vault and verify client memory access is blocked
	lockHookCalled := false
	store.RegisterOnLock(func() { lockHookCalled = true })
	store.Lock("manual lock test", "127.0.0.1")

	if !lockHookCalled {
		t.Fatalf("expected onLock callback to fire")
	}
	if store.Status() != StatusLocked {
		t.Fatalf("expected StatusLocked, got %s", store.Status())
	}
	if _, err := store.ListServers(); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("expected ErrVaultLocked on ListServers, got %v", err)
	}
	if _, err := store.GetServerSecret(srv.ID); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("expected ErrVaultLocked on GetServerSecret, got %v", err)
	}

	// Simulate Attacker Brute Force / Wrong Password on leaked vault file
	attackerStore := newFastTestClient(t, bs)
	if err := attackerStore.UnlockOrVerify("AttackerGuessPassword999", "1.2.3.4"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword for attacker, got %v", err)
	}

	// Refresh rawDiskBytes after lock audit entry
	rawDiskBytes, err = os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("ReadFile after lock: %v", err)
	}

	// Simulate Tampering (1-bit flip in ciphertext and 1-bit flip in header)
	tamperedCipher := bytes.Clone(rawDiskBytes)
	tamperedCipher[len(tamperedCipher)-10] ^= 0x01
	if _, _, _, _, _, err := OpenVaultContainer(tamperedCipher, masterPass, MinAllowedKDFMemoryKiB); err == nil {
		t.Fatalf("SECURITY FAILURE: tampered ciphertext passed AEAD verification!")
	}

	tamperedHeader := bytes.Clone(rawDiskBytes)
	tamperedHeader[20] ^= 0x01
	if _, _, _, _, _, err := OpenVaultContainer(tamperedHeader, masterPass, MinAllowedKDFMemoryKiB); err == nil {
		t.Fatalf("SECURITY FAILURE: tampered header AAD passed verification!")
	}

	// Legitimate Admin Unlocks Vault
	if err := store.UnlockOrVerify(masterPass, "127.0.0.1"); err != nil {
		t.Fatalf("Unlock with right password failed: %v", err)
	}
	secretSrv, err := store.GetServerSecret(srv.ID)
	if err != nil {
		t.Fatalf("GetServerSecret after unlock: %v", err)
	}
	if secretSrv.Password != "SuperSecretSSHPass!99" || secretSrv.Host != "10.240.88.19" {
		t.Fatalf("decrypted server mismatch: %+v", secretSrv)
	}

	// Password Rotation + Master DEK + Ed25519 AuthKey Re-encryption
	newPass := "RotatedMaster#2027$Ultra"
	if err := store.ChangePassword("wrongOldPass", newPass, "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword on wrong old password, got %v", err)
	}
	if err := store.ChangePassword(masterPass, newPass, "127.0.0.1"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	backupBytes, err := store.ExportEncryptedBytes("127.0.0.1")
	if err != nil {
		t.Fatalf("ExportEncryptedBytes: %v", err)
	}

	store.Lock("lock before testing new password", "127.0.0.1")
	if err := store.UnlockOrVerify(masterPass, "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("old password should no longer unlock rotated vault, got %v", err)
	}
	if err := store.UnlockOrVerify(newPass, "127.0.0.1"); err != nil {
		t.Fatalf("new password failed to unlock rotated vault: %v", err)
	}

	// Test Importing Encrypted Backup into a Fresh Location
	restoreBS, err := NewBlindStore(filepath.Join(t.TempDir(), "restored.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore restore: %v", err)
	}
	restoreStore := newFastTestClient(t, restoreBS)
	if err := restoreStore.ImportEncryptedVault(backupBytes, masterPass, "", "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("import with wrong password should fail, got %v", err)
	}
	if err := restoreStore.ImportEncryptedVault(backupBytes, newPass, "", "127.0.0.1"); err != nil {
		t.Fatalf("ImportEncryptedVault failed: %v", err)
	}
	restoredServers, err := restoreStore.ListServers()
	if err != nil || len(restoredServers) != 1 || restoredServers[0].Name != "prod-core-postgres" {
		t.Fatalf("restored servers mismatch: %v, err=%v", restoredServers, err)
	}
}

func TestBlindStoreBlocksUnauthenticatedOverwriteAndDowngradeAndRollback(t *testing.T) {
	victimBS, err := NewBlindStore(filepath.Join(t.TempDir(), "victim.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore victim: %v", err)
	}
	victimClient := newFastTestClient(t, victimBS)
	if err := victimClient.Setup("VictimStrong#Pass2026", "127.0.0.1"); err != nil {
		t.Fatalf("victim Setup: %v", err)
	}
	rev1Snapshot, _, _, err := victimBS.ReadBlob()
	if err != nil {
		t.Fatalf("ReadBlob rev1: %v", err)
	}

	// Advance victim vault to revision 2+
	if _, err := victimClient.AddGroup("机密研发组"); err != nil {
		t.Fatalf("AddGroup: %v", err)
	}
	pinnedAnchor := victimClient.GetAnchor()
	if pinnedAnchor == nil || pinnedAnchor.MinRevision < 2 {
		t.Fatalf("expected anchor MinRevision >= 2, got %+v", pinnedAnchor)
	}

	// 1. Attacker creates their own valid SNSVAULT v2 container and tries to overwrite victim's BlindStore via ImportBlob!
	attackerBS, _ := NewBlindStore(filepath.Join(t.TempDir(), "attacker.sns"))
	attackerClient := newFastTestClient(t, attackerBS)
	if err := attackerClient.Setup("AttackerOwn#Pass999", "9.9.9.9"); err != nil {
		t.Fatalf("attacker Setup: %v", err)
	}
	attackerBlob, _, _, _ := attackerBS.ReadBlob()
	attackerPriv := attackerClient.AuthPrivateKeyCopy()
	_, _, attackerHdr, _, _ := ParseVaultContainer(attackerBlob)
	attackerNewSig := SignVaultImport(attackerPriv, attackerHdr.VaultID, attackerHdr.Revision, attackerBlob)
	forgedOverwriteSig := SignVaultImportOverwrite(attackerPriv, pinnedAnchor.VaultID, attackerHdr.VaultID, attackerBlob)

	if _, _, err := victimBS.ImportBlob(attackerBlob, attackerNewSig, nil); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("SECURITY FAILURE: ImportBlob allowed overwrite without overwriteSig: %v", err)
	}
	if _, _, err := victimBS.ImportBlob(attackerBlob, attackerNewSig, forgedOverwriteSig); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("SECURITY FAILURE: ImportBlob allowed overwrite with attacker's forged signature: %v", err)
	}

	// Legitimate overwrite WITH victim's current password succeeds when needed
	lockedVictim := newFastTestClient(t, victimBS)
	if err := lockedVictim.ImportEncryptedVault(attackerBlob, "AttackerOwn#Pass999", "WrongVictimPass", "127.0.0.1"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword when currentAdminPassword is wrong, got %v", err)
	}

	// 2. KDF Downgrade Attack: Compromised server returns kdf_memory_kib = 1024 (1 MiB)
	salt := make([]byte, 32)
	if _, _, _, err := DeriveVaultKeys("VictimStrong#Pass2026", salt, 1, 1024, 1, MinAllowedKDFMemoryKiB); !errors.Is(err, ErrKDFDowngrade) {
		t.Fatalf("SECURITY FAILURE: expected ErrKDFDowngrade on 1 MiB KDF parameter, got %v", err)
	}

	// 3. Server Rollback Attack: Root attacker replaces victim.sns on disk with older rev1Snapshot!
	if err := os.WriteFile(victimBS.FilePath(), rev1Snapshot, 0o600); err != nil {
		t.Fatalf("WriteFile rollback: %v", err)
	}
	rolledBackBS, err := NewBlindStore(victimBS.FilePath())
	if err != nil {
		t.Fatalf("NewBlindStore rolled back: %v", err)
	}
	returningClient := newFastTestClient(t, rolledBackBS)
	returningClient.SetAnchor(pinnedAnchor)
	if err := returningClient.UnlockOrVerify("VictimStrong#Pass2026", "127.0.0.1"); !errors.Is(err, ErrRollbackDetected) {
		t.Fatalf("SECURITY FAILURE: expected ErrRollbackDetected when server replayed older vault revision, got %v", err)
	}

	// 4. Server Wipe Attack: Root attacker deletes vault.sns to trick returning client into Setup!
	emptyBS, _ := NewBlindStore(filepath.Join(t.TempDir(), "wiped.sns"))
	wipedCheckClient := newFastTestClient(t, emptyBS)
	wipedCheckClient.SetAnchor(pinnedAnchor)
	if err := wipedCheckClient.Setup("VictimStrong#Pass2026", "127.0.0.1"); !errors.Is(err, ErrRollbackDetected) {
		t.Fatalf("SECURITY FAILURE: expected ErrRollbackDetected when anchored server was wiped, got %v", err)
	}
}

func TestConcurrentClientCASConflictAutoMerge(t *testing.T) {
	bs, err := NewBlindStore(filepath.Join(t.TempDir(), "cas.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	pass := "ConcurrentAdmin#2026"
	clientA := newFastTestClient(t, bs)
	if err := clientA.Setup(pass, "127.0.0.1"); err != nil {
		t.Fatalf("Setup clientA: %v", err)
	}

	// Client B unlocks at revision 1/2
	clientB := newFastTestClient(t, bs)
	if err := clientB.UnlockOrVerify(pass, "127.0.0.2"); err != nil {
		t.Fatalf("Unlock clientB: %v", err)
	}

	// Client A mutates vault (advances server revision behind Client B's back)
	if _, err := clientA.CreateServer(ServerMutationInput{
		Name:     "node-alpha",
		Host:     "10.0.1.10",
		Port:     22,
		Username: "root",
		AuthType: AuthPassword,
		Password: strPtr("AlphaPass"),
	}, "127.0.0.1"); err != nil {
		t.Fatalf("clientA CreateServer: %v", err)
	}

	// Client B now mutates with stale revision -> should hit ErrRevisionConflict internally,
	// fetch & authenticate Client A's latest ciphertext with its DEK, and preserve BOTH servers!
	if _, err := clientB.CreateServer(ServerMutationInput{
		Name:     "node-beta",
		Host:     "10.0.1.11",
		Port:     22,
		Username: "ubuntu",
		AuthType: AuthPassword,
		Password: strPtr("BetaPass"),
	}, "127.0.0.2"); err != nil {
		t.Fatalf("clientB CreateServer auto-merge failed: %v", err)
	}

	servers, err := clientB.ListServers()
	if err != nil || len(servers) != 2 {
		t.Fatalf("expected both node-alpha and node-beta after CAS merge, got %d servers (err=%v)", len(servers), err)
	}
}

func TestLegacyV1BackupMigrationToV2(t *testing.T) {
	// Synthesize a genuine SNSVAULT v1 container and verify ImportEncryptedVault upgrades it seamlessly to v2
	pass := "LegacyV1Pass#8899"
	salt, _ := randomBytes(kdfSaltSize)
	dek, _ := randomBytes(dekSize)
	kek := argon2.IDKey([]byte(pass), salt, 1, 16*1024, 2, dekSize)

	hdr := &EnvelopeHeader{
		KDFAlgo:      "argon2id",
		KDFTime:      1,
		KDFMemoryKiB: 16 * 1024,
		KDFThreads:   2,
		KDFSalt:      salt,
		WrapAlgo:     "aes-256-gcm",
		CipherAlgo:   "xchacha20-poly1305",
	}
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	wrapNonce, _ := randomBytes(gcm.NonceSize())
	hdr.WrappedDEKNonce = wrapNonce
	hdr.WrappedDEK = gcm.Seal(nil, wrapNonce, dek, dekWrapAADV1(hdr))

	aead, _ := chacha20poly1305.NewX(dek)
	payNonce, _ := randomBytes(aead.NonceSize())
	hdr.PayloadNonce = payNonce
	hdrBytes, _ := json.Marshal(hdr)

	prefix := make([]byte, 14+len(hdrBytes))
	copy(prefix[0:8], vaultMagic)
	binary.BigEndian.PutUint16(prefix[8:10], vaultFormatVersionV1)
	binary.BigEndian.PutUint32(prefix[10:14], uint32(len(hdrBytes)))
	copy(prefix[14:], hdrBytes)

	st := DefaultVaultState()
	st.SchemaVersion = 1
	st.VaultID = ""
	st.Revision = 0
	st.Servers = append(st.Servers, ServerConfig{
		ID:       "v1-srv-1",
		Name:     "legacy-v1-host",
		Group:    "生产环境",
		Host:     "192.168.50.10",
		Port:     22,
		Username: "admin",
		AuthType: AuthPassword,
		Password: "LegacySecret!1",
	})
	frame, err := packPlaintext(st)
	if err != nil {
		t.Fatalf("packPlaintext v1: %v", err)
	}
	ct := aead.Seal(nil, payNonce, frame, prefix)
	v1Raw := append(prefix, ct...)

	bs, _ := NewBlindStore(filepath.Join(t.TempDir(), "upgraded.sns"))
	client := newFastTestClient(t, bs)
	if err := client.ImportEncryptedVault(v1Raw, pass, "", "127.0.0.1"); err != nil {
		t.Fatalf("ImportEncryptedVault v1->v2 failed: %v", err)
	}
	info, _ := client.EncryptionInfo()
	if info.FormatVersion != 2 || !info.ZeroKnowledge || len(ed25519.PrivateKey(client.AuthPrivateKeyCopy())) != ed25519.PrivateKeySize {
		t.Fatalf("expected upgraded v2 zero-knowledge container, got %+v", info)
	}
	srvs, err := client.ListServers()
	if err != nil || len(srvs) != 1 || srvs[0].Name != "legacy-v1-host" {
		t.Fatalf("expected migrated server legacy-v1-host, got %+v (err=%v)", srvs, err)
	}
}
