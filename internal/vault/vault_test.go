package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func strPtr(s string) *string { return &s }

func TestVaultZeroKnowledgeEncryptionAndTamperResistance(t *testing.T) {
	tmpDir := t.TempDir()
	vaultFile := filepath.Join(tmpDir, "vault.sns")

	store, err := NewStore(vaultFile)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// Use moderately fast Argon2id parameters for unit test speed while exercising full algorithm
	store.kdfTime = 1
	store.kdfMemoryKiB = 16 * 1024
	store.kdfThreads = 2

	if store.Status() != StatusUninitialized {
		t.Fatalf("expected uninitialized, got %s", store.Status())
	}

	if err := store.Setup("short", "127.0.0.1"); err != ErrWeakPassword {
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

	// Simulate Data Package Leak: inspect raw bytes on disk!
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

	// Verify UnlockOrVerify still rejects wrong password even while unlocked
	if err := store.UnlockOrVerify("WrongAdminPass!123", "127.0.0.1"); err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword while unlocked, got %v", err)
	}
	if err := store.UnlockOrVerify(masterPass, "127.0.0.1"); err != nil {
		t.Fatalf("expected valid password verification while unlocked, got %v", err)
	}

	// Lock vault and verify memory access is blocked
	lockHookCalled := false
	store.RegisterOnLock(func() { lockHookCalled = true })
	store.Lock("manual lock test", "127.0.0.1")

	if !lockHookCalled {
		t.Fatalf("expected onLock callback to fire")
	}
	if store.Status() != StatusLocked {
		t.Fatalf("expected StatusLocked, got %s", store.Status())
	}
	if _, err := store.ListServers(); err != ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked on ListServers, got %v", err)
	}
	if _, err := store.GetServerSecret(srv.ID); err != ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked on GetServerSecret, got %v", err)
	}

	// Simulate Attacker Brute Force / Wrong Password on leaked vault file
	attackerStore, err := NewStore(vaultFile)
	if err != nil {
		t.Fatalf("NewStore attacker: %v", err)
	}
	if err := attackerStore.UnlockOrVerify("AttackerGuessPassword999", "1.2.3.4"); err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword for attacker, got %v", err)
	}

	// Simulate Tampering (1-bit flip in ciphertext and 1-bit flip in header)
	tamperedCipher := bytes.Clone(rawDiskBytes)
	tamperedCipher[len(tamperedCipher)-10] ^= 0x01
	if _, _, _, err := openVaultContainer(tamperedCipher, masterPass); err == nil {
		t.Fatalf("SECURITY FAILURE: tampered ciphertext passed AEAD verification!")
	}

	tamperedHeader := bytes.Clone(rawDiskBytes)
	tamperedHeader[20] ^= 0x01
	if _, _, _, err := openVaultContainer(tamperedHeader, masterPass); err == nil {
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

	// Password Rotation + Master DEK Re-encryption
	newPass := "RotatedMaster#2027$Ultra"
	if err := store.ChangePassword("wrongOldPass", newPass, "127.0.0.1"); err != ErrInvalidPassword {
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
	if err := store.UnlockOrVerify(masterPass, "127.0.0.1"); err != ErrInvalidPassword {
		t.Fatalf("old password should no longer unlock rotated vault, got %v", err)
	}
	if err := store.UnlockOrVerify(newPass, "127.0.0.1"); err != nil {
		t.Fatalf("new password failed to unlock rotated vault: %v", err)
	}

	// Test Importing Encrypted Backup into a Fresh Location
	restoreStore, err := NewStore(filepath.Join(t.TempDir(), "restored.sns"))
	if err != nil {
		t.Fatalf("NewStore restore: %v", err)
	}
	if err := restoreStore.ImportEncryptedVault(backupBytes, masterPass, "127.0.0.1"); err != ErrInvalidPassword {
		t.Fatalf("import with wrong password should fail, got %v", err)
	}
	if err := restoreStore.ImportEncryptedVault(backupBytes, newPass, "127.0.0.1"); err != nil {
		t.Fatalf("ImportEncryptedVault failed: %v", err)
	}
	restoredServers, err := restoreStore.ListServers()
	if err != nil || len(restoredServers) != 1 || restoredServers[0].Name != "prod-core-postgres" {
		t.Fatalf("restored servers mismatch: %v, err=%v", restoredServers, err)
	}
}
