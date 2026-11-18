package vault

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const regressionPass = "RegressionAdmin#2026!Pass"

func newRegressionVault(t *testing.T) (string, *BlindStore, *ClientVault) {
	t.Helper()
	dir := t.TempDir()
	bs, err := NewBlindStore(filepath.Join(dir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	cv := newFastTestClient(t, bs)
	if err := cv.Setup(regressionPass, "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return dir, bs, cv
}

// Crafted backups / remote containers must not be able to make the daemon allocate unbounded Argon2id memory.
func TestKDFCeilingRejectsOOMParameters(t *testing.T) {
	salt := make([]byte, kdfSaltSize)
	cases := []struct {
		name    string
		time    uint32
		mem     uint32
		threads uint8
	}{
		{"memory", 1, MaxAllowedKDFMemoryKiB + 1, 1},
		{"time", MaxAllowedKDFTime + 1, MinAllowedKDFMemoryKiB, 1},
		{"threads", 1, MinAllowedKDFMemoryKiB, MaxAllowedKDFThreads + 1},
	}
	for _, tc := range cases {
		start := time.Now()
		_, _, _, err := DeriveVaultKeys("whatever-password", salt, tc.time, tc.mem, tc.threads, 0)
		if !errors.Is(err, ErrCorruptedVault) {
			t.Fatalf("%s: expected ErrCorruptedVault for over-ceiling KDF params, got %v", tc.name, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("%s: ceiling check must reject before running Argon2id", tc.name)
		}
	}

	_, _, cv := newRegressionVault(t)
	_, hdr, err := cv.LastSealedBlob()
	if err != nil || hdr == nil {
		t.Fatalf("LastSealedBlob: %v", err)
	}
	if err := ValidateV2HeaderStructural(vaultFormatVersion, hdr); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
	evil := *hdr
	evil.KDFMemoryKiB = 4 * 1024 * 1024 // 4 GiB
	if err := ValidateV2HeaderStructural(vaultFormatVersion, &evil); !errors.Is(err, ErrCorruptedVault) {
		t.Fatalf("expected structural validation to reject 4 GiB KDF header, got %v", err)
	}
}

// A password unlock must adopt the container's tuned KDF profile; previously a later ChangePassword
// silently reset it to the process defaults.
func TestPasswordUnlockPreservesTunedKDFProfile(t *testing.T) {
	_, bs, cv := newRegressionVault(t)
	const tunedMem = uint32(24 * 1024)
	if _, err := cv.UpdateKDFParams(regressionPass, 2, tunedMem, 2, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateKDFParams: %v", err)
	}

	// Fresh daemon process: default (64 MiB) profile in memory, unlocks by password.
	daemon := NewClientVault(NewBlindStoreBackend(bs))
	if err := daemon.UnlockOrVerify(regressionPass, "127.0.0.1"); err != nil {
		t.Fatalf("UnlockOrVerify: %v", err)
	}
	newPass := "RegressionAdmin#2026!Rotated"
	if err := daemon.ChangePassword(regressionPass, newPass, "127.0.0.1"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	info, err := daemon.EncryptionInfo()
	if err != nil {
		t.Fatalf("EncryptionInfo: %v", err)
	}
	if info.KDFMemoryKiB != tunedMem || info.KDFTime != 2 || info.KDFThreads != 2 {
		t.Fatalf("tuned KDF profile lost after password unlock + change: got mem=%d t=%d p=%d", info.KDFMemoryKiB, info.KDFTime, info.KDFThreads)
	}
}

// After another writer (remote signed PUT) advanced vault.sns, the running daemon must reload it with
// its in-memory DEK instead of keeping (and later re-persisting) stale state.
func TestRefreshFromBackendReloadsNewerRevision(t *testing.T) {
	_, bs, daemon := newRegressionVault(t)

	remote := newFastTestClient(t, bs)
	if err := remote.UnlockOrVerify(regressionPass, "127.0.0.1"); err != nil {
		t.Fatalf("remote UnlockOrVerify: %v", err)
	}
	if _, err := remote.UpsertSnippet(Snippet{Title: "remote-written", Category: "ops", Command: "uptime"}, "127.0.0.1"); err != nil {
		t.Fatalf("remote UpsertSnippet: %v", err)
	}

	refreshed, err := daemon.RefreshFromBackend()
	if err != nil || !refreshed {
		t.Fatalf("RefreshFromBackend: refreshed=%v err=%v", refreshed, err)
	}
	snips, _ := daemon.ListSnippets()
	found := false
	for _, s := range snips {
		if s.Title == "remote-written" {
			found = true
		}
	}
	if !found {
		t.Fatalf("daemon did not see remotely written snippet after refresh")
	}
	if again, err := daemon.RefreshFromBackend(); err != nil || again {
		t.Fatalf("second refresh should be a no-op, got refreshed=%v err=%v", again, err)
	}
	// Daemon can keep writing on top of the refreshed revision without losing the remote write.
	if _, err := daemon.UpsertSnippet(Snippet{Title: "daemon-written", Category: "ops", Command: "df -h"}, "127.0.0.1"); err != nil {
		t.Fatalf("daemon UpsertSnippet after refresh: %v", err)
	}
	check := newFastTestClient(t, bs)
	if err := check.UnlockOrVerify(regressionPass, "127.0.0.1"); err != nil {
		t.Fatalf("check UnlockOrVerify: %v", err)
	}
	snips, _ = check.ListSnippets()
	titles := map[string]bool{}
	for _, s := range snips {
		titles[s.Title] = true
	}
	if !titles["remote-written"] || !titles["daemon-written"] {
		t.Fatalf("lost update: on-disk snippets=%v", titles)
	}

	locked := newFastTestClient(t, bs)
	if _, err := locked.RefreshFromBackend(); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("expected ErrVaultLocked for locked vault refresh, got %v", err)
	}
}

func TestServerKeySealEnvHardening(t *testing.T) {
	dir, bs, cv := newRegressionVault(t)
	km := NewServerKeyManager(dir)

	// Weak external master key is rejected (no silent low-entropy seal).
	t.Setenv("SNS_MASTER_KEY", "too-short-key")
	if err := km.SaveFromStore(cv); !errors.Is(err, ErrWeakMasterKey) {
		t.Fatalf("expected ErrWeakMasterKey, got %v", err)
	}
	if km.HasLocalKey() {
		t.Fatalf("no seal must be written with a weak SNS_MASTER_KEY")
	}

	strong := strings.Repeat("k", 24) + "-Strong-Random-Env-Key-2026"
	t.Setenv("SNS_MASTER_KEY", strong)
	if err := km.SaveFromStore(cv); err != nil {
		t.Fatalf("SaveFromStore(env): %v", err)
	}
	if km.SealMode() != SealModeEnv {
		t.Fatalf("expected env seal mode, got %q", km.SealMode())
	}

	// Restart without the env var: must NOT silently downgrade to a plaintext-key file seal.
	t.Setenv("SNS_MASTER_KEY", "")
	if err := km.SaveFromStore(cv); !errors.Is(err, ErrSealDowngrade) {
		t.Fatalf("expected ErrSealDowngrade, got %v", err)
	}
	if km.SealMode() != SealModeEnv {
		t.Fatalf("env-protected seal was downgraded to %q", km.SealMode())
	}
	fresh := NewClientVault(NewBlindStoreBackend(bs))
	unlocked, mig, err := km.TryAutoUnlock(fresh, bs)
	if unlocked || !mig || err == nil {
		t.Fatalf("expected descriptive auto-unlock failure without env key, got unlocked=%v mig=%v err=%v", unlocked, mig, err)
	}

	t.Setenv("SNS_MASTER_KEY", strong)
	fresh2 := NewClientVault(NewBlindStoreBackend(bs))
	if unlocked, _, err := km.TryAutoUnlock(fresh2, bs); !unlocked || err != nil {
		t.Fatalf("auto-unlock with correct env key failed: unlocked=%v err=%v", unlocked, err)
	}

	if err := km.Remove(); err != nil || km.HasLocalKey() {
		t.Fatalf("Remove: err=%v hasKey=%v", err, km.HasLocalKey())
	}
}

func TestSealVaultIDAndFileMode(t *testing.T) {
	dir, bs, cv := newRegressionVault(t)
	t.Setenv("SNS_MASTER_KEY", "")
	km := NewServerKeyManager(dir)
	if err := km.SaveFromStore(cv); err != nil {
		t.Fatalf("SaveFromStore(file): %v", err)
	}
	if km.SealMode() != SealModeFile {
		t.Fatalf("expected file seal mode, got %q", km.SealMode())
	}
	params, err := bs.PublicChallengeParams()
	if err != nil {
		t.Fatalf("PublicChallengeParams: %v", err)
	}
	if km.SealVaultID() != params.VaultID {
		t.Fatalf("seal VaultID %q != vault %q", km.SealVaultID(), params.VaultID)
	}
}

func TestAIProviderStoredKeyNotRepointed(t *testing.T) {
	_, _, cv := newRegressionVault(t)
	key := "sk-regression-secret-key"
	view, _, err := cv.UpsertAIProvider(AIProviderMutationInput{
		Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://api.example.com/v1/", APIKey: &key, Model: "m1",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider(create): %v", err)
	}
	// Same endpoint (trailing slash / host case only) without re-entering key → allowed.
	if _, _, err := cv.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm-renamed", Protocol: AIProtocolOpenAI, BaseURL: "https://API.example.com/v1", Model: "m2",
	}, "127.0.0.1"); err != nil {
		t.Fatalf("same-endpoint update rejected: %v", err)
	}
	// Re-pointing to an attacker endpoint while keeping the stored key → rejected.
	if _, _, err := cv.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://attacker.example/v1", Model: "m2",
	}, "127.0.0.1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput when re-pointing stored key, got %v", err)
	}
	stored, err := cv.GetAIProviderSecret(view.ID)
	if err != nil || stored.BaseURL != "https://API.example.com/v1" || stored.APIKey != key {
		t.Fatalf("stored provider changed unexpectedly: %+v err=%v", stored, err)
	}
	// Supplying a new key together with the new endpoint is fine.
	newKey := "sk-new-endpoint-key"
	if _, _, err := cv.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://other.example/v1", APIKey: &newKey, Model: "m2",
	}, "127.0.0.1"); err != nil {
		t.Fatalf("endpoint change with new key rejected: %v", err)
	}
}
