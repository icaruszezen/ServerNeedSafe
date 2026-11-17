package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/zkclient"
)

func TestZeroKnowledgeAPIAuthMultiClientCASAndLock(t *testing.T) {
	tmpDir := t.TempDir()
	blindStore, err := vault.NewBlindStore(filepath.Join(tmpDir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	authMgr, err := auth.NewManager(time.Hour, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := NewServer(Config{
		DeployMode: "server",
		BlindStore: blindStore,
		Auth:       authMgr,
		Relay:      relay.NewManager("127.0.0.1:0"),
	})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rawHTTP := &http.Client{}

	// 1. Protected ciphertext endpoint rejects unauthenticated call
	res, err := rawHTTP.Get(ts.URL + "/api/vault/blob")
	if err != nil {
		t.Fatalf("GET /api/vault/blob: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before setup, got %d", res.StatusCode)
	}

	// 2. Wire-level guard: sending legacy plaintext {"password": "..."} MUST be rejected with 400 BAD_JSON!
	legacySetup, _ := json.Marshal(map[string]string{"password": "AdminSecretPassword!2026"})
	res, err = rawHTTP.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(legacySetup))
	if err != nil {
		t.Fatalf("POST legacy /api/auth/setup: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("SECURITY FAILURE: server did not reject plaintext password field! got %d", res.StatusCode)
	}

	// 3. Legitimate Zero-Knowledge Client 1 sets up vault locally and uploads ONLY signed ciphertext
	client1 := zkclient.NewEngine(ts.URL, nil)
	client1.Vault().SetKDFParams(1, 16*1024, 2)

	st1, err := client1.Setup("AdminSecretPassword!2026")
	if err != nil {
		t.Fatalf("client1.Setup: %v", err)
	}
	if !st1.Authenticated || st1.VaultStatus != vault.StatusUnlocked {
		t.Fatalf("unexpected client1 status after setup: %+v", st1)
	}

	sshPass := "SecretSSH123!"
	createdSrv, err := client1.Vault().CreateServer(vault.ServerMutationInput{
		Name:     "gateway-01",
		Group:    "生产环境",
		Host:     "192.168.10.5",
		Port:     22,
		Username: "root",
		AuthType: vault.AuthPassword,
		Password: &sshPass,
	}, "client-1")
	if err != nil {
		t.Fatalf("client1 CreateServer: %v", err)
	}

	// 4. Unauthenticated HTTP caller sees vault_status="locked", authenticated=false, redacted VaultID="", and 401 on /api/vault/blob
	res, err = rawHTTP.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status: %v", err)
	}
	var pubStatus struct {
		VaultStatus   string               `json:"vault_status"`
		Authenticated bool                 `json:"authenticated"`
		Encryption    vault.EncryptionInfo `json:"encryption"`
	}
	_ = json.NewDecoder(res.Body).Decode(&pubStatus)
	res.Body.Close()
	if pubStatus.Authenticated || pubStatus.VaultStatus != "locked" {
		t.Fatalf("SECURITY FAILURE: unauthenticated caller got %+v", pubStatus)
	}
	if pubStatus.Encryption.AuthPubKeySHA256 != "" {
		t.Fatalf("expected AuthPubKeySHA256 redacted before auth, got %+v", pubStatus.Encryption)
	}

	res, _ = rawHTTP.Get(ts.URL + "/api/vault/blob")
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY FAILURE: unauthenticated caller accessed /api/vault/blob (%d)", res.StatusCode)
	}

	// 5. Client 2 tries wrong Admin Password -> rejected via Ed25519 challenge-response!
	client2 := zkclient.NewEngine(ts.URL, nil)
	client2.Vault().SetKDFParams(1, 16*1024, 2)
	if _, err := client2.Unlock("WrongPassword!999"); !errors.Is(err, vault.ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword on wrong unlock password, got %v", err)
	}

	// 6. Client 2 unlocks with right password, decrypts Client 1's server, and both clients make concurrent edits (CAS auto-merge!)
	if _, err := client2.Unlock("AdminSecretPassword!2026"); err != nil {
		t.Fatalf("client2.Unlock: %v", err)
	}
	srvs2, err := client2.Vault().ListServers()
	if err != nil || len(srvs2) != 1 || srvs2[0].ID != createdSrv.ID {
		t.Fatalf("client2 failed to decrypt client1's server: %+v (err=%v)", srvs2, err)
	}

	// Client 2 adds a second server (advancing server revision), then Client 1 adds a snippet from stale base revision -> auto-merged!
	sshPass2 := "SecondSSHPass!456"
	if _, err := client2.Vault().CreateServer(vault.ServerMutationInput{
		Name:     "db-replica-02",
		Group:    "核心数据库",
		Host:     "10.20.30.40",
		Port:     2222,
		Username: "postgres",
		AuthType: vault.AuthPassword,
		Password: &sshPass2,
	}, "client-2"); err != nil {
		t.Fatalf("client2 CreateServer: %v", err)
	}

	if _, err := client1.Vault().UpsertSnippet(vault.Snippet{
		Title:    "Check Replication",
		Category: "数据库",
		Command:  "pg_isready",
	}, "client-1"); err != nil {
		t.Fatalf("client1 UpsertSnippet (CAS auto-merge): %v", err)
	}

	mergedServers, err := client1.Vault().ListServers()
	if err != nil || len(mergedServers) != 2 {
		t.Fatalf("expected 2 servers after CAS auto-merge on client1, got %d (err=%v)", len(mergedServers), err)
	}

	// 7. Client 1 locks vault -> wipes Client 1 memory AND revokes all server sessions (Client 2's token is also invalidated)
	if err := client1.Lock(); err != nil {
		t.Fatalf("client1.Lock: %v", err)
	}
	if _, err := client1.Vault().ListServers(); !errors.Is(err, vault.ErrVaultLocked) {
		t.Fatalf("expected ErrVaultLocked on client1 after Lock, got %v", err)
	}

	reqAfterLock, _ := http.NewRequest("GET", ts.URL+"/api/vault/blob", nil)
	reqAfterLock.Header.Set("Authorization", "Bearer "+client2.Token())
	res, err = rawHTTP.Do(reqAfterLock)
	if err != nil {
		t.Fatalf("GET /api/vault/blob after lock: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected Client 2 token revoked (401) after global vault lock, got %d", res.StatusCode)
	}
}
