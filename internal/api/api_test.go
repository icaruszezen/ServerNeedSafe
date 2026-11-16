package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func TestAPIAuthGateMultiSessionAndVaultLock(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := vault.NewStore(filepath.Join(tmpDir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	authMgr, err := auth.NewManager(time.Hour, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sshMgr := sshmanager.NewManager(store)
	srv := NewServer(Config{
		DeployMode: "server",
		Store:      store,
		Auth:       authMgr,
		SSH:        sshMgr,
	})
	defer srv.Close()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{}

	// 1. Protected endpoint rejects unauthenticated call
	res, err := client.Get(ts.URL + "/api/servers")
	if err != nil {
		t.Fatalf("GET /api/servers: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before setup, got %d", res.StatusCode)
	}

	// 2. Setup Admin Password
	setupBody, _ := json.Marshal(map[string]string{"password": "AdminSecretPassword!2026"})
	res, err = client.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil {
		t.Fatalf("POST /api/auth/setup: %v", err)
	}
	var setupResp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&setupResp)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || setupResp.Token == "" {
		t.Fatalf("setup failed: status=%d token=%q", res.StatusCode, setupResp.Token)
	}

	// 3. Create server with Client 1 token
	createPayload, _ := json.Marshal(map[string]any{
		"name":      "gateway-01",
		"group":     "生产环境",
		"host":      "192.168.10.5",
		"port":      22,
		"username":  "root",
		"auth_type": "password",
		"password":  "SecretSSH123",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/api/servers", bytes.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+setupResp.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusCreated {
		t.Fatalf("create server failed: status=%v err=%v", res.StatusCode, err)
	}
	res.Body.Close()

	// 4. Client 2 (new browser entering app WITHOUT token) MUST NOT be authenticated!
	res, err = client.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status: %v", err)
	}
	var statusResp struct {
		VaultStatus   string `json:"vault_status"`
		Authenticated bool   `json:"authenticated"`
	}
	_ = json.NewDecoder(res.Body).Decode(&statusResp)
	res.Body.Close()
	if statusResp.Authenticated {
		t.Fatalf("SECURITY FAILURE: new client without token was treated as authenticated!")
	}
	res, _ = client.Get(ts.URL + "/api/servers")
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY FAILURE: Client 2 accessed /api/servers without Admin Password!")
	}

	// 5. Client 2 tries wrong Admin Password -> rejected!
	badUnlock, _ := json.Marshal(map[string]string{"password": "WrongPassword999"})
	res, _ = client.Post(ts.URL+"/api/auth/unlock", "application/json", bytes.NewReader(badUnlock))
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong unlock password, got %d", res.StatusCode)
	}

	// 6. Client 1 locks vault -> Client 1's own token is immediately invalidated & vault is locked!
	lockReq, _ := http.NewRequest("POST", ts.URL+"/api/auth/lock", nil)
	lockReq.Header.Set("Authorization", "Bearer "+setupResp.Token)
	res, _ = client.Do(lockReq)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("lock failed: %d", res.StatusCode)
	}

	checkReq, _ := http.NewRequest("GET", ts.URL+"/api/servers", nil)
	checkReq.Header.Set("Authorization", "Bearer "+setupResp.Token)
	res, _ = client.Do(checkReq)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after lock, got %d", res.StatusCode)
	}
}
