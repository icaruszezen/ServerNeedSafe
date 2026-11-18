package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func newTestServerInstance(t *testing.T, dataDir string, sessionTTL time.Duration) (*Server, *httptest.Server) {
	t.Helper()
	blindStore, err := vault.NewBlindStore(filepath.Join(dataDir, "vault.sns"))
	if err != nil {
		t.Fatalf("NewBlindStore: %v", err)
	}
	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := NewServer(Config{
		DeployMode: "server",
		BlindStore: blindStore,
		KeyMgr:     vault.NewServerKeyManager(dataDir),
		Auth:       authMgr,
		Relay:      relay.NewManager("127.0.0.1:0"),
	})
	ts := httptest.NewServer(srv.Handler())
	return srv, ts
}

func newCookieHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func TestNativeDaemonAuthSessionIdleMigrationAndKDF(t *testing.T) {
	dataDir := t.TempDir()
	srv, ts := newTestServerInstance(t, dataDir, 8*time.Hour)

	rawHTTP := &http.Client{}
	adminClient := newCookieHTTPClient()

	// 1. Unauthenticated callers get 401 on all protected routes & zero metadata before setup
	for _, ep := range []string{
		"/api/workspace/bootstrap",
		"/api/servers",
		"/api/credentials",
		"/api/snippets",
		"/api/monitor/overview",
		"/api/ai/overview",
		"/api/vault/security",
		"/api/vault/export",
		"/api/vault/blob",
	} {
		res, err := rawHTTP.Get(ts.URL + ep)
		if err != nil {
			t.Fatalf("GET %s: %v", ep, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 on %s before setup, got %d", ep, res.StatusCode)
		}
	}

	// 2. Native Admin Setup creates encrypted vault.sns + 0600 .vault.key + HttpOnly session cookie
	adminPass1 := "AdminSecretPassword!2026"
	setupBody, _ := json.Marshal(map[string]string{"password": adminPass1})
	res, err := adminClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil {
		t.Fatalf("POST /api/auth/setup: %v", err)
	}
	var setupResp struct {
		Encryption vault.EncryptionInfo `json:"encryption"`
		Status     struct {
			Authenticated     bool   `json:"authenticated"`
			DaemonRunning     bool   `json:"daemon_running"`
			MigrationPending  bool   `json:"migration_pending"`
			AutoUnlockEnabled bool   `json:"auto_unlock_enabled"`
			VaultStatus       string `json:"vault_status"`
		} `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&setupResp); err != nil {
		res.Body.Close()
		t.Fatalf("decode setupResp: %v", err)
	}
	cookies := res.Cookies()
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !setupResp.Status.Authenticated || !setupResp.Status.DaemonRunning || !setupResp.Status.AutoUnlockEnabled || setupResp.Status.MigrationPending {
		t.Fatalf("unexpected setup response: status=%d body=%+v", res.StatusCode, setupResp)
	}

	hasSessionCookie := false
	for _, ck := range cookies {
		if ck.Name == adminSessionCookieName && ck.HttpOnly && ck.SameSite == http.SameSiteStrictMode {
			hasSessionCookie = true
		}
	}
	if !hasSessionCookie {
		t.Fatalf("expected HttpOnly SameSite=Strict %s cookie on setup, got %+v", adminSessionCookieName, cookies)
	}

	keyPath := filepath.Join(dataDir, ".vault.key")
	stKey, err := os.Stat(keyPath)
	if err != nil || stKey.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 .vault.key at %s, stat=%v err=%v", keyPath, stKey, err)
	}

	// 3. Unauthenticated caller STILL sees zero vault metadata while 7x24 daemon runs in background!
	res, err = rawHTTP.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("unauth GET /api/auth/status: %v", err)
	}
	var pubStatus struct {
		Authenticated bool                 `json:"authenticated"`
		DaemonRunning bool                 `json:"daemon_running"`
		VaultPath     string               `json:"vault_path"`
		KeySealPath   string               `json:"key_seal_path"`
		Encryption    vault.EncryptionInfo `json:"encryption"`
	}
	_ = json.NewDecoder(res.Body).Decode(&pubStatus)
	res.Body.Close()
	if pubStatus.Authenticated || !pubStatus.DaemonRunning {
		t.Fatalf("unexpected unauth status: %+v", pubStatus)
	}
	if pubStatus.VaultPath != "" || pubStatus.KeySealPath != "" || pubStatus.Encryption.VaultID != "" || pubStatus.Encryption.AuthPubKeySHA256 != "" || pubStatus.Encryption.Revision != 0 {
		t.Fatalf("SECURITY FAILURE: unauthenticated /api/auth/status leaked metadata: %+v", pubStatus)
	}

	// 4. Create server + snippet via authenticated cookie session & verify 1-RTT /api/workspace/bootstrap
	srvInput, _ := json.Marshal(map[string]any{
		"name":      "prod-gateway-01",
		"group":     "生产环境",
		"host":      "192.168.10.5",
		"port":      22,
		"username":  "root",
		"auth_type": "password",
		"password":  "SecretSSHPass!123",
	})
	cRes, err := adminClient.Post(ts.URL+"/api/servers", "application/json", bytes.NewReader(srvInput))
	if err != nil || cRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/servers failed: status=%v err=%v", cRes.StatusCode, err)
	}
	cRes.Body.Close()

	snipInput, _ := json.Marshal(map[string]any{
		"title":    "Check Load",
		"category": "系统监控",
		"command":  "uptime",
	})
	sRes, err := adminClient.Post(ts.URL+"/api/snippets", "application/json", bytes.NewReader(snipInput))
	if err != nil || sRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/snippets failed: status=%v err=%v", sRes.StatusCode, err)
	}
	sRes.Body.Close()

	bootRes, err := adminClient.Get(ts.URL + "/api/workspace/bootstrap")
	if err != nil || bootRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/workspace/bootstrap failed: status=%v err=%v", bootRes.StatusCode, err)
	}
	var bootstrapPayload struct {
		Servers  []vault.ServerView `json:"servers"`
		Snippets []vault.Snippet    `json:"snippets"`
	}
	_ = json.NewDecoder(bootRes.Body).Decode(&bootstrapPayload)
	bootRes.Body.Close()
	if len(bootstrapPayload.Servers) != 1 || len(bootstrapPayload.Snippets) < 5 {
		t.Fatalf("expected 1 server and >=5 snippets in bootstrap, got %+v", bootstrapPayload)
	}

	// 5. Wrong password rejected with 401; Session Lock revokes ALL Web sessions while keeping 7x24 daemon running!
	badLogin, _ := json.Marshal(map[string]string{"password": "WrongPassword!999"})
	badRes, err := rawHTTP.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(badLogin))
	if err != nil {
		t.Fatalf("POST wrong login: %v", err)
	}
	badRes.Body.Close()
	if badRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong admin password, got %d", badRes.StatusCode)
	}

	adminClient2 := newCookieHTTPClient()
	goodLogin, _ := json.Marshal(map[string]string{"password": adminPass1})
	loginRes2, err := adminClient2.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(goodLogin))
	if err != nil || loginRes2.StatusCode != http.StatusOK {
		t.Fatalf("adminClient2 login failed: status=%v err=%v", loginRes2.StatusCode, err)
	}
	loginRes2.Body.Close()

	// Lock via adminClient -> revokes BOTH adminClient and adminClient2, while 7x24 daemon stays unlocked!
	lockRes, err := adminClient.Post(ts.URL+"/api/auth/lock", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || lockRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/lock failed: status=%v err=%v", lockRes.StatusCode, err)
	}
	lockRes.Body.Close()

	if !srv.isDaemonUnlocked() {
		t.Fatalf("CRITICAL: locking Web sessions MUST NOT stop 7x24 background daemon!")
	}
	for idx, cl := range []*http.Client{adminClient, adminClient2} {
		chk, _ := cl.Get(ts.URL + "/api/servers")
		chk.Body.Close()
		if chk.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected client #%d session revoked (401) after /api/auth/lock, got %d", idx+1, chk.StatusCode)
		}
	}

	// 6. Restarting server auto-unlocks in <1ms via .vault.key without requiring admin password!
	ts.Close()
	srv.Close()

	srvRestarted, tsRestarted := newTestServerInstance(t, dataDir, 8*time.Hour)
	if !srvRestarted.isDaemonUnlocked() {
		tsRestarted.Close()
		srvRestarted.Close()
		t.Fatalf("expected restarted server to auto-unlock immediately via .vault.key")
	}
	tsRestarted.Close()
	srvRestarted.Close()

	// 7. Delete .vault.key to simulate legacy vault.sns upgrade -> enters migration_pending, then auto-migrates on first login!
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("os.Remove(.vault.key): %v", err)
	}
	srvLegacy, tsLegacy := newTestServerInstance(t, dataDir, 8*time.Hour)
	defer tsLegacy.Close()
	defer srvLegacy.Close()

	if srvLegacy.isDaemonUnlocked() {
		t.Fatalf("expected daemon to remain locked before migration when .vault.key is absent")
	}
	migStatusRes, _ := rawHTTP.Get(tsLegacy.URL + "/api/auth/status")
	var migStatus struct {
		DaemonRunning    bool `json:"daemon_running"`
		MigrationPending bool `json:"migration_pending"`
	}
	_ = json.NewDecoder(migStatusRes.Body).Decode(&migStatus)
	migStatusRes.Body.Close()
	if migStatus.DaemonRunning || !migStatus.MigrationPending {
		t.Fatalf("expected migration_pending=true before first login, got %+v", migStatus)
	}

	migratedClient := newCookieHTTPClient()
	migLoginRes, err := migratedClient.Post(tsLegacy.URL+"/api/auth/login", "application/json", bytes.NewReader(goodLogin))
	if err != nil || migLoginRes.StatusCode != http.StatusOK {
		t.Fatalf("migration login failed: status=%v err=%v", migLoginRes.StatusCode, err)
	}
	var migAfter struct {
		Status struct {
			Authenticated     bool `json:"authenticated"`
			DaemonRunning     bool `json:"daemon_running"`
			MigrationPending  bool `json:"migration_pending"`
			AutoUnlockEnabled bool `json:"auto_unlock_enabled"`
		} `json:"status"`
	}
	_ = json.NewDecoder(migLoginRes.Body).Decode(&migAfter)
	migLoginRes.Body.Close()
	if !migAfter.Status.Authenticated || !migAfter.Status.DaemonRunning || migAfter.Status.MigrationPending || !migAfter.Status.AutoUnlockEnabled {
		t.Fatalf("expected seamless .vault.key migration on first login, got %+v", migAfter)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected .vault.key regenerated during migration: %v", err)
	}

	// 8. Argon2id KDF Profile Tuning (POST /api/vault/kdf) + Admin Password Rotation (POST /api/auth/password)
	kdfReq, _ := json.Marshal(map[string]any{
		"password":       adminPass1,
		"kdf_memory_kib": 32 * 1024,
		"kdf_time":       2,
		"kdf_threads":    4,
	})
	kdfRes, err := migratedClient.Post(tsLegacy.URL+"/api/vault/kdf", "application/json", bytes.NewReader(kdfReq))
	if err != nil || kdfRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/vault/kdf failed: status=%v err=%v", kdfRes.StatusCode, err)
	}
	var kdfOut struct {
		Encryption vault.EncryptionInfo `json:"encryption"`
	}
	_ = json.NewDecoder(kdfRes.Body).Decode(&kdfOut)
	kdfRes.Body.Close()
	if kdfOut.Encryption.KDFMemoryKiB != 32*1024 || kdfOut.Encryption.KDFTime != 2 {
		t.Fatalf("expected KDF updated to 32768 KiB / t=2, got %+v", kdfOut.Encryption)
	}

	adminPass2 := "RotatedAdminMasterPass!2027"
	rotReq, _ := json.Marshal(map[string]string{
		"old_password": adminPass1,
		"new_password": adminPass2,
	})
	rotRes, err := migratedClient.Post(tsLegacy.URL+"/api/auth/password", "application/json", bytes.NewReader(rotReq))
	if err != nil || rotRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/password failed: status=%v err=%v", rotRes.StatusCode, err)
	}
	rotRes.Body.Close()

	// Verify old password fails and new password works!
	oldTry, _ := rawHTTP.Post(tsLegacy.URL+"/api/auth/login", "application/json", bytes.NewReader(goodLogin))
	oldTry.Body.Close()
	if oldTry.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected old password rejected after rotation, got %d", oldTry.StatusCode)
	}
	newLoginBody, _ := json.Marshal(map[string]string{"password": adminPass2})
	newClient := newCookieHTTPClient()
	newTry, err := newClient.Post(tsLegacy.URL+"/api/auth/login", "application/json", bytes.NewReader(newLoginBody))
	if err != nil || newTry.StatusCode != http.StatusOK {
		t.Fatalf("expected rotated password login to succeed: status=%v err=%v", newTry.StatusCode, err)
	}
	newTry.Body.Close()
}
