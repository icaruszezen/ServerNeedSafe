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
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func newTestServerInstance(t *testing.T, dataDir string, sessionTTL time.Duration) (*Server, *httptest.Server) {
	t.Helper()
	store, err := vault.NewStore(dataDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		store.Close()
		t.Fatalf("NewManager: %v", err)
	}
	srv := NewServer(Config{
		DeployMode: "server",
		Store:      store,
		Auth:       authMgr,
	})
	ts := httptest.NewServer(srv.Handler())
	return srv, ts
}

func newCookieHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func TestDecoupledAuthSessionLockRestartAndPasswordRotation(t *testing.T) {
	dataDir := t.TempDir()
	srv, ts := newTestServerInstance(t, dataDir, auth.DefaultSessionTTL)

	rawHTTP := &http.Client{}
	adminClient := newCookieHTTPClient()

	// 1. Unauthenticated callers get 401 on all protected routes before setup
	for _, ep := range []string{
		"/api/workspace/bootstrap",
		"/api/servers",
		"/api/credentials",
		"/api/snippets",
		"/api/monitor/overview",
		"/api/ai/overview",
		"/api/vault/security",
		"/api/vault/sync/snapshot",
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
	expUnauth, err := rawHTTP.Post(ts.URL+"/api/vault/export", "application/json", bytes.NewReader([]byte(`{"backup_password":"BackupPass!2026"}`)))
	if err != nil {
		t.Fatalf("unauth POST /api/vault/export: %v", err)
	}
	expUnauth.Body.Close()
	if expUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on POST /api/vault/export before setup, got %d", expUnauth.StatusCode)
	}

	// 2. Setup creates secrets.enc + 0600 master.key + HttpOnly SameSite=Lax cookie + 7-day default session
	adminPass1 := "AdminSecretPassword!2026"
	setupBody, _ := json.Marshal(map[string]string{"password": adminPass1})
	res, err := adminClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil {
		t.Fatalf("POST /api/auth/setup: %v", err)
	}
	var setupResp struct {
		Encryption vault.EncryptionInfo `json:"encryption"`
		Settings   vault.AppSettings    `json:"settings"`
		Status     struct {
			Authenticated          bool   `json:"authenticated"`
			DaemonRunning          bool   `json:"daemon_running"`
			LegacyMigrationPending bool   `json:"legacy_migration_pending"`
			SessionTTLHours        int    `json:"session_ttl_hours"`
			VaultStatus            string `json:"vault_status"`
		} `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&setupResp); err != nil {
		res.Body.Close()
		t.Fatalf("decode setupResp: %v", err)
	}
	cookies := res.Cookies()
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !setupResp.Status.Authenticated || !setupResp.Status.DaemonRunning || setupResp.Status.LegacyMigrationPending {
		t.Fatalf("unexpected setup response: status=%d body=%+v", res.StatusCode, setupResp)
	}
	if setupResp.Status.SessionTTLHours != 168 {
		t.Fatalf("expected default 168h (7d) session TTL, got %d", setupResp.Status.SessionTTLHours)
	}
	if setupResp.Settings.AutoLockMinutes != 0 {
		t.Fatalf("expected default AutoLockMinutes=0 (idle auto-logout disabled), got %d", setupResp.Settings.AutoLockMinutes)
	}

	hasSessionCookie := false
	for _, ck := range cookies {
		if ck.Name == adminSessionCookieName && ck.HttpOnly && ck.SameSite == http.SameSiteLaxMode {
			hasSessionCookie = true
		}
	}
	if !hasSessionCookie {
		t.Fatalf("expected HttpOnly SameSite=Lax %s cookie on setup, got %+v", adminSessionCookieName, cookies)
	}

	keyPath := filepath.Join(dataDir, "master.key")
	stKey, err := os.Stat(keyPath)
	if err != nil || stKey.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 master.key at %s, stat=%v err=%v", keyPath, stKey, err)
	}
	masterKeyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}

	// 3. Unauthenticated caller sees daemon_running=true while sensitive storage paths/settings remain hidden
	res, err = rawHTTP.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("unauth GET /api/auth/status: %v", err)
	}
	var pubStatus struct {
		Authenticated bool                    `json:"authenticated"`
		DaemonRunning bool                    `json:"daemon_running"`
		Storage       *vault.StorageFilesInfo `json:"storage"`
		Settings      *vault.AppSettings      `json:"settings"`
	}
	_ = json.NewDecoder(res.Body).Decode(&pubStatus)
	res.Body.Close()
	if pubStatus.Authenticated || !pubStatus.DaemonRunning {
		t.Fatalf("unexpected unauth status: %+v", pubStatus)
	}
	if pubStatus.Storage != nil || pubStatus.Settings != nil {
		t.Fatalf("unauthenticated /api/auth/status should not expose storage paths or settings: %+v", pubStatus)
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

	// Lock via adminClient -> revokes BOTH adminClient and adminClient2, while 7x24 daemon stays ready!
	lockRes, err := adminClient.Post(ts.URL+"/api/auth/lock", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || lockRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/lock failed: status=%v err=%v", lockRes.StatusCode, err)
	}
	lockRes.Body.Close()

	if !srv.isDaemonReady() {
		t.Fatalf("CRITICAL: locking Web sessions MUST NOT stop 7x24 background daemon!")
	}
	for idx, cl := range []*http.Client{adminClient, adminClient2} {
		chk, _ := cl.Get(ts.URL + "/api/servers")
		chk.Body.Close()
		if chk.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected client #%d session revoked (401) after /api/auth/lock, got %d", idx+1, chk.StatusCode)
		}
	}

	// 6. Restarting server auto-loads secrets.enc via master.key without requiring admin password!
	ts.Close()
	srv.Close()

	srvRestarted, tsRestarted := newTestServerInstance(t, dataDir, auth.DefaultSessionTTL)
	defer tsRestarted.Close()
	defer srvRestarted.Close()

	if !srvRestarted.isDaemonReady() {
		t.Fatalf("expected restarted server to auto-boot ready via master.key")
	}

	// 7. Admin Password Change: never rotates master.key, never stops daemon, invalidates old password & old sessions
	reloginClient := newCookieHTTPClient()
	rlRes, err := reloginClient.Post(tsRestarted.URL+"/api/auth/login", "application/json", bytes.NewReader(goodLogin))
	if err != nil || rlRes.StatusCode != http.StatusOK {
		t.Fatalf("login after restart failed: status=%v err=%v", rlRes.StatusCode, err)
	}
	rlRes.Body.Close()

	adminPass2 := "RotatedAdminMasterPass!2027"
	rotReq, _ := json.Marshal(map[string]string{
		"old_password": adminPass1,
		"new_password": adminPass2,
	})
	rotRes, err := reloginClient.Post(tsRestarted.URL+"/api/auth/password", "application/json", bytes.NewReader(rotReq))
	if err != nil || rotRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/auth/password failed: status=%v err=%v", rotRes.StatusCode, err)
	}
	rotRes.Body.Close()

	if !srvRestarted.isDaemonReady() {
		t.Fatalf("changing admin password MUST NOT lock or interrupt daemon")
	}
	masterKeyAfter, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(masterKeyBefore, masterKeyAfter) {
		t.Fatalf("changing admin password MUST NOT rotate master.key")
	}

	// Verify old password fails and new password works!
	oldTry, _ := rawHTTP.Post(tsRestarted.URL+"/api/auth/login", "application/json", bytes.NewReader(goodLogin))
	oldTry.Body.Close()
	if oldTry.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected old password rejected after rotation, got %d", oldTry.StatusCode)
	}
	newLoginBody, _ := json.Marshal(map[string]string{"password": adminPass2})
	newClient := newCookieHTTPClient()
	newTry, err := newClient.Post(tsRestarted.URL+"/api/auth/login", "application/json", bytes.NewReader(newLoginBody))
	if err != nil || newTry.StatusCode != http.StatusOK {
		t.Fatalf("expected rotated password login to succeed: status=%v err=%v", newTry.StatusCode, err)
	}
	newTry.Body.Close()

	// Verify /api/vault/security reports split storage & encryption info
	secRes, err := newClient.Get(tsRestarted.URL + "/api/vault/security")
	if err != nil || secRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/vault/security failed: status=%v err=%v", secRes.StatusCode, err)
	}
	var secPayload struct {
		DaemonRunning   bool                   `json:"daemon_running"`
		SessionTTLHours int                    `json:"session_ttl_hours"`
		Encryption      vault.EncryptionInfo   `json:"encryption"`
		Storage         vault.StorageFilesInfo `json:"storage"`
	}
	_ = json.NewDecoder(secRes.Body).Decode(&secPayload)
	secRes.Body.Close()
	if !secPayload.DaemonRunning || secPayload.SessionTTLHours != 168 || secPayload.Storage.MasterKeyMode != "file" || secPayload.Storage.SecretsSizeBytes == 0 {
		t.Fatalf("unexpected /api/vault/security payload: %+v", secPayload)
	}
}
