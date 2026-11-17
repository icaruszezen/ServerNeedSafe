package zkclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// HTTPJSONDoer executes an HTTP JSON request without coupling WASM builds to Go's heavy net/http + crypto/tls stack.
type HTTPJSONDoer func(method, fullURL string, reqJSON []byte, bearerToken string, sameOrigin bool) (statusCode int, respBody []byte, err error)

type apiErrorPayload struct {
	Error          string `json:"error"`
	Code           string `json:"code"`
	RetryAfterSec  int    `json:"retry_after_sec,omitempty"`
	FailedAttempts int    `json:"failed_attempts,omitempty"`
}

// APIError preserves structured HTTP status and error codes returned by sns-server.
type APIError struct {
	StatusCode     int
	Code           string
	Message        string
	RetryAfterSec  int
	FailedAttempts int
}

func (e *APIError) Error() string {
	return e.Message
}

func (e *APIError) Unwrap() error {
	switch e.Code {
	case "INVALID_PASSWORD":
		return vault.ErrInvalidPassword
	case "REVISION_CONFLICT":
		return vault.ErrRevisionConflict
	case "VAULT_NOT_INIT":
		return vault.ErrVaultNotInit
	case "VAULT_ALREADY_INIT":
		return vault.ErrVaultAlreadyInit
	case "CORRUPTED_VAULT":
		return vault.ErrCorruptedVault
	default:
		return nil
	}
}

type challengeResponse struct {
	ChallengeID string                 `json:"challenge_id"`
	Nonce       string                 `json:"nonce"`
	KDF         *vault.PublicKDFParams `json:"kdf"`
}

// ServerStatusResponse combines server blind-store metadata with local client zero-knowledge state.
type ServerStatusResponse struct {
	Initialized    bool                  `json:"initialized"`
	VaultStatus    vault.VaultStatus     `json:"vault_status"`
	Authenticated  bool                  `json:"authenticated"`
	DeployMode     string                `json:"deploy_mode"`
	ZeroKnowledge  bool                  `json:"zero_knowledge"`
	VaultPath      string                `json:"vault_path"`
	Encryption     *vault.EncryptionInfo `json:"encryption"`
	Settings       *vault.AppSettings    `json:"settings,omitempty"`
	Anchor         *vault.VaultAnchor    `json:"anchor,omitempty"`
	ActiveSessions int                   `json:"active_sessions,omitempty"`
	ActiveRelays   int                   `json:"active_relays,omitempty"`
}

// SyncSummary reports the outcome of a Remote Zero-Knowledge Vault Sync operation.
type SyncSummary struct {
	Direction string `json:"direction"` // "push" or "pull"
	RemoteURL string `json:"remote_url"`
	VaultID   string `json:"vault_id"`
	Revision  uint64 `json:"revision"`
	Bytes     int    `json:"bytes"`
}

type httpBlindBackend struct {
	mu         sync.RWMutex
	baseURL    string
	doer       HTTPJSONDoer
	sameOrigin bool
	token      string
}

func newHTTPBlindBackendWithDoer(baseURL string, doer HTTPJSONDoer, sameOrigin bool) *httpBlindBackend {
	return &httpBlindBackend{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		doer:       doer,
		sameOrigin: sameOrigin,
	}
}

func (b *httpBlindBackend) Token() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.token
}

func (b *httpBlindBackend) SetToken(tok string) {
	b.mu.Lock()
	b.token = tok
	b.mu.Unlock()
}

func (b *httpBlindBackend) doJSON(method, path string, reqBody any, dst any, withAuth bool) error {
	var rawReq []byte
	if reqBody != nil {
		var err error
		rawReq, err = json.Marshal(reqBody)
		if err != nil {
			return err
		}
	}
	tok := ""
	if withAuth {
		tok = b.Token()
	}

	statusCode, respBytes, err := b.doer(method, b.baseURL+path, rawReq, tok, b.sameOrigin)
	if err != nil {
		return fmt.Errorf("无法连接到服务端 (%s): %w", b.baseURL, err)
	}

	if statusCode < 200 || statusCode >= 300 {
		var errPayload apiErrorPayload
		_ = json.Unmarshal(respBytes, &errPayload)
		msg := errPayload.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d 请求失败", statusCode)
		}
		return &APIError{
			StatusCode:     statusCode,
			Code:           errPayload.Code,
			Message:        msg,
			RetryAfterSec:  errPayload.RetryAfterSec,
			FailedAttempts: errPayload.FailedAttempts,
		}
	}
	if dst != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *httpBlindBackend) fetchServerStatus() (*ServerStatusResponse, error) {
	var st ServerStatusResponse
	if err := b.doJSON("GET", "/api/auth/status", nil, &st, true); err != nil {
		return nil, err
	}
	return &st, nil
}

func (b *httpBlindBackend) IsInitialized() (bool, error) {
	st, err := b.fetchServerStatus()
	if err != nil {
		return false, err
	}
	return st.Initialized, nil
}

func (b *httpBlindBackend) requestChallengeFull() (*challengeResponse, error) {
	var ch challengeResponse
	if err := b.doJSON("POST", "/api/auth/challenge", map[string]any{}, &ch, false); err != nil {
		return nil, err
	}
	if ch.KDF == nil || ch.ChallengeID == "" || ch.Nonce == "" {
		return nil, vault.ErrCorruptedVault
	}
	return &ch, nil
}

func (b *httpBlindBackend) PublicParams() (*vault.PublicKDFParams, error) {
	ch, err := b.requestChallengeFull()
	if err != nil {
		return nil, err
	}
	return ch.KDF, nil
}

func (b *httpBlindBackend) verifyChallenge(challengeID string, sig []byte) error {
	var resp struct {
		Token string `json:"token"`
	}
	err := b.doJSON("POST", "/api/auth/verify", map[string]any{
		"challenge_id":  challengeID,
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
	}, &resp, false)
	if err != nil {
		return err
	}
	b.SetToken(resp.Token)
	return nil
}

func (b *httpBlindBackend) Initialize(raw []byte, sig []byte) error {
	var resp struct {
		Token string `json:"token"`
	}
	err := b.doJSON("POST", "/api/auth/setup", map[string]any{
		"blob_b64":      base64.StdEncoding.EncodeToString(raw),
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
	}, &resp, false)
	if err != nil {
		return err
	}
	b.SetToken(resp.Token)
	return nil
}

func (b *httpBlindBackend) Read() ([]byte, error) {
	var resp struct {
		BlobB64 string `json:"blob_b64"`
	}
	if err := b.doJSON("GET", "/api/vault/blob", nil, &resp, true); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.BlobB64)
}

func (b *httpBlindBackend) Put(raw []byte, expectedPrevRev uint64, sig []byte) error {
	return b.doJSON("PUT", "/api/vault/blob", map[string]any{
		"expected_prev_revision": expectedPrevRev,
		"blob_b64":               base64.StdEncoding.EncodeToString(raw),
		"signature_b64":          base64.StdEncoding.EncodeToString(sig),
	}, nil, true)
}

func (b *httpBlindBackend) RotatePassword(raw []byte, expectedPrevRev uint64, oldSig, newSig []byte) error {
	var resp struct {
		Token string `json:"token"`
	}
	err := b.doJSON("POST", "/api/auth/password", map[string]any{
		"expected_prev_revision": expectedPrevRev,
		"blob_b64":               base64.StdEncoding.EncodeToString(raw),
		"old_signature_b64":      base64.StdEncoding.EncodeToString(oldSig),
		"new_signature_b64":      base64.StdEncoding.EncodeToString(newSig),
	}, &resp, true)
	if err != nil {
		return err
	}
	b.SetToken(resp.Token)
	return nil
}

func (b *httpBlindBackend) Import(raw []byte, newSig, overwriteSig []byte) error {
	payload := map[string]any{
		"blob_b64":          base64.StdEncoding.EncodeToString(raw),
		"new_signature_b64": base64.StdEncoding.EncodeToString(newSig),
	}
	if len(overwriteSig) > 0 {
		payload["overwrite_signature_b64"] = base64.StdEncoding.EncodeToString(overwriteSig)
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := b.doJSON("POST", "/api/vault/import", payload, &resp, false); err != nil {
		return err
	}
	b.SetToken(resp.Token)
	return nil
}

func (b *httpBlindBackend) notifyLock() {
	if b.Token() != "" {
		_ = b.doJSON("POST", "/api/auth/lock", map[string]any{}, nil, true)
		b.SetToken("")
	}
}

func (b *httpBlindBackend) notifyLogout() {
	if b.Token() != "" {
		_ = b.doJSON("POST", "/api/auth/logout", map[string]any{}, nil, true)
		b.SetToken("")
	}
}

func (b *httpBlindBackend) issueRelayTicket() (string, error) {
	var resp struct {
		Ticket string `json:"ticket"`
	}
	if err := b.doJSON("POST", "/api/ws/ticket", map[string]any{}, &resp, true); err != nil {
		return "", err
	}
	if resp.Ticket == "" {
		return "", errors.New("获取安全中继票据失败")
	}
	return resp.Ticket, nil
}

func (b *httpBlindBackend) wsRelayURL(ticket string) (string, error) {
	u, err := url.Parse(b.baseURL)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported base URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/ws/tcp-relay"
	q := u.Query()
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (b *httpBlindBackend) dialRelayTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	ticket, err := b.issueRelayTicket()
	if err != nil {
		return nil, err
	}
	wsURL, err := b.wsRelayURL(ticket)
	if err != nil {
		return nil, err
	}
	return dialWebSocketConn(ctx, wsURL, b.baseURL, addr, timeout)
}

// Engine unifies the client-side Zero-Knowledge Vault, Ed25519 Challenge-Response Auth,
// End-to-End SSHv2/SFTP/Monitoring Manager over Blind TCP Relay, and Remote Zero-Knowledge Sync.
type Engine struct {
	baseURL string
	doer    HTTPJSONDoer
	backend *httpBlindBackend
	cv      *vault.ClientVault
	sshMgr  *sshmanager.Manager
	mon     *monitor.Engine
}

func newEngineWithDoer(baseURL string, doer HTTPJSONDoer) *Engine {
	backend := newHTTPBlindBackendWithDoer(baseURL, doer, true)
	cv := vault.NewClientVault(backend)
	sshMgr := sshmanager.NewManager(cv)
	sshMgr.SetDialTCPFunc(backend.dialRelayTCP)
	mon := monitor.NewEngine(cv, sshMgr)

	return &Engine{
		baseURL: backend.baseURL,
		doer:    doer,
		backend: backend,
		cv:      cv,
		sshMgr:  sshMgr,
		mon:     mon,
	}
}

func (e *Engine) Vault() *vault.ClientVault {
	return e.cv
}

func (e *Engine) SSH() *sshmanager.Manager {
	return e.sshMgr
}

func (e *Engine) Monitor() *monitor.Engine {
	return e.mon
}

func (e *Engine) Close() {
	if e.mon != nil {
		e.mon.Close()
	}
	if e.sshMgr != nil {
		e.sshMgr.CloseAllSessions()
	}
}

func (e *Engine) Token() string {
	return e.backend.Token()
}

// Status queries server blind metadata and merges local zero-knowledge unlock state.
func (e *Engine) Status() (*ServerStatusResponse, error) {
	srvSt, err := e.backend.fetchServerStatus()
	if err != nil {
		return nil, err
	}
	localStatus := e.cv.Status()
	if !srvSt.Initialized {
		if anchor := e.cv.GetAnchor(); anchor != nil && anchor.VaultID != "" {
			srvSt.Anchor = anchor
		}
		srvSt.VaultStatus = vault.StatusUninitialized
		srvSt.Authenticated = false
		return srvSt, nil
	}

	if localStatus == vault.StatusUnlocked && srvSt.Authenticated {
		srvSt.VaultStatus = vault.StatusUnlocked
		srvSt.Settings, _ = e.cv.GetSettings()
		if enc, encErr := e.cv.EncryptionInfo(); encErr == nil {
			srvSt.Encryption = enc
		}
	} else {
		srvSt.VaultStatus = vault.StatusLocked
		srvSt.Authenticated = false
	}
	srvSt.Anchor = e.cv.GetAnchor()
	return srvSt, nil
}

// Setup initializes a new Zero-Knowledge Vault locally and pushes ONLY signed ciphertext to the server.
func (e *Engine) Setup(password string) (*ServerStatusResponse, error) {
	if err := e.cv.Setup(password, "client-zk"); err != nil {
		return nil, err
	}
	return e.Status()
}

// Unlock performs Zero-Knowledge Ed25519 challenge-response login and decrypts the vault strictly in client memory.
func (e *Engine) Unlock(password string) (*ServerStatusResponse, error) {
	if password == "" {
		return nil, vault.ErrInvalidPassword
	}
	ch, err := e.backend.requestChallengeFull()
	if err != nil {
		return nil, err
	}

	if anchor := e.cv.GetAnchor(); anchor != nil {
		if anchor.VaultID != "" && ch.KDF.VaultID != anchor.VaultID {
			return nil, fmt.Errorf("%w: 保险库 ID 发生变化（本地锚定 %s，服务端返回 %s）", vault.ErrRollbackDetected, anchor.VaultID, ch.KDF.VaultID)
		}
		if ch.KDF.Revision < anchor.MinRevision {
			return nil, fmt.Errorf("%w: 检测到服务端密文回滚（本地已锚定版本 #%d，服务端返回 #%d）", vault.ErrRollbackDetected, anchor.MinRevision, ch.KDF.Revision)
		}
	}

	kek, authPriv, authPub, err := vault.DeriveVaultKeys(
		password,
		ch.KDF.KDFSalt,
		ch.KDF.KDFTime,
		ch.KDF.KDFMemoryKiB,
		ch.KDF.KDFThreads,
		e.cv.MinMemoryKiB(),
	)
	if err != nil {
		return nil, err
	}
	defer vault.ZeroBytes(kek)
	defer vault.ZeroBytes(authPriv)

	sig := vault.SignAuthChallenge(authPriv, ch.ChallengeID, ch.Nonce, ch.KDF.VaultID)
	if err := e.backend.verifyChallenge(ch.ChallengeID, sig); err != nil {
		return nil, err
	}

	rawBlob, err := e.backend.Read()
	if err != nil {
		e.backend.SetToken("")
		return nil, err
	}

	if err := e.cv.UnlockWithPreDerivedKeys(rawBlob, kek, authPriv, authPub, ch.KDF, "client-zk", true); err != nil {
		e.backend.SetToken("")
		return nil, err
	}
	return e.Status()
}

// Lock wipes client memory keys, closes all active SSH/SFTP tunnels, and revokes all server sessions & relays.
func (e *Engine) Lock() error {
	e.cv.Lock("管理员手动锁定零知识保险库", "client-zk")
	e.backend.notifyLock()
	return nil
}

// Logout closes local SSH sessions, wipes client memory keys, and revokes the caller's session token.
func (e *Engine) Logout() error {
	e.sshMgr.CloseAllSessions()
	e.cv.Lock("", "client-zk")
	e.backend.notifyLogout()
	return nil
}

// ChangePassword rotates Argon2id salt, master DEK, and Ed25519 AuthKeyPair locally and updates the server atomically.
func (e *Engine) ChangePassword(oldPassword, newPassword string) error {
	return e.cv.ChangePassword(oldPassword, newPassword, "client-zk")
}

// ExportBackup returns the authenticated SNSVAULT v2 ciphertext container bytes.
func (e *Engine) ExportBackup() ([]byte, error) {
	return e.cv.ExportEncryptedBytes("client-zk")
}

// ImportBackup decrypts & verifies a .sns backup locally, upgrades/re-seals it, and atomically imports it.
func (e *Engine) ImportBackup(raw []byte, backupPassword, currentAdminPassword string) (*ServerStatusResponse, error) {
	if err := e.cv.ImportEncryptedVault(raw, backupPassword, currentAdminPassword, "client-zk"); err != nil {
		return nil, err
	}
	return e.Status()
}

// SyncPushToRemote pushes the local client's opaque SNSVAULT v2 ciphertext container to a remote Zero-Knowledge sns-server.
func (e *Engine) SyncPushToRemote(remoteURL, remoteAdminPassword string) (*SyncSummary, error) {
	remoteURL = strings.TrimRight(strings.TrimSpace(remoteURL), "/")
	if remoteURL == "" {
		return nil, errors.New("请先填写远程零知识同步服务端地址")
	}
	rawBlob, hdr, err := e.cv.LastSealedBlob()
	if err != nil {
		return nil, err
	}
	localPriv := e.cv.AuthPrivateKeyCopy()
	if len(localPriv) == 0 {
		return nil, vault.ErrVaultLocked
	}
	defer vault.ZeroBytes(localPriv)

	remoteBackend := newHTTPBlindBackendWithDoer(remoteURL, e.doer, false)
	init, err := remoteBackend.IsInitialized()
	if err != nil {
		return nil, err
	}

	newSig := vault.SignVaultImport(localPriv, hdr.VaultID, hdr.Revision, rawBlob)
	var overwriteSig []byte
	if init {
		params, pErr := remoteBackend.PublicParams()
		if pErr != nil {
			return nil, pErr
		}
		if remoteAdminPassword == "" && params.VaultID == hdr.VaultID {
			overwriteSig = vault.SignVaultImportOverwrite(localPriv, params.VaultID, hdr.VaultID, rawBlob)
		} else {
			if remoteAdminPassword == "" {
				return nil, errors.New("远程服务端已存在不同保险库，请提供远程当前管理员密码以生成零知识覆盖授权签名")
			}
			kekTmp, remPriv, _, dErr := vault.DeriveVaultKeys(
				remoteAdminPassword,
				params.KDFSalt,
				params.KDFTime,
				params.KDFMemoryKiB,
				params.KDFThreads,
				e.cv.MinMemoryKiB(),
			)
			if dErr != nil {
				return nil, dErr
			}
			vault.ZeroBytes(kekTmp)
			overwriteSig = vault.SignVaultImportOverwrite(remPriv, params.VaultID, hdr.VaultID, rawBlob)
			vault.ZeroBytes(remPriv)
		}
	}

	if err := remoteBackend.Import(rawBlob, newSig, overwriteSig); err != nil {
		return nil, err
	}
	remoteBackend.notifyLogout()

	e.cv.RecordAudit("vault.sync_push", remoteURL, fmt.Sprintf("零知识推送加密密文容器 (Revision #%d)", hdr.Revision), "client-zk", true)
	return &SyncSummary{
		Direction: "push",
		RemoteURL: remoteURL,
		VaultID:   hdr.VaultID,
		Revision:  hdr.Revision,
		Bytes:     len(rawBlob),
	}, nil
}

// SyncPullFromRemote authenticates via Zero-Knowledge Ed25519 challenge-response against remoteURL,
// downloads its opaque ciphertext container, verifies & decrypts locally, and updates the local vault.
func (e *Engine) SyncPullFromRemote(remoteURL, remotePassword, currentLocalPassword string) (*SyncSummary, error) {
	remoteURL = strings.TrimRight(strings.TrimSpace(remoteURL), "/")
	if remoteURL == "" || remotePassword == "" {
		return nil, errors.New("请提供远程服务端地址与加密保险库密码")
	}

	remoteBackend := newHTTPBlindBackendWithDoer(remoteURL, e.doer, false)
	ch, err := remoteBackend.requestChallengeFull()
	if err != nil {
		return nil, err
	}

	kekTmp, remPriv, _, err := vault.DeriveVaultKeys(
		remotePassword,
		ch.KDF.KDFSalt,
		ch.KDF.KDFTime,
		ch.KDF.KDFMemoryKiB,
		ch.KDF.KDFThreads,
		e.cv.MinMemoryKiB(),
	)
	if err != nil {
		return nil, err
	}
	vault.ZeroBytes(kekTmp)
	sig := vault.SignAuthChallenge(remPriv, ch.ChallengeID, ch.Nonce, ch.KDF.VaultID)
	vault.ZeroBytes(remPriv)

	if err := remoteBackend.verifyChallenge(ch.ChallengeID, sig); err != nil {
		return nil, err
	}
	remoteBlob, err := remoteBackend.Read()
	remoteBackend.notifyLogout()
	if err != nil {
		return nil, err
	}

	if anchor := e.cv.GetAnchor(); anchor != nil && anchor.VaultID != ch.KDF.VaultID {
		e.cv.SetAnchor(nil)
	}
	if _, err := e.ImportBackup(remoteBlob, remotePassword, currentLocalPassword); err != nil {
		return nil, err
	}
	_, hdr, _ := e.cv.LastSealedBlob()
	rev := ch.KDF.Revision
	if hdr != nil {
		rev = hdr.Revision
	}
	return &SyncSummary{
		Direction: "pull",
		RemoteURL: remoteURL,
		VaultID:   ch.KDF.VaultID,
		Revision:  rev,
		Bytes:     len(remoteBlob),
	}, nil
}
