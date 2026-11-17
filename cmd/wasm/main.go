//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/zkclient"
)

type wasmRuntime struct {
	mu          sync.RWMutex
	engine      *zkclient.Engine
	tabSessions map[string]string // tabId -> sshSessionId
}

func (rt *wasmRuntime) getEngine() (*zkclient.Engine, error) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.engine == nil {
		return nil, errors.New("零知识密码学引擎尚未完成初始化")
	}
	return rt.engine, nil
}

func main() {
	rt := &wasmRuntime{
		tabSessions: make(map[string]string),
	}

	// Periodic idle auto-lock check inside Worker WASM linear memory
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rt.mu.RLock()
			eng := rt.engine
			rt.mu.RUnlock()
			if eng != nil && eng.Vault().CheckAutoLock() {
				_ = eng.Lock()
				fn := js.Global().Get("__snsOnVaultLocked")
				if fn.Type() == js.TypeFunction {
					fn.Invoke("idle_timeout")
				}
			}
		}
	}()

	apiObj := js.Global().Get("Object").New()

	callFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		action := ""
		payloadJSON := "{}"
		var binData []byte

		if len(args) > 0 && args[0].Type() == js.TypeString {
			action = args[0].String()
		}
		if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
			payloadJSON = args[1].String()
		}
		if len(args) > 2 && args[2].Type() == js.TypeObject && !args[2].IsNull() && !args[2].IsUndefined() {
			n := args[2].Get("byteLength").Int()
			if n > 0 {
				binData = make([]byte, n)
				js.CopyBytesToGo(binData, args[2])
			}
		}

		promiseCtor := js.Global().Get("Promise")
		var executor js.Func
		executor = js.FuncOf(func(this js.Value, pArgs []js.Value) any {
			resolve := pArgs[0]
			go func() {
				defer executor.Release()
				defer vault.ZeroBytes(binData)
				resObj := rt.dispatch(action, payloadJSON, binData)
				resolve.Invoke(resObj)
			}()
			return nil
		})
		return promiseCtor.New(executor)
	})

	termInputFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return nil
		}
		tabID := args[0].String()
		u8 := args[1]
		if u8.IsUndefined() || u8.IsNull() {
			return nil
		}
		n := u8.Get("byteLength").Int()
		if n <= 0 {
			return nil
		}
		buf := make([]byte, n)
		js.CopyBytesToGo(buf, u8)

		rt.mu.RLock()
		eng := rt.engine
		sessID := rt.tabSessions[tabID]
		rt.mu.RUnlock()

		if eng != nil && sessID != "" {
			eng.Vault().TouchActivity()
			if sess := eng.SSH().GetSession(sessID); sess != nil {
				go func(data []byte) {
					defer vault.ZeroBytes(data)
					_ = sess.WriteInput(data)
				}(buf)
				return nil
			}
		}
		vault.ZeroBytes(buf)
		return nil
	})

	termResizeFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return nil
		}
		tabID := args[0].String()
		cols := args[1].Int()
		rows := args[2].Int()

		rt.mu.RLock()
		eng := rt.engine
		sessID := rt.tabSessions[tabID]
		rt.mu.RUnlock()

		if eng != nil && sessID != "" {
			if sess := eng.SSH().GetSession(sessID); sess != nil {
				go func() {
					_ = sess.Resize(cols, rows)
				}()
			}
		}
		return nil
	})

	termCloseFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		tabID := args[0].String()
		rt.mu.Lock()
		eng := rt.engine
		sessID := rt.tabSessions[tabID]
		delete(rt.tabSessions, tabID)
		rt.mu.Unlock()

		if eng != nil && sessID != "" {
			go eng.SSH().CloseSession(sessID)
		}
		return nil
	})

	apiObj.Set("call", callFn)
	apiObj.Set("termInput", termInputFn)
	apiObj.Set("termResize", termResizeFn)
	apiObj.Set("termClose", termCloseFn)
	js.Global().Set("__snsWasm", apiObj)

	readyFn := js.Global().Get("__snsOnWasmReady")
	if readyFn.Type() == js.TypeFunction {
		readyFn.Invoke()
	}

	// Keep WASM runtime alive inside Dedicated Web Worker until terminated
	select {}
}

func makeSuccessEnvelope(data any, rawBytes []byte) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("ok", true)
	if data != nil {
		rawJSON, _ := json.Marshal(data)
		obj.Set("json", string(rawJSON))
		vault.ZeroBytes(rawJSON)
	} else {
		obj.Set("json", "{}")
	}
	if len(rawBytes) > 0 {
		u8 := js.Global().Get("Uint8Array").New(len(rawBytes))
		js.CopyBytesToJS(u8, rawBytes)
		obj.Set("bytes", u8)
	}
	return obj
}

func makeErrorEnvelope(err error) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("ok", false)
	obj.Set("error", err.Error())

	status := 400
	code := "OPERATION_FAILED"

	var apiErr *zkclient.APIError
	var hkErr *sshmanager.HostKeyUntrustedError

	switch {
	case errors.As(err, &hkErr):
		status = 409
		code = "HOST_KEY_UNTRUSTED"
		hkBytes, _ := json.Marshal(hkErr)
		obj.Set("hostKeyJson", string(hkBytes))
	case errors.As(err, &apiErr):
		status = apiErr.StatusCode
		if apiErr.Code != "" {
			code = apiErr.Code
		}
		if apiErr.RetryAfterSec > 0 {
			obj.Set("retryAfterSec", apiErr.RetryAfterSec)
		}
	case errors.Is(err, vault.ErrVaultLocked):
		status = 401
		code = "VAULT_LOCKED"
	case errors.Is(err, vault.ErrInvalidPassword), errors.Is(err, vault.ErrInvalidSignature):
		status = 401
		code = "INVALID_PASSWORD"
	case errors.Is(err, vault.ErrRollbackDetected):
		status = 409
		code = "ROLLBACK_DETECTED"
	case errors.Is(err, vault.ErrKDFDowngrade):
		status = 409
		code = "KDF_DOWNGRADE"
	case errors.Is(err, vault.ErrWeakPassword), errors.Is(err, vault.ErrInvalidInput):
		status = 400
		code = "INVALID_INPUT"
	case errors.Is(err, vault.ErrNotFound):
		status = 404
		code = "NOT_FOUND"
	}

	obj.Set("status", status)
	obj.Set("code", code)
	return obj
}

func (rt *wasmRuntime) dispatch(action, payloadJSON string, binData []byte) js.Value {
	if action == "init" {
		var req struct {
			Origin string             `json:"origin"`
			Anchor *vault.VaultAnchor `json:"anchor"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng := zkclient.NewWasmEngine(req.Origin)
		if req.Anchor != nil && req.Anchor.VaultID != "" {
			eng.Vault().SetAnchor(req.Anchor)
		}
		eng.Monitor().SetOnPersist(func() {
			anchor := eng.Vault().GetAnchor()
			if anchor == nil || anchor.VaultID == "" {
				return
			}
			fn := js.Global().Get("__snsOnAnchorUpdated")
			if fn.Type() == js.TypeFunction {
				if raw, mErr := json.Marshal(anchor); mErr == nil {
					fn.Invoke(string(raw))
				}
			}
		})
		rt.mu.Lock()
		prevEng := rt.engine
		rt.engine = eng
		rt.mu.Unlock()
		if prevEng != nil {
			prevEng.Close()
		}
		eng.Monitor().Start()
		return makeSuccessEnvelope(map[string]any{"ok": true}, nil)
	}

	eng, err := rt.getEngine()
	if err != nil {
		return makeErrorEnvelope(err)
	}

	switch action {
	case "getAuthStatus":
		st, err := eng.Status()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(st, nil)

	case "setupVault":
		var req struct {
			Password string `json:"password"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		st, err := eng.Setup(req.Password)
		req.Password = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"status":   st,
			"settings": st.Settings,
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "unlockVault":
		var req struct {
			Password string `json:"password"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		st, err := eng.Unlock(req.Password)
		req.Password = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"status":   st,
			"settings": st.Settings,
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "lockVault":
		_ = eng.Lock()
		return makeSuccessEnvelope(map[string]any{"ok": true}, nil)

	case "logoutSession":
		_ = eng.Logout()
		return makeSuccessEnvelope(map[string]any{"ok": true}, nil)

	case "clearAnchor":
		eng.Vault().SetAnchor(nil)
		return makeSuccessEnvelope(map[string]any{"ok": true}, nil)

	case "changePassword":
		var req struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		err := eng.ChangePassword(req.OldPassword, req.NewPassword)
		req.OldPassword = ""
		req.NewPassword = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "exportVault":
		raw, err := eng.ExportBackup()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		filename := fmt.Sprintf("ServerNeedSafe-vault-%s.sns", time.Now().Format("20060102-150405"))
		return makeSuccessEnvelope(map[string]any{
			"filename": filename,
			"anchor":   eng.Vault().GetAnchor(),
		}, raw)

	case "importVault":
		var req struct {
			Password             string `json:"password"`
			CurrentAdminPassword string `json:"current_admin_password"`
			ClearAnchor          bool   `json:"clear_anchor"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if req.ClearAnchor {
			eng.Vault().SetAnchor(nil)
		}
		st, err := eng.ImportBackup(binData, req.Password, req.CurrentAdminPassword)
		req.Password = ""
		req.CurrentAdminPassword = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":       true,
			"status":   st,
			"settings": st.Settings,
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "getVaultSecurity":
		srvSt, err := eng.Status()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		encInfo, err := eng.Vault().EncryptionInfo()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		settings, err := eng.Vault().GetSettings()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		knownHosts, _ := eng.Vault().ListKnownHosts()
		auditLogs, _ := eng.Vault().ListAuditLogs(200)
		return makeSuccessEnvelope(map[string]any{
			"deploy_mode":     srvSt.DeployMode,
			"vault_path":      srvSt.VaultPath,
			"zero_knowledge":  true,
			"encryption":      encInfo,
			"settings":        settings,
			"known_hosts":     knownHosts,
			"audit_logs":      auditLogs,
			"active_sessions": srvSt.ActiveSessions,
			"active_relays":   srvSt.ActiveRelays,
			"active_ssh_tabs": len(eng.SSH().ListActiveSessions()),
			"anchor":          eng.Vault().GetAnchor(),
		}, nil)

	case "updateSettings":
		var in vault.AppSettings
		if err := json.Unmarshal([]byte(payloadJSON), &in); err != nil {
			return makeErrorEnvelope(err)
		}
		updated, err := eng.Vault().UpdateSettings(in, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"settings": updated,
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "deleteKnownHost":
		var req struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.Vault().DeleteKnownHost(req.Address, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "listServers":
		eng.Vault().TouchActivity()
		servers, err := eng.Vault().ListServers()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		groups, err := eng.Vault().ListGroups()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"servers":         servers,
			"groups":          groups,
			"active_sessions": eng.SSH().ListActiveSessions(),
		}, nil)

	case "createServer":
		var in vault.ServerMutationInput
		if err := json.Unmarshal([]byte(payloadJSON), &in); err != nil {
			return makeErrorEnvelope(err)
		}
		srv, err := eng.Vault().CreateServer(in, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Monitor().Wake()
		return makeSuccessEnvelope(map[string]any{
			"server": srv,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "updateServer":
		var req struct {
			ID      string                    `json:"id"`
			Payload vault.ServerMutationInput `json:"payload"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		srv, err := eng.Vault().UpdateServer(req.ID, req.Payload, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Monitor().Wake()
		return makeSuccessEnvelope(map[string]any{
			"server": srv,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "deleteServer":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.Vault().DeleteServer(req.ID, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Monitor().Wake()
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "probeServer":
		var req struct {
			ID               string `json:"id"`
			TrustFingerprint string `json:"trust_fingerprint"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		probe, err := eng.SSH().ProbeServer(req.ID, req.TrustFingerprint, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"probe":  probe,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "addGroup":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		groups, err := eng.Vault().AddGroup(req.Name)
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"groups": groups,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "deleteGroup":
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		groups, err := eng.Vault().DeleteGroup(req.Name)
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"groups": groups,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "listCredentials":
		creds, err := eng.Vault().ListCredentials()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"credentials": creds}, nil)

	case "createCredential":
		var in vault.CredentialMutationInput
		if err := json.Unmarshal([]byte(payloadJSON), &in); err != nil {
			return makeErrorEnvelope(err)
		}
		cred, err := eng.Vault().CreateCredential(in, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"credential": cred,
			"anchor":     eng.Vault().GetAnchor(),
		}, nil)

	case "updateCredential":
		var req struct {
			ID      string                        `json:"id"`
			Payload vault.CredentialMutationInput `json:"payload"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		cred, err := eng.Vault().UpdateCredential(req.ID, req.Payload, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"credential": cred,
			"anchor":     eng.Vault().GetAnchor(),
		}, nil)

	case "deleteCredential":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.Vault().DeleteCredential(req.ID, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "generateKeyPair":
		var req struct {
			Algorithm    string `json:"algorithm"`
			Comment      string `json:"comment"`
			Passphrase   string `json:"passphrase"`
			SaveName     string `json:"save_name"`
			UsernameHint string `json:"username_hint"`
			Notes        string `json:"notes"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		kp, err := sshmanager.GenerateSSHKeyPair(req.Algorithm, req.Comment, req.Passphrase)
		if err != nil {
			return makeErrorEnvelope(err)
		}
		resp := map[string]any{
			"algorithm":   kp.Algorithm,
			"public_key":  kp.PublicKey,
			"fingerprint": kp.Fingerprint,
		}
		if strings.TrimSpace(req.SaveName) != "" {
			privCopy := kp.PrivateKey
			passCopy := req.Passphrase
			saved, cErr := eng.Vault().CreateCredential(vault.CredentialMutationInput{
				Name:         req.SaveName,
				Kind:         vault.AuthPrivateKey,
				UsernameHint: req.UsernameHint,
				PrivateKey:   &privCopy,
				Passphrase:   &passCopy,
				PublicKey:    kp.PublicKey,
				Fingerprint:  kp.Fingerprint,
				KeyAlgorithm: kp.Algorithm,
				Notes:        req.Notes,
			}, "client-zk")
			if cErr != nil {
				return makeErrorEnvelope(cErr)
			}
			resp["credential"] = saved
		} else {
			resp["private_key"] = kp.PrivateKey
		}
		resp["anchor"] = eng.Vault().GetAnchor()
		return makeSuccessEnvelope(resp, nil)

	case "deployPublicKey":
		var req struct {
			ServerID     string `json:"server_id"`
			CredentialID string `json:"credential_id"`
			PublicKey    string `json:"public_key"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		pubKey := strings.TrimSpace(req.PublicKey)
		if pubKey == "" && req.CredentialID != "" {
			cred, cErr := eng.Vault().GetCredentialSecret(req.CredentialID)
			if cErr != nil {
				return makeErrorEnvelope(cErr)
			}
			pubKey = cred.PublicKey
		}
		if err := eng.SSH().DeployPublicKey(req.ServerID, pubKey, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "listSnippets":
		snips, err := eng.Vault().ListSnippets()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"snippets": snips}, nil)

	case "upsertSnippet":
		var in vault.Snippet
		if err := json.Unmarshal([]byte(payloadJSON), &in); err != nil {
			return makeErrorEnvelope(err)
		}
		snip, err := eng.Vault().UpsertSnippet(in, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"snippet": snip,
			"anchor":  eng.Vault().GetAnchor(),
		}, nil)

	case "deleteSnippet":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.Vault().DeleteSnippet(req.ID, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "batchExec":
		var req struct {
			ServerIDs  []string `json:"server_ids"`
			Command    string   `json:"command"`
			TimeoutSec int      `json:"timeout_sec"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		results := eng.SSH().BatchExecute(req.ServerIDs, req.Command, time.Duration(req.TimeoutSec)*time.Second, "client-zk")
		return makeSuccessEnvelope(map[string]any{
			"results": results,
			"anchor":  eng.Vault().GetAnchor(),
		}, nil)

	case "openTerminal":
		var req struct {
			TabID            string `json:"tab_id"`
			ServerID         string `json:"server_id"`
			Cols             int    `json:"cols"`
			Rows             int    `json:"rows"`
			TrustFingerprint string `json:"trust_fingerprint"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}

		// Close any previous PTY attached to this tabId
		rt.mu.Lock()
		oldSessID := rt.tabSessions[req.TabID]
		delete(rt.tabSessions, req.TabID)
		rt.mu.Unlock()
		if oldSessID != "" {
			eng.SSH().CloseSession(oldSessID)
		}

		tabID := req.TabID
		ts, ready, err := eng.SSH().OpenTerminalSession(
			req.ServerID,
			req.Cols,
			req.Rows,
			req.TrustFingerprint,
			"client-zk",
			sshmanager.TerminalCallbacks{
				OnOutput: func(chunk []byte) {
					outFn := js.Global().Get("__snsOnTermOutput")
					if outFn.Type() == js.TypeFunction {
						u8 := js.Global().Get("Uint8Array").New(len(chunk))
						js.CopyBytesToJS(u8, chunk)
						outFn.Invoke(tabID, u8)
					}
					vault.ZeroBytes(chunk)
				},
				OnExit: func(msg string) {
					exitFn := js.Global().Get("__snsOnTermExit")
					if exitFn.Type() == js.TypeFunction {
						exitFn.Invoke(tabID, msg)
					}
				},
			},
		)
		if err != nil {
			return makeErrorEnvelope(err)
		}
		rt.mu.Lock()
		rt.tabSessions[tabID] = ts.ID
		rt.mu.Unlock()

		return makeSuccessEnvelope(map[string]any{
			"ready":  ready,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "sftpList":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		resp, err := eng.SSH().SFTPList(req.ServerID, req.Path, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(resp, nil)

	case "sftpRead":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		content, err := eng.SSH().SFTPReadText(req.ServerID, req.Path, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"path":    req.Path,
			"content": content,
		}, nil)

	case "sftpWrite":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
			Content  string `json:"content"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.SSH().SFTPWriteText(req.ServerID, req.Path, req.Content, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "sftpUpload":
		var req struct {
			ServerID string `json:"server_id"`
			Dir      string `json:"dir"`
			Filename string `json:"filename"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		destPath, written, err := eng.SSH().SFTPUpload(req.ServerID, req.Dir, req.Filename, bytes.NewReader(binData), "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"path":   destPath,
			"bytes":  written,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "sftpDownload":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		data, name, err := eng.SSH().SFTPDownloadBytes(req.ServerID, req.Path, 128*1024*1024, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"filename": name,
			"anchor":   eng.Vault().GetAnchor(),
		}, data)

	case "sftpMkdir":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.SSH().SFTPMkdir(req.ServerID, req.Path, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"ok": true, "anchor": eng.Vault().GetAnchor()}, nil)

	case "sftpRename":
		var req struct {
			ServerID string `json:"server_id"`
			OldPath  string `json:"old_path"`
			NewPath  string `json:"new_path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.SSH().SFTPRename(req.ServerID, req.OldPath, req.NewPath, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"ok": true, "anchor": eng.Vault().GetAnchor()}, nil)

	case "sftpDelete":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.SSH().SFTPRemove(req.ServerID, req.Path, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"ok": true, "anchor": eng.Vault().GetAnchor()}, nil)

	case "sftpChmod":
		var req struct {
			ServerID string `json:"server_id"`
			Path     string `json:"path"`
			Mode     string `json:"mode"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if err := eng.SSH().SFTPChmod(req.ServerID, req.Path, req.Mode, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"ok": true, "anchor": eng.Vault().GetAnchor()}, nil)

	case "syncPush":
		var req struct {
			RemoteURL      string `json:"remote_url"`
			RemotePassword string `json:"remote_password"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		sum, err := eng.SyncPushToRemote(req.RemoteURL, req.RemotePassword)
		req.RemotePassword = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"summary": sum,
			"anchor":  eng.Vault().GetAnchor(),
		}, nil)

	case "syncPull":
		var req struct {
			RemoteURL            string `json:"remote_url"`
			RemotePassword       string `json:"remote_password"`
			CurrentLocalPassword string `json:"current_local_password"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		sum, err := eng.SyncPullFromRemote(req.RemoteURL, req.RemotePassword, req.CurrentLocalPassword)
		req.RemotePassword = ""
		req.CurrentLocalPassword = ""
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"summary": sum,
			"anchor":  eng.Vault().GetAnchor(),
		}, nil)

	case "getMonitorOverview":
		ov, err := eng.Vault().GetMonitorOverview()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"settings": ov.Settings,
			"kpi":      ov.KPI,
			"nodes":    ov.Nodes,
			"alerts":   ov.Alerts,
			"runtime":  eng.Monitor().Status(),
		}, nil)

	case "getServerMonitorDetail":
		var req struct {
			ID    string `json:"id"`
			Range string `json:"range"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		detail, err := eng.Vault().GetServerMonitorDetail(req.ID, monitor.ParseHistoryRange(req.Range))
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"detail":  detail,
			"runtime": eng.Monitor().Status(),
		}, nil)

	case "collectAllMonitor":
		var req struct {
			ServerIDs []string `json:"server_ids"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		snaps, err := eng.Monitor().CollectAllNow(context.Background(), req.ServerIDs, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":        true,
			"count":     len(snaps),
			"snapshots": snaps,
			"runtime":   eng.Monitor().Status(),
			"anchor":    eng.Vault().GetAnchor(),
		}, nil)

	case "collectServerMonitor":
		var req struct {
			ID               string `json:"id"`
			TrustFingerprint string `json:"trust_fingerprint"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		snap, err := eng.Monitor().CollectServerNow(context.Background(), req.ID, req.TrustFingerprint, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":       true,
			"snapshot": snap,
			"runtime":  eng.Monitor().Status(),
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "acceptPortBaseline":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		base, err := eng.Vault().AcceptServerPortBaseline(req.ID, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":            true,
			"port_baseline": base,
			"anchor":        eng.Vault().GetAnchor(),
		}, nil)

	case "listMonitorAlerts":
		var req struct {
			Status   string `json:"status"`
			ServerID string `json:"server_id"`
			Limit    int    `json:"limit"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		if req.Limit <= 0 {
			req.Limit = 300
		}
		alerts, err := eng.Vault().ListMonitorAlerts(req.Status, req.ServerID, req.Limit)
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{"alerts": alerts}, nil)

	case "ackMonitorAlert":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		al, err := eng.Vault().AcknowledgeMonitorAlert(req.ID, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"alert":  al,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "clearResolvedMonitorAlerts":
		eng.Vault().TouchActivity()
		removed, err := eng.Vault().ClearResolvedMonitorAlerts("client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":      true,
			"removed": removed,
			"anchor":  eng.Vault().GetAnchor(),
		}, nil)

	case "getMonitorPolicy":
		settings, rules, err := eng.Vault().GetMonitorPolicy()
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"settings": settings,
			"rules":    rules,
			"runtime":  eng.Monitor().Status(),
		}, nil)

	case "updateMonitorPolicy":
		var req struct {
			Settings vault.MonitorSettings    `json:"settings"`
			Rules    []vault.MonitorAlertRule `json:"rules"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		settings, rules, err := eng.Vault().UpdateMonitorPolicy(req.Settings, req.Rules, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Monitor().Wake()
		return makeSuccessEnvelope(map[string]any{
			"ok":       true,
			"settings": settings,
			"rules":    rules,
			"runtime":  eng.Monitor().Status(),
			"anchor":   eng.Vault().GetAnchor(),
		}, nil)

	case "clearMonitorHistory":
		var req struct {
			ServerID string `json:"server_id"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		if err := eng.Vault().ClearMonitorHistory(req.ServerID, "client-zk"); err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"ok":     true,
			"anchor": eng.Vault().GetAnchor(),
		}, nil)

	case "exportMonitorHistory":
		var req struct {
			Format   string `json:"format"`
			ServerID string `json:"server_id"`
			Range    string `json:"range"`
		}
		if err := json.Unmarshal([]byte(payloadJSON), &req); err != nil {
			return makeErrorEnvelope(err)
		}
		eng.Vault().TouchActivity()
		raw, filename, contentType, err := monitor.ExportHistory(eng.Vault(), req.Format, req.ServerID, req.Range, "client-zk")
		if err != nil {
			return makeErrorEnvelope(err)
		}
		return makeSuccessEnvelope(map[string]any{
			"filename":     filename,
			"content_type": contentType,
			"anchor":       eng.Vault().GetAnchor(),
		}, raw)

	default:
		return makeErrorEnvelope(fmt.Errorf("unknown WASM RPC action %q", action))
	}
}
