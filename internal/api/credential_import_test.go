package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func postMultipartKeyImport(
	t *testing.T,
	client *http.Client,
	url string,
	privFilename string,
	privContent []byte,
	pubFilename string,
	pubContent []byte,
	fields map[string]string,
) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	if privFilename != "" {
		part, err := mw.CreateFormFile("private_key_file", privFilename)
		if err != nil {
			t.Fatalf("CreateFormFile(private): %v", err)
		}
		if _, err := part.Write(privContent); err != nil {
			t.Fatalf("Write(private): %v", err)
		}
	}
	if pubFilename != "" {
		part, err := mw.CreateFormFile("public_key_file", pubFilename)
		if err != nil {
			t.Fatalf("CreateFormFile(public): %v", err)
		}
		if _, err := part.Write(pubContent); err != nil {
			t.Fatalf("Write(public): %v", err)
		}
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%s): %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return res
}

func TestCredentialFileUploadImportAndServerKeyValidation(t *testing.T) {
	dataDir := t.TempDir()
	srv, ts := newTestServerInstance(t, dataDir, auth.DefaultSessionTTL)
	defer func() {
		ts.Close()
		srv.Close()
	}()

	rawHTTP := &http.Client{}
	adminClient := newCookieHTTPClient()

	// 1. Unauthenticated multipart upload must be rejected with 401
	unauthRes := postMultipartKeyImport(t, rawHTTP, ts.URL+"/api/credentials/import-file", "id_ed25519", []byte("dummy"), "", nil, nil)
	unauthRes.Body.Close()
	if unauthRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before setup/login, got %d", unauthRes.StatusCode)
	}

	// Setup admin password
	setupBody, _ := json.Marshal(map[string]string{"password": "AdminKeyImportPass!2026"})
	setupRes, err := adminClient.Post(ts.URL+"/api/auth/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil || setupRes.StatusCode != http.StatusOK {
		t.Fatalf("setup failed: status=%v err=%v", setupRes.StatusCode, err)
	}
	setupRes.Body.Close()

	// 2. Upload plain Ed25519 private key file (BOM+CRLF, no explicit name or .pub) -> auto-name + auto-derive metadata
	plainKP, err := sshmanager.GenerateSSHKeyPair("ed25519", "ops@tokyo", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(plain): %v", err)
	}
	bomCRLF := "\uFEFF" + strings.ReplaceAll(plainKP.PrivateKey, "\n", "\r\n")
	res1 := postMultipartKeyImport(
		t,
		adminClient,
		ts.URL+"/api/credentials/import-file",
		"aws-tokyo-bastion.pem",
		[]byte(bomCRLF),
		"",
		nil,
		map[string]string{"notes": "东京生产跳板机密钥"},
	)
	var out1 struct {
		Credential       vault.CredentialView `json:"credential"`
		ImportedFilename string               `json:"imported_filename"`
	}
	if err := json.NewDecoder(res1.Body).Decode(&out1); err != nil {
		res1.Body.Close()
		t.Fatalf("decode import-file response: %v", err)
	}
	res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on valid key file upload, got %d", res1.StatusCode)
	}
	if out1.Credential.Name != "aws-tokyo-bastion" {
		t.Fatalf("expected auto-derived name aws-tokyo-bastion, got %q", out1.Credential.Name)
	}
	if out1.Credential.KeyAlgorithm != "ed25519" || out1.Credential.Fingerprint != plainKP.Fingerprint {
		t.Fatalf("expected auto-derived ed25519 metadata, got %+v", out1.Credential)
	}
	if !strings.HasPrefix(out1.Credential.PublicKey, "ssh-ed25519 ") || !out1.Credential.HasPrivateKey || out1.Credential.HasPassphrase {
		t.Fatalf("unexpected credential flags/public_key: %+v", out1.Credential)
	}
	if out1.ImportedFilename != "aws-tokyo-bastion.pem" {
		t.Fatalf("expected imported_filename aws-tokyo-bastion.pem, got %q", out1.ImportedFilename)
	}

	// 3. Upload passphrase-encrypted key file: missing passphrase -> 400, wrong passphrase -> 400, valid passphrase + matching .pub -> 200
	encKP, err := sshmanager.GenerateSSHKeyPair("ed25519", "secops@hk-cluster", "KeyFilePass#2026")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(encrypted): %v", err)
	}
	resNoPass := postMultipartKeyImport(
		t,
		adminClient,
		ts.URL+"/api/credentials/import-file",
		"id_ed25519",
		[]byte(encKP.PrivateKey),
		"",
		nil,
		map[string]string{"name": "HK-Encrypted-Key"},
	)
	resNoPass.Body.Close()
	if resNoPass.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when passphrase omitted for encrypted key, got %d", resNoPass.StatusCode)
	}

	resWrongPass := postMultipartKeyImport(
		t,
		adminClient,
		ts.URL+"/api/credentials/import-file",
		"id_ed25519",
		[]byte(encKP.PrivateKey),
		"",
		nil,
		map[string]string{"name": "HK-Encrypted-Key", "passphrase": "WrongPass!"},
	)
	resWrongPass.Body.Close()
	if resWrongPass.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when passphrase wrong, got %d", resWrongPass.StatusCode)
	}

	// Mismatched .pub file must be rejected
	resMismatchPub := postMultipartKeyImport(
		t,
		adminClient,
		ts.URL+"/api/credentials/import-file",
		"id_ed25519",
		[]byte(encKP.PrivateKey),
		"other.pub",
		[]byte(plainKP.PublicKey),
		map[string]string{"name": "HK-Encrypted-Key", "passphrase": "KeyFilePass#2026"},
	)
	resMismatchPub.Body.Close()
	if resMismatchPub.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on mismatched .pub file, got %d", resMismatchPub.StatusCode)
	}

	// Matching .pub file preserves user comment and succeeds
	resValidEnc := postMultipartKeyImport(
		t,
		adminClient,
		ts.URL+"/api/credentials/import-file",
		"id_ed25519",
		[]byte(encKP.PrivateKey),
		"id_ed25519.pub",
		[]byte(encKP.PublicKey),
		map[string]string{"name": "HK-Encrypted-Key", "passphrase": "KeyFilePass#2026"},
	)
	var outEnc struct {
		Credential vault.CredentialView `json:"credential"`
	}
	if err := json.NewDecoder(resValidEnc.Body).Decode(&outEnc); err != nil {
		resValidEnc.Body.Close()
		t.Fatalf("decode encrypted import response: %v", err)
	}
	resValidEnc.Body.Close()
	if resValidEnc.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on encrypted key + matching .pub upload, got %d", resValidEnc.StatusCode)
	}
	if !outEnc.Credential.HasPassphrase || outEnc.Credential.PublicKey != encKP.PublicKey || outEnc.Credential.Fingerprint != encKP.Fingerprint {
		t.Fatalf("unexpected encrypted credential result: %+v", outEnc.Credential)
	}

	// 4. Reject invalid/binary/.pub files in private_key_file slot
	for _, tc := range []struct {
		name     string
		filename string
		data     []byte
	}{
		{"binary", "photo.png", []byte{0x89, 'P', 'N', 'G', 0x00, 0x01}},
		{"pub_in_priv", "id_ed25519.pub", []byte(plainKP.PublicKey)},
		{"putty_ppk", "legacy.ppk", []byte("PuTTY-User-Key-File-2: ssh-rsa\n")},
	} {
		r := postMultipartKeyImport(t, adminClient, ts.URL+"/api/credentials/import-file", tc.filename, tc.data, "", nil, nil)
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("case %s: expected 400, got %d", tc.name, r.StatusCode)
		}
	}

	// 5. JSON POST /api/credentials also auto-derives algorithm, fingerprint & public key
	jsonCredBody, _ := json.Marshal(map[string]any{
		"name":        "Pasted-Ed25519-Key",
		"kind":        "private_key",
		"private_key": plainKP.PrivateKey,
	})
	jsonCredRes, err := adminClient.Post(ts.URL+"/api/credentials", "application/json", bytes.NewReader(jsonCredBody))
	if err != nil {
		t.Fatalf("POST /api/credentials: %v", err)
	}
	var jsonCredOut struct {
		Credential vault.CredentialView `json:"credential"`
	}
	_ = json.NewDecoder(jsonCredRes.Body).Decode(&jsonCredOut)
	jsonCredRes.Body.Close()
	if jsonCredRes.StatusCode != http.StatusOK || jsonCredOut.Credential.Fingerprint != plainKP.Fingerprint || jsonCredOut.Credential.KeyAlgorithm != "ed25519" {
		t.Fatalf("expected auto-derived metadata on JSON credential import, status=%d cred=%+v", jsonCredRes.StatusCode, jsonCredOut.Credential)
	}

	// 6. Server creation with inline private_key validates invalid key & accepts valid key
	badSrvBody, _ := json.Marshal(map[string]any{
		"name":        "Bad-Key-Server",
		"host":        "10.0.0.10",
		"port":        22,
		"username":    "root",
		"auth_type":   "private_key",
		"private_key": "not-a-valid-private-key",
	})
	badSrvRes, err := adminClient.Post(ts.URL+"/api/servers", "application/json", bytes.NewReader(badSrvBody))
	if err != nil {
		t.Fatalf("POST /api/servers(bad): %v", err)
	}
	badSrvRes.Body.Close()
	if badSrvRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid server private_key, got %d", badSrvRes.StatusCode)
	}

	goodSrvBody, _ := json.Marshal(map[string]any{
		"name":        "Uploaded-Key-Server",
		"host":        "10.0.0.11",
		"port":        22,
		"username":    "ubuntu",
		"auth_type":   "private_key",
		"private_key": bomCRLF,
	})
	goodSrvRes, err := adminClient.Post(ts.URL+"/api/servers", "application/json", bytes.NewReader(goodSrvBody))
	if err != nil {
		t.Fatalf("POST /api/servers(good): %v", err)
	}
	goodSrvRes.Body.Close()
	if goodSrvRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid server private_key, got %d", goodSrvRes.StatusCode)
	}
}
