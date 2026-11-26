package vault

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	secretsMagic = "SNSSEC01"

	vaultMagic            = "SNSVAULT"
	vaultFormatVersionV1  = uint16(1)
	vaultFormatVersionV2  = uint16(2)
	backupFormatVersionV3 = uint16(3)

	// Lightweight fixed Argon2id parameters (~10ms native Go, low memory, zero queueing).
	PasswordHashTime      = uint32(2)
	PasswordHashMemoryKiB = uint32(16 * 1024) // 16 MiB
	PasswordHashThreads   = uint8(2)

	BackupKDFTime      = uint32(2)
	BackupKDFMemoryKiB = uint32(16 * 1024) // 16 MiB
	BackupKDFThreads   = uint8(2)

	// Upper bounds when importing external backup headers to prevent accidental OOM from corrupted files.
	MaxAllowedKDFMemoryKiB = uint32(1024 * 1024) // 1 GiB
	MaxAllowedKDFTime      = uint32(32)
	MaxAllowedKDFThreads   = uint8(64)

	kdfSaltSize       = 32
	dekSize           = 32
	maxHeaderBytes    = 64 * 1024
	maxVaultBlobBytes = 128 * 1024 * 1024
)

var (
	ErrInvalidPassword  = errors.New("管理员密码错误或加密文件认证失败")
	ErrCorruptedVault   = errors.New("加密数据文件格式损坏或遭到篡改")
	ErrVaultLocked      = errors.New("检测到旧版加密容器待迁移，请先验证一次原管理员密码完成自动升级")
	ErrVaultNotInit     = errors.New("尚未初始化管理员密码与敏感资产加密库")
	ErrVaultAlreadyInit = errors.New("系统已初始化管理员密码")
	ErrWeakPassword     = errors.New("密码长度至少需要 8 位字符")
)

// EncryptionInfo exposes clean read-only cryptographic metadata for the Security Center UI.
type EncryptionInfo struct {
	FormatVersion    int    `json:"format_version"`
	VaultID          string `json:"vault_id,omitempty"`
	Revision         uint64 `json:"revision,omitempty"`
	CipherAlgo       string `json:"cipher_algo"`
	PasswordHashAlgo string `json:"password_hash_algo"`
	MasterKeyMode    string `json:"master_key_mode,omitempty"`
	VaultSizeBytes   int64  `json:"vault_size_bytes"`
}

// LegacyEnvelopeHeader is retained ONLY for reading legacy v1/v2 .sns backups and auto-migrating v2.x vault.sns.
type LegacyEnvelopeHeader struct {
	VaultID         string `json:"vault_id"`
	Revision        uint64 `json:"revision"`
	KDFAlgo         string `json:"kdf_algo"`
	KDFTime         uint32 `json:"kdf_time"`
	KDFMemoryKiB    uint32 `json:"kdf_memory_kib"`
	KDFThreads      uint8  `json:"kdf_threads"`
	KDFSalt         []byte `json:"kdf_salt"`
	AuthAlgo        string `json:"auth_algo"`
	AuthPublicKey   []byte `json:"auth_public_key"`
	WrapAlgo        string `json:"wrap_algo"`
	WrappedDEKNonce []byte `json:"wrapped_dek_nonce"`
	WrappedDEK      []byte `json:"wrapped_dek"`
	CipherAlgo      string `json:"cipher_algo"`
	PayloadNonce    []byte `json:"payload_nonce"`
}

// BackupHeaderV3 is the authenticated JSON header for portable password-encrypted .sns v3 backups.
type BackupHeaderV3 struct {
	VaultID        string    `json:"vault_id"`
	IncludeRuntime bool      `json:"include_runtime"`
	CreatedAt      time.Time `json:"created_at"`
	KDFAlgo        string    `json:"kdf_algo"`
	KDFTime        uint32    `json:"kdf_time"`
	KDFMemoryKiB   uint32    `json:"kdf_memory_kib"`
	KDFThreads     uint8     `json:"kdf_threads"`
	KDFSalt        []byte    `json:"kdf_salt"`
	CipherAlgo     string    `json:"cipher_algo"`
	PayloadNonce   []byte    `json:"payload_nonce"`
}

// ZeroBytes overwrites a byte slice in memory with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroBytes(b []byte) {
	ZeroBytes(b)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto/rand failure: %w", err)
	}
	return b, nil
}

func hkdfDerive32(secret, salt []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		zeroBytes(out)
		return nil, err
	}
	return out, nil
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func checkKDFCeiling(kdfTime, kdfMemoryKiB uint32, kdfThreads uint8) error {
	if kdfTime < 1 || kdfMemoryKiB < 1024 || kdfThreads < 1 ||
		kdfTime > MaxAllowedKDFTime || kdfMemoryKiB > MaxAllowedKDFMemoryKiB || kdfThreads > MaxAllowedKDFThreads {
		return fmt.Errorf("%w: Argon2id 参数超出合理范围", ErrCorruptedVault)
	}
	return nil
}

// --- Lightweight Admin Login Password Hashing (decoupled from data encryption) ---

// HashAdminPassword creates a PHC-formatted lightweight Argon2id password hash.
func HashAdminPassword(password string) (string, error) {
	if len([]rune(password)) < 8 {
		return "", ErrWeakPassword
	}
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	pwBytes := []byte(password)
	hash := argon2.IDKey(pwBytes, salt, PasswordHashTime, PasswordHashMemoryKiB, PasswordHashThreads, 32)
	zeroBytes(pwBytes)
	defer zeroBytes(hash)

	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		PasswordHashMemoryKiB,
		PasswordHashTime,
		PasswordHashThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyAdminPassword verifies a plaintext password against a PHC Argon2id hash in constant time.
func VerifyAdminPassword(password, encoded string) bool {
	if password == "" || encoded == "" {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem, timeCost uint32
	var threads uint8
	for _, kv := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return false
		}
		v, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return false
		}
		switch pair[0] {
		case "m":
			mem = uint32(v)
		case "t":
			timeCost = uint32(v)
		case "p":
			threads = uint8(v)
		}
	}
	if checkKDFCeiling(timeCost, mem, threads) != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	expectedHash, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(expectedHash) < 16 {
		return false
	}

	pwBytes := []byte(password)
	derived := argon2.IDKey(pwBytes, salt, timeCost, mem, threads, uint32(len(expectedHash)))
	zeroBytes(pwBytes)
	defer zeroBytes(derived)
	return constantTimeEqual(derived, expectedHash)
}

// VerifyLegacyAuth verifies a password against a migrated v2.x vault's Ed25519 derived public key.
func VerifyLegacyAuth(password string, legacy *LegacyPasswordVerifier) bool {
	if password == "" || legacy == nil || len(legacy.KDFSalt) < 16 || len(legacy.AuthPublicKey) != ed25519.PublicKeySize {
		return false
	}
	if checkKDFCeiling(legacy.KDFTime, legacy.KDFMemoryKiB, legacy.KDFThreads) != nil {
		return false
	}
	pwBytes := []byte(password)
	master := argon2.IDKey(pwBytes, legacy.KDFSalt, legacy.KDFTime, legacy.KDFMemoryKiB, legacy.KDFThreads, dekSize)
	zeroBytes(pwBytes)
	defer zeroBytes(master)

	authSeed, err := hkdfDerive32(master, legacy.KDFSalt, "SNSVAULT-v2-AUTH-ED25519")
	if err != nil {
		return false
	}
	defer zeroBytes(authSeed)

	authPriv := ed25519.NewKeyFromSeed(authSeed)
	defer zeroBytes(authPriv)
	authPub := authPriv.Public().(ed25519.PublicKey)
	return constantTimeEqual(authPub, legacy.AuthPublicKey)
}

// --- Secrets File Encryption (secrets.enc: gzip + XChaCha20-Poly1305, zero padding overhead) ---

func gzipJSON(v any) ([]byte, error) {
	rawJSON, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(rawJSON)

	var gzBuf bytes.Buffer
	gzW, err := gzip.NewWriterLevel(&gzBuf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := gzW.Write(rawJSON); err != nil {
		_ = gzW.Close()
		return nil, err
	}
	if err := gzW.Close(); err != nil {
		return nil, err
	}
	return gzBuf.Bytes(), nil
}

func gunzipJSON(comp []byte, dst any) error {
	gzR, err := gzip.NewReader(bytes.NewReader(comp))
	if err != nil {
		return ErrCorruptedVault
	}
	defer gzR.Close()

	rawJSON, err := io.ReadAll(io.LimitReader(gzR, 256*1024*1024))
	if err != nil {
		return ErrCorruptedVault
	}
	defer zeroBytes(rawJSON)

	if err := json.Unmarshal(rawJSON, dst); err != nil {
		return ErrCorruptedVault
	}
	return nil
}

// SealSecretsBytes encrypts SecretsState with XChaCha20-Poly1305 under the local master key.
// Binary layout: magic("SNSSEC01", 8B) + nonce(24B) + ciphertext(AEAD, AAD=magic).
func SealSecretsBytes(masterKey []byte, secrets *SecretsState) ([]byte, error) {
	if len(masterKey) != dekSize {
		return nil, errors.New("invalid master key length")
	}
	compressed, err := gzipJSON(secrets)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(compressed)

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, compressed, []byte(secretsMagic))

	out := make([]byte, len(secretsMagic)+len(nonce)+len(ct))
	copy(out[0:8], secretsMagic)
	copy(out[8:8+len(nonce)], nonce)
	copy(out[8+len(nonce):], ct)
	return out, nil
}

// OpenSecretsBytes authenticates and decrypts secrets.enc using the local master key.
func OpenSecretsBytes(masterKey []byte, raw []byte) (*SecretsState, error) {
	minLen := len(secretsMagic) + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(masterKey) != dekSize || len(raw) < minLen || len(raw) > maxVaultBlobBytes {
		return nil, ErrCorruptedVault
	}
	if string(raw[0:8]) != secretsMagic {
		return nil, ErrCorruptedVault
	}
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, ErrCorruptedVault
	}
	nonce := raw[8 : 8+chacha20poly1305.NonceSizeX]
	ct := raw[8+chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, ct, []byte(secretsMagic))
	if err != nil {
		return nil, ErrCorruptedVault
	}
	defer zeroBytes(plain)

	var st SecretsState
	if err := gunzipJSON(plain, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// --- Portable Password-Encrypted Backup Format (SNSVAULT v3) + Legacy v1/v2 Import ---

// SealBackupContainer encrypts a portable BackupBundle with a user-chosen backup passphrase.
func SealBackupContainer(password string, bundle *BackupBundle) ([]byte, error) {
	if len([]rune(password)) < 8 {
		return nil, ErrWeakPassword
	}
	salt, err := randomBytes(kdfSaltSize)
	if err != nil {
		return nil, err
	}
	pwBytes := []byte(password)
	key := argon2.IDKey(pwBytes, salt, BackupKDFTime, BackupKDFMemoryKiB, BackupKDFThreads, dekSize)
	zeroBytes(pwBytes)
	defer zeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	hdr := BackupHeaderV3{
		VaultID:        bundle.Config.VaultID,
		IncludeRuntime: bundle.IncludeRuntime,
		CreatedAt:      bundle.ExportedAt,
		KDFAlgo:        "argon2id",
		KDFTime:        BackupKDFTime,
		KDFMemoryKiB:   BackupKDFMemoryKiB,
		KDFThreads:     BackupKDFThreads,
		KDFSalt:        salt,
		CipherAlgo:     "xchacha20-poly1305",
		PayloadNonce:   nonce,
	}
	hdrBytes, err := json.Marshal(&hdr)
	if err != nil {
		return nil, err
	}

	prefix := make([]byte, len(vaultMagic)+2+4+len(hdrBytes))
	copy(prefix[0:8], vaultMagic)
	binary.BigEndian.PutUint16(prefix[8:10], backupFormatVersionV3)
	binary.BigEndian.PutUint32(prefix[10:14], uint32(len(hdrBytes)))
	copy(prefix[14:], hdrBytes)

	compressed, err := gzipJSON(bundle)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(compressed)

	ct := aead.Seal(nil, nonce, compressed, prefix)
	out := make([]byte, len(prefix)+len(ct))
	copy(out, prefix)
	copy(out[len(prefix):], ct)
	return out, nil
}

// OpenBackupContainer decrypts a .sns backup file (supports new v3 backups as well as legacy v1/v2 vaults).
func OpenBackupContainer(raw []byte, password string) (*BackupBundle, int, error) {
	if password == "" {
		return nil, 0, ErrInvalidPassword
	}
	minLen := len(vaultMagic) + 2 + 4 + 2 + chacha20poly1305.Overhead
	if len(raw) < minLen || len(raw) > maxVaultBlobBytes || string(raw[0:8]) != vaultMagic {
		return nil, 0, ErrCorruptedVault
	}
	ver := binary.BigEndian.Uint16(raw[8:10])
	switch ver {
	case backupFormatVersionV3:
		hdrLen := int(binary.BigEndian.Uint32(raw[10:14]))
		if hdrLen <= 0 || hdrLen > maxHeaderBytes || 14+hdrLen >= len(raw) {
			return nil, 0, ErrCorruptedVault
		}
		prefix := raw[:14+hdrLen]
		ct := raw[14+hdrLen:]
		var hdr BackupHeaderV3
		if err := json.Unmarshal(raw[14:14+hdrLen], &hdr); err != nil {
			return nil, 0, ErrCorruptedVault
		}
		if hdr.KDFAlgo != "argon2id" || len(hdr.KDFSalt) < 16 || hdr.CipherAlgo != "xchacha20-poly1305" {
			return nil, 0, ErrCorruptedVault
		}
		if err := checkKDFCeiling(hdr.KDFTime, hdr.KDFMemoryKiB, hdr.KDFThreads); err != nil {
			return nil, 0, err
		}
		pwBytes := []byte(password)
		key := argon2.IDKey(pwBytes, hdr.KDFSalt, hdr.KDFTime, hdr.KDFMemoryKiB, hdr.KDFThreads, dekSize)
		zeroBytes(pwBytes)
		defer zeroBytes(key)

		aead, err := chacha20poly1305.NewX(key)
		if err != nil || len(hdr.PayloadNonce) != aead.NonceSize() {
			return nil, 0, ErrCorruptedVault
		}
		plain, err := aead.Open(nil, hdr.PayloadNonce, ct, prefix)
		if err != nil {
			return nil, 0, ErrInvalidPassword
		}
		defer zeroBytes(plain)

		var bundle BackupBundle
		if err := gunzipJSON(plain, &bundle); err != nil {
			return nil, 0, err
		}
		return &bundle, int(ver), nil

	case vaultFormatVersionV2, vaultFormatVersionV1:
		_, st, _, err := OpenLegacyVaultContainer(raw, password)
		if err != nil {
			return nil, 0, err
		}
		return legacyVaultStateToBackupBundle(st), int(ver), nil

	default:
		return nil, 0, fmt.Errorf("%w: unsupported version %d", ErrCorruptedVault, ver)
	}
}

// --- Legacy v1 / v2 SNSVAULT Reader (Migration & Old Backup Import Compatibility) ---

func parseLegacyContainer(raw []byte) (ver uint16, prefix []byte, hdr *LegacyEnvelopeHeader, ciphertext []byte, err error) {
	minLen := len(vaultMagic) + 2 + 4 + 2 + chacha20poly1305.Overhead
	if len(raw) < minLen || len(raw) > maxVaultBlobBytes || string(raw[0:8]) != vaultMagic {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	ver = binary.BigEndian.Uint16(raw[8:10])
	if ver != vaultFormatVersionV2 && ver != vaultFormatVersionV1 {
		return 0, nil, nil, nil, fmt.Errorf("%w: unsupported legacy version %d", ErrCorruptedVault, ver)
	}
	hdrLen := int(binary.BigEndian.Uint32(raw[10:14]))
	if hdrLen <= 0 || hdrLen > maxHeaderBytes || 14+hdrLen >= len(raw) {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	prefix = raw[:14+hdrLen]
	ciphertext = raw[14+hdrLen:]
	if len(ciphertext) <= chacha20poly1305.Overhead {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	var parsed LegacyEnvelopeHeader
	if err := json.Unmarshal(raw[14:14+hdrLen], &parsed); err != nil {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	return ver, prefix, &parsed, ciphertext, nil
}

func legacyDekWrapAADV2(h *LegacyEnvelopeHeader) []byte {
	var buf bytes.Buffer
	buf.WriteString("SNSVAULT-v2-DEK-WRAP:")
	buf.WriteString(h.VaultID)
	buf.WriteByte(':')
	buf.WriteString(h.KDFAlgo)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFTime)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFMemoryKiB)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFThreads)
	buf.Write(h.KDFSalt)
	buf.WriteString(h.AuthAlgo)
	buf.Write(h.AuthPublicKey)
	return buf.Bytes()
}

func legacyDekWrapAADV1(h *LegacyEnvelopeHeader) []byte {
	var buf bytes.Buffer
	buf.WriteString("SNSVAULT-v1-DEK-WRAP:")
	buf.WriteString(h.KDFAlgo)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFTime)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFMemoryKiB)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFThreads)
	buf.Write(h.KDFSalt)
	return buf.Bytes()
}

func unpackLegacyPlaintext(frame []byte) (*VaultState, error) {
	if len(frame) < 4 {
		return nil, ErrCorruptedVault
	}
	compLen := int(binary.BigEndian.Uint32(frame[0:4]))
	if compLen <= 0 || 4+compLen > len(frame) {
		return nil, ErrCorruptedVault
	}
	var state VaultState
	if err := gunzipJSON(frame[4:4+compLen], &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// OpenLegacyVaultContainer decrypts a legacy v1 or v2 SNSVAULT container with its password.
func OpenLegacyVaultContainer(raw []byte, password string) (*LegacyEnvelopeHeader, *VaultState, uint16, error) {
	ver, prefix, hdr, ciphertext, err := parseLegacyContainer(raw)
	if err != nil {
		return nil, nil, 0, err
	}
	if hdr.CipherAlgo != "xchacha20-poly1305" || hdr.WrapAlgo != "aes-256-gcm" || hdr.KDFAlgo != "argon2id" || len(hdr.KDFSalt) < 16 {
		return nil, nil, 0, ErrCorruptedVault
	}
	if err := checkKDFCeiling(hdr.KDFTime, hdr.KDFMemoryKiB, hdr.KDFThreads); err != nil {
		return nil, nil, 0, err
	}

	pwBytes := []byte(password)
	master := argon2.IDKey(pwBytes, hdr.KDFSalt, hdr.KDFTime, hdr.KDFMemoryKiB, hdr.KDFThreads, dekSize)
	zeroBytes(pwBytes)
	defer zeroBytes(master)

	var kek []byte
	var wrapAAD []byte
	if ver == vaultFormatVersionV2 {
		var hErr error
		kek, hErr = hkdfDerive32(master, hdr.KDFSalt, "SNSVAULT-v2-KEK")
		if hErr != nil {
			return nil, nil, 0, ErrCorruptedVault
		}
		defer zeroBytes(kek)
		wrapAAD = legacyDekWrapAADV2(hdr)
	} else {
		kek = master
		wrapAAD = legacyDekWrapAADV1(hdr)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, 0, ErrCorruptedVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(hdr.WrappedDEKNonce) != gcm.NonceSize() {
		return nil, nil, 0, ErrCorruptedVault
	}
	dek, err := gcm.Open(nil, hdr.WrappedDEKNonce, hdr.WrappedDEK, wrapAAD)
	if err != nil || len(dek) != dekSize {
		return nil, nil, 0, ErrInvalidPassword
	}
	defer zeroBytes(dek)

	state, err := decryptLegacyPayloadWithDEK(dek, hdr, prefix, ciphertext)
	if err != nil {
		return nil, nil, 0, err
	}
	return hdr, state, ver, nil
}

// OpenLegacyVaultWithDEK decrypts a legacy v2 vault.sns using an unwrapped DEK from .vault.key.
func OpenLegacyVaultWithDEK(raw []byte, dek []byte) (*LegacyEnvelopeHeader, *VaultState, error) {
	if len(dek) != dekSize {
		return nil, nil, ErrCorruptedVault
	}
	ver, prefix, hdr, ciphertext, err := parseLegacyContainer(raw)
	if err != nil {
		return nil, nil, err
	}
	if ver != vaultFormatVersionV2 {
		return nil, nil, ErrCorruptedVault
	}
	state, err := decryptLegacyPayloadWithDEK(dek, hdr, prefix, ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return hdr, state, nil
}

func decryptLegacyPayloadWithDEK(dek []byte, hdr *LegacyEnvelopeHeader, prefix, ciphertext []byte) (*VaultState, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil || len(hdr.PayloadNonce) != aead.NonceSize() {
		return nil, ErrCorruptedVault
	}
	frame, err := aead.Open(nil, hdr.PayloadNonce, ciphertext, prefix)
	if err != nil {
		return nil, ErrCorruptedVault
	}
	defer zeroBytes(frame)
	return unpackLegacyPlaintext(frame)
}

func legacyVaultStateToBackupBundle(st *VaultState) *BackupBundle {
	if st == nil {
		st = DefaultVaultState()
	}
	ensureMonitorInitialized(st)
	EnsureStateDefaults(st)

	monRT := DefaultMonitorRuntimeState()
	if st.Monitor != nil {
		monRT.LatestSnapshots = st.Monitor.LatestSnapshots
		monRT.HistoryByServer = st.Monitor.HistoryByServer
		monRT.Alerts = st.Monitor.Alerts
		monRT.BreachStreaks = st.Monitor.BreachStreaks
		monRT.PortBaselines = st.Monitor.PortBaselines
	}
	for _, srv := range st.Servers {
		if srv.LastConnectedAt != nil || srv.LastLatencyMs > 0 || srv.LastOSInfo != "" {
			monRT.ServerRuntime[srv.ID] = ServerRuntimeMeta{
				LastConnectedAt: srv.LastConnectedAt,
				LastLatencyMs:   srv.LastLatencyMs,
				LastOSInfo:      srv.LastOSInfo,
			}
		}
	}

	return &BackupBundle{
		SchemaVersion:  3,
		IncludeRuntime: true,
		ExportedAt:     time.Now().UTC(),
		Config: CoreConfigSnapshot{
			VaultID:         st.VaultID,
			Revision:        st.Revision,
			Groups:          st.Groups,
			Servers:         st.Servers,
			Credentials:     st.Credentials,
			Snippets:        st.Snippets,
			KnownHosts:      st.KnownHosts,
			Settings:        st.Settings,
			MonitorSettings: st.Monitor.Settings,
			MonitorRules:    st.Monitor.Rules,
			AISettings:      st.AISettings,
		},
		AIKnowledge: AIKnowledgeSnapshot{
			HostMemories: st.HostMemories,
			AIMemories:   st.AIMemories,
			Runbooks:     st.Runbooks,
		},
		Runtime: &RuntimeDataSnapshot{
			Monitor:         monRT,
			AISessions:      st.AISessions,
			PatrolBaselines: st.PatrolBaselines,
			PatrolRecords:   st.PatrolRecords,
			AuditLogs:       st.AuditLogs,
		},
	}
}
