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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	vaultMagic                = "SNSVAULT"
	vaultFormatVersionV1      = uint16(1)
	vaultFormatVersion        = uint16(2)
	DefaultKDFTime            = uint32(3)
	DefaultKDFMemoryKiB       = uint32(64 * 1024) // 64 MiB Argon2id memory-hard cost
	DefaultKDFThreads         = uint8(4)
	MinAllowedKDFMemoryKiB    = uint32(16 * 1024) // 16 MiB strict floor to block server KDF downgrade attacks
	kdfSaltSize               = 32
	dekSize                   = 32
	paddingBlockSize          = 4096
	maxHeaderBytes            = 64 * 1024
	maxVaultBlobBytes         = 64 * 1024 * 1024
)

var (
	ErrInvalidPassword   = errors.New("管理员密码错误或加密容器认证失败")
	ErrCorruptedVault    = errors.New("加密数据文件格式损坏或遭到篡改")
	ErrVaultLocked       = errors.New("应用加密保险库处于锁定状态，请先验证管理员密码")
	ErrVaultNotInit      = errors.New("尚未初始化管理员密码与加密保险库")
	ErrVaultAlreadyInit  = errors.New("加密保险库已初始化")
	ErrWeakPassword      = errors.New("管理员密码长度至少需要 8 位字符")
	ErrRevisionConflict  = errors.New("加密保险库版本冲突，检测到并发修改")
	ErrRollbackDetected  = errors.New("安全警报：检测到服务端加密数据包版本回滚或替换篡改")
	ErrInvalidSignature  = errors.New("零知识密码学签名验证失败")
	ErrKDFDowngrade      = errors.New("安全警报：服务端返回的密钥派生参数低于安全下限，已阻断降级攻击")
)

// EnvelopeHeader contains ONLY public cryptographic key-derivation, zero-knowledge Ed25519
// verification public key, anti-rollback revision, and AEAD nonce parameters.
// Zero application metadata, server IPs, usernames, or user secrets exist in this header.
type EnvelopeHeader struct {
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

// PublicKDFParams contains ONLY the non-oracle KDF salt and cost parameters needed by a client
// to derive its zero-knowledge Ed25519 authentication key during login challenge-response.
// Notice AuthPublicKey and WrappedDEK are intentionally omitted so unauthenticated network callers
// obtain zero offline password-verification oracle.
type PublicKDFParams struct {
	VaultID      string `json:"vault_id"`
	Revision     uint64 `json:"revision"`
	KDFAlgo      string `json:"kdf_algo"`
	KDFTime      uint32 `json:"kdf_time"`
	KDFMemoryKiB uint32 `json:"kdf_memory_kib"`
	KDFThreads   uint8  `json:"kdf_threads"`
	KDFSalt      []byte `json:"kdf_salt"`
}

// EncryptionInfo exposes safe read-only cryptographic parameters for the Security Center UI.
type EncryptionInfo struct {
	FormatVersion     int    `json:"format_version"`
	VaultID           string `json:"vault_id,omitempty"`
	Revision          uint64 `json:"revision,omitempty"`
	KDFAlgo           string `json:"kdf_algo"`
	KDFTime           uint32 `json:"kdf_time"`
	KDFMemoryKiB      uint32 `json:"kdf_memory_kib"`
	KDFThreads        uint8  `json:"kdf_threads"`
	WrapAlgo          string `json:"wrap_algo"`
	CipherAlgo        string `json:"cipher_algo"`
	AuthAlgo          string `json:"auth_algo"`
	AuthPubKeySHA256  string `json:"auth_pubkey_sha256,omitempty"`
	VaultSizeBytes    int64  `json:"vault_size_bytes"`
	ZeroKnowledge     bool   `json:"zero_knowledge"`
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

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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

// DeriveVaultKeys runs memory-hard Argon2id followed by domain-separated HKDF-SHA256
// to produce two cryptographically independent keys:
//  1. kek (32B): wraps/unwraps the random 256-bit DEK exclusively on the client.
//  2. authPriv / authPub (Ed25519): proves admin password knowledge via zero-knowledge signatures
//     without ever revealing password, master secret, kek, or dek to the server.
func DeriveVaultKeys(
	password string,
	salt []byte,
	kdfTime uint32,
	kdfMemoryKiB uint32,
	kdfThreads uint8,
	minMemoryKiB uint32,
) (kek []byte, authPriv ed25519.PrivateKey, authPub ed25519.PublicKey, err error) {
	if minMemoryKiB == 0 {
		minMemoryKiB = MinAllowedKDFMemoryKiB
	}
	if len(salt) < kdfSaltSize || kdfTime < 1 || kdfThreads < 1 {
		return nil, nil, nil, ErrCorruptedVault
	}
	if kdfMemoryKiB < minMemoryKiB {
		return nil, nil, nil, ErrKDFDowngrade
	}

	pwBytes := []byte(password)
	master := argon2.IDKey(pwBytes, salt, kdfTime, kdfMemoryKiB, kdfThreads, dekSize)
	zeroBytes(pwBytes)
	defer zeroBytes(master)

	kek, err = hkdfDerive32(master, salt, "SNSVAULT-v2-KEK")
	if err != nil {
		return nil, nil, nil, err
	}

	authSeed, err := hkdfDerive32(master, salt, "SNSVAULT-v2-AUTH-ED25519")
	if err != nil {
		zeroBytes(kek)
		return nil, nil, nil, err
	}
	defer zeroBytes(authSeed)

	authPriv = ed25519.NewKeyFromSeed(authSeed)
	authPub = slices.Clone(authPriv.Public().(ed25519.PublicKey))
	return kek, authPriv, authPub, nil
}

// legacy v1 KEK derivation for seamless v1 backup import & upgrade
func deriveLegacyV1KEK(password string, h *EnvelopeHeader) ([]byte, error) {
	if h.KDFAlgo != "argon2id" || len(h.KDFSalt) < 16 || h.KDFTime < 1 || h.KDFMemoryKiB < 8192 || h.KDFThreads < 1 {
		return nil, ErrCorruptedVault
	}
	pwBytes := []byte(password)
	defer zeroBytes(pwBytes)
	return argon2.IDKey(pwBytes, h.KDFSalt, h.KDFTime, h.KDFMemoryKiB, h.KDFThreads, dekSize), nil
}

func dekWrapAADV2(h *EnvelopeHeader) []byte {
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

func dekWrapAADV1(h *EnvelopeHeader) []byte {
	var buf bytes.Buffer
	buf.WriteString("SNSVAULT-v1-DEK-WRAP:")
	buf.WriteString(h.KDFAlgo)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFTime)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFMemoryKiB)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFThreads)
	buf.Write(h.KDFSalt)
	return buf.Bytes()
}

func wrapDEKV2(kek, dek []byte, h *EnvelopeHeader) error {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return err
	}
	h.WrapAlgo = "aes-256-gcm"
	h.WrappedDEKNonce = nonce
	h.WrappedDEK = gcm.Seal(nil, nonce, dek, dekWrapAADV2(h))
	return nil
}

func unwrapDEKV2(password string, h *EnvelopeHeader, minMemoryKiB uint32) ([]byte, ed25519.PrivateKey, error) {
	if h.WrapAlgo != "aes-256-gcm" || h.KDFAlgo != "argon2id" || h.AuthAlgo != "ed25519" || len(h.AuthPublicKey) != ed25519.PublicKeySize {
		return nil, nil, ErrCorruptedVault
	}
	kek, authPriv, authPub, err := DeriveVaultKeys(password, h.KDFSalt, h.KDFTime, h.KDFMemoryKiB, h.KDFThreads, minMemoryKiB)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(kek)

	if !constantTimeEqual(authPub, h.AuthPublicKey) {
		zeroBytes(authPriv)
		return nil, nil, ErrInvalidPassword
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		zeroBytes(authPriv)
		return nil, nil, ErrCorruptedVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(authPriv)
		return nil, nil, ErrCorruptedVault
	}
	if len(h.WrappedDEKNonce) != gcm.NonceSize() {
		zeroBytes(authPriv)
		return nil, nil, ErrCorruptedVault
	}
	dek, err := gcm.Open(nil, h.WrappedDEKNonce, h.WrappedDEK, dekWrapAADV2(h))
	if err != nil {
		zeroBytes(authPriv)
		return nil, nil, ErrInvalidPassword
	}
	if len(dek) != dekSize {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return nil, nil, ErrCorruptedVault
	}
	return dek, authPriv, nil
}

func unwrapDEKV1(password string, h *EnvelopeHeader) ([]byte, error) {
	if h.WrapAlgo != "aes-256-gcm" {
		return nil, ErrCorruptedVault
	}
	kek, err := deriveLegacyV1KEK(password, h)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrCorruptedVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCorruptedVault
	}
	if len(h.WrappedDEKNonce) != gcm.NonceSize() {
		return nil, ErrCorruptedVault
	}
	dek, err := gcm.Open(nil, h.WrappedDEKNonce, h.WrappedDEK, dekWrapAADV1(h))
	if err != nil {
		return nil, ErrInvalidPassword
	}
	if len(dek) != dekSize {
		zeroBytes(dek)
		return nil, ErrCorruptedVault
	}
	return dek, nil
}

// packPlaintext compresses JSON state and pads it to 4 KiB blocks with CSPRNG bytes
// to eliminate exact-size side-channel leakage on disk and over HTTP transfers.
func packPlaintext(state *VaultState) ([]byte, error) {
	rawJSON, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(rawJSON)

	var gzBuf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&gzBuf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := gzWriter.Write(rawJSON); err != nil {
		_ = gzWriter.Close()
		return nil, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, err
	}
	compressed := gzBuf.Bytes()
	compLen := len(compressed)

	totalUnaligned := 4 + compLen
	rem := totalUnaligned % paddingBlockSize
	padLen := 0
	if rem != 0 {
		padLen = paddingBlockSize - rem
	}
	frame := make([]byte, totalUnaligned+padLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(compLen))
	copy(frame[4:4+compLen], compressed)
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, frame[4+compLen:]); err != nil {
			zeroBytes(frame)
			return nil, err
		}
	}
	return frame, nil
}

func unpackPlaintext(frame []byte) (*VaultState, error) {
	if len(frame) < 4 {
		return nil, ErrCorruptedVault
	}
	compLen := int(binary.BigEndian.Uint32(frame[0:4]))
	if compLen <= 0 || 4+compLen > len(frame) {
		return nil, ErrCorruptedVault
	}
	gzReader, err := gzip.NewReader(bytes.NewReader(frame[4 : 4+compLen]))
	if err != nil {
		return nil, ErrCorruptedVault
	}
	defer gzReader.Close()

	rawJSON, err := io.ReadAll(io.LimitReader(gzReader, 256*1024*1024))
	if err != nil {
		return nil, ErrCorruptedVault
	}
	defer zeroBytes(rawJSON)

	var state VaultState
	if err := json.Unmarshal(rawJSON, &state); err != nil {
		return nil, ErrCorruptedVault
	}
	return &state, nil
}

// SealVaultContainer creates a full authenticated SNSVAULT v2 binary container with a fresh 24-byte XChaCha20-Poly1305 nonce.
func SealVaultContainer(dek []byte, baseHeader *EnvelopeHeader, state *VaultState) ([]byte, *EnvelopeHeader, error) {
	if baseHeader.VaultID == "" {
		baseHeader.VaultID = uuid.NewString()
	}
	if baseHeader.Revision == 0 {
		baseHeader.Revision = 1
	}
	state.SchemaVersion = 2
	state.VaultID = baseHeader.VaultID
	state.Revision = baseHeader.Revision

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, err
	}
	payloadNonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}

	hdr := *baseHeader
	hdr.KDFSalt = slices.Clone(baseHeader.KDFSalt)
	hdr.AuthPublicKey = slices.Clone(baseHeader.AuthPublicKey)
	hdr.WrappedDEKNonce = slices.Clone(baseHeader.WrappedDEKNonce)
	hdr.WrappedDEK = slices.Clone(baseHeader.WrappedDEK)
	hdr.CipherAlgo = "xchacha20-poly1305"
	hdr.PayloadNonce = payloadNonce

	hdrBytes, err := json.Marshal(&hdr)
	if err != nil {
		return nil, nil, err
	}

	// Prefix = magic(8) + version(2) + hdrLen(4) + hdrBytes
	prefixLen := len(vaultMagic) + 2 + 4 + len(hdrBytes)
	prefix := make([]byte, prefixLen)
	copy(prefix[0:8], vaultMagic)
	binary.BigEndian.PutUint16(prefix[8:10], vaultFormatVersion)
	binary.BigEndian.PutUint32(prefix[10:14], uint32(len(hdrBytes)))
	copy(prefix[14:], hdrBytes)

	plaintextFrame, err := packPlaintext(state)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(plaintextFrame)

	// Seal payload using full prefix as AAD so any header or revision tampering invalidates Poly1305 tag
	ciphertext := aead.Seal(nil, payloadNonce, plaintextFrame, prefix)

	out := make([]byte, len(prefix)+len(ciphertext))
	copy(out, prefix)
	copy(out[len(prefix):], ciphertext)
	return out, &hdr, nil
}

// ParseVaultContainer extracts the format version, prefix bytes (AAD), parsed EnvelopeHeader, and ciphertext slice.
func ParseVaultContainer(raw []byte) (ver uint16, prefix []byte, hdr *EnvelopeHeader, ciphertext []byte, err error) {
	minLen := len(vaultMagic) + 2 + 4 + 2 + chacha20poly1305.Overhead
	if len(raw) < minLen || len(raw) > maxVaultBlobBytes {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	if string(raw[0:8]) != vaultMagic {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	ver = binary.BigEndian.Uint16(raw[8:10])
	if ver != vaultFormatVersion && ver != vaultFormatVersionV1 {
		return 0, nil, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptedVault, ver)
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

	var parsed EnvelopeHeader
	if err := json.Unmarshal(raw[14:14+hdrLen], &parsed); err != nil {
		return 0, nil, nil, nil, ErrCorruptedVault
	}
	return ver, prefix, &parsed, ciphertext, nil
}

// ValidateV2HeaderStructural checks that an EnvelopeHeader has well-formed v2 cryptographic parameters
// without requiring or possessing any secret key (used by BlindStore on the untrusted server).
func ValidateV2HeaderStructural(ver uint16, h *EnvelopeHeader) error {
	if ver != vaultFormatVersion || h == nil {
		return ErrCorruptedVault
	}
	if h.VaultID == "" || h.Revision < 1 {
		return ErrCorruptedVault
	}
	if h.KDFAlgo != "argon2id" || len(h.KDFSalt) != kdfSaltSize || h.KDFTime < 1 || h.KDFMemoryKiB < MinAllowedKDFMemoryKiB || h.KDFThreads < 1 {
		return ErrCorruptedVault
	}
	if h.AuthAlgo != "ed25519" || len(h.AuthPublicKey) != ed25519.PublicKeySize {
		return ErrCorruptedVault
	}
	if h.WrapAlgo != "aes-256-gcm" || len(h.WrappedDEKNonce) != 12 || len(h.WrappedDEK) != dekSize+16 {
		return ErrCorruptedVault
	}
	if h.CipherAlgo != "xchacha20-poly1305" || len(h.PayloadNonce) != chacha20poly1305.NonceSizeX {
		return ErrCorruptedVault
	}
	return nil
}

// OpenVaultContainer verifies password, derives keys, unwraps DEK, and authenticates + decrypts VaultState.
// Supports both v2 zero-knowledge containers and v1 legacy backup containers for seamless migration.
func OpenVaultContainer(raw []byte, password string, minMemoryKiB uint32) (
	dek []byte,
	authPriv ed25519.PrivateKey,
	hdr *EnvelopeHeader,
	state *VaultState,
	ver uint16,
	err error,
) {
	ver, prefix, hdr, ciphertext, err := ParseVaultContainer(raw)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	if hdr.CipherAlgo != "xchacha20-poly1305" {
		return nil, nil, nil, nil, 0, ErrCorruptedVault
	}

	if ver == vaultFormatVersion {
		if err := ValidateV2HeaderStructural(ver, hdr); err != nil {
			return nil, nil, nil, nil, 0, err
		}
		dek, authPriv, err = unwrapDEKV2(password, hdr, minMemoryKiB)
		if err != nil {
			return nil, nil, nil, nil, 0, err
		}
	} else {
		dek, err = unwrapDEKV1(password, hdr)
		if err != nil {
			return nil, nil, nil, nil, 0, err
		}
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return nil, nil, nil, nil, 0, ErrCorruptedVault
	}
	if len(hdr.PayloadNonce) != aead.NonceSize() {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return nil, nil, nil, nil, 0, ErrCorruptedVault
	}

	frame, err := aead.Open(nil, hdr.PayloadNonce, ciphertext, prefix)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return nil, nil, nil, nil, 0, ErrCorruptedVault
	}
	defer zeroBytes(frame)

	state, err = unpackPlaintext(frame)
	if err != nil {
		zeroBytes(dek)
		zeroBytes(authPriv)
		return nil, nil, nil, nil, 0, err
	}

	if ver == vaultFormatVersion {
		if state.VaultID != hdr.VaultID || state.Revision != hdr.Revision {
			zeroBytes(dek)
			zeroBytes(authPriv)
			return nil, nil, nil, nil, 0, ErrCorruptedVault
		}
	}
	return dek, authPriv, hdr, state, ver, nil
}

// OpenVaultWithKnownDEK authenticates and decrypts a v2 container using an already-unwrapped client DEK
// and verifies that the header's VaultID and AuthPublicKey match the client's pinned session keys.
func OpenVaultWithKnownDEK(raw []byte, dek []byte, expectedVaultID string, expectedAuthPub []byte) (*EnvelopeHeader, *VaultState, error) {
	ver, prefix, hdr, ciphertext, err := ParseVaultContainer(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateV2HeaderStructural(ver, hdr); err != nil {
		return nil, nil, err
	}
	if hdr.VaultID != expectedVaultID || !constantTimeEqual(hdr.AuthPublicKey, expectedAuthPub) {
		return nil, nil, ErrRollbackDetected
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, ErrCorruptedVault
	}
	frame, err := aead.Open(nil, hdr.PayloadNonce, ciphertext, prefix)
	if err != nil {
		return nil, nil, ErrCorruptedVault
	}
	defer zeroBytes(frame)

	state, err := unpackPlaintext(frame)
	if err != nil {
		return nil, nil, err
	}
	if state.VaultID != hdr.VaultID || state.Revision != hdr.Revision {
		return nil, nil, ErrCorruptedVault
	}
	return hdr, state, nil
}

// OpenVaultContainerPreDerived unwraps DEK and decrypts a v2 container using KEK + AuthKeyPair already derived
// during the zero-knowledge login challenge step, avoiding a redundant second 64 MiB Argon2id pass.
func OpenVaultContainerPreDerived(raw []byte, kek []byte, authPub []byte, expectedKDF *PublicKDFParams) ([]byte, *EnvelopeHeader, *VaultState, error) {
	ver, prefix, hdr, ciphertext, err := ParseVaultContainer(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := ValidateV2HeaderStructural(ver, hdr); err != nil {
		return nil, nil, nil, err
	}
	if expectedKDF != nil {
		if hdr.VaultID != expectedKDF.VaultID ||
			hdr.KDFTime != expectedKDF.KDFTime ||
			hdr.KDFMemoryKiB != expectedKDF.KDFMemoryKiB ||
			hdr.KDFThreads != expectedKDF.KDFThreads ||
			!constantTimeEqual(hdr.KDFSalt, expectedKDF.KDFSalt) {
			return nil, nil, nil, ErrRollbackDetected
		}
	}
	if !constantTimeEqual(hdr.AuthPublicKey, authPub) {
		return nil, nil, nil, ErrInvalidPassword
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, nil, ErrCorruptedVault
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, ErrCorruptedVault
	}
	dek, err := gcm.Open(nil, hdr.WrappedDEKNonce, hdr.WrappedDEK, dekWrapAADV2(hdr))
	if err != nil {
		return nil, nil, nil, ErrInvalidPassword
	}
	if len(dek) != dekSize {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}
	frame, err := aead.Open(nil, hdr.PayloadNonce, ciphertext, prefix)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}
	defer zeroBytes(frame)

	state, err := unpackPlaintext(frame)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, err
	}
	if state.VaultID != hdr.VaultID || state.Revision != hdr.Revision {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}
	return dek, hdr, state, nil
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// --- Domain-Separated Zero-Knowledge Ed25519 Request Signing & Verification ---

func msgSetup(vaultID string, revision uint64, rawBlob []byte) []byte {
	return []byte("SNS-ZK-SETUP-v2:" + vaultID + ":" + strconv.FormatUint(revision, 10) + ":" + sha256Hex(rawBlob))
}

func SignSetup(authPriv ed25519.PrivateKey, vaultID string, revision uint64, rawBlob []byte) []byte {
	return ed25519.Sign(authPriv, msgSetup(vaultID, revision, rawBlob))
}

func VerifySetup(authPub ed25519.PublicKey, vaultID string, revision uint64, rawBlob, sig []byte) bool {
	return len(authPub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(authPub, msgSetup(vaultID, revision, rawBlob), sig)
}

func msgAuthChallenge(challengeID, nonceHex, vaultID string) []byte {
	return []byte("SNS-ZK-AUTH-v2:" + challengeID + ":" + nonceHex + ":" + vaultID)
}

func SignAuthChallenge(authPriv ed25519.PrivateKey, challengeID, nonceHex, vaultID string) []byte {
	return ed25519.Sign(authPriv, msgAuthChallenge(challengeID, nonceHex, vaultID))
}

func VerifyAuthChallenge(authPub ed25519.PublicKey, challengeID, nonceHex, vaultID string, sig []byte) bool {
	return len(authPub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(authPub, msgAuthChallenge(challengeID, nonceHex, vaultID), sig)
}

func msgVaultPut(vaultID string, prevRev, newRev uint64, rawBlob []byte) []byte {
	return []byte("SNS-ZK-PUT-v2:" + vaultID + ":" + strconv.FormatUint(prevRev, 10) + "->" + strconv.FormatUint(newRev, 10) + ":" + sha256Hex(rawBlob))
}

func SignVaultPut(authPriv ed25519.PrivateKey, vaultID string, prevRev, newRev uint64, rawBlob []byte) []byte {
	return ed25519.Sign(authPriv, msgVaultPut(vaultID, prevRev, newRev, rawBlob))
}

func VerifyVaultPut(authPub ed25519.PublicKey, vaultID string, prevRev, newRev uint64, rawBlob, sig []byte) bool {
	return len(authPub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(authPub, msgVaultPut(vaultID, prevRev, newRev, rawBlob), sig)
}

func msgRotateOld(vaultID string, prevRev, newRev uint64, newAuthPub, rawBlob []byte) []byte {
	return []byte("SNS-ZK-ROTATE-OLD-v2:" + vaultID + ":" + strconv.FormatUint(prevRev, 10) + "->" + strconv.FormatUint(newRev, 10) + ":" + hex.EncodeToString(newAuthPub) + ":" + sha256Hex(rawBlob))
}

func msgRotateNew(vaultID string, prevRev, newRev uint64, oldAuthPub, rawBlob []byte) []byte {
	return []byte("SNS-ZK-ROTATE-NEW-v2:" + vaultID + ":" + strconv.FormatUint(prevRev, 10) + "->" + strconv.FormatUint(newRev, 10) + ":" + hex.EncodeToString(oldAuthPub) + ":" + sha256Hex(rawBlob))
}

func SignPasswordRotate(oldPriv, newPriv ed25519.PrivateKey, vaultID string, prevRev, newRev uint64, oldPub, newPub, rawBlob []byte) (oldSig, newSig []byte) {
	oldSig = ed25519.Sign(oldPriv, msgRotateOld(vaultID, prevRev, newRev, newPub, rawBlob))
	newSig = ed25519.Sign(newPriv, msgRotateNew(vaultID, prevRev, newRev, oldPub, rawBlob))
	return oldSig, newSig
}

func VerifyPasswordRotate(oldPub, newPub ed25519.PublicKey, vaultID string, prevRev, newRev uint64, rawBlob, oldSig, newSig []byte) bool {
	if len(oldPub) != ed25519.PublicKeySize || len(newPub) != ed25519.PublicKeySize {
		return false
	}
	if len(oldSig) != ed25519.SignatureSize || len(newSig) != ed25519.SignatureSize {
		return false
	}
	okOld := ed25519.Verify(oldPub, msgRotateOld(vaultID, prevRev, newRev, newPub, rawBlob), oldSig)
	okNew := ed25519.Verify(newPub, msgRotateNew(vaultID, prevRev, newRev, oldPub, rawBlob), newSig)
	return okOld && okNew
}

func msgImportNew(newVaultID string, newRev uint64, rawBlob []byte) []byte {
	return []byte("SNS-ZK-IMPORT-NEW-v2:" + newVaultID + ":" + strconv.FormatUint(newRev, 10) + ":" + sha256Hex(rawBlob))
}

func msgImportOverwrite(oldVaultID, newVaultID string, rawBlob []byte) []byte {
	return []byte("SNS-ZK-IMPORT-OVERWRITE-v2:" + oldVaultID + "->" + newVaultID + ":" + sha256Hex(rawBlob))
}

func SignVaultImport(newPriv ed25519.PrivateKey, newVaultID string, newRev uint64, rawBlob []byte) []byte {
	return ed25519.Sign(newPriv, msgImportNew(newVaultID, newRev, rawBlob))
}

func SignVaultImportOverwrite(currentPriv ed25519.PrivateKey, oldVaultID, newVaultID string, rawBlob []byte) []byte {
	return ed25519.Sign(currentPriv, msgImportOverwrite(oldVaultID, newVaultID, rawBlob))
}

func VerifyVaultImportNew(newPub ed25519.PublicKey, newVaultID string, newRev uint64, rawBlob, sig []byte) bool {
	return len(newPub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(newPub, msgImportNew(newVaultID, newRev, rawBlob), sig)
}

func VerifyVaultImportOverwrite(oldPub ed25519.PublicKey, oldVaultID, newVaultID string, rawBlob, sig []byte) bool {
	return len(oldPub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(oldPub, msgImportOverwrite(oldVaultID, newVaultID, rawBlob), sig)
}
