package vault

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vaultMagic          = "SNSVAULT"
	vaultFormatVersion  = uint16(1)
	defaultKDFTime      = uint32(3)
	defaultKDFMemoryKiB = uint32(64 * 1024) // 64 MiB Argon2id memory-hard cost
	defaultKDFThreads   = uint8(4)
	kdfSaltSize         = 32
	dekSize             = 32
	paddingBlockSize    = 4096
	maxHeaderBytes      = 64 * 1024
)

var (
	ErrInvalidPassword  = errors.New("管理员密码错误或加密容器认证失败")
	ErrCorruptedVault   = errors.New("加密数据文件格式损坏或遭到篡改")
	ErrVaultLocked      = errors.New("应用加密保险库处于锁定状态，请先验证管理员密码")
	ErrVaultNotInit     = errors.New("尚未初始化管理员密码与加密保险库")
	ErrVaultAlreadyInit = errors.New("加密保险库已初始化")
	ErrWeakPassword     = errors.New("管理员密码长度至少需要 8 位字符")
)

// EnvelopeHeader contains ONLY cryptographic key-derivation & AEAD parameters.
// Zero application metadata or user data is stored in this header.
type EnvelopeHeader struct {
	KDFAlgo         string `json:"kdf_algo"`
	KDFTime         uint32 `json:"kdf_time"`
	KDFMemoryKiB    uint32 `json:"kdf_memory_kib"`
	KDFThreads      uint8  `json:"kdf_threads"`
	KDFSalt         []byte `json:"kdf_salt"`
	WrapAlgo        string `json:"wrap_algo"`
	WrappedDEKNonce []byte `json:"wrapped_dek_nonce"`
	WrappedDEK      []byte `json:"wrapped_dek"`
	CipherAlgo      string `json:"cipher_algo"`
	PayloadNonce    []byte `json:"payload_nonce"`
}

// EncryptionInfo exposes safe read-only cryptographic parameters for the Security Center UI.
type EncryptionInfo struct {
	FormatVersion int    `json:"format_version"`
	KDFAlgo       string `json:"kdf_algo"`
	KDFTime       uint32 `json:"kdf_time"`
	KDFMemoryKiB  uint32 `json:"kdf_memory_kib"`
	KDFThreads    uint8  `json:"kdf_threads"`
	WrapAlgo      string `json:"wrap_algo"`
	CipherAlgo    string `json:"cipher_algo"`
	VaultSizeBytes int64 `json:"vault_size_bytes"`
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto/rand failure: %w", err)
	}
	return b, nil
}

func deriveKEK(password string, h *EnvelopeHeader) ([]byte, error) {
	if h.KDFAlgo != "argon2id" || len(h.KDFSalt) < 16 || h.KDFTime < 1 || h.KDFMemoryKiB < 8192 || h.KDFThreads < 1 {
		return nil, ErrCorruptedVault
	}
	kek := argon2.IDKey([]byte(password), h.KDFSalt, h.KDFTime, h.KDFMemoryKiB, h.KDFThreads, dekSize)
	return kek, nil
}

func dekWrapAAD(h *EnvelopeHeader) []byte {
	var buf bytes.Buffer
	buf.WriteString("SNSVAULT-v1-DEK-WRAP:")
	buf.WriteString(h.KDFAlgo)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFTime)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFMemoryKiB)
	_ = binary.Write(&buf, binary.BigEndian, h.KDFThreads)
	buf.Write(h.KDFSalt)
	return buf.Bytes()
}

func wrapDEK(kek, dek []byte, h *EnvelopeHeader) error {
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
	h.WrappedDEK = gcm.Seal(nil, nonce, dek, dekWrapAAD(h))
	return nil
}

func unwrapDEK(password string, h *EnvelopeHeader) ([]byte, error) {
	if h.WrapAlgo != "aes-256-gcm" {
		return nil, ErrCorruptedVault
	}
	kek, err := deriveKEK(password, h)
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
	dek, err := gcm.Open(nil, h.WrappedDEKNonce, h.WrappedDEK, dekWrapAAD(h))
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
// to eliminate exact-size side-channel leakage on disk.
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

	// Frame: [4-byte uint32 compressed length][compressed bytes][random padding to 4096-byte multiple]
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

// sealVaultContainer creates a full authenticated SNSVAULT binary container with a fresh 24-byte XChaCha20-Poly1305 nonce.
func sealVaultContainer(dek []byte, baseHeader *EnvelopeHeader, state *VaultState) ([]byte, *EnvelopeHeader, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, err
	}
	payloadNonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}

	hdr := *baseHeader
	hdr.CipherAlgo = "xchacha20-poly1305"
	hdr.PayloadNonce = payloadNonce

	hdrBytes, err := json.Marshal(&hdr)
	if err != nil {
		return nil, nil, err
	}

	// Build prefix = magic(8) + version(2) + hdrLen(4) + hdrBytes
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

	// Seal payload using prefix as AAD so any header modification invalidates Poly1305 tag
	ciphertext := aead.Seal(nil, payloadNonce, plaintextFrame, prefix)

	out := make([]byte, len(prefix)+len(ciphertext))
	copy(out, prefix)
	copy(out[len(prefix):], ciphertext)
	return out, &hdr, nil
}

// parseVaultHeader extracts the prefix bytes (AAD), parsed EnvelopeHeader, and ciphertext slice.
func parseVaultContainer(raw []byte) (prefix []byte, hdr *EnvelopeHeader, ciphertext []byte, err error) {
	minLen := len(vaultMagic) + 2 + 4 + 2 + chacha20poly1305.Overhead
	if len(raw) < minLen {
		return nil, nil, nil, ErrCorruptedVault
	}
	if string(raw[0:8]) != vaultMagic {
		return nil, nil, nil, ErrCorruptedVault
	}
	ver := binary.BigEndian.Uint16(raw[8:10])
	if ver != vaultFormatVersion {
		return nil, nil, nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptedVault, ver)
	}
	hdrLen := int(binary.BigEndian.Uint32(raw[10:14]))
	if hdrLen <= 0 || hdrLen > maxHeaderBytes || 14+hdrLen >= len(raw) {
		return nil, nil, nil, ErrCorruptedVault
	}
	prefix = raw[:14+hdrLen]
	ciphertext = raw[14+hdrLen:]

	var parsed EnvelopeHeader
	if err := json.Unmarshal(raw[14:14+hdrLen], &parsed); err != nil {
		return nil, nil, nil, ErrCorruptedVault
	}
	return prefix, &parsed, ciphertext, nil
}

// openVaultContainer verifies password, unwraps DEK, and authenticates + decrypts the full VaultState.
func openVaultContainer(raw []byte, password string) (dek []byte, hdr *EnvelopeHeader, state *VaultState, err error) {
	prefix, hdr, ciphertext, err := parseVaultContainer(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if hdr.CipherAlgo != "xchacha20-poly1305" {
		return nil, nil, nil, ErrCorruptedVault
	}

	dek, err = unwrapDEK(password, hdr)
	if err != nil {
		return nil, nil, nil, err
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}
	if len(hdr.PayloadNonce) != aead.NonceSize() {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}

	frame, err := aead.Open(nil, hdr.PayloadNonce, ciphertext, prefix)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, ErrCorruptedVault
	}
	defer zeroBytes(frame)

	state, err = unpackPlaintext(frame)
	if err != nil {
		zeroBytes(dek)
		return nil, nil, nil, err
	}
	return dek, hdr, state, nil
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
