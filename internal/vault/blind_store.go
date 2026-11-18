package vault

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// BlindStore manages atomic persistence and Ed25519 signature verification of opaque SNSVAULT v2
// ciphertext blobs on the server.
//
// SECURITY INVARIANT:
// BlindStore NEVER receives Admin Passwords, NEVER holds DEK/KEK/AuthPrivateKey, and NEVER
// parses or holds plaintext VaultState in memory or on disk. Even if the host OS root account
// is compromised and full server RAM + disk are dumped, zero application data can be obtained.
type BlindStore struct {
	mu       sync.RWMutex
	filePath string
	header   *EnvelopeHeader
	fileSize int64
}

// NewBlindStore creates a zero-knowledge BlindStore backed by vaultFilePath (e.g. /data/vault.sns).
func NewBlindStore(vaultFilePath string) (*BlindStore, error) {
	dir := filepath.Dir(vaultFilePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	bs := &BlindStore{
		filePath: vaultFilePath,
	}
	if err := bs.reloadHeaderFromDiskLocked(); err != nil {
		return nil, err
	}
	return bs, nil
}

func (b *BlindStore) reloadHeaderFromDiskLocked() error {
	info, err := os.Stat(b.filePath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		b.header = nil
		b.fileSize = 0
		return nil
	}
	raw, err := os.ReadFile(b.filePath)
	if err != nil {
		return fmt.Errorf("read vault container: %w", err)
	}
	ver, _, hdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return err
	}
	if err := ValidateV2HeaderStructural(ver, hdr); err != nil {
		return err
	}
	b.header = hdr
	b.fileSize = int64(len(raw))
	return nil
}

// FilePath returns the encrypted vault file path on disk.
func (b *BlindStore) FilePath() string {
	return b.filePath
}

// IsInitialized returns true when a valid SNSVAULT v2 ciphertext container exists on disk.
func (b *BlindStore) IsInitialized() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.header != nil
}

// PublicChallengeParams returns ONLY the public KDF salt and cost parameters needed for
// client-side zero-knowledge Ed25519 challenge-response login.
// AuthPublicKey and WrappedDEK are NOT exposed here so unauthenticated callers gain zero offline oracle.
func (b *BlindStore) PublicChallengeParams() (*PublicKDFParams, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.header == nil {
		return nil, ErrVaultNotInit
	}
	return &PublicKDFParams{
		VaultID:      b.header.VaultID,
		Revision:     b.header.Revision,
		KDFAlgo:      b.header.KDFAlgo,
		KDFTime:      b.header.KDFTime,
		KDFMemoryKiB: b.header.KDFMemoryKiB,
		KDFThreads:   b.header.KDFThreads,
		KDFSalt:      slices.Clone(b.header.KDFSalt),
	}, nil
}

// EncryptionInfo returns safe read-only cryptographic metadata.
// When includeAuthFingerprint is false (unauthenticated status check), AuthPubKeySHA256 is omitted.
func (b *BlindStore) EncryptionInfo(includeAuthFingerprint bool) *EncryptionInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.header == nil {
		return &EncryptionInfo{
			FormatVersion: int(vaultFormatVersion),
			KDFAlgo:       "argon2id",
			KDFTime:       DefaultKDFTime,
			KDFMemoryKiB:  DefaultKDFMemoryKiB,
			KDFThreads:    DefaultKDFThreads,
			WrapAlgo:      "aes-256-gcm",
			CipherAlgo:    "xchacha20-poly1305",
			AuthAlgo:      "ed25519",
			ZeroKnowledge: true,
		}
	}
	info := &EncryptionInfo{
		FormatVersion: int(vaultFormatVersion),
		KDFAlgo:       b.header.KDFAlgo,
		KDFTime:       b.header.KDFTime,
		KDFMemoryKiB:  b.header.KDFMemoryKiB,
		KDFThreads:    b.header.KDFThreads,
		WrapAlgo:      b.header.WrapAlgo,
		CipherAlgo:    b.header.CipherAlgo,
		AuthAlgo:      b.header.AuthAlgo,
		ZeroKnowledge: true,
	}
	if includeAuthFingerprint {
		info.VaultID = b.header.VaultID
		info.Revision = b.header.Revision
		info.VaultSizeBytes = b.fileSize
		if len(b.header.AuthPublicKey) == ed25519.PublicKeySize {
			info.AuthPubKeySHA256 = sha256Hex(b.header.AuthPublicKey)
		}
	}
	return info
}

// VerifyClientChallenge verifies a zero-knowledge Ed25519 challenge signature without ever seeing any password or secret key.
func (b *BlindStore) VerifyClientChallenge(challengeID, nonceHex string, signature []byte) (authPubSHA256 string, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.header == nil {
		return "", ErrVaultNotInit
	}
	if !VerifyAuthChallenge(ed25519.PublicKey(b.header.AuthPublicKey), challengeID, nonceHex, b.header.VaultID, signature) {
		return "", ErrInvalidPassword
	}
	return sha256Hex(b.header.AuthPublicKey), nil
}

// InitializeBlob stores the initial client-sealed SNSVAULT v2 ciphertext container when uninitialized.
func (b *BlindStore) InitializeBlob(raw []byte, signature []byte) (authPubSHA256 string, info *EncryptionInfo, err error) {
	ver, _, hdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return "", nil, err
	}
	if err := ValidateV2HeaderStructural(ver, hdr); err != nil {
		return "", nil, err
	}
	if hdr.Revision != 1 {
		return "", nil, ErrCorruptedVault
	}
	if !VerifySetup(ed25519.PublicKey(hdr.AuthPublicKey), hdr.VaultID, hdr.Revision, raw, signature) {
		return "", nil, ErrInvalidSignature
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.header != nil {
		return "", nil, ErrVaultAlreadyInit
	}
	if err := b.atomicWriteRawLocked(raw, hdr); err != nil {
		return "", nil, err
	}
	return sha256Hex(hdr.AuthPublicKey), b.encryptionInfoLocked(true), nil
}

// ReadBlob returns the raw opaque SNSVAULT v2 ciphertext container from disk.
func (b *BlindStore) ReadBlob() (raw []byte, vaultID string, revision uint64, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.header == nil {
		return nil, "", 0, ErrVaultNotInit
	}
	raw, err = os.ReadFile(b.filePath)
	if err != nil {
		return nil, "", 0, fmt.Errorf("read vault blob: %w", err)
	}
	return raw, b.header.VaultID, b.header.Revision, nil
}

// PutBlob atomically updates the opaque SNSVAULT v2 ciphertext container with optimistic concurrency (CAS)
// and mandatory Ed25519 signature verification under the vault's AuthPublicKey.
func (b *BlindStore) PutBlob(raw []byte, expectedPrevRev uint64, signature []byte) (*EncryptionInfo, error) {
	ver, _, newHdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return nil, err
	}
	if err := ValidateV2HeaderStructural(ver, newHdr); err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.header == nil {
		return nil, ErrVaultNotInit
	}
	if newHdr.VaultID != b.header.VaultID || !constantTimeEqual(newHdr.AuthPublicKey, b.header.AuthPublicKey) {
		return nil, ErrInvalidSignature
	}
	if b.header.Revision != expectedPrevRev {
		return nil, ErrRevisionConflict
	}
	if newHdr.Revision != b.header.Revision+1 {
		return nil, ErrRevisionConflict
	}
	if !VerifyVaultPut(ed25519.PublicKey(b.header.AuthPublicKey), b.header.VaultID, b.header.Revision, newHdr.Revision, raw, signature) {
		return nil, ErrInvalidSignature
	}
	if err := b.atomicWriteRawLocked(raw, newHdr); err != nil {
		return nil, err
	}
	return b.encryptionInfoLocked(true), nil
}

// RotatePasswordBlob atomically replaces the vault with a re-encrypted container having a fresh salt, DEK,
// and AuthPublicKey, requiring dual Ed25519 signatures from BOTH the previous AuthPrivateKey and new AuthPrivateKey.
func (b *BlindStore) RotatePasswordBlob(raw []byte, expectedPrevRev uint64, oldSig, newSig []byte) (newAuthPubSHA256 string, info *EncryptionInfo, err error) {
	ver, _, newHdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return "", nil, err
	}
	if err := ValidateV2HeaderStructural(ver, newHdr); err != nil {
		return "", nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.header == nil {
		return "", nil, ErrVaultNotInit
	}
	if newHdr.VaultID != b.header.VaultID {
		return "", nil, ErrInvalidSignature
	}
	if b.header.Revision != expectedPrevRev || newHdr.Revision != b.header.Revision+1 {
		return "", nil, ErrRevisionConflict
	}
	if !VerifyPasswordRotate(
		ed25519.PublicKey(b.header.AuthPublicKey),
		ed25519.PublicKey(newHdr.AuthPublicKey),
		b.header.VaultID,
		b.header.Revision,
		newHdr.Revision,
		raw,
		oldSig,
		newSig,
	) {
		return "", nil, ErrInvalidPassword
	}
	if err := b.atomicWriteRawLocked(raw, newHdr); err != nil {
		return "", nil, err
	}
	return sha256Hex(newHdr.AuthPublicKey), b.encryptionInfoLocked(true), nil
}

// ImportBlob atomically imports an encrypted SNSVAULT v2 backup container.
// If the server already holds an initialized vault, overwriteSig MUST also prove possession of
// the existing vault's AuthPrivateKey so unauthenticated callers can NEVER overwrite an initialized vault.
func (b *BlindStore) ImportBlob(raw []byte, newSig, overwriteSig []byte) (authPubSHA256 string, info *EncryptionInfo, err error) {
	ver, _, newHdr, _, err := ParseVaultContainer(raw)
	if err != nil {
		return "", nil, err
	}
	if err := ValidateV2HeaderStructural(ver, newHdr); err != nil {
		return "", nil, err
	}
	if !VerifyVaultImportNew(ed25519.PublicKey(newHdr.AuthPublicKey), newHdr.VaultID, newHdr.Revision, raw, newSig) {
		return "", nil, ErrInvalidPassword
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.header != nil {
		if !VerifyVaultImportOverwrite(ed25519.PublicKey(b.header.AuthPublicKey), b.header.VaultID, newHdr.VaultID, raw, overwriteSig) {
			return "", nil, ErrInvalidPassword
		}
	}
	if err := b.atomicWriteRawLocked(raw, newHdr); err != nil {
		return "", nil, err
	}
	return sha256Hex(newHdr.AuthPublicKey), b.encryptionInfoLocked(true), nil
}

func (b *BlindStore) encryptionInfoLocked(includeAuthFP bool) *EncryptionInfo {
	if b.header == nil {
		return &EncryptionInfo{
			FormatVersion: int(vaultFormatVersion),
			ZeroKnowledge: true,
		}
	}
	info := &EncryptionInfo{
		FormatVersion:  int(vaultFormatVersion),
		VaultID:        b.header.VaultID,
		Revision:       b.header.Revision,
		KDFAlgo:        b.header.KDFAlgo,
		KDFTime:        b.header.KDFTime,
		KDFMemoryKiB:   b.header.KDFMemoryKiB,
		KDFThreads:     b.header.KDFThreads,
		WrapAlgo:       b.header.WrapAlgo,
		CipherAlgo:     b.header.CipherAlgo,
		AuthAlgo:       b.header.AuthAlgo,
		VaultSizeBytes: b.fileSize,
		ZeroKnowledge:  true,
	}
	if includeAuthFP {
		info.AuthPubKeySHA256 = sha256Hex(b.header.AuthPublicKey)
	}
	return info
}

func (b *BlindStore) atomicWriteRawLocked(raw []byte, hdr *EnvelopeHeader) error {
	tmpPath := b.filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp vault file: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp vault file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp vault file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, b.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename vault file: %w", err)
	}
	b.header = hdr
	b.fileSize = int64(len(raw))
	return nil
}
