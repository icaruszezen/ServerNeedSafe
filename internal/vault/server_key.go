package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	masterKeyFileName = "master.key"
	legacyKeyFileName = ".vault.key"
	legacySealAAD     = "SNS-LOCAL-SEAL-v1:"

	MasterKeyModeEnv  = "env"
	MasterKeyModeFile = "file"
)

type legacyLocalKeySealFile struct {
	Version           int    `json:"version"`
	VaultID           string `json:"vault_id"`
	EnvProtected      bool   `json:"env_protected,omitempty"`
	MasterKeyB64      string `json:"master_key_b64,omitempty"`
	NonceB64          string `json:"nonce_b64"`
	WrappedSecretsB64 string `json:"wrapped_secrets_b64"`
}

func deriveEnvMasterKeyV3(rawEnv string) ([]byte, error) {
	return hkdfDerive32([]byte(rawEnv), []byte("ServerNeedSafe-MasterKey-Salt-v3"), "SNS-SECRETS-KEY-v3")
}

func deriveLegacyEnvMasterKeyV1(rawEnv string) ([]byte, error) {
	return hkdfDerive32([]byte(rawEnv), []byte("ServerNeedSafe-MasterKey-Salt-v1"), "SNS-LOCAL-MASTER-KEY-v1")
}

// loadOrCreateMasterKey loads the 256-bit local encryption key for secrets.enc.
// Priority:
//  1. SNS_MASTER_KEY environment variable (derived via HKDF-SHA256)
//  2. <dataDir>/master.key (auto-generated on first boot with 0600 permissions)
func loadOrCreateMasterKey(dataDir string) (key []byte, mode string, keyPath string, err error) {
	if rawEnv := strings.TrimSpace(os.Getenv("SNS_MASTER_KEY")); rawEnv != "" {
		k, err := deriveEnvMasterKeyV3(rawEnv)
		if err != nil {
			return nil, "", "", err
		}
		return k, MasterKeyModeEnv, "", nil
	}
	return loadOrCreateFileMasterKey(dataDir)
}

func loadOrCreateFileMasterKey(dataDir string) (key []byte, mode string, keyPath string, err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, "", "", fmt.Errorf("create data dir: %w", err)
	}
	keyPath = filepath.Join(dataDir, masterKeyFileName)
	raw, rErr := os.ReadFile(keyPath)
	if rErr == nil {
		defer zeroBytes(raw)
		trimmed := strings.TrimSpace(string(raw))
		if decoded, hErr := hex.DecodeString(trimmed); hErr == nil && len(decoded) == dekSize {
			return decoded, MasterKeyModeFile, keyPath, nil
		}
		if len(raw) == dekSize {
			return slices.Clone(raw), MasterKeyModeFile, keyPath, nil
		}
		return nil, "", "", fmt.Errorf("invalid master.key format at %s", keyPath)
	}
	if !errors.Is(rErr, os.ErrNotExist) {
		return nil, "", "", fmt.Errorf("read master.key: %w", rErr)
	}

	k, err := randomBytes(dekSize)
	if err != nil {
		return nil, "", "", err
	}
	encoded := []byte(hex.EncodeToString(k) + "\n")
	defer zeroBytes(encoded)
	if err := atomicWriteFile(keyPath, encoded, 0o600, true); err != nil {
		zeroBytes(k)
		return nil, "", "", fmt.Errorf("write master.key: %w", err)
	}
	return k, MasterKeyModeFile, keyPath, nil
}

// tryReadFileMasterKey reads an existing master.key without creating one (used to seamlessly
// re-key secrets.enc if an operator adds SNS_MASTER_KEY to an existing deployment).
func tryReadFileMasterKey(dataDir string) ([]byte, error) {
	keyPath := filepath.Join(dataDir, masterKeyFileName)
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	trimmed := strings.TrimSpace(string(raw))
	if decoded, hErr := hex.DecodeString(trimmed); hErr == nil && len(decoded) == dekSize {
		return decoded, nil
	}
	if len(raw) == dekSize {
		return slices.Clone(raw), nil
	}
	return nil, errors.New("invalid master.key")
}

// tryOpenLegacyVaultWithLocalKey unwraps a legacy v2.1 .vault.key and decrypts vault.sns
// so upgrading from v2.1.x to v3 split storage happens automatically on boot with zero downtime.
func tryOpenLegacyVaultWithLocalKey(dataDir string, legacyVaultRaw []byte) (*LegacyEnvelopeHeader, *VaultState, error) {
	sealPath := filepath.Join(dataDir, legacyKeyFileName)
	sealBytes, err := os.ReadFile(sealPath)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(sealBytes)

	var seal legacyLocalKeySealFile
	if err := json.Unmarshal(sealBytes, &seal); err != nil {
		return nil, nil, fmt.Errorf("parse legacy .vault.key: %w", err)
	}
	if seal.VaultID == "" {
		return nil, nil, errors.New("legacy .vault.key missing vault_id")
	}

	var wrapKey []byte
	if seal.EnvProtected {
		rawEnv := strings.TrimSpace(os.Getenv("SNS_MASTER_KEY"))
		if rawEnv == "" {
			return nil, nil, errors.New("legacy .vault.key requires SNS_MASTER_KEY")
		}
		wrapKey, err = deriveLegacyEnvMasterKeyV1(rawEnv)
		if err != nil {
			return nil, nil, err
		}
	} else {
		wrapKey, err = base64.StdEncoding.DecodeString(seal.MasterKeyB64)
		if err != nil || len(wrapKey) != dekSize {
			return nil, nil, errors.New("invalid legacy .vault.key master_key_b64")
		}
	}
	defer zeroBytes(wrapKey)

	nonce, err1 := base64.StdEncoding.DecodeString(seal.NonceB64)
	wrapped, err2 := base64.StdEncoding.DecodeString(seal.WrappedSecretsB64)
	if err1 != nil || err2 != nil {
		return nil, nil, errors.New("invalid legacy .vault.key encoding")
	}

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, nil, errors.New("invalid legacy .vault.key nonce")
	}
	plain, err := gcm.Open(nil, nonce, wrapped, []byte(legacySealAAD+seal.VaultID))
	if err != nil {
		return nil, nil, errors.New("legacy .vault.key unwrap failed")
	}
	defer zeroBytes(plain)

	if len(plain) != dekSize+ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid legacy .vault.key payload length")
	}
	dek := slices.Clone(plain[:dekSize])
	defer zeroBytes(dek)

	return OpenLegacyVaultWithDEK(legacyVaultRaw, dek)
}

func removeFileBestEffort(path string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}
	if info.Size() > 0 {
		if f, oErr := os.OpenFile(path, os.O_WRONLY, 0o600); oErr == nil {
			_, _ = f.Write(make([]byte, info.Size()))
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(path)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode, fsyncFile bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if fsyncFile {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("fsync temp file: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
