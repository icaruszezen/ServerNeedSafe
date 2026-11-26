package sshmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"golang.org/x/crypto/ssh"
)

const (
	// MaxPrivateKeyBytes caps imported SSH private key size to prevent memory abuse.
	MaxPrivateKeyBytes = 256 * 1024
	// MaxPublicKeyBytes caps imported SSH public key size.
	MaxPublicKeyBytes = 64 * 1024
)

// GeneratedKeyPair holds an in-memory generated SSH key pair ready for encrypted storage.
type GeneratedKeyPair struct {
	Algorithm   string `json:"algorithm"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// InspectedPrivateKey describes a validated SSH private key and its derived public metadata.
type InspectedPrivateKey struct {
	NormalizedPEM string `json:"-"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	Fingerprint   string `json:"fingerprint"`
	Encrypted     bool   `json:"encrypted"`
}

// ErrPrivateKeyPassphraseRequired indicates an imported SSH private key is encrypted and requires a passphrase.
var ErrPrivateKeyPassphraseRequired = errors.New("该 SSH 私钥受口令保护，请填写私钥口令 (Passphrase) 后再导入")

// NormalizeKeyText removes UTF-8 BOM, normalizes CRLF/CR line endings to LF, and trims outer whitespace.
func NormalizeKeyText(raw string) string {
	s := strings.TrimPrefix(raw, "\uFEFF")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

// InspectPrivateKey validates an OpenSSH or PEM SSH private key (with optional passphrase)
// and derives its normalized PEM, algorithm label, OpenSSH public key, and SHA-256 fingerprint.
func InspectPrivateKey(rawPEM, passphrase string) (*InspectedPrivateKey, error) {
	if len(rawPEM) > MaxPrivateKeyBytes {
		return nil, errors.New("私钥文件体积超过限制（最大支持 256 KB）")
	}
	if strings.ContainsRune(rawPEM, '\x00') {
		return nil, errors.New("检测到二进制文件内容，请上传有效的文本格式 SSH 私钥文件")
	}

	normalized := NormalizeKeyText(rawPEM)
	if normalized == "" {
		return nil, errors.New("SSH 私钥内容不能为空")
	}
	if strings.HasPrefix(normalized, "PuTTY-User-Key-File-") {
		return nil, errors.New("暂不支持 PuTTY (.ppk) 格式，请先使用 PuTTYgen 转换为 OpenSSH 或 PEM 格式后再导入")
	}
	if looksLikeOpenSSHPublicKey(normalized) {
		return nil, errors.New("检测到您提供的是 SSH 公钥内容 (.pub)，请上传或粘贴对应的私钥文件")
	}

	pemBytes := []byte(normalized + "\n")
	defer vault.ZeroBytes(pemBytes)

	var (
		rawKey    interface{}
		signer    ssh.Signer
		encrypted bool
		err       error
	)

	rawKey, err = ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		var passMissing *ssh.PassphraseMissingError
		if errors.As(err, &passMissing) {
			encrypted = true
			if passphrase == "" {
				return nil, ErrPrivateKeyPassphraseRequired
			}
			passBytes := []byte(passphrase)
			defer vault.ZeroBytes(passBytes)

			rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passBytes)
			if err != nil {
				// Fallback to ssh.ParsePrivateKeyWithPassphrase in case the key type is supported
				// as an ssh.Signer (e.g., security keys) even if ParseRawPrivateKey cannot unwrap it.
				signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passBytes)
				if err != nil {
					return nil, errors.New("无法解密该 SSH 私钥，请检查私钥口令 (Passphrase) 或私钥文件是否正确")
				}
			}
		} else {
			// Fallback to ssh.ParsePrivateKey for non-raw-unwrappable key types.
			var signerErr error
			if passphrase != "" {
				passBytes := []byte(passphrase)
				defer vault.ZeroBytes(passBytes)
				signer, signerErr = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passBytes)
				if signerErr == nil {
					encrypted = bytes.Contains(pemBytes, []byte("ENCRYPTED"))
				}
			} else {
				signer, signerErr = ssh.ParsePrivateKey(pemBytes)
			}
			if signerErr != nil {
				if errors.As(signerErr, &passMissing) {
					return nil, ErrPrivateKeyPassphraseRequired
				}
				return nil, errors.New("无法解析 SSH 私钥，请确认文件为有效的 OpenSSH 或 PEM 私钥格式")
			}
		}
	}

	if signer == nil {
		signer, err = ssh.NewSignerFromKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("无法构造 SSH 私钥签名器: %w", err)
		}
	}

	pub := signer.PublicKey()
	return &InspectedPrivateKey{
		NormalizedPEM: normalized + "\n",
		Algorithm:     detectKeyAlgorithm(rawKey, pub),
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   ssh.FingerprintSHA256(pub),
		Encrypted:     encrypted,
	}, nil
}

// ValidateAndMatchPublicKey validates an OpenSSH authorized_keys public key line and
// optionally verifies that its SHA-256 fingerprint matches expectedFingerprint.
func ValidateAndMatchPublicKey(rawPub, expectedFingerprint string) (string, error) {
	if len(rawPub) > MaxPublicKeyBytes {
		return "", errors.New("公钥文件体积超过限制（最大支持 64 KB）")
	}
	if strings.ContainsRune(rawPub, '\x00') {
		return "", errors.New("检测到二进制文件内容，请上传有效的 OpenSSH 公钥 (.pub) 文件")
	}
	cleaned := NormalizeKeyText(rawPub)
	if cleaned == "" {
		return "", nil
	}
	if strings.ContainsRune(cleaned, '\n') {
		// Allow trailing comments/blank lines? Take only if single non-empty line to prevent ambiguity.
		lines := make([]string, 0, 2)
		for _, ln := range strings.Split(cleaned, "\n") {
			trimmed := strings.TrimSpace(ln)
			if trimmed != "" {
				lines = append(lines, trimmed)
			}
		}
		if len(lines) != 1 {
			return "", errors.New("公钥内容须为单行有效的 OpenSSH 公钥")
		}
		cleaned = lines[0]
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cleaned))
	if err != nil {
		return "", errors.New("无效的 OpenSSH 公钥格式，请检查 .pub 文件内容")
	}
	if expectedFingerprint != "" && ssh.FingerprintSHA256(pub) != expectedFingerprint {
		return "", errors.New("提供的公钥与私钥不匹配，请检查是否选错了公钥文件")
	}
	return cleaned, nil
}

func looksLikeOpenSSHPublicKey(s string) bool {
	prefixes := []string{
		"ssh-ed25519 ",
		"ssh-rsa ",
		"ssh-dss ",
		"ecdsa-sha2-",
		"sk-ssh-ed25519@",
		"sk-ecdsa-sha2-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func detectKeyAlgorithm(rawKey interface{}, pub ssh.PublicKey) string {
	switch k := rawKey.(type) {
	case *ed25519.PrivateKey:
		return "ed25519"
	case ed25519.PrivateKey:
		return "ed25519"
	case *rsa.PrivateKey:
		if k != nil && k.N != nil {
			return fmt.Sprintf("rsa-%d", k.N.BitLen())
		}
		return "rsa"
	case *ecdsa.PrivateKey:
		if k != nil && k.Curve != nil {
			return fmt.Sprintf("ecdsa-p%d", k.Curve.Params().BitSize)
		}
		return "ecdsa"
	}
	if pub != nil {
		switch t := pub.Type(); t {
		case ssh.KeyAlgoED25519:
			return "ed25519"
		case ssh.KeyAlgoRSA:
			return "rsa"
		case ssh.KeyAlgoECDSA256:
			return "ecdsa-p256"
		case ssh.KeyAlgoECDSA384:
			return "ecdsa-p384"
		case ssh.KeyAlgoECDSA521:
			return "ecdsa-p521"
		default:
			return strings.TrimPrefix(t, "ssh-")
		}
	}
	return "ssh-key"
}

// GenerateSSHKeyPair generates a cryptographically strong Ed25519 or RSA-4096 SSH key pair in memory.
func GenerateSSHKeyPair(algorithm, comment, passphrase string) (*GeneratedKeyPair, error) {
	algo := strings.ToLower(strings.TrimSpace(algorithm))
	if algo == "" {
		algo = "ed25519"
	}
	comment = strings.TrimSpace(comment)
	if comment == "" {
		comment = "sns-managed-key"
	}

	var rawPriv interface{}
	var sshPub ssh.PublicKey
	var err error

	switch algo {
	case "ed25519":
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		rawPriv = priv
		sshPub, err = ssh.NewPublicKey(pub)
		if err != nil {
			return nil, err
		}

	case "rsa", "rsa-4096":
		algo = "rsa-4096"
		priv, genErr := rsa.GenerateKey(rand.Reader, 4096)
		if genErr != nil {
			return nil, genErr
		}
		rawPriv = priv
		sshPub, err = ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("不支持的密钥算法 %q（支持 ed25519 或 rsa-4096）", algorithm)
	}

	var pemBlock *pem.Block
	if passphrase != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(rawPriv, comment, []byte(passphrase))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(rawPriv, comment)
	}
	if err != nil {
		return nil, fmt.Errorf("序列化 OpenSSH 私钥失败: %w", err)
	}

	privPEM := string(pem.EncodeToMemory(pemBlock))
	pubAuthorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	fp := ssh.FingerprintSHA256(sshPub)

	return &GeneratedKeyPair{
		Algorithm:   algo,
		PrivateKey:  privPEM,
		PublicKey:   pubAuthorized,
		Fingerprint: fp,
	}, nil
}

// DeployPublicKey appends an OpenSSH public key line into ~/.ssh/authorized_keys on the target server safely.
func (m *Manager) DeployPublicKey(serverID, publicKeyLine, clientIP string) error {
	pubLine := strings.TrimSpace(publicKeyLine)
	if pubLine == "" || strings.ContainsAny(pubLine, "\r\n") {
		return errors.New("公钥格式不合法")
	}
	// Verify valid OpenSSH authorized_key syntax before sending to remote server
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubLine)); err != nil {
		return fmt.Errorf("无效的 OpenSSH 公钥格式: %w", err)
	}

	client, err := m.Dial(serverID, DialOptions{ClientIP: clientIP})
	if err != nil {
		return err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	// Safely write via stdin so shell metacharacters in comment cannot cause command injection
	script := `umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && KEY=$(cat) && grep -qxF "$KEY" ~/.ssh/authorized_keys || printf '%s\n' "$KEY" >> ~/.ssh/authorized_keys`
	sess.Stdin = strings.NewReader(pubLine)
	out, err := sess.CombinedOutput(script)
	if err != nil {
		return fmt.Errorf("部署公钥失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	m.store.RecordAudit("key.deploy", fmt.Sprintf("%s (%s:%d)", client.Server.Name, client.Server.Host, client.Server.Port), "成功部署 SSH 公钥至远程 ~/.ssh/authorized_keys", clientIP, true)
	return nil
}
