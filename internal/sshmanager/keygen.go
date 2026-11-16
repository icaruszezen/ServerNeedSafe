package sshmanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GeneratedKeyPair holds an in-memory generated SSH key pair ready for encrypted storage.
type GeneratedKeyPair struct {
	Algorithm   string `json:"algorithm"`
	PrivateKey  string `json:"private_key"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
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
