package sshmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestInspectPrivateKeyFormatsAndErrors(t *testing.T) {
	// 1. Unencrypted Ed25519 OpenSSH key with UTF-8 BOM & Windows CRLF line endings
	edKP, err := GenerateSSHKeyPair("ed25519", "ops@prod", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(ed25519): %v", err)
	}
	bomCRLF := "\uFEFF" + strings.ReplaceAll(edKP.PrivateKey, "\n", "\r\n")
	info, err := InspectPrivateKey(bomCRLF, "")
	if err != nil {
		t.Fatalf("InspectPrivateKey(ed25519 BOM+CRLF): %v", err)
	}
	if info.Algorithm != "ed25519" || info.Encrypted {
		t.Fatalf("unexpected ed25519 info: %+v", info)
	}
	if info.Fingerprint != edKP.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", info.Fingerprint, edKP.Fingerprint)
	}
	if !strings.HasPrefix(info.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("expected derived ssh-ed25519 public key, got %q", info.PublicKey)
	}
	if strings.Contains(info.NormalizedPEM, "\r") || strings.HasPrefix(info.NormalizedPEM, "\uFEFF") {
		t.Fatalf("expected normalized LF PEM without BOM")
	}

	// 2. Passphrase-protected OpenSSH Ed25519 key
	encKP, err := GenerateSSHKeyPair("ed25519", "vault@secops", "SuperKeyPass#2026")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(encrypted): %v", err)
	}
	if _, err := InspectPrivateKey(encKP.PrivateKey, ""); !errors.Is(err, ErrPrivateKeyPassphraseRequired) {
		t.Fatalf("expected ErrPrivateKeyPassphraseRequired without passphrase, got %v", err)
	}
	if _, err := InspectPrivateKey(encKP.PrivateKey, "wrong-passphrase"); err == nil {
		t.Fatalf("expected error on wrong passphrase")
	}
	encInfo, err := InspectPrivateKey(encKP.PrivateKey, "SuperKeyPass#2026")
	if err != nil {
		t.Fatalf("InspectPrivateKey(encrypted with passphrase): %v", err)
	}
	if !encInfo.Encrypted || encInfo.Algorithm != "ed25519" || encInfo.Fingerprint != encKP.Fingerprint {
		t.Fatalf("unexpected encrypted key info: %+v", encInfo)
	}

	// 3. Traditional PEM PKCS#1 RSA-2048 private key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
	}))
	rsaInfo, err := InspectPrivateKey(rsaPEM, "")
	if err != nil {
		t.Fatalf("InspectPrivateKey(RSA-2048 PEM): %v", err)
	}
	if rsaInfo.Algorithm != "rsa-2048" || rsaInfo.Encrypted || !strings.HasPrefix(rsaInfo.PublicKey, "ssh-rsa ") {
		t.Fatalf("unexpected rsa-2048 info: %+v", rsaInfo)
	}

	// 4. ECDSA P-256 PEM private key
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecPriv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	ecInfo, err := InspectPrivateKey(ecPEM, "")
	if err != nil {
		t.Fatalf("InspectPrivateKey(ECDSA-P256): %v", err)
	}
	ecSSHPub, _ := ssh.NewPublicKey(&ecPriv.PublicKey)
	if ecInfo.Algorithm != "ecdsa-p256" || ecInfo.Fingerprint != ssh.FingerprintSHA256(ecSSHPub) {
		t.Fatalf("unexpected ecdsa info: %+v", ecInfo)
	}

	// 5. Validation rejections: public key, PuTTY .ppk, binary NUL, oversized
	if _, err := InspectPrivateKey(edKP.PublicKey, ""); err == nil || !strings.Contains(err.Error(), "公钥") {
		t.Fatalf("expected public key rejection error, got %v", err)
	}
	if _, err := InspectPrivateKey("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n", ""); err == nil || !strings.Contains(err.Error(), "PuTTY") {
		t.Fatalf("expected PuTTY .ppk rejection error, got %v", err)
	}
	if _, err := InspectPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\x00binary", ""); err == nil || !strings.Contains(err.Error(), "二进制") {
		t.Fatalf("expected binary rejection error, got %v", err)
	}
	if _, err := InspectPrivateKey(strings.Repeat("A", MaxPrivateKeyBytes+10), ""); err == nil {
		t.Fatalf("expected oversized key rejection error")
	}
}

func TestValidateAndMatchPublicKey(t *testing.T) {
	kp1, err := GenerateSSHKeyPair("ed25519", "alice@prod-bastion", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(1): %v", err)
	}
	kp2, err := GenerateSSHKeyPair("ed25519", "bob@other", "")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(2): %v", err)
	}

	matched, err := ValidateAndMatchPublicKey("\uFEFF"+kp1.PublicKey+"\r\n", kp1.Fingerprint)
	if err != nil {
		t.Fatalf("ValidateAndMatchPublicKey(matching): %v", err)
	}
	if matched != kp1.PublicKey {
		t.Fatalf("expected preserved public key with comment, got %q want %q", matched, kp1.PublicKey)
	}

	if _, err := ValidateAndMatchPublicKey(kp2.PublicKey, kp1.Fingerprint); err == nil || !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("expected mismatch error for wrong .pub file, got %v", err)
	}
	if _, err := ValidateAndMatchPublicKey("not a public key", kp1.Fingerprint); err == nil {
		t.Fatalf("expected invalid format error")
	}
}
