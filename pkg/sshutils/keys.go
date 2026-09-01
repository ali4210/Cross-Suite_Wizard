package sshutils

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// GetOrCreateEd25519Key returns the path to a local key or creates a new Ed25519 pair.
func GetOrCreateEd25519Key() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", "", err
	}

	privPath := filepath.Join(sshDir, "id_ed25519_universal")
	pubPath := privPath + ".pub"

	if _, err := os.Stat(privPath); err == nil {
		pubBytes, err := os.ReadFile(pubPath)
		return privPath, string(pubBytes), err
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return "", "", err
	}
	privBytes := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(privPath, privBytes, 0600); err != nil {
		return "", "", err
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPubKey)
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		return "", "", err
	}

	return privPath, string(pubBytes), nil
}
