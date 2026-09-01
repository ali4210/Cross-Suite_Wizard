package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cross-ssh/pkg/osdetect"

	"golang.org/x/crypto/ssh"
)

func DeployKey(client *ssh.Client, targetOS osdetect.TargetOS, isAdmin bool, pubKey string, host string, user string, privKeyPath string, aliasName string) error {
	pubKey = strings.TrimSpace(pubKey)

	var err error
	switch targetOS {
	case osdetect.OSLinux, osdetect.OSMacOS:
		err = deployUnixKey(client, pubKey)
	case osdetect.OSWindows:
		if isAdmin {
			err = deployWindowsAdminKey(client, pubKey)
		} else {
			err = deployWindowsUserKey(client, pubKey)
		}
	default:
		return fmt.Errorf("unsupported OS target")
	}

	if err != nil {
		return err
	}

	// 1. Register in ~/.ssh/config
	if err := registerLocalSSHConfig(host, user, privKeyPath, aliasName); err != nil {
		return err
	}

	// 2. Register Shell Alias & Auto-Source
	if aliasName != "" {
		if err := registerAndAutoSourceAlias(aliasName, host, user); err != nil {
			return fmt.Errorf("failed to register alias: %w", err)
		}
	}

	return nil
}

func deployUnixKey(client *ssh.Client, pubKey string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	cmd := fmt.Sprintf(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qF '%s' ~/.ssh/authorized_keys 2>/dev/null || echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, pubKey, pubKey)
	return session.Run(cmd)
}

func deployWindowsUserKey(client *ssh.Client, pubKey string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	cmd := fmt.Sprintf(`powershell -Command "New-Item -ItemType Directory -Force -Path $ENV:USERPROFILE\.ssh; Add-Content -Path $ENV:USERPROFILE\.ssh\authorized_keys -Value '%s'"`, pubKey)
	return session.Run(cmd)
}

func deployWindowsAdminKey(client *ssh.Client, pubKey string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	psScript := fmt.Sprintf(`
	$Path = "$ENV:ProgramData\ssh\administrators_authorized_keys"
	Add-Content -Path $Path -Value "%s"
	icacls $Path /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
	`, pubKey)

	cmd := fmt.Sprintf(`powershell -Command "%s"`, psScript)
	return session.Run(cmd)
}

func registerLocalSSHConfig(host string, user string, privKeyPath string, aliasName string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, ".ssh", "config")
	hostPattern := host
	if aliasName != "" {
		hostPattern = fmt.Sprintf("%s %s", host, aliasName)
	}

	configEntry := fmt.Sprintf("\nHost %s\n  HostName %s\n  User %s\n  IdentityFile %s\n  StrictHostKeyChecking accept-new\n", hostPattern, host, user, privKeyPath)

	existing, _ := os.ReadFile(configPath)
	if strings.Contains(string(existing), fmt.Sprintf("HostName %s", host)) {
		return nil
	}

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(configEntry)
	return err
}

func registerAndAutoSourceAlias(aliasName, host, user string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	aliasCmd := fmt.Sprintf("\nalias %s='ssh %s@%s'\n", aliasName, user, host)

	// Target both .zshrc and .bashrc automatically
	rcFiles := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
	}

	for _, rc := range rcFiles {
		existing, _ := os.ReadFile(rc)
		if !strings.Contains(string(existing), fmt.Sprintf("alias %s=", aliasName)) {
			f, err := os.OpenFile(rc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				_, _ = f.WriteString(aliasCmd)
				f.Close()
			}
		}
	}

	// AUTOMATION: Execute unalias/alias directly in current process shell
	execShellAlias(aliasName, host, user)
	return nil
}

func execShellAlias(aliasName, host, user string) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}

	// Trigger automated background shell evaluation so it persists without manual source
	aliasDef := fmt.Sprintf("alias %s='ssh %s@%s'", aliasName, user, host)
	_ = exec.Command(shell, "-c", aliasDef).Run()
}