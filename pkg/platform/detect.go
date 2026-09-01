package platform

import (
	"strings"

	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
)

// Platform holds all detected attributes of the remote system
type Platform struct {
	OS           string // "linux", "windows", "darwin"
	Distro       string // "debian", "ubuntu", "kali", "rhel", "centos", "fedora", "arch", "alpine", "opensuse", etc.
	PackageMgr   string // "apt", "dnf", "yum", "pacman", "apk", "zypper", "unknown"
	Firewall     string // "ufw", "firewalld", "iptables", "nftables", "none", "unknown"
	InitSystem   string // "systemd", "sysvinit", "openrc", "unknown"
	Architecture string // "x86_64", "aarch64", etc.
}

// Detect probes the remote host (via SSH) and returns a filled Platform struct.
func Detect(client *ssh.Client) (*Platform, error) {
	p := &Platform{OS: "linux"} // default; we'll refine

	// 1. Detect distribution from /etc/os-release
	out, _ := common.ExecuteRemoteCommand(client, "cat /etc/os-release 2>/dev/null || echo 'ID=unknown'", common.DefaultCmdTimeout)
	lines := strings.Split(out, "\n")
	id := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
	}
	if id == "" {
		// fallback to lsb_release
		out, _ = common.ExecuteRemoteCommand(client, "lsb_release -is 2>/dev/null", common.DefaultCmdTimeout)
		id = strings.ToLower(strings.TrimSpace(out))
	}
	if id == "" {
		id = "unknown"
	}
	p.Distro = id

	// 2. Detect package manager based on distro or command presence
	switch p.Distro {
	case "debian", "ubuntu", "kali", "linuxmint", "raspbian":
		p.PackageMgr = "apt"
	case "rhel", "centos", "fedora", "rocky", "almalinux", "ol":
		if _, err := common.ExecuteRemoteCommand(client, "command -v dnf", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "dnf"
		} else {
			p.PackageMgr = "yum"
		}
	case "arch", "manjaro", "endeavouros":
		p.PackageMgr = "pacman"
	case "alpine":
		p.PackageMgr = "apk"
	case "opensuse", "suse", "sles":
		p.PackageMgr = "zypper"
	default:
		// Auto‑detect by checking commands
		if _, err := common.ExecuteRemoteCommand(client, "command -v apt-get", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "apt"
		} else if _, err := common.ExecuteRemoteCommand(client, "command -v dnf", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "dnf"
		} else if _, err := common.ExecuteRemoteCommand(client, "command -v yum", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "yum"
		} else if _, err := common.ExecuteRemoteCommand(client, "command -v pacman", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "pacman"
		} else if _, err := common.ExecuteRemoteCommand(client, "command -v apk", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "apk"
		} else if _, err := common.ExecuteRemoteCommand(client, "command -v zypper", common.DefaultCmdTimeout); err == nil {
			p.PackageMgr = "zypper"
		} else {
			p.PackageMgr = "unknown"
		}
	}

	// 3. Detect firewall
	if _, err := common.ExecuteRemoteCommand(client, "command -v ufw", common.DefaultCmdTimeout); err == nil {
		p.Firewall = "ufw"
	} else if _, err := common.ExecuteRemoteCommand(client, "command -v firewall-cmd", common.DefaultCmdTimeout); err == nil {
		p.Firewall = "firewalld"
	} else if _, err := common.ExecuteRemoteCommand(client, "command -v iptables", common.DefaultCmdTimeout); err == nil {
		p.Firewall = "iptables"
	} else if _, err := common.ExecuteRemoteCommand(client, "command -v nft", common.DefaultCmdTimeout); err == nil {
		p.Firewall = "nftables"
	} else {
		p.Firewall = "none"
	}

	// 4. Detect init system
	if _, err := common.ExecuteRemoteCommand(client, "command -v systemctl", common.DefaultCmdTimeout); err == nil {
		p.InitSystem = "systemd"
	} else if _, err := common.ExecuteRemoteCommand(client, "command -v service", common.DefaultCmdTimeout); err == nil {
		p.InitSystem = "sysvinit"
	} else {
		p.InitSystem = "unknown"
	}

	// 5. Detect architecture
	out, _ = common.ExecuteRemoteCommand(client, "uname -m 2>/dev/null", common.DefaultCmdTimeout)
	p.Architecture = strings.TrimSpace(out)

	return p, nil
}