package platform

import (
	"fmt"
	"strings"

	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
)

// fixCustomRepos removes custom-cross-repo-* files and cleans DNF cache.
func fixCustomRepos(client *ssh.Client) {
	// Remove broken repos entirely
	cmd := `sudo rm -f /etc/yum.repos.d/custom-cross-repo-*.repo && sudo dnf clean all 2>/dev/null || true`
	_, _ = common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)

	// Install EPEL if missing
	epelCheck := `dnf repolist | grep -q epel && echo "OK" || echo "MISSING"`
	out, _ := common.ExecuteRemoteCommand(client, epelCheck, common.DefaultCmdTimeout)
	if strings.TrimSpace(out) != "OK" {
		_, _ = common.ExecuteRemoteCommand(client, "sudo dnf install -y epel-release 2>/dev/null", common.LongCmdTimeout)
	}
	// Rebuild cache
	_, _ = common.ExecuteRemoteCommand(client, "sudo dnf makecache 2>/dev/null", common.DefaultCmdTimeout)
}

// InstallPackages installs packages using the detected package manager.
func InstallPackages(client *ssh.Client, packages ...string) error {
	if len(packages) == 0 {
		// If no packages, just run the repo fix
		fixCustomRepos(client)
		return nil
	}
	plat, err := Detect(client)
	if err != nil {
		return fmt.Errorf("failed to detect platform: %w", err)
	}

	// Fix custom repos on RHEL/CentOS
	if plat.PackageMgr == "dnf" || plat.PackageMgr == "yum" {
		fixCustomRepos(client)
	}

	var installCmd string
	switch plat.PackageMgr {
	case "apt":
		installCmd = fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq %s", strings.Join(packages, " "))
	case "dnf":
		installCmd = fmt.Sprintf("sudo dnf install -y %s", strings.Join(packages, " "))
	case "yum":
		installCmd = fmt.Sprintf("sudo yum install -y %s", strings.Join(packages, " "))
	case "pacman":
		installCmd = fmt.Sprintf("sudo pacman -S --noconfirm %s", strings.Join(packages, " "))
	case "apk":
		installCmd = fmt.Sprintf("sudo apk add %s", strings.Join(packages, " "))
	case "zypper":
		installCmd = fmt.Sprintf("sudo zypper install -y %s", strings.Join(packages, " "))
	default:
		return fmt.Errorf("unsupported package manager: %s", plat.PackageMgr)
	}
	_, err = common.ExecuteRemoteCommand(client, installCmd, common.LongCmdTimeout)
	return err
}