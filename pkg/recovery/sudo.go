package recovery

import (
	"fmt"
	"strings"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/platform"
	"golang.org/x/crypto/ssh"
)

// RecoverSudo checks if the user is in the sudo/wheel group and provides recovery instructions.
func RecoverSudo(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== RECOVER SUDOERS ACCESS ===" + common.Reset)
	fmt.Println()

	// Detect platform
	plat, err := platform.Detect(client)
	if err != nil {
		fmt.Println(common.Red+"[!] Failed to detect platform: "+err.Error()+common.Reset)
		return
	}

	// Determine group name
	group := "sudo"
	if plat.Distro == "rhel" || plat.Distro == "centos" || plat.Distro == "fedora" ||
		plat.Distro == "rocky" || plat.Distro == "almalinux" || plat.Distro == "ol" {
		group = "wheel"
	}

	// Get current username
	userCmd := "whoami"
	userOut, err := common.ExecuteRemoteCommand(client, userCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Println(common.Red+"[!] Failed to get username: "+err.Error()+common.Reset)
		return
	}
	username := strings.TrimSpace(userOut)

	// Check if user is already in the group
	groupsCmd := fmt.Sprintf("id -nG %s | grep -qE '\\b(%s)\\b' && echo 1 || echo 0", username, group)
	out, err := common.ExecuteRemoteCommand(client, groupsCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Println(common.Red+"[!] Failed to check group membership: "+err.Error()+common.Reset)
		return
	}

	if strings.TrimSpace(out) == "1" {
		fmt.Printf(common.Green+"✅ User '%s' is already in the '%s' group.\n"+common.Reset, username, group)
		fmt.Println(common.Yellow + "   No recovery needed." + common.Reset)
		return
	}

	// User is NOT in the group – provide recovery instructions
	fmt.Printf(common.Red+"[!] User '%s' is NOT in the '%s' group.\n"+common.Reset, username, group)
	fmt.Println(common.Yellow + "   To restore sudo access, you must add the user to the group.")
	fmt.Println(common.Yellow + "   You need ROOT privileges to do this.")
	fmt.Println()

	// Try to use sudo if available (maybe passwordless sudo or still have access)
	if sudoStillWorks(client) {
		fmt.Println(common.Green + "✅ Sudo still works – adding user to group now...")
		fixCmd := fmt.Sprintf("sudo usermod -aG %s %s", group, username)
		out2, err := common.ExecuteRemoteCommand(client, fixCmd, common.LongCmdTimeout)
		if err == nil && strings.TrimSpace(out2) == "" {
			fmt.Printf(common.Green+"✅ User '%s' successfully added to '%s' group.\n"+common.Reset, username, group)
			fmt.Println(common.Yellow + "   Please log out and back in for the change to take effect.")
			return
		} else {
			fmt.Println(common.Red+"[!] Failed to add user via sudo: "+err.Error()+common.Reset)
			// fall through to manual instructions
		}
	}

	// Manual recovery instructions
	fmt.Println(common.Cyan + "=== MANUAL RECOVERY INSTRUCTIONS ===" + common.Reset)
	fmt.Printf(common.Yellow+"1. Log in as root (console or SSH as root) or use 'su -' from a terminal.\n")
	fmt.Printf("2. Run the following command to add user '%s' to group '%s':\n", username, group)
	fmt.Printf(common.Cyan+"   usermod -aG %s %s\n"+common.Reset, group, username)
	fmt.Println(common.Yellow + "3. Log out and back in for the change to take effect.")
	fmt.Println()
	fmt.Println(common.Green + "After completing these steps, your sudo access will be restored." + common.Reset)
}

// sudoStillWorks checks if sudo is usable without a password (or with cached credentials)
func sudoStillWorks(client *ssh.Client) bool {
	cmd := "sudo -n true 2>/dev/null && echo 'OK' || echo 'FAIL'"
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	return err == nil && strings.TrimSpace(out) == "OK"
}