package security

import (
	"bufio"
	"fmt"
	"strings"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/recovery"
	"golang.org/x/crypto/ssh"
)

// MITREWrapper is the main entry point for the MITRE ATTACK! ENGINE
func MITREWrapper(reader *bufio.Reader, client *ssh.Client) {
	// Validate sudo password before showing any options
	if !promptAndValidateSudo(client) {
		fmt.Println(common.Red + "[!] Sudo validation failed. Access to MITRE ATTACK! ENGINE denied." + common.Reset)
		fmt.Println(common.Yellow + "    Please check your password and try again." + common.Reset)
		common.PausePrompt()
		return
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== MITRE ATTACK! ENGINE ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Yellow + "  [1] Recover Sudoers Access (Emergency Recovery)" + common.Reset)
		fmt.Println(common.Green + "  [2] MITRE ATTACK SURFACE (Full Audit & Remediation)" + common.Reset)
		fmt.Println(common.Red + "  [0] Back" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select option [0-2]: " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			recovery.RecoverSudo(client)
			common.PausePrompt()
		case "2":
			ShowMITREMenu(reader, client) // Existing MITRE surface
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		}
	}
}