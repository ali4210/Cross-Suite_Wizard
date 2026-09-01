package localinfo

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cross-ssh/pkg/transfer"
)

// ANSI color constants
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// Tag prefixes for metadata discrimination
const (
	TagPrefixA = "tag:cross-ssh:wf-a:"
	TagPrefixB = "tag:cross-ssh:wf-b:"
)

// =============================================================================
// DISPLAY LOCAL SSH CONNECTION INFO
// =============================================================================

type NetworkAddr struct {
	Interface string
	IP        string
	SSHCmd    string
}

func DisplayLocalSSHInfo(reader *bufio.Reader) {
	fmt.Println(Cyan + Bold + "=== MY LOCAL SSH CONNECTION INFO ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	username := GetCurrentUsername()
	fmt.Printf(Yellow+"Local Terminal User: "+Reset+Bold+"%s\n"+Reset, username)

	addrs := getLocalIPAddresses(username)
	if len(addrs) == 0 {
		fmt.Println(Red + "[!] No active non-loopback network interfaces found." + Reset)
	} else {
		fmt.Println(Bold + "\n=> Ready-to-Copy SSH Connection Commands:" + Reset)
		for _, addr := range addrs {
			fmt.Printf(Green+Bold+"   [%s] "+Reset+Cyan+"%s\n"+Reset, addr.Interface, addr.SSHCmd)
		}
	}

	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	sshListening := isLocalSSHActive()
	if sshListening {
		fmt.Println(Green + Bold + "[STATUS] Local SSH Daemon (sshd) is ACTIVE and listening on port 22!" + Reset)
	} else {
		fmt.Println(Red + Bold + "[WARNING] Local SSH Daemon (sshd) is NOT listening on port 22." + Reset)
		fmt.Println(Yellow + "Others will NOT be able to connect until sshd service is started." + Reset)

		fmt.Print(Yellow + "\nWould you like to start the local SSH service now? [Y/n]: " + Reset)
		ans := transfer.ReadRealtimeInput("")
		if ans == "" || ans == "y" || ans == "Y" {
			startLocalSSHService()
		}
	}
}

func GetCurrentUsername() string {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		return sudoUser
	}
	u, err := user.Current()
	if err == nil && u.Username != "" {
		parts := strings.Split(u.Username, "\\")
		return parts[len(parts)-1]
	}
	envUser := os.Getenv("USER")
	if envUser != "" {
		return envUser
	}
	return "user"
}

func getCurrentUsername() string {
	return GetCurrentUsername()
}

func getLocalIPAddresses(username string) []NetworkAddr {
	var results []NetworkAddr
	interfaces, err := net.Interfaces()
	if err != nil {
		return results
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			ipStr := ip.String()
			sshCmd := fmt.Sprintf("ssh %s@%s", username, ipStr)
			results = append(results, NetworkAddr{
				Interface: iface.Name,
				IP:        ipStr,
				SSHCmd:    sshCmd,
			})
		}
	}
	return results
}

func startLocalSSHService() {
	fmt.Println(Yellow + "Attempting to start SSH service..." + Reset)
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("sudo", "systemsetup", "-setremotelogin", "on")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	default:
		cmd := exec.Command("sudo", "systemctl", "start", "ssh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			_ = exec.Command("sudo", "service", "ssh", "start").Run()
		}
	}
	time.Sleep(1 * time.Second)
	if isLocalSSHActive() {
		fmt.Println(Green + Bold + "[SUCCESS] Local SSH Daemon started successfully!" + Reset)
	} else {
		fmt.Println(Red + "[!] Could not start SSH daemon. Make sure openssh-server is installed." + Reset)
	}
}

// =============================================================================
// FULL PROVISIONER MENU
// =============================================================================

func ShowLocalSSHProvisionerMenu(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== LOCAL WORKSTATION SSH SERVER AUTOMATION ENGINE ===" + Reset)
		fmt.Println(Yellow + "[!] Enterprise lifecycle management – auto-provision, configure & interlock." + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		statusStr := checkLocalSSHStatus()
		fmt.Printf(Bold+"Current Local SSH Status: %s\n"+Reset, statusStr)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		fmt.Println("  [1] Full Auto-Provision (Install, Keygen, Enable, Start)")
		fmt.Println("  [2] Repair / Re-enable (Fix config, regenerate host keys)")
		fmt.Println("  [3] Complete Uninstall & Purge (Remove packages, delete ALL keys)")
		fmt.Println("  [4] Show Current Status & Active Keys")
		fmt.Println(Green + "  [5] Configure Root Login (PermitRootLogin) on Local SSH Server" + Reset)
		fmt.Println(Cyan + "  [6] Configure Local Login & Universal Interconnection" + Reset)
		fmt.Println(Red + "  [0] Back" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-6]: ")

		switch choice {
		case "1":
			fullAutoProvision(reader)
			pausePrompt()
		case "2":
			repairAndReenable()
			pausePrompt()
		case "3":
			completeUninstallAndPurge(reader)
			pausePrompt()
		case "4":
			showStatus()
			pausePrompt()
		case "5":
			configureLocalRootLogin(reader)
			pausePrompt()
		case "6":
			configureLocalLogin(reader)
			pausePrompt()
		case "0", "q", "Q":
			return
		}
	}
}

// -----------------------------------------------------------------------------
// CONFIGURE LOCAL LOGIN
// -----------------------------------------------------------------------------
func configureLocalLogin(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "\n=== CONFIGURE LOCAL LOGIN SETTINGS ===" + Reset)
		fmt.Println(Yellow + "Manage password and key authentication on the local SSH server." + Reset)

		pwdAuth, pubAuth := getCurrentAuthSettings()
		fmt.Printf("\nCurrent Password Authentication : %s\n", pwdAuth)
		fmt.Printf("Current Pubkey Authentication   : %s\n", pubAuth)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		fmt.Println("Select an action:")
		fmt.Println("  [1] Allow local login with password (enables both password & key)")
		fmt.Println("  [2] Prohibit password local login (key ONLY login, recommended)")
		fmt.Println("  [3] Completely disable local login (disables both password & key)")
		fmt.Println(Green + "  [4] [Workflow A] Paste & Authorize Client Public Key (With Signature Tag)" + Reset)
		fmt.Println(Cyan + "  [5] [Workflow B] Generate 1-Click Injection Payload for Client (With Signature Tag)" + Reset)
		fmt.Println(Red + Bold + "  [6] [Revoke] Revoke Tagged Injected Keys (Granular Workflow A & B)" + Reset)
		fmt.Println(Red + "  [0] Back to previous menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Choice [0-6]: ")

		switch choice {
		case "1":
			setLocalLoginMode("allow-password")
			pausePrompt()
			return
		case "2":
			setLocalLoginMode("key-only")
			pausePrompt()
			return
		case "3":
			setLocalLoginMode("disable-all")
			pausePrompt()
			return
		case "4":
			workflowAAuthorizeClientKey(reader)
			pausePrompt()
			return
		case "5":
			workflowBExportPrivateKey(reader)
			pausePrompt()
			return
		case "6":
			revokeInjectedPayloadKeys(reader)
			pausePrompt()
			return
		case "0", "q", "Q":
			return
		}
	}
}

// -----------------------------------------------------------------------------
// WORKFLOW A: Paste & Authorize Client Public Key with Signature Tag
// -----------------------------------------------------------------------------
func workflowAAuthorizeClientKey(reader *bufio.Reader) {
	fmt.Println(Cyan + Bold + "\n=== WORKFLOW A: AUTHORIZE CLIENT PUBLIC KEY ===" + Reset)
	currentUser := GetCurrentUsername()
	home := getUserHomePath()
	sshDir := filepath.Join(home, ".ssh")
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	fmt.Printf(Yellow+"Target Server User : "+Reset+Bold+"%s\n"+Reset, currentUser)
	fmt.Printf(Yellow+"Target Config File  : "+Reset+Bold+"%s\n\n"+Reset, authKeysPath)

	fmt.Println(Yellow + "[!] Enter a recognizable identifier/machine name for this client (e.g. mobaxterm-win, laptop-mac):" + Reset)
	clientLabel := transfer.ReadRealtimeInput("Client Identifier: ")
	clientLabel = strings.TrimSpace(clientLabel)
	if clientLabel == "" {
		clientLabel = "unnamed-client"
	}
	clientLabel = strings.ReplaceAll(clientLabel, " ", "-")

	fmt.Println(Yellow + "\n[!] Paste the client public key (starts with ssh-ed25519, ssh-rsa, etc.):" + Reset)
	pasted := transfer.ReadRealtimeInput("Paste Client Public Key: ")
	pubKeyRaw := strings.TrimSpace(pasted)
	if pubKeyRaw == "" || (!strings.HasPrefix(pubKeyRaw, "ssh-") && !strings.HasPrefix(pubKeyRaw, "ecdsa-")) {
		fmt.Println(Red + "[!] Invalid public key format entered. Must start with ssh- or ecdsa-" + Reset)
		return
	}

	parts := strings.Fields(pubKeyRaw)
	if len(parts) < 2 {
		fmt.Println(Red + "[!] Invalid public key structure." + Reset)
		return
	}
	timestamp := time.Now().Format("20060102-150405")
	tag := fmt.Sprintf("%s%s:%s", TagPrefixA, clientLabel, timestamp)
	taggedKeyLine := fmt.Sprintf("%s %s %s", parts[0], parts[1], tag)

	_ = os.MkdirAll(sshDir, 0700)
	_ = os.Chmod(sshDir, 0700)

	appendKeyToAuthFiles(taggedKeyLine, parts[1])

	applySSHDirective("PubkeyAuthentication", "yes")
	restartLocalSSH()

	fmt.Println(Green + Bold + "\n[✔] Workflow A Completed: Client public key authorized with signature!" + Reset)
	fmt.Printf(Yellow+"Signature Tag Applied: %s\n"+Reset, tag)
	fmt.Printf(Cyan+"Now connect from client terminal: ssh %s@%s\n"+Reset, currentUser, getLocalIP())
}

// -----------------------------------------------------------------------------
// WORKFLOW B: Autonomous Dedicated 1-Click Provisioner with Signature Tag
// -----------------------------------------------------------------------------
func workflowBExportPrivateKey(reader *bufio.Reader) {
	fmt.Println(Cyan + Bold + "\n=== WORKFLOW B: 1-CLICK CLIENT INJECTION & CONFIG GENERATOR ===" + Reset)
	currentUser := GetCurrentUsername()
	home := getUserHomePath()
	sshDir := filepath.Join(home, ".ssh")
	keysVaultDir := filepath.Join(sshDir, "wf_b_vault")
	_ = os.MkdirAll(keysVaultDir, 0700)

	defaultAlias := fmt.Sprintf("%s-kali", currentUser)
	fmt.Printf(Yellow+"\nEnter Host Alias for this export [Press Enter for default: '%s']: "+Reset, defaultAlias)
	customAlias := transfer.ReadRealtimeInput("")
	aliasName := strings.TrimSpace(customAlias)
	if aliasName == "" {
		aliasName = defaultAlias
	}
	aliasName = strings.ReplaceAll(aliasName, " ", "-")

	fmt.Printf(Yellow+"Enter target username on this machine [Press Enter for default '%s']: "+Reset, currentUser)
	targetUser := transfer.ReadRealtimeInput("")
	if strings.TrimSpace(targetUser) == "" {
		targetUser = currentUser
	}

	privKeyPath := filepath.Join(keysVaultDir, fmt.Sprintf("%s_id_ed25519", aliasName))
	pubKeyPath := filepath.Join(keysVaultDir, fmt.Sprintf("%s_id_ed25519.pub", aliasName))

	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		fmt.Printf(Yellow+"[+] Generating unique dedicated Ed25519 keypair for alias '%s'...\n"+Reset, aliasName)
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privKeyPath, "-N", "", "-C", fmt.Sprintf("wf-b-%s", aliasName))
		_ = cmd.Run()
	}

	pubData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to read generated public key: %v\n"+Reset, err)
		return
	}
	pubStr := strings.TrimSpace(string(pubData))
	parts := strings.Fields(pubStr)
	if len(parts) < 2 {
		fmt.Println(Red + "[!] Invalid public key format." + Reset)
		return
	}

	timestamp := time.Now().Format("20060102-150405")
	tag := fmt.Sprintf("%s%s:%s", TagPrefixB, aliasName, timestamp)
	taggedKeyLine := fmt.Sprintf("%s %s %s", parts[0], parts[1], tag)

	_ = os.MkdirAll(sshDir, 0700)
	_ = os.Chmod(sshDir, 0700)

	appendKeyToAuthFiles(taggedKeyLine, parts[1])

	applySSHDirective("PubkeyAuthentication", "yes")
	if targetUser == "root" {
		applySSHDirective("PermitRootLogin", "prohibit-password")
	}
	restartLocalSSH()

	privData, err := os.ReadFile(privKeyPath)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to read private key: %v\n"+Reset, err)
		return
	}
	b64Key := base64.StdEncoding.EncodeToString(privData)
	serverIP := getLocalIP()
	keyFileName := fmt.Sprintf("%s_key", aliasName)

	unixPayload := fmt.Sprintf(
		`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "%s" | base64 -d > ~/.ssh/%s && chmod 600 ~/.ssh/%s && touch ~/.ssh/config && chmod 600 ~/.ssh/config && sed -i '/Host %s$/,/IdentitiesOnly/d' ~/.ssh/config 2>/dev/null; printf "\nHost %s\n  HostName %s\n  User %s\n  IdentityFile ~/.ssh/%s\n  IdentitiesOnly yes\n" >> ~/.ssh/config && echo "Key and Alias configured successfully! Connect using: ssh %s"`,
		b64Key, keyFileName, keyFileName, aliasName, aliasName, serverIP, targetUser, keyFileName, aliasName,
	)

	psPayload := fmt.Sprintf(
		`$p="$HOME\.ssh"; if(-not(Test-Path $p)){New-Item -ItemType Directory -Path $p -Force|Out-Null}; [IO.File]::WriteAllBytes("$p\%s",[Convert]::FromBase64String('%s')); $c="`+"`n"+`Host %s`+"`n"+`  HostName %s`+"`n"+`  User %s`+"`n"+`  IdentityFile ~/.ssh/%s`+"`n"+`  IdentitiesOnly yes`+"`n"+`"; if(Test-Path "$p\config"){ $old=(Get-Content "$p\config" -Raw); $clean=($old -replace '(?s)Host %s\r?\n.+?IdentitiesOnly yes\r?\n?','').TrimEnd(); Set-Content "$p\config" $clean }; Add-Content -Path "$p\config" -Value $c; Write-Host 'Key and Alias configured successfully! Connect using: ssh %s' -ForegroundColor Green`,
		keyFileName, b64Key, aliasName, serverIP, targetUser, keyFileName, aliasName, aliasName,
	)

	fmt.Printf("\033]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(unixPayload)))

	fmt.Println(Green + Bold + "\n[✔] Configuration Generated Successfully with Dedicated Tagged Key!" + Reset)
	fmt.Println(Yellow + "Tell your friend to run the matching command on their local terminal (outside the SSH session):" + Reset)
	fmt.Println(Blue + "==================================================================================" + Reset)
	fmt.Println(Green + Bold + "Option 1: For Linux / macOS / MobaXterm Local Terminal / WSL / Git Bash:" + Reset)
	fmt.Println(Cyan + unixPayload + Reset)
	fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
	fmt.Println(Green + Bold + "Option 2: For Windows PowerShell / Windows Terminal:" + Reset)
	fmt.Println(Yellow + psPayload + Reset)
	fmt.Println(Blue + "==================================================================================" + Reset)

	fmt.Println(Green + Bold + "\n=> Connection Command:" + Reset)
	fmt.Printf(Green+Bold+"   ssh %s\n"+Reset, aliasName)
}

func getUserHomePath() string {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		return filepath.Join("/home", sudoUser)
	}
	h, err := os.UserHomeDir()
	if err == nil {
		return h
	}
	return "/root"
}

func appendKeyToAuthFiles(taggedKeyLine, keySignature string) {
	targets := []string{
		filepath.Join(getUserHomePath(), ".ssh", "authorized_keys"),
		"/root/.ssh/authorized_keys",
	}

	for _, targetPath := range targets {
		_ = runSudoCommand("mkdir", "-p", filepath.Dir(targetPath))
		_ = runSudoCommand("chmod", "700", filepath.Dir(targetPath))

		authData, _ := os.ReadFile(targetPath)
		lines := strings.Split(string(authData), "\n")
		var newLines []string
		found := false

		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" {
				continue
			}
			if strings.Contains(trimmed, keySignature) {
				newLines = append(newLines, taggedKeyLine)
				found = true
			} else {
				newLines = append(newLines, trimmed)
			}
		}
		if !found {
			newLines = append(newLines, taggedKeyLine)
		}

		out := strings.Join(newLines, "\n") + "\n"
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("auth_tmp_%d", time.Now().UnixNano()))
		_ = os.WriteFile(tmpFile, []byte(out), 0600)
		_ = runSudoCommand("cp", tmpFile, targetPath)
		_ = runSudoCommand("chmod", "600", targetPath)
		_ = os.Remove(tmpFile)
	}
}

// -----------------------------------------------------------------------------
// REVOCATION ENGINE: Hierarchical Revocation Menu
// -----------------------------------------------------------------------------
type TaggedKeyEntry struct {
	LineNumber int
	RawLine    string
	Tag        string
	Type       string
	TargetName string
	Timestamp  string
}

func parseAuthorizedKeys() ([]TaggedKeyEntry, []string) {
	authKeysPath := filepath.Join(getUserHomePath(), ".ssh", "authorized_keys")

	var tagged []TaggedKeyEntry
	var allLines []string

	contentBytes, err := os.ReadFile(authKeysPath)
	if err != nil {
		return tagged, allLines
	}

	lines := strings.Split(string(contentBytes), "\n")
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		allLines = append(allLines, trimmed)

		if strings.Contains(trimmed, TagPrefixA) {
			idx := strings.Index(trimmed, TagPrefixA)
			tag := trimmed[idx:]
			meta := strings.TrimPrefix(tag, TagPrefixA)
			parts := strings.Split(meta, ":")
			label, ts := "unknown", "unknown"
			if len(parts) >= 1 {
				label = parts[0]
			}
			if len(parts) >= 2 {
				ts = parts[1]
			}
			tagged = append(tagged, TaggedKeyEntry{
				LineNumber: i,
				RawLine:    trimmed,
				Tag:        tag,
				Type:       "WF-A",
				TargetName: label,
				Timestamp:  ts,
			})
		} else if strings.Contains(trimmed, TagPrefixB) {
			idx := strings.Index(trimmed, TagPrefixB)
			tag := trimmed[idx:]
			meta := strings.TrimPrefix(tag, TagPrefixB)
			parts := strings.Split(meta, ":")
			label, ts := "unknown", "unknown"
			if len(parts) >= 1 {
				label = parts[0]
			}
			if len(parts) >= 2 {
				ts = parts[1]
			}
			tagged = append(tagged, TaggedKeyEntry{
				LineNumber: i,
				RawLine:    trimmed,
				Tag:        tag,
				Type:       "WF-B",
				TargetName: label,
				Timestamp:  ts,
			})
		}
	}
	return tagged, allLines
}

func writeAuthorizedKeys(lines []string) error {
	targets := []string{
		filepath.Join(getUserHomePath(), ".ssh", "authorized_keys"),
		"/root/.ssh/authorized_keys",
	}

	out := strings.Join(lines, "\n")
	if len(lines) > 0 {
		out += "\n"
	}

	for _, targetPath := range targets {
		tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("auth_tmp_%d", time.Now().UnixNano()))
		_ = os.WriteFile(tmpFile, []byte(out), 0600)
		_ = runSudoCommand("cp", tmpFile, targetPath)
		_ = runSudoCommand("chmod", "600", targetPath)
		_ = os.Remove(tmpFile)
	}
	return nil
}

func revokeInjectedPayloadKeys(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "\n=== REVOKE GENERATED & INJECTED PAYLOAD KEYS ===" + Reset)
		fmt.Println(Yellow + "Surgically purge tagged keys without affecting your native system keys." + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Revoke Workflow A Keys (Client Public Keys pasted to this machine)")
		fmt.Println("  [2] Revoke Workflow B Keys (Payloads exported to Client machines)")
		fmt.Println("  [3] Revoke ALL Workflow A & Workflow B Keys Together (1-Click Clean)")
		fmt.Println(Red + "  [0] Back to previous menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-3]: ")

		switch choice {
		case "1":
			menuRevokeWorkflowA()
			pausePrompt()
			return
		case "2":
			menuRevokeWorkflowB()
			pausePrompt()
			return
		case "3":
			revokeAllWorkflowAAndB()
			pausePrompt()
			return
		case "0", "q", "Q":
			return
		}
	}
}

func menuRevokeWorkflowA() {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "\n=== REVOKE WORKFLOW A KEYS (CLIENT PUBLIC KEYS) ===" + Reset)

		tagged, _ := parseAuthorizedKeys()
		var wfA []TaggedKeyEntry
		for _, k := range tagged {
			if k.Type == "WF-A" {
				wfA = append(wfA, k)
			}
		}

		if len(wfA) == 0 {
			fmt.Println(Yellow + "\n[!] No Workflow A tagged keys found in authorized_keys." + Reset)
			return
		}

		fmt.Println("\nDetected Active Workflow A Key(s):")
		for idx, k := range wfA {
			fmt.Printf(Green+"  [%d] "+Reset+"Client Identifier: "+Bold+"%s"+Reset+" | Tagged Date: %s\n", idx+1, k.TargetName, k.Timestamp)
		}

		fmt.Println(Blue + "\n------------------------------------------------------------------" + Reset)
		fmt.Println("  [A] Revoke ALL Workflow A Keys")
		fmt.Println("  [1-" + fmt.Sprintf("%d", len(wfA)) + "] Revoke Specific Key")
		fmt.Println(Red + "  [0] Cancel" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice: ")
		if choice == "0" || strings.ToLower(choice) == "q" {
			return
		}

		if strings.ToUpper(choice) == "A" {
			_, allLines := parseAuthorizedKeys()
			var newLines []string
			for _, l := range allLines {
				if !strings.Contains(l, TagPrefixA) {
					newLines = append(newLines, l)
				}
			}
			_ = writeAuthorizedKeys(newLines)
			fmt.Println(Green + Bold + "\n[✔] Successfully revoked ALL Workflow A keys!" + Reset)
			return
		}

		var selectedIdx int
		_, err := fmt.Sscanf(choice, "%d", &selectedIdx)
		if err == nil && selectedIdx >= 1 && selectedIdx <= len(wfA) {
			targetKey := wfA[selectedIdx-1]
			_, allLines := parseAuthorizedKeys()
			var newLines []string
			for _, l := range allLines {
				if !strings.Contains(l, targetKey.Tag) {
					newLines = append(newLines, l)
				}
			}
			_ = writeAuthorizedKeys(newLines)
			fmt.Printf(Green+Bold+"\n[✔] Successfully revoked Workflow A key for '%s'!\n"+Reset, targetKey.TargetName)
			return
		}
	}
}

func menuRevokeWorkflowB() {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "\n=== REVOKE WORKFLOW B KEYS (INJECTED PAYLOADS) ===" + Reset)

		tagged, _ := parseAuthorizedKeys()
		var wfB []TaggedKeyEntry
		for _, k := range tagged {
			if k.Type == "WF-B" {
				wfB = append(wfB, k)
			}
		}

		if len(wfB) == 0 {
			fmt.Println(Yellow + "\n[!] No Workflow B tagged keys found in authorized_keys." + Reset)
			return
		}

		fmt.Println("\nDetected Active Workflow B Host Alias(es):")
		for idx, k := range wfB {
			fmt.Printf(Green+"  [%d] "+Reset+"Host Alias: "+Bold+"%s"+Reset+" | Tagged Date: %s\n", idx+1, k.TargetName, k.Timestamp)
		}

		fmt.Println(Blue + "\n------------------------------------------------------------------" + Reset)
		fmt.Println("  [A] Revoke ALL Workflow B Keys")
		fmt.Println("  [1-" + fmt.Sprintf("%d", len(wfB)) + "] Revoke Specific Key")
		fmt.Println(Red + "  [0] Cancel" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice: ")
		if choice == "0" || strings.ToLower(choice) == "q" {
			return
		}

		if strings.ToUpper(choice) == "A" {
			_, allLines := parseAuthorizedKeys()
			var newLines []string
			for _, l := range allLines {
				if !strings.Contains(l, TagPrefixB) {
					newLines = append(newLines, l)
				}
			}
			_ = writeAuthorizedKeys(newLines)
			fmt.Println(Green + Bold + "\n[✔] Successfully revoked ALL Workflow B host keys from authorized_keys!" + Reset)
			fmt.Println(Yellow + "All client machines with injected keys are now locked out." + Reset)
			return
		}

		var selectedIdx int
		_, err := fmt.Sscanf(choice, "%d", &selectedIdx)
		if err == nil && selectedIdx >= 1 && selectedIdx <= len(wfB) {
			targetKey := wfB[selectedIdx-1]
			_, allLines := parseAuthorizedKeys()
			var newLines []string
			for _, l := range allLines {
				if !strings.Contains(l, targetKey.Tag) {
					newLines = append(newLines, l)
				}
			}
			_ = writeAuthorizedKeys(newLines)
			fmt.Printf(Green+Bold+"\n[✔] Successfully revoked Workflow B key for alias '%s'!\n"+Reset, targetKey.TargetName)

			aliasName := targetKey.TargetName
			keyFileName := fmt.Sprintf("%s_key", aliasName)

			unixCleanup := fmt.Sprintf(
				`rm -f ~/.ssh/%s && sed -i '/Host %s$/,/IdentitiesOnly/d' ~/.ssh/config 2>/dev/null && echo "[✔] Key and Alias '%s' successfully purged from this machine!"`,
				keyFileName, aliasName, aliasName,
			)

			psCleanup := fmt.Sprintf(
				`$p="$HOME\.ssh"; Remove-Item -Path "$p\%s" -Force -ErrorAction SilentlyContinue; if(Test-Path "$p\config"){ $old=(Get-Content "$p\config" -Raw); $clean=($old -replace '(?s)Host %s\r?\n.+?IdentitiesOnly yes\r?\n?','').TrimEnd(); Set-Content "$p\config" $clean }; Write-Host "[✔] Key and Alias '%s' successfully purged from this machine!" -ForegroundColor Green`,
				keyFileName, aliasName, aliasName,
			)

			fmt.Printf("\033]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(unixCleanup)))

			fmt.Println(Blue + "\n==================================================================================" + Reset)
			fmt.Printf(Yellow+Bold+"OPTIONAL CLIENT CLEANUP COMMANDS FOR ALIAS '%s':\n"+Reset, aliasName)
			fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
			fmt.Println(Green + Bold + "Option 1: Run on Linux / macOS / MobaXterm / WSL / Git Bash:" + Reset)
			fmt.Println(Cyan + unixCleanup + Reset)
			fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
			fmt.Println(Green + Bold + "Option 2: Run on Windows PowerShell / Windows Terminal:" + Reset)
			fmt.Println(Yellow + psCleanup + Reset)
			fmt.Println(Blue + "==================================================================================" + Reset)
			return
		}
	}
}

func revokeAllWorkflowAAndB() {
	fmt.Println(Red + Bold + "\n=== REVOKE ALL WORKFLOW A & B KEYS (1-CLICK FLUSH) ===" + Reset)
	fmt.Println(Yellow + "This will purge all keys tagged with Workflow A and Workflow B signatures." + Reset)
	fmt.Println(Green + "Native system keys (not generated by this tool) will remain completely untouched." + Reset)

	confirm := transfer.ReadRealtimeInput("\nType 'REVOKE' to confirm flush: ")
	if confirm != "REVOKE" {
		fmt.Println(Yellow + "[!] Operation canceled." + Reset)
		return
	}

	_, allLines := parseAuthorizedKeys()
	var newLines []string
	purgedA, purgedB := 0, 0

	for _, l := range allLines {
		if strings.Contains(l, TagPrefixA) {
			purgedA++
		} else if strings.Contains(l, TagPrefixB) {
			purgedB++
		} else {
			newLines = append(newLines, l)
		}
	}

	_ = writeAuthorizedKeys(newLines)

	fmt.Println(Green + Bold + "\n[✔] Flush Operation Completed Successfully!" + Reset)
	fmt.Printf(Cyan+"  • Revoked Workflow A Keys : %d\n"+Reset, purgedA)
	fmt.Printf(Cyan+"  • Revoked Workflow B Keys : %d\n"+Reset, purgedB)
	fmt.Println(Green + "Your genuine/native system keys remain safe and intact." + Reset)
}

func setLocalLoginMode(mode string) {
	fmt.Println(Yellow + "\n[+] Applying configuration to SSH server..." + Reset)

	bakPath := fmt.Sprintf("/etc/ssh/sshd_config.bak.%d", time.Now().Unix())
	_ = runSudoCommand("cp", "/etc/ssh/sshd_config", bakPath)

	var pwdVal, kbdVal, pubVal string
	switch mode {
	case "allow-password":
		pwdVal, kbdVal, pubVal = "yes", "yes", "yes"
	case "key-only":
		pwdVal, kbdVal, pubVal = "no", "no", "yes"
	case "disable-all":
		pwdVal, kbdVal, pubVal = "no", "no", "no"
	}

	applySSHDirective("PasswordAuthentication", pwdVal)
	applySSHDirective("KbdInteractiveAuthentication", kbdVal)
	applySSHDirective("ChallengeResponseAuthentication", kbdVal)
	applySSHDirective("PubkeyAuthentication", pubVal)

	cleanDropInOverrides()

	if err := runSudoCommand("sshd", "-t"); err != nil {
		fmt.Println(Red + "[!] Configuration validation failed! Restoring backup..." + Reset)
		_ = runSudoCommand("cp", bakPath, "/etc/ssh/sshd_config")
		_ = runSudoCommand("sshd", "-t")
		fmt.Println(Red + "[!] Original configuration restored. Please review manually." + Reset)
		return
	}

	restartLocalSSH()
	fmt.Println(Green + Bold + "\n[✔] SSH authentication configuration applied and service restarted successfully!" + Reset)
}

func applySSHDirective(directive, value string) {
	cmdStr := fmt.Sprintf(
		`sed -i 's/^#*%s.*/%s %s/' /etc/ssh/sshd_config || echo "%s %s" >> /etc/ssh/sshd_config`,
		directive, directive, value, directive, value)
	_ = runSudoCommand("sh", "-c", cmdStr)
}

func cleanDropInOverrides() {
	dropInDir := "/etc/ssh/sshd_config.d"
	if _, err := os.Stat(dropInDir); err == nil {
		cmdStr := fmt.Sprintf(`sed -i 's/^#*PasswordAuthentication.*/# PasswordAuthentication managed/' %s/*.conf 2>/dev/null || true`, dropInDir)
		_ = runSudoCommand("sh", "-c", cmdStr)
	}
}

func getCurrentAuthSettings() (string, string) {
	pwdAuth := "default (yes)"
	pubAuth := "default (yes)"

	cmd := exec.Command("sudo", "grep", "^PasswordAuthentication", "/etc/ssh/sshd_config")
	if out, err := cmd.Output(); err == nil && len(out) > 0 {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			pwdAuth = parts[1]
		}
	}

	cmdPub := exec.Command("sudo", "grep", "^PubkeyAuthentication", "/etc/ssh/sshd_config")
	if out, err := cmdPub.Output(); err == nil && len(out) > 0 {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			pubAuth = parts[1]
		}
	}

	return pwdAuth, pubAuth
}

func configureLocalRootLogin(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "\n=== CONFIGURE ROOT LOGIN ON LOCAL SSH SERVER ===" + Reset)
		fmt.Println(Yellow + "This will modify /etc/ssh/sshd_config to set PermitRootLogin." + Reset)

		currentSetting := getCurrentPermitRootLogin()
		fmt.Printf("Current PermitRootLogin setting: %s\n", currentSetting)

		fmt.Println("\nSelect an action:")
		fmt.Println("  [1] yes – allow root login with password (least secure)")
		fmt.Println("  [2] prohibit-password – allow root login with key ONLY (recommended)")
		fmt.Println("  [3] no – completely disable root login")
		fmt.Println(Green + "  [4] Inject Your Public Key into Root (Enable Local Root SSH)" + Reset)
		fmt.Println(Red + "  [0] Back to previous menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Choice [0-4]: ")

		switch choice {
		case "1":
			setPermitRootLogin("yes")
		case "2":
			setPermitRootLogin("prohibit-password")
		case "3":
			setPermitRootLogin("no")
		case "4":
			injectPublicKeyToLocalRoot()
			pausePrompt()
			return
		case "0", "q", "Q":
			return
		}
	}
}

func injectPublicKeyToLocalRoot() {
	fmt.Println(Cyan + Bold + "\n=== INJECT PUBLIC KEY TO LOCAL ROOT ===" + Reset)
	fmt.Println(Yellow + "This will copy your public key to /root/.ssh/authorized_keys" + Reset)

	home := getUserHomePath()
	pubKeyPath := filepath.Join(home, ".ssh", "id_ed25519.pub")
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		pubKeyPath = filepath.Join(home, ".ssh", "id_rsa.pub")
	}
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		fmt.Println(Red + "[!] No SSH public key found! Generate one using Option 1 first." + Reset)
		return
	}

	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to read public key: %v\n"+Reset, err)
		return
	}
	pubKeyStr := strings.TrimSpace(string(pubKeyData))
	fmt.Println(Green + "    Found public key: " + filepath.Base(pubKeyPath) + Reset)

	cmd := exec.Command("sudo", "grep", "-F", pubKeyStr, "/root/.ssh/authorized_keys")
	if err := cmd.Run(); err == nil {
		fmt.Println(Green + "[✔] This public key is already present in /root/.ssh/authorized_keys." + Reset)
		return
	}

	fmt.Println(Yellow + "[+] Creating /root/.ssh directory..." + Reset)
	_ = runSudoCommand("mkdir", "-p", "/root/.ssh")
	_ = runSudoCommand("chmod", "700", "/root/.ssh")

	fmt.Println(Yellow + "[+] Appending public key to /root/.ssh/authorized_keys..." + Reset)
	cmdStr := fmt.Sprintf("echo '%s' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys", pubKeyStr)
	if err := runSudoCommand("sh", "-c", cmdStr); err != nil {
		fmt.Printf(Red+"[!] Failed to add public key: %v\n"+Reset, err)
		return
	}

	fmt.Println(Green + Bold + "\n[✔] Public key successfully injected to root!" + Reset)
	fmt.Println(Cyan + "Now you can do: ssh root@localhost or ssh root@" + getLocalIP() + Reset)
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}

func setPermitRootLogin(value string) {
	fmt.Printf(Yellow+"\n[+] Setting PermitRootLogin to '%s'...\n"+Reset, value)

	bakPath := fmt.Sprintf("/etc/ssh/sshd_config.bak.%d", time.Now().Unix())
	_ = runSudoCommand("cp", "/etc/ssh/sshd_config", bakPath)

	cmdStr := fmt.Sprintf(
		`sed -i 's/^#*PermitRootLogin.*/PermitRootLogin %s/' /etc/ssh/sshd_config || echo "PermitRootLogin %s" >> /etc/ssh/sshd_config`,
		value, value)
	if err := runSudoCommand("sh", "-c", cmdStr); err != nil {
		fmt.Printf(Red+"[!] Failed to update config: %v\n"+Reset, err)
		return
	}

	if err := runSudoCommand("sshd", "-t"); err != nil {
		fmt.Println(Red + "[!] Config validation failed! Restoring backup..." + Reset)
		_ = runSudoCommand("cp", bakPath, "/etc/ssh/sshd_config")
		_ = runSudoCommand("sshd", "-t")
		fmt.Println(Red + "[!] Restored backup. Please check manually." + Reset)
		return
	}

	restartLocalSSH()
	fmt.Println(Green + Bold + "\n[✔] PermitRootLogin set to '" + value + "' and SSH restarted!" + Reset)
}

func restartLocalSSH() {
	switch runtime.GOOS {
	case "linux":
		if err := runSudoCommand("systemctl", "restart", "sshd"); err != nil {
			_ = runSudoCommand("systemctl", "restart", "ssh")
		}
	case "darwin":
		_ = runSudoCommand("systemsetup", "-setremotelogin", "off")
		_ = runSudoCommand("systemsetup", "-setremotelogin", "on")
	case "windows":
		psCmd := `Restart-Service sshd -ErrorAction SilentlyContinue`
		_ = exec.Command("powershell", "-NoProfile", "-Command", psCmd).Run()
	}
}

func getCurrentPermitRootLogin() string {
	cmd := exec.Command("sudo", "grep", "^PermitRootLogin", "/etc/ssh/sshd_config")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	cmd2 := exec.Command("sudo", "grep", "^#PermitRootLogin", "/etc/ssh/sshd_config")
	out2, _ := cmd2.Output()
	if len(out2) > 0 {
		parts := strings.Fields(string(out2))
		if len(parts) >= 2 {
			return "default (" + parts[1] + ")"
		}
	}
	return "(not set)"
}

func fullAutoProvision(reader *bufio.Reader) {
	fmt.Println(Cyan + Bold + "\n=== FULL AUTO-PROVISION: INSTALL, KEYGEN, ENABLE, START ===" + Reset)

	switch runtime.GOOS {
	case "windows":
		provisionWindowsSSH()
	case "darwin":
		provisionMacOSSSH()
	default:
		provisionLinuxSSH()
	}

	home := getUserHomePath()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0700)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Println(Yellow + "[+] No user SSH key found. Generating new Ed25519 keypair..." + Reset)
		email := transfer.ReadRealtimeInput("Enter your email address for SSH key comment (or press Enter to skip): ")
		comment := "cross-ssh-local-host"
		if strings.TrimSpace(email) != "" {
			comment = email
		}
		genCmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", comment)
		genCmd.Stdout = os.Stdout
		genCmd.Stderr = os.Stderr
		if err := genCmd.Run(); err != nil {
			fmt.Printf(Red+"[!] Key generation error: %v\n"+Reset, err)
		} else {
			fmt.Printf(Green+"[✔] SSH key generated with comment: %s\n"+Reset, comment)
		}
	} else {
		fmt.Println(Green + "[✔] Existing user SSH key found. Skipping generation." + Reset)
	}

	fmt.Println(Yellow + "[+] Setting strict permissions on ~/.ssh..." + Reset)
	_ = os.Chmod(sshDir, 0700)
	_ = os.Chmod(keyPath, 0600)
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(pubPath); err == nil {
		_ = os.Chmod(pubPath, 0644)
	}
	authKeys := filepath.Join(sshDir, "authorized_keys")
	if _, err := os.Stat(authKeys); err == nil {
		_ = os.Chmod(authKeys, 0600)
	}

	addToAuth := transfer.ReadRealtimeInput("Add this public key to your own authorized_keys (for passwordless 'ssh localhost')? [Y/n]: ")
	if addToAuth == "" || strings.ToLower(addToAuth) == "y" {
		pubKeyData, err := os.ReadFile(keyPath + ".pub")
		if err == nil {
			f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err == nil {
				_, _ = f.Write(append(pubKeyData, '\n'))
				f.Close()
				fmt.Println(Green + "[✔] Public key added to authorized_keys." + Reset)
			}
		}
	}

	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		fmt.Println(Yellow + "[+] Auditing sshd_config..." + Reset)
		_ = runSudoCommand("sshd", "-t")
		if err := runSudoCommand("sshd", "-t"); err != nil {
			fmt.Println(Red + "[!] Config syntax error. Attempting to restore default config..." + Reset)
			_ = runSudoCommand("cp", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.bak")
		}
	}

	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		fmt.Println(Yellow + "[+] Enabling and starting SSH service..." + Reset)
		_ = runSudoCommand("systemctl", "unmask", "ssh")
		_ = runSudoCommand("systemctl", "enable", "--now", "ssh")
		_ = runSudoCommand("systemctl", "enable", "--now", "sshd")
		if err := runSudoCommand("systemctl", "is-active", "ssh"); err != nil {
			_ = runSudoCommand("service", "ssh", "restart")
		}
	}

	time.Sleep(1 * time.Second)
	if isLocalSSHActive() {
		fmt.Println(Green + Bold + "\n[✔] SUCCESS: SSH engine is fully provisioned and active!" + Reset)
	} else {
		fmt.Println(Yellow + "\n[!] SSH service not responding. You may need to check logs." + Reset)
	}
}

func repairAndReenable() {
	fmt.Println(Cyan + Bold + "\n=== REPAIR & RE-ENABLE SSH SERVICE ===" + Reset)

	if runtime.GOOS == "linux" {
		fmt.Println(Yellow + "[+] Regenerating host keys..." + Reset)
		_ = runSudoCommand("ssh-keygen", "-A")

		fmt.Println(Yellow + "[+] Validating sshd_config..." + Reset)
		if err := runSudoCommand("sshd", "-t"); err != nil {
			fmt.Println(Red + "[!] Config error. Restoring from backup if available..." + Reset)
			_ = runSudoCommand("cp", "/etc/ssh/sshd_config.bak", "/etc/ssh/sshd_config")
			_ = runSudoCommand("sshd", "-t")
		}

		fmt.Println(Yellow + "[+] Restarting SSH service..." + Reset)
		_ = runSudoCommand("systemctl", "unmask", "ssh")
		_ = runSudoCommand("systemctl", "restart", "ssh")
		_ = runSudoCommand("systemctl", "enable", "ssh")
		_ = runSudoCommand("systemctl", "restart", "sshd")
		_ = runSudoCommand("systemctl", "enable", "sshd")
	} else if runtime.GOOS == "darwin" {
		_ = runSudoCommand("systemsetup", "-setremotelogin", "on")
	} else if runtime.GOOS == "windows" {
		psCmd := `Restart-Service sshd -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Automatic`
		_ = exec.Command("powershell", "-NoProfile", "-Command", psCmd).Run()
	}

	time.Sleep(1 * time.Second)
	if isLocalSSHActive() {
		fmt.Println(Green + Bold + "[✔] SSH service repaired and running." + Reset)
	} else {
		fmt.Println(Red + "[!] Repair failed. Please check manually." + Reset)
	}
}

func completeUninstallAndPurge(reader *bufio.Reader) {
	fmt.Println(Red + Bold + "\n=== COMPLETE UNINSTALL & PURGE – DESTRUCTIVE OPERATION ===" + Reset)
	fmt.Println(Red + "This will:" + Reset)
	fmt.Println("  • Stop and disable the SSH service")
	if runtime.GOOS == "linux" {
		fmt.Println("  • Uninstall openssh-server package")
	} else if runtime.GOOS == "darwin" {
		fmt.Println("  • Disable Remote Login (macOS)")
	}
	fmt.Println("  • DELETE all user SSH keys (~/.ssh/id_*)")
	fmt.Println("  • DELETE all host keys (/etc/ssh/ssh_host_*) on Linux")
	fmt.Println("  • Remove ~/.ssh/authorized_keys and ~/.ssh/known_hosts")
	fmt.Println(Red + "This action is IRREVERSIBLE!" + Reset)

	confirm := transfer.ReadRealtimeInput("\nType 'PURGE' to confirm: ")
	if confirm != "PURGE" {
		fmt.Println(Yellow + "[!] Uninstall canceled." + Reset)
		return
	}

	fmt.Println(Yellow + "[+] Stopping and disabling SSH service..." + Reset)
	switch runtime.GOOS {
	case "windows":
		psCmd := `Stop-Service sshd -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Disabled`
		_ = exec.Command("powershell", "-NoProfile", "-Command", psCmd).Run()
	case "darwin":
		_ = runSudoCommand("systemsetup", "-setremotelogin", "off")
	default:
		_ = runSudoCommand("systemctl", "stop", "ssh")
		_ = runSudoCommand("systemctl", "disable", "ssh")
		_ = runSudoCommand("systemctl", "mask", "ssh")
		_ = runSudoCommand("systemctl", "stop", "sshd")
		_ = runSudoCommand("systemctl", "disable", "sshd")
		_ = runSudoCommand("systemctl", "mask", "sshd")
	}

	if runtime.GOOS == "linux" {
		fmt.Println(Yellow + "[+] Removing openssh-server package..." + Reset)
		if _, err := exec.LookPath("apt-get"); err == nil {
			_ = runSudoCommand("apt-get", "remove", "--purge", "-y", "openssh-server")
		} else if _, err := exec.LookPath("dnf"); err == nil {
			_ = runSudoCommand("dnf", "remove", "-y", "openssh-server")
		} else if _, err := exec.LookPath("pacman"); err == nil {
			_ = runSudoCommand("pacman", "-R", "--noconfirm", "openssh")
		}
		_ = runSudoCommand("rm", "-f", "/usr/local/sbin/sshd", "/usr/local/bin/sshd")
	}

	home := getUserHomePath()
	sshDir := filepath.Join(home, ".ssh")
	fmt.Println(Yellow + "[+] Deleting user SSH keys and configuration..." + Reset)
	if _, err := os.Stat(sshDir); err == nil {
		_ = os.RemoveAll(sshDir)
		fmt.Println(Green + "    Removed " + sshDir + Reset)
	}

	if runtime.GOOS == "linux" {
		fmt.Println(Yellow + "[+] Deleting host SSH keys..." + Reset)
		_ = runSudoCommand("rm", "-f", "/etc/ssh/ssh_host_*")
		_ = runSudoCommand("rm", "-f", "/etc/ssh/sshd_config")
		_ = runSudoCommand("rm", "-f", "/etc/ssh/ssh_config")
	}

	fmt.Println(Green + Bold + "\n[✔] SSH has been completely purged from this system." + Reset)
}

func showStatus() {
	fmt.Println(Cyan + Bold + "\n=== LOCAL SSH STATUS ===" + Reset)

	if isLocalSSHActive() {
		fmt.Println(Green + "  Listening on port 22: YES" + Reset)
	} else {
		fmt.Println(Red + "  Listening on port 22: NO" + Reset)
	}

	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "is-active", "ssh")
		out, _ := cmd.Output()
		status := strings.TrimSpace(string(out))
		if status != "" {
			fmt.Printf("  Service 'ssh' status: %s\n", status)
		}
		cmd2 := exec.Command("systemctl", "is-active", "sshd")
		out2, _ := cmd2.Output()
		status2 := strings.TrimSpace(string(out2))
		if status2 != "" {
			fmt.Printf("  Service 'sshd' status: %s\n", status2)
		}
	case "darwin":
		cmd := exec.Command("sudo", "systemsetup", "-getremotelogin")
		out, err := cmd.Output()
		if err == nil {
			output := strings.TrimSpace(string(out))
			fmt.Printf("  Remote Login (SSH): %s\n", output)
		}
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-Service -Name sshd | Select-Object -ExpandProperty Status")
		out, _ := cmd.Output()
		status := strings.TrimSpace(string(out))
		if status != "" {
			fmt.Printf("  Service 'sshd' status: %s\n", status)
		}
	}

	home := getUserHomePath()
	sshDir := filepath.Join(home, ".ssh")
	if _, err := os.Stat(sshDir); err == nil {
		files, _ := os.ReadDir(sshDir)
		fmt.Println("\n  User keys in ~/.ssh:")
		found := false
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "id_") && !strings.HasSuffix(f.Name(), ".pub") {
				fmt.Printf("    - %s\n", f.Name())
				found = true
			}
		}
		if !found {
			fmt.Println("    (none)")
		}
		if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err == nil {
			fmt.Println("  authorized_keys: PRESENT")
		} else {
			fmt.Println("  authorized_keys: NOT FOUND")
		}
	} else {
		fmt.Println("  No user SSH directory (~/.ssh) found.")
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		fmt.Println("\n  Root Login Setting:")
		current := getCurrentPermitRootLogin()
		fmt.Printf("    %s\n", current)

		pwdAuth, pubAuth := getCurrentAuthSettings()
		fmt.Println("\n  Authentication Settings:")
		fmt.Printf("    PasswordAuthentication: %s\n", pwdAuth)
		fmt.Printf("    PubkeyAuthentication:   %s\n", pubAuth)
	}
}

func checkLocalSSHStatus() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-Service -Name sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
		out, err := cmd.Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			return Green + Bold + "[ACTIVE & RUNNING]" + Reset
		}
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return Yellow + Bold + "[STOPPED / DISABLED]" + Reset
		}
		return Red + Bold + "[NOT INSTALLED]" + Reset

	case "darwin":
		cmd := exec.Command("sudo", "systemsetup", "-getremotelogin")
		out, err := cmd.Output()
		if err == nil {
			output := strings.TrimSpace(string(out))
			if strings.Contains(output, "On") {
				return Green + Bold + "[ACTIVE & RUNNING]" + Reset
			}
			return Yellow + Bold + "[STOPPED / DISABLED]" + Reset
		}
		_, err = exec.LookPath("sshd")
		if err == nil {
			return Yellow + Bold + "[STOPPED / INACTIVE]" + Reset
		}
		return Red + Bold + "[NOT INSTALLED]" + Reset

	default:
		cmd := exec.Command("systemctl", "is-active", "sshd")
		out, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return Green + Bold + "[ACTIVE & RUNNING]" + Reset
		}
		cmd = exec.Command("systemctl", "is-active", "ssh")
		out, err = cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return Green + Bold + "[ACTIVE & RUNNING]" + Reset
		}
		_, err = exec.LookPath("sshd")
		if err == nil {
			return Yellow + Bold + "[STOPPED / INACTIVE]" + Reset
		}
		return Red + Bold + "[NOT INSTALLED]" + Reset
	}
}

func provisionMacOSSSH() {
	fmt.Println(Yellow + "[1/2] Checking macOS SSH (Remote Login) status..." + Reset)
	cmd := exec.Command("sudo", "systemsetup", "-setremotelogin", "on")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(Red+"[!] Failed to enable Remote Login: %v\n", err)
		return
	}
	fmt.Println(Green + "[✔] Remote Login (SSH) enabled on macOS." + Reset)
	fmt.Println(Yellow + "[2/2] Firewall will auto-configure – no action needed." + Reset)
}

func provisionLinuxSSH() {
	fmt.Println(Yellow + "[1/4] Checking Linux SSH Server installation..." + Reset)

	_, err := exec.LookPath("sshd")
	if err != nil {
		fmt.Println(Yellow + "[!] SSHD binary missing. Attempting package manager installation..." + Reset)
		installed := false

		if _, err := exec.LookPath("apt-get"); err == nil {
			fmt.Println(Cyan + "Running: sudo apt-get update && sudo apt-get install -y openssh-server" + Reset)
			cmd := exec.Command("sudo", "apt-get", "update")
			_ = cmd.Run()
			cmd2 := exec.Command("sudo", "apt-get", "install", "-y", "openssh-server")
			cmd2.Stdin, cmd2.Stdout, cmd2.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := cmd2.Run(); err == nil {
				installed = true
			}
		}
		if !installed {
			if _, err := exec.LookPath("dnf"); err == nil {
				fmt.Println(Cyan + "Running: sudo dnf install -y openssh-server" + Reset)
				cmd := exec.Command("sudo", "dnf", "install", "-y", "openssh-server")
				cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := cmd.Run(); err == nil {
					installed = true
				}
			}
		}
		if !installed {
			if _, err := exec.LookPath("pacman"); err == nil {
				fmt.Println(Cyan + "Running: sudo pacman -S --noconfirm openssh" + Reset)
				cmd := exec.Command("sudo", "pacman", "-S", "--noconfirm", "openssh")
				cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := cmd.Run(); err == nil {
					installed = true
				}
			}
		}
		if !installed {
			fmt.Println(Yellow + "[!] Package managers failed. Downloading static OpenSSH release..." + Reset)
			if err := downloadStaticLinuxSSH(); err != nil {
				fmt.Printf(Red+"[!] Static SSH installation failed: %v\n"+Reset, err)
				return
			}
		}
	}

	fmt.Println(Yellow + "[2/4] Generating SSH Host Keys..." + Reset)
	_ = exec.Command("sudo", "ssh-keygen", "-A").Run()

	fmt.Println(Yellow + "[3/4] Enabling and starting SSH service via systemd..." + Reset)
	_ = exec.Command("sudo", "systemctl", "enable", "sshd").Run()
	_ = exec.Command("sudo", "systemctl", "start", "sshd").Run()
	_ = exec.Command("sudo", "systemctl", "enable", "ssh").Run()
	_ = exec.Command("sudo", "systemctl", "start", "ssh").Run()

	fmt.Println(Yellow + "[4/4] Opening Port 22 in Firewall..." + Reset)
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("sudo", "ufw", "allow", "22/tcp").Run()
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		_ = exec.Command("sudo", "firewall-cmd", "--add-port=22/tcp", "--permanent").Run()
		_ = exec.Command("sudo", "firewall-cmd", "--reload").Run()
	}

	fmt.Println(Green + Bold + "\n[SUCCESS] Local SSH Server Enabled & Active on Port 22!" + Reset)
}

func provisionWindowsSSH() {
	fmt.Println(Yellow + "[1/3] Enabling OpenSSH Server capability via PowerShell..." + Reset)

	psCmd := `
	if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
		Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
	}
	Set-Service -Name sshd -StartupType Automatic
	Start-Service sshd
	New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue
	`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(Yellow + "[!] Windows Capability failed. Downloading Win32-OpenSSH release..." + Reset)
		downloadWin32OpenSSH()
	} else {
		fmt.Println(Green + Bold + "\n[SUCCESS] Windows OpenSSH Server Enabled & Running!" + Reset)
	}
}

func downloadStaticLinuxSSH() error {
	url := "https://github.com/sagemathinc/static-openssh-binaries/releases/download/OpenSSH_9.9p2/openssh-static-x86_64-small-OpenSSH_9.9p2.tar.gz"
	tarPath := "/tmp/openssh-static.tar.gz"

	out, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("failed to download static SSH binary release")
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	_ = exec.Command("sudo", "tar", "-xzf", tarPath, "-C", "/usr/local/bin").Run()
	_ = os.Remove(tarPath)
	return nil
}

func downloadWin32OpenSSH() {
	url := "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64.zip"
	psCmd := fmt.Sprintf(`
	$zip = "$env:TEMP\OpenSSH-Win64.zip"
	Invoke-WebRequest -Uri '%s' -OutFile $zip
	Expand-Archive -Path $zip -DestinationPath "$env:ProgramFiles" -Force
	& "$env:ProgramFiles\OpenSSH-Win64\install-sshd.ps1"
	Set-Service -Name sshd -StartupType Automatic
	Start-Service sshd
	`, url)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = cmd.Run()
}

func isLocalSSHActive() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func runSudoCommand(args ...string) error {
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return to SSH automation menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}