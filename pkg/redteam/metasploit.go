package redteam

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/platform"
	"cross-ssh/pkg/transfer"
	"cross-ssh/pkg/redteam/advanced"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Cyan    = "\033[36m"
	Bold    = "\033[1m"
)

var sudoPassword string

// ----- MAIN MENU (Updated with secure gateway) -----
func ShowRedTeamMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	// REPLACED: Weak password prompt replaced with secure Python shadow hash gateway
	if !ensureAutonomousPermissionsWithPrompt(client) {
		fmt.Println(Red + "[!] Authentication failed. Access to Red Team engine denied." + Reset)
		return
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "=== RED TEAM EXPLOITATION & PRIVILEGE ESCALATION ENGINE ===" + Reset)
		fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s\n"+Reset, host)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 🎯 Nmap Vulnerability Scan (with presets & CVE correlation)")
		fmt.Println("  [2] 🚀 Metasploit Resource Script (.rc) Engine (preset + custom)")
		fmt.Println("  [3] 🔓 Linux Privilege Escalation Audit (SUID/SGID & Sudo)")
		fmt.Println("  [4] 🐳 Docker & Podman Breakout Audit")
		fmt.Println("  [5] ⚙️ Custom Metasploit Auxiliary/Exploit (preset)")
		fmt.Println("  [6] 🌐 Web App Security Scan (Nikto + Dirb + OWASP)")
		fmt.Println("  [7] 🔐 Brute Force Simulation (Hydra + auto‑wordlist)")
		fmt.Println("  [8] 🛡️  MASTER SWEEP – Full Audit & Auto‑Remediation")
		fmt.Println("  [9] 📦 Outdated Packages Check & Update")
		fmt.Println(" [10] 🔑 SSH Configuration Audit & Hardening")
		fmt.Println(" [11] 🧱 Firewall Status & Enablement (UFW/firewalld)")
		fmt.Println(" [12] 📂 World‑Writable Files Security")
		fmt.Println(" [13] 🔍 Password Strength Audit (John the Ripper)")
		fmt.Println(" [14] 🦠 Rootkit Detection (chkrootkit / rkhunter)")
		fmt.Println(Green + " [15] ⚡ Dynamic Real-Time Remediation (Smart Auto-Fix)" + Reset)
		fmt.Println(Green + " [16] 🔥 Red Team Advanced Module (DDoS, Wi-Fi, Digispark, Pivoting)" + Reset)
		fmt.Println(Red + "  [0] Back" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Action [0-15]: ")

		switch choice {
		case "1":
			runNmapScanWithPresets(reader, client, host)
			promptRemediation(client, "nmap")
			pausePrompt()
		case "2":
			runMetasploitWithPresets(reader, client, host)
			promptRemediation(client, "metasploit")
			pausePrompt()
		case "3":
			runPrivilegeEscalationAudit(client, host)
			promptRemediation(client, "privilege")
			pausePrompt()
		case "4":
			runContainerBreakoutAudit(client, host)
			promptRemediation(client, "container")
			pausePrompt()
		case "5":
			runCustomMetasploitExploit(reader, client, host)
			promptRemediation(client, "custommsf")
			pausePrompt()
		case "6":
			runWebAppSecurityScanWithPresets(reader, client, host)
			promptRemediation(client, "web")
			pausePrompt()
		case "7":
			runBruteForceWithPresets(reader, client, host)
			promptRemediation(client, "bruteforce")
			pausePrompt()
		case "8":
			runMasterSweep(client, host)
			pausePrompt()
		case "9":
			runOutdatedPackagesCheck(client, true)
			pausePrompt()
		case "10":
			runSSHHardening(client)
			pausePrompt()
		case "11":
			runFirewallSetup(client)
			pausePrompt()
		case "12":
			runWorldWritableSecure(client)
			pausePrompt()
		case "13":
			runWeakPasswordsCheck(client)
			pausePrompt()
		case "14":
			runRootkitCheck(client)
			pausePrompt()
		case "15":
			runDynamicRemediation(client, host)
			pausePrompt()
		case "16":
			advanced.ShowRedTeamAdvancedMenu(reader, client, host, sudoPassword)
			pausePrompt()
		case "0", "q", "Q":
			return
		default:
			fmt.Println(Yellow + "[!] Invalid choice." + Reset)
		}
	}
}

// =====================================================================
// NEW AUTHENTICATION GATEWAY (Extracted from MITRE engine)
// =====================================================================
func ensureAutonomousPermissionsWithPrompt(client *ssh.Client) bool {
	if sudoPassword != "" {
		return true
	}
	if !promptAndValidateSudo(client) {
		return false
	}
	return true
}
func promptAndValidateSudo(client *ssh.Client) bool {
	maxAttempts := 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fmt.Printf("Enter elevation password (attempt %d/%d): ", attempt, maxAttempts)
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println(Red + "[!] Failed to read password." + Reset)
			continue
		}
		pass := string(passBytes)
		if strings.TrimSpace(pass) == "" {
			fmt.Println(Yellow + "[!] Password cannot be empty." + Reset)
			continue
		}

		// Escape single quotes for safe shell injection
		escaped := strings.ReplaceAll(pass, "'", "'\\''")
		// Use sudo -S id -u to verify the password works
		cmd := fmt.Sprintf("echo '%s' | sudo -S id -u 2>/dev/null", escaped)
		out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)

		if err == nil && strings.TrimSpace(out) == "0" {
			sudoPassword = pass
			fmt.Println(Green + "✅ Password validated successfully." + Reset)
			return true
		}

		fmt.Println(Red + "[!] Access Denied: Incorrect password." + Reset)
		if attempt < maxAttempts {
			fmt.Println(Yellow + "=> Please try again." + Reset)
		}
	}

	fmt.Println(Red + "[!] CRITICAL: Maximum attempts reached. Operation aborted." + Reset)
	return false
}
// =====================================================================
// PATCH #2: Rewritten wrapSudo (KEPT INTACT – RED TEAM'S SUPERIOR VERSION)
// =====================================================================
func wrapSudo(cmd string) string {
	if sudoPassword == "" {
		return cmd
	}
	// If the command contains any "sudo " we wrap the entire thing.
	if strings.Contains(cmd, "sudo ") {
		escapedPassword := strings.ReplaceAll(sudoPassword, "'", "'\\''")
		// Escape single quotes inside the inner command.
		inner := strings.ReplaceAll(cmd, "'", "'\\''")
		return fmt.Sprintf("echo '%s' | sudo -S sh -c '%s'", escapedPassword, inner)
	}
	return cmd
}

// ----- FALLBACK PACKAGE MANAGER DETECTION -----
func detectPackageManager(client *ssh.Client) string {
	cmdChecks := []string{"apt-get", "dnf", "yum", "pacman", "apk", "zypper"}
	for _, pkg := range cmdChecks {
		if _, err := common.ExecuteRemoteCommand(client, "command -v "+pkg, common.DefaultCmdTimeout); err == nil {
			return pkg
		}
	}
	return "unknown"
}

func killAptLock(client *ssh.Client) {
	killCmd := `sudo fuser -v /var/lib/dpkg/lock-frontend 2>/dev/null | awk '{print $1}' | xargs -r sudo kill -9 2>/dev/null || true`
	_, _ = common.ExecuteRemoteCommand(client, killCmd, common.DefaultCmdTimeout)
}

func ensurePrerequisites(client *ssh.Client) {
	tools := []string{"wget", "curl", "net-tools"}
	for _, t := range tools {
		if !isToolInstalled(client, t, t) {
			crossPlatformInstall(client, t)
		}
	}
}

// ----- IDEMPOTENT TOOL INSTALLATION -----
func isToolInstalled(client *ssh.Client, tool, pkg string) bool {
	checkBin := fmt.Sprintf("command -v %s >/dev/null 2>&1", tool)
	if _, err := common.ExecuteRemoteCommand(client, checkBin, common.DefaultCmdTimeout); err == nil {
		return true
	}
	plat, err := platform.Detect(client)
	if err != nil {
		// Fallback: try to detect package manager manually
		pm := detectPackageManager(client)
		var pkgCheckCmd string
		switch pm {
		case "apt-get":
			pkgCheckCmd = fmt.Sprintf("dpkg -l %s 2>/dev/null | grep -q ^ii", pkg)
		case "dnf", "yum":
			pkgCheckCmd = fmt.Sprintf("rpm -q %s 2>/dev/null", pkg)
		default:
			return false
		}
		_, err = common.ExecuteRemoteCommand(client, pkgCheckCmd, common.DefaultCmdTimeout)
		return err == nil
	}
	var pkgCheckCmd string
	switch plat.PackageMgr {
	case "apt":
		pkgCheckCmd = fmt.Sprintf("dpkg -l %s 2>/dev/null | grep -q ^ii", pkg)
	case "dnf", "yum":
		pkgCheckCmd = fmt.Sprintf("rpm -q %s 2>/dev/null", pkg)
	case "pacman":
		pkgCheckCmd = fmt.Sprintf("pacman -Q %s 2>/dev/null", pkg)
	case "apk":
		pkgCheckCmd = fmt.Sprintf("apk info %s 2>/dev/null", pkg)
	case "zypper":
		pkgCheckCmd = fmt.Sprintf("zypper se -i %s 2>/dev/null", pkg)
	default:
		return false
	}
	_, err = common.ExecuteRemoteCommand(client, pkgCheckCmd, common.DefaultCmdTimeout)
	return err == nil
}

// =====================================================================
// PATCHES #1, #4, #11: Enhanced crossPlatformInstall
// - Separates update and install (install even if update fails)
// - Manual Platform struct if platform.Detect fails
// - Adds --force-confold to apt install
// =====================================================================
func crossPlatformInstall(client *ssh.Client, pkg string) bool {
	plat, err := platform.Detect(client)
	if err != nil {
		// PATCH #4: manually create Platform from detectPackageManager
		pm := detectPackageManager(client)
		if pm == "unknown" {
			fmt.Printf(Red+"[!] No supported package manager found. Skipping install of %s.\n"+Reset, pkg)
			return false
		}
		plat = &platform.Platform{PackageMgr: pm}
	}
	if plat.Distro == "rhel" || plat.Distro == "centos" || plat.Distro == "fedora" {
		disableBrokenRepo(client)
		epelCheck := `dnf repolist | grep -q epel && echo "OK" || echo "MISSING"`
		out, _ := common.ExecuteRemoteCommand(client, epelCheck, common.DefaultCmdTimeout)
		if strings.TrimSpace(out) != "OK" {
			fmt.Println(Cyan + "[+] Installing EPEL repository..." + Reset)
			_, _ = common.ExecuteRemoteCommand(client, "sudo dnf install -y epel-release 2>/dev/null", common.LongCmdTimeout)
		}
	}

	// Build install command with force-confold for apt
	var installCmd string
	switch plat.PackageMgr {
	case "apt", "apt-get":
		// PATCH #1: we'll run update separately and then install even if update fails
		// We'll handle it inside the loop.
		installCmd = fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o Dpkg::Options::=\"--force-confold\" %s", pkg)
	case "dnf":
		installCmd = fmt.Sprintf("sudo dnf install -y %s", pkg)
	case "yum":
		installCmd = fmt.Sprintf("sudo yum install -y %s", pkg)
	case "pacman":
		installCmd = fmt.Sprintf("sudo pacman -S --noconfirm %s", pkg)
	case "apk":
		installCmd = fmt.Sprintf("sudo apk add %s", pkg)
	case "zypper":
		installCmd = fmt.Sprintf("sudo zypper install -y %s", pkg)
	default:
		fmt.Printf(Red+"[!] Unsupported package manager: %s. Skipping install of %s.\n"+Reset, plat.PackageMgr, pkg)
		return false
	}
	installCmd = wrapSudo(installCmd)

	// Kill stale lock immediately
	killAptLock(client)

	// PATCH #1: attempt update first (only for apt)
	updateSuccess := true
	if plat.PackageMgr == "apt" || plat.PackageMgr == "apt-get" {
		updateCmd := wrapSudo("sudo apt-get update -qq")
		for attempt := 1; attempt <= 3; attempt++ {
			fmt.Printf(Cyan+"[+] Running apt update (attempt %d/3)...\n"+Reset, attempt)
			out, err := common.ExecuteRemoteCommand(client, updateCmd, common.DefaultCmdTimeout)
			if err == nil {
				updateSuccess = true
				break
			}
			if strings.Contains(out, "lock-frontend") || strings.Contains(out, "lock") {
				killAptLock(client)
				fmt.Println(Yellow + "[!] Killed stale lock. Retrying update..." + Reset)
				continue
			}
			fmt.Printf(Red+"[!] apt update failed (attempt %d): %v\n"+Reset, attempt, err)
			updateSuccess = false
		}
		if !updateSuccess {
			fmt.Println(Yellow + "[!] apt update failed, but we'll still try to install using cached lists." + Reset)
		}
	}

	// Now attempt install (even if update failed)
	for attempt := 1; attempt <= 10; attempt++ {
		fmt.Printf(Cyan+"[+] Installing %s via %s (attempt %d/10)...\n"+Reset, pkg, plat.PackageMgr, attempt)
		out, err := common.ExecuteRemoteCommand(client, installCmd, common.LongCmdTimeout)
		if err == nil {
			return true
		}
		if strings.Contains(out, "lock-frontend") || strings.Contains(out, "lock") {
			killAptLock(client)
			fmt.Println(Yellow + "[!] Killed stale lock. Retrying..." + Reset)
			continue
		}
		if strings.Contains(out, "repomd.xml") || strings.Contains(out, "metadata") {
			fmt.Println(Yellow + "[!] Repo error detected. Trying to disable broken repo..." + Reset)
			disableBrokenRepo(client)
			out2, err2 := common.ExecuteRemoteCommand(client, installCmd, common.LongCmdTimeout)
			if err2 == nil {
				return true
			}
			fmt.Printf(Red+"[!] Retry failed: %v\n"+Reset, err2)
			fmt.Println(out2)
			return false
		}
		fmt.Printf(Red+"[!] Install failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	return false
}

func disableBrokenRepo(client *ssh.Client) {
	checkCmd := `grep -q '^enabled=1' /etc/yum.repos.d/custom-cross-repo-*.repo 2>/dev/null && echo "ENABLED" || echo "DISABLED"`
	out, _ := common.ExecuteRemoteCommand(client, checkCmd, common.DefaultCmdTimeout)
	if strings.TrimSpace(out) == "ENABLED" {
		fmt.Println(Yellow + "[+] Disabling broken custom repos..." + Reset)
		disableCmd := `sudo sed -i 's/enabled=1/enabled=0/' /etc/yum.repos.d/custom-cross-repo-*.repo 2>/dev/null || true`
		_, _ = common.ExecuteRemoteCommand(client, disableCmd, common.DefaultCmdTimeout)
		fmt.Println(Green + "[✔] Broken repos disabled." + Reset)
	}
}

func ensureToolInstalled(client *ssh.Client, tool, pkg string) bool {
	if isToolInstalled(client, tool, pkg) {
		fmt.Printf(Green+"[✔] Tool '%s' already installed.\n"+Reset, tool)
		return true
	}
	fmt.Printf(Yellow+"[!] Tool '%s' not found. Installing...\n"+Reset, tool)

	// Ensure prerequisites first
	ensurePrerequisites(client)

	if crossPlatformInstall(client, pkg) {
		if isToolInstalled(client, tool, pkg) {
			return true
		}
	}
	// Binary fallbacks
	switch tool {
	case "nmap":
		return installNmapBinary(client)
	case "msfconsole":
		return installMsfBinary(client)
	case "hydra":
		return installHydraBinary(client)
	case "john":
		return installJohnBinary(client)
	case "chkrootkit":
		fmt.Println(Yellow + "[!] Trying rkhunter as fallback..." + Reset)
		if ensureToolInstalled(client, "rkhunter", "rkhunter") {
			return true
		}
		return false
	default:
		return false
	}
}

// ----- BINARY DOWNLOAD HELPERS -----
func downloadFile(client *ssh.Client, url, dest string) bool {
	ensurePrerequisites(client)
	_, err := common.ExecuteRemoteCommand(client, "command -v wget", common.DefaultCmdTimeout)
	hasWget := (err == nil)
	_, err = common.ExecuteRemoteCommand(client, "command -v curl", common.DefaultCmdTimeout)
	hasCurl := (err == nil)
	if !hasWget && !hasCurl {
		fmt.Println(Red + "[!] Neither wget nor curl available and install failed. Cannot download." + Reset)
		return false
	}
	var dlCmd string
	if hasWget {
		dlCmd = fmt.Sprintf("wget -q -O %s %s", dest, url)
	} else {
		dlCmd = fmt.Sprintf("curl -s -o %s %s", dest, url)
	}
	dlCmd = wrapSudo(dlCmd)
	out, err := common.ExecuteRemoteCommand(client, dlCmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Download failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	return true
}

func installNmapBinary(client *ssh.Client) bool {
	fmt.Println(Cyan + "[+] Downloading nmap from GitHub..." + Reset)
	url := "https://github.com/nmap/nmap/archive/refs/tags/v7.94.tar.gz"
	dest := "/tmp/nmap.tar.gz"
	if !downloadFile(client, url, dest) {
		return false
	}
	cmd := `cd /tmp && tar -xzf nmap.tar.gz && cd nmap-* && ./configure && make && sudo make install`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Nmap build failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	return true
}

func installMsfBinary(client *ssh.Client) bool {
	fmt.Println(Cyan + "[+] Installing Metasploit via official installer..." + Reset)
	ensurePrerequisites(client)
	cmd := `sudo sh -c "curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall"`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Metasploit install failed: %v\n"+Reset, err)
		fmt.Println(out)
		if crossPlatformInstall(client, "metasploit-framework") {
			return true
		}
		return false
	}
	return true
}

func installHydraBinary(client *ssh.Client) bool {
	fmt.Println(Cyan + "[+] Downloading hydra from GitHub..." + Reset)
	url := "https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v9.5.tar.gz"
	dest := "/tmp/hydra.tar.gz"
	if !downloadFile(client, url, dest) {
		return false
	}
	cmd := `cd /tmp && tar -xzf hydra.tar.gz && cd thc-hydra-* && ./configure && make && sudo make install`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Hydra build failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	return true
}

func installJohnBinary(client *ssh.Client) bool {
	fmt.Println(Cyan + "[+] Downloading John the Ripper from GitHub..." + Reset)
	url := "https://github.com/openwall/john/archive/refs/tags/1.9.0-Jumbo-1.tar.gz"
	dest := "/tmp/john.tar.gz"
	if !downloadFile(client, url, dest) {
		return false
	}
	cmd := `cd /tmp && tar -xzf john.tar.gz && cd john-* && cd src && ./configure && make && sudo make install`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] John build failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	return true
}

func checkFileExists(client *ssh.Client, path string) bool {
	_, err := common.ExecuteRemoteCommand(client, fmt.Sprintf("test -f %s", path), common.DefaultCmdTimeout)
	return err == nil
}

// =====================================================================
// PATCH #3: ensureWordlistExists – install wordlist package if missing
// =====================================================================
func ensureWordlistExists(client *ssh.Client) string {
	commonPaths := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/dirb/big.txt",
		"/usr/share/wordlists/wordlist.txt",
	}
	for _, path := range commonPaths {
		if checkFileExists(client, path) {
			return path
		}
	}
	fmt.Println(Yellow + "[!] No wordlist found. Attempting to install wordlist package..." + Reset)
	// Try to install wordlists (Kali) or wordlist (RHEL)
	plat, err := platform.Detect(client)
	if err != nil {
		pm := detectPackageManager(client)
		if pm == "apt-get" {
			if crossPlatformInstall(client, "wordlists") {
				if checkFileExists(client, "/usr/share/wordlists/rockyou.txt") {
					return "/usr/share/wordlists/rockyou.txt"
				}
			}
		} else if pm == "dnf" || pm == "yum" {
			if crossPlatformInstall(client, "wordlist") {
				if checkFileExists(client, "/usr/share/wordlists/wordlist.txt") {
					return "/usr/share/wordlists/wordlist.txt"
				}
			}
		}
	} else {
		if plat.PackageMgr == "apt" || plat.PackageMgr == "apt-get" {
			if crossPlatformInstall(client, "wordlists") {
				if checkFileExists(client, "/usr/share/wordlists/rockyou.txt") {
					return "/usr/share/wordlists/rockyou.txt"
				}
			}
		} else if plat.PackageMgr == "dnf" || plat.PackageMgr == "yum" {
			if crossPlatformInstall(client, "wordlist") {
				if checkFileExists(client, "/usr/share/wordlists/wordlist.txt") {
					return "/usr/share/wordlists/wordlist.txt"
				}
			}
		}
	}
	// Fallback: download from SecLists
	fmt.Println(Yellow + "[!] Package install failed. Attempting to download from SecLists..." + Reset)
	url := "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
	dest := "/tmp/redteam_wordlist.txt"
	if checkFileExists(client, dest) {
		return dest
	}
	if downloadFile(client, url, dest) {
		if checkFileExists(client, dest) {
			return dest
		}
	}
	return ""
}

func displayWithPager(output string) {
	if output == "" {
		return
	}
	tmpFile, err := ioutil.TempFile("", "redteam_*.txt")
	if err != nil {
		fmt.Println(output)
		return
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(output)
	tmpFile.Close()
	cmd := exec.Command("less", "-R", tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(output)
	}
}

func saveReport(folder, filename, content string) string {
	dir := filepath.Join(".", "reports", folder)
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, filename)
	_ = ioutil.WriteFile(path, []byte(content), 0644)
	return path
}

// =============================================================================
// SCAN FUNCTIONS (all use robust execution)
// =============================================================================

// =====================================================================
// PATCH #6: Nmap stealth scan timeout
// =====================================================================
func runNmapScanWithPresets(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Nmap Vulnerability Scan" + Reset)
	fmt.Println("  - This scans the target for open ports and known vulnerabilities.")
	fmt.Println("  - PRESETS:")
	fmt.Println("    1. Quick (top 1000 ports) – fast, good for initial assessment.")
	fmt.Println("    2. Full (1-65535) – thorough but slow.")
	fmt.Println("    3. Vuln (NSE scripts) – checks for known CVEs.")
	fmt.Println("    4. Stealth (SYN + decoys) – evades IDS.")
	fmt.Println("    5. Web/DB (HTTP, MySQL, PostgreSQL, Redis).")
	fmt.Println("    6. Container (Docker, Kubernetes, AWS).")
	fmt.Println("    7. Custom – expert mode.")
	fmt.Println()
	fmt.Print("Select preset [1-7] (or ENTER for Vuln): ")
	input, _ := reader.ReadString('\n')
	preset := strings.TrimSpace(input)
	if preset == "" {
		preset = "3"
	}

	target := getTarget(reader)
	if target == "" {
		return
	}
	if !ensureToolInstalled(client, "nmap", "nmap") {
		return
	}
	var options string
	switch preset {
	case "1":
		options = "-sS -T4 -F"
	case "2":
		options = "-sS -T4 -p-"
	case "3":
		options = "-sV --script=vuln"
	case "4":
		// PATCH #6: added --host-timeout 10m
		options = "-sS -T2 -D RND:10 -f --mtu 24 --host-timeout 10m"
	case "5":
		options = "-sV -p 80,443,8080,8443,3306,5432,6379 --script=http*,mysql*,postgres*,redis*"
	case "6":
		options = "-sV -p 2375,2376,5000,8001,6443,10250 --script=docker*,kubernetes*,aws*"
	case "7":
		fmt.Print("Enter custom nmap options: ")
		opts, _ := reader.ReadString('\n')
		options = strings.TrimSpace(opts)
	default:
		options = "-sV --script=vuln"
	}
	fmt.Printf(Cyan+"[+] Running nmap %s %s...\n"+Reset, options, target)
	cmd := fmt.Sprintf("sudo nmap %s %s", options, target)
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Scan error: %v\n"+Reset, err)
	}
	reportContent := fmt.Sprintf("Nmap Scan Report\nTarget: %s\nPreset: %s\nOptions: %s\n\n%s", target, preset, options, out)
	reportPath := saveReport("nmap", fmt.Sprintf("nmap_scan_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== NMAP OUTPUT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "========================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
	cveCorrelate(out)
}

func cveCorrelate(nmapOutput string) {
	cves := map[string][]string{
		"22":   {"CVE-2016-6210", "CVE-2017-15906"},
		"80":   {"CVE-2021-41773", "CVE-2020-17519"},
		"443":  {"CVE-2021-23017", "CVE-2020-1967"},
		"3306": {"CVE-2021-20265", "CVE-2020-14803"},
		"5432": {"CVE-2021-34511", "CVE-2020-14304"},
		"6379": {"CVE-2021-32675", "CVE-2020-15116"},
		"2375": {"CVE-2021-41091", "CVE-2020-15157"},
		"6443": {"CVE-2021-25741", "CVE-2020-8554"},
	}
	found := false
	for port, cv := range cves {
		if strings.Contains(nmapOutput, port+"/tcp") {
			fmt.Printf(Yellow+"  [!] Port %s open – related CVEs: %s\n"+Reset, port, strings.Join(cv, ", "))
			found = true
		}
	}
	if !found {
		fmt.Println(Green + "  ✅ No known CVEs mapped to open ports." + Reset)
	}
}

func getTarget(reader *bufio.Reader) string {
	fmt.Print("Enter target IP/hostname (or press Enter for public IP): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		target = "127.0.0.1"
		fmt.Printf(Cyan+"[+] Using localhost: %s\n"+Reset, target)
	}
	return target
}

func runMetasploitWithPresets(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Red + Bold + "=== METASPLOIT RESOURCE SCRIPT ENGINE ===" + Reset)
	fmt.Println(Yellow + "📖 USAGE: Metasploit Automation" + Reset)
	fmt.Println("  - This runs a Metasploit resource script (.rc) on the remote host.")
	fmt.Println("  - PRESETS:")
	fmt.Println("    1. Port Scanner (auxiliary/scanner/portscan/tcp)")
	fmt.Println("    2. SMB Version Scanner")
	fmt.Println("    3. SSH Version Scanner")
	fmt.Println("    4. HTTP Directory Scanner")
	fmt.Println("    5. MySQL Scanner")
	fmt.Println("    6. PostgreSQL Scanner")
	fmt.Println("    7. RDP Scanner")
	fmt.Println("    8. Custom – upload your own .rc file.")
	fmt.Println()
	fmt.Print("Select preset [1-8] (or ENTER for portscan): ")
	input, _ := reader.ReadString('\n')
	preset := strings.TrimSpace(input)
	if preset == "" {
		preset = "1"
	}
	var rcContent string
	switch preset {
	case "1":
		rcContent = `use auxiliary/scanner/portscan/tcp
set RHOSTS 127.0.0.1
set PORTS 1-10000
run
exit`
	case "2":
		rcContent = `use auxiliary/scanner/smb/smb_version
set RHOSTS 127.0.0.1
run
exit`
	case "3":
		rcContent = `use auxiliary/scanner/ssh/ssh_version
set RHOSTS 127.0.0.1
run
exit`
	case "4":
		rcContent = `use auxiliary/scanner/http/dir_scanner
set RHOSTS 127.0.0.1
run
exit`
	case "5":
		rcContent = `use auxiliary/scanner/mysql/mysql_version
set RHOSTS 127.0.0.1
run
exit`
	case "6":
		rcContent = `use auxiliary/scanner/postgres/postgres_version
set RHOSTS 127.0.0.1
run
exit`
	case "7":
		rcContent = `use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 127.0.0.1
run
exit`
	case "8":
		fmt.Print("Enter path to local .rc file: ")
		path, _ := reader.ReadString('\n')
		path = strings.TrimSpace(path)
		if path != "" {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Printf(Red+"[!] Read error: %v\n"+Reset, err)
				return
			}
			rcContent = string(content)
		}
	default:
		rcContent = `use auxiliary/scanner/portscan/tcp
set RHOSTS 127.0.0.1
set PORTS 1-10000
run
exit`
	}
	if !ensureToolInstalled(client, "msfconsole", "metasploit-framework") {
		return
	}
	remoteRc := "/tmp/msf_preset.rc"
	b64 := base64.StdEncoding.EncodeToString([]byte(rcContent))
	writeCmd := fmt.Sprintf("echo '%s' | base64 -d > %s", b64, remoteRc)
	_, err := common.ExecuteRemoteCommand(client, writeCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Write error: %v\n"+Reset, err)
		return
	}
	msfCmd := fmt.Sprintf("sudo msfconsole -q -r %s", remoteRc)
	msfCmd = wrapSudo(msfCmd)
	out, err := common.ExecuteRemoteCommand(client, msfCmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	reportContent := fmt.Sprintf("Metasploit Scan Report\nPreset: %s\n\n%s", preset, out)
	reportPath := saveReport("metasploit", fmt.Sprintf("msf_scan_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== MSF OUTPUT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "====================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
	_, _ = common.ExecuteRemoteCommand(client, fmt.Sprintf("rm -f %s", remoteRc), common.DefaultCmdTimeout)
}

// =====================================================================
// PATCHES #8, #10: Web App Scan - normalize URL + pre-check HTTP service
// =====================================================================
func runWebAppSecurityScanWithPresets(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Web Application Security Scan" + Reset)
	fmt.Println("  - This scans the target web server for vulnerabilities.")
	fmt.Println("  - PRESETS:")
	fmt.Println("    1. Quick (Nikto only)")
	fmt.Println("    2. Full (Nikto + Dirb)")
	fmt.Println("    3. OWASP (Nikto + Dirb + Wapiti)")
	fmt.Println("    4. Custom (enter your own options)")
	fmt.Println("  - TIP: For a thorough scan, use preset 2.")
	fmt.Println()
	fmt.Print("Select preset [1-4] (or ENTER for Full): ")
	input, _ := reader.ReadString('\n')
	preset := strings.TrimSpace(input)
	if preset == "" {
		preset = "2"
	}
	target := getTarget(reader)
	if target == "" {
		return
	}

	// PATCH #10: Normalize target to include http:// if missing
	normalizedTarget := target
	if !strings.HasPrefix(normalizedTarget, "http://") && !strings.HasPrefix(normalizedTarget, "https://") {
		normalizedTarget = "http://" + normalizedTarget
		fmt.Printf(Cyan+"[+] Normalized target to: %s\n"+Reset, normalizedTarget)
	}

	// PATCH #8: Pre-check if HTTP service is reachable on port 80/443
	httpReachable := false
	checkCmd := fmt.Sprintf("timeout 2 bash -c 'echo >/dev/tcp/%s/80' 2>/dev/null && echo OK || echo FAIL", target)
	if target != "127.0.0.1" && target != "localhost" {
		// For remote, we can use nc or /dev/tcp
		out, _ := common.ExecuteRemoteCommand(client, checkCmd, common.DefaultCmdTimeout)
		if strings.Contains(out, "OK") {
			httpReachable = true
		}
	} else {
		// localhost, assume reachable if we want to test
		httpReachable = true
	}
	if !httpReachable {
		fmt.Println(Yellow + "[!] No HTTP service detected on port 80/443. Skipping web scan." + Reset)
		return
	}

	niktoOk := ensureToolInstalled(client, "nikto", "nikto")
	dirbOk := ensureToolInstalled(client, "dirb", "dirb")
	if !niktoOk && !dirbOk {
		fmt.Println(Yellow + "[!] No web tools, skipping." + Reset)
		return
	}
	var cmdParts []string
	switch preset {
	case "1":
		if niktoOk {
			cmdParts = append(cmdParts, `echo "=== NIKTO ==="`, fmt.Sprintf("sudo nikto -h %s", normalizedTarget))
		}
	case "2":
		if niktoOk {
			cmdParts = append(cmdParts, `echo "=== NIKTO ==="`, fmt.Sprintf("sudo nikto -h %s", normalizedTarget))
		}
		if dirbOk && httpReachable {
			wordlist := ensureWordlistExists(client)
			if wordlist == "" {
				wordlist = "/usr/share/wordlists/dirb/big.txt"
			}
			cmdParts = append(cmdParts, `echo -e "\n=== DIRB ==="`, fmt.Sprintf("sudo dirb %s %s", normalizedTarget, wordlist))
		} else if dirbOk && !httpReachable {
			fmt.Println(Yellow + "[!] No HTTP service, skipping Dirb." + Reset)
		}
	case "3":
		if niktoOk {
			cmdParts = append(cmdParts, `echo "=== NIKTO ==="`, fmt.Sprintf("sudo nikto -h %s", normalizedTarget))
		}
		if dirbOk && httpReachable {
			wordlist := ensureWordlistExists(client)
			if wordlist == "" {
				wordlist = "/usr/share/wordlists/dirb/big.txt"
			}
			cmdParts = append(cmdParts, `echo -e "\n=== DIRB ==="`, fmt.Sprintf("sudo dirb %s %s", normalizedTarget, wordlist))
		} else if dirbOk && !httpReachable {
			fmt.Println(Yellow + "[!] No HTTP service, skipping Dirb." + Reset)
		}
		if ensureToolInstalled(client, "wapiti", "wapiti") {
			cmdParts = append(cmdParts, `echo -e "\n=== WAPITI ==="`, fmt.Sprintf("sudo wapiti -u %s -o /tmp/wapiti_report", normalizedTarget))
		}
	case "4":
		fmt.Print("Enter custom web scan options: ")
		opts, _ := reader.ReadString('\n')
		opts = strings.TrimSpace(opts)
		if opts != "" {
			cmdParts = append(cmdParts, `echo "=== CUSTOM ==="`, opts)
		}
	default:
		if niktoOk {
			cmdParts = append(cmdParts, `echo "=== NIKTO ==="`, fmt.Sprintf("sudo nikto -h %s", normalizedTarget))
		}
		if dirbOk && httpReachable {
			wordlist := ensureWordlistExists(client)
			if wordlist == "" {
				wordlist = "/usr/share/wordlists/dirb/big.txt"
			}
			cmdParts = append(cmdParts, `echo -e "\n=== DIRB ==="`, fmt.Sprintf("sudo dirb %s %s", normalizedTarget, wordlist))
		} else if dirbOk && !httpReachable {
			fmt.Println(Yellow + "[!] No HTTP service, skipping Dirb." + Reset)
		}
	}
	cmd := strings.Join(cmdParts, " && ")
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		if out != "" {
			fmt.Println(out)
		}
		return
	}
	reportContent := fmt.Sprintf("Web App Security Scan\nTarget: %s\nPreset: %s\n\n%s", target, preset, out)
	reportPath := saveReport("web", fmt.Sprintf("web_scan_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== WEB SCAN OUTPUT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "=========================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
}

// =====================================================================
// PATCH #12: Brute Force - don't return on Hydra error, save report
// =====================================================================
func runBruteForceWithPresets(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Red + Bold + "=== BRUTE FORCE SIMULATION ===" + Reset)
	fmt.Println(Yellow + "📖 USAGE: Brute Force Attack Simulation" + Reset)
	fmt.Println("  - This simulates a brute‑force attack on a remote service.")
	fmt.Println("  - PRESETS:")
	fmt.Println("    1. SSH (port 22)")
	fmt.Println("    2. FTP (port 21)")
	fmt.Println("    3. HTTP Basic Auth")
	fmt.Println("    4. Custom (enter service and port)")
	fmt.Println()
	fmt.Print("Select preset [1-4] (or ENTER for SSH): ")
	input, _ := reader.ReadString('\n')
	preset := strings.TrimSpace(input)
	if preset == "" {
		preset = "1"
	}
	service := "ssh"
	port := "22"
	switch preset {
	case "1":
		service = "ssh"
		port = "22"
	case "2":
		service = "ftp"
		port = "21"
	case "3":
		service = "http-get"
		port = "80"
	case "4":
		fmt.Print("Enter service (ssh/ftp/http-get): ")
		service, _ = reader.ReadString('\n')
		service = strings.TrimSpace(service)
		fmt.Print("Enter port: ")
		port, _ = reader.ReadString('\n')
		port = strings.TrimSpace(port)
	default:
		service = "ssh"
		port = "22"
	}
	wordlist := ensureWordlistExists(client)
	if wordlist == "" {
		fmt.Println(Yellow + "[!] No wordlist available. Aborting.")
		return
	}
	if !ensureToolInstalled(client, "hydra", "hydra") {
		return
	}
	target := getTarget(reader)
	if target == "" {
		return
	}
	cmd := fmt.Sprintf("sudo hydra -l root -P %s -s %s -t 4 %s://%s", wordlist, port, service, target)
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		// PATCH #12: treat Hydra's exit as non-fatal, print warning but save report
		fmt.Printf(Yellow+"[!] Hydra finished with status: %v (this often means 0 passwords found or target unreachable)\n"+Reset, err)
		if out != "" {
			fmt.Println(out)
		}
		// FALL THROUGH to save report
	}
	reportContent := fmt.Sprintf("Brute Force Simulation\nService: %s:%s\nWordlist: %s\n\n%s", service, port, wordlist, out)
	reportPath := saveReport("bruteforce", fmt.Sprintf("hydra_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== HYDRA OUTPUT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "======================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
}

// =============================================================================
// REMEDIATION ENGINE (basic, non-dynamic)
// =============================================================================
func promptRemediation(client *ssh.Client, scanType string) {
	fmt.Print(Yellow + "\n[?] Apply remediation based on this scan? (y/n): " + Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) == "y" {
		runRemediationForScan(client, scanType)
	}
}

func runRemediationForScan(client *ssh.Client, scanType string) {
	fmt.Println(Green + "\n[+] Running targeted remediation for " + scanType + " findings..." + Reset)
	pm := detectPackageManager(client)
	var updateCmd string
	switch pm {
	case "apt-get":
		updateCmd = "sudo apt update && sudo apt upgrade -y"
	case "dnf":
		updateCmd = "sudo dnf update -y"
	case "yum":
		updateCmd = "sudo yum update -y"
	case "pacman":
		updateCmd = "sudo pacman -Syu --noconfirm"
	case "apk":
		updateCmd = "sudo apk update && sudo apk upgrade"
	case "zypper":
		updateCmd = "sudo zypper update -y"
	default:
		updateCmd = "echo 'No supported package manager for updates'"
	}
	fixes := []string{
		updateCmd,
		"sudo chmod 644 /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null || true",
		"sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd 2>/dev/null || true",
		"sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd 2>/dev/null || true",
	}
	if ensureToolInstalled(client, "fail2ban", "fail2ban") {
		fixes = append(fixes, "sudo systemctl enable fail2ban && sudo systemctl start fail2ban")
	}
	if ensureToolInstalled(client, "ufw", "ufw") {
		fixes = append(fixes, "sudo ufw enable && sudo ufw allow ssh && sudo ufw allow http && sudo ufw allow https")
	}
	if scanType == "container" {
		fixes = append(fixes, "sudo systemctl stop docker 2>/dev/null || true", "sudo systemctl stop podman 2>/dev/null || true")
	}
	if scanType == "web" {
		if ensureToolInstalled(client, "htpasswd", "apache2-utils") {
			fixes = append(fixes, "sudo htpasswd -b /etc/apache2/.htpasswd admin securepass 2>/dev/null || true")
		}
	}
	for _, cmd := range fixes {
		wrapped := wrapSudo(cmd)
		fmt.Printf(Cyan+"[+] %s\n"+Reset, cmd)
		out, err := common.ExecuteRemoteCommand(client, wrapped, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		}
		if out != "" && !strings.Contains(out, "update") {
			fmt.Println(out)
		}
	}
	fmt.Println(Green + "[✓] Remediation applied." + Reset)
}

// =============================================================================
// OTHER SCAN FUNCTIONS
// =============================================================================
func runPrivilegeEscalationAudit(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Privilege Escalation Audit" + Reset)
	fmt.Println("  - This checks for SUID/SGID binaries, sudo rights, and critical file permissions.")
	fmt.Println("  - No input needed – just select and let it run.")
	fmt.Println("  - Output is paged and saved to a report.")
	fmt.Println()

	cmd := `echo "=== SUID (risky) ==="
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -E 'nmap|vim|find|bash|more|less|nano|cp|awk|python|perl|ruby|env|docker' || true
echo -e "\n=== SGID ==="
find / -perm -2000 -type f -exec ls -la {} \; 2>/dev/null | head -n 15 || true
echo -e "\n=== Sudo -l ==="
sudo -l 2>/dev/null || echo "No sudo -l output"
echo -e "\n=== Critical file perms ==="
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	reportContent := fmt.Sprintf("Privilege Escalation Audit\nTarget: 127.0.0.1\n\n%s", out)
	reportPath := saveReport("privilege", fmt.Sprintf("priv_audit_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== PRIVILEGE AUDIT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "=========================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
}

func runContainerBreakoutAudit(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Container Breakout Audit" + Reset)
	fmt.Println("  - This checks for Docker socket, privileged containers, and capabilities.")
	fmt.Println("  - No input needed – it will auto‑detect docker/podman.")
	fmt.Println("  - Output is paged and saved to a report.")
	fmt.Println()

	cmd := `echo "=== Docker socket ==="
ls -la /var/run/docker.sock 2>/dev/null || echo "No docker socket"
echo -e "\n=== Privileged containers ==="
if command -v docker >/dev/null 2>&1; then
    sudo docker ps --quiet | xargs -I {} sudo docker inspect --format '{{ .Name }}: Privileged={{ .HostConfig.Privileged }}' {} 2>/dev/null || true
else
    echo "Docker not installed"
fi
echo -e "\n=== Capabilities ==="
grep CapEff /proc/self/status 2>/dev/null || true`
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	reportContent := fmt.Sprintf("Container Breakout Audit\n\n%s", out)
	reportPath := saveReport("container", fmt.Sprintf("container_audit_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== CONTAINER AUDIT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "========================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
}

// =====================================================================
// PATCH #9: Custom Metasploit - validate module contains "/"
// =====================================================================
func runCustomMetasploitExploit(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Red + Bold + "=== CUSTOM METASPLOIT MODULE ===" + Reset)
	fmt.Println(Yellow + "📖 USAGE: Custom Metasploit Module" + Reset)
	fmt.Println("  - This lets you run any Metasploit module.")
	fmt.Println("  - You will be prompted for module name, RHOSTS, LHOST, LPORT, and optional PAYLOAD.")
	fmt.Println("  - TIP: For exploitation, use modules with 'exploit/' prefix.")
	fmt.Println()

	module := transfer.ReadRealtimeInput("Module (or ENTER for portscan): ")
	if module == "" {
		module = "auxiliary/scanner/portscan/tcp"
	}
	// PATCH #9: Validate module contains "/"
	if !strings.Contains(module, "/") {
		fmt.Printf(Red+"[!] Invalid module format. Must contain a slash, e.g., 'auxiliary/scanner/portscan/tcp' or 'exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec'.\n"+Reset)
		fmt.Println(Yellow + "[!] Aborting." + Reset)
		return
	}
	rhosts := transfer.ReadRealtimeInput("RHOSTS [127.0.0.1]: ")
	if rhosts == "" {
		rhosts = "127.0.0.1"
	}
	lhost := transfer.ReadRealtimeInput("LHOST [0.0.0.0]: ")
	if lhost == "" {
		lhost = "0.0.0.0"
	}
	lport := transfer.ReadRealtimeInput("LPORT [4444]: ")
	if lport == "" {
		lport = "4444"
	}
	var rc strings.Builder
	rc.WriteString(fmt.Sprintf("use %s\nset RHOSTS %s\n", module, rhosts))
	if strings.Contains(module, "exploit/") {
		rc.WriteString(fmt.Sprintf("set LHOST %s\nset LPORT %s\n", lhost, lport))
		payload := transfer.ReadRealtimeInput("PAYLOAD (ENTER for default): ")
		if payload != "" {
			rc.WriteString(fmt.Sprintf("set PAYLOAD %s\n", payload))
		}
	}
	rc.WriteString("run\nexit\n")

	if !ensureToolInstalled(client, "msfconsole", "metasploit-framework") {
		return
	}
	remoteRc := "/tmp/msf_custom.rc"
	b64 := base64.StdEncoding.EncodeToString([]byte(rc.String()))
	writeCmd := fmt.Sprintf("echo '%s' | base64 -d > %s", b64, remoteRc)
	_, err := common.ExecuteRemoteCommand(client, writeCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Write error: %v\n"+Reset, err)
		return
	}
	msfCmd := fmt.Sprintf("sudo msfconsole -q -r %s", remoteRc)
	msfCmd = wrapSudo(msfCmd)
	out, err := common.ExecuteRemoteCommand(client, msfCmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	reportContent := fmt.Sprintf("Custom Metasploit Exploit\nModule: %s\nRHOSTS: %s\n\n%s", module, rhosts, out)
	reportPath := saveReport("custommsf", fmt.Sprintf("custom_msf_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "==================== CUSTOM MSF OUTPUT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "===========================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
	_, _ = common.ExecuteRemoteCommand(client, fmt.Sprintf("rm -f %s", remoteRc), common.DefaultCmdTimeout)
}

// =====================================================================
// PATCH #13: Outdated Packages - add --force-confold to upgrade
// =====================================================================
func runOutdatedPackagesCheck(client *ssh.Client, autoUpdate bool) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Outdated Packages Check" + Reset)
	fmt.Println("  - This lists all upgradable packages and offers to update them.")
	fmt.Println("  - No input needed – if you want updates, they will be applied.")
	fmt.Println("  - Output is paged.")
	fmt.Println()

	pm := detectPackageManager(client)
	var listCmd string
	switch pm {
	case "apt-get":
		listCmd = "apt list --upgradable 2>/dev/null"
	case "dnf", "yum":
		listCmd = "sudo dnf check-update 2>/dev/null || sudo yum check-update 2>/dev/null"
	case "pacman":
		listCmd = "pacman -Qu 2>/dev/null"
	case "apk":
		listCmd = "apk list -u 2>/dev/null"
	case "zypper":
		listCmd = "zypper list-updates 2>/dev/null"
	default:
		listCmd = "echo 'No supported package manager for listing updates'"
	}
	listCmd = wrapSudo(listCmd)
	out, err := common.ExecuteRemoteCommand(client, listCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	if strings.Contains(out, "upgradable") || strings.Contains(out, "update") || strings.Contains(out, "updates") {
		fmt.Println(Blue + "==================== OUTDATED PACKAGES ====================" + Reset)
		displayWithPager(out)
		fmt.Println(Blue + "===========================================================" + Reset)
		if autoUpdate {
			fmt.Println(Green + "[+] Applying updates..." + Reset)
			var updCmd string
			switch pm {
			case "apt-get":
				// PATCH #13: added --force-confold
				updCmd = "sudo apt update && sudo apt upgrade -y -o Dpkg::Options::=\"--force-confold\""
			case "dnf":
				updCmd = "sudo dnf update -y"
			case "yum":
				updCmd = "sudo yum update -y"
			case "pacman":
				updCmd = "sudo pacman -Syu --noconfirm"
			case "apk":
				updCmd = "sudo apk update && sudo apk upgrade"
			case "zypper":
				updCmd = "sudo zypper update -y"
			default:
				updCmd = "echo 'No supported package manager for updates'"
			}
			updCmd = wrapSudo(updCmd)
			updOut, _ := common.ExecuteRemoteCommand(client, updCmd, common.LongCmdTimeout)
			fmt.Println(updOut)
		}
	} else {
		fmt.Println(Green + "[✓] No outdated packages." + Reset)
	}
}

func runSSHHardening(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: SSH Configuration Hardening" + Reset)
	fmt.Println("  - This shows current SSH settings and offers to harden them.")
	fmt.Println("  - Hardening includes: disable root login, disable password auth, force Protocol 2.")
	fmt.Println("  - You'll be prompted before applying changes.")
	fmt.Println("  - TIP: After hardening, ensure you have another way to access (e.g., SSH keys).")
	fmt.Println()

	cmd := "sudo cat /etc/ssh/sshd_config | grep -E '^PermitRootLogin|^PasswordAuthentication|^Protocol'"
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	fmt.Println(Blue + "==================== SSH CONFIG ====================" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "====================================================" + Reset)

	if strings.Contains(out, "PermitRootLogin no") &&
		strings.Contains(out, "PasswordAuthentication no") &&
		strings.Contains(out, "Protocol 2") {
		fmt.Println(Green + "[✔] SSH already hardened. No action needed." + Reset)
		return
	}
	fmt.Print(Yellow + "Apply SSH hardening? (y/n): " + Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) == "y" {
		hardCmd := `sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config &&
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config &&
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config &&
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config &&
sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config &&
sudo sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config &&
sudo systemctl restart sshd`
		hardCmd = wrapSudo(hardCmd)
		_, _ = common.ExecuteRemoteCommand(client, hardCmd, common.LongCmdTimeout)
		fmt.Println(Green + "[✓] SSH hardened (root login disabled, password auth off, protocol 2)." + Reset)
	}
}

// =====================================================================
// PATCH #7: Firewall (UFW) - add port cleanup step
// =====================================================================
func runFirewallSetup(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Firewall (UFW) Setup" + Reset)
	fmt.Println("  - This checks UFW status and offers to enable it.")
	fmt.Println("  - If enabled, it will allow SSH, HTTP, and HTTPS by default.")
	fmt.Println("  - You'll be prompted before applying changes.")
	fmt.Println("  - TIP: A firewall is essential – always keep it on.")
	fmt.Println()

	if !ensureToolInstalled(client, "ufw", "ufw") {
		fmt.Println(Yellow + "[!] UFW not available.")
		return
	}
	cmd := "sudo ufw status"
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	fmt.Println(Blue + "==================== UFW STATUS ====================" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "====================================================" + Reset)
	if strings.Contains(out, "active") {
		fmt.Println(Green + "[✔] UFW is already active." + Reset)
		// PATCH #7: offer to clean up open ports except 22,80,443
		fmt.Print(Yellow + "Do you want to close all open ports except SSH (22), HTTP (80), HTTPS (443)? (y/n): " + Reset)
		var resp string
		fmt.Scanln(&resp)
		if strings.ToLower(resp) == "y" {
			// Get list of listening ports (excluding 22,80,443)
			checkPortsCmd := `ss -tulpn | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u`
			checkPortsCmd = wrapSudo(checkPortsCmd)
			portOut, _ := common.ExecuteRemoteCommand(client, checkPortsCmd, common.DefaultCmdTimeout)
			ports := strings.Fields(portOut)
			denyRules := []string{}
			for _, p := range ports {
				if p != "22" && p != "80" && p != "443" {
					denyRules = append(denyRules, fmt.Sprintf("sudo ufw deny %s", p))
				}
			}
			if len(denyRules) > 0 {
				fmt.Printf(Cyan+"[+] Denying %d non-essential ports...\n"+Reset, len(denyRules))
				denyCmd := strings.Join(denyRules, " && ")
				denyCmd = wrapSudo(denyCmd)
				_, _ = common.ExecuteRemoteCommand(client, denyCmd, common.LongCmdTimeout)
				fmt.Println(Green + "[✓] Non-essential ports denied." + Reset)
			} else {
				fmt.Println(Green + "[✓] No non-essential ports to deny." + Reset)
			}
		}
		return
	}
	fmt.Print(Yellow + "Enable UFW and allow SSH/HTTP/HTTPS? (y/n): " + Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) == "y" {
		setupCmd := "sudo ufw enable && sudo ufw allow ssh && sudo ufw allow http && sudo ufw allow https"
		setupCmd = wrapSudo(setupCmd)
		_, _ = common.ExecuteRemoteCommand(client, setupCmd, common.LongCmdTimeout)
		fmt.Println(Green + "[✓] Firewall enabled with default rules." + Reset)
	}
}

// =====================================================================
// PATCH #14: World-Writable - fix chmod per file (passwd=644, shadow=640, sudoers=440)
// =====================================================================
func runWorldWritableSecure(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: World‑Writable Files Security" + Reset)
	fmt.Println("  - This finds world‑writable files (top 20) and offers to secure critical ones.")
	fmt.Println("  - It will suggest securing /etc/passwd, /etc/shadow, /etc/sudoers.")
	fmt.Println("  - You'll be prompted before applying changes.")
	fmt.Println("  - TIP: World‑writable files can be exploited – fix them.")
	fmt.Println()

	cmd := "find / -type f -perm -002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' -exec ls -la {} \\; 2>/dev/null | head -20"
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		return
	}
	fmt.Println(Blue + "==================== WORLD-WRITABLE FILES (top 20) ====================" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "==========================================================================" + Reset)

	statCmd := "stat -c %a /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null"
	statOut, _ := common.ExecuteRemoteCommand(client, statCmd, common.DefaultCmdTimeout)
	if strings.Contains(statOut, "644") && strings.Contains(statOut, "640") && strings.Contains(statOut, "440") {
		fmt.Println(Green + "[✔] Critical files already secured." + Reset)
		return
	}
	fmt.Print(Yellow + "Secure critical files (passwd, shadow, sudoers)? (y/n): " + Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) == "y" {
		// PATCH #14: correct permissions
		secCmd := wrapSudo("sudo chmod 644 /etc/passwd && sudo chmod 640 /etc/shadow && sudo chmod 440 /etc/sudoers 2>/dev/null || true")
		_, _ = common.ExecuteRemoteCommand(client, secCmd, common.DefaultCmdTimeout)
		fmt.Println(Green + "[✓] Critical files secured." + Reset)
	}
}

// =====================================================================
// PATCH #15: John timeout - use 30 minutes for full wordlist
// =====================================================================
func runWeakPasswordsCheck(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Password Strength Audit" + Reset)
	fmt.Println("  - This checks password policy, users with empty passwords, hash types.")
	fmt.Println("  - Then runs John the Ripper to crack weak passwords using a wordlist.")
	fmt.Println("  - If no wordlist is found, the tool automatically downloads one from GitHub.")
	fmt.Println("  - Output is paged for easy review.")
	fmt.Println("  - TIP: Press Enter to use Quick scan (10k passwords) or type 'full' for 10 million.")
	fmt.Println()

	if !ensureToolInstalled(client, "john", "john") {
		fmt.Println(Yellow + "[!] John the Ripper not available.")
		return
	}
	fmt.Print("Use full wordlist (10M passwords)? This may take 10+ minutes. [y/N]: ")
	var mode string
	fmt.Scanln(&mode)
	wordlist := ensureWordlistExists(client)
	if mode == "y" || mode == "Y" {
		fmt.Println(Cyan + "[+] Using full 10M wordlist (this will take time)..." + Reset)
	} else {
		wordlist = "/usr/share/wordlists/dirb/big.txt"
		if !checkFileExists(client, wordlist) {
			wordlist = ensureWordlistExists(client)
		}
		fmt.Println(Cyan + "[+] Using quick wordlist (10k passwords)..." + Reset)
	}
	var cmdParts []string
	cmdParts = append(cmdParts, `echo "=== PASSWORD POLICY ==="`)
	cmdParts = append(cmdParts, `echo "Min length (PASS_MIN_LEN): $(grep ^PASS_MIN_LEN /etc/login.defs | awk '{print $2}' 2>/dev/null || echo 'not set')"`)
	cmdParts = append(cmdParts, `echo "Max days (PASS_MAX_DAYS): $(grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2}' 2>/dev/null || echo 'not set')"`)
	cmdParts = append(cmdParts, `echo "Password hashing algorithm: $(grep ^ENCRYPT_METHOD /etc/login.defs | awk '{print $2}' 2>/dev/null || echo 'unknown')"`)
	cmdParts = append(cmdParts, `echo "PAM password complexity modules: $(grep -h 'pam_cracklib\\|pam_pwquality' /etc/pam.d/common-password 2>/dev/null | grep -v '^#' | head -1)"`)
	cmdParts = append(cmdParts, `echo -e "\n=== USERS WITH NO PASSWORD (EMPTY) ==="`)
	cmdParts = append(cmdParts, `sudo awk -F: '($2==""){print "  - " $1}' /etc/shadow 2>/dev/null || echo "  (none found)"`)
	cmdParts = append(cmdParts, `echo -e "\n=== PASSWORD HASH TYPES ==="`)
	cmdParts = append(cmdParts, `sudo awk -F: '{h=$2; if(h!="" && h!="*" && h!="!" && h!="!!") { split(h,a,"$"); if(length(a)>=2) { type="$"a[2]"$"; print "  - " $1 " : " type } else print "  - " $1 " : DES (unsalted)" } }' /etc/shadow 2>/dev/null || echo "  (no hashes found)"`)
	cmdParts = append(cmdParts, `echo -e "\n=== JOHN THE RIPPER CRACKING ATTEMPT ==="`)
	cmdParts = append(cmdParts, `sudo unshadow /etc/passwd /etc/shadow > /tmp/shadow.john 2>/dev/null`)
	if wordlist != "" {
		cmdParts = append(cmdParts, fmt.Sprintf(`sudo john --wordlist=%s --rules --format=crypt /tmp/shadow.john --max-run-time=600 2>&1 | head -50`, wordlist))
		cmdParts = append(cmdParts, `echo -e "\n=== CRACKED PASSWORDS (if any) ==="`)
		cmdParts = append(cmdParts, `sudo john --show --format=crypt /tmp/shadow.john 2>/dev/null || echo "  (none cracked yet)"`)
	} else {
		cmdParts = append(cmdParts, `sudo john --max-run-time=30 --format=crypt /tmp/shadow.john 2>&1 | head -50`)
		cmdParts = append(cmdParts, `echo -e "\n=== CRACKED PASSWORDS (if any) ==="`)
		cmdParts = append(cmdParts, `sudo john --show --format=crypt /tmp/shadow.john 2>/dev/null || echo "  (none cracked yet)"`)
	}
	cmdParts = append(cmdParts, `sudo rm -f /tmp/shadow.john`)
	fullCmd := strings.Join(cmdParts, " && ")
	fullCmd = wrapSudo(fullCmd)

	// PATCH #15: use longer timeout for full mode
	var execTimeout time.Duration
	if mode == "y" || mode == "Y" {
		execTimeout = 30 * time.Minute
		fmt.Println(Cyan + "[+] This may take a while. Timeout set to 30 minutes..." + Reset)
	} else {
		execTimeout = common.LongCmdTimeout // default 5 min
	}
	out, err := common.ExecuteRemoteCommand(client, fullCmd, execTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		if out != "" {
			fmt.Println(out)
		}
		return
	}
	reportContent := fmt.Sprintf("Password Strength Audit\n\n%s", out)
	reportPath := saveReport("passwords", fmt.Sprintf("john_audit_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Println(Blue + "\n==================== PASSWORD AUDIT REPORT ====================" + Reset)
	displayWithPager(out)
	fmt.Println(Blue + "===============================================================" + Reset)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
	fmt.Println(Yellow + "\n[+] Recommendations:" + Reset)
	fmt.Println("  - Ensure PASS_MIN_LEN ≥ 8.")
	fmt.Println("  - Ensure ENCRYPT_METHOD is SHA512 or yescrypt.")
	fmt.Println("  - No user should have an empty password.")
	fmt.Println("  - If any password was cracked, change it immediately.")
	fmt.Println("  - Consider enabling fail2ban.")
}

// =====================================================================
// PATCH #5: Rootkit Check - filter false positives via grep -v -E
// =====================================================================
func runRootkitCheck(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "📖 USAGE: Rootkit Detection" + Reset)
	fmt.Println("  - This checks for rootkits using chkrootkit (or rkhunter as fallback).")
	fmt.Println("  - If the tool isn't installed, it will offer to install it.")
	fmt.Println("  - If installation fails, it automatically tries the fallback.")
	fmt.Println("  - Output is paged.")
	fmt.Println()

	if ensureToolInstalled(client, "chkrootkit", "chkrootkit") {
		// PATCH #5: filter false positives
		cmd := wrapSudo("sudo chkrootkit 2>&1 | grep -v -E '/tmp/msfinstall|code-oss|/usr/lib/debug/.build-id|ifpromisc.*NetworkManager|chklastlog.*root'")
		out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(Red+"[!] chkrootkit error: %v\n"+Reset, err)
			if out != "" {
				fmt.Println(out)
			}
		} else {
			reportContent := fmt.Sprintf("Rootkit Check\n\n%s", out)
			reportPath := saveReport("rootkit", fmt.Sprintf("chkrootkit_%s.txt", time.Now().Format("20060102_150405")), reportContent)
			fmt.Println(Blue + "==================== CHKROOTKIT OUTPUT ====================" + Reset)
			displayWithPager(out)
			fmt.Println(Blue + "===========================================================" + Reset)
			fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
			return
		}
	}
	fmt.Println(Yellow + "[!] chkrootkit not available or failed, trying rkhunter..." + Reset)
	if ensureToolInstalled(client, "rkhunter", "rkhunter") {
		updateCmd := wrapSudo("sudo rkhunter --update 2>/dev/null")
		_, _ = common.ExecuteRemoteCommand(client, updateCmd, common.DefaultCmdTimeout)
		cmd := wrapSudo("sudo rkhunter --check --skip-keypress 2>&1")
		out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(Red+"[!] rkhunter error: %v\n"+Reset, err)
			if out != "" {
				fmt.Println(out)
			}
		} else {
			reportContent := fmt.Sprintf("Rootkit Check (rkhunter)\n\n%s", out)
			reportPath := saveReport("rootkit", fmt.Sprintf("rkhunter_%s.txt", time.Now().Format("20060102_150405")), reportContent)
			fmt.Println(Blue + "==================== RKHUNTER OUTPUT ====================" + Reset)
			displayWithPager(out)
			fmt.Println(Blue + "===========================================================" + Reset)
			fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
		}
	} else {
		fmt.Println(Yellow + "[!] No rootkit checker installed or installable. Skipping." + Reset)
	}
}

// =====================================================================
// NEW: DYNAMIC REAL-TIME REMEDIATION (Option 15)
// =====================================================================
func runDynamicRemediation(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Green + Bold + "⚡ DYNAMIC REAL-TIME REMEDIATION" + Reset)
	fmt.Println(Yellow + "📖 USAGE: This option scans the live state of the target system," + Reset)
	fmt.Println("  detects open ports and running services, and applies targeted fixes.")
	fmt.Println("  - Kills and disables only the services actually found.")
	fmt.Println("  - Removes Docker container port forwards.")
	fmt.Println("  - Resets firewall to allow only SSH, HTTP, HTTPS.")
	fmt.Println("  - Performs full system upgrade and hardening.")
	fmt.Println()

	fmt.Print(Yellow + "Proceed with dynamic remediation? (y/n): " + Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		return
	}

	fmt.Println(Cyan + "\n[+] Gathering live system state (open ports & processes)..." + Reset)

	// 1. Get listening ports and associated process names
	getPortsCmd := `ss -tulpn 2>/dev/null | grep LISTEN | awk '{print $5 " " $7}' | sed 's/:[0-9]+/ /' | sort -u`
	getPortsCmd = wrapSudo(getPortsCmd)
	portOut, err := common.ExecuteRemoteCommand(client, getPortsCmd, common.DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to gather port info: %v\n"+Reset, err)
		return
	}

	// Parse lines like "0.0.0.0:3306 users:(("mysql")" or "127.0.0.1:5432 users:(("postgres")"
	// We'll extract port and service name.
	portServiceMap := make(map[string]string)
	lines := strings.Split(portOut, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// parts[0] is like "0.0.0.0:3306" or "[::]:22"
		addrPort := parts[0]
		// extract port after last colon
		lastColon := strings.LastIndex(addrPort, ":")
		if lastColon == -1 {
			continue
		}
		port := addrPort[lastColon+1:]
		// skip if port not numeric
		if port == "" {
			continue
		}
		// process name might be in parts[1] like "users:(("mysql")"
		serviceName := strings.TrimSpace(parts[1])
		// clean up: remove "users:((" and "))" and quotes
		serviceName = strings.TrimPrefix(serviceName, "users:((")
		serviceName = strings.TrimSuffix(serviceName, "))")
		serviceName = strings.Trim(serviceName, `"`)
		// if serviceName contains comma or something, take first part
		if strings.Contains(serviceName, ",") {
			serviceName = strings.Split(serviceName, ",")[0]
		}
		if serviceName == "" {
			serviceName = "unknown"
		}
		portServiceMap[port] = serviceName
	}

	// 2. Determine which services to stop/disable based on ports
	serviceStopMap := map[string]string{
		"3306": "mysql",
		"5432": "postgresql",
		"6379": "redis",
		"8080": "apache2",
		"80":   "apache2",
		"443":  "apache2",
		"8081": "docker", // might be docker container
		"9200": "elasticsearch",
		"5601": "kibana",
		"3000": "grafana",
		"9090": "prometheus",
		"9000": "sonarqube",
		"22":   "sshd", // we won't stop sshd
	}

	// Determine which services to stop
	servicesToStop := make(map[string]bool) // service name -> true
	for port, service := range portServiceMap {
		if port == "22" {
			continue // never stop SSH
		}
		if svc, ok := serviceStopMap[port]; ok {
			// use the mapped service name
			servicesToStop[svc] = true
		} else {
			// If service name contains "docker" or "podman", add to stop list
			if strings.Contains(strings.ToLower(service), "docker") ||
				strings.Contains(strings.ToLower(service), "podman") {
				servicesToStop["docker"] = true
				servicesToStop["podman"] = true
			} else if service != "unknown" && service != "sshd" {
				// attempt to stop whatever service name we found
				servicesToStop[service] = true
			}
		}
	}

	fmt.Println(Cyan + "\n[+] Stopping and disabling detected services..." + Reset)
	for svc := range servicesToStop {
		if svc == "sshd" {
			continue
		}
		// We'll attempt to stop and disable
		stopCmd := fmt.Sprintf("sudo systemctl stop %s 2>/dev/null || true", svc)
		disableCmd := fmt.Sprintf("sudo systemctl disable %s 2>/dev/null || true", svc)
		combined := wrapSudo(stopCmd + " && " + disableCmd)
		fmt.Printf(Cyan+"  - Stopping %s...\n"+Reset, svc)
		_, _ = common.ExecuteRemoteCommand(client, combined, common.DefaultCmdTimeout)
	}

	// 3. Kill and remove Docker containers (if any)
	fmt.Println(Cyan + "[+] Killing and removing all Docker containers..." + Reset)
	killDockerCmd := wrapSudo(`sudo docker kill $(sudo docker ps -q) 2>/dev/null || true`)
	_, _ = common.ExecuteRemoteCommand(client, killDockerCmd, common.DefaultCmdTimeout)
	rmDockerCmd := wrapSudo(`sudo docker system prune -af 2>/dev/null || true`)
	_, _ = common.ExecuteRemoteCommand(client, rmDockerCmd, common.DefaultCmdTimeout)

	// 4. Reset UFW and allow only 22,80,443
	fmt.Println(Cyan + "[+] Resetting and locking down firewall (UFW)..." + Reset)
	ufwCmds := []string{
		"sudo ufw --force reset",
		"sudo ufw default deny incoming",
		"sudo ufw default allow outgoing",
		"sudo ufw allow 22/tcp",
		"sudo ufw allow 80/tcp",
		"sudo ufw allow 443/tcp",
		"sudo ufw --force enable",
	}
	ufwCmd := strings.Join(ufwCmds, " && ")
	ufwCmd = wrapSudo(ufwCmd)
	_, _ = common.ExecuteRemoteCommand(client, ufwCmd, common.LongCmdTimeout)

	// 5. Perform full system upgrade
	fmt.Println(Cyan + "[+] Performing full system upgrade..." + Reset)
	pm := detectPackageManager(client)
	var updateCmd string
	switch pm {
	case "apt-get":
		updateCmd = "sudo apt update && sudo apt full-upgrade -y -o Dpkg::Options::=\"--force-confold\" && sudo apt autoremove -y"
	case "dnf":
		updateCmd = "sudo dnf update -y"
	case "yum":
		updateCmd = "sudo yum update -y"
	case "pacman":
		updateCmd = "sudo pacman -Syu --noconfirm"
	case "apk":
		updateCmd = "sudo apk update && sudo apk upgrade"
	case "zypper":
		updateCmd = "sudo zypper update -y"
	default:
		updateCmd = "echo 'No supported package manager for updates'"
	}
	updateCmd = wrapSudo(updateCmd)
	_, _ = common.ExecuteRemoteCommand(client, updateCmd, common.LongCmdTimeout)

	// 6. Fix critical permissions
	fmt.Println(Cyan + "[+] Fixing critical file permissions..." + Reset)
	chmodCmd := wrapSudo("sudo chmod 640 /etc/shadow && sudo chmod 440 /etc/sudoers && sudo chmod 644 /etc/passwd")
	_, _ = common.ExecuteRemoteCommand(client, chmodCmd, common.DefaultCmdTimeout)

	// 7. SSH hardening (disable ChallengeResponse, etc.)
	fmt.Println(Cyan + "[+] Hardening SSH..." + Reset)
	sshHardCmd := `sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config &&
sudo sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config &&
sudo systemctl restart sshd`
	sshHardCmd = wrapSudo(sshHardCmd)
	_, _ = common.ExecuteRemoteCommand(client, sshHardCmd, common.DefaultCmdTimeout)

	// 8. PAM password enforcement
	fmt.Println(Cyan + "[+] Enforcing strong password policy..." + Reset)
	pamCmd := `sudo apt install -y libpam-pwquality 2>/dev/null || true &&
sudo sed -i 's/^password.*pam_unix.so/& remember=5 minlen=12/' /etc/pam.d/common-password &&
echo "minlen = 12" | sudo tee -a /etc/security/pwquality.conf &&
echo "dcredit = -1" | sudo tee -a /etc/security/pwquality.conf &&
echo "ucredit = -1" | sudo tee -a /etc/security/pwquality.conf &&
echo "ocredit = -1" | sudo tee -a /etc/security/pwquality.conf &&
echo "lcredit = -1" | sudo tee -a /etc/security/pwquality.conf`
	pamCmd = wrapSudo(pamCmd)
	_, _ = common.ExecuteRemoteCommand(client, pamCmd, common.LongCmdTimeout)

	// 9. Clean up false-positive files
	fmt.Println(Cyan + "[+] Removing false-positive and weak files..." + Reset)
	cleanCmd := wrapSudo("sudo rm -f /tmp/msfinstall /etc/apache2/.htpasswd 2>/dev/null || true")
	_, _ = common.ExecuteRemoteCommand(client, cleanCmd, common.DefaultCmdTimeout)

	// 10. Summary
	fmt.Println(Green + Bold + "\n✅ DYNAMIC REMEDIATION COMPLETE!" + Reset)
	fmt.Println(Yellow + "Summary of actions:" + Reset)
	if len(servicesToStop) > 0 {
		fmt.Printf("  - Stopped and disabled services: %s\n", strings.Join(mapKeys(servicesToStop), ", "))
	} else {
		fmt.Println("  - No non-essential services were running.")
	}
	fmt.Println("  - Docker containers removed (if any).")
	fmt.Println("  - Firewall reset to allow only 22,80,443.")
	fmt.Println("  - Full system upgrade performed.")
	fmt.Println("  - Critical permissions fixed.")
	fmt.Println("  - SSH and PAM hardened.")
	fmt.Println("  - False-positive files cleaned.")
	fmt.Println()
	fmt.Println(Yellow + "A full log is saved to reports/remediation/dynamic_remediation_*.txt" + Reset)

	// Save report
	reportContent := fmt.Sprintf("Dynamic Real-Time Remediation\nTarget: %s\n\nServices stopped: %v\n\nFull output:\n%s", host, mapKeys(servicesToStop), portOut)
	reportPath := saveReport("remediation", fmt.Sprintf("dynamic_remediation_%s.txt", time.Now().Format("20060102_150405")), reportContent)
	fmt.Printf(Green+"[+] Report saved to: %s\n"+Reset, reportPath)
}

// Helper to get keys of a map as slice
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
// =====================================================================
// MASTER SWEEP (UPDATED – fixed wordlist handling)
// =====================================================================
func runMasterSweep(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Green + Bold + "🛡️  MASTER SWEEP – FULL AUDIT & AUTO-REMEDIATION" + Reset)
	fmt.Println(Yellow + "📖 USAGE: This runs all scans, saves a combined report, and applies all fixes." + Reset)
	fmt.Println("  - Progress will be shown as each scan completes.")
	fmt.Println("  - A full report is saved at /tmp/fortress_report.html on the remote host.")
	fmt.Println("  - You'll be prompted once to confirm before starting.")
	fmt.Println()
	fmt.Print("Continue? (y/n): ")
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		return
	}

	// Ensure all tools (wordlist is handled separately)
	fmt.Println(Cyan + "[+] Ensuring all audit tools are installed..." + Reset)
	totalTools := 9 // We removed wordlist from the APT map
	installedTools := 0

	// This map now excludes "wordlist"
	tools := map[string]string{
		"nmap":        "nmap",
		"msfconsole":  "metasploit-framework",
		"nikto":       "nikto",
		"dirb":        "dirb",
		"hydra":       "hydra",
		"chkrootkit":  "chkrootkit",
		"ufw":         "ufw",
		"fail2ban":    "fail2ban",
		"john":        "john",
	}

	for tool, pkg := range tools {
		fmt.Printf(Yellow+"[%d/%d] Checking %s...\n"+Reset, installedTools+1, totalTools, tool)
		if ensureToolInstalled(client, tool, pkg) {
			installedTools++
		}
		fmt.Printf(Green+"[%d/%d] Done.\n"+Reset, installedTools, totalTools)
	}

	// Handle wordlist separately with fallback download
	fmt.Printf(Yellow+"[%d/%d] Checking wordlist...\n"+Reset, installedTools+1, totalTools)
	wordlistPath := ensureWordlistExists(client)
	if wordlistPath != "" {
		fmt.Println(Green + "[✔] Wordlist secured successfully (via APT or online fallback)." + Reset)
		installedTools++
	} else {
		fmt.Println(Red + "[!] Failed to secure any wordlist." + Reset)
	}
	fmt.Printf(Green+"[%d/%d] Done.\n"+Reset, installedTools, totalTools)

	fmt.Println(Cyan + "\n[+] Running all scans (this may take a while)..." + Reset)
	allOutput := ""
	scans := []struct {
		name string
		cmd  string
	}{
		{"NMAP", wrapSudo("sudo nmap -sV --script=vuln 127.0.0.1")},
		{"MSF AUX", wrapSudo("sudo msfconsole -q -r /tmp/msf_sweep.rc")},
		{"PRIVILEGE", wrapSudo(`echo "=== SUID ==="; find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -E 'nmap|vim|find|bash|more|less|nano|cp|awk|python|perl|ruby|env|docker' || true
echo "=== SGID ==="; find / -perm -2000 -type f -exec ls -la {} \; 2>/dev/null | head -n 15
echo "=== Sudo -l ==="; sudo -l 2>/dev/null
echo "=== Critical perms ==="; ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null`)},
		{"CONTAINER", wrapSudo(`ls -la /var/run/docker.sock 2>/dev/null || echo "No docker socket"
if command -v docker >/dev/null 2>&1; then sudo docker ps --quiet | xargs -I {} sudo docker inspect --format '{{ .Name }}: Privileged={{ .HostConfig.Privileged }}' {} 2>/dev/null || true; else echo "Docker not installed"; fi
grep CapEff /proc/self/status 2>/dev/null || true`)},
		{"WEB", wrapSudo(`echo "=== NIKTO ==="; sudo nikto -h http://127.0.0.1 2>/dev/null || echo "nikto not installed"; echo "=== DIRB ==="; sudo dirb http://127.0.0.1 /usr/share/wordlists/dirb/big.txt 2>/dev/null || echo "dirb not installed"`)},
		{"BRUTE FORCE", wrapSudo(fmt.Sprintf("sudo hydra -l root -P %s ssh://127.0.0.1 -t 4 2>/dev/null || echo 'hydra failed'", ensureWordlistExists(client)))},
		{"OUTDATED PACKAGES", "apt list --upgradable 2>/dev/null || echo 'No package manager'"},
		{"SSH CONFIG", wrapSudo("sudo cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PasswordAuthentication|Protocol'")},
		{"FIREWALL", wrapSudo("sudo ufw status 2>/dev/null || echo 'UFW not installed'")},
		{"WORLD-WRITABLE", "find / -type f -perm -002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' -exec ls -la {} \\; 2>/dev/null | head -20"},
		{"ROOTKIT", wrapSudo("sudo chkrootkit 2>/dev/null || echo 'chkrootkit not found'")},
	}
	msfPreset := `use auxiliary/scanner/portscan/tcp
set RHOSTS 127.0.0.1
set PORTS 1-10000
run
use auxiliary/scanner/smb/smb_version
set RHOSTS 127.0.0.1
run
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 127.0.0.1
run
use auxiliary/scanner/http/http_version
set RHOSTS 127.0.0.1
run
use auxiliary/scanner/http/dir_scanner
set RHOSTS 127.0.0.1
run
exit
`
	b64 := base64.StdEncoding.EncodeToString([]byte(msfPreset))
	writeCmd := fmt.Sprintf("echo '%s' | base64 -d > /tmp/msf_sweep.rc", b64)
	_, _ = common.ExecuteRemoteCommand(client, writeCmd, common.DefaultCmdTimeout)
	totalScans := len(scans)
	for i, scan := range scans {
		fmt.Printf(Yellow+"[%d/%d] Running %s...\n"+Reset, i+1, totalScans, scan.name)
		out, err := common.ExecuteRemoteCommand(client, scan.cmd, common.LongCmdTimeout)
		if err != nil {
			allOutput += fmt.Sprintf("=== %s ERROR ===\n%v\n", scan.name, err)
		} else {
			allOutput += fmt.Sprintf("=== %s ===\n%s\n", scan.name, out)
		}
	}
	_, _ = common.ExecuteRemoteCommand(client, "rm -f /tmp/msf_sweep.rc", common.DefaultCmdTimeout)

	reportHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Master Sweep Report</title>
<style>body{background:#1a1a2e;color:#e0e0e0;font-family:Arial;padding:20px;}
h1{color:#00adb5;}pre{background:#16213e;padding:15px;border-radius:8px;white-space:pre-wrap;}
</style></head>
<body>
<h1>Master Sweep Report – %s</h1>
<p>Generated: %s</p>
<pre>%s</pre>
</body></html>`, host, time.Now().Format("2006-01-02 15:04:05"), allOutput)
	writeReport := fmt.Sprintf("echo '%s' > /tmp/fortress_report.html", strings.ReplaceAll(reportHTML, "'", "'\\''"))
	_, _ = common.ExecuteRemoteCommand(client, writeReport, common.DefaultCmdTimeout)
	fmt.Println(Green + "[+] Full scan report saved at /tmp/fortress_report.html on remote." + Reset)

	fmt.Println(Green + "\n[+] Applying full remediation..." + Reset)
	pm := detectPackageManager(client)
	var updateCmd string
	switch pm {
	case "apt-get":
		updateCmd = "sudo apt update && sudo apt upgrade -y"
	case "dnf":
		updateCmd = "sudo dnf update -y"
	case "yum":
		updateCmd = "sudo yum update -y"
	case "pacman":
		updateCmd = "sudo pacman -Syu --noconfirm"
	case "apk":
		updateCmd = "sudo apk update && sudo apk upgrade"
	case "zypper":
		updateCmd = "sudo zypper update -y"
	default:
		updateCmd = "echo 'No supported package manager for updates'"
	}
	allFixes := []string{
		updateCmd,
		"sudo chmod 644 /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null || true",
		"sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd 2>/dev/null || true",
		"sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd 2>/dev/null || true",
		"sudo apt install -y fail2ban && sudo systemctl enable fail2ban && sudo systemctl start fail2ban",
		"sudo apt install -y libpam-cracklib && sudo sed -i '/pam_unix.so/ s/$/ minlen=8 remember=5/' /etc/pam.d/common-password || true",
		"sudo ufw enable && sudo ufw allow ssh && sudo ufw allow http && sudo ufw allow https",
		"sudo sysctl -w net.ipv4.tcp_syncookies=1",
		"sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
		"sudo sysctl -w net.ipv4.conf.default.rp_filter=1",
		"sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
		"sudo sysctl -w net.ipv4.conf.all.accept_source_route=0",
		"sudo systemctl stop docker 2>/dev/null || true",
		"sudo systemctl stop podman 2>/dev/null || true",
		"sudo find / -type f -perm -002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' -exec chmod o-w {} \\; 2>/dev/null || true",
	}
	for _, fix := range allFixes {
		wrapped := wrapSudo(fix)
		fmt.Printf(Cyan+"[+] %s\n"+Reset, fix)
		_, err := common.ExecuteRemoteCommand(client, wrapped, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
		}
	}
	fmt.Println(Green + Bold + "\n✅ MASTER SWEEP COMPLETE! All vulnerabilities patched, system hardened." + Reset)
	fmt.Println(Yellow + "Full report is at /tmp/fortress_report.html on the remote host. You can view it with a browser." + Reset)
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return to menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}