package nmap

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/platform"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var localSudoPassword string

// ---------------------------------------------------------------------
// Authentication gateway (unchanged – already robust)
// ---------------------------------------------------------------------
func ensureAutonomousPermissionsWithPrompt(client *ssh.Client) bool {
	if localSudoPassword != "" {
		return true
	}
	return promptAndValidateSudo(client)
}

func promptAndValidateSudo(client *ssh.Client) bool {
	maxAttempts := 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fmt.Printf("Enter elevation password (attempt %d/%d): ", attempt, maxAttempts)
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println(common.Red + "[!] Failed to read password." + common.Reset)
			continue
		}
		pass := string(passBytes)
		if strings.TrimSpace(pass) == "" {
			fmt.Println(common.Yellow + "[!] Password cannot be empty." + common.Reset)
			continue
		}

		escaped := strings.ReplaceAll(pass, "'", "'\"'\"'")

		validateCmd := fmt.Sprintf(`python3 -c "
import sys, subprocess, os

user = os.environ.get('USER') or subprocess.getoutput('whoami').strip()
pwd = '''%s'''

proc = subprocess.Popen(['su', '-', user, '-c', 'true'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
stdout, stderr = proc.communicate(input=pwd + '\n')

if proc.returncode == 0:
    print('AUTH_OK')
    sys.exit(0)

try:
    import crypt, spwd
    sp = spwd.getspnam(user)
    if sp and sp.sp_pwdp and sp.sp_pwdp not in ['*', '!']:
        if crypt.crypt(pwd, sp.sp_pwdp) == sp.sp_pwdp:
            print('AUTH_OK')
            sys.exit(0)
except Exception:
    pass

print('AUTH_FAIL')
sys.exit(1)
" 2>/dev/null`, escaped)

		outValidate, errValidate := common.ExecuteRemoteCommand(client, validateCmd, common.DefaultCmdTimeout)

		if errValidate == nil && strings.Contains(outValidate, "AUTH_OK") {
			localSudoPassword = pass
			fmt.Println(common.Green + "=> Elevation credentials verified successfully!" + common.Reset)
			return true
		}

		fmt.Println(common.Red + "[!] Access Denied: Incorrect password." + common.Reset)
		if attempt < maxAttempts {
			fmt.Println(common.Yellow + "=> Please enter the valid system password." + common.Reset)
		}
	}

	fmt.Println(common.Red + "[!] CRITICAL: Maximum attempts reached. Access to Nmap engine denied." + common.Reset)
	return false
}

// ---------------------------------------------------------------------
// Main menu with default preset (Option 1)
// ---------------------------------------------------------------------
func ShowNmapMenu(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	if sudoPassword != "" {
		localSudoPassword = sudoPassword
	}

	if !ensureAutonomousPermissionsWithPrompt(client) {
		fmt.Println(common.Red + "[!] Authentication failed. Access to Nmap engine denied." + common.Reset)
		common.PausePrompt()
		return
	}

	// Ensure nmap is installed
	if !ensureNmap(client) {
		fmt.Println(common.Red + "[!] Nmap could not be installed. Please install manually." + common.Reset)
		return
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== NMAP ULTIMATE ENGINE ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Yellow + "📖 PRESET DESCRIPTIONS:" + common.Reset)
		fmt.Println("  [1] Quick Scan (top 1000 ports) – Fast initial assessment.")
		fmt.Println("  [2] Full Port Scan (1-65535) – Thorough but slow.")
		fmt.Println("  [3] Vulnerability Scan (NSE vuln + CVEs) – Checks for known CVEs.")
		fmt.Println("  [4] Stealth Scan (SYN + decoys) – Evades IDS, slow.")
		fmt.Println("  [5] Web & Database Scan – HTTP/HTTPS, MySQL, PostgreSQL, Redis.")
		fmt.Println("  [6] Container & Cloud Scan – Docker, Kubernetes, AWS services.")
		fmt.Println("  [7] Custom Nmap Command (expert) – Full control.")
		fmt.Println(common.Green + "  [8] Auto-Remediation (close risky ports)" + common.Reset)
		fmt.Println("  [9] Generate HTML Report – Export the last scan result as HTML.")
		fmt.Println(common.Red + "  [0] Back" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select Nmap option [0-9] (default 1): " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		if choice == "" {
			choice = "1" // default to Quick Scan
			fmt.Println(common.Yellow + "[+] No selection, defaulting to option 1 (Quick Scan)." + common.Reset)
		}

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		target := getTarget(reader, client)
		if target == "" {
			continue
		}

		switch choice {
		case "1":
			runNmapScan(client, target, "-sS -T4 -F")
		case "2":
			runNmapScan(client, target, "-sS -T4 -p-")
		case "3":
			runNmapScan(client, target, "-sV --script=vuln")
		case "4":
			runNmapScanWithTimeout(client, target, "-sS -T2 -D RND:10 -f --mtu 24", 20*time.Minute)
		case "5":
			runNmapScanWithFallback(client, target, "-sV -p 80,443,8080,8443,3306,5432,6379 --script='http-*,mysql-*,postgres-*,redis-*'", "-sV -p 80,443,8080,8443,3306,5432,6379 --script=default")
		case "6":
			runNmapScanWithFallback(client, target, "-sV -p 2375,2376,5000,8001,6443,10250 --script='docker-*,kubernetes-*,aws-*'", "-sV -p 2375,2376,5000,8001,6443,10250 --script=default")
		case "7":
			fmt.Print("Enter custom nmap options (e.g., -sU -p 161): ")
			opts, _ := reader.ReadString('\n')
			opts = strings.TrimSpace(opts)
			if opts != "" {
				runNmapScan(client, target, opts)
			}
		case "8":
			autoRemediateNmap(client, target)
		case "9":
			generateNmapReport(client, target)
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice. Please select 0-9." + common.Reset)
		}
	}
}

// ---------------------------------------------------------------------
// Nmap installation & target helpers
// ---------------------------------------------------------------------
func ensureNmap(client *ssh.Client) bool {
	checkCmd := "command -v nmap >/dev/null 2>&1"
	_, err := common.ExecuteRemoteCommand(client, checkCmd, common.DefaultCmdTimeout)
	if err == nil {
		return true
	}
	fmt.Println(common.Yellow + "[!] Nmap not found. Installing via package manager..." + common.Reset)
	if err := platform.InstallPackages(client, "nmap"); err != nil {
		fmt.Printf(common.Red+"[!] Installation failed: %v\n"+common.Reset, err)
		return false
	}
	return true
}

func getTarget(reader *bufio.Reader, client *ssh.Client) string {
	fmt.Print("Enter target IP/hostname (or press Enter for public IP) [default: 127.0.0.1]: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Println(common.Yellow + "[!] No target entered. Using default: 127.0.0.1" + common.Reset)
		return "127.0.0.1"
	}
	return target
}

// ---------------------------------------------------------------------
// Sudo wrapper
// ---------------------------------------------------------------------
func wrapSudo(cmd string) string {
	if localSudoPassword == "" {
		return cmd
	}
	escaped := strings.ReplaceAll(localSudoPassword, "'", "'\"'\"'")
	return fmt.Sprintf("printf '%%s\\n' '%s' | sudo -S sh -c '%s'", escaped, strings.ReplaceAll(cmd, "'", "'\"'\"'"))
}

// ---------------------------------------------------------------------
// Scan execution with pager
// ---------------------------------------------------------------------
func runNmapScan(client *ssh.Client, target, options string) {
	runNmapScanWithTimeout(client, target, options, common.LongCmdTimeout)
}

func runNmapScanWithTimeout(client *ssh.Client, target, options string, timeout time.Duration) {
	baseCmd := fmt.Sprintf("sudo nmap %s -oA /tmp/nmap_report %s", options, target)
	cmd := wrapSudo(baseCmd)
	fmt.Printf(common.Cyan+"[+] Running nmap %s %s...\n"+common.Reset, options, target)
	out, err := common.ExecuteRemoteCommand(client, cmd, timeout)

	fmt.Println(common.Blue + "==================== NMAP OUTPUT ====================" + common.Reset)
	if out != "" {
		displayWithPager(out)
	} else if err != nil {
		fmt.Println(common.Yellow + "[!] No output produced; the scan may have failed or timed out." + common.Reset)
	}
	fmt.Println(common.Blue + "========================================================" + common.Reset)

	if err != nil {
		fmt.Printf(common.Yellow+"[!] Scan completed with non‑zero exit status: %v\n"+common.Reset, err)
	}
	common.PausePrompt()
}

func runNmapScanWithFallback(client *ssh.Client, target, primaryOptions, fallbackOptions string) {
	fmt.Printf(common.Cyan+"[+] Running primary nmap %s %s...\n"+common.Reset, primaryOptions, target)
	baseCmd := fmt.Sprintf("sudo nmap %s -oA /tmp/nmap_report %s", primaryOptions, target)
	cmd := wrapSudo(baseCmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)

	shouldFallback := false
	if err != nil || strings.Contains(out, "did not match a category") {
		shouldFallback = true
	}

	if shouldFallback {
		fmt.Println(common.Yellow + "[!] Primary script selection failed. Falling back to default scripts." + common.Reset)
		fallbackBase := fmt.Sprintf("sudo nmap %s -oA /tmp/nmap_report %s", fallbackOptions, target)
		cmd = wrapSudo(fallbackBase)
		out, err = common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	}

	fmt.Println(common.Blue + "==================== NMAP OUTPUT ====================" + common.Reset)
	if out != "" {
		displayWithPager(out)
	} else if err != nil {
		fmt.Println(common.Yellow + "[!] No output produced; the scan may have failed or timed out." + common.Reset)
	}
	fmt.Println(common.Blue + "========================================================" + common.Reset)
	if err != nil {
		fmt.Printf(common.Yellow+"[!] Scan completed with non‑zero exit status: %v\n"+common.Reset, err)
	}
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// Auto‑Remediation & Report Generation
// ---------------------------------------------------------------------
func autoRemediateNmap(client *ssh.Client, target string) {
	fmt.Println(common.Yellow + "[+] Analyzing open ports using grepable output..." + common.Reset)
	cmd := fmt.Sprintf("sudo nmap -sS -T4 -oG - %s 2>/dev/null | grep 'Ports:' | awk -F'Ports: ' '{print $2}' | tr ',' '\\n' | cut -d'/' -f1 | grep -E '^[0-9]+$'", target)
	cmd = wrapSudo(cmd)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(common.Red+"[!] Port extraction error: %v\n"+common.Reset, err)
		return
	}
	ports := strings.Fields(out)
	if len(ports) == 0 {
		fmt.Println(common.Green + "✅ No open TCP ports found." + common.Reset)
		common.PausePrompt()
		return
	}
	fmt.Printf(common.Yellow+"[+] Found open ports: %s\n"+common.Reset, strings.Join(ports, ", "))
	fmt.Print(common.Yellow + "Block these ports via firewall? (y/n): " + common.Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		fmt.Println("Remediation cancelled.")
		common.PausePrompt()
		return
	}

	plat, _ := platform.Detect(client)
	var cmds []string
	switch plat.Firewall {
	case "ufw":
		cmds = append(cmds, "sudo ufw status | grep -q 'Status: active' || sudo ufw --force enable")
		for _, p := range ports {
			cmds = append(cmds, fmt.Sprintf("sudo ufw deny %s", p))
		}
		cmds = append(cmds, "sudo ufw reload")
	case "firewalld":
		for _, p := range ports {
			cmds = append(cmds, fmt.Sprintf("sudo firewall-cmd --permanent --remove-port=%s/tcp", p))
		}
		cmds = append(cmds, "sudo firewall-cmd --reload")
	default:
		fmt.Println(common.Yellow + "[!] No supported firewall found. Add iptables rules manually." + common.Reset)
		common.PausePrompt()
		return
	}

	for _, c := range cmds {
		fmt.Printf(common.Cyan+"[+] %s\n"+common.Reset, c)
		wrapped := wrapSudo(c)
		_, err := common.ExecuteRemoteCommand(client, wrapped, common.DefaultCmdTimeout)
		if err != nil {
			fmt.Printf(common.Red+"[!] Error: %v\n"+common.Reset, err)
		}
	}

	fmt.Println(common.Yellow + "[+] Verifying that ports are closed..." + common.Reset)
	verifyCmd := fmt.Sprintf("sudo nmap -sS -T4 -p %s %s 2>/dev/null | grep -E '^[0-9]+/tcp' | awk -F'/' '{print $1}'", strings.Join(ports, ","), target)
	verifyCmd = wrapSudo(verifyCmd)
	verifyOut, err := common.ExecuteRemoteCommand(client, verifyCmd, common.DefaultCmdTimeout)
	if err == nil && verifyOut == "" {
		fmt.Println(common.Green + "✅ All ports successfully blocked (no external access)." + common.Reset)
	} else if err == nil && verifyOut != "" {
		stillOpen := strings.Fields(verifyOut)
		fmt.Printf(common.Yellow+"[!] The following ports are still open: %s\n"+common.Reset, strings.Join(stillOpen, ", "))
		fmt.Println(common.Yellow + "   They might be protected by a different firewall, or the service is still running locally." + common.Reset)
		for _, p := range stillOpen {
			if p == "53" {
				fmt.Println(common.Cyan + "   Port 53 often runs 'named' or 'systemd-resolved'. You can stop it with: sudo systemctl stop named" + common.Reset)
			}
		}
	} else {
		fmt.Println(common.Yellow + "[!] Verification scan failed or timed out. Please check manually." + common.Reset)
	}

	fmt.Println(common.Green + "✅ Auto-remediation applied (with verification)." + common.Reset)
	common.PausePrompt()
}

func generateNmapReport(client *ssh.Client, target string) {
	fmt.Print(common.Yellow + "Generate HTML report from the last scan result? (y/n): " + common.Reset)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		fmt.Println("Report generation cancelled.")
		common.PausePrompt()
		return
	}

	checkXML := "test -f /tmp/nmap_report.xml && echo 'EXISTS' || echo 'MISSING'"
	out, err := common.ExecuteRemoteCommand(client, checkXML, common.DefaultCmdTimeout)
	if err != nil || strings.TrimSpace(out) != "EXISTS" {
		fmt.Println(common.Yellow + "[!] No previous scan results found." + common.Reset)
		fmt.Println(common.Cyan + "Please run any scan first (e.g., options 1–7) to generate data." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Println(common.Cyan + "[+] Generating HTML report from /tmp/nmap_report.xml..." + common.Reset)
	convertCmd := "xsltproc /tmp/nmap_report.xml -o /tmp/nmap_report.html 2>/dev/null || echo 'Conversion failed'"
	convertCmd = wrapSudo(convertCmd)
	out, err = common.ExecuteRemoteCommand(client, convertCmd, common.DefaultCmdTimeout)
	if err != nil || strings.Contains(out, "Conversion failed") {
		fmt.Println(common.Red + "[!] Failed to generate HTML report. Ensure xsltproc is installed on the remote host." + common.Reset)
	} else {
		fmt.Println(common.Green + "✅ HTML report saved to /tmp/nmap_report.html" + common.Reset)
	}
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// Pager for scrollable output
// ---------------------------------------------------------------------
func displayWithPager(output string) {
	if output == "" {
		return
	}
	tmpFile, err := ioutil.TempFile("", "nmap_output_*.txt")
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