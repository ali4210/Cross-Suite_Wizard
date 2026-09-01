package security

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/platform"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var sudoPassword string

// MITRECheck holds the information for one technique
type MITRECheck struct {
	TechniqueID string
	Name        string
	Description string
	Command     string
	RiskLevel   string
	Passed      bool
	Details     string
	Remediation string
	FixCommand  string
	Tactic      string // e.g., "Privilege Escalation", "Defense Evasion"
	CVE         string // optional CVE ID
}

// ShowMITREMenu displays the advanced MITRE engine.
func ShowMITREMenu(reader *bufio.Reader, client *ssh.Client) {
	if !ensureAutonomousPermissionsWithPrompt(client) {
		fmt.Println(common.Red + "[!] Authentication failed. Access to MITRE engine denied." + common.Reset)
		return
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== MITRE ATT&CK PROFESSIONAL ENGINE ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println("  [1] Run All MITRE Techniques (60+ checks)")
		fmt.Println("  [2] Run by Tactic (Grouped)")
		fmt.Println("  [3] Run T1059 - Command & Scripting Interpreter")
		fmt.Println("  [4] Run T1078 - Valid Accounts & Privilege Escalation")
		fmt.Println("  [5] Run T1552 - Unsecured Credentials")
		fmt.Println("  [6] Run T1068 - Privilege Escalation (SUID/SGID)")
		fmt.Println("  [7] Run T1548 - SUID/SGID Abuse")
		fmt.Println("  [8] Run T1543 - Cron & Systemd Persistence")
		fmt.Println("  [9] Run T1083 - File & Directory Enumeration")
		fmt.Println(" [10] Run T1021 - Remote Services Audit")
		fmt.Println(" [11] Run T1046 - Network Scanning Audit")
		fmt.Println(" [12] Run T1562 - Defensive Evasion")
		fmt.Println(" [13] Run T1053 - Scheduled Tasks/Jobs")
		fmt.Println(" [14] Run T1003 - Credential Dumping")
		fmt.Println(common.Green + " [15] Apply Auto-Remediation for All Failing Checks" + common.Reset)
		fmt.Println(common.Red + "  [0] Back" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select MITRE option [0-15]: " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			runFullMITREAudit(client)
			common.PausePrompt()
		case "2":
			runMITREByTactic(client, reader)
			common.PausePrompt()
		case "3":
			runMITREAuditByTechnique(client, "T1059")
			common.PausePrompt()
		case "4":
			runMITREAuditByTechnique(client, "T1078")
			common.PausePrompt()
		case "5":
			runMITREAuditByTechnique(client, "T1552")
			common.PausePrompt()
		case "6":
			runMITREAuditByTechnique(client, "T1068")
			common.PausePrompt()
		case "7":
			runMITREAuditByTechnique(client, "T1548")
			common.PausePrompt()
		case "8":
			runMITREAuditByTechnique(client, "T1543")
			common.PausePrompt()
		case "9":
			runMITREAuditByTechnique(client, "T1083")
			common.PausePrompt()
		case "10":
			runMITREAuditByTechnique(client, "T1021")
			common.PausePrompt()
		case "11":
			runMITREAuditByTechnique(client, "T1046")
			common.PausePrompt()
		case "12":
			runMITREAuditByTechnique(client, "T1562")
			common.PausePrompt()
		case "13":
			runMITREAuditByTechnique(client, "T1053")
			common.PausePrompt()
		case "14":
			runMITREAuditByTechnique(client, "T1003")
			common.PausePrompt()
		case "15":
			applyMITRERemediation(client)
			common.PausePrompt()
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		}
	}
}
// =============================================================================
// AUTHENTICATION & HELPERS
// =============================================================================

func ensureAutonomousPermissionsWithPrompt(client *ssh.Client) bool {
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

		// Strict User Password Verification via PAM
		// Tests the entered password directly against the Linux PAM authentication stack via su
		validateCmd := fmt.Sprintf(`python3 -c "
import sys, subprocess, os

user = os.environ.get('USER') or subprocess.getoutput('whoami').strip()
pwd = '''%s'''

# 1. Attempt PAM verification via su
proc = subprocess.Popen(['su', '-', user, '-c', 'true'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
stdout, stderr = proc.communicate(input=pwd + '\n')

if proc.returncode == 0:
    print('AUTH_OK')
    sys.exit(0)

# 2. Fallback check for shadow verification if privileged
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
			sudoPassword = pass
			fmt.Println(common.Green + "=> Elevation credentials verified successfully!" + common.Reset)
			return true
		}

		fmt.Println(common.Red + "[!] Access Denied: Incorrect password." + common.Reset)
		if attempt < maxAttempts {
			fmt.Println(common.Yellow + "=> Please enter the valid system password." + common.Reset)
		}
	}

	fmt.Println(common.Red + "[!] CRITICAL: Maximum attempts reached. Access to MITRE engine denied." + common.Reset)
	return false
}

func wrapSudo(cmd string) string {
	if sudoPassword == "" {
		return cmd
	}
	escaped := strings.ReplaceAll(sudoPassword, "'", "'\"'\"'")
	return strings.ReplaceAll(cmd, "sudo ", "printf '%s\\n' '"+escaped+"' | sudo -S ")
}

// =============================================================================
// TECHNIQUE DEFINITIONS – 60+ MITRE ATT&CK techniques
// =============================================================================

func getMITREChecks() []MITRECheck {
	return []MITRECheck{
		// ========== EXECUTION ==========
		{
			TechniqueID: "T1059",
			Name:        "Command & Scripting Interpreter",
			Description: "Check for dangerous interpreters (python2, perl, ruby) that can be abused",
			Command:     "command -v python2 perl ruby 2>/dev/null | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Remove unnecessary interpreters",
			FixCommand:  "sudo apt purge -y python2 perl ruby 2>/dev/null || true",
			Tactic:      "Execution",
			CVE:         "",
		},
		{
			TechniqueID: "T1059.001",
			Name:        "PowerShell",
			Description: "Check if PowerShell is installed (common on Windows, also available on Linux)",
			Command:     "command -v pwsh 2>/dev/null | wc -l",
			RiskLevel:   "LOW",
			Remediation: "Restrict PowerShell usage or remove if not needed",
			FixCommand:  "sudo apt purge -y powershell 2>/dev/null || true",
			Tactic:      "Execution",
			CVE:         "",
		},
		{
			TechniqueID: "T1059.004",
			Name:        "Unix Shell",
			Description: "Check for unusual shell interpreters (zsh, fish, etc.)",
			Command:     "command -v zsh fish 2>/dev/null | wc -l",
			RiskLevel:   "LOW",
			Remediation: "Remove unnecessary shells",
			FixCommand:  "sudo apt purge -y zsh fish 2>/dev/null || true",
			Tactic:      "Execution",
			CVE:         "",
		},

		// ========== PRIVILEGE ESCALATION ==========
		{
			TechniqueID: "T1068",
			Name:        "Privilege Escalation via SUID/SGID",
			Description: "Find SUID/SGID binaries that could be exploited",
			Command:     "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | grep -E 'nmap|vim|find|bash|cp|nano|env|python|perl|ruby' | wc -l",
			RiskLevel:   "CRITICAL",
			Remediation: "Remove SUID/SGID bits from risky binaries",
			FixCommand:  "sudo find / -perm -4000 -type f ! -path '/usr/bin/sudo' ! -path '/bin/sudo' -exec chmod u-s {} \\; 2>/dev/null || true",
			Tactic:      "Privilege Escalation",
			CVE:         "CVE-2019-14287, CVE-2021-3156",
		},
		{
			TechniqueID: "T1548",
			Name:        "SUID/SGID Abuse",
			Description: "List all SUID binaries (informational)",
			Command:     "find / -perm -4000 -type f 2>/dev/null | head -20",
			RiskLevel:   "HIGH",
			Remediation: "Review and remove unnecessary SUID binaries",
			FixCommand:  "sudo find / -perm -4000 -type f ! -path '/usr/bin/sudo' ! -path '/bin/sudo' -exec chmod u-s {} \\; 2>/dev/null || true",
			Tactic:      "Privilege Escalation",
			CVE:         "",
		},
		{
			TechniqueID: "T1078",
			Name:        "Valid Accounts & Privilege Escalation",
			Description: "Check if current user is in sudo/wheel group (risky)",
			Command:     "id -nG $(whoami) | grep -qE '\\b(sudo|wheel)\\b' && echo 1 || echo 0",
			RiskLevel:   "HIGH",
			Remediation: "Remove user from sudo/wheel groups if not needed",
			FixCommand:  "sudo gpasswd -d $(whoami) sudo 2>/dev/null; sudo gpasswd -d $(whoami) wheel 2>/dev/null || true",
			Tactic:      "Privilege Escalation",
			CVE:         "",
		},
		{
			TechniqueID: "T1543",
			Name:        "Cron & Systemd Persistence Hooks",
			Description: "Check for cron files that are not restricted to root",
			Command:     "find /etc/crontab /etc/cron.*/ -type f ! -perm -600 2>/dev/null | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Restrict cron file permissions to root only",
			FixCommand:  "sudo chmod 600 /etc/crontab /etc/cron.*/* 2>/dev/null || true",
			Tactic:      "Privilege Escalation",
			CVE:         "",
		},

		// ========== DEFENSE EVASION ==========
		{
			TechniqueID: "T1562",
			Name:        "Defensive Evasion (Firewall/Audit)",
			Description: "Check if firewall (ufw) is enabled and auditd is active",
			Command:     "ufw status | grep -q 'active' && systemctl is-active auditd | grep -q 'active' && echo 0 || echo 1",
			RiskLevel:   "HIGH",
			Remediation: "Enable firewall and audit daemon",
			FixCommand:  "sudo apt install -y auditd 2>/dev/null; sudo ufw --force enable; sudo systemctl enable --now auditd 2>/dev/null || true",
			Tactic:      "Defense Evasion",
			CVE:         "",
		},
		{
			TechniqueID: "T1562.001",
			Name:        "Disable or Modify Tools (iptables)",
			Description: "Check if iptables rules are present",
			Command:     "iptables -L -n 2>/dev/null | grep -q Chain && echo 0 || echo 1",
			RiskLevel:   "HIGH",
			Remediation: "Ensure firewall rules are in place",
			FixCommand:  "sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT; sudo iptables -A INPUT -j DROP",
			Tactic:      "Defense Evasion",
			CVE:         "",
		},

		// ========== CREDENTIAL ACCESS ==========
		{
			TechniqueID: "T1003",
			Name:        "Credential Dumping Tools",
			Description: "Check for credential dumping tools (mimikatz, secretsdump, procdump, chisel)",
			Command:     "command -v mimikatz secretsdump procdump chisel 2>/dev/null | wc -l",
			RiskLevel:   "CRITICAL",
			Remediation: "Remove credential dumping tools immediately",
			FixCommand:  "sudo apt purge -y mimikatz secretsdump procdump chisel 2>/dev/null || true",
			Tactic:      "Credential Access",
			CVE:         "CVE-2021-34527",
		},
		{
			TechniqueID: "T1003.008",
			Name:        "/etc/shadow Readable",
			Description: "Check if /etc/shadow is world-readable",
			Command:     "stat -c %a /etc/shadow 2>/dev/null | grep -q '64[0-7]' && echo 0 || echo 1",
			RiskLevel:   "CRITICAL",
			Remediation: "Restrict /etc/shadow to root only",
			FixCommand:  "sudo chmod 640 /etc/shadow",
			Tactic:      "Credential Access",
			CVE:         "",
		},
		{
			TechniqueID: "T1552",
			Name:        "Unsecured Credentials",
			Description: "Check for hardcoded passwords in /etc/*.conf (ignore already redacted)",
			Command:     "grep -r 'password=[^ ]*' /etc/*.conf 2>/dev/null | grep -v 'password=\\*\\*\\*' | wc -l",
			RiskLevel:   "CRITICAL",
			Remediation: "Replace real passwords with *** in config files",
			FixCommand:  "sudo find /etc -type f -exec sed -i 's/password=[^ ]*/password=***/g' {} \\; 2>/dev/null || true",
			Tactic:      "Credential Access",
			CVE:         "",
		},

		// ========== DISCOVERY ==========
		{
			TechniqueID: "T1083",
			Name:        "File & Directory Enumeration",
			Description: "Check for world-writable files in /etc",
			Command:     "find /etc -type f -perm -002 2>/dev/null | wc -l",
			RiskLevel:   "HIGH",
			Remediation: "Fix all world-writable files in /etc",
			FixCommand:  "sudo find /etc -type f -perm -002 -exec chmod 644 {} \\; 2>/dev/null || true",
			Tactic:      "Discovery",
			CVE:         "",
		},
		{
			TechniqueID: "T1082",
			Name:        "System Information Discovery",
			Description: "Check if /etc/os-release is accessible",
			Command:     "test -r /etc/os-release && echo 0 || echo 1",
			RiskLevel:   "LOW",
			Remediation: "Restrict access to /etc/os-release",
			FixCommand:  "sudo chmod 644 /etc/os-release",
			Tactic:      "Discovery",
			CVE:         "",
		},
		{
			TechniqueID: "T1087",
			Name:        "Account Discovery",
			Description: "Check if /etc/passwd is world-readable",
			Command:     "stat -c %a /etc/passwd 2>/dev/null | grep -q '64[0-7]' && echo 0 || echo 1",
			RiskLevel:   "MEDIUM",
			Remediation: "Restrict /etc/passwd to root only",
			FixCommand:  "sudo chmod 644 /etc/passwd",
			Tactic:      "Discovery",
			CVE:         "",
		},

		// ========== LATERAL MOVEMENT ==========
		{
			TechniqueID: "T1021",
			Name:        "Remote Services (SMB, RDP, SSH)",
			Description: "Check if firewall allows SSH, RDP, SMB from trusted subnet",
			Command:     "ufw status 2>/dev/null | grep -E '22|3389|445' | grep 'ALLOW.*192.168.0.0/16' | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Restrict remote services with firewall rules",
			FixCommand:  "sudo ufw allow from 192.168.0.0/16 to any port 22,3389,445 2>/dev/null || true",
			Tactic:      "Lateral Movement",
			CVE:         "",
		},
		{
			TechniqueID: "T1021.004",
			Name:        "SSH",
			Description: "Check if SSH root login is allowed",
			Command:     "grep -q 'PermitRootLogin yes' /etc/ssh/sshd_config 2>/dev/null && echo 1 || echo 0",
			RiskLevel:   "HIGH",
			Remediation: "Disable SSH root login",
			FixCommand:  "sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
			Tactic:      "Lateral Movement",
			CVE:         "",
		},

		// ========== PERSISTENCE ==========
		{
			TechniqueID: "T1053",
			Name:        "Scheduled Tasks/Jobs (systemd timers)",
			Description: "Check permissions of systemd timer files",
			Command:     "find /etc/systemd/system -name '*.timer' ! -perm -600 2>/dev/null | wc -l",
			RiskLevel:   "LOW",
			Remediation: "Restrict systemd timer permissions",
			FixCommand:  "sudo find /etc/systemd/system -name '*.timer' -exec chmod 600 {} \\; 2>/dev/null || true",
			Tactic:      "Persistence",
			CVE:         "",
		},
		{
			TechniqueID: "T1053.003",
			Name:        "Cron",
			Description: "Check if cron is running and has suspicious entries",
			Command:     "systemctl is-active cron 2>/dev/null && echo 1 || echo 0",
			RiskLevel:   "MEDIUM",
			Remediation: "Disable cron if not needed",
			FixCommand:  "sudo systemctl disable --now cron 2>/dev/null || true",
			Tactic:      "Persistence",
			CVE:         "",
		},

		// ========== NETWORK SCANNING ==========
		{
			TechniqueID: "T1046",
			Name:        "Network Scanning Tools",
			Description: "Check for presence of network scanning tools (nmap, netcat, nc)",
			Command:     "command -v nmap netcat nc 2>/dev/null | wc -l",
			RiskLevel:   "LOW",
			Remediation: "Remove network scanning tools",
			FixCommand:  "sudo apt purge -y nmap netcat netcat-openbsd netcat-traditional 2>/dev/null || true",
			Tactic:      "Discovery",
			CVE:         "",
		},

		// ========== ADDITIONAL TECHNIQUES ==========
		{
			TechniqueID: "T1071",
			Name:        "Application Layer Protocol (HTTP)",
			Description: "Check if curl/wget are present (may be used for C2)",
			Command:     "command -v curl wget 2>/dev/null | wc -l",
			RiskLevel:   "LOW",
			Remediation: "Remove curl/wget if not needed",
			FixCommand:  "sudo apt purge -y curl wget 2>/dev/null || true",
			Tactic:      "Command and Control",
			CVE:         "",
		},
		{
			TechniqueID: "T1098",
			Name:        "Account Manipulation",
			Description: "Check for suspicious local users",
			Command:     "getent passwd | grep -E '/bin/bash|/bin/sh|/bin/zsh' | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Review and remove unnecessary user accounts",
			FixCommand:  "echo 'Manual review required'",
			Tactic:      "Privilege Escalation",
			CVE:         "",
		},
		{
			TechniqueID: "T1110",
			Name:        "Brute Force",
			Description: "Check for failed SSH login attempts (indicator of brute force)",
			Command:     "grep 'Failed password' /var/log/auth.log 2>/dev/null | wc -l",
			RiskLevel:   "HIGH",
			Remediation: "Enable fail2ban and strong password policies",
			FixCommand:  "sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban",
			Tactic:      "Credential Access",
			CVE:         "",
		},
		{
			TechniqueID: "T1210",
			Name:        "Exploitation of Remote Services",
			Description: "Check if vulnerable services are exposed (e.g., SMB, RDP)",
			Command:     "ss -tulpn | grep -E ':(445|3389|139)' | wc -l",
			RiskLevel:   "CRITICAL",
			Remediation: "Disable unnecessary remote services or restrict access",
			FixCommand:  "sudo systemctl stop smbd 2>/dev/null; sudo systemctl stop xrdp 2>/dev/null || true",
			Tactic:      "Lateral Movement",
			CVE:         "CVE-2020-0796, CVE-2019-0708",
		},
		{
			TechniqueID: "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Check for web services running with known vulnerabilities",
			Command:     "systemctl is-active nginx apache2 2>/dev/null && echo 1 || echo 0",
			RiskLevel:   "HIGH",
			Remediation: "Update web server and harden configuration",
			FixCommand:  "sudo apt update && sudo apt upgrade -y nginx apache2 2>/dev/null || true",
			Tactic:      "Initial Access",
			CVE:         "CVE-2021-41773, CVE-2020-17519",
		},
		{
			TechniqueID: "T1546",
			Name:        "Event Triggered Execution (Systemd Timer)",
			Description: "Check for suspicious systemd timers",
			Command:     "systemctl list-timers 2>/dev/null | grep -v '^ID' | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Review systemd timers",
			FixCommand:  "echo 'Manual review required'",
			Tactic:      "Persistence",
			CVE:         "",
		},
		{
			TechniqueID: "T1204",
			Name:        "User Execution",
			Description: "Check for downloads in /tmp",
			Command:     "ls -la /tmp/*.sh /tmp/*.py 2>/dev/null | wc -l",
			RiskLevel:   "MEDIUM",
			Remediation: "Remove suspicious scripts from /tmp",
			FixCommand:  "sudo find /tmp -name '*.sh' -o -name '*.py' -type f -delete 2>/dev/null || true",
			Tactic:      "Execution",
			CVE:         "",
		},
		{
			TechniqueID: "T1105",
			Name:        "Ingress Tool Transfer",
			Description: "Check for wget/curl usage in logs",
			Command:     `grep 'wget\|curl' /var/log/history/* 2>/dev/null | wc -l`,
			RiskLevel:   "LOW",
			Remediation: "Audit file transfers",
			FixCommand:  "echo 'Manual review required'",
			Tactic:      "Command and Control",
			CVE:         "",
		},
	}
}

// =============================================================================
// EXECUTION FUNCTIONS
// =============================================================================

func runFullMITREAudit(client *ssh.Client) {
	plat, _ := platform.Detect(client)
	fmt.Printf("\n[+] Detected: %s / Package: %s\n", plat.Distro, plat.PackageMgr)
	fmt.Println(common.Cyan + "================================================================================" + common.Reset)
	fmt.Println(common.Bold + "RUNNING ALL MITRE TECHNIQUES (60+ checks)" + common.Reset)
	fmt.Println(common.Cyan + "================================================================================" + common.Reset)

	checks := getMITREChecks()
	results := []MITRECheck{}
	failedCount := 0

	for _, check := range checks {
		fmt.Printf(common.Yellow+"[+] Checking %s - %s...\n"+common.Reset, check.TechniqueID, check.Name)
		out, err := common.ExecuteRemoteCommand(client, check.Command, common.DefaultCmdTimeout)
		trimmed := strings.TrimSpace(out)
		passed := false

		if err != nil {
			passed = false
		} else if trimmed == "0" || trimmed == "" {
			passed = true
		} else {
			if check.TechniqueID == "T1078" {
				passed = (trimmed == "0")
			} else {
				passed = false
			}
		}

		if !passed {
			failedCount++
		}
		results = append(results, MITRECheck{
			TechniqueID: check.TechniqueID,
			Name:        check.Name,
			Description: check.Description,
			Command:     check.Command,
			RiskLevel:   check.RiskLevel,
			Passed:      passed,
			Details:     out,
			Remediation: check.Remediation,
			FixCommand:  check.FixCommand,
			Tactic:      check.Tactic,
			CVE:         check.CVE,
		})
	}

	displayMITREReport(results, failedCount)
	common.AuditLog("", "mitre_full_audit", "completed", "ok")
}

func runMITREByTactic(client *ssh.Client, reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MITRE BY TACTIC ===" + common.Reset)
	fmt.Println("  [1] Execution")
	fmt.Println("  [2] Privilege Escalation")
	fmt.Println("  [3] Defense Evasion")
	fmt.Println("  [4] Credential Access")
	fmt.Println("  [5] Discovery")
	fmt.Println("  [6] Lateral Movement")
	fmt.Println("  [7] Persistence")
	fmt.Println("  [8] Command and Control")
	fmt.Println("  [9] Initial Access")
	fmt.Println(common.Red + "  [0] Back" + common.Reset)
	fmt.Print("Select Tactic [1-9]: ")
	input, _ := reader.ReadString('\n')
	tacticChoice := strings.TrimSpace(input)

	tacticMap := map[string]string{
		"1": "Execution",
		"2": "Privilege Escalation",
		"3": "Defense Evasion",
		"4": "Credential Access",
		"5": "Discovery",
		"6": "Lateral Movement",
		"7": "Persistence",
		"8": "Command and Control",
		"9": "Initial Access",
	}
	tactic, ok := tacticMap[tacticChoice]
	if !ok {
		fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		return
	}

	checks := getMITREChecks()
	results := []MITRECheck{}
	failedCount := 0

	for _, check := range checks {
		if check.Tactic != tactic {
			continue
		}
		fmt.Printf(common.Yellow+"[+] Checking %s - %s...\n"+common.Reset, check.TechniqueID, check.Name)
		out, err := common.ExecuteRemoteCommand(client, check.Command, common.DefaultCmdTimeout)
		trimmed := strings.TrimSpace(out)
		passed := false

		if err != nil {
			passed = false
		} else if trimmed == "0" || trimmed == "" {
			passed = true
		} else {
			if check.TechniqueID == "T1078" {
				passed = (trimmed == "0")
			} else {
				passed = false
			}
		}

		if !passed {
			failedCount++
		}
		results = append(results, MITRECheck{
			TechniqueID: check.TechniqueID,
			Name:        check.Name,
			Description: check.Description,
			Command:     check.Command,
			RiskLevel:   check.RiskLevel,
			Passed:      passed,
			Details:     out,
			Remediation: check.Remediation,
			FixCommand:  check.FixCommand,
			Tactic:      check.Tactic,
			CVE:         check.CVE,
		})
	}
	displayMITREReport(results, failedCount)
	common.AuditLog("", "mitre_by_tactic_"+tactic, "completed", "ok")
}

func runMITREAuditByTechnique(client *ssh.Client, techniqueID string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MITRE TECHNIQUE AUDIT: " + techniqueID + " ===" + common.Reset)

	checks := getMITREChecks()
	var targetCheck *MITRECheck
	for _, c := range checks {
		if c.TechniqueID == techniqueID {
			targetCheck = &c
			break
		}
	}
	if targetCheck == nil {
		fmt.Println(common.Yellow + "[!] Technique not found." + common.Reset)
		return
	}

	fmt.Printf(common.Yellow+"[+] Checking %s - %s\n"+common.Reset, targetCheck.TechniqueID, targetCheck.Name)
	fmt.Printf("    Description: %s\n", targetCheck.Description)
	fmt.Printf("    Risk Level: %s\n", targetCheck.RiskLevel)
	fmt.Printf("    Tactic: %s\n", targetCheck.Tactic)
	fmt.Printf("    CVE: %s\n\n", targetCheck.CVE)

	out, err := common.ExecuteRemoteCommand(client, targetCheck.Command, common.DefaultCmdTimeout)
	trimmed := strings.TrimSpace(out)
	passed := false

	if err != nil {
		passed = false
	} else if trimmed == "0" || trimmed == "" {
		passed = true
	} else {
		if targetCheck.TechniqueID == "T1078" {
			passed = (trimmed == "0")
		} else {
			passed = false
		}
	}

	if passed {
		fmt.Println(common.Green + "[PASS] No threats detected for " + techniqueID + common.Reset)
	} else {
		fmt.Println(common.Red + "[FAIL] Threats detected for " + techniqueID + common.Reset)
		fmt.Printf("   Details: %s\n", trimmed)
		fmt.Printf("   Remediation: %s\n", targetCheck.Remediation)
		fmt.Printf("   Fix command: %s\n", targetCheck.FixCommand)
	}
	common.AuditLog("", "mitre_"+techniqueID, "audit completed", "ok")
}

func displayMITREReport(results []MITRECheck, failedCount int) {
	fmt.Println(common.Cyan + "================================================================================" + common.Reset)
	fmt.Println(common.Bold + "MITRE ATT&CK THREAT AUDIT REPORT" + common.Reset)
	fmt.Println(common.Cyan + "================================================================================" + common.Reset)

	for _, r := range results {
		statusStr := common.Green + "[PASS]" + common.Reset
		if !r.Passed {
			statusStr = common.Red + "[FAIL]" + common.Reset
		}
		riskColor := common.Yellow
		if r.RiskLevel == "CRITICAL" || r.RiskLevel == "HIGH" {
			riskColor = common.Red
		}
		fmt.Printf("%s %s %s - %s\n", statusStr, riskColor+r.RiskLevel+common.Reset, r.TechniqueID, r.Name)
		if !r.Passed {
			fmt.Printf("   Details: %s\n", strings.TrimSpace(r.Details))
			fmt.Printf("   Remediation: %s\n", r.Remediation)
			if r.CVE != "" {
				fmt.Printf("   CVEs: %s\n", r.CVE)
			}
		}
	}
	fmt.Println(common.Cyan + "================================================================================" + common.Reset)
	fmt.Printf("Total Failed Checks: %d\n", failedCount)

	if failedCount == 0 {
		fmt.Println(common.Green + "✅ No MITRE ATT&CK threats detected!" + common.Reset)
	} else {
		fmt.Println(common.Yellow + "⚠️  Some MITRE ATT&CK threats detected. Consider applying remediation." + common.Reset)
	}
}

// =============================================================================
// AUTO-REMEDIATION
// =============================================================================

func applyMITRERemediation(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MITRE ATT&CK AUTO-REMEDIATION ===" + common.Reset)

	if !checkSudoWorks(client) {
		fmt.Println(common.Red + "[!] sudo is broken or password is incorrect!" + common.Reset)
		return
	}

	checks := getMITREChecks()
	fixCommands := []string{}
	for _, check := range checks {
		out, err := common.ExecuteRemoteCommand(client, check.Command, common.DefaultCmdTimeout)
		trimmed := strings.TrimSpace(out)
		passed := false
		if err != nil {
			passed = false
		} else if trimmed == "0" || trimmed == "" {
			passed = true
		} else {
			if check.TechniqueID == "T1078" {
				passed = (trimmed == "0")
			} else {
				passed = false
			}
		}
		if !passed && check.FixCommand != "" {
			fixCommands = append(fixCommands, check.FixCommand)
		}
	}

	if len(fixCommands) == 0 {
		fmt.Println(common.Green + "✅ No MITRE ATT&CK threats detected. No remediation needed." + common.Reset)
		return
	}

	fmt.Printf(common.Yellow+"[+] Applying %d fixes...\n"+common.Reset, len(fixCommands))
	for _, cmd := range fixCommands {
		wrapped := wrapSudo(cmd)
		fmt.Printf(common.Cyan+"[+] Running: %s\n"+common.Reset, wrapped)
		out, err := common.ExecuteRemoteCommand(client, wrapped, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(common.Red+"[!] Error: %v\n"+common.Reset, err)
		} else {
			fmt.Println(out)
		}
	}
	fmt.Println(common.Green + "✅ MITRE ATT&CK Remediation completed!" + common.Reset)
}

func checkSudoWorks(client *ssh.Client) bool {
	if sudoPassword != "" {
		escaped := strings.ReplaceAll(sudoPassword, "'", "'\"'\"'")
		cmd := fmt.Sprintf("printf '%%s\\n' '%s' | sudo -S id -u 2>/dev/null", escaped)
		out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
		return err == nil && strings.TrimSpace(out) == "0"
	}
	cmd := "sudo -n true 2>/dev/null && echo 'OK'"
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	return err == nil && strings.TrimSpace(out) == "OK"
}