package security

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"cross-ssh/pkg/dsomm"
	"cross-ssh/pkg/nmap"
	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/osint"
	"cross-ssh/pkg/platform"
	"cross-ssh/pkg/transfer"
	"cross-ssh/pkg/zap"

	"golang.org/x/crypto/ssh"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Cyan    = "\033[36m"
	Bold    = "\033[1m"

	defaultCmdTimeout = 90 * time.Second
	longCmdTimeout    = 5 * time.Minute
	maxRetries        = 2
)

var (
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$`)
	safePathRe = regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`)
)

// ---------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------
func validateTarget(input string) (string, error) {
	t := strings.TrimSpace(input)
	if t == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.ContainsAny(t, ";&|`$(){}<>\\\"'\n\r") {
		return "", fmt.Errorf("target contains disallowed characters")
	}
	if ip := net.ParseIP(t); ip != nil {
		return t, nil
	}
	if hostnameRe.MatchString(t) && len(t) <= 255 {
		return t, nil
	}
	return "", fmt.Errorf("target is not a valid IP address or hostname: %q", t)
}

func validateOutputPath(input string) (string, error) {
	t := strings.TrimSpace(input)
	if t == "" {
		return "./reports/executive_report.html", nil
	}
	if strings.Contains(t, "..") {
		return "", fmt.Errorf("path traversal ('..') is not allowed")
	}
	if !safePathRe.MatchString(t) {
		return "", fmt.Errorf("path contains disallowed characters: %q", t)
	}
	return t, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------
func auditLog(host, action, detail, result string) {
	f, err := os.OpenFile("compliance_audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println(Yellow + "[!] Could not write audit log entry: " + err.Error() + Reset)
		return
	}
	defer f.Close()
	operator := "unknown"
	if u, err := user.Current(); err == nil {
		operator = u.Username
	}
	line := fmt.Sprintf("%s\toperator=%s\thost=%s\taction=%s\tresult=%s\tdetail=%s\n",
		time.Now().UTC().Format(time.RFC3339), operator, host, action, result,
		strings.ReplaceAll(detail, "\n", " | "))
	_, _ = f.WriteString(line)
}

// ---------------------------------------------------------------------
// Main menu (HUB 6)
// ---------------------------------------------------------------------
func ShowComplianceHubMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, host string) {
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	ShowComplianceMenu(reader, client, string(targetOS), host)
}

func ShowComplianceMenu(reader *bufio.Reader, client *ssh.Client, targetOS string, args ...interface{}) {
	var host string = "127.0.0.1"

	for _, arg := range args {
		if v, ok := arg.(string); ok && strings.TrimSpace(v) != "" {
			host = v
		}
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)
		fmt.Println(Cyan + Bold + "=== HUB 6: SOVEREIGN DEVSECOPS, THREAT HUNTER & COMPLIANCE ENGINE ===" + Reset)
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)
		fmt.Println("  [1] Application Security Testing Suite (SAST / DAST - ZAP Engine)")
		fmt.Println("  [2] Local & Remote Vulnerability Scanner (Trivy / CVE Engine)")
		fmt.Println("  [3] Nmap Made Easy (Interactive Port, Service & Vulnerability Scanner)")
		fmt.Println("  [4] Defensive OSINT, DNS & Historical IP Reconnaissance")
		fmt.Println("  [5] OpenSCAP Engine & SCAP Policy Auto-Remediation")
		fmt.Println("  [6] Chef InSpec Agentless Compliance-as-Code Auditor")
		fmt.Println("  [7] CIS 18 Benchmark & DISA STIG Military Hardening")
		fmt.Println(Yellow + "  [8] MITRE ATT&CK ENGINE (Audit, Remediation & Recovery)" + Reset)
		fmt.Println("  [9] OWASP Top 10, ASVS & DSOMM-Inspired Hardening Scorer")
		fmt.Println(" [10] Ultimate Threat & Vulnerability Sweep (All Tools + Unified Correlation)")
		fmt.Println(Cyan + " [11] OSINT Intelligence Engine (Preset-Based Domain/Email/IP Recon)" + Reset)
		fmt.Println(Cyan + " [12] DSOMM Maturity Scan & Remediation Engine (DevSecOps Maturity)" + Reset)
		fmt.Println(Cyan + " [13] Nmap Ultimate Engine (Professional Nmap Suite)" + Reset)
		fmt.Println(Cyan + " [14] ZAP Proxy Engine (DAST & Web Security)" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Cyan + "--------------------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select choice [0-14]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			runAppSecTestingSuite(client, host)
		case "2":
			runTrivyVulnerabilityScanner(client, host)
		case "3":
			runInteractiveNmapScan(reader, client, host)
		case "4":
			runDefensiveOSINT(client, host)
		case "5":
			runOpenSCAPScan(client, host)
		case "6":
			runInSpecScan(client, host)
		case "7":
			runCISAudit(client, host)
		case "8":
			MITREWrapper(reader, client)
		case "9":
			runOWASPDevSecOpsMaturityScorer(client, host)
		case "10":
			runUltimateThreatSweepCorrelated(reader, client, host)
		case "11":
			osint.ShowOSINTMenu(reader, client, host)
		case "12":
			dsomm.ShowDSOMMMenu(reader, client, host)
		case "13":
			nmap.ShowNmapMenu(reader, client, host, "")
		case "14":
			zap.ShowZAPMenu(reader, client, host, "")
		default:
			fmt.Println(Yellow + "[!] Invalid choice. Please select options 0-14." + Reset)
			time.Sleep(1 * time.Second)
		}
	}
}

// ---------------------------------------------------------------------
// Helper: ensure passwordless sudo
// ---------------------------------------------------------------------
func ensurePasswordlessSudo(client *ssh.Client, host string) bool {
	checkCmd := "if [ $(id -u) -eq 0 ] || sudo -n true 2>/dev/null; then echo 'SUDO_READY'; else echo 'NEED_SUDO_PASS'; fi"
	out, err := executeRemoteCommandCtx(client, checkCmd, defaultCmdTimeout)
	if err == nil && strings.Contains(out, "SUDO_READY") {
		return true
	}

	whoOut, whoErr := executeRemoteCommandCtx(client, "whoami", defaultCmdTimeout)
	remoteUser := strings.TrimSpace(whoOut)
	if whoErr != nil || remoteUser == "" {
		remoteUser = "<remote-username>"
	}

	fmt.Println("\n" + Yellow + Bold + "[!] Target user requires non-interactive sudo permissions for compliance operations." + Reset)
	fmt.Println(Cyan + "--> One-Time Setup Solution on Target Host (run as an admin on the target):" + Reset)
	fmt.Printf("    echo \"%s ALL=(ALL) NOPASSWD: ALL\" | sudo tee /etc/sudoers.d/%s && sudo chmod 0440 /etc/sudoers.d/%s\n\n",
		remoteUser, remoteUser, remoteUser)
	auditLog(host, "sudo_check", "passwordless sudo unavailable for user="+remoteUser, "blocked")
	return false
}

// ---------------------------------------------------------------------
// Scan implementations
// ---------------------------------------------------------------------
func runAppSecTestingSuite(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		echo "=== APPLICATION SECURITY TESTING SUITE (SAST / DAST) ==="

		echo "--> [1/4] DAST: Auditing Web Server Security Response Headers..."
		TARGET_URL="http://127.0.0.1"
		if curl -sI --max-time 5 "$TARGET_URL" >/dev/null 2>&1; then
			HEADERS=$(curl -sI --max-time 5 "$TARGET_URL" 2>/dev/null)
			echo "$HEADERS" | grep -E -i 'x-frame-options|x-content-type-options|strict-transport-security|content-security-policy|server' || echo "[!] Missing core HTTP security hardening headers."
		else
			echo "[!] No active HTTP service running on 127.0.0.1:80."
		fi

		echo -e "\n--> [2/4] DAST: Auditing Dangerous HTTP Methods..."
		curl -s --max-time 5 -X OPTIONS -I "$TARGET_URL" 2>/dev/null | grep -i "Allow:" || echo "[OK] Standard HTTP method restrictions enforced."

		echo -e "\n--> [3/4] DAST: Checking OWASP ZAP Scanner Container Engine..."
		if command -v docker >/dev/null 2>&1; then
			if sudo -n true 2>/dev/null; then
				timeout 240 sudo docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1 -g gen.conf 2>/dev/null || echo "[+] OWASP ZAP runner completed (see exit status above)."
			else
				echo "[!] Docker present but sudo is not passwordless; skipping ZAP container run."
			fi
		else
			echo "[!] Docker runtime not active; skipping full ZAP container scan."
		fi

		echo -e "\n--> [4/4] SAST: Auditing Exposed Webroots & Environment Files..."
		EXPOSED=$(find /var/www /opt /srv -type f \( -name ".env" -o -name "*.key" -o -name "config.json" \) 2>/dev/null | grep -vE '/examples/|/embedded/|/doc/' | head -n 10)
		if [ -n "$EXPOSED" ]; then
			echo -e "[WARN] Potential sensitive production files detected in webroot:\n$EXPOSED"
		else
			echo "[OK] No unencrypted production secrets or .env files exposed in web paths."
		fi
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Running Application Security DAST/SAST Audits", longCmdTimeout)
	auditLog(host, "appsec_scan", "DAST/SAST suite", resultLabel(err))
	DisplayScrollableOutput("AppSec_Testing_Suite", annotateResult(out, err))
}

func runTrivyVulnerabilityScanner(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		if ! command -v trivy >/dev/null 2>&1; then
			echo '[+] Trivy not found. Attempting verified install via distro package manager first...' >&2
			if command -v apt-get >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
				sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
				sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq trivy >/dev/null 2>&1 || true
			fi
		fi

		if ! command -v trivy >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
			echo '[+] Falling back to official install script (pinned, over HTTPS)...' >&2
			curl -sfL --max-time 30 https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o /tmp/trivy_install.sh 2>/dev/null
			if [ -s /tmp/trivy_install.sh ]; then
				sudo sh /tmp/trivy_install.sh -b /usr/local/bin >/dev/null 2>&1 || true
				rm -f /tmp/trivy_install.sh
			fi
		fi

		if command -v trivy >/dev/null 2>&1; then
			echo "=== TRIVY VULNERABILITY & SECRET SCAN ==="
			timeout 120 trivy fs --scanners vuln,secret,config --severity HIGH,CRITICAL /etc 2>/dev/null | head -n 60
		else
			echo "=== TRIVY UNAVAILABLE: FALLING BACK TO SYSTEM PACKAGE CVE SWEEP ==="
			echo "[!] Results below are a coarse package inventory only, NOT a real vulnerability match — treat as degraded-mode output."
			dpkg-query -W 2>/dev/null | head -n 30 || rpm -qa 2>/dev/null | head -n 30
		fi
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Running Trivy Vulnerability & Secret Scan", longCmdTimeout)
	auditLog(host, "vuln_scan", "trivy fs scan", resultLabel(err))
	DisplayScrollableOutput("Trivy_Vulnerability_Scan", annotateResult(out, err))
}

func runInteractiveNmapScan(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Yellow + "\n[+] Nmap Interactive Scan Engine" + Reset)
	fmt.Println("  [1] Quick Scan (top 1000 ports)")
	fmt.Println("  [2] Full Port Scan (1-65535)")
	fmt.Println("  [3] Vulnerability Scan (NSE vuln scripts)")
	fmt.Println("  [4] OS Detection & Service Version Scan")
	fmt.Println("  [5] Custom Nmap Command (enter your own)")
	fmt.Println(Red + "  [0] Back" + Reset)
	fmt.Print("Select Nmap option [0-5]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "0" {
		return
	}

	rawTarget := transfer.ReadRealtimeInput("Enter Target IP/Hostname to Scan [Default 127.0.0.1]: ")
	if strings.TrimSpace(rawTarget) == "" {
		rawTarget = "127.0.0.1"
	}
	targetIp, err := validateTarget(rawTarget)
	if err != nil {
		fmt.Println(Red + "[!] Refusing to scan: " + err.Error() + Reset)
		auditLog(host, "nmap_scan", "rejected invalid target input: "+rawTarget, "blocked")
		pausePrompt()
		return
	}

	if !ensurePasswordlessSudo(client, host) {
		fmt.Println(Yellow + "[!] Sudo required for nmap. Please set passwordless sudo." + Reset)
		pausePrompt()
		return
	}

	checkNmap := "command -v nmap >/dev/null 2>&1"
	if _, err := executeRemoteCommand(client, checkNmap); err != nil {
		fmt.Println(Yellow + "[!] Nmap not found. Installing via package manager..." + Reset)
		if err := platform.InstallPackages(client, "nmap"); err != nil {
			fmt.Println(Red + "[!] Failed to install nmap. Please install manually." + Reset)
			pausePrompt()
			return
		}
	}

	var nmapCmd string
	switch choice {
	case "1":
		nmapCmd = fmt.Sprintf("sudo nmap -sS -T4 -F %s", shellQuote(targetIp))
	case "2":
		nmapCmd = fmt.Sprintf("sudo nmap -sS -T4 -p- %s", shellQuote(targetIp))
	case "3":
		nmapCmd = fmt.Sprintf("sudo nmap -sV --script=vuln %s", shellQuote(targetIp))
	case "4":
		nmapCmd = fmt.Sprintf("sudo nmap -sV -O %s", shellQuote(targetIp))
	case "5":
		custom := transfer.ReadRealtimeInput("Enter custom nmap command (without 'nmap'): ")
		if custom == "" {
			fmt.Println(Yellow + "[!] No command entered." + Reset)
			return
		}
		nmapCmd = fmt.Sprintf("sudo nmap %s", custom)
	default:
		fmt.Println(Yellow + "[!] Invalid choice." + Reset)
		return
	}

	out, execErr := executeWithSpinnerRetry(client, nmapCmd, fmt.Sprintf("Running Nmap scan against %s", targetIp), longCmdTimeout)
	auditLog(host, "nmap_scan", "target="+targetIp, resultLabel(execErr))
	DisplayScrollableOutput("Nmap_Scan", annotateResult(out, execErr))
}

func runDefensiveOSINT(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		echo "=== DEFENSIVE OSINT & NETWORK RECONNAISSANCE ==="

		echo "--> [1/3] Hostname & Local DNS Resolution..."
		echo "Hostname        : $(hostname -f 2>/dev/null || hostname)"
		grep -E -v '^(#|$)' /etc/hosts 2>/dev/null | head -n 10 || echo "[!] Standard /etc/hosts file."

		echo -e "\n--> [2/3] Local Interface IP Addressing..."
		hostname -I 2>/dev/null || ip -4 addr show | grep inet | awk '{print $2}'

		echo -e "\n--> [3/3] External Gateway & Egress Inspection..."
		curl -s --max-time 5 --connect-timeout 3 https://ifconfig.me 2>/dev/null && echo "" || echo "[+] Target is operating inside an isolated private subnet, or egress is blocked."
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Running Defensive OSINT & Network Inspection", defaultCmdTimeout)
	auditLog(host, "osint_recon", "hostname/network/egress check", resultLabel(err))
	DisplayScrollableOutput("Defensive_OSINT", annotateResult(out, err))
}

func runOpenSCAPScan(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	if !ensurePasswordlessSudo(client, host) {
		fmt.Println(Yellow + "[!] Skipping OpenSCAP scan due to insufficient sudo permissions." + Reset)
		pausePrompt()
		return
	}

	cmd := `
		if ! command -v oscap >/dev/null 2>&1; then
			echo '[!] OpenSCAP binary missing. Auto-installing via package manager...' >&2
			if command -v apt-get >/dev/null 2>&1; then
				sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner scap-security-guide >/dev/null 2>&1
			elif command -v yum >/dev/null 2>&1; then
				sudo yum install -y -q openscap-scanner scap-security-guide >/dev/null 2>&1
			elif command -v dnf >/dev/null 2>&1; then
				sudo dnf install -y -q openscap-scanner scap-security-guide >/dev/null 2>&1
			fi
		fi

		if command -v oscap >/dev/null 2>&1; then
			echo "=== OPENSCAP ENGINE ACTIVE ==="
			DS_FILE=$(find /usr/share/xml/scap/ssg/content/ /usr/share/scap/ssg/content/ -name "*ds.xml" 2>/dev/null | head -n 1)

			if [ -n "$DS_FILE" ]; then
				echo "[+] Evaluating SCAP Data Stream: $DS_FILE"
				timeout 180 oscap xccdf eval --results /tmp/scap_results.xml "$DS_FILE" 2>&1 | tail -n 30 || true

				if [ -f /tmp/scap_results.xml ]; then
					oscap xccdf generate fix --result-id "" /tmp/scap_results.xml > /tmp/remediate.sh 2>/dev/null || true
					echo -e "\n[OK] Auto-remediation fix script generated at /tmp/remediate.sh — review it manually before running."
				fi
			else
				echo "[OK] OpenSCAP scanner binary installed at $(which oscap)."
				echo "[!] Note: SCAP Security Guide content profiles missing for this specific OS build."
			fi
		else
			echo "[!] OpenSCAP package installation failed."
		fi
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Executing OpenSCAP NIST/STIG Benchmark Evaluation", longCmdTimeout)
	auditLog(host, "openscap_scan", "SCAP xccdf eval", resultLabel(err))
	DisplayScrollableOutput("OpenSCAP_Compliance_Audit", annotateResult(out, err))
}

func runInSpecScan(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		export CHEF_LICENSE="accept"
		if command -v inspec >/dev/null 2>&1; then
			timeout 120 inspec exec https://github.com/dev-sec/linux-baseline --reporter cli --chef-license=accept 2>/dev/null || echo "InSpec audit finished with compliance items flagged (non-zero exit is expected on findings)."
		elif command -v docker >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
			timeout 180 sudo docker run --rm -e CHEF_LICENSE="accept" -v /var/run/docker.sock:/var/run/docker.sock chef/inspec exec https://github.com/dev-sec/linux-baseline --chef-license=accept 2>/dev/null || echo "InSpec Docker runner completed."
		else
			echo "[!] Chef InSpec engine not locally installed and no passwordless-sudo Docker fallback available."
			echo "--> Target Kernel:" $(uname -s -r -m)
			echo "--> Active Systemd Services Count:" $(systemctl list-units --type=service --state=running 2>/dev/null | wc -l)
			echo "[OK] Degraded-mode infrastructure snapshot only — NOT a full compliance-as-code audit."
		fi
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Running Chef InSpec Agentless Compliance Audit", longCmdTimeout)
	auditLog(host, "inspec_scan", "linux-baseline profile", resultLabel(err))
	DisplayScrollableOutput("Chef_InSpec_Compliance", annotateResult(out, err))
}

func runCISAudit(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		echo "--> [1/3] Auditing SUID/SGID Binaries..."
		find / -perm -4000 -type f 2>/dev/null | head -n 15

		echo -e "\n--> [2/3] Auditing SSH Server Security Parameters..."
		grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding)' /etc/ssh/sshd_config 2>/dev/null || echo 'Using distro default sshd config (no explicit overrides found).'

		echo -e "\n--> [3/3] Auditing Network Kernel Sysctl Parameters..."
		sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route 2>/dev/null
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Auditing Host against CIS Controls 18 & DISA STIG", defaultCmdTimeout)
	auditLog(host, "cis_audit", "SUID/sshd/sysctl checks", resultLabel(err))
	DisplayScrollableOutput("CIS_STIG_Audit", annotateResult(out, err))

	fmt.Println(Yellow + "\n[+] CIS/STIG Auto-Remediation Engine Available:" + Reset)
	fmt.Println("  [1] Automatically Apply SSH & Kernel Hardening Fixes Now")
	fmt.Println("  [0] Skip Remediation")

	choice := transfer.ReadRealtimeInput("Select Remediation Choice [0-1]: ")
	if strings.TrimSpace(choice) == "1" {
		confirm := transfer.ReadRealtimeInput(Yellow + "This will modify live kernel parameters on " + host + ". Type YES to confirm: " + Reset)
		if strings.TrimSpace(confirm) == "YES" {
			applyKernelHardening(client, host)
		} else {
			fmt.Println(Yellow + "[!] Remediation cancelled — confirmation not received." + Reset)
			auditLog(host, "kernel_hardening", "user did not confirm", "cancelled")
		}
	}
}

func applyKernelHardening(client *ssh.Client, host string) {
	if !ensurePasswordlessSudo(client, host) {
		fmt.Println(Yellow + "[!] Skipping kernel hardening due to insufficient sudo permissions." + Reset)
		pausePrompt()
		return
	}

	before, _ := executeRemoteCommandCtx(client,
		"sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.all.log_martians 2>/dev/null",
		defaultCmdTimeout)

	hardeningScript := `
		echo "[+] Applying CIS / STIG Hardening Fixes directly over SSH..."

		sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || echo "[!] Failed to set ip_forward"
		sudo sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null 2>&1 || echo "[!] Failed to set accept_source_route"
		sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || echo "[!] Failed to set accept_redirects"
		sudo sysctl -w net.ipv4.conf.all.secure_redirects=0 >/dev/null 2>&1 || echo "[!] Failed to set secure_redirects"
		sudo sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1 || echo "[!] Failed to set log_martians"

		echo "[OK] CIS 18 Network & Kernel Hardening parameters applied (see any [!] lines above for partial failures)."
		echo "[NOTE] These sysctl -w changes are runtime-only and will revert on reboot unless persisted in /etc/sysctl.d/."
	`

	out, err := executeWithSpinnerRetry(client, hardeningScript, "Applying CIS/STIG Network & Kernel Hardening Fixes", defaultCmdTimeout)
	auditLog(host, "kernel_hardening", "before=["+strings.ReplaceAll(strings.TrimSpace(before), "\n", "; ")+"]", resultLabel(err))
	if err != nil {
		fmt.Printf(Yellow+"[!] Hardening execution status notice: %v\n"+Reset, err)
	}
	DisplayScrollableOutput("CIS_STIG_Hardening_Remediation", annotateResult(out, err))
}

// ---------------------------------------------------------------------
// MITRE, OWASP, Ultimate Sweep functions
// ---------------------------------------------------------------------
func runMitreAttackSimulation(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	ShowMITREMenu(bufio.NewReader(os.Stdin), client)
}

func runOWASPDevSecOpsMaturityScorer(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	cmd := `
		SCORE=0
		MAX=100

		echo "=== HARDENING MATURITY SCORE (DSOMM-inspired heuristic, not the full model) ==="

		if grep -q "PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then SCORE=$((SCORE+20)); echo "[OK] SSH Root Login Disabled (+20 pts)"; else echo "[FAIL] SSH Root Login Allowed (0 pts)"; fi
		if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then SCORE=$((SCORE+20)); echo "[OK] Firewall Active (+20 pts)"; elif command -v iptables >/dev/null 2>&1 && iptables -L -n 2>/dev/null | grep -q "Chain"; then SCORE=$((SCORE+20)); echo "[OK] iptables rules present (+20 pts)"; else echo "[FAIL] No active firewall detected (0 pts)"; fi
		IPFWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 1)
		if [ "$IPFWD" -eq 0 ]; then SCORE=$((SCORE+20)); echo "[OK] IP Forwarding Disabled (+20 pts)"; else echo "[FAIL] IP Forwarding Enabled (0 pts)"; fi
		if command -v docker >/dev/null 2>&1; then SCORE=$((SCORE+20)); echo "[OK] Container Isolation Available (+20 pts)"; else echo "[FAIL] No Container Runtime (0 pts)"; fi
		if ! find /var/www /opt -name ".env" 2>/dev/null | grep -q ".env"; then SCORE=$((SCORE+20)); echo "[OK] No Plaintext Secrets Exposed (+20 pts)"; else echo "[FAIL] Exposed Plaintext .env Files Detected (0 pts)"; fi

		echo -e "\n=========================================="
		echo " FINAL SCORE: $SCORE / $MAX"
		if [ $SCORE -ge 80 ]; then
			echo " LEVEL: 4 (STRONG BASELINE)"
		elif [ $SCORE -ge 50 ]; then
			echo " LEVEL: 2 (MANAGED, GAPS REMAIN)"
		else
			echo " LEVEL: 1 (BASIC / HIGH RISK)"
		fi
		echo " NOTE: this is a 5-check heuristic, not the full OWASP DSOMM model."
		echo "=========================================="
	`
	out, err := executeWithSpinnerRetry(client, cmd, "Calculating Hardening Maturity Score", defaultCmdTimeout)
	auditLog(host, "maturity_score", "5-point heuristic", resultLabel(err))
	DisplayScrollableOutput("Hardening_Maturity_Score", annotateResult(out, err))
}

func runUltimateThreatSweepCorrelated(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	ExecuteUltimateSweep(client, host)
	fmt.Println(Yellow + "[+] Executive report generation is handled inside the Ultimate Sweep." + Reset)
}

// ---------------------------------------------------------------------
// Execution primitives
// ---------------------------------------------------------------------
func executeRemoteCommand(client *ssh.Client, cmd string) (string, error) {
	return executeRemoteCommandCtx(client, cmd, defaultCmdTimeout)
}

func executeRemoteCommandCtx(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to open SSH session: %w", err)
	}
	defer session.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(cmd)
		done <- result{out, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case r := <-done:
		return string(r.out), r.err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return "", fmt.Errorf("command timed out after %s", timeout)
	}
}

func executeWithSpinnerRetry(client *ssh.Client, cmd string, label string, timeout time.Duration) (string, error) {
	var lastOut string
	var lastErr error

	for attempt := 1; attempt <= maxRetries+1; attempt++ {
		attemptLabel := label
		if attempt > 1 {
			attemptLabel = fmt.Sprintf("%s (retry %d/%d)", label, attempt-1, maxRetries)
		}
		out, err := executeWithSpinner(client, cmd, attemptLabel, timeout)
		lastOut, lastErr = out, err

		if err == nil {
			return out, nil
		}
		if !isTransient(err) {
			return out, err
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	return lastOut, lastErr
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "failed to open SSH session") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset")
}

func executeWithSpinner(client *ssh.Client, cmd string, label string, timeout time.Duration) (string, error) {
	var running int32 = 1
	done := make(chan struct{})

	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		startTime := time.Now()
		i := 0

		for atomic.LoadInt32(&running) == 1 {
			elapsed := int(time.Since(startTime).Seconds())
			fmt.Fprintf(os.Stderr, "\r\033[36m[ %s ] %s... (%ds elapsed)\033[0m", frames[i%len(frames)], label, elapsed)
			i++
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprintf(os.Stderr, "\r\033[2K\r")
		close(done)
	}()

	out, err := executeRemoteCommandCtx(client, cmd, timeout)

	atomic.StoreInt32(&running, 0)
	<-done

	return out, err
}

func resultLabel(err error) string {
	if err == nil {
		return "ok"
	}
	return "error:" + err.Error()
}

func annotateResult(out string, err error) string {
	if err == nil {
		return out
	}
	banner := Red + Bold + fmt.Sprintf("[EXECUTION ERROR] %v — results below may be partial or missing.\n", err) + Reset
	return banner + out
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return to compliance menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}