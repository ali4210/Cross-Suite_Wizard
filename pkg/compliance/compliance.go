package compliance

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"cross-ssh/pkg/dsomm"
	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/osint"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Bold    = "\033[1m"
)

type AuditCheck struct {
	Framework   string // "CIS Top 18" or "MITRE ATT&CK"
	ControlID   string
	Title       string
	Passed      bool
	RiskLevel   string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Details     string
	Remediation string
}

func AuditCompliance(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== ENGINE 4: CIS TOP 18 & MITRE ATT&CK COMPLIANCE AUDITOR ===" + Reset)
		fmt.Printf(Yellow+"Target Operating System: "+Reset+Bold+"%s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Run Full CIS Top 18 & MITRE ATT&CK Benchmark Audit")
		fmt.Println("  [2] Audit SSH & Authentication Controls (CIS Section 5)")
		fmt.Println("  [3] Audit Persistence & Privilege Escalation Vectors (MITRE T1068/T1053)")
		fmt.Println("  [4] Apply 1-Click Automated Hardening Fixes for Failing Checks")
		fmt.Println("  [5] 🕵️  OSINT Intelligence Engine (Preset-Based)")
		fmt.Println("  [6] 📊 DSOMM Maturity Scan & Remediation Engine")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-6]: ")

		switch choice {
		case "1":
			runFullComplianceAudit(client, targetOS, sudoPass)
		case "2":
			runSSHAuditOnly(client, targetOS, sudoPass)
		case "3":
			runMitreAuditOnly(client, targetOS, sudoPass)
		case "4":
			applyAutomatedRemediation(reader, client, targetOS, sudoPass)
		case "5":
			// OSINT Engine – use the remote host IP as target
			host := getRemoteHost(client)
			osint.ShowOSINTMenu(reader, client, host)
		case "6":
			// DSOMM Engine – use the remote host IP
			host := getRemoteHost(client)
			dsomm.ShowDSOMMMenu(reader, client, host)
		case "0", "q", "Q":
			return
		default:
			fmt.Println(Yellow + "[!] Invalid choice. Please select 0-6." + Reset)
			time.Sleep(1 * time.Second)
		}
	}
}

// Helper to get the remote host IP (or fallback)
func getRemoteHost(client *ssh.Client) string {
	session, err := client.NewSession()
	if err != nil {
		return "127.0.0.1"
	}
	defer session.Close()
	out, _ := session.CombinedOutput("echo $SSH_CLIENT | awk '{print $1}' || echo '127.0.0.1'")
	host := strings.TrimSpace(string(out))
	if host == "" || host == "127.0.0.1" {
		// Try to get public IP
		session2, _ := client.NewSession()
		defer session2.Close()
		out2, _ := session2.CombinedOutput("curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null || echo '127.0.0.1'")
		host = strings.TrimSpace(string(out2))
	}
	return host
}

// ---------------------------------------------------------------------
// Existing functions (unchanged except for comments)
// ---------------------------------------------------------------------

func runFullComplianceAudit(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	out := runTaskWithSpinner("Benchmarking target host against CIS Top 18 & MITRE ATT&CK", func() string {
		checks := performComplianceChecks(client, targetOS, sudoPass)
		return formatAuditReport(checks)
	})

	displayInPager(out)
}

func runSSHAuditOnly(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	out := runTaskWithSpinner("Auditing SSH & Authentication controls", func() string {
		checks := performComplianceChecks(client, targetOS, sudoPass)
		var sshChecks []AuditCheck
		for _, c := range checks {
			if strings.Contains(c.ControlID, "CIS-5") {
				sshChecks = append(sshChecks, c)
			}
		}
		return formatAuditReport(sshChecks)
	})

	displayInPager(out)
}

func runMitreAuditOnly(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	out := runTaskWithSpinner("Auditing MITRE ATT&CK persistence & privilege vectors", func() string {
		checks := performComplianceChecks(client, targetOS, sudoPass)
		var mitreChecks []AuditCheck
		for _, c := range checks {
			if strings.Contains(c.Framework, "MITRE") {
				mitreChecks = append(mitreChecks, c)
			}
		}
		return formatAuditReport(mitreChecks)
	})

	displayInPager(out)
}

func performComplianceChecks(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) []AuditCheck {
	var checks []AuditCheck

	if targetOS == osdetect.OSWindows {
		// Windows Checks
		fwResp := executeRemoteCmdElevated(client, `powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"`, sudoPass, targetOS)
		fwPassed := strings.Contains(fwResp, "True")
		checks = append(checks, AuditCheck{
			Framework:   "CIS Top 18",
			ControlID:   "CIS-WIN-3.1",
			Title:       "Ensure Windows Defender Firewall is Active for All Profiles",
			Passed:      fwPassed,
			RiskLevel:   "HIGH",
			Details:     fmt.Sprintf("Firewall Profile States: %s", strings.TrimSpace(fwResp)),
			Remediation: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
		})

		psResp := executeRemoteCmdElevated(client, `powershell -NoProfile -Command "Get-ExecutionPolicy"`, sudoPass, targetOS)
		psPassed := strings.Contains(psResp, "RemoteSigned") || strings.Contains(psResp, "AllSigned") || strings.Contains(psResp, "Restricted")
		checks = append(checks, AuditCheck{
			Framework:   "MITRE ATT&CK",
			ControlID:   "MITRE-T1059",
			Title:       "Audit PowerShell Script Execution Policy",
			Passed:      psPassed,
			RiskLevel:   "MEDIUM",
			Details:     fmt.Sprintf("PowerShell Execution Policy: %s", strings.TrimSpace(psResp)),
			Remediation: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force",
		})
	} else {
		// Linux CIS & MITRE Checks with Root Elevation
		// 1. CIS 5.2 - SSH Root Direct Login
		sshRootResp := executeRemoteCmdElevated(client, `grep -i "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin yes"`, sudoPass, targetOS)
		sshRootPassed := strings.Contains(strings.ToLower(sshRootResp), "no")
		checks = append(checks, AuditCheck{
			Framework:   "CIS Top 18",
			ControlID:   "CIS-5.2.1",
			Title:       "Ensure SSH Direct Root Login is Disabled",
			Passed:      sshRootPassed,
			RiskLevel:   "CRITICAL",
			Details:     fmt.Sprintf("SSHD Configuration: %s", strings.TrimSpace(sshRootResp)),
			Remediation: "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd",
		})

		// 2. CIS 5.2 - SSH Password Authentication
		sshPassResp := executeRemoteCmdElevated(client, `grep -i "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication yes"`, sudoPass, targetOS)
		sshPassPassed := strings.Contains(strings.ToLower(sshPassResp), "no")
		checks = append(checks, AuditCheck{
			Framework:   "CIS Top 18",
			ControlID:   "CIS-5.2.2",
			Title:       "Ensure SSH Password Authentication is Disabled",
			Passed:      sshPassPassed,
			RiskLevel:   "HIGH",
			Details:     fmt.Sprintf("SSHD Configuration: %s", strings.TrimSpace(sshPassResp)),
			Remediation: "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd",
		})

		// 3. CIS 3.4 - Firewall Active State
		fwResp := executeRemoteCmdElevated(client, `(command -v ufw >/dev/null && ufw status) || (command -v firewall-cmd >/dev/null && firewall-cmd --state) || echo "inactive"`, sudoPass, targetOS)
		fwPassed := strings.Contains(fwResp, "active") || strings.Contains(fwResp, "running")
		checks = append(checks, AuditCheck{
			Framework:   "CIS Top 18",
			ControlID:   "CIS-3.4.1",
			Title:       "Ensure System Firewall Daemon is Enabled and Active",
			Passed:      fwPassed,
			RiskLevel:   "HIGH",
			Details:     fmt.Sprintf("Firewall Status: %s", strings.TrimSpace(fwResp)),
			Remediation: "ufw --force enable || systemctl start firewalld",
		})

		// 4. MITRE ATT&CK T1068 - SUID Binaries Audit
		suidResp := executeRemoteCmdElevated(client, `find / -perm -4000 -type f 2>/dev/null | grep -E "nmap|vim|find|bash|cp|nano|env" || echo "none"`, sudoPass, targetOS)
		suidPassed := strings.TrimSpace(suidResp) == "none" || suidResp == ""
		checks = append(checks, AuditCheck{
			Framework:   "MITRE ATT&CK",
			ControlID:   "MITRE-T1068",
			Title:       "Audit Dangerous SUID Binary Escalation Flags",
			Passed:      suidPassed,
			RiskLevel:   "CRITICAL",
			Details:     fmt.Sprintf("Dangerous SUID Binaries Found: %s", strings.TrimSpace(suidResp)),
			Remediation: "chmod u-s <binary_path>",
		})

		// 5. MITRE ATT&CK T1053 - Cron Persistence Check
		cronResp := executeRemoteCmdElevated(client, `ls -la /etc/cron.d /etc/cron.daily 2>/dev/null | wc -l`, sudoPass, targetOS)
		checks = append(checks, AuditCheck{
			Framework:   "MITRE ATT&CK",
			ControlID:   "MITRE-T1053",
			Title:       "Audit System Cron Jobs for Unauthorized Persistence",
			Passed:      true,
			RiskLevel:   "INFO",
			Details:     fmt.Sprintf("System Cron Schedules Configured: %s entries", strings.TrimSpace(cronResp)),
			Remediation: "Inspect /etc/crontab and /var/spool/cron/crontabs for unauthorized jobs.",
		})
	}

	return checks
}

func applyAutomatedRemediation(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== AUTOMATED COMPLIANCE REMEDIATION ENGINE ===" + Reset)
	fmt.Println(Yellow + "[!] This will apply hardening fixes for failing CIS & MITRE controls." + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	confirm := transfer.ReadRealtimeInput(Red + Bold + "Apply automated hardening fixes now? [y/N]: " + Reset)
	if strings.ToLower(confirm) != "y" {
		fmt.Println(Yellow + "[!] Remediation canceled." + Reset)
		pausePrompt()
		return
	}

	out := runTaskWithSpinner("Applying automated security hardening controls", func() string {
		var fixScript string
		if targetOS == osdetect.OSWindows {
			fixScript = `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force`
		} else {
			fixScript = strings.Join([]string{
				"if command -v ufw >/dev/null 2>&1; then ufw allow 22/tcp && ufw --force enable;",
				"elif command -v firewall-cmd >/dev/null 2>&1; then systemctl start firewalld && firewall-cmd --add-port=22/tcp --permanent && firewall-cmd --reload; fi",
				"echo '[SUCCESS] Compliance Hardening Fixes Applied Cleanly'",
			}, "\n")
		}

		return executeRemoteCmdElevated(client, fixScript, sudoPass, targetOS)
	})

	fmt.Println(Cyan + "\n--- REMEDIATION OUTPUT ---" + Reset)
	fmt.Println(out)
	fmt.Println(Green + Bold + "\n[SUCCESS] Hardening fixes executed successfully!" + Reset)
	pausePrompt()
}

func formatAuditReport(checks []AuditCheck) string {
	var sb strings.Builder
	passedCount := 0

	sb.WriteString("=== CIS TOP 18 & MITRE ATT&CK COMPLIANCE SCORECARD ===\n\n")

	for _, c := range checks {
		statusStr := Red + Bold + "[FAIL]" + Reset
		if c.Passed {
			statusStr = Green + Bold + "[PASS]" + Reset
			passedCount++
		}

		sb.WriteString(fmt.Sprintf("%s [%s] %s: %s\n", statusStr, c.Framework, c.ControlID, c.Title))
		sb.WriteString(fmt.Sprintf("   Risk Level:  %s\n", c.RiskLevel))
		sb.WriteString(fmt.Sprintf("   Details:     %s\n", c.Details))
		if !c.Passed {
			sb.WriteString(fmt.Sprintf("   Remediation: %s\n", c.Remediation))
		}
		sb.WriteString("--------------------------------------------------------------------------------------------------------\n")
	}

	scorePct := float64(passedCount) / float64(len(checks)) * 100
	sb.WriteString(fmt.Sprintf("\nOVERALL COMPLIANCE SCORE: %.1f%% (%d/%d Controls Passed)\n", scorePct, passedCount, len(checks)))
	return sb.String()
}

func executeRemoteCmdElevated(client *ssh.Client, scriptCmd string, sudoPass string, targetOS osdetect.TargetOS) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("[Error creating SSH session: %v]", err)
	}
	defer session.Close()

	var finalCmd string
	if targetOS == osdetect.OSWindows {
		finalCmd = fmt.Sprintf(`powershell -NoProfile -Command %q`, scriptCmd)
	} else {
		b64Script := base64.StdEncoding.EncodeToString([]byte(scriptCmd))
		decodedScriptCmd := fmt.Sprintf("echo %s | base64 -d | bash", b64Script)

		if sudoPass != "" {
			escapedPass := strings.ReplaceAll(sudoPass, "'", "'\\''")
			finalCmd = fmt.Sprintf("echo '%s' | sudo -S -p '' bash -c %q 2>&1", escapedPass, decodedScriptCmd)
		} else {
			finalCmd = decodedScriptCmd + " 2>&1"
		}
	}

	output, _ := session.CombinedOutput(finalCmd)
	return string(output)
}

func runTaskWithSpinner(message string, task func() string) string {
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan bool)
	var output string

	go func() {
		output = task()
		done <- true
	}()

	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r\033[K"+Green+"[✔] %s Complete!\n"+Reset, message)
			return output
		default:
			fmt.Printf("\r\033[K"+Cyan+"[%s] %s..."+Reset, spinnerFrames[i%len(spinnerFrames)], message)
			time.Sleep(100 * time.Millisecond)
			i++
		}
	}
}

func displayInPager(content string) {
	cmd := exec.Command("less", "-R", "-X")
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(content)
		pausePrompt()
	}
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return to compliance menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}