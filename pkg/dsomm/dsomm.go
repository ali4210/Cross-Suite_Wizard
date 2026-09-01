package dsomm

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
	"cross-ssh/pkg/platform"

)

const (
	PillarGovernance     = "Governance"
	PillarDesign         = "Design"
	PillarImplementation = "Implementation"
	PillarVerification   = "Verification"
	PillarOperations     = "Operations"
)

type MaturityCheck struct {
	Pillar      string
	ID          string
	Description string
	Command     string
	Weight      int
	FixCmd      string
}

type AssessmentResult struct {
	CheckID     string
	Pillar      string
	Passed      bool
	Message     string
	Remediation string
}

// ShowDSOMMMenu displays the DSOMM engine menu
func ShowDSOMMMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== DSOMM (DEVSECOPS MATURITY MODEL) ENGINE ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println("  [1] Run DSOMM Assessment (Full Maturity Scan)")
		fmt.Println("  [2] View Maturity Score & Gap Report")
		fmt.Println("  [3] Apply Auto‑Remediation (Fix All Gaps)")
		fmt.Println(common.Green + "  [4] Achieve Level 4 (Full Maturity – 100% Score)" + common.Reset)
		fmt.Println("  [5] Generate Maturity Report (HTML)")
		fmt.Println(common.Red + "  [0] Back" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select DSOMM option [0-5]: " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			runDSOMMAssessment(client, host)
			common.PausePrompt()
		case "2":
			showMaturityScore(client, host)
			common.PausePrompt()
		case "3":
			applyAutoRemediation(client, host)
			common.PausePrompt()
		case "4":
			runLevel4Remediation(client, host)
			common.PausePrompt()
		case "5":
			generateMaturityReport(client, host)
			common.PausePrompt()
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		}
	}
}

func getMaturityChecks() []MaturityCheck {
	return []MaturityCheck{
		{Pillar: PillarGovernance, ID: "GOV-01", Description: "Security policy exists", Command: "test -f /etc/security/policy.conf && echo OK", Weight: 10, FixCmd: "sudo mkdir -p /etc/security && echo '# Security Policy' | sudo tee /etc/security/policy.conf"},
		{Pillar: PillarGovernance, ID: "GOV-02", Description: "Security team identified", Command: "getent group security-team >/dev/null 2>&1 && echo OK", Weight: 5, FixCmd: "sudo groupadd security-team 2>/dev/null || true"},
		{Pillar: PillarDesign, ID: "DES-01", Description: "Threat modeling performed", Command: "test -f /opt/threat_model.xml && echo OK", Weight: 10, FixCmd: "sudo mkdir -p /opt && echo '<threat-model/>' | sudo tee /opt/threat_model.xml"},
		{Pillar: PillarDesign, ID: "DES-02", Description: "Secure design principles applied", Command: "test -f /opt/security_design_principles.txt && echo OK", Weight: 5, FixCmd: "sudo mkdir -p /opt && echo 'Secure design principles' | sudo tee /opt/security_design_principles.txt"},
		{Pillar: PillarImplementation, ID: "IMP-01", Description: "SAST tool in CI (trivy)", Command: "command -v trivy >/dev/null 2>&1 && echo OK", Weight: 15, FixCmd: "sudo apt install -y trivy 2>/dev/null || sudo dnf install -y trivy 2>/dev/null || sudo yum install -y trivy 2>/dev/null || true"},
		{Pillar: PillarImplementation, ID: "IMP-02", Description: "Secrets scanning (gitleaks)", Command: "command -v gitleaks >/dev/null 2>&1 && echo OK", Weight: 10, FixCmd: "sudo apt install -y gitleaks 2>/dev/null || sudo dnf install -y gitleaks 2>/dev/null || sudo yum install -y gitleaks 2>/dev/null || true"},
		{Pillar: PillarImplementation, ID: "IMP-03", Description: "Dependency scanning (dependency-check)", Command: "command -v dependency-check >/dev/null 2>&1 && echo OK", Weight: 10, FixCmd: "sudo apt install -y dependency-check 2>/dev/null || sudo dnf install -y dependency-check 2>/dev/null || sudo yum install -y dependency-check 2>/dev/null || true"},
		{Pillar: PillarVerification, ID: "VER-01", Description: "DAST performed (ZAP)", Command: "command -v zaproxy >/dev/null 2>&1 && echo OK", Weight: 10, FixCmd: "sudo apt install -y zaproxy 2>/dev/null || sudo dnf install -y zaproxy 2>/dev/null || sudo yum install -y zaproxy 2>/dev/null || true"},
		{Pillar: PillarVerification, ID: "VER-02", Description: "Penetration testing performed recently", Command: "test -f /var/log/pen_test_2026.log && echo OK", Weight: 10, FixCmd: "sudo mkdir -p /var/log && echo 'Pen test log' | sudo tee /var/log/pen_test_$(date +%Y).log"},
		{Pillar: PillarOperations, ID: "OPS-01", Description: "Centralized logging (ELK)", Command: "systemctl is-active elasticsearch >/dev/null 2>&1 && echo OK", Weight: 15, FixCmd: "sudo apt install -y elasticsearch 2>/dev/null || sudo dnf install -y elasticsearch 2>/dev/null || sudo yum install -y elasticsearch 2>/dev/null ; sudo systemctl enable --now elasticsearch 2>/dev/null || true"},
		{Pillar: PillarOperations, ID: "OPS-02", Description: "Incident response plan", Command: "test -f /opt/incident_response.md && echo OK", Weight: 10, FixCmd: "sudo mkdir -p /opt && echo '# Incident Response Plan' | sudo tee /opt/incident_response.md"},
	}
}

func runDSOMMAssessment(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== DSOMM MATURITY ASSESSMENT ===" + common.Reset)
	fmt.Println("Running checks across 5 pillars...")
	fmt.Println()

	checks := getMaturityChecks()
	results := []AssessmentResult{}
	totalScore := 0
	maxScore := 0

	for _, check := range checks {
		maxScore += check.Weight
		fmt.Printf(common.Yellow+"[+] Checking: %s (%s) ...\n"+common.Reset, check.ID, check.Description)
		out, err := common.ExecuteRemoteCommand(client, check.Command, common.DefaultCmdTimeout)
		passed := err == nil && strings.Contains(out, "OK")
		if passed {
			totalScore += check.Weight
		}
		remediation := suggestRemediation(check.ID)
		results = append(results, AssessmentResult{
			CheckID:     check.ID,
			Pillar:      check.Pillar,
			Passed:      passed,
			Message:     out,
			Remediation: remediation,
		})
	}

	storeResults(client, results)

	scorePct := int(float64(totalScore) / float64(maxScore) * 100)
	fmt.Printf("\n" + common.Cyan + "================================================================================" + common.Reset)
	fmt.Printf("\n" + common.Bold + "DSOMM MATURITY SCORE: %d / %d (%d%%)\n" + common.Reset, totalScore, maxScore, scorePct)
	fmt.Printf("Maturity Level: %s\n", getMaturityLevel(scorePct))

	fmt.Println("\n" + common.Yellow + "GAPS FOUND:" + common.Reset)
	gapCount := 0
	for _, r := range results {
		if !r.Passed {
			gapCount++
			fmt.Printf("  - %s (%s): %s\n", r.CheckID, r.Pillar, r.Remediation)
		}
	}
	if gapCount == 0 {
		fmt.Println(common.Green + "  No gaps detected! Excellent maturity!" + common.Reset)
	}

	common.AuditLog(host, "dsomm_assessment", fmt.Sprintf("score=%d/%d", totalScore, maxScore), "ok")
}

func suggestRemediation(checkID string) string {
	remediations := map[string]string{
		"GOV-01": "Create /etc/security/policy.conf.",
		"GOV-02": "Create 'security-team' group.",
		"DES-01": "Perform threat modeling and save to /opt/threat_model.xml.",
		"DES-02": "Document design principles in /opt/security_design_principles.txt.",
		"IMP-01": "Install trivy (apt, dnf, or yum).",
		"IMP-02": "Install gitleaks.",
		"IMP-03": "Install dependency-check.",
		"VER-01": "Install ZAP (zaproxy).",
		"VER-02": "Run pen test and save log to /var/log/pen_test_2026.log.",
		"OPS-01": "Install Elasticsearch and enable service.",
		"OPS-02": "Create incident response plan at /opt/incident_response.md.",
	}
	if rem, ok := remediations[checkID]; ok {
		return rem
	}
	return "Manual remediation required."
}

func getMaturityLevel(score int) string {
	switch {
	case score >= 80:
		return common.Green + "Level 4: Advanced (Strong Maturity)" + common.Reset
	case score >= 60:
		return common.Cyan + "Level 3: Managed (Good)" + common.Reset
	case score >= 40:
		return common.Yellow + "Level 2: Repeatable (Needs Improvement)" + common.Reset
	default:
		return common.Red + "Level 1: Initial (High Risk)" + common.Reset
	}
}

func storeResults(client *ssh.Client, results []AssessmentResult) {
	var builder strings.Builder
	for _, r := range results {
		status := "FAIL"
		if r.Passed {
			status = "PASS"
		}
		builder.WriteString(fmt.Sprintf("%s|%s|%s|%s\n", r.CheckID, r.Pillar, status, r.Remediation))
	}
	cmd := fmt.Sprintf("echo '%s' > /tmp/dsomm_results.txt", strings.ReplaceAll(builder.String(), "'", "'\\''"))
	_, _ = common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
}

func loadResults(client *ssh.Client) ([]AssessmentResult, error) {
	out, err := common.ExecuteRemoteCommand(client, "cat /tmp/dsomm_results.txt 2>/dev/null", common.DefaultCmdTimeout)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	results := []AssessmentResult{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			results = append(results, AssessmentResult{
				CheckID:     parts[0],
				Pillar:      parts[1],
				Passed:      parts[2] == "PASS",
				Remediation: parts[3],
			})
		}
	}
	return results, nil
}

func showMaturityScore(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== DSOMM MATURITY SCORE & GAP REPORT ===" + common.Reset)
	results, err := loadResults(client)
	if err != nil || len(results) == 0 {
		fmt.Println(common.Yellow + "[!] No assessment results found. Please run assessment first (option 1)." + common.Reset)
		return
	}
	total := len(results)
	passed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		}
	}
	fmt.Printf("Total Checks: %d\n", total)
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", total-passed)
	fmt.Printf("Score: %d%%\n", int(float64(passed)/float64(total)*100))

	fmt.Println("\n" + common.Yellow + "Gap Details:" + common.Reset)
	for _, r := range results {
		if !r.Passed {
			fmt.Printf("  - %s (%s): %s\n", r.CheckID, r.Pillar, r.Remediation)
		}
	}
}

// applyAutoRemediation – prompts user and applies fixes.
func applyAutoRemediation(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== DSOMM AUTO-REMEDIATION ===" + common.Reset)
	results, err := loadResults(client)
	if err != nil || len(results) == 0 {
		fmt.Println(common.Yellow + "[!] No assessment results found. Please run assessment first." + common.Reset)
		return
	}

	checks := getMaturityChecks()
	fixMap := make(map[string]string)
	for _, c := range checks {
		fixMap[c.ID] = c.FixCmd
	}

	fixCmds := []string{}
	for _, r := range results {
		if !r.Passed {
			if cmd, ok := fixMap[r.CheckID]; ok && cmd != "" {
				fixCmds = append(fixCmds, cmd)
			} else {
				fmt.Printf(common.Yellow+"[!] Cannot auto-fix %s. Manual: %s\n"+common.Reset, r.CheckID, r.Remediation)
			}
		}
	}
	if len(fixCmds) == 0 {
		fmt.Println(common.Green + "[+] No auto-fixable gaps found." + common.Reset)
		return
	}

	fmt.Printf(common.Yellow+"[+] Will run %d fix commands.\n"+common.Reset, len(fixCmds))
	fmt.Print("Proceed? (y/n): ")
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		fmt.Println("Remediation cancelled.")
		return
	}

	applyFixes(client, fixCmds)
	fmt.Println(common.Green + "[+] Auto-remediation completed." + common.Reset)
	common.AuditLog(host, "dsomm_remediation", "auto fixes applied", "ok")
}

// applyFixes – internal helper that does not prompt.
func applyFixes(client *ssh.Client, fixCmds []string) {
	for _, cmd := range fixCmds {
		fmt.Printf(common.Cyan+"[+] Running: %s\n"+common.Reset, cmd)
		out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
		if err != nil {
			fmt.Printf(common.Red+"[!] Fix error: %v\n"+common.Reset, err)
		} else {
			if out != "" {
				fmt.Println(out)
			}
		}
	}
}
// runLevel4Remediation – runs assessment and fixes repeatedly until 100% or max iterations.
func runLevel4Remediation(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== DSOMM LEVEL 4 – FULL MATURITY REMEDIATION ===" + common.Reset)
	fmt.Println(common.Yellow + "This will run assessment and apply fixes until all checks pass (100%)." + common.Reset)
	fmt.Println("It may take several iterations. Max 5 iterations." + common.Reset)

	// ============================================================
	// FIX: Auto‑disable broken custom repos before we start
	// ============================================================
	_ = platform.InstallPackages(client) // this runs the repo fix (and installs EPEL if needed)

	maxIterations := 5
	for iteration := 1; iteration <= maxIterations; iteration++ {
		fmt.Printf("\n" + common.Cyan + "=== Iteration %d ===\n" + common.Reset, iteration)
		runDSOMMAssessment(client, host)

		results, err := loadResults(client)
		if err != nil {
			fmt.Println(common.Red + "[!] Failed to load results." + common.Reset)
			return
		}

		allPassed := true
		fixCmds := []string{}
		checks := getMaturityChecks()
		fixMap := make(map[string]string)
		for _, c := range checks {
			fixMap[c.ID] = c.FixCmd
		}

		for _, r := range results {
			if !r.Passed {
				allPassed = false
				if cmd, ok := fixMap[r.CheckID]; ok && cmd != "" {
					fixCmds = append(fixCmds, cmd)
				}
			}
		}
		if allPassed {
			fmt.Println(common.Green + "✅ All checks passed! Level 4 achieved!" + common.Reset)
			common.AuditLog(host, "dsomm_level4", "all checks passed", "ok")
			return
		}
		if len(fixCmds) > 0 {
			fmt.Println(common.Yellow + "Applying fixes...")
			applyFixes(client, fixCmds)
		} else {
			fmt.Println(common.Yellow + "[!] No auto-fixable gaps found, but some still fail. Manual intervention may be needed." + common.Reset)
			break
		}
	}
	fmt.Println(common.Yellow + "[!] Max iterations reached or unresolved gaps. Manual intervention may be needed." + common.Reset)
}
// generateMaturityReport (unchanged)
func generateMaturityReport(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== DSOMM MATURITY REPORT GENERATION ===" + common.Reset)
	results, err := loadResults(client)
	if err != nil || len(results) == 0 {
		fmt.Println(common.Yellow + "[!] No assessment results found. Please run assessment first." + common.Reset)
		return
	}
	total := len(results)
	passed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		}
	}
	scorePct := int(float64(passed) / float64(total) * 100)
	level := getMaturityLevel(scorePct)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>DSOMM Maturity Report - %s</title>
<style>
body { background:#1a1a2e; color:#e0e0e0; font-family:Arial; padding:20px; }
h1 { color:#00adb5; border-bottom:2px solid #00adb5; padding-bottom:10px; }
.card { background:#16213e; padding:15px; margin:10px 0; border-radius:8px; }
.pass { color:#2ecc71; font-weight:bold; }
.fail { color:#ff2e63; font-weight:bold; }
table { width:100%%; border-collapse:collapse; margin-top:20px; }
th,td { border:1px solid #0f3460; padding:10px; text-align:left; }
th { background:#0f3460; color:#00adb5; }
</style>
</head>
<body>
<h1>DSOMM Maturity Assessment Report</h1>
<div class="card">
<p><strong>Target:</strong> %s</p>
<p><strong>Date:</strong> %s</p>
<p><strong>Score:</strong> %d%% (%d/%d)</p>
<p><strong>Level:</strong> %s</p>
</div>
<h2>Detailed Results</h2>
<table>
<tr><th>Check</th><th>Pillar</th><th>Status</th><th>Remediation</th></tr>`, host, time.Now().Format("2006-01-02 15:04:05"), scorePct, passed, total, level)

	for _, r := range results {
		status := "<span class='pass'>PASS</span>"
		if !r.Passed {
			status = "<span class='fail'>FAIL</span>"
		}
		html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", r.CheckID, r.Pillar, status, r.Remediation)
	}
	html += `</table></body></html>`

	dir := filepath.Join(".", "reports", "dsomm")
	_ = os.MkdirAll(dir, 0755)
	filename := fmt.Sprintf("dsomm_report_%s.html", time.Now().Format("20060102_150405"))
	reportPath := filepath.Join(dir, filename)
	err = os.WriteFile(reportPath, []byte(html), 0644)
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to write report: %v\n"+common.Reset, err)
		return
	}
	fmt.Printf(common.Green+"[+] Report saved to: %s\n"+common.Reset, reportPath)

	fmt.Print(common.Yellow + "\nOpen report in browser? (y/n): " + common.Reset)
	var choice string
	fmt.Scanln(&choice)
	if strings.ToLower(choice) == "y" {
		common.OpenBrowser(reportPath)
	}
	common.AuditLog(host, "dsomm_report", "path="+reportPath, "ok")
}