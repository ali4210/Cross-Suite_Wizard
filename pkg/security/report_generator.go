package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VulnerabilityFinding represents a single security finding
type VulnerabilityFinding struct {
	ID          string
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW
	Title       string
	Description string
	Sources     []string // Scanner sources
	AutoFixable bool
}

// GenerateExecutiveReport builds a styled HTML report summarizing the audit findings
func GenerateExecutiveReport(targetHost string, findings []VulnerabilityFinding) string {
	home, _ := os.UserHomeDir()
	reportDir := filepath.Join(home, ".cross-ssh", "reports")
	_ = os.MkdirAll(reportDir, 0755)

	reportPath := filepath.Join(reportDir, fmt.Sprintf("Executive_Security_Report_%s.html", time.Now().Format("20060102_150405")))

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Executive Security & Compliance Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #1a1a2e; color: #e0e0e0; margin: 40px; }
        h1 { color: #00adb5; border-bottom: 2px solid #00adb5; padding-bottom: 10px; }
        .card { background-color: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .CRITICAL, .HIGH { color: #ff2e63; font-weight: bold; }
        .MEDIUM { color: #f39c12; font-weight: bold; }
        .LOW { color: #2ecc71; font-weight: bold; }
        table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #0f3460; padding: 12px; text-align: left; }
        th { background-color: #0f3460; color: #00adb5; }
        .fixable { background-color: #1b3a2b; }
    </style>
</head>
<body>
    <h1>Executive DevSecOps Security & Compliance Report</h1>
    <div class="card">
        <p><strong>Target Host:</strong> %s</p>
        <p><strong>Audit Timestamp:</strong> %s</p>
        <p><strong>Assessment Scope:</strong> Nmap, Trivy, OpenSCAP, InSpec, OWASP ZAP, CIS 18, MITRE ATT&CK, SAST, DAST</p>
        <p><strong>Total Findings:</strong> %d</p>
    </div>

    <h2>Correlated Security Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Description</th>
            <th>Sources</th>
            <th>Auto-Fixable</th>
        </tr>`, targetHost, time.Now().Format("2006-01-02 15:04:05"), len(findings))

	for _, f := range findings {
		fixable := "No"
		if f.AutoFixable {
			fixable = "Yes"
		}
		rowClass := ""
		if f.AutoFixable {
			rowClass = " class=\"fixable\""
		}
		htmlContent += fmt.Sprintf(`
        <tr%s>
            <td class="%s">%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>`, rowClass, f.Severity, f.Severity, f.Title, f.Description, strings.Join(f.Sources, ", "), fixable)
	}

	htmlContent += `
    </table>
    <p style="margin-top:30px; color:#aaa;">This report was generated automatically by the Cross-Suite_Wizard DevSecOps platform.</p>
</body>
</html>`

	_ = os.WriteFile(reportPath, []byte(htmlContent), 0644)
	return reportPath
}