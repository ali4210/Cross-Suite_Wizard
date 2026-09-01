package report

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cross-ssh/pkg/transfer"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// GenerateExecutiveHTMLReport compiles audit logs into a clean HTML dashboard stored in ./reports/
func GenerateExecutiveHTMLReport(targetHost string, scanData string, userPath string) {
	fmt.Println(Cyan + Bold + "\n[+] Compiling Executive HTML Security Audit Report..." + Reset)

	userPath = strings.TrimSpace(userPath)

	// Ensure the reports directory exists in the tool root
	reportsDir := filepath.Join(".", "reports")
	_ = os.MkdirAll(reportsDir, 0755)

	var finalPath string
	if userPath == "" {
		finalPath = filepath.Join(reportsDir, "executive_report.html")
	} else {
		fileInfo, err := os.Stat(userPath)
		if (err == nil && fileInfo.IsDir()) || strings.HasSuffix(userPath, "/") || strings.HasSuffix(userPath, "\\") {
			finalPath = filepath.Join(userPath, "executive_report.html")
		} else if !strings.HasSuffix(strings.ToLower(userPath), ".html") {
			finalPath = filepath.Join(userPath, "executive_report.html")
		} else {
			finalPath = userPath
		}
	}

	// Create parent directory for whatever final path was resolved
	parentDir := filepath.Dir(finalPath)
	if parentDir != "" && parentDir != "." {
		_ = os.MkdirAll(parentDir, 0755)
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	sanitizedData := strings.ReplaceAll(scanData, "<", "&lt;")
	sanitizedData = strings.ReplaceAll(sanitizedData, ">", "&gt;")

	criticalCount := strings.Count(scanData, "CRITICAL") + strings.Count(scanData, "[✘]")
	warningCount := strings.Count(scanData, "HIGH") + strings.Count(scanData, "[⚠]")
	passCount := strings.Count(scanData, "[✔]") + strings.Count(scanData, "COMPLIANT")

	htmlTemplate := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Audit Report - %s</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 30px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 25px; }
        .header h1 { margin: 0; font-size: 26px; color: #38bdf8; }
        .header p { margin: 5px 0 0 0; color: #94a3b8; font-size: 14px; }
        .badge { background: #0284c7; color: white; padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #0f172a; padding: 20px; border-radius: 8px; border: 1px solid #334155; text-align: center; }
        .stat-card h3 { margin: 0; font-size: 14px; color: #94a3b8; text-transform: uppercase; }
        .stat-card .value { font-size: 32px; font-weight: bold; margin-top: 10px; }
        .val-red { color: #f87171; }
        .val-yellow { color: #facc15; }
        .val-green { color: #4ade80; }
        .section-title { font-size: 18px; font-weight: bold; color: #f1f5f9; margin-bottom: 15px; border-left: 4px solid #38bdf8; padding-left: 10px; }
        pre { background: #090d16; color: #38bdf8; padding: 20px; border-radius: 8px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; font-size: 13px; line-height: 1.5; border: 1px solid #1e293b; white-space: pre-wrap; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>EXECUTIVE SECURITY & COMPLIANCE AUDIT</h1>
                <p>Target Host: <strong>%s</strong> | Generated: <strong>%s</strong></p>
            </div>
            <div class="badge">CROSS-SSH V2.0 ENTERPRISE</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Critical Findings / Failures</h3>
                <div class="value val-red">%d</div>
            </div>
            <div class="stat-card">
                <h3>High Warnings / Risk Items</h3>
                <div class="value val-yellow">%d</div>
            </div>
            <div class="stat-card">
                <h3>Passed Controls / Hardened</h3>
                <div class="value val-green">%d</div>
            </div>
        </div>

        <div class="section-title">RAW UNIFIED SCAN & THREAT AUDIT LOGS</div>
        <pre>%s</pre>

        <div class="footer">
            Generated autonomously by Cross-SSH Sovereign DevSecOps & Security Engine. Confidential report for internal security review.
        </div>
    </div>
</body>
</html>`, targetHost, targetHost, timestamp, criticalCount, warningCount, passCount, sanitizedData)

	writeErr := os.WriteFile(finalPath, []byte(htmlTemplate), 0644)
	if writeErr != nil {
		fmt.Printf(Red+"[!] Failed to write Executive HTML Report to %s: %v\n"+Reset, finalPath, writeErr)
		return
	}

	fmt.Println(Green + Bold + "================================================================================" + Reset)
	fmt.Println(Green + Bold + "   EXECUTIVE HTML REPORT GENERATED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Report Destination : %s\n"+Reset, finalPath)
	fmt.Println(Green + Bold + "================================================================================" + Reset)

	// PROMPT USER TO OPEN DIRECTLY IN BROWSER
	openChoice := transfer.ReadRealtimeInput("\nWould you like to open the HTML report file directly in your browser now? [Y/n]: ")
	if openChoice == "" || strings.ToLower(openChoice) == "y" {
		openReportInBrowser(finalPath)
	}
}

// openReportInBrowser automatically opens the generated HTML file using system default browser
func openReportInBrowser(reportPath string) {
	absPath, err := filepath.Abs(reportPath)
	if err != nil {
		absPath = reportPath
	}

	fmt.Printf(Yellow+"[+] Launching %s in web browser...\n"+Reset, absPath)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", absPath)
	case "darwin":
		cmd = exec.Command("open", absPath)
	default: // Linux / Kali
		if exec.Command("which", "xdg-open").Run() == nil {
			cmd = exec.Command("xdg-open", absPath)
		} else if exec.Command("which", "firefox").Run() == nil {
			cmd = exec.Command("firefox", absPath)
		} else {
			cmd = exec.Command("google-chrome-stable", absPath)
		}
	}

	err = cmd.Start()
	if err != nil {
		fmt.Printf(Red+"[!] Could not auto-launch browser: %v\n"+Reset, err)
		fmt.Printf(Cyan+"=> You can manually open it using: xdg-open %s\n"+Reset, absPath)
	} else {
		fmt.Println(Green + Bold + "[✔] HTML Security Report launched in web browser!" + Reset)
	}
}