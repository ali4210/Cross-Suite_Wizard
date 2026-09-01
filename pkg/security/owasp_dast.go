package security

import (
	"bufio"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ShowDASTMenu renders the OWASP ZAP DAST Scanner sub-menu
func ShowDASTMenu(reader *bufio.Reader, client *ssh.Client, targetHost string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println("\n================================================================================")
	fmt.Println("=== HUB 5: AUTOMATED DAST ENGINE (OWASP ZAP CONTAINER) ===")
	fmt.Println("================================================================================")
	fmt.Println("📖 USAGE GUIDE:")
	fmt.Println("  - This will run an OWASP ZAP baseline scan against a web target.")
	fmt.Println("  - You will need to provide the target URL (e.g., http://localhost:8080).")
	fmt.Println("  - The scan runs inside a Docker container on the remote host.")
	fmt.Println("  - If Docker is not installed, the tool will attempt to install it.")
	fmt.Println("  - The HTML report is saved on the remote host at /tmp/zap_reports/zap_report.html")
	fmt.Println("  - Use the File Transfer Hub to download the report.")
	fmt.Println()
	fmt.Println(Cyan + "💡 TIP: Ensure the target web service is reachable from the remote host." + Reset)
	fmt.Println()

	fmt.Print("Enter Target Web Application URL (e.g., http://localhost:8080): ")
	urlInput, _ := reader.ReadString('\n')
	targetURL := strings.TrimSpace(urlInput)

	if targetURL == "" {
		fmt.Println("[!] Target URL cannot be empty.")
		return
	}

	// Ensure Docker is installed
	if !ensureTool(client, "docker", "docker.io") {
		fmt.Println("[!] Docker is required for ZAP. Please install Docker manually.")
		return
	}

	// Ensure passwordless sudo for Docker
	if !ensurePasswordlessSudo(client, targetHost) {
		fmt.Println("[!] ZAP requires passwordless sudo to run Docker. Aborting.")
		return
	}

	fmt.Printf("\n[+] Spawning OWASP ZAP Container against target: %s...\n", targetURL)
	zapCmd := fmt.Sprintf(`sudo docker run --rm -v /tmp/zap_reports:/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t %s -g gen.conf -r zap_report.html 2>&1`, targetURL)

	out, err := executeWithSpinnerRetry(client, zapCmd, "OWASP ZAP Baseline Scan", longCmdTimeout)
	if err != nil {
		fmt.Printf("[!] ZAP Execution failed: %v\n", err)
		if out != "" {
			fmt.Println(out)
		}
		return
	}

	fmt.Println("\n================================================================================")
	fmt.Println(Green + "   [✔] OWASP ZAP DAST SCAN COMPLETED!" + Reset)
	fmt.Println(Yellow + "   => HTML Report generated on target at: /tmp/zap_reports/zap_report.html" + Reset)
	fmt.Println(Yellow + "   => Use the File Transfer Hub (Hub 2) to download and view the report." + Reset)
	fmt.Println("================================================================================")
	fmt.Println(out)
}

// ensureTool is a local helper to install a tool if missing (similar to redteam's)
func ensureTool(client *ssh.Client, tool, pkg string) bool {
	// Check if tool exists
	checkCmd := fmt.Sprintf("command -v %s >/dev/null 2>&1", tool)
	_, err := executeRemoteCommand(client, checkCmd)
	if err == nil {
		return true
	}

	fmt.Printf(Yellow+"[!] Tool '%s' not found. Installing package '%s'...\n"+Reset, tool, pkg)
	installCmd := fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq %s", pkg)
	_, err = executeRemoteCommand(client, installCmd)
	if err != nil {
		fmt.Printf(Red+"[!] Install failed: %v\n"+Reset, err)
		return false
	}
	fmt.Println(Green + "[+] Installation done." + Reset)
	return true
}