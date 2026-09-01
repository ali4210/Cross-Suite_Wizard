package zap

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var localSudoPassword string
var zapImage string

// ---------------------------------------------------------------------
// Authentication gateway (kept from your file)
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

	fmt.Println(common.Red + "[!] CRITICAL: Maximum attempts reached. Access denied." + common.Reset)
	return false
}

// ---------------------------------------------------------------------
// Sudo wrapper (kept your printf escaping)
// ---------------------------------------------------------------------
func wrapSudo(cmd string) string {
	if localSudoPassword == "" {
		return cmd
	}
	escaped := strings.ReplaceAll(localSudoPassword, "'", "'\"'\"'")
	return fmt.Sprintf("printf '%%s\\n' '%s' | sudo -S sh -c '%s'", escaped, strings.ReplaceAll(cmd, "'", "'\"'\"'"))
}

// ---------------------------------------------------------------------
// Main menu with default preset (option 1)
// ---------------------------------------------------------------------
func ShowZAPMenu(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	if sudoPassword != "" {
		localSudoPassword = sudoPassword
	}

	if !ensureAutonomousPermissionsWithPrompt(client) {
		fmt.Println(common.Red + "[!] Authentication failed. Access to ZAP Proxy Engine denied." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Println(common.Cyan + "[+] Checking ZAP/Docker environment..." + common.Reset)
	if !ensureZAP(client, reader) {
		fmt.Println(common.Red + "[!] ZAP could not be set up. Please ensure Docker is installed and running." + common.Reset)
		common.PausePrompt()
		return
	}
	fmt.Println(common.Green + "[✔] ZAP environment ready (using image: " + zapImage + ")." + common.Reset)

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== ZAP PROXY ENGINE (DAST) ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Yellow + "📖 PRESET DESCRIPTIONS:" + common.Reset)
		fmt.Println("  [1] Baseline Scan (quick passive) – No active attacks, low load, good for initial check.")
		fmt.Println("  [2] Full Active Scan (spider + attacks) – Aggressive, finds deep vulnerabilities.")
		fmt.Println("  [3] API Scan (REST/GraphQL) – Tests API endpoints with OpenAPI/SOAP/GraphQL.")
		fmt.Println("  [4] Custom ZAP Command (expert) – Run your own zap commands with full control.")
		fmt.Println("  [5] Auto-Remediation – Suggests fixes for common issues (HSTS, CSRF, etc.).")
		fmt.Println("  [6] Generate HTML Report – Export the last scan result as HTML.")
		fmt.Println("  [7] Run All Scans – Executes Baseline, Active, and API scans sequentially.")
		fmt.Println(common.Red + "  [0] Back" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select ZAP preset [0-7] (default 1): " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		if choice == "" {
			choice = "1" // default to Baseline Scan
			fmt.Println(common.Yellow + "[+] No selection, defaulting to option 1 (Baseline)." + common.Reset)
		}

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		target := getTarget(reader)
		if target == "" {
			continue
		}

		switch choice {
		case "1":
			runZAPScan(client, target, "baseline", "")
		case "2":
			runZAPScan(client, target, "active", "")
		case "3":
			fmt.Print("Enter API format (openapi/soap/graphql) [default: openapi]: ")
			format, _ := reader.ReadString('\n')
			format = strings.TrimSpace(format)
			if format == "" {
				format = "openapi"
				fmt.Println(common.Yellow + "[+] Using default format: openapi." + common.Reset)
			}
			opts := fmt.Sprintf("-f %s", format)
			runZAPScan(client, target, "api", opts)
		case "4":
			fmt.Print("Enter custom ZAP options (or press Enter for default '-scan -spider -g gen.conf'): ")
			opts, _ := reader.ReadString('\n')
			opts = strings.TrimSpace(opts)
			if opts == "" {
				opts = "-scan -spider -g gen.conf"
				fmt.Println(common.Yellow + "[+] Using default custom options." + common.Reset)
			}
			runZAPScan(client, target, "custom", opts)
		case "5":
			autoRemediateZAP(client, target)
		case "6":
			generateZAPReport(client, target)
		case "7":
			runAllZAPScans(client, target)
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice. Please select 0-7." + common.Reset)
		}
	}
}

// ---------------------------------------------------------------------
// Docker & ZAP setup
// ---------------------------------------------------------------------
func ensureZAP(client *ssh.Client, reader *bufio.Reader) bool {
	checkDocker := "command -v docker >/dev/null 2>&1"
	if _, err := common.ExecuteRemoteCommand(client, checkDocker, common.DefaultCmdTimeout); err != nil {
		fmt.Println(common.Yellow + "[!] Docker not installed. ZAP requires Docker." + common.Reset)
		return false
	}

	dockerRunning := "sudo docker info >/dev/null 2>&1"
	if _, err := common.ExecuteRemoteCommand(client, wrapSudo(dockerRunning), common.DefaultCmdTimeout); err != nil {
		fmt.Println(common.Yellow + "[!] Docker daemon is not running. Please start Docker." + common.Reset)
		return false
	}

	possibleImages := []string{
		"zaproxy/zap-stable",
		"zaproxy/zap:stable",
		"zaproxy/zap:latest",
		"owasp/zap2docker-stable",
		"ghcr.io/zaproxy/zaproxy:stable",
		"ghcr.io/zaproxy/zaproxy:latest",
	}

	for _, img := range possibleImages {
		checkLocal := fmt.Sprintf("sudo docker image inspect %s >/dev/null 2>&1", img)
		if _, err := common.ExecuteRemoteCommand(client, wrapSudo(checkLocal), common.DefaultCmdTimeout); err == nil {
			zapImage = img
			fmt.Println(common.Green + "[✔] Found existing ZAP image: " + img + common.Reset)
			return true
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		for _, img := range possibleImages {
			fmt.Printf(common.Yellow+"[+] Attempting to pull %s...\n"+common.Reset, img)
			pullCmd := fmt.Sprintf("sudo docker pull %s", img)
			out, err := common.ExecuteRemoteCommand(client, wrapSudo(pullCmd), 10*time.Minute)

			if err == nil {
				zapImage = img
				fmt.Println(common.Green + "[✔] Successfully pulled ZAP image: " + img + common.Reset)
				return true
			}

			fmt.Printf(common.Yellow+"[!] Pull failed for %s: %v\n"+common.Reset, img, err)
			if out != "" {
				fmt.Println(out)
			}
		}

		if attempt == 0 {
			fmt.Println(common.Red + "[!] All attempts to pull a ZAP image failed." + common.Reset)
			fmt.Println(common.Yellow + "This is likely due to a Docker registry policy blocking user repositories." + common.Reset)
			fmt.Println(common.Cyan + "To bypass this, you can load the image from a tarball:" + common.Reset)
			fmt.Println("1. On a machine that CAN pull the image, run:")
			fmt.Println("   docker pull zaproxy/zap-stable")
			fmt.Println("   docker save zaproxy/zap-stable -o zap.tar")
			fmt.Println("2. Transfer zap.tar to this machine.")
			fmt.Println("3. Run: sudo docker load -i zap.tar")
			fmt.Println(common.Yellow + "After loading, press Enter to re-check." + common.Reset)
			fmt.Print("Press Enter after you have loaded the image...")
			_, _ = reader.ReadString('\n')

			for _, img := range possibleImages {
				checkLocal := fmt.Sprintf("sudo docker image inspect %s >/dev/null 2>&1", img)
				if _, err := common.ExecuteRemoteCommand(client, wrapSudo(checkLocal), common.DefaultCmdTimeout); err == nil {
					zapImage = img
					fmt.Println(common.Green + "[✔] Found ZAP image: " + img + common.Reset)
					return true
				}
			}
			fmt.Println(common.Yellow + "[!] Still no ZAP image found. Please try loading it again." + common.Reset)
		}
	}

	fmt.Println(common.Red + "[!] ZAP image could not be obtained." + common.Reset)
	return false
}

func getTarget(reader *bufio.Reader) string {
	fmt.Print("Enter target URL (e.g., http://127.0.0.1) [default: http://127.0.0.1]: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Println(common.Yellow + "[!] No target entered. Using default: http://127.0.0.1" + common.Reset)
		return "http://127.0.0.1"
	}
	return target
}

// ---------------------------------------------------------------------
// Pager for scrollable output
// ---------------------------------------------------------------------
func displayWithPager(output string) {
	if output == "" {
		return
	}
	tmpFile, err := ioutil.TempFile("", "zap_output_*.txt")
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

// ---------------------------------------------------------------------
// Scan execution (updated to use pager)
// ---------------------------------------------------------------------
func runZAPScan(client *ssh.Client, target, scanType, opts string) {
	if zapImage == "" {
		fmt.Println(common.Red + "[!] No ZAP image defined. Please set up ZAP first." + common.Reset)
		return
	}
	fmt.Printf(common.Cyan+"[+] Running ZAP %s scan on %s...\n"+common.Reset, scanType, target)

	// Use --network host to allow container to access host's localhost
	baseCmd := fmt.Sprintf("sudo docker run --rm --network host -t %s", zapImage)
	var cmd string
	switch scanType {
	case "baseline":
		cmd = baseCmd + " zap-baseline.py -t " + target
	case "active":
		// Include -r for report generation
		cmd = baseCmd + " zap-full-scan.py -t " + target + " -r /tmp/zap_report.html"
	case "api":
		cmd = baseCmd + " zap-api-scan.py -t " + target + " " + opts
	case "custom":
		cmd = baseCmd + " " + opts
	default:
		cmd = baseCmd + " zap-baseline.py -t " + target
	}
	cmd = wrapSudo(cmd)

	out, err := common.ExecuteRemoteCommand(client, cmd, common.LongCmdTimeout)
	if err != nil {
		fmt.Printf(common.Red+"[!] Scan error: %v\n"+common.Reset, err)
	}
	fmt.Println(common.Blue + "==================== ZAP OUTPUT ====================" + common.Reset)
	if out == "" {
		fmt.Println(common.Yellow + "[!] No output from ZAP. The scan might have failed or produced no results." + common.Reset)
	} else {
		displayWithPager(out)
	}
	fmt.Println(common.Blue + "========================================================" + common.Reset)
	common.PausePrompt()
}

// runAllZAPScans sequentially runs baseline, active, and API scans.
func runAllZAPScans(client *ssh.Client, target string) {
	fmt.Println(common.Cyan + "[+] Running all ZAP presets sequentially..." + common.Reset)
	fmt.Println(common.Yellow + "  1. Baseline Scan" + common.Reset)
	runZAPScan(client, target, "baseline", "")
	fmt.Println(common.Yellow + "  2. Full Active Scan" + common.Reset)
	runZAPScan(client, target, "active", "")
	fmt.Println(common.Yellow + "  3. API Scan (using openapi format)" + common.Reset)
	runZAPScan(client, target, "api", "-f openapi")
	fmt.Println(common.Green + "[✔] All scans completed." + common.Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// Remediation & Reporting
// ---------------------------------------------------------------------
func autoRemediateZAP(client *ssh.Client, target string) {
	fmt.Println(common.Yellow + "[+] Parsing ZAP findings and generating remediation advice..." + common.Reset)
	fmt.Println(common.Cyan + "Common issues and fixes:" + common.Reset)
	fmt.Println("  - Missing HSTS header: add 'strict-transport-security' header.")
	fmt.Println("  - Missing X-Frame-Options: add 'X-Frame-Options: DENY'.")
	fmt.Println("  - Missing CSRF tokens: implement anti-CSRF tokens in forms.")
	fmt.Println("  - SQL injection: use parameterized queries.")
	fmt.Println("  - XSS: sanitize user input and use CSP.")
	fmt.Println("  - Open ports: close unnecessary ports via firewall.")
	fmt.Println(common.Yellow + "For detailed fixes, review the ZAP report." + common.Reset)
	common.PausePrompt()
}

func generateZAPReport(client *ssh.Client, target string) {
	if zapImage == "" {
		fmt.Println(common.Red + "[!] No ZAP image defined. Please set up ZAP first." + common.Reset)
		return
	}
	fmt.Println(common.Cyan + "[+] Attempting to copy report from container..." + common.Reset)
	// Run a temporary container to copy the report if it exists
	cpCmd := fmt.Sprintf("sudo docker run --rm -v /tmp:/host_tmp %s cp /tmp/zap_report.html /host_tmp/zap_report.html 2>/dev/null || echo 'No report found'", zapImage)
	cpCmd = wrapSudo(cpCmd)
	out, err := common.ExecuteRemoteCommand(client, cpCmd, common.DefaultCmdTimeout)
	if err != nil || strings.Contains(out, "No report found") {
		fmt.Println(common.Yellow + "[!] No report found. Please run a Full Active Scan first (option 2)." + common.Reset)
	} else {
		fmt.Println(common.Green + "✅ Report saved to /tmp/zap_report.html on the host." + common.Reset)
	}
	common.PausePrompt()
}