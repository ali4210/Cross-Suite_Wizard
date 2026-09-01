package security

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ShowReconMenu renders the interactive Nmap & OSINT menu
func ShowReconMenu(reader *bufio.Reader, client *ssh.Client, targetHost string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
		fmt.Println(Cyan + Bold + "=== HUB 5: RECONNAISSANCE, NMAP MADE EASY & OSINT ENGINE ===" + Reset)
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)
		fmt.Println("  [1] Quick Port & Service Banner Scan (Fast)")
		fmt.Println("  [2] Deep Security Vulnerability Audit (Nmap --script=vuln)")
		fmt.Println("  [3] Full 65535 Port Reconnaissance (Comprehensive)")
		fmt.Println("  [4] OSINT - DNS, WHOIS & Historical IP Inspection")
		fmt.Println("  [5] Passive Web Leak & Exposed .env File Audit")
		fmt.Println("  [6] UDP Service Scan (ports 1-1000)")
		fmt.Println("  [7] Aggressive Scan (-A) with OS/Version Detection")
		fmt.Println("  [0] Back to Security Menu")
		fmt.Println(Cyan + "--------------------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select recon option [0-7]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			runNmapScanWithSpinner(client, targetHost, "nmap -sV -F", "Quick_Service_Banner_Scan")
		case "2":
			runNmapScanWithSpinner(client, targetHost, "nmap -sV --script=vuln", "Nmap_Vulnerability_Audit")
		case "3":
			runNmapScanWithSpinner(client, targetHost, "nmap -p- -T4", "Full_65535_Port_Scan")
		case "4":
			runOSINTScan(client, targetHost)
		case "5":
			runEnvLeakCheck(client, targetHost)
		case "6":
			runNmapScanWithSpinner(client, targetHost, "nmap -sU -p 1-1000 -T4", "UDP_Service_Scan")
		case "7":
			runNmapScanWithSpinner(client, targetHost, "nmap -A -T4", "Aggressive_OS_Service_Scan")
		default:
			fmt.Println(Yellow + "[!] Invalid choice. Please try again." + Reset)
		}
	}
}

// runNmapScanWithSpinner ensures Nmap is present, executes scan, and opens interactive scrollable viewer
func runNmapScanWithSpinner(client *ssh.Client, targetHost string, baseCmd string, scanTitle string) {
	provisionCmd := `
		if ! command -v nmap >/dev/null 2>&1; then
			echo '[!] Nmap missing on target. Auto-installing packages...' >&2
			if command -v apt-get >/dev/null 2>&1; then
				sudo apt-get update -qq && sudo apt-get install -y -qq nmap >/dev/null 2>&1
			elif command -v yum >/dev/null 2>&1; then
				sudo yum install -y -q nmap >/dev/null 2>&1
			elif command -v dnf >/dev/null 2>&1; then
				sudo dnf install -y -q nmap >/dev/null 2>&1
			elif command -v apk >/dev/null 2>&1; then
				sudo apk add --no-cache nmap >/dev/null 2>&1
			fi
		fi
	`

	fullScanCmd := fmt.Sprintf("%s && %s %s", strings.TrimSpace(provisionCmd), baseCmd, targetHost)

	fmt.Printf("\n"+Cyan+Bold+"[+] Target Locked: %s"+Reset+"\n", targetHost)

	out, err := executeRemoteCommandWithSpinner(client, fullScanCmd, scanTitle)

	if err != nil {
		fmt.Printf(Yellow+"[!] Scan completed with notice: %v\n"+Reset, err)
	}

	DisplayScrollableOutput(scanTitle, out)
}

// executeRemoteCommandWithSpinner is a local version; could also use the generic one.
// We'll keep this as it already exists in the file.
func executeRemoteCommandWithSpinner(client *ssh.Client, cmd string, taskLabel string) (string, error) {
	var running int32 = 1
	done := make(chan struct{})

	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		startTime := time.Now()
		i := 0

		for atomic.LoadInt32(&running) == 1 {
			elapsed := int(time.Since(startTime).Seconds())
			fmt.Fprintf(os.Stderr, "\r\033[36m[ %s ] %s... (%ds elapsed)\033[0m", frames[i%len(frames)], taskLabel, elapsed)
			i++
			time.Sleep(100 * time.Millisecond)
		}

		fmt.Fprintf(os.Stderr, "\r\033[2K")
		close(done)
	}()

	session, err := client.NewSession()
	if err != nil {
		atomic.StoreInt32(&running, 0)
		<-done
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	outputBytes, err := session.CombinedOutput(cmd)

	atomic.StoreInt32(&running, 0)
	<-done

	return string(outputBytes), err
}

func runOSINTScan(client *ssh.Client, targetHost string) {
	cmd := fmt.Sprintf("whois %s 2>/dev/null || dig %s ANY 2>/dev/null || host %s", targetHost, targetHost, targetHost)
	out, _ := executeRemoteCommandWithSpinner(client, cmd, fmt.Sprintf("Gathering DNS & WHOIS OSINT for %s", targetHost))

	DisplayScrollableOutput("OSINT_DNS_Whois", out)
}

func runEnvLeakCheck(client *ssh.Client, targetHost string) {
	cmd := `find /var/www/ /opt/ /srv/ -name '.env' -o -name 'config.json' -o -name 'id_rsa' -o -name '*.pem' 2>/dev/null | head -n 20`
	out, _ := executeRemoteCommandWithSpinner(client, cmd, "Auditing target filesystem for exposed .env & SSH keys")

	DisplayScrollableOutput("Secret_Leak_Audit", out)
}