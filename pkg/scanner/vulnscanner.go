package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
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

type ShodanHostResponse struct {
	IPStr     string   `json:"ip_str"`
	Ports     []int    `json:"ports"`
	Vulls     []string `json:"vulns"`
	OS        string   `json:"os"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
}

type VulnerabilityItem struct {
	Service     string
	Port        string
	Severity    string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
	Description string
	Mitigation  string
}

func ShowScannerMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, host string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== ENGINE 3: LOCAL & API-DRIVEN VULNERABILITY ENGINE ===" + Reset)
		fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"Target OS: "+Reset+Bold+"%s\n"+Reset, host, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Run Full Internal Audit (Banner Grabber & Misconfig Detector)")
		fmt.Println("  [2] Check High-Risk Exposed Ports (Unauth Redis, Mongo, Telnet, FTP)")
		fmt.Println("  [3] Shodan Threat Intelligence Scan (API Key Query for Public Surface)")
		fmt.Println("  [4] Full Hybrid Scan (Internal Service Audit + External Shodan Threat)")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

		switch choice {
		case "1":
			runInternalVulnScan(client, targetOS, host)
		case "2":
			checkHighRiskPorts(client, targetOS)
		case "3":
			runShodanScan(reader, client, host)
		case "4":
			runHybridScan(reader, client, targetOS, host)
		case "0", "q", "Q":
			return
		}
	}
}

func runInternalVulnScan(client *ssh.Client, targetOS osdetect.TargetOS, host string) {
	out := runTaskWithSpinner("Probing listening services and banner signatures", func() string {
		return performInternalServiceAudit(client, targetOS, host)
	})

	displayInPager("=== INTERNAL VULNERABILITY AUDIT REPORT: " + host + " ===\n\n" + out + "\n\n(Press 'q' to return to scanner menu)")
}

func checkHighRiskPorts(client *ssh.Client, targetOS osdetect.TargetOS) {
	out := runTaskWithSpinner("Auditing high-risk cleartext & unauthenticated database ports", func() string {
		return auditDangerousServices(client, targetOS)
	})

	displayInPager("=== HIGH-RISK PORT AUDIT REPORT ===\n\n" + out + "\n\n(Press 'q' to return to scanner menu)")
}

func runShodanScan(reader *bufio.Reader, client *ssh.Client, host string) {
	apiKey := transfer.ReadRealtimeInput("\nEnter Shodan API Key (or press Enter to cancel): ")
	if apiKey == "" {
		return
	}

	queryIP := resolvePublicIPIfNeeded(client, host)

	out := runTaskWithSpinner("Querying Shodan Threat Intelligence API for "+queryIP, func() string {
		return queryShodanAPI(queryIP, apiKey)
	})

	displayInPager("=== SHODAN THREAT INTELLIGENCE AUDIT: " + queryIP + " ===\n\n" + out + "\n\n(Press 'q' to return to scanner menu)")
}

func runHybridScan(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, host string) {
	apiKey := transfer.ReadRealtimeInput("\nEnter Shodan API Key (Leave blank to skip external API threat query): ")

	out := runTaskWithSpinner("Executing Full Hybrid Vulnerability & Surface Audit", func() string {
		var sb strings.Builder
		sb.WriteString("=== 1. INTERNAL SERVICE & BANNER AUDIT ===\n")
		sb.WriteString(performInternalServiceAudit(client, targetOS, host))
		sb.WriteString("\n\n=== 2. HIGH-RISK PORT ANALYSIS ===\n")
		sb.WriteString(auditDangerousServices(client, targetOS))

		if apiKey != "" {
			queryIP := resolvePublicIPIfNeeded(client, host)
			sb.WriteString(fmt.Sprintf("\n\n=== 3. EXTERNAL SHODAN THREAT INTELLIGENCE (%s) ===\n", queryIP))
			sb.WriteString(queryShodanAPI(queryIP, apiKey))
		}

		return sb.String()
	})

	displayInPager("=== HYBRID VULNERABILITY REPORT: " + host + " ===\n\n" + out + "\n\n(Press 'q' to return to scanner menu)")
}

func resolvePublicIPIfNeeded(client *ssh.Client, host string) string {
	if isPrivateIP(host) {
		fmt.Printf(Yellow + "\n[!] Target host '%s' is an RFC 1918 Private LAN IP." + Reset, host)
		fmt.Printf(Cyan + "\n[+] Auto-resolving target host's Public WAN IP over SSH...\n" + Reset)
		
		pubIP := executeRemoteCmd(client, "curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 api.ipify.org")
		pubIP = strings.TrimSpace(pubIP)

		if pubIP != "" && !strings.Contains(pubIP, "Error") && !strings.Contains(pubIP, "<html") {
			fmt.Printf(Green+Bold+"[✔] Auto-detected Public WAN IP: %s\n"+Reset, pubIP)
			return pubIP
		}
		fmt.Printf(Yellow + "[!] Could not resolve public WAN IP automatically. Falling back to host IP: %s\n" + Reset, host)
	}
	return host
}

func isPrivateIP(ipStr string) bool {
	return strings.HasPrefix(ipStr, "192.168.") ||
		strings.HasPrefix(ipStr, "10.") ||
		strings.HasPrefix(ipStr, "127.") ||
		strings.HasPrefix(ipStr, "172.16.") ||
		strings.HasPrefix(ipStr, "172.17.") ||
		strings.HasPrefix(ipStr, "172.18.") ||
		strings.HasPrefix(ipStr, "172.19.") ||
		strings.HasPrefix(ipStr, "172.2") ||
		strings.HasPrefix(ipStr, "172.30.") ||
		strings.HasPrefix(ipStr, "172.31.")
}

func performInternalServiceAudit(client *ssh.Client, targetOS osdetect.TargetOS, host string) string {
	var sb strings.Builder
	var cmd string

	if targetOS == osdetect.OSWindows {
		cmd = `powershell -NoProfile -Command "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { '$([string]$_.LocalAddress):' + $_.LocalPort + ' ' + $_.OwningProcess }"`
	} else {
		cmd = `ss -tulpn || netstat -tuln`
	}

	rawPorts := executeRemoteCmd(client, cmd)
	lines := strings.Split(rawPorts, "\n")

	var vulnerabilities []VulnerabilityItem

	for _, l := range lines {
		lTrim := strings.TrimSpace(l)
		if lTrim == "" || strings.HasPrefix(lTrim, "Netid") || strings.HasPrefix(lTrim, "Active") {
			continue
		}

		port := extractPortNumber(lTrim)
		if port == "" {
			continue
		}

		banner := grabLocalBanner(client, port)
		vuln := analyzeBannerVulnerabilities(port, banner)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		} else {
			vulnerabilities = append(vulnerabilities, VulnerabilityItem{
				Service:     fmt.Sprintf("Port %s Service", port),
				Port:        port,
				Severity:    "INFO",
				Description: fmt.Sprintf("Active listening service on port %s. Banner: %s", port, banner),
				Mitigation:  "Ensure service is properly patched and protected by firewall rules.",
			})
		}
	}

	sb.WriteString(fmt.Sprintf("Total Active Port Surface Scanned: %d Ports\n", len(vulnerabilities)))
	sb.WriteString("--------------------------------------------------------------------------------------------------------\n")

	for _, v := range vulnerabilities {
		sevColor := Green
		switch v.Severity {
		case "CRITICAL":
			sevColor = Red + Bold
		case "HIGH":
			sevColor = Red
		case "MEDIUM":
			sevColor = Yellow + Bold
		case "LOW":
			sevColor = Yellow
		}

		sb.WriteString(fmt.Sprintf("[%s] PORT %s - %s\n", sevColor+v.Severity+Reset, v.Port, v.Service))
		sb.WriteString(fmt.Sprintf("   Details:    %s\n", v.Description))
		sb.WriteString(fmt.Sprintf("   Mitigation: %s\n", v.Mitigation))
		sb.WriteString("--------------------------------------------------------------------------------------------------------\n")
	}

	return sb.String()
}

func auditDangerousServices(client *ssh.Client, targetOS osdetect.TargetOS) string {
	var sb strings.Builder
	dangerousPorts := map[string]string{
		"21":    "FTP (Cleartext Authentication)",
		"23":    "Telnet (Unencrypted Remote Administration)",
		"3389":  "RDP (Exposed Remote Desktop Protocol)",
		"5900":  "VNC (Exposed Remote Framebuffer)",
		"6379":  "Redis Database (Check for Unauthenticated Access)",
		"27017": "MongoDB (Check for Unauthenticated Remote Access)",
		"11211": "Memcached (Potential UDP Amplification Vector)",
	}

	var cmd string
	if targetOS == osdetect.OSWindows {
		cmd = `powershell -NoProfile -Command "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort"`
	} else {
		cmd = `ss -tulpn || netstat -tuln`
	}

	output := executeRemoteCmd(client, cmd)
	foundDangerous := 0

	for port, svcName := range dangerousPorts {
		if strings.Contains(output, ":"+port+" ") || strings.Contains(output, ":"+port+"\n") || strings.Contains(output, " "+port+" ") {
			foundDangerous++
			sb.WriteString(fmt.Sprintf("%s[HIGH RISK DETECTED]%s Port %s - %s\n", Red+Bold, Reset, port, svcName))

			if port == "6379" {
				redisResp := executeRemoteCmd(client, "redis-cli ping 2>/dev/null || echo 'PING' | nc 127.0.0.1 6379 2>/dev/null")
				if strings.Contains(redisResp, "PONG") {
					sb.WriteString(fmt.Sprintf("   %s[CRITICAL VULNERABILITY]%s Unauthenticated Redis Instance Active! Allows arbitrary file write/remote code execution.\n", Red+Bold, Reset))
				}
			}
		}
	}

	if foundDangerous == 0 {
		sb.WriteString(Green + Bold + "[✔] No high-risk cleartext or unauthenticated database ports exposed locally!\n" + Reset)
	}

	return sb.String()
}

func queryShodanAPI(ip string, apiKey string) string {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	client := http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Sprintf("[Error querying Shodan API: %v]", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Sprintf("[Shodan API Query Failed for IP %s - HTTP Status Code: %d]", ip, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "[Error reading Shodan response body]"
	}

	var sData ShodanHostResponse
	if err := json.Unmarshal(body, &sData); err != nil {
		return "[Error parsing Shodan JSON response]"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Public Query IP:  %s\n", sData.IPStr))
	sb.WriteString(fmt.Sprintf("Organization:     %s (%s)\n", sData.Org, sData.ISP))
	sb.WriteString(fmt.Sprintf("Operating System: %s\n", sData.OS))
	sb.WriteString(fmt.Sprintf("Open Public Ports: %v\n\n", sData.Ports))

	if len(sData.Vulls) > 0 {
		sb.WriteString(Red + Bold + fmt.Sprintf("EXPOSED PUBLIC CVES DETECTED (%d Total):\n", len(sData.Vulls)) + Reset)
		for _, cve := range sData.Vulls {
			sb.WriteString(fmt.Sprintf("  - %s%s%s (Public Surface Exploit Candidate)\n", Red, cve, Reset))
		}
	} else {
		sb.WriteString(Green + Bold + "[✔] No public CVE vulnerabilities indexed on Shodan for this IP.\n" + Reset)
	}

	return sb.String()
}

func grabLocalBanner(client *ssh.Client, port string) string {
	cmd := fmt.Sprintf("echo '' | nc -w 2 127.0.0.1 %s 2>/dev/null || curl -sI 127.0.0.1:%s | head -n 1", port, port)
	out := executeRemoteCmd(client, cmd)
	return strings.TrimSpace(out)
}

func analyzeBannerVulnerabilities(port string, banner string) *VulnerabilityItem {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "openssh_7.2") || strings.Contains(bannerLower, "openssh_6.") {
		return &VulnerabilityItem{
			Service:     "OpenSSH Daemon",
			Port:        port,
			Severity:    "HIGH",
			Description: fmt.Sprintf("Legacy OpenSSH banner detected: '%s'. Susceptible to enumeration and cipher vulnerabilities.", banner),
			Mitigation:  "Upgrade OpenSSH to latest version and restrict SSH MACs and Ciphers.",
		}
	}

	if strings.Contains(bannerLower, "apache/2.4.18") || strings.Contains(bannerLower, "apache/2.2") {
		return &VulnerabilityItem{
			Service:     "Apache HTTP Server",
			Port:        port,
			Severity:    "MEDIUM",
			Description: fmt.Sprintf("Outdated Apache HTTP Server version: '%s'.", banner),
			Mitigation:  "Apply APT/YUM security updates to patch web server modules.",
		}
	}

	if port == "21" || strings.Contains(bannerLower, "vsftpd") {
		return &VulnerabilityItem{
			Service:     "FTP Service",
			Port:        port,
			Severity:    "HIGH",
			Description: "FTP transfers credentials and data in cleartext.",
			Mitigation:  "Disable plain FTP and enforce SFTP or FTPS (TLS).",
		}
	}

	return nil
}

func extractPortNumber(line string) string {
	fields := strings.Fields(line)
	for _, f := range fields {
		if strings.Contains(f, ":") {
			parts := strings.Split(f, ":")
			p := parts[len(parts)-1]
			if p != "" && regexp.MustCompile(`^[0-9]+$`).MatchString(p) {
				return p
			}
		}
	}
	return ""
}

func executeRemoteCmd(client *ssh.Client, rawCmd string) string {
	session, err := client.NewSession()
	if err != nil {
		return ""
	}
	defer session.Close()

	output, _ := session.CombinedOutput(rawCmd + " 2>&1")
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
	fmt.Print(Yellow + "\nPress Enter to return to scanner menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}