package osint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/platform"
	"golang.org/x/crypto/ssh"
)

var hibpAPIKey string

// ShowOSINTMenu displays the OSINT engine menu.
func ShowOSINTMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== OSINT INTELLIGENCE ENGINE (PRESET-BASED) ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println("  [1] Domain Enumeration (Subdomains + DNS Records)")
		fmt.Println("  [2] Email Harvesting (Search for emails @domain)")
		fmt.Println("  [3] Username Search (Social Media Footprint)")
		fmt.Println("  [4] IP/WHOIS Intelligence (Geolocation, ASN, Whois)")
		fmt.Println("  [5] Custom OSINT Query (dig, whois, nslookup, theHarvester, etc.)")
		fmt.Println("  [6] Full OSINT Sweep (All Presets + Correlation)")
		fmt.Println(common.Cyan + "  [7] 🔍 Have I Been Pwned (Check email breach – API key required)" + common.Reset)
		fmt.Println(common.Red + "  [0] Back to Security Menu" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select OSINT option [0-7]: " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			runDomainEnumeration(client, host)
			common.PausePrompt()
		case "2":
			runEmailHarvesting(client, host)
			common.PausePrompt()
		case "3":
			runUsernameSearch(client, host)
			common.PausePrompt()
		case "4":
			runIPWhoisIntel(client, host)
			common.PausePrompt()
		case "5":
			runCustomOSINTQuery(reader, client, host)
			common.PausePrompt()
		case "6":
			runFullOSINTSweep(client, host)
			common.PausePrompt()
		case "7":
			runHaveIBeenPwned(reader, client, host)
			common.PausePrompt()
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		}
	}
}

// ensureOSINTTools installs dig, whois, host using the platform's package manager.
func ensureOSINTTools(client *ssh.Client) bool {
	plat, err := platform.Detect(client)
	if err != nil {
		fmt.Println(common.Yellow + "[!] Platform detection failed. Falling back to apt." + common.Reset)
		plat = &platform.Platform{PackageMgr: "apt"}
	}

	// On RHEL/CentOS, ensure EPEL is enabled for whois
	if plat.Distro == "rhel" || plat.Distro == "centos" || plat.Distro == "fedora" {
		epelCheck := "dnf repolist | grep -q epel && echo 'OK' || echo 'MISSING'"
		out, _ := common.ExecuteRemoteCommand(client, epelCheck, common.DefaultCmdTimeout)
		if strings.TrimSpace(out) != "OK" {
			fmt.Println(common.Cyan + "[+] Enabling EPEL repository..." + common.Reset)
			_, _ = common.ExecuteRemoteCommand(client, "sudo dnf install -y epel-release 2>/dev/null", common.LongCmdTimeout)
		}
	}

	tools := []struct {
		cmd string
		pkg string
	}{
		{"dig", "dnsutils"},
		{"whois", "whois"},
		{"host", "dnsutils"},
	}
	missing := []string{}
	for _, t := range tools {
		if !common.EnsureToolInstalled(client, t.cmd, t.pkg) {
			missing = append(missing, t.cmd)
		}
	}
	if len(missing) > 0 {
		fmt.Printf(common.Yellow+"[!] Missing tools: %s. Trying to install...\n"+common.Reset, strings.Join(missing, ", "))
		if err := platform.InstallPackages(client, "dnsutils", "whois"); err != nil {
			fmt.Printf(common.Red+"[!] Failed to install tools: %v\n"+common.Reset, err)
			return false
		}
		allOk := true
		for _, t := range tools {
			if !common.EnsureToolInstalled(client, t.cmd, t.pkg) {
				fmt.Printf(common.Yellow+"[!] %s still not available.\n"+common.Reset, t.cmd)
				allOk = false
			}
		}
		return allOk
	}
	return true
}

func saveReport(folder, filename, content string) string {
	dir := filepath.Join(".", "reports", folder)
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, filename)
	_ = ioutil.WriteFile(path, []byte(content), 0644)
	return path
}

// ---- Domain Enumeration ----
func runDomainEnumeration(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: Domain Enumeration" + common.Reset)
	fmt.Println("  - Enter a domain (e.g., example.com) to enumerate subdomains and DNS records.")
	fmt.Println("  - You can press Enter to use the target IP as the domain.")
	fmt.Println("  - Examples: example.com, github.com, your-own-domain.com")
	fmt.Println()
	fmt.Print("Enter domain (or press Enter for target IP): ")
	var domain string
	fmt.Scanln(&domain)
	if domain == "" {
		ipOut, _ := common.ExecuteRemoteCommand(client, "curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null || echo '127.0.0.1'", common.DefaultCmdTimeout)
		domain = strings.TrimSpace(ipOut)
		fmt.Printf(common.Cyan+"[+] Using IP as domain: %s\n"+common.Reset, domain)
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println(common.Yellow + "[!] No domain provided." + common.Reset)
		return
	}

	if !ensureOSINTTools(client) {
		fmt.Println(common.Yellow + "[!] Missing required tools. Skipping." + common.Reset)
		return
	}

	cmd := fmt.Sprintf(`
		echo "=== DNS RECORDS ==="
		dig %s ANY +short 2>/dev/null || echo "No records"
		echo -e "\n=== SUBDOMAINS (via API) ==="
		curl -s --max-time 10 "https://api.hackertarget.com/hostsearch/?q=%s" 2>/dev/null | head -n 20 || echo "API unavailable"
	`, domain, domain)

	out, err := common.ExecuteWithSpinner(client, cmd, "Enumerating domain "+domain, common.LongCmdTimeout)
	common.AuditLog(host, "osint_domain", "domain="+domain, common.ResultLabel(err))

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== DOMAIN ENUMERATION REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Target Domain: %s\n", domain))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(out)
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("domain_enum_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Domain Enumeration", sb.String(), reportPath)
}

// ---- Email Harvesting ----
func runEmailHarvesting(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: Email Harvesting" + common.Reset)
	fmt.Println("  - Enter a domain to search for email addresses using public APIs.")
	fmt.Println("  - Examples: example.com, your-domain.com")
	fmt.Println("  - Note: Free APIs have rate limits. May not return all emails.")
	fmt.Println()
	fmt.Print("Enter domain: ")
	var domain string
	fmt.Scanln(&domain)
	domain = strings.TrimSpace(domain)
	if domain == "" {
		fmt.Println(common.Yellow + "[!] No domain provided." + common.Reset)
		return
	}

	cmd := fmt.Sprintf(`
		echo "=== EMAIL SEARCH (via emailhippo) ==="
		curl -s --max-time 10 "https://api.emailhippo.com/v1/domain/%s" 2>/dev/null | grep -o '[^@]*@%s' | head -20 || echo "No emails found"
		echo -e "\n=== EMAIL SEARCH (via emailrep.io) ==="
		curl -s --max-time 10 "https://emailrep.io/%s" 2>/dev/null | grep -o '"email":"[^"]*"' | head -5 || echo "No data"
	`, domain, domain, domain)

	out, err := common.ExecuteWithSpinner(client, cmd, "Harvesting emails for "+domain, common.DefaultCmdTimeout)
	common.AuditLog(host, "osint_email", "domain="+domain, common.ResultLabel(err))

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== EMAIL HARVEST REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Target Domain: %s\n", domain))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	if strings.Contains(out, "No emails") || strings.Contains(out, "No data") || out == "" {
		sb.WriteString(common.Yellow + "No emails found. Try using a custom OSINT query with theHarvester.\n" + common.Reset)
	} else {
		sb.WriteString(common.Green + "Found the following emails:\n" + common.Reset)
		sb.WriteString(out)
	}
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("email_harvest_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Email Harvest", sb.String(), reportPath)
}

// ---- Username Search ----
func runUsernameSearch(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: Username Search" + common.Reset)
	fmt.Println("  - Enter a username to search across popular social media platforms.")
	fmt.Println("  - Examples: 'johndoe', 'alice', 'your-username'")
	fmt.Println("  - The tool will check if the username exists on sites like GitHub, Twitter, etc.")
	fmt.Println()
	fmt.Print("Enter username: ")
	var username string
	fmt.Scanln(&username)
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println(common.Yellow + "[!] No username provided." + common.Reset)
		return
	}

	sites := []string{
		"github.com", "twitter.com", "reddit.com", "youtube.com",
		"instagram.com", "facebook.com", "linkedin.com", "gitlab.com",
		"bitbucket.org", "pinterest.com", "tumblr.com", "twitch.tv",
	}
	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== USERNAME SEARCH REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Username: %s\n", username))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("%-25s %-10s\n", "Platform", "Status"))
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for _, site := range sites {
		url := fmt.Sprintf("https://%s/%s", site, username)
		resp, err := http.Head(url)
		status := "Not Found"
		color := common.Red
		if err == nil && resp.StatusCode == 200 {
			status = "Found"
			color = common.Green
		}
		sb.WriteString(fmt.Sprintf("%s%-25s %s%s\n", color, site, status, common.Reset))
	}
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("username_search_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Username Search", sb.String(), reportPath)
}

// ---- IP/WHOIS Intelligence ----
func runIPWhoisIntel(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: IP/WHOIS Intelligence" + common.Reset)
	fmt.Println("  - Enter an IP address (or press Enter to use the target's public IP).")
	fmt.Println("  - Retrieves WHOIS info, geolocation, and ASN.")
	fmt.Println("  - Examples: 8.8.8.8, 192.168.1.1, or press Enter for auto-detection.")
	fmt.Println()
	fmt.Print("Enter IP (or press Enter for target's public IP): ")
	var ip string
	fmt.Scanln(&ip)
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ipOut, _ := common.ExecuteRemoteCommand(client, "curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null || echo '127.0.0.1'", common.DefaultCmdTimeout)
		ip = strings.TrimSpace(ipOut)
		if ip == "" || ip == "127.0.0.1" {
			fmt.Println(common.Yellow + "[!] Could not determine public IP. Using 127.0.0.1" + common.Reset)
			ip = "127.0.0.1"
		}
		fmt.Printf(common.Cyan+"[+] Using IP: %s\n"+common.Reset, ip)
	}
	if !ensureOSINTTools(client) {
		return
	}

	cmd := fmt.Sprintf(`
		echo "=== WHOIS INFO ==="
		whois %s 2>/dev/null | head -n 30 || echo "whois failed"
		echo -e "\n=== GEOLOCATION (free API) ==="
		curl -s --max-time 5 "http://ip-api.com/json/%s" 2>/dev/null | grep -E '"(country|regionName|city|org|isp)"' || echo "API unavailable"
	`, ip, ip)

	out, err := common.ExecuteWithSpinner(client, cmd, "IP Intelligence for "+ip, common.DefaultCmdTimeout)
	common.AuditLog(host, "osint_ip", "ip="+ip, common.ResultLabel(err))

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== IP/WHOIS REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Target IP: %s\n", ip))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(out)
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("ip_whois_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("IP/WHOIS Intelligence", sb.String(), reportPath)
}

// ---- Custom OSINT Query (with presets list printed) ----
func runCustomOSINTQuery(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: Custom OSINT Query" + common.Reset)
	fmt.Println("  - Run any OSINT tool/command on the remote host.")
	fmt.Println("  - PRESETS (1-12):")
	fmt.Println("    1. 'dig google.com ANY' - DNS lookup")
	fmt.Println("    2. 'whois 8.8.8.8' - WHOIS info")
	fmt.Println("    3. 'nslookup github.com' - DNS resolution")
	fmt.Println("    4. 'theHarvester -d example.com -l 10 -b google' - Email/domain harvest")
	fmt.Println("    5. 'dnsrecon -d example.com' - DNS reconnaissance")
	fmt.Println("    6. 'sublist3r -d example.com' - Subdomain enumeration")
	fmt.Println("    7. 'whatweb example.com' - Web fingerprinting")
	fmt.Println("    8. 'wafw00f example.com' - WAF detection")
	fmt.Println("    9. 'enum4linux 192.168.1.1' - SMB enumeration")
	fmt.Println("    10. 'nbtscan 192.168.1.0/24' - NetBIOS scan")
	fmt.Println("    11. 'smbclient -L //192.168.1.1' - SMB share listing")
	fmt.Println("    12. 'snmpwalk -v 2c -c public 192.168.1.1' - SNMP walk")
	fmt.Println("  - You can also type your own command (e.g., 'dig example.com')")
	fmt.Println()
	fmt.Print("Enter OSINT command (or preset number 1-12): ")
	cmdStr, _ := reader.ReadString('\n')
	cmdStr = strings.TrimSpace(cmdStr)

	presets := map[string]string{
		"1":  "dig google.com ANY",
		"2":  "whois 8.8.8.8",
		"3":  "nslookup github.com",
		"4":  "theHarvester -d example.com -l 10 -b google 2>/dev/null || echo 'theHarvester not installed'",
		"5":  "dnsrecon -d example.com 2>/dev/null || echo 'dnsrecon not installed'",
		"6":  "sublist3r -d example.com 2>/dev/null || echo 'sublist3r not installed'",
		"7":  "whatweb example.com 2>/dev/null || echo 'whatweb not installed'",
		"8":  "wafw00f example.com 2>/dev/null || echo 'wafw00f not installed'",
		"9":  "enum4linux 192.168.1.1 2>/dev/null || echo 'enum4linux not installed'",
		"10": "nbtscan 192.168.1.0/24 2>/dev/null || echo 'nbtscan not installed'",
		"11": "smbclient -L //192.168.1.1 2>/dev/null || echo 'smbclient not installed'",
		"12": "snmpwalk -v 2c -c public 192.168.1.1 2>/dev/null || echo 'snmpwalk not installed'",
	}

	if val, ok := presets[cmdStr]; ok {
		cmdStr = val
		fmt.Printf(common.Cyan+"[+] Using preset: %s\n"+common.Reset, cmdStr)
	}

	if cmdStr == "" {
		fmt.Println(common.Yellow + "[!] No command provided." + common.Reset)
		return
	}

	allowedTools := []string{"dig", "whois", "nslookup", "host", "theHarvester", "dnsrecon", "sublist3r", "whatweb", "wafw00f", "enum4linux", "nbtscan", "smbclient", "snmpwalk", "curl"}
	allowed := false
	for _, tool := range allowedTools {
		if strings.Contains(cmdStr, tool) {
			allowed = true
			break
		}
	}
	if !allowed {
		fmt.Println(common.Yellow + "[!] Only OSINT tools are allowed. Please use dig, whois, nslookup, theHarvester, etc." + common.Reset)
		return
	}
	if strings.ContainsAny(cmdStr, ";&|`$(){}<>") {
		fmt.Println(common.Yellow + "[!] Suspicious characters detected. Aborting." + common.Reset)
		return
	}

	out, err := common.ExecuteWithSpinner(client, cmdStr, "Custom OSINT query: "+cmdStr, common.DefaultCmdTimeout)
	common.AuditLog(host, "osint_custom", "cmd="+cmdStr, common.ResultLabel(err))

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== CUSTOM OSINT QUERY REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Command: %s\n", cmdStr))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(out)
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("custom_query_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Custom OSINT Query", sb.String(), reportPath)
}

// ---- Full OSINT Sweep ----
func runFullOSINTSweep(client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== FULL OSINT SWEEP (All Presets) ===" + common.Reset)
	fmt.Println(common.Yellow + "This will run domain, email, username, IP/WHOIS checks for the target host." + common.Reset)
	fmt.Print("Enter domain (or press Enter to use target IP as domain): ")
	var domain string
	fmt.Scanln(&domain)
	domain = strings.TrimSpace(domain)
	if domain == "" {
		ipOut, _ := common.ExecuteRemoteCommand(client, "curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null || echo '127.0.0.1'", common.DefaultCmdTimeout)
		domain = strings.TrimSpace(ipOut)
		fmt.Printf(common.Cyan+"[+] Using IP as domain: %s\n"+common.Reset, domain)
	}
	if !ensureOSINTTools(client) {
		fmt.Println(common.Yellow + "[!] Missing tools. Sweep may be incomplete." + common.Reset)
	}

	cmd := fmt.Sprintf(`
		echo "========== DOMAIN ENUMERATION =========="
		dig %s ANY +short 2>/dev/null || echo "No DNS records"
		curl -s --max-time 10 "https://api.hackertarget.com/hostsearch/?q=%s" 2>/dev/null | head -n 20

		echo -e "\n========== EMAIL HARVEST =========="
		curl -s --max-time 10 "https://api.emailhippo.com/v1/domain/%s" 2>/dev/null | grep -o '[^@]*@%s' | head -20 || echo "No emails found"

		echo -e "\n========== WHOIS =========="
		whois %s 2>/dev/null | head -n 30

		echo -e "\n========== GEOLOCATION =========="
		curl -s --max-time 5 "http://ip-api.com/json/%s" 2>/dev/null | grep -E '"(country|regionName|city|org)"'
	`, domain, domain, domain, domain, domain, domain)

	out, err := common.ExecuteWithSpinner(client, cmd, "Full OSINT Sweep for "+domain, common.LongCmdTimeout)
	common.AuditLog(host, "osint_full_sweep", "domain="+domain, common.ResultLabel(err))

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== FULL OSINT SWEEP REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Target: %s\n", domain))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(out)
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("full_sweep_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Full OSINT Sweep", sb.String(), reportPath)
}

// ---- Have I Been Pwned with API key support ----
func runHaveIBeenPwned(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Yellow + "📖 USAGE: Have I Been Pwned" + common.Reset)
	fmt.Println("  - Check if an email address has been compromised in known data breaches.")
	fmt.Println("  - Uses the HIBP v3 API (requires a free API key).")
	fmt.Println("  - To get a free key: https://haveibeenpwned.com/API/Key")
	fmt.Println("  - You can set the key via environment variable HIBP_API_KEY")
	fmt.Println()

	if hibpAPIKey == "" {
		hibpAPIKey = os.Getenv("HIBP_API_KEY")
		if hibpAPIKey == "" {
			fmt.Print(common.Yellow + "Enter your HIBP API Key (or press Enter to skip): " + common.Reset)
			var key string
			fmt.Scanln(&key)
			hibpAPIKey = strings.TrimSpace(key)
		}
	}

	fmt.Print("Enter email address to check: ")
	var email string
	fmt.Scanln(&email)
	email = strings.TrimSpace(email)
	if email == "" {
		fmt.Println(common.Yellow + "[!] No email provided." + common.Reset)
		return
	}

	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s", email)
	clientHTTP := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf(common.Red+"[!] Request creation failed: %v\n"+common.Reset, err)
		return
	}
	if hibpAPIKey != "" {
		req.Header.Set("hibp-api-key", hibpAPIKey)
	}
	req.Header.Set("User-Agent", "Cross-Suite-Wizard")

	resp, err := clientHTTP.Do(req)
	if err != nil {
		fmt.Printf(common.Red+"[!] API request failed: %v\n"+common.Reset, err)
		return
	}
	defer resp.Body.Close()

	var sb strings.Builder
	sb.WriteString(common.Cyan + common.Bold + "========== HAVE I BEEN PWNED REPORT ==========\n" + common.Reset)
	sb.WriteString(fmt.Sprintf("Email: %s\n", email))
	sb.WriteString(fmt.Sprintf("Check Time: %s\n\n", time.Now().Format(time.RFC3339)))

	if resp.StatusCode == 404 {
		sb.WriteString(common.Green + "✅ Good news! This email was not found in any known breaches.\n" + common.Reset)
	} else if resp.StatusCode == 200 {
		var breaches []struct {
			Name         string `json:"Name"`
			Domain       string `json:"Domain"`
			BreachDate   string `json:"BreachDate"`
			Description  string `json:"Description"`
		}
		body, _ := ioutil.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &breaches); err != nil {
			sb.WriteString(common.Red + "[!] Failed to parse response.\n" + common.Reset)
		} else {
			sb.WriteString(common.Red + "⚠️  This email has been pwned in the following breaches:\n" + common.Reset)
			for _, b := range breaches {
				sb.WriteString(fmt.Sprintf("  - %s (%s) - %s\n", b.Name, b.Domain, b.BreachDate))
				if b.Description != "" {
					sb.WriteString(fmt.Sprintf("    %s\n", b.Description))
				}
			}
		}
	} else if resp.StatusCode == 401 {
		sb.WriteString(common.Red + "[!] Invalid API Key. Please get a free key from https://haveibeenpwned.com/API/Key\n" + common.Reset)
		sb.WriteString(common.Yellow + "You can set the key using: export HIBP_API_KEY=your_key_here\n" + common.Reset)
	} else if resp.StatusCode == 429 {
		sb.WriteString(common.Yellow + "[!] Rate limit exceeded. Please wait a few seconds and try again.\n" + common.Reset)
	} else {
		sb.WriteString(common.Red + fmt.Sprintf("[!] API returned status %d.\n", resp.StatusCode) + common.Reset)
	}
	sb.WriteString("\n" + common.Cyan + "==================================================\n" + common.Reset)

	reportPath := saveReport("osint", fmt.Sprintf("hibp_%s.txt", time.Now().Format("20060102_150405")), sb.String())
	common.DisplayScrollableOutputWithPath("Have I Been Pwned", sb.String(), reportPath)
}