package rbac

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"cross-ssh/pkg/common"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var localSudoPassword string
var currentHostAlias string

// ====================================================================
//  WINDOWS / POWERSHELL EXECUTION LAYER
//  - sends scripts with -EncodedCommand (immune to cmd.exe / outer-PowerShell
//    quoting and $variable expansion, which silently broke every inline
//    `powershell -Command "..."` string)
//  - detects real failures via a sentinel instead of assuming success
// ====================================================================

const psPrefix = `powershell -Command "`

var psMutating = regexp.MustCompile(`\b(New|Set|Add|Remove|Enable|Disable|Rename)-[A-Za-z]`)

func psEncode(script string) string {
	u := utf16.Encode([]rune(script))
	buf := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// psExec runs a raw PowerShell script. State-changing scripts run with
// ErrorActionPreference=Stop and must reach the PS_OK sentinel to count as success.
func psExec(client *ssh.Client, script string) (string, error) {
	stop := psMutating.MatchString(script)
	pref := "Continue"
	if stop {
		pref = "Stop"
	}
	wrapped := "$ErrorActionPreference='" + pref + "'; $ProgressPreference='SilentlyContinue'; try { " +
		script + "\n; Write-Output 'PS_OK' } catch { Write-Output ('PS_ERR: ' + $_.Exception.Message); exit 1 }"
	cmd := psBuildCommand(wrapped)
	out, err := common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
	cleaned := strings.TrimSpace(strings.ReplaceAll(out, "PS_OK", ""))

	if stop && !strings.Contains(out, "PS_OK") {
		msg := strings.TrimSpace(out)
		if i := strings.Index(msg, "PS_ERR:"); i >= 0 {
			msg = strings.TrimSpace(msg[i+len("PS_ERR:"):])
		}
		if msg == "" && err != nil {
			msg = err.Error()
		}
		fmt.Println(common.Red + "[!] Windows command failed: " + msg + common.Reset)
		low := strings.ToLower(msg)
		if strings.Contains(low, "access") || strings.Contains(low, "denied") ||
			strings.Contains(low, "privilege") || strings.Contains(low, "administrator") {
			fmt.Println(common.Yellow + "=> The SSH session is probably NOT elevated (UAC token filtering). See the fix shown when Hub 7 opens." + common.Reset)
		}
		return cleaned, fmt.Errorf("powershell failed: %s", msg)
	}
	return cleaned, err
}

// execRemote is a drop-in for common.ExecuteRemoteCommand: legacy
// `powershell -Command "..."` strings are unwrapped and re-sent encoded.
func execRemote(client *ssh.Client, cmd string) (string, error) {
	t := strings.TrimSpace(cmd)
	if strings.HasPrefix(t, psPrefix) && strings.HasSuffix(t, `"`) {
		script := strings.TrimSuffix(strings.TrimPrefix(t, psPrefix), `"`)
		return psExec(client, script)
	}
	return common.ExecuteRemoteCommand(client, cmd, common.DefaultCmdTimeout)
}

func checkWindowsElevation(client *ssh.Client) {
	out, _ := psExec(client, `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`)
	if strings.Contains(strings.ToLower(out), "true") {
		return
	}
	fmt.Println(common.Red + common.Bold + "[!] This SSH session is NOT running elevated on the Windows target." + common.Reset)
	fmt.Println(common.Yellow + "    Firewall, user, group and DNS changes will be refused. Fix on the Windows host (Admin PowerShell), then restart sshd:" + common.Reset)
	fmt.Println(`    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force`)
	fmt.Println(`    Restart-Service sshd`)
	fmt.Println(common.Yellow + "    (or SSH in as the built-in Administrator account). Only do this on machines you control." + common.Reset)
	common.PausePrompt()
}

const rbacTierRegistry = "/etc/cross_rbac_tiers.txt"

type UserSummary struct {
	Index       int
	Username    string
	UID         string
	AssignedIP  string
	GeoLocation string
	Shell       string
	RBACTier    string
	Status      string
	IsTool      bool
	HostAlias   string
}

type NetworkInterface struct {
	Name string
	IP   string
}

type HostSignature struct {
	OS        string
	Distro    string
	Kernel    string
	Hostname  string
	PrimaryIP string
}

type ProvisionPayload struct {
	Username                 string `json:"username"`
	Password                 string `json:"password"`
	PasswordHash             string `json:"password_hash"`
	ForceExpire              bool   `json:"force_expire"`
	MaxDays                  int    `json:"max_days"`
	AssignedIP               string `json:"assigned_ip"`
	BoundInterface           string `json:"bound_interface"`
	SSHPublicKey             string `json:"ssh_public_key"`
	AutoGenerateDedicatedKey bool   `json:"auto_generate_dedicated_key"`
}

// ====================================================================
//  PORT PRESETS – PROFESSIONAL & PRODUCTION-READY PORT CATEGORIES
// ====================================================================

var portPresets = map[string][]string{
	"🌐 Web":          {"80", "443", "8080", "8443"},
	"🗄️  Database":   {"3306", "5432", "27017", "6379", "1433", "1521"},
	"🔑 SSH":          {"22"},
	"☸️  Kubernetes": {"6443", "10250", "10255"},
	"🐳 Docker":       {"2375", "2376"},
	"📊 Monitoring":   {"9090", "9100", "3000"},
	"📦 Others":       {"25", "53", "123", "161", "389", "636", "1194", "3389", "5900", "5901"},
}

// ====================================================================
//  INTERACTIVE SELECT
// ====================================================================

func InteractiveSelect(prompt string, options []string) int {
	fmt.Println(prompt)
	for i, opt := range options {
		fmt.Printf("  [%d] %s\n", i+1, opt)
	}
	fmt.Print("Select option (0 to cancel): ")
	var input string
	fmt.Scanln(&input)
	choice, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || choice < 0 || choice > len(options) {
		return -1
	}
	if choice == 0 {
		return -1
	}
	return choice - 1
}

// ====================================================================
//  IMPROVED PORT ACCESS CONTROL (Option 10) – WITH PERSISTENT LOOP & ALL-PORTS TRACKING
// ====================================================================

func managePortAccessControl(reader *bufio.Reader, client *ssh.Client) {
	username := selectUserInteractive(reader, client, "Select User to manage port access:")
	if username == "" {
		return
	}

	sig := fetchHostSignature(client)

	if sig.OS == "windows" {
		if out, err := psExec(client, `(Get-NetFirewallProfile -Name Private).Enabled.ToString() + ',' + (Get-NetFirewallProfile -Name Public).Enabled.ToString() + ',' + (Get-NetFirewallProfile -Name Domain).Enabled.ToString()`); err == nil {
			parts := strings.Split(strings.TrimSpace(out), ",")
			if len(parts) == 3 && (parts[0] == "False" || parts[1] == "False" || parts[2] == "False") {
				fmt.Println(common.Red + common.Bold + "[!] WARNING: One or more Windows Firewall profiles are DISABLED." + common.Reset)
				fmt.Println(common.Yellow + "    Port rules will be created but WILL NOT be enforced until all profiles are enabled." + common.Reset)
				fmt.Print(common.Yellow + "    Enable all firewall profiles now? (y/N): " + common.Reset)
				ans, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(ans)) == "y" {
					if _, e := psExec(client, `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True`); e == nil {
						fmt.Println(common.Green + "    ✔ All firewall profiles enabled." + common.Reset)
					}
				}
			}
		}
	}

	// Fetch UID (POSIX) or SID/Username (Windows)
	var uid string
	if sig.OS == "windows" {
		uid = username
	} else {
		uidCmd := fmt.Sprintf("id -u %s 2>/dev/null", username)
		uidOut, _ := execRemote(client, uidCmd)
		uid = strings.TrimSpace(uidOut)
		if uid == "" {
			fmt.Println(common.Red + "[!] Could not determine UID for user." + common.Reset)
			common.PausePrompt()
			return
		}
	}

	// Loop to stay in the submenu until 0 is chosen
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "=== USER PORT ACCESS CONTROL (Security‑Group Style) ===" + common.Reset)
		fmt.Printf("Managing User: %s (UID/ID: %s) [Target OS: %s]\n", common.Bold+username+common.Reset, common.Bold+uid+common.Reset, common.Bold+sig.OS+common.Reset)

		// Show current listening ports
		fmt.Println(common.Cyan + "\n📡 Current Listening Ports on System:" + common.Reset)
		var listenCmd string
		if sig.OS == "windows" {
			listenCmd = `powershell -Command "Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort | Format-Table -HideTableHeaders"`
		} else if sig.OS == "darwin" {
			listenCmd = "lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null"
		} else {
			listenCmd = "ss -tulpn 2>/dev/null | grep LISTEN"
		}
		listenOut, _ := execRemote(client, listenCmd)
		if listenOut != "" {
			fmt.Println(common.Yellow + listenOut + common.Reset)
		} else {
			fmt.Println(common.Yellow + "  (none or command output not available)" + common.Reset)
		}

		// Show current rules for this user
		fmt.Println(common.Cyan + "\n🛡️  Current firewall OUTPUT/Egress rules for user [" + username + "]:" + common.Reset)
		if sig.OS == "windows" {
			winRulesScript := fmt.Sprintf(`Get-NetFirewallRule -DisplayName 'cross_%s_*' -ErrorAction SilentlyContinue | ForEach-Object { $p = @(($_ | Get-NetFirewallPortFilter).RemotePort) -join ','; if(-not $p){ $p = 'Any' }; '{0,-26} {1,-6} {2,-9} [{3}]' -f $_.DisplayName, $_.Action, $_.Direction, $p }`, username)
			winRulesOut, _ := psExec(client, winRulesScript)
			if strings.TrimSpace(winRulesOut) != "" {
				fmt.Println(common.Yellow + winRulesOut + common.Reset)
			} else {
				fmt.Println(common.Green + "  No Windows Firewall rules found for this user." + common.Reset)
			}
			allowed := winAllowedPorts(client, username)
			fmt.Println(common.Cyan + "\n🔓 Allowed (carved-out) egress ports for [" + username + "]:" + common.Reset)
			if len(allowed) == 0 {
				fmt.Println(common.Yellow + "  (none — user is unrestricted or fully blocked)" + common.Reset)
			} else {
				fmt.Println(common.Green + common.Bold + "  " + strings.Join(allowed, ", ") + common.Reset)
			}
			fmt.Println(common.Yellow + "  (Note: these are OUTBOUND remote ports, not the listening ports above.)" + common.Reset)
		} else if sig.OS == "darwin" {
			pfRulesOut, _ := execRemote(client, wrapSudo("pfctl -a cross_access -sr 2>/dev/null"))
			if strings.TrimSpace(pfRulesOut) != "" {
				fmt.Println(common.Yellow + pfRulesOut + common.Reset)
			} else {
				fmt.Println(common.Green + "  No macOS PF rules found for this user." + common.Reset)
			}
		} else {
			rulesCmd := fmt.Sprintf(`
python3 -c "
import subprocess, pwd
u = '%s'
try:
    uid = str(pwd.getpwnam(u).pw_uid)
except:
    uid = u
proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
found = False
for line in proc.stdout.splitlines():
    if 'owner UID match ' + uid in line:
        print(line)
        found = True
if not found:
    print('EMPTY')
"
`, username)
			rulesOut, _ := execRemote(client, wrapSudo(rulesCmd))
			if rulesOut != "" && !strings.Contains(rulesOut, "EMPTY") {
				lines := strings.Split(strings.TrimSpace(rulesOut), "\n")
				for _, l := range lines {
					if l != "" {
						fmt.Println(common.Yellow + l + common.Reset)
					}
				}
			} else {
				fmt.Println(common.Green + "  No iptables rules found for this user." + common.Reset)
			}
		}

		// Sub-menu options
		fmt.Println(common.Cyan + "\nSelect Action:" + common.Reset)
		fmt.Println("  [1] ➕ Add a port allow rule")
		fmt.Println("  [2] ➖ Remove a port allow rule")
		fmt.Println("  [0] ⬅ Back to Access Control Menu")
		fmt.Print(common.Bold + "Choice: " + common.Reset)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			addPortRule(reader, client, username, uid)
		case "2":
			removePortRule(reader, client, username, uid)
		case "0", "q", "Q":
			return
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
			time.Sleep(1 * time.Second)
		}
	}
}

func addPortRule(reader *bufio.Reader, client *ssh.Client, username, uid string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "=== ADD PORT ALLOW RULE ===" + common.Reset)
		fmt.Printf("User: %s (UID/ID: %s)\n", common.Bold+username+common.Reset, common.Bold+uid+common.Reset)

		var flatOptions []string
		for category, ports := range portPresets {
			for _, p := range ports {
				flatOptions = append(flatOptions, fmt.Sprintf("%-15s : %s", category, p))
			}
		}
		flatOptions = append(flatOptions, "🚀 ALLOW ALL PORTS (Full access)")
		flatOptions = append(flatOptions, "✏️  Custom (Enter port manually)")

		fmt.Println(common.Blue + "\nSelect a preset port, allow all, or choose Custom:" + common.Reset)
		sel := InteractiveSelect("", flatOptions)
		if sel == -1 {
			return
		}

		if sel == len(flatOptions)-1 {
			fmt.Print("Enter port number (e.g., 3306): ")
			portStr, _ := reader.ReadString('\n')
			port := strings.TrimSpace(portStr)
			if port == "" {
				fmt.Println(common.Red + "[!] No port entered." + common.Reset)
				common.PausePrompt()
				continue
			}
			if !isNumeric(port) {
				fmt.Println(common.Red + "[!] Invalid port number." + common.Reset)
				common.PausePrompt()
				continue
			}
			applyPortRule(client, username, uid, port, "add")
		} else if sel == len(flatOptions)-2 {
			applyPortRule(client, username, uid, "all", "add-all")
		} else {
			parts := strings.Split(flatOptions[sel], ":")
			port := strings.TrimSpace(parts[len(parts)-1])
			applyPortRule(client, username, uid, port, "add")
		}

		common.PausePrompt()
	}
}

func removePortRule(reader *bufio.Reader, client *ssh.Client, username, uid string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(common.Cyan + common.Bold + "=== REMOVE PORT ALLOW RULE ===" + common.Reset)
		fmt.Printf("User: %s (UID/ID: %s)\n", common.Bold+username+common.Reset, common.Bold+uid+common.Reset)

		allowed := getUserAllowedPorts(client, username, uid)
		if len(allowed) == 0 {
			fmt.Println(common.Yellow + "[!] No port allow rules found for this user." + common.Reset)
			common.PausePrompt()
			return
		}

		var options []string
		for _, item := range allowed {
			if item == "ALL-PORTS" {
				options = append(options, "🚀 Blanket Allow-All Rule (Full Access)")
			} else {
				options = append(options, fmt.Sprintf("Port %s", item))
			}
		}
		options = append(options, "🗑️  REMOVE ALL PORT RULES")
		options = append(options, "✏️  Custom (Enter port manually)")

		fmt.Println(common.Blue + "\nSelect a port to remove, remove all, or enter custom:" + common.Reset)
		sel := InteractiveSelect("", options)
		if sel == -1 {
			return
		}

		if sel == len(options)-1 {
			fmt.Print("Enter port number to remove: ")
			portStr, _ := reader.ReadString('\n')
			port := strings.TrimSpace(portStr)
			if port == "" {
				fmt.Println(common.Red + "[!] No port entered." + common.Reset)
				common.PausePrompt()
				continue
			}
			if !isNumeric(port) {
				fmt.Println(common.Red + "[!] Invalid port number." + common.Reset)
				common.PausePrompt()
				continue
			}
			if !containsPort(allowed, port) {
				fmt.Println(common.Yellow + "[!] Port " + port + " is not currently allowed. No action taken." + common.Reset)
				common.PausePrompt()
				continue
			}
			applyPortRule(client, username, uid, port, "remove")
		} else if sel == len(options)-2 {
			fmt.Print(common.Red + "Are you sure you want to remove ALL port rules for user [" + username + "]? (y/N): " + common.Reset)
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
				applyPortRule(client, username, uid, "all", "remove-all")
			} else {
				fmt.Println(common.Yellow + "[!] Cancelled." + common.Reset)
			}
		} else {
			chosen := options[sel]
			if strings.Contains(chosen, "Blanket Allow-All Rule") {
				applyPortRule(client, username, uid, "all", "remove-blanket")
			} else {
				port := strings.TrimPrefix(chosen, "Port ")
				applyPortRule(client, username, uid, port, "remove")
			}
		}

		common.PausePrompt()
	}
}

func getUserAllowedPorts(client *ssh.Client, username, uid string) []string {
	sig := fetchHostSignature(client)
	if sig.OS == "windows" {
		return winAllowedPorts(client, username)
	}
	if sig.OS == "windows" {
		cmd := fmt.Sprintf(`powershell -Command "$rules = Get-NetFirewallRule -DisplayName 'cross_%s_*' 2>$null; $ports = @(); foreach($r in $rules){ $p = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r).RemotePort; if($p -and $p -ne 'Any'){ $ports += $p } else { $ports += 'ALL-PORTS' } }; $ports -join ','"`, username)
		out, _ := execRemote(client, cmd)
		if strings.TrimSpace(out) == "" {
			return []string{}
		}
		return strings.Split(strings.TrimSpace(out), ",")
	}

	if sig.OS == "darwin" {
		out, _ := execRemote(client, wrapSudo("pfctl -a cross_access -sr 2>/dev/null"))
		var ports []string
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "port") {
				fields := strings.Fields(l)
				for idx, f := range fields {
					if f == "port" && idx+1 < len(fields) {
						ports = append(ports, fields[idx+1])
					}
				}
			}
		}
		return ports
	}

	cmd := fmt.Sprintf(`
python3 -c "
import subprocess, re
uid = '%s'
proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
ports = []
for line in proc.stdout.splitlines():
    if 'owner UID match ' + uid in line:
        match = re.search(r'(dpt|spt):(\d+)', line)
        if match:
            ports.append(match.group(2))
        elif 'ACCEPT' in line:
            if 'ALL-PORTS' not in ports:
                ports.append('ALL-PORTS')
print(','.join(ports))
"
`, uid)
	out, _ := execRemote(client, wrapSudo(cmd))
	if out == "" {
		return []string{}
	}
	parts := strings.Split(strings.TrimSpace(out), ",")
	var res []string
	for _, p := range parts {
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func containsPort(slice []string, port string) bool {
	for _, p := range slice {
		if p == port {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func applyPortRule(client *ssh.Client, username, uid, port, action string) {
	fmt.Println(common.Cyan + "[+] Applying rule..." + common.Reset)
	sig := fetchHostSignature(client)
	if sig.OS == "windows" {
		winApplyPortRule(client, username, port, action)
		return
	}

	if sig.OS == "windows" {
		switch action {
		case "add":
			cmd := fmt.Sprintf(`powershell -Command "$sid = (New-Object System.Security.Principal.NTAccount('%s')).Translate([System.Security.Principal.SecurityIdentifier]).Value; Remove-NetFirewallRule -DisplayName 'cross_%s_%s' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'cross_%s_%s' -Direction Outbound -RemotePort %s -Protocol TCP -Action Allow -LocalUser ('D:(A;;CC;;;' + $sid + ')') | Out-Null"`, username, username, port, username, port, port)
			if _, psErr := execRemote(client, cmd); psErr == nil {
				fmt.Printf(common.Green+"[✔] Windows Firewall: Port %s allowed for user %s.\n"+common.Reset, port, username)
			}
		case "add-all":
			cmd := fmt.Sprintf(`powershell -Command "$sid = (New-Object System.Security.Principal.NTAccount('%s')).Translate([System.Security.Principal.SecurityIdentifier]).Value; Remove-NetFirewallRule -DisplayName 'cross_%s_all' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'cross_%s_all' -Direction Outbound -Protocol Any -Action Allow -LocalUser ('D:(A;;CC;;;' + $sid + ')') | Out-Null"`, username, username, username)
			if _, psErr := execRemote(client, cmd); psErr == nil {
				fmt.Printf(common.Green+"[✔] Windows Firewall: ALL traffic allowed for user %s.\n"+common.Reset, username)
			}
		case "remove":
			cmd := fmt.Sprintf(`powershell -Command "Remove-NetFirewallRule -DisplayName 'cross_%s_%s' -ErrorAction SilentlyContinue"`, username, port)
			if _, psErr := execRemote(client, cmd); psErr == nil {
				fmt.Printf(common.Green+"[✔] Windows Firewall: Port %s rule removed for user %s.\n"+common.Reset, port, username)
			}
		case "remove-blanket", "remove-all":
			cmd := fmt.Sprintf(`powershell -Command "Remove-NetFirewallRule -DisplayName 'cross_%s_*' -ErrorAction SilentlyContinue"`, username)
			if _, psErr := execRemote(client, cmd); psErr == nil {
				fmt.Printf(common.Green+"[✔] Windows Firewall: ALL rules removed for user %s.\n"+common.Reset, username)
			}
		}
		return
	}

	if action == "add" && port != "all" {
		allowed := getUserAllowedPorts(client, username, uid)
		if containsPort(allowed, port) {
			fmt.Println(common.Yellow + "[!] Port " + port + " is already allowed. Skipping." + common.Reset)
			return
		}
	}

	var script string
	switch action {
	case "add":
		script = fmt.Sprintf(`
python3 -c "
import subprocess, pwd
u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)
port = '%s'
subprocess.run(['iptables', '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', uid, '-p', 'tcp', '--dport', port, '-j', 'ACCEPT'], check=False)
print('PORT_ALLOW_ADDED')
"
`, username, port)

	case "add-all":
		script = fmt.Sprintf(`
python3 -c "
import subprocess, pwd, sys

u = '%s'
try:
    uid = str(pwd.getpwnam(u).pw_uid)
except Exception as e:
    print('ERROR: Failed to get UID: ' + str(e))
    sys.exit(1)

for iteration in range(20):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    nums = []
    for line in lines:
        if 'owner UID match ' + uid in line and 'ACCEPT' in line and 'tcp' not in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                nums.append(int(parts[0]))
    if not nums:
        break
    for num in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], check=False)

result = subprocess.run(['iptables', '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', uid, '-j', 'ACCEPT'], capture_output=True, text=True)
if result.returncode != 0:
    print('ERROR: iptables failed - OUTPUT: ' + result.stderr)
    sys.exit(1)

print('ALL_ALLOWED')
"
`, username)

	case "remove":
		script = fmt.Sprintf(`
python3 -c "
import subprocess, pwd
u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)
port = '%s'
proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
nums = []
for line in proc.stdout.splitlines():
    if 'owner UID match ' + uid in line and ('dpt:' + port in line or 'spt:' + port in line):
        parts = line.split()
        if parts and parts[0].isdigit():
            nums.append(int(parts[0]))
for num in sorted(nums, reverse=True):
    subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], check=False)
print('PORT_ALLOW_REMOVED')
"
`, username, port)

	case "remove-blanket":
		script = fmt.Sprintf(`
python3 -c "
import subprocess, pwd
u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)
for iteration in range(20):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    nums = []
    for line in lines:
        if 'owner UID match ' + uid in line and 'ACCEPT' in line and 'tcp' not in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                nums.append(int(parts[0]))
    if not nums:
        break
    for num in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], check=False)
print('BLANKET_REMOVED')
"
`, username)

	case "remove-all":
		script = fmt.Sprintf(`
python3 -c "
import subprocess, pwd
u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)
for iteration in range(50):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    nums = []
    for line in proc.stdout.splitlines():
        if 'owner UID match ' + uid in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                nums.append(int(parts[0]))
    if not nums:
        break
    for num in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], check=False)
print('ALL_REMOVED')
"
`, username)
	}

	out, err := execRemote(client, wrapSudo(script))
	if err == nil {
		switch {
		case action == "add" && strings.Contains(out, "PORT_ALLOW_ADDED"):
			fmt.Printf(common.Green+"[✔] Port %s allowed for user %s.\n"+common.Reset, port, username)
		case action == "add-all" && strings.Contains(out, "ALL_ALLOWED"):
			fmt.Printf(common.Green+"[✔] ALL traffic allowed for user %s.\n"+common.Reset, username)
		case strings.Contains(out, "ERROR"):
			fmt.Printf(common.Red+"[!] Error: %s\n"+common.Reset, out)
		case action == "remove" && strings.Contains(out, "PORT_ALLOW_REMOVED"):
			fmt.Printf(common.Green+"[✔] Port %s rule removed for user %s.\n"+common.Reset, port, username)
		case action == "remove-blanket" && strings.Contains(out, "BLANKET_REMOVED"):
			fmt.Printf(common.Green+"[✔] Blanket Allow-All rule removed for user %s.\n"+common.Reset, username)
		case action == "remove-all" && strings.Contains(out, "ALL_REMOVED"):
			fmt.Printf(common.Green+"[✔] ALL port rules removed for user %s.\n"+common.Reset, username)
		default:
			fmt.Println(common.Yellow + "[!] Operation completed." + common.Reset)
		}
	} else {
		fmt.Printf(common.Red+"[!] Error: %v\nOutput: %s\n"+common.Reset, err, out)
	}
}

// ====================================================================
//  ELEVATION & PRIVILEGE WRAPPERS
// ====================================================================

func ensureElevation(client *ssh.Client) bool {
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

		sig := fetchHostSignature(client)
		if sig.OS == "windows" {
			localSudoPassword = pass
			return true
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

		outValidate, errValidate := execRemote(client, validateCmd)

		if errValidate == nil && strings.Contains(outValidate, "AUTH_OK") {
			localSudoPassword = pass
			fmt.Println(common.Green + "=> Elevation credentials verified successfully!" + common.Reset)
			return true
		}

		// Fallback for macOS standard sudo check
		macSudoCheck := fmt.Sprintf("printf '%%s\\n' '%s' | sudo -S -k true 2>/dev/null && echo 'AUTH_OK'", escaped)
		outMac, errMac := execRemote(client, macSudoCheck)
		if errMac == nil && strings.Contains(outMac, "AUTH_OK") {
			localSudoPassword = pass
			fmt.Println(common.Green + "=> Elevation credentials verified successfully (POSIX Sudo)!" + common.Reset)
			return true
		}

		fmt.Println(common.Red + "[!] Access Denied: Incorrect password." + common.Reset)
		if attempt < maxAttempts {
			fmt.Println(common.Yellow + "=> Please enter valid credentials." + common.Reset)
		}
	}
	return false
}

func wrapSudo(cmd string) string {
	if localSudoPassword == "" {
		return cmd
	}
	escapedPass := strings.ReplaceAll(localSudoPassword, "'", "'\"'\"'")
	b64Payload := base64.StdEncoding.EncodeToString([]byte(cmd))
	return fmt.Sprintf("printf '%%s\\n' '%s' | sudo -S bash -c 'echo \"%s\" | base64 -d | bash'", escapedPass, b64Payload)
}

func generateSha512Crypt(password string) string {
	const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	saltBytes := make([]byte, 16)
	_, _ = rand.Read(saltBytes)
	salt := ""
	for _, b := range saltBytes {
		salt += string(itoa64[int(b)%len(itoa64)])
	}

	hash := sha512.New()
	hash.Write([]byte(password + "$6$" + salt))
	digest := hash.Sum(nil)
	b64Digest := base64.RawStdEncoding.EncodeToString(digest)
	return fmt.Sprintf("$6$%s$%s", salt, b64Digest)
}

func validateComplexPassword(pass string) bool {
	if len(pass) < 12 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range pass {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}

var hostSigCache = map[*ssh.Client]HostSignature{}

func fetchHostSignature(client *ssh.Client) HostSignature {
	if s, ok := hostSigCache[client]; ok {
		return s
	}
	s := fetchHostSignatureUncached(client)
	if s.OS != "unknown" {
		hostSigCache[client] = s
	}
	return s
}

func fetchHostSignatureUncached(client *ssh.Client) HostSignature {
	checkCmd := `
if [ -f /etc/os-release ]; then
    DISTRO=$(grep -oP '(?<=^PRETTY_NAME=").+(?=")' /etc/os-release 2>/dev/null)
    [ -z "$DISTRO" ] && DISTRO=$(uname -s)
    KERNEL=$(uname -r)
    HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)
    PRIMARY_IP=$(ip -o -4 addr show 2>/dev/null | awk '!/ lo /{print $4; exit}' | cut -d/ -f1)
    [ -z "$PRIMARY_IP" ] && PRIMARY_IP="unknown"
    echo "linux|${DISTRO}|${KERNEL}|${HOST}|${PRIMARY_IP}"
elif [ "$(uname -s)" = "Darwin" ]; then
    DISTRO="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
    KERNEL=$(uname -r)
    HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
    PRIMARY_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "unknown")
    echo "darwin|${DISTRO}|${KERNEL}|${HOST}|${PRIMARY_IP}"
else
    echo "probe_windows"
fi
`
	out, err := execRemote(client, checkCmd)
	if err != nil || strings.Contains(out, "probe_windows") || strings.TrimSpace(out) == "" ||
		!(strings.HasPrefix(strings.TrimSpace(out), "linux|") || strings.HasPrefix(strings.TrimSpace(out), "darwin|")) {
		winCmd := `powershell -Command "$os = (Get-CimInstance Win32_OperatingSystem).Caption; $ver = [System.Environment]::OSVersion.Version.ToString(); $h = $env:COMPUTERNAME; $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch 'Loopback'} | Select-Object -First 1 -ExpandProperty IPAddress); Write-Output ('windows|' + $os + '|' + $ver + '|' + $h + '|' + $ip)"`
		winOut, winErr := execRemote(client, winCmd)
		if winErr == nil && strings.Contains(winOut, "windows|") {
			parts := strings.Split(strings.TrimSpace(winOut), "|")
			return HostSignature{OS: "windows", Distro: parts[1], Kernel: parts[2], Hostname: parts[3], PrimaryIP: parts[4]}
		}
		return HostSignature{OS: "unknown", Distro: "Unknown OS", Kernel: "unknown", Hostname: "unknown", PrimaryIP: "unknown"}
	}

	parts := strings.SplitN(strings.TrimSpace(out), "|", 5)
	if len(parts) >= 5 {
		return HostSignature{OS: parts[0], Distro: parts[1], Kernel: parts[2], Hostname: parts[3], PrimaryIP: parts[4]}
	}
	return HostSignature{OS: "linux", Distro: "Linux Generic", Kernel: "unknown", Hostname: "unknown", PrimaryIP: "unknown"}
}

func renderHostBanner(sig HostSignature) {
	fmt.Println(common.Cyan + common.Bold + "┌─ LIVE HOST SIGNATURE " + strings.Repeat("─", 56) + common.Reset)
	fmt.Printf(common.Cyan+"│ "+common.Reset+"OS: "+common.Bold+"%-30s"+common.Reset+"  Kernel: "+common.Bold+"%s\n"+common.Reset, sig.Distro, sig.Kernel)
	fmt.Printf(common.Cyan+"│ "+common.Reset+"Host: "+common.Bold+"%-28s"+common.Reset+"  IP: "+common.Bold+"%s\n"+common.Reset, sig.Hostname, sig.PrimaryIP)
	fmt.Println(common.Cyan + common.Bold + "└" + strings.Repeat("─", 78) + common.Reset)
}

func fetchSystemUsers(client *ssh.Client) []UserSummary {
	sig := fetchHostSignature(client)
	if sig.OS == "windows" {
		return winFetchUsers(client, sig)
	}
	var users []UserSummary
	idx := 1

	if sig.OS == "windows" {
		psCmd := `powershell -Command "$admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Split('\')[-1] }); Get-LocalUser | ForEach-Object { $t = if($admins -contains $_.Name){'Super-Admin'}else{'Standard User'}; $s = if($_.Enabled){'ACTIVE'}else{'LOCKED'}; $_.Name + '|' + $_.SID.Value + '|' + $s + '|' + $t }"`
		out, _ := execRemote(client, psCmd)
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			parts := strings.Split(strings.TrimSpace(l), "|")
			if len(parts) >= 4 {
				users = append(users, UserSummary{
					Index:       idx,
					Username:    parts[0],
					UID:         parts[1],
					AssignedIP:  sig.PrimaryIP,
					GeoLocation: "Local Windows",
					Shell:       "powershell.exe",
					Status:      parts[2],
					RBACTier:    parts[3],
					IsTool:      false,
					HostAlias:   currentHostAlias,
				})
				idx++
			}
		}
		return users
	}

	if sig.OS == "darwin" {
		dsclCmd := `dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1 "|" $2 "|Unassigned|Dhaka, BD|/bin/zsh|ACTIVE|Standard User|SYSTEM"}'`
		out, _ := execRemote(client, wrapSudo(dsclCmd))
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			parts := strings.Split(strings.TrimSpace(l), "|")
			if len(parts) >= 8 {
				users = append(users, UserSummary{
					Index:       idx,
					Username:    parts[0],
					UID:         parts[1],
					AssignedIP:  sig.PrimaryIP,
					GeoLocation: "Dhaka, BD",
					Shell:       parts[4],
					Status:      parts[5],
					RBACTier:    parts[6],
					IsTool:      false,
					HostAlias:   currentHostAlias,
				})
				idx++
			}
		}
		return users
	}

	scriptPython := fmt.Sprintf(`
import pwd, spwd, os, glob, subprocess, re, json, urllib.request

host_lan_ip = '127.0.0.1'
secondary_ips = []
try:
    for line in subprocess.getoutput('ip -o -4 addr show').splitlines():
        parts = line.split()
        if len(parts) >= 4 and not parts[1].startswith('lo'):
            ip_val = parts[3].split('/')[0]
            if host_lan_ip == '127.0.0.1':
                host_lan_ip = ip_val
            secondary_ips.append(ip_val)
except Exception:
    pass

public_geo = 'Dhaka, BD'
try:
    req = urllib.request.Request('http://ip-api.com/json/?fields=city,countryCode', headers={'User-Agent': 'CrossSuite/1.0'})
    with urllib.request.urlopen(req, timeout=1.5) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        c = data.get('city', '')
        cc = data.get('countryCode', '')
        if c or cc:
            public_geo = f'{c}, {cc}'.strip(', ')
except Exception:
    pass

user_ips = {}
for reg_path in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
    if os.path.exists(reg_path):
        try:
            with open(reg_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                            user_ips[parts[0].strip()] = parts[1].strip()
        except Exception:
            pass

tier_registry = {}
if os.path.exists('%s'):
    try:
        with open('%s', 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    un, t = line.split(':', 1)
                    if un.strip():
                        tier_registry[un.strip()] = t.strip()
    except Exception:
        pass

session_ips = {}
try:
    for l in subprocess.getoutput('who -u').splitlines():
        parts = l.split()
        if len(parts) >= 5:
            cand = parts[-1].strip('()')
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cand):
                session_ips[parts[0]] = cand
except Exception:
    pass

active_users = set()
try:
    for l in subprocess.getoutput('who').splitlines():
        parts = l.split()
        if parts:
            active_users.add(parts[0])
except Exception:
    pass

sudo_members = set()
for grp_name in ['sudo', 'wheel', 'admin', 'root']:
    try:
        grp_out = subprocess.getoutput(f'getent group {grp_name} 2>/dev/null')
        if ':' in grp_out:
            members = grp_out.split(':')[-1].split(',')
            for m in members:
                if m.strip():
                    sudo_members.add(m.strip())
    except Exception:
        pass

sudoers_raw = []
for sf in ['/etc/sudoers'] + glob.glob('/etc/sudoers.d/*'):
    if os.path.exists(sf):
        try:
            with open(sf, 'r', errors='ignore') as f:
                sudoers_raw.extend(f.readlines())
        except Exception:
            pass

geo_cache = {}
def resolve_geo(ip):
    clean_ip = ip.split('/')[0].strip()
    if not clean_ip or clean_ip.startswith('Unassigned'):
        return public_geo
    if clean_ip in geo_cache:
        return geo_cache[clean_ip]
    if clean_ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
        geo_cache[clean_ip] = public_geo
        return public_geo
    try:
        req = urllib.request.Request(f'http://ip-api.com/json/{clean_ip}?fields=city,countryCode', headers={'User-Agent': 'CrossSuite/1.0'})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            city = data.get('city', '')
            cc = data.get('countryCode', '')
            res = f'{city}, {cc}'.strip(', ')
            if not res:
                res = public_geo
            geo_cache[clean_ip] = res
            return res
    except Exception:
        geo_cache[clean_ip] = public_geo
        return public_geo

tool_created = set()
if os.path.exists('/etc/cross_rbac_users.txt'):
    try:
        with open('/etc/cross_rbac_users.txt', 'r', errors='ignore') as f:
            tool_created = {line.strip() for line in f if line.strip()}
    except Exception:
        pass

for p in pwd.getpwall():
    if p.pw_uid < 1000 and p.pw_uid != 0:
        continue

    status = 'INACTIVE'
    try:
        sp = spwd.getspnam(p.pw_name)
        if sp and sp.sp_pwdp and sp.sp_pwdp.startswith('!'):
            status = 'LOCKED'
        elif p.pw_name in active_users:
            status = 'ACTIVE'
    except Exception:
        if p.pw_name in active_users:
            status = 'ACTIVE'

    u_name = p.pw_name
    short_shell = p.pw_shell.split('/')[-1]
    if not short_shell:
        short_shell = p.pw_shell

    if p.pw_uid == 0:
        rbac = 'Super-Admin'
    elif u_name in tier_registry:
        rbac = tier_registry[u_name]
    elif u_name in sudo_members:
        rbac = 'Super-Admin'
    else:
        rbac = 'Standard User'
        for line in sudoers_raw:
            line_s = line.strip()
            if line_s.startswith('#') or not line_s:
                continue
            if re.search(r'\b' + re.escape(u_name) + r'\b', line_s):
                if 'ALL=(ALL:ALL) ALL' in line_s or 'ALL=(ALL) ALL' in line_s or 'ALL=(ALL) NOPASSWD: ALL' in line_s:
                    rbac = 'Super-Admin'
                    break
                elif 'docker' in line_s or 'kubectl' in line_s or 'systemctl' in line_s:
                    rbac = 'DevOps Eng'
                    break
                elif 'nmap' in line_s or 'journalctl' in line_s or 'trivy' in line_s or 'ps' in line_s:
                    rbac = 'Sec Auditor'
                    break
                elif 'mysql' in line_s or 'psql' in line_s or 'redis' in line_s:
                    rbac = 'DB Admin'
                    break
                else:
                    rbac = 'Custom RBAC'
                    break

    assigned_ip = user_ips.get(u_name, '')
    if not assigned_ip:
        assigned_ip = session_ips.get(u_name, '')
    if not assigned_ip:
        if p.pw_uid == 0 or u_name == 'kali':
            assigned_ip = host_lan_ip
        else:
            assigned_ip = 'Unassigned'

    geo = resolve_geo(assigned_ip)
    is_tool = 'TOOL' if u_name in tool_created else 'SYSTEM'
    print(f'{u_name}|{p.pw_uid}|{assigned_ip}|{geo}|{short_shell}|{status}|{rbac}|{is_tool}')
`, rbacTierRegistry, rbacTierRegistry)

	b64Py := base64.StdEncoding.EncodeToString([]byte(scriptPython))
	execCmd := fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode('utf-8'))\"", b64Py)

	out, err := execRemote(client, wrapSudo(execCmd))

	if err != nil || strings.TrimSpace(out) == "" {
		hostIPCmd := "ip -o -4 addr show | awk '!/lo/ {print $4; exit}' | cut -d/ -f1"
		hip, _ := execRemote(client, hostIPCmd)
		hip = strings.TrimSpace(hip)
		if hip == "" {
			hip = "192.168.0.150"
		}
		fallbackCmd := fmt.Sprintf(`
awk -F: -v hip="%s" '
BEGIN {
    while ((getline l < "/etc/cross_assigned_ips.txt") > 0) {
        split(l, a, ":")
        if (a[1] != "") ips[a[1]] = a[2]
    }
    while ((getline l < "%s") > 0) {
        split(l, t, ":")
        if (t[1] != "") tiers[t[1]] = t[2]
    }
    while (("who" | getline wl) > 0) {
        split(wl, w, " ")
        if (w[1] != "") active[w[1]] = 1
    }
    close("who")
}
($3 >= 1000 || $3 == 0) {
    n = split($7, sh, "/")
    shell = sh[n]
    u_ip = ($1 in ips) ? ips[$1] : (($3 == 0 || $1 == "kali") ? hip : "Unassigned")
    if ($3 == 0) {
        tier = "Super-Admin"
    } else if ($1 in tiers) {
        tier = tiers[$1]
    } else {
        tier = "Standard User"
    }
    st = ($1 in active) ? "ACTIVE" : "INACTIVE"
    print $1 "|" $3 "|" u_ip "|Dhaka, BD|" shell "|" st "|" tier "|SYSTEM"
}' /etc/passwd
`, hip, rbacTierRegistry)
		out, _ = execRemote(client, wrapSudo(fallbackCmd))
	}

	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(l, "|")
		if len(parts) >= 8 {
			users = append(users, UserSummary{
				Index:       idx,
				Username:    parts[0],
				UID:         parts[1],
				AssignedIP:  parts[2],
				GeoLocation: parts[3],
				Shell:       parts[4],
				Status:      parts[5],
				RBACTier:    parts[6],
				IsTool:      parts[7] == "TOOL",
				HostAlias:   currentHostAlias,
			})
			idx++
		}
	}
	return users
}

func pad(s string, length int) string {
	if len(s) > length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

func renderUserTable(users []UserSummary) {
	if len(users) == 0 {
		fmt.Println(common.Yellow + "[!] No users to display." + common.Reset)
		return
	}

	fmt.Println(common.Cyan + "┌─────┬──────────────────┬───────┬──────────────────┬────────────────┬─────────┬──────────┬────────────────┬─────────────┬────────────────┐" + common.Reset)
	fmt.Println(common.Cyan + "│ NO  │ USERNAME         │ UID   │ IP ADDRESS       │ GEO-LOCATION   │ SHELL   │ STATUS   │ CURRENT RBAC   │ ORIGIN      │ TARGET HOST    │" + common.Reset)
	fmt.Println(common.Cyan + "├─────┼──────────────────┼───────┼──────────────────┼────────────────┼─────────┼──────────┼────────────────┼─────────────┼────────────────┤" + common.Reset)

	for _, u := range users {
		cNo := pad(fmt.Sprintf("%d", u.Index), 3)
		cUser := pad(u.Username, 16)
		cUID := pad(u.UID, 5)
		cIPRaw := pad(u.AssignedIP, 16)
		cGeoRaw := pad(u.GeoLocation, 14)
		cShell := pad(u.Shell, 7)
		cStatusRaw := pad(u.Status, 8)
		cRBACRaw := pad(u.RBACTier, 14)

		var cOrigin string
		if u.IsTool {
			cOrigin = common.Green + common.Bold + "[RBAC-TOOL]" + common.Reset
		} else {
			cOrigin = common.Blue + "[SYSTEM]   " + common.Reset
		}

		var cIP string
		if u.AssignedIP == "Unassigned" {
			cIP = common.Reset + cIPRaw
		} else {
			cIP = common.Cyan + common.Bold + cIPRaw + common.Reset
		}

		cGeo := common.Yellow + cGeoRaw + common.Reset

		var cStatus string
		switch u.Status {
		case "LOCKED":
			cStatus = common.Red + common.Bold + cStatusRaw + common.Reset
		case "ACTIVE":
			cStatus = common.Green + common.Bold + cStatusRaw + common.Reset
		case "OFFLINE", "POWERED-OFF":
			cStatus = common.Red + cStatusRaw + common.Reset
		default:
			cStatus = common.Yellow + cStatusRaw + common.Reset
		}

		var cRBAC string
		if u.RBACTier == "Super-Admin" {
			cRBAC = common.Red + common.Bold + cRBACRaw + common.Reset
		} else if u.RBACTier == "DevOps Eng" || u.RBACTier == "DB Admin" || u.RBACTier == "Sec Auditor" || u.RBACTier == "Custom RBAC" || u.RBACTier == "Custom Whitelist" {
			cRBAC = common.Cyan + common.Bold + cRBACRaw + common.Reset
		} else {
			cRBAC = common.Yellow + cRBACRaw + common.Reset
		}

		cHost := common.Blue + pad(u.HostAlias, 14) + common.Reset

		fmt.Printf("│ %s │ %s │ %s │ %s │ %s │ %s │ %s │ %s │ %s │ %s │\n",
			cNo, cUser, cUID, cIP, cGeo, cShell, cStatus, cRBAC, cOrigin, cHost)
	}
	fmt.Println(common.Cyan + "└─────┴──────────────────┴───────┴──────────────────┴────────────────┴─────────┴──────────┴────────────────┴─────────────┴────────────────┘" + common.Reset)
}

func selectUserInteractive(reader *bufio.Reader, client *ssh.Client, promptTitle string) string {
	users := fetchSystemUsers(client)
	if len(users) == 0 {
		fmt.Println(common.Yellow + "[!] No users found on system." + common.Reset)
		fmt.Print("Enter username manually: ")
		manual, _ := reader.ReadString('\n')
		return strings.TrimSpace(manual)
	}

	labels := make([]string, len(users))
	for i, u := range users {
		labels[i] = fmt.Sprintf("%-14s UID:%-6s %-10s %s", u.Username, u.UID, u.Status, u.RBACTier)
	}

	for reader.Buffered() > 0 {
		reader.ReadByte()
	}

	idx := InteractiveSelect(promptTitle, labels)
	if idx == -1 {
		return ""
	}
	return users[idx].Username
}

func fetchActiveNetworkInterfaces(client *ssh.Client) []NetworkInterface {
	sig := fetchHostSignature(client)
	var ifaces []NetworkInterface

	if sig.OS == "windows" {
		cmd := `powershell -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch 'Loopback'} | ForEach-Object { $_.InterfaceAlias + ':' + $_.IPAddress + '/' + $_.PrefixLength }"`
		out, _ := execRemote(client, cmd)
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			l = strings.TrimSpace(l)
			if strings.Contains(l, ":") {
				parts := strings.Split(l, ":")
				ifaces = append(ifaces, NetworkInterface{Name: parts[0], IP: parts[1]})
			}
		}
		return ifaces
	}

	if sig.OS == "darwin" {
		cmd := "ifconfig -l"
		out, _ := execRemote(client, cmd)
		for _, ifName := range strings.Fields(strings.TrimSpace(out)) {
			if ifName != "lo0" {
				ipCmd := fmt.Sprintf("ipconfig getifaddr %s 2>/dev/null", ifName)
				ipOut, _ := execRemote(client, ipCmd)
				ipOut = strings.TrimSpace(ipOut)
				if ipOut != "" {
					ifaces = append(ifaces, NetworkInterface{Name: ifName, IP: ipOut + "/24"})
				}
			}
		}
		return ifaces
	}

	cmd := "ip -o -4 addr show | awk '{print $2 \":\" $4}'"
	out, _ := execRemote(client, cmd)

	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(l, ":")
		if len(parts) >= 2 && !strings.HasPrefix(parts[0], "lo") {
			ifaces = append(ifaces, NetworkInterface{
				Name: parts[0],
				IP:   parts[1],
			})
		}
	}
	return ifaces
}

func ShowRBACMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	if !ensureElevation(client) {
		fmt.Println(common.Red + "[!] Authentication failed. Access to Access Control Assigner denied." + common.Reset)
		common.PausePrompt()
		return
	}

	currentHostAlias = host
	if fetchHostSignature(client).OS == "windows" {
		checkWindowsElevation(client)
	}

	for {
		fmt.Print("\033[H\033[2J")
		sig := fetchHostSignature(client)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "=== HUB 7: SOVEREIGN IDENTITY, ZERO-TRUST ACCESS & RBAC ENFORCER ===" + common.Reset)
		fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
		fmt.Printf(common.Yellow+"🖥  Target: %s   OS: %s   Kernel: %s   Host: %s\n"+common.Reset, host, sig.Distro, sig.Kernel, sig.Hostname)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)
		fmt.Println("  [1] Identity Provisioning (Create User + Password + Dedicated IP + Key Options)")
		fmt.Println("  [2] RBAC Privilege Tiering (Root / DevOps / Auditor / Database / Custom)")
		fmt.Println("  [3] Multiple IP Stacking & Virtual Pingable IP Assigner (Standard Stacking)")
		fmt.Println("  [4] Identity DNS Profile Assigner & Upstream Revert/Purge Engine")
		fmt.Println("  [5] User Network & Internet Confinement (Granular LAN/WAN/Blackhole & Unblock)")
		fmt.Println("  [6] Master Host Network & Adapter Orchestrator (Change Own IP, Gateway, Hostname)")
		fmt.Println("  [7] Active Session Monitor & Remote Terminal Killswitch (Single or ALL Non-Root)")
		fmt.Println("  [8] Active Identity & Permission Matrix Auditor (Inspect Users, GeoIP & Tiers)")
		fmt.Println(common.Red + "  [9] Emergency Quarantine, Single Purge & ULTIMATE MASS NUCLEAR PURGE (With Dry-Run)" + common.Reset)
		fmt.Println("  [10] User Port Access Provider (Security-Group Style Ingress/Egress Port ACL)")
		fmt.Println(common.Green + common.Bold + "  [11] Master Node — Switch Target to Another LAN Machine (Slave Host)" + common.Reset)
		fmt.Println(common.Red + "  [0] Back to Main Menu" + common.Reset)
		fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

		fmt.Print(common.Bold + "Select Access Control option [0-11]: " + common.Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			provisionNewIdentity(reader, client)
		case "2":
			manageUserRBACTiers(reader, client)
		case "3":
			assignIPAndVirtualInterface(reader, client)
		case "4":
			assignDNSResolverProfile(reader, client)
		case "5":
			manageNetworkAndInternetConfinement(reader, client)
		case "6":
			orchestrateHostNetwork(reader, client)
		case "7":
			monitorAndKillSessions(reader, client)
		case "8":
			auditIdentityMatrix(client)
		case "9":
			emergencyQuarantine(reader, client)
		case "10":
			managePortAccessControl(reader, client)
		case "11":
			manageMasterNode(reader, client, host)
		default:
			fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
			time.Sleep(1 * time.Second)
		}
	}
}

// -----------------------------------------------------------------------------
// [1] Identity Provisioning
// -----------------------------------------------------------------------------
func provisionNewIdentity(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== PROVISION NEW SECURE IDENTITY ===" + common.Reset)

	fmt.Print("Enter New Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" || strings.ContainsAny(username, ";&|`$ \t\n\r") {
		fmt.Println(common.Red + "[!] Invalid username." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Println("\nChoose Password Type for Provisioning:")
	fmt.Println("  [1] Simple / Easy Password (Any length, any character, e.g. 0000, 123, user) [Default]")
	fmt.Println("  [2] Complex Password (NIST Standard: >=12 chars, Upper, Lower, Numbers, Symbols)")
	fmt.Print("Select Password Policy [1-2] [default: 1]: ")
	passTypeChoice, _ := reader.ReadString('\n')
	passTypeChoice = strings.TrimSpace(passTypeChoice)
	if passTypeChoice == "" {
		passTypeChoice = "1"
	}

	var password string
	for {
		if passTypeChoice == "2" {
			fmt.Print("Enter Complex Password (>=12 chars, Upper, Lower, Number, Symbol): ")
		} else {
			fmt.Print("Enter Simple Password (e.g. 0000, pass, 1234): ")
		}
		passBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		password = string(passBytes)
		if strings.TrimSpace(password) == "" {
			fmt.Println(common.Red + "[!] Password cannot be empty." + common.Reset)
			continue
		}

		if passTypeChoice == "2" {
			if !validateComplexPassword(password) {
				fmt.Println(common.Red + "[!] Password does not meet international standard (Must be >=12 chars with upper, lower, numbers, and symbols)." + common.Reset)
				continue
			}
		}
		break
	}

	fmt.Print("\nEnforce password change when user logs in via SSH/Local Terminal? (y/n) [default: n]: ")
	forceExpire, _ := reader.ReadString('\n')
	forceExpire = strings.TrimSpace(strings.ToLower(forceExpire))
	if forceExpire == "" {
		forceExpire = "n"
	}

	fmt.Print("Enter Password Maximum Lifetime in Days (e.g. 90, or 0 for unlimited) [default: 0]: ")
	maxDaysStr, _ := reader.ReadString('\n')
	maxDaysStr = strings.TrimSpace(maxDaysStr)
	maxDays := 0
	if maxDaysStr != "" {
		if val, err := strconv.Atoi(maxDaysStr); err == nil && val >= 0 {
			maxDays = val
		}
	}

	ifaces := fetchActiveNetworkInterfaces(client)
	var dedicatedIP string
	var boundIface string

	fmt.Print("\nAssign dedicated secondary IP address for this user now? (y/n) [default: n]: ")
	assignIPChoice, _ := reader.ReadString('\n')
	assignIPChoice = strings.TrimSpace(strings.ToLower(assignIPChoice))

	if assignIPChoice == "y" && len(ifaces) > 0 {
		fmt.Println("Available Network Interfaces:")
		for i, iface := range ifaces {
			fmt.Printf("  [%d] %-12s (Current IP: %s)\n", i+1, iface.Name, iface.IP)
		}
		fmt.Printf("Select Interface [1-%d] [default: 1]: ", len(ifaces))
		ifChoice, _ := reader.ReadString('\n')
		ifIdx, _ := strconv.Atoi(strings.TrimSpace(ifChoice))
		if ifIdx < 1 || ifIdx > len(ifaces) {
			ifIdx = 1
		}
		boundIface = ifaces[ifIdx-1].Name

		fmt.Print("Enter Dedicated IP with CIDR (e.g. 192.168.0.210/24): ")
		ipInput, _ := reader.ReadString('\n')
		dedicatedIP = strings.TrimSpace(ipInput)
		if dedicatedIP != "" && !strings.Contains(dedicatedIP, "/") {
			dedicatedIP += "/24"
		}
	}

	fmt.Println("\nSSH Key Authentication Provisioning:")
	fmt.Println("  [1] ⚡ Auto-Authorize My Current Workstation's SSH Public Key (Instant Connection) - [Recommended]")
	fmt.Println("  [2] 🔑 Auto-Generate a Brand New Dedicated ED25519 Keypair on the Remote Machine")
	fmt.Println("  [3] 📋 Manually Paste an Existing Public Key String")
	fmt.Println("  [4] ⏩ Skip SSH Key Provisioning (Password Only)")
	fmt.Print("Select Key Option [1-4] [default: 1]: ")

	keyChoice, _ := reader.ReadString('\n')
	keyChoice = strings.TrimSpace(keyChoice)
	if keyChoice == "" {
		keyChoice = "1"
	}

	var sshPubKey string
	var autoGenerateDedicatedKey bool

	switch keyChoice {
	case "1":
		home, _ := os.UserHomeDir()
		pubKeyPaths := []string{
			filepath.Join(home, ".ssh", "id_ed25519.pub"),
			filepath.Join(home, ".ssh", "id_rsa.pub"),
			filepath.Join(home, ".ssh", "id_ecdsa.pub"),
		}
		for _, p := range pubKeyPaths {
			if data, err := os.ReadFile(p); err == nil {
				sshPubKey = strings.TrimSpace(string(data))
				fmt.Println(common.Green + "[✔] Found local public key: " + p + common.Reset)
				break
			}
		}
		if sshPubKey == "" {
			fmt.Println(common.Yellow + "[!] No local public key found on workstation. Falling back to dedicated keypair generation..." + common.Reset)
			autoGenerateDedicatedKey = true
		}

	case "2":
		autoGenerateDedicatedKey = true

	case "3":
		fmt.Print("Paste Public SSH Key (e.g. ssh-ed25519 ...): ")
		manualKey, _ := reader.ReadString('\n')
		sshPubKey = strings.TrimSpace(manualKey)

	case "4":
		sshPubKey = ""
	}

	sig := fetchHostSignature(client)
	fmt.Println(common.Cyan + "[+] Provisioning identity on remote host (" + sig.OS + ")..." + common.Reset)

	if sig.OS == "windows" {
		psPass := strings.ReplaceAll(password, "'", "''")
		neverExp := "$true"
		if maxDays > 0 {
			neverExp = "$false"
		}
		winScript := fmt.Sprintf("$sec = ConvertTo-SecureString '%s' -AsPlainText -Force; New-LocalUser -Name '%s' -Password $sec -PasswordNeverExpires:%s -ErrorAction Stop | Out-Null; Add-LocalGroupMember -Group 'Users' -Member '%s' -ErrorAction SilentlyContinue", psPass, username, neverExp, username)
		if forceExpire == "y" {
			winScript += fmt.Sprintf("; net user '%s' /logonpasswordchg:yes | Out-Null", username)
		}
		if sshPubKey != "" {
			psKey := strings.ReplaceAll(sshPubKey, "'", "''")
			winScript += fmt.Sprintf("; $d = 'C:\\Users\\%s\\.ssh'; New-Item -ItemType Directory -Force -Path $d | Out-Null; Add-Content -Path ($d + '\\authorized_keys') -Value '%s'; icacls $d /inheritance:r /grant '%s:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null", username, psKey, username)
		}
		winScript += winProvisionExtras(username, dedicatedIP, boundIface)
		winCmd := `powershell -Command "` + winScript + `"`
		_, err := execRemote(client, winCmd)
		if err != nil {
			fmt.Printf(common.Red+"[!] Windows provisioning error: %v\n"+common.Reset, err)
		} else {
			fmt.Println(common.Green + "✅ Identity successfully created for Windows user [" + username + "]!" + common.Reset)
		}
		common.PausePrompt()
		return
	}

	if sig.OS == "darwin" {
		macCmd := fmt.Sprintf(`sysadminctl -addUser "%s" -password "%s" -home "/Users/%s"`, username, password, username)
		_, err := execRemote(client, wrapSudo(macCmd))
		if err != nil {
			fmt.Printf(common.Red+"[!] macOS provisioning error: %v\n"+common.Reset, err)
		} else {
			fmt.Println(common.Green + "✅ Identity successfully created for macOS user [" + username + "]!" + common.Reset)
		}
		common.PausePrompt()
		return
	}

	payload := ProvisionPayload{
		Username:                 username,
		Password:                 password,
		PasswordHash:             generateSha512Crypt(password),
		ForceExpire:              forceExpire == "y",
		MaxDays:                  maxDays,
		AssignedIP:               dedicatedIP,
		BoundInterface:           boundIface,
		SSHPublicKey:             sshPubKey,
		AutoGenerateDedicatedKey: autoGenerateDedicatedKey,
	}

	payloadJSON, _ := json.Marshal(payload)
	b64Payload := base64.StdEncoding.EncodeToString(payloadJSON)

	pythonScript := fmt.Sprintf(`
import base64, json, os, subprocess, pwd

data = json.loads(base64.b64decode('%s').decode('utf-8'))
u = data['username']
pwd_hash = data['password_hash']
force_expire = data['force_expire']
max_days = data['max_days']
assigned_ip = data.get('assigned_ip', '')
bound_iface = data.get('bound_interface', '')
pub_key = data['ssh_public_key']
auto_gen = data['auto_generate_dedicated_key']

try:
    pwd.getpwnam(u)
except KeyError:
    subprocess.run(['useradd', '-m', '-s', '/bin/bash', u], check=True)

try:
    subprocess.run(['usermod', '-p', pwd_hash, u], check=True)
except Exception:
    p = subprocess.Popen(['chpasswd', '-e'], stdin=subprocess.PIPE, text=True)
    p.communicate(input=f'{u}:{pwd_hash}\n')

if max_days > 0:
    subprocess.run(['chage', '-M', str(max_days), '-W', '7', u], check=False)

with open('/etc/cross_rbac_users.txt', 'a+') as f:
    f.seek(0)
    lines = [line.strip() for line in f]
    if u not in lines:
        f.write(f'{u}\n')

if assigned_ip and bound_iface:
    subprocess.run(['ip', 'addr', 'add', assigned_ip, 'dev', bound_iface], check=False)
    for reg_f in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
        reg_lines = []
        if os.path.exists(reg_f):
            with open(reg_f, 'r') as f:
                reg_lines = [l for l in f if not l.startswith(f'{u}:')]
        reg_lines.append(f'{u}:{assigned_ip}\n')
        with open(reg_f, 'w') as f:
            f.writelines(reg_lines)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(reg_f, 0o644)

ssh_dir = f'/home/{u}/.ssh'
auth_keys = f'{ssh_dir}/authorized_keys'
os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
if not os.path.exists(auth_keys):
    with open(auth_keys, 'w') as f:
        pass
os.chmod(auth_keys, 0o600)

u_info = pwd.getpwnam(u)
os.chown(ssh_dir, u_info.pw_uid, u_info.pw_gid)
os.chown(auth_keys, u_info.pw_uid, u_info.pw_gid)

if auto_gen:
    key_path = f'{ssh_dir}/id_ed25519'
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(f'{key_path}.pub'):
        os.remove(f'{key_path}.pub')
    subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', key_path, '-C', f'{u}-key'], check=True)
    with open(f'{key_path}.pub', 'r') as pub_f:
        pub_content = pub_f.read()
    with open(auth_keys, 'a') as ak_f:
        ak_f.write(f'\n{pub_content.strip()}\n')
    os.chmod(key_path, 0o600)
    os.chmod(f'{key_path}.pub', 0o644)
    os.chown(key_path, u_info.pw_uid, u_info.pw_gid)
    os.chown(f'{key_path}.pub', u_info.pw_uid, u_info.pw_gid)
    print('KEYPAIR_GEN_SUCCESS')
elif pub_key:
    with open(auth_keys, 'a') as ak_f:
        ak_f.write(f'\n{pub_key.strip()}\n')
    os.chmod(auth_keys, 0o600)
    os.chown(auth_keys, u_info.pw_uid, u_info.pw_gid)

if force_expire:
    sudo_temp = f'/etc/sudoers.d/cross_init_{u}'
    with open(sudo_temp, 'w') as sf:
        sf.write(f'{u} ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd, /usr/sbin/usermod, /usr/bin/rm\n')
    os.chmod(sudo_temp, 0o440)

    wizard_code = '''#!/bin/bash
if [ -f "$HOME/.cross_first_login_done" ]; then
    return 0 2>/dev/null || exit 0
fi

echo ""
echo "=================================================================="
echo "    INITIAL SECURITY SETUP: PLEASE UPDATE YOUR PASSWORD"
echo "=================================================================="
echo "Choose your preferred password policy:"
echo "  [1] Simple Password (Any length/digits, e.g. 0000, 1234)"
echo "  [2] Complex Password (NIST Standard: 12+ chars, mixed cases & symbols)"
echo "=================================================================="

while true; do
    read -p "Select policy [1-2] [default: 1]: " p_choice
    p_choice=${p_choice:-1}
    
    if [ "$p_choice" = "1" ]; then
        read -s -p "Enter new simple password: " p1
        echo ""
        read -s -p "Confirm new simple password: " p2
        echo ""
        if [ "$p1" != "$p2" ]; then
            echo "[!] Passwords do not match. Try again."
            continue
        fi
        echo "$USER:$p1" | sudo /usr/sbin/chpasswd 2>/dev/null || echo "$USER:$p1" | sudo /usr/sbin/chpasswd -e
        echo "[✔] Password updated successfully!"
        break
    elif [ "$p_choice" = "2" ]; then
        read -s -p "Enter new complex password (12+ chars, upper, lower, digit, symbol): " p1
        echo ""
        read -s -p "Confirm new complex password: " p2
        echo ""
        if [ "$p1" != "$p2" ]; then
            echo "[!] Passwords do not match. Try again."
            continue
        fi
        echo "$USER:$p1" | sudo /usr/sbin/chpasswd
        echo "[✔] Complex password updated successfully!"
        break
    fi
done

sudo /usr/bin/rm -f /etc/sudoers.d/cross_init_$USER 2>/dev/null || true
touch "$HOME/.cross_first_login_done"
sed -i '/cross_login_setup.sh/d' "$HOME/.bashrc" "$HOME/.zshrc" 2>/dev/null || true
rm -f "$HOME/.cross_login_setup.sh"
echo "Setup complete. Welcome!"
echo "------------------------------------------------------------------"
'''
    wizard_path = f'/home/{u}/.cross_login_setup.sh'
    with open(wizard_path, 'w') as wf:
        wf.write(wizard_code)
    os.chmod(wizard_path, 0o755)
    os.chown(wizard_path, u_info.pw_uid, u_info.pw_gid)
    
    for rc in [f'/home/{u}/.bashrc', f'/home/{u}/.zshrc']:
        if os.path.exists(rc):
            with open(rc, 'a') as rcf:
                rcf.write(f'\nbash ~/.cross_login_setup.sh\n')

print('PROVISION_SUCCESS')
`, b64Payload)

	b64Python := base64.StdEncoding.EncodeToString([]byte(pythonScript))
	remoteCmd := fmt.Sprintf("python3 -c \"import base64; exec(base64.b64decode('%s').decode('utf-8'))\"", b64Python)

	out, err := execRemote(client, wrapSudo(remoteCmd))
	if err != nil || !strings.Contains(out, "PROVISION_SUCCESS") {
		fmt.Printf(common.Red+"[!] Provisioning error: %v\nOutput: %s\n"+common.Reset, err, out)
	} else {
		fmt.Println(common.Green + "✅ Identity successfully created for user [" + username + "]!" + common.Reset)

		if dedicatedIP != "" {
			fmt.Printf(common.Cyan+"[✔] Dedicated IP [%s] assigned to user [%s] on adapter [%s]\n"+common.Reset, dedicatedIP, username, boundIface)
		}

		if autoGenerateDedicatedKey {
			fetchPrivCmd := fmt.Sprintf("cat /home/%s/.ssh/id_ed25519", username)
			privKeyData, privErr := execRemote(client, wrapSudo(fetchPrivCmd))
			if privErr == nil && strings.Contains(privKeyData, "PRIVATE KEY") {
				home, _ := os.UserHomeDir()
				localKeyFile := filepath.Join(home, ".ssh", fmt.Sprintf("%s_id_ed25519", username))
				_ = os.WriteFile(localKeyFile, []byte(strings.TrimSpace(privKeyData)+"\n"), 0600)
				fmt.Printf(common.Green+common.Bold+"[✔] Dedicated Private Key saved locally to: %s\n"+common.Reset, localKeyFile)
				fmt.Printf(common.Yellow+"=> You can connect immediately using: ssh -i %s %s@<target-ip>\n"+common.Reset, localKeyFile, username)
			}
		} else if sshPubKey != "" {
			fmt.Printf(common.Green+common.Bold+"[✔] Workstation public key linked! Connect immediately using: ssh %s@<target-ip>\n"+common.Reset, username)
		}
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [2] RBAC Privilege Tiering
// -----------------------------------------------------------------------------
func manageUserRBACTiers(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== ROLE-BASED ACCESS CONTROL (RBAC) PRIVILEGE TIERING ===" + common.Reset)

	username := selectUserInteractive(reader, client, "Select User to Assign / Modify RBAC Privilege Tier:")
	if username == "" {
		return
	}

	sig := fetchHostSignature(client)
	fmt.Printf("\nSelected Target: [%s] (Target OS: %s)\n", username, sig.OS)
	fmt.Println("Available Privilege Tiers:")
	fmt.Println("  [1] Tier 1: Super-Admin (Full Unrestricted Root / Admin Access)")
	fmt.Println("  [2] Tier 2: DevOps Engineer (Docker, K8s, Systemd, Logs, Network Mgmt)")
	fmt.Println("  [3] Tier 3: Security Auditor (Read-Only commands: ss, ps, journalctl, nmap, cat, ls)")
	fmt.Println("  [4] Tier 4: Database Administrator (PostgreSQL, MySQL, Redis, Dump tools)")
	fmt.Println("  [5] Tier 5: Custom Whitelist (Enter specific allowed binary paths)")
	fmt.Println("  [6] Revoke All Elevated Privileges (Demote to standard unprivileged user)")
	fmt.Println("  [0] Cancel")
	fmt.Print("Select RBAC Tier [0-6]: ")

	tierChoice, _ := reader.ReadString('\n')
	tierChoice = strings.TrimSpace(tierChoice)

	if tierChoice == "0" {
		return
	}

	if sig.OS == "windows" {
		winApplyTier(reader, client, username, tierChoice)
		common.PausePrompt()
		return
	}

	if sig.OS == "windows" {
		if tierChoice == "1" {
			winAdd := fmt.Sprintf(`powershell -Command "Add-LocalGroupMember -Group 'Administrators' -Member '%s'"`, username)
			if _, psErr := execRemote(client, winAdd); psErr == nil {
				fmt.Printf(common.Green+"✅ Success: User [%s] elevated to Windows Administrators Group!\n"+common.Reset, username)
			}
		} else if tierChoice == "6" {
			winRem := fmt.Sprintf(`powershell -Command "Remove-LocalGroupMember -Group 'Administrators' -Member '%s'"`, username)
			if _, psErr := execRemote(client, winRem); psErr == nil {
				fmt.Printf(common.Green+"✅ All elevated privileges revoked for user [%s]!\n"+common.Reset, username)
			}
		} else {
			fmt.Println(common.Yellow + "[!] Granular sudoers whitelisting is tailored for POSIX. User remains in standard group." + common.Reset)
		}
		common.PausePrompt()
		return
	}

	if sig.OS == "darwin" {
		if tierChoice == "1" {
			macAdd := fmt.Sprintf("dseditgroup -o edit -a %s -t user admin", username)
			execRemote(client, wrapSudo(macAdd))
			fmt.Printf(common.Green+"✅ Success: User [%s] elevated to macOS Admin!\n"+common.Reset, username)
		} else if tierChoice == "6" {
			macRem := fmt.Sprintf("dseditgroup -o edit -d %s -t user admin", username)
			execRemote(client, wrapSudo(macRem))
			fmt.Printf(common.Green+"✅ Privileges revoked for user [%s] on macOS!\n"+common.Reset, username)
		} else {
			fmt.Println(common.Yellow + "[!] Custom whitelists for macOS are applied via standard sudoers." + common.Reset)
		}
		common.PausePrompt()
		return
	}

	var sudoersContent string
	tierName := "Custom RBAC"

	switch tierChoice {
	case "1":
		tierName = "Super-Admin"
		sudoersContent = fmt.Sprintf("%s ALL=(ALL:ALL) ALL", username)
	case "2":
		tierName = "DevOps Eng"
		sudoersContent = fmt.Sprintf("%s ALL=(ALL) /usr/bin/docker, /usr/bin/kubectl, /usr/bin/systemctl, /usr/bin/journalctl, /usr/bin/ip, /usr/bin/ss, /usr/bin/apt, /usr/bin/yum, /usr/bin/dnf", username)
	case "3":
		tierName = "Sec Auditor"
		sudoersContent = fmt.Sprintf("%s ALL=(ALL) NOPASSWD: /usr/bin/ps, /usr/bin/ss, /usr/bin/netstat, /usr/bin/ip, /usr/bin/cat, /usr/bin/tail, /usr/bin/head, /usr/bin/ls, /usr/bin/journalctl -n *, /usr/bin/trivy, /usr/bin/nmap", username)
	case "4":
		tierName = "DB Admin"
		sudoersContent = fmt.Sprintf("%s ALL=(ALL) /usr/bin/mysql, /usr/bin/mysqldump, /usr/bin/psql, /usr/bin/pg_dump, /usr/bin/redis-cli, /usr/bin/systemctl * mysql, /usr/bin/systemctl * postgresql, /usr/bin/systemctl * redis", username)
	case "5":
		fmt.Print("Enter comma-separated absolute binary paths (e.g. /usr/bin/docker, /usr/bin/systemctl): ")
		paths, _ := reader.ReadString('\n')
		paths = strings.TrimSpace(paths)
		if paths == "" {
			fmt.Println(common.Yellow + "[!] No paths provided. Operation cancelled." + common.Reset)
			common.PausePrompt()
			return
		}
		tierName = "Custom Whitelist"
		sudoersContent = fmt.Sprintf("%s ALL=(ALL) %s", username, paths)
	case "6":
		revokeCmd := fmt.Sprintf("rm -f /etc/sudoers.d/cross_rbac_%s", username)
		_, err := execRemote(client, wrapSudo(revokeCmd))

		regCleanCmd := fmt.Sprintf(`python3 -c "
import os
u = '%s'
reg = '%s'
if os.path.exists(reg):
    lines = [l for l in open(reg, errors='ignore') if not l.startswith(u + ':')]
    with open(reg, 'w') as f:
        f.writelines(lines)
"`, username, rbacTierRegistry)
		execRemote(client, wrapSudo(regCleanCmd))

		if err == nil {
			fmt.Println(common.Green + "✅ All elevated privileges revoked for user [" + username + "]!" + common.Reset)
		} else {
			fmt.Printf(common.Red+"[!] Error revoking privileges: %v\n"+common.Reset, err)
		}
		common.PausePrompt()
		return
	default:
		fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		common.PausePrompt()
		return
	}

	script := fmt.Sprintf(`
TMP_FILE="/etc/sudoers.d/.tmp_rbac_%s"
TARGET_FILE="/etc/sudoers.d/cross_rbac_%s"

echo "%s" | tee "$TMP_FILE" >/dev/null
chmod 0440 "$TMP_FILE"

if visudo -cf "$TMP_FILE" >/dev/null 2>&1; then
    mv "$TMP_FILE" "$TARGET_FILE"
    echo "VISUDO_SUCCESS"
else
    rm -f "$TMP_FILE"
    echo "VISUDO_FAILED_SYNTAX_ERROR"
    exit 1
fi
`, username, username, sudoersContent)

	fmt.Println(common.Cyan + "[+] Validating and applying RBAC rule atomically..." + common.Reset)
	out, err := execRemote(client, wrapSudo(script))

	if err == nil && strings.Contains(out, "VISUDO_SUCCESS") {
		regWriteCmd := fmt.Sprintf(`python3 -c "
import os
u = '%s'
tier = '%s'
reg = '%s'
lines = []
if os.path.exists(reg):
    lines = [l for l in open(reg, errors='ignore') if not l.startswith(u + ':')]
lines.append(u + ':' + tier + '\n')
with open(reg, 'w') as f:
    f.writelines(lines)
    f.flush()
    os.fsync(f.fileno())
os.chmod(reg, 0o644)
"`, username, tierName, rbacTierRegistry)
		execRemote(client, wrapSudo(regWriteCmd))

		fmt.Printf(common.Green+"✅ Success: User [%s] elevated to Tier [%s]!\n"+common.Reset, username, tierName)
	} else {
		fmt.Printf(common.Red+"[!] Security Fail-Safe Triggered: visudo rejected rule syntax. No changes were made.\nOutput: %s\n"+common.Reset, out)
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [3] Multiple IP Stacking & Virtual Pingable IP Provisioner
// -----------------------------------------------------------------------------
func assignIPAndVirtualInterface(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MULTIPLE IP STACKING & VIRTUAL PINGABLE INTERFACE ENGINE ===" + common.Reset)
	fmt.Println(common.Yellow + "📖 CROSS-PLATFORM IP STACKING:" + common.Reset)
	fmt.Println("  • Multiple Secondary IPs are bound cleanly without adapter list overflow.")
	fmt.Println("  • Ping-Worthy Status: The assigned IP immediately responds to ICMP echo pings.")
	fmt.Println("  • Dedicated Mapping : The assigned IP is tracked and shown in the master table.")

	username := selectUserInteractive(reader, client, "Select Target User for IP Stacking / Purge:")
	if username == "" {
		return
	}

	ifaces := fetchActiveNetworkInterfaces(client)
	if len(ifaces) == 0 {
		fmt.Println(common.Red + "[!] No active network interfaces detected on remote system." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Println("\nSelect Operation Mode:")
	fmt.Println("  [1] Assign Permanent Stacked Pingable IP (Attached directly to main adapter)")
	fmt.Println("  [2] Assign Ephemeral TTL Pingable IP (Auto-destructs after timer expires)")
	fmt.Println(common.Red + "  [3] Purge & Destroy Assigned IP Address for this user" + common.Reset)
	fmt.Println("  [0] Cancel")
	fmt.Print("Select Mode [0-3]: ")

	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	if mode == "0" {
		return
	}

	sig := fetchHostSignature(client)

	if sig.OS == "windows" {
		winIPStack(reader, client, username, ifaces, mode)
		return
	}

	if mode == "3" {
		if sig.OS == "windows" {
			psDel := `powershell -Command "Get-NetIPAddress | Where-Object {$_.InterfaceAlias -notmatch 'Loopback' -and $_.SkipAsSource -eq $true} | Remove-NetIPAddress -Confirm:$false"`
			if _, psErr := execRemote(client, psDel); psErr == nil {
				fmt.Printf(common.Green + "✅ Success: Stacked IP addresses purged on Windows host!\n" + common.Reset)
			}
			common.PausePrompt()
			return
		}

		purgeScript := fmt.Sprintf(`
python3 -c "
import subprocess, os

u = '%s'
for reg_path in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
    if os.path.exists(reg_path):
        new_lines = []
        with open(reg_path, 'r') as f:
            for line in f:
                if line.startswith(f'{u}:'):
                    ip_cidr = line.split(':')[1].strip()
                    subprocess.run(f'ip -o -4 addr show | awk \'{{print $2}}\' | xargs -I {{}} ip addr del {ip_cidr} dev {{}} 2>/dev/null', shell=True)
                else:
                    new_lines.append(line)
        with open(reg_path, 'w') as f:
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

subprocess.run(['rm', '-f', f'/etc/ssh/sshd_config.d/rbac_{u}.conf'], check=False)
subprocess.run(['systemctl', 'reload', 'sshd'], check=False)
print('PURGE_IP_OK')
"
`, username)

		out, err := execRemote(client, wrapSudo(purgeScript))
		if err == nil && strings.Contains(out, "PURGE_IP_OK") {
			fmt.Printf(common.Green+"✅ Success: Assigned IP address for user [%s] has been unbound and purged!\n"+common.Reset, username)
		} else {
			fmt.Printf(common.Red+"[!] Error purging IP: %v\nOutput: %s\n"+common.Reset, err, out)
		}
		common.PausePrompt()
		return
	}

	fmt.Println("\nAvailable Network Interfaces on Remote Host:")
	for i, iface := range ifaces {
		fmt.Printf("  [%d] %-12s (Current IP: %s)\n", i+1, iface.Name, iface.IP)
	}

	fmt.Printf("Select Adapter to Stack IP [1-%d]: ", len(ifaces))
	ifaceChoice, _ := reader.ReadString('\n')
	ifaceIdx, err := strconv.Atoi(strings.TrimSpace(ifaceChoice))
	if err != nil || ifaceIdx < 1 || ifaceIdx > len(ifaces) {
		fmt.Println(common.Yellow + "[!] Invalid interface selected." + common.Reset)
		common.PausePrompt()
		return
	}
	selectedIface := ifaces[ifaceIdx-1].Name

	fmt.Print("\nEnter Dedicated Secondary IP to Stack (e.g. 192.168.0.210/24): ")
	assignIP, _ := reader.ReadString('\n')
	assignIP = strings.TrimSpace(assignIP)
	if !strings.Contains(assignIP, "/") {
		assignIP += "/24"
	}

	parsedIP, _, errIP := net.ParseCIDR(assignIP)
	if errIP != nil || parsedIP == nil {
		fmt.Println(common.Red + "[!] Invalid IP address or CIDR format." + common.Reset)
		common.PausePrompt()
		return
	}

	ttlSeconds := 0
	if mode == "2" {
		fmt.Print("Enter Active Duration in Minutes (e.g. 30 for 30 mins, 480 for 8 hrs): ")
		ttlStr, _ := reader.ReadString('\n')
		ttlMin, _ := strconv.Atoi(strings.TrimSpace(ttlStr))
		if ttlMin <= 0 {
			ttlMin = 60
		}
		ttlSeconds = ttlMin * 60
	}

	if sig.OS == "windows" {
		cleanIP := strings.Split(assignIP, "/")[0]
		psAdd := fmt.Sprintf(`powershell -Command "New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 24"`, selectedIface, cleanIP)
		_, errWin := execRemote(client, psAdd)
		if errWin == nil {
			fmt.Printf(common.Green+"✅ Success: Stacked IP [%s] assigned to Windows adapter [%s]!\n"+common.Reset, cleanIP, selectedIface)
		}
		common.PausePrompt()
		return
	}

	if sig.OS == "darwin" {
		cleanIP := strings.Split(assignIP, "/")[0]
		macAdd := fmt.Sprintf("ifconfig %s alias %s netmask 255.255.255.0", selectedIface, cleanIP)
		_, errMac := execRemote(client, wrapSudo(macAdd))
		if errMac == nil {
			fmt.Printf(common.Green+"✅ Success: Stacked IP [%s] aliased onto macOS [%s]!\n"+common.Reset, cleanIP, selectedIface)
		}
		common.PausePrompt()
		return
	}

	script := fmt.Sprintf(`
ip addr add %s dev %s 2>/dev/null || true

python3 -c "
import os
for reg_f in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
    lines = []
    if os.path.exists(reg_f):
        with open(reg_f, 'r') as f:
            lines = [l for l in f if not l.startswith('%s:')]
    lines.append('%s:%s\n')
    with open(reg_f, 'w') as f:
        f.writelines(lines)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(reg_f, 0o644)
"

mkdir -p /etc/ssh/sshd_config.d/
cat << 'EOF' > /etc/ssh/sshd_config.d/rbac_%s.conf
Match User %s
    AllowUsers %s
EOF

systemctl reload sshd 2>/dev/null || true
echo "IP_PROVISION_OK"
`, assignIP, selectedIface, username, username, assignIP, username, username, username)

	fmt.Println(common.Cyan + "[+] Stacking pingable IP onto adapter and updating registry..." + common.Reset)
	out, err := execRemote(client, wrapSudo(script))

	if err == nil && strings.Contains(out, "IP_PROVISION_OK") {
		if ttlSeconds > 0 {
			ttlCmd := fmt.Sprintf("systemd-run --unit=cross_ip_%s --on-active=%ds sh -c 'ip addr del %s dev %s 2>/dev/null; python3 -c \"import os; lines=[l for l in open(\\\"/etc/cross_assigned_ips.txt\\\") if not l.startswith(\\\"%s:\\\")]; open(\\\"/etc/cross_assigned_ips.txt\\\", \\\"w\\\").writelines(lines)\"; rm -f /etc/ssh/sshd_config.d/rbac_%s.conf && systemctl reload sshd'",
				username, ttlSeconds, assignIP, selectedIface, username, username)
			_, _ = execRemote(client, wrapSudo(ttlCmd))
			fmt.Printf(common.Green+"✅ Success: Ephemeral Pingable IP [%s] stacked for user [%s] on [%s] (TTL: %d seconds)!\n"+common.Reset, assignIP, username, selectedIface, ttlSeconds)
		} else {
			fmt.Printf(common.Green+"✅ Success: Permanent Pingable IP [%s] stacked cleanly for user [%s] on [%s]!\n"+common.Reset, assignIP, username, selectedIface)
		}
		fmt.Println(common.Yellow + "=> You can now ping this IP from any computer on the subnet." + common.Reset)
	} else {
		fmt.Printf(common.Red+"[!] Error assigning IP: %v\nOutput: %s\n"+common.Reset, err, out)
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [4] Identity DNS Profile & Upstream Resolver Assigner / Purge Engine
// -----------------------------------------------------------------------------
func assignDNSResolverProfile(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== IDENTITY DNS PROFILE ASSIGNER & PURGE ENGINE ===" + common.Reset)

	username := selectUserInteractive(reader, client, "Select Target User / Identity for DNS Policy Assignment:")
	if username == "" {
		return
	}

	fmt.Printf("\nSelected User Profile: [%s]\n", username)
	fmt.Println("Select DNS Policy Action:")
	fmt.Println("  [1] Enforce Cloudflare Secure DNS (1.1.1.1, 1.0.0.1) - [Recommended]")
	fmt.Println("  [2] Enforce Google Public DNS (8.8.8.8, 8.8.4.4)")
	fmt.Println("  [3] Enforce Quad9 Security DNS with Malware Blocking (9.9.9.9, 149.112.112.112)")
	fmt.Println("  [4] Enforce AdGuard Privacy & Ad-Blocking DNS (94.140.14.14, 94.140.15.15)")
	fmt.Println("  [5] Enforce Custom DNS Resolver IP")
	fmt.Println(common.Red + "  [6] Purge & Reset DNS (Revert to default DHCP / Gateway resolvers)" + common.Reset)
	fmt.Println("  [0] Cancel")
	fmt.Print("Select DNS Choice [0-6]: ")

	dnsChoice, _ := reader.ReadString('\n')
	dnsChoice = strings.TrimSpace(dnsChoice)

	if dnsChoice == "0" {
		return
	}

	sig := fetchHostSignature(client)

	if dnsChoice == "6" {
		if sig.OS == "windows" {
			if _, psErr := execRemote(client, `powershell -Command "Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object Status -eq 'Up').Name -ResetServerAddresses"`); psErr == nil {
				fmt.Println(common.Green + "✅ Windows DNS reset to DHCP default." + common.Reset)
			}
			common.PausePrompt()
			return
		}
		if sig.OS == "darwin" {
			execRemote(client, wrapSudo("networksetup -setdnsservers Wi-Fi empty 2>/dev/null; networksetup -setdnsservers Ethernet empty 2>/dev/null"))
			fmt.Println(common.Green + "✅ macOS DNS reset to DHCP default." + common.Reset)
			common.PausePrompt()
			return
		}

		revertScript := `
if [ -f /etc/resolv.conf.bak ]; then
    cp /etc/resolv.conf.bak /etc/resolv.conf
fi
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl revert $(ip -o -4 route show to default | awk '{print $5}' | head -n 1) 2>/dev/null || true
    systemctl restart systemd-resolved 2>/dev/null || true
fi
echo "DNS_REVERT_OK"
`
		out, err := execRemote(client, wrapSudo(revertScript))
		if err == nil && strings.Contains(out, "DNS_REVERT_OK") {
			fmt.Println(common.Green + "✅ Custom DNS purged! System reverted to default network upstream resolvers." + common.Reset)
		} else {
			fmt.Printf(common.Red+"[!] Error resetting DNS: %v\n"+common.Reset, err)
		}
		common.PausePrompt()
		return
	}

	primaryDNS := "1.1.1.1"
	secondaryDNS := "1.0.0.1"
	dnsName := "Cloudflare 1.1.1.1"

	switch dnsChoice {
	case "1":
		primaryDNS = "1.1.1.1"
		secondaryDNS = "1.0.0.1"
		dnsName = "Cloudflare 1.1.1.1"
	case "2":
		primaryDNS = "8.8.8.8"
		secondaryDNS = "8.8.4.4"
		dnsName = "Google 8.8.8.8"
	case "3":
		primaryDNS = "9.9.9.9"
		secondaryDNS = "149.112.112.112"
		dnsName = "Quad9 Security"
	case "4":
		primaryDNS = "94.140.14.14"
		secondaryDNS = "94.140.15.15"
		dnsName = "AdGuard DNS"
	case "5":
		fmt.Print("Enter Primary DNS IP: ")
		pDNS, _ := reader.ReadString('\n')
		primaryDNS = strings.TrimSpace(pDNS)
		fmt.Print("Enter Secondary DNS IP (Optional): ")
		sDNS, _ := reader.ReadString('\n')
		secondaryDNS = strings.TrimSpace(sDNS)
		dnsName = "Custom DNS"
	default:
		fmt.Println(common.Yellow + "[!] Invalid selection." + common.Reset)
		common.PausePrompt()
		return
	}

	if sig.OS == "windows" {
		winDNS := fmt.Sprintf(`powershell -Command "Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter | Where-Object Status -eq 'Up').Name -ServerAddresses ('%s','%s')"`, primaryDNS, secondaryDNS)
		if _, psErr := execRemote(client, winDNS); psErr == nil {
			fmt.Printf(common.Green+"✅ Success: DNS Policy [%s (%s, %s)] assigned on Windows!\n"+common.Reset, dnsName, primaryDNS, secondaryDNS)
		}
		common.PausePrompt()
		return
	}

	if sig.OS == "darwin" {
		macDNS := fmt.Sprintf("networksetup -setdnsservers Wi-Fi %s %s 2>/dev/null || networksetup -setdnsservers Ethernet %s %s 2>/dev/null", primaryDNS, secondaryDNS, primaryDNS, secondaryDNS)
		execRemote(client, wrapSudo(macDNS))
		fmt.Printf(common.Green+"✅ Success: DNS Policy [%s (%s, %s)] assigned on macOS!\n"+common.Reset, dnsName, primaryDNS, secondaryDNS)
		common.PausePrompt()
		return
	}

	script := fmt.Sprintf(`
if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl dns $(ip -o -4 route show to default | awk '{print $5}' | head -n 1) %s %s 2>/dev/null || true
fi

cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
cat << 'EOF' > /etc/resolv.conf
# Managed by Cross-Suite Sovereign Access Assigner
nameserver %s
nameserver %s
options timeout:2 attempts:3 rotate
EOF

echo "DNS_UPDATE_SUCCESS"
`, primaryDNS, secondaryDNS, primaryDNS, secondaryDNS)

	fmt.Println(common.Cyan + "[+] Enforcing DNS upstream configuration on remote system..." + common.Reset)
	out, err := execRemote(client, wrapSudo(script))

	if err == nil && strings.Contains(out, "DNS_UPDATE_SUCCESS") {
		fmt.Printf(common.Green+"✅ Success: DNS Policy [%s (%s, %s)] assigned to user [%s]!\n"+common.Reset, dnsName, primaryDNS, secondaryDNS, username)
	} else {
		fmt.Printf(common.Red+"[!] Error updating DNS: %v\nOutput: %s\n"+common.Reset, err, out)
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [5] User Network & Internet Confinement
// -----------------------------------------------------------------------------
func manageNetworkAndInternetConfinement(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== USER NETWORK & INTERNET CONFINEMENT ENGINE ===" + common.Reset)
	fmt.Println(common.Yellow + "📖 ISOLATION POLICIES:" + common.Reset)
	fmt.Println("  • Block Local LAN     : Drops 192.168.x.x, 10.x.x.x, 172.16.x.x packets while allowing WAN internet.")
	fmt.Println("  • Blackhole Internet  : Drops public WAN packets while allowing private LAN communication.")
	fmt.Println("  • Complete Blackhole  : True Airgap Isolation (Strict 127.0.0.1 loopback only - drops Host IP, LAN & WAN).")
	fmt.Println("  • Unblock Sub-Menu    : Granular unblocking per policy or complete firewall reset.")

	username := selectUserInteractive(reader, client, "Select Target User for Network Confinement:")
	if username == "" || username == "root" {
		fmt.Println(common.Red + "[!] Invalid or protected account." + common.Reset)
		common.PausePrompt()
		return
	}

	sig := fetchHostSignature(client)
	if sig.OS == "windows" {
		winConfinement(reader, client, username)
		return
	}
	if sig.OS != "linux" {
		fmt.Println(common.Yellow + "[!] User network socket ownership confinement (UID-bound packet dropping) is Linux-specific via iptables owner module." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Printf("\nSelected User: [%s]\n", username)
	fmt.Println("Select Confinement Policy:")
	fmt.Println("  [1] Block Local Private LAN Subnets (Prevent lateral network traversal)")
	fmt.Println("  [2] Blackhole External Internet Access (Block WAN / Egress completely)")
	fmt.Println("  [3] Complete Network Blackhole (Isolate user to 127.0.0.1 only - ZERO LAN & ZERO Internet)")
	fmt.Println(common.Green + "  [4] Granular Unblock & Restore Engine (Select what to unblock)" + common.Reset)
	fmt.Println("  [0] Cancel")
	fmt.Print("Select Policy [0-4]: ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "0":
		return
	case "1":
		script := fmt.Sprintf(`
python3 -c "
import subprocess, pwd

u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)

for _ in range(5):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    nums = [int(l.split()[0]) for l in proc.stdout.splitlines() if f'cross_{u}' in l]
    if not nums:
        break
    for n in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(n)], capture_output=True)

subprocess.run(['iptables', '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', uid, '-d', '192.168.0.0/16', '-m', 'comment', '--comment', f'cross_{u}_lan', '-j', 'DROP'])
subprocess.run(['iptables', '-I', 'OUTPUT', '2', '-m', 'owner', '--uid-owner', uid, '-d', '10.0.0.0/8', '-m', 'comment', '--comment', f'cross_{u}_lan', '-j', 'DROP'])
subprocess.run(['iptables', '-I', 'OUTPUT', '3', '-m', 'owner', '--uid-owner', uid, '-d', '172.16.0.0/12', '-m', 'comment', '--comment', f'cross_{u}_lan', '-j', 'DROP'])
print('LAN_BLOCKED_OK')
"
`, username)

		out, err := execRemote(client, wrapSudo(script))
		if err == nil && strings.Contains(out, "LAN_BLOCKED_OK") {
			fmt.Printf(common.Green+"✅ Success: Local LAN access is now blocked for user [%s]!\n"+common.Reset, username)
		} else {
			fmt.Printf(common.Red+"[!] Error applying LAN confinement: %v\n"+common.Reset, err)
		}

	case "2":
		script := fmt.Sprintf(`
python3 -c "
import subprocess, pwd

u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)

for _ in range(5):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    nums = [int(l.split()[0]) for l in proc.stdout.splitlines() if f'cross_{u}' in l]
    if not nums:
        break
    for n in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(n)], capture_output=True)

subprocess.run(['iptables', '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', uid, '-d', '127.0.0.0/8', '-m', 'comment', '--comment', f'cross_{u}_wan', '-j', 'ACCEPT'])
subprocess.run(['iptables', '-I', 'OUTPUT', '2', '-m', 'owner', '--uid-owner', uid, '-d', '192.168.0.0/16', '-m', 'comment', '--comment', f'cross_{u}_wan', '-j', 'ACCEPT'])
subprocess.run(['iptables', '-I', 'OUTPUT', '3', '-m', 'owner', '--uid-owner', uid, '-d', '10.0.0.0/8', '-m', 'comment', '--comment', f'cross_{u}_wan', '-j', 'ACCEPT'])
subprocess.run(['iptables', '-I', 'OUTPUT', '4', '-m', 'owner', '--uid-owner', uid, '-d', '172.16.0.0/12', '-m', 'comment', '--comment', f'cross_{u}_wan', '-j', 'ACCEPT'])
subprocess.run(['iptables', '-I', 'OUTPUT', '5', '-m', 'owner', '--uid-owner', uid, '-m', 'comment', '--comment', f'cross_{u}_wan', '-j', 'DROP'])
print('WAN_BLOCKED_OK')
"
`, username)

		out, err := execRemote(client, wrapSudo(script))
		if err == nil && strings.Contains(out, "WAN_BLOCKED_OK") {
			fmt.Printf(common.Green+"✅ Success: External internet access is now blackholed for user [%s]!\n"+common.Reset, username)
		} else {
			fmt.Printf(common.Red+"[!] Error applying WAN blackhole: %v\n"+common.Reset, err)
		}

	case "3":
		script := fmt.Sprintf(`
python3 -c "
import subprocess, pwd

u = '%s'
uid = str(pwd.getpwnam(u).pw_uid)

for _ in range(5):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    nums = [int(l.split()[0]) for l in proc.stdout.splitlines() if f'cross_{u}' in l or f'owner UID match {uid}' in l]
    if not nums:
        break
    for n in sorted(nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(n)], capture_output=True)

subprocess.run(['iptables', '-I', 'OUTPUT', '1', '-m', 'owner', '--uid-owner', uid, '-d', '127.0.0.0/8', '-o', 'lo', '-m', 'comment', '--comment', f'cross_{u}_total', '-j', 'ACCEPT'])
subprocess.run(['iptables', '-I', 'OUTPUT', '2', '-m', 'owner', '--uid-owner', uid, '-m', 'comment', '--comment', f'cross_{u}_total', '-j', 'DROP'])
print('TOTAL_BLACKHOLE_OK')
"
`, username)

		out, err := execRemote(client, wrapSudo(script))
		if err == nil && strings.Contains(out, "TOTAL_BLACKHOLE_OK") {
			fmt.Printf(common.Green+"✅ Success: TRUE AIRGAP BLACKHOLE ENFORCED for user [%s]! (Zero LAN, Zero Host IP, Zero Internet, 127.0.0.1 Only)\n"+common.Reset, username)
		} else {
			fmt.Printf(common.Red+"[!] Error applying blackhole: %v\n"+common.Reset, err)
		}

	case "4":
		fmt.Printf("\n--- GRANULAR UNBLOCK ENGINE FOR [%s] ---\n", username)
		fmt.Println("  [1] Unblock Local LAN Only (Restore local network communication)")
		fmt.Println("  [2] Unblock External Internet Only (Restore WAN egress)")
		fmt.Println("  [3] Lift Complete Network Blackhole")
		fmt.Println(common.Green + "  [4] Clean Full Reset (Remove ALL firewall blocks for this user)" + common.Reset)
		fmt.Println("  [0] Cancel")
		fmt.Print("Select Unblock Action [0-4]: ")

		unblockChoice, _ := reader.ReadString('\n')
		unblockChoice = strings.TrimSpace(unblockChoice)

		var targetTag string
		switch unblockChoice {
		case "1":
			targetTag = fmt.Sprintf("cross_%s_lan", username)
		case "2":
			targetTag = fmt.Sprintf("cross_%s_wan", username)
		case "3":
			targetTag = fmt.Sprintf("cross_%s_total", username)
		case "4":
			targetTag = fmt.Sprintf("cross_%s", username)
		default:
			return
		}

		unblockScript := fmt.Sprintf(`
python3 -c "
import subprocess, pwd

u = '%s'
tag = '%s'
try:
    uid = str(pwd.getpwnam(u).pw_uid)
except Exception:
    uid = u

for iteration in range(10):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    matching_nums = []
    for l in lines:
        if tag in l or (tag == f'cross_{u}' and f'owner UID match {uid}' in l):
            parts = l.split()
            if parts and parts[0].isdigit():
                matching_nums.append(int(parts[0]))
    if not matching_nums:
        break
    for num in sorted(matching_nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], capture_output=True)

print('RESTORE_NET_OK')
"
`, username, targetTag)

		out, err := execRemote(client, wrapSudo(unblockScript))
		if err == nil && strings.Contains(out, "RESTORE_NET_OK") {
			fmt.Printf(common.Green+"✅ Success: Selected network confinement rules cleanly unblocked for user [%s]!\n"+common.Reset, username)
		} else {
			fmt.Printf(common.Red+"[!] Error unblocking: %v\nOutput: %s\n"+common.Reset, err, out)
		}
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [6] Master Host Network & Adapter Orchestrator
// -----------------------------------------------------------------------------
func orchestrateHostNetwork(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MASTER HOST NETWORK & ADAPTER ORCHESTRATOR ===" + common.Reset)
	fmt.Println("Configure Host Adapter IP, Default Gateway, DNS, and Hostname:")

	ifaces := fetchActiveNetworkInterfaces(client)
	if len(ifaces) == 0 {
		fmt.Println(common.Red + "[!] No active network interfaces detected." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Println("\nSelect Network Adapter to Configure:")
	for i, iface := range ifaces {
		fmt.Printf("  [%d] %-12s (Current IP: %s)\n", i+1, iface.Name, iface.IP)
	}

	fmt.Printf("Choose Interface [1-%d]: ", len(ifaces))
	ifaceChoice, _ := reader.ReadString('\n')
	idx, err := strconv.Atoi(strings.TrimSpace(ifaceChoice))
	if err != nil || idx < 1 || idx > len(ifaces) {
		return
	}
	selectedIface := ifaces[idx-1].Name

	fmt.Print("\nEnter New Primary Static IP with CIDR (e.g. 192.168.0.160/24) [or press Enter to keep current]: ")
	newIP, _ := reader.ReadString('\n')
	newIP = strings.TrimSpace(newIP)

	fmt.Print("Enter New Default Gateway (e.g. 192.168.0.1) [or press Enter to keep current]: ")
	newGW, _ := reader.ReadString('\n')
	newGW = strings.TrimSpace(newGW)

	fmt.Print("Enter Upstream DNS (e.g. 1.1.1.1 or 8.8.8.8) [or press Enter to keep current]: ")
	newDNS, _ := reader.ReadString('\n')
	newDNS = strings.TrimSpace(newDNS)

	fmt.Print("Enter New Machine Hostname [or press Enter to keep current]: ")
	newHostname, _ := reader.ReadString('\n')
	newHostname = strings.TrimSpace(newHostname)

	sig := fetchHostSignature(client)

	if sig.OS == "windows" {
		winOrchestrate(client, selectedIface, newIP, newGW, newDNS, newHostname)
		common.PausePrompt()
		return
	}

	if sig.OS == "windows" {
		if newHostname != "" {
			execRemote(client, fmt.Sprintf(`powershell -Command "Rename-Computer -NewName '%s' -Force"`, newHostname))
		}
		if newIP != "" {
			cleanIP := strings.Split(newIP, "/")[0]
			execRemote(client, fmt.Sprintf(`powershell -Command "New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 24"`, selectedIface, cleanIP))
		}
		if newDNS != "" {
			execRemote(client, fmt.Sprintf(`powershell -Command "Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses ('%s')"`, selectedIface, newDNS))
		}
		fmt.Println(common.Green + "✅ Host Network Parameters applied on Windows!" + common.Reset)
		common.PausePrompt()
		return
	}

	if sig.OS == "darwin" {
		if newHostname != "" {
			execRemote(client, wrapSudo(fmt.Sprintf("scutil --set HostName '%s'", newHostname)))
		}
		if newIP != "" {
			cleanIP := strings.Split(newIP, "/")[0]
			execRemote(client, wrapSudo(fmt.Sprintf("ifconfig %s alias %s netmask 255.255.255.0", selectedIface, cleanIP)))
		}
		if newDNS != "" {
			execRemote(client, wrapSudo(fmt.Sprintf("networksetup -setdnsservers Ethernet %s 2>/dev/null || networksetup -setdnsservers Wi-Fi %s", newDNS, newDNS)))
		}
		fmt.Println(common.Green + "✅ Host Network Parameters applied on macOS!" + common.Reset)
		common.PausePrompt()
		return
	}

	script := "#!/bin/bash\nset -e\n"

	if newHostname != "" {
		script += fmt.Sprintf("hostnamectl set-hostname '%s'\n", newHostname)
	}

	if newIP != "" {
		if !strings.Contains(newIP, "/") {
			newIP += "/24"
		}
		script += fmt.Sprintf("ip addr add %s dev %s 2>/dev/null || true\n", newIP, selectedIface)
	}

	if newGW != "" {
		script += fmt.Sprintf("ip route replace default via %s dev %s 2>/dev/null || true\n", newGW, selectedIface)
	}

	if newDNS != "" {
		script += fmt.Sprintf(`
cat << 'EOF' > /etc/resolv.conf
nameserver %s
nameserver 1.0.0.1
EOF
`, newDNS)
	}

	script += "echo 'NET_ORCHESTRATE_SUCCESS'\n"

	fmt.Println(common.Cyan + "[+] Applying network configuration changes..." + common.Reset)
	out, err := execRemote(client, wrapSudo(script))

	if err == nil && strings.Contains(out, "NET_ORCHESTRATE_SUCCESS") {
		fmt.Println(common.Green + "✅ Host Network Parameters successfully updated and applied!" + common.Reset)
		if newHostname != "" {
			fmt.Printf("=> Hostname changed to: %s\n", newHostname)
		}
		if newIP != "" {
			fmt.Printf("=> Interface %s assigned: %s\n", selectedIface, newIP)
		}
	} else {
		fmt.Printf(common.Red+"[!] Error orchestrating network: %v\nOutput: %s\n"+common.Reset, err, out)
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [7] Active Session Monitor & Remote Terminal Killswitch
// -----------------------------------------------------------------------------
func monitorAndKillSessions(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== ACTIVE LIVE SESSIONS & TERMINAL CONTROL ===" + common.Reset)

	sig := fetchHostSignature(client)
	renderHostBanner(sig)
	fmt.Println()

	var cmd string
	if sig.OS == "windows" {
		cmd = `powershell -Command "$q = quser 2>&1 | Out-String; if ($q -match 'USERNAME') { $q } else { whoami }"`
	} else {
		cmd = "w -h 2>/dev/null || who"
	}
	out, _ := execRemote(client, cmd)

	fmt.Println("Current Active Logins:")
	fmt.Printf("%-15s %-10s %-18s %-10s %-10s %s\n", "USER", "TTY", "FROM IP", "LOGIN@", "IDLE", "WHAT")
	fmt.Println("--------------------------------------------------------------------------------")

	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 1 {
			fmt.Println(l)
		}
	}
	fmt.Println("--------------------------------------------------------------------------------")

	users := fetchSystemUsers(client)
	renderUserTable(users)

	menuLabels := make([]string, 0, len(users)+1)
	for _, u := range users {
		menuLabels = append(menuLabels, fmt.Sprintf("%-14s UID:%-6s %-10s", u.Username, u.UID, u.Status))
	}
	menuLabels = append(menuLabels, "⚠  KILL ALL non-root sessions")

	for reader.Buffered() > 0 {
		reader.ReadByte()
	}
	sel := InteractiveSelect("Select a session to act on (or KILL ALL):", menuLabels)
	if sel == -1 {
		return
	}

	if sel == len(users) {
		fmt.Print(common.Red + "Are you sure you want to terminate all non-root user sessions? (y/N): " + common.Reset)
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
			if sig.OS == "windows" {
				if _, psErr := execRemote(client, winKillAllCmd()); psErr == nil {
					fmt.Println(common.Green + "✅ All active user terminal sessions have been terminated on Windows!" + common.Reset)
				}
			} else {
				killAllScript := `
python3 -c "
import pwd, subprocess

for p in pwd.getpwall():
    if p.pw_uid >= 1000 and p.pw_name != 'root':
        subprocess.run(['pkill', '-9', '-u', p.pw_name], check=False)
print('KILLALL_OK')
"
`
				outKill, _ := execRemote(client, wrapSudo(killAllScript))
				if strings.Contains(outKill, "KILLALL_OK") {
					fmt.Println(common.Green + "✅ All active non-root user terminal sessions have been terminated!" + common.Reset)
				}
			}
		}
		common.PausePrompt()
		return
	}

	targetUser := users[sel].Username

	actionIdx := InteractiveSelect(fmt.Sprintf("Action for user [%s]:", targetUser), []string{
		"Terminate Session (kill -9 / logoff, keep account)",
		"Terminate Session + Lock Account",
		"Unlock Account (undo a previous lock)",
		"Keep / Do Nothing (cancel)",
	})

	switch actionIdx {
	case 2:
		var unlockErr error
		if sig.OS == "windows" {
			_, unlockErr = execRemote(client, fmt.Sprintf(`powershell -Command "Enable-LocalUser -Name '%[1]s' -ErrorAction Stop; if(-not (Get-LocalUser -Name '%[1]s').Enabled){ throw 'Account is still disabled after Enable-LocalUser' }"`, targetUser))
		} else if sig.OS == "darwin" {
			_, unlockErr = execRemote(client, wrapSudo(fmt.Sprintf("dscl . -delete /Users/%s AuthenticationAuthority", targetUser)))
		} else {
			_, unlockErr = execRemote(client, wrapSudo(fmt.Sprintf("passwd -u %s", targetUser)))
		}
		if unlockErr != nil {
			fmt.Println(common.Red + "[!] Failed to unlock [" + targetUser + "]: " + unlockErr.Error() + common.Reset)
		} else {
			fmt.Println(common.Green + "✅ Account [" + targetUser + "] unlocked!" + common.Reset)
		}
	case 0:
		var killErr error
		if sig.OS == "windows" {
			_, killErr = execRemote(client, winKillUserCmd(targetUser))
		} else {
			killCmd := fmt.Sprintf("pkill -9 -u %s", targetUser)
			_, killErr = execRemote(client, wrapSudo(killCmd))
		}
		if killErr != nil {
			fmt.Println(common.Red + "[!] Failed to terminate sessions for [" + targetUser + "]: " + killErr.Error() + common.Reset)
		} else {
			fmt.Println(common.Green + "✅ Active sessions terminated for user [" + targetUser + "]!" + common.Reset)
		}
	case 1:
		var lockErr error
		if sig.OS == "windows" {
			_, lockErr = execRemote(client, winLockUserCmd(targetUser))
		} else {
			killLockCmd := fmt.Sprintf("pkill -9 -u %s; passwd -l %s 2>/dev/null || pw lock %s", targetUser, targetUser, targetUser)
			_, lockErr = execRemote(client, wrapSudo(killLockCmd))
		}
		if lockErr != nil {
			fmt.Println(common.Red + "[!] Failed to terminate/lock [" + targetUser + "]: " + lockErr.Error() + common.Reset)
		} else {
			fmt.Println(common.Green + "✅ Sessions terminated and account [" + targetUser + "] locked!" + common.Reset)
		}
	default:
		fmt.Println(common.Yellow + "[!] No action taken." + common.Reset)
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [8] Active Identity & Permission Matrix Auditor
// -----------------------------------------------------------------------------
func auditIdentityMatrix(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)
	fmt.Println(common.Cyan + common.Bold + "=== ACTIVE SYSTEM IDENTITY, GEOLOCATION & PRIVILEGE MATRIX ===" + common.Reset)
	fmt.Println(common.Cyan + common.Bold + "================================================================================" + common.Reset)

	sig := fetchHostSignature(client)
	renderHostBanner(sig)
	fmt.Println()

	users := fetchSystemUsers(client)
	renderUserTable(users)

	tierCounts := map[string]int{}
	for _, u := range users {
		tierCounts[u.RBACTier]++
	}
	fmt.Println()
	fmt.Println(common.Cyan + "Tier Summary:" + common.Reset)
	for tier, count := range tierCounts {
		fmt.Printf("  • %-16s : %d\n", tier, count)
	}

	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [9] Emergency Quarantine & Mass Nuclear Purge
// -----------------------------------------------------------------------------
func emergencyQuarantine(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Red + common.Bold + "================================================================================" + common.Reset)
	fmt.Println(common.Red + common.Bold + "=== EMERGENCY IDENTITY QUARANTINE & ULTIMATE MASS PURGE ENGINE ===" + common.Reset)
	fmt.Println(common.Red + common.Bold + "================================================================================" + common.Reset)

	sig := fetchHostSignature(client)
	renderHostBanner(sig)
	fmt.Println()

	users := fetchSystemUsers(client)
	renderUserTable(users)

	fmt.Println("\nSelect Enforcement Action:")
	fmt.Println("  [1] Instant Account Lockdown (Lock password, terminate active sessions, block SSH)")
	fmt.Println("  [2] Unlock Account (passwd -u / Enable-LocalUser)")
	fmt.Println("  [3] Purge Single Selected User (Delete user, home directory, permissions & IP)")
	fmt.Println(common.Cyan + common.Bold + "  [4] 🛡️  DRY RUN MASS PURGE SIMULATION (Test Whitelist & Safety without modifying system)" + common.Reset)
	fmt.Println(common.Red + common.Bold + "  [5] 💥 LIVE NUCLEAR MASS PURGE (Wipe ALL users, stacked IPs, rules EXCEPT Root & Native Admin)" + common.Reset)
	fmt.Println("  [0] Cancel")
	fmt.Print("Choose Action [0-5]: ")

	action, _ := reader.ReadString('\n')
	action = strings.TrimSpace(action)

	if action == "0" || action == "" {
		return
	}

	if action == "4" {
		if sig.OS == "windows" {
			winDryRun(client)
			common.PausePrompt()
			return
			fmt.Println(common.Cyan + "\n[+] Running pre-flight Mass Purge simulation for Windows..." + common.Reset)
			fmt.Println(common.Green + "[✔] IMMUNE / PROTECTED IDENTITIES: Administrator, DefaultAccount, Guest, Current User" + common.Reset)
			fmt.Println(common.Yellow + "[!] TARGET IDENTITIES QUEUED FOR MASS PURGE: Non-default local accounts" + common.Reset)
			fmt.Println(common.Green + "=== DRY RUN VERDICT: SIMULATION COMPLETED SAFELY (ZERO CHANGES APPLIED) ===" + common.Reset)
			common.PausePrompt()
			return
		}

		dryRunPythonScript := `
python3 -c "
import pwd, os, subprocess

current_user = os.environ.get('SUDO_USER') or os.environ.get('USER') or subprocess.getoutput('whoami').strip()
protected_whitelist = {'root', 'kali', 'ubuntu', 'centos', 'debian', 'rocky', 'alma', 'ec2-user', 'vagrant', 'admin', 'systemd-coredump', 'nobody'}
if current_user:
    protected_whitelist.add(current_user)

protected_list = []
purge_list = []

for p in pwd.getpwall():
    if p.pw_uid == 0 or p.pw_name in protected_whitelist:
        protected_list.append((p.pw_name, p.pw_uid))
    elif p.pw_uid >= 1000:
        purge_list.append((p.pw_name, p.pw_uid))

print('=== DRY RUN SAFETY AUDIT REPORT ===')
print('\n[✔] IMMUNE / PROTECTED IDENTITIES (Will NEVER be touched):')
for u, uid in protected_list:
    marker = ' (Current Active Session)' if u == current_user else ''
    print(f'  • {u} (UID: {uid}) -> [SAFE / PROTECTED]{marker}')

print('\n[!] TARGET IDENTITIES QUEUED FOR MASS PURGE:')
if not purge_list:
    print('  • None. No third-party or test users detected.')
else:
    for u, uid in purge_list:
        print(f'  • {u} (UID: {uid}) -> [SCHEDULED FOR DELETION]')

print('\n[!] STACKED IP CLEANUP PREVIEW:')
if os.path.exists('/etc/cross_assigned_ips.txt'):
    with open('/etc/cross_assigned_ips.txt', 'r') as f:
        for line in f:
            if ':' in line:
                u_part, ip_part = line.strip().split(':', 1)
                print(f'  • Unbind IP [{ip_part}] assigned to user [{u_part}]')
else:
    print('  • No stacked IPs registered.')

print('\n=== DRY RUN VERDICT: SIMULATION COMPLETED SAFELY (ZERO CHANGES APPLIED) ===')
"
`
		fmt.Println(common.Cyan + "\n[+] Running pre-flight Mass Purge simulation..." + common.Reset)
		out, err := execRemote(client, wrapSudo(dryRunPythonScript))
		if err == nil {
			fmt.Println(common.Green + out + common.Reset)
		} else {
			fmt.Printf(common.Red+"[!] Error running dry run: %v\nOutput: %s\n"+common.Reset, err, out)
		}
		common.PausePrompt()
		return
	}

	if action == "5" {
		fmt.Println(common.Red + common.Bold + "\n⚠️  CRITICAL WARNING: ZERO-STATE SYSTEM REVERSION TRIGGERED" + common.Reset)
		fmt.Println("This operation will:")
		fmt.Println("  • Terminate all processes and login sessions for all created identities.")
		fmt.Println("  • Delete all non-native user accounts and permanently purge their home directories.")
		fmt.Println("  • Unbind and delete all stacked secondary IP addresses from network adapters.")
		fmt.Println("  • Flush all firewall socket confinement rules and restore full network access.")
		fmt.Println("  • Remove all RBAC sudoers files, SSH match configurations, and tier registry entries.")
		fmt.Println("  • PROTECT AND PRESERVE root and your native administrative account (kali/ubuntu/centos/etc.).")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Print(common.Red + common.Bold + "Type 'NUKE' to execute full system purge: " + common.Reset)

		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirm) != "NUKE" {
			fmt.Println(common.Yellow + "[!] Nuclear purge aborted. No changes made." + common.Reset)
			common.PausePrompt()
			return
		}

		if sig.OS == "windows" {
			winNuke := winNukeCmd()
			if _, psErr := execRemote(client, winNuke); psErr == nil {
				fmt.Println(common.Green + "✅ Windows System Sanitization Complete!" + common.Reset)
			}
			common.PausePrompt()
			return
		}

		nuclearPythonScript := fmt.Sprintf(`
python3 -c "
import pwd, subprocess, os

current_user = os.environ.get('SUDO_USER') or os.environ.get('USER') or subprocess.getoutput('whoami').strip()
protected_whitelist = {'root', 'kali', 'ubuntu', 'centos', 'debian', 'rocky', 'alma', 'ec2-user', 'vagrant', 'admin', 'systemd-coredump', 'nobody'}
if current_user:
    protected_whitelist.add(current_user)

to_purge = []
for p in pwd.getpwall():
    if p.pw_uid >= 1000 and p.pw_name not in protected_whitelist:
        to_purge.append((p.pw_name, str(p.pw_uid)))

for u, uid in to_purge:
    subprocess.run(['pkill', '-9', '-u', u], check=False)
    subprocess.run(['userdel', '-r', '-f', u], check=False)
    subprocess.run(['rm', '-f', f'/etc/sudoers.d/cross_rbac_{u}', f'/etc/sudoers.d/cross_init_{u}', f'/etc/ssh/sshd_config.d/rbac_{u}.conf'], check=False)

for reg_path in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
    if os.path.exists(reg_path):
        with open(reg_path, 'r') as f:
            for line in f:
                if ':' in line:
                    user_part, ip_part = line.strip().split(':', 1)
                    subprocess.run(f'ip -o -4 addr show | awk \'{{print $2}}\' | xargs -I {{}} ip addr del {ip_part} dev {{}} 2>/dev/null', shell=True)
        os.remove(reg_path)

if os.path.exists('%s'):
    os.remove('%s')

for iteration in range(10):
    proc = subprocess.run(['iptables', '-L', 'OUTPUT', '-n', '--line-numbers'], capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    matching_nums = []
    for l in lines:
        if 'owner UID match' in l or 'cross_' in l:
            parts = l.split()
            if parts and parts[0].isdigit():
                matching_nums.append(int(parts[0]))
    if not matching_nums:
        break
    for num in sorted(matching_nums, reverse=True):
        subprocess.run(['iptables', '-D', 'OUTPUT', str(num)], capture_output=True)

if os.path.exists('/etc/cross_rbac_users.txt'):
    os.remove('/etc/cross_rbac_users.txt')

subprocess.run(['systemctl', 'reload', 'sshd'], check=False)
print(f'NUCLEAR_PURGE_SUCCESS|Purged {len(to_purge)} users.')
"
`, rbacTierRegistry, rbacTierRegistry)
		fmt.Println(common.Cyan + "\n[+] Executing full-spectrum system sanitization..." + common.Reset)
		out, err := execRemote(client, wrapSudo(nuclearPythonScript))

		if err == nil && strings.Contains(out, "NUCLEAR_PURGE_SUCCESS") {
			fmt.Println(common.Green + common.Bold + "\n✅ SYSTEM SANITIZATION COMPLETE:" + common.Reset)
			fmt.Println("  • All created identities, home directories, stacked IPs, and firewall rules purged.")
			fmt.Println("  • RBAC tier registry cleared.")
			fmt.Println("  • Root and Native OS Admin accounts remain active and untouched.")
		} else {
			fmt.Printf(common.Red+"[!] Error during nuclear purge: %v\nOutput: %s\n"+common.Reset, err, out)
		}
		common.PausePrompt()
		return
	}

	username := selectUserInteractive(reader, client, "Select Target User for Enforcement:")
	if username == "" || username == "root" || username == "Administrator" {
		fmt.Println(common.Red + "[!] Invalid or protected user account." + common.Reset)
		common.PausePrompt()
		return
	}

	switch action {
	case "1":
		var qErr error
		if sig.OS == "windows" {
			_, qErr = execRemote(client, winQuarantineCmd(username))
		} else if sig.OS == "darwin" {
			_, qErr = execRemote(client, wrapSudo(fmt.Sprintf("dscl . -create /Users/%s AuthenticationAuthority ';DisabledUser;'", username)))
		} else {
			cmd := fmt.Sprintf("passwd -l %s && pkill -9 -u %s && rm -f /etc/sudoers.d/cross_rbac_%s /etc/ssh/sshd_config.d/rbac_%s.conf && systemctl reload sshd",
				username, username, username, username)
			_, qErr = execRemote(client, wrapSudo(cmd))
		}
		if qErr != nil {
			fmt.Println(common.Red + "[!] Failed to quarantine [" + username + "]: " + qErr.Error() + common.Reset)
		} else {
			fmt.Println(common.Green + "✅ User [" + username + "] is now fully quarantined and locked out." + common.Reset)
		}

	case "2":
		var uErr error
		if sig.OS == "windows" {
			_, uErr = execRemote(client, fmt.Sprintf(`powershell -Command "Enable-LocalUser -Name '%[1]s' -ErrorAction Stop; if(-not (Get-LocalUser -Name '%[1]s').Enabled){ throw 'Account is still disabled after Enable-LocalUser' }"`, username))
		} else if sig.OS == "darwin" {
			_, uErr = execRemote(client, wrapSudo(fmt.Sprintf("dscl . -delete /Users/%s AuthenticationAuthority", username)))
		} else {
			cmd := fmt.Sprintf("passwd -u %s", username)
			_, uErr = execRemote(client, wrapSudo(cmd))
		}
		if uErr != nil {
			fmt.Println(common.Red + "[!] Failed to unlock [" + username + "]: " + uErr.Error() + common.Reset)
		} else {
			fmt.Println(common.Green + "✅ User [" + username + "] unlocked successfully." + common.Reset)
		}

	case "3":
		fmt.Print(common.Red + "Type 'PURGE' to permanently delete user [" + username + "] and all files: " + common.Reset)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirm) == "PURGE" {
			if sig.OS == "windows" {
				if _, psErr := execRemote(client, winPurgeUserCmd(username)); psErr == nil {
					fmt.Println(common.Green + "✅ User [" + username + "] purged from Windows." + common.Reset)
				}
			} else if sig.OS == "darwin" {
				execRemote(client, wrapSudo(fmt.Sprintf("sysadminctl -deleteUser %s", username)))
				fmt.Println(common.Green + "✅ User [" + username + "] purged from macOS." + common.Reset)
			} else {
				singlePurgeScript := fmt.Sprintf(`
python3 -c "
import subprocess, os

u = '%[1]s'

subprocess.run(['pkill', '-9', '-u', u], check=False)
subprocess.run(['userdel', '-r', '-f', u], check=False)

for reg_path in ['/etc/cross_assigned_ips.txt', '/var/log/cross_assigned_ips.txt']:
    if os.path.exists(reg_path):
        new_lines = []
        with open(reg_path, 'r') as f:
            for line in f:
                if line.startswith(f'{u}:'):
                    ip_part = line.split(':')[1].strip()
                    subprocess.run(f'ip -o -4 addr show | awk \'{{print $2}}\' | xargs -I {{}} ip addr del {ip_part} dev {{}} 2>/dev/null', shell=True)
                else:
                    new_lines.append(line)
        with open(reg_path, 'w') as f:
            f.writelines(new_lines)

subprocess.run(['rm', '-f', f'/etc/sudoers.d/cross_rbac_{u}', f'/etc/sudoers.d/cross_init_{u}', f'/etc/ssh/sshd_config.d/rbac_{u}.conf'], check=False)

if os.path.exists('/etc/cross_rbac_users.txt'):
    lines = [l for l in open('/etc/cross_rbac_users.txt') if l.strip() != u]
    with open('/etc/cross_rbac_users.txt', 'w') as f:
        f.writelines(lines)

if os.path.exists('%[2]s'):
    lines = [l for l in open('%[2]s', errors='ignore') if not l.startswith(u + ':')]
    with open('%[2]s', 'w') as f:
        f.writelines(lines)

subprocess.run(['systemctl', 'reload', 'sshd'], check=False)
print('SINGLE_PURGE_SUCCESS')
"
`, username, rbacTierRegistry)
				out, err := execRemote(client, wrapSudo(singlePurgeScript))
				if err == nil && strings.Contains(out, "SINGLE_PURGE_SUCCESS") {
					fmt.Println(common.Green + "✅ User [" + username + "] has been completely removed from the system." + common.Reset)
				} else {
					fmt.Printf(common.Red+"[!] Error purging user: %v\nOutput: %s\n"+common.Reset, err, out)
				}
			}
		} else {
			fmt.Println(common.Yellow + "[!] Purge aborted." + common.Reset)
		}
	default:
		return
	}
	common.PausePrompt()
}

// -----------------------------------------------------------------------------
// [11] Master Node Switch
// -----------------------------------------------------------------------------
func manageMasterNode(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== MASTER NODE – SWITCH TARGET TO ANOTHER LAN MACHINE ===" + common.Reset)

	fmt.Printf("Current target host: %s\n", host)

	fmt.Println("\nDiscovering active hosts on the local subnet (ping sweep)...")
	discoverCmd := `nmap -sn 192.168.0.0/24 2>/dev/null | grep -E "Nmap scan|MAC" | grep -v "Host is up" || echo "No nmap, try arp-scan"`
	out, _ := execRemote(client, discoverCmd)
	fmt.Println(out)

	fmt.Print("\nEnter new target IP or hostname (or press Enter to cancel): ")
	newTarget, _ := reader.ReadString('\n')
	newTarget = strings.TrimSpace(newTarget)
	if newTarget == "" {
		fmt.Println(common.Yellow + "[!] No target entered. Returning." + common.Reset)
		common.PausePrompt()
		return
	}

	fmt.Printf(common.Yellow+"\nTo switch to %s, you must re‑authenticate from the main menu (the session will be replaced).\n"+common.Reset, newTarget)
	fmt.Println("Please exit this menu and use the 'Switch Target' option from the main menu, or use the command line.")
	common.PausePrompt()
}
