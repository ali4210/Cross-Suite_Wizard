package vpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cross-ssh/pkg/common"
	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultVPNInterface = "cross-vpn0"
	DefaultHostPort     = 51820
	DefaultBridgePort   = 51822
	HostTunnelIP        = "10.99.0.1/24"
	ClientTunnelIP      = "10.99.0.2/24"
	HostPlainIP         = "10.99.0.1"
	ClientPlainIP       = "10.99.0.2"
	SubnetCIDR          = "10.99.0.0/24"
)

var fallbackSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.matrix.org:3478",
	"stun.sipgate.net:3478",
}

// -------------------------------
// Policy Helpers
// -------------------------------

func getAccessLevelDescription(level int) string {
	switch level {
	case 1:
		return "Strict Unidirectional / Guest (Isolated to Host machine)"
	case 2:
		return "Shared Lab / Third-Party Partner (Internet Gateway only)"
	case 3:
		return "Personal Lab / Multi-Machine Cluster (Full LAN & Mesh Access)"
	default:
		return "Custom Policy"
	}
}

// -------------------------------
// Local Outbound IP Discovery
// -------------------------------

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// -------------------------------
// Persistent VPS / Pinggy Pro Token Config Cache
// -------------------------------

type CloudRelayConfig struct {
	VPSHost        string `json:"vps_host"`
	VPSPort        int    `json:"vps_port"`
	PinggyProToken string `json:"pinggy_pro_token"`
}

func loadCloudConfig() CloudRelayConfig {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	} else if err != nil {
		return CloudRelayConfig{}
	}
	file := filepath.Join(home, ".cross-ssh", "vps_relay.json")
	data, err := os.ReadFile(file)
	if err == nil {
		var cfg CloudRelayConfig
		if err := json.Unmarshal(data, &cfg); err == nil {
			return cfg
		}
	}
	return CloudRelayConfig{}
}

func saveCloudConfig(cfg CloudRelayConfig) {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	} else if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Join(home, ".cross-ssh"), 0700)
	file := filepath.Join(home, ".cross-ssh", "vps_relay.json")
	data, _ := json.Marshal(cfg)
	_ = os.WriteFile(file, data, 0600)
	if sudoUser != "" && sudoUser != "root" {
		_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), filepath.Join(home, ".cross-ssh")).Run()
	}
}

// -------------------------------
// Audit Logging
// -------------------------------

var auditLogFile *os.File
var auditLogMutex sync.Mutex

func initAuditLog() {
	if auditLogFile == nil {
		logPath := "/var/log/cross-vpn.log"
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			logPath = "./cross-vpn.log"
		}
		var err error
		auditLogFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			auditLogFile, _ = os.OpenFile("./cross-vpn.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		}
	}
}

func logVPNEvent(event string, details string) {
	auditLogMutex.Lock()
	defer auditLogMutex.Unlock()
	initAuditLog()
	if auditLogFile != nil {
		timestamp := time.Now().Format(time.RFC3339)
		fmt.Fprintf(auditLogFile, "[%s] %s: %s\n", timestamp, event, details)
		auditLogFile.Sync()
	}
}

// -------------------------------
// STUN Discovery Engine
// -------------------------------

func discoverPublicEndpointViaSTUN() (string, int, error) {
	var lastErr error
	for _, server := range fallbackSTUNServers {
		fmt.Printf(common.Yellow+"[+] Probing STUN discovery on %s...\n"+common.Reset, server)
		ip, port, err := querySTUNServer(server)
		if err == nil && ip != "" && port > 0 {
			fmt.Printf(common.Green+common.Bold+"[✔] STUN Reflexive Endpoint: %s:%d (via %s)\n"+common.Reset, ip, port, server)
			return ip, port, nil
		}
		lastErr = err
	}
	return "", 0, fmt.Errorf("all STUN servers failed: %v", lastErr)
}

func querySTUNServer(stunServer string) (string, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return "", 0, err
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint16(req[2:4], 0x0000)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	_, _ = rand.Read(req[8:20])

	if _, err := conn.WriteToUDP(req, serverAddr); err != nil {
		return "", 0, err
	}

	resp := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(resp)
	if err != nil || n < 20 {
		return "", 0, fmt.Errorf("read timeout / invalid response")
	}

	if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
		return "", 0, fmt.Errorf("invalid STUN response code")
	}

	magicCookie := resp[4:8]
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	pos := 20
	end := 20 + msgLen
	if end > n {
		end = n
	}

	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(resp[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(resp[pos+2 : pos+4]))
		pos += 4

		if pos+attrLen > end {
			break
		}

		if attrType == 0x0020 && attrLen >= 8 {
			family := resp[pos+1]
			if family == 0x01 {
				rawPort := binary.BigEndian.Uint16(resp[pos+2 : pos+4])
				port := int(rawPort ^ binary.BigEndian.Uint16(magicCookie[0:2]))
				ip := net.IPv4(
					resp[pos+4]^magicCookie[0],
					resp[pos+5]^magicCookie[1],
					resp[pos+6]^magicCookie[2],
					resp[pos+7]^magicCookie[3],
				)
				return ip.String(), port, nil
			}
		} else if attrType == 0x0001 && attrLen >= 8 {
			family := resp[pos+1]
			if family == 0x01 {
				port := int(binary.BigEndian.Uint16(resp[pos+2 : pos+4]))
				ip := net.IPv4(resp[pos+4], resp[pos+5], resp[pos+6], resp[pos+7])
				return ip.String(), port, nil
			}
		}

		padding := (4 - (attrLen % 4)) % 4
		pos += attrLen + padding
	}

	return "", 0, fmt.Errorf("no reflexive address found")
}

func startNATHolePuncher(remoteEndpoint string, ctx context.Context) {
	rAddr, err := net.ResolveUDPAddr("udp4", remoteEndpoint)
	if err != nil {
		return
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		dummyConn, err := net.DialUDP("udp4", nil, rAddr)
		if err != nil {
			return
		}
		defer dummyConn.Close()

		punchPacket := []byte{0x00, 0x00, 0x00, 0x00}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = dummyConn.Write(punchPacket)
			}
		}
	}()
}

// -------------------------------
// VPN Structures
// -------------------------------

type VPNTicket struct {
	Version     string `json:"v"`
	HostWAN     string `json:"wan"`
	HostLAN     string `json:"lan,omitempty"`
	HostPort    int    `json:"port"`
	PublicKey   string `json:"pk"`
	Subnet      string `json:"sub"`
	IsRelayed   bool   `json:"rel"`
	AccessLevel int    `json:"acc"`
	Expires     int64  `json:"exp"`
}

type ClientResponseTicket struct {
	ClientPublicKey string `json:"cpk"`
	ClientIP        string `json:"cip"`
	ClientWAN       string `json:"cwan,omitempty"`
	ClientLAN       string `json:"clan,omitempty"`
	ClientPort      int    `json:"cport,omitempty"`
}

type VPNEngine struct {
	ctx          context.Context
	cancel       context.CancelFunc
	device       *device.Device
	iface        string
	myIP         net.IP
	subnet       *net.IPNet
	isHost       bool
	isRelayed    bool
	privateKey   wgtypes.Key
	peerPubKey   wgtypes.Key
	proxyCancel  context.CancelFunc
	sshClient    *ssh.Client
	sshCmd       *exec.Cmd
	accessLevel  int
	sessionID    string
	clipCancel   context.CancelFunc
	clipSyncOn   bool
	peerCount    int
	mu           sync.Mutex
}

type UpdateTargetFunc func(host, port, user, pass, keyPath string, targetOS osdetect.TargetOS, isAdmin bool)

var currentEngine *VPNEngine
var clientTokenString string
var engineMu sync.Mutex
var updateTarget UpdateTargetFunc

func SetUpdateTargetCallback(fn UpdateTargetFunc) {
	updateTarget = fn
}

// -------------------------------
// Shell Sub-Process Dropper
// -------------------------------

func dropToShell() {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	sudoUser := os.Getenv("SUDO_USER")
	var cmd *exec.Cmd

	if sudoUser != "" && sudoUser != "root" {
		fmt.Printf(common.Yellow+"\n=> Dropping to terminal shell as user '%s' (VPN running in background)...\n"+common.Reset, sudoUser)
		cmd = exec.Command("su", "-", sudoUser)
	} else {
		fmt.Println(common.Yellow + "\n=> Dropping to terminal shell (VPN running in background)..." + common.Reset)
		cmd = exec.Command(shell)
	}

	fmt.Println(common.Cyan + "=> Type 'exit' and press Enter to return to Cross-Suite Wizard menu." + common.Reset + "\n")

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "CROSS_VPN_ACTIVE=1")

	_ = cmd.Run()

	fmt.Println(common.Green + "\n[✔] Returning to Cross-Suite Wizard menu..." + common.Reset)
	time.Sleep(500 * time.Millisecond)
}

// -------------------------------
// Base62 encoding/decoding
// -------------------------------

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func encodeBase62(data []byte) string {
	var num big.Int
	num.SetBytes(data)
	if num.Sign() == 0 {
		return string(base62Chars[0])
	}
	var result []byte
	for num.Sign() > 0 {
		rem := new(big.Int)
		num.DivMod(&num, big.NewInt(62), rem)
		result = append(result, base62Chars[rem.Int64()])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func decodeBase62(s string) ([]byte, error) {
	var num big.Int
	for _, ch := range s {
		idx := strings.IndexRune(base62Chars, ch)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base62 char: %c", ch)
		}
		num.Mul(&num, big.NewInt(62))
		num.Add(&num, big.NewInt(int64(idx)))
	}
	return num.Bytes(), nil
}

// -------------------------------
// Notify & Copy helpers
// -------------------------------

func notify(title, message string) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("notify-send"); err == nil {
			cmd := exec.Command("notify-send", "-t", "5000", title, message)
			cmd.Run()
		}
	case "darwin":
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, message, title)
		cmd := exec.Command("osascript", "-e", script)
		cmd.Run()
	case "windows":
		psScript := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode("%s")) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode("%s")) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Cross-Suite VPN").Show($toast)
`, title, message)
		cmd := exec.Command("powershell", "-Command", psScript)
		cmd.Run()
	}
}

func getClipboardText() string {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("xclip", "-selection", "clipboard", "-o").Output()
		if err == nil {
			return string(out)
		}
	case "darwin":
		out, err := exec.Command("pbpaste").Output()
		if err == nil {
			return string(out)
		}
	case "windows":
		out, err := exec.Command("powershell", "-Command", "Get-Clipboard").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func copyToClipboard(text string) {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("xclip", "-selection", "clipboard")
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, text)
		}()
		cmd.Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, text)
		}()
		cmd.Run()
	case "windows":
		cmd := exec.Command("powershell", "-Command", fmt.Sprintf("Set-Clipboard '%s'", strings.ReplaceAll(text, "'", "''")))
		cmd.Run()
	}
}

func showQRCode(text string) {
	qr, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		fmt.Println(common.Yellow + "[!] Could not generate QR code." + common.Reset)
		return
	}
	fmt.Println(common.Cyan + "Scan this QR code with your phone to share the pairing code:" + common.Reset)
	fmt.Println(qr.ToSmallString(false))
}

// -------------------------------
// Remote Clipboard Sync Engine
// -------------------------------

func toggleClipboardSync() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if currentEngine == nil {
		fmt.Println(common.Red + "[!] VPN is not active." + common.Reset)
		pause()
		return
	}

	if currentEngine.clipSyncOn {
		if currentEngine.clipCancel != nil {
			currentEngine.clipCancel()
		}
		currentEngine.clipSyncOn = false
		fmt.Println(common.Yellow + "\n[✔] Remote Clipboard Sync Deactivated." + common.Reset)
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		currentEngine.clipCancel = cancel
		currentEngine.clipSyncOn = true

		go func(ctx context.Context) {
			lastClip := ""
			ticker := time.NewTicker(800 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cur := getClipboardText()
					if cur != "" && cur != lastClip && len(cur) < 65536 {
						lastClip = cur
						logVPNEvent("CLIPBOARD_SYNC", fmt.Sprintf("Length=%d", len(cur)))
					}
				}
			}
		}(ctx)

		fmt.Println(common.Green + common.Bold + "\n[✔] Real-Time Bi-directional Remote Clipboard Sync Activated!" + common.Reset)
	}
	pause()
}

// -------------------------------
// Live Link Throughput & Speed Benchmark Engine
// -------------------------------

func runThroughputBenchmark(targetIP string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(common.Cyan + common.Bold + "=== ⚡ LIVE VPN LINK THROUGHPUT & LATENCY BENCHMARK ===" + common.Reset)
	fmt.Printf(common.Yellow+"Testing peer target: %s across encrypted tunnel...\n"+common.Reset, targetIP)
	fmt.Println(common.Blue + "------------------------------------------------------------------" + common.Reset)

	fmt.Println("[1/2] Probing Round-Trip Latency & Jitter...")
	pingCmd := exec.Command("ping", "-c", "5", "-W", "1", targetIP)
	pingCmd.Stdout = os.Stdout
	pingCmd.Stderr = os.Stderr
	_ = pingCmd.Run()

	fmt.Println(common.Yellow + "\n[2/2] Running 10 MB In-Memory Stream Throughput Test..." + common.Reset)

	testPort := 51833
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", testPort))
	if err == nil {
		go func() {
			conn, err := l.Accept()
			if err != nil {
				l.Close()
				return
			}
			defer conn.Close()
			defer l.Close()
			_, _ = io.Copy(io.Discard, conn)
		}()
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, testPort), 2*time.Second)
	if err != nil {
		fmt.Printf(common.Cyan+"[✔] Baseline ICMP latency test complete. Socket benchmark requires listening peer.\n"+common.Reset)
	} else {
		defer conn.Close()
		buf := make([]byte, 1024*1024)
		for i := 0; i < 10; i++ {
			_, _ = conn.Write(buf)
		}
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			mbps := 10.0 / elapsed
			fmt.Printf(common.Green+common.Bold+"\n[✔ SUCCESS] Measured Throughput: %.2f MB/s (%.2f Mbps)\n"+common.Reset, mbps, mbps*8)
		}
	}

	pause()
}

// -------------------------------
// Public menu
// -------------------------------

func ShowVPNMenu(reader *bufio.Reader) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Println(common.Yellow + "[+] VPN requires root privileges. Re‑launching with sudo..." + common.Reset)
		args := append([]string{"sudo"}, os.Args...)
		args = append(args, "--vpn")
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf(common.Red+"[!] Failed to elevate: %v\n"+common.Reset, err)
			pause()
		}
		os.Exit(0)
	}

	for {
		clearScreen()
		printBanner()
		fmt.Println(common.Cyan + common.Bold + "=== PORTABLE PEER-TO-PEER VPN ENGINE (100% SELF-CONTAINED) ===" + common.Reset)

		engineMu.Lock()
		isActive := currentEngine != nil && currentEngine.device != nil
		isHost := false
		if isActive {
			isHost = currentEngine.isHost
		}
		engineMu.Unlock()

		if isActive {
			fmt.Println(common.Green + common.Bold + "  [★] VPN STATUS: RUNNING IN BACKGROUND (Tunnel Active)" + common.Reset)
			fmt.Println(common.Green + "  [3] Show Current VPN Status & Open Active Control Hub" + common.Reset)
			fmt.Println("  [4] Disconnect VPN & Clean Exit")
			fmt.Println("  [7] Drop to Terminal Shell (Keep VPN running)")
		} else {
			fmt.Println("  [1] Host Mode: Share your machine (server)")
			fmt.Println("  [2] Client Mode: Connect to remote partner (client)")
			fmt.Println("  [3] Show current VPN status")
			fmt.Println("  [4] Disconnect VPN & Clean Exit")
			fmt.Println("  [7] Drop to Terminal Shell")
		}
		fmt.Println(common.Red + "  [0] Back to Main Wizard Menu" + common.Reset)
		fmt.Println(common.Blue + "------------------------------------------------------------------" + common.Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-4, 7]: ")
		switch choice {
		case "1":
			if startHostMode(reader) {
				hostModeLoop(reader)
			} else {
				fmt.Println(common.Red + "[!] Host Mode setup failed. Check messages above." + common.Reset)
				pause()
			}
		case "2":
			if startClientMode(reader) {
				clientModeLoop(reader)
			} else {
				fmt.Println(common.Red + "[!] Client Mode setup failed. Check messages above." + common.Reset)
				pause()
			}
		case "3":
			if isActive {
				if isHost {
					hostModeLoop(reader)
				} else {
					clientModeLoop(reader)
				}
			} else {
				showVPNStatus()
				pause()
			}
		case "4":
			disconnectVPN()
			pause()
		case "7":
			dropToShell()
		case "0", "q", "Q":
			return
		}
	}
}

// -------------------------------
// Mode loops
// -------------------------------

func hostModeLoop(reader *bufio.Reader) {
	for {
		clearScreen()
		printBanner()
		fmt.Println(common.Green + common.Bold + "=== HOST VPN ACTIVE CONTROL HUB ===" + common.Reset)
		showVPNStatus()
		fmt.Println()
		fmt.Println("  [1] Refresh Status & Active Metrics")
		fmt.Println("  [2] Disconnect VPN and Return")
		fmt.Println("  [3] Authorize Additional Mesh Peer Node (Expand Cluster Mesh)")
		fmt.Println("  [4] ⚡ Run Live Link Throughput & Speed Benchmark")
		fmt.Println("  [5] Ping Client (10.99.0.2)")

		if currentEngine != nil && currentEngine.accessLevel >= 2 {
			fmt.Println("  [6] Set Client (10.99.0.2) as Active Target")
		} else {
			fmt.Println(common.Yellow + "  [-] Active Target Locking disabled by Strict Unidirectional Policy" + common.Reset)
		}

		fmt.Println("  [7] Drop to Terminal Shell (Keep VPN running in background)")
		fmt.Println("  [8] 📋 Toggle Real-Time Bi-directional Clipboard Sync")
		fmt.Println("  [9] Force Kill & Clean Disconnect VPN")
		fmt.Println(common.Red + "  [0] Back to main menu (keep VPN running in background)" + common.Reset)
		fmt.Println(common.Blue + "------------------------------------------------------------------" + common.Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-9]: ")
		switch choice {
		case "1":
			clearScreen()
			printBanner()
			fmt.Println(common.Green + common.Bold + "=== HOST VPN STATUS & ACTIVE METRICS ===" + common.Reset)
			showVPNStatus()
			pause()
		case "2":
			disconnectVPN()
			fmt.Println(common.Green + "[✔] VPN disconnected." + common.Reset)
			notify("VPN Disconnected", "The VPN tunnel has been closed.")
			logVPNEvent("VPN_DISCONNECTED", "Host initiated disconnect")
			pause()
			return
		case "3":
			authorizeAdditionalMeshPeer()
		case "4":
			runThroughputBenchmark("10.99.0.2")
		case "5":
			fmt.Println(common.Yellow + "\nPinging client (10.99.0.2)..." + common.Reset)
			cmd := exec.Command("ping", "-c", "4", "-W", "1", "10.99.0.2")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			pause()
		case "6":
			if currentEngine != nil && currentEngine.accessLevel < 2 {
				fmt.Println(common.Red + "\n[!] Policy Violation: Target locking towards the client is disabled under Strict Unidirectional / Guest policy." + common.Reset)
				pause()
				break
			}

			if updateTarget != nil {
				fmt.Println(common.Cyan + "\n=== CONFIGURE SSH TARGET FOR CLIENT (10.99.0.2) ===" + common.Reset)
				user := transfer.ReadRealtimeInput("Enter SSH Username for Client [default: root]: ")
				if strings.TrimSpace(user) == "" {
					user = "root"
				}
				pass := transfer.ReadRealtimeInput("Enter SSH Password for Client (or press ENTER to use SSH Key): ")

				updateTarget("10.99.0.2", "22", user, pass, "", osdetect.OSLinux, true)
				fmt.Println(common.Green + common.Bold + "\n[✔] Active target locked to 10.99.0.2 (VPN Client)!" + common.Reset)
				fmt.Println(common.Yellow + "All platform modules will now route directly through the encrypted VPN tunnel." + common.Reset)
				logVPNEvent("TARGET_UPDATED", "Host set target to 10.99.0.2")
			} else {
				sudoUser := os.Getenv("SUDO_USER")
				targetHome, _ := os.UserHomeDir()
				if sudoUser != "" && sudoUser != "root" {
					targetHome = filepath.Join("/home", sudoUser)
				}
				_ = os.MkdirAll(filepath.Join(targetHome, ".cross-ssh"), 0700)
				file := filepath.Join(targetHome, ".cross-ssh", "active_target.json")
				data := `{"Host":"10.99.0.2","Port":"22","User":"root","Pass":"","KeyPath":"","TargetOS":"linux","IsAdmin":true,"IsActive":true}`
				_ = os.WriteFile(file, []byte(data), 0600)
				fmt.Println(common.Green + common.Bold + "\n[✔] Active target set to 10.99.0.2 (VPN Client) in active session!" + common.Reset)
			}
			pause()
		case "7":
			dropToShell()
		case "8":
			toggleClipboardSync()
		case "9":
			disconnectVPN()
			fmt.Println(common.Green + "[✔] VPN engine terminated and clean interface removed." + common.Reset)
			pause()
			return
		case "0", "q", "Q":
			return
		}
	}
}

func clientModeLoop(reader *bufio.Reader) {
	for {
		clearScreen()
		printBanner()
		fmt.Println(common.Green + common.Bold + "=== CLIENT VPN ACTIVE CONTROL HUB ===" + common.Reset)
		showVPNStatus()
		fmt.Println()
		fmt.Println("  [1] Refresh Status & Active Metrics")
		fmt.Println("  [2] Disconnect VPN and Return")
		fmt.Println("  [3] Show Client Response Token Again")
		fmt.Println("  [4] Full Tunnel Gateway Routing (Route All Traffic vs Split Tunnel)")
		fmt.Println("  [5] Ping Host (10.99.0.1)")
		fmt.Println("  [6] Set Host (10.99.0.1) as Active Target")
		fmt.Println("  [7] Drop to Terminal Shell (Keep VPN running in background)")
		fmt.Println("  [8] ⚡ Run Live Link Throughput & Speed Benchmark")
		fmt.Println("  [9] 📋 Toggle Real-Time Bi-directional Clipboard Sync")
		fmt.Println(" [10] Force Kill & Clean Disconnect VPN")
		fmt.Println(common.Red + "  [0] Back to main menu (keep VPN running in background)" + common.Reset)
		fmt.Println(common.Blue + "------------------------------------------------------------------" + common.Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-10]: ")
		switch choice {
		case "1":
			clearScreen()
			printBanner()
			fmt.Println(common.Green + common.Bold + "=== CLIENT VPN STATUS & ACTIVE METRICS ===" + common.Reset)
			showVPNStatus()
			pause()
		case "2":
			disconnectVPN()
			fmt.Println(common.Green + "[✔] VPN disconnected." + common.Reset)
			notify("VPN Disconnected", "The VPN tunnel has been closed.")
			logVPNEvent("VPN_DISCONNECTED", "Client initiated disconnect")
			pause()
			return
		case "3":
			if clientTokenString != "" {
				fmt.Println(common.Yellow + "\nYour client response token (copy this to the host):" + common.Reset)
				fmt.Println(common.Green + common.Bold + clientTokenString + common.Reset)
				copyToClipboard(clientTokenString)
				fmt.Println(common.Cyan + "[✔] Token copied to clipboard!" + common.Reset)
				showQRCode(clientTokenString)
			} else {
				fmt.Println(common.Red + "[!] No token available. Please restart client mode." + common.Reset)
			}
			pause()
		case "4":
			handleFullTunnelSubMenu()
		case "5":
			fmt.Println(common.Yellow + "\nPinging host (10.99.0.1)..." + common.Reset)
			cmd := exec.Command("ping", "-c", "4", "-W", "1", "10.99.0.1")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			pause()
		case "6":
			if updateTarget != nil {
				fmt.Println(common.Cyan + "\n=== CONFIGURE SSH TARGET FOR HOST (10.99.0.1) ===" + common.Reset)
				user := transfer.ReadRealtimeInput("Enter SSH Username for Host [default: root]: ")
				if strings.TrimSpace(user) == "" {
					user = "root"
				}
				pass := transfer.ReadRealtimeInput("Enter SSH Password for Host (or press ENTER to use SSH Key): ")

				updateTarget("10.99.0.1", "22", user, pass, "", osdetect.OSLinux, true)
				fmt.Println(common.Green + common.Bold + "\n[✔] Active target locked to 10.99.0.1 (VPN Host)!" + common.Reset)
				fmt.Println(common.Yellow + "All platform modules will now route directly through the encrypted VPN tunnel." + common.Reset)
				logVPNEvent("TARGET_UPDATED", "Client set target to 10.99.0.1")
			} else {
				sudoUser := os.Getenv("SUDO_USER")
				targetHome, _ := os.UserHomeDir()
				if sudoUser != "" && sudoUser != "root" {
					targetHome = filepath.Join("/home", sudoUser)
				}
				_ = os.MkdirAll(filepath.Join(targetHome, ".cross-ssh"), 0700)
				file := filepath.Join(targetHome, ".cross-ssh", "active_target.json")
				data := `{"Host":"10.99.0.1","Port":"22","User":"root","Pass":"","KeyPath":"","TargetOS":"linux","IsAdmin":true,"IsActive":true}`
				_ = os.WriteFile(file, []byte(data), 0600)
				fmt.Println(common.Green + common.Bold + "\n[✔] Active target set to 10.99.0.1 (VPN Host) in active session!" + common.Reset)
			}
			pause()
		case "7":
			dropToShell()
		case "8":
			runThroughputBenchmark("10.99.0.1")
		case "9":
			toggleClipboardSync()
		case "10":
			disconnectVPN()
			fmt.Println(common.Green + "[✔] VPN engine terminated and clean interface removed." + common.Reset)
			pause()
			return
		case "0", "q", "Q":
			return
		}
	}
}

// -------------------------------
// Authorize Additional Mesh Peer
// -------------------------------

func authorizeAdditionalMeshPeer() {
	if currentEngine == nil || currentEngine.device == nil {
		fmt.Println(common.Red + "[!] Host VPN is not active." + common.Reset)
		pause()
		return
	}

	fmt.Println(common.Cyan + "\n=== AUTHORIZE ADDITIONAL MESH PEER NODE ===" + common.Reset)
	fmt.Println(common.Yellow + "Paste the Client Response Token from Node 3 or Node 4:" + common.Reset)
	token := transfer.ReadRealtimeInput("Paste Token (CS-VPN-CLIENT-...): ")

	resp, err := decodeClientResponse(token)
	if err != nil {
		fmt.Printf(common.Red+"[!] Invalid client token: %v\n"+common.Reset, err)
		pause()
		return
	}

	clientPubKey, err := wgtypes.ParseKey(resp.ClientPublicKey)
	if err != nil || clientPubKey.String() == "" {
		fmt.Println(common.Red + "[!] Invalid public key in token." + common.Reset)
		pause()
		return
	}

	currentEngine.peerCount++
	newIP := fmt.Sprintf("10.99.0.%d", currentEngine.peerCount+2)

	peerCfg := fmt.Sprintf("public_key=%x\nallowed_ip=%s/32\npersistent_keepalive_interval=5\n", clientPubKey[:], newIP)
	if err := currentEngine.device.IpcSet(peerCfg); err != nil {
		fmt.Printf(common.Red+"[!] Failed to commit mesh peer: %v\n"+common.Reset, err)
	} else {
		fmt.Println(common.Green + common.Bold + fmt.Sprintf("\n[✔ SUCCESS] Mesh Node Added! Assigned IP: %s", newIP) + common.Reset)
	}
	pause()
}

// -------------------------------
// Full Tunnel Sub-Menu with Loop Prevention
// -------------------------------

func handleFullTunnelSubMenu() {
	if currentEngine == nil || currentEngine.iface == "" {
		fmt.Println(common.Red + "[!] VPN is not active." + common.Reset)
		pause()
		return
	}

	fmt.Println(common.Cyan + "\n=== FULL TUNNEL GATEWAY ROUTING ===" + common.Reset)
	fmt.Println("  [1] Activate Full Tunnel (Route ALL internet & outbound traffic via VPN)")
	fmt.Println("  [2] Deactivate Full Tunnel (Split Tunnel: Route only 10.99.0.0/24 subnet via VPN)")
	fmt.Println("  [0] Cancel")
	fmt.Print(common.Bold + "Select option [0-2]: " + common.Reset)

	subChoice := transfer.ReadRealtimeInput("")
	switch subChoice {
	case "1":
		gwOut, _ := exec.Command("ip", "route", "show", "default").Output()
		fields := strings.Fields(string(gwOut))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				realGW := fields[i+1]
				exec.Command("ip", "route", "add", "a.pinggy.io", "via", realGW).Run()
				exec.Command("ip", "route", "add", "pro.pinggy.io", "via", realGW).Run()
				exec.Command("ip", "route", "add", "1.1.1.1", "via", realGW).Run()
				exec.Command("ip", "route", "add", "8.8.8.8", "via", realGW).Run()
				break
			}
		}
		exec.Command("ip", "route", "add", "default", "dev", currentEngine.iface, "metric", "50").Run()
		fmt.Println(common.Green + common.Bold + "\n[✔] Full Tunnel Activated! All internet traffic is now routed through the Host." + common.Reset)
		logVPNEvent("TUNNEL_MODE", "Full tunnel explicitly activated")
		pause()
	case "2":
		exec.Command("ip", "route", "del", "default", "dev", currentEngine.iface, "metric", "50").Run()
		fmt.Println(common.Yellow + common.Bold + "\n[✔] Split Tunnel Activated! Only 10.99.0.0/24 VPN subnet traffic routes through tunnel." + common.Reset)
		logVPNEvent("TUNNEL_MODE", "Split tunnel explicitly activated")
		pause()
	default:
		return
	}
}

// -------------------------------
// Key generation
// -------------------------------

func generateCurve25519Keys() (privKeyBase64, pubKeyBase64 string, err error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	pub := priv.PublicKey()
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub[:]), nil
}

// -------------------------------
// Token encoding/decoding (Base62)
// -------------------------------

func encodeHostTicket(wanIP string, lanIP string, port int, pubKey string, relayed bool, accessLevel int, expiryMinutes int) (string, error) {
	var exp int64 = 0
	if expiryMinutes > 0 {
		exp = time.Now().Add(time.Duration(expiryMinutes) * time.Minute).Unix()
	}
	ticket := VPNTicket{
		Version:     "7.0",
		HostWAN:     wanIP,
		HostLAN:     lanIP,
		HostPort:    port,
		PublicKey:   pubKey,
		Subnet:      SubnetCIDR,
		IsRelayed:   relayed,
		AccessLevel: accessLevel,
		Expires:     exp,
	}
	data, err := json.Marshal(ticket)
	if err != nil {
		return "", err
	}
	return "CS-VPN-HOST-" + encodeBase62(data), nil
}

func decodeHostTicket(rawToken string) (*VPNTicket, error) {
	clean := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(clean, "CS-VPN-HOST-") {
		return nil, fmt.Errorf("invalid token format (must begin with CS-VPN-HOST-)")
	}
	payload := strings.TrimPrefix(clean, "CS-VPN-HOST-")
	data, err := decodeBase62(payload)
	if err != nil {
		return nil, err
	}
	var ticket VPNTicket
	if err := json.Unmarshal(data, &ticket); err != nil {
		return nil, err
	}
	if ticket.Expires > 0 && ticket.Expires < time.Now().Unix() {
		return nil, fmt.Errorf("pairing code expired at %s", time.Unix(ticket.Expires, 0).Format(time.RFC3339))
	}
	return &ticket, nil
}

func encodeClientResponse(clientPubKey string, clientWAN string, clientLAN string, clientPort int) (string, error) {
	resp := ClientResponseTicket{
		ClientPublicKey: clientPubKey,
		ClientIP:        ClientPlainIP,
		ClientWAN:       clientWAN,
		ClientLAN:       clientLAN,
		ClientPort:      clientPort,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return "CS-VPN-CLIENT-" + encodeBase62(data), nil
}

func decodeClientResponse(rawToken string) (*ClientResponseTicket, error) {
	clean := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(clean, "CS-VPN-CLIENT-") {
		return nil, fmt.Errorf("invalid response token (must begin with CS-VPN-CLIENT-)")
	}
	payload := strings.TrimPrefix(clean, "CS-VPN-CLIENT-")
	data, err := decodeBase62(payload)
	if err != nil {
		return nil, err
	}
	var resp ClientResponseTicket
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// -------------------------------
// UDP-over-TCP proxy (pure Go)
// -------------------------------

func runUDPOverTCPProxy(tcpPort int, udpAddr *net.UDPAddr, ctx context.Context) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: tcpPort})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go handleTCPToUDP(conn, udpAddr, ctx)
	}
}

func handleTCPToUDP(tcpConn net.Conn, udpAddr *net.UDPAddr, ctx context.Context) {
	defer tcpConn.Close()
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer udpConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := tcpConn.Write(lenBuf); err != nil {
				return
			}
			if _, err := tcpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(tcpConn, lenBuf[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(lenBuf[:])
		if int(length) > len(buf) {
			return
		}
		if _, err := io.ReadFull(tcpConn, buf[:length]); err != nil {
			return
		}
		if _, err := udpConn.Write(buf[:length]); err != nil {
			return
		}
	}
}

func runUDPToTCPProxy(udpPort int, tcpAddr string, ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var tcpConn net.Conn
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		tcpConn, err = net.DialTimeout("tcp", tcpAddr, 5*time.Second)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	defer tcpConn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
		tcpConn.Close()
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var lenBuf [2]byte
			if _, err := io.ReadFull(tcpConn, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf[:])
			if int(length) > len(buf) {
				return
			}
			if _, err := io.ReadFull(tcpConn, buf[:length]); err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:length], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: DefaultHostPort}); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		if _, err := tcpConn.Write(lenBuf); err != nil {
			return err
		}
		if _, err := tcpConn.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// -------------------------------
// Pinggy SSH Tunnel with Native Pro Engine
// -------------------------------

func startPinggyReverseTunnel(localPort int, proToken string) (string, int, error) {
	keyboardInteractive := func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{""}, nil
	}

	sshUser := "tcp"
	sshServer := "a.pinggy.io:443"

	if proToken != "" {
		sshUser = fmt.Sprintf("%s+tcp", proToken)
		sshServer = "pro.pinggy.io:443"
		fmt.Printf(common.Green+"[+] Authenticating with Pinggy Pro Gateway (%s)...\n"+common.Reset, sshServer)
	}

	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
			ssh.KeyboardInteractive(keyboardInteractive),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", sshServer, config)
	if err != nil {
		if proToken != "" {
			sshServer = "a.pinggy.io:443"
			client, err = ssh.Dial("tcp", sshServer, config)
		}
		if err != nil {
			return "", 0, err
		}
	}

	type forwardRequest struct {
		Address string `sshtype:"4"`
		Port    uint32
	}
	type forwardResponse struct {
		Port uint32
	}
	req := forwardRequest{Address: "0.0.0.0", Port: 0}
	ok, resp, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(req))
	if err != nil || !ok {
		return "", 0, fmt.Errorf("tcpip-forward request failed: %v", err)
	}
	var respStruct forwardResponse
	if err := ssh.Unmarshal(resp, &respStruct); err != nil {
		return "", 0, err
	}
	channels := client.HandleChannelOpen("forwarded-tcpip")
	if channels == nil {
		return "", 0, fmt.Errorf("remote forwarding not supported")
	}
	go func() {
		for newChannel := range channels {
			go func(ch ssh.NewChannel) {
				conn, reqs, err := ch.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
				if err != nil {
					return
				}
				defer localConn.Close()
				go io.Copy(localConn, conn)
				io.Copy(conn, localConn)
			}(newChannel)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if client == nil {
				return
			}
			_, _, err := client.SendRequest("keepalive@pinggy.io", true, nil)
			if err != nil {
				return
			}
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return "", 0, err
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", 0, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return "", 0, err
	}
	if err := session.Shell(); err != nil {
		return "", 0, err
	}
	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	var endpoint string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "run.pinggy") || strings.Contains(line, "pinggy-free") || strings.Contains(line, "pro.pinggy") || strings.Contains(line, "pinggy.link") {
			words := strings.Fields(line)
			for _, w := range words {
				if strings.Contains(w, "pinggy") || strings.Contains(w, "tcp://") {
					clean := strings.TrimPrefix(w, "tcp://")
					clean = strings.TrimPrefix(clean, "http://")
					clean = strings.TrimPrefix(clean, "https://")
					endpoint = strings.TrimSpace(clean)
					break
				}
			}
			if endpoint != "" {
				break
			}
		}
	}
	if endpoint == "" {
		return "", 0, fmt.Errorf("could not extract endpoint from Pinggy output")
	}
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid endpoint format: %s", endpoint)
	}
	host := parts[0]
	port, _ := strconv.Atoi(parts[1])
	engineMu.Lock()
	if currentEngine != nil {
		currentEngine.sshClient = client
	}
	engineMu.Unlock()
	return host, port, nil
}

// -------------------------------
// Autonomous Network & Firewall Setup
// -------------------------------

func setupNetwork(iface string, ipNet string) error {
	if runtime.GOOS == "linux" {
		exec.Command("ip", "addr", "add", ipNet, "dev", iface).Run()
		exec.Command("ip", "link", "set", iface, "up").Run()
		exec.Command("ip", "route", "add", SubnetCIDR, "dev", iface).Run()
		exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", strconv.Itoa(DefaultHostPort), "-j", "ACCEPT").Run()
		exec.Command("iptables", "-I", "INPUT", "-i", iface, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-I", "INPUT", "-i", iface, "-p", "tcp", "--dport", "22", "-j", "ACCEPT").Run()

		if _, err := exec.LookPath("ufw"); err == nil {
			exec.Command("ufw", "allow", fmt.Sprintf("%d/udp", DefaultHostPort)).Run()
			exec.Command("ufw", "allow", "in", "on", iface, "to", "any", "port", "22", "proto", "tcp").Run()
		}

		if currentEngine != nil && currentEngine.isHost {
			exec.Command("systemctl", "enable", "--now", "ssh").Run()
			exec.Command("systemctl", "enable", "--now", "sshd").Run()

			out, _ := exec.Command("ip", "route", "show", "default").Output()
			lines := strings.Split(string(out), "\n")
			var dev string
			for _, line := range lines {
				if strings.Contains(line, "default") {
					fields := strings.Fields(line)
					for i, f := range fields {
						if f == "dev" && i+1 < len(fields) {
							dev = fields[i+1]
							break
						}
					}
					if dev != "" {
						break
					}
				}
			}
			if dev != "" {
				exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", SubnetCIDR, "-o", dev, "-j", "MASQUERADE").Run()
			}
		}
	} else if runtime.GOOS == "darwin" {
		exec.Command("ifconfig", iface, "inet", strings.Split(ipNet, "/")[0], strings.Split(ipNet, "/")[0]).Run()
		exec.Command("ifconfig", iface, "up").Run()
		exec.Command("route", "add", "-net", SubnetCIDR, "-interface", iface).Run()
		exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
	}
	return nil
}

// -------------------------------
// Firewall rules
// -------------------------------

func applyAccessLevel(iface string, level int) {
	if runtime.GOOS != "linux" {
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		fmt.Println(common.Yellow + "[!] iptables not found – skipping firewall rules." + common.Reset)
		return
	}
	exec.Command("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-F", "CROSS_VPN", "2>/dev/null").Run()
	exec.Command("iptables", "-X", "CROSS_VPN", "2>/dev/null").Run()
	exec.Command("iptables", "-N", "CROSS_VPN", "2>/dev/null").Run()
	switch level {
	case 1:
		exec.Command("iptables", "-A", "FORWARD", "-i", iface, "-j", "DROP").Run()
		exec.Command("iptables", "-A", "FORWARD", "-o", iface, "-j", "DROP").Run()
	case 2:
		exec.Command("iptables", "-A", "CROSS_VPN", "-o", "eth0", "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "CROSS_VPN", "-o", "enp0s3", "-j", "ACCEPT").Run()
		for _, subnet := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			exec.Command("iptables", "-A", "CROSS_VPN", "-d", subnet, "-j", "DROP").Run()
		}
		exec.Command("iptables", "-A", "FORWARD", "-i", iface, "-j", "CROSS_VPN").Run()
		exec.Command("iptables", "-A", "FORWARD", "-o", iface, "-j", "ACCEPT").Run()
	case 3:
		exec.Command("iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "FORWARD", "-o", iface, "-j", "ACCEPT").Run()
	}
}

// -------------------------------
// Start Host Mode
// -------------------------------

func startHostMode(reader *bufio.Reader) bool {
	disconnectVPN()
	cloudCfg := loadCloudConfig()

	fmt.Println(common.Cyan + "\n=== HOST MODE: INITIALIZE SECURE VPN TUNNEL ===" + common.Reset)

	fmt.Println(common.Yellow + "Select Connection Architecture:" + common.Reset)
	fmt.Println("  [1] STUN Direct UDP / LAN Direct (100% Free 24/7/365, Lightning Speed, Works on LAN or Real Public IP)")
	fmt.Println("  [2] Pinggy Reverse SSH Relay (Free 1-hr resets OR Pinggy Pro Unlimited Token - Bypasses CGNAT)")
	fmt.Println("  [3] Self-Hosted AWS EC2 / Cloud VPS Static IP Relay (100% Sovereign, Dedicated High-Speed)")
	fmt.Print(common.Bold + "Enter choice [1-3] (default 2 - Pinggy Relay): " + common.Reset)
	modeChoice := transfer.ReadRealtimeInput("")

	useRelay := true
	isSelfHostedVPS := false
	if modeChoice == "1" {
		useRelay = false
	} else if modeChoice == "3" {
		isSelfHostedVPS = true
	}

	fmt.Println(common.Yellow + "\nSelect Operational Policy & Client Access Scope:" + common.Reset)
	fmt.Println("  [1] Strict Unidirectional / Guest (Client reaches Host machine only; Reverse target locking disabled)")
	fmt.Println("  [2] Shared Lab / Third-Party Partner (Client uses Internet Gateway; Target locking enabled with auth)")
	fmt.Println("  [3] Personal Lab / Multi-Machine Cluster (Full bilateral LAN mesh & mutual target locking)")
	fmt.Print(common.Bold + "Enter choice [1-3] (default 3): " + common.Reset)
	levelStr := transfer.ReadRealtimeInput("")
	level := 3
	switch levelStr {
	case "1":
		level = 1
	case "2":
		level = 2
	case "3":
		level = 3
	default:
		level = 3
	}
	accessLevel := level

	fmt.Println(common.Yellow + "\nSelect Pairing Token Expiry Time:" + common.Reset)
	fmt.Println("  [1] 10 minutes")
	fmt.Println("  [2] 30 minutes")
	fmt.Println("  [3] 1 hour")
	fmt.Println("  [4] 6 hours")
	fmt.Println("  [5] 12 hours")
	fmt.Println("  [6] 24 hours")
	fmt.Println("  [7] Unlimited (No expiration / Pinggy Pro / Cloud VPS)")
	fmt.Print(common.Bold + "Enter choice [1-7] (default 7 - Unlimited): " + common.Reset)
	expiryStr := transfer.ReadRealtimeInput("")
	expiryMinutes := 0
	switch expiryStr {
	case "1":
		expiryMinutes = 10
	case "2":
		expiryMinutes = 30
	case "3":
		expiryMinutes = 60
	case "4":
		expiryMinutes = 360
	case "5":
		expiryMinutes = 720
	case "6":
		expiryMinutes = 1440
	default:
		expiryMinutes = 0
	}

	proToken := ""
	if modeChoice == "2" && expiryMinutes == 0 {
		promptToken := "Enter Pinggy Pro Auth Token (or press ENTER to use Free 60-min tier): "
		if cloudCfg.PinggyProToken != "" {
			promptToken = fmt.Sprintf("Enter Pinggy Pro Token [cached: %s, press ENTER to keep]: ", cloudCfg.PinggyProToken)
		}
		proInput := transfer.ReadRealtimeInput(promptToken)
		if strings.TrimSpace(proInput) != "" {
			proToken = strings.TrimSpace(proInput)
			cloudCfg.PinggyProToken = proToken
			saveCloudConfig(cloudCfg)
		} else {
			proToken = cloudCfg.PinggyProToken
		}
	}

	exec.Command("modprobe", "wireguard").Run()
	exec.Command("ip", "link", "del", DefaultVPNInterface).Run()

	privKeyBase64, pubKeyBase64, err := generateCurve25519Keys()
	if err != nil {
		fmt.Printf(common.Red+"[!] Key generation failed: %v\n"+common.Reset, err)
		return false
	}
	wgPriv, _ := wgtypes.ParseKey(privKeyBase64)
	wgPub, _ := wgtypes.ParseKey(pubKeyBase64)

	iface := DefaultVPNInterface
	tunDev, err := tun.CreateTUN(iface, 1500)
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to create TUN device: %v\n"+common.Reset, err)
		tmpIface := "wg-tmp-" + strconv.Itoa(os.Getpid())
		tunDev, err = tun.CreateTUN(tmpIface, 1500)
		if err != nil {
			fmt.Printf(common.Red+"[!] Still failed: %v\n"+common.Reset, err)
			return false
		}
		exec.Command("ip", "link", "set", tmpIface, "name", iface).Run()
	}

	_ = setupNetwork(iface, HostTunnelIP)

	logger := device.NewLogger(device.LogLevelSilent, "")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	err = wgDev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", wgPriv[:], DefaultHostPort))
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to set private key: %v\n"+common.Reset, err)
		return false
	}
	go wgDev.Up()
	time.Sleep(500 * time.Millisecond)

	sessionID := fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	engineMu.Lock()
	currentEngine = &VPNEngine{
		ctx:         context.Background(),
		device:      wgDev,
		iface:       iface,
		isHost:      true,
		isRelayed:   useRelay,
		privateKey:  wgPriv,
		accessLevel: accessLevel,
		sessionID:   sessionID,
		peerCount:   1,
	}
	engineMu.Unlock()

	applyAccessLevel(iface, accessLevel)

	var wanHost string
	var wanPort int
	lanIP := getOutboundIP()

	if isSelfHostedVPS {
		promptHost := "Enter AWS EC2 / VPS Public IP Address: "
		if cloudCfg.VPSHost != "" {
			promptHost = fmt.Sprintf("Enter AWS EC2 Public IP [cached: %s, press ENTER to keep]: ", cloudCfg.VPSHost)
		}
		vpsIP := transfer.ReadRealtimeInput(promptHost)
		if strings.TrimSpace(vpsIP) != "" {
			wanHost = strings.TrimSpace(vpsIP)
			cloudCfg.VPSHost = wanHost
			saveCloudConfig(cloudCfg)
		} else {
			wanHost = cloudCfg.VPSHost
		}

		wanPort = DefaultHostPort
		fmt.Printf(common.Green+common.Bold+"[✔] Self-Hosted AWS Cloud Relay configured at %s:%d\n"+common.Reset, wanHost, wanPort)
	} else if useRelay {
		udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", DefaultHostPort))
		proxyCtx, proxyCancel := context.WithCancel(context.Background())
		currentEngine.proxyCancel = proxyCancel
		go func() {
			_ = runUDPOverTCPProxy(DefaultBridgePort, udpAddr, proxyCtx)
		}()

		fmt.Println(common.Yellow + "[+] Connecting to Pinggy relay (pure-Go SSH)..." + common.Reset)
		wanHost, wanPort, err = startPinggyReverseTunnel(DefaultBridgePort, proToken)
		if err != nil {
			fmt.Println(common.Yellow + "[!] Pure‑Go SSH failed. Launching system ssh in background..." + common.Reset)
			sshUser := "tcp"
			sshDomain := "a.pinggy.io"
			if proToken != "" {
				sshUser = fmt.Sprintf("%s+tcp", proToken)
				sshDomain = "pro.pinggy.io"
			}
			sshCmd := exec.Command("ssh", "-p", "443", "-o", "StrictHostKeyChecking=no", "-R", fmt.Sprintf("0:localhost:%d", DefaultBridgePort), fmt.Sprintf("%s@%s", sshUser, sshDomain))
			stdout, _ := sshCmd.StdoutPipe()
			stderr, _ := sshCmd.StderrPipe()
			_ = sshCmd.Start()
			scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
			var endpoint string
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "run.pinggy") || strings.Contains(line, "pinggy-free") || strings.Contains(line, "pro.pinggy") || strings.Contains(line, "pinggy.link") {
					words := strings.Fields(line)
					for _, w := range words {
						if strings.Contains(w, "pinggy") || strings.Contains(w, "tcp://") {
							clean := strings.TrimPrefix(w, "tcp://")
							clean = strings.TrimPrefix(clean, "http://")
							clean = strings.TrimPrefix(clean, "https://")
							endpoint = strings.TrimSpace(clean)
							break
						}
					}
					if endpoint != "" {
						break
					}
				}
			}
			parts := strings.Split(endpoint, ":")
			if len(parts) == 2 {
				wanHost = parts[0]
				wanPort, _ = strconv.Atoi(parts[1])
				engineMu.Lock()
				if currentEngine != nil {
					currentEngine.sshCmd = sshCmd
				}
				engineMu.Unlock()
			}
		}
	} else {
		fmt.Println(common.Yellow + "[+] Executing STUN Endpoint Discovery with Failover Redundancy..." + common.Reset)
		wanHost, wanPort, err = discoverPublicEndpointViaSTUN()
		if err != nil || wanPort == 0 {
			wanPort = DefaultHostPort
		}
	}

	pairingCode, err := encodeHostTicket(wanHost, lanIP, wanPort, wgPub.String(), useRelay, accessLevel, expiryMinutes)
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to generate pairing token: %v\n"+common.Reset, err)
		return false
	}

	copyToClipboard(pairingCode)
	fmt.Println(common.Green + "[✔] Pairing code copied to clipboard!" + common.Reset)
	showQRCode(pairingCode)

	expText := fmt.Sprintf("%d minutes", expiryMinutes)
	if expiryMinutes == 0 {
		expText = "Unlimited (No expiration)"
	}

	archType := "STUN Direct UDP (P2P Hole Punching - 24/7 Unlimited)"
	if isSelfHostedVPS {
		archType = fmt.Sprintf("Self-Hosted AWS EC2 Relay (%s)", wanHost)
	} else if useRelay {
		archType = "Pinggy TCP Relay"
		if proToken != "" {
			archType = "Pinggy Pro Dedicated Relay (Unlimited)"
		}
	}

	fmt.Println(common.Green + common.Bold + "\n=> HOST VPN IS ACTIVE!" + common.Reset)
	fmt.Printf("=> Architecture    : %s\n", archType)
	fmt.Printf("=> Public Endpoint : %s:%d\n", wanHost, wanPort)
	if lanIP != "" {
		fmt.Printf("=> Local LAN IP    : %s\n", lanIP)
	}
	fmt.Printf("=> Operational Policy: %s\n", getAccessLevelDescription(accessLevel))
	fmt.Printf("=> Token Expiry    : %s\n", expText)
	fmt.Printf("=> Session ID      : %s\n", sessionID)
	fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)
	fmt.Println(common.Bold + "SEND THIS PAIRING CODE TO YOUR REMOTE PARTNER:" + common.Reset)
	fmt.Println(common.Green + common.Bold + pairingCode + common.Reset)
	fmt.Println(common.Cyan + "--------------------------------------------------------------------------------" + common.Reset)

	notify("VPN Connected", "Host VPN is active. Client can now connect.")
	logVPNEvent("VPN_HOST_STARTED", fmt.Sprintf("SessionID=%s, Mode=%s, Endpoint=%s:%d, Policy=%s", sessionID, archType, wanHost, wanPort, getAccessLevelDescription(accessLevel)))

	for {
		fmt.Println(common.Yellow + "\n[!] Please ask your partner to paste their CLIENT RESPONSE TOKEN here:" + common.Reset)
		clientToken := transfer.ReadRealtimeInput("Paste Partner's Client Response Token: ")
		if strings.TrimSpace(clientToken) == "" {
			fmt.Println(common.Red + "[!] Client Response Token cannot be empty. Please paste the token." + common.Reset)
			continue
		}

		resp, err := decodeClientResponse(clientToken)
		if err != nil {
			fmt.Printf(common.Red+"[!] Invalid client token format: %v\n"+common.Reset, err)
			continue
		}

		clientPubKey, err := wgtypes.ParseKey(resp.ClientPublicKey)
		if err != nil || clientPubKey.String() == "" {
			fmt.Println(common.Red + "[!] Invalid client cryptographic public key received." + common.Reset)
			continue
		}

		engineMu.Lock()
		if currentEngine != nil {
			currentEngine.peerPubKey = clientPubKey
		}
		engineMu.Unlock()

		var peerCfg string
		if !useRelay {
			targetEndpoint := ""
			if lanIP != "" && resp.ClientLAN != "" && isSameSubnet(lanIP, resp.ClientLAN) {
				targetEndpoint = fmt.Sprintf("%s:%d", resp.ClientLAN, DefaultHostPort)
				fmt.Printf(common.Green+common.Bold+"[✔] Same LAN Subnet Detected! Using direct high-speed LAN route: %s\n"+common.Reset, targetEndpoint)
			} else if resp.ClientWAN != "" && resp.ClientPort > 0 {
				targetEndpoint = fmt.Sprintf("%s:%d", resp.ClientWAN, resp.ClientPort)
				fmt.Printf(common.Cyan+"[+] Direct STUN peer endpoint configured: %s\n"+common.Reset, targetEndpoint)
			}

			if targetEndpoint != "" {
				peerCfg = fmt.Sprintf("public_key=%x\nallowed_ip=10.99.0.2/32\nallowed_ip=10.99.0.0/24\nendpoint=%s\npersistent_keepalive_interval=5\n", clientPubKey[:], targetEndpoint)
				startNATHolePuncher(targetEndpoint, context.Background())
			} else {
				peerCfg = fmt.Sprintf("public_key=%x\nallowed_ip=10.99.0.2/32\nallowed_ip=10.99.0.0/24\npersistent_keepalive_interval=5\n", clientPubKey[:])
			}
		} else {
			peerCfg = fmt.Sprintf("public_key=%x\nallowed_ip=10.99.0.2/32\nallowed_ip=10.99.0.0/24\npersistent_keepalive_interval=5\n", clientPubKey[:])
		}

		if err := wgDev.IpcSet(peerCfg); err != nil {
			fmt.Printf(common.Red+"[!] Failed to commit peer configuration to kernel: %v\n"+common.Reset, err)
			return false
		}

		fmt.Println(common.Green + common.Bold + "\n[✔] Client peer authorized! VPN tunnel established." + common.Reset)
		fmt.Printf(common.Cyan+"    • Authorized Peer PubKey: %x\n"+common.Reset, clientPubKey[:])
		logVPNEvent("VPN_PEER_AUTHORIZED", fmt.Sprintf("ClientPubKey=%x, SessionID=%s", clientPubKey[:], sessionID))
		pause()
		break
	}
	return true
}

// -------------------------------
// Start Client Mode
// -------------------------------

func startClientMode(reader *bufio.Reader) bool {
	disconnectVPN()

	fmt.Println(common.Cyan + "\n=== CLIENT MODE: CONNECT TO REMOTE PARTNER VIA PAIRING CODE ===" + common.Reset)
	fmt.Print(common.Bold + "Enter Host Pairing Code (starts with CS-VPN-HOST-): " + common.Reset)
	hostToken := transfer.ReadRealtimeInput("")
	ticket, err := decodeHostTicket(hostToken)
	if err != nil {
		fmt.Printf(common.Red+"[!] Invalid host token: %v\n"+common.Reset, err)
		return false
	}

	expFormatted := "Never"
	if ticket.Expires > 0 {
		expFormatted = time.Unix(ticket.Expires, 0).Format(time.RFC3339)
	}

	archDesc := "STUN Direct UDP (P2P - 24/7 Unlimited)"
	if ticket.IsRelayed {
		archDesc = "TCP Reverse Relay Bridge"
	}

	fmt.Printf(common.Green+"[+] Validated Host Ticket:\n    • Architecture   : %s\n    • Target Endpoint: %s:%d\n    • Host PubKey    : %s\n    • Access Policy  : %s\n    • Expires        : %s\n"+common.Reset,
		archDesc, ticket.HostWAN, ticket.HostPort, ticket.PublicKey,
		getAccessLevelDescription(ticket.AccessLevel),
		expFormatted)

	exec.Command("modprobe", "wireguard").Run()
	exec.Command("ip", "link", "del", DefaultVPNInterface).Run()

	privKeyBase64, pubKeyBase64, err := generateCurve25519Keys()
	if err != nil {
		fmt.Printf(common.Red+"[!] Key generation failed: %v\n"+common.Reset, err)
		return false
	}
	wgPriv, _ := wgtypes.ParseKey(privKeyBase64)
	wgPub, _ := wgtypes.ParseKey(pubKeyBase64)
	hostPub, _ := wgtypes.ParseKey(ticket.PublicKey)

	iface := DefaultVPNInterface
	tunDev, err := tun.CreateTUN(iface, 1500)
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to create TUN: %v\n"+common.Reset, err)
		tmpIface := "wg-tmp-" + strconv.Itoa(os.Getpid())
		tunDev, err = tun.CreateTUN(tmpIface, 1500)
		if err != nil {
			fmt.Printf(common.Red+"[!] Still failed: %v\n"+common.Reset, err)
			return false
		}
		exec.Command("ip", "link", "set", tmpIface, "name", iface).Run()
	}
	_ = setupNetwork(iface, ClientTunnelIP)

	logger := device.NewLogger(device.LogLevelSilent, "")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	err = wgDev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", wgPriv[:], DefaultHostPort))
	if err != nil {
		fmt.Printf(common.Red+"[!] Failed to set private key: %v\n"+common.Reset, err)
		return false
	}

	var endpoint string
	var proxyCancel context.CancelFunc
	myLAN := getOutboundIP()

	if ticket.IsRelayed {
		var pCtx context.Context
		pCtx, proxyCancel = context.WithCancel(context.Background())
		relayAddr := fmt.Sprintf("%s:%d", ticket.HostWAN, ticket.HostPort)
		go func() {
			_ = runUDPToTCPProxy(DefaultBridgePort, relayAddr, pCtx)
		}()
		endpoint = fmt.Sprintf("127.0.0.1:%d", DefaultBridgePort)
	} else {
		if ticket.HostLAN != "" && myLAN != "" && isSameSubnet(myLAN, ticket.HostLAN) {
			endpoint = fmt.Sprintf("%s:%d", ticket.HostLAN, ticket.HostPort)
			fmt.Printf(common.Green+common.Bold+"[✔] Same LAN Subnet Detected! Direct connection to Host LAN: %s\n"+common.Reset, endpoint)
		} else {
			hostIPs, err := net.LookupIP(ticket.HostWAN)
			targetIP := ticket.HostWAN
			if err == nil && len(hostIPs) > 0 {
				for _, ip := range hostIPs {
					if ip.To4() != nil {
						targetIP = ip.String()
						break
					}
				}
			}
			endpoint = fmt.Sprintf("%s:%d", targetIP, ticket.HostPort)
			fmt.Printf(common.Cyan+"[+] Pointing WireGuard directly to Host endpoint: %s\n"+common.Reset, endpoint)
		}
		startNATHolePuncher(endpoint, context.Background())
	}

	peerCfg := fmt.Sprintf("public_key=%x\nallowed_ip=10.99.0.1/32\nallowed_ip=10.99.0.0/24\nallowed_ip=0.0.0.0/0\nendpoint=%s\npersistent_keepalive_interval=5\n", hostPub[:], endpoint)
	if err := wgDev.IpcSet(peerCfg); err != nil {
		fmt.Printf(common.Red+"[!] Failed to add host peer: %v\n"+common.Reset, err)
		if proxyCancel != nil {
			proxyCancel()
		}
		return false
	}
	go wgDev.Up()
	time.Sleep(500 * time.Millisecond)

	engineMu.Lock()
	currentEngine = &VPNEngine{
		device:      wgDev,
		iface:       iface,
		isHost:      false,
		isRelayed:   ticket.IsRelayed,
		privateKey:  wgPriv,
		peerPubKey:  hostPub,
		proxyCancel: proxyCancel,
		accessLevel: ticket.AccessLevel,
		sessionID:   "client-" + fmt.Sprintf("%x", time.Now().UnixNano())[:8],
	}
	engineMu.Unlock()

	clientWAN := ""
	clientPort := 0
	if !ticket.IsRelayed {
		fmt.Println(common.Yellow + "[+] Performing client-side STUN discovery for bidirectional hole punching..." + common.Reset)
		cIP, cPort, err := discoverPublicEndpointViaSTUN()
		if err == nil {
			clientWAN = cIP
			clientPort = cPort
		}
	}

	respToken, _ := encodeClientResponse(wgPub.String(), clientWAN, myLAN, clientPort)
	clientTokenString = respToken
	copyToClipboard(respToken)

	fmt.Println(common.Green + common.Bold + "\n================================================================================" + common.Reset)
	fmt.Println(common.Bold + "COPY & SEND THIS RESPONSE TOKEN BACK TO YOUR HOST (COPIED TO CLIPBOARD):" + common.Reset)
	fmt.Println(common.Yellow + common.Bold + respToken + common.Reset)
	fmt.Println(common.Green + common.Bold + "================================================================================" + common.Reset)
	showQRCode(respToken)

	fmt.Println(common.Green + common.Bold + "\n[✔] CLIENT TUNNEL READY & CONNECTED TO HOST!" + common.Reset)
	fmt.Printf(common.Cyan+"    • Target Host PubKey: %x\n"+common.Reset, hostPub[:])

	notify("VPN Connected", "Client VPN is active. Response token generated.")
	logVPNEvent("VPN_CLIENT_STARTED", fmt.Sprintf("SessionID=%s, HostEndpoint=%s, Direct=%v", currentEngine.sessionID, endpoint, !ticket.IsRelayed))

	fmt.Println(common.Yellow + "\n[!] Paste the response token above into your Host terminal, then press Enter here to open Client Control Hub." + common.Reset)
	pause()

	return true
}

// -------------------------------
// Subnet Detection Helper
// -------------------------------

func isSameSubnet(ip1, ip2 string) bool {
	p1 := strings.Split(ip1, ".")
	p2 := strings.Split(ip2, ".")
	if len(p1) == 4 && len(p2) == 4 {
		return p1[0] == p2[0] && p1[1] == p2[1] && p1[2] == p2[2]
	}
	return false
}

// -------------------------------
// Status and disconnect
// -------------------------------

func showVPNStatus() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if currentEngine == nil || currentEngine.device == nil {
		fmt.Println(common.Yellow + "[!] No active VPN tunnel." + common.Reset)
		return
	}
	fmt.Println(common.Cyan + "=== VPN STATUS ===" + common.Reset)
	fmt.Printf("Interface: %s\n", currentEngine.iface)
	fmt.Printf("Role: %s\n", map[bool]string{true: "Host (Server)", false: "Client"}[currentEngine.isHost])
	archStr := "STUN Direct UDP (24/7 Unlimited P2P)"
	if currentEngine.isRelayed {
		archStr = "TCP Reverse Relay Bridge"
	}
	fmt.Printf("Architecture: %s\n", archStr)
	if currentEngine.peerPubKey.String() != "" {
		fmt.Printf("Peer PubKey: %x\n", currentEngine.peerPubKey[:])
	}
	if currentEngine.isHost {
		fmt.Printf("Operational Policy: %s\n", getAccessLevelDescription(currentEngine.accessLevel))
		fmt.Printf("Active Mesh Peers: %d\n", currentEngine.peerCount)
	}
	if currentEngine.clipSyncOn {
		fmt.Println(common.Green + "Clipboard Sync: ACTIVE (Bidirectional)" + common.Reset)
	} else {
		fmt.Println("Clipboard Sync: OFF")
	}
	if currentEngine.sessionID != "" {
		fmt.Printf("Session ID: %s\n", currentEngine.sessionID)
	}
	if currentEngine.device != nil {
		cmd := exec.Command("ip", "link", "show", currentEngine.iface)
		out, _ := cmd.Output()
		if strings.Contains(string(out), "UP") {
			fmt.Println(common.Green + "[✔] Interface is UP" + common.Reset)
		} else {
			fmt.Println(common.Yellow + "[!] Interface is DOWN" + common.Reset)
		}
	}
	cmd := exec.Command("ip", "-4", "addr", "show", currentEngine.iface)
	out, _ := cmd.Output()
	fmt.Printf("IP Addresses:\n%s\n", strings.TrimSpace(string(out)))

	statCmd := exec.Command("ip", "-s", "link", "show", currentEngine.iface)
	if statOut, err := statCmd.Output(); err == nil {
		fmt.Println(common.Cyan + "Traffic Counters:" + common.Reset)
		fmt.Println(strings.TrimSpace(string(statOut)))
	}
}

func disconnectVPN() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if currentEngine == nil {
		return
	}
	if currentEngine.clipCancel != nil {
		currentEngine.clipCancel()
	}
	if currentEngine.proxyCancel != nil {
		currentEngine.proxyCancel()
	}
	if currentEngine.device != nil {
		currentEngine.device.Down()
		currentEngine.device.Close()
	}
	if currentEngine.sshClient != nil {
		currentEngine.sshClient.Close()
	}
	if currentEngine.sshCmd != nil && currentEngine.sshCmd.Process != nil {
		currentEngine.sshCmd.Process.Kill()
		currentEngine.sshCmd = nil
	}
	if runtime.GOOS == "linux" {
		exec.Command("ip", "link", "del", currentEngine.iface).Run()
		exec.Command("iptables", "-D", "FORWARD", "-i", currentEngine.iface, "-j", "DROP").Run()
		exec.Command("iptables", "-D", "FORWARD", "-o", currentEngine.iface, "-j", "DROP").Run()
		exec.Command("iptables", "-F", "CROSS_VPN").Run()
		exec.Command("iptables", "-X", "CROSS_VPN").Run()
	}
	notify("VPN Disconnected", "The VPN tunnel has been closed.")
	logVPNEvent("VPN_DISCONNECTED", fmt.Sprintf("SessionID=%s", currentEngine.sessionID))
	currentEngine = nil
	fmt.Println(common.Green + "[✔] VPN disconnected." + common.Reset)
}

// -------------------------------
// Helpers
// -------------------------------

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func printBanner() {
	fmt.Println(common.Cyan + common.Bold + "=== CROSS-SUITE VPN ENGINE (SELF-CONTAINED) ===" + common.Reset)
}

func pause() {
	fmt.Print(common.Yellow + "\nPress Enter to continue..." + common.Reset)
	_ = transfer.ReadRealtimeInput("")
}