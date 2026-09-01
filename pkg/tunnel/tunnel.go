package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"
	"cross-ssh/pkg/vault"

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
	Dim     = "\033[2m"

	VoIPDisconnectMagic = "CROSS_VOIP_CALL_HANGUP_ACK"
)

type ActiveTunnel struct {
	ID          int
	LocalPort   int
	RemotePort  int
	ServiceName string
	Listener    net.Listener
	StopChan    chan bool
	StartTime   time.Time
	IsReverse   bool
}

type NotificationItem struct {
	ID        int       `json:"id"`
	SenderIP  string    `json:"sender_ip"`
	SenderTag string    `json:"sender_tag"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	IsRead    bool      `json:"is_read"`
}

type ChatMessage struct {
	ID        string    `json:"id"`
	Seq       int64     `json:"seq"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

type DiscoveredApp struct {
	Name  string
	Exec  string
	IsTUI bool
}

type MeshContact struct {
	Alias     string `json:"alias"`
	IP        string `json:"ip"`
	Port      string `json:"port"`
	User      string `json:"user"`
	KeyPath   string `json:"key_path"`
	CreatedAt string `json:"created_at"`
}

type AudioDeviceEndpoint struct {
	Index       string
	Name        string
	Description string
	PortName    string
	IsDefault   bool
}

type NodeStatus struct {
	Label string
	Color string
}

var (
	tunnels     []*ActiveTunnel
	tunnelMutex sync.Mutex
	nextID      = 1

	socksListener   net.Listener
	socksStopChan   chan struct{}
	socksMutex      sync.Mutex
	isSocksActive   bool
	activeSocksPort = 1080

	activeVoIPCancel context.CancelFunc
	activeVoIPSess   *ssh.Session
	activeVoIPPeer   string
	isVoIPLive       bool
	voipCallMutex    sync.Mutex

	chatSyncMutex sync.Mutex

	usbAudioWatcherActive bool
	usbWatcherCancel      context.CancelFunc
	usbWatcherMutex       sync.Mutex

	currentToastMessage string
	toastExpireTime     time.Time
	toastMutex          sync.Mutex
	lastKnownUSBMic     string
	lastKnownUSBSink    string
)

// === NATIVE DETERMINISTIC AES-256-GCM SECURITY ENGINE ===

func getMasterMeshKey() []byte {
	h := sha256.Sum256([]byte("CrossSSH-Universal-Mesh-Zero-Trust-Key-Seed-v2"))
	return h[:]
}

func encryptPayloadAES(plaintext []byte) (string, error) {
	key := getMasterMeshKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptPayloadAES(encodedStr string) ([]byte, error) {
	clean := strings.TrimSpace(encodedStr)
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")

	data, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		data, err = hex.DecodeString(clean)
		if err != nil {
			return nil, err
		}
	}

	key := getMasterMeshKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// === NEW: WAV parser to extract raw PCM (handles extra chunks) ===

func extractRawPCMFromWAV(data []byte) ([]byte, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("WAV data too short")
	}
	if string(data[0:4]) != "RIFF" || string(data[8:12]) != "WAVE" {
		return nil, fmt.Errorf("not a valid WAV file")
	}
	offset := 12
	for offset+8 <= len(data) {
		chunkID := string(data[offset : offset+4])
		chunkSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		if chunkID == "data" {
			if offset+8+int(chunkSize) > len(data) {
				return nil, fmt.Errorf("data chunk size exceeds file size")
			}
			return data[offset+8 : offset+8+int(chunkSize)], nil
		}
		offset += 8 + int(chunkSize)
	}
	return nil, fmt.Errorf("data chunk not found")
}

func restoreTerminalState() {
	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "sane").Run()
		_ = exec.Command("stty", "echo").Run()
		_ = exec.Command("stty", "icanon").Run()
		_ = exec.Command("stty", "-F", "/dev/tty", "sane").Run()
		_ = exec.Command("stty", "-F", "/dev/tty", "echo").Run()
		_ = exec.Command("stty", "-F", "/dev/tty", "icanon").Run()
	}
	drainStdinBuffer()
}

func drainStdinBuffer() {
	if runtime.GOOS == "windows" {
		return
	}
	_ = exec.Command("stty", "-F", "/dev/tty", "-icanon", "min", "0", "time", "0").Run()
	buf := make([]byte, 256)
	for {
		n, _ := os.Stdin.Read(buf)
		if n <= 0 {
			break
		}
	}
	_ = exec.Command("stty", "-F", "/dev/tty", "sane", "echo", "icanon").Run()
}

func ClearAllActiveNotifications() {
	targetFiles := []string{
		filepath.Join(GetUniversalBaseDir(), "notifications.json"),
		"/tmp/cross_notifications.json",
		filepath.Join(os.TempDir(), "cross_notifications.json"),
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		targetFiles = append(targetFiles, filepath.Join("/home", sudoUser, ".cross-ssh", "notifications.json"))
	}

	for _, tf := range targetFiles {
		_ = os.WriteFile(tf, []byte(""), 0666)
	}
}

func MarkNotificationRead(notifType, senderIP string) {
	targetFiles := []string{
		filepath.Join(GetUniversalBaseDir(), "notifications.json"),
		"/tmp/cross_notifications.json",
		filepath.Join(os.TempDir(), "cross_notifications.json"),
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		targetFiles = append(targetFiles, filepath.Join("/home", sudoUser, ".cross-ssh", "notifications.json"))
	}

	cleanTarget := sanitizePeerTag(senderIP)

	for _, tf := range targetFiles {
		data, err := os.ReadFile(tf)
		if err != nil || len(data) == 0 {
			continue
		}
		var retainedLines []string
		for _, l := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" {
				continue
			}
			payloadBytes := []byte(trimmed)
			if strings.HasPrefix(trimmed, "ENC:") {
				dec, errD := decryptPayloadAES(strings.TrimPrefix(trimmed, "ENC:"))
				if errD == nil {
					payloadBytes = dec
				}
			}

			var item NotificationItem
			if err := json.Unmarshal(payloadBytes, &item); err == nil {
				itemClean := sanitizePeerTag(item.SenderIP)
				if notifType == "" || item.Type == notifType {
					if senderIP == "" || item.SenderIP == senderIP || itemClean == cleanTarget || item.SenderTag == senderIP {
						continue
					}
				}
			}
			retainedLines = append(retainedLines, trimmed)
		}
		_ = os.WriteFile(tf, []byte(strings.Join(retainedLines, "\n")), 0666)
	}
}

func GetActiveTunnels() []*ActiveTunnel {
	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()
	return tunnels
}

func GetVoIPCallState() (bool, string) {
	voipCallMutex.Lock()
	defer voipCallMutex.Unlock()
	return isVoIPLive, activeVoIPPeer
}

func TerminateBackgroundVoIPCall() {
	voipCallMutex.Lock()
	defer voipCallMutex.Unlock()
	if isVoIPLive {
		if activeVoIPCancel != nil {
			activeVoIPCancel()
		}
		if activeVoIPSess != nil {
			_ = activeVoIPSess.Signal(ssh.SIGTERM)
			_ = activeVoIPSess.Close()
		}
		isVoIPLive = false
		activeVoIPPeer = ""
	}
	_ = exec.Command("pkill", "-9", "-f", "speaker-test").Run()
	_ = exec.Command("pkill", "-9", "-f", "pacat").Run()
	_ = exec.Command("pkill", "-9", "-f", "parec").Run()
	_ = exec.Command("pkill", "-9", "-f", "paplay").Run()
	_ = exec.Command("pkill", "-9", "-f", "arecord").Run()
	_ = exec.Command("pkill", "-9", "-f", "aplay").Run()
	restoreTerminalState()
}

func GetLocalNodeIdentity() string {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		return sudoUser
	}
	u, err := user.Current()
	if err == nil && u.Username != "" {
		parts := strings.Split(u.Username, "\\")
		return parts[len(parts)-1]
	}
	envUser := os.Getenv("USER")
	if envUser != "" {
		return envUser
	}
	return "user"
}

func GetUniversalBaseDir() string {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		if runtime.GOOS == "linux" {
			home = filepath.Join("/home", sudoUser)
		} else if runtime.GOOS == "darwin" {
			home = filepath.Join("/Users", sudoUser)
		}
	} else if err != nil || home == "" {
		home = os.TempDir()
	}
	base := filepath.Join(home, ".cross-ssh")
	_ = os.MkdirAll(base, 0777)
	if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
		_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), base).Run()
	}
	return base
}

func ensureAudioToolsInstalled() {
	if runtime.GOOS != "linux" {
		return
	}
	missing := []string{}
	checks := map[string]string{
		"pactl":   "pulseaudio-utils",
		"pacat":   "pulseaudio-utils",
		"amixer":  "alsa-utils",
		"arecord": "alsa-utils",
		"aplay":   "alsa-utils",
		"parec":   "pulseaudio-utils",
		"paplay":  "pulseaudio-utils",
	}

	for cmd, pkg := range checks {
		if _, err := exec.LookPath(cmd); err != nil {
			missing = append(missing, pkg)
		}
	}

	if len(missing) == 0 {
		return
	}

	seen := make(map[string]bool)
	uniquePkgs := []string{}
	for _, m := range missing {
		if !seen[m] {
			seen[m] = true
			uniquePkgs = append(uniquePkgs, m)
		}
	}

	if _, err := exec.LookPath("apt-get"); err == nil {
		args := append([]string{"install", "-y", "-qq"}, uniquePkgs...)
		_ = exec.Command("apt-get", args...).Run()
	} else if _, err := exec.LookPath("dnf"); err == nil {
		args := append([]string{"install", "-y", "-q"}, uniquePkgs...)
		_ = exec.Command("dnf", args...).Run()
	} else if _, err := exec.LookPath("yum"); err == nil {
		args := append([]string{"install", "-y", "-q"}, uniquePkgs...)
		_ = exec.Command("yum", args...).Run()
	} else if _, err := exec.LookPath("pacman"); err == nil {
		args := append([]string{"-Sy", "--noconfirm"}, uniquePkgs...)
		_ = exec.Command("pacman", args...).Run()
	}
}

// === TOAST NOTIFICATION & AUDIO HOT-PLUG ENGINE ===

func TriggerAudioToast(msg string, isSuccess bool) {
	toastMutex.Lock()
	color := Green + Bold
	tag := "[✔ USB AUDIO HOTPLUG]"
	if !isSuccess {
		color = Yellow + Bold
		tag = "[⚠ USB AUDIO DISCONNECTED]"
	}
	currentToastMessage = fmt.Sprintf("%s%s %s%s", color, tag, msg, Reset)
	toastExpireTime = time.Now().Add(3500 * time.Millisecond)
	toastMutex.Unlock()

	if runtime.GOOS != "windows" {
		fmt.Fprintf(os.Stderr, "\033[s\033[1;1H\033[K%s\033[u", currentToastMessage)
	}
}

func RenderAudioStatusToast() {
	toastMutex.Lock()
	defer toastMutex.Unlock()

	if time.Now().Before(toastExpireTime) && currentToastMessage != "" {
		fmt.Printf("\n  %s\n", currentToastMessage)
	}
}

func StartUSBAudioHotplugDaemon() {
	usbWatcherMutex.Lock()
	defer usbWatcherMutex.Unlock()

	if usbAudioWatcherActive {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	usbWatcherCancel = cancel
	usbAudioWatcherActive = true

	go runUSBAudioHotplugLoop(ctx)
}

func StopUSBAudioHotplugDaemon() {
	usbWatcherMutex.Lock()
	defer usbWatcherMutex.Unlock()

	if usbWatcherCancel != nil {
		usbWatcherCancel()
		usbAudioWatcherActive = false
	}
}

func runUSBAudioHotplugLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			cmd := getDesktopAudioUserCmd("pactl", "subscribe")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				time.Sleep(3 * time.Second)
				continue
			}

			if err := cmd.Start(); err != nil {
				time.Sleep(3 * time.Second)
				continue
			}

			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					_ = cmd.Process.Kill()
					return
				default:
					line := scanner.Text()
					if strings.Contains(line, "'new'") || strings.Contains(line, "'remove'") {
						if strings.Contains(line, "source") || strings.Contains(line, "sink") {
							time.Sleep(250 * time.Millisecond)
							handleAudioTopologyChange()
						}
					}
				}
			}
			_ = cmd.Wait()
			time.Sleep(1 * time.Second)
		}
	}
}

func handleAudioTopologyChange() {
	sources := parseAudioEndpoints("source")
	sinks := parseAudioEndpoints("sink")

	var foundUSBMic *AudioDeviceEndpoint
	for i := range sources {
		if strings.HasPrefix(sources[i].Name, "alsa_input.usb-") || strings.Contains(strings.ToLower(sources[i].Description), "usb") {
			foundUSBMic = &sources[i]
			break
		}
	}

	var foundUSBSpeaker *AudioDeviceEndpoint
	for i := range sinks {
		if strings.HasPrefix(sinks[i].Name, "alsa_output.usb-") || strings.Contains(strings.ToLower(sinks[i].Description), "usb") {
			foundUSBSpeaker = &sinks[i]
			break
		}
	}

	if foundUSBMic != nil {
		if lastKnownUSBMic != foundUSBMic.Name {
			lastKnownUSBMic = foundUSBMic.Name
			setSelectedMicSource(foundUSBMic.Name, foundUSBMic.PortName)
			TriggerAudioToast(fmt.Sprintf("Activated Microphone: %s", truncateStr(foundUSBMic.Description, 40)), true)
		}
	} else if lastKnownUSBMic != "" {
		lastKnownUSBMic = ""
		enforceHardwareAudioLocks()
		TriggerAudioToast("USB Headset / Mic unplugged. Restored Motherboard Jack.", false)
	}

	if foundUSBSpeaker != nil {
		if lastKnownUSBSink != foundUSBSpeaker.Name {
			lastKnownUSBSink = foundUSBSpeaker.Name
			setSelectedSpeakerSink(foundUSBSpeaker.Name)
			TriggerAudioToast(fmt.Sprintf("Activated Speaker: %s", truncateStr(foundUSBSpeaker.Description, 40)), true)
		}
	} else if lastKnownUSBSink != "" {
		lastKnownUSBSink = ""
		enforceHardwareAudioLocks()
		TriggerAudioToast("USB Speaker output unplugged. Restored System Default.", false)
	}
}

// === PURE HARDWARE GAIN & PORT ENFORCEMENT ENGINE ===
func enforceHardwareAudioLocks() {
	_ = getDesktopAudioUserCmd("pactl", "unload-module", "module-echo-cancel").Run()

	source := getActiveSelectedMicSource()
	if source != "" {
		_ = getDesktopAudioUserCmd("pactl", "set-default-source", source).Run()
		_ = getDesktopAudioUserCmd("pactl", "set-source-mute", source, "0").Run()
		_ = getDesktopAudioUserCmd("pactl", "set-source-volume", source, "100%").Run()

		if portData, err := os.ReadFile(getSelectedAudioPortPath()); err == nil {
			savedPort := strings.TrimSpace(string(portData))
			if savedPort != "" {
				_ = getDesktopAudioUserCmd("pactl", "set-source-port", source, savedPort).Run()
			}
		}
	}

	sink := getActiveSelectedSpeakerSink()
	if sink != "" {
		_ = getDesktopAudioUserCmd("pactl", "set-default-sink", sink).Run()
		_ = getDesktopAudioUserCmd("pactl", "set-sink-mute", sink, "0").Run()
		_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", sink, "100%").Run()
	}

	_ = exec.Command("amixer", "set", "Capture", "100%", "cap").Run()
	_ = exec.Command("amixer", "set", "Mic Boost", "0%").Run()
	_ = exec.Command("amixer", "set", "Internal Mic Boost", "0%").Run()
	_ = exec.Command("amixer", "set", "Master", "100%", "unmute").Run()
	_ = exec.Command("amixer", "set", "Headphone", "100%", "unmute").Run()
	_ = exec.Command("amixer", "set", "Speaker", "100%", "unmute").Run()
}

// === TUNNELING AND SERVICE HUB ===

func ShowTunnelMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, host, user, pass, keyPath string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== ENGINE 1: SMART WEB, GUI, DOCKER & P2P SOCKET HUB ===" + Reset)
		fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"Target OS: "+Reset+Bold+"%s\n"+Reset, host, targetOS)
		fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Tunnel GitLab / Jenkins / Web Service (Port 8080 / Auto-Detect)")
		fmt.Println("  [2] Tunnel Grafana Metrics Dashboard (Port 3000)")
		fmt.Println("  [3] Tunnel Prometheus Monitoring (Port 9090)")
		fmt.Println("  [4] Tunnel Cockpit / Proxmox Admin Web Console (Port 8006 / 9090)")
		fmt.Println("  [5] Custom Port Forwarding (Specify Any Remote Port)")
		fmt.Println("  [6] Universal Native HTTP/TCP Web Forwarding Bridge")
		fmt.Println(Green + Bold + "  [7] Launch Remote Host Web Browser (Firefox SOCKS5 Egress Tunnel)" + Reset)
		fmt.Println(Cyan + Bold + "  [8] Remote GUI & TUI App Streaming Engine (Deep Interactive Scan)" + Reset)
		fmt.Println(Magenta + Bold + "  [9] Remote Docker & Kubernetes Engine Context Orchestrator" + Reset)
		fmt.Println(Yellow + Bold + " [10] Reverse Ingress Service Exposer (Expose Localhost to Target)" + Reset)
		fmt.Println(Green + Bold + " [11] P2P Mesh Network: Encrypted Intercom, Live VoIP & Messenger Matrix" + Reset)
		fmt.Println(" [12] View Active Forward / Reverse Tunnels")
		fmt.Println(" [13] Close an Active Tunnel")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-13]: ")

		switch choice {
		case "1":
			portStr := transfer.ReadRealtimeInput("\nEnter Remote Port [Press Enter for Auto 8080/8082]: ")
			rPort := 8080
			if p, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && p > 0 {
				rPort = p
			} else {
				rPort = probeRemoteWebPort(client, []int{8080, 8082, 8081, 8929})
			}
			startTunnelFlow(reader, client, "GitLab/Jenkins", rPort)
		case "2":
			startTunnelFlow(reader, client, "Grafana", 3000)
		case "3":
			startTunnelFlow(reader, client, "Prometheus", 9090)
		case "4":
			startTunnelFlow(reader, client, "Cockpit/Proxmox", 8006)
		case "5":
			rPortStr := transfer.ReadRealtimeInput("\nEnter Remote Port to Tunnel (e.g. 80, 443, 3306): ")
			rPort, err := strconv.Atoi(strings.TrimSpace(rPortStr))
			if err == nil && rPort > 0 {
				svcName := transfer.ReadRealtimeInput("Enter Label/Name for this service: ")
				if svcName == "" {
					svcName = fmt.Sprintf("Port-%d", rPort)
				}
				startTunnelFlow(reader, client, svcName, rPort)
			}
		case "6":
			startUniversalWebBridge(reader, client)
		case "7":
			LaunchRemoteHostBrowser(reader, client, host)
		case "8":
			LaunchRemoteGUIApp(reader, client, host, user, pass, keyPath, targetOS)
		case "9":
			ShowDockerK8sOrchestratorMenu(reader, client, host)
		case "10":
			ShowReverseIngressMenu(reader, client)
		case "11":
			ShowP2PCommunicationsMatrix(reader, client, host, user)
		case "12":
			listActiveTunnelsMenu(reader)
		case "13":
			closeTunnelMenu(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func LaunchRemoteHostBrowser(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== LAUNCH WEB BROWSER VIA REMOTE HOST NETWORK (SOCKS5) ===" + Reset)
	fmt.Printf(Yellow+"Tunnel Gateway: %s (Encrypted Dynamic SOCKS5 Egress)\n"+Reset, host)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	socksPort := 1080
	err := startSocks5Proxy(client, socksPort)
	if err != nil {
		socksPort = findFreeLocalPort(1081)
		err = startSocks5Proxy(client, socksPort)
		if err != nil {
			fmt.Printf(Red+"[!] Failed to start SOCKS5 proxy: %v\n"+Reset, err)
			pausePrompt()
			return
		}
	}

	fmt.Printf(Green+Bold+"[✔] SOCKS5 Egress Tunnel Active on 127.0.0.1:%d\n"+Reset, socksPort)
	fmt.Println(Yellow + "[+] Testing remote DNS & tunnel loopback..." + Reset)

	confirm := transfer.ReadRealtimeInput("\nLaunch isolated Firefox browser now? [Y/n]: ")
	if strings.ToLower(confirm) == "n" {
		fmt.Println(Yellow + "\n[+] SOCKS5 proxy remains live in background for manual configuration." + Reset)
		fmt.Printf(Cyan+"    • SOCKS Host: 127.0.0.1 | Port: %d | SOCKSv5 + Remote DNS\n"+Reset, socksPort)
		pausePrompt()
		return
	}

	launched, browserName := spawnIsolatedProxyBrowser(socksPort)
	if !launched {
		fmt.Println(Red + "[!] Automatic browser spawn failed. Open Firefox manually and set SOCKS5 to 127.0.0.1:" + strconv.Itoa(socksPort) + Reset)
	} else {
		fmt.Println(Green + Bold + fmt.Sprintf("[✔ SUCCESS] %s launched on desktop! All traffic routes via remote host.", browserName) + Reset)
	}
	pausePrompt()
}

func startSocks5Proxy(client *ssh.Client, localPort int) error {
	socksMutex.Lock()
	defer socksMutex.Unlock()

	if isSocksActive && socksListener != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	socksListener = l
	socksStopChan = make(chan struct{})
	isSocksActive = true
	activeSocksPort = localPort

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-socksStopChan:
					return
				default:
					continue
				}
			}
			go handleSocks5Client(client, conn)
		}
	}()

	return nil
}

func handleSocks5Client(sshClient *ssh.Client, clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 256)
	n, err := io.ReadFull(clientConn, buf[:2])
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}

	var destAddr string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, ip); err != nil {
			return
		}
		destAddr = net.IP(ip).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			return
		}
		destAddr = string(domain)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, ip); err != nil {
			return
		}
		destAddr = net.IP(ip).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	destPort := int(portBuf[0])<<8 | int(portBuf[1])
	targetEndpoint := fmt.Sprintf("%s:%d", destAddr, destPort)

	remoteConn, err := sshClient.Dial("tcp", targetEndpoint)
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remoteConn, clientConn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(clientConn, remoteConn) }()
	wg.Wait()
}

func spawnIsolatedProxyBrowser(socksPort int) (bool, string) {
	tempProfileDir := filepath.Join(GetUniversalBaseDir(), fmt.Sprintf("proxy_browser_%d", time.Now().UnixNano()))
	_ = os.MkdirAll(tempProfileDir, 0755)

	targetURL := "https://ifconfig.me"

	if path, err := exec.LookPath("firefox"); err == nil {
		userJsContent := fmt.Sprintf(`
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", %d);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
`, socksPort)
		_ = os.WriteFile(filepath.Join(tempProfileDir, "user.js"), []byte(userJsContent), 0644)

		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
			_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), tempProfileDir).Run()
			xauth := filepath.Join("/home", sudoUser, ".Xauthority")
			cmd := exec.Command("sudo", "-u", sudoUser, "env", "DISPLAY=:0", fmt.Sprintf("XAUTHORITY=%s", xauth), path, "--profile", tempProfileDir, "--no-remote", targetURL)
			if cmd.Start() == nil {
				return true, "Firefox"
			}
		} else {
			cmd := exec.Command(path, "--profile", tempProfileDir, "--no-remote", targetURL)
			if cmd.Start() == nil {
				return true, "Firefox"
			}
		}
	}

	proxyArg := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
	chromes := []string{"google-chrome", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"}
	for _, b := range chromes {
		if path, err := exec.LookPath(b); err == nil {
			args := []string{
				fmt.Sprintf("--proxy-server=%s", proxyArg),
				fmt.Sprintf("--user-data-dir=%s", tempProfileDir),
				"--no-first-run",
				"--no-default-browser-check",
				"--no-sandbox",
				targetURL,
			}
			sudoUser := os.Getenv("SUDO_USER")
			if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
				_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), tempProfileDir).Run()
				xauth := filepath.Join("/home", sudoUser, ".Xauthority")
				sudoArgs := append([]string{"-u", sudoUser, "env", "DISPLAY=:0", fmt.Sprintf("XAUTHORITY=%s", xauth), path}, args...)
				cmd := exec.Command("sudo", sudoArgs...)
				if cmd.Start() == nil {
					return true, b
				}
			} else {
				cmd := exec.Command(path, args...)
				if cmd.Start() == nil {
					return true, b
				}
			}
		}
	}

	return false, ""
}

func LaunchRemoteGUIApp(reader *bufio.Reader, client *ssh.Client, host, user, pass, keyPath string, targetOS osdetect.TargetOS) {
	baseDir := GetUniversalBaseDir()
	localPrivKey := filepath.Join(baseDir, "id_tunnel_rsa")
	localPubKey := filepath.Join(baseDir, "id_tunnel_rsa.pub")
	if _, err := os.Stat(localPrivKey); os.IsNotExist(err) {
		_ = exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", localPrivKey).Run()
	}

	pubBytes, err := os.ReadFile(localPubKey)
	if err == nil && client != nil {
		sess, errS := client.NewSession()
		if errS == nil {
			injectCmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", strings.TrimSpace(string(pubBytes)))
			_ = sess.Run(injectCmd)
			sess.Close()
		}
	}

	if client != nil {
		healSess, errH := client.NewSession()
		if errH == nil {
			_ = healSess.Run("command -v xauth >/dev/null 2>&1 || (sudo yum install -y -q xorg-x11-xauth || sudo dnf install -y -q xorg-x11-xauth || sudo apt-get install -y -qq xauth) >/dev/null 2>&1")
			healSess.Close()
		}
	}

	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== DEEP SYSTEM SCAN: PROBING ALL REMOTE BINARIES & APPLICATIONS ===" + Reset)
	fmt.Printf(Yellow+"Executing live target scan: %s@%s (%s)...\n"+Reset, user, host, targetOS)

	discoveredApps := discoverRemoteGUIAndTUIApps(client)
	selectedIndex := 0

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== REMOTE GUI & TUI APPLICATION STREAMING CONSOLE ===" + Reset)
		fmt.Printf(Yellow+"Target Node: "+Reset+Bold+"%s@%s"+Reset+" | "+Yellow+"OS: "+Reset+Bold+"%s"+Reset+" | "+Green+"[Zero Password Mode]"+Reset+"\n", user, host, targetOS)
		fmt.Println(Cyan + "Use [↑/↓] or [W/S] to navigate, [ENTER] to launch, [ESC/Q] to return" + Reset)
		fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)

		menuItems := []string{}
		for _, app := range discoveredApps {
			tag := "[GUI]"
			if app.IsTUI {
				tag = "[TUI/CLI]"
			}
			menuItems = append(menuItems, fmt.Sprintf("%-26s %-10s -> %s", app.Name, tag, app.Exec))
		}
		menuItems = append(menuItems, "⚡ Custom Executable / Command Entry", "⬅ Back to Tunneling Hub")

		if selectedIndex < 0 {
			selectedIndex = 0
		}
		if selectedIndex >= len(menuItems) {
			selectedIndex = len(menuItems) - 1
		}

		for i, item := range menuItems {
			if i == selectedIndex {
				fmt.Printf(Green+Bold+"  ➔ [ %-72s ]\n"+Reset, item)
			} else {
				fmt.Printf(Dim+"    %-74s \n"+Reset, item)
			}
		}

		fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)

		key := readRawKeyStroke()

		switch key {
		case "UP", "w", "W":
			if selectedIndex > 0 {
				selectedIndex--
			} else {
				selectedIndex = len(menuItems) - 1
			}
		case "DOWN", "s", "S":
			if selectedIndex < len(menuItems)-1 {
				selectedIndex++
			} else {
				selectedIndex = 0
			}
		case "ESC", "q", "Q":
			return
		case "ENTER":
			if selectedIndex == len(menuItems)-1 {
				return
			}

			appCmd := ""
			isTUI := false

			if selectedIndex == len(menuItems)-2 {
				appCmd = transfer.ReadRealtimeInput("\nEnter executable name to launch (e.g. htop, glances, wireshark): ")
				isTUI = checkIfCommandIsTUI(appCmd)
			} else {
				appCmd = discoveredApps[selectedIndex].Exec
				isTUI = discoveredApps[selectedIndex].IsTUI
			}

			if strings.TrimSpace(appCmd) != "" {
				launchAppSubprocess(appCmd, user, host, localPrivKey, isTUI)
			}
		}
	}
}

func checkIfCommandIsTUI(cmd string) bool {
	tuiList := []string{"htop", "top", "btop", "glances", "ncdu", "iftop", "nethogs", "iotop", "tmux", "vim", "nano", "mc", "ranger", "gdb", "radare2", "nload", "bmon", "iptraf-ng", "nmap", "tshark", "tcpdump"}
	c := strings.ToLower(strings.TrimSpace(cmd))
	for _, t := range tuiList {
		if c == t {
			return true
		}
	}
	return false
}

func launchAppSubprocess(appCmd, user, host, localPrivKey string, isTUI bool) {
	fmt.Printf(Yellow+"\n[+] Initializing execution channel for '%s'...\n"+Reset, appCmd)

	sudoUser := os.Getenv("SUDO_USER")
	if isTUI {
		fmt.Printf(Green+"[✔] Spawning dedicated pseudo-terminal for TUI executable: %s\n"+Reset, appCmd)
		terms := []string{"x-terminal-emulator", "gnome-terminal", "xfce4-terminal", "qterminal", "alacritty", "kitty", "xterm"}
		spawned := false
		for _, term := range terms {
			if path, err := exec.LookPath(term); err == nil {
				sshFullCmd := fmt.Sprintf("ssh -t -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s '%s'", localPrivKey, user, host, appCmd)
				var cmd *exec.Cmd
				if term == "gnome-terminal" || term == "xfce4-terminal" || term == "qterminal" {
					cmd = exec.Command(path, "--", "bash", "-c", sshFullCmd)
				} else {
					cmd = exec.Command(path, "-e", "bash", "-c", sshFullCmd)
				}
				if cmd.Start() == nil {
					spawned = true
					break
				}
			}
		}

		if !spawned {
			cmd := exec.Command("ssh", "-t", "-i", localPrivKey, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("%s@%s", user, host), appCmd)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
		}
	} else {
		sshArgs := []string{
			"-X", "-Y", "-C",
			"-i", localPrivKey,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			fmt.Sprintf("%s@%s", user, host),
			appCmd,
		}

		var cmd *exec.Cmd
		if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
			xauth := filepath.Join("/home", sudoUser, ".Xauthority")
			sudoArgs := append([]string{"-u", sudoUser, "env", "DISPLAY=:0", fmt.Sprintf("XAUTHORITY=%s", xauth), "ssh"}, sshArgs...)
			cmd = exec.Command("sudo", sudoArgs...)
		} else {
			cmd = exec.Command("ssh", sshArgs...)
		}

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			fmt.Printf(Red+"[!] Execution failed: %v\n"+Reset, err)
			pausePrompt()
			return
		}
	}

	fmt.Println(Green + Bold + "[✔ SUCCESS] Process dispatched! Remaining active in console..." + Reset)
	time.Sleep(1200 * time.Millisecond)
}

func discoverRemoteGUIAndTUIApps(client *ssh.Client) []DiscoveredApp {
	var verifiedApps []DiscoveredApp
	if client == nil {
		return verifiedApps
	}

	sess, err := client.NewSession()
	if err != nil {
		return verifiedApps
	}
	defer sess.Close()

	probeScript := `
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:$PATH"
export PATH

for b in htop top btop glances ncdu iftop nethogs iptraf-ng nload bmon iotop tmux mc ranger vim nano gdb radare2 nmap tshark tcpdump curl wget git docker podman kubectl journalctl dmesg bash zsh sh; do
    if command -v "$b" >/dev/null 2>&1 || [ -x "/usr/bin/$b" ] || [ -x "/bin/$b" ] || [ -x "/usr/local/bin/$b" ] || [ -x "/usr/sbin/$b" ]; then
        echo "TUI:::${b}:::${b}"
    fi
done

for d in /usr/share/applications /usr/local/share/applications "$HOME/.local/share/applications"; do
    [ -d "$d" ] || continue
    for f in "$d"/*.desktop; do
        [ -f "$f" ] || continue
        name=$(grep -m1 '^Name=' "$f" 2>/dev/null | cut -d= -f2-)
        exec_line=$(grep -m1 '^Exec=' "$f" 2>/dev/null | cut -d= -f2- | awk '{print $1}')
        [ -z "$name" ] || [ -z "$exec_line" ] && continue
        bin_clean=$(basename "$exec_line")
        if command -v "$bin_clean" >/dev/null 2>&1 || [ -x "/usr/bin/$bin_clean" ] || [ -x "/bin/$bin_clean" ]; then
            echo "GUI:::${name}:::${bin_clean}"
        fi
    done
done
`

	out, err := sess.Output(probeScript)
	if err == nil {
		lines := strings.Split(string(out), "\n")
		seen := make(map[string]bool)
		for _, l := range lines {
			parts := strings.Split(l, ":::")
			if len(parts) == 3 {
				appType := strings.TrimSpace(parts[0])
				name := strings.TrimSpace(parts[1])
				execCmd := strings.TrimSpace(parts[2])

				if name != "" && execCmd != "" && !seen[execCmd] {
					seen[execCmd] = true
					verifiedApps = append(verifiedApps, DiscoveredApp{
						Name:  name,
						Exec:  execCmd,
						IsTUI: (appType == "TUI"),
					})
				}
			}
		}
	}

	return verifiedApps
}

func readRawKeyStroke() string {
	if runtime.GOOS == "windows" {
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}
	_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	_ = exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer func() {
		_ = exec.Command("stty", "-F", "/dev/tty", "-cbreak").Run()
		_ = exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	}()

	var b [3]byte
	n, _ := os.Stdin.Read(b[:])
	if n == 1 {
		if b[0] == 10 || b[0] == 13 {
			return "ENTER"
		}
		if b[0] == 27 {
			return "ESC"
		}
		return string(b[0])
	}
	if n == 3 && b[0] == 27 && b[1] == 91 {
		switch b[2] {
		case 65:
			return "UP"
		case 66:
			return "DOWN"
		case 67:
			return "RIGHT"
		case 68:
			return "LEFT"
		}
	}
	return ""
}

func ShowDockerK8sOrchestratorMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== REMOTE DOCKER & KUBERNETES ORCHESTRATION CONTEXT ===" + Reset)
		fmt.Printf(Yellow+"Target Daemon Link: %s\n"+Reset, host)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Auto-Pipe Remote Docker Daemon Socket (/var/run/docker.sock)")
		fmt.Println("  [2] Live Probe & Inspect Remote Containers (Real docker ps)")
		fmt.Println("  [3] Bridge Remote Kubernetes API & Export Kubeconfig Context")
		fmt.Println("  [4] Custom Docker / Kubernetes TCP Port Forwarder (e.g. 2375 / 6443)")
		fmt.Println(Red + "  [0] Back to Tunneling Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

		switch choice {
		case "1":
			PipeRemoteDockerSocket(reader, client, host)
		case "2":
			inspectRemoteContainersLive(reader, client)
		case "3":
			bridgeKubernetesContext(reader, client, host)
		case "4":
			rPortStr := transfer.ReadRealtimeInput("Enter Remote Daemon TCP Port [2375 (Docker) or 6443 (K8s)]: ")
			rPort, _ := strconv.Atoi(strings.TrimSpace(rPortStr))
			if rPort > 0 {
				startTunnelFlow(reader, client, "Custom-Container-Daemon", rPort)
			}
		case "0", "q", "Q":
			return
		}
	}
}

func inspectRemoteContainersLive(reader *bufio.Reader, client *ssh.Client) {
	if client == nil {
		fmt.Println(Red + "[!] SSH client is not active." + Reset)
		pausePrompt()
		return
	}
	sess, err := client.NewSession()
	if err != nil {
		fmt.Printf(Red+"[!] Session failure: %v\n"+Reset, err)
		pausePrompt()
		return
	}
	defer sess.Close()

	fmt.Println(Yellow + "\n[+] Querying remote Docker daemon for active containers..." + Reset)
	out, err := sess.CombinedOutput("docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null || podman ps 2>/dev/null")
	if err != nil || len(out) == 0 {
		fmt.Println(Yellow + "[!] Docker daemon unreachable or no active containers found on target." + Reset)
	} else {
		fmt.Println(Green + Bold + "\n=== LIVE REMOTE CONTAINER INVENTORY ===" + Reset)
		fmt.Println(string(out))
	}
	pausePrompt()
}

func bridgeKubernetesContext(reader *bufio.Reader, client *ssh.Client, host string) {
	fmt.Println(Yellow + "\n[+] Pulling remote kubeconfig credentials & forwarding API server (6443)..." + Reset)
	startTunnelFlow(reader, client, "K8s-APIServer", 6443)

	sess, err := client.NewSession()
	if err == nil {
		defer sess.Close()
		kcOut, errK := sess.Output("cat ~/.kube/config 2>/dev/null || sudo cat /etc/rancher/k3s/k3s.yaml 2>/dev/null")
		if errK == nil && len(kcOut) > 0 {
			home, _ := os.UserHomeDir()
			localKube := filepath.Join(home, ".kube", fmt.Sprintf("remote_%s.yaml", strings.ReplaceAll(host, ".", "_")))
			_ = os.MkdirAll(filepath.Dir(localKube), 0755)
			_ = os.WriteFile(localKube, kcOut, 0600)
			fmt.Printf(Green+Bold+"[✔] Saved isolated Kubeconfig context to: %s\n"+Reset, localKube)
			fmt.Printf(Cyan+"=> Run locally: 'kubectl --kubeconfig=%s get nodes'\n"+Reset, localKube)
		}
	}
	pausePrompt()
}

func PipeRemoteDockerSocket(reader *bufio.Reader, client *ssh.Client, host string) {
	localSock := filepath.Join(os.TempDir(), "remote_docker.sock")
	_ = os.Remove(localSock)

	fmt.Printf(Yellow+"\n[+] Forwarding %s to remote /var/run/docker.sock...\n"+Reset, localSock)

	l, err := net.Listen("unix", localSock)
	if err != nil {
		startTunnelFlow(reader, client, "Docker-Daemon", 2375)
		return
	}

	go func() {
		for {
			cConn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rConn, err := client.Dial("unix", "/var/run/docker.sock")
				if err != nil {
					return
				}
				defer rConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); _, _ = io.Copy(rConn, c) }()
				go func() { defer wg.Done(); _, _ = io.Copy(c, rConn) }()
				wg.Wait()
			}(cConn)
		}
	}()

	fmt.Println(Green + Bold + "\n[✔ SUCCESS] Docker Socket Bridge Active!" + Reset)
	fmt.Println(Cyan + "=> Execute this in any terminal to control the remote host's containers:" + Reset)
	fmt.Println(Yellow + Bold + fmt.Sprintf("   export DOCKER_HOST=\"unix://%s\"", localSock) + Reset)
	fmt.Println(Cyan + "=> Then run: 'docker ps', 'docker logs <container>', or 'docker build'!" + Reset)
	pausePrompt()
}

func ShowReverseIngressMenu(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== REVERSE INGRESS SERVICE EXPOSER ===" + Reset)
	fmt.Println(Yellow + "Expose a port running on YOUR local machine so the Remote Target can access it!" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] Expose Local Web App (Port 3000 / 5000 / 8000 / 8080)")
	fmt.Println("  [2] Expose Local Database (MySQL 3306 / PostgreSQL 5432 / Redis 6379)")
	fmt.Println("  [3] Expose Local Webhook Listener (Port 9000 / 4444)")
	fmt.Println("  [4] Custom Local Ingress Port")
	fmt.Println(Red + "  [0] Cancel" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select preset [0-4]: ")
	localPort := 0
	svcName := ""

	switch choice {
	case "1":
		pStr := transfer.ReadRealtimeInput("Enter Local Web Port [default 3000]: ")
		localPort, _ = strconv.Atoi(strings.TrimSpace(pStr))
		if localPort == 0 {
			localPort = 3000
		}
		svcName = fmt.Sprintf("Local-Web-%d", localPort)
	case "2":
		pStr := transfer.ReadRealtimeInput("Enter Local Database Port [default 3306]: ")
		localPort, _ = strconv.Atoi(strings.TrimSpace(pStr))
		if localPort == 0 {
			localPort = 3306
		}
		svcName = fmt.Sprintf("Local-DB-%d", localPort)
	case "3":
		pStr := transfer.ReadRealtimeInput("Enter Local Webhook Port [default 9000]: ")
		localPort, _ = strconv.Atoi(strings.TrimSpace(pStr))
		if localPort == 0 {
			localPort = 9000
		}
		svcName = fmt.Sprintf("Local-Webhook-%d", localPort)
	case "4":
		pStr := transfer.ReadRealtimeInput("Enter Custom Local Port: ")
		localPort, _ = strconv.Atoi(strings.TrimSpace(pStr))
		svcName = transfer.ReadRealtimeInput("Enter Service Label: ")
	default:
		return
	}

	if localPort <= 0 {
		return
	}

	remotePortStr := transfer.ReadRealtimeInput(fmt.Sprintf("Enter Target Host Port to bind [Press Enter for %d]: ", localPort))
	remotePort := localPort
	if p, err := strconv.Atoi(strings.TrimSpace(remotePortStr)); err == nil && p > 0 {
		remotePort = p
	}

	rListener, err := client.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
	if err != nil {
		fallbackPort := remotePort + 10000
		fmt.Printf(Yellow+"[!] Port %d occupied or restricted on remote. Auto-binding to fallback port %d...\n"+Reset, remotePort, fallbackPort)
		rListener, err = client.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", fallbackPort))
		if err != nil {
			fmt.Printf(Red+"[!] Reverse ingress failed: %v\n"+Reset, err)
			pausePrompt()
			return
		}
		remotePort = fallbackPort
	}

	tunnelMutex.Lock()
	t := &ActiveTunnel{
		ID:          nextID,
		LocalPort:   localPort,
		RemotePort:  remotePort,
		ServiceName: svcName,
		Listener:    rListener,
		StopChan:    make(chan bool),
		StartTime:   time.Now(),
		IsReverse:   true,
	}
	nextID++
	tunnels = append(tunnels, t)
	tunnelMutex.Unlock()

	go func(t *ActiveTunnel, l net.Listener) {
		for {
			rConn, err := l.Accept()
			if err != nil {
				select {
				case <-t.StopChan:
					return
				default:
					continue
				}
			}
			go func(remoteConn net.Conn) {
				defer remoteConn.Close()
				lConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", t.LocalPort))
				if err != nil {
					return
				}
				defer lConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); _, _ = io.Copy(lConn, remoteConn) }()
				go func() { defer wg.Done(); _, _ = io.Copy(remoteConn, lConn) }()
				wg.Wait()
			}(rConn)
		}
	}(t, rListener)

	fmt.Println(Green + Bold + "\n[✔ SUCCESS] Reverse Ingress Port Active Without Passwords!" + Reset)
	fmt.Printf(Cyan+" Local Port 127.0.0.1:%d is now live on Target Host Port %d!\n"+Reset, localPort, remotePort)
	pausePrompt()
}

// === P2P COMMUNICATIONS & MATRIX ===

func ShowP2PCommunicationsMatrix(reader *bufio.Reader, client *ssh.Client, host, currentUser string) {
	StartUSBAudioHotplugDaemon()

	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		alias := getMeshAliasForIP(host)
		displayName := host
		if host == "" {
			displayName = "No Target Dialed (Local Standalone Mode)"
		} else if alias != "" {
			displayName = fmt.Sprintf("%s (%s)", alias, host)
		}

		realUser := GetLocalNodeIdentity()

		fmt.Println(Cyan + Bold + "=== P2P MESH INTERCOM, VOIP & MESSENGER MATRIX ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Active Selected Peer: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"My Node ID: "+Reset+Bold+"%s\n"+Reset, displayName, realUser)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println(Cyan + Bold + "  [1] Select / Dial Target Peer from Mesh Phonebook & Vault" + Reset)
		fmt.Println(Green + Bold + "  [2] Duplex VoIP Audio Phone & Intercom (Call / Answer / Ringtone / Vol)" + Reset)
		fmt.Println("  [3] Voice Memo Studio & Audio Vault (Record, Dispatch & Inbox)")
		fmt.Println(Cyan + Bold + "  [4] Multi-Peer Synced Messenger Matrix" + Reset)
		fmt.Println(Yellow + "  [5] Troubleshoot Audio Subsystem & Hardware Endpoints" + Reset)
		fmt.Println(Red + "  [0] Return to Previous Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-5]: ")

		switch choice {
		case "1":
			host = showMeshPhonebookMenu(reader, host)
		case "2":
			if client == nil || host == "" {
				fmt.Println(Yellow + "\n[!] VoIP Call Channel requires an active SSH connection to the peer." + Reset)
				pausePrompt()
				continue
			}
			ShowVoIPPhoneDispatchMenu(reader, client, host, realUser)
		case "3":
			ShowUnifiedVoiceMemoMenu(reader, client, host, realUser)
		case "4":
			showThreadedMessengerMenu(reader, client, host, realUser)
		case "5":
			ShowMicrophoneTroubleshooterMenu(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func sanitizePeerTag(peer string) string {
	if peer == "" {
		return "standalone"
	}
	clean := strings.ReplaceAll(peer, ".", "_")
	clean = strings.ReplaceAll(clean, ":", "_")
	clean = strings.ReplaceAll(clean, "@", "_")
	clean = strings.ReplaceAll(clean, " ", "_")
	return clean
}

func getPeerAudioDir(peer, category string) string {
	tag := sanitizePeerTag(peer)
	dir := filepath.Join(os.TempDir(), "cross_voicenotes", "peers", tag, category)
	_ = os.MkdirAll(dir, 0777)
	return dir
}

func ShowUnifiedVoiceMemoMenu(reader *bufio.Reader, client *ssh.Client, host, author string) {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		alias := getMeshAliasForIP(host)
		displayName := host
		if host == "" {
			displayName = "Standalone Mode (All Received Peer Audio)"
		} else if alias != "" {
			displayName = fmt.Sprintf("%s (%s)", alias, host)
		}

		fmt.Println(Cyan + Bold + "=== VOICE MEMO STUDIO & AUDIO VAULT ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Context Peer: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"My Node ID: "+Reset+Bold+"%s\n"+Reset, displayName, author)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println(Green + Bold + "  [1] Record & Send New Voice Memo (Direct Hardware WAV Capture)" + Reset)
		fmt.Println(Cyan + Bold + "  [2] Voice Memo Inbox & Archives (Strict Peer-Isolated Buffers)" + Reset)
		fmt.Println("  [3] Sync & Pull Inbound Audio Memos from Target Peer")
		fmt.Println("  [4] Purge Temporary Audio Buffer for Active Peer")
		fmt.Println(Red + "  [0] Return to P2P Matrix" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select memo option [0-4]: ")

		switch choice {
		case "1":
			if client == nil || host == "" {
				fmt.Println(Yellow + "\n[!] Active connection to peer required to send voice memos." + Reset)
				pausePrompt()
				continue
			}
			RecordAndSendVoiceNote(reader, client, host, author)
		case "2":
			ShowVoiceMemoInboxMenu(reader, client, host)
		case "3":
			if client == nil || host == "" {
				fmt.Println(Yellow + "\n[!] Active connection to peer required to sync remote memos." + Reset)
				pausePrompt()
				continue
			}
			syncRemoteVoiceMemos(reader, client, host, author)
		case "4":
			tag := sanitizePeerTag(host)
			_ = os.RemoveAll(filepath.Join(os.TempDir(), "cross_voicenotes", "peers", tag))
			_ = os.RemoveAll(filepath.Join(GetUniversalBaseDir(), "voicenotes", "peers", tag))
			if client != nil {
				sess, _ := client.NewSession()
				if sess != nil {
					_ = sess.Run(fmt.Sprintf("sh -c 'rm -rf /tmp/cross_voicenotes/peers/%s ~/.cross-ssh/voicenotes/peers/%s 2>/dev/null; sync'", tag, tag))
					sess.Close()
				}
			}
			fmt.Println(Green + Bold + "\n[✔ SUCCESS] Peer-specific voice memos purged cleanly on both endpoints!" + Reset)
			pausePrompt()
		case "0", "q", "Q":
			return
		}
	}
}

func writeCompleteWavHeader(w io.Writer, dataSize int, sampleRate int, channels int, bitsPerSample int) {
	byteRate := sampleRate * channels * bitsPerSample / 8
	blockAlign := channels * bitsPerSample / 8

	header := make([]byte, 44)
	copy(header[0:4], "RIFF")
	binary.LittleEndian.PutUint32(header[4:8], uint32(36+dataSize))
	copy(header[8:12], "WAVE")
	copy(header[12:16], "fmt ")
	binary.LittleEndian.PutUint32(header[16:20], 16)
	binary.LittleEndian.PutUint16(header[20:22], 1)
	binary.LittleEndian.PutUint16(header[22:24], uint16(channels))
	binary.LittleEndian.PutUint32(header[24:28], uint32(sampleRate))
	binary.LittleEndian.PutUint32(header[28:32], uint32(byteRate))
	binary.LittleEndian.PutUint16(header[32:34], uint16(blockAlign))
	binary.LittleEndian.PutUint16(header[34:36], uint16(bitsPerSample))
	copy(header[36:40], "data")
	binary.LittleEndian.PutUint32(header[40:44], uint32(dataSize))

	_, _ = w.Write(header)
}

func renderDynamicVUBar(rms float64, currentLevel *float64, maxBars int) string {
	targetLevel := 0.0
	if rms > 12.0 {
		dB := 20.0 * math.Log10(rms)
		targetLevel = (dB - 22.0) / (68.0 - 22.0)
		if targetLevel < 0.0 {
			targetLevel = 0.0
		}
		if targetLevel > 1.0 {
			targetLevel = 1.0
		}
	}

	if targetLevel > *currentLevel {
		*currentLevel = targetLevel
	} else {
		*currentLevel = *currentLevel*0.60 + targetLevel*0.40
	}

	activeBars := int(math.Round(*currentLevel * float64(maxBars)))
	if activeBars > maxBars {
		activeBars = maxBars
	}
	if activeBars < 0 {
		activeBars = 0
	}

	var sb strings.Builder
	for i := 0; i < maxBars; i++ {
		if i < activeBars {
			if i < int(float64(maxBars)*0.60) {
				sb.WriteString(Green + "█" + Reset)
			} else if i < int(float64(maxBars)*0.85) {
				sb.WriteString(Yellow + "█" + Reset)
			} else {
				sb.WriteString(Red + "█" + Reset)
			}
		} else {
			sb.WriteString(Dim + "░" + Reset)
		}
	}
	return sb.String()
}

// MODIFIED: RecordAndSendVoiceNote with proper WAV parsing
func RecordAndSendVoiceNote(reader *bufio.Reader, client *ssh.Client, host, author string) {
	defer restoreTerminalState()
	fmt.Print("\033[H\033[2J")
	alias := getMeshAliasForIP(host)
	targetDisplay := host
	if alias != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
	}

	fmt.Println(Cyan + Bold + "=== VOICE MEMO RECORDING STUDIO ===" + Reset)
	RenderAudioStatusToast()
	fmt.Printf(Yellow+"Target Peer: %s | Dynamic Studio Capture\n"+Reset, targetDisplay)
	fmt.Println(Blue + "-------------------------------------------------------------------------------------------------------" + Reset)
	fmt.Println(Green + Bold + "  [1] Fixed Timer Mode (Set recording length in seconds)" + Reset)
	fmt.Println(Cyan + Bold + "  [2] Continuous Mode (Speak freely -> Press ENTER to Finish & Send)" + Reset)
	fmt.Println(Red + "  [0] Cancel" + Reset)
	fmt.Println(Blue + "-------------------------------------------------------------------------------------------------------" + Reset)

	modeChoice := transfer.ReadRealtimeInput("Select recording mode [1/2/0]: ")
	if modeChoice == "0" || strings.ToLower(modeChoice) == "q" {
		return
	}

	isContinuous := (modeChoice == "2")
	durationSec := 10

	if !isContinuous {
		durStr := transfer.ReadRealtimeInput("\nEnter recording length in seconds [default: 10s]: ")
		if d, err := strconv.Atoi(strings.TrimSpace(durStr)); err == nil && d > 0 {
			durationSec = d
		}
	}

	ensureAudioToolsInstalled()
	enforceHardwareAudioLocks()

	sentDir := getPeerAudioDir(host, "sent")
	timestamp := time.Now().UTC().Unix()
	localEncAudio := filepath.Join(sentDir, fmt.Sprintf("sent_to_%s_%d.encwav", sanitizePeerTag(host), timestamp))
	rawTempWav := filepath.Join(os.TempDir(), fmt.Sprintf("raw_rec_%d.wav", timestamp))
	defer os.Remove(rawTempWav)

	selectedSource := getActiveSelectedMicSource()

	args := []string{"--rate=48000", "--channels=1", "--format=s16le", "--file-format=wav", "--latency-msec=80"}
	if selectedSource != "" {
		args = append([]string{"-d", selectedSource}, args...)
	}
	args = append(args, rawTempWav)
	recCmd := getDesktopAudioUserCmd("parec", args...)

	if err := recCmd.Start(); err != nil {
		fmt.Printf(Red+"[!] Audio recording start failed: %v\n"+Reset, err)
		pausePrompt()
		return
	}

	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== RECORDING IN PROGRESS ===" + Reset)
	if isContinuous {
		fmt.Printf(Green+Bold+"[LIVE]: Speak into microphone... %s[PRESS ENTER OR SPACE WHEN FINISHED]%s\n\n"+Reset, Yellow+Bold, Reset)
	} else {
		fmt.Printf(Green+Bold+"[LIVE]: Speak into microphone (%d seconds fixed timer)...\n\n"+Reset, durationSec)
	}

	stopSignal := make(chan bool, 1)

	if isContinuous {
		if runtime.GOOS != "windows" {
			_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
		}

		go func() {
			var b [1]byte
			for {
				n, _ := os.Stdin.Read(b[:])
				if n > 0 {
					k := b[0]
					if k == 10 || k == 13 || k == ' ' || k == 's' || k == 'S' {
						stopSignal <- true
						return
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}

	startTime := time.Now()
	smoothedLevel := 0.0
	targetDuration := time.Duration(durationSec) * time.Second

	var latestVU float64 = 0.0
	var vuMutex sync.Mutex
	ctxVU, cancelVU := context.WithCancel(context.Background())

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctxVU.Done():
				return
			default:
				if fi, err := os.Stat(rawTempWav); err == nil && fi.Size() > 4096 {
					f, errO := os.OpenFile(rawTempWav, os.O_RDONLY, 0)
					if errO == nil {
						_, _ = f.Seek(-2048, io.SeekEnd)
						n, _ := f.Read(buf)
						_ = f.Close()

						if n > 0 {
							sum := 0.0
							samples := n / 2
							for i := 0; i < n-1; i += 2 {
								val := int16(buf[i]) | (int16(buf[i+1]) << 8)
								sum += float64(val) * float64(val)
							}
							rms := math.Sqrt(sum / float64(samples+1))
							vuMutex.Lock()
							latestVU = rms
							vuMutex.Unlock()
						}
					}
				}
				time.Sleep(30 * time.Millisecond)
			}
		}
	}()

	for {
		elapsed := time.Since(startTime)

		if isContinuous {
			select {
			case <-stopSignal:
				goto EndRecording
			default:
				if elapsed >= 10*time.Minute {
					goto EndRecording
				}
			}
		} else {
			if elapsed >= targetDuration {
				goto EndRecording
			}
		}

		vuMutex.Lock()
		curRMS := latestVU
		vuMutex.Unlock()

		meter := renderDynamicVUBar(curRMS, &smoothedLevel, 32)

		if isContinuous {
			elapsedSec := int(elapsed.Seconds())
			fmt.Printf("\r\033[K%s[RECORDING]:%s VU [%s] %s%02d:%02d%s (Press ENTER to finish)...", Cyan+Bold, Reset, meter, Yellow+Bold, elapsedSec/60, elapsedSec%60, Reset)
		} else {
			remainingSec := int(math.Ceil((targetDuration - elapsed).Seconds()))
			if remainingSec < 0 {
				remainingSec = 0
			}
			fmt.Printf("\r\033[K%s[RECORDING]:%s VU [%s] %s%ds%s remaining...", Cyan+Bold, Reset, meter, Yellow+Bold, remainingSec, Reset)
		}

		time.Sleep(35 * time.Millisecond)
	}

EndRecording:
	cancelVU()
	if recCmd.Process != nil {
		_ = recCmd.Process.Signal(os.Interrupt)
		time.Sleep(150 * time.Millisecond)
		_ = recCmd.Process.Kill()
		_ = recCmd.Wait()
	}
	restoreTerminalState()

	actualDuration := int(math.Ceil(time.Since(startTime).Seconds()))
	if actualDuration <= 0 {
		actualDuration = 1
	}

	rawAudioBytes, errRead := os.ReadFile(rawTempWav)
	if errRead != nil || len(rawAudioBytes) < 500 {
		fmt.Printf(Red+"\n[!] Audio recording failed or was empty. Check Audio Troubleshooter.\n"+Reset)
		pausePrompt()
		return
	}

	// --- NEW: Extract raw PCM, normalise, re-wrap with clean header ---
	pcmData, err := extractRawPCMFromWAV(rawAudioBytes)
	if err != nil {
		fmt.Printf(Red+"\n[!] Failed to parse recorded WAV: %v\n"+Reset, err)
		pausePrompt()
		return
	}
	if len(pcmData) < 500 {
		fmt.Printf(Red+"\n[!] Audio recording too short or empty.\n"+Reset)
		pausePrompt()
		return
	}

	// Normalize volume
	numSamples := len(pcmData) / 2
	var maxAmp int16 = 0
	for i := 0; i < numSamples; i++ {
		val := int16(binary.LittleEndian.Uint16(pcmData[i*2 : i*2+2]))
		absVal := val
		if absVal < 0 {
			if absVal == -32768 {
				absVal = 32767
			} else {
				absVal = -absVal
			}
		}
		if absVal > maxAmp {
			maxAmp = absVal
		}
	}
	if maxAmp > 40 {
		targetPeak := 30000.0
		gain := targetPeak / float64(maxAmp)
		if gain > 6.0 {
			gain = 6.0
		}
		if gain < 1.0 {
			gain = 1.0
		}
		for i := 0; i < numSamples; i++ {
			val := int16(binary.LittleEndian.Uint16(pcmData[i*2 : i*2+2]))
			boosted := float64(val) * gain
			if boosted > 32767.0 {
				boosted = 32767.0
			} else if boosted < -32768.0 {
				boosted = -32768.0
			}
			binary.LittleEndian.PutUint16(pcmData[i*2:i*2+2], uint16(int16(boosted)))
		}
	}

	// Build pristine WAV with our own 44‑byte header
	var wavBuf bytes.Buffer
	writeCompleteWavHeader(&wavBuf, len(pcmData), 48000, 1, 16)
	wavBuf.Write(pcmData)
	cleanWavBytes := wavBuf.Bytes()

	encAudioString, errEnc := encryptPayloadAES(cleanWavBytes)
	if errEnc != nil {
		fmt.Printf(Red+"\n[!] Audio encryption failed: %v\n"+Reset, errEnc)
		pausePrompt()
		return
	}

	_ = os.WriteFile(localEncAudio, []byte(encAudioString), 0600)

	fmt.Printf(Yellow+"\n\n[+] Transmitting %d-second crystal voice memo to remote host...\n"+Reset, actualDuration)

	if client != nil {
		myIP := getLocalOutboundIP(host)
		authorTag := sanitizePeerTag(myIP)
		fileName := fmt.Sprintf("from_%s_%d.encwav", authorTag, timestamp)

		prepCmd := fmt.Sprintf(`sh -c 'mkdir -p /tmp/cross_voicenotes/received /tmp/cross_voicenotes/peers/%s/received "$HOME/.cross-ssh/voicenotes/received" "$HOME/.cross-ssh/voicenotes/peers/%s/received" 2>/dev/null; chmod -R 777 /tmp/cross_voicenotes 2>/dev/null || true'`, authorTag, authorTag)

		initSess, errI := client.NewSession()
		if errI == nil {
			_ = initSess.Run(prepCmd)
			initSess.Close()
		}

		streamSess, errS := client.NewSession()
		if errS == nil {
			rStdin, errP := streamSess.StdinPipe()
			if errP == nil {
				transferScript := fmt.Sprintf(`sh -c 'cat > /tmp/%s && `+
					`cp -f /tmp/%s /tmp/cross_voicenotes/received/%s 2>/dev/null; `+
					`cp -f /tmp/%s /tmp/cross_voicenotes/peers/%s/received/%s 2>/dev/null; `+
					`cp -f /tmp/%s "$HOME/.cross-ssh/voicenotes/received/%s" 2>/dev/null; `+
					`cp -f /tmp/%s "$HOME/.cross-ssh/voicenotes/peers/%s/received/%s" 2>/dev/null; `+
					`chmod 666 /tmp/cross_voicenotes/received/%s "$HOME/.cross-ssh/voicenotes/received/%s" 2>/dev/null; `+
					`rm -f /tmp/%s 2>/dev/null; sync'`,
					fileName, fileName, fileName, fileName, authorTag, fileName, fileName, fileName, fileName, authorTag, fileName, fileName, fileName, fileName)

				if errStart := streamSess.Start(transferScript); errStart == nil {
					_, _ = io.WriteString(rStdin, encAudioString+"\n")
					_ = rStdin.Close()
					_ = streamSess.Wait()
				}
			}
			streamSess.Close()
		}
	}

	dispatchNotification(client, host, author, "VOICE_MEMO", fmt.Sprintf("Incoming %d-second voice memo delivered", actualDuration))
	fmt.Printf(Green+Bold+"[✔ SUCCESS] %d-second loud, crystal-clear voice memo delivered!\n"+Reset, actualDuration)
	pausePrompt()
}

func ShowVoiceMemoInboxMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	if client != nil {
		syncRemoteVoiceMemosSilent(client, host, GetLocalNodeIdentity())
	}

	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		alias := getMeshAliasForIP(host)
		targetDisplay := host
		if host == "" {
			targetDisplay = "All Discovered Peers (Standalone Mode)"
		} else if alias != "" {
			targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
		}

		fmt.Println(Cyan + Bold + "=== VOICE MEMO INBOX (RECORDINGS ARCHIVE) ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Filtered Peer Context: "+Reset+Bold+"%s"+Reset+"\n", targetDisplay)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] View & Listen to SENT Voice Memos")
		fmt.Println("  [2] View & Listen to RECEIVED Voice Memos")
		fmt.Println("  [3] Sync & Pull Inbound Audio Memos from Target Peer")
		fmt.Println(Red + Bold + "  [4] 🗑️ Purge Voice Memos (Sent / Received Archive Cleaner)" + Reset)
		fmt.Println(Red + "  [0] Return to Memo Studio" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select category [0-4]: ")

		switch choice {
		case "1":
			listAndPlayVoiceMemos(reader, host, "sent")
		case "2":
			if client != nil {
				syncRemoteVoiceMemosSilent(client, host, GetLocalNodeIdentity())
			}
			listAndPlayVoiceMemos(reader, host, "received")
		case "3":
			if client == nil || host == "" {
				fmt.Println(Yellow + "\n[!] Active connection to peer required to sync remote memos." + Reset)
				pausePrompt()
				continue
			}
			syncRemoteVoiceMemos(reader, client, host, GetLocalNodeIdentity())
		case "4":
			showPurgeVoiceMemosMenu(reader, client, host)
		case "0", "q", "Q":
			return
		}
	}
}

func showPurgeVoiceMemosMenu(reader *bufio.Reader, client *ssh.Client, host string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Red + Bold + "=== 🗑️ VOICE MEMO PURGE & CLEANUP MATRIX ===" + Reset)
		fmt.Println(Yellow + "Select purge scope to permanently delete audio recordings:" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println(Red + "  [1] Purge ALL SENT Voice Memos (Local & Peer Sent Buffers)" + Reset)
		fmt.Println(Red + "  [2] Purge ALL RECEIVED Voice Memos (Local & Remote Sync Buffers)" + Reset)
		fmt.Println(Red + Bold + "  [3] PURGE EVERYTHING (Permanent Wipe Across Local & Remote Host)" + Reset)
		fmt.Println(Cyan + "  [0] Back to Voice Memo Inbox" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select purge option [0-3]: ")

		switch choice {
		case "1":
			confirm := transfer.ReadRealtimeInput(Red + "Are you sure you want to delete SENT voice memos? [y/N]: " + Reset)
			if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
				purgeVoiceMemoCategory("sent", host, client)
				fmt.Println(Green + Bold + "\n[✔ SUCCESS] Sent voice memos purged successfully!" + Reset)
				pausePrompt()
			}
		case "2":
			confirm := transfer.ReadRealtimeInput(Red + "Are you sure you want to delete RECEIVED voice memos? [y/N]: " + Reset)
			if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
				purgeVoiceMemoCategory("received", host, client)
				MarkNotificationRead("VOICE_MEMO", "")
				fmt.Println(Green + Bold + "\n[✔ SUCCESS] Received voice memos purged locally and from remote sync buffers!" + Reset)
				pausePrompt()
			}
		case "3":
			confirm := transfer.ReadRealtimeInput(Red + Bold + "WARNING: This will permanently delete ALL audio files on BOTH sides! Proceed? [y/N]: " + Reset)
			if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
				purgeVoiceMemoCategory("sent", "", client)
				purgeVoiceMemoCategory("received", "", client)

				targetDirs := []string{
					filepath.Join(os.TempDir(), "cross_voicenotes"),
					filepath.Join(GetUniversalBaseDir(), "voicenotes"),
					"/tmp/cross_voicenotes",
					"/root/.cross-ssh/voicenotes",
				}
				sudoUser := os.Getenv("SUDO_USER")
				if sudoUser != "" && sudoUser != "root" {
					targetDirs = append(targetDirs, filepath.Join("/home", sudoUser, ".cross-ssh", "voicenotes"))
				}
				for _, td := range targetDirs {
					_ = os.RemoveAll(td)
				}

				_ = os.MkdirAll(filepath.Join(os.TempDir(), "cross_voicenotes", "received"), 0777)
				_ = os.MkdirAll(filepath.Join(GetUniversalBaseDir(), "voicenotes", "received"), 0777)

				if client != nil {
					sess, errS := client.NewSession()
					if errS == nil {
						_ = sess.Run("sh -c 'rm -rf /tmp/cross_voicenotes ~/.cross-ssh/voicenotes; mkdir -p /tmp/cross_voicenotes/received ~/.cross-ssh/voicenotes/received && chmod -R 777 /tmp/cross_voicenotes ~/.cross-ssh/voicenotes 2>/dev/null; sync'")
						sess.Close()
					}
				}

				MarkNotificationRead("", "")
				fmt.Println(Green + Bold + "\n[✔ SUCCESS] Entire voice memo archive completely wiped on both nodes!" + Reset)
				pausePrompt()
			}
		case "0", "q", "Q":
			return
		}
	}
}

func purgeVoiceMemoCategory(category, peerHost string, client *ssh.Client) {
	searchRoots := []string{
		filepath.Join(os.TempDir(), "cross_voicenotes"),
		filepath.Join(GetUniversalBaseDir(), "voicenotes"),
		"/tmp/cross_voicenotes",
		"/root/.cross-ssh/voicenotes",
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		searchRoots = append(searchRoots, filepath.Join("/home", sudoUser, ".cross-ssh", "voicenotes"))
	}

	for _, root := range searchRoots {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && (strings.HasSuffix(info.Name(), ".encwav") || strings.HasSuffix(info.Name(), ".wav")) {
				lowerName := strings.ToLower(info.Name())
				lowerPath := strings.ToLower(p)

				isTarget := false
				if category == "sent" {
					if strings.HasPrefix(lowerName, "sent_") || strings.Contains(lowerPath, "/sent/") || strings.Contains(lowerPath, "\\sent\\") {
						isTarget = true
					}
				} else if category == "received" {
					if strings.HasPrefix(lowerName, "from_") || strings.Contains(lowerPath, "/received/") || strings.Contains(lowerPath, "\\received\\") {
						isTarget = true
					}
				}

				if isTarget {
					_ = os.Remove(p)
				}
			}
			return nil
		})
	}

	if peerHost != "" {
		tag := sanitizePeerTag(peerHost)
		for _, root := range searchRoots {
			_ = os.RemoveAll(filepath.Join(root, "peers", tag, category))
		}
	}

	if category == "received" && client != nil {
		sess, errS := client.NewSession()
		if errS == nil {
			_ = sess.Run("sh -c 'rm -rf /tmp/cross_voicenotes/received/* ~/.cross-ssh/voicenotes/received/* /tmp/cross_voicenotes/peers/* ~/.cross-ssh/voicenotes/peers/* 2>/dev/null; sync'")
			sess.Close()
		}
	}
}

// MODIFIED: listAndPlayVoiceMemos – uses the new parser for playback
func listAndPlayVoiceMemos(reader *bufio.Reader, peerHost, category string) {
	var files []struct {
		Path     string
		FileName string
		Size     int64
		ModTime  time.Time
		Peer     string
	}

	seenFileNames := make(map[string]bool)
	cleanPeerTag := sanitizePeerTag(peerHost)
	alias := vault.ResolveAliasForIP(peerHost)

	myOutboundIP := getLocalOutboundIP(peerHost)
	myAuthorTag := sanitizePeerTag(myOutboundIP)
	myNodeID := GetLocalNodeIdentity()

	searchRoots := []string{
		getPeerAudioDir(peerHost, category),
		filepath.Join(GetUniversalBaseDir(), "voicenotes", "peers", cleanPeerTag, category),
		filepath.Join(os.TempDir(), "cross_voicenotes", "peers", cleanPeerTag, category),
		filepath.Join(GetUniversalBaseDir(), "voicenotes", category),
		filepath.Join(os.TempDir(), "cross_voicenotes", category),
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		searchRoots = append(searchRoots,
			filepath.Join("/home", sudoUser, ".cross-ssh", "voicenotes", "peers", cleanPeerTag, category),
			filepath.Join("/home", sudoUser, ".cross-ssh", "voicenotes", category),
		)
	}

	for _, root := range searchRoots {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && (strings.HasSuffix(info.Name(), ".encwav") || strings.HasSuffix(info.Name(), ".wav")) {
				lowerName := strings.ToLower(info.Name())
				isMatch := false

				if category == "sent" {
					if strings.HasPrefix(lowerName, "sent_to_") {
						isMatch = true
					}
				} else if category == "received" {
					if strings.HasPrefix(lowerName, "from_") {
						if !strings.HasPrefix(lowerName, fmt.Sprintf("from_%s_", myAuthorTag)) &&
							!strings.HasPrefix(lowerName, fmt.Sprintf("from_%s_", sanitizePeerTag(myNodeID))) {
							isMatch = true
						}
					}
				}

				if isMatch && !seenFileNames[info.Name()] {
					seenFileNames[info.Name()] = true
					originPeer := peerHost
					if originPeer == "" {
						originPeer = "Remote-Peer"
					}
					if alias != "" {
						originPeer = fmt.Sprintf("%s (%s)", alias, peerHost)
					}

					files = append(files, struct {
						Path     string
						FileName string
						Size     int64
						ModTime  time.Time
						Peer     string
					}{Path: p, FileName: info.Name(), Size: info.Size(), ModTime: info.ModTime(), Peer: originPeer})
				}
			}
			return nil
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	fmt.Print("\033[H\033[2J")
	fmt.Printf(Cyan+Bold+"=== %s ENCRYPTED VOICE MEMOS [%s] ===\n"+Reset, strings.ToUpper(category), peerHost)
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+" %-4s | %-40s | %-24s | %-10s | %-20s\n"+Reset, "#", "RECORDING FILE", "ORIGIN / TARGET", "SIZE", "TIMESTAMP")
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)

	if len(files) == 0 {
		fmt.Printf(Yellow+"  No %s voice memos found in this isolated buffer.\n"+Reset, strings.ToUpper(category))
		fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
		pausePrompt()
		return
	}

	for i, f := range files {
		szKB := f.Size / 1024
		if szKB == 0 && f.Size > 0 {
			szKB = 1
		}
		sz := fmt.Sprintf("%d KB", szKB)
		tm := f.ModTime.Format("2006-01-02 15:04:05")
		fmt.Printf(" [%d]  | %-40s | %-24s | %-10s | %-20s\n", i+1, truncateStr(f.FileName, 40), truncateStr(f.Peer, 24), sz, tm)
	}

	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	selStr := transfer.ReadRealtimeInput("Enter memo number to PLAY through speakers (or 0 to return): ")
	sel, errA := strconv.Atoi(strings.TrimSpace(selStr))
	if errA == nil && sel >= 1 && sel <= len(files) {
		targetWav := files[sel-1].Path
		playAudioFileLocally(targetWav)
		if category == "received" {
			MarkNotificationRead("VOICE_MEMO", peerHost)
		}
		pausePrompt()
	}
}

// MODIFIED: playAudioFileLocally – uses the new parser
func playAudioFileLocally(filePath string) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}

	fileBytes, err := os.ReadFile(absPath)
	if err != nil || len(fileBytes) == 0 {
		fmt.Printf(Red+"\n[!] Audio file is empty or corrupted: %s\n"+Reset, absPath)
		return
	}

	var playableWavBytes []byte
	if strings.HasSuffix(absPath, ".encwav") {
		decBytes, errD := decryptPayloadAES(string(fileBytes))
		if errD != nil {
			fmt.Printf(Red+"\n[!] Failed to decrypt voice memo with AES Master Key: %v\n"+Reset, errD)
			return
		}
		playableWavBytes = decBytes
	} else {
		playableWavBytes = fileBytes
	}

	if len(playableWavBytes) < 44 {
		fmt.Printf(Red+"\n[!] Voice memo audio payload is too small to play.\n"+Reset)
		return
	}

	// Extract raw PCM (handles any extra chunks)
	rawPCM, err := extractRawPCMFromWAV(playableWavBytes)
	if err != nil {
		fmt.Printf(Red+"\n[!] Failed to parse voice memo WAV: %v\n"+Reset, err)
		return
	}
	if len(rawPCM) == 0 {
		fmt.Println(Red + "\n[!] Voice memo contains no audio data." + Reset)
		return
	}

	// Reconstruct a pristine, strictly compliant 48,000 Hz RIFF/WAVE header
	var validWav bytes.Buffer
	writeCompleteWavHeader(&validWav, len(rawPCM), 48000, 1, 16)
	validWav.Write(rawPCM)
	playableWavBytes = validWav.Bytes()

	fmt.Println(Cyan + Bold + "\n=== 🎧 VOICE MEMO PLAYBACK CONTROLLER ===" + Reset)
	fmt.Println(Yellow + "Select listening speed:" + Reset)
	fmt.Println("  [1] 1.0x (Standard Normal Speed)")
	fmt.Println("  [2] 1.5x (Fast Listening)")
	fmt.Println("  [3] 2.0x (Double Speed)")
	fmt.Println("  [4] 3.0x (Super Fast Speed)")
	fmt.Println(Red + "  [0] Cancel Playback" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	speedChoice := transfer.ReadRealtimeInput("Select speed [default: 1]: ")
	if speedChoice == "0" || strings.ToLower(speedChoice) == "q" {
		return
	}

	speedMultiplier := 1.0
	switch speedChoice {
	case "2":
		speedMultiplier = 1.5
	case "3":
		speedMultiplier = 2.0
	case "4":
		speedMultiplier = 3.0
	default:
		speedMultiplier = 1.0
	}

	tempPlaybackWav := filepath.Join(os.TempDir(), fmt.Sprintf("stream_play_%d.wav", time.Now().UnixNano()))
	tempPlaybackRaw := filepath.Join(os.TempDir(), fmt.Sprintf("stream_play_%d.raw", time.Now().UnixNano()))
	_ = os.WriteFile(tempPlaybackWav, playableWavBytes, 0666)
	_ = os.WriteFile(tempPlaybackRaw, rawPCM, 0666)
	defer os.Remove(tempPlaybackWav)
	defer os.Remove(tempPlaybackRaw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var playCmd *exec.Cmd

	if speedMultiplier == 1.0 {
		if _, errP := exec.LookPath("paplay"); errP == nil {
			playCmd = getDesktopAudioUserCmd("paplay", "--latency-msec=500", tempPlaybackWav)
		} else if _, errA := exec.LookPath("aplay"); errA == nil {
			playCmd = exec.CommandContext(ctx, "aplay", "-q", "-r", "48000", "-f", "S16_LE", "-c", "1", "-t", "raw", "--buffer-time=1000000", "--period-time=500000", tempPlaybackRaw)
		} else if _, errF := exec.LookPath("ffplay"); errF == nil {
			playCmd = exec.CommandContext(ctx, "ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", tempPlaybackWav)
		}
	} else {
		if _, errF := exec.LookPath("ffplay"); errF == nil {
			speedFilter := fmt.Sprintf("atempo=%.2f", speedMultiplier)
			playCmd = exec.CommandContext(ctx, "ffplay", "-nodisp", "-autoexit", "-af", speedFilter, "-loglevel", "quiet", tempPlaybackWav)
		} else if _, errA := exec.LookPath("aplay"); errA == nil {
			targetRate := int(48000.0 * speedMultiplier)
			playCmd = exec.CommandContext(ctx, "aplay", "-q", "-r", strconv.Itoa(targetRate), "-f", "S16_LE", "-c", "1", "-t", "raw", "--buffer-time=1000000", "--period-time=500000", tempPlaybackRaw)
		}
	}

	if playCmd == nil {
		fmt.Println(Red + "[!] No working audio player found (paplay/aplay/ffplay)." + Reset)
		pausePrompt()
		return
	}

	if errStart := playCmd.Start(); errStart != nil {
		fmt.Printf(Red+"[!] Playback engine failed to start: %v\n"+Reset, errStart)
		return
	}

	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== 🎧 PLAYING VOICE MEMO ===" + Reset)
	fmt.Printf(Yellow+"File: %s | Hardware Clock: 48,000 Hz | Speed: %.1fx\n"+Reset, filepath.Base(absPath), speedMultiplier)
	fmt.Println(Green + Bold + ">> [PRESS ENTER, SPACE OR 'Q' AT ANY TIME TO STOP PLAYBACK] <<" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	drainStdinBuffer()

	donePlayback := make(chan error, 1)
	go func() {
		donePlayback <- playCmd.Wait()
	}()

	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
	}

	time.Sleep(200 * time.Millisecond)

	spinChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	stoppedManually := false

	for {
		select {
		case <-donePlayback:
			goto PlaybackFinished
		default:
			var b [1]byte
			n, _ := os.Stdin.Read(b[:])
			if n > 0 {
				k := b[0]
				if k == 10 || k == 13 || k == ' ' || k == 'q' || k == 'Q' || k == 27 {
					cancel()
					_ = playCmd.Process.Kill()
					stoppedManually = true
					goto PlaybackFinished
				}
			}
			fmt.Printf("\r\033[K%s %sPlaying Voice Memo (%.1fx)...%s [Press ENTER or 'Q' to Stop]", Green+Bold, spinChars[i%len(spinChars)], speedMultiplier, Reset)
			i++
			time.Sleep(80 * time.Millisecond)
		}
	}

PlaybackFinished:
	restoreTerminalState()
	_ = exec.Command("pkill", "-9", "-f", "aplay").Run()
	_ = exec.Command("pkill", "-9", "-f", "paplay").Run()
	_ = exec.Command("pkill", "-9", "-f", "ffplay").Run()

	if stoppedManually {
		fmt.Println(Yellow + Bold + "\n\n[⏹ STOPPED] Playback stopped by user." + Reset)
	} else {
		fmt.Println(Green + Bold + "\n\n[✔ FINISHED] Voice memo playback completed." + Reset)
	}
}

func syncRemoteVoiceMemosSilent(client *ssh.Client, host, author string) {
	if client == nil {
		return
	}

	cleanPeerTag := sanitizePeerTag(host)
	localReceivedDir := getPeerAudioDir(host, "received")
	localBaseDir := filepath.Join(GetUniversalBaseDir(), "voicenotes", "peers", cleanPeerTag, "received")
	_ = os.MkdirAll(localReceivedDir, 0777)
	_ = os.MkdirAll(localBaseDir, 0777)

	myOutboundIP := getLocalOutboundIP(host)
	myAuthorTag := sanitizePeerTag(myOutboundIP)

	sess, err := client.NewSession()
	if err != nil {
		return
	}
	defer sess.Close()

	remoteCheckCmd := fmt.Sprintf(`sh -c 'find /tmp/cross_voicenotes "$HOME/.cross-ssh/voicenotes" -type f -name "from_*.encwav" 2>/dev/null || true'`)
	out, err := sess.Output(remoteCheckCmd)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return
	}

	remoteFiles := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, rf := range remoteFiles {
		rfTrim := strings.TrimSpace(rf)
		if rfTrim == "" {
			continue
		}
		baseName := filepath.Base(rfTrim)

		if strings.HasPrefix(baseName, fmt.Sprintf("from_%s_", myAuthorTag)) {
			continue
		}

		localDest := filepath.Join(localReceivedDir, baseName)
		localBaseDest := filepath.Join(localBaseDir, baseName)

		if _, errSt := os.Stat(localDest); os.IsNotExist(errSt) {
			fSess, errF := client.NewSession()
			if errF == nil {
				fBytes, errR := fSess.Output(fmt.Sprintf("cat '%s'", rfTrim))
				fSess.Close()
				if errR == nil && len(fBytes) > 0 {
					_ = os.WriteFile(localDest, fBytes, 0666)
					_ = os.WriteFile(localBaseDest, fBytes, 0666)
				}
			}
		}
	}
}

func syncRemoteVoiceMemos(reader *bufio.Reader, client *ssh.Client, host, author string) {
	fmt.Print("\033[H\033[2J")
	alias := getMeshAliasForIP(host)
	targetDisplay := host
	if alias != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
	}

	fmt.Println(Cyan + Bold + "=== SYNCING REMOTE INBOUND VOICE MEMOS ===" + Reset)
	RenderAudioStatusToast()
	fmt.Printf(Yellow+"Peer Endpoint: %s\n"+Reset, targetDisplay)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	if client == nil {
		fmt.Println(Red + "[!] SSH client is not active." + Reset)
		pausePrompt()
		return
	}

	cleanPeerTag := sanitizePeerTag(host)
	localReceivedDir := getPeerAudioDir(host, "received")
	localBaseDir := filepath.Join(GetUniversalBaseDir(), "voicenotes", "peers", cleanPeerTag, "received")
	_ = os.MkdirAll(localReceivedDir, 0777)
	_ = os.MkdirAll(localBaseDir, 0777)

	myOutboundIP := getLocalOutboundIP(host)
	myAuthorTag := sanitizePeerTag(myOutboundIP)

	sess, err := client.NewSession()
	if err != nil {
		fmt.Printf(Red+"[!] Session failure: %v\n"+Reset, err)
		pausePrompt()
		return
	}
	defer sess.Close()

	remoteCheckCmd := fmt.Sprintf(`sh -c 'find /tmp/cross_voicenotes "$HOME/.cross-ssh/voicenotes" -type f -name "from_*.encwav" 2>/dev/null || true'`)
	out, err := sess.Output(remoteCheckCmd)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		fmt.Println(Yellow + "[i] No new inbound voice memos found on remote host." + Reset)
		pausePrompt()
		return
	}

	remoteFiles := strings.Split(strings.TrimSpace(string(out)), "\n")
	pulledCount := 0
	for _, rf := range remoteFiles {
		rfTrim := strings.TrimSpace(rf)
		if rfTrim == "" {
			continue
		}
		baseName := filepath.Base(rfTrim)

		if strings.HasPrefix(baseName, fmt.Sprintf("from_%s_", myAuthorTag)) {
			continue
		}

		localDest := filepath.Join(localReceivedDir, baseName)
		localBaseDest := filepath.Join(localBaseDir, baseName)

		fSess, errF := client.NewSession()
		if errF == nil {
			fBytes, errR := fSess.Output(fmt.Sprintf("cat '%s'", rfTrim))
			fSess.Close()
			if errR == nil && len(fBytes) > 0 {
				_ = os.WriteFile(localDest, fBytes, 0666)
				_ = os.WriteFile(localBaseDest, fBytes, 0666)
				pulledCount++
			}
		}
	}

	if pulledCount > 0 {
		fmt.Printf(Green+Bold+"\n[✔ SUCCESS] Synced %d genuine inbound voice memo(s) from '%s'!\n"+Reset, pulledCount, targetDisplay)
	} else {
		fmt.Println(Green + "[✔] Received inbox is already completely up to date with zero echo files." + Reset)
	}
	pausePrompt()
}

// === PURE NATIVE AUDIO SYNTHESIZER (MELODIC & SOFT RINGTONES) ===

type ToneSegment struct {
	Freq     float64
	Duration time.Duration
	Volume   float64
}

func generateSineWavData(segments []ToneSegment) []byte {
	sampleRate := 48000
	var rawPCM bytes.Buffer

	for _, seg := range segments {
		totalSamples := int(float64(sampleRate) * seg.Duration.Seconds())
		for i := 0; i < totalSamples; i++ {
			t := float64(i) / float64(sampleRate)
			envelope := 1.0
			decayThreshold := float64(totalSamples) * 0.7
			if float64(i) > decayThreshold {
				envelope = (float64(totalSamples-i) / float64(totalSamples-int(decayThreshold)))
			}
			val := math.Sin(2.0*math.Pi*seg.Freq*t) * seg.Volume * envelope
			intVal := int16(val * 32767.0)

			b0 := byte(intVal & 0xFF)
			b1 := byte((intVal >> 8) & 0xFF)
			rawPCM.WriteByte(b0)
			rawPCM.WriteByte(b1)
		}
	}

	var wavBuf bytes.Buffer
	writeCompleteWavHeader(&wavBuf, rawPCM.Len(), sampleRate, 1, 16)
	wavBuf.Write(rawPCM.Bytes())
	return wavBuf.Bytes()
}

func getRingtoneToneSegments(choice string) []ToneSegment {
	switch choice {
	case "1":
		return []ToneSegment{
			{Freq: 440.0, Duration: 400 * time.Millisecond, Volume: 0.3},
			{Freq: 480.0, Duration: 400 * time.Millisecond, Volume: 0.3},
		}
	case "2":
		return []ToneSegment{
			{Freq: 853.0, Duration: 150 * time.Millisecond, Volume: 0.25},
			{Freq: 960.0, Duration: 150 * time.Millisecond, Volume: 0.25},
			{Freq: 853.0, Duration: 150 * time.Millisecond, Volume: 0.25},
			{Freq: 960.0, Duration: 150 * time.Millisecond, Volume: 0.25},
		}
	case "3":
		return []ToneSegment{
			{Freq: 587.33, Duration: 200 * time.Millisecond, Volume: 0.25},
			{Freq: 880.00, Duration: 350 * time.Millisecond, Volume: 0.25},
		}
	case "4":
		return []ToneSegment{
			{Freq: 523.25, Duration: 300 * time.Millisecond, Volume: 0.2},
			{Freq: 659.25, Duration: 400 * time.Millisecond, Volume: 0.2},
		}
	case "5":
		return []ToneSegment{
			{Freq: 783.99, Duration: 160 * time.Millisecond, Volume: 0.35},
			{Freq: 987.77, Duration: 160 * time.Millisecond, Volume: 0.35},
			{Freq: 1174.66, Duration: 320 * time.Millisecond, Volume: 0.35},
		}
	case "6":
		return []ToneSegment{
			{Freq: 659.25, Duration: 200 * time.Millisecond, Volume: 0.3},
			{Freq: 880.00, Duration: 400 * time.Millisecond, Volume: 0.3},
		}
	case "7":
		return []ToneSegment{
			{Freq: 1046.50, Duration: 200 * time.Millisecond, Volume: 0.25},
			{Freq: 1567.98, Duration: 200 * time.Millisecond, Volume: 0.25},
			{Freq: 2093.00, Duration: 400 * time.Millisecond, Volume: 0.25},
		}
	case "8":
		return []ToneSegment{
			{Freq: 432.00, Duration: 900 * time.Millisecond, Volume: 0.35},
		}
	case "9":
		return []ToneSegment{
			{Freq: 698.46, Duration: 120 * time.Millisecond, Volume: 0.25},
			{Freq: 880.00, Duration: 120 * time.Millisecond, Volume: 0.25},
			{Freq: 698.46, Duration: 120 * time.Millisecond, Volume: 0.25},
			{Freq: 880.00, Duration: 240 * time.Millisecond, Volume: 0.25},
		}
	default:
		return []ToneSegment{
			{Freq: 440.0, Duration: 400 * time.Millisecond, Volume: 0.3},
			{Freq: 480.0, Duration: 400 * time.Millisecond, Volume: 0.3},
		}
	}
}

func getSelectedRingtoneStyle() string {
	ringtoneFile := filepath.Join(GetUniversalBaseDir(), "selected_ringtone.txt")
	data, err := os.ReadFile(ringtoneFile)
	if err == nil {
		style := strings.TrimSpace(string(data))
		if style != "" {
			return style
		}
	}
	return "5"
}

func triggerRemoteHardwareRingtone(ctx context.Context, client *ssh.Client) {
	if client == nil {
		return
	}
	preset := getSelectedRingtoneStyle()
	wavBytes := generateSineWavData(getRingtoneToneSegments(preset))

	go func() {
		sessInit, errI := client.NewSession()
		if errI == nil {
			sessInit.Stdin = bytes.NewReader(wavBytes)
			_ = sessInit.Run("cat > /tmp/cross_remote_ringtone.wav; chmod 666 /tmp/cross_remote_ringtone.wav 2>/dev/null")
			sessInit.Close()
		}

		sess, err := client.NewSession()
		if err != nil {
			return
		}
		defer sess.Close()

		go func() {
			<-ctx.Done()
			_ = sess.Signal(ssh.SIGTERM)
			_ = sess.Close()
			killSess, errK := client.NewSession()
			if errK == nil {
				_ = killSess.Run("pkill -9 -f aplay; pkill -9 -f paplay; pkill -9 -f speaker-test; rm -f /tmp/cross_remote_ringtone.wav; true")
				killSess.Close()
			}
		}()

		ringScript := `
while true; do
    (which aplay >/dev/null 2>&1 && aplay -q /tmp/cross_remote_ringtone.wav >/dev/null 2>&1 || which paplay >/dev/null 2>&1 && paplay /tmp/cross_remote_ringtone.wav >/dev/null 2>&1)
    sleep 1
done
`
		_ = sess.Run(ringScript)
	}()
}

func previewRingtoneLocally(choice string) {
	wavBytes := generateSineWavData(getRingtoneToneSegments(choice))
	tempPreview := filepath.Join(os.TempDir(), "ringtone_preview.wav")
	_ = os.WriteFile(tempPreview, wavBytes, 0600)
	defer os.Remove(tempPreview)

	playAudioFileLocally(tempPreview)
}

func ShowVoIPPhoneDispatchMenu(reader *bufio.Reader, client *ssh.Client, host, author string) {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		alias := getMeshAliasForIP(host)
		targetDisplay := host
		if alias != "" {
			targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
		}

		fmt.Println(Cyan + Bold + "=== FULL-DUPLEX VOIP AUDIO & INTERCOM HUB ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Locked Peer: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"My Node ID: "+Reset+Bold+"%s\n"+Reset, targetDisplay, author)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println(Green + Bold + "  [1] 📞 CALL Remote Peer (Dial & Ring Remote Target)" + Reset)
		fmt.Println(Cyan + Bold + "  [2] 📥 ANSWER Incoming Call (Accept & Connect Audio Pipe)" + Reset)
		fmt.Println(Red + "  [3] ❌ DECLINE / REJECT Incoming Call (Silence Ringers)" + Reset)
		fmt.Println(Yellow + "  [4] 🔔 Configure Ringtone Style & Soft Melodies" + Reset)
		fmt.Println(Magenta + "  [5] 🔊 Manipulate Live Call Master Volume & Capture Gain" + Reset)
		fmt.Println(Red + "  [0] Back to P2P Matrix" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select VoIP option [0-5]: ")

		switch choice {
		case "1":
			startOutboundVoIPCall(reader, client, host, author)
		case "2":
			answerInboundVoIPCall(reader, client, host)
		case "3":
			rejectInboundVoIPCall(reader, client, host)
		case "4":
			showRingtoneConfigSubMenu(reader)
		case "5":
			showVolumeGainControlSubMenu(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func showRingtoneConfigSubMenu(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		cur := getSelectedRingtoneStyle()

		fmt.Println(Cyan + Bold + "=== CONFIGURE VOIP CALL RINGTONE STYLE ===" + Reset)
		RenderAudioStatusToast()
		fmt.Println(Yellow + "Select a ringtone to preview audio and confirm default choice:" + Reset)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Println(Bold + "--- MODERN SOFT SMARTPHONE RINGTONES ---" + Reset)
		fmt.Printf("  [1] 🎵 WhatsApp Soft Marimba (Tri-Tone G5 -> B5 -> D6)%s\n", markSelected(cur, "5"))
		fmt.Printf("  [2] 🌐 Skype Soft Ripple (Dual-Chime E5 -> A5)%s\n", markSelected(cur, "6"))
		fmt.Printf("  [3] 🔔 Ambient Glass Harp Chime (Crystal Soft Sine Decay)%s\n", markSelected(cur, "7"))
		fmt.Printf("  [4] 🌿 Zen Meditation Gong (432 Hz Harmonic Frequency)%s\n", markSelected(cur, "8"))
		fmt.Printf("  [5] 📱 Modern Digital Trill (F5 / A5 Fast Pulse)%s\n", markSelected(cur, "9"))
		fmt.Println(Bold + "--- CLASSIC DUAL-FREQUENCY TONES ---" + Reset)
		fmt.Printf("  [6] 📞 Classic Dual-Tone Telephone (440 Hz + 480 Hz)%s\n", markSelected(cur, "1"))
		fmt.Printf("  [7] ⚡ Electronic High-Pitch Warble (853 Hz + 960 Hz)%s\n", markSelected(cur, "2"))
		fmt.Printf("  [8] 🔮 Cyber Digital Chime (587 Hz + 880 Hz)%s\n", markSelected(cur, "3"))
		fmt.Printf("  [9] 🌸 Soft Gentle Pulse (523 Hz + 659 Hz)%s\n", markSelected(cur, "4"))
		fmt.Println(Red + "  [0] Back to VoIP Menu" + Reset)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select ringtone to test [0-9]: ")
		if choice == "0" || strings.ToLower(choice) == "q" {
			return
		}

		mapChoice := choice
		switch choice {
		case "1":
			mapChoice = "5"
		case "2":
			mapChoice = "6"
		case "3":
			mapChoice = "7"
		case "4":
			mapChoice = "8"
		case "5":
			mapChoice = "9"
		case "6":
			mapChoice = "1"
		case "7":
			mapChoice = "2"
		case "8":
			mapChoice = "3"
		case "9":
			mapChoice = "4"
		}

		fmt.Println(Cyan + "\n[▶] Playing live synthesized acoustic preview through speakers..." + Reset)
		previewRingtoneLocally(mapChoice)

		confirm := transfer.ReadRealtimeInput("\nSet this tone as your default ringtone? [Y/n]: ")
		if confirm == "" || strings.ToLower(confirm) == "y" {
			ringFile := filepath.Join(GetUniversalBaseDir(), "selected_ringtone.txt")
			_ = os.WriteFile(ringFile, []byte(mapChoice), 0644)
			fmt.Println(Green + Bold + "[✔ SUCCESS] Default ringtone updated successfully!" + Reset)
			time.Sleep(1 * time.Second)
			return
		}
	}
}

func markSelected(current, target string) string {
	if current == target {
		return Green + Bold + " ★ [CURRENT DEFAULT]" + Reset
	}
	return ""
}

func showVolumeGainControlSubMenu(reader *bufio.Reader) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== VOIP VOLUME & GAIN CONTROLLER ===" + Reset)
		RenderAudioStatusToast()
		fmt.Println(Yellow + "Adjust real-time hardware amplification levels:" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Normal Volume (100% Speaker / 100% Mic Capture)")
		fmt.Println(Green + "  [2] Boost Volume (130% Speaker / 120% Mic Capture)" + Reset)
		fmt.Println(Magenta + Bold + "  [3] Super Boost Volume (150% Amplified Speaker / 140% Mic)" + Reset)
		fmt.Println("  [4] Custom Speaker & Microphone Volume Entry")
		fmt.Println(Red + "  [0] Back to VoIP Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select volume preset [0-4]: ")
		switch choice {
		case "1":
			_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", "@DEFAULT_SINK@", "100%").Run()
			_ = getDesktopAudioUserCmd("pactl", "set-source-volume", "@DEFAULT_SOURCE@", "100%").Run()
			fmt.Println(Green + Bold + "\n[✔] Volume set to 100%!" + Reset)
			time.Sleep(1 * time.Second)
			return
		case "2":
			_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", "@DEFAULT_SINK@", "130%").Run()
			_ = getDesktopAudioUserCmd("pactl", "set-source-volume", "@DEFAULT_SOURCE@", "120%").Run()
			fmt.Println(Green + Bold + "\n[✔] Boosted volume to 130%!" + Reset)
			time.Sleep(1 * time.Second)
			return
		case "3":
			_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", "@DEFAULT_SINK@", "150%").Run()
			_ = getDesktopAudioUserCmd("pactl", "set-source-volume", "@DEFAULT_SOURCE@", "140%").Run()
			fmt.Println(Green + Bold + "\n[✔] Super Boost volume set to 150%!" + Reset)
			time.Sleep(1 * time.Second)
			return
		case "4":
			spk := transfer.ReadRealtimeInput("Enter Speaker Volume (e.g. 100%, 120%): ")
			mic := transfer.ReadRealtimeInput("Enter Microphone Volume (e.g. 100%, 120%): ")
			if spk != "" {
				_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", "@DEFAULT_SINK@", spk).Run()
			}
			if mic != "" {
				_ = getDesktopAudioUserCmd("pactl", "set-source-volume", "@DEFAULT_SOURCE@", mic).Run()
			}
			fmt.Println(Green + Bold + "\n[✔] Custom volume applied!" + Reset)
			time.Sleep(1 * time.Second)
			return
		case "0", "q", "Q":
			return
		}
	}
}

func startOutboundVoIPCall(reader *bufio.Reader, client *ssh.Client, host, author string) {
	defer restoreTerminalState()
	fmt.Print("\033[H\033[2J")
	alias := getMeshAliasForIP(host)
	targetDisplay := host
	if alias != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
	}

	fmt.Printf(Cyan+Bold+"=== 📞 DIALING OUTBOUND VOIP CALL: %s ===\n"+Reset, targetDisplay)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "[+] Handshaking session & ringing remote speakers..." + Reset)

	_ = os.Remove("/tmp/cross_voip_state")
	cleanSess, errCl := client.NewSession()
	if errCl == nil {
		_ = cleanSess.Run("rm -f /tmp/cross_voip_state; pkill -9 -f speaker-test; pkill -9 -f pacat; pkill -9 -f parec; pkill -9 -f aplay; pkill -9 -f paplay; true")
		cleanSess.Close()
	}

	dispatchNotification(client, host, author, "CALL", "Incoming Full-Duplex VoIP Call! Open Hub [12] -> Option [2] -> [2] to ANSWER")

	ringCtx, stopRing := context.WithCancel(context.Background())
	defer stopRing()
	triggerRemoteHardwareRingtone(ringCtx, client)

	answeredChan := make(chan string, 1)
	ctxWait, cancelWait := context.WithCancel(context.Background())
	defer cancelWait()

	go func() {
		for {
			select {
			case <-ctxWait.Done():
				return
			default:
				chkSess, errC := client.NewSession()
				if errC == nil {
					out, _ := chkSess.Output("cat /tmp/cross_voip_state 2>/dev/null || true")
					chkSess.Close()
					str := strings.TrimSpace(string(out))
					if str == "ACCEPTED" || str == "REJECTED" {
						answeredChan <- str
						return
					}
				}
				time.Sleep(400 * time.Millisecond)
			}
		}
	}()

	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
	}

	go func() {
		var b [1]byte
		for {
			select {
			case <-ctxWait.Done():
				return
			default:
				n, _ := os.Stdin.Read(b[:])
				if n > 0 {
					k := b[0]
					if k == 'c' || k == 'C' || k == 27 || k == '0' || k == 'q' || k == 'Q' {
						answeredChan <- "CANCELED"
						return
					}
				}
				time.Sleep(30 * time.Millisecond)
			}
		}
	}()

	finalState := ""
	spinChars := []string{"|", "/", "-", "\\"}

	for i := 0; i < 120; i++ {
		select {
		case state := <-answeredChan:
			finalState = state
			break
		default:
			fmt.Printf("\r\033[K%s🔔 [CALL RINGING %s]: Waiting for %s to answer... [Press 'C' or ESC to Cancel] (%ds)%s", Cyan+Bold, spinChars[i%4], targetDisplay, i/2, Reset)
			time.Sleep(500 * time.Millisecond)
		}
		if finalState != "" {
			break
		}
	}

	cancelWait()
	stopRing()
	restoreTerminalState()

	if finalState == "REJECTED" {
		fmt.Println(Red + Bold + "\n\n[❌ CALL DECLINED]: The remote peer declined your call." + Reset)
		pausePrompt()
		return
	} else if finalState == "CANCELED" {
		fmt.Println(Yellow + Bold + "\n\n[⚠ CALL CANCELED]: You hung up the call." + Reset)
		killSess, _ := client.NewSession()
		if killSess != nil {
			_ = killSess.Run("rm -f /tmp/cross_voip_state; pkill -9 -f speaker-test; pkill -9 -f pacat; pkill -9 -f parec; pkill -9 -f aplay; pkill -9 -f paplay; true")
			killSess.Close()
		}
		pausePrompt()
		return
	} else if finalState != "ACCEPTED" {
		fmt.Println(Red + "\n\n[!] Call timed out (No answer from remote peer)." + Reset)
		killSess, _ := client.NewSession()
		if killSess != nil {
			_ = killSess.Run("rm -f /tmp/cross_voip_state; pkill -9 -f speaker-test; pkill -9 -f pacat; pkill -9 -f parec; pkill -9 -f aplay; pkill -9 -f paplay; true")
			killSess.Close()
		}
		pausePrompt()
		return
	}

	fmt.Println(Green + Bold + "\n\n[✔ CALL CONNECTED]: Peer answered! Full-duplex audio stream is LIVE." + Reset)
	StartVoiceIntercomWithVUMeter(reader, client, host, true)
}

func answerInboundVoIPCall(reader *bufio.Reader, client *ssh.Client, host string) {
	defer restoreTerminalState()
	fmt.Print("\033[H\033[2J")
	alias := getMeshAliasForIP(host)
	targetDisplay := host
	if alias != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", alias, host)
	}

	fmt.Printf(Green+Bold+"=== 📥 ANSWERING INCOMING VOIP CALL FROM: %s ===\n"+Reset, targetDisplay)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "[+] Silencing ringer and establishing audio bridge..." + Reset)

	_ = exec.Command("pkill", "-9", "-f", "speaker-test").Run()
	_ = exec.Command("pkill", "-9", "-f", "pacat").Run()
	_ = exec.Command("pkill", "-9", "-f", "parec").Run()
	_ = exec.Command("aplay", "-q", "-d", "0").Run()
	_ = os.WriteFile("/tmp/cross_voip_state", []byte("ACCEPTED\n"), 0666)

	if client != nil {
		ansSess, errA := client.NewSession()
		if errA == nil {
			_ = ansSess.Run("echo 'ACCEPTED' > /tmp/cross_voip_state && chmod 666 /tmp/cross_voip_state 2>/dev/null; pkill -9 -f speaker-test; pkill -9 -f aplay; pkill -9 -f paplay; true")
			ansSess.Close()
		}
	}

	MarkNotificationRead("CALL", "")

	fmt.Println(Green + Bold + "\n[✔ CALL CONNECTED]: Audio bridge established! Press ENTER or 'q' to hang up." + Reset)
	StartVoiceIntercomWithVUMeter(reader, client, host, false)
}

func rejectInboundVoIPCall(reader *bufio.Reader, client *ssh.Client, host string) {
	defer restoreTerminalState()
	fmt.Print("\033[H\033[2J")
	fmt.Println(Red + Bold + "=== ❌ REJECTING INCOMING VOIP CALL ===" + Reset)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "[+] Silencing local ringer and notifying caller..." + Reset)

	_ = exec.Command("pkill", "-9", "-f", "speaker-test").Run()
	_ = exec.Command("pkill", "-9", "-f", "pacat").Run()
	_ = exec.Command("pkill", "-9", "-f", "parec").Run()
	_ = exec.Command("aplay", "-q", "-d", "0").Run()
	_ = os.WriteFile("/tmp/cross_voip_state", []byte("REJECTED\n"), 0666)

	if client != nil {
		rejSess, errR := client.NewSession()
		if errR == nil {
			_ = rejSess.Run("echo 'REJECTED' > /tmp/cross_voip_state && chmod 666 /tmp/cross_voip_state 2>/dev/null; pkill -9 -f speaker-test; pkill -9 -f pacat; pkill -9 -f parec; pkill -9 -f aplay; pkill -9 -f paplay; true")
			rejSess.Close()
		}
	}

	MarkNotificationRead("CALL", "")
	restoreTerminalState()
	fmt.Println(Green + Bold + "[✔ SUCCESS] Call declined cleanly." + Reset)
	time.Sleep(800 * time.Millisecond)
}

func StartVoiceIntercomWithVUMeter(reader *bufio.Reader, client *ssh.Client, host string, isCaller bool) {
	defer restoreTerminalState()
	ensureAudioToolsInstalled()
	enforceHardwareAudioLocks()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const audioUDPPort = 44778
	targetIP := host
	if targetIP == "" {
		targetIP = "127.0.0.1"
	}

	localUDPAddr, errL := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", audioUDPPort))
	if errL != nil {
		fmt.Printf(Red+"[!] Failed to resolve local UDP: %v\n"+Reset, errL)
		pausePrompt()
		return
	}

	udpConn, errU := net.ListenUDP("udp", localUDPAddr)
	if errU != nil {
		fmt.Printf(Red+"[!] Audio UDP port occupied: %v\n"+Reset, errU)
		pausePrompt()
		return
	}
	defer udpConn.Close()

	remoteUDPAddr, errR := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetIP, audioUDPPort))
	if errR != nil {
		fmt.Printf(Red+"[!] Failed to resolve remote UDP target: %v\n"+Reset, errR)
		pausePrompt()
		return
	}

	selectedSink := getActiveSelectedSpeakerSink()
	var playCmd *exec.Cmd
	if _, err := exec.LookPath("pacat"); err == nil {
		args := []string{
			"--playback",
			"--raw",
			"--rate=48000",
			"--channels=1",
			"--format=s16le",
			"--latency-msec=10",
			"--process-time-msec=5",
		}
		if selectedSink != "" {
			args = append(args, "-d", selectedSink)
		}
		playCmd = getDesktopAudioUserCmd("pacat", args...)
	} else {
		playCmd = exec.CommandContext(ctx, "aplay", "-q", "-r", "48000", "-f", "S16_LE", "-c", "1", "--buffer-time=20000")
	}

	playIn, errP := playCmd.StdinPipe()
	if errP == nil {
		_ = playCmd.Start()
	}

	var isSpeakerReceivingAudio int32

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctx.Done():
				if playIn != nil {
					_ = playIn.Close()
				}
				return
			default:
				_ = udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, errRead := udpConn.ReadFrom(buf)
				if n > 0 {
					if string(buf[:n]) == VoIPDisconnectMagic {
						cancel()
						return
					}

					atomic.StoreInt32(&isSpeakerReceivingAudio, 1)
					if playIn != nil {
						_, _ = playIn.Write(buf[:n])
					}
				} else {
					atomic.StoreInt32(&isSpeakerReceivingAudio, 0)
				}
				if errRead != nil {
					continue
				}
			}
		}
	}()

	selectedSource := getActiveSelectedMicSource()
	var recCmd *exec.Cmd
	if _, err := exec.LookPath("parec"); err == nil {
		args := []string{
			"--raw",
			"--rate=48000",
			"--channels=1",
			"--format=s16le",
			"--latency-msec=10",
			"--process-time-msec=5",
		}
		if selectedSource != "" {
			args = append([]string{"-d", selectedSource}, args...)
		}
		recCmd = getDesktopAudioUserCmd("parec", args...)
	} else {
		recCmd = exec.CommandContext(ctx, "arecord", "-D", "default", "-q", "-r", "48000", "-f", "S16_LE", "-c", "1", "-t", "raw", "--period-size=512", "--buffer-size=2048")
	}

	micPipe, errM := recCmd.StdoutPipe()
	if errM == nil {
		_ = recCmd.Start()
	}

	var latestRMSBits uint64

	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if micPipe == nil {
					return
				}
				n, errR := micPipe.Read(buf)
				if errR != nil || n == 0 {
					time.Sleep(1 * time.Millisecond)
					continue
				}

				sum := 0.0
				samples := n / 2
				for i := 0; i < n-1; i += 2 {
					val := int16(buf[i]) | (int16(buf[i+1]) << 8)
					sum += float64(val) * float64(val)
				}
				rms := math.Sqrt(sum / float64(samples+1))
				atomic.StoreUint64(&latestRMSBits, math.Float64bits(rms))

				if rms < 32.0 {
					for i := 0; i < n; i++ {
						buf[i] = 0
					}
				}

				if atomic.LoadInt32(&isSpeakerReceivingAudio) == 1 && rms < 55.0 {
					for i := 0; i < n; i++ {
						buf[i] = 0
					}
				}

				_, _ = udpConn.WriteTo(buf[:n], remoteUDPAddr)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		smoothedLevel := 0.0

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				bits := atomic.LoadUint64(&latestRMSBits)
				rms := math.Float64frombits(bits)
				meter := renderDynamicVUBar(rms, &smoothedLevel, 16)
				fmt.Printf("\r\033[K%s[LIVE VOIP]:%s MIC LEVEL [%s] Speaking... (Press ENTER or 'q' to hang up)", Cyan+Bold, Reset, meter)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(350 * time.Millisecond):
				if client != nil {
					chkSess, errC := client.NewSession()
					if errC == nil {
						out, _ := chkSess.Output("cat /tmp/cross_voip_state 2>/dev/null || true")
						chkSess.Close()
						if strings.TrimSpace(string(out)) == "DISCONNECTED" {
							cancel()
							return
						}
					}
				}
			}
		}
	}()

	hangupChan := make(chan bool, 1)
	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
	}

	go func() {
		var b [1]byte
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, _ := os.Stdin.Read(b[:])
				if n > 0 {
					k := b[0]
					if k == 10 || k == 13 || k == 'q' || k == 'Q' || k == 27 || k == 'c' || k == 'C' {
						hangupChan <- true
						return
					}
				}
				time.Sleep(30 * time.Millisecond)
			}
		}
	}()

	select {
	case <-hangupChan:
	case <-ctx.Done():
	}

	cancel()

	for i := 0; i < 5; i++ {
		_, _ = udpConn.WriteTo([]byte(VoIPDisconnectMagic), remoteUDPAddr)
		time.Sleep(10 * time.Millisecond)
	}

	if recCmd != nil && recCmd.Process != nil {
		_ = recCmd.Process.Kill()
	}
	if playCmd != nil && playCmd.Process != nil {
		_ = playCmd.Process.Kill()
	}

	_ = exec.Command("pkill", "-9", "-f", "speaker-test").Run()
	_ = exec.Command("pkill", "-9", "-f", "pacat").Run()
	_ = exec.Command("pkill", "-9", "-f", "parec").Run()
	_ = exec.Command("aplay", "-q", "-d", "0").Run()
	_ = os.WriteFile("/tmp/cross_voip_state", []byte("DISCONNECTED\n"), 0666)

	if client != nil {
		killSess, errK := client.NewSession()
		if errK == nil {
			_ = killSess.Run("echo 'DISCONNECTED' > /tmp/cross_voip_state; pkill -9 -f pacat; pkill -9 -f parec; pkill -9 -f arecord; pkill -9 -f aplay; pkill -9 -f speaker-test; true")
			killSess.Close()
		}
	}

	restoreTerminalState()
	MarkNotificationRead("CALL", "")

	fmt.Println(Green + "\n\n[✔] Call disconnected cleanly on both endpoints." + Reset)
	time.Sleep(400 * time.Millisecond)
}

// === MESSENGER AND CHAT CORE ===

func cleanMessageID(sender, text string, ts time.Time) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(sender) + "|" + strings.TrimSpace(text) + "|" + ts.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func resolveCanonicalPeer(id string) string {
	if id == "" || id == "YOU" || id == GetLocalNodeIdentity() {
		return id
	}
	for _, c := range loadMeshContacts() {
		if c.IP == id {
			return c.IP
		}
		if c.Alias == id && c.IP != "" {
			return c.IP
		}
	}
	return id
}

func getLocalOutboundIP(targetHost string) string {
	if targetHost == "" {
		targetHost = "8.8.8.8"
	}
	conn, err := net.DialTimeout("udp", targetHost+":80", 400*time.Millisecond)
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return GetLocalNodeIdentity()
}

func SyncAllLocalChatInboxes(activePeer ...string) {
	chatSyncMutex.Lock()
	defer chatSyncMutex.Unlock()

	targetPeer := ""
	if len(activePeer) > 0 && activePeer[0] != "" {
		targetPeer = resolveCanonicalPeer(activePeer[0])
	}

	candidates := []string{
		filepath.Join(GetUniversalBaseDir(), "chat_inbox.json"),
		filepath.Join(os.TempDir(), "cross_chat_inbox.enc"),
		filepath.Join(os.TempDir(), "cross_chat_inbox.json"),
		"/tmp/cross_chat_inbox.enc",
		"/tmp/cross_chat_inbox.json",
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		candidates = append(candidates, filepath.Join("/home", sudoUser, ".cross-ssh", "chat_inbox.json"))
	}

	for _, c := range candidates {
		claimPath := c + fmt.Sprintf(".claim.%d", os.Getpid())
		if err := os.Rename(c, claimPath); err != nil {
			continue
		}
		data, err := os.ReadFile(claimPath)
		_ = os.Remove(claimPath)
		if err != nil || len(data) == 0 {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" {
				continue
			}

			payloadBytes := []byte(trimmed)
			if strings.HasPrefix(trimmed, "ENC:") {
				dec, errD := decryptPayloadAES(strings.TrimPrefix(trimmed, "ENC:"))
				if errD == nil {
					payloadBytes = dec
				}
			}

			var msg ChatMessage
			if err := json.Unmarshal(payloadBytes, &msg); err == nil && msg.Text != "" {
				peerKey := targetPeer
				if peerKey == "" {
					myNode := GetLocalNodeIdentity()
					if msg.Sender != "" && msg.Sender != myNode && msg.Sender != "YOU" {
						peerKey = resolveCanonicalPeer(msg.Sender)
					} else if msg.Recipient != "" && msg.Recipient != myNode && msg.Recipient != "YOU" {
						peerKey = resolveCanonicalPeer(msg.Recipient)
					}
				}
				if peerKey != "" {
					saveChatMessageToPeerVault(peerKey, msg)
				}
			}
		}
	}
}

func loadRawChatHistoryForPeer(peerIdentifier string) []ChatMessage {
	if peerIdentifier == "" {
		return nil
	}
	cleanTag := sanitizePeerTag(peerIdentifier)
	vaultDir := filepath.Join(GetUniversalBaseDir(), "chat_vault")
	encPath := filepath.Join(vaultDir, fmt.Sprintf("thread_%s.enc", cleanTag))
	rawPath := filepath.Join(vaultDir, fmt.Sprintf("thread_%s.json", cleanTag))

	var all []ChatMessage

	if data, err := os.ReadFile(encPath); err == nil && len(data) > 0 {
		dec, errD := decryptPayloadAES(string(data))
		if errD == nil {
			_ = json.Unmarshal(dec, &all)
			return all
		}
	}

	if data, err := os.ReadFile(rawPath); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &all)
		return all
	}

	return all
}

func LoadChatHistory(peerIdentifier string) []ChatMessage {
	canonicalPeer := resolveCanonicalPeer(peerIdentifier)
	SyncAllLocalChatInboxes(canonicalPeer)

	seen := make(map[string]bool)
	var merged []ChatMessage

	alias := vault.ResolveAliasForIP(canonicalPeer)
	peerClean := sanitizePeerTag(canonicalPeer)

	identifiersToPoll := []string{canonicalPeer}
	if alias != "" && alias != canonicalPeer {
		identifiersToPoll = append(identifiersToPoll, alias)
	}

	for _, ident := range identifiersToPoll {
		rawMsgs := loadRawChatHistoryForPeer(ident)
		for _, m := range rawMsgs {
			key := fmt.Sprintf("%s|%s", m.Sender, strings.TrimSpace(m.Text))
			if !seen[key] {
				seen[key] = true
				merged = append(merged, m)
			}
		}
	}

	notifFiles := []string{
		filepath.Join(GetUniversalBaseDir(), "notifications.json"),
		"/tmp/cross_notifications.json",
		filepath.Join(os.TempDir(), "cross_notifications.json"),
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		sudoNotif := filepath.Join("/home", sudoUser, ".cross-ssh", "notifications.json")
		notifFiles = append(notifFiles, sudoNotif)
	}

	for _, nf := range notifFiles {
		nData, err := os.ReadFile(nf)
		if err != nil || len(nData) == 0 {
			continue
		}
		for _, nl := range strings.Split(string(nData), "\n") {
			nTrim := strings.TrimSpace(nl)
			if nTrim == "" {
				continue
			}

			payloadBytes := []byte(nTrim)
			if strings.HasPrefix(nTrim, "ENC:") {
				dec, errD := decryptPayloadAES(strings.TrimPrefix(nTrim, "ENC:"))
				if errD == nil {
					payloadBytes = dec
				}
			}

			var item NotificationItem
			if err := json.Unmarshal(payloadBytes, &item); err == nil && (item.Type == "MSG" || item.Type == "MESSAGE" || item.Type == "") && item.Message != "" {
				cleanSenderIP := sanitizePeerTag(item.SenderIP)
				cleanSenderTag := sanitizePeerTag(item.SenderTag)

				isTargetPeer := item.SenderIP == canonicalPeer ||
					cleanSenderIP == peerClean ||
					cleanSenderTag == peerClean ||
					item.SenderTag == canonicalPeer ||
					(alias != "" && (item.SenderIP == alias || item.SenderTag == alias))

				if isTargetPeer {
					senderName := item.SenderTag
					if senderName == "" {
						senderName = item.SenderIP
					}
					key := fmt.Sprintf("%s|%s", senderName, strings.TrimSpace(item.Message))
					if !seen[key] {
						seen[key] = true
						msg := ChatMessage{
							ID:        cleanMessageID(senderName, item.Message, item.Timestamp),
							Seq:       int64(len(merged) + 1),
							Sender:    senderName,
							Recipient: "YOU",
							Text:      item.Message,
							Timestamp: item.Timestamp,
						}
						merged = append(merged, msg)
						saveChatMessageToPeerVault(canonicalPeer, msg)
					}
				}
			}
		}
	}

	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Seq != 0 && merged[j].Seq != 0 && merged[i].Seq != merged[j].Seq {
			return merged[i].Seq < merged[j].Seq
		}
		return merged[i].Timestamp.Before(merged[j].Timestamp)
	})

	return merged
}

func saveChatMessageToPeerVault(peerIdentifier string, msg ChatMessage) {
	canonicalPeer := resolveCanonicalPeer(peerIdentifier)
	if canonicalPeer == "" {
		canonicalPeer = "standalone"
	}
	if msg.ID == "" {
		msg.ID = cleanMessageID(msg.Sender, msg.Text, msg.Timestamp)
	}

	cleanTag := sanitizePeerTag(canonicalPeer)
	vaultDir := filepath.Join(GetUniversalBaseDir(), "chat_vault")
	_ = os.MkdirAll(vaultDir, 0777)
	encPath := filepath.Join(vaultDir, fmt.Sprintf("thread_%s.enc", cleanTag))

	history := loadRawChatHistoryForPeer(canonicalPeer)
	for _, m := range history {
		if msg.ID != "" && m.ID == msg.ID {
			return
		}
	}

	var highestSeq int64 = 0
	for _, m := range history {
		if m.Seq > highestSeq {
			highestSeq = m.Seq
		}
	}

	if msg.Seq <= highestSeq {
		msg.Seq = highestSeq + 1
	}

	history = append(history, msg)
	out, err := json.Marshal(history)
	if err == nil {
		enc, errE := encryptPayloadAES(out)
		if errE == nil {
			_ = os.WriteFile(encPath, []byte(enc), 0600)
			_ = os.Remove(filepath.Join(vaultDir, fmt.Sprintf("thread_%s.json", cleanTag)))
		}
	}
}

func renderInteractiveChatCanvas(host, author string, history []ChatMessage, scrollOffset int, currentInput string) {
	fmt.Print("\033[H\033[2J")
	alias := getMeshAliasForIP(host)
	displayName := host
	if host == "" {
		displayName = "All Cached Peer Messages (Standalone)"
	} else if alias != "" {
		displayName = fmt.Sprintf("%s (%s)", alias, host)
	}

	fmt.Println(Cyan + Bold + "=== P2P SYNCHRONIZED THREADED MESSENGER ===" + Reset)
	RenderAudioStatusToast()
	fmt.Printf(Yellow+"Chat Thread with: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"My Identity: "+Reset+Bold+"%s"+Reset+" | "+Green+"[AES-256 GCM Namespace Vault]"+Reset+"\n", displayName, author)
	fmt.Println(Blue + "-------------------------------------------------------------------------------------------------------" + Reset)

	windowSize := 20
	totalMessages := len(history)

	if totalMessages == 0 {
		fmt.Println(Yellow + "  [No previous messages in this conversation thread]" + Reset)
	} else {
		maxOffset := totalMessages - windowSize
		if maxOffset < 0 {
			maxOffset = 0
		}
		if scrollOffset > maxOffset {
			scrollOffset = maxOffset
		}
		if scrollOffset < 0 {
			scrollOffset = 0
		}

		endIdx := totalMessages - scrollOffset
		startIdx := endIdx - windowSize
		if startIdx < 0 {
			startIdx = 0
		}

		if scrollOffset > 0 {
			fmt.Printf(Yellow+"  ▲ [%d newer message(s) hidden below - Scroll Down to view]\n"+Reset, scrollOffset)
		}

		for _, m := range history[startIdx:endIdx] {
			timeStr := m.Timestamp.Local().Format("15:04:05")
			if m.Sender == author || m.Sender == "YOU" {
				fmt.Printf("  %s[%s] YOU (%s):%s %s\n", Green+Bold, timeStr, author, Reset, m.Text)
			} else {
				fmt.Printf("  %s[%s] %s:%s %s\n", Magenta+Bold, timeStr, m.Sender, Reset, m.Text)
			}
		}
	}

	fmt.Println(Blue + "-------------------------------------------------------------------------------------------------------" + Reset)
	fmt.Println(Dim + "Controls: [Up/Down or Mouse Wheel] Scroll History | [Enter] Send | Type '0' or 'exit' to Return" + Reset)
	fmt.Printf("%s[YOU]:%s %s", Cyan+Bold, Reset, currentInput)
}

func showThreadedMessengerMenu(reader *bufio.Reader, client *ssh.Client, host, author string) {
	MarkNotificationRead("MSG", host)
	MarkNotificationRead("MSG", "")

	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1", "-echo").Run()
		defer func() {
			_ = exec.Command("stty", "-F", "/dev/tty", "-cbreak", "echo").Run()
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stateMutex sync.Mutex
	scrollOffset := 0
	inputBuffer := ""

	SyncAllLocalChatInboxes(host)
	if client != nil {
		syncRemoteChatInbox(client, host)
	}
	history := LoadChatHistory(host)

	renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)

	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				SyncAllLocalChatInboxes(host)
				if client != nil {
					syncRemoteChatInbox(client, host)
				}
				latest := LoadChatHistory(host)

				stateMutex.Lock()
				hasNew := len(latest) != len(history)
				if !hasNew && len(latest) > 0 && len(history) > 0 {
					if latest[len(latest)-1].ID != history[len(history)-1].ID {
						hasNew = true
					}
				}

				if hasNew {
					history = latest
					renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)
				}
				stateMutex.Unlock()
			}
		}
	}()

	keyBuf := make([]byte, 16)
	for {
		n, err := os.Stdin.Read(keyBuf)
		if err != nil || n == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		stateMutex.Lock()
		if n == 1 {
			b := keyBuf[0]
			switch b {
			case 10, 13:
				trimmed := strings.TrimSpace(inputBuffer)
				if trimmed == "0" || strings.EqualFold(trimmed, "exit") || strings.EqualFold(trimmed, "quit") || strings.EqualFold(trimmed, "q") {
					stateMutex.Unlock()
					MarkNotificationRead("MSG", host)
					MarkNotificationRead("MSG", "")
					return
				}
				if trimmed != "" {
					var curMaxSeq int64 = 0
					for _, m := range history {
						if m.Seq > curMaxSeq {
							curMaxSeq = m.Seq
						}
					}
					now := time.Now()
					chatMsg := ChatMessage{
						ID:        cleanMessageID(author, trimmed, now),
						Seq:       curMaxSeq + 1,
						Sender:    author,
						Recipient: host,
						Text:      trimmed,
						Timestamp: now,
					}
					saveChatMessageToPeerVault(host, chatMsg)

					if client != nil {
						dispatchChatMessageToRemote(client, chatMsg, host, author)
						dispatchNotification(client, host, author, "MSG", trimmed)
					}

					history = LoadChatHistory(host)
					scrollOffset = 0
				}
				inputBuffer = ""
				renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)

			case 127, 8:
				if len(inputBuffer) > 0 {
					inputBuffer = inputBuffer[:len(inputBuffer)-1]
					renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)
				}

			case 27:
				stateMutex.Unlock()
				MarkNotificationRead("MSG", host)
				MarkNotificationRead("MSG", "")
				return

			default:
				if b >= 32 && b <= 126 {
					inputBuffer += string(b)
					fmt.Print(string(b))
				}
			}
		} else if n >= 3 && keyBuf[0] == 27 {
			if keyBuf[1] == 91 {
				switch keyBuf[2] {
				case 65:
					scrollOffset += 3
					renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)
				case 66:
					if scrollOffset >= 3 {
						scrollOffset -= 3
					} else {
						scrollOffset = 0
					}
					renderInteractiveChatCanvas(host, author, history, scrollOffset, inputBuffer)
				}
			}
		}
		stateMutex.Unlock()
	}
}

func dispatchChatMessageToRemote(client *ssh.Client, msg ChatMessage, host, author string) {
	if client == nil {
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	enc, errE := encryptPayloadAES(data)
	if errE != nil {
		return
	}

	go func() {
		payloadLine := fmt.Sprintf("ENC:%s\n", enc)
		remoteCmd := `sh -c 'mkdir -p "$HOME/.cross-ssh" /tmp 2>/dev/null; tee -a "$HOME/.cross-ssh/chat_inbox.json" /tmp/cross_chat_inbox.json >/dev/null 2>&1; chmod 666 "$HOME/.cross-ssh/chat_inbox.json" /tmp/cross_chat_inbox.json 2>/dev/null || true; sync'`

		const maxAttempts = 4
		backoff := 100 * time.Millisecond

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			sess, errS := client.NewSession()
			if errS != nil {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			sess.Stdin = strings.NewReader(payloadLine)
			runErr := sess.Run(remoteCmd)
			sess.Close()

			if runErr == nil {
				return
			}

			time.Sleep(backoff)
			backoff *= 2
		}

		saveChatMessageToPeerVault(host, msg)
	}()
}

func syncRemoteChatInbox(client *ssh.Client, activeHost string) {
	if client == nil {
		return
	}
	sess, err := client.NewSession()
	if err != nil {
		return
	}
	defer sess.Close()

	fetchCmd := `sh -c '
P=$$
for f in "$HOME/.cross-ssh/chat_inbox.json" /tmp/cross_chat_inbox.enc /tmp/cross_chat_inbox.json; do
  [ -f "$f" ] && mv "$f" "$f.claim.$P" 2>/dev/null
done
cat "$HOME/.cross-ssh/chat_inbox.json.claim.$P" /tmp/cross_chat_inbox.enc.claim.$P /tmp/cross_chat_inbox.json.claim.$P 2>/dev/null
rm -f "$HOME/.cross-ssh/chat_inbox.json.claim.$P" /tmp/cross_chat_inbox.enc.claim.$P /tmp/cross_chat_inbox.json.claim.$P 2>/dev/null
'`
	out, err := sess.Output(fetchCmd)
	if err != nil || len(out) == 0 {
		return
	}

	lines := strings.Split(string(out), "\n")
	chatSyncMutex.Lock()
	defer chatSyncMutex.Unlock()

	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}

		payloadBytes := []byte(trimmed)
		if strings.HasPrefix(trimmed, "ENC:") {
			dec, errD := decryptPayloadAES(strings.TrimPrefix(trimmed, "ENC:"))
			if errD == nil {
				payloadBytes = dec
			}
		}

		var msg ChatMessage
		if err := json.Unmarshal(payloadBytes, &msg); err == nil && msg.Text != "" {
			saveChatMessageToPeerVault(activeHost, msg)
		}
	}
}

func dispatchNotification(client *ssh.Client, host, author, notifType, msg string) {
	if client == nil {
		return
	}
	myIP := getLocalOutboundIP(host)
	item := NotificationItem{
		SenderIP:  myIP,
		SenderTag: author,
		Type:      notifType,
		Message:   msg,
		Timestamp: time.Now(),
		IsRead:    false,
	}
	data, _ := json.Marshal(item)
	encData, _ := encryptPayloadAES(data)
	payloadLine := fmt.Sprintf("ENC:%s\n", encData)

	go func() {
		cmd := `sh -c 'mkdir -p "$HOME/.cross-ssh" /tmp 2>/dev/null; tee -a "$HOME/.cross-ssh/notifications.json" /tmp/cross_notifications.json >/dev/null 2>&1; chmod 666 "$HOME/.cross-ssh/notifications.json" /tmp/cross_notifications.json 2>/dev/null || true; sync'`

		const maxAttempts = 4
		backoff := 150 * time.Millisecond

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			sess, err := client.NewSession()
			if err != nil {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}

			sess.Stdin = strings.NewReader(payloadLine)
			runErr := sess.Run(cmd)
			sess.Close()

			if runErr == nil {
				return
			}

			time.Sleep(backoff)
			backoff *= 2
		}
	}()
}

// saveNotificationToVault processes a notification of type MSG and saves it to the chat vault.
func saveNotificationToVault(peer string, item NotificationItem) {
	if peer == "" {
		return
	}
	// Only process message-type notifications
	if item.Type != "MSG" && item.Type != "MESSAGE" && item.Type != "" {
		return
	}
	if strings.TrimSpace(item.Message) == "" {
		return
	}
	// Build a ChatMessage from the notification
	msg := ChatMessage{
		ID:        cleanMessageID(item.SenderTag, item.Message, item.Timestamp),
		Seq:       0, // will be auto-assigned in saveChatMessageToPeerVault
		Sender:    item.SenderTag,
		Recipient: peer,
		Text:      item.Message,
		Timestamp: item.Timestamp,
	}
	saveChatMessageToPeerVault(peer, msg)
}

// === SINGLE-TRANSACTION ATOMIC BACKGROUND SYNC FOR MAIN MENU ===
// SyncRemoteNotificationsAndChatSilent fetches remote chat inbox and notifications,
// then processes them into the local vault. Also processes local pending notifications.
func SyncRemoteNotificationsAndChatSilent(client *ssh.Client, activeHost string) {
	if client == nil || activeHost == "" {
		return
	}

	sess, err := client.NewSession()
	if err != nil {
		return
	}
	defer sess.Close()

	combinedCmd := `sh -c '
P=$$
for f in "$HOME/.cross-ssh/chat_inbox.json" /tmp/cross_chat_inbox.enc /tmp/cross_chat_inbox.json; do
  [ -f "$f" ] && mv "$f" "$f.claim.$P" 2>/dev/null
done
echo "---CHAT_DELIMITER---"
cat "$HOME/.cross-ssh/chat_inbox.json.claim.$P" /tmp/cross_chat_inbox.enc.claim.$P /tmp/cross_chat_inbox.json.claim.$P 2>/dev/null
rm -f "$HOME/.cross-ssh/chat_inbox.json.claim.$P" /tmp/cross_chat_inbox.enc.claim.$P /tmp/cross_chat_inbox.json.claim.$P 2>/dev/null
echo "---NOTIF_DELIMITER---"
for f in "$HOME/.cross-ssh/notifications.json" /tmp/cross_notifications.json; do
  [ -f "$f" ] && mv "$f" "$f.claim.$P" 2>/dev/null
done
cat "$HOME/.cross-ssh/notifications.json.claim.$P" /tmp/cross_notifications.json.claim.$P 2>/dev/null
rm -f "$HOME/.cross-ssh/notifications.json.claim.$P" /tmp/cross_notifications.json.claim.$P 2>/dev/null
'`
	out, err := sess.Output(combinedCmd)
	if err != nil || len(out) == 0 {
		return
	}

	sections := strings.Split(string(out), "---NOTIF_DELIMITER---")
	if len(sections) < 2 {
		return
	}

	// --- Process chat inbox ---
	chatRaw := strings.TrimPrefix(sections[0], "---CHAT_DELIMITER---")
	chatLines := strings.Split(strings.TrimSpace(chatRaw), "\n")
	chatSyncMutex.Lock()
	for _, l := range chatLines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		payloadBytes := []byte(trimmed)
		if strings.HasPrefix(trimmed, "ENC:") {
			if dec, errD := decryptPayloadAES(strings.TrimPrefix(trimmed, "ENC:")); errD == nil {
				payloadBytes = dec
			}
		}
		var msg ChatMessage
		if err := json.Unmarshal(payloadBytes, &msg); err == nil && msg.Text != "" {
			saveChatMessageToPeerVault(activeHost, msg)
		}
	}
	chatSyncMutex.Unlock()

	// --- Process notifications ---
	notifRaw := sections[1]
	notifLines := strings.Split(strings.TrimSpace(notifRaw), "\n")

	// Also read local notifications file to process messages that might not have been synced yet
	localNotifFile := filepath.Join(GetUniversalBaseDir(), "notifications.json")
	if localData, err := os.ReadFile(localNotifFile); err == nil && len(localData) > 0 {
		for _, nl := range strings.Split(string(localData), "\n") {
			tr := strings.TrimSpace(nl)
			if tr != "" {
				notifLines = append(notifLines, tr)
			}
		}
		// After reading, we can clear the file to avoid re-processing
		_ = os.WriteFile(localNotifFile, []byte(""), 0666)
	}

	// Also append remote notifications to local file (for display in notification area)
	if len(notifLines) > 0 {
		f, err := os.OpenFile(localNotifFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			for _, nl := range notifLines {
				tr := strings.TrimSpace(nl)
				if tr != "" {
					_, _ = f.WriteString(tr + "\n")
				}
			}
			f.Close()
		}
	}

	// Process each notification and save MSG types to vault
	for _, nl := range notifLines {
		tr := strings.TrimSpace(nl)
		if tr == "" {
			continue
		}
		payloadBytes := []byte(tr)
		if strings.HasPrefix(tr, "ENC:") {
			if dec, errD := decryptPayloadAES(strings.TrimPrefix(tr, "ENC:")); errD == nil {
				payloadBytes = dec
			}
		}
		var item NotificationItem
		if err := json.Unmarshal(payloadBytes, &item); err != nil {
			continue
		}
		// Only process if not already in vault (avoid duplicates)
		// We'll rely on saveNotificationToVault to check uniqueness.
		saveNotificationToVault(activeHost, item)
	}
}
// === AUDIO ENDPOINT MANAGEMENT & PULSEAUDIO CONTROL ===

func getDesktopAudioUserCmd(audioBinary string, args ...string) *exec.Cmd {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
		uidOut, _ := exec.Command("id", "-u", sudoUser).Output()
		uid := strings.TrimSpace(string(uidOut))
		if uid == "" {
			uid = "1000"
		}
		home := filepath.Join("/home", sudoUser)
		pulseSocket := fmt.Sprintf("unix:/run/user/%s/pulse/native", uid)
		envArgs := []string{
			"-u", sudoUser,
			"env",
			fmt.Sprintf("HOME=%s", home),
			fmt.Sprintf("USER=%s", sudoUser),
			fmt.Sprintf("LOGNAME=%s", sudoUser),
			fmt.Sprintf("PULSE_SERVER=%s", pulseSocket),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%s", uid),
			audioBinary,
		}
		return exec.Command("sudo", append(envArgs, args...)...)
	}
	return exec.Command(audioBinary, args...)
}

func getSelectedAudioSourcePath() string {
	return filepath.Join(GetUniversalBaseDir(), "selected_mic.txt")
}

func getSelectedAudioPortPath() string {
	return filepath.Join(GetUniversalBaseDir(), "selected_mic_port.txt")
}

func getSelectedAudioSinkPath() string {
	return filepath.Join(GetUniversalBaseDir(), "selected_speaker.txt")
}

func getActiveSelectedMicSource() string {
	data, err := os.ReadFile(getSelectedAudioSourcePath())
	if err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			return s
		}
	}
	defSourceCmd := getDesktopAudioUserCmd("pactl", "get-default-source")
	defSource, errD := defSourceCmd.Output()
	if errD == nil {
		return strings.TrimSpace(string(defSource))
	}
	return ""
}

func getActiveSelectedSpeakerSink() string {
	data, err := os.ReadFile(getSelectedAudioSinkPath())
	if err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			return s
		}
	}
	defSinkCmd := getDesktopAudioUserCmd("pactl", "get-default-sink")
	defSink, errD := defSinkCmd.Output()
	if errD == nil {
		return strings.TrimSpace(string(defSink))
	}
	return ""
}

func setSelectedMicSource(sourceName string, portName string) {
	cleanSource := strings.TrimSpace(sourceName)
	cleanPort := strings.TrimSpace(portName)

	_ = os.WriteFile(getSelectedAudioSourcePath(), []byte(cleanSource), 0644)
	_ = getDesktopAudioUserCmd("pactl", "set-default-source", cleanSource).Run()

	if cleanPort != "" {
		_ = os.WriteFile(getSelectedAudioPortPath(), []byte(cleanPort), 0644)
		_ = getDesktopAudioUserCmd("pactl", "set-source-port", cleanSource, cleanPort).Run()
	}

	_ = getDesktopAudioUserCmd("pactl", "set-source-mute", cleanSource, "0").Run()
	_ = getDesktopAudioUserCmd("pactl", "set-source-volume", cleanSource, "100%").Run()
	_ = exec.Command("amixer", "set", "Capture", "100%", "cap").Run()
}

func setSelectedSpeakerSink(sinkName string) {
	_ = os.WriteFile(getSelectedAudioSinkPath(), []byte(strings.TrimSpace(sinkName)), 0644)
	_ = getDesktopAudioUserCmd("pactl", "set-default-sink", strings.TrimSpace(sinkName)).Run()
}

func parseAudioEndpoints(mode string) []AudioDeviceEndpoint {
	var devices []AudioDeviceEndpoint
	currentDefSource := getActiveSelectedMicSource()
	currentDefSink := getActiveSelectedSpeakerSink()

	savedPort := ""
	if portData, err := os.ReadFile(getSelectedAudioPortPath()); err == nil {
		savedPort = strings.TrimSpace(string(portData))
	}

	cmdFlag := "sources"
	delimiter := "Source #"
	if mode == "sink" {
		cmdFlag = "sinks"
		delimiter = "Sink #"
	}

	cmd := getDesktopAudioUserCmd("pactl", "list", cmdFlag)
	out, err := cmd.Output()
	if err != nil {
		return devices
	}

	blocks := strings.Split(string(out), delimiter)
	for _, b := range blocks {
		if strings.TrimSpace(b) == "" {
			continue
		}
		lines := strings.Split(b, "\n")
		idx := strings.TrimSpace(lines[0])
		name := ""
		desc := ""
		activePort := ""

		type portInfo struct {
			pName string
			pDesc string
		}
		var ports []portInfo
		inPortsSection := false

		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, "Name: ") {
				name = strings.TrimPrefix(trimmed, "Name: ")
			}
			if strings.HasPrefix(trimmed, "Description: ") {
				desc = strings.TrimPrefix(trimmed, "Description: ")
			}
			if strings.HasPrefix(trimmed, "Active Port: ") {
				activePort = strings.TrimPrefix(trimmed, "Active Port: ")
			}
			if strings.HasPrefix(trimmed, "Ports:") {
				inPortsSection = true
				continue
			}
			if inPortsSection {
				if strings.HasPrefix(l, "\t\t") || strings.HasPrefix(l, "    ") {
					parts := strings.SplitN(trimmed, ": ", 2)
					if len(parts) == 2 {
						pName := strings.TrimSpace(parts[0])
						pDesc := strings.TrimSpace(parts[1])
						pDesc = strings.Split(pDesc, " (type:")[0]
						pDesc = strings.Split(pDesc, " (priority:")[0]
						ports = append(ports, portInfo{pName: pName, pDesc: pDesc})
					}
				} else if strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "  ") {
					if !strings.HasPrefix(trimmed, "analog-") && !strings.HasPrefix(trimmed, "digital-") && !strings.HasPrefix(trimmed, "input-") {
						inPortsSection = false
					}
				}
			}
		}

		if mode == "source" && strings.HasSuffix(name, ".monitor") {
			continue
		}

		if name != "" {
			if desc == "" {
				desc = name
			}

			if mode == "source" && len(ports) > 0 {
				for _, p := range ports {
					isCurActive := (name == currentDefSource) && ((savedPort != "" && p.pName == savedPort) || (savedPort == "" && p.pName == activePort))
					fullDesc := fmt.Sprintf("%s (%s)", desc, p.pDesc)
					devices = append(devices, AudioDeviceEndpoint{
						Index:       idx,
						Name:        name,
						Description: fullDesc,
						PortName:    p.pName,
						IsDefault:   isCurActive,
					})
				}
			} else {
				isDef := (name == currentDefSource)
				if mode == "sink" {
					isDef = (name == currentDefSink)
				}
				devices = append(devices, AudioDeviceEndpoint{
					Index:       idx,
					Name:        name,
					Description: desc,
					PortName:    activePort,
					IsDefault:   isDef,
				})
			}
		}
	}

	return devices
}

func showInteractiveAudioSelector(reader *bufio.Reader, mode string) {
	fmt.Print("\033[H\033[2J")
	title := "MICROPHONE INPUT SOURCE & HARDWARE JACK"
	if mode == "sink" {
		title = "SPEAKER OUTPUT SINK"
	}

	fmt.Printf(Cyan+Bold+"=== SELECT YOUR ACTIVE %s ===\n"+Reset, title)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "Scanning audio server for all cards, external jacks & hardware ports:" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+" %-4s | %-46s | %-32s | %-12s\n"+Reset, "#", "HARDWARE / JACK LABEL", "PORT / NODE", "STATE")
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)

	devices := parseAudioEndpoints(mode)
	if len(devices) == 0 {
		fmt.Println(Red + " No audio endpoints detected by audio server." + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
		pausePrompt()
		return
	}

	for i, d := range devices {
		stateTag := Dim + "[Available]" + Reset
		if d.IsDefault {
			stateTag = Green + Bold + "★ [ACTIVE]" + Reset
		}
		rawNode := d.PortName
		if rawNode == "" {
			rawNode = d.Name
		}
		fmt.Printf(" [%d]  | %-46s | %-32s | %s\n", i+1, truncateStr(d.Description, 46), truncateStr(rawNode, 32), stateTag)
	}

	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	selStr := transfer.ReadRealtimeInput("Enter device number to activate (or 0 to cancel): ")
	sel, err := strconv.Atoi(strings.TrimSpace(selStr))
	if err == nil && sel >= 1 && sel <= len(devices) {
		chosen := devices[sel-1]
		if mode == "sink" {
			setSelectedSpeakerSink(chosen.Name)
		} else {
			setSelectedMicSource(chosen.Name, chosen.PortName)
		}
		fmt.Printf(Green+Bold+"\n[✔ SUCCESS] Active hardware input locked to: %s\n"+Reset, chosen.Description)
		time.Sleep(1200 * time.Millisecond)
	}
}

// === MULTI-TIER AUDIO TROUBLESHOOTER HUB ===

func ShowMicrophoneTroubleshooterMenu(reader *bufio.Reader) {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		activeMic := getActiveSelectedMicSource()
		if activeMic == "" {
			activeMic = "System Default / Auto"
		}
		activeSpeaker := getActiveSelectedSpeakerSink()
		if activeSpeaker == "" {
			activeSpeaker = "System Default / Auto"
		}

		fmt.Println(Cyan + Bold + "=== MULTI-TIER AUDIO & HARDWARE TROUBLESHOOTER HUB ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Active Input (Mic)    : "+Reset+Green+Bold+"%s\n"+Reset, activeMic)
		fmt.Printf(Yellow+"Active Output (Speaker): "+Reset+Cyan+Bold+"%s\n"+Reset, activeSpeaker)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Println(Green + Bold + "  [1] Microphone (Input) Troubleshooting & Calibration Sub-Hub" + Reset)
		fmt.Println(Cyan + Bold + "  [2] Speaker (Output) Troubleshooting & Playback Sub-Hub" + Reset)
		fmt.Println("  [3] Master Autonomous Auto-Healer (Unmute & Reset All Audio Channels)")
		fmt.Println("  [4] Comprehensive Live System Audio Hardware Probe Report")
		fmt.Println(Red + "  [0] Return to P2P Matrix" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select troubleshooting category [0-4]: ")

		switch choice {
		case "1":
			showMicrophoneSubMenu(reader)
		case "2":
			showSpeakerSubMenu(reader)
		case "3":
			runAutoHealAudioSubsystem(reader)
		case "4":
			runLiveAudioProbe(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func showMicrophoneSubMenu(reader *bufio.Reader) {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		activeMic := getActiveSelectedMicSource()
		if activeMic == "" {
			activeMic = "System Default / Auto"
		}

		fmt.Println(Green + Bold + "=== MICROPHONE (INPUT) TROUBLESHOOTING & CALIBRATION HUB ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Current Bound Mic: "+Reset+Green+Bold+"%s\n"+Reset, activeMic)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Select & Lock Input Microphone Endpoint (BOYA, USB, Analog)")
		fmt.Println("  [2] Interactive 5-Second Real-Time Mic Gain & Audio VU Level Test")
		fmt.Println("  [3] Boost Microphone Capture Sensitivity (120% Gain & Unmute)")
		fmt.Println("  [4] Oracle VirtualBox Microphone Input Passthrough Guide")
		fmt.Println("  [5] VMware Workstation Microphone Input Passthrough Guide")
		fmt.Println(Red + "  [0] Back to Audio Hub" + Reset)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select mic option [0-5]: ")

		switch choice {
		case "1":
			showInteractiveAudioSelector(reader, "source")
		case "2":
			runInteractiveMicGainTest(reader)
		case "3":
			_ = getDesktopAudioUserCmd("pactl", "set-source-volume", "@DEFAULT_SOURCE@", "120%").Run()
			_ = getDesktopAudioUserCmd("pactl", "set-source-mute", "@DEFAULT_SOURCE@", "0").Run()
			_ = exec.Command("amixer", "set", "Capture", "100%", "cap").Run()
			fmt.Println(Green + Bold + "\n[✔ SUCCESS] Microphone input sensitivity boosted to 120%!" + Reset)
			pausePrompt()
		case "4":
			showVirtualBoxAudioGuide(reader)
		case "5":
			showVMwareAudioGuide(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func showSpeakerSubMenu(reader *bufio.Reader) {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		activeSpeaker := getActiveSelectedSpeakerSink()
		if activeSpeaker == "" {
			activeSpeaker = "System Default / Auto"
		}

		fmt.Println(Cyan + Bold + "=== SPEAKER (OUTPUT) TROUBLESHOOTING & PLAYBACK HUB ===" + Reset)
		RenderAudioStatusToast()
		fmt.Printf(Yellow+"Current Bound Speaker: "+Reset+Cyan+Bold+"%s\n"+Reset, activeSpeaker)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Select & Lock Output Speaker / Headphone Sink")
		fmt.Println("  [2] Play Calibrated 440Hz Stereo Test Chime (Verify Physical Output)")
		fmt.Println("  [3] Boost Speaker Master Volume (140% Amplification & Unmute)")
		fmt.Println("  [4] Oracle VirtualBox Speaker Audio Passthrough Guide")
		fmt.Println("  [5] VMware Workstation Speaker Audio Passthrough Guide")
		fmt.Println(Red + "  [0] Back to Audio Hub" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select speaker option [0-5]: ")

		switch choice {
		case "1":
			showInteractiveAudioSelector(reader, "sink")
		case "2":
			runSpeakerPlaybackTest(reader)
		case "3":
			_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", "@DEFAULT_SINK@", "140%").Run()
			_ = getDesktopAudioUserCmd("pactl", "set-sink-mute", "@DEFAULT_SINK@", "0").Run()
			_ = exec.Command("amixer", "set", "Master", "100%", "unmute").Run()
			fmt.Println(Green + Bold + "\n[✔ SUCCESS] Speaker output amplified to 140%!" + Reset)
			pausePrompt()
		case "4":
			showVirtualBoxAudioGuide(reader)
		case "5":
			showVMwareAudioGuide(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func runLiveAudioProbe(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== DEEP SYSTEM AUDIO HARDWARE EXTRACTION REPORT ===" + Reset)
	RenderAudioStatusToast()
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	fmt.Println(Yellow + Bold + "=> Physical USB Connected Audio Hardware (lsusb):" + Reset)
	usbOut, err := exec.Command("lsusb").Output()
	if err == nil {
		lines := strings.Split(string(usbOut), "\n")
		foundUSB := false
		for _, l := range lines {
			low := strings.ToLower(l)
			if strings.Contains(low, "audio") || strings.Contains(low, "mic") || strings.Contains(low, "boya") || strings.Contains(low, "sound") || strings.Contains(low, "c-media") || strings.Contains(low, "realtek") {
				fmt.Printf(Green+"  • %s\n"+Reset, l)
				foundUSB = true
			}
		}
		if !foundUSB {
			fmt.Println(Dim + "    No dedicated USB audio chips identified in raw USB bus enumeration." + Reset)
		}
	}

	fmt.Println(Yellow + Bold + "\n=> Default PulseAudio / PipeWire Endpoints:" + Reset)
	defSourceCmd := getDesktopAudioUserCmd("pactl", "get-default-source")
	defSource, _ := defSourceCmd.Output()
	fmt.Printf(Green+"  • Default Input (Mic)   : %s"+Reset, string(defSource))

	defSinkCmd := getDesktopAudioUserCmd("pactl", "get-default-sink")
	defSink, _ := defSinkCmd.Output()
	fmt.Printf(Cyan+"  • Default Output (Audio): %s"+Reset, string(defSink))
	fmt.Println(Blue + "\n------------------------------------------------------------------" + Reset)
	pausePrompt()
}

func runSpeakerPlaybackTest(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== SPEAKER OUTPUT TEST (CALIBRATED CHIME) ===" + Reset)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "Emitting a test sound through your selected output sink..." + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	testWav := filepath.Join(os.TempDir(), "test_chime.wav")
	defer os.Remove(testWav)

	_ = getDesktopAudioUserCmd("speaker-test", "-t", "sine", "-f", "440", "-l", "1").Run()

	fmt.Println(Green + Bold + "\n[✔ TEST COMPLETE] Test chime sequence finalized." + Reset)
	pausePrompt()
}

func runInteractiveMicGainTest(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== REAL-TIME 5-SECOND MICROPHONE AUDIO LEVEL TEST ===" + Reset)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "Speak into your microphone now to test live audio decibel response:" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	ensureAudioToolsInstalled()
	enforceHardwareAudioLocks()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	selectedSource := getActiveSelectedMicSource()

	var recCmd *exec.Cmd
	if _, err := exec.LookPath("parec"); err == nil {
		args := []string{"--raw", "--rate=48000", "--channels=1", "--format=s16le", "--latency-msec=20"}
		if selectedSource != "" {
			args = append([]string{"-d", selectedSource}, args...)
		}
		recCmd = getDesktopAudioUserCmd("parec", args...)
	} else {
		recCmd = exec.Command("arecord", "-D", "default", "-q", "-r", "48000", "-f", "S16_LE", "-c", "1", "-t", "raw", "--period-size=1024", "--buffer-size=8192")
	}

	micPipe, err := recCmd.StdoutPipe()
	if err != nil {
		fmt.Printf(Red+"[!] Pipe creation failed: %v\n"+Reset, err)
		pausePrompt()
		return
	}

	_ = recCmd.Start()

	var latestRMSBits uint64
	samplesReceived := false

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, errR := micPipe.Read(buf)
				if errR != nil || n == 0 {
					time.Sleep(1 * time.Millisecond)
					continue
				}

				sum := 0.0
				samples := n / 2
				for i := 0; i < n-1; i += 2 {
					val := int16(buf[i]) | (int16(buf[i+1]) << 8)
					sum += float64(val) * float64(val)
				}
				rms := math.Sqrt(sum / float64(samples+1))
				atomic.StoreUint64(&latestRMSBits, math.Float64bits(rms))

				if rms > 25.0 {
					samplesReceived = true
				}
			}
		}
	}()

	startTime := time.Now()
	smoothedLevel := 0.0
	targetDuration := 5 * time.Second

	for {
		elapsed := time.Since(startTime)
		if elapsed >= targetDuration {
			break
		}

		remainingSec := int(math.Ceil((targetDuration - elapsed).Seconds()))
		if remainingSec < 0 {
			remainingSec = 0
		}

		bits := atomic.LoadUint64(&latestRMSBits)
		rms := math.Float64frombits(bits)
		meter := renderDynamicVUBar(rms, &smoothedLevel, 24)

		fmt.Printf("\r\033[K%s[LIVE MIC PROBE]:%s LEVEL [%s] Speaking (%ds remaining)...", Cyan+Bold, Reset, meter, remainingSec)
		time.Sleep(25 * time.Millisecond)
	}

	cancel()
	_ = recCmd.Process.Kill()
	_ = recCmd.Wait()

	fmt.Println()
	if samplesReceived {
		fmt.Println(Green + Bold + "\n[✔ TEST COMPLETE] Microphone is operational and streaming sound packets!" + Reset)
	} else {
		fmt.Println(Red + Bold + "\n[✖ SILENCE DETECTED] No audio samples reached the system." + Reset)
	}
	pausePrompt()
}

func runAutoHealAudioSubsystem(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== AUTONOMOUS AUDIO SUBSYSTEM AUTO-HEALER ===" + Reset)
	RenderAudioStatusToast()
	fmt.Println(Yellow + "Resolving audio server muting, missing packages, and permissions..." + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	ensureAudioToolsInstalled()

	_ = exec.Command("amixer", "set", "Master", "100%", "unmute").Run()
	_ = exec.Command("amixer", "set", "Capture", "cap").Run()
	_ = exec.Command("amixer", "set", "Capture", "100%").Run()
	_ = exec.Command("amixer", "set", "Mic", "cap").Run()
	_ = exec.Command("amixer", "set", "Mic", "100%").Run()
	_ = exec.Command("amixer", "sset", "'Capture'", "unmute").Run()

	pactlSourceCmd := getDesktopAudioUserCmd("pactl", "list", "sources", "short")
	pOut, err := pactlSourceCmd.Output()
	if err == nil {
		for _, l := range strings.Split(string(pOut), "\n") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				sourceName := parts[1]
				_ = getDesktopAudioUserCmd("pactl", "set-source-mute", sourceName, "0").Run()
				_ = getDesktopAudioUserCmd("pactl", "set-source-volume", sourceName, "100%").Run()
			}
		}
	}

	pactlSinkCmd := getDesktopAudioUserCmd("pactl", "list", "sinks", "short")
	pSinkOut, err := pactlSinkCmd.Output()
	if err == nil {
		for _, l := range strings.Split(string(pSinkOut), "\n") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				sinkName := parts[1]
				_ = getDesktopAudioUserCmd("pactl", "set-sink-mute", sinkName, "0").Run()
				_ = getDesktopAudioUserCmd("pactl", "set-sink-volume", sinkName, "100%").Run()
			}
		}
	}

	enforceHardwareAudioLocks()

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
		_ = exec.Command("usermod", "-aG", "audio", sudoUser).Run()
	}

	fmt.Println(Green + Bold + "\n[✔ SUCCESS] Audio subsystem unmuted, healed, and endpoint ports locked!" + Reset)
	pausePrompt()
}

func showVirtualBoxAudioGuide(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== ORACLE VIRTUALBOX: MICROPHONE & SPEAKER SETUP GUIDE ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Println("  1. Ensure the 'VirtualBox Extension Pack' is installed on your host.")
	fmt.Println("  2. Open VM Settings -> Audio -> Enable Audio Input & Output (Intel HD Audio).")
	fmt.Println("  3. For USB Microphones (BOYA etc.): Settings -> USB -> Add USB Filter.")
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	pausePrompt()
}

func showVMwareAudioGuide(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== VMWARE WORKSTATION / PLAYER: AUDIO PASSTHROUGH GUIDE ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Println("  1. Top Menu: VM -> Removable Devices -> Select Mic -> Connect.")
	fmt.Println("  2. Settings -> Sound Card -> Check 'Connect at power on'.")
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	pausePrompt()
}

// === PHONEBOOK VAULT & HELPERS ===

func getMeshPhonebookPath() string {
	return filepath.Join(GetUniversalBaseDir(), "p2p_mesh_phonebook.json")
}

func loadMeshContacts() []MeshContact {
	data, err := os.ReadFile(getMeshPhonebookPath())
	if err != nil {
		return nil
	}
	var contacts []MeshContact
	_ = json.Unmarshal(data, &contacts)
	return contacts
}

func saveMeshContacts(contacts []MeshContact) {
	out, _ := json.MarshalIndent(contacts, "", "  ")
	_ = os.WriteFile(getMeshPhonebookPath(), out, 0644)
}

func getMeshAliasForIP(ip string) string {
	if ip == "" {
		return ""
	}
	for _, c := range loadMeshContacts() {
		if c.IP == ip {
			return c.Alias
		}
	}
	return vault.ResolveAliasForIP(ip)
}

func checkNodeStatus(ip, port string) NodeStatus {
	if port == "" {
		port = "22"
	}
	target := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return NodeStatus{Label: "● ACTIVE (Online)", Color: Green}
	}

	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	}
	if cmd.Run() == nil {
		return NodeStatus{Label: "▲ STANDBY (Ping OK)", Color: Yellow}
	}

	return NodeStatus{Label: "✖ OFFLINE", Color: Red}
}

func showMeshPhonebookMenu(reader *bufio.Reader, currentHost string) string {
	for {
		restoreTerminalState()
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== P2P MESH PHONEBOOK & PRIVATE PEER VAULT ===" + Reset)
		RenderAudioStatusToast()
		fmt.Println(Yellow + "Real-time health checking registered node endpoints:" + Reset)
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Printf(Bold+" %-4s | %-20s | %-24s | %-8s | %-22s\n"+Reset, "#", "ALIAS", "IP ADDRESS", "PORT", "LIVE STATUS")
		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)

		contacts := loadMeshContacts()

		if currentHost != "" {
			currSt := checkNodeStatus(currentHost, "22")
			fmt.Printf(" %-4s | %-20s | %-24s | %-8s | %s%-22s%s\n", "[1]", truncateStr("Current Locked Node", 20), truncateStr(currentHost, 24), "22", currSt.Color+Bold, currSt.Label, Reset)
		}

		offset := 1
		if currentHost != "" {
			offset = 2
		}

		for i, c := range contacts {
			st := checkNodeStatus(c.IP, c.Port)
			idStr := fmt.Sprintf("[%d]", i+offset)
			userHost := fmt.Sprintf("%s@%s", c.User, c.IP)
			fmt.Printf(" %-4s | %-20s | %-24s | %-8s | %s%-22s%s\n", idStr, truncateStr(c.Alias, 20), truncateStr(userHost, 24), truncateStr(c.Port, 8), st.Color+Bold, st.Label, Reset)
		}

		fmt.Println(Blue + "-----------------------------------------------------------------------------------------" + Reset)
		fmt.Println(Green + "  [S] Select Peer from List to Dial / Lock as Active" + Reset)
		fmt.Println(Cyan + "  [A] Add New Peer / IP to Phonebook Vault" + Reset)
		fmt.Println(Yellow + "  [R] Remove a Peer from Phonebook Vault" + Reset)
		fmt.Println(Red + "  [0] Return to Intercom Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select action [S/A/R/0]: ")
		switch strings.ToUpper(strings.TrimSpace(choice)) {
		case "S":
			total := len(contacts) + offset - 1
			selStr := transfer.ReadRealtimeInput("Enter entry number to select [1 to " + strconv.Itoa(total) + "]: ")
			sel, err := strconv.Atoi(strings.TrimSpace(selStr))
			if err == nil {
				if currentHost != "" && sel == 1 {
					return currentHost
				} else if sel >= offset && sel <= total {
					selectedPeer := contacts[sel-offset].IP
					fmt.Printf(Green+Bold+"\n[✔ SUCCESS] Active peer locked to: %s (%s)\n"+Reset, contacts[sel-offset].Alias, selectedPeer)
					time.Sleep(1 * time.Second)
					return selectedPeer
				}
			}
		case "A":
			newIP := transfer.ReadRealtimeInput("\nEnter Peer Hostname or IP: ")
			if strings.TrimSpace(newIP) == "" {
				continue
			}
			newAlias := transfer.ReadRealtimeInput("Enter Human-Readable Alias: ")
			if newAlias == "" {
				newAlias = fmt.Sprintf("Peer-%s", strings.ReplaceAll(newIP, ".", "-"))
			}
			newUser := transfer.ReadRealtimeInput("Enter SSH Username [default: root]: ")
			if newUser == "" {
				newUser = "root"
			}
			newPort := transfer.ReadRealtimeInput("Enter SSH Port [default: 22]: ")
			if newPort == "" {
				newPort = "22"
			}

			contacts = append(contacts, MeshContact{
				Alias:     newAlias,
				IP:        newIP,
				Port:      newPort,
				User:      newUser,
				CreatedAt: time.Now().Format("2006-01-02 15:04"),
			})
			saveMeshContacts(contacts)
			fmt.Println(Green + Bold + "[✔ SUCCESS] Contact registered into P2P Mesh Phonebook!" + Reset)
			time.Sleep(1 * time.Second)
		case "R":
			if len(contacts) == 0 {
				fmt.Println(Yellow + "[!] No registered contacts to delete." + Reset)
				time.Sleep(1 * time.Second)
				continue
			}
			total := len(contacts) + offset - 1
			delStr := transfer.ReadRealtimeInput("Enter contact # to remove [" + strconv.Itoa(offset) + " to " + strconv.Itoa(total) + "]: ")
			delIdx, err := strconv.Atoi(strings.TrimSpace(delStr))
			if err == nil && delIdx >= offset && delIdx <= total {
				idx := delIdx - offset
				contacts = append(contacts[:idx], contacts[idx+1:]...)
				saveMeshContacts(contacts)
				fmt.Println(Green + Bold + "[✔ SUCCESS] Contact removed from Phonebook!" + Reset)
				time.Sleep(1 * time.Second)
			}
		case "0", "Q":
			return currentHost
		}
	}
}

func truncateStr(str string, maxLen int) string {
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}

func startUniversalWebBridge(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== UNIVERSAL HTTP/TCP WEB FORWARDING BRIDGE ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	remotePath := transfer.ReadRealtimeInput("\nEnter Remote Directory Path [Press Enter for /]: ")
	if strings.TrimSpace(remotePath) == "" {
		remotePath = "/"
	}

	remotePortStr := transfer.ReadRealtimeInput("Enter Remote Port [Press Enter for 8888]: ")
	rPort := 8888
	if p, err := strconv.Atoi(strings.TrimSpace(remotePortStr)); err == nil && p > 0 {
		rPort = p
	}

	pyCmd := fmt.Sprintf("nohup python3 -m http.server %d --directory %s >/dev/null 2>&1 & nohup python -m SimpleHTTPServer %d >/dev/null 2>&1 &", rPort, remotePath, rPort)
	session, err := client.NewSession()
	if err == nil {
		_ = session.Run(pyCmd)
		session.Close()
	}

	time.Sleep(1 * time.Second)
	startTunnelFlow(reader, client, fmt.Sprintf("Web-Bridge(%s)", remotePath), rPort)
}

func probeRemoteWebPort(client *ssh.Client, candidatePorts []int) int {
	for _, p := range candidatePorts {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		conn, err := client.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			return p
		}
	}
	return candidatePorts[0]
}

func startTunnelFlow(reader *bufio.Reader, client *ssh.Client, serviceName string, remotePort int) {
	localPort := findFreeLocalPort(remotePort)
	fmt.Printf(Yellow+"\n[+] Establishing SSH Port Forwarding: 127.0.0.1:%d ==> 127.0.0.1:%d (%s)...\n"+Reset, localPort, remotePort, serviceName)

	_, err := createSSHTunnel(client, localPort, remotePort, serviceName)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to start SSH Tunnel: %v\n"+Reset, err)
		pausePrompt()
		return
	}

	fmt.Printf(Green+Bold+"[SUCCESS] Tunnel active! Bound 127.0.0.1:%d to Remote Port %d\n"+Reset, localPort, remotePort)
	url := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	fmt.Printf(Cyan+"[+] Web URL: %s\n"+Reset, url)

	autoLaunch := transfer.ReadRealtimeInput("\nLaunch in local Web Browser automatically? [Y/n]: ")
	if autoLaunch == "" || strings.ToLower(autoLaunch) == "y" {
		openBrowser(url)
	}
	pausePrompt()
}

func createSSHTunnel(client *ssh.Client, localPort int, remotePort int, serviceName string) (*ActiveTunnel, error) {
	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("local net.Listen failed on %s: %w", localAddr, err)
	}

	tunnelMutex.Lock()
	t := &ActiveTunnel{
		ID:          nextID,
		LocalPort:   localPort,
		RemotePort:  remotePort,
		ServiceName: serviceName,
		Listener:    listener,
		StopChan:    make(chan bool),
		StartTime:   time.Now(),
		IsReverse:   false,
	}
	nextID++
	tunnels = append(tunnels, t)
	tunnelMutex.Unlock()

	go func(t *ActiveTunnel) {
		for {
			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-t.StopChan:
					return
				default:
					continue
				}
			}
			go handleTunnelConn(client, localConn, t.RemotePort)
		}
	}(t)

	return t, nil
}

func handleTunnelConn(client *ssh.Client, localConn net.Conn, remotePort int) {
	defer localConn.Close()
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", remotePort)
	remoteConn, err := client.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remoteConn, localConn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(localConn, remoteConn) }()
	wg.Wait()
}

func listActiveTunnelsMenu(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== ACTIVE SSH FORWARD & REVERSE TUNNELS ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+" %-4s | %-8s | %-20s | %-16s | %-16s | %-15s | %-20s\n"+Reset, "ID", "TYPE", "SERVICE", "LOCAL PORT", "REMOTE PORT", "UPTIME", "URL / ENDPOINT")
	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)

	tunnelMutex.Lock()
	count := len(tunnels)
	if count == 0 {
		fmt.Println(Yellow + " No active SSH tunnels running." + Reset)
		tunnelMutex.Unlock()
		pausePrompt()
		return
	}

	for _, t := range tunnels {
		uptime := time.Since(t.StartTime).Round(time.Second).String()
		typeStr := "FORWARD"
		url := fmt.Sprintf("http://127.0.0.1:%d", t.LocalPort)
		if t.IsReverse {
			typeStr = "REVERSE"
			url = fmt.Sprintf("Host-Port:%d", t.RemotePort)
		}
		fmt.Printf(" %-4d | %-8s | %-20s | %-16d | %-16d | %-15s | %-20s\n", t.ID, typeStr, t.ServiceName, t.LocalPort, t.RemotePort, uptime, Green+url+Reset)
	}
	tunnelMutex.Unlock()

	fmt.Println(Blue + "------------------------------------------------------------------------------------------------------------------" + Reset)
	choice := transfer.ReadRealtimeInput("\nEnter Tunnel ID to open in Browser (or press Enter to return): ")
	if choice != "" {
		id, err := strconv.Atoi(strings.TrimSpace(choice))
		if err == nil {
			tunnelMutex.Lock()
			for _, t := range tunnels {
				if t.ID == id && !t.IsReverse {
					openBrowser(fmt.Sprintf("http://127.0.0.1:%d", t.LocalPort))
					break
				}
			}
			tunnelMutex.Unlock()
		}
	}
}

func closeTunnelMenu(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== CLOSE ACTIVE SSH TUNNEL ===" + Reset)

	tunnelMutex.Lock()
	if len(tunnels) == 0 {
		fmt.Println(Yellow + " No active tunnels to close." + Reset)
		tunnelMutex.Unlock()
		pausePrompt()
		return
	}

	for _, t := range tunnels {
		fmt.Printf("  [%d] %s (127.0.0.1:%d ==> Remote %d)\n", t.ID, t.ServiceName, t.LocalPort, t.RemotePort)
	}
	tunnelMutex.Unlock()

	choice := transfer.ReadRealtimeInput("\nEnter Tunnel ID to close (or 0 to cancel): ")
	id, err := strconv.Atoi(strings.TrimSpace(choice))
	if err != nil || id <= 0 {
		return
	}

	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()

	for i, t := range tunnels {
		if t.ID == id {
			close(t.StopChan)
			_ = t.Listener.Close()
			tunnels = append(tunnels[:i], tunnels[i+1:]...)
			fmt.Printf(Green+Bold+"[SUCCESS] Tunnel ID %d (%s) closed cleanly.\n"+Reset, id, t.ServiceName)
			pausePrompt()
			return
		}
	}

	fmt.Println(Red + "[!] Tunnel ID not found." + Reset)
	pausePrompt()
}

func findFreeLocalPort(preferredPort int) int {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", preferredPort))
	if err == nil {
		l, err := net.ListenTCP("tcp", addr)
		if err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port
		}
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 8081
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		fmt.Printf(" Please open URL manually: %s\n", url)
		return
	}
	_ = cmd.Start()
}

func pausePrompt() {
	restoreTerminalState()
	fmt.Print(Yellow + "\nPress Enter to return..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}