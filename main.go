package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"cross-ssh/pkg/cleaner"
	"cross-ssh/pkg/localinfo"
	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/p2p"
	"cross-ssh/pkg/payload"
	"cross-ssh/pkg/playbook"
	"cross-ssh/pkg/probe"
	"cross-ssh/pkg/rbac"
	"cross-ssh/pkg/redteam"
	"cross-ssh/pkg/security"
	"cross-ssh/pkg/services"
	"cross-ssh/pkg/shell"
	"cross-ssh/pkg/ticket"
	"cross-ssh/pkg/transfer"
	"cross-ssh/pkg/troubleshoot"
	"cross-ssh/pkg/tunnel"
	"cross-ssh/pkg/vault"
	"cross-ssh/pkg/vpn"

	"golang.org/x/crypto/ssh"
)

const AppVersion = "v2.0.0"
const GitHubRepoUser = "ali4210"
const GitHubRepoName = "Cross-Suite_Wizard"

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
)

type TargetSession struct {
	Host     string
	Port     string
	User     string
	Pass     string
	KeyPath  string
	TargetOS osdetect.TargetOS
	IsAdmin  bool
	IsActive bool
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

var (
	currentSession     TargetSession
	sessionMutex       sync.RWMutex
	lastStateSignature string
	globalSSHClient    *ssh.Client
	globalSSHMutex     sync.Mutex

	stickyNotifMutex sync.RWMutex
	stickyNotif      tunnel.NotificationItem
	stickyNotifValid bool
	acknowledgedSig  string
)

// AcknowledgeNotification clears the persistent HUD banner AND remembers
// the exact message we just cleared to prevent re-sticking on the next poll.
func AcknowledgeNotification() {
	stickyNotifMutex.Lock()
	acknowledgedSig = fmt.Sprintf("%s|%s|%s", stickyNotif.SenderTag, stickyNotif.Message, stickyNotif.Type)
	stickyNotif = tunnel.NotificationItem{}
	stickyNotifValid = false
	stickyNotifMutex.Unlock()
	lastStateSignature = ""
}

func enterAlternateScreenBuffer() {
	fmt.Print("\033[?1049h\033[H")
}

func exitAlternateScreenBuffer() {
	if runtime.GOOS != "windows" {
		_ = exec.Command("stty", "-F", "/dev/tty", "sane").Run()
	}
	fmt.Print("\033[?1049l")
}

func clearScreen() {
	fmt.Print("\033[H\033[2J\033[3J")
}

func appendProfileLog(message string) {
	f, err := os.OpenFile(
		"/tmp/cross-suite-localinfo-profile.log",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = fmt.Fprintf(
		f,
		"%s %s\n",
		time.Now().Format(time.RFC3339Nano),
		message,
	)
}

func getMasterMeshKeyMain() []byte {
	h := sha256.Sum256([]byte("CrossSSH-Universal-Mesh-Zero-Trust-Key-Seed-v2"))
	return h[:]
}

func decryptNotificationPayload(encodedStr string) ([]byte, error) {
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

	key := getMasterMeshKeyMain()
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

func parseNotificationLine(rawLine string) (tunnel.NotificationItem, bool) {
	trimmed := strings.TrimSpace(rawLine)
	if trimmed == "" {
		return tunnel.NotificationItem{}, false
	}

	payloadBytes := []byte(trimmed)
	if strings.HasPrefix(trimmed, "ENC:") {
		dec, err := decryptNotificationPayload(strings.TrimPrefix(trimmed, "ENC:"))
		if err == nil {
			payloadBytes = dec
		}
	}

	var item tunnel.NotificationItem
	if err := json.Unmarshal(payloadBytes, &item); err == nil && item.Message != "" {
		return item, true
	}
	return tunnel.NotificationItem{}, false
}

func getVisualWidth(s string) int {
	w := 0
	inEsc := false
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			inEsc = true
			i++
			continue
		}
		if inEsc {
			if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || s[i] == 'm' {
				inEsc = false
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		w++
	}
	return w
}

func truncatePlain(s string, maxWidth int) string {
	if getVisualWidth(s) <= maxWidth {
		return s
	}
	res := ""
	for _, r := range s {
		if getVisualWidth(res+string(r)+"...") > maxWidth {
			break
		}
		res += string(r)
	}
	return res + "..."
}

func getLatestNotificationMessage(activeHost string) (string, string, string) {
	candidates := []string{
		filepath.Join(tunnel.GetUniversalBaseDir(), "notifications.json"),
		"/tmp/cross_notifications.json",
		filepath.Join(os.TempDir(), "cross_notifications.json"),
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		candidates = append(candidates, filepath.Join("/home", sudoUser, ".cross-ssh", "notifications.json"))
	}

	localIdentity := tunnel.GetLocalNodeIdentity()

	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			if l == "" {
				continue
			}

			item, ok := parseNotificationLine(l)
			if ok && !item.IsRead {
				sender := item.SenderTag
				if sender == "" {
					sender = item.SenderIP
				}

				if sender == localIdentity || item.SenderIP == localIdentity || sender == "YOU" {
					continue
				}

				return sender, item.Message, item.Type
			}
		}
	}

	return "", "", ""
}

func renderDynamicEnterpriseHUD(targetDisplay, port, user string, targetOS osdetect.TargetOS, isAdmin, isActive bool, activeTunnelsCount int, isVoIPActive bool, voipPeer string) {
	innerBoxWidth := 67

	activePlainText := ""
	activeColoredText := ""
	if isActive && targetDisplay != "" {
		role := "User"
		if isAdmin {
			role = "Admin"
		}
		osLabel := string(targetOS)
		if osLabel == "" {
			osLabel = "linux"
		}
		activePlainText = fmt.Sprintf(" ACTIVE: %s@%s:%s [%s|%s]", user, targetDisplay, port, osLabel, role)
		activeColoredText = fmt.Sprintf(" %sACTIVE:%s %s%s@%s:%s%s [%s%s%s|%s%s%s]",
			Bold+Green, Reset,
			Bold+Cyan, user, targetDisplay, port, Reset,
			Yellow, osLabel, Reset,
			Magenta, role, Reset,
		)
	} else {
		activePlainText = " ACTIVE: NO TARGET LOCKED (Select option [1] to connect)"
		activeColoredText = fmt.Sprintf(" %sACTIVE:%s %sNO TARGET LOCKED (Select option [1] to connect)%s", Bold+Red, Reset, Dim+Yellow, Reset)
	}

	pad1 := innerBoxWidth - getVisualWidth(activePlainText)
	if pad1 < 0 {
		pad1 = 0
	}

	stickyNotifMutex.RLock()
	rawMsgSender, rawMsgContent, rawMsgType := stickyNotif.SenderTag, stickyNotif.Message, stickyNotif.Type
	if rawMsgSender == "" {
		rawMsgSender = stickyNotif.SenderIP
	}
	notifValid := stickyNotifValid
	stickyNotifMutex.RUnlock()

	if !notifValid {
		rawMsgContent = ""
	}

	statusPlainBase := fmt.Sprintf(" TUNNELS: %d", activeTunnelsCount)
	statusColoredBase := fmt.Sprintf(" %sTUNNELS:%s %s%d%s", Bold+Cyan, Reset, Bold+Green, activeTunnelsCount, Reset)

	if isVoIPActive {
		statusPlainBase += fmt.Sprintf(" | [CALL: %s]", voipPeer)
		statusColoredBase += fmt.Sprintf(" %s|%s %s[CALL: %s]%s", Blue, Reset, Bold+Magenta, voipPeer, Reset)
	}

	statusPlain := statusPlainBase
	statusColored := statusColoredBase

	if rawMsgContent != "" {
		colorPrefix := Bold + Yellow
		tagLabel := "[MSG ALERT"
		if rawMsgType == "CALL" {
			tagLabel = "[CALL ALERT"
			colorPrefix = Bold + Red
		} else if rawMsgType == "VOICE_MEMO" {
			tagLabel = "[VOICE ALERT"
			colorPrefix = Bold + Magenta
		}

		notifPrefixPlain := fmt.Sprintf(" | %s from %s]: ", tagLabel, rawMsgSender)
		availWidth := innerBoxWidth - getVisualWidth(statusPlainBase) - getVisualWidth(notifPrefixPlain)
		if availWidth > 5 {
			truncatedMsg := truncatePlain(rawMsgContent, availWidth)
			statusPlain += notifPrefixPlain + truncatedMsg
			statusColored += fmt.Sprintf(" %s|%s %s%s from %s]:%s %s%s%s",
				Blue, Reset,
				colorPrefix, tagLabel, rawMsgSender, Reset,
				Bold+Green, truncatedMsg, Reset,
			)
		}
	}

	pad2 := innerBoxWidth - getVisualWidth(statusPlain)
	if pad2 < 0 {
		pad2 = 0
	}

	fmt.Println(Blue + "┌" + strings.Repeat("─", innerBoxWidth) + "┐" + Reset)
	fmt.Printf("%s│%s%s%s%s│%s\n", Blue, Reset, activeColoredText, strings.Repeat(" ", pad1), Blue, Reset)
	fmt.Println(Blue + "├" + strings.Repeat("─", innerBoxWidth) + "┤" + Reset)
	fmt.Printf("%s│%s%s%s%s│%s\n", Blue, Reset, statusColored, strings.Repeat(" ", pad2), Blue, Reset)
	fmt.Println(Blue + "└" + strings.Repeat("─", innerBoxWidth) + "┘" + Reset)
}

func getOrEstablishGlobalSSH() *ssh.Client {
	globalSSHMutex.Lock()
	defer globalSSHMutex.Unlock()

	sessionMutex.RLock()
	activeHost := currentSession.Host
	port := currentSession.Port
	user := currentSession.User
	pass := currentSession.Pass
	keyPath := currentSession.KeyPath
	isActive := currentSession.IsActive
	sessionMutex.RUnlock()

	if !isActive || activeHost == "" {
		if globalSSHClient != nil {
			_ = globalSSHClient.Close()
			globalSSHClient = nil
		}
		return nil
	}

	if globalSSHClient != nil {
		testSess, err := globalSSHClient.NewSession()
		if err == nil {
			_ = testSess.Close()
			return globalSSHClient
		}
		_ = globalSSHClient.Close()
		globalSSHClient = nil
	}

	client, err := dialSSH(activeHost, port, user, pass, keyPath)
	if err == nil {
		globalSSHClient = client
		return globalSSHClient
	}
	return nil
}

func syncInboundNotifications() bool {
	sessionMutex.RLock()
	activeHost := currentSession.Host
	sessionMutex.RUnlock()

	if activeHost != "" {
		tunnel.SyncAllLocalChatInboxes(activeHost)
	}

	rawSender, rawMsg, rawType := getLatestNotificationMessage(activeHost)

	// Keep the sticky banner steady once rendered.
	// Only update on fresh incoming signals or clear when explicitly acknowledged.
	stickyNotifMutex.Lock()
	rawSig := fmt.Sprintf("%s|%s|%s", rawSender, rawMsg, rawType)
	if rawMsg != "" && rawSig != acknowledgedSig {
		stickyNotif = tunnel.NotificationItem{SenderTag: rawSender, SenderIP: rawSender, Message: rawMsg, Type: rawType}
		stickyNotifValid = true
	}
	sender, msg, typ := stickyNotif.SenderTag, stickyNotif.Message, stickyNotif.Type
	valid := stickyNotifValid
	stickyNotifMutex.Unlock()

	isVoIP, voipPeer := tunnel.GetVoIPCallState()
	activeTunnels := len(tunnel.GetActiveTunnels())
	currentSig := fmt.Sprintf("%s|%s|%s|%t|%t|%s|%d", sender, msg, typ, valid, isVoIP, voipPeer, activeTunnels)

	if currentSig != lastStateSignature {
		lastStateSignature = currentSig
		return true
	}

	return false
}
func printBanner() {
	banner := fmt.Sprintf(`
                                                #    #
                                            %%%%%% ##   ##
                                         %%%%%%%%%% ###%%%%%%###
                                        %%%%%%%%%% ### %%%%%% #
                                      %%%%%%%%%%%% ### %%%%%% ###
                                       %%%%%%%% ## %%%% #######
                                      %%%%%%%%%% # %%%% #O#####
                                    %%%%%%%%%%%% # %% #########
                                   %%%%%%%%%% ##### #########
                         ###        %%%% ####### #########
                %%%%%% ############    ########### ########
             %%%%%%%% ############################### #######
           %%%%%%%%%% ################################## ######
         %%%%%%%%%%%% #################################### #C###
        %%%%%%%%%%%% #####################################  ###
        %%%%%%%%%% #######################################
       %%%%%%%%%%%% ########################################
    %% %%%%%%%%%%%%%% ########################################
     %%%%%%%%%%%%%%%%%% #######################################
    %%%%%%%%%%%%%%%%%%%% ########################################
 %%%%%% %%%%%%%%%%%%%%%%   ###### ################################
   %%%%%%%%%%%%%%%%      ###### #################### ##########
%% %%%%%%%%%%%%%%%%        ####### ########### ###### ##########
 %%%%%%%%%%%%%%%%%%         #######  ########### ###### ########
%%%%%%%%%%%%%%%%%%%%          ##### ###  ######### ####### ######
 %%%%%%%%%%%%%%%%%%%%          #### ##               ####### ####
 %%%%%%%%%%%%%%%%%%%%%%           ## #                  ##### ###
  %%%%  %%%% %% %%%%         # ##                      ## ###
    %%   %%    %%        # ###                      # ###
                       # ###                     ## ###
                       # ###                     ## ###
                       # ####                   #### ##
                      ### ###                  ##### ###
                     ####  ###                 ####   ##
                    #####   ###                 ##    ##
                   #####    ####                      ###
                    ##        ###                     ###
                               ####                     ##
                                ####                    ###
                                                        ####
                                                         ##
=====================================================================

 ██████╗██████╗  ██████╗ ███████╗███████╗    ███████╗███████╗██╗  ██╗
██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██║  ██║
██║     ██████╔╝██║   ██║███████╗███████╗    ███████╗███████╗███████║
██║     ██╔══██╗██║   ██║╚════██║╚════██║    ╚════██║╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝███████║███████║    ███████║███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝

        CROSS-DISTRO MULTI-ENGINE DEVSECOPS PLATFORM [%s]

=====================================================================`, AppVersion)

	fmt.Println(Cyan + Bold + banner + Reset)
	fmt.Printf(Yellow + "  GitHub  : " + Bold + "https://github.com/ali4210" + Reset + "\n")
	displaySessionStatus()
}

func printSubBanner() {
	banner := fmt.Sprintf(`
=====================================================================
 
 ██████╗██████╗  ██████╗ ███████╗███████╗    ███████╗███████╗██╗  ██╗
██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██║  ██║
██║     ██████╔╝██║   ██║███████╗███████╗    ███████╗███████╗███████║
██║     ██╔══██╗██║   ██║╚════██║╚════██║    ╚════██║╚════██║██╔══██║
╚██████╗██║  ██║╚██████╔╝███████║███████║    ███████║███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝
           
 	ENTERPRISE MULTI-ENGINE DEVSECOPS PLATFORM [%s]

=====================================================================`, AppVersion)

	fmt.Println(Cyan + Bold + banner + Reset)
	fmt.Printf(Yellow + "  GitHub  : " + Bold + "https://github.com/ali4210" + Reset + "\n")
	displaySessionStatus()
}

func displaySessionStatus() {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()

	alias := vault.ResolveAliasForIP(currentSession.Host)
	targetDisplay := currentSession.Host
	if alias != "" {
		targetDisplay = fmt.Sprintf("%s (%s)", alias, currentSession.Host)
	}

	activeTunnelsCount := len(tunnel.GetActiveTunnels())
	isVoIPActive, voipPeer := tunnel.GetVoIPCallState()
	renderDynamicEnterpriseHUD(targetDisplay, currentSession.Port, currentSession.User, currentSession.TargetOS, currentSession.IsAdmin, currentSession.IsActive, activeTunnelsCount, isVoIPActive, voipPeer)
}

func pause(reader *bufio.Reader) {
	fmt.Print(Yellow + "\nPress Enter to continue..." + Reset)
	_, _ = reader.ReadString('\n')
}

func initWindowsConsole() {
	if runtime.GOOS == "windows" {
		_ = exec.Command("chcp", "65001").Run()
	}
}

func initVPNTargetCallback() {
	vpn.SetUpdateTargetCallback(func(host, port, user, pass, keyPath string, targetOS osdetect.TargetOS, isAdmin bool) {
		sessionMutex.Lock()
		currentSession = TargetSession{
			Host:     host,
			Port:     port,
			User:     user,
			Pass:     pass,
			KeyPath:  keyPath,
			TargetOS: targetOS,
			IsAdmin:  isAdmin,
			IsActive: true,
		}
		sessionMutex.Unlock()
		savePersistentSession()

		globalSSHMutex.Lock()
		if globalSSHClient != nil {
			_ = globalSSHClient.Close()
			globalSSHClient = nil
		}
		globalSSHMutex.Unlock()

		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
			userHome := filepath.Join("/home", sudoUser)
			_ = os.MkdirAll(filepath.Join(userHome, ".cross-ssh"), 0700)
			file := filepath.Join(userHome, ".cross-ssh", "active_target.json")
			sessionMutex.RLock()
			data, _ := json.Marshal(currentSession)
			sessionMutex.RUnlock()
			_ = os.WriteFile(file, data, 0600)
			_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), filepath.Join(userHome, ".cross-ssh")).Run()
		}
	})
}

func main() {
	initWindowsConsole()
	enableConsoleVT() // <-- enable ANSI support on Windows; no-op elsewhere

	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		cmd := exec.Command("sudo", append([]string{"-E", os.Args[0]}, os.Args[1:]...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf(Red+"[!] Elevation failed: %v\n"+Reset, err)
		}
		os.Exit(0)
	}

	fmt.Println(Cyan + Bold + "[+] Launching Cross-Suite Wizard workspace..." + Reset)
	time.Sleep(100 * time.Millisecond)

	enterAlternateScreenBuffer()
	defer exitAlternateScreenBuffer()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		exitAlternateScreenBuffer()
		fmt.Println(Green + Bold + "[=>] Cross-Suite Wizard closed cleanly. Goodbye!" + Reset)
		os.Exit(0)
	}()

	initVPNTargetCallback()
	loadPersistentSession()

	runInteractiveMenu()

	exitAlternateScreenBuffer()
	fmt.Println(Green + Bold + "[=>] Cross-Suite Wizard closed cleanly. Goodbye!" + Reset)
}

func loadPersistentSession() {
	file := filepath.Join(tunnel.GetUniversalBaseDir(), "active_target.json")
	data, err := os.ReadFile(file)
	if err == nil {
		var loaded TargetSession
		if err := json.Unmarshal(data, &loaded); err == nil && loaded.Host != "" {
			sessionMutex.Lock()
			currentSession = loaded
			currentSession.IsActive = true
			sessionMutex.Unlock()
		}
	}
}

func savePersistentSession() {
	file := filepath.Join(tunnel.GetUniversalBaseDir(), "active_target.json")
	sessionMutex.RLock()
	data, _ := json.Marshal(currentSession)
	sessionMutex.RUnlock()
	_ = os.WriteFile(file, data, 0666)
}

func clearPersistentSession() {
	file := filepath.Join(tunnel.GetUniversalBaseDir(), "active_target.json")
	_ = os.Remove(file)
}

func renderMainMenuOptions(currentInput string) {
	fmt.Println(Bold + "=> SELECT OPERATIONAL DOMAIN HUB:" + Reset)
	fmt.Println(Cyan + "  [1]" + Reset + " Target Session Management & Vault (Connect, Switch Host, Vault)")
	fmt.Println(Cyan + "  [2]" + Reset + " File Operations & Live Remote Drive Mount (Upload, Download, SSHFS)")
	fmt.Println(Cyan + "  [3]" + Reset + " Interactive Terminal & Smart Web/GUI Tunneling (TTY, SOCKS5, X11, Docker)")
	fmt.Println(Cyan + "  [4]" + Reset + " Remote Service, Port, Log, Firewall & Tool Manager")
	fmt.Println(Green + "  [5]" + Reset + " Universal Package Engine & System Self-Healer (GOLD STANDARD HUB)")
	fmt.Println(Cyan + "  [6]" + Reset + " Sovereign DevSecOps, Threat Hunter, Red Team & Compliance Hub")
	fmt.Println(Green + Bold + "  [7]" + Reset + " Access Control Assigner (Zero-Trust Identity & RBAC Enforcer)")
	fmt.Println(Cyan + "  [8]" + Reset + " Local Workstation & SSH Server Tools (Local Info, Enabler, Global CLI)")
	fmt.Println(Cyan + "  [9]" + Reset + " Network Diagnostics & Troubleshooting (Port Probe, Health Check, Pre-Flight)")
	fmt.Println(Green + Bold + " [10]" + Reset + " Peer-to-Peer Encrypted WireGuard VPN Engine (Token Pairing & Mesh)")
	fmt.Println(Cyan + Bold + " [11]" + Reset + " P2P TeamViewer-Style Remote Assistance & Session Pairing")
	fmt.Println(Green + Bold + " [12]" + Reset + " P2P Mesh Intercom, Live VoIP, Voice Memo Studio & Messenger Matrix")
	fmt.Println(Cyan + Bold + " [13]" + Reset + " P2P Task & Work Approval Ticket Tracker (Jira-Style Ledger)")
	fmt.Println(Red + "  [0]" + Reset + " Exit Platform")
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Printf("Enter choice [0-13]: %s", currentInput)
}

func renderFullMainMenuCanvas(inputBuffer string) {
	fmt.Print("\033[H\033[2J")
	printBanner()
	renderMainMenuOptions(inputBuffer)
}

func runInteractiveMenu() {
	reader := bufio.NewReader(os.Stdin)

	ctxRemote, cancelRemote := context.WithCancel(context.Background())
	defer cancelRemote()

	go func(ctx context.Context) {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessionMutex.RLock()
				activeHost := currentSession.Host
				sessionMutex.RUnlock()

				if activeHost != "" {
					if client := getOrEstablishGlobalSSH(); client != nil {
						tunnel.SyncRemoteNotificationsAndChatSilent(client, activeHost)
						tunnel.SyncAllLocalChatInboxes(activeHost)
					}
				}
			}
		}
	}(ctxRemote)

	for {
		clearScreen()
		syncInboundNotifications()

		if runtime.GOOS != "windows" {
			_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
		}

		ctx, cancel := context.WithCancel(context.Background())
		var mu sync.Mutex
		var wg sync.WaitGroup
		inputBuffer := ""

		renderFullMainMenuCanvas(inputBuffer)

		wg.Add(1)
		go func(ctx context.Context) {
			defer wg.Done()
			ticker := time.NewTicker(300 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if syncInboundNotifications() {
						mu.Lock()
						renderFullMainMenuCanvas(inputBuffer)
						mu.Unlock()
					}
				}
			}
		}(ctx)

		var choice string
		keyBuf := make([]byte, 8)

		for {
			n, _ := os.Stdin.Read(keyBuf)
			if n > 0 {
				mu.Lock()
				if n == 1 {
					b := keyBuf[0]
					switch b {
					case 10, 13:
						choice = strings.TrimSpace(inputBuffer)
						mu.Unlock()
						cancel()
						wg.Wait()
						goto ExecuteChoice
					case 127, 8:
						if len(inputBuffer) > 0 {
							inputBuffer = inputBuffer[:len(inputBuffer)-1]
							renderFullMainMenuCanvas(inputBuffer)
						}
					default:
						if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
							inputBuffer += string(b)
							renderFullMainMenuCanvas(inputBuffer)
						}
					}
				}
				mu.Unlock()
			}
			time.Sleep(10 * time.Millisecond)
		}

	ExecuteChoice:
		if runtime.GOOS != "windows" {
			_ = exec.Command("stty", "-F", "/dev/tty", "sane").Run()
		}

		switch choice {
		case "1":
			hubTargetSessionManagement(reader)
		case "2":
			hubFileOperations(reader)
		case "3":
			hubInteractiveTerminalAndTunneling(reader)
		case "4":
			serviceManagerSubMenu(reader)
		case "5":
			hubUniversalPackageEngineAndHealer(reader)
		case "6":
			hubDevSecOpsAndSecurityOperations(reader)
		case "7":
			hubAccessControlAssigner(reader)
		case "8":
			option8Started := time.Now()
			hubLocalWorkstationTools(reader)
			appendProfileLog(
				fmt.Sprintf(
					"[OPTION8-PROFILE] Local Workstation hub returned after %s",
					time.Since(option8Started),
				),
			)
		case "9":
			hubNetworkDiagnosticsAndTroubleshooting(reader)
		case "10", "vpn", "VPN":
			hubVPNEngine(reader)
		case "11":
			p2p.ShowP2PMenu(reader)
		case "12":
			hubStandaloneP2PCommunications(reader)
		case "13":
			var client *ssh.Client
			sessionMutex.RLock()
			if currentSession.IsActive && currentSession.Host != "" {
				c, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
				if err == nil {
					client = c
					defer client.Close()
				}
			}
			currentUser := currentSession.User
			host := currentSession.Host
			sessionMutex.RUnlock()

			if currentUser == "" {
				currentUser = tunnel.GetLocalNodeIdentity()
			}
			ticket.ShowTicketMenu(reader, client, currentUser, host)
		case "0", "q", "Q":
			return
		}
	}
}

func hubStandaloneP2PCommunications(reader *bufio.Reader) {
	sessionMutex.RLock()
	currentUser := currentSession.User
	host := currentSession.Host
	port := currentSession.Port
	pass := currentSession.Pass
	keyPath := currentSession.KeyPath
	isActive := currentSession.IsActive
	sessionMutex.RUnlock()

	if currentUser == "" {
		currentUser = tunnel.GetLocalNodeIdentity()
	}

	var client *ssh.Client
	if isActive && host != "" {
		c, err := dialSSH(host, port, currentUser, pass, keyPath)
		if err == nil {
			client = c
			defer client.Close()
		}
	}

	tunnel.ShowP2PCommunicationsMatrix(reader, client, host, currentUser)
	AcknowledgeNotification()
	clearScreen()
	syncInboundNotifications()
}

func hubTargetSessionManagement(reader *bufio.Reader) {
	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 1: TARGET SESSION MANAGEMENT & VAULT ===" + Reset)
		fmt.Println("  [1] Enter New Target IP / Credentials Manually (Password or .PEM Key)")
		fmt.Println(Cyan + Bold + "  [2] Auto-Scan Local Subnet (Interactive Host Discovery & Vault Registration)" + Reset)
		fmt.Println("  [3] Select Saved Host Profile from Vault [ENGINE 5]")
		fmt.Println(Cyan + Bold + "  [4] Connect to Remote Teammate via Global P2P Relay (TeamViewer Mode)" + Reset)
		fmt.Println("  [5] Bootstrap Passwordless SSH Entry (with Alias Support)")
		fmt.Println(Green + "  [6] Instantly Refresh Terminal Shell Config (Source ~/.zshrc / ~/.bashrc)" + Reset)
		fmt.Println(Green + Bold + "  [7] Payload Tool Engine (Digispark / ATtiny85 Hardware Provisioner)" + Reset)
		fmt.Println(Cyan + Bold + "  [8] Create, Repair & Enable SSH Engine on Current Host (1-Click Pipeline)" + Reset)
		fmt.Println(Yellow + "  [9] Disconnect / Switch Active Target Host" + Reset)
		fmt.Println(Red + " [10] Factory Reset Vault & Purge All Credentials" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-10]: ")

		switch choice {
		case "1":
			connectManualPrompt(reader)
		case "2":
			host, port, user, pass, alias := vault.ScanSubnetAndSelectTarget(reader)
			if host == "" {
				pause(reader)
				continue
			}

			fmt.Printf(Yellow+"\nConnecting to discovered host '%s' (%s@%s:%s)...\n"+Reset, alias, user, host, port)
			client, err := dialSSH(host, port, user, pass, "")
			if err != nil {
				fmt.Printf(Red+"[!] Connection failed: %v\n"+Reset, err)
				pause(reader)
				continue
			}
			defer client.Close()

			targetOS, isAdmin, err := osdetect.DetectOS(client)
			if err != nil {
				targetOS = osdetect.OSLinux
				isAdmin = false
			}

			sessionMutex.Lock()
			currentSession = TargetSession{
				Host:     host,
				Port:     port,
				User:     user,
				Pass:     pass,
				TargetOS: targetOS,
				IsAdmin:  isAdmin,
				IsActive: true,
			}
			sessionMutex.Unlock()

			savePersistentSession()
			_ = vault.SaveActiveSessionToVault(alias, host, port, user, pass, "", targetOS, isAdmin)
			fmt.Println(Green + Bold + "\n[SUCCESS] Active Target Session Established & Saved to Vault!" + Reset)
			pause(reader)

		case "3":
			vault.ShowVaultMenu(reader, func(p vault.HostProfile) {
				fmt.Printf(Yellow+"\nConnecting to saved profile '%s' (%s@%s:%s)...\n"+Reset, p.Alias, p.User, p.Host, p.Port)
				client, err := dialSSH(p.Host, p.Port, p.User, p.Pass, p.KeyPath)
				if err != nil {
					fmt.Printf(Red+"[!] Connection failed: %v\n"+Reset, err)
					pause(reader)
					return
				}
				defer client.Close()

				targetOS, isAdmin, err := osdetect.DetectOS(client)
				if err != nil {
					targetOS = osdetect.OSLinux
					isAdmin = false
				}

				sessionMutex.Lock()
				currentSession = TargetSession{
					Host:     p.Host,
					Port:     p.Port,
					User:     p.User,
					Pass:     p.Pass,
					KeyPath:  p.KeyPath,
					TargetOS: targetOS,
					IsAdmin:  isAdmin,
					IsActive: true,
				}
				sessionMutex.Unlock()

				savePersistentSession()
				_ = vault.SaveActiveSessionToVault(p.Alias, p.Host, p.Port, p.User, p.Pass, p.KeyPath, targetOS, isAdmin)
				fmt.Println(Green + Bold + "\n[SUCCESS] Active Target Session Established & Saved!" + Reset)
				pause(reader)
			})
		case "4":
			host, port, user, pass, ok := p2p.ConnectAndGetSession(reader)
			if !ok {
				pause(reader)
				continue
			}

			client, err := dialSSH(host, port, user, pass, "")
			var targetOS osdetect.TargetOS = osdetect.OSLinux
			var isAdmin bool = true

			if err == nil {
				detectedOS, adminStatus, errOS := osdetect.DetectOS(client)
				client.Close()
				if errOS == nil {
					targetOS = detectedOS
					isAdmin = adminStatus
				}
			}

			sessionMutex.Lock()
			currentSession = TargetSession{
				Host:     host,
				Port:     port,
				User:     user,
				Pass:     pass,
				TargetOS: targetOS,
				IsAdmin:  isAdmin,
				IsActive: true,
			}
			sessionMutex.Unlock()

			savePersistentSession()
			fmt.Println(Green + Bold + "\n[SUCCESS] Active Target Session Locked to P2P Relay!" + Reset)
			pause(reader)
		case "5":
			bootstrapSubMenu(reader)
		case "6":
			reloadLocalShellConfig(reader)
		case "7":
			payload.ShowPayloadEngineMenu(reader, func(ip, port, user string) {
				defaultAlias := fmt.Sprintf("ds-node-%s", strings.ReplaceAll(ip, ".", "-"))
				customAlias := transfer.ReadRealtimeInput(fmt.Sprintf("Enter Profile Alias [default: %s]: ", defaultAlias))
				if strings.TrimSpace(customAlias) == "" {
					customAlias = defaultAlias
				}

				sshUser := transfer.ReadRealtimeInput("Enter Target OS Username [default: root]: ")
				if strings.TrimSpace(sshUser) == "" {
					sshUser = "root"
				}

				home, _ := os.UserHomeDir()
				defaultKeyPath := filepath.Join(home, ".ssh", "id_ed25519")
				if _, err := os.Stat(defaultKeyPath); os.IsNotExist(err) {
					defaultKeyPath = filepath.Join(home, ".ssh", "id_rsa")
				}

				client, err := dialSSH(ip, port, sshUser, "", defaultKeyPath)
				sshPass := ""
				if err != nil {
					sshPass = transfer.ReadRealtimeInput("Enter SSH Password fallback: ")
					client, err = dialSSH(ip, port, sshUser, sshPass, "")
					if err != nil {
						fmt.Printf(Red+Bold+"\n[!] Authentication Failed: %v\n"+Reset, err)
						return
					}
				}

				targetOS, isAdmin, _ := osdetect.DetectOS(client)
				client.Close()

				sessionMutex.Lock()
				currentSession = TargetSession{
					Host:     ip,
					Port:     port,
					User:     sshUser,
					Pass:     sshPass,
					KeyPath:  defaultKeyPath,
					TargetOS: targetOS,
					IsAdmin:  isAdmin,
					IsActive: true,
				}
				sessionMutex.Unlock()

				savePersistentSession()
				_ = vault.SaveActiveSessionToVault(customAlias, ip, port, sshUser, sshPass, defaultKeyPath, targetOS, isAdmin)
				fmt.Println(Green + Bold + "\n[SUCCESS] Node Locked as Active Target." + Reset)
			})
			pause(reader)
		case "8":
			vault.RunLocalSSHPipeline(reader)
			pause(reader)
		case "9":
			sessionMutex.Lock()
			currentSession = TargetSession{}
			sessionMutex.Unlock()
			clearPersistentSession()
			fmt.Println(Green + Bold + "\n[=>] Active target host cleared!" + Reset)
			pause(reader)
		case "10":
			vault.FactoryResetVault()
			sessionMutex.Lock()
			currentSession = TargetSession{}
			sessionMutex.Unlock()
			clearPersistentSession()
			pause(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func reloadLocalShellConfig(reader *bufio.Reader) {
	fmt.Println(Cyan + "\n=== INSTANT LOCAL SHELL CONFIG RELOADER ===" + Reset)
	home, _ := os.UserHomeDir()

	if runtime.GOOS == "windows" {
		_ = exec.Command("powershell", "-Command", "ipconfig /flushdns").Run()
		fmt.Println(Green + Bold + "[SUCCESS] Windows environment refreshed!" + Reset)
	} else {
		zshrc := filepath.Join(home, ".zshrc")
		bashrc := filepath.Join(home, ".bashrc")
		if _, err := os.Stat(zshrc); err == nil {
			_ = exec.Command("zsh", "-c", "source ~/.zshrc").Run()
		}
		if _, err := os.Stat(bashrc); err == nil {
			_ = exec.Command("bash", "-c", "source ~/.bashrc").Run()
		}
		fmt.Println(Green + Bold + "[SUCCESS] Shell configuration reloaded cleanly!" + Reset)
	}
	pause(reader)
}

func hubFileOperations(reader *bufio.Reader) {
	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 2: FILE OPERATIONS & REMOTE STORAGE VIRTUALIZATION ===" + Reset)
		fmt.Println("  [1] Upload File or Directory to Target Host (Parallel Chunk Engine)")
		fmt.Println("  [2] Download File or Directory from Target Host (Parallel Chunk Engine)")
		fmt.Println(Green + Bold + "  [3] Remote Storage Virtualization (Mount Remote Filesystem via SSHFS)" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-3]: ")

		switch choice {
		case "1":
			uploadSubMenu(reader)
		case "2":
			downloadSubMenu(reader)
		case "3":
			if !ensureSessionActive(reader) {
				return
			}
			sessionMutex.RLock()
			host := currentSession.Host
			port := currentSession.Port
			user := currentSession.User
			pass := currentSession.Pass
			keyPath := currentSession.KeyPath
			sessionMutex.RUnlock()
			transfer.ShowMountMenu(reader, host, port, user, pass, keyPath)
		case "0", "q", "Q":
			clearScreen()
			return
		}
	}
}

func hubInteractiveTerminalAndTunneling(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	host := currentSession.Host
	user := currentSession.User
	pass := currentSession.Pass
	keyPath := currentSession.KeyPath
	targetOS := currentSession.TargetOS
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 3: INTERACTIVE TERMINAL & SMART TUNNELING HUB ===" + Reset)
		fmt.Println("  [1] Open Embedded Interactive Remote Shell (TTY)")
		fmt.Println(Cyan + Bold + "  [2] Smart Web Forwarding, SOCKS5 Browser, GUI X11 & Docker Context [ENGINE 1]" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-2]: ")

		switch choice {
		case "1":
			_ = shell.StartInteractiveTTY(client, targetOS)
		case "2":
			tunnel.ShowTunnelMenu(reader, client, targetOS, host, user, pass, keyPath)
		case "0", "q", "Q":
			clearScreen()
			return
		}
	}
}

func hubUniversalPackageEngineAndHealer(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	playbook.ShowUniversalHealerMenu(reader, client, targetOS)
	clearScreen()
}

func hubDevSecOpsAndSecurityOperations(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	host := currentSession.Host
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 6: DEVSECOPS, RED TEAMING & COMPLIANCE MATRIX ===" + Reset)
		fmt.Println("  [1] One-Click DevSecOps & SOC Presets Manager (GitLab, Jenkins, OpenSearch)")
		fmt.Println("  [2] Sovereign Compliance, OSINT & Vulnerability Engine (Options 1-11)")
		fmt.Println("  [3] Red Teaming & Metasploit Exploitation Engine (PrivEsc, Containers)")
		fmt.Println("  [4] Zero-Touch Kubernetes Cluster Provisioner (Minikube & KinD)")
		fmt.Println("  [5] 3-Tier Storage Reclamation Suite (Safe / Hard / Super Hard Clean)")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-5]: ")

		switch choice {
		case "1":
			playbook.ShowPresetMenu(reader, client, targetOS)
		case "2":
			security.ShowComplianceMenu(reader, client, string(targetOS), func() {
				playbook.ShowPresetMenu(reader, client, targetOS)
			})
		case "3":
			redteam.ShowRedTeamMenu(reader, client, host)
		case "4":
			playbook.ShowKubernetesMenu(reader, client)
		case "5":
			playbook.ShowStorageCleanerMenu(reader, client)
		case "0", "q", "Q":
			clearScreen()
			return
		}
	}
}

func hubAccessControlAssigner(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	host := currentSession.Host
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	rbac.ShowRBACMenu(reader, client, host)
	clearScreen()
}

func hubVPNEngine(reader *bufio.Reader) {
	vpn.ShowVPNMenu(reader)
	clearScreen()
	loadPersistentSession()
}

func hubLocalWorkstationTools(reader *bufio.Reader) {
	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 8: LOCAL WORKSTATION & SSH SERVER TOOLS ===" + Reset)
		fmt.Println("  [1] Show My Local Connection Info (My SSH ID & IP)")
		fmt.Println("  [2] Local SSH Server Auto-Provisioner, Service Control & Uninstaller")
		fmt.Println("  [3] Install Cross-SSH as Global System CLI Tool")
		fmt.Println("  [4] Instantly Refresh Terminal Shell Config (Source ~/.zshrc / ~/.bashrc)")
		fmt.Println(Cyan + "  [5] Check GitHub for Platform Updates & Auto-Upgrade" + Reset)
		fmt.Println(Yellow + "  [6] Rollback to Previous Binary Version (~/cross-ssh.bak)" + Reset)
		fmt.Println(Green + Bold + "  [7] Tool Junk Cleaner (Remove old artifacts & free space)" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-7]: ")

		switch choice {
		case "1":
			clearScreen()
			printSubBanner()
			localinfo.DisplayLocalSSHInfo(reader)
			pause(reader)
		case "2":
			clearScreen()
			printSubBanner()
			localinfo.ShowLocalSSHProvisionerMenu(reader)
		case "3":
			installGlobalCLISubMenu(reader)
		case "4":
			reloadLocalShellConfig(reader)
		case "5":
			checkForGitHubUpdates(reader)
		case "6":
			rollbackToPreviousVersion(reader)
		case "7":
			clearScreen()
			printSubBanner()
			cleaner.CleanToolJunk()
			pause(reader)
		case "0", "q", "Q":
			clearScreen()
			return
		}
	}
}

func checkForGitHubUpdates(reader *bufio.Reader) {
	fmt.Println(Cyan + "\n=== CHECKING GITHUB FOR PLATFORM UPDATES ===" + Reset)
	fmt.Printf(Yellow+"Current Installed Version: %s\n"+Reset, AppVersion)
	fmt.Println("[+] Querying GitHub API for latest release...")

	apiUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", GitHubRepoUser, GitHubRepoName)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		fmt.Printf(Red+"[!] Failed creating update request: %v\n"+Reset, err)
		pause(reader)
		return
	}
	req.Header.Set("User-Agent", "Cross-SSH-Updater")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		fmt.Printf(Red + "[!] Unable to reach GitHub releases API. Re-syncing codebase via Git...\n" + Reset)
		syncViaGitPull(reader)
		return
	}
	defer resp.Body.Close()

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		syncViaGitPull(reader)
		return
	}

	if release.TagName == AppVersion || release.TagName == "" {
		fmt.Println(Green + Bold + "\n[=>] You are running the latest release! Codebase is fully up to date." + Reset)
		pause(reader)
		return
	}

	fmt.Printf(Green+Bold+"\n[NEW UPDATE AVAILABLE]: %s (Current: %s)\n"+Reset, release.TagName, AppVersion)
	confirm := transfer.ReadRealtimeInput("\nWould you like to upgrade now? [Y/n]: ")
	if strings.ToLower(confirm) != "y" && confirm != "" {
		return
	}

	syncViaGitPull(reader)
}

func syncViaGitPull(reader *bufio.Reader) {
	fmt.Println(Yellow + "[+] Re-syncing codebase with GitHub repository..." + Reset)
	cmd := exec.Command("git", "pull", "origin", "main")
	cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Printf(Red+"[!] Git pull sync encountered an issue: %v\n"+Reset, err)
		pause(reader)
		return
	}

	execPath, _ := os.Executable()
	makeCmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", execPath, "main.go")
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		makeCmd = exec.Command("sudo", "-u", sudoUser, "-E", "go", "build", "-ldflags=-s -w", "-o", execPath, "main.go")
	}
	if err := makeCmd.Run(); err != nil {
		fmt.Printf(Red+"[!] Rebuild failed: %v\n"+Reset, err)
		pause(reader)
		return
	}

	fmt.Println(Green + Bold + "\n[SUCCESS] Codebase pulled and re-compiled successfully!" + Reset)
	pause(reader)
}

func rollbackToPreviousVersion(reader *bufio.Reader) {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	backupPath := execPath + ".bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		fmt.Println(Red + "[!] No previous version backup (.bak) found to rollback to." + Reset)
		pause(reader)
		return
	}

	_ = os.Remove(execPath)
	_ = os.Rename(backupPath, execPath)
	_ = os.Chmod(execPath, 0755)
	fmt.Println(Green + Bold + "\n[SUCCESS] Successfully rolled back to previous version!" + Reset)
	pause(reader)
}

func hubNetworkDiagnosticsAndTroubleshooting(reader *bufio.Reader) {
	for {
		clearScreen()
		printSubBanner()
		fmt.Println(Bold + Magenta + "=== HUB 9: NETWORK DIAGNOSTICS & TROUBLESHOOTING ===" + Reset)
		fmt.Println("  [1] Diagnostic Port Probe (Telnet/TCP Banner Scan)")
		fmt.Println("  [2] Run System Health Check & Auto-Troubleshooter")
		fmt.Println(Cyan + "  [3] Run Autonomous Pre-Flight, Port Broker & Sysctl Diagnostics" + Reset)
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-3]: ")

		switch choice {
		case "1":
			probeSubMenu(reader)
		case "2":
			clearScreen()
			printSubBanner()
			sessionMutex.RLock()
			host := currentSession.Host
			port := currentSession.Port
			sessionMutex.RUnlock()
			troubleshoot.RunDiagnostics(reader, host, port)
			pause(reader)
		case "3":
			runPreFlightDiagnostics(reader)
		case "0", "q", "Q":
			clearScreen()
			return
		}
	}
}

func runPreFlightDiagnostics(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	sessionMutex.RUnlock()

	if err != nil {
		fmt.Printf(Red+"[!] Connection failed: %v\n"+Reset, err)
		pause(reader)
		return
	}
	defer client.Close()

	fmt.Println(Cyan + "\n================================================================================" + Reset)
	fmt.Println(Cyan + "   RUNNING AUTONOMOUS PRE-FLIGHT & PORT RESOLUTION DIAGNOSTICS" + Reset)
	fmt.Println(Cyan + "================================================================================" + Reset)

	resPort, shifted, err := security.ResolvePort(client, 8080)
	if err == nil {
		if shifted {
			fmt.Printf(Yellow+"  [!] Port 8080 occupied. Auto-shifted Jenkins mapping to: %d\n"+Reset, resPort)
		} else {
			fmt.Printf(Green + "  [=>] Port 8080 is FREE and ready for binding.\n" + Reset)
		}
	}

	patched, err := security.TuneKernelSettings(client)
	if err == nil && patched {
		fmt.Println(Green + "  [=>] Kernel vm.max_map_count successfully auto-patched to 262144." + Reset)
	}

	dindOk, err := security.FixDockerSocket(client)
	if err == nil && dindOk {
		fmt.Println(Green + "  [=>] Docker socket permissions set to 666 (DinD ready)." + Reset)
	}

	pause(reader)
}

func connectManualPrompt(reader *bufio.Reader) {
	profile, ok := vault.PromptNewTargetManual(reader)
	if !ok || profile.Host == "" {
		return
	}

	client, err := dialSSH(profile.Host, profile.Port, profile.User, profile.Pass, profile.KeyPath)
	if err != nil {
		fmt.Printf(Red+"[!] Connection failed: %v\n"+Reset, err)
		pause(reader)
		return
	}
	defer client.Close()

	targetOS, isAdmin, _ := osdetect.DetectOS(client)

	sessionMutex.Lock()
	currentSession = TargetSession{
		Host:     profile.Host,
		Port:     profile.Port,
		User:     profile.User,
		Pass:     profile.Pass,
		KeyPath:  profile.KeyPath,
		TargetOS: targetOS,
		IsAdmin:  isAdmin,
		IsActive: true,
	}
	sessionMutex.Unlock()

	savePersistentSession()
	fmt.Println(Green + Bold + "\n[=>] Target Session Established Successfully!" + Reset)
	pause(reader)
}

func bootstrapSubMenu(reader *bufio.Reader) {
	fmt.Println(Cyan + "\n=== BOOTSTRAP PASSWORDLESS SSH ENTRY ===" + Reset)
	if !ensureSessionActive(reader) {
		return
	}

	alias := transfer.ReadRealtimeInput("Set Host Alias (e.g., mypc, wind, prod-01) [Optional]: ")
	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	user := currentSession.User
	host := currentSession.Host
	port := currentSession.Port
	sessionMutex.RUnlock()

	if err != nil {
		fmt.Printf(Red+"[!] Connection failed: %v\n"+Reset, err)
		pause(reader)
		return
	}
	defer client.Close()

	home, _ := os.UserHomeDir()
	pubKeyPath := filepath.Join(home, ".ssh", "id_ed25519.pub")
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		pubKeyPath = filepath.Join(home, ".ssh", "id_rsa.pub")
	}

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Printf(Red+"[!] Public key not found at %s. Generate one with 'ssh-keygen'\n"+Reset, pubKeyPath)
		pause(reader)
		return
	}

	pubKeyStr := strings.TrimSpace(string(pubKeyBytes))
	sess, err := client.NewSession()
	if err == nil {
		if targetOS == osdetect.OSWindows {
			psScript := fmt.Sprintf(`
$key = '%s';
$uDir = 'C:\Users\%s\.ssh';
$uKey = "$uDir\authorized_keys";
$aKey = 'C:\ProgramData\ssh\administrators_authorized_keys';
$cfg = 'C:\ProgramData\ssh\sshd_config';

if (!(Test-Path $uDir)) { New-Item -ItemType Directory -Path $uDir -Force | Out-Null }
[System.IO.File]::WriteAllText($uKey, $key + [Environment]::NewLine, [System.Text.Encoding]::UTF8);
icacls $uKey /inheritance:r /grant '%s:F' /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null;

if (Test-Path 'C:\ProgramData\ssh') {
    [System.IO.File]::WriteAllText($aKey, $key + [Environment]::NewLine, [System.Text.Encoding]::UTF8);
    icacls $aKey /inheritance:r /grant 'Administrators:F' | Out-Null;
}

if (Test-Path $cfg) {
    (Get-Content $cfg) -replace 'Match Group administrators', '# Match Group administrators' -replace 'AuthorizedKeysFile __PROGRAMDATA__', '# AuthorizedKeysFile __PROGRAMDATA__' | Set-Content $cfg;
}
Restart-Service sshd;
`, pubKeyStr, user, user)

			utf16LE := []byte{}
			for _, r := range psScript {
				utf16LE = append(utf16LE, byte(r), byte(r>>8))
			}
			b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)
			_ = sess.Run(fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd))
		} else {
			_ = sess.Run(fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", pubKeyStr))
		}
		sess.Close()
	}

	fmt.Println(Green + Bold + "[SUCCESS] SSH Public Key Deployed Successfully!" + Reset)

	if alias != "" {
		cleanAlias := strings.TrimSpace(alias)
		sshConfigPath := filepath.Join(home, ".ssh", "config")
		sshConfigEntry := fmt.Sprintf("\nHost %s\n    HostName %s\n    User %s\n    Port %s\n    IdentityFile %s\n",
			cleanAlias, host, user, port, strings.TrimSuffix(pubKeyPath, ".pub"))

		_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
		f, err := os.OpenFile(sshConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.WriteString(sshConfigEntry)
			f.Close()
		}
		fmt.Printf(Cyan+"[Alias Registered Locally]: %s -> ssh %s@%s\n"+Reset, cleanAlias, user, host)
	}

	pause(reader)
}

func uploadSubMenu(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	localPath, err := transfer.SelectLocalPath(reader)
	if err != nil || localPath == "" {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	user := currentSession.User
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	engine, err := transfer.NewTransferEngine(client, targetOS)
	if err != nil {
		pause(reader)
		return
	}
	defer engine.Close()

	remotePath, err := transfer.SelectRemotePath(reader, engine.SFTPClient, user)
	if err != nil || remotePath == "" {
		return
	}

	cleanRemotePath := filepath.ToSlash(remotePath)
	fi, err := os.Stat(localPath)
	var transferErr error
	if err == nil && fi.IsDir() {
		transferErr = engine.UploadDirectoryZip(localPath, cleanRemotePath)
	} else {
		transferErr = engine.UploadFile(localPath, cleanRemotePath)
	}
	if transferErr != nil {
		fmt.Printf(Red+Bold+"\n[!] Upload failed: %v\n"+Reset, transferErr)
	} else {
		fmt.Println(Green + Bold + "\n[SUCCESS] Upload completed." + Reset)
	}
	pause(reader)
}

func downloadSubMenu(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	user := currentSession.User
	sessionMutex.RUnlock()

	if err != nil {
		handleSSHConnectionError(err)
		pause(reader)
		return
	}
	defer client.Close()

	engine, err := transfer.NewTransferEngine(client, targetOS)
	if err != nil {
		pause(reader)
		return
	}
	defer engine.Close()

	remotePath, err := transfer.SelectRemotePath(reader, engine.SFTPClient, user)
	if err != nil || remotePath == "" {
		return
	}

	localPath, err := transfer.SelectLocalPath(reader)
	if err != nil || localPath == "" {
		return
	}

	cleanRemotePath := filepath.ToSlash(remotePath)
	remoteStat, err := engine.SFTPClient.Stat(cleanRemotePath)
	var transferErr error
	if err == nil && remoteStat.IsDir() {
		transferErr = engine.DownloadDirectoryZip(cleanRemotePath, localPath)
	} else {
		transferErr = engine.DownloadFile(cleanRemotePath, localPath)
	}
	if transferErr != nil {
		fmt.Printf(Red+Bold+"\n[!] Download failed: %v\n"+Reset, transferErr)
	} else {
		fmt.Println(Green + Bold + "\n[SUCCESS] Download completed." + Reset)
	}
	pause(reader)
}

func serviceManagerSubMenu(reader *bufio.Reader) {
	if !ensureSessionActive(reader) {
		return
	}

	sessionMutex.RLock()
	client, err := dialSSH(currentSession.Host, currentSession.Port, currentSession.User, currentSession.Pass, currentSession.KeyPath)
	targetOS := currentSession.TargetOS
	pass := currentSession.Pass
	sessionMutex.RUnlock()

	if err != nil {
		pause(reader)
		return
	}
	defer client.Close()
	services.ShowServiceMenu(reader, client, targetOS, pass)
}

func probeSubMenu(reader *bufio.Reader) {
	sessionMutex.RLock()
	host := currentSession.Host
	sessionMutex.RUnlock()
	probe.ShowPortProbeMenu(reader, host)
}
func installGlobalCLISubMenu(reader *bufio.Reader) {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Println(Red+"[!] Failed to get executable path: "+Reset, err)
		pause(reader)
		return
	}

	// Target: /usr/bin/cross-ssh (this is almost always in sudo's secure_path)
	target := "/usr/bin/cross-ssh"

	fmt.Println(Yellow + "[+] Installing to " + target + " ..." + Reset)

	// Use sudo install to copy and set permissions, and create parent dirs if needed
	cmdCopy := exec.Command("sudo", "install", "-D", "-m", "755", execPath, target)
	if out, err := cmdCopy.CombinedOutput(); err != nil {
		fmt.Printf(Red+"[!] Installation failed: %v\n%s\n"+Reset, err, string(out))
		pause(reader)
		return
	}

	// Verify the file exists and is executable
	if _, err := os.Stat(target); err != nil {
		fmt.Printf(Red+"[!] Installation verification failed: %s not found\n"+Reset, target)
		pause(reader)
		return
	}

	fmt.Println(Green + Bold + "[SUCCESS] Installed globally! Run 'cross-ssh' anywhere in terminal." + Reset)

	// Clear shell command hash cache (so the new binary is found immediately)
	_ = exec.Command("hash", "-r").Run()
	_ = exec.Command("rehash").Run() // for some shells

	pause(reader)
}
func ensureSessionActive(reader *bufio.Reader) bool {
	sessionMutex.RLock()
	isActive := currentSession.IsActive && currentSession.Host != ""
	sessionMutex.RUnlock()

	if !isActive {
		fmt.Println(Red + Bold + "\n[!] NO ACTIVE TARGET HOST LOCKED IN PLATFORM SESSION" + Reset)
		fmt.Println(Yellow + "=> Navigate to HUB [1] to connect or select a saved target from Vault." + Reset)
		pause(reader)
		return false
	}
	return true
}

func dialSSH(host, port, user, pass, keyPath string) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if keyPath != "" {
		cleanKeyPath := strings.TrimSpace(keyPath)
		if strings.HasPrefix(cleanKeyPath, "~/") {
			home, _ := os.UserHomeDir()
			cleanKeyPath = filepath.Join(home, cleanKeyPath[2:])
		}
		if keyData, err := os.ReadFile(cleanKeyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" && runtime.GOOS == "linux" {
		home = filepath.Join("/home", sudoUser)
	}

	if err == nil {
		keyFiles := []string{
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
		}
		for _, kPath := range keyFiles {
			if keyData, err := os.ReadFile(kPath); err == nil {
				if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
					authMethods = append(authMethods, ssh.PublicKeys(signer))
				}
			}
		}
	}

	if pass != "" {
		authMethods = append(authMethods, ssh.Password(pass))
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port), config)
}

func handleSSHConnectionError(err error) {
	fmt.Println(Red + Bold + "\n================================================================================" + Reset)
	fmt.Println(Red + Bold + "  [!] ACTIVE TARGET CONNECTION FAILED / SESSION EXPIRED" + Reset)
	fmt.Println(Red + Bold + "================================================================================" + Reset)
	fmt.Printf(Yellow+"  Error Details : %v\n"+Reset, err)
}
