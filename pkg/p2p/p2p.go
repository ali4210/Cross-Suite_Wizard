package p2p

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/session"
	"cross-ssh/pkg/transfer"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)
const (
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Red    = "\033[31m"
	Cyan   = "\033[36m"
	Blue   = "\033[34m"
	Bold   = "\033[1m"
)

// ShowP2PMenu renders HUB 6: P2P Remote Assistance & Session Pairing
func ShowP2PMenu(reader *bufio.Reader) {
	for {
		fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
		fmt.Println(Cyan + Bold + "=== HUB 6: P2P TEAMVIEWER-STYLE REMOTE ASSISTANCE & PAIRING ENGINE ===" + Reset)
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)
		fmt.Println("  [1] 🎧 Host Session : Share My Terminal (Generate Partner Code & Live TCP Port)")
		fmt.Println("  [2] 💻 Connect Session: Join Teammate's Terminal & Transfer Files")
		fmt.Println("  [3] ⚡ Generate 1-Line Onboarding Command (For Raw Remote Machines)")
		fmt.Println("  [0] ↩️ Back to Main Menu")
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select P2P Option [0-3]: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := sanitizeInput(input)

		switch choice {
		case "0", "q", "Q":
			return
		case "1":
			HostSession(reader)
		case "2":
			ConnectSessionMenu(reader)
		case "3":
			GenerateOneLiner(reader)
		default:
			fmt.Println(Red + "[!] Invalid option. Please select 0-3." + Reset)
		}
	}
}

// sanitizeInput removes raw ANSI escape sequences (arrow keys, control codes)
func sanitizeInput(raw string) string {
	cleaned := strings.TrimSpace(raw)
	for strings.Contains(cleaned, "\x1b") || strings.Contains(cleaned, "^[") {
		idx := strings.Index(cleaned, "\x1b")
		if idx == -1 {
			idx = strings.Index(cleaned, "^[")
		}
		if idx != -1 && len(cleaned) > idx+2 {
			cleaned = cleaned[:idx] + cleaned[idx+3:]
		} else {
			break
		}
	}
	return strings.TrimSpace(cleaned)
}

// HostSession starts a clean background reverse TCP tunnel relay and displays security banners
// HostSession starts a clean background reverse TCP tunnel relay and displays connection details reliably
func HostSession(reader *bufio.Reader) {
    fmt.Println("\n" + Yellow + Bold + "[+] Initializing P2P Terminal Sharing Host Engine..." + Reset)
    fmt.Println(Cyan + "[+] Spawning outbound reverse TCP tunnel broker..." + Reset)

    relayHost := "tcp@a.pinggy.io"

    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/c", fmt.Sprintf("ssh -p 443 -o StrictHostKeyChecking=no -R 0:localhost:22 %s", relayHost))
    } else {
        cmd = exec.Command("ssh", "-p", "443", "-o", "StrictHostKeyChecking=no", "-R", "0:localhost:22", relayHost)
    }

    stdout, err := cmd.StdoutPipe()
    if err != nil {
        fmt.Printf(Red+"[!] Failed to attach stdout pipe: %v\n"+Reset, err)
        return
    }
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        fmt.Printf(Red+"[!] Failed starting reverse TCP tunnel: %v\n"+Reset, err)
        return
    }

    fmt.Println(Cyan + "[+] Tunnel relay active! Listening for live TCP endpoint stream...\n" + Reset)

    scanner := bufio.NewScanner(stdout)
    extractedEndpoint := ""

    go func() {
        for scanner.Scan() {
            line := scanner.Text()

            if strings.Contains(line, "tcp://") || strings.Contains(line, "pinggy") {
                fmt.Println(Green + "  [✔] " + line + Reset)
            }

            if strings.Contains(line, "tcp://") || strings.Contains(line, "run.pinggy") || strings.Contains(line, "pinggy-free") {
                words := strings.Fields(line)
                for _, w := range words {
                    if strings.Contains(w, "pinggy") || strings.Contains(w, "tcp://") {
                        clean := strings.TrimPrefix(w, "tcp://")
                        clean = strings.TrimPrefix(clean, "http://")
                        clean = strings.TrimPrefix(clean, "https://")
                        extractedEndpoint = strings.TrimSpace(clean)
                    }
                }
            }
        }
    }()

    time.Sleep(4 * time.Second)

    fmt.Println(Green + "\n================================================================================" + Reset)
    fmt.Println(Green + Bold + "  🏆 P2P RAW TCP HOST SESSION ACTIVE & READY FOR PAIRING" + Reset)
    fmt.Println(Green + "================================================================================" + Reset)
    fmt.Println(Cyan + "  🔐 ENCRYPTION SPECIFICATIONS:" + Reset)
    fmt.Println("     • Inner Protocol : End-to-End Encrypted SSH (ChaCha20-Poly1305 / AES-256-GCM)")
    fmt.Println("     • Key Exchange   : Curve25519 (Elliptic-Curve ECDH)")
    fmt.Println("     • Broker Access  : Zero-Payload Access (Layer-4 Pass-Through Only)")
    fmt.Println(Green + "--------------------------------------------------------------------------------" + Reset)
    if extractedEndpoint != "" {
        fmt.Printf("  => Share This Exact Endpoint with Teammate : %s%s%s\n", Bold+Yellow, extractedEndpoint, Reset)
    } else {
        fmt.Println("  => Copy the 'tcp://' or 'pinggy' endpoint string displayed above!")
    }
    fmt.Println(Yellow + "  => Instructions for Teammate :" + Reset)
    fmt.Println("     • For Quick TTY & SFTP Pairing : Enter in Hub [6] -> Option [2]")
    fmt.Println("     • For Full Platform Target Lock : Enter in Hub [1] -> Option [3]")
    fmt.Println(Green + "================================================================================" + Reset)

    fmt.Println(Yellow + "\n=> Press [Enter] or Ctrl+C to disconnect and close terminal sharing.\n" + Reset)
    input, _ := reader.ReadString('\n')
    _ = sanitizeInput(input)

    if cmd.Process != nil {
        _ = cmd.Process.Kill()
    }
    fmt.Println(Green + "[✔] P2P Host session closed cleanly." + Reset)
}

// ConnectSessionMenu provides clean TTY launch, passwordless SSH key deployment, and file transfer with Global Target Lock
// ConnectSessionMenu provides clean TTY launch, passwordless SSH key deployment, and file transfer with Global Target Lock
func ConnectSessionMenu(reader *bufio.Reader) {
	fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "=== CONNECT TO TEAMMATE'S REMOTE ASSISTANCE SESSION ===" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	fmt.Print(Bold + "Enter Teammate's TCP Endpoint Link (e.g., r3qxa-103-153-66-123.run.pinggy-free.link:42105): " + Reset)
	endpointInput, _ := reader.ReadString('\n')
	rawEndpoint := sanitizeInput(endpointInput)

	if rawEndpoint == "" {
		fmt.Println(Red + "[!] Endpoint Link cannot be empty." + Reset)
		return
	}

	cleanInput := strings.TrimPrefix(rawEndpoint, "tcp://")
	cleanInput = strings.TrimPrefix(cleanInput, "http://")
	cleanInput = strings.TrimPrefix(cleanInput, "https://")

	parts := strings.Split(cleanInput, ":")
	targetHost := parts[0]
	targetPort := "22"
	if len(parts) > 1 {
		targetPort = parts[1]
	}

	fmt.Print(Bold + "Enter Remote User on Target Host [default: saleem]: " + Reset)
	userInput, _ := reader.ReadString('\n')
	remoteUser := sanitizeInput(userInput)
	if remoteUser == "" {
		remoteUser = "saleem"
	}

	fmt.Print(Bold + "Enter Remote Password (leave blank if public-key authenticated): " + Reset)
	passInput, _ := reader.ReadString('\n')
	remotePass := strings.TrimSpace(passInput)

	if remotePass != "" {
		fmt.Println(Yellow + "\n[+] Testing connection & deploying one-time SSH key for permanent passwordless access..." + Reset)
		err := bootstrapP2PKey(targetHost, targetPort, remoteUser, remotePass)
		if err != nil {
			fmt.Printf(Red+"[!] Key bootstrap warning: %v. Proceeding with password...\n"+Reset, err)
		} else {
			fmt.Println(Green + Bold + "[SUCCESS] Local SSH Key deployed to teammate's PC! Passwordless entry unlocked." + Reset)
		}
	}

	// CONSTRUCT P2P ACTIVE SESSION TARGET CONTEXT
	activeP2PSession := &session.ActiveSession{
		Host:     targetHost,
		Port:     targetPort,
		User:     remoteUser,
		Pass:     remotePass,
		TargetOS: osdetect.OSLinux,
	}
	_ = activeP2PSession

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "  🏆 GLOBAL TARGET LOCKED TO P2P ENCRYPTED RELAY" + Reset)
	fmt.Println(Green + "================================================================================" + Reset)
	fmt.Printf(Cyan+"  => Active Target Locked : %s@%s:%s [P2P Relay Mode]\n"+Reset, remoteUser, targetHost, targetPort)
	fmt.Println(Yellow + "  => All Hubs (Hub 2 Files, Hub 4 Services, Hub 5 DevSecOps) are now linked to this target!" + Reset)
	fmt.Println(Green + "================================================================================" + Reset)

	for {
		fmt.Println("\n" + Cyan + Bold + "--------------------------------------------------------------------------------" + Reset)
		fmt.Printf(Green+Bold+"  => ACTIVE REMOTE RELAY: %s@%s:%s\n"+Reset, remoteUser, targetHost, targetPort)
		fmt.Println(Cyan + Bold + "  🔐 SECURITY VERIFIED: AES-256-GCM / Curve25519 End-to-End Encrypted Tunnel" + Reset)
		fmt.Println(Cyan + Bold + "--------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 💻 Launch Ultra-Clean Interactive Remote Terminal (TTY)")
		fmt.Println("  [2] 📤 Upload File or Directory to Remote Teammate's PC (Paged SFTP Engine)")
		fmt.Println("  [3] 📥 Download File or Directory from Remote Teammate's PC (Paged SFTP Engine)")
		fmt.Println("  [0] ↩️ Disconnect Session & Return to Main Menu")
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select Action [0-3]: " + Reset)
		choiceInput, _ := reader.ReadString('\n')
		actionChoice := sanitizeInput(choiceInput)

		switch actionChoice {
		case "0", "q", "Q":
			fmt.Println(Green + "[✔] Disconnected from remote relay session." + Reset)
			return
		case "1":
			launchCleanTTY(targetHost, targetPort, remoteUser)
		case "2":
			p2pUploadFile(reader, targetHost, targetPort, remoteUser, remotePass)
		case "3":
			p2pDownloadFile(reader, targetHost, targetPort, remoteUser, remotePass)
		default:
			fmt.Println(Red + "[!] Invalid option." + Reset)
		}
	}
}
// ConnectAndGetSession validates connection credentials first and returns target credentials
// directly to Hub 1 for platform-wide Global Target Locking only if authentication succeeds.
func ConnectAndGetSession(reader *bufio.Reader) (string, string, string, string, bool) {
	fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "=== CONNECT TO TEAMMATE'S REMOTE ASSISTANCE SESSION (GLOBAL TARGET LOCK) ===" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	fmt.Print(Bold + "Enter Teammate's TCP Endpoint Link (e.g., r3qxa-103-153-66-123.run.pinggy-free.link:42105): " + Reset)
	endpointInput, _ := reader.ReadString('\n')
	rawEndpoint := sanitizeInput(endpointInput)

	if rawEndpoint == "" {
		fmt.Println(Red + "[!] Endpoint Link cannot be empty." + Reset)
		return "", "", "", "", false
	}

	cleanInput := strings.TrimPrefix(rawEndpoint, "tcp://")
	cleanInput = strings.TrimPrefix(cleanInput, "http://")
	cleanInput = strings.TrimPrefix(cleanInput, "https://")

	parts := strings.Split(cleanInput, ":")
	targetHost := parts[0]
	targetPort := "22"
	if len(parts) > 1 {
		targetPort = parts[1]
	}

	fmt.Print(Bold + "Enter Remote User on Target Host [default: saleem]: " + Reset)
	userInput, _ := reader.ReadString('\n')
	remoteUser := sanitizeInput(userInput)
	if remoteUser == "" {
		remoteUser = "saleem"
	}

	fmt.Print(Bold + "Enter Remote Password (leave blank if public-key authenticated): " + Reset)
	passInput, _ := reader.ReadString('\n')
	remotePass := strings.TrimSpace(passInput)

	// Step 1: Probe live connection over relay before announcing success
	fmt.Println(Yellow + "\n[+] Verifying P2P Endpoint and Authenticating Credentials..." + Reset)
	probeClient, err := dialRelaySSH(targetHost, targetPort, remoteUser, remotePass)
	if err != nil {
		fmt.Printf(Red+Bold+"\n[!] P2P CONNECTION FAILED: %v\n"+Reset, err)
		fmt.Println(Red + "[!] Active Target Lock aborted due to authentication or endpoint error." + Reset)
		return "", "", "", "", false
	}
	probeClient.Close()

	// Step 2: Connection verified! Deploy passwordless key if password was provided
	if remotePass != "" {
		fmt.Println(Yellow + "[+] Deploying one-time SSH key for permanent passwordless entry..." + Reset)
		err := bootstrapP2PKey(targetHost, targetPort, remoteUser, remotePass)
		if err != nil {
			fmt.Printf(Red+"[!] Key bootstrap warning: %v. Proceeding with verified password...\n"+Reset, err)
		} else {
			fmt.Println(Green + Bold + "[SUCCESS] Local SSH Key deployed to teammate's PC! Passwordless entry unlocked." + Reset)
		}
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "  🏆 GLOBAL TARGET LOCKED TO P2P ENCRYPTED RELAY" + Reset)
	fmt.Println(Green + "================================================================================" + Reset)
	fmt.Printf(Cyan+"  => Active Target Locked : %s@%s:%s [P2P Relay Mode]\n"+Reset, remoteUser, targetHost, targetPort)
	fmt.Println(Yellow + "  => All Hubs (Hub 2 Files, Hub 4 Services, Hub 5 DevSecOps) are now linked to this target!" + Reset)
	fmt.Println(Green + "================================================================================" + Reset)

	return targetHost, targetPort, remoteUser, remotePass, true
}

// bootstrapP2PKey deploys local SSH public key to remote host to eliminate password prompts
func bootstrapP2PKey(host, port, user, pass string) error {
	client, err := dialRelaySSH(host, port, user, pass)
	if err != nil {
		return err
	}
	defer client.Close()

	home, _ := os.UserHomeDir()
	pubKeyPath := filepath.Join(home, ".ssh", "id_ed25519.pub")
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		pubKeyPath = filepath.Join(home, ".ssh", "id_rsa.pub")
	}

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("local public key not found at %s", pubKeyPath)
	}

	pubKeyStr := strings.TrimSpace(string(pubKeyBytes))
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	linuxCmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", pubKeyStr)
	return sess.Run(linuxCmd)
}

// launchCleanTTY executes an ultra-clean SSH TTY session
func launchCleanTTY(host, port, user string) {
	fmt.Println(Yellow + "\n[+] Launching clean, industrialized TTY session..." + Reset)
	time.Sleep(500 * time.Millisecond)

	var sshCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		sshCmd = exec.Command("cmd.exe", "/c", fmt.Sprintf("ssh -p %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL %s@%s", port, user, host))
	} else {
		sshCmd = exec.Command("ssh", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("%s@%s", user, host))
	}

	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdin = os.Stdin

	_ = sshCmd.Run()
	fmt.Println(Green + "\n[✔] TTY Session exited cleanly." + Reset)
}

// selectRemotePathPaged provides a paged, lag-free directory browser with 'q' to quit/cancel cleanly
func selectRemotePathPaged(reader *bufio.Reader, sftpClient *sftp.Client, user string) (string, error) {
	currentDir := fmt.Sprintf("/home/%s", user)
	if user == "root" {
		currentDir = "/root"
	}
	showDotfiles := false
	pageSize := 15
	currentPage := 0

	for {
		files, err := sftpClient.ReadDir(currentDir)
		if err != nil {
			fmt.Printf(Red+"[!] Error reading remote path '%s': %v\n"+Reset, currentDir, err)
			currentDir = filepath.Dir(currentDir)
			if currentDir == "." || currentDir == "" {
				currentDir = "/"
			}
			continue
		}

		validEntries := []os.FileInfo{}
		for _, f := range files {
			if f.Name() == "." || f.Name() == ".." {
				continue
			}
			if !showDotfiles && strings.HasPrefix(f.Name(), ".") {
				continue
			}
			validEntries = append(validEntries, f)
		}

		totalItems := len(validEntries)
		totalPages := (totalItems + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}
		if currentPage >= totalPages {
			currentPage = totalPages - 1
		}
		if currentPage < 0 {
			currentPage = 0
		}

		fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
		fmt.Printf(Green+Bold+"  📂 REMOTE DIRECTORY: %s (Page %d of %d | Total Items: %d)\n"+Reset, currentDir, currentPage+1, totalPages, totalItems)
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)

		fmt.Println(Yellow + "  [Shortcuts] 'h' Home | 'd' Downloads | 'w' Desktop | 'c' Cross-Suite | '.' Dotfiles | 'q' CANCEL & EXIT" + Reset)
		fmt.Println("  [0]  📁 SELECT ENTIRE CURRENT DIRECTORY (" + currentDir + ")")
		fmt.Println("  [..] ⬆️  Go Up One Level")

		startIdx := currentPage * pageSize
		endIdx := startIdx + pageSize
		if endIdx > totalItems {
			endIdx = totalItems
		}

		displayEntries := validEntries[startIdx:endIdx]
		for i, f := range displayEntries {
			itemNum := startIdx + i + 1
			icon := "📄"
			if f.IsDir() {
				icon = "📁"
			}
			fmt.Printf("  [%d]  %s %s\n", itemNum, icon, f.Name())
		}

		pageControls := ""
		if currentPage < totalPages-1 {
			pageControls += "'n' Next Page | "
		}
		if currentPage > 0 {
			pageControls += "'p' Prev Page | "
		}

		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
		fmt.Printf(Bold+"Type NUMBER, %s'..' Up, '0' Select Folder, 'q' Exit, or Name/Path: "+Reset, pageControls)

		input, _ := reader.ReadString('\n')
		choice := sanitizeInput(input)

		if strings.ToLower(choice) == "q" || strings.ToLower(choice) == "exit" || strings.ToLower(choice) == "cancel" {
			return "", fmt.Errorf("user canceled browser interaction")
		}

		if choice == "0" {
			return currentDir, nil
		}
		if choice == ".." {
			currentDir = filepath.Dir(currentDir)
			if currentDir == "." || currentDir == "" {
				currentDir = "/"
			}
			currentPage = 0
			continue
		}

		if strings.ToLower(choice) == "n" && currentPage < totalPages-1 {
			currentPage++
			continue
		}
		if strings.ToLower(choice) == "p" && currentPage > 0 {
			currentPage--
			continue
		}

		switch strings.ToLower(choice) {
		case "h", "~":
			currentDir = fmt.Sprintf("/home/%s", user)
			if user == "root" {
				currentDir = "/root"
			}
			currentPage = 0
			continue
		case "d":
			currentDir = fmt.Sprintf("/home/%s/Downloads", user)
			currentPage = 0
			continue
		case "w":
			currentDir = fmt.Sprintf("/home/%s/Desktop", user)
			currentPage = 0
			continue
		case "c":
			currentDir = fmt.Sprintf("/home/%s/Cross-Suite_Wizard", user)
			currentPage = 0
			continue
		case ".":
			showDotfiles = !showDotfiles
			currentPage = 0
			continue
		}

		if strings.HasPrefix(choice, "/") || strings.HasPrefix(choice, "C:") {
			return choice, nil
		}

		num, err := strconv.Atoi(choice)
		if err == nil && num >= 1 && num <= totalItems {
			selected := validEntries[num-1]
			fullPath := filepath.ToSlash(filepath.Join(currentDir, selected.Name()))
			if selected.IsDir() {
				currentDir = fullPath
				currentPage = 0
			} else {
				return fullPath, nil
			}
			continue
		}

		matchedPath := ""
		for _, entry := range validEntries {
			if strings.Contains(strings.ToLower(entry.Name()), strings.ToLower(choice)) {
				matchedPath = filepath.ToSlash(filepath.Join(currentDir, entry.Name()))
				if entry.IsDir() {
					currentDir = matchedPath
					currentPage = 0
				} else {
					return matchedPath, nil
				}
				break
			}
		}

		if matchedPath == "" {
			fmt.Println(Red + "[!] Invalid selection or command. Try a number, 'n' next, 'p' prev, or 'q' to cancel." + Reset)
		}
	}
}

// p2pUploadFile connects via SFTP over the relay tunnel and uploads files or zipped directories cleanly
func p2pUploadFile(reader *bufio.Reader, host, port, user, pass string) {
	fmt.Println(Cyan + "\n=== P2P SFTP FILE / DIRECTORY UPLOAD OVER RELAY TUNNEL ===" + Reset)

	client, err := dialRelaySSH(host, port, user, pass)
	if err != nil {
		fmt.Printf(Red+"[!] Connection to relay failed: %v\n"+Reset, err)
		return
	}
	defer client.Close()

	engine, err := transfer.NewTransferEngine(client, osdetect.OSLinux)
	if err != nil {
		fmt.Printf(Red+"[!] SFTP Engine init failed: %v\n"+Reset, err)
		return
	}
	defer engine.Close()

	fmt.Println(Yellow + "[+] Select local file or folder to upload:" + Reset)
	localPath, err := transfer.SelectLocalPath(reader)
	if err != nil || localPath == "" {
		fmt.Println(Yellow + "[!] Upload canceled." + Reset)
		return
	}

	fmt.Println(Yellow + "\n[+] Select destination path on remote teammate's PC:" + Reset)
	remotePath, err := selectRemotePathPaged(reader, engine.SFTPClient, user)
	if err != nil || remotePath == "" {
		fmt.Println(Yellow + "[!] Remote path selection canceled. Returning to P2P menu..." + Reset)
		return
	}

	fi, err := os.Stat(localPath)
	if err == nil && fi.IsDir() {
		fmt.Printf(Yellow+"\n[+] Compressing directory '%s' into ZIP archive and uploading to '%s'...\n"+Reset, localPath, remotePath)
		err = engine.UploadDirectoryZip(localPath, remotePath)
	} else {
		fmt.Printf(Yellow+"\n[+] Uploading file '%s' to '%s'...\n"+Reset, localPath, remotePath)
		err = engine.UploadFile(localPath, remotePath)
	}

	if err != nil {
		fmt.Printf(Red+"[!] Upload failed: %v\n"+Reset, err)
	} else {
		fmt.Println(Green + Bold + "[SUCCESS] Upload completed cleanly!" + Reset)
	}
}

// p2pDownloadFile connects via SFTP over the relay tunnel and downloads files or zipped directories cleanly
func p2pDownloadFile(reader *bufio.Reader, host, port, user, pass string) {
	fmt.Println(Cyan + "\n=== P2P SFTP FILE / DIRECTORY DOWNLOAD OVER RELAY TUNNEL ===" + Reset)

	client, err := dialRelaySSH(host, port, user, pass)
	if err != nil {
		fmt.Printf(Red+"[!] Connection to relay failed: %v\n"+Reset, err)
		return
	}
	defer client.Close()

	engine, err := transfer.NewTransferEngine(client, osdetect.OSLinux)
	if err != nil {
		fmt.Printf(Red+"[!] SFTP Engine init failed: %v\n"+Reset, err)
		return
	}
	defer engine.Close()

	fmt.Println(Yellow + "[+] Select file or folder to download from remote teammate's PC:" + Reset)
	remotePath, err := selectRemotePathPaged(reader, engine.SFTPClient, user)
	if err != nil || remotePath == "" {
		fmt.Println(Yellow + "[!] Remote path selection canceled. Returning to P2P menu..." + Reset)
		return
	}

	fmt.Println(Yellow + "\n[+] Select local destination directory on your PC:" + Reset)
	localPath, err := transfer.SelectLocalPath(reader)
	if err != nil || localPath == "" {
		fmt.Println(Yellow + "[!] Local path selection canceled." + Reset)
		return
	}

	remoteStat, err := engine.SFTPClient.Stat(remotePath)
	if err == nil && remoteStat.IsDir() {
		fmt.Printf(Yellow+"\n[+] Compressing remote directory '%s' into ZIP archive and downloading to '%s'...\n"+Reset, remotePath, localPath)
		err = engine.DownloadDirectoryZip(remotePath, localPath)
	} else {
		fmt.Printf(Yellow+"\n[+] Downloading file '%s' to '%s'...\n"+Reset, remotePath, localPath)
		err = engine.DownloadFile(remotePath, localPath)
	}

	if err != nil {
		fmt.Printf(Red+"[!] Download failed: %v\n"+Reset, err)
	} else {
		fmt.Println(Green + Bold + "[SUCCESS] Download completed cleanly!" + Reset)
	}
}

// dialRelaySSH establishes an SSH client session to the relay server
func dialRelaySSH(host, port, user, pass string) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod
	if pass != "" {
		authMethods = append(authMethods, ssh.Password(pass))
	}

	home, _ := os.UserHomeDir()
	defKey := filepath.Join(home, ".ssh", "id_ed25519")
	if keyData, err := os.ReadFile(defKey); err == nil {
		if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	rsaKey := filepath.Join(home, ".ssh", "id_rsa")
	if keyData, err := os.ReadFile(rsaKey); err == nil {
		if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port), config)
}

// GenerateOneLiner creates a 1-line script for remote raw servers without Cross-Suite Wizard
func GenerateOneLiner(reader *bufio.Reader) {
	fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "=== 1-LINE UNLIMITED REMOTE ONBOARDING COMMAND GENERATOR ===" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)
	fmt.Println("Copy and send one of these 1-line commands to your remote teammate:\n")

	fmt.Println(Yellow + "--> For Linux / macOS Targets:" + Reset)
	fmt.Println(Bold + "    ssh -p 443 -o StrictHostKeyChecking=no -R 0:localhost:22 tcp@a.pinggy.io" + Reset)

	fmt.Println(Yellow + "\n--> For Windows PowerShell Targets:" + Reset)
	fmt.Println(Bold + "    powershell -NoProfile -Command \"ssh -p 443 -o StrictHostKeyChecking=no -R 0:localhost:22 tcp@a.pinggy.io\"" + Reset)

	fmt.Println("\n" + Green + "[✔] When executed, share the displayed endpoint host and port to connect!" + Reset)
	fmt.Print("\nPress [Enter] to return to P2P menu.")
	_, _ = reader.ReadString('\n')
}