package transfer

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cross-ssh/pkg/osdetect"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	TransferBufferSize = 4 * 1024 * 1024
	ParallelWorkers    = 8
	ChunkBlockSize     = 8 * 1024 * 1024
)

type ActiveMount struct {
	ID         int       `json:"id"`
	Host       string    `json:"host"`
	RemotePath string    `json:"remote_path"`
	LocalMount string    `json:"local_mount"`
	MountedAt  time.Time `json:"mounted_at"`
}

var (
	activeMounts []*ActiveMount
	mountMutex   sync.Mutex
	mountNextID  = 1
)

type TransferEngine struct {
	SSHClient  *ssh.Client
	SFTPClient *sftp.Client
	TargetOS   osdetect.TargetOS
}

func NewTransferEngine(sshClient *ssh.Client, targetOS osdetect.TargetOS) (*TransferEngine, error) {
	// Turbocharged SFTP Engine with Standard Compliant 32KB Packets and 256 Window Concurrency
	sftpClient, err := sftp.NewClient(sshClient,
		sftp.UseConcurrentReads(true),
		sftp.UseConcurrentWrites(true),
		sftp.MaxConcurrentRequestsPerFile(256),
		sftp.MaxPacketChecked(32768),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start turbo SFTP subsystem: %w", err)
	}
	return &TransferEngine{
		SSHClient:  sshClient,
		SFTPClient: sftpClient,
		TargetOS:   targetOS,
	}, nil
}

func (t *TransferEngine) Close() {
	if t.SFTPClient != nil {
		t.SFTPClient.Close()
	}
}

// --------------------------------------------------------------------
//  PERSISTENT MOUNT REGISTRY & AUTONOMOUS FUSE HEALER
// --------------------------------------------------------------------

func getMountLedgerPath() string {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	} else if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".cross-ssh")
	_ = os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "mounts.json")
}

func loadPersistentMounts() []*ActiveMount {
	mountMutex.Lock()
	defer mountMutex.Unlock()

	data, err := os.ReadFile(getMountLedgerPath())
	if err == nil {
		var list []*ActiveMount
		if err := json.Unmarshal(data, &list); err == nil {
			activeMounts = list
			for _, m := range list {
				if m.ID >= mountNextID {
					mountNextID = m.ID + 1
				}
			}
		}
	}

	// Verify against live kernel mounts in /proc/mounts
	procData, err := os.ReadFile("/proc/mounts")
	if err == nil {
		procStr := string(procData)
		var verified []*ActiveMount
		for _, m := range activeMounts {
			if strings.Contains(procStr, m.LocalMount) {
				verified = append(verified, m)
			}
		}
		activeMounts = verified
	}

	return activeMounts
}

func savePersistentMounts() {
	data, err := json.MarshalIndent(activeMounts, "", "  ")
	if err == nil {
		_ = os.WriteFile(getMountLedgerPath(), data, 0600)
		sudoUser := os.Getenv("SUDO_USER")
		if sudoUser != "" && sudoUser != "root" {
			_ = exec.Command("chown", fmt.Sprintf("%s:%s", sudoUser, sudoUser), getMountLedgerPath()).Run()
		}
	}
}

func autoHealFUSEEnvironment() {
	if runtime.GOOS != "linux" {
		return
	}

	fuseConf := "/etc/fuse.conf"
	data, err := os.ReadFile(fuseConf)
	if err == nil {
		content := string(data)
		if !strings.Contains(content, "user_allow_other") || strings.Contains(content, "#user_allow_other") {
			newContent := strings.ReplaceAll(content, "#user_allow_other", "user_allow_other")
			if !strings.Contains(newContent, "user_allow_other") {
				newContent += "\nuser_allow_other\n"
			}
			_ = os.WriteFile(fuseConf, []byte(newContent), 0644)
		}
	} else if os.IsNotExist(err) {
		_ = os.WriteFile(fuseConf, []byte("user_allow_other\n"), 0644)
	}

	_ = exec.Command("chmod", "644", fuseConf).Run()
}

func autoCleanStaleMount(path string) {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		_ = exec.Command("sudo", "-u", sudoUser, "fusermount", "-u", "-z", path).Run()
	}
	_ = exec.Command("fusermount", "-u", "-z", path).Run()
	_ = exec.Command("umount", "-l", path).Run()
}

func ShowMountMenu(reader *bufio.Reader, host, port, user, pass, keyPath string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== 💽 REMOTE STORAGE VIRTUALIZATION ENGINE (SSHFS) ===" + Reset)
		fmt.Printf(Yellow+"Target Host: "+Reset+Bold+"%s@%s:%s\n"+Reset, user, host, port)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] 🚀 Mount Remote Filesystem as Local Directory (Live Drive)")
		fmt.Println("  [2] 📋 View Active Remote Mounts & Open in Local File Manager")
		fmt.Println("  [3] 🛑 Unmount an Active Remote Drive Cleanly")
		fmt.Println(Red + "  [0] Back to File Operations Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := ReadRealtimeInput("Select choice [0-3]: ")

		switch choice {
		case "1":
			mountRemoteDriveInteractive(reader, host, port, user, pass, keyPath)
		case "2":
			listAndOpenMounts(reader)
		case "3":
			unmountDrive(reader)
		case "0", "q", "Q":
			return
		}
	}
}

func mountRemoteDriveInteractive(reader *bufio.Reader, host, port, user, pass, keyPath string) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Println(Yellow + "\n[!] SSHFS Live Drive mounting is supported on Linux and macOS." + Reset)
		pausePrompt()
		return
	}

	autoHealFUSEEnvironment()

	if _, err := exec.LookPath("sshfs"); err != nil {
		fmt.Println(Yellow + "\n[+] sshfs utility not found. Auto-installing in background..." + Reset)
		if _, errApt := exec.LookPath("apt-get"); errApt == nil {
			_ = exec.Command("apt-get", "update", "-qq").Run()
			_ = exec.Command("apt-get", "install", "-y", "-qq", "sshfs").Run()
		} else if _, errBrew := exec.LookPath("brew"); errBrew == nil {
			_ = exec.Command("brew", "install", "--cask", "macfuse").Run()
			_ = exec.Command("brew", "install", "gromgit/fuse/sshfs-mac").Run()
		}
	}

	// Step 1: Remote Path Selection
	fmt.Println(Cyan + "\n=== STEP 1: SELECT REMOTE DIRECTORY TO MOUNT ===" + Reset)
	fmt.Println("  [1] 📂 Interactive Remote Directory Browser (Visual Tree Navigation)")
	fmt.Println("  [2] ⚡ Direct Manual Remote Path Entry")
	fmt.Println("  [3] 🏠 Mount Default User Home (/home/" + user + ")")
	fmt.Println(Red + "  [0] Back to Mount Menu" + Reset)
	choice := ReadRealtimeInput("Select selection mode [0-3] (default 1): ")

	if choice == "0" || strings.ToLower(choice) == "q" {
		return
	}

	remotePath := ""
	if choice == "2" {
		remotePath = ReadRealtimeInput("Enter Remote Directory Path (or 0 to cancel): ")
		if remotePath == "0" || strings.ToLower(remotePath) == "q" {
			return
		}
	} else if choice == "3" {
		remotePath = "/home/" + user
		if user == "root" {
			remotePath = "/root"
		}
	} else {
		client, err := dialDirectSSH(host, port, user, pass, keyPath)
		if err == nil {
			sftpClient, errSFTP := sftp.NewClient(client)
			if errSFTP == nil {
				picked, errPick := SelectRemotePath(reader, sftpClient, user)
				sftpClient.Close()
				client.Close()
				if errPick != nil || picked == "" || picked == "0" {
					return
				}
				remotePath = picked
			} else {
				client.Close()
				return
			}
		} else {
			fmt.Printf(Red+"[!] Unable to open remote file browser: %v\n"+Reset, err)
			pausePrompt()
			return
		}
	}

	if strings.TrimSpace(remotePath) == "" {
		remotePath = "/home/" + user
		if user == "root" {
			remotePath = "/root"
		}
	}

	// Step 2: Local Mount Point Selection
	fmt.Println(Cyan + "\n=== STEP 2: SELECT LOCAL MOUNT DIRECTORY ON YOUR MACHINE ===" + Reset)
	sudoUser := os.Getenv("SUDO_USER")
	home, _ := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	}

	cleanHost := strings.ReplaceAll(host, ".", "_")
	defaultLocalMount := filepath.Join(home, "remote_drives", fmt.Sprintf("%s_%s", user, cleanHost))

	fmt.Println("  [1] 📂 Interactive Local Directory Browser")
	fmt.Println("  [2] ⚡ Default Auto-Managed Mount Point (" + defaultLocalMount + ")")
	fmt.Println("  [3] ✏️  Direct Custom Local Path Entry")
	fmt.Println(Red + "  [0] Back to Mount Menu" + Reset)
	localChoice := ReadRealtimeInput("Select choice [0-3] (default 2): ")

	if localChoice == "0" || strings.ToLower(localChoice) == "q" {
		return
	}

	localMount := ""
	if localChoice == "1" {
		pickedLocal, errPickLocal := SelectLocalPath(reader)
		if errPickLocal != nil || pickedLocal == "" || pickedLocal == "0" {
			return
		}
		localMount = pickedLocal
	} else if localChoice == "3" {
		localMount = ReadRealtimeInput("Enter Local Directory Path (or 0 to cancel): ")
		if localMount == "0" || strings.ToLower(localMount) == "q" {
			return
		}
	}

	if strings.TrimSpace(localMount) == "" {
		localMount = defaultLocalMount
	}

	cleanLocalMount := filepath.Clean(localMount)
	remoteBaseName := filepath.Base(strings.TrimSuffix(remotePath, "/"))
	if remoteBaseName == "/" || remoteBaseName == "." || remoteBaseName == "" {
		remoteBaseName = fmt.Sprintf("Remote_%s", user)
	}

	// Only append the folder name if the user picked a broad system container
	isSystemRoot := cleanLocalMount == home ||
		cleanLocalMount == "/root" ||
		cleanLocalMount == filepath.Join(home, "Desktop") ||
		cleanLocalMount == filepath.Join(home, "Downloads") ||
		cleanLocalMount == filepath.Join(home, "Documents")

	if isSystemRoot {
		cleanLocalMount = filepath.Join(cleanLocalMount, remoteBaseName)
	}

	// Clean any previous stale FUSE lock on this path
	autoCleanStaleMount(cleanLocalMount)

	_ = os.MkdirAll(cleanLocalMount, 0755)
	if sudoUser != "" && sudoUser != "root" {
		_ = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", sudoUser, sudoUser), cleanLocalMount).Run()
	}

	fmt.Printf(Yellow+"\n[+] Mounting %s@%s:%s on %s...\n"+Reset, user, host, remotePath, cleanLocalMount)

	sshfsArgs := []string{
		fmt.Sprintf("%s@%s:%s", user, host, remotePath),
		cleanLocalMount,
		"-p", port,
		"-o", "reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,follow_symlinks,allow_other,StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null",
	}

	var cmd *exec.Cmd

	if sudoUser != "" && sudoUser != "root" {
		if keyPath != "" {
			sshfsArgs = append(sshfsArgs, "-o", fmt.Sprintf("IdentityFile=%s", keyPath))
			cmdArgs := append([]string{"-u", sudoUser, "sshfs"}, sshfsArgs...)
			cmd = exec.Command("sudo", cmdArgs...)
		} else if pass != "" {
			if _, errP := exec.LookPath("sshpass"); errP == nil {
				cmdArgs := append([]string{"-u", sudoUser, "sshpass", "-p", pass, "sshfs"}, sshfsArgs...)
				cmd = exec.Command("sudo", cmdArgs...)
			} else {
				cmdArgs := append([]string{"-u", sudoUser, "sshfs"}, sshfsArgs...)
				cmd = exec.Command("sudo", cmdArgs...)
				cmd.Stdin = strings.NewReader(pass + "\n")
			}
		} else {
			cmdArgs := append([]string{"-u", sudoUser, "sshfs"}, sshfsArgs...)
			cmd = exec.Command("sudo", cmdArgs...)
		}
	} else {
		if keyPath != "" {
			sshfsArgs = append(sshfsArgs, "-o", fmt.Sprintf("IdentityFile=%s", keyPath))
		}
		cmd = exec.Command("sshfs", sshfsArgs...)
		if pass != "" {
			if _, errP := exec.LookPath("sshpass"); errP == nil {
				passArgs := append([]string{"-p", pass, "sshfs"}, sshfsArgs...)
				cmd = exec.Command("sshpass", passArgs...)
			} else {
				cmd.Stdin = strings.NewReader(pass + "\n")
			}
		}
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf(Red+"[!] Mount failed: %v | Output: %s\n"+Reset, err, string(out))
		autoCleanStaleMount(cleanLocalMount)
		pausePrompt()
		return
	}

	registerMount(host, remotePath, cleanLocalMount)
	pausePrompt()
}

func dialDirectSSH(host, port, user, pass, keyPath string) (*ssh.Client, error) {
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
	if pass != "" {
		authMethods = append(authMethods, ssh.Password(pass))
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         6 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port), config)
}

func registerMount(host, remotePath, localMount string) {
	loadPersistentMounts()

	mountMutex.Lock()
	m := &ActiveMount{
		ID:         mountNextID,
		Host:       host,
		RemotePath: remotePath,
		LocalMount: localMount,
		MountedAt:  time.Now(),
	}
	mountNextID++
	activeMounts = append(activeMounts, m)
	savePersistentMounts()
	mountMutex.Unlock()

	fmt.Println(Green + Bold + "\n[✔ SUCCESS] Remote Drive Mounted Successfully!" + Reset)
	fmt.Printf(Cyan+" Local Access Point: %s\n"+Reset, localMount)
	fmt.Println(Yellow + " You can now edit files directly with VS Code, Vim, or file managers." + Reset)

	autoOpen := ReadRealtimeInput("\nOpen Mount Folder in File Explorer now? [Y/n]: ")
	if autoOpen == "" || strings.ToLower(autoOpen) == "y" {
		openInFileManager(localMount)
	}
}

func openInFileManager(path string) {
	sudoUser := os.Getenv("SUDO_USER")
	if runtime.GOOS == "darwin" {
		if sudoUser != "" && sudoUser != "root" {
			_ = exec.Command("sudo", "-u", sudoUser, "open", path).Start()
		} else {
			_ = exec.Command("open", path).Start()
		}
	} else {
		if sudoUser != "" && sudoUser != "root" {
			uidOut, _ := exec.Command("id", "-u", sudoUser).Output()
			uid := strings.TrimSpace(string(uidOut))
			dbusAddr := fmt.Sprintf("unix:path=/run/user/%s/bus", uid)

			cmd := exec.Command("sudo", "-u", sudoUser, "env", fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=%s", dbusAddr), "xdg-open", path)
			if err := cmd.Start(); err != nil {
				_ = exec.Command("sudo", "-u", sudoUser, "thunar", path).Start()
			}
		} else {
			_ = exec.Command("xdg-open", path).Start()
		}
	}
}

func listAndOpenMounts(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== ACTIVE REMOTE SSHFS DRIVES (PERSISTENT REGISTRY) ===" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+" %-4s | %-18s | %-24s | %-32s | %-12s\n"+Reset, "ID", "REMOTE HOST", "REMOTE PATH", "LOCAL MOUNT POINT", "UPTIME")
	fmt.Println(Blue + "--------------------------------------------------------------------------------------------------" + Reset)

	mounts := loadPersistentMounts()

	mountMutex.Lock()
	if len(mounts) == 0 {
		fmt.Println(Yellow + " No active remote SSHFS mounts." + Reset)
		mountMutex.Unlock()
		pausePrompt()
		return
	}

	for _, m := range mounts {
		uptime := time.Since(m.MountedAt).Round(time.Second).String()
		fmt.Printf(" %-4d | %-18s | %-24s | %-32s | %-12s\n", m.ID, m.Host, m.RemotePath, Green+m.LocalMount+Reset, uptime)
	}
	mountMutex.Unlock()

	fmt.Println(Blue + "--------------------------------------------------------------------------------------------------" + Reset)
	choice := ReadRealtimeInput("\nEnter Mount ID to open in File Manager (or press Enter to return): ")
	if choice != "" {
		id := 0
		fmt.Sscanf(strings.TrimSpace(choice), "%d", &id)
		mountMutex.Lock()
		for _, m := range mounts {
			if m.ID == id {
				openInFileManager(m.LocalMount)
				break
			}
		}
		mountMutex.Unlock()
	}
}

func unmountDrive(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== UNMOUNT REMOTE DRIVE ===" + Reset)

	mounts := loadPersistentMounts()

	mountMutex.Lock()
	if len(mounts) == 0 {
		fmt.Println(Yellow + " No active mounts to unmount." + Reset)
		mountMutex.Unlock()
		pausePrompt()
		return
	}

	for _, m := range mounts {
		fmt.Printf("  [%d] %s:%s ==> %s\n", m.ID, m.Host, m.RemotePath, m.LocalMount)
	}
	mountMutex.Unlock()

	choice := ReadRealtimeInput("\nEnter Mount ID to Unmount (or 0 to cancel): ")
	id := 0
	fmt.Sscanf(strings.TrimSpace(choice), "%d", &id)
	if id <= 0 {
		return
	}

	mountMutex.Lock()
	defer mountMutex.Unlock()

	for i, m := range activeMounts {
		if m.ID == id {
			// Detach FUSE mount
			autoCleanStaleMount(m.LocalMount)
			
			// Automatically purge the empty folder
			time.Sleep(200 * time.Millisecond)
			_ = os.Remove(m.LocalMount)

			activeMounts = append(activeMounts[:i], activeMounts[i+1:]...)
			savePersistentMounts()
			fmt.Printf(Green+Bold+"[SUCCESS] Drive %s unmounted and placeholder directory purged cleanly.\n"+Reset, m.LocalMount)
			pausePrompt()
			return
		}
	}
	fmt.Println(Red + "[!] Mount ID not found." + Reset)
	pausePrompt()
}

// --------------------------------------------------------------------
//  PARALLEL CHUNK PROGRESS WRITER
// --------------------------------------------------------------------

type ProgressWriter struct {
	Total      int64
	Current    int64
	StartTime  time.Time
	Label      string
	LastUpdate time.Time
}

func NewProgressWriter(label string, totalBytes int64) *ProgressWriter {
	return &ProgressWriter{
		Total:     totalBytes,
		Label:     label,
		StartTime: time.Now(),
	}
}

func (pw *ProgressWriter) Add(n int64) {
	atomic.AddInt64(&pw.Current, n)
	pw.renderThrottled()
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n := len(p)
	atomic.AddInt64(&pw.Current, int64(n))
	pw.renderThrottled()
	return n, nil
}

func (pw *ProgressWriter) renderThrottled() {
	if time.Since(pw.LastUpdate) > 60*time.Millisecond || pw.Current >= pw.Total {
		pw.LastUpdate = time.Now()
		pw.render()
	}
}

func (pw *ProgressWriter) render() {
	cur := atomic.LoadInt64(&pw.Current)
	percent := float64(0)
	if pw.Total > 0 {
		percent = (float64(cur) / float64(pw.Total)) * 100
		if percent > 100 {
			percent = 100
		}
	}

	barLength := 30
	filled := int((percent / 100) * float64(barLength))
	if filled > barLength {
		filled = barLength
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("-", barLength-filled)

	elapsed := time.Since(pw.StartTime).Seconds()
	speed := float64(0)
	if elapsed > 0 {
		speed = (float64(cur) / 1024 / 1024) / elapsed
	}

	currentMB := float64(cur) / (1024 * 1024)
	totalMB := float64(pw.Total) / (1024 * 1024)

	fmt.Printf("\r\033[K\033[36m\033[1m[%s]\033[0m \033[32m[%s]\033[0m \033[33m%5.1f%%\033[0m (\033[35m%.2f/%.2f MB\033[0m @ \033[32m\033[1m%.2f MB/s\033[0m)",
		pw.Label, bar, percent, currentMB, totalMB, speed)

	if cur >= pw.Total && pw.Total > 0 {
		fmt.Println()
	}
}

// --------------------------------------------------------------------
//  PARALLEL UPLOAD / DOWNLOAD STREAMERS
// --------------------------------------------------------------------

func (t *TransferEngine) UploadFile(localPath, remotePath string) error {
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("cannot open local file: %w", err)
	}
	defer localFile.Close()

	stat, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat local file: %w", err)
	}
	totalSize := stat.Size()

	cleanRemotePath := filepath.ToSlash(remotePath)
	remoteStat, err := t.SFTPClient.Stat(cleanRemotePath)
	if err == nil && remoteStat.IsDir() {
		filename := filepath.Base(localPath)
		cleanRemotePath = filepath.ToSlash(filepath.Join(cleanRemotePath, filename))
	}

	parentDir := filepath.Dir(cleanRemotePath)
	_ = t.SFTPClient.MkdirAll(parentDir)

	remoteFile, err := t.SFTPClient.Create(cleanRemotePath)
	if err != nil {
		return fmt.Errorf("cannot create remote file (%s): %w", cleanRemotePath, err)
	}
	defer remoteFile.Close()

	pw := NewProgressWriter("TURBO UPLOAD (PARALLEL)", totalSize)

	if totalSize < 16*1024*1024 {
		writer := io.MultiWriter(remoteFile, pw)
		buf := make([]byte, TransferBufferSize)
		_, err = io.CopyBuffer(writer, localFile, buf)
		if err != nil {
			return fmt.Errorf("failed streaming payload: %w", err)
		}
		return nil
	}

	numChunks := int((totalSize + ChunkBlockSize - 1) / ChunkBlockSize)
	chunkChan := make(chan int, numChunks)
	for i := 0; i < numChunks; i++ {
		chunkChan <- i
	}
	close(chunkChan)

	numWorkers := ParallelWorkers
	if numWorkers > runtime.NumCPU()*2 {
		numWorkers = runtime.NumCPU() * 2
	}

	var wg sync.WaitGroup
	var transferErr error
	var errOnce sync.Once

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, ChunkBlockSize)

			for chunkIdx := range chunkChan {
				if transferErr != nil {
					return
				}

				offset := int64(chunkIdx) * ChunkBlockSize
				bytesToRead := ChunkBlockSize
				if offset+int64(bytesToRead) > totalSize {
					bytesToRead = int(totalSize - offset)
				}

				n, err := localFile.ReadAt(buf[:bytesToRead], offset)
				if err != nil && err != io.EOF {
					errOnce.Do(func() { transferErr = err })
					return
				}

				if n > 0 {
					_, writeErr := remoteFile.WriteAt(buf[:n], offset)
					if writeErr != nil {
						errOnce.Do(func() { transferErr = writeErr })
						return
					}
					pw.Add(int64(n))
				}
			}
		}()
	}

	wg.Wait()
	if transferErr != nil {
		return fmt.Errorf("failed parallel chunk upload: %w", transferErr)
	}

	return nil
}

func (t *TransferEngine) DownloadFile(remotePath, localPath string) error {
	cleanRemotePath := filepath.ToSlash(remotePath)
	remoteFile, err := t.SFTPClient.Open(cleanRemotePath)
	if err != nil {
		return fmt.Errorf("cannot open remote file: %w", err)
	}
	defer remoteFile.Close()

	stat, err := remoteFile.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat remote file: %w", err)
	}
	totalSize := stat.Size()

	targetLocalPath := localPath
	localStat, err := os.Stat(localPath)
	if err == nil && localStat.IsDir() {
		targetLocalPath = filepath.Join(localPath, filepath.Base(remotePath))
	} else if os.IsNotExist(err) && filepath.Ext(localPath) == "" {
		_ = os.MkdirAll(localPath, 0755)
		targetLocalPath = filepath.Join(localPath, filepath.Base(remotePath))
	}

	if err := os.MkdirAll(filepath.Dir(targetLocalPath), 0755); err != nil {
		return fmt.Errorf("failed creating local parent directory: %w", err)
	}

	localFile, err := os.Create(targetLocalPath)
	if err != nil {
		return fmt.Errorf("cannot create local file: %w", err)
	}
	defer localFile.Close()

	pw := NewProgressWriter("TURBO DOWNLOAD (PARALLEL)", totalSize)

	if totalSize < 16*1024*1024 {
		writer := io.MultiWriter(localFile, pw)
		buf := make([]byte, TransferBufferSize)
		_, err = io.CopyBuffer(writer, remoteFile, buf)
		if err != nil {
			return fmt.Errorf("failed downloading file payload: %w", err)
		}
		return nil
	}

	_ = localFile.Truncate(totalSize)

	numChunks := int((totalSize + ChunkBlockSize - 1) / ChunkBlockSize)
	chunkChan := make(chan int, numChunks)
	for i := 0; i < numChunks; i++ {
		chunkChan <- i
	}
	close(chunkChan)

	numWorkers := ParallelWorkers
	if numWorkers > runtime.NumCPU()*2 {
		numWorkers = runtime.NumCPU() * 2
	}

	var wg sync.WaitGroup
	var transferErr error
	var errOnce sync.Once

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, ChunkBlockSize)

			for chunkIdx := range chunkChan {
				if transferErr != nil {
					return
				}

				offset := int64(chunkIdx) * ChunkBlockSize
				bytesToRead := ChunkBlockSize
				if offset+int64(bytesToRead) > totalSize {
					bytesToRead = int(totalSize - offset)
				}

				n, err := remoteFile.ReadAt(buf[:bytesToRead], offset)
				if err != nil && err != io.EOF {
					errOnce.Do(func() { transferErr = err })
					return
				}

				if n > 0 {
					_, writeErr := localFile.WriteAt(buf[:n], offset)
					if writeErr != nil {
						errOnce.Do(func() { transferErr = writeErr })
						return
					}
					pw.Add(int64(n))
				}
			}
		}()
	}

	wg.Wait()
	if transferErr != nil {
		return fmt.Errorf("failed parallel chunk download: %w", transferErr)
	}

	return nil
}

func (t *TransferEngine) UploadDirectoryZip(localFolder, remoteTargetFolder string) error {
	baseName := filepath.Base(localFolder)

	if err := t.SFTPClient.MkdirAll(filepath.ToSlash(remoteTargetFolder)); err != nil {
		return fmt.Errorf("failed to create remote target directory: %w", err)
	}

	fmt.Printf(Yellow+"[+] Archiving local folder '%s'...\n"+Reset, baseName)
	tmpZip, err := os.CreateTemp("", "cross-ssh-*.zip")
	if err != nil {
		return fmt.Errorf("failed creating temp zip: %w", err)
	}
	defer os.Remove(tmpZip.Name())
	defer tmpZip.Close()

	zipWriter := zip.NewWriter(tmpZip)
	err = filepath.Walk(localFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(localFolder, path)
		if err != nil {
			return err
		}

		w, err := zipWriter.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(w, file)
		return err
	})
	if err != nil {
		return fmt.Errorf("failed zipping directory: %w", err)
	}
	zipWriter.Close()

	remoteZipName := fmt.Sprintf("upload_%d.zip", os.Getpid())
	var remoteZipPath string
	if t.TargetOS == osdetect.OSWindows {
		remoteZipPath = remoteTargetFolder + "\\" + remoteZipName
	} else {
		remoteZipPath = remoteTargetFolder + "/" + remoteZipName
	}

	tmpZip.Seek(0, 0)
	err = t.UploadFile(tmpZip.Name(), remoteZipPath)
	if err != nil {
		return fmt.Errorf("failed uploading zip archive: %w", err)
	}

	finalRemoteDest := remoteTargetFolder
	if !strings.HasSuffix(remoteTargetFolder, baseName) {
		if t.TargetOS == osdetect.OSWindows {
			finalRemoteDest = remoteTargetFolder + "\\" + baseName
		} else {
			finalRemoteDest = remoteTargetFolder + "/" + baseName
		}
	}

	fmt.Println(Yellow + "\n[+] Extracting folder on target host..." + Reset)
	return t.remoteUnzip(remoteZipPath, finalRemoteDest)
}

func (t *TransferEngine) DownloadDirectoryZip(remoteFolder, localTargetFolder string) error {
	remoteZipPath := fmt.Sprintf("/tmp/download_%d.zip", os.Getpid())
	if t.TargetOS == osdetect.OSWindows {
		remoteZipPath = fmt.Sprintf("C:\\Windows\\Temp\\download_%d.zip", os.Getpid())
	}

	cleanRemoteFolder := filepath.ToSlash(remoteFolder)
	baseName := filepath.Base(cleanRemoteFolder)
	fmt.Printf(Yellow+"[+] Archiving remote directory '%s' on target...\n"+Reset, baseName)

	if err := t.remoteZip(remoteFolder, remoteZipPath); err != nil {
		return fmt.Errorf("failed remote directory archiving: %w", err)
	}
	defer t.remoteCleanup(remoteZipPath)

	localTmpZip, err := os.CreateTemp("", "cross-ssh-down-*.zip")
	if err != nil {
		return fmt.Errorf("failed creating local temp zip: %w", err)
	}
	defer os.Remove(localTmpZip.Name())
	defer localTmpZip.Close()

	if err := t.DownloadFile(remoteZipPath, localTmpZip.Name()); err != nil {
		return fmt.Errorf("failed downloading remote zip: %w", err)
	}

	finalLocalDest := filepath.Join(localTargetFolder, baseName)
	if strings.HasSuffix(localTargetFolder, baseName) {
		finalLocalDest = localTargetFolder
	}

	fmt.Printf(Yellow+"\n[+] Extracting directory archive to '%s'...\n"+Reset, finalLocalDest)

	return t.localUnzip(localTmpZip.Name(), finalLocalDest)
}

// normalizeWindowsRemotePath converts an SFTP-style Windows path
// (e.g. "/C:/Users/Saleem/Desktop") into a native Windows path
// (e.g. "C:\Users\Saleem\Desktop") that PowerShell/cmd can understand.
// OpenSSH's SFTP subsystem on Windows reports paths with a leading "/"
// before the drive letter and forward slashes; native shells need the
// drive letter first and backslashes.
func normalizeWindowsRemotePath(p string) string {
	p = strings.ReplaceAll(p, "/", "\\")
	if len(p) >= 3 && p[0] == '\\' && p[2] == ':' {
		p = p[1:]
	}
	return p
}

func (t *TransferEngine) remoteZip(remoteFolder, remoteZipPath string) error {
	session, err := t.SSHClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var cmd string
	switch t.TargetOS {
	case osdetect.OSWindows:
		winFolder := normalizeWindowsRemotePath(remoteFolder)
		winZipPath := normalizeWindowsRemotePath(remoteZipPath)
		cmd = fmt.Sprintf(`powershell -Command "Compress-Archive -Path '%s\*' -DestinationPath '%s' -Force"`,
			winFolder, winZipPath)
	case osdetect.OSLinux, osdetect.OSMacOS:
		cmd = fmt.Sprintf(`zip -r "%s" "%s" || python3 -m zipfile -c "%s" "%s"`,
			remoteZipPath, remoteFolder, remoteZipPath, remoteFolder)
	default:
		return fmt.Errorf("unsupported target OS for remote zip: %q", t.TargetOS)
	}

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("remote zip command failed: %s | err: %w", string(output), err)
	}
	return nil
}

func (t *TransferEngine) remoteUnzip(remoteZipPath, remoteTargetFolder string) error {
	session, err := t.SSHClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	var cmd string
	switch t.TargetOS {
	case osdetect.OSWindows:
		winZipPath := normalizeWindowsRemotePath(remoteZipPath)
		winTargetFolder := normalizeWindowsRemotePath(remoteTargetFolder)
		cmd = fmt.Sprintf(`powershell -Command "Expand-Archive -Path '%s' -DestinationPath '%s' -Force; Remove-Item '%s'"`,
			winZipPath, winTargetFolder, winZipPath)
	case osdetect.OSLinux, osdetect.OSMacOS:
		cmd = fmt.Sprintf(`unzip -o "%s" -d "%s" && rm -f "%s" || python3 -m zipfile -e "%s" "%s" && rm -f "%s"`,
			remoteZipPath, remoteTargetFolder, remoteZipPath, remoteZipPath, remoteTargetFolder, remoteZipPath)
	default:
		return fmt.Errorf("unsupported target OS for remote unzip: %q", t.TargetOS)
	}

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("remote unzip command output: %s | err: %w", string(output), err)
	}
	return nil
}

func (t *TransferEngine) remoteCleanup(remotePath string) {
	session, err := t.SSHClient.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	var cmd string
	if t.TargetOS == osdetect.OSWindows {
		cmd = fmt.Sprintf(`powershell -Command "Remove-Item -Path '%s' -Force"`, remotePath)
	} else {
		cmd = fmt.Sprintf(`rm -f "%s"`, remotePath)
	}
	_ = session.Run(cmd)
}

func (t *TransferEngine) localUnzip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	destDirClean := filepath.Clean(destDir)
	folderBaseName := filepath.Base(destDirClean)

	for _, f := range r.File {
		cleanName := filepath.ToSlash(f.Name)

		parts := strings.Split(cleanName, "/")
		for i, part := range parts {
			if part == folderBaseName && i < len(parts)-1 {
				cleanName = strings.Join(parts[i+1:], "/")
				break
			}
		}

		fpath := filepath.Join(destDirClean, filepath.FromSlash(cleanName))
		if !strings.HasPrefix(fpath, destDirClean+string(os.PathSeparator)) && fpath != destDirClean {
			continue
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		buf := make([]byte, TransferBufferSize)
		_, err = io.CopyBuffer(outFile, rc, buf)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to continue..." + Reset)
	_ = ReadRealtimeInput("")
}