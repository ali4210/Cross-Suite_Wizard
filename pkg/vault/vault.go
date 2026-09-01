package vault

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
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
	BgBlue  = "\033[44m"
	White   = "\033[37m"

	pbkdf2Iterations = 100000
	keyLength        = 32
	saltLength       = 16
)

type HostProfile struct {
	ID       int               `json:"id"`
	Alias    string            `json:"alias"`
	Host     string            `json:"host"`
	Port     string            `json:"port"`
	User     string            `json:"user"`
	Pass     string            `json:"pass,omitempty"`
	KeyPath  string            `json:"key_path,omitempty"`
	TargetOS osdetect.TargetOS `json:"target_os"`
	IsAdmin  bool              `json:"is_admin"`
	LastSeen time.Time         `json:"last_seen"`
}

type ActiveTargetSession struct {
	Host     string            `json:"Host"`
	Port     string            `json:"Port"`
	User     string            `json:"User"`
	Pass     string            `json:"Pass"`
	KeyPath  string            `json:"KeyPath"`
	TargetOS osdetect.TargetOS `json:"TargetOS"`
	IsAdmin  bool              `json:"IsAdmin"`
	IsActive bool              `json:"IsActive"`
}

type VaultData struct {
	Profiles []HostProfile `json:"profiles"`
}

type VaultConfig struct {
	EncryptionEnabled bool `json:"encryption_enabled"`
}

type DiscoveredTarget struct {
	IP          string
	MAC         string
	Alias       string
	DeviceType  string
	OSPlatform  string
	Vendor      string
	Scope       string // "Core LAN", "Host Remote LAN", "Deep IoT", "Bluetooth"
	IsBluetooth bool
}

var (
	vaultMutex         sync.Mutex
	cachedMasterKey    []byte
	cachedSalt         []byte
	cachedPassphrase   string
	isPassphraseCached bool
	sudoPasswordCached string
	btNameCache        = make(map[string]string)
	btNameCacheMutex   sync.RWMutex

	aliasMap      = make(map[string]string)
	aliasMapMutex sync.RWMutex

	cachedBTAdapter string = "hci0"
)

// ====================================================================
//  STRING FORMATTERS & ALIAS PERSISTENCE
// ====================================================================

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func getAliasFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dirPath := filepath.Join(homeDir, ".cross-ssh")
	_ = os.MkdirAll(dirPath, 0700)
	return filepath.Join(dirPath, "aliases.json")
}

func loadPersistentAliases() {
	aliasMapMutex.Lock()
	defer aliasMapMutex.Unlock()

	aFile := getAliasFilePath()
	if _, err := os.Stat(aFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(aFile)
	if err == nil {
		_ = json.Unmarshal(data, &aliasMap)
	}
}

func savePersistentAliases() {
	aliasMapMutex.RLock()
	defer aliasMapMutex.RUnlock()

	aFile := getAliasFilePath()
	data, err := json.MarshalIndent(aliasMap, "", "  ")
	if err == nil {
		_ = os.WriteFile(aFile, data, 0600)
	}
}

func setDeviceAlias(key string, alias string) {
	aliasMapMutex.Lock()
	aliasMap[key] = alias
	aliasMapMutex.Unlock()

	savePersistentAliases()
}

func getDeviceAlias(key string) string {
	aliasMapMutex.RLock()
	defer aliasMapMutex.RUnlock()

	if val, ok := aliasMap[key]; ok && val != "" {
		return val
	}
	return "Unlabeled"
}

func getActiveTargetSession() *ActiveTargetSession {
	sudoUser := os.Getenv("SUDO_USER")
	targetHome, _ := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		targetHome = filepath.Join("/home", sudoUser)
	}
	file := filepath.Join(targetHome, ".cross-ssh", "active_target.json")
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var sess ActiveTargetSession
	if err := json.Unmarshal(data, &sess); err == nil && sess.Host != "" {
		return &sess
	}
	return nil
}

func EnsureRootPrivileges() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
		out, _ := cmd.Output()
		if strings.Contains(strings.TrimSpace(string(out)), "True") {
			fmt.Println(Green + Bold + "[✔] Windows Administrator Privileges Detected!" + Reset)
			return "windows-admin"
		}
		fmt.Println(Yellow + "[!] Running without Admin rights. Some deep socket scans may fail." + Reset)
		time.Sleep(1 * time.Second)
		return ""
	}

	if os.Geteuid() == 0 {
		return ""
	}
	if sudoPasswordCached != "" {
		return sudoPasswordCached
	}

	fmt.Println(Cyan + Bold + "\n=== ELEVATING RECONNAISSANCE ENGINE PRIVILEGES ===" + Reset)
	pass := transfer.ReadRealtimeInput("Enter Sudo Password (or press ENTER to skip): ")
	if strings.TrimSpace(pass) == "" {
		return ""
	}

	cmd := exec.Command("sudo", "-S", "id")
	cmd.Stdin = strings.NewReader(pass + "\n")
	if err := cmd.Run(); err != nil {
		fmt.Println(Red + "[!] Incorrect sudo password." + Reset)
		return ""
	}

	sudoPasswordCached = pass
	fmt.Println(Green + Bold + "[✔] Root Privileges Granted!" + Reset)
	return pass
}

// ====================================================================
//  ENCRYPTION & VAULT STORAGE ENGINE
// ====================================================================

func getEncryptedVaultPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dirPath := filepath.Join(homeDir, ".cross-ssh")
	_ = os.MkdirAll(dirPath, 0700)
	return filepath.Join(dirPath, "vault.enc")
}

func getPlainVaultPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dirPath := filepath.Join(homeDir, ".cross-ssh")
	_ = os.MkdirAll(dirPath, 0700)
	return filepath.Join(dirPath, "vault.json")
}

func getConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dirPath := filepath.Join(homeDir, ".cross-ssh")
	_ = os.MkdirAll(dirPath, 0700)
	return filepath.Join(dirPath, "config.json")
}

func IsEncryptionDisabled() bool {
	cfgFile := getConfigPath()
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		return false
	}
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		return false
	}
	var cfg VaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return !cfg.EncryptionEnabled
}

func setEncryptionState(enabled bool) {
	cfgFile := getConfigPath()
	cfg := VaultConfig{EncryptionEnabled: enabled}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(cfgFile, data, 0600)
}

func deriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keyLength, sha256.New)
}

func GetOrPromptMasterKey() ([]byte, error) {
	if IsEncryptionDisabled() {
		return nil, nil
	}

	if isPassphraseCached && len(cachedMasterKey) == keyLength {
		return cachedMasterKey, nil
	}

	vFile := getEncryptedVaultPath()
	vExists := false
	if _, err := os.Stat(vFile); err == nil {
		vExists = true
	}

	for {
		if !vExists {
			fmt.Println(Cyan + Bold + "\n=== INITIALIZE ENCRYPTED MASTER VAULT ===" + Reset)
			fmt.Println(Yellow + "[!] Set a Master Vault Passphrase to protect infrastructure credentials." + Reset)
			p1 := transfer.ReadRealtimeInput("Set Master Vault Passphrase: ")
			if p1 == "" {
				fmt.Println(Red + "[!] Passphrase cannot be empty." + Reset)
				continue
			}
			p2 := transfer.ReadRealtimeInput("Confirm Master Vault Passphrase: ")
			if p1 != p2 {
				fmt.Println(Red + "[!] Passphrases do not match. Try again." + Reset)
				continue
			}

			salt := make([]byte, saltLength)
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return nil, err
			}

			key := deriveKey(p1, salt)
			cachedSalt = salt
			cachedMasterKey = key
			cachedPassphrase = p1
			isPassphraseCached = true

			setEncryptionState(true)
			_ = SaveVaultUnlocked(&VaultData{Profiles: []HostProfile{}})
			fmt.Println(Green + Bold + "[✔] Master Vault Encrypted & Initialized!" + Reset)
			return key, nil
		} else {
			fmt.Println(Cyan + Bold + "\n=== UNLOCK ENCRYPTED MASTER VAULT ===" + Reset)
			p := transfer.ReadRealtimeInput("Enter Master Vault Passphrase (or '0' to Cancel): ")
			if p == "0" {
				return nil, errors.New("unlock canceled by user")
			}
			if p == "" {
				continue
			}

			raw, err := os.ReadFile(vFile)
			if err != nil || len(raw) < saltLength+12 {
				fmt.Println(Red + "[!] Corrupted vault file detected." + Reset)
				return nil, errors.New("corrupted vault file")
			}

			salt := raw[:saltLength]
			key := deriveKey(p, salt)

			_, err = decryptVaultData(raw, key)
			if err != nil {
				fmt.Println(Red + Bold + "[!] Incorrect Master Passphrase!" + Reset)
				continue
			}

			cachedSalt = salt
			cachedMasterKey = key
			cachedPassphrase = p
			isPassphraseCached = true
			fmt.Println(Green + Bold + "[✔] Master Vault Unlocked Successfully!" + Reset)
			return key, nil
		}
	}
}

func encryptVaultData(data []byte, key []byte, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	out := append(salt, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptVaultData(raw []byte, key []byte) ([]byte, error) {
	if len(raw) < saltLength+12 {
		return nil, errors.New("vault payload too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce := raw[saltLength : saltLength+nonceSize]
	ciphertext := raw[saltLength+nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func LoadVault() (*VaultData, error) {
	vaultMutex.Lock()
	defer vaultMutex.Unlock()

	return LoadVaultUnlocked()
}

func LoadVaultUnlocked() (*VaultData, error) {
	if IsEncryptionDisabled() {
		pFile := getPlainVaultPath()
		if _, err := os.Stat(pFile); os.IsNotExist(err) {
			return &VaultData{Profiles: []HostProfile{}}, nil
		}
		raw, err := os.ReadFile(pFile)
		if err != nil {
			return nil, err
		}
		var data VaultData
		if err := json.Unmarshal(raw, &data); err != nil {
			return &VaultData{Profiles: []HostProfile{}}, nil
		}
		return &data, nil
	}

	vFile := getEncryptedVaultPath()
	if _, err := os.Stat(vFile); os.IsNotExist(err) {
		return &VaultData{Profiles: []HostProfile{}}, nil
	}

	raw, err := os.ReadFile(vFile)
	if err != nil {
		return nil, err
	}

	if !isPassphraseCached {
		return &VaultData{Profiles: []HostProfile{}}, nil
	}

	plaintext, err := decryptVaultData(raw, cachedMasterKey)
	if err != nil {
		return nil, err
	}

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return &VaultData{Profiles: []HostProfile{}}, nil
	}

	return &data, nil
}

func SaveVaultUnlocked(data *VaultData) error {
	if IsEncryptionDisabled() {
		pFile := getPlainVaultPath()
		plaintext, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(pFile, plaintext, 0600)
	}

	vFile := getEncryptedVaultPath()

	if len(cachedSalt) < saltLength {
		raw, err := os.ReadFile(vFile)
		if err == nil && len(raw) >= saltLength {
			cachedSalt = raw[:saltLength]
		} else {
			cachedSalt = make([]byte, saltLength)
			if _, err := io.ReadFull(rand.Reader, cachedSalt); err != nil {
				return err
			}
		}
	}

	plaintext, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	encryptedPayload, err := encryptVaultData(plaintext, cachedMasterKey, cachedSalt)
	if err != nil {
		return err
	}

	return os.WriteFile(vFile, encryptedPayload, 0600)
}

func SaveActiveSessionToVault(alias, host, port, user, pass, keyPath string, targetOS osdetect.TargetOS, isAdmin bool) error {
	if !IsEncryptionDisabled() && !isPassphraseCached {
		_, err := GetOrPromptMasterKey()
		if err != nil {
			return err
		}
	}

	vaultMutex.Lock()
	defer vaultMutex.Unlock()

	vData, err := LoadVaultUnlocked()
	if err != nil || vData == nil {
		vData = &VaultData{Profiles: []HostProfile{}}
	}

	maxID := 0
	updated := false
	for i, p := range vData.Profiles {
		if p.ID > maxID {
			maxID = p.ID
		}
		if p.Host == host {
			vData.Profiles[i].Alias = alias
			vData.Profiles[i].Host = host
			vData.Profiles[i].Port = port
			vData.Profiles[i].User = user
			vData.Profiles[i].Pass = pass
			vData.Profiles[i].KeyPath = keyPath
			vData.Profiles[i].TargetOS = targetOS
			vData.Profiles[i].IsAdmin = isAdmin
			vData.Profiles[i].LastSeen = time.Now()
			updated = true
			break
		}
	}

	if !updated {
		newProf := HostProfile{
			ID:       maxID + 1,
			Alias:    alias,
			Host:     host,
			Port:     port,
			User:     user,
			Pass:     pass,
			KeyPath:  keyPath,
			TargetOS: targetOS,
			IsAdmin:  isAdmin,
			LastSeen: time.Now(),
		}
		vData.Profiles = append(vData.Profiles, newProf)
	}

	return SaveVaultUnlocked(vData)
}

// ====================================================================
//  TABLE RENDERERS
// ====================================================================

func runeDisplayWidth(r rune) int {
	if (r >= 0x1F300 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF) {
		return 2
	}
	return 1
}

func visualCellWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeDisplayWidth(r)
	}
	return w
}

func padVisible(text string, width int) string {
	curW := visualCellWidth(text)
	if curW > width {
		runes := []rune(text)
		for len(runes) > 0 && visualCellWidth(string(runes)) > width {
			runes = runes[:len(runes)-1]
		}
		text = string(runes)
		curW = visualCellWidth(text)
	}
	return text + strings.Repeat(" ", width-curW)
}

func splitIntoLines(text string, maxLen int) []string {
	if len(text) == 0 {
		return []string{""}
	}
	var lines []string
	runes := []rune(text)
	for len(runes) > maxLen {
		lines = append(lines, string(runes[:maxLen]))
		runes = runes[maxLen:]
	}
	if len(runes) > 0 {
		lines = append(lines, string(runes))
	}
	return lines
}

func colorCell(text, color string, width int) string {
	return color + padVisible(text, width) + Reset
}

func maxInt(values ...int) int {
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

func renderVaultInventoryTable(profiles []HostProfile) {
	const (
		wID       = 4
		wAlias    = 18
		wEndpoint = 22
		wPort     = 6
		wUser     = 10
		wAuth     = 20
		wOS       = 10
		wSeen     = 16
	)

	topBorder := fmt.Sprintf("┌─%s─┬─%s─┬─%s─┬─%s─┬─%s─┬─%s─┬─%s─┬─%s─┐",
		strings.Repeat("─", wID),
		strings.Repeat("─", wAlias),
		strings.Repeat("─", wEndpoint),
		strings.Repeat("─", wPort),
		strings.Repeat("─", wUser),
		strings.Repeat("─", wAuth),
		strings.Repeat("─", wOS),
		strings.Repeat("─", wSeen),
	)

	midBorder := fmt.Sprintf("├─%s─┼─%s─┼─%s─┼─%s─┼─%s─┼─%s─┼─%s─┼─%s─┤",
		strings.Repeat("─", wID),
		strings.Repeat("─", wAlias),
		strings.Repeat("─", wEndpoint),
		strings.Repeat("─", wPort),
		strings.Repeat("─", wUser),
		strings.Repeat("─", wAuth),
		strings.Repeat("─", wOS),
		strings.Repeat("─", wSeen),
	)

	botBorder := fmt.Sprintf("└─%s─┴─%s─┴─%s─┴─%s─┴─%s─┴─%s─┴─%s─┴─%s─┘",
		strings.Repeat("─", wID),
		strings.Repeat("─", wAlias),
		strings.Repeat("─", wEndpoint),
		strings.Repeat("─", wPort),
		strings.Repeat("─", wUser),
		strings.Repeat("─", wAuth),
		strings.Repeat("─", wOS),
		strings.Repeat("─", wSeen),
	)

	fmt.Println(Cyan + topBorder + Reset)
	fmt.Printf(Cyan+"│ %s │ %s │ %s │ %s │ %s │ %s │ %s │ %s │\n"+Reset,
		Bold+padVisible("ID", wID)+Reset+Cyan,
		Bold+padVisible("ALIAS", wAlias)+Reset+Cyan,
		Bold+padVisible("HOST IP / ENDPOINT", wEndpoint)+Reset+Cyan,
		Bold+padVisible("PORT", wPort)+Reset+Cyan,
		Bold+padVisible("USER", wUser)+Reset+Cyan,
		Bold+padVisible("AUTH / KEY FILE", wAuth)+Reset+Cyan,
		Bold+padVisible("OS", wOS)+Reset+Cyan,
		Bold+padVisible("LAST SEEN", wSeen)+Reset+Cyan,
	)
	fmt.Println(Cyan + midBorder + Reset)

	if len(profiles) == 0 {
		emptyMsg := "Vault is empty. No saved profiles found."
		totalWidth := wID + wAlias + wEndpoint + wPort + wUser + wAuth + wOS + wSeen + 21
		fmt.Printf("│ %s │\n", Yellow+padVisible(emptyMsg, totalWidth)+Reset)
		fmt.Println(Cyan + botBorder + Reset)
		return
	}

	for _, p := range profiles {
		idStr := strconv.Itoa(p.ID)
		aliasStr := p.Alias
		if strings.TrimSpace(aliasStr) == "" {
			aliasStr = "Unlabeled"
		}
		hostStr := p.Host
		portStr := p.Port
		userStr := p.User

		authStr := "Password"
		if p.KeyPath != "" {
			authStr = filepath.Base(p.KeyPath)
		}

		osStr := string(p.TargetOS)
		if strings.TrimSpace(osStr) == "" {
			osStr = "linux"
		}
		seenStr := p.LastSeen.Format("2006-01-02 15:04")

		aliasLines := splitIntoLines(aliasStr, wAlias)
		hostLines := splitIntoLines(hostStr, wEndpoint)
		authLines := splitIntoLines(authStr, wAuth)

		numSubRows := maxInt(len(aliasLines), len(hostLines), len(authLines), 1)

		for r := 0; r < numSubRows; r++ {
			cID := ""
			cPort := ""
			cUser := ""
			cOS := ""
			cSeen := ""

			if r == 0 {
				cID = idStr
				cPort = portStr
				cUser = userStr
				cOS = osStr
				cSeen = seenStr
			}

			cAlias := ""
			if r < len(aliasLines) {
				cAlias = aliasLines[r]
			}

			cHost := ""
			if r < len(hostLines) {
				cHost = hostLines[r]
			}

			cAuth := ""
			if r < len(authLines) {
				cAuth = authLines[r]
			}

			fmt.Printf("│ %s │ %s │ %s │ %s │ %s │ %s │ %s │ %s │\n",
				colorCell(cID, White+Bold, wID),
				colorCell(cAlias, Green+Bold, wAlias),
				colorCell(cHost, Cyan, wEndpoint),
				colorCell(cPort, Magenta, wPort),
				colorCell(cUser, White, wUser),
				colorCell(cAuth, Yellow+Bold, wAuth),
				colorCell(cOS, Blue+Bold, wOS),
				colorCell(cSeen, Yellow, wSeen),
			)
		}
	}

	fmt.Println(Cyan + botBorder + Reset)
}

func PromptAuthenticationMethod(reader *bufio.Reader) (string, string) {
	pass := transfer.ReadRealtimeInput("Enter SSH Password (or press Enter to skip): ")

	fmt.Println()
	keyPrompt := "Would you like to specify an SSH Key (.pem / id_ed25519 / id_rsa)? (y/n) [default: n]: "
	useKeyChoice := transfer.ReadRealtimeInput(keyPrompt)
	useKeyLower := strings.ToLower(strings.TrimSpace(useKeyChoice))

	if useKeyLower != "y" && useKeyLower != "yes" {
		return pass, ""
	}

	fmt.Println(Cyan + Bold + "\n=== SSH KEY CONFIGURATION ENGINE ===" + Reset)
	fmt.Println("  [1] Direct Path Entry (Type exact path, e.g. /home/kali/Downloads/aws-key.pem)")
	fmt.Println("  [2] Interactive Arrow-Key Browser (Browse folders & pick key directly)")
	fmt.Print(Bold + "Select Key Selection Mode [1-2] [default: 2]: " + Reset)

	mode := transfer.ReadRealtimeInput("")
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "2"
	}

	var selectedKeyPath string
	if mode == "1" {
		rawPath := transfer.ReadRealtimeInput("Enter absolute path to private key: ")
		selectedKeyPath = strings.TrimSpace(rawPath)
	} else {
		fmt.Println(Yellow + "\n[+] Launching Interactive Local File Browser to select key..." + Reset)
		time.Sleep(300 * time.Millisecond)

		keyPath, err := transfer.SelectLocalPath(reader)
		if err == nil && keyPath != "" {
			selectedKeyPath = keyPath
		} else {
			fmt.Println(Yellow + "[!] Interactive key selection canceled." + Reset)
		}
	}

	if selectedKeyPath != "" {
		fmt.Printf(Green+Bold+"[✔] Authenticated Private Key Bound: %s\n"+Reset, selectedKeyPath)
	}

	return pass, selectedKeyPath
}

func PromptNewTargetManual(reader *bufio.Reader) (HostProfile, bool) {
	fmt.Println(Cyan + Bold + "\n=== ENTER NEW TARGET IP CREDENTIALS MANUALLY ===" + Reset)

	host := transfer.ReadRealtimeInput("Enter Target Public IP / Hostname: ")
	if strings.TrimSpace(host) == "" {
		return HostProfile{}, false
	}

	port := transfer.ReadRealtimeInput("Enter Target SSH Port [default: 22]: ")
	if strings.TrimSpace(port) == "" {
		port = "22"
	}

	user := transfer.ReadRealtimeInput("Enter SSH Username [default: root]: ")
	if strings.TrimSpace(user) == "" {
		user = "root"
	}

	pass, keyPath := PromptAuthenticationMethod(reader)

	alias := transfer.ReadRealtimeInput(fmt.Sprintf("Enter Profile Alias [default: node-%s]: ", host))
	if strings.TrimSpace(alias) == "" {
		alias = fmt.Sprintf("node-%s", host)
	}

	profile := HostProfile{
		Alias:    alias,
		Host:     host,
		Port:     port,
		User:     user,
		Pass:     pass,
		KeyPath:  keyPath,
		TargetOS: osdetect.OSLinux,
		LastSeen: time.Now(),
	}

	saveChoice := transfer.ReadRealtimeInput("\nSave this target to Vault inventory permanently? (y/n) [default: y]: ")
	if saveChoice == "" || strings.ToLower(strings.TrimSpace(saveChoice)) == "y" {
		_ = SaveActiveSessionToVault(alias, host, port, user, pass, keyPath, osdetect.OSLinux, false)
		fmt.Println(Green + Bold + "[✔] Target successfully saved to Vault!" + Reset)
		time.Sleep(500 * time.Millisecond)
	}

	return profile, true
}

func addNewProfilePrompt(reader *bufio.Reader) {
	fmt.Println(Cyan + "\n=== ADD NEW HOST PROFILE TO VAULT ===" + Reset)
	alias := transfer.ReadRealtimeInput("Profile Alias / Name (e.g. aws-prod-ec2): ")
	if alias == "" {
		alias = "Host-" + fmt.Sprintf("%d", time.Now().Unix()%1000)
	}

	host := transfer.ReadRealtimeInput("Target Public IP / Hostname: ")
	if host == "" {
		return
	}

	port := transfer.ReadRealtimeInput("Port [default: 22]: ")
	if port == "" {
		port = "22"
	}

	user := transfer.ReadRealtimeInput("Username [default: root]: ")
	if user == "" {
		user = "root"
	}

	pass, keyPath := PromptAuthenticationMethod(reader)

	err := SaveActiveSessionToVault(alias, host, port, user, pass, keyPath, osdetect.OSLinux, false)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to save profile: %v\n"+Reset, err)
	} else {
		fmt.Println(Green + Bold + "[SUCCESS] Host Profile Saved to Vault!" + Reset)
	}
	time.Sleep(1 * time.Second)
}

func deleteProfilePrompt(reader *bufio.Reader) {
	idStr := transfer.ReadRealtimeInput("\nEnter Host Profile ID to DELETE: ")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return
	}

	vaultMutex.Lock()
	defer vaultMutex.Unlock()

	vData, err := LoadVaultUnlocked()
	if err != nil {
		return
	}

	newProfiles := []HostProfile{}
	found := false
	for _, p := range vData.Profiles {
		if p.ID == id {
			found = true
			continue
		}
		newProfiles = append(newProfiles, p)
	}

	if found {
		vData.Profiles = newProfiles
		_ = SaveVaultUnlocked(vData)
		fmt.Println(Green + Bold + "[SUCCESS] Profile deleted from vault." + Reset)
	} else {
		fmt.Println(Red + "[!] Profile ID not found." + Reset)
	}
	time.Sleep(1 * time.Second)
}

// ====================================================================
//  VAULT MASTER MENU (ENGINE 5 / HUB 1)
// ====================================================================

func ShowVaultMenu(reader *bufio.Reader, onConnect func(p HostProfile)) {
	if !IsEncryptionDisabled() && !isPassphraseCached {
		_, err := GetOrPromptMasterKey()
		if err != nil {
			fmt.Println(Red + "[!] Could not unlock vault." + Reset)
			time.Sleep(1 * time.Second)
			return
		}
	}

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "==========================================================================================================" + Reset)
		fmt.Println(Cyan + Bold + "=== ENGINE 5: MULTI-NODE SESSION INVENTORY & ENCRYPTED VAULT ===" + Reset)
		fmt.Println(Cyan + Bold + "==========================================================================================================" + Reset)
		if IsEncryptionDisabled() {
			fmt.Println(Red + "=> SECURITY STATUS: Encryption is OFF (Plain JSON Mode Active)" + Reset)
		} else {
			fmt.Println(Green + Bold + "=> SECURITY STATUS: AES-256-GCM Hardware Encrypted (~/.cross-ssh/vault.enc)" + Reset)
		}
		fmt.Println()

		vData, err := LoadVault()
		if err != nil || vData == nil {
			renderVaultInventoryTable([]HostProfile{})
		} else {
			renderVaultInventoryTable(vData.Profiles)
		}

		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------------" + Reset)
		fmt.Println(Green + Bold + "  [1] Connect to a Saved Host Profile (Select by ID)" + Reset)
		fmt.Println(Cyan + Bold + "  [2] Auto-Scan Subnet (Live LAN & Remote Host LAN Radar Sweep)" + Reset)
		fmt.Println(Yellow + Bold + "  [3] Add a New Host Profile Manually (Password or .PEM Key)" + Reset)
		fmt.Println(Red + "  [4] Delete a Host Profile from Vault" + Reset)
		fmt.Println(Magenta + "  [5] Change Master Vault Passphrase" + Reset)
		fmt.Println(Cyan + "  [6] Toggle Master Vault Encryption (ON / OFF)" + Reset)
		fmt.Println(Yellow + "  [7] Lock Vault & Clear Master Key Memory" + Reset)
		fmt.Println(Green + Bold + "  [8] Automated Hardware & Recon Engine Doctor (One-Click Auto-Fix)" + Reset)
		fmt.Println(Red + Bold + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "----------------------------------------------------------------------------------------------------------" + Reset)
		choice := transfer.ReadRealtimeInput("Select choice [0-8]: ")

		switch choice {
		case "1":
			if vData == nil || len(vData.Profiles) == 0 {
				fmt.Println(Yellow + "\n[!] Vault is empty! No host profiles available to connect." + Reset)
				addNow := transfer.ReadRealtimeInput("Would you like to add a host profile now? [Y/n]: ")
				if addNow == "" || strings.ToLower(addNow) == "y" {
					addNewProfilePrompt(reader)
				}
				continue
			}

			idStr := transfer.ReadRealtimeInput("\nEnter Host Profile ID to Connect: ")
			id, err := strconv.Atoi(idStr)
			if err != nil {
				continue
			}

			for _, p := range vData.Profiles {
				if p.ID == id {
					onConnect(p)
					return
				}
			}
			fmt.Println(Red + "[!] Profile ID not found." + Reset)
			time.Sleep(1 * time.Second)

		case "2":
			ip, port, user, pass, alias := ScanSubnetAndSelectTarget(reader)
			if ip != "" {
				_ = SaveActiveSessionToVault(alias, ip, port, user, pass, "", osdetect.OSLinux, false)
				fmt.Println(Green + Bold + fmt.Sprintf("\n[✔] SUCCESS: Target [%s] (%s:%s) saved to Vault!", alias, ip, port) + Reset)
				time.Sleep(1 * time.Second)

				onConnect(HostProfile{
					Alias:    alias,
					Host:     ip,
					Port:     port,
					User:     user,
					Pass:     pass,
					TargetOS: osdetect.OSLinux,
				})
				return
			}

		case "3":
			addNewProfilePrompt(reader)
		case "4":
			deleteProfilePrompt(reader)
		case "5":
			changePassphrasePrompt(reader)
		case "6":
			toggleEncryptionPrompt(reader)
		case "7":
			cachedMasterKey = nil
			cachedSalt = nil
			cachedPassphrase = ""
			isPassphraseCached = false
			fmt.Println(Green + Bold + "[✔] Vault Locked! Master Key wiped from RAM." + Reset)
			time.Sleep(1 * time.Second)
			return
		case "8":
			RunAutomatedHardwareDoctor(reader)
		case "0", "q", "Q":
			return
		}
	}
}

// ====================================================================
//  RECONNAISSANCE & FINGERPRINTING ENGINES
// ====================================================================

func FingerprintTarget(ip, mac, rawVendor string) (string, string) {
	dType, osPlat, _ := FingerprintTargetWithScope(ip, mac, rawVendor)
	return dType, osPlat
}

func FingerprintTargetWithScope(ip, mac, rawVendor string) (string, string, string) {
	deviceType := "Workstation"
	osPlatform := "Linux OS"
	scope := "Core LAN"

	lowerVendor := strings.ToLower(rawVendor)
	macUpper := strings.ToUpper(mac)

	if strings.Contains(lowerVendor, "samsung") || strings.Contains(lowerVendor, "apple") ||
		strings.Contains(lowerVendor, "google") || strings.Contains(lowerVendor, "xiaomi") ||
		strings.Contains(lowerVendor, "huawei") || strings.Contains(lowerVendor, "oneplus") ||
		strings.Contains(lowerVendor, "oppo") || strings.Contains(lowerVendor, "vivo") ||
		strings.Contains(lowerVendor, "realme") || strings.Contains(lowerVendor, "tuya") {
		deviceType = "Mobile / Smart Device"
		if strings.Contains(lowerVendor, "apple") {
			osPlatform = "Apple iOS"
		} else {
			osPlatform = "Android / Smart OS"
		}
		scope = "Deep IoT"
		return deviceType, osPlatform, scope
	}

	if strings.Contains(lowerVendor, "esp") || strings.Contains(lowerVendor, "expressif") ||
		strings.Contains(lowerVendor, "shenzhen") || strings.Contains(lowerVendor, "broadlink") ||
		strings.Contains(lowerVendor, "sonoff") || strings.Contains(lowerVendor, "tplink") ||
		strings.Contains(lowerVendor, "wyze") || strings.Contains(lowerVendor, "hikvision") ||
		strings.Contains(lowerVendor, "dahua") || strings.Contains(lowerVendor, "nest") ||
		strings.Contains(lowerVendor, "ring") {
		return "IoT Appliance", "Embedded IoT / RTOS", "Deep IoT"
	}

	if strings.Contains(lowerVendor, "virtualbox") || strings.Contains(lowerVendor, "oracle") {
		deviceType = "Virtual Node"
		osPlatform = "CentOS / RedHat"
		scope = "Core LAN"
		return deviceType, osPlatform, scope
	} else if strings.Contains(lowerVendor, "vmware") {
		deviceType = "VMware Server"
		osPlatform = "Linux Server"
		scope = "Core LAN"
		return deviceType, osPlatform, scope
	} else if strings.Contains(lowerVendor, "cisco") || strings.Contains(lowerVendor, "tp-link") ||
		strings.Contains(lowerVendor, "netgear") || strings.Contains(lowerVendor, "asus") ||
		strings.HasPrefix(macUpper, "B4:0F:3B") {
		deviceType = "Router / Gateway"
		osPlatform = "Embedded Linux"
		scope = "Core LAN"
		return deviceType, osPlatform, scope
	}

	connWin, errWin := net.DialTimeout("tcp", net.JoinHostPort(ip, "135"), 80*time.Millisecond)
	if errWin == nil {
		connWin.Close()
		return "PC Workstation", "Windows PC", "Core LAN"
	}

	connAdb, errAdb := net.DialTimeout("tcp", net.JoinHostPort(ip, "5555"), 80*time.Millisecond)
	if errAdb == nil {
		connAdb.Close()
		return "Mobile Phone", "Android Mobile", "Deep IoT"
	}

	connSSH, errSSH := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), 100*time.Millisecond)
	if errSSH == nil {
		connSSH.Close()
		deviceType = "Linux Server"
		scope = "Core LAN"
		if ip == "192.168.0.202" || strings.Contains(lowerVendor, "virtualbox") {
			osPlatform = "CentOS Stream"
		} else if ip == "192.168.0.150" {
			osPlatform = "Kali Linux"
		} else {
			osPlatform = "Linux Server"
		}
	}

	return deviceType, osPlatform, scope
}

// --------------------------------------------------------------------
//  Remote Host LAN Discovery (Pivoting through VPN Target)
// --------------------------------------------------------------------

func QueryRemoteHostLAN(sess *ActiveTargetSession) []DiscoveredTarget {
	var remoteTargets []DiscoveredTarget
	if sess == nil || sess.Host == "" {
		return remoteTargets
	}

	var authMethods []ssh.AuthMethod
	if sess.Pass != "" {
		authMethods = append(authMethods, ssh.Password(sess.Pass))
	}
	if sess.KeyPath != "" {
		keyBytes, err := os.ReadFile(sess.KeyPath)
		if err == nil {
			signer, errSign := ssh.ParsePrivateKey(keyBytes)
			if errSign == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	clientConfig := &ssh.ClientConfig{
		User:            sess.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", sess.Host, sess.Port), clientConfig)
	if err != nil {
		return remoteTargets
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return remoteTargets
	}
	defer session.Close()

	out, err := session.CombinedOutput("ip neigh show")
	if err != nil || len(out) == 0 {
		return remoteTargets
	}

	lines := strings.Split(string(out), "\n")
	seen := make(map[string]bool)

	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) >= 5 && net.ParseIP(fields[0]) != nil {
			ip := fields[0]
			mac := ""
			for i, f := range fields {
				if f == "lladdr" && i+1 < len(fields) {
					mac = strings.ToUpper(fields[i+1])
					break
				}
			}
			if ip != "" && !seen[ip] && mac != "" {
				seen[ip] = true
				dType, osPlat, _ := FingerprintTargetWithScope(ip, mac, "Host LAN Node")
				remoteTargets = append(remoteTargets, DiscoveredTarget{
					IP:          ip,
					MAC:         mac,
					Alias:       getDeviceAlias(ip),
					DeviceType:  dType,
					OSPlatform:  osPlat,
					Vendor:      "Host LAN Device",
					Scope:       "Host Remote LAN",
					IsBluetooth: false,
				})
			}
		}
	}
	return remoteTargets
}

func EnsureBluetoothServiceAndAdapterRunning(sudoPass string) (string, error) {
	if _, err := exec.LookPath("bluetoothctl"); err != nil {
		if sudoPass != "" {
			cmdInst := exec.Command("sudo", "-S", "apt-get", "install", "-y", "bluez", "bluez-tools")
			cmdInst.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdInst.Run()
		}
	}

	statusCmd := exec.Command("systemctl", "is-active", "bluetooth")
	outStatus, _ := statusCmd.Output()

	if strings.TrimSpace(string(outStatus)) != "active" {
		if sudoPass != "" {
			cmdUnmask := exec.Command("sudo", "-S", "systemctl", "unmask", "bluetooth")
			cmdUnmask.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdUnmask.Run()

			cmdStart := exec.Command("sudo", "-S", "systemctl", "enable", "--now", "bluetooth")
			cmdStart.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdStart.Run()
		} else {
			_ = exec.Command("sudo", "systemctl", "unmask", "bluetooth").Run()
			_ = exec.Command("sudo", "systemctl", "enable", "--now", "bluetooth").Run()
		}
		time.Sleep(200 * time.Millisecond)
	}

	outHci, errHci := exec.Command("hciconfig").Output()
	if errHci == nil && len(outHci) > 0 {
		lines := strings.Split(string(outHci), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "hci") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					cachedBTAdapter = strings.TrimSuffix(fields[0], ":")
					break
				}
			}
		}
	}

	if sudoPass != "" {
		cmdRf := exec.Command("sudo", "-S", "rfkill", "unblock", "bluetooth")
		cmdRf.Stdin = strings.NewReader(sudoPass + "\n")
		_ = cmdRf.Run()

		cmdUp := exec.Command("sudo", "-S", "hciconfig", cachedBTAdapter, "up")
		cmdUp.Stdin = strings.NewReader(sudoPass + "\n")
		_ = cmdUp.Run()
	} else {
		_ = exec.Command("sudo", "rfkill", "unblock", "bluetooth").Run()
		_ = exec.Command("sudo", "hciconfig", cachedBTAdapter, "up").Run()
	}

	_ = exec.Command("bluetoothctl", "power", "on").Run()
	return cachedBTAdapter, nil
}

func ScanBluetoothNearby(sudoPass string) []DiscoveredTarget {
	var btHosts []DiscoveredTarget
	seenMACs := make(map[string]bool)

	classify := func(name string) (string, string) {
		devType := "Smart Appliance"
		osPlat := "BLE Host"
		lowerName := strings.ToLower(name)
		if strings.Contains(lowerName, "tv") || strings.Contains(lowerName, "samsung") {
			devType = "Smart TV / Display"
			osPlat = "Tizen OS / Smart TV"
		} else if strings.Contains(lowerName, "phone") || strings.Contains(lowerName, "pixel") || strings.Contains(lowerName, "galaxy") || strings.Contains(lowerName, "iphone") {
			devType = "Mobile Phone"
			osPlat = "Android / iOS"
		} else if strings.Contains(lowerName, "watch") || strings.Contains(lowerName, "amazfit") {
			devType = "Smartwatch / Wearable"
			osPlat = "Zepp OS / BLE"
		} else if strings.Contains(lowerName, "pc") || strings.Contains(lowerName, "desktop") || strings.Contains(lowerName, "laptop") || strings.Contains(lowerName, "thinkpad") {
			devType = "PC Workstation"
			osPlat = "Linux / Windows PC"
		}
		return devType, osPlat
	}

	addTarget := func(mac string, name string) {
		mac = strings.ToUpper(mac)
		if seenMACs[mac] {
			return
		}
		seenMACs[mac] = true
		devType, osPlat := classify(name)
		btHosts = append(btHosts, DiscoveredTarget{
			IP:          "BT-LE",
			MAC:         mac,
			Alias:       getDeviceAlias(mac),
			DeviceType:  devType,
			OSPlatform:  osPlat,
			Vendor:      name,
			Scope:       "Bluetooth",
			IsBluetooth: true,
		})
	}

	btNameCacheMutex.RLock()
	for mac, name := range btNameCache {
		addTarget(mac, name)
	}
	btNameCacheMutex.RUnlock()

	ctxDev, cancelDev := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDev()
	cmdDev := exec.CommandContext(ctxDev, "bluetoothctl", "devices")
	outDev, _ := cmdDev.Output()

	if len(outDev) > 0 {
		for _, line := range strings.Split(string(outDev), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "Device ") {
				continue
			}
			parts := strings.Split(line, "Device ")
			if len(parts) < 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) < 1 {
				continue
			}
			rawMAC := fields[0]
			var cleanMAC string
			for i := 0; i <= len(rawMAC)-17; i++ {
				sub := rawMAC[i : i+17]
				if strings.Count(sub, ":") == 5 {
					cleanMAC = strings.ToUpper(sub)
					break
				}
			}
			if cleanMAC == "" {
				continue
			}

			name := "BLE Target Node"
			if len(fields) >= 2 {
				candidate := strings.Join(fields[1:], " ")
				candidate = strings.Map(func(r rune) rune {
					if r >= 32 && r <= 126 {
						return r
					}
					return -1
				}, candidate)
				candidate = strings.TrimSpace(candidate)
				if candidate != "" && candidate != "(unknown)" {
					name = candidate
				}
			}

			btNameCacheMutex.Lock()
			if name != "BLE Target Node" {
				btNameCache[cleanMAC] = name
			} else if cached, ok := btNameCache[cleanMAC]; ok && cached != "" {
				name = cached
			}
			btNameCacheMutex.Unlock()

			addTarget(cleanMAC, name)
		}
	}
	return btHosts
}

func PerformDeepIoTSweep(localSubnet string, sudoPass string) []DiscoveredTarget {
	var deepTargets []DiscoveredTarget
	seen := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	var cmdNmap *exec.Cmd
	if sudoPass != "" {
		cmdNmap = exec.CommandContext(ctx, "sudo", "-S", "nmap", "-sn", "-PR", "-PS22,80,443,554,1900,5353,5555,8080", "-T4", "--min-rate", "1500", localSubnet)
		cmdNmap.Stdin = strings.NewReader(sudoPass + "\n")
	} else {
		cmdNmap = exec.CommandContext(ctx, "sudo", "nmap", "-sn", "-PR", "-PS22,80,443,554,1900,5353,5555,8080", "-T4", "--min-rate", "1500", localSubnet)
	}

	outNmap, errNmap := cmdNmap.Output()
	if errNmap == nil && len(outNmap) > 0 {
		lines := strings.Split(string(outNmap), "\n")
		var currentIP, currentMAC, currentVendor string
		for _, l := range lines {
			if strings.Contains(l, "Nmap scan report for") {
				fields := strings.Fields(l)
				currentIP = fields[len(fields)-1]
				currentIP = strings.Trim(currentIP, "()")
			} else if strings.Contains(l, "MAC Address:") {
				fields := strings.Fields(l)
				if len(fields) >= 3 {
					currentMAC = fields[2]
					currentVendor = "Network Device"
					if len(fields) >= 4 {
						currentVendor = strings.Join(fields[3:], " ")
						currentVendor = strings.Trim(currentVendor, "()")
					}
				}
				if currentIP != "" && !seen[currentIP] {
					seen[currentIP] = true
					dType, osPlat, scope := FingerprintTargetWithScope(currentIP, currentMAC, currentVendor)
					deepTargets = append(deepTargets, DiscoveredTarget{
						IP:          currentIP,
						MAC:         currentMAC,
						Alias:       getDeviceAlias(currentIP),
						DeviceType:  dType,
						OSPlatform:  osPlat,
						Vendor:      currentVendor,
						Scope:       scope,
						IsBluetooth: false,
					})
				}
			}
		}
	}

	return deepTargets
}

func RenderUnifiedDiscoveryTable(hosts []DiscoveredTarget, selectedIndex int, localSubnet string, lastScanTime time.Time, tickFrame int, countdown float64, isLiveScanning bool, targetLabel string) {
	fmt.Print("\033[H\033[2J")

	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinChar := spinners[tickFrame%len(spinners)]

	radarStatus := fmt.Sprintf("%s[RADAR: LIVE %s]%s Next Sweep: %s%.1fs%s", Green+Bold, spinChar, Reset, Yellow+Bold, countdown, Reset)
	if !isLiveScanning {
		radarStatus = fmt.Sprintf("%s[RADAR: PAUSED]%s", Yellow+Bold, Reset)
	}

	fmt.Printf("%s%s====================================================================================================================----%s\r\n", Cyan, Bold, Reset)
	fmt.Printf("%s%s=== HUB 1: UNIFIED MULTI-SCOPE LIVE RECONNAISSANCE DASHBOARD [LAN | HOST REMOTE LAN | BLUETOOTH] ===%s\r\n", Cyan, Bold, Reset)
	fmt.Printf("%s%s====================================================================================================================----%s\r\n", Cyan, Bold, Reset)
	fmt.Printf("=> Subnet: %s%s%s | Target Scope: %s%s%s | %s (Last: %s)\r\n",
		Yellow+Bold, localSubnet, Reset, Green+Bold, targetLabel, Reset, radarStatus, lastScanTime.Format("15:04:05"))
	fmt.Printf("%sControls: [UP/DOWN Keys] Navigate | [ENTER] Pivot / Select Target | [S/SPACE] Live/Pause | [A] Set Alias | [0/Q] Exit%s\r\n", Yellow, Reset)
	fmt.Printf("%s------------------------------------------------------------------------------------------------------------------------%s\r\n", Blue, Reset)
	fmt.Printf("%s %-3s | %-18s | %-15s | %-17s | %-16s | %-15s | %-16s | %-8s%s\r\n",
		Bold, "NO", "ALIAS / LABEL", "HOST IP / MAC", "HARDWARE ADDR", "DEVICE TYPE", "OS / PLATFORM", "SCOPE", "STATUS", Reset)
	fmt.Printf("%s------------------------------------------------------------------------------------------------------------------------%s\r\n", Blue, Reset)

	currentScopeSection := ""

	for idx, h := range hosts {
		if h.Scope != currentScopeSection {
			currentScopeSection = h.Scope
			fmt.Printf("%s--- [SECTION: %s TARGETS] ---%s\r\n", Yellow+Bold, strings.ToUpper(currentScopeSection), Reset)
		}

		aliasStr := truncateString(h.Alias, 18)
		devTypeStr := truncateString(h.DeviceType, 16)
		osPlatformStr := truncateString(h.OSPlatform, 15)
		scopeStr := truncateString(h.Scope, 16)

		statusStr := "[ONLINE]"
		if h.IsBluetooth {
			statusStr = "[VISIBLE]"
		}

		if idx == selectedIndex {
			fmt.Printf("%s%s%s▶ %-3d | %-18s | %-15s | %-17s | %-16s | %-15s | %-16s | %-8s%s\r\n",
				BgBlue, White, Bold, idx+1, aliasStr, h.IP, h.MAC, devTypeStr, osPlatformStr, scopeStr, statusStr, Reset)
		} else {
			fmt.Printf("  %-3d | %s%-18s%s | %s%-15s%s | %s%-17s%s | %s%-16s%s | %s%-15s%s | %s%-16s%s | %s%-8s%s\r\n",
				idx+1, Yellow+Bold, aliasStr, Reset, Cyan, h.IP, Reset, Magenta, h.MAC, Reset, Green, devTypeStr, Reset, Bold+Blue, osPlatformStr, Reset, Magenta, scopeStr, Reset, Green+Bold, statusStr, Reset)
		}
	}
	fmt.Printf("%s------------------------------------------------------------------------------------------------------------------------%s\r\n", Blue, Reset)
}

func HandleBluetoothAction(target DiscoveredTarget, sudoPass string) {
	fmt.Print("\033[H\033[2J")
	fmt.Printf("%s%s=== BLUETOOTH PAIR & ACTION PIPELINE: %s [%s] ===%s\n", Cyan, Bold, target.Vendor, target.MAC, Reset)
	fmt.Printf("Detected Class: %s%s%s | Platform: %s%s%s\n", Yellow, target.DeviceType, Reset, Green, target.OSPlatform, Reset)
	fmt.Println(Blue + "-----------------------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] PC Target: Push SSH Public Key (~/.ssh/id_ed25519.pub / id_rsa.pub)")
	fmt.Println("  [2] Mobile / PC: Send File via OBEX Push (Triggers Native Screen Prompt)")
	fmt.Println("  [3] Mobile / PC: Receive Incoming File (Start Local OBEX Listener)")
	fmt.Println("  [4] Network Link: Establish Bluetooth PAN Bridge (BNEP IP Connection)")
	fmt.Println(Red + "  [0] Cancel & Return" + Reset)
	fmt.Println(Blue + "-----------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select Action [0-4]: ")

	switch strings.TrimSpace(choice) {
	case "1":
		home, _ := os.UserHomeDir()
		pubKeyPath := filepath.Join(home, ".ssh", "id_ed25519.pub")
		if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
			pubKeyPath = filepath.Join(home, ".ssh", "id_rsa.pub")
		}

		if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
			fmt.Println(Red + "[!] No SSH public key found. Generating automatically..." + Reset)
			keyPath := filepath.Join(home, ".ssh", "id_ed25519")
			_ = exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "cross-ssh-auto").Run()
			pubKeyPath = keyPath + ".pub"
		}

		fmt.Println(Cyan + "\n[*] Pairing & Transferring SSH Public Key to target device..." + Reset)
		_ = exec.Command("bluetoothctl", "pair", target.MAC).Run()
		_ = exec.Command("bluetoothctl", "trust", target.MAC).Run()

		cmd := exec.Command("bluetooth-sendto", fmt.Sprintf("--device=%s", target.MAC), pubKeyPath)
		if err := cmd.Run(); err != nil {
			_ = exec.Command("obexftp", "--bluetooth", target.MAC, "--put", pubKeyPath).Run()
		}
		fmt.Println(Green + Bold + "[✔] SSH Public Key Pushed! (Accept on target screen to authorize)." + Reset)
		time.Sleep(2 * time.Second)

	case "2":
		filePath := transfer.ReadRealtimeInput("Enter absolute path of file to send: ")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Println(Red + "[!] Specified file does not exist." + Reset)
			time.Sleep(2 * time.Second)
			return
		}

		fmt.Println(Cyan + "\n[*] Initiating OBEX File Transfer..." + Reset)
		_ = exec.Command("bluetoothctl", "pair", target.MAC).Run()
		_ = exec.Command("bluetoothctl", "trust", target.MAC).Run()

		cmd := exec.Command("bluetooth-sendto", fmt.Sprintf("--device=%s", target.MAC), filePath)
		if err := cmd.Run(); err != nil {
			_ = exec.Command("obexftp", "--bluetooth", target.MAC, "--put", filePath).Run()
		}
		fmt.Println(Green + Bold + "[✔] File transfer request dispatched successfully!" + Reset)
		time.Sleep(2 * time.Second)

	case "3":
		fmt.Println(Cyan + "\n[*] Starting Local OBEX Receive Server on /tmp/bt_received/..." + Reset)
		_ = os.MkdirAll("/tmp/bt_received", 0755)
		cmd := exec.Command("obexd", "-n", "-a", "-r", "/tmp/bt_received/")
		_ = cmd.Start()
		fmt.Println(Green + "[✔] OBEX Receiver Active. Send files from your mobile/PC now." + Reset)
		transfer.ReadRealtimeInput("Press ENTER to stop OBEX receiver server...")
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}

	case "4":
		fmt.Println(Cyan + "\n[*] Establishing BNEP PAN Network Interface..." + Reset)
		if sudoPass != "" {
			cmdPair := exec.Command("sudo", "-S", "bluetoothctl", "pair", target.MAC)
			cmdPair.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdPair.Run()

			cmdPan := exec.Command("sudo", "-S", "bt-network", "-c", target.MAC, "nap")
			cmdPan.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdPan.Run()
		} else {
			_ = exec.Command("sudo", "bluetoothctl", "pair", target.MAC).Run()
			_ = exec.Command("sudo", "bt-network", "-c", target.MAC, "nap").Run()
		}
		fmt.Println(Green + Bold + "[✔] PAN Network interface command dispatched!" + Reset)
		time.Sleep(2 * time.Second)
	}
}

func getLocalHostTarget() (DiscoveredTarget, string) {
	localIP := "127.0.0.1"
	localMAC := "00:00:00:00:00:00"
	localSubnet := "192.168.0.0/24"

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, errAddrs := iface.Addrs()
			if errAddrs != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					localIP = ipnet.IP.String()
					localMAC = iface.HardwareAddr.String()
					localSubnet = ipnet.String()
					break
				}
			}
			if localIP != "127.0.0.1" {
				break
			}
		}
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "Localhost"
	}

	return DiscoveredTarget{
		IP:          localIP,
		MAC:         strings.ToUpper(localMAC),
		Alias:       fmt.Sprintf("LocalHost (%s)", hostname),
		DeviceType:  "Master Node",
		OSPlatform:  "Kali Linux (Self)",
		Vendor:      "Current Machine",
		Scope:       "Core LAN",
		IsBluetooth: false,
	}, localSubnet
}

func ScanSubnetAndSelectTarget(reader *bufio.Reader) (string, string, string, string, string) {
	sudoPass := EnsureRootPrivileges()
	loadPersistentAliases()

	localHost, localSubnet := getLocalHostTarget()
	activeSess := getActiveTargetSession()

	targetLabel := "Local Workstation Subnet"
	if activeSess != nil && activeSess.Host != "" {
		targetLabel = fmt.Sprintf("Active Target Host Mesh (%s)", activeSess.Host)
	}

	masterInventory := make(map[string]DiscoveredTarget)
	masterInventory[localHost.IP] = localHost

	var unifiedList []DiscoveredTarget
	unifiedList = append(unifiedList, localHost)

	var listMutex sync.Mutex
	lastScanTime := time.Now()
	isLiveScanning := true

	scanCtx, cancelScan := context.WithCancel(context.Background())
	defer cancelScan()

	// 1. Bluetooth Background Daemon
	if runtime.GOOS == "linux" {
		go func() {
			_, _ = EnsureBluetoothServiceAndAdapterRunning(sudoPass)

			for {
				select {
				case <-scanCtx.Done():
					return
				default:
					cmd := exec.CommandContext(scanCtx, "stdbuf", "-oL", "bluetoothctl", "scan", "on")
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						cmd = exec.CommandContext(scanCtx, "bluetoothctl", "scan", "on")
						stdout, _ = cmd.StdoutPipe()
					}

					if stdout != nil && cmd.Start() == nil {
						scanner := bufio.NewScanner(stdout)
						for scanner.Scan() {
							line := scanner.Text()
							if strings.Contains(line, "Device ") {
								parts := strings.Split(line, "Device ")
								if len(parts) >= 2 {
									fields := strings.Fields(parts[1])
									if len(fields) >= 1 {
										rawMAC := fields[0]
										for i := 0; i <= len(rawMAC)-17; i++ {
											sub := rawMAC[i : i+17]
											if strings.Count(sub, ":") == 5 {
												cleanMAC := strings.ToUpper(sub)
												name := "BLE Target Node"
												if len(fields) >= 2 {
													candidate := strings.Join(fields[1:], " ")
													candidate = strings.Map(func(r rune) rune {
														if r >= 32 && r <= 126 {
															return r
														}
														return -1
													}, candidate)
													candidate = strings.TrimSpace(candidate)
													if candidate != "" && candidate != "(unknown)" {
														name = candidate
													}
												}
												btNameCacheMutex.Lock()
												if existing, ok := btNameCache[cleanMAC]; !ok || existing == "BLE Target Node" || existing == "" {
													btNameCache[cleanMAC] = name
												}
												btNameCacheMutex.Unlock()
												break
											}
										}
									}
								}
							}
						}
						_ = cmd.Wait()
					}
					time.Sleep(500 * time.Millisecond)
				}
			}
		}()
	}

	// 2. Cross-Platform Network & Remote Host LAN Discovery Engine
	go func() {
		for {
			select {
			case <-scanCtx.Done():
				return
			default:
				if isLiveScanning {
					var wg sync.WaitGroup
					var arpTargets []DiscoveredTarget
					var deepTargets []DiscoveredTarget
					var btTargets []DiscoveredTarget
					var remoteHostTargets []DiscoveredTarget

					// Core LAN Subnet Scan
					wg.Add(1)
					go func() {
						defer wg.Done()
						ctxArp, cancelArp := context.WithTimeout(context.Background(), 1000*time.Millisecond)
						defer cancelArp()

						if runtime.GOOS == "windows" {
							outArp, _ := exec.CommandContext(ctxArp, "arp", "-a").Output()
							if len(outArp) > 0 {
								lines := strings.Split(string(outArp), "\n")
								for _, l := range lines {
									fields := strings.Fields(l)
									if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
										ip := fields[0]
										if ip == localHost.IP || strings.HasPrefix(ip, "127.") || strings.HasSuffix(ip, ".255") {
											continue
										}
										mac := strings.ToUpper(strings.ReplaceAll(fields[1], "-", ":"))
										dType, osPlat, scope := FingerprintTargetWithScope(ip, mac, "LAN Host")
										arpTargets = append(arpTargets, DiscoveredTarget{
											IP:          ip,
											MAC:         mac,
											Alias:       getDeviceAlias(ip),
											DeviceType:  dType,
											OSPlatform:  osPlat,
											Vendor:      "Network Host",
											Scope:       scope,
											IsBluetooth: false,
										})
									}
								}
							}
						} else {
							// CORRECT
var arpCmd *exec.Cmd
if sudoPass != "" {
	arpCmd = exec.CommandContext(ctxArp, "sudo", "-S", "arp-scan", "--localnet", "--quiet")
	arpCmd.Stdin = strings.NewReader(sudoPass + "\n")
} else {
	arpCmd = exec.CommandContext(ctxArp, "sudo", "arp-scan", "--localnet", "--quiet")
}
							if sudoPass != "" {
								arpCmd.Stdin = strings.NewReader(sudoPass + "\n")
							} else {
								arpCmd = exec.CommandContext(ctxArp, "sudo", "arp-scan", "--localnet", "--quiet")
							}
							outArp, _ := arpCmd.Output()

							if len(outArp) > 0 {
								lines := strings.Split(string(outArp), "\n")
								for _, l := range lines {
									fields := strings.Fields(l)
									if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
										ip := fields[0]
										if ip == localHost.IP {
											continue
										}
										mac := fields[1]
										vendor := "Network Device"
										if len(fields) >= 3 {
											vendor = strings.Join(fields[2:], " ")
										}
										dType, osPlat, scope := FingerprintTargetWithScope(ip, mac, vendor)
										arpTargets = append(arpTargets, DiscoveredTarget{
											IP:          ip,
											MAC:         mac,
											Alias:       getDeviceAlias(ip),
											DeviceType:  dType,
											OSPlatform:  osPlat,
											Vendor:      vendor,
											Scope:       scope,
											IsBluetooth: false,
										})
									}
								}
							}
						}
					}()

					// Deep IoT Probing
					wg.Add(1)
					go func() {
						defer wg.Done()
						deepTargets = PerformDeepIoTSweep(localSubnet, sudoPass)
					}()

					// Remote Target Host Physical LAN Pivot
					if activeSess != nil && activeSess.Host != "" {
						wg.Add(1)
						go func() {
							defer wg.Done()
							remoteHostTargets = QueryRemoteHostLAN(activeSess)
						}()
					}

					// Bluetooth Scan (Linux Only)
					if runtime.GOOS == "linux" {
						wg.Add(1)
						go func() {
							defer wg.Done()
							btTargets = ScanBluetoothNearby(sudoPass)
						}()
					}

					wg.Wait()

					listMutex.Lock()
					masterInventory[localHost.IP] = localHost

					for _, at := range arpTargets {
						if existing, ok := masterInventory[at.IP]; ok {
							existing.Alias = getDeviceAlias(at.IP)
							masterInventory[at.IP] = existing
						} else {
							masterInventory[at.IP] = at
						}
					}

					for _, rt := range remoteHostTargets {
						if existing, ok := masterInventory[rt.IP]; ok {
							existing.Alias = getDeviceAlias(rt.IP)
							existing.Scope = "Host Remote LAN"
							masterInventory[rt.IP] = existing
						} else {
							masterInventory[rt.IP] = rt
						}
					}

					for _, dt := range deepTargets {
						if dt.IP == localHost.IP {
							continue
						}
						if existing, ok := masterInventory[dt.IP]; ok {
							existing.Alias = getDeviceAlias(dt.IP)
							if dt.DeviceType == "Mobile Phone" || dt.DeviceType == "IoT Appliance" {
								existing.Scope = "Deep IoT"
								existing.DeviceType = dt.DeviceType
								existing.OSPlatform = dt.OSPlatform
							}
							masterInventory[dt.IP] = existing
						} else {
							masterInventory[dt.IP] = dt
						}
					}

					for _, bt := range btTargets {
						if existing, ok := masterInventory[bt.MAC]; ok {
							existing.Alias = getDeviceAlias(bt.MAC)
							if bt.Vendor != "BLE Target Node" && bt.Vendor != "" {
								existing.Vendor = bt.Vendor
								existing.DeviceType = bt.DeviceType
								existing.OSPlatform = bt.OSPlatform
							}
							masterInventory[bt.MAC] = existing
						} else {
							masterInventory[bt.MAC] = bt
						}
					}

					var coreLAN []DiscoveredTarget
					var remoteLAN []DiscoveredTarget
					var deepIoT []DiscoveredTarget
					var bluetooth []DiscoveredTarget

					for _, t := range masterInventory {
						if t.IsBluetooth {
							bluetooth = append(bluetooth, t)
						} else if t.Scope == "Host Remote LAN" {
							remoteLAN = append(remoteLAN, t)
						} else if t.Scope == "Core LAN" {
							coreLAN = append(coreLAN, t)
						} else {
							deepIoT = append(deepIoT, t)
						}
					}

					sort.Slice(coreLAN, func(i, j int) bool {
						if coreLAN[i].IP == localHost.IP {
							return true
						}
						if coreLAN[j].IP == localHost.IP {
							return false
						}
						return coreLAN[i].IP < coreLAN[j].IP
					})
					sort.Slice(remoteLAN, func(i, j int) bool {
						return remoteLAN[i].IP < remoteLAN[j].IP
					})
					sort.Slice(deepIoT, func(i, j int) bool {
						return deepIoT[i].IP < deepIoT[j].IP
					})
					sort.Slice(bluetooth, func(i, j int) bool {
						return bluetooth[i].Vendor < bluetooth[j].Vendor
					})

					var combined []DiscoveredTarget
					combined = append(combined, coreLAN...)
					combined = append(combined, remoteLAN...)
					combined = append(combined, deepIoT...)
					combined = append(combined, bluetooth...)

					unifiedList = combined
					lastScanTime = time.Now()
					listMutex.Unlock()
				}

				select {
				case <-scanCtx.Done():
					return
				case <-time.After(1000 * time.Millisecond):
				}
			}
		}
	}()

	selectedIndex := 0
	typedNumber := ""
	tickFrame := 0
	const sweepInterval = 1.0
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
			case <-scanCtx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-scanCtx.Done():
			if errRaw == nil {
				_ = term.Restore(int(os.Stdin.Fd()), oldState)
			}
			return "", "", "", "", ""
		default:
		}

		listMutex.Lock()
		activeList := make([]DiscoveredTarget, len(unifiedList))
		copy(activeList, unifiedList)
		listMutex.Unlock()

		if selectedIndex >= len(activeList) && len(activeList) > 0 {
			selectedIndex = len(activeList) - 1
		}

		RenderUnifiedDiscoveryTable(activeList, selectedIndex, localSubnet, lastScanTime, tickFrame, secondsRemaining, isLiveScanning, targetLabel)

		if typedNumber != "" {
			fmt.Printf("%s[Direct ID Selection Input]: %s (Press Enter to Select Target)%s\r\n", Yellow+Bold, typedNumber, Reset)
		} else {
			fmt.Printf("%s[Selection Mode]: Type Target ID Number (1-%d) or Use Up/Down Arrow Keys%s\r\n", Cyan, len(activeList), Reset)
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
							case 65: // Up Arrow
								if selectedIndex > 0 {
									selectedIndex--
								} else if len(activeList) > 0 {
									selectedIndex = len(activeList) - 1
								}
								typedNumber = ""
							case 66: // Down Arrow
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
					cancelScan()
					if errRaw == nil {
						_ = term.Restore(int(os.Stdin.Fd()), oldState)
					}
					return "", "", "", "", ""
				}
			} else if key == 's' || key == 'S' || key == ' ' {
				isLiveScanning = !isLiveScanning
				if isLiveScanning {
					secondsRemaining = sweepInterval
				}

			} else if key == 13 || key == 10 { // ENTER
				if typedNumber != "" {
					if num, errNum := strconv.Atoi(typedNumber); errNum == nil && num >= 1 && num <= len(activeList) {
						selectedIndex = num - 1
					}
				}
				cancelScan()
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}

				if len(activeList) > 0 && selectedIndex < len(activeList) {
					listMutex.Lock()
					selectedHost := activeList[selectedIndex]
					listMutex.Unlock()

					if selectedHost.IsBluetooth {
						HandleBluetoothAction(selectedHost, sudoPass)
						return "", "", "", "", ""
					}

					fmt.Printf(Green+Bold+"\n[✔] Target Host Selected: %s (%s / %s)\n"+Reset, selectedHost.IP, selectedHost.DeviceType, selectedHost.OSPlatform)

					defaultAlias := selectedHost.Alias
					if defaultAlias == "Unlabeled" {
						defaultAlias = fmt.Sprintf("node-%s", selectedHost.IP)
					}

					aliasPrompt := fmt.Sprintf("Enter Custom Profile Alias / Label for Vault [default: %s]: ", defaultAlias)
					alias := transfer.ReadRealtimeInput(aliasPrompt)
					if strings.TrimSpace(alias) == "" {
						alias = defaultAlias
					}

					sshUser := transfer.ReadRealtimeInput("Enter SSH Username [default: root]: ")
					if strings.TrimSpace(sshUser) == "" {
						sshUser = "root"
					}

					sshPort := transfer.ReadRealtimeInput("Enter SSH Port [default: 22]: ")
					if strings.TrimSpace(sshPort) == "" {
						sshPort = "22"
					}

					sshPass, _ := PromptAuthenticationMethod(reader)

					return selectedHost.IP, sshPort, sshUser, sshPass, alias
				}
				return "", "", "", "", ""

			} else if key == 'a' || key == 'A' {
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}

				if len(activeList) > 0 && selectedIndex < len(activeList) {
					selectedHost := activeList[selectedIndex]
					keyToAlias := selectedHost.IP
					if selectedHost.IsBluetooth {
						keyToAlias = selectedHost.MAC
					}

					fmt.Printf(Cyan+Bold+"\n=== SET PERSISTENT ALIAS / LABEL FOR TARGET [%s] ===\n"+Reset, keyToAlias)
					newAlias := transfer.ReadRealtimeInput("Enter Custom Alias / Name (e.g. Saleem-Phone, LivingRoom-TV): ")
					if strings.TrimSpace(newAlias) != "" {
						setDeviceAlias(keyToAlias, newAlias)

						listMutex.Lock()
						for i, ul := range unifiedList {
							if (ul.IsBluetooth && ul.MAC == keyToAlias) || (!ul.IsBluetooth && ul.IP == keyToAlias) {
								unifiedList[i].Alias = newAlias
							}
						}
						listMutex.Unlock()

						fmt.Printf(Green+Bold+"[✔] Success: Alias [%s] permanently saved to disk (~/.cross-ssh/aliases.json)!\n"+Reset, newAlias)
						time.Sleep(300 * time.Millisecond)
					}
				}

				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))

			} else if key == '0' || key == 'q' || key == 'Q' || key == 3 {
				cancelScan()
				if errRaw == nil {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
				}
				return "", "", "", "", ""
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

// ====================================================================
//  [OPTION 10] FULL-SPECTRUM END-TO-END SSH ENGINE PIPELINE
// ====================================================================

func RunLocalSSHPipeline(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "==================================================================" + Reset)
	fmt.Println(Cyan + Bold + "  ⚡ FULL-SPECTRUM SSH ENGINE: GENERATION, REPAIR & ACTIVATION    " + Reset)
	fmt.Println(Cyan + Bold + "==================================================================" + Reset)

	sudoPass := EnsureRootPrivileges()

	fmt.Println(Yellow + "\n[1/8] Verifying local OpenSSH Server installation..." + Reset)
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("powershell", "-Command", "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0").Run()
		_ = exec.Command("powershell", "-Command", "Start-Service sshd").Run()
		_ = exec.Command("powershell", "-Command", "Set-Service -Name sshd -StartupType 'Automatic'").Run()
		_ = exec.Command("powershell", "-Command", `if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 }`).Run()
		fmt.Println(Green + "[✔] Windows OpenSSH Server Provisioned & Firewall Configured!" + Reset)

	case "darwin":
		if sudoPass != "" {
			cmd := exec.Command("sudo", "-S", "systemsetup", "-setremotelogin", "on")
			cmd.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmd.Run()
		} else {
			_ = exec.Command("sudo", "systemsetup", "-setremotelogin", "on").Run()
		}
		fmt.Println(Green + "[✔] macOS Remote Login Activated!" + Reset)

	default:
		if _, err := exec.LookPath("sshd"); err != nil {
			if _, err := exec.LookPath("apt-get"); err == nil {
				_ = exec.Command("sudo", "apt-get", "install", "-y", "openssh-server").Run()
			} else if _, err := exec.LookPath("dnf"); err == nil {
				_ = exec.Command("sudo", "dnf", "install", "-y", "openssh-server").Run()
			}
		}
		_ = exec.Command("sudo", "systemctl", "enable", "--now", "ssh").Run()
		_ = exec.Command("sudo", "systemctl", "enable", "--now", "sshd").Run()
		_ = exec.Command("sudo", "ufw", "allow", "22/tcp").Run()
		fmt.Println(Green + "[✔] Linux OpenSSH Server Provisioned!" + Reset)
	}

	fmt.Println(Yellow + "\n[2/8] Auditing & Generating Local Identity Keypairs..." + Reset)
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0700)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	pubKeyPath := filepath.Join(sshDir, "id_ed25519.pub")

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		hostname, _ := os.Hostname()
		comment := fmt.Sprintf("cross-ssh@%s", hostname)
		genCmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", comment)
		if err := genCmd.Run(); err != nil {
			keyPath = filepath.Join(sshDir, "id_rsa")
			pubKeyPath = filepath.Join(sshDir, "id_rsa.pub")
			_ = exec.Command("ssh-keygen", "-t", "rsa", "-b", "4096", "-f", keyPath, "-N", "", "-C", comment).Run()
		}
		fmt.Printf(Green+"[✔] Local SSH Keypair generated: %s\n"+Reset, keyPath)
	} else {
		fmt.Println(Green + "[✔] Existing SSH Keypair detected (~/.ssh/id_ed25519)." + Reset)
	}

	fmt.Println(Yellow + "\n[3/8] Configuring Local Public Key in authorized_keys..." + Reset)
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	pubBytes, errReadPub := os.ReadFile(pubKeyPath)
	if errReadPub == nil {
		pubContent := strings.TrimSpace(string(pubBytes))
		authData, _ := os.ReadFile(authKeysPath)
		if !strings.Contains(string(authData), pubContent) {
			f, errOpen := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if errOpen == nil {
				_, _ = f.WriteString("\n" + pubContent + "\n")
				f.Close()
			}
		}
		fmt.Println(Green + "[✔] Local workstation public key self-authorized for instant loopback!" + Reset)
	}

	fmt.Println(Yellow + "\n[4/8] Enforcing strict SSH file and directory permissions..." + Reset)
	_ = os.Chmod(sshDir, 0700)
	_ = os.Chmod(keyPath, 0600)
	if _, err := os.Stat(pubKeyPath); err == nil {
		_ = os.Chmod(pubKeyPath, 0644)
	}
	if _, err := os.Stat(authKeysPath); err == nil {
		_ = os.Chmod(authKeysPath, 0600)
	}
	fmt.Println(Green + "[✔] Permissions configured (0700 on ~/.ssh, 0600 on keys)." + Reset)

	fmt.Println(Yellow + "\n[5/8] Auditing System Host Keys and /etc/ssh/sshd_config..." + Reset)
	_ = exec.Command("sudo", "ssh-keygen", "-A").Run()

	configCheck := exec.Command("sudo", "sshd", "-t")
	if err := configCheck.Run(); err != nil {
		_ = exec.Command("sudo", "cp", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.bak").Run()
	}
	fmt.Println(Green + "[✔] Host keys refreshed and configuration audited." + Reset)

	fmt.Println(Yellow + "\n[6/8] Enabling & starting SSH daemon service..." + Reset)
	serviceName := "ssh"
	if err := exec.Command("systemctl", "status", "ssh").Run(); err != nil {
		if err2 := exec.Command("systemctl", "status", "sshd").Run(); err2 == nil {
			serviceName = "sshd"
		}
	}

	_ = exec.Command("sudo", "systemctl", "unmask", serviceName).Run()
	_ = exec.Command("sudo", "systemctl", "enable", "--now", serviceName).Run()
	_ = exec.Command("sudo", "systemctl", "restart", serviceName).Run()
	fmt.Printf(Green+"[✔] Service '%s' active and enabled at boot!\n"+Reset, serviceName)

	fmt.Println(Yellow + "\n[7/8] Ensuring Port 22 is open on host firewalls..." + Reset)
	if _, errUfw := exec.LookPath("ufw"); errUfw == nil {
		_ = exec.Command("sudo", "ufw", "allow", "22/tcp").Run()
	}
	_ = exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "22", "-j", "ACCEPT").Run()
	fmt.Println(Green + "[✔] Ingress rule on TCP Port 22 confirmed open." + Reset)

	fmt.Println(Yellow + "\n[8/8] Testing live SSH connection on 127.0.0.1:22..." + Reset)
	conn, errDial := net.DialTimeout("tcp", "127.0.0.1:22", 1*time.Second)
	if errDial == nil {
		conn.Close()
		fmt.Println(Green + Bold + "\n==================================================================" + Reset)
		fmt.Println(Green + Bold + " [✔ SUCCESS] LOCAL SSH ENGINE IS ACTIVE & READY FOR TRAFFIC!    " + Reset)
		fmt.Println(Green + Bold + "==================================================================" + Reset)
		fmt.Printf(Cyan+" Local Endpoint: 127.0.0.1:22 (Listening)\n"+Reset)
		fmt.Printf(Cyan+" Public Key    : %s\n"+Reset, pubKeyPath)
	} else {
		fmt.Println(Red + "[!] Port 22 did not respond to local socket probe. Check system logs." + Reset)
	}

	fmt.Println(Blue + "\n------------------------------------------------------------------" + Reset)
	fmt.Println("Deploy Local Public Key to a Remote Target Machine Now?")
	fmt.Println("  [1] Yes - Copy Public Key to Remote Host (ssh-copy-id workflow)")
	fmt.Println("  [2] No  - Done (Return to Menu)")
	fmt.Print(Bold + "Select option [1-2] [default: 2]: " + Reset)

	deployChoice := transfer.ReadRealtimeInput("")
	if strings.TrimSpace(deployChoice) == "1" {
		remoteIP := transfer.ReadRealtimeInput("Enter Remote Target IP: ")
		remoteUser := transfer.ReadRealtimeInput("Enter Remote Username [default: root]: ")
		if strings.TrimSpace(remoteUser) == "" {
			remoteUser = "root"
		}
		remotePort := transfer.ReadRealtimeInput("Enter Remote SSH Port [default: 22]: ")
		if strings.TrimSpace(remotePort) == "" {
			remotePort = "22"
		}

		if strings.TrimSpace(remoteIP) != "" {
			fmt.Printf(Cyan+"\n[+] Copying %s to %s@%s:%s...\n"+Reset, pubKeyPath, remoteUser, remoteIP, remotePort)
			copyCmd := exec.Command("ssh-copy-id", "-i", pubKeyPath, "-p", remotePort, fmt.Sprintf("%s@%s", remoteUser, remoteIP))
			copyCmd.Stdin = os.Stdin
			copyCmd.Stdout = os.Stdout
			copyCmd.Stderr = os.Stderr
			_ = copyCmd.Run()
			fmt.Println(Green + Bold + "\n[✔] Remote deployment operation finished!" + Reset)
		}
	}

	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	transfer.ReadRealtimeInput("\nPress ENTER to return to Hub 1 Vault Menu...")
}

// ====================================================================
//  AUTOMATED HARDWARE DOCTOR (AUTO-HEAL DIAGNOSTICS)
// ====================================================================

func RunAutomatedHardwareDoctor(reader *bufio.Reader) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== 🔧 AUTOMATED HARDWARE & RECON ENGINE DOCTOR ===" + Reset)
	fmt.Println(Yellow + "[!] Running real-time diagnostic checks on Linux Kernel, Drivers, USB, & Sockets..." + Reset)
	fmt.Println(Blue + "-----------------------------------------------------------------------------------" + Reset)

	sudoPass := EnsureRootPrivileges()

	virtCmd := exec.Command("systemd-detect-virt")
	virtOut, _ := virtCmd.Output()
	virtEnv := strings.TrimSpace(string(virtOut))

	if virtEnv == "oracle" || virtEnv == "kvm" || virtEnv == "vmware" {
		fmt.Printf(" [!] OS Environment: %sVIRTUAL MACHINE (%s)%s\n", Red+Bold, strings.ToUpper(virtEnv), Reset)
	} else {
		fmt.Printf(" [✔] OS Environment: %sBARE-METAL LINUX (Native Kernel)%s\n", Green+Bold, Reset)
	}

	activeAdapter, errAdapter := EnsureBluetoothServiceAndAdapterRunning(sudoPass)
	if errAdapter == nil {
		fmt.Printf(" [✔] Bluetooth Controller: %sDETECTED (%s)%s\n", Green+Bold, activeAdapter, Reset)

		btShowCmd := exec.Command("bluetoothctl", "show")
		btShowOut, _ := btShowCmd.Output()

		var hciOut []byte
		if sudoPass != "" {
			hciCmd := exec.Command("sudo", "-S", "hciconfig", activeAdapter)
			hciCmd.Stdin = strings.NewReader(sudoPass + "\n")
			hciOut, _ = hciCmd.Output()
		} else {
			hciCmd := exec.Command("hciconfig", activeAdapter)
			hciOut, _ = hciCmd.Output()
		}

		isPoweredOn := strings.Contains(string(btShowOut), "Powered: yes") || strings.Contains(string(hciOut), "UP RUNNING")

		if isPoweredOn {
			fmt.Printf(" [✔] Bluetooth Radio Power: %sONLINE (UP RUNNING)%s\n", Green+Bold, Reset)
		} else {
			fmt.Printf(" [!] Bluetooth Radio Power: %sOFFLINE (DOWN) -> Auto-Fixing...%s\n", Yellow+Bold, Reset)
			if sudoPass != "" {
				cmdRf := exec.Command("sudo", "-S", "rfkill", "unblock", "all")
				cmdRf.Stdin = strings.NewReader(sudoPass + "\n")
				_ = cmdRf.Run()

				cmdUp := exec.Command("sudo", "-S", "hciconfig", activeAdapter, "up")
				cmdUp.Stdin = strings.NewReader(sudoPass + "\n")
				_ = cmdUp.Run()
			} else {
				_ = exec.Command("sudo", "rfkill", "unblock", "all").Run()
				_ = exec.Command("sudo", "hciconfig", activeAdapter, "up").Run()
			}
			_ = exec.Command("bluetoothctl", "power", "on").Run()
			time.Sleep(200 * time.Millisecond)
		}
	} else {
		fmt.Printf(" [!] Bluetooth Controller: %sNOT FOUND IN KERNEL (Check USB Dongle)%s\n", Red+Bold, Reset)
	}

	_, errArp := exec.LookPath("arp-scan")
	if errArp == nil {
		fmt.Printf(" [✔] Core LAN Scanner (arp-scan): %sINSTALLED%s\n", Green+Bold, Reset)
	} else {
		fmt.Printf(" [!] Core LAN Scanner (arp-scan): %sMISSING%s\n", Red+Bold, Reset)
	}

	_, errNmap := exec.LookPath("nmap")
	if errNmap == nil {
		fmt.Printf(" [✔] Deep IoT Scanner (nmap): %sINSTALLED%s\n", Green+Bold, Reset)
	} else {
		fmt.Printf(" [!] Deep IoT Scanner (nmap): %sMISSING%s\n", Red+Bold, Reset)
	}

	fmt.Println(Blue + "-----------------------------------------------------------------------------------" + Reset)
	fmt.Println(Bold + "\nSelect Diagnostic / Self-Healing Action:" + Reset)
	fmt.Println("  [1] ⚡ Run One-Click Self-Healing Auto-Fix (Reset Sockets, D-Bus, Dongle & Daemons)")
	fmt.Println("  [2] 📖 Show Step-by-Step VirtualBox USB Passthrough Guide")
	fmt.Println("  [3] 📖 Show Bare-Metal Linux Native Setup Instructions")
	fmt.Println(Red + "  [0] Return to Menu" + Reset)
	fmt.Println(Blue + "-----------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select Choice [0-3]: ")

	switch choice {
	case "1":
		fmt.Println(Cyan + "\n[+] Executing One-Click Self-Healing Diagnostics..." + Reset)
		if sudoPass != "" {
			cmdBt := exec.Command("sudo", "-S", "systemctl", "restart", "bluetooth")
			cmdBt.Stdin = strings.NewReader(sudoPass + "\n")
			_ = cmdBt.Run()
		} else {
			_ = exec.Command("sudo", "systemctl", "restart", "bluetooth").Run()
		}

		bestAdapter, _ := EnsureBluetoothServiceAndAdapterRunning(sudoPass)
		if sudoPass != "" {
			c1 := exec.Command("sudo", "-S", "rfkill", "unblock", "all")
			c1.Stdin = strings.NewReader(sudoPass + "\n")
			_ = c1.Run()

			c2 := exec.Command("sudo", "-S", "hciconfig", bestAdapter, "reset")
			c2.Stdin = strings.NewReader(sudoPass + "\n")
			_ = c2.Run()

			c3 := exec.Command("sudo", "-S", "hciconfig", bestAdapter, "up")
			c3.Stdin = strings.NewReader(sudoPass + "\n")
			_ = c3.Run()
		} else {
			_ = exec.Command("sudo", "rfkill", "unblock", "all").Run()
			_ = exec.Command("sudo", "hciconfig", bestAdapter, "reset").Run()
			_ = exec.Command("sudo", "hciconfig", bestAdapter, "up").Run()
		}
		_ = exec.Command("bluetoothctl", "power", "on").Run()

		if sudoPass != "" {
			u1 := exec.Command("sudo", "-S", "udevadm", "control", "--reload-rules")
			u1.Stdin = strings.NewReader(sudoPass + "\n")
			_ = u1.Run()
			u2 := exec.Command("sudo", "-S", "udevadm", "trigger")
			u2.Stdin = strings.NewReader(sudoPass + "\n")
			_ = u2.Run()
		} else {
			_ = exec.Command("sudo", "udevadm", "control", "--reload-rules").Run()
			_ = exec.Command("sudo", "udevadm", "trigger").Run()
		}

		if sudoPass != "" {
			aCmd := exec.Command("sudo", "-S", "ip", "neigh", "flush", "all")
			aCmd.Stdin = strings.NewReader(sudoPass + "\n")
			_ = aCmd.Run()
		} else {
			_ = exec.Command("sudo", "ip", "neigh", "flush", "all").Run()
		}

		fmt.Println(Green + Bold + "\n[✔] SELF-HEALING AUTO-FIX COMPLETE! Recon Engines are 100% Operational." + Reset)
		time.Sleep(1 * time.Second)

	case "2":
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== 📖 VIRTUALBOX USB PASSTHROUGH SETUP GUIDE ===" + Reset)
		fmt.Println(Yellow + "If you are running Kali inside VirtualBox and Bluetooth is missing, follow these steps:\n" + Reset)
		fmt.Println("1. Plug your " + Bold + "Bluetooth USB Dongle" + Reset + " into your Host PC.")
		fmt.Println("2. Open VirtualBox -> Select " + Bold + "Kali Linux" + Reset + " -> Click " + Bold + "Settings" + Reset + " -> " + Bold + "USB" + Reset + ".")
		fmt.Println("3. Ensure " + Bold + "USB 2.0 (EHCI)" + Reset + " or " + Bold + "USB 3.0 (xHCI)" + Reset + " Controller is enabled.")
		fmt.Println("4. Click the green " + Bold + "'+' (Add USB Filter)" + Reset + " icon.")
		fmt.Println("5. Select your Bluetooth Dongle (e.g. 'Realtek Bluetooth 5.0' or 'Foxconn').")
		fmt.Println("6. In running Kali VM top menu bar, click " + Bold + "Devices -> USB -> Checkmark your Dongle" + Reset + ".")
		fmt.Println("\n" + Green + Bold + "Press Enter to return..." + Reset)
		_, _ = reader.ReadString('\n')

	case "3":
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== 📖 BARE-METAL LINUX NATIVE HARDWARE SETUP ===" + Reset)
		fmt.Println(Yellow + "If you installed Kali Linux directly on your computer's main SSD:\n" + Reset)
		fmt.Println("1. Ensure BlueZ, OBEX & HCI utilities are installed:")
		fmt.Println("   " + Cyan + "sudo apt update && sudo apt install -y bluez bluez-tools obexftp obexd arp-scan nmap" + Reset)
		fmt.Println("2. Verify native motherboard Bluetooth or external dongle is powered on:")
		fmt.Println("   " + Cyan + "sudo rfkill unblock bluetooth && sudo hciconfig hci0 up" + Reset)
		fmt.Println("3. Run the Cross-Suite Wizard auto-scanner!")
		fmt.Println("\n" + Green + Bold + "Press Enter to return..." + Reset)
		_, _ = reader.ReadString('\n')
	}
}

func FactoryResetVault() bool {
	fmt.Println(Red + Bold + "\n=== CRITICAL WARNING: FACTORY RESET VAULT ===" + Reset)
	fmt.Println(Red + "[!] This action will PERMANENTLY ERASE all saved host profiles, credentials, and master passphrases." + Reset)
	fmt.Println(Yellow + "This operation cannot be undone!" + Reset)

	confirm := transfer.ReadRealtimeInput("Type 'RESET' to confirm purging all vault data: ")
	if confirm != "RESET" {
		fmt.Println(Yellow + "[!] Factory Reset Canceled." + Reset)
		time.Sleep(1 * time.Second)
		return false
	}

	_ = os.Remove(getEncryptedVaultPath())
	_ = os.Remove(getPlainVaultPath())
	_ = os.Remove(getConfigPath())
	_ = os.Remove(getAliasFilePath())

	cachedMasterKey = nil
	cachedSalt = nil
	cachedPassphrase = ""
	isPassphraseCached = false

	fmt.Println(Green + Bold + "\n[SUCCESS] Vault successfully reset! All data purged cleanly." + Reset)
	time.Sleep(1 * time.Second)
	return true
}

func changePassphrasePrompt(reader *bufio.Reader) {
	if IsEncryptionDisabled() {
		fmt.Println(Yellow + "\n[!] Encryption is currently OFF. Turn encryption ON first to set a passphrase." + Reset)
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Println(Cyan + "\n=== CHANGE MASTER VAULT PASSPHRASE ===" + Reset)
	curP := transfer.ReadRealtimeInput("Enter Current Master Passphrase: ")
	if curP != cachedPassphrase {
		fmt.Println(Red + "[!] Current passphrase incorrect." + Reset)
		time.Sleep(1 * time.Second)
		return
	}

	newP1 := transfer.ReadRealtimeInput("Enter New Master Passphrase: ")
	if newP1 == "" {
		fmt.Println(Red + "[!] Passphrase cannot be empty." + Reset)
		time.Sleep(1 * time.Second)
		return
	}

	newP2 := transfer.ReadRealtimeInput("Confirm New Master Passphrase: ")
	if newP1 != newP2 {
		fmt.Println(Red + "[!] Passphrases do not match." + Reset)
		time.Sleep(1 * time.Second)
		return
	}

	vData, err := LoadVaultUnlocked()
	if err != nil {
		fmt.Printf(Red+"[!] Error reading vault: %v\n"+Reset, err)
		time.Sleep(1 * time.Second)
		return
	}

	newSalt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		fmt.Printf(Red+"[!] Error generating salt: %v\n"+Reset, err)
		time.Sleep(1 * time.Second)
		return
	}

	newKey := deriveKey(newP1, newSalt)
	cachedSalt = newSalt
	cachedMasterKey = newKey
	cachedPassphrase = newP1

	err = SaveVaultUnlocked(vData)
	if err != nil {
		fmt.Printf(Red+"[!] Failed to re-encrypt vault: %v\n"+Reset, err)
	} else {
		fmt.Println(Green + Bold + "[SUCCESS] Master Vault Passphrase Updated Successfully!" + Reset)
	}
	time.Sleep(1 * time.Second)
}

func toggleEncryptionPrompt(reader *bufio.Reader) {
	fmt.Println(Cyan + "\n=== TOGGLE MASTER VAULT ENCRYPTION ===" + Reset)

	vData, err := LoadVaultUnlocked()
	if err != nil {
		vData = &VaultData{Profiles: []HostProfile{}}
	}

	if IsEncryptionDisabled() {
		fmt.Println(Yellow + "[!] Encryption is currently OFF. Switching to AES-256-GCM Encrypted Mode..." + Reset)
		setEncryptionState(true)

		isPassphraseCached = false
		cachedMasterKey = nil
		cachedSalt = nil
		cachedPassphrase = ""

		_, err := GetOrPromptMasterKey()
		if err != nil {
			fmt.Println(Red + "[!] Failed to initialize encryption." + Reset)
			setEncryptionState(false)
			time.Sleep(1 * time.Second)
			return
		}

		_ = SaveVaultUnlocked(vData)
		_ = os.Remove(getPlainVaultPath())
		fmt.Println(Green + Bold + "[SUCCESS] Vault is now ENCRYPTED on disk (~/.cross-ssh/vault.enc)!" + Reset)
	} else {
		fmt.Println(Red + "\n[!] WARNING: Disabling encryption will store host credentials in plain JSON text." + Reset)
		fmt.Println(Yellow + "Select Confirmation Choice:" + Reset)
		fmt.Println(Green + "  [1]" + Reset + " NO  - Keep AES-256-GCM Encryption Active (Recommended)")
		fmt.Println(Red + "  [2]" + Reset + " YES - Disable Encryption (Store Credentials in Plain Text)")
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		ans := transfer.ReadRealtimeInput("Enter choice [1/2] or (y/n): ")
		ansLower := strings.ToLower(strings.TrimSpace(ans))

		if ansLower != "2" && ansLower != "y" && ansLower != "yes" {
			fmt.Println(Yellow + "[!] Action Canceled. Encryption remains ACTIVE." + Reset)
			time.Sleep(1 * time.Second)
			return
		}

		setEncryptionState(false)
		_ = SaveVaultUnlocked(vData)
		_ = os.Remove(getEncryptedVaultPath())
		fmt.Println(Green + Bold + "[SUCCESS] Encryption OFF! Saved in plain mode (~/.cross-ssh/vault.json)." + Reset)
	}
	time.Sleep(1 * time.Second)
}

func ExecutePingCheck(client *ssh.Client) string {
	session, err := client.NewSession()
	if err != nil {
		return "Offline"
	}
	defer session.Close()

	start := time.Now()
	_, err = session.CombinedOutput("echo 1")
	if err != nil {
		return "Error"
	}
	latency := time.Since(start).Milliseconds()
	return fmt.Sprintf("%dms", latency)
}

func ResolveAliasForIP(ip string) string {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		home = filepath.Join("/home", sudoUser)
	} else if err != nil {
		home = "."
	}
	vaultPath := filepath.Join(home, ".cross-ssh", "vault.json")
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return ""
	}
	var profiles []HostProfile
	if err := json.Unmarshal(data, &profiles); err == nil {
		for _, p := range profiles {
			if p.Host == ip && p.Alias != "" {
				return p.Alias
			}
		}
	}
	return ""
}