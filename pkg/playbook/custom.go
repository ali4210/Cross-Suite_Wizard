package playbook

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// ExecuteCustomPlaybook transfers and executes a user-provided local script/playbook on the remote target
func ExecuteCustomPlaybook(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== CUSTOM USER PLAYBOOK EXECUTION ENGINE ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	localPath := transfer.ReadRealtimeInput("\nEnter local path to script/playbook (e.g., ./my_playbook.sh or .yml): ")
	localPath = strings.TrimSpace(localPath)

	if localPath == "" {
		fmt.Println(Yellow + "[!] No file path provided. Returning to menu." + Reset)
		pausePrompt()
		return
	}

	fileInfo, err := os.Stat(localPath)
	if err != nil || fileInfo.IsDir() {
		fmt.Printf(Red+"[!] Local file not found or invalid: %s\n"+Reset, localPath)
		pausePrompt()
		return
	}

	remoteTmpPath := fmt.Sprintf("/tmp/custom_playbook_%s", filepath.Base(localPath))

	// Step 1: Transfer File via SFTP Engine
	fmt.Printf(Yellow+"\n[+] Uploading %s ==> Remote:%s...\n"+Reset, localPath, remoteTmpPath)
	engine, err := transfer.NewTransferEngine(client, osdetect.OSLinux)
	if err != nil {
		fmt.Printf(Red+"[!] Transfer Engine Initialization failed: %v\n"+Reset, err)
		pausePrompt()
		return
	}

	err = engine.UploadFile(localPath, remoteTmpPath)
	engine.Close()

	if err != nil {
		fmt.Printf(Red+"[!] SFTP Transfer failed: %v\n"+Reset, err)
		pausePrompt()
		return
	}

	// Step 2: Determine Execution Strategy based on file extension
	var execCmd string
	ext := strings.ToLower(filepath.Ext(localPath))

	switch ext {
	case ".sh":
		execCmd = fmt.Sprintf("chmod +x %s && sudo %s", remoteTmpPath, remoteTmpPath)
	case ".yml", ".yaml":
		execCmd = fmt.Sprintf("if command -v ansible-playbook >/dev/null 2>&1; then ansible-playbook %s; else bash %s; fi", remoteTmpPath, remoteTmpPath)
	default:
		execCmd = fmt.Sprintf("chmod +x %s && sudo %s", remoteTmpPath, remoteTmpPath)
	}

	fmt.Println(Cyan + "[+] Executing Playbook on Remote Host..." + Reset)
	fmt.Println(Blue + "=================== PLAYBOOK OUTPUT START ===================" + Reset)

	out, err := executeRemoteCommandWithSpinner(client, execCmd, "Executing Custom Playbook")
	fmt.Println(out)

	fmt.Println(Blue + "==================== PLAYBOOK OUTPUT END ====================" + Reset)

	// Step 3: Cleanup Remote Temporary Artifact
	_, _ = executeRemoteCommand(client, fmt.Sprintf("rm -f %s", remoteTmpPath))

	if err != nil {
		fmt.Printf(Red+"[!] Playbook execution completed with errors: %v\n"+Reset, err)
	} else {
		fmt.Println(Green + Bold + "[✔] Custom Playbook executed successfully!" + Reset)
	}

	pausePrompt()
}