package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cross-ssh/pkg/transfer"
)

// DisplayScrollableOutput streams long scan results through an interactive 'less' terminal pager
// and automatically saves a persistent copy in ./reports/
func DisplayScrollableOutput(toolName string, rawOutput string) {
	// Ensure ./reports/ directory exists
	reportsDir := filepath.Join(".", "reports")
	_ = os.MkdirAll(reportsDir, 0755)

	// Clean filename key (e.g. nmap, trivy, zap)
	cleanName := strings.ToLower(strings.ReplaceAll(toolName, " ", "_"))
	timestamp := time.Now().Format("20060102_150405")
	logPath := filepath.Join(reportsDir, fmt.Sprintf("%s_%s.txt", cleanName, timestamp))

	// Write full raw output to file so zero data is lost
	_ = os.WriteFile(logPath, []byte(rawOutput), 0644)

	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Printf(Green+Bold+"[✔] %s SCAN COMPLETED SUCCESSFULLY!\n"+Reset, strings.ToUpper(toolName))
	fmt.Printf(Yellow+"=> Full output log saved to: %s\n"+Reset, logPath)
	fmt.Println(Cyan + "================================================================================" + Reset)

	openChoice := transfer.ReadRealtimeInput("\nLaunch interactive scrollable viewer (Arrow Keys to scroll, 'q' to exit)? [Y/n]: ")
	if openChoice == "" || strings.ToLower(openChoice) == "y" {
		// Launch less pager with color formatting (-R)
		cmd := exec.Command("less", "-R", logPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			// Fallback if 'less' is missing: print output cleanly
			fmt.Println(rawOutput)
		}
	}
}