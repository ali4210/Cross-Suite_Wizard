package cleaner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cross-ssh/pkg/transfer"
)

// ANSI color constants
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// getTempEngineDir returns the OS‑appropriate temp directory.
func getTempEngineDir() string {
	return filepath.Join(os.TempDir(), "cross_payload_engine")
}

// CleanToolJunk is the main entry point for the Tool Junk Cleaner.
func CleanToolJunk() {
	fmt.Println(Cyan + Bold + "\n================================================================" + Reset)
	fmt.Println(Cyan + Bold + "          🧽 TOOL JUNK CLEANER (Safe Removal)              " + Reset)
	fmt.Println(Cyan + Bold + "================================================================" + Reset)
	fmt.Println(Yellow + "This will scan and remove the following junk items:\n" + Reset)
	fmt.Println("  • dist/              – Cross‑compiled binaries (unused locally)")
	fmt.Println("  • reports/           – Old scan logs and reports (can be regenerated)")
	fmt.Println("  • downloads/         – Temporary downloaded files")
	fmt.Println("  • *.syso, *.o        – Object files from previous builds")
	fmt.Println("  • ~/.arduino15       – Old Arduino core & toolchains (saved space)")
	fmt.Println("  • ~/.cross-ssh       – Old sketch build directories")
	fmt.Println("  • /tmp/cross_payload_engine – Temporary toolchain (if not purged)")
	fmt.Println("  • Go build cache     – (optional) 'go clean -cache'")
	fmt.Println("  • Go module cache    – (optional) 'go clean -modcache' (will redownload later)")
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	// Confirm
	fmt.Print(Yellow + "Do you want to proceed with cleaning? (y/N): " + Reset)
	confirm := transfer.ReadRealtimeInput("")
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		fmt.Println(Green + "[✔] Clean cancelled." + Reset)
		return
	}

	fmt.Println(Yellow + "\n[+] Starting junk cleanup..." + Reset)

	// 1. Remove dist/
	distPath := "dist"
	if _, err := os.Stat(distPath); err == nil {
		fmt.Printf("[+] Removing %s ...\n", distPath)
		_ = os.RemoveAll(distPath)
	}

	// 2. Remove reports/ (ask user)
	fmt.Print(Yellow + "Remove all old reports (reports/)? (y/N): " + Reset)
	confirmReports := transfer.ReadRealtimeInput("")
	if strings.ToLower(strings.TrimSpace(confirmReports)) == "y" {
		reportsPath := "reports"
		if _, err := os.Stat(reportsPath); err == nil {
			fmt.Printf("[+] Removing %s ...\n", reportsPath)
			_ = os.RemoveAll(reportsPath)
		}
	}

	// 3. Remove downloads/
	downloadsPath := "downloads"
	if _, err := os.Stat(downloadsPath); err == nil {
		fmt.Printf("[+] Removing %s ...\n", downloadsPath)
		_ = os.RemoveAll(downloadsPath)
	}

	// 4. Remove object files (*.syso and *.o)
	objFiles, _ := filepath.Glob("*.syso")
	oFiles, _ := filepath.Glob("*.o")
	objFiles = append(objFiles, oFiles...)
	for _, f := range objFiles {
		fmt.Printf("[+] Removing %s ...\n", f)
		_ = os.Remove(f)
	}

	// 5. Remove old Arduino core (global)
	home, _ := os.UserHomeDir()
	arduino15 := filepath.Join(home, ".arduino15")
	if _, err := os.Stat(arduino15); err == nil {
		fmt.Printf("[+] Removing %s ...\n", arduino15)
		_ = os.RemoveAll(arduino15)
	}
	crossSSH := filepath.Join(home, ".cross-ssh")
	if _, err := os.Stat(crossSSH); err == nil {
		fmt.Printf("[+] Removing %s ...\n", crossSSH)
		_ = os.RemoveAll(crossSSH)
	}

	// 6. Purge temporary engine (/tmp)
	tmpEngine := getTempEngineDir()
	if _, err := os.Stat(tmpEngine); err == nil {
		fmt.Printf("[+] Removing temporary toolchain at %s ...\n", tmpEngine)
		_ = os.RemoveAll(tmpEngine)
	}

	// 7. Clean Go cache (optional)
	fmt.Print(Yellow + "Do you want to run 'go clean -cache' (removes compiled packages)? (y/N): " + Reset)
	confirmCache := transfer.ReadRealtimeInput("")
	if strings.ToLower(strings.TrimSpace(confirmCache)) == "y" {
		fmt.Println("[+] Running go clean -cache ...")
		_ = exec.Command("go", "clean", "-cache").Run()
	}

	// 8. Clean Go module cache (optional)
	fmt.Print(Yellow + "Do you want to run 'go clean -modcache' (removes all downloaded modules)? (y/N): " + Reset)
	confirmModCache := transfer.ReadRealtimeInput("")
	if strings.ToLower(strings.TrimSpace(confirmModCache)) == "y" {
		fmt.Println("[+] Running go clean -modcache ...")
		_ = exec.Command("go", "clean", "-modcache").Run()
	}

	fmt.Println(Green + Bold + "\n[✔] Junk cleanup completed! Your project folder is now lean." + Reset)
	fmt.Println(Yellow + "If you need to rebuild, run 'make build' or './autorun.sh'." + Reset)

	// Pause so user can read
	fmt.Print(Yellow + "\nPress Enter to continue..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}