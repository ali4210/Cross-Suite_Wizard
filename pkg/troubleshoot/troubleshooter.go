package troubleshoot

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"cross-ssh/pkg/transfer"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

type DiagnosticCheck struct {
	Name     string
	Passed   bool
	Message  string
	Fixable  bool
	FixFunc  func() error
}

func RunDiagnostics(reader *bufio.Reader, activeHost string, activePort string) {
	fmt.Println(Cyan + Bold + "=== RUNNING SYSTEM HEALTH CHECK & AUTOMATED TROUBLESHOOTER ===" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	var checks []DiagnosticCheck

	// 1. Local SSH Dir & Permission Check
	checks = append(checks, checkSSHKeyPermissions())

	// 2. Terminal Discipline Check
	checks = append(checks, checkTerminalDiscipline())

	// 3. Global Binary PATH Check
	checks = append(checks, checkGlobalBinaryInstallation())

	// 4. Remote Host Network Probe
	if activeHost != "" {
		checks = append(checks, checkRemoteConnectivity(activeHost, activePort))
	} else {
		checks = append(checks, DiagnosticCheck{
			Name:    "Remote Host Connectivity",
			Passed:  true,
			Message: "Skipped (No active session selected in option [1])",
		})
	}

	// Output Diagnostic Results
	fixedCount := 0
	failedCount := 0

	for i, check := range checks {
		if check.Passed {
			fmt.Printf(Green+"  [%d/%d] [PASS] %s: %s\n"+Reset, i+1, len(checks), check.Name, check.Message)
		} else {
			failedCount++
			fmt.Printf(Red+"  [%d/%d] [FAIL] %s: %s\n"+Reset, i+1, len(checks), check.Name, check.Message)

			if check.Fixable && check.FixFunc != nil {
				fmt.Print(Yellow + "         => Automated fix available. Apply fix now? [Y/n]: " + Reset)
				ans := transfer.ReadRealtimeInput("")
				if ans == "" || ans == "y" || ans == "Y" {
					if err := check.FixFunc(); err == nil {
						fmt.Println(Green + "         [SUCCESS] Auto-fix applied successfully!" + Reset)
						fixedCount++
					} else {
						fmt.Printf(Red+"         [ERROR] Failed to apply fix: %v\n"+Reset, err)
					}
				}
			}
		}
	}

	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	if failedCount == 0 {
		fmt.Println(Green + Bold + "[SYSTEM HEALTHY] All diagnostic checks passed cleanly!" + Reset)
	} else {
		fmt.Printf(Yellow+Bold+"[SUMMARY] Diagnostics complete: %d issues detected, %d resolved.\n"+Reset, failedCount, fixedCount)
	}
}

func checkSSHKeyPermissions() DiagnosticCheck {
	home, err := os.UserHomeDir()
	if err != nil {
		return DiagnosticCheck{Name: "Local SSH Directory", Passed: false, Message: "Cannot resolve user home directory"}
	}

	sshDir := filepath.Join(home, ".ssh")
	info, err := os.Stat(sshDir)
	if os.IsNotExist(err) {
		return DiagnosticCheck{
			Name:    "Local SSH Directory Permissions",
			Passed:  false,
			Message: "~/.ssh directory does not exist",
			Fixable: true,
			FixFunc: func() error {
				return os.MkdirAll(sshDir, 0700)
			},
		}
	}

	mode := info.Mode().Perm()
	if mode != 0700 {
		return DiagnosticCheck{
			Name:    "Local SSH Directory Permissions",
			Passed:  false,
			Message: fmt.Sprintf("Loose permissions on ~/.ssh (%o, expected 0700)", mode),
			Fixable: true,
			FixFunc: func() error {
				return os.Chmod(sshDir, 0700)
			},
		}
	}

	return DiagnosticCheck{Name: "Local SSH Directory Permissions", Passed: true, Message: "~/.ssh permissions are secure (0700)"}
}

func checkTerminalDiscipline() DiagnosticCheck {
	cmd := exec.Command("stty", "-F", "/dev/tty", "sane")
	if err := cmd.Run(); err != nil {
		return DiagnosticCheck{
			Name:    "Terminal TTY Discipline",
			Passed:  false,
			Message: "Terminal TTY discipline requires sanitization",
			Fixable: true,
			FixFunc: func() error {
				transfer.ResetTerminal()
				return nil
			},
		}
	}
	return DiagnosticCheck{Name: "Terminal TTY Discipline", Passed: true, Message: "Terminal echo and control flags are healthy"}
}

func checkGlobalBinaryInstallation() DiagnosticCheck {
	targetBin := "/usr/local/bin/cross-ssh"
	_, err := os.Stat(targetBin)
	if os.IsNotExist(err) {
		return DiagnosticCheck{
			Name:    "Global System CLI Installation",
			Passed:  false,
			Message: "cross-ssh is not yet installed in /usr/local/bin (Use option [8] to install globally)",
		}
	}
	return DiagnosticCheck{Name: "Global System CLI Installation", Passed: true, Message: "cross-ssh is installed globally in /usr/local/bin"}
}

func checkRemoteConnectivity(host string, port string) DiagnosticCheck {
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return DiagnosticCheck{
			Name:    "Remote SSH Port Reachability",
			Passed:  false,
			Message: fmt.Sprintf("Cannot establish TCP connection to %s (%v)", address, err),
		}
	}
	conn.Close()
	return DiagnosticCheck{Name: "Remote SSH Port Reachability", Passed: true, Message: fmt.Sprintf("Target %s is reachable", address)}
}