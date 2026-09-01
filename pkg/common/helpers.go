package common

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"

	DefaultCmdTimeout = 90 * time.Second
	LongCmdTimeout    = 5 * time.Minute
	MaxRetries        = 2
)

var (
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$`)
	safePathRe = regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`)
)

// ---------------------------------------------------------------------
// Audit Logging
// ---------------------------------------------------------------------
func AuditLog(host, action, detail, result string) {
	f, err := os.OpenFile("compliance_audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println(Yellow + "[!] Could not write audit log entry: " + err.Error() + Reset)
		return
	}
	defer f.Close()
	operator := "unknown"
	if u, err := user.Current(); err == nil {
		operator = u.Username
	}
	line := fmt.Sprintf("%s\toperator=%s\thost=%s\taction=%s\tresult=%s\tdetail=%s\n",
		time.Now().UTC().Format(time.RFC3339), operator, host, action, result,
		strings.ReplaceAll(detail, "\n", " | "))
	_, _ = f.WriteString(line)
}

// ---------------------------------------------------------------------
// SSH Execution
// ---------------------------------------------------------------------
func ExecuteRemoteCommand(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to open SSH session: %w", err)
	}
	defer session.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(cmd)
		done <- result{out, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case r := <-done:
		return string(r.out), r.err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return "", fmt.Errorf("command timed out after %s", timeout)
	}
}

func ExecuteWithSpinner(client *ssh.Client, cmd string, label string, timeout time.Duration) (string, error) {
	var running int32 = 1
	done := make(chan struct{})

	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		startTime := time.Now()
		i := 0

		for atomic.LoadInt32(&running) == 1 {
			elapsed := int(time.Since(startTime).Seconds())
			fmt.Fprintf(os.Stderr, "\r\033[36m[ %s ] %s... (%ds elapsed)\033[0m", frames[i%len(frames)], label, elapsed)
			i++
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprintf(os.Stderr, "\r\033[2K\r")
		close(done)
	}()

	out, err := ExecuteRemoteCommand(client, cmd, timeout)

	atomic.StoreInt32(&running, 0)
	<-done

	return out, err
}

// ---------------------------------------------------------------------
// Result Helpers
// ---------------------------------------------------------------------
func ResultLabel(err error) string {
	if err == nil {
		return "ok"
	}
	return "error:" + err.Error()
}

func AnnotateResult(out string, err error) string {
	if err == nil {
		return out
	}
	banner := Red + Bold + fmt.Sprintf("[EXECUTION ERROR] %v — results below may be partial or missing.\n", err) + Reset
	return banner + out
}

// ---------------------------------------------------------------------
// Display & Pager
// ---------------------------------------------------------------------
func DisplayScrollableOutput(toolName string, rawOutput string) {
	reportsDir := filepath.Join(".", "reports")
	_ = os.MkdirAll(reportsDir, 0755)

	cleanName := strings.ToLower(strings.ReplaceAll(toolName, " ", "_"))
	timestamp := time.Now().Format("20060102_150405")
	logPath := filepath.Join(reportsDir, fmt.Sprintf("%s_%s.txt", cleanName, timestamp))
	_ = os.WriteFile(logPath, []byte(rawOutput), 0644)

	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Printf(Green+Bold+"[✔] %s SCAN COMPLETED SUCCESSFULLY!\n"+Reset, strings.ToUpper(toolName))
	fmt.Printf(Yellow+"=> Full output log saved to: %s\n"+Reset, logPath)
	fmt.Println(Cyan + "================================================================================" + Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nLaunch interactive scrollable viewer (Arrow Keys to scroll, 'q' to exit)? [Y/n]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	if choice == "" || strings.ToLower(choice) == "y" {
		cmd := exec.Command("less", "-R", logPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(rawOutput)
		}
	}
}

func DisplayScrollableOutputWithPath(toolName string, rawOutput string, reportPath string) {
	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Printf(Green+Bold+"[✔] %s SCAN COMPLETED SUCCESSFULLY!\n"+Reset, strings.ToUpper(toolName))
	fmt.Printf(Yellow+"=> Full output log saved to: %s\n"+Reset, reportPath)
	fmt.Println(Cyan + "================================================================================" + Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nLaunch interactive scrollable viewer (Arrow Keys to scroll, 'q' to exit)? [Y/n]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	if choice == "" || strings.ToLower(choice) == "y" {
		cmd := exec.Command("less", "-R", reportPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println(rawOutput)
		}
	}
}

// ---------------------------------------------------------------------
// Open Browser
// ---------------------------------------------------------------------
func OpenBrowser(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default: // linux, etc.
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}

// ---------------------------------------------------------------------
// Tool Installation
// ---------------------------------------------------------------------
func EnsureToolInstalled(client *ssh.Client, tool, pkg string) bool {
	checkCmd := fmt.Sprintf("command -v %s >/dev/null 2>&1", tool)
	_, err := ExecuteRemoteCommand(client, checkCmd, DefaultCmdTimeout)
	if err == nil {
		return true
	}
	updateCmd := "sudo apt-get update >/dev/null 2>&1"
	_, _ = ExecuteRemoteCommand(client, updateCmd, DefaultCmdTimeout)

	availCmd := fmt.Sprintf("apt-cache show %s >/dev/null 2>&1", pkg)
	_, err = ExecuteRemoteCommand(client, availCmd, DefaultCmdTimeout)
	if err != nil {
		fmt.Printf(Yellow+"[!] Package '%s' not found in repos.\n"+Reset, pkg)
		return false
	}
	fmt.Printf(Yellow+"[!] Tool '%s' not found. Install package '%s'? (y/n): "+Reset, tool, pkg)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(resp) != "y" {
		return false
	}
	installCmd := fmt.Sprintf("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq %s", pkg)
	fmt.Printf(Cyan+"[+] Installing %s...\n"+Reset, pkg)
	out, err := ExecuteRemoteCommand(client, installCmd, LongCmdTimeout)
	if err != nil {
		fmt.Printf(Red+"[!] Install failed: %v\n"+Reset, err)
		fmt.Println(out)
		return false
	}
	fmt.Println(Green + "[+] Installation done." + Reset)
	return true
}

// ---------------------------------------------------------------------
// Pause Prompt
// ---------------------------------------------------------------------
func PausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to continue..." + Reset)
	bufio.NewReader(os.Stdin).ReadString('\n')
}