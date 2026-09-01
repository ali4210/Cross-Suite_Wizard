package playbook

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)


type PlaybookItem struct {
	Name        string
	Description string
	Command     string
}

func ShowPlaybookMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== ENGINE 2: AGENTLESS TASK & PLAYBOOK ENGINE ===" + Reset)
		fmt.Printf(Yellow+"Target OS: "+Reset+Bold+"%s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		if targetOS == osdetect.OSWindows {
			fmt.Println("Select Windows Agentless Playbook to Execute:")
			fmt.Println("  [1] Windows Defender Firewall Complete Lockdown")
			fmt.Println("  [2] PowerShell Environment & WinRM Security Hardening")
			fmt.Println("  [3] System Log, Temp Cache, & Memory Vacuum")
			fmt.Println("  [4] Upload & Execute Local Script File (.ps1 / .bat)")
			fmt.Println("  [5] Inline Ad-hoc PowerShell Command Execution")
			fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		} else {
			fmt.Println("Select Linux Agentless Playbook to Execute:")
			fmt.Println("  [1] Install Docker Engine & Docker Compose (Universal Static Binary Setup)")
			fmt.Println("  [2] SSH Hardening (Safe Check: Disables Root/Password Auth ONLY if SSH Key Exists)")
			fmt.Println("  [3] Firewall Lockdown (Enable UFW/Firewalld & Allow Safe Admin Ports)")
			fmt.Println("  [4] System Maintenance (Vacuum Journal Logs, Cache & RAM)")
			fmt.Println("  [5] Nginx Web Server Auto-Installation & Service Verification")
			fmt.Println("  [6] Upload & Execute Local Script File (.sh / .py)")
			fmt.Println("  [7] Inline Ad-hoc Bash Shell Command Execution")
			fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		}

		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		choice := transfer.ReadRealtimeInput("Select choice: ")

		if choice == "0" || choice == "q" || choice == "Q" {
			return
		}

		executeSelectedPlaybook(reader, client, targetOS, sudoPass, choice)
	}
}

func executeSelectedPlaybook(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, choice string) {
	var pb PlaybookItem

	if targetOS == osdetect.OSWindows {
		switch choice {
		case "1":
			pb = PlaybookItem{
				Name:        "Windows Firewall Lockdown",
				Description: "Enables Firewall profiles (Domain/Private/Public) and enables Remote Desktop.",
				Command:     "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True -ErrorAction SilentlyContinue",
			}
		case "2":
			pb = PlaybookItem{
				Name:        "WinRM & PowerShell Security Hardening",
				Description: "Configures PowerShell execution policies and restricts WinRM remote access.",
				Command:     "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force; Enable-PSRemoting -Force -SkipNetworkProfileCheck",
			}
		case "3":
			pb = PlaybookItem{
				Name:        "Windows Log & Cache Vacuum",
				Description: "Purges Windows Update cache, temp files, and flushes DNS resolver.",
				Command:     `Clear-DnsClientCache; Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Windows Cleanup Complete"`,
			}
		case "4":
			localScriptPath, err := transfer.SelectLocalPath(reader)
			if err != nil || localScriptPath == "" {
				return
			}
			content, err := os.ReadFile(localScriptPath)
			if err != nil {
				fmt.Printf(Red+"[!] Cannot read local script file: %v\n"+Reset, err)
				pausePrompt()
				return
			}
			pb = PlaybookItem{
				Name:        "Local Script File: " + localScriptPath,
				Description: "Executing uploaded local script file contents.",
				Command:     string(content),
			}
		case "5":
			customScript := transfer.ReadRealtimeInput("\nEnter PowerShell Script payload to execute over SSH:\n> ")
			if customScript != "" {
				pb = PlaybookItem{
					Name:        "Custom PowerShell Script",
					Description: "User-defined ad-hoc PowerShell payload.",
					Command:     customScript,
				}
			} else {
				return
			}
		default:
			return
		}
	} else {
		// Universal Linux Binary Playbooks
		switch choice {
		case "1":
			pb = PlaybookItem{
				Name:        "Docker Engine & Docker Compose (Universal Binary Setup)",
				Description: "Installs Docker Engine via get.docker.com script and creates docker-compose standalone binary.",
				Command: strings.Join([]string{
					"if ! command -v docker >/dev/null 2>&1; then",
					"  curl -fsSL https://get.docker.com | sh",
					"fi",
					"systemctl start docker && systemctl enable docker",
					"mkdir -p /usr/local/bin /usr/bin",
					"curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose 2>/dev/null",
					"chmod +x /usr/local/bin/docker-compose",
					"ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose 2>/dev/null",
					"docker --version",
					"docker compose version || docker-compose --version",
				}, "\n"),
			}
		case "2":
			pb = PlaybookItem{
				Name:        "SSH Server Security Hardening (Safe Guarded)",
				Description: "Verifies SSH Public Key existence before disabling Root/Password Auth to prevent lockout.",
				Command: strings.Join([]string{
					"if [ ! -s ~/.ssh/authorized_keys ] && [ ! -s /root/.ssh/authorized_keys ]; then",
					"  echo '[ABORTED] No authorized_keys file found! Install SSH public key first to avoid lockout.'",
					"  exit 1",
					"fi",
					"sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
					"sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
					"systemctl restart ssh || systemctl restart sshd",
					"echo '[SUCCESS] SSH Hardening Applied cleanly.'",
				}, "\n"),
			}
		case "3":
			pb = PlaybookItem{
				Name:        "Firewall Lockdown & Admin Port Allow",
				Description: "Enables UFW / Firewalld and ensures SSH port 22 remains accessible.",
				Command: strings.Join([]string{
					"if command -v ufw >/dev/null 2>&1; then ufw allow 22/tcp && ufw --force enable;",
					"elif command -v firewall-cmd >/dev/null 2>&1; then systemctl start firewalld && firewall-cmd --add-port=22/tcp --permanent && firewall-cmd --reload; fi",
					"echo 'Firewall Configured'",
				}, "\n"),
			}
		case "4":
			pb = PlaybookItem{
				Name:        "System Maintenance & Memory Vacuum",
				Description: "Vacuums journalctl logs older than 2 days, clears package cache, and flushes RAM pagecache.",
				Command: strings.Join([]string{
					"journalctl --vacuum-time=2d 2>/dev/null",
					"apt-get clean 2>/dev/null || yum clean all 2>/dev/null || dnf clean all 2>/dev/null",
					"sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null",
					"echo 'System Memory & Log Cleanup Complete'",
				}, "\n"),
			}
		case "5":
			pb = PlaybookItem{
				Name:        "Nginx Web Server Installation",
				Description: "Installs/upgrades Nginx and verifies service status.",
				Command: strings.Join([]string{
					"(apt-get update -y && apt-get install -y nginx) || (yum install -y nginx || dnf install -y nginx)",
					"systemctl restart nginx || systemctl start nginx",
					"systemctl is-active nginx",
				}, "\n"),
			}
		case "6":
			localScriptPath, err := transfer.SelectLocalPath(reader)
			if err != nil || localScriptPath == "" {
				return
			}
			content, err := os.ReadFile(localScriptPath)
			if err != nil {
				fmt.Printf(Red+"[!] Cannot read local script file: %v\n"+Reset, err)
				pausePrompt()
				return
			}
			pb = PlaybookItem{
				Name:        "Local Script File: " + localScriptPath,
				Description: "Executing uploaded local script file contents.",
				Command:     string(content),
			}
		case "7":
			customScript := transfer.ReadRealtimeInput("\nEnter Bash Script payload to execute over SSH:\n> ")
			if customScript != "" {
				pb = PlaybookItem{
					Name:        "Custom Bash Playbook",
					Description: "User-defined ad-hoc Bash script payload.",
					Command:     customScript,
				}
			} else {
				return
			}
		default:
			return
		}
	}

	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== PLAYBOOK EXECUTION SUMMARY ===" + Reset)
	fmt.Printf(Yellow+"Playbook Name: "+Reset+Bold+"%s\n"+Reset, pb.Name)
	fmt.Printf(Yellow+"Description:   "+Reset+"%s\n", pb.Description)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	confirm := transfer.ReadRealtimeInput(Red + Bold + "Execute this agentless playbook on target? [y/N]: " + Reset)
	if strings.ToLower(confirm) != "y" {
		fmt.Println(Yellow + "[!] Playbook execution canceled." + Reset)
		pausePrompt()
		return
	}

	out := runTaskWithSpinner("Executing playbook '"+pb.Name+"'", func() string {
		return executePlaybookRemoteElevated(client, pb.Command, targetOS, sudoPass)
	})

	// Wrap execution output in an interactive pager so you can scroll up and down full output
	fullOutput := fmt.Sprintf("=== PLAYBOOK EXECUTION LOG: %s ===\n\n%s\n\n(Press 'q' to exit viewer and return to menu)", pb.Name, out)
	displayInPager(fullOutput)
}

func executePlaybookRemoteElevated(client *ssh.Client, scriptCmd string, targetOS osdetect.TargetOS, sudoPass string) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("[Error creating SSH session: %v]", err)
	}
	defer session.Close()

	var finalCmd string
	if targetOS == osdetect.OSWindows {
		finalCmd = fmt.Sprintf(`powershell -NoProfile -Command %q`, scriptCmd)
	} else {
		b64Script := base64.StdEncoding.EncodeToString([]byte(scriptCmd))
		decodedScriptCmd := fmt.Sprintf("echo %s | base64 -d | bash", b64Script)

		if sudoPass != "" {
			escapedPass := strings.ReplaceAll(sudoPass, "'", "'\\''")
			finalCmd = fmt.Sprintf("echo '%s' | sudo -S -p '' bash -c %q 2>&1", escapedPass, decodedScriptCmd)
		} else {
			finalCmd = decodedScriptCmd + " 2>&1"
		}
	}

	output, _ := session.CombinedOutput(finalCmd)
	return string(output)
}

func runTaskWithSpinner(message string, task func() string) string {
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan bool)
	var output string

	go func() {
		output = task()
		done <- true
	}()

	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\r\033[K"+Green+"[✔] %s Complete!\n"+Reset, message)
			return output
		default:
			fmt.Printf("\r\033[K"+Cyan+"[%s] %s..."+Reset, spinnerFrames[i%len(spinnerFrames)], message)
			time.Sleep(100 * time.Millisecond)
			i++
		}
	}
}

func displayInPager(content string) {
	cmd := exec.Command("less", "-R", "-X")
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(content)
		pausePrompt()
	}
}

