package playbook

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cross-ssh/pkg/transfer"
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
)

// ShowStorageCleanerMenu provides the 3-Tier Storage Reclamation Engine
func ShowStorageCleanerMenu(reader *bufio.Reader, client *ssh.Client) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)
		fmt.Println(Cyan + Bold + "=== AUTONOMOUS REMOTE STORAGE RECLAMATION SUITE ===" + Reset)
		fmt.Println(Cyan + Bold + "================================================================================" + Reset)

		// 1. Audit Root Filesystem Space
		diskReport, _ := executeRemoteCommand(client, "df -h /")
		fmt.Println(Yellow + "\n[+] Current Root Filesystem Usage (df -h /):" + Reset)
		fmt.Println(diskReport)

		// 2. Audit Directory Footprints
		fmt.Println(Yellow + "[+] Top Storage Consuming Directories in /var, /tmp & /root:" + Reset)
		topDirsCmd := `sh -c 'du -sh /var/lib/docker /var/lib/containers /var/log /tmp /var/tmp /root/.cache /var/cache 2>/dev/null | sort -rh || true'`
		dirUsage, _ := executeElevatedCommand(client, topDirsCmd)
		fmt.Println(dirUsage)

		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Tier 1: Safe Clean (Package caches, temp directories, 1-day journal logs)")
		fmt.Println("  [2] Tier 2: Hard Clean (Stopped containers, builders, log truncations, old caches)")
		fmt.Println("  [3] Tier 3: Super Hard Clean (FORCE Stop & Purge ALL Docker/Podman layers + Deep Logs)")
		fmt.Println(Red + "  [0] Return to Previous Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Reclamation Tier [0-3]: ")

		switch strings.TrimSpace(choice) {
		case "1":
			fmt.Println(Yellow + "\n[+] Executing Tier 1: Safe System Storage Reclamation..." + Reset)
			safeCmd := `sh -c '
				echo "--> Cleaning package caches..."
				if command -v dnf >/dev/null 2>&1; then dnf clean all 2>/dev/null || true; fi
				if command -v yum >/dev/null 2>&1; then yum clean all 2>/dev/null || true; fi
				if command -v apt-get >/dev/null 2>&1; then apt-get clean 2>/dev/null || true; fi
				if command -v pacman >/dev/null 2>&1; then pacman -Scc --noconfirm 2>/dev/null || true; fi

				echo "--> Vacuuming logs & cleaning /tmp..."
				if command -v journalctl >/dev/null 2>&1; then journalctl --vacuum-time=1d 2>/dev/null || true; fi
				rm -rf /tmp/* /var/tmp/* /var/cache/dnf/* /var/cache/yum/* 2>/dev/null || true
			'`
			out, _ := executeElevatedCommandWithSpinner(client, safeCmd, "Performing Safe System Cleaning")
			if strings.TrimSpace(out) != "" {
				fmt.Println(out)
			}
			fmt.Println(Green + "\n[✔] Tier 1 Safe Cleaning completed successfully!" + Reset)
			pausePrompt()

		case "2":
			fmt.Println(Yellow + "\n[+] Executing Tier 2: Hard Storage Reclamation (Docker + Podman + System)..." + Reset)
			hardCmd := `sh -c '
				echo "--> Removing unused package caches & autoremove..."
				if command -v dnf >/dev/null 2>&1; then dnf autoremove -y 2>/dev/null; dnf clean all 2>/dev/null || true; fi
				if command -v yum >/dev/null 2>&1; then yum autoremove -y 2>/dev/null; yum clean all 2>/dev/null || true; fi
				if command -v apt-get >/dev/null 2>&1; then apt-get autoremove -y 2>/dev/null && apt-get clean 2>/dev/null || true; fi

				echo "--> Truncating log files & purging user cache..."
				if command -v journalctl >/dev/null 2>&1; then journalctl --vacuum-size=20M 2>/dev/null || true; fi
				find /var/log -type f -name "*.log" -exec truncate -s 0 {} + 2>/dev/null || true
				rm -rf /root/.cache/* /home/*/.cache/* /tmp/* /var/tmp/* /var/cache/* 2>/dev/null || true

				echo "--> Pruning stopped containers & builders..."
				if command -v docker >/dev/null 2>&1; then
					docker system prune -a -f --volumes 2>/dev/null || true
					docker builder prune -a -f 2>/dev/null || true
				fi
				if command -v podman >/dev/null 2>&1; then
					podman system prune -a -f --volumes 2>/dev/null || true
				fi
			'`
			out, _ := executeElevatedCommandWithSpinner(client, hardCmd, "Executing Tier 2 Hard Cleaning")
			if strings.TrimSpace(out) != "" {
				fmt.Println(out)
			}
			fmt.Println(Green + "\n[✔] Tier 2 Hard Cleaning completed successfully!" + Reset)
			pausePrompt()

		case "3":
			fmt.Println(Red + Bold + "\n⚠ TIER 3 SUPER HARD CLEANING: Complete Reset & Destruction of Cached Layers!" + Reset)
			fmt.Println(Yellow + "This will stop all running Docker/Podman containers, wipe overlay2 layers, and truncate all system logs." + Reset)
			confirm := transfer.ReadRealtimeInput("Type 'CONFIRM' to execute Super Hard Clean: ")

			if strings.TrimSpace(confirm) == "CONFIRM" {
				fmt.Println(Yellow + "\n[+] Executing Tier 3: Super Hard System Reset & Deep Reclamation..." + Reset)
				superHardCmd := `sh -c '
					echo "--> [1/5] Stopping and removing all Docker containers & overlay storage..."
					if command -v docker >/dev/null 2>&1; then
						CONTAINERS=$(docker ps -aq)
						if [ -n "$CONTAINERS" ]; then
							docker stop $CONTAINERS 2>/dev/null || true
							docker rm -f $CONTAINERS 2>/dev/null || true
						fi
						docker system prune -a --volumes -f 2>/dev/null || true
						docker volume prune -f 2>/dev/null || true
						docker network prune -f 2>/dev/null || true
						docker builder prune -a -f 2>/dev/null || true
					fi

					echo "--> [2/5] Stopping and removing Podman containers..."
					if command -v podman >/dev/null 2>&1; then
						podman stop -a 2>/dev/null || true
						podman system prune -a --volumes -f 2>/dev/null || true
					fi

					echo "--> [3/5] Truncating container JSON logs and system log streams..."
					find /var/lib/docker/containers/ -type f -name "*-json.log" -exec truncate -s 0 {} + 2>/dev/null || true
					if command -v journalctl >/dev/null 2>&1; then
						journalctl --rotate 2>/dev/null || true
						journalctl --vacuum-time=1s 2>/dev/null || true
					fi
					find /var/log -type f -name "*.log" -exec truncate -s 0 {} + 2>/dev/null || true
					rm -rf /var/log/journal/* /var/log/*.gz /var/log/*-[0-9]* /var/lib/systemd/coredump/* /var/crash/* 2>/dev/null || true

					echo "--> [4/5] Purging root and system package caches..."
					rm -rf /var/cache/* /root/.cache/* /home/*/.cache/* /tmp/* /var/tmp/* 2>/dev/null || true
					rm -f /etc/group.* /etc/passwd.* /etc/shadow.* /etc/gshadow.* 2>/dev/null || true

					if command -v dnf >/dev/null 2>&1; then dnf clean all --enablerepo="*" 2>/dev/null || true; fi
					if command -v yum >/dev/null 2>&1; then yum clean all --enablerepo="*" 2>/dev/null || true; fi
					if command -v apt-get >/dev/null 2>&1; then apt-get clean 2>/dev/null || true; fi

					echo "--> [5/5] Current Filesystem Disk Usage:"
					df -h /
				'`
				out, _ := executeElevatedCommandWithSpinner(client, superHardCmd, "Executing Tier 3 Super Hard Clean")
				if strings.TrimSpace(out) != "" {
					fmt.Println(out)
				}
				fmt.Println(Green + "\n[✔] Tier 3 Super Hard Cleaning completed! Storage reset to baseline." + Reset)
			} else {
				fmt.Println(Yellow + "\n[!] Tier 3 cleaning cancelled." + Reset)
			}
			pausePrompt()

		case "0", "q", "Q":
			return
		}
	}
}

// CheckSpacePreFlight audits available disk space before launching heavy deployments
func CheckSpacePreFlight(client *ssh.Client, requiredMB int) bool {
	cmd := "df -m / | awk 'NR==2 {print $4}'"
	out, err := executeRemoteCommand(client, cmd)
	if err != nil {
		return true
	}

	freeMB, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return true
	}

	if freeMB < requiredMB {
		fmt.Printf(Red+Bold+"\n[!] INSUFFICIENT STORAGE DETECTED! Available: %d MB | Required: %d MB\n"+Reset, freeMB, requiredMB)
		fmt.Println(Yellow + "[+] Launching Storage Reclamation Engine to free space..." + Reset)

		buf := bufio.NewReader(strings.NewReader("\n"))
		ShowStorageCleanerMenu(buf, client)

		outCheck, _ := executeRemoteCommand(client, cmd)
		newFreeMB, _ := strconv.Atoi(strings.TrimSpace(outCheck))
		if newFreeMB < requiredMB {
			fmt.Printf(Red+"[!] Storage still insufficient (%d MB < %d MB). Deployment aborted.\n"+Reset, newFreeMB, requiredMB)
			return false
		}
	}
	return true
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return to menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}

func executeRemoteCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

func executeRemoteCommandWithSpinner(client *ssh.Client, cmd string, label string) (string, error) {
	done := make(chan bool)
	go func() {
		spinChars := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r%-70s\r", " ")
				return
			default:
				fmt.Printf("\r"+Cyan+"[%s] %s..."+Reset, spinChars[i%len(spinChars)], label)
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	out, err := executeRemoteCommand(client, cmd)
	done <- true
	return out, err
}

func executeElevatedCommand(client *ssh.Client, cmd string) (string, error) {
	wrappedCmd := fmt.Sprintf("if [ $(id -u) -eq 0 ]; then %s; else sudo -n %s 2>/dev/null || sudo %s; fi", cmd, cmd, cmd)
	return executeRemoteCommand(client, wrappedCmd)
}

func executeElevatedCommandWithSpinner(client *ssh.Client, cmd string, label string) (string, error) {
	done := make(chan bool)
	go func() {
		spinChars := []string{"|", "/", "-", "\\"}
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r%-70s\r", " ")
				return
			default:
				fmt.Printf("\r"+Cyan+"[%s] %s..."+Reset, spinChars[i%len(spinChars)], label)
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	wrappedCmd := fmt.Sprintf("if [ $(id -u) -eq 0 ]; then %s; else sudo -n %s 2>/dev/null || sudo %s; fi", cmd, cmd, cmd)
	out, err := executeRemoteCommand(client, wrappedCmd)
	done <- true
	return out, err
}