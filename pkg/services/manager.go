package services

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
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
)

type ProcessItem struct {
	PID     string
	User    string
	CPU     string
	Mem     string
	Command string
}

func ShowServiceMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== REMOTE SERVICE, PORT, LOG & PROCESS MANAGER ===" + Reset)
		fmt.Printf(Yellow+"Target Operating System: "+Reset+Bold+"%s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] List & Manage Listening Ports (Active State, PID, Search)")
		fmt.Println("  [2] Service Management (Status, Reload/Restart, Interactive Picker, Purge)")
		fmt.Println("  [3] Inspect System / App Logs (Interactive Pager / Journalctl)")
		fmt.Println("  [4] Firewall Audit & Manipulation Engine (Smart Auto-Detect & Installer)")
		fmt.Println("  [5] Install Essential DevSecOps & SysAdmin CLI Tools (Linux & Windows)")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-5]: ")

		switch choice {
		case "1":
			portManagerSubMenu(reader, client, targetOS, sudoPass)
		case "2":
			serviceManagementSubMenu(reader, client, targetOS, sudoPass)
		case "3":
			inspectLogsMenu(reader, client, targetOS, sudoPass)
		case "4":
			firewallManipulationMenu(reader, client, targetOS, sudoPass)
		case "5":
			installEssentialToolsMenu(reader, client, targetOS, sudoPass)
		case "0", "q", "Q":
			return
		}
	}
}

func navigationChoice(reader *bufio.Reader) bool {
	fmt.Println(Blue + "\n------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] Stay on Current Menu / Run Another Action")
	fmt.Println(Red + "  [0] Return to Parent Sub-Menu" + Reset)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select choice [0-1]: ")
	return choice == "1"
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
	}
}

// ---------------- 1. PORT & PROCESS MANAGEMENT ----------------
func portManagerSubMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== PORT & PROCESS MANAGEMENT ENGINE ===" + Reset)
		fmt.Println("  [1] View All Active Listening Ports (Formatted Table)")
		fmt.Println("  [2] Search Port by Service Name, Port, or PID (Fuzzy Search)")
		fmt.Println("  [3] Lookup PID & Formatted Details for Service / Process Name")
		fmt.Println("  [4] Process Control Panel (Launch, Terminate, Check PID Status)")
		fmt.Println(Red + "  [0] Back to Service Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

		switch choice {
		case "1":
			for {
				listListeningPortsFormatted(client, targetOS, sudoPass, "")
				if !navigationChoice(reader) {
					break
				}
			}
		case "2":
			for {
				searchTerm := transfer.ReadRealtimeInput("\nEnter Service Name, Port, or PID to filter (e.g. network manager, 901, 53, nginx): ")
				listListeningPortsFormatted(client, targetOS, sudoPass, searchTerm)
				if !navigationChoice(reader) {
					break
				}
			}
		case "3":
			for {
				name := transfer.ReadRealtimeInput("\nEnter Service or Process Name to find PID (e.g. NetworkManager, sshd, nginx): ")
				if name != "" && name != "0" {
					lookupPIDByServiceNameFormatted(client, targetOS, sudoPass, name)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "4":
			processControlSubMenu(reader, client, targetOS, sudoPass)
		case "0", "q", "Q":
			return
		}
	}
}

func listListeningPortsFormatted(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, filter string) {
	rawOutput := runTaskWithSpinner("Fetching active listening ports", func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = `powershell -NoProfile -Command "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { '$([string]$_.LocalAddress):' + $_.LocalPort + ' ' + $_.OwningProcess }"`
		case osdetect.OSMacOS:
			cmd = `netstat -anv -p tcp | grep LISTEN`
		default: // OSLinux
			cmd = `ss -tulpn || netstat -tuln`
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n========================================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-10s | %-16s | %-10s | %-20s | %-25s\n"+Reset, "PROTOCOL", "STATE", "PORT", "BIND ADDRESS", "SERVICE / PID"))
	sb.WriteString(Blue + "--------------------------------------------------------------------------------------------------------\n" + Reset)

	cleanFilter := strings.ToLower(strings.ReplaceAll(filter, " ", ""))
	lines := strings.Split(rawOutput, "\n")
	found := 0

	for _, line := range lines {
		lineTrim := strings.TrimSpace(line)
		if lineTrim == "" || strings.HasPrefix(lineTrim, "Netid") || strings.HasPrefix(lineTrim, "Active") || strings.HasPrefix(lineTrim, "Proto") || strings.Contains(lineTrim, "+") || strings.Contains(lineTrim, "char:") {
			continue
		}

		lineNormalized := strings.ToLower(strings.ReplaceAll(lineTrim, " ", ""))
		if cleanFilter != "" && !strings.Contains(lineNormalized, cleanFilter) {
			continue
		}

		proto, port, bind, proc := parsePortLine(lineTrim, targetOS)
		if port == "" && bind == "" {
			continue
		}

		found++
		stateStr := Green + Bold + "[ACTIVE/LISTEN]" + Reset
		portColor := Cyan
		switch port {
		case "22":
			portColor = Green + Bold + "22 (SSH)"
		case "80", "443":
			portColor = Yellow + Bold + port + " (Web)"
		case "3306", "5432", "27017", "6379", "3389":
			portColor = Red + Bold + port + " (Database/RDP)"
		}

		displayPort := portColor + Reset
		if port == "" {
			displayPort = Yellow + "N/A" + Reset
		}

		sb.WriteString(fmt.Sprintf(" %-10s | %-16s | %-10s | %-20s | %-25s\n", proto, stateStr, displayPort, bind, proc))
	}

	if found == 0 {
		sb.WriteString(Yellow + " No matching active ports found.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "========================================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	displayInPager(sb.String())
}

func parsePortLine(line string, targetOS osdetect.TargetOS) (proto, port, bind, proc string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", "", ""
	}

	if targetOS == osdetect.OSWindows {
		addrPart := fields[0]
		pidPart := fields[1]

		if strings.Contains(addrPart, ":") {
			parts := strings.Split(addrPart, ":")
			port = parts[len(parts)-1]
			bind = strings.Join(parts[:len(parts)-1], ":")
			if bind == "" {
				bind = "0.0.0.0"
			}
			return "TCP", port, bind, "PID: " + pidPart
		}
		return "TCP", fields[0], "0.0.0.0", "PID: " + fields[1]
	}

	proto = strings.ToUpper(fields[0])
	portRegex := regexp.MustCompile(`^([a-zA-Z0-9\.\:\*\[\]\-]+)\:([0-9]+|\*)$`)

	for _, f := range fields {
		matches := portRegex.FindStringSubmatch(f)
		if len(matches) == 3 {
			bind = matches[1]
			port = matches[2]
			if bind == "" || bind == "*" {
				bind = "0.0.0.0"
			}
			break
		}
	}

	if bind == "" && len(fields) >= 5 {
		bind = fields[4]
	}

	proc = "Unknown"
	if strings.Contains(line, "users:(") {
		idx := strings.Index(line, "users:(")
		proc = line[idx:]
	} else if len(fields) > 4 {
		proc = fields[len(fields)-1]
	}

	return proto, port, bind, proc
}

func lookupPIDByServiceNameFormatted(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, name string) {
	raw := runTaskWithSpinner("Searching process details for '"+name+"'", func() string {
		var cmd string
		if targetOS == osdetect.OSWindows {
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "Get-Process -Name '*%s*' -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CPU, WorkingSet | Format-Table -HideTableHeaders"`, name)
		} else {
			cmd = fmt.Sprintf(`ps -eo pid,user,%%cpu,%%mem,vsz,rss,comm | grep -i '%s' | grep -v 'grep'`, name)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n===============================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-8s | %-12s | %-8s | %-8s | %-16s | %-20s\n"+Reset, "PID", "USER", "%CPU", "%MEM", "VSZ/RSS", "COMMAND/SERVICE"))
	sb.WriteString(Blue + "-----------------------------------------------------------------------------------------------\n" + Reset)

	lines := strings.Split(raw, "\n")
	found := 0

	for _, l := range lines {
		lTrim := strings.TrimSpace(l)
		if lTrim == "" {
			continue
		}

		fields := strings.Fields(lTrim)
		if len(fields) >= 2 {
			found++
			if targetOS == osdetect.OSWindows {
				sb.WriteString(fmt.Sprintf(" %-8s | %-12s | %-8s | %-8s | %-16s | %-20s\n", fields[0], "N/A", "N/A", "N/A", fields[3], fields[1]))
			} else if len(fields) >= 7 {
				memStr := fmt.Sprintf("%s/%s", fields[4], fields[5])
				sb.WriteString(fmt.Sprintf(" %-8s | %-12s | %-8s | %-8s | %-16s | %-20s\n", fields[0], fields[1], fields[2]+"%", fields[3]+"%", memStr, fields[6]))
			}
		}
	}

	if found == 0 {
		sb.WriteString(Red + " No active processes or services matching '" + name + "' found.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "===============================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	displayInPager(sb.String())
}

// ---------------- PROCESS CONTROL SUB-MENU ----------------
func processControlSubMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== PROCESS CONTROL & STATUS PANEL ===" + Reset)
		fmt.Println("  [1] Interactive Process List (Navigate with Arrow Keys ↑/↓ to Terminate)")
		fmt.Println("  [2] Direct PID Termination (Type exact PID Number)")
		fmt.Println("  [3] Check Live PID Status (Verify if PID is Running or Terminated)")
		fmt.Println("  [4] Launch / Start Background Process or Service")
		fmt.Println(Red + "  [0] Back to Port Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

		switch choice {
		case "1":
			killProcessInteractiveArrowKeys(client, targetOS, sudoPass)
		case "2":
			for {
				pid := transfer.ReadRealtimeInput("\nEnter exact PID Number to terminate: ")
				if pid != "" && pid != "0" {
					killProcessByPID(client, targetOS, sudoPass, pid)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "3":
			for {
				pid := transfer.ReadRealtimeInput("\nEnter PID Number to inspect status: ")
				if pid != "" && pid != "0" {
					checkPIDStatus(client, targetOS, sudoPass, pid)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "4":
			for {
				cmdStr := transfer.ReadRealtimeInput("\nEnter Command or Service Name to launch (e.g. consul, nginx, /usr/bin/app): ")
				if cmdStr != "" && cmdStr != "0" {
					launchBackgroundProcess(client, targetOS, sudoPass, cmdStr)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "0", "q", "Q":
			return
		}
	}
}

func checkPIDStatus(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, pid string) {
	raw := runTaskWithSpinner("Checking live status for PID "+pid, func() string {
		var cmd string
		if targetOS == osdetect.OSWindows {
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "Get-Process -Id %s -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CPU"`, pid)
		} else {
			cmd = fmt.Sprintf(`ps -p %s -o pid,user,%%cpu,%%mem,comm --no-headers`, pid)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(Cyan + "\n=== PID HEALTH & STATUS AUDIT ===" + Reset)
	if strings.TrimSpace(raw) != "" {
		fmt.Printf(" => STATUS: %s[● RUNNING / ALIVE]%s\n", Green+Bold, Reset)
		fmt.Println(raw)
	} else {
		fmt.Printf(" => STATUS: %s[○ TERMINATED / DEAD / NOT FOUND]%s\n", Red+Bold, Reset)
	}
	fmt.Println(Cyan + "---------------------------------" + Reset)
}

func killProcessInteractiveArrowKeys(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	raw := runTaskWithSpinner("Fetching active processes", func() string {
		var cmd string
		if targetOS == osdetect.OSWindows {
			cmd = `powershell -NoProfile -Command "Get-Process | Select-Object Id, ProcessName | Format-Table -HideTableHeaders"`
		} else {
			cmd = `ps -eo pid,user,%cpu,%mem,comm --sort=-%mem | head -n 40`
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	lines := strings.Split(raw, "\n")
	var processes []ProcessItem

	for _, line := range lines {
		lineTrim := strings.TrimSpace(line)
		if lineTrim == "" || strings.HasPrefix(lineTrim, "PID") {
			continue
		}

		fields := strings.Fields(lineTrim)
		if len(fields) >= 2 {
			if targetOS == osdetect.OSWindows {
				processes = append(processes, ProcessItem{
					PID:     fields[0],
					Command: fields[1],
				})
			} else if len(fields) >= 5 {
				processes = append(processes, ProcessItem{
					PID:     fields[0],
					User:    fields[1],
					CPU:     fields[2] + "%",
					Mem:     fields[3] + "%",
					Command: fields[4],
				})
			}
		}
	}

	if len(processes) == 0 {
		fmt.Println(Red + "[!] Could not fetch processes." + Reset)
		return
	}

	selectedIndex := 0
	_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1", "-echo").Run()
	defer transfer.ResetTerminal()

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== INTERACTIVE PROCESS TERMINATION SELECTOR ===" + Reset)
		fmt.Println(Yellow + "[↑/↓] Navigate  |  [ENTER] Select Process to Terminate  |  [0/Q] Cancel" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Printf(Bold+" %-8s | %-12s | %-8s | %-8s | %-25s\n"+Reset, "PID", "USER", "CPU", "MEM", "COMMAND")
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		for i, p := range processes {
			prefix := "   "
			if i == selectedIndex {
				prefix = Red + Bold + "=> " + Reset
			}

			if targetOS == osdetect.OSWindows {
				fmt.Printf("%s %-8s | %-25s\n", prefix, p.PID, p.Command)
			} else {
				fmt.Printf("%s %-8s | %-12s | %-8s | %-8s | %-25s\n", prefix, p.PID, p.User, p.CPU, p.Mem, p.Command)
			}
		}

		b := make([]byte, 3)
		os.Stdin.Read(b)

		if b[0] == 'q' || b[0] == 'Q' || b[0] == '0' {
			return
		}
		if b[0] == 27 && b[1] == 91 {
			switch b[2] {
			case 65: // Up
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 66: // Down
				if selectedIndex < len(processes)-1 {
					selectedIndex++
				}
			}
			continue
		}
		if b[0] == 10 || b[0] == 13 {
			targetProc := processes[selectedIndex]
			transfer.ResetTerminal()
			confirm := transfer.ReadRealtimeInput(Red + Bold + fmt.Sprintf("\n[CONFIRM] Terminate process '%s' (PID %s)? [y/N]: ", targetProc.Command, targetProc.PID) + Reset)
			if confirm == "y" || confirm == "Y" {
				killProcessByPID(client, targetOS, sudoPass, targetProc.PID)
			}
			return
		}
	}
}

func launchBackgroundProcess(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, cmdStr string) {
	out := runTaskWithSpinner("Launching process / service '"+cmdStr+"'", func() string {
		var cmd string
		if targetOS == osdetect.OSWindows {
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "Start-Process '%s' -NoNewWindow"`, cmdStr)
		} else {
			cmd = fmt.Sprintf(`systemctl start '%s' || service '%s' start || nohup %s > /dev/null 2>&1 &`, cmdStr, cmdStr, cmdStr)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

// ---------------- 2. SERVICE MANAGEMENT ENGINE ----------------
func serviceManagementSubMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== SERVICE MANAGEMENT ENGINE ===" + Reset)
		fmt.Println("  [1] Select Service from Interactive List (Arrow Keys ↑/↓)")
		fmt.Println("  [2] Enter Service Name Directly (e.g. consul, nginx, NetworkManager, sshd)")
		fmt.Println(Red + "  [0] Back to Service Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select option [0-2]: ")

		var selectedService string
		switch choice {
		case "1":
			selectedService = pickServiceArrowKeys(client, targetOS, sudoPass)
		case "2":
			selectedService = transfer.ReadRealtimeInput("\nEnter Service Name: ")
		case "0", "q", "Q":
			return
		}

		if selectedService == "" || selectedService == "0" {
			continue
		}

		manageSpecificService(reader, client, targetOS, selectedService, sudoPass)
	}
}

func pickServiceArrowKeys(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) string {
	raw := runTaskWithSpinner("Fetching active/inactive services", func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = `powershell -NoProfile -Command "Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"`
		case osdetect.OSMacOS:
			cmd = `launchctl list | awk '{print $3}'`
		default: // OSLinux
			cmd = `systemctl list-unit-files --type=service --no-pager --no-legend`
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	lines := strings.Split(raw, "\n")
	var services []string

	for _, l := range lines {
		l = strings.TrimSpace(strings.ReplaceAll(l, "\r", ""))
		if l == "" || strings.HasPrefix(l, "At ") || strings.HasPrefix(l, "char:") || strings.Contains(l, "CategoryInfo") {
			continue
		}

		fields := strings.Fields(l)
		if len(fields) > 0 {
			cleanName := strings.TrimSuffix(fields[0], ".service")
			if cleanName != "" {
				services = append(services, cleanName)
			}
		}
	}

	if len(services) == 0 {
		fmt.Println(Red + "[!] Could not auto-detect services." + Reset)
		return ""
	}

	sort.Strings(services)
	if len(services) > 50 {
		services = services[:50]
	}

	selectedIndex := 0
	_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1", "-echo").Run()
	defer transfer.ResetTerminal()

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== INTERACTIVE SERVICE SELECTOR ===" + Reset)
		fmt.Println(Yellow + "[↑/↓] Navigate  |  [ENTER] Select Service  |  [0/Q] Cancel" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		for i, s := range services {
			if i == selectedIndex {
				fmt.Printf(Green+Bold+" =>  %s\n"+Reset, s)
			} else {
				fmt.Printf("     %s\n", s)
			}
		}

		b := make([]byte, 3)
		os.Stdin.Read(b)

		if b[0] == 'q' || b[0] == 'Q' || b[0] == '0' {
			return ""
		}
		if b[0] == 27 && b[1] == 91 {
			switch b[2] {
			case 65: // Up
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 66: // Down
				if selectedIndex < len(services)-1 {
					selectedIndex++
				}
			}
			continue
		}
		if b[0] == 10 || b[0] == 13 {
			return services[selectedIndex]
		}
	}
}

func manageSpecificService(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, service string, sudoPass string) {
	service = strings.Fields(service)[0]

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== SERVICE CONTROL PANEL: " + Yellow + service + Reset)

		renderServiceStatusSummary(client, targetOS, service, sudoPass)

		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] Start Service")
		fmt.Println("  [2] Stop Service")
		fmt.Println("  [3] Restart Service")
		fmt.Println("  [4] Enable Service on Boot")
		fmt.Println("  [5] Daemon Reload (systemctl daemon-reload)")
		fmt.Println("  [6] Daemon Reload + Restart Service (Combination)")
		fmt.Println("  [7] Fully Purge & Uninstall Service (apt purge --autoremove)")
		fmt.Println(Red + "  [0] Back to Service List" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		action := transfer.ReadRealtimeInput("Select action [0-7]: ")

		var cmd string
		switch action {
		case "1":
			cmd = getServiceControlCmd(targetOS, "start", service)
		case "2":
			cmd = getServiceControlCmd(targetOS, "stop", service)
		case "3":
			cmd = getServiceControlCmd(targetOS, "restart", service)
		case "4":
			cmd = getServiceControlCmd(targetOS, "enable", service)
		case "5":
			cmd = "systemctl daemon-reload"
		case "6":
			cmd = fmt.Sprintf("systemctl daemon-reload && systemctl restart '%s'", service)
		case "7":
			if targetOS == osdetect.OSLinux {
				confirm := transfer.ReadRealtimeInput(Red + Bold + "Type 'YES' to permanently purge package " + service + ": " + Reset)
				if confirm == "YES" {
					cmd = fmt.Sprintf("apt-get purge -y %s || dnf remove -y %s || yum remove -y %s", service, service, service)
				}
			} else {
				fmt.Println(Yellow + "[!] Package purge is optimized for Linux systems." + Reset)
			}
		case "0", "q", "Q":
			return
		}

		if cmd != "" {
			out := runTaskWithSpinner("Executing service action on '"+service+"'", func() string {
				return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
			})
			fmt.Println(out)
			if !navigationChoice(reader) {
				return
			}
		}
	}
}

func renderServiceStatusSummary(client *ssh.Client, targetOS osdetect.TargetOS, service string, sudoPass string) {
	var cmd string
	switch targetOS {
	case osdetect.OSWindows:
		cmd = fmt.Sprintf(`powershell -NoProfile -Command "Get-Service -Name '%s' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType"`, service)
	case osdetect.OSMacOS:
		cmd = fmt.Sprintf(`launchctl list | grep '%s'`, service)
	default: // OSLinux
		cmd = fmt.Sprintf(`systemctl is-active '%s' && systemctl is-enabled '%s'`, service, service)
	}

	raw := executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)

	var sb strings.Builder
	sb.WriteString(" => HEALTH BADGE: ")
	if strings.Contains(raw, "active") || strings.Contains(raw, "Running") {
		sb.WriteString(Green + Bold + "[● ACTIVE / RUNNING]\n" + Reset)
	} else if strings.Contains(raw, "activating") {
		sb.WriteString(Yellow + Bold + "[◐ ACTIVATING / STARTING...]\n" + Reset)
	} else {
		sb.WriteString(Red + Bold + "[○ INACTIVE / STOPPED]\n" + Reset)
	}

	sb.WriteString(Cyan + "\n--- RAW SERVICE STATUS ---\n" + Reset)
	statusCmd := getServiceControlCmd(targetOS, "status", service)
	sb.WriteString(executeRemoteCommandElevated(client, statusCmd, sudoPass, targetOS))
	sb.WriteString(Yellow + "\n\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	displayInPager(sb.String())
}

func getServiceControlCmd(targetOS osdetect.TargetOS, action string, service string) string {
	switch targetOS {
	case osdetect.OSWindows:
		switch action {
		case "start":
			return fmt.Sprintf("powershell -NoProfile -Command \"Start-Service -Name '%s'\"", service)
		case "stop":
			return fmt.Sprintf("powershell -NoProfile -Command \"Stop-Service -Name '%s'\"", service)
		case "restart":
			return fmt.Sprintf("powershell -NoProfile -Command \"Restart-Service -Name '%s'\"", service)
		case "status":
			return fmt.Sprintf("powershell -NoProfile -Command \"Get-Service -Name '%s'\"", service)
		}
	default: // Linux / macOS
		switch action {
		case "start":
			return fmt.Sprintf("systemctl start '%s' || service '%s' start", service, service)
		case "stop":
			return fmt.Sprintf("systemctl stop '%s' || service '%s' stop", service, service)
		case "restart":
			return fmt.Sprintf("systemctl restart '%s' || service '%s' restart", service, service)
		case "enable":
			return fmt.Sprintf("systemctl enable '%s'", service)
		case "status":
			return fmt.Sprintf("systemctl status '%s' --no-pager || service '%s' status", service, service)
		}
	}
	return ""
}

// ---------------- 3. LOG INSPECTOR ----------------
func inspectLogsMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== REMOTE SYSTEM LOG INSPECTOR ===" + Reset)
		fmt.Println("  [1] Pick Service Log from Interactive List")
		fmt.Println("  [2] Type Service Name directly for Journalctl")
		fmt.Println("  [3] View General System Log (Journalctl / syslog)")
		fmt.Println(Red + "  [0] Back to Service Menu" + Reset)

		choice := transfer.ReadRealtimeInput("Select option [0-3]: ")
		var service string

		switch choice {
		case "1":
			service = pickServiceArrowKeys(client, targetOS, sudoPass)
		case "2":
			service = transfer.ReadRealtimeInput("\nEnter Service Name for logs: ")
		case "3":
			service = ""
		case "0", "q", "Q":
			return
		}

		if choice != "3" && service == "" {
			continue
		}

		out := runTaskWithSpinner("Extracting log entries", func() string {
			var cmd string
			if targetOS == osdetect.OSWindows {
				cmd = `powershell -NoProfile -Command "Get-EventLog -LogName System -Newest 100 | Format-Table -AutoSize"`
			} else if service != "" {
				cmd = fmt.Sprintf("journalctl -u '%s' -n 150 --no-pager || tail -n 150 /var/log/syslog", service)
			} else {
				cmd = "journalctl -n 150 --no-pager || tail -n 150 /var/log/syslog"
			}
			return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
		})

		formattedLog := formatLogsOutput(out)
		displayInPager(formattedLog)
	}
}

func formatLogsOutput(raw string) string {
	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n========================================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-15s | %-18s | %-15s | %-40s\n"+Reset, "TIMESTAMP", "HOST / COMPONENT", "LEVEL / STATUS", "MESSAGE LOG DETAIL"))
	sb.WriteString(Blue + "--------------------------------------------------------------------------------------------------------\n" + Reset)

	lines := strings.Split(raw, "\n")
	found := 0

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		found++

		levelBadge := Cyan + "[INFO]" + Reset
		if strings.Contains(strings.ToLower(l), "error") || strings.Contains(strings.ToLower(l), "failed") || strings.Contains(strings.ToLower(l), "err") {
			levelBadge = Red + Bold + "[ERROR]" + Reset
		} else if strings.Contains(strings.ToLower(l), "warn") || strings.Contains(strings.ToLower(l), "warning") {
			levelBadge = Yellow + Bold + "[WARN]" + Reset
		}

		fields := strings.Fields(l)
		if len(fields) >= 5 {
			timestamp := strings.Join(fields[:3], " ")
			hostAndComp := fields[3]
			msgDetail := strings.Join(fields[4:], " ")

			if len(msgDetail) > 50 {
				msgDetail = msgDetail[:47] + "..."
			}

			sb.WriteString(fmt.Sprintf(" %-15s | %-18s | %-15s | %-40s\n", timestamp, hostAndComp, levelBadge, msgDetail))
		} else {
			sb.WriteString(fmt.Sprintf(" %-90s\n", l))
		}
	}

	if found == 0 {
		sb.WriteString(Yellow + " No system logs found.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "========================================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	return sb.String()
}

// ---------------- 4. SMART MULTI-OS FIREWALL ENGINE ----------------
func firewallManipulationMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== MULTI-OS FIREWALL AUDIT & MANIPULATION ENGINE ===" + Reset)
		fmt.Printf(Yellow+"Target OS: "+Reset+Bold+"%s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] View Active Firewall Rules & Profile Status")
		fmt.Println("  [2] Enable Firewall Service (UFW / Firewalld / Windows Firewall)")
		fmt.Println("  [3] Disable Firewall Service")
		fmt.Println("  [4] Allow / Open Specific Port (TCP/UDP)")
		fmt.Println("  [5] Deny / Block Specific Port (TCP/UDP)")
		fmt.Println("  [6] Reload Firewall Configuration")
		fmt.Println("  [7] Install Firewall Package on Target Host (UFW / Firewalld)")
		fmt.Println(Red + "  [0] Back to Service Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select choice [0-7]: ")

		switch choice {
		case "1":
			checkFirewallStatusFixed(client, targetOS, sudoPass)
		case "2":
			for {
				toggleFirewallState(client, targetOS, sudoPass, true)
				if !navigationChoice(reader) {
					break
				}
			}
		case "3":
			for {
				toggleFirewallState(client, targetOS, sudoPass, false)
				if !navigationChoice(reader) {
					break
				}
			}
		case "4":
			for {
				port := transfer.ReadRealtimeInput("\nEnter Port Number to ALLOW (e.g. 80, 443, 8080): ")
				if port != "" && port != "0" {
					allowPortInFirewall(client, targetOS, sudoPass, port)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "5":
			for {
				port := transfer.ReadRealtimeInput("\nEnter Port Number to DENY/BLOCK (e.g. 3306, 6379): ")
				if port != "" && port != "0" {
					blockPortInFirewall(client, targetOS, sudoPass, port)
				}
				if !navigationChoice(reader) {
					break
				}
			}
		case "6":
			for {
				reloadFirewallConfig(client, targetOS, sudoPass)
				if !navigationChoice(reader) {
					break
				}
			}
		case "7":
			for {
				installFirewallPackage(client, targetOS, sudoPass)
				if !navigationChoice(reader) {
					break
				}
			}
		case "0", "q", "Q":
			return
		}
	}
}

func checkFirewallStatusFixed(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	out := runTaskWithSpinner("Inspecting firewall rule set", func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = `powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name, Enabled; Get-NetFirewallRule -Enabled True | Select-Object Name, DisplayName, Direction, Action -First 30"`
		case osdetect.OSMacOS:
			cmd = `defaults read /Library/Preferences/com.apple.alf globalstate`
		default: // OSLinux
			cmd = `if command -v ufw >/dev/null 2>&1; then ufw status verbose; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --list-all; else iptables -L -n -v | head -n 30; fi`
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n========================================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-20s | %-75s\n"+Reset, "FIREWALL ENGINE", "ACTIVE RULE SET & PROFILE STATUS"))
	sb.WriteString(Blue + "--------------------------------------------------------------------------------------------------------\n" + Reset)

	if strings.TrimSpace(out) != "" {
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			lTrim := strings.TrimSpace(l)
			if lTrim != "" {
				sb.WriteString(fmt.Sprintf(" %-20s | %-75s\n", Green+"[ACTIVE RULE]"+Reset, lTrim))
			}
		}
	} else {
		sb.WriteString(Yellow + " No active firewall rules detected or firewall daemon stopped.\n" + Reset)
	}

	sb.WriteString(Cyan + Bold + "========================================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	displayInPager(sb.String())
}

func toggleFirewallState(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, enable bool) {
	stateWord := "ENABLE"
	if !enable {
		stateWord = "DISABLE"
	}

	out := runTaskWithSpinner(stateWord+" firewall service", func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			if enable {
				cmd = `powershell -NoProfile -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"`
			} else {
				cmd = `powershell -NoProfile -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"`
			}
		default: // Linux
			if enable {
				cmd = `if command -v ufw >/dev/null 2>&1; then ufw --force enable; elif command -v firewall-cmd >/dev/null 2>&1; then systemctl start firewalld && systemctl enable firewalld; fi`
			} else {
				cmd = `if command -v ufw >/dev/null 2>&1; then ufw disable; elif command -v firewall-cmd >/dev/null 2>&1; then systemctl stop firewalld; fi`
			}
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

func allowPortInFirewall(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, port string) {
	out := runTaskWithSpinner("Adding ALLOW rule for port "+port, func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "New-NetFirewallRule -DisplayName 'Allow-Port-%s' -Direction Inbound -LocalPort %s -Protocol TCP -Action Allow"`, port, port)
		default: // Linux
			cmd = fmt.Sprintf(`if command -v ufw >/dev/null 2>&1; then ufw allow %s/tcp; elif command -v firewall-cmd >/dev/null 2>&1; then systemctl start firewalld && firewall-cmd --add-port=%s/tcp --permanent && firewall-cmd --reload; else iptables -A INPUT -p tcp --dport %s -j ACCEPT; fi`, port, port, port)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

func blockPortInFirewall(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, port string) {
	out := runTaskWithSpinner("Adding BLOCK rule for port "+port, func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "New-NetFirewallRule -DisplayName 'Block-Port-%s' -Direction Inbound -LocalPort %s -Protocol TCP -Action Block"`, port, port)
		default: // Linux
			cmd = fmt.Sprintf(`if command -v ufw >/dev/null 2>&1; then ufw deny %s/tcp; elif command -v firewall-cmd >/dev/null 2>&1; then systemctl start firewalld && firewall-cmd --remove-port=%s/tcp --permanent && firewall-cmd --reload; else iptables -A INPUT -p tcp --dport %s -j DROP; fi`, port, port, port)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

func reloadFirewallConfig(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	out := runTaskWithSpinner("Reloading firewall configuration", func() string {
		var cmd string
		switch targetOS {
		case osdetect.OSWindows:
			cmd = `powershell -NoProfile -Command "Get-NetFirewallProfile"`
		default: // Linux
			cmd = `if command -v ufw >/dev/null 2>&1; then ufw reload; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --reload; fi`
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

func installFirewallPackage(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	if targetOS != osdetect.OSLinux {
		fmt.Println(Yellow + "[!] Firewall installation is designed for Linux targets." + Reset)
		return
	}

	fmt.Println(Cyan + "\n[+] Select Firewall Backend Package to Install:" + Reset)
	fmt.Println("  [1] Install UFW (Uncomplicated Firewall - Debian / Ubuntu)")
	fmt.Println("  [2] Install Firewalld (CentOS / RHEL / Fedora)")

	choice := transfer.ReadRealtimeInput("Select choice [1-2]: ")
	var cmd string

	if choice == "1" {
		cmd = "apt-get update -y && apt-get install -y ufw && ufw --force enable"
	} else if choice == "2" {
		cmd = "(yum install -y firewalld || dnf install -y firewalld) && systemctl start firewalld && systemctl enable firewalld"
	}

	if cmd != "" {
		out := runTaskWithSpinner("Installing firewall package on target", func() string {
			return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
		})
		fmt.Println(out)
		fmt.Println(Green + Bold + "[SUCCESS] Firewall package installation complete!" + Reset)
	}
}

func killProcessByPID(client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string, pid string) {
	out := runTaskWithSpinner("Terminating process PID "+pid, func() string {
		var cmd string
		if targetOS == osdetect.OSWindows {
			cmd = fmt.Sprintf(`powershell -NoProfile -Command "Stop-Process -Id %s -Force"`, pid)
		} else {
			cmd = fmt.Sprintf(`kill -9 %s`, pid)
		}
		return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
	})

	fmt.Println(out)
}

// ---------------- 5. ESSENTIAL DEVSECOPS TOOL INSTALLER (MULTI-OS: LINUX & WINDOWS) ----------------
func installEssentialToolsMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, sudoPass string) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== ESSENTIAL SYSADMIN / DEVSECOPS CLI TOOL INSTALLER ===" + Reset)
		fmt.Printf(Yellow+"Target Operating System: "+Reset+Bold+"%s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		if targetOS == osdetect.OSWindows {
			fmt.Println("Select Windows CLI tools package to install via Winget / PowerShell:")
			fmt.Println("  [1] System Monitors & Info (btop, fastfetch)")
			fmt.Println("  [2] DevSecOps Utilities (jq, ripgrep, nmap, curl)")
			fmt.Println("  [3] Shell Upgrades (PowerShell 7, Oh-My-Posh, Windows Terminal)")
			fmt.Println("  [4] FULL SUITE (Install All Windows CLI Tools)")
			fmt.Println(Red + "  [0] Back to Service Menu" + Reset)
			fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

			choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

			var wingetIds string
			switch choice {
			case "1":
				wingetIds = "aristocratos.btop Fastfetch-cli.Fastfetch"
			case "2":
				wingetIds = "jqlang.jq BurntSushi.ripgrep.MSVC Insecure.Nmap cURL.cURL"
			case "3":
				wingetIds = "Microsoft.PowerShell JanDeDobbeleer.OhMyPosh Microsoft.WindowsTerminal"
			case "4":
				wingetIds = "aristocratos.btop Fastfetch-cli.Fastfetch jqlang.jq BurntSushi.ripgrep.MSVC Insecure.Nmap Microsoft.PowerShell JanDeDobbeleer.OhMyPosh"
			case "0", "q", "Q":
				return
			}

			if wingetIds != "" {
				out := runTaskWithSpinner("Installing Windows packages via Winget", func() string {
					cmd := fmt.Sprintf(`powershell -NoProfile -Command "
						$pkgs = '%s'.Split(' ');
						foreach ($p in $pkgs) {
							winget install --id $p --exact --accept-source-agreements --accept-package-agreements --silent
						}
					"`, wingetIds)
					return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
				})

				fmt.Println(out)
				fmt.Println(Green + Bold + "\n[SUCCESS] Windows CLI tools installation completed!" + Reset)

				if !navigationChoice(reader) {
					return
				}
			}
		} else {
			fmt.Println("Select Linux essential tools package to install automatically:")
			fmt.Println("  [1] System & Process Monitors (htop, btop, ncdu, fastfetch)")
			fmt.Println("  [2] Network & Security Utilities (nmap, tcpdump, net-tools, ufw, curl, wget)")
			fmt.Println("  [3] Productivity & Terminal Utilities (tmux, zsh, jq, git, tree, ripgrep, unzip)")
			fmt.Println("  [4] FULL SUITE (Install ALL of the above tools at once)")
			fmt.Println(Red + "  [0] Back to Service Menu" + Reset)
			fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

			choice := transfer.ReadRealtimeInput("Select choice [0-4]: ")

			var debPkgs, rpmPkgs string
			switch choice {
			case "1":
				debPkgs = "htop btop ncdu fastfetch neofetch"
				rpmPkgs = "htop btop ncdu neofetch"
			case "2":
				debPkgs = "nmap tcpdump net-tools ufw curl wget"
				rpmPkgs = "nmap tcpdump net-tools firewalld curl wget"
			case "3":
				debPkgs = "tmux zsh jq git tree ripgrep unzip"
				rpmPkgs = "tmux zsh jq git tree ripgrep unzip"
			case "4":
				debPkgs = "htop btop ncdu fastfetch nmap tcpdump net-tools ufw curl wget tmux zsh jq git tree ripgrep unzip"
				rpmPkgs = "htop btop ncdu nmap tcpdump net-tools firewalld curl wget tmux zsh jq git tree ripgrep unzip"
			case "0", "q", "Q":
				return
			}

			if debPkgs != "" {
				out := runTaskWithSpinner("Detecting package manager and installing packages", func() string {
					cmd := fmt.Sprintf(`if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y %s; elif command -v dnf >/dev/null 2>&1; then dnf install -y epel-release 2>/dev/null; dnf install -y %s; elif command -v yum >/dev/null 2>&1; then yum install -y epel-release 2>/dev/null; yum install -y %s; elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm %s; elif command -v zypper >/dev/null 2>&1; then zypper install -y %s; else echo "Error: No supported Linux package manager found."; fi`, debPkgs, rpmPkgs, rpmPkgs, debPkgs, debPkgs)

					return executeRemoteCommandElevated(client, cmd, sudoPass, targetOS)
				})

				fmt.Println(out)
				fmt.Println(Green + Bold + "\n[SUCCESS] Linux CLI tools installation completed!" + Reset)

				if !navigationChoice(reader) {
					return
				}
			}
		}
	}
}

func executeRemoteCommandElevated(client *ssh.Client, rawCmd string, sudoPass string, targetOS osdetect.TargetOS) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("[Error creating SSH session: %v]", err)
	}
	defer session.Close()

	var finalCmd string
	if targetOS == osdetect.OSWindows {
		finalCmd = rawCmd
	} else if sudoPass != "" {
		escapedPass := strings.ReplaceAll(sudoPass, "'", "'\\''")
		finalCmd = fmt.Sprintf("echo '%s' | sudo -S -p '' bash -c %q 2>&1", escapedPass, rawCmd)
	} else {
		finalCmd = rawCmd + " 2>&1"
	}

	output, _ := session.CombinedOutput(finalCmd)
	return string(output)
}