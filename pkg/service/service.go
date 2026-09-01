package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

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

func ShowServiceManagerMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Cyan + Bold + "=== REMOTE SERVICE, PORT, LOG & PROCESS MANAGER ===" + Reset)
		fmt.Printf(Yellow+"Target Operating System: %s\n"+Reset, targetOS)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
		fmt.Println("  [1] List Running Services")
		fmt.Println("  [2] Check Open Ports & Listening Sockets")
		fmt.Println("  [3] View Live System Logs")
		fmt.Println("  [4] List Running Top Processes")
		fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
		fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

		rawChoice := transfer.ReadRealtimeInput("Select choice [0-4]: ")
		choice := cleanInput(rawChoice)

		switch choice {
		case "1":
			runRemoteCmdFormatted(client, targetOS, "services")
		case "2":
			runRemoteCmdFormatted(client, targetOS, "ports")
		case "3":
			runRemoteCmdFormatted(client, targetOS, "logs")
		case "4":
			runRemoteCmdFormatted(client, targetOS, "ps")
		case "0", "q", "Q":
			return
		default:
			// Safely ignore invalid inputs or arrow key escape codes
			continue
		}
	}
}

func cleanInput(in string) string {
	clean := strings.TrimSpace(in)
	clean = regexp.MustCompile(`\x1b\[[A-Za-z0-9]+`).ReplaceAllString(clean, "")
	clean = regexp.MustCompile(`\[[A-Z]`).ReplaceAllString(clean, "")
	return strings.TrimSpace(clean)
}

func runRemoteCmdFormatted(client *ssh.Client, targetOS osdetect.TargetOS, cmdType string) {
	session, err := client.NewSession()
	if err != nil {
		displayInPager(Red + fmt.Sprintf("[!] SSH session creation failed: %v", err) + Reset)
		return
	}
	defer session.Close()

	var command string
	if targetOS == osdetect.OSWindows {
		switch cmdType {
		case "services":
			command = "powershell -NoProfile -Command Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, Status, DisplayName"
		case "ports":
			command = "powershell -NoProfile -Command Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess"
		case "logs":
			command = "powershell -NoProfile -Command Get-EventLog -LogName System -Newest 100"
		case "ps":
			command = "powershell -NoProfile -Command Get-Process | Sort-Object CPU -Descending | Select-Object Id, ProcessName, CPU, WorkingSet"
		}
	} else {
		switch cmdType {
		case "services":
			command = "systemctl list-units --type=service --state=running --no-pager --no-legend || service --status-all"
		case "ports":
			command = "ss -tulpn || netstat -tuln"
		case "logs":
			command = "journalctl -n 150 --no-pager || tail -n 150 /var/log/syslog"
		case "ps":
			command = "ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu"
		}
	}

	out, err := session.CombinedOutput(command)
	raw := string(out)

	if err != nil && raw == "" {
		displayInPager(Red + fmt.Sprintf("[!] Command execution error: %v", err) + Reset)
		return
	}

	var formattedOutput string
	switch cmdType {
	case "ports":
		formattedOutput = formatPortsOutput(raw, targetOS)
	case "services":
		formattedOutput = formatServicesOutput(raw, targetOS)
	case "ps":
		formattedOutput = formatProcessesOutput(raw, targetOS)
	case "logs":
		formattedOutput = formatLogsOutput(raw)
	default:
		formattedOutput = raw
	}

	displayInPager(formattedOutput)
}

// ---------------- FORMATTERS ----------------

func formatPortsOutput(raw string, targetOS osdetect.TargetOS) string {
	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n========================================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-10s | %-16s | %-12s | %-20s | %-25s\n"+Reset, "PROTOCOL", "STATE", "PORT", "BIND ADDRESS", "SERVICE / PID"))
	sb.WriteString(Blue + "--------------------------------------------------------------------------------------------------------\n" + Reset)

	lines := strings.Split(raw, "\n")
	found := 0

	for _, line := range lines {
		lineTrim := strings.TrimSpace(line)
		if lineTrim == "" || strings.HasPrefix(lineTrim, "Netid") || strings.HasPrefix(lineTrim, "Active") || strings.HasPrefix(lineTrim, "Proto") {
			continue
		}

		proto, port, bind, proc := parsePortLineSimple(lineTrim, targetOS)
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

		sb.WriteString(fmt.Sprintf(" %-10s | %-16s | %-12s | %-20s | %-25s\n", proto, stateStr, displayPort, bind, proc))
	}

	if found == 0 {
		sb.WriteString(Yellow + " No active listening ports found.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "========================================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	return sb.String()
}

func parsePortLineSimple(line string, targetOS osdetect.TargetOS) (proto, port, bind, proc string) {
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
	
	// Scan fields for address:port patterns (e.g. 0.0.0.0:22 or [::]:80 or 127.0.0.1:5432)
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
	} else if len(fields) > 5 {
		proc = fields[len(fields)-1]
	}

	return proto, port, bind, proc
}

func formatServicesOutput(raw string, targetOS osdetect.TargetOS) string {
	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n===============================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-35s | %-18s | %-20s\n"+Reset, "SERVICE UNIT", "STATE", "HEALTH STATUS"))
	sb.WriteString(Blue + "-----------------------------------------------------------------------------------------------\n" + Reset)

	lines := strings.Split(raw, "\n")
	found := 0

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "UNIT") || strings.HasPrefix(l, "LOAD") {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) >= 1 {
			found++
			svcName := strings.TrimSuffix(fields[0], ".service")
			if len(svcName) > 35 {
				svcName = svcName[:32] + "..."
			}

			stateStr := "active (running)"
			stateBadge := Green + Bold + "[● RUNNING]" + Reset

			if strings.Contains(l, "[ - ]") || strings.Contains(l, "dead") || strings.Contains(l, "stopped") {
				stateStr = "inactive (stopped)"
				stateBadge = Red + Bold + "[○ STOPPED]" + Reset
			}

			sb.WriteString(fmt.Sprintf(" %-35s | %-18s | %-20s\n", svcName, stateStr, stateBadge))
		}
	}

	if found == 0 {
		sb.WriteString(Yellow + " No active running services detected.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "===============================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	return sb.String()
}

func formatProcessesOutput(raw string, targetOS osdetect.TargetOS) string {
	var sb strings.Builder
	sb.WriteString(Cyan + Bold + "\n===============================================================================================\n" + Reset)
	sb.WriteString(fmt.Sprintf(Bold+" %-8s | %-12s | %-8s | %-8s | %-25s\n"+Reset, "PID", "USER", "%CPU", "%MEM", "COMMAND"))
	sb.WriteString(Blue + "-----------------------------------------------------------------------------------------------\n" + Reset)

	lines := strings.Split(raw, "\n")
	found := 0

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "PID") || strings.HasPrefix(l, "USER") {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) >= 5 {
			found++
			cpuVal := fields[2]
			cpuFormatted := Cyan + cpuVal + "%" + Reset
			if strings.HasPrefix(cpuVal, "1") || strings.HasPrefix(cpuVal, "2") || strings.HasPrefix(cpuVal, "3") || strings.HasPrefix(cpuVal, "4") || strings.HasPrefix(cpuVal, "5") {
				cpuFormatted = Red + Bold + cpuVal + "%" + Reset
			}
			sb.WriteString(fmt.Sprintf(" %-8s | %-12s | %-8s | %-8s | %-25s\n", fields[0], fields[1], cpuFormatted, fields[3]+"%", fields[4]))
		}
	}

	if found == 0 {
		sb.WriteString(Yellow + " No active top processes found.\n" + Reset)
	}
	sb.WriteString(Cyan + Bold + "===============================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	return sb.String()
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
		if strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "ERR") {
			levelBadge = Red + Bold + "[ERROR]" + Reset
		} else if strings.Contains(l, "warn") || strings.Contains(l, "WARNING") {
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
	sb.WriteString(Cyan + Bold + "===============================================================================================\n" + Reset)
	sb.WriteString(Yellow + "\n[ Navigation: ARROW KEYS / SPACEBAR to Scroll | Press 'q' to Exit to Menu ]\n" + Reset)

	return sb.String()
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