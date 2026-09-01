package probe

import (
	"bufio"
	"fmt"
	"net"
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

func ShowPortProbeMenu(reader *bufio.Reader, targetHost string) {
	fmt.Println(Cyan + Bold + "\n=== DIAGNOSTIC PORT PROBE & TCP BANNER SCANNER ===" + Reset)
	if targetHost == "" {
		targetHost = transfer.ReadRealtimeInput("Enter Target IP / Hostname to Probe: ")
		if targetHost == "" {
			return
		}
	} else {
		fmt.Printf(Yellow+"Probing active target: %s\n"+Reset, targetHost)
	}

	ports := []string{"22", "80", "443", "21", "23", "25", "3306", "5432", "6379", "8080", "8443"}
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+" %-8s | %-12s | %-30s\n"+Reset, "PORT", "STATUS", "SERVICE BANNER / RESPONSE")
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	for _, port := range ports {
		addr := net.JoinHostPort(targetHost, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			fmt.Printf(" %-8s | %s | -\n", port, Red+"CLOSED/FILTERED"+Reset)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		conn.Close()

		banner := "Open (No Banner Response)"
		if n > 0 {
			banner = fmt.Sprintf("%q", string(buf[:n]))
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}
		}

		fmt.Printf(" %-8s | %s | %s\n", port, Green+"OPEN"+Reset, banner)
	}
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)
	fmt.Print(Yellow + "\nPress Enter to return to menu..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}