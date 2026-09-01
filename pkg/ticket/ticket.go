package ticket

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Dim     = "\033[2m"
)

type TicketStatus string

const (
	StatusPending  TicketStatus = "PENDING_REVIEW"
	StatusApproved TicketStatus = "APPROVED"
	StatusRejected TicketStatus = "NEEDS_REVISION"
)

type TaskTicket struct {
	ID          int          `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Author      string       `json:"author"`
	Approver    string       `json:"approver,omitempty"`
	Status      TicketStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	ResolvedAt  time.Time    `json:"resolved_at,omitempty"`
	HostNote    string       `json:"host_note,omitempty"`
}

type TicketLedger struct {
	Tickets []TaskTicket `json:"tickets"`
}

type NotificationItem struct {
	ID        int       `json:"id"`
	SenderIP  string    `json:"sender_ip"`
	SenderTag string    `json:"sender_tag"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	IsRead    bool      `json:"is_read"`
}

var (
	ledgerMutex sync.Mutex
	nextID      = 1
)

func getLocalIdentity() string {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		return sudoUser
	}
	u, err := user.Current()
	if err == nil && u.Username != "" {
		parts := strings.Split(u.Username, "\\")
		return parts[len(parts)-1]
	}
	envUser := os.Getenv("USER")
	if envUser != "" {
		return envUser
	}
	return "local-node"
}

func getLedgerPath() string {
	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		if runtime.GOOS == "linux" {
			home = filepath.Join("/home", sudoUser)
		} else if runtime.GOOS == "darwin" {
			home = filepath.Join("/Users", sudoUser)
		}
	} else if err != nil || home == "" {
		home = os.TempDir()
	}
	dir := filepath.Join(home, ".cross-ssh")
	_ = os.MkdirAll(dir, 0777)
	return filepath.Join(dir, "tickets.json")
}

func getInboxCandidatePaths() []string {
	var candidates []string
	candidates = append(candidates, "/tmp/cross_peer_inbox.json", filepath.Join(os.TempDir(), "cross_peer_inbox.json"))

	sudoUser := os.Getenv("SUDO_USER")
	home, err := os.UserHomeDir()
	if sudoUser != "" && sudoUser != "root" {
		candidates = append(candidates, filepath.Join("/home", sudoUser, ".cross-ssh", "peer_inbox.json"))
	}
	if err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".cross-ssh", "peer_inbox.json"))
	}
	candidates = append(candidates, "/root/.cross-ssh/peer_inbox.json")
	return candidates
}

func loadLocalLedger() *TicketLedger {
	ledgerMutex.Lock()
	defer ledgerMutex.Unlock()

	data, err := os.ReadFile(getLedgerPath())
	if err != nil {
		return &TicketLedger{Tickets: []TaskTicket{}}
	}
	var ledger TicketLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		return &TicketLedger{Tickets: []TaskTicket{}}
	}

	for _, t := range ledger.Tickets {
		if t.ID >= nextID {
			nextID = t.ID + 1
		}
	}
	return &ledger
}

func saveLocalLedger(ledger *TicketLedger) error {
	ledgerMutex.Lock()
	defer ledgerMutex.Unlock()

	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getLedgerPath(), data, 0666)
}

func renderTicketMenuCanvas(peerDisplay, realAuthor, currentInput string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== 📋 P2P TASK & WORK APPROVAL TICKET ENGINE ===" + Reset)
	fmt.Printf(Yellow+"Active Peer Target: "+Reset+Bold+"%s"+Reset+" | "+Yellow+"My Submitter Tag: "+Reset+Bold+"%s"+Reset+" | "+Green+"[Live Auto-Sync Active]"+Reset+"\n", peerDisplay, realAuthor)
	fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)

	ledger := loadLocalLedger()
	renderTicketTable(ledger.Tickets)

	fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
	fmt.Println(Green + Bold + "  [1] ✍️  Submit Completed Work Ticket (Send to Peer for Approval)" + Reset)
	fmt.Println(Cyan + Bold + "  [2] 🟢 Inspect Ticket & Give Green Signal (Approve / Sign-Off)" + Reset)
	fmt.Println(Yellow + "  [3] 🔄 Force Sync & Pull Peer Tickets Across Tunnel" + Reset)
	fmt.Println(Red + "  [4] 🗑️  Delete a Ticket Record" + Reset)
	fmt.Println(Red + "  [0] Back to Main Menu" + Reset)
	fmt.Println(Blue + "----------------------------------------------------------------------------------" + Reset)
	fmt.Printf("Select choice [0-4]: %s", currentInput)
}

func ShowTicketMenu(reader *bufio.Reader, client *ssh.Client, localUser, targetHost string) {
	syncAllLocalInboxesToLedger()
	if client != nil {
		pullRemoteTicketsSilent(client)
	}

	realAuthor := getLocalIdentity()
	peerDisplay := "Standalone (Offline / No Active Target)"
	if targetHost != "" {
		peerDisplay = targetHost
	}

	for {
		if runtime.GOOS != "windows" {
			_ = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "0", "time", "1", "-echo").Run()
		}

		ctx, cancel := context.WithCancel(context.Background())
		var mu sync.Mutex
		inputBuffer := ""

		renderTicketMenuCanvas(peerDisplay, realAuthor, inputBuffer)

		// Real-time autonomous background sync goroutine
		go func(ctx context.Context) {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					updatedLocal := syncAllLocalInboxesToLedger()
					updatedRemote := false
					if client != nil {
						updatedRemote = pullRemoteTicketsSilent(client)
					}
					if updatedLocal || updatedRemote {
						mu.Lock()
						renderTicketMenuCanvas(peerDisplay, realAuthor, inputBuffer)
						mu.Unlock()
					}
				}
			}
		}(ctx)

		var choice string
		keyBuf := make([]byte, 8)

		for {
			n, _ := os.Stdin.Read(keyBuf)
			if n > 0 {
				mu.Lock()
				if n == 1 {
					b := keyBuf[0]
					switch b {
					case 10, 13:
						choice = strings.TrimSpace(inputBuffer)
						mu.Unlock()
						cancel()
						goto ExecuteChoice
					case 127, 8:
						if len(inputBuffer) > 0 {
							inputBuffer = inputBuffer[:len(inputBuffer)-1]
							renderTicketMenuCanvas(peerDisplay, realAuthor, inputBuffer)
						}
					default:
						if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
							inputBuffer += string(b)
							renderTicketMenuCanvas(peerDisplay, realAuthor, inputBuffer)
						}
					}
				}
				mu.Unlock()
			}
			time.Sleep(20 * time.Millisecond)
		}

	ExecuteChoice:
		if runtime.GOOS != "windows" {
			_ = exec.Command("stty", "-F", "/dev/tty", "-cbreak", "echo").Run()
		}

		switch choice {
		case "1":
			if client == nil || targetHost == "" {
				fmt.Println(Yellow + "\n[!] To dispatch a ticket to a peer, lock target in Hub [1] first." + Reset)
				pausePrompt()
				continue
			}
			createTicketPrompt(client, realAuthor, targetHost)
		case "2":
			reviewTicketPrompt(client, realAuthor, targetHost)
		case "3":
			syncRemoteTickets(client)
		case "4":
			deleteTicketPrompt()
		case "0", "q", "Q":
			return
		}
	}
}

func createTicketPrompt(client *ssh.Client, realAuthor, targetHost string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Cyan + Bold + "=== ✍️ SUBMIT WORK TICKET FOR PEER REVIEW ===" + Reset)
	fmt.Printf(Yellow+"Dispatching as Submitter: %s ==> Target Host: %s\n"+Reset, realAuthor, targetHost)
	fmt.Println(Blue + "------------------------------------------------------------------" + Reset)

	title := transfer.ReadRealtimeInput("Enter Task Title / Summary (e.g. Configured WireGuard Routing): ")
	if strings.TrimSpace(title) == "" {
		return
	}
	desc := transfer.ReadRealtimeInput("Enter Work Commit Notes / Changes Made: ")

	ledger := loadLocalLedger()
	timestamp := time.Now().UnixNano()

	ticket := TaskTicket{
		ID:          int((timestamp / 1000000) % 100000),
		Title:       title,
		Description: desc,
		Author:      realAuthor,
		Status:      StatusPending,
		CreatedAt:   time.Now(),
	}

	ledger.Tickets = append(ledger.Tickets, ticket)
	_ = saveLocalLedger(ledger)

	if client != nil {
		syncTicketToRemote(client, ticket)
		dispatchTicketNotification(client, targetHost, realAuthor, fmt.Sprintf("New Task Ticket Submitted #%d: %s", ticket.ID, ticket.Title))
	}

	fmt.Println(Green + Bold + "\n[✔ SUCCESS] Ticket Submitted & Dispatched to Peer System Inboxes!" + Reset)
	pausePrompt()
}

func reviewTicketPrompt(client *ssh.Client, approver, targetHost string) {
	idStr := transfer.ReadRealtimeInput("\nEnter Ticket ID to Review & Approve: ")
	id, err := strconv.Atoi(strings.TrimSpace(idStr))
	if err != nil {
		return
	}

	ledger := loadLocalLedger()
	for i, t := range ledger.Tickets {
		if t.ID == id {
			fmt.Printf(Cyan+"\n--- TICKET #%d: %s ---\n"+Reset, t.ID, t.Title)
			fmt.Printf("Submitter (Author) : %s\n", t.Author)
			fmt.Printf("Submitted Time     : %s\n", t.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Work Commit Notes  : %s\n", t.Description)
			fmt.Println(Blue + "--------------------------------------------------------" + Reset)
			fmt.Println(Green + "  [1] 🟢 Approve & Give Green Signal (Mark Completed)" + Reset)
			fmt.Println(Red + "  [2] ❌ Request Revision / Reject" + Reset)
			fmt.Println(Yellow + "  [0] Cancel" + Reset)

			action := transfer.ReadRealtimeInput("\nSelect Decision [0-2]: ")

			if action == "1" {
				note := transfer.ReadRealtimeInput("Enter Approval Note [default: Verified & Approved]: ")
				if strings.TrimSpace(note) == "" {
					note = "Verified & Approved"
				}
				ledger.Tickets[i].Status = StatusApproved
				ledger.Tickets[i].Approver = approver
				ledger.Tickets[i].HostNote = note
				ledger.Tickets[i].ResolvedAt = time.Now()

				_ = saveLocalLedger(ledger)

				if client != nil {
					syncTicketToRemote(client, ledger.Tickets[i])
					dispatchTicketNotification(client, targetHost, approver, fmt.Sprintf("Ticket #%d APPROVED: %s", t.ID, t.Title))
				}
				fmt.Println(Green + Bold + "\n[✔ SUCCESS] Green Signal Given! Work Approved & Synced." + Reset)
			} else if action == "2" {
				reason := transfer.ReadRealtimeInput("Enter Revision Reason: ")
				ledger.Tickets[i].Status = StatusRejected
				ledger.Tickets[i].HostNote = reason
				ledger.Tickets[i].ResolvedAt = time.Now()

				_ = saveLocalLedger(ledger)

				if client != nil {
					syncTicketToRemote(client, ledger.Tickets[i])
					dispatchTicketNotification(client, targetHost, approver, fmt.Sprintf("Ticket #%d Revision Requested: %s", t.ID, reason))
				}
				fmt.Println(Yellow + Bold + "\n[!] Marked as Needs Revision & Synced to Peer." + Reset)
			}
			pausePrompt()
			return
		}
	}
	fmt.Println(Red + "[!] Ticket ID not found." + Reset)
	pausePrompt()
}

func deleteTicketPrompt() {
	idStr := transfer.ReadRealtimeInput("\nEnter Ticket ID to Delete: ")
	id, err := strconv.Atoi(strings.TrimSpace(idStr))
	if err != nil {
		return
	}
	ledger := loadLocalLedger()
	var newTickets []TaskTicket
	found := false
	for _, t := range ledger.Tickets {
		if t.ID == id {
			found = true
			continue
		}
		newTickets = append(newTickets, t)
	}
	if found {
		ledger.Tickets = newTickets
		_ = saveLocalLedger(ledger)
		fmt.Println(Green + "[✔] Ticket deleted from ledger." + Reset)
	} else {
		fmt.Println(Red + "[!] Ticket ID not found." + Reset)
	}
	pausePrompt()
}

func syncAllLocalInboxesToLedger() bool {
	paths := getInboxCandidatePaths()
	ledger := loadLocalLedger()
	updates := 0

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" {
				continue
			}
			var incoming TaskTicket
			if err := json.Unmarshal([]byte(trimmed), &incoming); err == nil && incoming.ID > 0 {
				merged := false
				for i, existing := range ledger.Tickets {
					if existing.ID == incoming.ID {
						if incoming.ResolvedAt.After(existing.ResolvedAt) ||
							(existing.Status == StatusPending && incoming.Status != StatusPending) ||
							incoming.Status != existing.Status {
							ledger.Tickets[i] = incoming
							updates++
						}
						merged = true
						break
					}
				}
				if !merged {
					ledger.Tickets = append(ledger.Tickets, incoming)
					updates++
				}
			}
		}
		_ = os.Remove(p)
	}

	if updates > 0 {
		_ = saveLocalLedger(ledger)
		return true
	}
	return false
}

func syncTicketToRemote(client *ssh.Client, t TaskTicket) {
	data, err := json.Marshal(t)
	if err != nil {
		return
	}
	sess, err := client.NewSession()
	if err != nil {
		return
	}
	defer sess.Close()

	cmd := fmt.Sprintf(`mkdir -p ~/.cross-ssh /tmp && echo '%s' >> ~/.cross-ssh/peer_inbox.json && echo '%s' >> /tmp/cross_peer_inbox.json && chmod 666 /tmp/cross_peer_inbox.json ~/.cross-ssh/peer_inbox.json 2>/dev/null`, string(data), string(data))
	_ = sess.Run(cmd)
}

func dispatchTicketNotification(client *ssh.Client, host, author, msg string) {
	if client == nil {
		return
	}
	item := NotificationItem{
		SenderIP:  host,
		SenderTag: author,
		Type:      "TICKET",
		Message:   msg,
		Timestamp: time.Now(),
		IsRead:    false,
	}
	data, _ := json.Marshal(item)
	sess, err := client.NewSession()
	if err == nil {
		defer sess.Close()
		_ = sess.Run(fmt.Sprintf(`mkdir -p ~/.cross-ssh /tmp && echo '%s' >> ~/.cross-ssh/notifications.json && echo '%s' >> /tmp/cross_notifications.json && chmod 666 ~/.cross-ssh/notifications.json /tmp/cross_notifications.json 2>/dev/null`, string(data), string(data)))
	}
}

func pullRemoteTicketsSilent(client *ssh.Client) bool {
	if client == nil {
		return false
	}
	sess, err := client.NewSession()
	if err != nil {
		return false
	}
	defer sess.Close()

	// Pull from remote ledger and any pending inbox updates on remote host
	out, err := sess.CombinedOutput("cat ~/.cross-ssh/tickets.json /tmp/cross_peer_inbox.json ~/.cross-ssh/peer_inbox.json 2>/dev/null")
	if err != nil || len(out) == 0 {
		return false
	}

	local := loadLocalLedger()
	updatedCount := 0

	// 1. Try parsing as full ledger JSON
	var remoteLedger TicketLedger
	if err := json.Unmarshal(out, &remoteLedger); err == nil && len(remoteLedger.Tickets) > 0 {
		for _, rt := range remoteLedger.Tickets {
			found := false
			for i, lt := range local.Tickets {
				if lt.ID == rt.ID {
					found = true
					if rt.ResolvedAt.After(lt.ResolvedAt) ||
						(lt.Status == StatusPending && rt.Status != StatusPending) ||
						rt.Status != lt.Status {
						local.Tickets[i] = rt
						updatedCount++
					}
					break
				}
			}
			if !found {
				local.Tickets = append(local.Tickets, rt)
				updatedCount++
			}
		}
	}

	// 2. Also parse line-by-line in case peer_inbox lines are present
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "{ \"tickets\":") {
			continue
		}
		var incoming TaskTicket
		if err := json.Unmarshal([]byte(trimmed), &incoming); err == nil && incoming.ID > 0 {
			found := false
			for i, lt := range local.Tickets {
				if lt.ID == incoming.ID {
					found = true
					if incoming.ResolvedAt.After(lt.ResolvedAt) ||
						(lt.Status == StatusPending && incoming.Status != StatusPending) ||
						incoming.Status != lt.Status {
						local.Tickets[i] = incoming
						updatedCount++
					}
					break
				}
			}
			if !found {
				local.Tickets = append(local.Tickets, incoming)
				updatedCount++
			}
		}
	}

	if updatedCount > 0 {
		_ = saveLocalLedger(local)
		return true
	}
	return false
}

func syncRemoteTickets(client *ssh.Client) {
	if client == nil {
		fmt.Println(Yellow + "[!] No active SSH session to pull remote ledger." + Reset)
		pausePrompt()
		return
	}

	fmt.Println(Yellow + "[+] Synchronizing peer ledger across encrypted tunnel..." + Reset)
	syncAllLocalInboxesToLedger()

	if pullRemoteTicketsSilent(client) {
		fmt.Println(Green + Bold + "[✔ SUCCESS] Bi-directional sync complete! Merged updates from peer ledger." + Reset)
	} else {
		fmt.Println(Green + "[✔] Ledgers are already perfectly in sync." + Reset)
	}
	pausePrompt()
}

func renderTicketTable(tickets []TaskTicket) {
	if len(tickets) == 0 {
		fmt.Println(Yellow + " No task tickets found. Submit a task with Option [1]." + Reset)
		return
	}

	fmt.Printf(Bold+" %-5s | %-26s | %-14s | %-16s | %-16s\n"+Reset, "ID", "TASK SUMMARY", "SUBMITTER", "STATUS", "DECISION / NOTE")
	fmt.Println(Blue + "-------------------------------------------------------------------------------------------------------" + Reset)

	for _, t := range tickets {
		statusStr := Yellow + "[PENDING]" + Reset
		if t.Status == StatusApproved {
			statusStr = Green + Bold + "[✔ APPROVED]" + Reset
		} else if t.Status == StatusRejected {
			statusStr = Red + "[REVISION]" + Reset
		}

		note := t.HostNote
		if note == "" {
			note = "-"
		}
		if len(note) > 16 {
			note = note[:13] + "..."
		}

		title := t.Title
		if len(title) > 26 {
			title = title[:23] + "..."
		}

		author := t.Author
		if len(author) > 14 {
			author = author[:11] + "..."
		}

		fmt.Printf(" %-5d | %-26s | %-14s | %-25s | %-16s\n", t.ID, title, author, statusStr, note)
	}
}

func pausePrompt() {
	fmt.Print(Yellow + "\nPress Enter to return..." + Reset)
	_ = transfer.ReadRealtimeInput("")
}